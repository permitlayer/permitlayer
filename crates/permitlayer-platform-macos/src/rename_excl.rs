//! `renameatx_np` wrapper with `RENAME_EXCL` semantics.
//!
//! Apple's `renameatx_np(2)` is a Darwin extension (Sierra 10.12+;
//! PermitLayer min-macOS is 13.0 Ventura per Story 7.7 so it is
//! unconditionally available). `RENAME_EXCL` (`0x4`) tells the kernel
//! to fail the rename with `EEXIST` if the destination already
//! exists — atomic create-or-fail semantics, no TOCTOU window.
//!
//! Primary source: Darwin SDK header
//! `/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/stdio.h`:
//!
//! ```c
//! int renameatx_np(int fromfd, const char *from,
//!                  int tofd,   const char *to,
//!                  unsigned int flags);
//! #define RENAME_SECLUDE  0x00000001
//! #define RENAME_SWAP     0x00000002
//! #define RENAME_EXCL     0x00000004
//! ```
//!
//! Used by Story 7.27's per-user `agent-bearer.token` write to
//! prevent a hostile end-user from pre-creating the target file as
//! a symlink to (say) `/etc/sudoers`. The token-write helper
//! first opens the parent directory with `O_NOFOLLOW`, then writes
//! the token to a temp file in the daemon's own state dir (chowns
//! it to the end-user), then `rename_excl`s the temp file to the
//! target. On `EEXIST`, the caller audit-logs the existing-token
//! replacement event and retries with plain `renameat` (so token
//! rotation continues to work).

use std::ffi::CString;
use std::io;
use std::os::raw::{c_char, c_int, c_uint};
use std::path::Path;

/// `AT_FDCWD` sentinel (`-2` on Darwin); means "the path is resolved
/// relative to the current working directory."
const AT_FDCWD: c_int = -2;

/// `RENAME_EXCL` flag from `<sys/stdio.h>`. Fails with `EEXIST` if
/// the destination already exists. Atomic — no TOCTOU window between
/// the existence check and the rename, unlike `link(2)`+`unlink(2)`
/// dances.
const RENAME_EXCL: c_uint = 0x0000_0004;

unsafe extern "C" {
    fn renameatx_np(
        fromfd: c_int,
        from: *const c_char,
        tofd: c_int,
        to: *const c_char,
        flags: c_uint,
    ) -> c_int;
}

/// Atomic rename-if-target-does-not-exist.
///
/// Returns `Ok(())` on success.
/// Returns `Err` with `io::ErrorKind::AlreadyExists` (raw os error
/// `EEXIST` = 17) when the destination already exists.
/// Returns other `io::Error` variants for other failure modes
/// (permission denied, source missing, etc.) — caller matches on
/// `raw_os_error()` if it cares about the specific errno.
///
/// **Symlink semantics**: `renameatx_np` resolves the destination
/// path's containing directory normally (following symlinks on
/// intermediate components). The check is "does an inode exist at
/// the resolved destination path?" — NOT "is the destination path a
/// symlink?". For the per-user token-write path, symlink defense at
/// the parent-directory layer is required (open parent with
/// `O_NOFOLLOW` before constructing the destination path); this
/// function alone is NOT sufficient defense against a symlinked
/// parent dir.
pub fn rename_excl(src: &Path, dst: &Path) -> io::Result<()> {
    let src_c = CString::new(src.as_os_str().as_encoded_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let dst_c = CString::new(dst.as_os_str().as_encoded_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    // SAFETY: `src_c` and `dst_c` are valid NUL-terminated C strings
    // for the duration of the call (their `Drop` runs after the
    // `unsafe` block). `AT_FDCWD` is the standard sentinel accepted
    // by every `*at` syscall on Darwin. `RENAME_EXCL` is a documented
    // flag value defined in `<sys/stdio.h>`. The libc function does
    // not retain pointers after return.
    let rc =
        unsafe { renameatx_np(AT_FDCWD, src_c.as_ptr(), AT_FDCWD, dst_c.as_ptr(), RENAME_EXCL) };

    if rc == -1 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn rename_excl_succeeds_when_dst_missing() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let dst = dir.path().join("dst.txt");
        fs::write(&src, b"hello").unwrap();

        rename_excl(&src, &dst).expect("rename should succeed");

        assert!(!src.exists(), "src must be moved");
        assert_eq!(fs::read(&dst).unwrap(), b"hello");
    }

    #[test]
    fn rename_excl_fails_with_already_exists_when_dst_present() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let dst = dir.path().join("dst.txt");
        fs::write(&src, b"new").unwrap();
        fs::write(&dst, b"old").unwrap();

        let err = rename_excl(&src, &dst).expect_err("rename must fail");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "expected AlreadyExists, got {err:?}");
        // EEXIST = 17 on Darwin (and Linux).
        assert_eq!(err.raw_os_error(), Some(libc::EEXIST));
        // Both files survive — the source is NOT consumed on failure.
        assert_eq!(fs::read(&src).unwrap(), b"new");
        assert_eq!(fs::read(&dst).unwrap(), b"old");
    }

    #[test]
    fn rename_excl_fails_when_src_missing() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("does-not-exist");
        let dst = dir.path().join("dst.txt");

        let err = rename_excl(&src, &dst).expect_err("rename must fail");
        // ENOENT on src.
        assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
    }

    #[test]
    fn rename_excl_path_with_nul_byte_rejected() {
        // Defense-in-depth: paths containing interior NUL would
        // produce a truncated C string. We reject up front instead of
        // delegating to the kernel.
        let bad_src = Path::new("/tmp/has\0nul");
        let dst = Path::new("/tmp/ignore");
        let err = rename_excl(bad_src, dst).expect_err("nul byte must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn rename_excl_dst_is_symlink_to_nonexistent_target() {
        // Documents the symlink-on-dst behavior: if the destination
        // path is a symlink that points to a non-existent target,
        // `renameatx_np(RENAME_EXCL)` still fails with `EEXIST` —
        // because the symlink ITSELF is an inode that "exists". The
        // call does NOT silently overwrite the symlink. This is the
        // behavior we want for the token-write path: an attacker who
        // pre-creates a symlink at the target location cannot trick
        // us into writing through it.
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let dst = dir.path().join("dst-symlink");
        let phantom = dir.path().join("does-not-exist");
        let mut f = fs::File::create(&src).unwrap();
        f.write_all(b"new").unwrap();
        std::os::unix::fs::symlink(&phantom, &dst).unwrap();

        let err = rename_excl(&src, &dst).expect_err("symlink at dst must produce EEXIST");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        // The symlink survives.
        assert!(dst.symlink_metadata().unwrap().file_type().is_symlink());
    }
}
