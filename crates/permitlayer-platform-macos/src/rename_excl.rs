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
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::Path;

/// Reject path-component names that contain `/`, `..`, or embedded
/// NUL bytes. The dir-fd-anchored security model assumes
/// `from_name`/`to_name` are single path components; a `/` in the
/// name would resolve relative to the dir fd but traverse
/// upward/inward, defeating the anchoring. A `..` component would let
/// a caller escape the dir entirely. An embedded NUL would otherwise
/// be caught by `CString::new` downstream, but explicit rejection
/// here keeps the failure attributable to the validator — and lets
/// the test below assert that the validator (not the downstream
/// `CString` path) is what rejected the name.
///
/// Current call-sites pass fixed literals so this is defense-in-depth
/// only — but the public API surface accepts arbitrary `&str` and a
/// future caller could pass attacker-controlled input.
fn validate_single_component(name: &str) -> io::Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("not a single path component: {name:?}"),
        ));
    }
    Ok(())
}

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
    let src_c = CString::new(src.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let dst_c = CString::new(dst.as_os_str().as_bytes())
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

/// `renameatx_np` variant relative to an open directory file
/// descriptor on both sides. Caller is responsible for opening
/// `dir_fd` with `O_NOFOLLOW | O_DIRECTORY` if symlink defense on
/// the parent path is required (Story 7.27 token-write path).
///
/// Errors mirror [`rename_excl`]: `AlreadyExists` on `EEXIST`,
/// `last_os_error()` otherwise.
///
/// Story 7.27 review fix: the original `rename_excl` resolved
/// `tmp_path` and `target` via `AT_FDCWD`, which follows symlinks on
/// every intermediate path component. Holding the parent dir fd open
/// across the bind sequence ensures the rename targets the inode the
/// daemon validated, not whatever path resolution finds at rename
/// time.
pub fn rename_excl_at(
    from_dirfd: RawFd,
    from_name: &str,
    to_dirfd: RawFd,
    to_name: &str,
) -> io::Result<()> {
    validate_single_component(from_name)?;
    validate_single_component(to_name)?;
    let from_c =
        CString::new(from_name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let to_c = CString::new(to_name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    // SAFETY: `from_c` and `to_c` are valid NUL-terminated C strings
    // for the duration of the call. The dir fds are caller-supplied;
    // if either is invalid the kernel returns EBADF and we propagate
    // it as io::Error.
    let rc =
        unsafe { renameatx_np(from_dirfd, from_c.as_ptr(), to_dirfd, to_c.as_ptr(), RENAME_EXCL) };

    if rc == -1 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// `renameat(from_dir_fd, from_name, to_dir_fd, to_name)` — plain
/// POSIX rename relative to dir fds, no `RENAME_EXCL`. Used by the
/// token-rotation fallback after the EEXIST audit event is emitted.
///
/// **Threat model.** This is the *clobbering* variant — it overwrites
/// the destination unconditionally. Between an exclusive
/// [`rename_excl_at`] that returned `EEXIST` and a subsequent
/// `rename_at` over the same destination, an attacker who can write
/// into the parent dir could swap the destination inode (TOCTOU). To
/// stay safe, callers MUST guarantee:
/// - The parent dir is mode `0700` (or tighter) and owned by a
///   principal the attacker cannot impersonate, OR
/// - The destination name lives in a per-peer-UID dir whose
///   ownership the caller has just attested via [`crate::fs_safe`]
///   (`fstatat_nofollow` + `open_dir_nofollow` chain), AND
/// - The caller validates the destination inode post-rename
///   (`S_ISREG` + expected uid/gid/mode) before treating the rename
///   as authoritative.
///
/// Story 7.27 callers (`agent_token.rs` rotation flow) satisfy this:
/// the parent dir is `<home>/.agentsso/` validated via a dir-fd chain
/// before the call, and a post-rename `fstatat_nofollow` checks
/// owner/mode/`S_ISREG`. Other callers MUST replicate the pattern.
pub fn rename_at(
    from_dirfd: RawFd,
    from_name: &str,
    to_dirfd: RawFd,
    to_name: &str,
) -> io::Result<()> {
    validate_single_component(from_name)?;
    validate_single_component(to_name)?;
    let from_c =
        CString::new(from_name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let to_c = CString::new(to_name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    // SAFETY: same rationale as `rename_excl_at`. Uses the libc
    // binding for `renameat(2)` so the ABI source is the standard
    // libc crate, not a one-off extern block in this file.
    let rc = unsafe { libc::renameat(from_dirfd, from_c.as_ptr(), to_dirfd, to_c.as_ptr()) };
    if rc == -1 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::os::unix::io::AsRawFd;
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
        // Tighten coverage: the cause must be a NUL byte (downcast to
        // CString's NulError). This decouples the test from the
        // io::ErrorKind classification, which could shift to e.g.
        // NotFound if CString::new were ever bypassed and we delegated
        // to the kernel.
        let inner = err.into_inner().expect("io::Error must carry an inner cause");
        assert!(
            inner.downcast::<std::ffi::NulError>().is_ok(),
            "inner cause must be CString NulError"
        );
    }

    #[test]
    fn rename_excl_at_rejects_path_separator_in_name() {
        // Defense-in-depth: dir-fd-anchored renames must reject names
        // containing `/`, `..`, or embedded NUL so a caller cannot
        // escape the anchoring. Round-3 review fix: the previous test
        // included `"..\0nul"` and asserted `InvalidInput`, but the
        // validator did not check for NUL bytes; the rejection came
        // from `CString::new` downstream. With NUL now in the
        // validator, the assertion below verifies the validator
        // (not `CString`) refused the name.
        let dir = tempdir().unwrap();
        let dir_fd = crate::open_dir_nofollow(dir.path()).expect("open_dir_nofollow");
        let raw = dir_fd.as_raw_fd();
        for bad in ["with/slash", "..", "./inner", "", "has\0nul"] {
            let err = rename_excl_at(raw, bad, raw, "ok")
                .expect_err(&format!("rename_excl_at must reject {bad:?}"));
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            // The validator wraps its rejection in `io::Error::new`
            // with a `String` message; a `CString::NulError` would
            // wrap a `NulError` typed cause. Verify the cause is the
            // validator's string-error (no NulError downcast available).
            let inner = err.into_inner().expect("validator must attach an inner cause");
            assert!(
                inner.downcast::<std::ffi::NulError>().is_err(),
                "rejection must come from validator, not CString"
            );

            let err = rename_at(raw, "ok", raw, bad)
                .expect_err(&format!("rename_at must reject {bad:?}"));
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn rename_excl_at_actually_anchors_to_dir_fd() {
        // Positive test: `rename_excl_at` must resolve `from_name` /
        // `to_name` relative to the supplied dir fds, NOT relative to
        // the process's current working directory. Round-3 review fix
        // (Edge Case Hunter): previous tests only exercised the
        // negative path (bad names rejected); no test asserted that
        // the rename actually anchored on the dir fd.
        //
        // Setup: create two tempdirs (A and B). Chdir to A. Create
        // `src` inside B and dir-fd-anchor a rename of `src` → `dst`
        // in B. Then verify:
        //   1. The file lives at B/dst, NOT at A/dst.
        //   2. Neither A/src nor A/dst exists.
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        fs::write(dir_b.path().join("src.txt"), b"anchored").unwrap();

        let prev_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir_a.path()).expect("chdir to A");

        let b_fd = crate::open_dir_nofollow(dir_b.path()).expect("open B");
        let result = rename_excl_at(b_fd.as_raw_fd(), "src.txt", b_fd.as_raw_fd(), "dst.txt");

        std::env::set_current_dir(&prev_cwd).expect("restore cwd");
        result.expect("rename must succeed when anchored to B");

        // File moved within B.
        assert!(!dir_b.path().join("src.txt").exists(), "B/src must be gone");
        assert_eq!(fs::read(dir_b.path().join("dst.txt")).unwrap(), b"anchored");
        // A is untouched.
        assert!(!dir_a.path().join("src.txt").exists(), "A/src must not exist");
        assert!(!dir_a.path().join("dst.txt").exists(), "A/dst must not exist");
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
