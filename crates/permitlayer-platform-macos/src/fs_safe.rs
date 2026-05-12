//! Safe wrappers around filesystem syscalls that work on dir fds.
//!
//! All wrappers in this module isolate the `unsafe { libc::* }` calls
//! the daemon needs for symlink-resistant token-writes (Story 7.27
//! review fix) and the umask-tightened UDS bind window (P0 fix).
//! `permitlayer-daemon` is under `#![forbid(unsafe_code)]`; this
//! crate is the documented unsafe-isolation seam.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};
use std::path::Path;

/// Open `path` as a directory with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`.
/// Symlinks at the final path component return `ELOOP` so callers can
/// refuse closed. The returned `OwnedFd` closes on drop.
///
/// Bounded EINTR retry (8 attempts) — `open(2)` is interruptible on
/// some Darwin paths (NFS-mounted home dirs, slow APFS volumes); a
/// spurious signal should not surface as a token-write failure.
pub fn open_dir_nofollow(path: &Path) -> io::Result<OwnedFd> {
    let cstr = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut attempts = 0;
    let fd = loop {
        // SAFETY: `cstr` is a valid NUL-terminated C string for the
        // call. The kernel returns either a valid fd (>= 0) or -1 with
        // errno set.
        let fd = unsafe {
            libc::open(
                cstr.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd >= 0 {
            break fd;
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) && attempts < 8 {
            attempts += 1;
            continue;
        }
        return Err(err);
    };
    // SAFETY: `fd` is a freshly opened fd owned by this thread.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `fchown(fd, uid, gid)` — chown an open file/dir fd in-place.
///
/// Refuses `u32::MAX` for either argument. Defense-in-depth: the
/// `LOCAL_PEERCRED` failure path in [`crate::peer_cred`] produces
/// `u32::MAX` as a sentinel; POSIX `fchown(fd, -1, -1)` is documented
/// as a no-op (preserve ownership), so an accidental sentinel-flow
/// would leave the dir root-owned silently. Reject loudly instead.
pub fn fchown_fd(fd: RawFd, uid: u32, gid: u32) -> io::Result<()> {
    if uid == u32::MAX || gid == u32::MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fchown_fd: sentinel UID/GID (u32::MAX) rejected",
        ));
    }
    // SAFETY: `fchown` only reads (fd, uid, gid) and reports success
    // via return code. No memory aliasing.
    let rc = unsafe { libc::fchown(fd, uid, gid) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `fchmod(fd, mode)` — chmod an open file/dir fd in-place.
///
/// `mode` is `u32` for caller convenience (Rust permission literals
/// `0o600` are `u32` by default), but on macOS `mode_t` is `u16`. A
/// `debug_assert` guards against accidental bit-loss in the cast;
/// production callers stay in the 12-bit permission range.
pub fn fchmod_fd(fd: RawFd, mode: u32) -> io::Result<()> {
    debug_assert!(
        mode <= libc::mode_t::MAX as u32,
        "fchmod_fd: mode 0o{mode:o} exceeds mode_t range",
    );
    // SAFETY: same rationale as `fchown_fd`.
    let rc = unsafe { libc::fchmod(fd, mode as libc::mode_t) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `fstatat(dir_fd, name, AT_SYMLINK_NOFOLLOW)` — stat a name relative
/// to an open dir fd, without following symlinks at the final
/// component. Returns the raw `libc::stat` so callers can read `uid`,
/// `gid`, `mode` without re-traversing the path.
///
/// Bounded EINTR retry (8 attempts) — same rationale as
/// [`open_dir_nofollow`].
pub fn fstatat_nofollow(dir_fd: RawFd, name: &str) -> io::Result<libc::stat> {
    let cstr = CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut buf = std::mem::MaybeUninit::<libc::stat>::uninit();
    let mut attempts = 0;
    loop {
        // SAFETY: `buf` is sized for `libc::stat`; the kernel writes
        // into it iff `rc == 0`. `cstr` is a valid NUL-terminated
        // string for the call.
        let rc = unsafe {
            libc::fstatat(dir_fd, cstr.as_ptr(), buf.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW)
        };
        if rc == 0 {
            break;
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) && attempts < 8 {
            attempts += 1;
            continue;
        }
        return Err(err);
    }
    // SAFETY: `fstatat` returned 0, so the kernel initialized `buf`.
    Ok(unsafe { buf.assume_init() })
}

/// `unlinkat(dir_fd, name, 0)` — remove a name relative to an open
/// dir fd. Pass `AT_REMOVEDIR` via a future overload if needed.
pub fn unlinkat_dir_fd(dir_fd: RawFd, name: &str) -> io::Result<()> {
    let cstr = CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // SAFETY: standard syscall, no aliasing.
    let rc = unsafe { libc::unlinkat(dir_fd, cstr.as_ptr(), 0) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// RAII guard that restores the process umask on drop. Returned by
/// [`with_umask`]; constructed via [`UmaskGuard::set`].
///
/// Restoring on `Drop` is the load-bearing property — if `f` inside
/// `with_umask` panics, unwinding past straight-line code skips the
/// restore call and the process is left with the tight mask
/// indefinitely (every subsequent file write across every thread
/// inherits the tight perms). Drop runs during unwind, closing that
/// hole.
struct UmaskGuard {
    prev: libc::mode_t,
}

impl UmaskGuard {
    /// Set the process umask to `tight` and return a guard that
    /// restores the previous mask on drop.
    fn set(tight: libc::mode_t) -> Self {
        // SAFETY: `umask(2)` is documented as always-succeeds and
        // returns the previous mask.
        let prev = unsafe { libc::umask(tight) };
        Self { prev }
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: same as `UmaskGuard::set`.
        unsafe {
            libc::umask(self.prev);
        }
    }
}

/// Run `f` with the process umask temporarily set to `tight`. Restores
/// the previous umask before returning AND on panic (RAII via
/// [`UmaskGuard`]).
///
/// The mask change is **process-global** and **not thread-safe**.
/// Callers MUST:
/// - Keep `f` short — a long-running closure holds the tighter mask
///   across unrelated thread allocations, silently affecting other
///   threads' file modes.
/// - Avoid concurrent invocation — two threads calling `with_umask`
///   simultaneously can interleave their set/restore calls and leak a
///   wrong mask. The intended discipline is single-call-at-startup
///   (e.g., the `bind_control_listener_no_perms` path on daemon boot).
///
/// Story 7.27 P0 review fix: used to wrap `UnixListener::bind` so the
/// socket inode is created mode 0600 from the moment it exists,
/// closing the window between `bind` and the post-bind chgrp+chmod
/// 0660 where any local process could `connect(2)` to it.
pub fn with_umask<R>(tight: u32, f: impl FnOnce() -> R) -> R {
    let _guard = UmaskGuard::set(tight as libc::mode_t);
    f()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    use tempfile::tempdir;

    #[test]
    fn open_dir_nofollow_succeeds_on_real_dir() {
        let dir = tempdir().unwrap();
        let fd = open_dir_nofollow(dir.path()).expect("open should succeed");
        // Verify fd is usable.
        assert!(fd.as_raw_fd() > 0);
    }

    #[test]
    fn open_dir_nofollow_refuses_symlinked_dir() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        std::fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = open_dir_nofollow(&link).expect_err("symlink must be refused");
        // Darwin returns ELOOP for symlink-to-file under O_NOFOLLOW,
        // but ENOTDIR for symlink-to-dir under O_DIRECTORY|O_NOFOLLOW
        // because the kernel checks the dir-ness of the *symlink
        // inode* (a symlink isn't a directory). Either errno
        // satisfies the symlink-defense contract: the call refuses
        // to traverse the symlink, which is what callers test for.
        let errno = err.raw_os_error();
        assert!(
            errno == Some(libc::ELOOP) || errno == Some(libc::ENOTDIR),
            "expected ELOOP or ENOTDIR, got {errno:?}",
        );
    }

    #[test]
    fn with_umask_restores_previous_mask() {
        // Establish a known prior umask, then verify with_umask
        // restores it. Probe via `umask(0)`-then-restore round-trip
        // — reading the current umask without changing it requires
        // this dance since POSIX `umask(2)` is set-and-return.
        let saved = unsafe { libc::umask(0o022) };
        let result = with_umask(0o177, || 42);
        assert_eq!(result, 42);
        let after_probe = unsafe { libc::umask(0o077) };
        unsafe {
            libc::umask(saved);
        }
        assert_eq!(after_probe, 0o022, "with_umask must restore the prior mask");
    }

    #[test]
    fn with_umask_actually_applies_tight_mask_inside_closure() {
        // Functional test: create a file inside the closure with
        // mode 0o666 requested. With tight=0o177 the on-disk mode
        // should be 0o600 (0o666 & !0o177).
        let dir = tempdir().unwrap();
        let saved = unsafe { libc::umask(0o022) };
        let path = dir.path().join("probe");
        with_umask(0o177, || {
            std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o666)
                .open(&path)
                .unwrap();
        });
        unsafe {
            libc::umask(saved);
        }
        let meta = std::fs::metadata(&path).unwrap();
        let mode = std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o777;
        assert_eq!(
            mode, 0o600,
            "with_umask(0o177) should yield 0o600 for a 0o666 create — got 0o{mode:o}"
        );
    }

    #[test]
    fn with_umask_restores_on_panic() {
        // Panic-safety: the RAII guard must restore the umask even
        // when the closure unwinds.
        let saved = unsafe { libc::umask(0o022) };
        let result = std::panic::catch_unwind(|| {
            with_umask(0o177, || panic!("intentional"));
        });
        // After panic the mask must be 0o022, not 0o177.
        let probe = unsafe { libc::umask(0o077) };
        unsafe {
            libc::umask(saved);
        }
        assert!(result.is_err(), "panic should propagate out of with_umask");
        assert_eq!(probe, 0o022, "umask must be restored after panic in closure");
    }
}
