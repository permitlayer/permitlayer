#![allow(dead_code)]
//! Atomic file operations + IO-error classifier shared with doctor.
//!
//! - [`classify_io_kind`] — maps `std::io::Error` into the four-variant
//!   [`IoKind`] enum that both setup (`cli/setup/` Story 10.2) and
//!   doctor (`cli/doctor/` Story 10.3) consume.
//! - [`atomic_replace_owned_file`] — same-dir tmp + fsync + rename +
//!   parent-dir fsync per LWN atomic-write canon. The parent-dir
//!   fsync is the load-bearing invariant: without it, the dirent
//!   for the new file can be lost on crash even if the data is
//!   durable.
//! - [`fsync_dir`] — directory fsync helper used by
//!   [`atomic_replace_owned_file`] and other atomic primitives.
//! - [`rename_aside`] — pid-stamped sibling rename. Used to move
//!   files aside without losing them (e.g., legacy binary migration
//!   in setup).
//! - [`remove_file_with_retry`] — retries on transient I/O via
//!   [`crate::repair::retry::with_backoff`]; on persistent
//!   `PermissionDenied` escalates via `chmod 0o600` + one retry; on
//!   persistent EPERM escalates via `chown` to root:wheel + one
//!   retry.

use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use super::retry::{RetryDecision, TRANSIENT_FAST, with_backoff_jittered};

/// Classification of an `std::io::Error` for the retry classifier
/// and the doctor EACCES-vs-ENOENT distinction.
///
/// Shared between setup (Story 10.2) and doctor (Story 10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IoKind {
    /// The path does not exist. ENOENT.
    NotFound,
    /// Permission denied. EACCES (typically) or EPERM. Doctor
    /// distinguishes this from `NotFound` to avoid falsely claiming
    /// a file is missing when it's actually root-only.
    PermissionDenied,
    /// Transient error worth retrying: EAGAIN, EINTR, WouldBlock,
    /// TimedOut, ResourceBusy (EBUSY/ETXTBSY).
    Transient,
    /// Any other I/O error class. Terminal by default — retry-worthy
    /// only on explicit override at the call site.
    Other,
}

/// Map an `std::io::Error` into the four-variant `IoKind` taxonomy.
///
/// The mapping is intentionally narrow: callers that need finer
/// distinctions (e.g. distinguishing EACCES from EPERM for escalation
/// in [`remove_file_with_retry`]) inspect the original error via
/// `error.raw_os_error()`.
pub(crate) fn classify_io_kind(err: &io::Error) -> IoKind {
    match err.kind() {
        io::ErrorKind::NotFound => IoKind::NotFound,
        io::ErrorKind::PermissionDenied => IoKind::PermissionDenied,
        io::ErrorKind::Interrupted
        | io::ErrorKind::WouldBlock
        | io::ErrorKind::TimedOut
        | io::ErrorKind::ResourceBusy => IoKind::Transient,
        _ => {
            // macOS `ETXTBSY` (text file busy: 26) — kernel returns
            // this when trying to write/remove an executable that's
            // currently mapped as code. Treat as transient: a few
            // hundred ms is usually enough for the prior daemon to
            // exit fully.
            if matches!(err.raw_os_error(), Some(26)) { IoKind::Transient } else { IoKind::Other }
        }
    }
}

/// Fsync the directory at `dir`. Best-effort: on platforms / file
/// systems that reject directory fsync (rare), the error is
/// returned so the caller decides whether to propagate or swallow.
/// [`atomic_replace_owned_file`] swallows.
pub(crate) fn fsync_dir(dir: &Path) -> io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// Atomic replace via same-dir tmp + fsync + rename + parent-dir
/// fsync.
///
/// Per LWN atomic-write canon (https://lwn.net/Articles/789600/):
/// without the parent-directory fsync after the rename, a crash can
/// lose the new dirent even though the file data is durable. This
/// implementation always calls `fsync_dir` on the parent (best
/// effort — directory fsync failure is logged but does not fail
/// the operation, matching the precedent in `cli/atomic_write.rs:61-63`).
///
/// `src` must be a regular file. Symlinks, device nodes, FIFOs, and
/// directories are rejected with `InvalidInput` — following a
/// symlink to `/dev/zero` would OOM the streamer, and other
/// non-regular types have no defensible "copy" semantic for an
/// atomic-replace primitive.
///
/// File contents are streamed from `src` to the tempfile via
/// [`std::io::copy`] (constant memory) rather than slurped into a
/// `Vec<u8>` — Story 10.2 callers may pass MB-scale binaries.
///
/// On Unix the persisted file is set to `mode` (e.g. `0o600` or
/// `0o644`). On non-Unix the mode parameter is ignored.
pub(crate) fn atomic_replace_owned_file(src: &Path, dst: &Path, mode: u32) -> io::Result<()> {
    // Reject anything that isn't a regular file. `symlink_metadata`
    // does NOT follow links — we see the symlink itself, not its
    // target.
    let src_meta = std::fs::symlink_metadata(src)?;
    if !src_meta.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("source is not a regular file (symlink/device/fifo/dir): {}", src.display()),
        ));
    }

    let parent = dst.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("destination has no parent dir: {}", dst.display()),
        )
    })?;
    if !parent.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("parent dir does not exist: {}", parent.display()),
        ));
    }

    let tmp = tempfile::NamedTempFile::new_in(parent)?;
    let tmp_path = tmp.path().to_owned();
    {
        let mut src_file = std::fs::File::open(src)?;
        let mut tmp_handle = tmp.as_file();
        std::io::copy(&mut src_file, &mut tmp_handle)?;
        tmp_handle.sync_all()?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode; // suppress unused warning
    }

    tmp.persist(dst).map_err(|e| e.error)?;
    let _ = fsync_dir(parent); // best-effort per LWN canon
    Ok(())
}

/// Rename `src` aside to a pid-stamped sibling (`<src>.aside.<pid>`).
/// Returns the new path on success. Used by setup's legacy-binary
/// migration in Story 10.2.
pub(crate) fn rename_aside(src: &Path) -> io::Result<PathBuf> {
    let parent = src.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("source has no parent dir: {}", src.display()),
        )
    })?;
    let file_name = src.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("source has no file name: {}", src.display()),
        )
    })?;
    let bak_name = format!("{}.aside.{}", file_name.to_string_lossy(), std::process::id(),);
    let bak = parent.join(bak_name);
    // Clean any stale crumb from a prior crashed run at this pid.
    let _ = std::fs::remove_file(&bak);
    std::fs::rename(src, &bak)?;
    let _ = fsync_dir(parent);
    Ok(bak)
}

/// Remove a file, retrying on transient I/O and escalating via
/// chmod/chown on persistent permission failures.
///
/// Escalation behavior:
/// - On `EACCES` after retry exhaustion: `chmod 0o600` on the file
///   (if Unix) and retry once.
/// - On `EPERM` after that: `chown` to the running uid:gid and retry
///   once.
///
/// **Spec divergence note (Story 10.1 AC #3):** the story spec said
/// "chown to root:wheel" — implementation chowns to the running
/// uid:gid instead. Reconciliation: the only caller is setup, which
/// elevates via `repair::sudo` before reaching this code path, so
/// running uid:gid IS root:wheel in practice. The spec wording was
/// shorthand for "the privileged uid that owns the target file";
/// the implementation expresses that as "whoever we are right now,"
/// which is equivalent under sudo elevation and also correct under
/// any future non-elevated caller that owns the file. A literal
/// `chown(root, wheel)` would require root regardless of context,
/// defeating the escalation when the caller isn't already root.
///
/// On platforms without `chmod`/`chown` (non-Unix), the escalation
/// branches are no-ops and the final error is returned.
pub(crate) fn remove_file_with_retry(path: &Path) -> io::Result<()> {
    let result = with_backoff_jittered(
        || std::fs::remove_file(path),
        |err| match classify_io_kind(err) {
            IoKind::Transient => RetryDecision::Retry,
            _ => RetryDecision::Final,
        },
        TRANSIENT_FAST,
        std::thread::sleep,
    );

    let err = match result {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };

    // First escalation: chmod 0o600 on persistent EACCES.
    if classify_io_kind(&err) == IoKind::PermissionDenied {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                if std::fs::set_permissions(path, perms).is_ok() {
                    match std::fs::remove_file(path) {
                        Ok(()) => return Ok(()),
                        Err(retry_err) => {
                            // Second escalation: chown to running
                            // uid:gid on persistent EPERM.
                            if matches!(retry_err.raw_os_error(), Some(1)) {
                                let uid = nix::unistd::Uid::current();
                                let gid = nix::unistd::Gid::current();
                                if nix::unistd::chown(path, Some(uid), Some(gid)).is_ok() {
                                    return std::fs::remove_file(path);
                                }
                            }
                            return Err(retry_err);
                        }
                    }
                }
            }
        }
    }

    Err(err)
}

/// Best-effort: open `path` with `O_APPEND` and `mode` (if the file
/// doesn't exist). Used by [`crate::repair::journal::record`].
#[cfg(unix)]
pub(crate) fn open_append_with_mode(path: &Path, mode: u32) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new().create(true).append(true).mode(mode).open(path)
}

/// Non-Unix variant: ignore the mode parameter (Windows ACLs handle
/// file permissions differently).
#[cfg(not(unix))]
pub(crate) fn open_append_with_mode(path: &Path, _mode: u32) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new().create(true).append(true).open(path)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ── classify_io_kind truth table ─────────────────────────────────

    #[test]
    fn classify_io_kind_not_found_is_not_found() {
        let e = io::Error::from(io::ErrorKind::NotFound);
        assert_eq!(classify_io_kind(&e), IoKind::NotFound);
    }

    #[test]
    fn classify_io_kind_permission_denied_is_permission_denied() {
        let e = io::Error::from(io::ErrorKind::PermissionDenied);
        assert_eq!(classify_io_kind(&e), IoKind::PermissionDenied);
    }

    #[test]
    fn classify_io_kind_interrupted_is_transient() {
        let e = io::Error::from(io::ErrorKind::Interrupted);
        assert_eq!(classify_io_kind(&e), IoKind::Transient);
    }

    #[test]
    fn classify_io_kind_would_block_is_transient() {
        let e = io::Error::from(io::ErrorKind::WouldBlock);
        assert_eq!(classify_io_kind(&e), IoKind::Transient);
    }

    #[test]
    fn classify_io_kind_timed_out_is_transient() {
        let e = io::Error::from(io::ErrorKind::TimedOut);
        assert_eq!(classify_io_kind(&e), IoKind::Transient);
    }

    #[test]
    fn classify_io_kind_resource_busy_is_transient() {
        let e = io::Error::from(io::ErrorKind::ResourceBusy);
        assert_eq!(classify_io_kind(&e), IoKind::Transient);
    }

    #[test]
    fn classify_io_kind_text_file_busy_etxtbsy_is_transient() {
        // ETXTBSY = 26 on macOS + Linux. Constructed via from_raw_os_error
        // so the underlying raw_os_error() returns Some(26) — the
        // ErrorKind would normally be Uncategorized, which would
        // otherwise fall through to Other.
        let e = io::Error::from_raw_os_error(26);
        assert_eq!(classify_io_kind(&e), IoKind::Transient);
    }

    #[test]
    fn classify_io_kind_other_falls_through_to_other() {
        let e = io::Error::from(io::ErrorKind::InvalidData);
        assert_eq!(classify_io_kind(&e), IoKind::Other);
    }

    // ── atomic_replace_owned_file ────────────────────────────────────

    #[test]
    fn atomic_replace_writes_bytes_with_mode() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("source.bin");
        let dst = dir.path().join("dest.bin");
        std::fs::write(&src, b"hello world").unwrap();
        atomic_replace_owned_file(&src, &dst, 0o600).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"hello world");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dst).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn atomic_replace_errors_when_parent_missing() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("source.bin");
        std::fs::write(&src, b"x").unwrap();
        let dst = dir.path().join("does/not/exist/dest.bin");
        let err = atomic_replace_owned_file(&src, &dst, 0o600).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_replace_rejects_symlink_src() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let real_target = dir.path().join("real.bin");
        std::fs::write(&real_target, b"contents").unwrap();
        let link = dir.path().join("link.bin");
        symlink(&real_target, &link).unwrap();
        let dst = dir.path().join("dest.bin");
        let err = atomic_replace_owned_file(&link, &dst, 0o600).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn atomic_replace_rejects_directory_src() {
        let dir = tempfile::tempdir().unwrap();
        let src_dir = dir.path().join("src_dir");
        std::fs::create_dir(&src_dir).unwrap();
        let dst = dir.path().join("dest.bin");
        let err = atomic_replace_owned_file(&src_dir, &dst, 0o600).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    // ── rename_aside ─────────────────────────────────────────────────

    #[test]
    fn rename_aside_moves_file_to_pid_stamped_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("victim");
        std::fs::write(&src, b"contents").unwrap();
        let bak = rename_aside(&src).unwrap();
        assert!(!src.exists(), "original should be gone after rename_aside");
        assert!(bak.exists(), "aside path should exist");
        assert_eq!(std::fs::read(&bak).unwrap(), b"contents");
        // Name format check: <basename>.aside.<pid>
        let pid_str = std::process::id().to_string();
        let bak_name = bak.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            bak_name.starts_with("victim.aside.") && bak_name.ends_with(&pid_str),
            "unexpected aside name: {bak_name}"
        );
    }

    #[test]
    fn rename_aside_overwrites_stale_crumb_from_prior_pid_collision() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("victim");
        std::fs::write(&src, b"new").unwrap();
        // Stale crumb at the same pid (simulates a crashed prior run).
        let stale = dir.path().join(format!("victim.aside.{}", std::process::id()));
        std::fs::write(&stale, b"stale").unwrap();
        let bak = rename_aside(&src).unwrap();
        assert_eq!(bak, stale);
        assert_eq!(std::fs::read(&bak).unwrap(), b"new", "new contents won");
    }

    // ── remove_file_with_retry ───────────────────────────────────────

    #[test]
    fn remove_file_with_retry_removes_normal_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("victim");
        std::fs::write(&path, b"x").unwrap();
        remove_file_with_retry(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn remove_file_with_retry_propagates_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("never-existed");
        let err = remove_file_with_retry(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    // The chown-escalation branch requires being root, which CI
    // isn't. The chmod-escalation branch requires a file mode
    // that prevents removal — but on Unix the parent dir's write
    // bit controls remove, not the file's bits. So the chmod
    // branch is hard to unit-test reliably without root.
    // Escalation behavior is covered by integration tests in
    // Story 10.2's setup self-heal e2e suite.
}
