//! Vault-level advisory file lock (Story 7.6a AC #1).
//!
//! [`VaultLock`] is an `flock(LOCK_EX)` (Unix) / `LockFileEx` (Windows)
//! RAII guard around `~/.agentsso/.vault.lock` (sibling of
//! `~/.agentsso/vault/`, not inside it — Windows `LockFileEx` is
//! mandatory and would block the v1 → v2 migration's
//! `rename(vault/, vault.bak/)` step). It serializes every writer of
//! the vault — the long-running daemon, every CLI subcommand that
//! mutates credentials (`agentsso setup`, `agentsso rotate-key`), and
//! the `cli::update::migrations` schema-upgrade path.
//!
//! # Why an advisory lock and not a mutex
//!
//! The lock has to coordinate across **processes**, not threads. The
//! daemon is one process; `agentsso setup` is a separate process; the
//! migration runs inside `agentsso update --apply` which is yet another
//! process. A `tokio::sync::Mutex` or `parking_lot::Mutex` only
//! serializes within the running process. `flock` / `LockFileEx` give
//! us cross-process exclusion that the kernel releases automatically on
//! process exit (so a SIGKILL'd holder can't permanently strand the
//! lock).
//!
//! On Unix the lock is **advisory** — readers and writers that don't
//! call `flock` can still touch the files. We control every writer in
//! tree, so this is fine; an operator hand-editing the vault while
//! `agentsso rotate-key` runs is on their own. On Windows `LockFileEx`
//! is **mandatory** (kernel-enforced), which is strictly stronger but
//! shouldn't matter in practice for the same reason.
//!
//! # Holder-identity reporting
//!
//! When [`VaultLock::try_acquire`] returns [`VaultLockError::Busy`] the
//! error carries the lock-holder's PID and `argv[0]` so an operator
//! seeing `daemon_start_vault_busy` immediately knows whether the
//! conflict is `agentsso rotate-key`, `agentsso setup`, or another
//! daemon already running. The holder writes the metadata after
//! acquiring the lock; a write failure is logged but does NOT block
//! lock acquisition (the lock is real, the metadata is forensic).
//!
//! # Deadlock-prevention rule
//!
//! **A single Tokio task MUST NOT hold two `VaultLock` instances
//! simultaneously.** [`crate::store::fs::CredentialFsStore`] acquires the
//! lock inside its own scope on every `put`; callers that already hold
//! a `VaultLock` (the migration path, future bulk operations) MUST NOT
//! call `CredentialFsStore::put` while holding the lock — that would
//! deadlock as the inner `acquire` blocks on the outer guard. Such
//! callers should use byte-layer atomic-write helpers (the same
//! discipline as
//! [`crate::store::fs::credential_fs::atomic_write_real`][^aw]).
//!
//! [^aw]: `atomic_write_real` is private to the `credential_fs` module
//!   today; the migration in Story 7.6a duplicates the
//!   tempfile-+-rename-+-fsync sequence directly to avoid the
//!   re-acquire deadlock.
//!
//! # Cross-platform conformance
//!
//! `fs4::fs_std::FileExt` wraps `flock`/`LockFileEx` behind a single
//! API. The blocking variant ([`VaultLock::acquire`]) maps to
//! `flock(LOCK_EX)` / `LockFileEx(LOCKFILE_EXCLUSIVE_LOCK)`; the
//! non-blocking variant ([`VaultLock::try_acquire`]) maps to
//! `flock(LOCK_EX | LOCK_NB)` /
//! `LockFileEx(LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY)`.
//! `WouldBlock`-class errors translate to [`VaultLockError::Busy`];
//! everything else surfaces as [`VaultLockError::Io`].

use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};

use fs4::FileExt;
use fs4::TryLockError;
use thiserror::Error;

/// Filename of the vault advisory-lock marker, **relative to the
/// `<home>` directory** (sibling of `vault/`, NOT inside it).
/// Persisted across boots — never deleted by `VaultLock` itself.
///
/// See the module docs for why the lock lives next to `vault/` rather
/// than inside it (Windows mandatory `LockFileEx` vs the v1 → v2
/// migration's `rename(vault/, vault.bak/)`).
const LOCK_FILENAME: &str = ".vault.lock";

/// Maximum number of bytes [`try_acquire`] reads from the lock file
/// when reporting the holder's PID + command. Anything larger would
/// indicate a corrupt or operator-edited file; cap at 256 bytes (PID
/// is at most 10 decimal digits + newline; argv[0] is bounded by
/// `PATH_MAX` ≈ 4096 on most systems but operator-readable paths are
/// typically <100 bytes — 256 is comfortable headroom).
const HOLDER_METADATA_READ_LIMIT: u64 = 256;

/// Errors returned by [`VaultLock::acquire`] / [`VaultLock::try_acquire`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VaultLockError {
    /// `try_acquire` failed because another process already holds the
    /// lock. The holder's PID and argv[0] are surfaced when the lock
    /// file's holder-metadata read succeeded.
    #[error("vault lock is busy (held by pid={holder_pid:?} command={holder_command:?})")]
    Busy {
        /// PID of the holder, if the lock file's metadata read succeeded.
        holder_pid: Option<u32>,
        /// First-line of `argv[0]` for the holder, if the lock file's
        /// metadata read succeeded. Truncated to a reasonable display
        /// length by the writer.
        holder_command: Option<String>,
    },

    /// I/O failure unrelated to lock contention — e.g. permission
    /// denied on the vault dir, lock file is a symlink, disk full
    /// while creating the file.
    #[error("vault lock I/O failure")]
    Io(#[from] io::Error),
}

/// RAII guard for the vault-level advisory lock.
///
/// The lock is held for the lifetime of the [`VaultLock`] value;
/// dropping the guard releases it. Drop runs on both the success path
/// AND a panic-unwind path — the `flock` is bound to the underlying
/// `File`, and the kernel releases it when the file descriptor closes.
///
/// See the module docs for the full discipline (deadlock-prevention,
/// holder-metadata, cross-platform mapping).
pub struct VaultLock {
    /// Open handle to `<home>/.vault.lock`. The kernel-side lock is
    /// associated with this descriptor; `Drop` closes it via the
    /// `File`'s own `Drop` and releases the lock.
    file: File,
    /// Path to the lock file — retained so [`Drop`] can clear the
    /// holder metadata best-effort before the file closes.
    path: PathBuf,
}

impl VaultLock {
    /// Acquire the vault lock, blocking until it becomes available.
    ///
    /// Creates `<home>/.vault.lock` (and the `vault/` directory
    /// itself, mode `0o700` on Unix) if absent. Returns once the
    /// kernel grants the exclusive lock; the guard's [`Drop`]
    /// releases it.
    ///
    /// # Errors
    ///
    /// [`VaultLockError::Io`] on filesystem failure (vault dir
    /// uncreatable, lock file is a symlink, permission denied, etc.).
    /// [`VaultLockError::Busy`] is **never** returned by the blocking
    /// variant — use [`VaultLock::try_acquire`] for the non-blocking
    /// surface.
    pub fn acquire(home: &Path) -> Result<Self, VaultLockError> {
        let (file, path) = open_lock_file(home)?;
        // fs4 1.0 renames `lock_exclusive` → `lock` (mirroring std's
        // `File::lock`). Underlying syscall is still `flock(LOCK_EX)`
        // on Unix and `LockFileEx(LOCKFILE_EXCLUSIVE_LOCK)` on Windows.
        //
        // Retry on `EINTR`: blocking `flock` can be interrupted by an
        // unhandled signal (SIGCHLD during boot, SIGWINCH, etc.). The
        // kernel-side acquire is idempotent for our purposes —
        // re-issuing the syscall after EINTR resumes waiting cleanly.
        // `fs4` does NOT auto-retry on every platform, so we wrap.
        loop {
            match FileExt::lock(&file) {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(VaultLockError::Io(e)),
            }
        }
        let lock = VaultLock { file, path };
        lock.write_holder_metadata_best_effort();
        Ok(lock)
    }

    /// Try to acquire the vault lock without blocking.
    ///
    /// On success returns the guard. If another process holds the
    /// lock, returns [`VaultLockError::Busy`] populated with the
    /// holder's PID + argv[0] (best-effort — read from the lock file
    /// itself).
    ///
    /// # Errors
    ///
    /// [`VaultLockError::Busy`] when the lock is held; the holder's
    /// metadata fields are populated when the file read succeeded
    /// (otherwise both are `None`). [`VaultLockError::Io`] on every
    /// other filesystem failure.
    pub fn try_acquire(home: &Path) -> Result<Self, VaultLockError> {
        let (file, path) = open_lock_file(home)?;
        // fs4 1.0 returns `Result<(), TryLockError>` where
        // `TryLockError::WouldBlock` is "the lock is held". Other
        // I/O failures are wrapped in `TryLockError::Error(io::Error)`.
        match FileExt::try_lock(&file) {
            Ok(()) => {
                let lock = VaultLock { file, path };
                lock.write_holder_metadata_best_effort();
                Ok(lock)
            }
            Err(TryLockError::WouldBlock) => {
                // Lock is busy — read the holder metadata so the
                // operator's error message can name the holder.
                let (holder_pid, holder_command) = read_holder_metadata(&path);
                Err(VaultLockError::Busy { holder_pid, holder_command })
            }
            Err(TryLockError::Error(e)) => Err(VaultLockError::Io(e)),
        }
    }

    /// Best-effort write of `<pid>\n<argv0>\n` to the lock file. Called
    /// after the kernel-side lock is granted; a write failure is
    /// logged at `tracing::debug!` and does NOT propagate (the lock
    /// is real, the metadata is forensic).
    fn write_holder_metadata_best_effort(&self) {
        if let Err(e) = self.write_holder_metadata() {
            tracing::debug!(
                error = %e,
                path = %self.path.display(),
                "failed to write vault-lock holder metadata (non-fatal)"
            );
        }
    }

    fn write_holder_metadata(&self) -> io::Result<()> {
        // Truncate any prior holder's metadata, then write our own.
        // The lock is held during this whole sequence, so a racing
        // reader (`try_acquire` failure path) could only observe the
        // empty-or-prior state, never a torn write.
        let pid = std::process::id();
        let argv0 = std::env::args().next().unwrap_or_default();
        let line = format!("{pid}\n{argv0}\n");
        // `set_len(0)` truncates without re-opening; we still hold
        // the writable handle from `open_lock_file`.
        self.file.set_len(0)?;
        let mut handle = &self.file;
        // Always rewind to start before writing; otherwise the
        // truncate-then-append leaves us writing at the (now-zero)
        // file end which is still position 0 *but* on Windows the
        // file pointer isn't auto-reset by `set_len(0)`. Belt and
        // braces: explicit seek.
        use std::io::Seek as _;
        handle.seek(io::SeekFrom::Start(0))?;
        handle.write_all(line.as_bytes())?;
        handle.flush()?;
        Ok(())
    }
}

impl Drop for VaultLock {
    fn drop(&mut self) {
        // Best-effort: clear the holder-metadata so the next acquirer
        // doesn't see a stale PID. We do NOT delete the file — that
        // would race with another process that just opened it before
        // we get to `unlock`. The kernel-side lock is released when
        // `self.file` is dropped at the end of this scope.
        let _ = self.file.set_len(0);
        // No need to call `FileExt::unlock` explicitly — `flock`/
        // `LockFileEx` releases on file-descriptor close (i.e., when
        // `self.file` is dropped). Calling `unlock` here would just
        // duplicate the kernel work.
    }
}

/// Open the lock file (creating the home dir + vault subdir + lock
/// file if absent), returning the file handle + its absolute path.
/// Does NOT acquire the kernel-side lock — callers do that next.
///
/// The lock file lives at `<home>/.vault.lock` (sibling of the
/// `<home>/vault/` directory). The vault subdir is still created
/// here as a side effect because `cli/start.rs` daemon startup and
/// `crate::store::fs::CredentialFsStore::put` both rely on
/// `try_acquire` ensuring `vault/` exists before they read or write
/// any credential file.
fn open_lock_file(home: &Path) -> Result<(File, PathBuf), VaultLockError> {
    // Ensure ~/.agentsso/ itself exists before we try to drop a file
    // into it. `create_vault_dir_if_absent` handles `vault/` next,
    // including the `0o700` permissions on Unix.
    std::fs::create_dir_all(home)?;
    create_vault_dir_if_absent(&home.join("vault"))?;
    let lock_path = home.join(LOCK_FILENAME);

    // Reject symlinks at the lock-file path: a symlink could redirect
    // the lock to a writable-by-other-users path and silently break
    // the exclusion guarantee. Mirrors the `create_vault_dir`
    // discipline in `credential_fs.rs`.
    if let Ok(meta) = std::fs::symlink_metadata(&lock_path)
        && meta.file_type().is_symlink()
    {
        return Err(VaultLockError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("vault lock path is a symlink (refusing to follow): {}", lock_path.display()),
        )));
    }

    let file = open_or_create_lock_file(&lock_path)?;
    Ok((file, lock_path))
}

#[cfg(unix)]
fn open_or_create_lock_file(path: &Path) -> Result<File, VaultLockError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    // `O_NOFOLLOW` closes the TOCTOU window between the symlink probe
    // in `open_lock_file` and this open: if an attacker plants a
    // symlink at the lock path between those calls, `O_NOFOLLOW`
    // makes `open` fail with `ELOOP` rather than silently following
    // the new target (which could be a writable-by-other-users path
    // and break the exclusion guarantee).
    //
    // Custom flags: `libc::O_NOFOLLOW` (the constant is `0x100` on
    // Linux and `0x100` on macOS, but using the libc constant keeps
    // us portable across platforms that have moved it).
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?)
}

#[cfg(not(unix))]
fn open_or_create_lock_file(path: &Path) -> Result<File, VaultLockError> {
    Ok(OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?)
}

/// Create the vault directory at `dir` if absent, with mode `0o700`
/// on Unix. Re-uses the same idea as `credential_fs::create_vault_dir`
/// but is intentionally local to this module: the lock file's
/// containing directory may need to exist BEFORE
/// `CredentialFsStore::new` is ever called (e.g., the daemon's
/// `agentsso start` acquires the lock before constructing the store).
fn create_vault_dir_if_absent(dir: &Path) -> Result<(), VaultLockError> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        match std::fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let meta = std::fs::symlink_metadata(dir)?;
                if meta.file_type().is_symlink() {
                    return Err(VaultLockError::Io(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("vault path is a symlink (refusing to follow): {}", dir.display()),
                    )));
                }
                if !meta.is_dir() {
                    return Err(VaultLockError::Io(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("vault path exists but is not a directory: {}", dir.display()),
                    )));
                }
                use std::os::unix::fs::PermissionsExt;
                let mut perms = meta.permissions();
                perms.set_mode(0o700);
                std::fs::set_permissions(dir, perms)?;
                Ok(())
            }
            Err(e) => Err(VaultLockError::Io(e)),
        }
    }
    #[cfg(not(unix))]
    {
        match std::fs::create_dir(dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let meta = std::fs::symlink_metadata(dir)?;
                if meta.file_type().is_symlink() {
                    return Err(VaultLockError::Io(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("vault path is a symlink (refusing to follow): {}", dir.display()),
                    )));
                }
                if !meta.is_dir() {
                    return Err(VaultLockError::Io(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("vault path exists but is not a directory: {}", dir.display()),
                    )));
                }
                Ok(())
            }
            Err(e) => Err(VaultLockError::Io(e)),
        }
    }
}

/// Best-effort read of holder metadata from the lock file. Returns
/// `(pid, command)` — both `None` on read failure or unparseable
/// content. NEVER fails the calling operation; the metadata is
/// purely forensic.
fn read_holder_metadata(path: &Path) -> (Option<u32>, Option<String>) {
    let mut file = match OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(_) => return (None, None),
    };
    let mut buf = String::new();
    if (&mut file).take(HOLDER_METADATA_READ_LIMIT).read_to_string(&mut buf).is_err() {
        return (None, None);
    }
    let mut lines = buf.lines();
    let pid_line = lines.next().unwrap_or("");
    let cmd_line = lines.next().unwrap_or("");
    let pid = pid_line.trim().parse::<u32>().ok();
    let command = if cmd_line.trim().is_empty() { None } else { Some(cmd_line.trim().to_owned()) };
    (pid, command)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    fn home() -> TempDir {
        TempDir::new().expect("tempdir creation must succeed in tests")
    }

    #[test]
    fn try_acquire_returns_busy_when_held() {
        let h = home();
        let _first = VaultLock::try_acquire(h.path()).expect("first acquire");
        match VaultLock::try_acquire(h.path()) {
            Err(VaultLockError::Busy { .. }) => {}
            Err(other) => panic!("expected Busy, got error {other}"),
            Ok(_) => panic!("expected Busy on second acquirer"),
        }
    }

    #[test]
    fn lock_released_on_drop() {
        let h = home();
        {
            let _first = VaultLock::try_acquire(h.path()).expect("first acquire");
        }
        // Drop has run — second try_acquire must succeed.
        let _second = VaultLock::try_acquire(h.path()).expect("second acquire after drop");
    }

    /// Unix-only: on Windows, `LockFileEx` excludes other handles
    /// from reading the locked file, so `read_holder_metadata` returns
    /// `(None, None)` even though the lock is correctly held. The
    /// holder-metadata mechanism is best-effort forensic info; the
    /// kernel-side mutual exclusion (validated by
    /// `try_acquire_returns_busy_when_held`) is the actual safety
    /// guarantee and works on all platforms.
    #[cfg(unix)]
    #[test]
    fn holder_metadata_present_in_busy_error() {
        let h = home();
        let _first = VaultLock::try_acquire(h.path()).expect("first acquire");
        match VaultLock::try_acquire(h.path()) {
            Err(VaultLockError::Busy { holder_pid, holder_command }) => {
                assert_eq!(holder_pid, Some(std::process::id()));
                // `cargo test` arg0 is the test binary path; non-empty
                // is the contract.
                assert!(holder_command.is_some_and(|s| !s.is_empty()), "holder_command empty");
            }
            Err(other) => panic!("expected Busy with metadata, got error {other}"),
            Ok(_) => panic!("expected Busy with metadata, got second-acquire success"),
        }
    }

    #[test]
    fn acquire_blocks_concurrent_acquirer() {
        // First thread acquires (blocking), holds for ~50ms, then
        // drops. Second thread's blocking `acquire` must wait for the
        // first to release, then succeed.
        let h = home();
        let path = h.path().to_path_buf();
        let first_holding = Arc::new(AtomicBool::new(false));
        let first_done = Arc::new(AtomicBool::new(false));

        let path1 = path.clone();
        let holding1 = Arc::clone(&first_holding);
        let done1 = Arc::clone(&first_done);
        let t1 = thread::spawn(move || {
            let _g = VaultLock::acquire(&path1).expect("first thread acquire");
            holding1.store(true, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(50));
            done1.store(true, Ordering::SeqCst);
            // _g drops here, releasing the lock.
        });

        // Wait for first thread to actually hold the lock.
        while !first_holding.load(Ordering::SeqCst) {
            thread::yield_now();
        }
        // Second blocking acquire must wait until t1 finishes.
        let _g2 = VaultLock::acquire(&path).expect("second thread acquire");
        assert!(first_done.load(Ordering::SeqCst), "second acquire returned before first released");
        t1.join().expect("first thread joined");
    }

    #[test]
    fn lock_released_on_panic_unwind() {
        // RAII: a panic inside the lock-holding scope must still run
        // Drop, releasing the lock for the next acquirer.
        let h = home();
        let path = h.path().to_path_buf();
        let path1 = path.clone();
        let result = thread::spawn(move || {
            let _g = VaultLock::acquire(&path1).expect("acquire pre-panic");
            panic!("intentional panic to test unwind release");
        })
        .join();
        assert!(result.is_err(), "panic must propagate");
        // After the panicking thread joined, the lock is free.
        let _g2 = VaultLock::try_acquire(&path).expect("second acquire after panic-unwind");
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_created_with_0o600() {
        use std::os::unix::fs::PermissionsExt;
        let h = home();
        let _g = VaultLock::try_acquire(h.path()).expect("acquire");
        let mode = std::fs::metadata(h.path().join(".vault.lock"))
            .expect("stat lock file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn vault_dir_created_with_0o700_if_absent() {
        use std::os::unix::fs::PermissionsExt;
        let h = home();
        // `home` is a fresh tempdir — the vault subdirectory does
        // NOT exist yet. `try_acquire` must create it.
        assert!(!h.path().join("vault").exists());
        let _g = VaultLock::try_acquire(h.path()).expect("acquire creates vault dir");
        let mode =
            std::fs::metadata(h.path().join("vault")).expect("stat vault dir").permissions().mode()
                & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn lock_file_persists_across_acquire_release() {
        // The lock file is a marker, not a per-acquire artifact.
        // Acquiring then releasing must leave the file behind so
        // subsequent acquirers don't pay creation cost or race on
        // simultaneous-create-and-lock.
        let h = home();
        {
            let _g = VaultLock::try_acquire(h.path()).expect("first acquire");
        }
        assert!(
            h.path().join(".vault.lock").exists(),
            "lock file must persist across acquire/release"
        );
    }

    /// Unix-only: the test mutates the lock file via `std::fs::write`
    /// while a `flock` is held on it. POSIX `flock` is advisory so
    /// this works; Windows `LockFileEx` excludes the write with a
    /// sharing violation, and the holder-metadata read pattern this
    /// test exercises is itself Unix-only (see
    /// `holder_metadata_present_in_busy_error`).
    #[cfg(unix)]
    #[test]
    fn busy_holder_metadata_falls_back_to_none_on_unreadable_file() {
        // Acquire, then truncate the lock file behind the holder's
        // back so the metadata read returns empty. The Busy error
        // should still fire (lock is held), but holder fields are
        // None.
        let h = home();
        let _first = VaultLock::try_acquire(h.path()).expect("first acquire");
        let lock_path = h.path().join(".vault.lock");
        // Replace the holder metadata with empty bytes — the lock
        // itself stays held (kernel state, not file content).
        std::fs::write(&lock_path, b"").expect("truncate metadata");
        match VaultLock::try_acquire(h.path()) {
            Err(VaultLockError::Busy { holder_pid, holder_command }) => {
                assert!(holder_pid.is_none());
                assert!(holder_command.is_none());
            }
            Err(other) => panic!("expected Busy with empty metadata, got error {other}"),
            Ok(_) => panic!("expected Busy with empty metadata, got success"),
        }
    }
}
