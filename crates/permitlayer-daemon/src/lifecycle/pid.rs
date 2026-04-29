use std::io::Write;
use std::path::{Path, PathBuf};

/// Manages the daemon's PID file at `{home}/agentsso.pid`.
///
/// Acquiring a `PidFile` writes the current process PID. The file is
/// automatically removed on drop (best-effort) or via `release()`.
pub struct PidFile {
    path: PathBuf,
}

/// Errors related to PID file operations.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum PidFileError {
    #[error("daemon is already running (PID {pid})")]
    DaemonAlreadyRunning { pid: u32 },

    #[error("daemon is not running")]
    #[allow(dead_code)] // Used by stop/status CLI commands for error reporting.
    DaemonNotRunning,

    #[error("invalid PID file at {}: {content:?}", path.display())]
    InvalidPidFile { path: PathBuf, content: String },

    #[error("I/O error accessing PID file")]
    IoError(#[from] std::io::Error),
}

impl PidFile {
    /// PID file path within the home directory.
    fn pid_path(home: &Path) -> PathBuf {
        home.join("agentsso.pid")
    }

    /// Acquire the PID file by writing the current process PID.
    ///
    /// If a stale PID file exists (process not running), it is overwritten
    /// with a warning. If the process IS running, returns
    /// `PidFileError::DaemonAlreadyRunning`.
    pub fn acquire(home: &Path) -> Result<Self, PidFileError> {
        let path = Self::pid_path(home);

        // Ensure the home directory exists.
        std::fs::create_dir_all(home)?;

        // Check for existing PID file.
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            let content = content.trim();
            if let Ok(existing_pid) = content.parse::<u32>() {
                if is_process_alive(existing_pid) {
                    return Err(PidFileError::DaemonAlreadyRunning { pid: existing_pid });
                }
                // Stale PID file — process is not running. Overwrite.
                tracing::warn!(pid = existing_pid, "removing stale PID file (process not running)");
            } else if !content.is_empty() {
                // PID file has garbage content — remove it.
                tracing::warn!(
                    path = %path.display(),
                    "removing PID file with invalid content"
                );
            }
        }

        // Write the current PID atomically: write to temp, fsync, rename.
        let current_pid = std::process::id();
        let tmp_path = path.with_extension("pid.tmp");
        {
            let mut f = std::fs::File::create(&tmp_path)?;
            writeln!(f, "{current_pid}")?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp_path, &path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        }

        Ok(Self { path })
    }

    /// Read the PID from an existing PID file. Returns `Ok(None)` if the
    /// file does not exist.
    pub fn read(home: &Path) -> Result<Option<u32>, PidFileError> {
        let path = Self::pid_path(home);
        if !path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(&path)?;
        let content = content.trim();
        let pid = content.parse::<u32>().map_err(|_| PidFileError::InvalidPidFile {
            path: path.clone(),
            content: content.to_owned(),
        })?;
        Ok(Some(pid))
    }

    /// Check whether a daemon process is currently running by reading the
    /// PID file and checking the process.
    pub fn is_daemon_running(home: &Path) -> Result<bool, PidFileError> {
        match Self::read(home)? {
            Some(pid) => Ok(is_process_alive(pid)),
            None => Ok(false),
        }
    }

    /// Remove the PID file on clean shutdown.
    pub fn release(self) -> Result<(), PidFileError> {
        std::fs::remove_file(&self.path)?;
        // Prevent the Drop impl from trying again.
        std::mem::forget(self);
        Ok(())
    }

    /// Return the path of the PID file.
    #[must_use]
    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        // Best-effort removal — don't panic in Drop.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Safely convert a u32 PID to i32 for use with nix APIs.
/// Returns `None` if the PID is 0 or exceeds `i32::MAX` (which would wrap
/// negative and cause `kill()` to signal a process group).
///
/// Unix-only: nix's `Pid::from_raw` takes i32. Windows uses raw u32
/// PIDs throughout the OpenProcess / TerminateProcess API surface so
/// no conversion is needed there.
#[cfg(unix)]
fn pid_to_raw(pid: u32) -> Option<i32> {
    if pid == 0 || pid > i32::MAX as u32 { None } else { Some(pid as i32) }
}

/// Check if a process with the given PID is alive.
fn is_process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // kill(pid, 0) checks if the process exists without sending a signal.
        // Returns ESRCH if the process doesn't exist.
        use nix::sys::signal::kill;
        use nix::unistd::Pid;
        match pid_to_raw(pid) {
            Some(raw) => kill(Pid::from_raw(raw), None).is_ok(),
            None => false, // Invalid PID range — treat as not alive.
        }
    }
    #[cfg(not(unix))]
    {
        // On non-Unix, we can't easily check. Assume alive if PID file exists.
        // This is a best-effort check; the integration test covers Unix.
        let _ = pid;
        true
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn test_home() -> tempfile::TempDir {
        tempfile::TempDir::new().unwrap()
    }

    #[test]
    fn acquire_writes_correct_pid() {
        let home = test_home();
        let pid_file = PidFile::acquire(home.path()).unwrap();
        let content = std::fs::read_to_string(pid_file.path()).unwrap();
        let stored_pid: u32 = content.trim().parse().unwrap();
        assert_eq!(stored_pid, std::process::id());
    }

    #[test]
    fn read_returns_correct_pid() {
        let home = test_home();
        let _pid_file = PidFile::acquire(home.path()).unwrap();
        let pid = PidFile::read(home.path()).unwrap();
        assert_eq!(pid, Some(std::process::id()));
    }

    #[test]
    fn read_returns_none_when_no_file() {
        let home = test_home();
        let pid = PidFile::read(home.path()).unwrap();
        assert_eq!(pid, None);
    }

    #[test]
    fn release_removes_file() {
        let home = test_home();
        let pid_file = PidFile::acquire(home.path()).unwrap();
        let path = pid_file.path().to_owned();
        assert!(path.exists());
        pid_file.release().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn double_acquire_with_live_process_fails() {
        let home = test_home();
        let _pid_file = PidFile::acquire(home.path()).unwrap();
        // The current process is alive, so acquiring again should fail.
        let result = PidFile::acquire(home.path());
        match result {
            Err(PidFileError::DaemonAlreadyRunning { pid }) => {
                assert_eq!(pid, std::process::id());
            }
            Ok(_) => panic!("expected DaemonAlreadyRunning, got Ok"),
            Err(other) => panic!("expected DaemonAlreadyRunning, got {other}"),
        }
    }

    #[test]
    fn stale_pid_is_cleaned_up() {
        let home = test_home();
        // Write a PID for a process that (almost certainly) doesn't exist.
        let pid_path = home.path().join("agentsso.pid");
        std::fs::write(&pid_path, "999999999\n").unwrap();

        // Acquiring should succeed — the stale PID is overwritten.
        let pid_file = PidFile::acquire(home.path()).unwrap();
        let content = std::fs::read_to_string(pid_file.path()).unwrap();
        let stored_pid: u32 = content.trim().parse().unwrap();
        assert_eq!(stored_pid, std::process::id());
    }

    #[test]
    fn is_daemon_running_returns_false_when_not_running() {
        let home = test_home();
        assert!(!PidFile::is_daemon_running(home.path()).unwrap());
    }

    #[test]
    fn is_daemon_running_returns_true_for_current_process() {
        let home = test_home();
        let _pid_file = PidFile::acquire(home.path()).unwrap();
        assert!(PidFile::is_daemon_running(home.path()).unwrap());
    }
}
