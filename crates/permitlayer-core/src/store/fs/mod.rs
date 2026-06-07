//! Filesystem adapters for the storage traits.
//!
//! Hosts the `~/.agentsso/`-rooted adapters for credentials, audit
//! events, agent identities, connections, and bindings. Each adapter is
//! its own module so the production crate compiles cleanly with
//! `#![forbid(unsafe_code)]` and so tests can target one adapter at a
//! time.

pub mod agent_fs;
pub mod audit_fs;
pub mod binding_fs;
pub mod connection_fs;
pub mod credential_fs;

pub use agent_fs::AgentIdentityFsStore;
pub use audit_fs::AuditFsStore;
pub use binding_fs::BindingFsStore;
pub use connection_fs::ConnectionFsStore;
pub use credential_fs::CredentialFsStore;

use std::io::Write as _;
use std::path::Path;

use crate::store::error::StoreError;

/// Atomic write shared by the TOML-record adapters (agent / connection /
/// binding): tempfile → fsync → rename → fsync parent dir.
///
/// The parent-dir fsync is Unix-only: ext4/xfs/btrfs need
/// `fsync(parent)` after a rename for the dirent to be durable. Windows
/// NTFS is journaled and `MoveFileEx`-class renames are atomic without an
/// extra parent flush; opening a directory for read on Windows fails with
/// `PermissionDenied`. Skipping the parent fsync on Windows is the
/// standard pattern (also used by `tempfile`, `sled`, etc.).
pub(crate) fn atomic_write(
    tmp: &Path,
    target: &Path,
    parent: &Path,
    bytes: &[u8],
) -> Result<(), StoreError> {
    let mut file = create_tempfile_0600(tmp)?;
    let guard = TempfileGuard { path: tmp };
    file.write_all(bytes).map_err(StoreError::IoError)?;
    file.sync_all().map_err(StoreError::IoError)?;
    drop(file);
    std::fs::rename(tmp, target).map_err(StoreError::IoError)?;
    std::mem::forget(guard);
    #[cfg(unix)]
    {
        let dir = std::fs::File::open(parent).map_err(StoreError::IoError)?;
        dir.sync_all().map_err(StoreError::IoError)?;
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
    }
    Ok(())
}

fn create_tempfile_0600(tmp: &Path) -> Result<std::fs::File, StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(tmp)
            .map_err(StoreError::IoError)
    }
    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(tmp)
            .map_err(StoreError::IoError)
    }
}

/// RAII guard that deletes a tempfile if [`atomic_write`] aborts before
/// the rename.
struct TempfileGuard<'a> {
    path: &'a Path,
}

impl Drop for TempfileGuard<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.path);
    }
}

/// Create a restricted leaf directory with mode `0o700` on Unix (parents
/// inherit umask defaults). Refuses to follow a symlink at the leaf path
/// (a symlink redirect would silently ship the registry to an
/// attacker-controlled location). `label` names the namespace for error
/// messages (`"connections"`, `"bindings"`).
pub(crate) fn create_restricted_dir(dir: &Path, label: &str) -> Result<(), StoreError> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).map_err(StoreError::IoError)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        match std::fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let meta = std::fs::symlink_metadata(dir).map_err(StoreError::IoError)?;
                if meta.file_type().is_symlink() {
                    return Err(StoreError::IoError(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!(
                            "{label} path is a symlink (refusing to follow): {}",
                            dir.display()
                        ),
                    )));
                }
                if !meta.is_dir() {
                    return Err(StoreError::IoError(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!("{label} path exists but is not a directory: {}", dir.display()),
                    )));
                }
                use std::os::unix::fs::PermissionsExt;
                let mut perms = meta.permissions();
                perms.set_mode(0o700);
                std::fs::set_permissions(dir, perms).map_err(StoreError::IoError)?;
            }
            Err(e) => return Err(StoreError::IoError(e)),
        }
    }
    #[cfg(not(unix))]
    {
        match std::fs::create_dir(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let meta = std::fs::symlink_metadata(dir).map_err(StoreError::IoError)?;
                if meta.file_type().is_symlink() {
                    return Err(StoreError::IoError(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!(
                            "{label} path is a symlink (refusing to follow): {}",
                            dir.display()
                        ),
                    )));
                }
                if !meta.is_dir() {
                    return Err(StoreError::IoError(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!("{label} path exists but is not a directory: {}", dir.display()),
                    )));
                }
            }
            Err(e) => return Err(StoreError::IoError(e)),
        }
    }
    Ok(())
}
