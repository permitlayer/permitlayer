//! Shared atomic-write helper for CLI output files.
//!
//! Story 7.17 Task 1.4 factored this out of `cli::openclaw::write_snippet_atomic`
//! so `agent register --token-out` (mode 0o600, owner-only token bytes) and
//! `connect --mcp-config-out` (mode 0o644, cross-user-readable snippet) share
//! the same write-tempfile-then-rename plus parent-dir-must-exist plus
//! refuse-existing-symlink contract.
//!
//! Pattern preserved verbatim from openclaw.rs:172 (Story 7.13 round-1 P7).

use std::io::{self, Write as _};
use std::path::Path;

/// Atomic same-directory tempfile + rename with explicit Unix mode.
///
/// - Parent directory must exist (returns `NotFound` otherwise).
/// - Refuses to overwrite an existing symlink (returns `InvalidInput`).
/// - On Unix the persisted file is set to `mode` (e.g. `0o600` or `0o644`).
/// - The parent directory is fsynced after the rename so the new dirent
///   survives a crash (best-effort: fsync errors on the parent are ignored).
pub(crate) fn write_atomic_with_mode(
    path: &Path,
    bytes: &[u8],
    #[cfg(unix)] mode: u32,
    #[cfg(not(unix))] _mode: u32,
) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("output path has no parent dir: {}", path.display()),
        )
    })?;
    if !parent.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("parent dir does not exist: {}", parent.display()),
        ));
    }

    if let Ok(md) = std::fs::symlink_metadata(path)
        && md.file_type().is_symlink()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to follow symlink at output path: {}", path.display()),
        ));
    }

    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(tmp.path(), perms)?;
    }

    tmp.persist(path).map_err(|e| e.error)?;
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn writes_bytes_verbatim() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("out.bin");
        write_atomic_with_mode(&path, b"hello", 0o600).unwrap();
        let read = std::fs::read(&path).unwrap();
        assert_eq!(read, b"hello");
    }

    #[cfg(unix)]
    #[test]
    fn applies_0o600_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("out.bin");
        write_atomic_with_mode(&path, b"x", 0o600).unwrap();
        let md = std::fs::metadata(&path).unwrap();
        let mode = md.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn applies_0o644_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("out.bin");
        write_atomic_with_mode(&path, b"x", 0o644).unwrap();
        let md = std::fs::metadata(&path).unwrap();
        let mode = md.permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn errors_when_parent_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does-not-exist").join("out.bin");
        let err = write_atomic_with_mode(&path, b"x", 0o600).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[cfg(unix)]
    #[test]
    fn errors_when_path_is_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("real.bin");
        std::fs::write(&target, b"existing").unwrap();
        let link = tmp.path().join("link.bin");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = write_atomic_with_mode(&link, b"replace", 0o600).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        // Real file's contents must be untouched.
        assert_eq!(std::fs::read(&target).unwrap(), b"existing");
    }
}
