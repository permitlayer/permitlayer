#![allow(dead_code)]
//! Rename-aside-to-snapshot for operator-recoverable archival.
//!
//! Story 10.2's legacy-seed shadow heal moves shadowing files into
//! a single timestamped snapshot dir
//! (`policies/.legacy-seed-snapshot-<isotime>/`) rather than deleting.
//! Operator-recoverable via a single `sudo mv` for ≤30 days, then
//! GC'd by `doctor --fix` (Story 10.3). Matches mature installer
//! breadcrumb discipline (dpkg `status-old`, Btrfs pre-transaction
//! snapshot).

use std::io;
use std::path::{Path, PathBuf};

use super::fs_repair::fsync_dir;

/// Snapshot subdirectory name format. Colons replaced with hyphens
/// for FS portability — the daemon's existing `design/format.rs`
/// uses `%H:%M:%S` with literal colons, but that produces names
/// that some Windows tooling chokes on. Snapshot dirs are
/// operator-visible (they sit next to the live tree), so the
/// portable form wins here.
const SNAPSHOT_TIMESTAMP_FORMAT: &str = "%Y-%m-%dT%H-%M-%SZ";

/// Move `paths` into a single new
/// `<home>/<subdir>/.legacy-seed-snapshot-<isotime>/` directory
/// via individual `rename(2)` calls. Returns the snapshot dir path
/// + a Vec of `(original_path, new_path)` pairs.
///
/// Each rename is atomic per inode — the daemon's open file
/// descriptors stay valid even if the daemon is still running
/// mid-archive. The snapshot dir is created at mode `0o700` (only
/// root + the daemon owner can list its contents).
///
/// On a per-rename failure, the function continues with the
/// remaining paths and reports the partial outcome via the
/// returned tuple list — only paths that successfully moved appear
/// in the `Vec<(orig, new)>` result.
pub(crate) fn rename_aside_to_snapshot(
    home: &Path,
    subdir: &str,
    paths: &[&Path],
) -> io::Result<(PathBuf, Vec<(PathBuf, PathBuf)>)> {
    let subdir_path = home.join(subdir);
    if !subdir_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("operator subdir does not exist: {}", subdir_path.display()),
        ));
    }

    let snapshot_dir = create_unique_snapshot_dir(&subdir_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&snapshot_dir, std::fs::Permissions::from_mode(0o700))?;
    }

    let mut moved: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(paths.len());
    let mut used_names: std::collections::HashSet<std::ffi::OsString> =
        std::collections::HashSet::new();
    for &original in paths {
        let file_name = match original.file_name() {
            Some(n) => n.to_owned(),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("path has no basename: {}", original.display()),
                ));
            }
        };
        // Defensive: refuse to pull files from outside the subdir.
        // The primitive's contract is "archive operator files under
        // <home>/<subdir>"; a path elsewhere is a caller bug.
        if !original.starts_with(&subdir_path) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("path is outside subdir {}: {}", subdir_path.display(), original.display()),
            ));
        }
        // Disambiguate same-basename collisions (e.g. /a/x and /b/x).
        let unique_name = disambiguate_name(&file_name, &used_names);
        used_names.insert(unique_name.clone());
        let dest = snapshot_dir.join(&unique_name);
        match std::fs::rename(original, &dest) {
            Ok(()) => moved.push((original.to_owned(), dest)),
            Err(e) => {
                // Per-rename failure: surface to the forensic trail
                // rather than swallowing silently. Continue with the
                // remaining paths; the caller sees which moved via
                // the returned vec.
                tracing::warn!(
                    target: "repair.archive",
                    event = "rename_failed",
                    original = %original.display(),
                    dest = %dest.display(),
                    error = %e,
                    "snapshot rename failed; continuing with remaining paths",
                );
            }
        }
    }

    let _ = fsync_dir(&subdir_path); // best-effort durability
    Ok((snapshot_dir, moved))
}

/// Create the snapshot dir with an EEXIST-tolerant suffix.
///
/// Two heal-retries within the same UTC second would collide on the
/// base name; we append `-1`, `-2`, ... up to a small cap before
/// giving up.
fn create_unique_snapshot_dir(subdir_path: &Path) -> io::Result<PathBuf> {
    let now = chrono::Utc::now();
    let base = format!(".legacy-seed-snapshot-{}", now.format(SNAPSHOT_TIMESTAMP_FORMAT));
    let candidate = subdir_path.join(&base);
    match std::fs::create_dir(&candidate) {
        Ok(()) => return Ok(candidate),
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
        Err(_) => {}
    }
    for suffix in 1..=99 {
        let candidate = subdir_path.join(format!("{base}-{suffix}"));
        match std::fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
            Err(_) => continue,
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("snapshot dir name space exhausted under {}", subdir_path.display()),
    ))
}

/// Pick an unused basename for the snapshot. If `name` is already in
/// `used_names`, append `.1`, `.2`, ... until we find a free slot.
fn disambiguate_name(
    name: &std::ffi::OsStr,
    used_names: &std::collections::HashSet<std::ffi::OsString>,
) -> std::ffi::OsString {
    if !used_names.contains(name) {
        return name.to_owned();
    }
    for suffix in 1..u32::MAX {
        let mut candidate = name.to_owned();
        candidate.push(format!(".{suffix}"));
        if !used_names.contains(&candidate) {
            return candidate;
        }
    }
    // Unreachable in practice (u32 namespace) — falls back to the
    // original name (which will collide and fail in rename below).
    name.to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn touch(p: &Path) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, b"x").unwrap();
    }

    #[test]
    fn snapshot_dir_name_is_colon_free_iso_sortable() {
        let home = tempfile::tempdir().unwrap();
        let policies = home.path().join("policies");
        std::fs::create_dir(&policies).unwrap();
        touch(&policies.join("default.toml"));
        let absolute = policies.join("default.toml");
        let (snapshot_dir, _moved) =
            rename_aside_to_snapshot(home.path(), "policies", &[&absolute]).unwrap();
        let name = snapshot_dir.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with(".legacy-seed-snapshot-"));
        assert!(!name.contains(':'), "name must be colon-free: {name}");
        assert!(name.ends_with('Z'), "name must be Z-suffixed: {name}");
    }

    #[test]
    fn rename_aside_moves_files_into_snapshot_dir() {
        let home = tempfile::tempdir().unwrap();
        let policies = home.path().join("policies");
        std::fs::create_dir(&policies).unwrap();
        touch(&policies.join("default.toml"));
        touch(&policies.join("legacy.toml"));
        let to_move = [policies.join("default.toml"), policies.join("legacy.toml")];
        let refs: Vec<&Path> = to_move.iter().map(|p| p.as_path()).collect();
        let (snapshot_dir, moved) =
            rename_aside_to_snapshot(home.path(), "policies", &refs).unwrap();
        assert_eq!(moved.len(), 2);
        assert!(snapshot_dir.is_dir());
        assert!(snapshot_dir.join("default.toml").is_file());
        assert!(snapshot_dir.join("legacy.toml").is_file());
        // Originals are gone.
        assert!(!policies.join("default.toml").exists());
        assert!(!policies.join("legacy.toml").exists());
    }

    #[test]
    fn rename_aside_continues_past_per_path_failure() {
        let home = tempfile::tempdir().unwrap();
        let policies = home.path().join("policies");
        std::fs::create_dir(&policies).unwrap();
        touch(&policies.join("good.toml"));
        let bad = policies.join("nonexistent.toml");
        let good = policies.join("good.toml");
        let refs: Vec<&Path> = vec![&bad, &good];
        let (_snapshot_dir, moved) =
            rename_aside_to_snapshot(home.path(), "policies", &refs).unwrap();
        // Only `good.toml` moved; `nonexistent.toml` was silently
        // skipped (the caller sees which moved via the returned vec).
        assert_eq!(moved.len(), 1);
        assert_eq!(moved[0].0, good);
    }

    #[test]
    fn rename_aside_errors_when_subdir_absent() {
        let home = tempfile::tempdir().unwrap();
        let err = rename_aside_to_snapshot(home.path(), "policies", &[]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn snapshot_dir_mode_is_0o700_on_unix() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let home = tempfile::tempdir().unwrap();
            let policies = home.path().join("policies");
            std::fs::create_dir(&policies).unwrap();
            touch(&policies.join("default.toml"));
            let target = policies.join("default.toml");
            let (snapshot_dir, _) =
                rename_aside_to_snapshot(home.path(), "policies", &[&target]).unwrap();
            let mode = std::fs::metadata(&snapshot_dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
    }

    #[test]
    fn rename_aside_disambiguates_same_basename_paths() {
        // Two input paths with identical basenames must NOT clobber
        // each other in the snapshot dir.
        let home = tempfile::tempdir().unwrap();
        let policies = home.path().join("policies");
        std::fs::create_dir_all(policies.join("a")).unwrap();
        std::fs::create_dir_all(policies.join("b")).unwrap();
        let path_a = policies.join("a/default.toml");
        let path_b = policies.join("b/default.toml");
        std::fs::write(&path_a, b"from-a").unwrap();
        std::fs::write(&path_b, b"from-b").unwrap();
        let refs: Vec<&Path> = vec![&path_a, &path_b];
        let (snapshot_dir, moved) =
            rename_aside_to_snapshot(home.path(), "policies", &refs).unwrap();
        assert_eq!(moved.len(), 2, "both paths should be archived");
        // Both files must exist in the snapshot dir under distinct names.
        let entries: Vec<_> = std::fs::read_dir(&snapshot_dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries.len(), 2, "snapshot dir should have 2 distinct entries: {entries:?}");
        assert!(entries.iter().any(|n| n == "default.toml"));
        assert!(entries.iter().any(|n| n == "default.toml.1"));
        // Contents preserved (no clobber).
        let mut contents: Vec<Vec<u8>> =
            moved.iter().map(|(_, dest)| std::fs::read(dest).unwrap()).collect();
        contents.sort();
        assert_eq!(contents, vec![b"from-a".to_vec(), b"from-b".to_vec()]);
    }

    #[test]
    fn rename_aside_errors_on_path_outside_subdir() {
        let home = tempfile::tempdir().unwrap();
        let policies = home.path().join("policies");
        std::fs::create_dir(&policies).unwrap();
        let outside = home.path().join("not-policies.toml");
        std::fs::write(&outside, b"x").unwrap();
        let err = rename_aside_to_snapshot(home.path(), "policies", &[&outside]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        // Original untouched.
        assert!(outside.exists());
    }

    #[test]
    fn rename_aside_errors_on_path_with_no_basename() {
        let home = tempfile::tempdir().unwrap();
        let policies = home.path().join("policies");
        std::fs::create_dir(&policies).unwrap();
        // `policies/..` resolves to a path with no file_name.
        let weird = policies.join("..");
        let err = rename_aside_to_snapshot(home.path(), "policies", &[&weird]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn create_unique_snapshot_dir_tolerates_same_second_collision() {
        let home = tempfile::tempdir().unwrap();
        let policies = home.path().join("policies");
        std::fs::create_dir(&policies).unwrap();
        // First call wins the base name; second call must get a
        // suffixed variant.
        let first = create_unique_snapshot_dir(&policies).unwrap();
        let second = create_unique_snapshot_dir(&policies).unwrap();
        assert_ne!(first, second);
        assert!(first.is_dir());
        assert!(second.is_dir());
    }
}
