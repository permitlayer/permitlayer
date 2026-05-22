#![allow(dead_code)]
//! Operator-state wipe with policy selection.
//!
//! Two modes:
//! - [`WipePolicy::All`] — wipe every entry under the named subdirs.
//!   Used by Story 10.2's `setup --fresh-install` flag.
//! - [`WipePolicy::Predicate`] — wipe only entries the predicate
//!   accepts. Used by Story 10.2's legacy-seed shadow heal: walk
//!   operator policy files, archive only those whose parsed `name`
//!   values overlap with managed-bundle names.
//!
//! Idempotent: missing subdirs are not an error. Per-file failures
//! are collected in [`WipeReport`] so callers can decide whether
//! partial failure is fatal at the call site.

use std::io;
use std::path::{Path, PathBuf};

use super::fs_repair::remove_file_with_retry;

/// Policy controlling which entries [`wipe_subdirs`] removes.
pub(crate) enum WipePolicy {
    /// Remove every entry under each named subdir.
    All,
    /// Remove only entries for which the predicate returns `true`.
    /// The predicate is called once per file (NOT per subdir).
    Predicate(Box<dyn Fn(&Path) -> bool + Send + Sync>),
}

/// Outcome of a [`wipe_subdirs`] call.
///
/// **Spec divergence note (Story 10.1 AC #4):** the story spec
/// proposed `skipped: Vec<(PathBuf, &'static str)>` carrying a
/// skip-reason tag. This implementation uses
/// `skipped_by_predicate: Vec<PathBuf>` without the tag because
/// `WipePolicy::Predicate` is the only path that can produce a
/// skip — the reason is structural ("predicate returned false") and
/// there's nothing else to disambiguate it from. If a future
/// `WipePolicy` variant introduces additional skip causes, this
/// field should grow back into a tagged variant.
#[derive(Debug, Default)]
pub(crate) struct WipeReport {
    /// Paths successfully removed.
    pub removed: Vec<PathBuf>,
    /// Paths skipped due to the predicate (Predicate mode only;
    /// always empty for `WipePolicy::All`).
    pub skipped_by_predicate: Vec<PathBuf>,
    /// Per-file IO errors encountered during the walk. Callers
    /// decide whether to treat this as fatal.
    pub errors: Vec<(PathBuf, io::Error)>,
}

impl WipeReport {
    /// `true` iff no errors occurred.
    pub(crate) fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Wipe the named subdirs under `home` per `policy`.
///
/// For each `subdir`:
/// - If absent, skip (idempotent).
/// - If present, walk one level deep. For each entry:
///   - If a directory, recursively `remove_dir_all` (subject to the
///     same predicate logic — the predicate is evaluated against
///     the top-level entry path).
///   - If a file, call [`remove_file_with_retry`].
/// - After all entries processed, remove the (now empty) subdir
///   itself when `WipePolicy::All`. For predicate mode, the subdir
///   is left in place since other (unmatched) entries may remain.
///
/// Returns `Err` only for the top-level read-dir failure on a
/// present subdir. Per-entry failures populate
/// [`WipeReport::errors`] without aborting the walk.
pub(crate) fn wipe_subdirs(
    home: &Path,
    subdirs: &[&str],
    policy: WipePolicy,
) -> io::Result<WipeReport> {
    // Validate every subdir up front — `home.join(absolute)` would
    // replace `home` with the absolute path, letting a buggy caller
    // wipe `/etc` instead of `<home>/etc`. Path-traversal segments
    // (`..`) are similarly refused.
    for subdir in subdirs {
        validate_subdir_component(subdir)?;
    }

    let mut report = WipeReport::default();
    for subdir in subdirs {
        let path = home.join(subdir);
        if !path.exists() {
            continue;
        }

        let entries = match std::fs::read_dir(&path) {
            Ok(rd) => rd,
            Err(e) => {
                report.errors.push((path.clone(), e));
                continue;
            }
        };

        let mut removed_all_entries = true;
        for entry_result in entries {
            let entry = match entry_result {
                Ok(e) => e,
                Err(e) => {
                    report.errors.push((path.clone(), e));
                    removed_all_entries = false;
                    continue;
                }
            };
            let entry_path = entry.path();

            // Predicate gate (Predicate mode only).
            if let WipePolicy::Predicate(ref pred) = policy
                && !pred(&entry_path)
            {
                report.skipped_by_predicate.push(entry_path);
                removed_all_entries = false;
                continue;
            }

            let removal_result = if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                std::fs::remove_dir_all(&entry_path)
            } else {
                remove_file_with_retry(&entry_path)
            };
            match removal_result {
                Ok(()) => report.removed.push(entry_path),
                Err(e) => {
                    report.errors.push((entry_path, e));
                    removed_all_entries = false;
                }
            }
        }

        // Remove the subdir itself only when fully drained AND we're
        // in WipePolicy::All mode. Predicate mode leaves the dir.
        if matches!(policy, WipePolicy::All)
            && removed_all_entries
            && let Err(e) = std::fs::remove_dir(&path)
        {
            report.errors.push((path, e));
        }
    }
    Ok(report)
}

/// Reject empty, absolute, multi-component, or `..`-bearing subdir
/// names. `wipe_subdirs` joins these onto `home`; an absolute or
/// traversal-bearing component would escape the home root.
fn validate_subdir_component(subdir: &str) -> io::Result<()> {
    if subdir.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "subdir is empty"));
    }
    let p = Path::new(subdir);
    if p.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("subdir must not be absolute: {subdir}"),
        ));
    }
    let mut components = p.components();
    let first = components.next();
    if components.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("subdir must be a single path component: {subdir}"),
        ));
    }
    match first {
        Some(std::path::Component::Normal(_)) => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("subdir must be a normal component (no `.`, `..`, root): {subdir}"),
        )),
    }
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
    fn wipe_all_removes_everything_under_named_subdirs() {
        let home = tempfile::tempdir().unwrap();
        touch(&home.path().join("policies/default.toml"));
        touch(&home.path().join("policies/openclaw-dev.toml"));
        touch(&home.path().join("agents/angie.json"));
        touch(&home.path().join("vault/envelope-1"));

        let report =
            wipe_subdirs(home.path(), &["policies", "agents", "vault"], WipePolicy::All).unwrap();

        assert_eq!(report.removed.len(), 4);
        assert!(report.errors.is_empty(), "got errors: {:?}", report.errors);
        // All three subdirs themselves should be gone.
        assert!(!home.path().join("policies").exists());
        assert!(!home.path().join("agents").exists());
        assert!(!home.path().join("vault").exists());
    }

    #[test]
    fn wipe_all_is_idempotent_on_missing_subdir() {
        let home = tempfile::tempdir().unwrap();
        // Only `policies/` exists.
        touch(&home.path().join("policies/file.toml"));
        let report =
            wipe_subdirs(home.path(), &["policies", "agents", "vault"], WipePolicy::All).unwrap();
        assert_eq!(report.removed.len(), 1);
        assert!(report.ok());
    }

    #[test]
    fn wipe_predicate_only_removes_matching_files() {
        let home = tempfile::tempdir().unwrap();
        touch(&home.path().join("policies/default.toml"));
        touch(&home.path().join("policies/openclaw-dev.toml"));
        touch(&home.path().join("policies/my-overrides.toml"));

        // Only remove files whose stem starts with "default".
        let predicate: Box<dyn Fn(&Path) -> bool + Send + Sync> = Box::new(|p: &Path| {
            p.file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.starts_with("default"))
                .unwrap_or(false)
        });
        let report =
            wipe_subdirs(home.path(), &["policies"], WipePolicy::Predicate(predicate)).unwrap();

        assert_eq!(report.removed.len(), 1);
        assert_eq!(report.skipped_by_predicate.len(), 2);
        assert!(report.ok());
        // `policies/` itself stays — predicate mode never removes the
        // subdir even if all files happened to be removed.
        assert!(home.path().join("policies").exists());
        assert!(!home.path().join("policies/default.toml").exists());
        assert!(home.path().join("policies/openclaw-dev.toml").exists());
        assert!(home.path().join("policies/my-overrides.toml").exists());
    }

    #[test]
    fn wipe_predicate_leaves_subdir_when_some_entries_remain() {
        let home = tempfile::tempdir().unwrap();
        touch(&home.path().join("policies/a.toml"));
        touch(&home.path().join("policies/b.toml"));
        let pred: Box<dyn Fn(&Path) -> bool + Send + Sync> =
            Box::new(|p: &Path| p.to_string_lossy().ends_with("a.toml"));
        let _ = wipe_subdirs(home.path(), &["policies"], WipePolicy::Predicate(pred)).unwrap();
        assert!(home.path().join("policies").exists());
        assert!(home.path().join("policies/b.toml").exists());
    }

    #[test]
    fn wipe_recurses_into_subdirs() {
        let home = tempfile::tempdir().unwrap();
        touch(&home.path().join("policies/.legacy-seed-snapshot-X/default.toml"));
        touch(&home.path().join("policies/.legacy-seed-snapshot-X/openclaw.toml"));
        let report = wipe_subdirs(home.path(), &["policies"], WipePolicy::All).unwrap();
        assert!(report.ok());
        assert!(!home.path().join("policies").exists());
    }

    #[test]
    fn wipe_subdirs_refuses_absolute_path() {
        let home = tempfile::tempdir().unwrap();
        let err = wipe_subdirs(home.path(), &["/etc"], WipePolicy::All).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn wipe_subdirs_refuses_path_traversal() {
        let home = tempfile::tempdir().unwrap();
        let err = wipe_subdirs(home.path(), &["../escape"], WipePolicy::All).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn wipe_subdirs_refuses_multi_component_subdir() {
        let home = tempfile::tempdir().unwrap();
        let err = wipe_subdirs(home.path(), &["a/b"], WipePolicy::All).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn wipe_subdirs_refuses_empty_subdir() {
        let home = tempfile::tempdir().unwrap();
        let err = wipe_subdirs(home.path(), &[""], WipePolicy::All).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
