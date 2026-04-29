//! Binary-path resolver for `agentsso uninstall` (Story 7.4).
//!
//! Goal: figure out which file (or directory) on disk represents the
//! installed `agentsso` binary, and decide whether `uninstall` should
//! delete it or refuse and tell the user to run their package
//! manager's uninstall instead.
//!
//! # Resolution order
//!
//! 1. `std::env::current_exe()` — the running binary. This is correct
//!    for curl|sh, Homebrew (resolves to the Cellar path; we then
//!    detect that and refuse), and PowerShell installs.
//! 2. **Package-manager detection.** If the resolved path is part of
//!    a package manager's footprint, refuse to delete:
//!    - **Homebrew (macOS / Linux):** path contains a
//!      `Cellar/agentsso/<version>` segment OR the parent dir
//!      contains an `INSTALL_RECEIPT.json` file.
//!    - **Linux distro packages:** `/usr/bin/agentsso` AND
//!      `dpkg -S` or `rpm -qf` reports a package owner. Phase-2
//!      forward-compat — `apt`/`dnf` packages aren't shipped at MVP,
//!      but the detection guards against a future trip.
//! 3. **Owned-binary delete.** Anything else is treated as an
//!    `agentsso uninstall`-controlled binary and is removed via
//!    [`BinaryRemover::remove_owned_target`].
//!
//! # Symmetry with the autostart module
//!
//! Story 7.3's `lifecycle::autostart::current_daemon_path` performs
//! the symmetric "what is the canonical path of MY binary?" lookup,
//! including a Linux-only argv[0] recovery for Homebrew-on-Linux's
//! `/proc/self/exe` symlink-canonicalization bug (Story 7.3 P39).
//! We **deliberately do not** reuse that helper here — `uninstall`
//! actually wants the canonicalized path. The autostart module needs
//! to detect drift; uninstall needs to delete the real file.

use std::path::{Path, PathBuf};

/// Result of [`resolve_binary_target`] — what the uninstall flow
/// should do about the binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BinaryTarget {
    /// We own this binary. Delete it (or skip on `--keep-binary`).
    /// On Windows, `path` may be a directory (the
    /// `%LOCALAPPDATA%\Programs\agentsso\` install dir from
    /// `install.ps1`); on POSIX it's the binary file itself.
    Owned(PathBuf),

    /// A package manager owns this binary. Skip deletion and direct
    /// the user to the package manager's uninstall command.
    ManagedByPackageManager {
        /// Identifier — `"brew"`, `"dpkg"`, `"rpm"`. Used in the
        /// remediation string and in tests.
        manager: &'static str,
        /// Where the binary lives.
        path: PathBuf,
        /// Operator-facing remediation text — e.g.,
        /// `"brew uninstall agentsso"`.
        remediation: String,
    },
}

/// Errors returned by binary-path resolution.
///
/// Genuine impossibilities (no `current_exe()`, etc.) — distinct
/// from the warn-and-continue paths that go through [`BinaryTarget`].
#[derive(thiserror::Error, Debug)]
pub(crate) enum BinaryResolveError {
    /// `std::env::current_exe()` failed. Extremely rare — happens on
    /// some heavily-sandboxed Linux contexts where `/proc/self/exe`
    /// isn't readable.
    #[error("could not determine current executable path: {source}")]
    CurrentExeUnavailable { source: std::io::Error },
}

/// Resolve the binary target for the running `agentsso` process.
///
/// Production callers pass `current_exe = std::env::current_exe`;
/// tests pass a closure returning a fixture path so package-manager
/// detection can be unit-tested without owning a real Cellar/dpkg
/// install.
///
/// **Story 7.5 — second consumer.** The `agentsso update` flow uses
/// this same helper for "where do I install the new binary, and is
/// the binary package-manager-managed?". When the result is
/// [`BinaryTarget::ManagedByPackageManager`], update refuses with
/// exit 3 and points the user at `brew upgrade` / `apt upgrade`
/// rather than performing an in-place swap that would conflict with
/// the package manager's bookkeeping.
pub(crate) fn resolve_binary_target_with<F>(
    current_exe: F,
) -> Result<BinaryTarget, BinaryResolveError>
where
    F: FnOnce() -> std::io::Result<PathBuf>,
{
    let exe =
        current_exe().map_err(|source| BinaryResolveError::CurrentExeUnavailable { source })?;

    // Cellar / brew-receipt detection: walk parents looking for either
    // a `Cellar/agentsso/<version>` segment OR a sibling
    // `INSTALL_RECEIPT.json` file. Either signal classifies this as
    // brew-managed.
    //
    // P3 (review): on Windows, `current_exe()` returns the .exe; the
    // install dir at `%LOCALAPPDATA%\Programs\agentsso\` may also
    // contain `extract/` and signature artifacts. Promote to the
    // parent dir so the entire install dir is removed.
    let exe_resolved = if cfg!(target_os = "windows") {
        if let Some(parent) = exe.parent() {
            // Only promote if the parent dir is named `agentsso` or
            // `Programs\agentsso` — i.e., it looks like our install
            // dir, NOT some shared bin dir.
            let is_install_dir = parent
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.eq_ignore_ascii_case("agentsso"))
                .unwrap_or(false);
            if is_install_dir { parent.to_path_buf() } else { exe.clone() }
        } else {
            exe.clone()
        }
    } else {
        exe.clone()
    };

    if path_in_homebrew_cellar(&exe) || any_ancestor_has_brew_receipt(&exe) {
        return Ok(BinaryTarget::ManagedByPackageManager {
            manager: "brew",
            path: exe,
            remediation: "brew uninstall agentsso".to_owned(),
        });
    }

    // Linux distro-package detection: only a concern when we're under
    // `/usr/bin` (Homebrew on Linux installs to `/home/linuxbrew/...`,
    // already caught above; cargo-dist installs go to `~/.local/bin`
    // or whatever the user picked). Guard the dpkg/rpm shell-out
    // behind that path check so we don't probe at all on the common
    // case.
    #[cfg(target_os = "linux")]
    if (exe.starts_with("/usr/bin") || exe.starts_with("/usr/local/bin"))
        && let Some(pkg) = detect_distro_package_owner(&exe)
    {
        return Ok(BinaryTarget::ManagedByPackageManager {
            manager: pkg.manager,
            path: exe,
            remediation: pkg.remediation,
        });
    }

    Ok(BinaryTarget::Owned(exe_resolved))
}

/// Default [`resolve_binary_target_with`] using the real
/// [`std::env::current_exe`].
#[allow(dead_code)] // Used by the run() path in mod.rs.
pub(crate) fn resolve_binary_target() -> Result<BinaryTarget, BinaryResolveError> {
    resolve_binary_target_with(std::env::current_exe)
}

/// Brew prefix sentinels — the only legitimate parents of a
/// `Cellar/...` segment for us to refuse-to-delete on. P27 (review):
/// without this anchor, `/Users/Cellar/agentsso/...` would falsely
/// classify a non-brew path as brew-managed.
const BREW_PREFIXES: &[&str] = &[
    "/opt/homebrew",              // Apple Silicon
    "/usr/local",                 // Intel / Linux mac-style
    "/home/linuxbrew/.linuxbrew", // Homebrew on Linux
];

/// Walk parent components looking for a `<brew-prefix>/Cellar/agentsso*` segment.
///
/// Matches both `/opt/homebrew/Cellar/agentsso/0.3.0/bin/agentsso`
/// (Apple Silicon) and `/usr/local/Cellar/agentsso/0.3.0/bin/agentsso`
/// (Intel). P27 + P35 (review): require the path to start with a
/// known brew prefix AND match `agentsso` OR `agentsso@<version>`
/// (versioned formulae like `agentsso@0.3` use the `agentsso@`
/// prefix per Homebrew's versioned-formula convention).
fn path_in_homebrew_cellar(p: &Path) -> bool {
    let p_str = p.to_string_lossy();
    if !BREW_PREFIXES.iter().any(|prefix| p_str.starts_with(prefix)) {
        return false;
    }
    let mut components = p.components().peekable();
    while let Some(c) = components.next() {
        if c.as_os_str() == "Cellar"
            && let Some(next) = components.peek()
            && let Some(name) = next.as_os_str().to_str()
            && (name == "agentsso" || name.starts_with("agentsso@"))
        {
            return true;
        }
    }
    false
}

/// Check whether any ancestor directory of `exe` contains an
/// `INSTALL_RECEIPT.json` file with a name matching `agentsso*`.
///
/// This catches Homebrew installs even if the path layout changes
/// (e.g., a `bottles/` reorganization in a future brew release).
///
/// P36 (review): cap walk at 5 ancestors AND verify the receipt's
/// `name` field matches `agentsso*` so a stray INSTALL_RECEIPT.json
/// from an unrelated formula in a sibling dir doesn't false-positive.
/// Standard brew Cellar layout is `<prefix>/Cellar/agentsso/<version>/bin/agentsso`
/// — 4 ancestors deep — so 5 is generous.
fn any_ancestor_has_brew_receipt(exe: &Path) -> bool {
    const MAX_DEPTH: usize = 5;
    let mut current = exe.parent();
    let mut depth = 0;
    while let Some(dir) = current {
        if depth > MAX_DEPTH {
            return false;
        }
        let receipt_path = dir.join("INSTALL_RECEIPT.json");
        if receipt_path.exists() && brew_receipt_is_for_agentsso(&receipt_path) {
            return true;
        }
        current = dir.parent();
        depth += 1;
    }
    false
}

/// Read the brew INSTALL_RECEIPT.json and confirm its `name` field
/// (or any field that spells out the formula identifier) starts with
/// `agentsso`. Lenient — if the file is unparseable, return true so
/// the receipt's mere presence still acts as defense-in-depth.
fn brew_receipt_is_for_agentsso(receipt_path: &Path) -> bool {
    let bytes = match std::fs::read(receipt_path) {
        Ok(b) => b,
        Err(_) => return true, // Permission-denied or other read error
                               // — defense-in-depth: assume agentsso.
    };
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return true, // Unparseable — defense-in-depth.
    };
    // Brew receipts include a `source.formula` key with the formula
    // identifier (e.g., `permitlayer/tap/agentsso`). Fall back to
    // a top-level `name` if the schema differs.
    let formula = value
        .pointer("/source/formula")
        .and_then(|v| v.as_str())
        .or_else(|| value.get("name").and_then(|v| v.as_str()));
    match formula {
        Some(name) => {
            // Match `agentsso`, `permitlayer/tap/agentsso`,
            // `agentsso@0.3`, etc.
            name == "agentsso"
                || name.ends_with("/agentsso")
                || name.starts_with("agentsso@")
                || name.contains("/agentsso@")
        }
        None => true, // Unknown shape — defense-in-depth.
    }
}

#[cfg(target_os = "linux")]
struct DistroPackage {
    manager: &'static str,
    remediation: String,
}

/// Spawn a `Command` and wait up to `timeout` for it to finish.
/// Mirrors `lifecycle::autostart::run_with_timeout` (Story 7.3 P37
/// pattern) for symmetry. P34 (review): a wedged `dpkg` (apt-lock
/// held by another terminal) used to hang uninstall indefinitely.
#[cfg(target_os = "linux")]
fn run_with_timeout(
    program: &str,
    args: &[&std::ffi::OsStr],
    timeout: std::time::Duration,
) -> std::io::Result<std::process::Output> {
    use std::io::Read as _;
    use std::time::Instant;

    let mut child = std::process::Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let start = Instant::now();
    loop {
        match child.try_wait()? {
            Some(status) => {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(mut h) = child.stdout.take() {
                    let _ = h.read_to_end(&mut stdout);
                }
                if let Some(mut h) = child.stderr.take() {
                    let _ = h.read_to_end(&mut stderr);
                }
                return Ok(std::process::Output { status, stdout, stderr });
            }
            None => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("{program} did not exit within {}s", timeout.as_secs()),
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}

/// Probe `dpkg -S` and then `rpm -qf` to detect package ownership of
/// `exe`. Returns the first match.
///
/// Tolerates "tool not on PATH" (returns `None`); a non-zero exit
/// from dpkg/rpm means "not owned" (also returns `None`); a timeout
/// (e.g., `dpkg` lock held by `apt`) also returns `None` per
/// P34 (review).
#[cfg(target_os = "linux")]
fn detect_distro_package_owner(exe: &Path) -> Option<DistroPackage> {
    let timeout = std::time::Duration::from_secs(10);
    let exe_os = exe.as_os_str();

    // dpkg first — Debian/Ubuntu majority on the supported matrix.
    if let Ok(out) = run_with_timeout("dpkg", &[std::ffi::OsStr::new("-S"), exe_os], timeout)
        && out.status.success()
    {
        // Output shape: `<package>: <path>`. Take the package
        // name for the remediation.
        let stdout = String::from_utf8_lossy(&out.stdout);
        let pkg = stdout
            .lines()
            .next()
            .and_then(|line| line.split(':').next())
            .map(|s| s.trim())
            .unwrap_or("agentsso")
            .to_owned();
        return Some(DistroPackage { manager: "dpkg", remediation: format!("apt remove {pkg}") });
    }

    // rpm — Fedora / RHEL.
    if let Ok(out) = run_with_timeout("rpm", &[std::ffi::OsStr::new("-qf"), exe_os], timeout)
        && out.status.success()
    {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let pkg = stdout.lines().next().map(|s| s.trim()).unwrap_or("agentsso").to_owned();
        return Some(DistroPackage { manager: "rpm", remediation: format!("rpm -e {pkg}") });
    }

    None
}

/// Pluggable binary-removal abstraction.
///
/// Production uses [`RealBinaryRemover`] which actually deletes
/// files. Unit tests substitute a recording mock so they don't
/// rm-self the test binary.
pub(crate) trait BinaryRemover: Send + Sync {
    /// Remove the file (or directory, on Windows) at `path`. Errors
    /// are surfaced to the caller via [`std::io::Result`]; the
    /// uninstall orchestrator translates them into per-step warnings.
    fn remove_owned_target(&self, path: &Path) -> std::io::Result<()>;
}

/// Real `BinaryRemover` — calls into [`std::fs`].
pub(crate) struct RealBinaryRemover;

impl BinaryRemover for RealBinaryRemover {
    fn remove_owned_target(&self, path: &Path) -> std::io::Result<()> {
        // On Windows, `install.ps1` writes the binary into
        // `%LOCALAPPDATA%\Programs\agentsso\` (a directory). On POSIX,
        // the binary is a single file at `/usr/local/bin/agentsso`
        // (or wherever the user pointed `AGENTSSO_INSTALL_DIR`).
        // Detect which case we're in by stat'ing the path.
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.is_dir() {
            // P2 (review): on Windows, removing the install dir
            // also requires cleaning up the corresponding HKCU PATH
            // entry. Best-effort — log via stderr if the registry
            // edit fails, but DO NOT block the directory removal.
            #[cfg(target_os = "windows")]
            update_user_path_remove(path);
            std::fs::remove_dir_all(path)
        } else {
            std::fs::remove_file(path)
        }
    }
}

/// P2 (review): remove the install dir from the user PATH on
/// Windows. Mirrors `install.ps1:489-540` in reverse — splits HKCU
/// `Environment.Path` on `;`, filters out the install dir under
/// literal/expanded/trailing-backslash variants, writes back, and
/// broadcasts WM_SETTINGCHANGE so newly-spawned terminals see the
/// updated PATH without logout.
///
/// Best-effort: errors are logged via `eprintln!` but do not block
/// the data-dir removal. The user-facing remediation in the closing
/// line documents that they may need to manually clean PATH.
///
/// Manual smoke verification on a real Windows 11 host is part of
/// Story 7.4 Task 8 (Austin event-driven follow-up); this code is
/// deliberately defensive — `reg.exe` is on the System32 path of
/// every supported Windows version (Windows 10 v2004+ per PRD §608).
#[cfg(target_os = "windows")]
fn update_user_path_remove(install_dir: &Path) {
    use std::process::Command;
    let install_str = match install_dir.to_str() {
        Some(s) => s,
        None => {
            eprintln!("warning: install dir contains non-UTF-8 chars; skipping PATH cleanup");
            return;
        }
    };
    let needle = install_str.trim_end_matches('\\');

    // Read the current PATH from HKCU\Environment.
    let read = match Command::new("reg").args(["query", r"HKCU\Environment", "/v", "Path"]).output()
    {
        Ok(o) if o.status.success() => o,
        _ => {
            // No PATH entry, or reg.exe failed. Either way, nothing
            // to remove.
            return;
        }
    };
    let stdout = String::from_utf8_lossy(&read.stdout);
    // The `reg query` output shape is:
    //     HKEY_CURRENT_USER\Environment
    //         Path    REG_EXPAND_SZ    <value>
    let current_path = match stdout
        .lines()
        .find(|line| line.trim_start().starts_with("Path"))
        .and_then(|line| {
            // Split on multiple spaces or tabs; the value is the LAST
            // whitespace-separated token. To preserve embedded spaces
            // in path components, take everything after the third
            // whitespace-delimited token.
            let mut parts = line.splitn(3, char::is_whitespace).filter(|p| !p.is_empty());
            parts.next()?; // "Path"
            parts.next()?; // "REG_EXPAND_SZ"
            parts.next()
        })
        .map(str::trim)
    {
        Some(p) => p.to_owned(),
        None => return,
    };

    // Filter out entries matching the install dir.
    let filtered: Vec<&str> = current_path
        .split(';')
        .filter(|entry| {
            let trimmed = entry.trim_end_matches('\\');
            !trimmed.eq_ignore_ascii_case(needle)
        })
        .collect();
    if filtered.len() == current_path.split(';').count() {
        // No match — nothing to remove.
        return;
    }
    let new_path = filtered.join(";");
    let write = Command::new("reg")
        .args([
            "add",
            r"HKCU\Environment",
            "/v",
            "Path",
            "/t",
            "REG_EXPAND_SZ",
            "/d",
            &new_path,
            "/f",
        ])
        .output();
    match write {
        Ok(o) if o.status.success() => {
            // Broadcast WM_SETTINGCHANGE so File Explorer and new
            // terminals see the update without logout.
            let _ = Command::new("setx").args(["AGENTSSO_PATH_CLEANUP_NUDGE", ""]).output();
        }
        _ => {
            eprintln!(
                "warning: could not update HKCU\\Environment\\Path to remove {install_str}; \
                 clean it manually via System Properties > Environment Variables"
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn cellar_path_classified_as_brew_managed() {
        let exe = PathBuf::from("/opt/homebrew/Cellar/agentsso/0.3.0/bin/agentsso");
        let target = resolve_binary_target_with(|| Ok(exe.clone())).unwrap();
        match target {
            BinaryTarget::ManagedByPackageManager { manager, ref path, ref remediation } => {
                assert_eq!(manager, "brew");
                assert_eq!(path, &exe);
                assert_eq!(remediation, "brew uninstall agentsso");
            }
            other => panic!("expected ManagedByPackageManager(brew), got {other:?}"),
        }
    }

    #[test]
    fn intel_homebrew_cellar_path_classified_as_brew_managed() {
        // Intel Homebrew lives under /usr/local/Cellar/...
        let exe = PathBuf::from("/usr/local/Cellar/agentsso/0.3.0/bin/agentsso");
        let target = resolve_binary_target_with(|| Ok(exe.clone())).unwrap();
        assert!(matches!(target, BinaryTarget::ManagedByPackageManager { manager: "brew", .. }));
    }

    #[test]
    fn cellar_substring_in_username_does_not_match() {
        // Component-based detection: a username called "Cellar" must
        // not trip the brew classifier.
        let exe = PathBuf::from("/Users/Cellar/dev/agentsso/target/release/agentsso");
        let target = resolve_binary_target_with(|| Ok(exe.clone())).unwrap();
        assert!(matches!(target, BinaryTarget::Owned(_)));
    }

    #[test]
    fn cellar_with_wrong_formula_name_does_not_match() {
        // Cellar segment present but for a different formula —
        // shouldn't match. (Pathological case, but defensively
        // tested.)
        // P25 (review): use a path constructed under a tempdir so a
        // real INSTALL_RECEIPT.json in `/opt/homebrew/Cellar/...`
        // (which a developer running these tests on their own brew
        // install might have!) can't false-positive via the
        // ancestor-receipt fallback.
        let tmp = tempfile::TempDir::new().unwrap();
        let exe = tmp.path().join("opt/homebrew/Cellar/some-other-formula/1.0/bin/agentsso");
        let target = resolve_binary_target_with(|| Ok(exe.clone())).unwrap();
        // Path doesn't have a brew prefix nor an INSTALL_RECEIPT —
        // classified as Owned.
        assert!(matches!(target, BinaryTarget::Owned(_)));
    }

    #[test]
    fn install_receipt_in_ancestor_classifies_as_brew_managed() {
        // Even without the literal `Cellar/agentsso` segment, an
        // INSTALL_RECEIPT.json in any ancestor dir signals brew.
        let tmp = tempfile::TempDir::new().unwrap();
        let cellar = tmp.path().join("brew-keg/0.3.0");
        std::fs::create_dir_all(cellar.join("bin")).unwrap();
        std::fs::write(cellar.join("INSTALL_RECEIPT.json"), "{}").unwrap();
        let exe = cellar.join("bin/agentsso");
        std::fs::write(&exe, "fake").unwrap();
        let target = resolve_binary_target_with(|| Ok(exe.clone())).unwrap();
        assert!(matches!(target, BinaryTarget::ManagedByPackageManager { manager: "brew", .. }));
    }

    #[test]
    fn usr_local_bin_classified_as_owned_on_macos() {
        // The default curl|sh install destination on POSIX. We DO
        // own this — `install.sh` put it there and `agentsso
        // uninstall` should remove it.
        let exe = PathBuf::from("/usr/local/bin/agentsso");
        let target = resolve_binary_target_with(|| Ok(exe.clone())).unwrap();
        // On Linux, this could trip the dpkg/rpm probe in production
        // but in tests we don't have those binaries-as-package-source,
        // so it stays Owned.
        match target {
            BinaryTarget::Owned(p) => assert_eq!(p, exe),
            BinaryTarget::ManagedByPackageManager { manager, .. } => {
                // Linux CI runners may legitimately have dpkg installed,
                // so this branch is acceptable in environment-dependent
                // ways. Guard the assertion to acknowledge that.
                assert!(matches!(manager, "dpkg" | "rpm"));
            }
        }
    }

    #[test]
    fn windows_localappdata_path_classified_as_owned() {
        // The `%LOCALAPPDATA%\Programs\agentsso\agentsso.exe` install
        // path from install.ps1:650. Owned, not package-managed.
        let exe = PathBuf::from(r"C:\Users\maya\AppData\Local\Programs\agentsso\agentsso.exe");
        let target = resolve_binary_target_with(|| Ok(exe.clone())).unwrap();
        assert!(matches!(target, BinaryTarget::Owned(_)));
    }

    #[test]
    fn current_exe_failure_surfaces_as_error() {
        let err = resolve_binary_target_with(|| {
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no exe"))
        })
        .unwrap_err();
        assert!(matches!(err, BinaryResolveError::CurrentExeUnavailable { .. }));
    }

    /// Recording mock for [`BinaryRemover`] used in orchestrator
    /// tests. Does NOT actually delete anything.
    #[derive(Default)]
    pub(crate) struct MockBinaryRemover {
        calls: std::sync::Mutex<Vec<PathBuf>>,
        next_error: std::sync::Mutex<Option<std::io::Error>>,
    }

    impl MockBinaryRemover {
        #[allow(dead_code)] // Reserved for future tests.
        pub(crate) fn calls(&self) -> Vec<PathBuf> {
            self.calls.lock().unwrap().clone()
        }

        #[allow(dead_code)] // Reserved for future tests.
        pub(crate) fn arm_error(&self, e: std::io::Error) {
            *self.next_error.lock().unwrap() = Some(e);
        }
    }

    impl BinaryRemover for MockBinaryRemover {
        fn remove_owned_target(&self, path: &Path) -> std::io::Result<()> {
            self.calls.lock().unwrap().push(path.to_path_buf());
            if let Some(err) = self.next_error.lock().unwrap().take() {
                return Err(err);
            }
            Ok(())
        }
    }

    /// P17 (review): exercise MockBinaryRemover so it isn't dead code.
    /// Validates the trait dispatch + error-arming + call-recording
    /// behavior tests can rely on.
    #[test]
    fn mock_binary_remover_records_calls_and_arms_errors() {
        let mock = MockBinaryRemover::default();
        let p1 = PathBuf::from("/usr/local/bin/agentsso");
        let p2 = PathBuf::from("/opt/agentsso/agentsso");
        // First call succeeds, records the path.
        mock.remove_owned_target(&p1).unwrap();
        // Arm an error for the second call.
        mock.arm_error(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "armed"));
        let err = mock.remove_owned_target(&p2).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        // Both calls were recorded; armed error was one-shot.
        let calls = mock.calls();
        assert_eq!(calls, vec![p1, p2.clone()]);
        // A third call has no armed error and succeeds.
        mock.remove_owned_target(&p2).unwrap();
        assert_eq!(mock.calls().len(), 3);
    }
}
