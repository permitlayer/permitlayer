//! `sudo agentsso setup` — the single idempotent install / upgrade /
//! repair command for the privileged macOS daemon (UX-overhaul epic,
//! Story 2 — the keystone).
//!
//! Replaces `agentsso service install` as the primary verb. The
//! install/upgrade UX was unreliable by construction: a two-copy
//! binary split that drifted, copy-before-bootout (`Bootstrap failed:
//! 5` on every upgrade), no version-verify, and a first-run-only
//! policy seed. `setup` fixes all of that *by construction*:
//!
//! - **Versioned-symlink model.** The active binary lives at
//!   `<helper-dir>/agentsso-<V>` (immutable once written). The stable
//!   `<helper-dir>/agentsso` is a **symlink** to it; the LaunchDaemon
//!   plist points at the stable symlink path and **never changes
//!   across upgrades** (launchd re-resolves the symlink at each
//!   `bootstrap`).
//! - **bootout FIRST**, before any binary mutation — kills the
//!   copy-before-bootout `Bootstrap failed: 5` class.
//! - **Atomic cutover.** `symlink(new, .tmp); rename(.tmp, stable)`
//!   (same-dir, parent fsync) — never a half-installed state.
//! - **Self-verifying.** After bootstrap, `setup` polls
//!   `GET /v1/control/whoami` over the control UDS and refuses to
//!   declare success until the daemon reports `version == V`, the
//!   stable symlink resolves to `agentsso-<V>`, that file is
//!   byte-identical to what we staged, and launchd reports it
//!   `running`. Any post-cutover failure rolls the symlink back to
//!   the prior versioned binary and re-bootstraps.
//!
//! ## Trust model (why no minisign-verify on the local binary)
//!
//! `setup` stages a copy of **this process's own `current_exe()`**.
//! That binary was already minisign-verified at install time by the
//! curl|sh installer (`install/install.sh`) or sha256-pinned by the
//! Homebrew formula. There is no `.minisig` sidecar on disk for an
//! *extracted* binary, and `release_verify::verify_minisign` checks a
//! signature over a release **tarball**, not a bare binary — so it is
//! not applicable here (see `release_verify.rs` module docs). The
//! local fail-closed control is instead: (a) a content-hash
//! idempotency gate — a pre-existing `agentsso-<V>` whose bytes
//! differ from the staged copy is refused (tamper/corruption), never
//! silently overwritten; and (b) the self-verify activation gate — a
//! binary that won't run or reports the wrong version never becomes
//! the active symlink target.

#[cfg(target_os = "macos")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Args;

use crate::cli::silent_cli_error;
use crate::design::render::error_block;

/// Arguments for `agentsso setup`. Mirrors `service::InstallArgs` so
/// the `--from` dev seam (point setup at an alternate source binary)
/// survives the rename.
#[derive(Args, Debug, Default, Clone)]
pub struct SetupArgs {
    /// Dev/test seam: install from this binary path instead of the
    /// running executable. Production operators never pass this.
    #[arg(long)]
    pub from: Option<std::path::PathBuf>,
}

/// Run `agentsso setup`.
pub async fn run(args: SetupArgs) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        run_macos(args).await
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = args;
        eprint!(
            "{}",
            error_block(
                "setup.macos_only",
                "`agentsso setup` installs a privileged macOS LaunchDaemon and is \
                 macOS-only in this release",
                "on Linux/Windows, run `agentsso start` directly (foreground) — the \
                 privileged-install model is macOS-specific",
                None,
            )
        );
        Err(silent_cli_error("setup is macOS-only"))
    }
}

// ── Glyphs (mirror cli::update / cli::uninstall) ────────────────────

#[cfg(target_os = "macos")]
struct Glyphs {
    arrow: &'static str,
    check: &'static str,
    warn: &'static str,
}

#[cfg(target_os = "macos")]
fn glyphs() -> Glyphs {
    use crate::design::terminal::ColorSupport;
    match ColorSupport::detect() {
        ColorSupport::NoColor => Glyphs { arrow: "->", check: "[ok]", warn: "[!]" },
        _ => Glyphs {
            arrow: "\u{2192}", // →
            check: "\u{2713}", // ✓
            warn: "\u{26A0}",  // ⚠
        },
    }
}

// ── SHA-256 helper ──────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn sha256_file(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex_lower(&hasher.finalize()))
}

#[cfg(target_os = "macos")]
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ── whoami parse (mirror cli::update::parse_whoami_version) ──────────

#[cfg(target_os = "macos")]
fn parse_whoami_version(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get("version")?.as_str().map(str::to_owned)
}

// ── macOS implementation ────────────────────────────────────────────

#[cfg(target_os = "macos")]
async fn run_macos(args: SetupArgs) -> Result<()> {
    use crate::cli::service::install_macos as im;

    let g = glyphs();
    let started = Instant::now();

    // (1) Root.
    if !nix::unistd::Uid::effective().is_root() {
        eprint!(
            "{}",
            error_block(
                "setup.requires_root",
                "`agentsso setup` installs a privileged system LaunchDaemon and must \
                 run as root",
                "sudo agentsso setup",
                None,
            )
        );
        return Err(silent_cli_error("setup requires root"));
    }

    // (2) Install-lock — serialize against a concurrent setup/install.
    let _lock = im::acquire_install_lock_pub()?;

    // (3) Operator resolution (refuses missing/root SUDO_UID).
    let (operator_uid, operator_username) = im::resolve_operator()?;
    println!("{} setup for operator {operator_username} (uid {operator_uid})", g.arrow);

    // (4) rc.21 LaunchAgent cleanup (idempotent — usually a no-op).
    let cleaned = im::cleanup_rc21_launchagents_pub().await;
    for (path, uid) in &cleaned {
        println!("  {} removed stale rc.21 LaunchAgent: {} (uid {uid})", g.check, path.display());
    }

    // (5) Group + state dirs + keychain (all idempotent / warn-cont).
    im::ensure_permitlayer_clients_group(&operator_username).await?;
    println!("  {} group ensured (operator {operator_username})", g.check);
    im::create_state_dirs()?;
    println!("  {} state + log + runtime dirs ensured", g.check);
    let keychain_warning = im::disable_keychain_lock_on_sleep();

    // (6) Resolve source binary + version V. The source IS this
    // running executable (unless --from); its compile-time
    // CARGO_PKG_VERSION is therefore the staged binary's version AND
    // exactly what the daemon will report via `whoami.version`
    // (server/control.rs uses the same env! — verified).
    let source = im::resolve_binary_source_path(args.from.as_deref())?;
    let version = env!("CARGO_PKG_VERSION");
    let staged_hash = sha256_file(&source).map_err(|e| {
        eprint!(
            "{}",
            error_block(
                "setup.source_unreadable",
                &format!("could not hash the source binary {}: {e}", source.display()),
                "check the binary exists and is readable",
                None,
            )
        );
        silent_cli_error("source binary unreadable")
    })?;

    let helper_path = Path::new(im::PRIVILEGED_HELPER_PATH);
    let helper_dir = helper_path.parent().unwrap_or(Path::new("/"));
    let versioned = helper_dir.join(format!("agentsso-{version}"));

    // (7) bootout FIRST — before ANY binary mutation. This is the
    // copy-before-bootout `Bootstrap failed: 5` fix.
    im::bootout_daemon()?;
    println!("  {} daemon booted out (pre-mutation)", g.check);

    // (8) Stage the versioned binary. Idempotent + fail-closed.
    if versioned.exists() {
        let existing_hash = sha256_file(&versioned).map_err(|e| {
            eprint!(
                "{}",
                error_block(
                    "setup.versioned_unreadable",
                    &format!("could not hash existing {}: {e}", versioned.display()),
                    "remove the file and re-run `sudo agentsso setup`",
                    None,
                )
            );
            silent_cli_error("versioned binary unreadable")
        })?;
        if existing_hash != staged_hash {
            // Same version, different bytes ⇒ tamper or a botched
            // prior install. Refuse — NEVER silently overwrite.
            eprint!(
                "{}",
                error_block(
                    "setup.versioned_binary_mismatch",
                    &format!(
                        "{} already exists but its contents differ from the binary being \
                         installed (same version {version}, different bytes) — refusing to \
                         overwrite (possible tampering or a corrupted prior install)",
                        versioned.display()
                    ),
                    &format!(
                        "investigate {}, then `sudo rm {}` and re-run `sudo agentsso setup`",
                        versioned.display(),
                        versioned.display()
                    ),
                    None,
                )
            );
            return Err(silent_cli_error("versioned binary content mismatch"));
        }
        println!("  {} versioned binary already staged (hash match)", g.check);
    } else {
        im::stage_file_atomic(&source, &versioned)?;
        println!("  {} staged {}", g.check, versioned.display());
    }

    // ── EVERYTHING BELOW IS "POST-STEP-5" (post-cutover): any
    //    failure triggers rollback to `prior_target`. ──────────────

    // (9) Record the prior symlink target for rollback, then do the
    // atomic symlink swap.
    let prior_target: Option<PathBuf> = std::fs::read_link(helper_path).ok();
    // Legacy/regular-file migration: pre-symlink installs had a real
    // binary at the helper path. Remove it so the symlink can be
    // created (breaking change is acceptable — sole consumer is
    // wiped+reinstalled — but handle it gracefully).
    if helper_path.exists()
        && prior_target.is_none()
        && let Err(e) = std::fs::remove_file(helper_path)
    {
        eprint!(
            "{}",
            error_block(
                "setup.legacy_helper_unremovable",
                &format!(
                    "a non-symlink binary exists at {} and could not be removed: {e}",
                    helper_path.display()
                ),
                "manually remove it and re-run `sudo agentsso setup`",
                None,
            )
        );
        return Err(silent_cli_error("legacy helper not removable"));
    }
    if let Err(e) = atomic_symlink_swap(&versioned, helper_path, helper_dir) {
        // Swap itself failed BEFORE the symlink moved → nothing to
        // roll back (the old target, if any, is still in place).
        eprint!(
            "{}",
            error_block(
                "setup.symlink_swap_failed",
                &format!(
                    "could not point {} at {}: {e}",
                    helper_path.display(),
                    versioned.display()
                ),
                "check filesystem permissions on /Library/PrivilegedHelperTools and re-run",
                None,
            )
        );
        return Err(silent_cli_error("symlink swap failed"));
    }
    println!("  {} {} → {}", g.check, helper_path.display(), versioned.display());

    // (10) Plist compare-then-write (no-op on upgrades — it already
    // points at the stable symlink path).
    let wrote = match im::write_launchdaemon_plist(operator_uid, &operator_username) {
        Ok(w) => w,
        Err(e) => {
            return rollback(
                &g,
                prior_target.as_deref(),
                helper_path,
                helper_dir,
                &format!("plist write failed: {e}"),
            )
            .await;
        }
    };
    println!("  {} LaunchDaemon plist {}", g.check, if wrote { "written" } else { "unchanged" });

    // (11) Bootstrap.
    if let Err(e) = im::launchctl_bootstrap_system() {
        return rollback(
            &g,
            prior_target.as_deref(),
            helper_path,
            helper_dir,
            &format!("launchctl bootstrap failed: {e}"),
        )
        .await;
    }
    println!("  {} launchctl bootstrap", g.check);

    // (12) Self-verify: poll whoami over the control UDS until the
    // daemon reports version == V; then assert the symlink resolves
    // to agentsso-<V>, that file's hash == staged_hash, and launchd
    // reports it running with a non-zero pid.
    match self_verify(version, &versioned, &staged_hash, Duration::from_secs(15)).await {
        Ok(pid) => {
            println!("  {} self-verified: daemon {version} running (pid {pid})", g.check);
            im::emit_install_complete_audit(
                operator_uid,
                &operator_username,
                pid,
                started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            );
        }
        Err(reason) => {
            return rollback(&g, prior_target.as_deref(), helper_path, helper_dir, &reason).await;
        }
    }

    // (13) GC old versioned binaries — keep current + the single most
    // recent other version. Best-effort; never aborts setup.
    gc_old_versions(&g, helper_dir, version);

    // (14) Caveats.
    println!();
    println!("──────────────────────────────────────────────────────────────");
    println!("{} PermitLayer installed/upgraded as a macOS system service.", g.check);
    println!();
    println!("Daemon log: /Library/Logs/permitlayer/daemon.log");
    if let Some(stderr) = &keychain_warning {
        println!();
        println!("{} System.keychain lock-on-sleep could not be disabled:", g.warn);
        for line in stderr.lines() {
            println!("    {line}");
        }
        println!("  The daemon may re-prompt for the master key after sleep/wake.");
    }
    println!();
    println!("End-users on this Mac connect an agent with:");
    println!("  agentsso quickstart <service>   (gmail | calendar | drive)");
    println!("──────────────────────────────────────────────────────────────");
    Ok(())
}

/// `symlink(target, <dir>/agentsso.tmp); rename(.tmp, stable)` —
/// atomic on the same filesystem; fsync the parent dir so the swap is
/// durable across a crash.
#[cfg(target_os = "macos")]
fn atomic_symlink_swap(target: &Path, stable: &Path, dir: &Path) -> std::io::Result<()> {
    let tmp = dir.join(format!("agentsso.tmp.{}", std::process::id()));
    // Clean any stale tmp from a prior crashed run.
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(target, &tmp)?;
    if let Err(e) = std::fs::rename(&tmp, stable) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Poll `whoami` over the control UDS, then assert symlink integrity +
/// launchd-running. Returns the daemon pid on success, or a
/// human-readable failure reason.
#[cfg(target_os = "macos")]
async fn self_verify(
    expected_version: &str,
    versioned: &Path,
    staged_hash: &str,
    timeout: Duration,
) -> std::result::Result<u32, String> {
    use crate::cli::kill;
    use crate::config::{CliOverrides, DaemonConfig};

    let config = DaemonConfig::load(&CliOverrides::default()).unwrap_or_default();
    let endpoint = kill::resolve_control_endpoint(&config);
    let home = crate::cli::agentsso_home()
        .map_err(|e| format!("could not resolve agentsso home for control token: {e}"))?;

    let deadline = Instant::now() + timeout;
    let interval = Duration::from_millis(250);
    let mut last = "control plane never became reachable".to_owned();
    while Instant::now() < deadline {
        // Re-read the token every iteration — the daemon mints it on
        // start, so it may not exist on the first poll.
        let token = kill::read_control_token(&home);
        match kill::http_get_via(&endpoint, "/v1/control/whoami", token.as_deref()).await {
            Ok(body) => match parse_whoami_version(&body) {
                Some(v) if v == expected_version => {
                    // Daemon is the right version. Now prove the
                    // symlink topology + content (Decision B: this
                    // replaces an infeasible pid→path check).
                    return finalize_verify(versioned, staged_hash);
                }
                Some(v) => {
                    last = format!(
                        "daemon reports version {v} but {expected_version} was installed \
                         (restart race — still polling)"
                    );
                }
                None => {
                    last = "whoami response had no parseable version field".to_owned();
                }
            },
            Err(_) => {
                last = "control UDS not yet answering".to_owned();
            }
        }
        tokio::time::sleep(interval).await;
    }
    Err(format!("self-verify timed out after {timeout:?}: {last}"))
}

/// The non-UDS half of self-verify: the stable symlink resolves to
/// the version we staged, that file is byte-identical to what we
/// staged, and launchd reports the daemon running with a non-zero
/// pid. (Decision B — strongest feasible substitute for pid→path.)
#[cfg(target_os = "macos")]
fn finalize_verify(versioned: &Path, staged_hash: &str) -> std::result::Result<u32, String> {
    use crate::cli::service::install_macos as im;

    let helper_path = Path::new(im::PRIVILEGED_HELPER_PATH);
    let resolved = std::fs::read_link(helper_path)
        .map_err(|e| format!("stable symlink {} unreadable: {e}", helper_path.display()))?;
    // The recorded target is an absolute path under helper_dir; the
    // symlink we wrote is also absolute, so compare directly.
    if resolved != versioned {
        return Err(format!(
            "stable symlink resolves to {} but the active version should be {}",
            resolved.display(),
            versioned.display()
        ));
    }
    let on_disk = sha256_file(versioned)
        .map_err(|e| format!("could not re-hash active binary {}: {e}", versioned.display()))?;
    if on_disk != staged_hash {
        return Err(format!(
            "active binary {} hash {on_disk} != staged hash {staged_hash} (tamper after stage?)",
            versioned.display()
        ));
    }
    // launchd must report it running with a real pid.
    let out = std::process::Command::new("/bin/launchctl")
        .args(["print", "system/dev.permitlayer.daemon"])
        .output()
        .map_err(|e| format!("could not invoke launchctl print: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    match im::parse_launchctl_running(&stdout) {
        Some(pid) => Ok(pid),
        None => Err("launchctl does not report the daemon as `state = running` with a \
                     non-zero pid"
            .to_owned()),
    }
}

/// Best-effort post-rollback reachability poll. After `rollback`
/// re-bootstraps the prior binary we want to confirm the *old* daemon
/// actually came back and report which version it is — but unlike
/// `self_verify` we do NOT know the prior version statically, so this
/// asserts only "control plane answers `whoami` with a parseable
/// version" within a short deadline. Returns the recovered version
/// string, or `None` if it never became reachable in time. NEVER
/// fails rollback — this only enriches the operator report.
#[cfg(target_os = "macos")]
async fn poll_recovered_version(timeout: Duration) -> Option<String> {
    use crate::cli::kill;
    use crate::config::{CliOverrides, DaemonConfig};

    let config = DaemonConfig::load(&CliOverrides::default()).unwrap_or_default();
    let endpoint = kill::resolve_control_endpoint(&config);
    let home = crate::cli::agentsso_home().ok()?;

    let deadline = Instant::now() + timeout;
    let interval = Duration::from_millis(250);
    while Instant::now() < deadline {
        let token = kill::read_control_token(&home);
        if let Ok(body) =
            kill::http_get_via(&endpoint, "/v1/control/whoami", token.as_deref()).await
            && let Some(v) = parse_whoami_version(&body)
        {
            return Some(v);
        }
        tokio::time::sleep(interval).await;
    }
    None
}

/// Roll the symlink back to `prior_target` and re-bootstrap. Emits a
/// structured error and returns the silent-cli error so the caller
/// just `return rollback(...).await`.
#[cfg(target_os = "macos")]
async fn rollback(
    g: &Glyphs,
    prior_target: Option<&Path>,
    helper_path: &Path,
    helper_dir: &Path,
    cause: &str,
) -> Result<()> {
    use crate::cli::service::install_macos as im;

    eprintln!("{} setup failed: {cause}", g.warn);
    match prior_target {
        Some(prior) if prior.exists() => {
            eprintln!("{} rolling back to prior binary {}", g.arrow, prior.display());
            let swap_ok = atomic_symlink_swap(prior, helper_path, helper_dir).is_ok();
            let _ = im::bootout_daemon();
            let boot_ok = im::launchctl_bootstrap_system().is_ok();
            if swap_ok && boot_ok {
                // Re-verify the old daemon actually came back reachable
                // and report its whoami.version. Best-effort: if it
                // does not answer within the deadline, the rollback
                // mechanics still succeeded (symlink + bootstrap) but
                // we downgrade the report so the operator knows the
                // control plane has not yet confirmed liveness.
                match poll_recovered_version(Duration::from_secs(5)).await {
                    Some(recovered) => {
                        eprint!(
                            "{}",
                            error_block(
                                "setup.rolled_back",
                                &format!(
                                    "setup failed ({cause}); the prior binary at {} was \
                                     restored and re-bootstrapped (daemon {recovered} is back \
                                     and answering)",
                                    prior.display()
                                ),
                                "investigate the failure cause above, then re-run \
                                 `sudo agentsso setup`",
                                None,
                            )
                        );
                    }
                    None => {
                        eprint!(
                            "{}",
                            error_block(
                                "setup.rollback_incomplete",
                                &format!(
                                    "setup failed ({cause}); the prior binary at {} was \
                                     restored and re-bootstrapped, but the control plane did \
                                     not confirm the daemon is back within 5s — it may still \
                                     be starting, or rollback did not fully recover",
                                    prior.display()
                                ),
                                "check /Library/Logs/permitlayer/daemon.log and \
                                 `sudo launchctl print system/dev.permitlayer.daemon`; if the \
                                 daemon is down, re-run `sudo agentsso setup`",
                                None,
                            )
                        );
                    }
                }
            } else {
                eprint!(
                    "{}",
                    error_block(
                        "setup.rollback_incomplete",
                        &format!(
                            "setup failed ({cause}) AND rollback did not fully succeed \
                             (symlink_restored={swap_ok}, rebootstrapped={boot_ok}) — the \
                             daemon may be down"
                        ),
                        "manually run `sudo launchctl bootstrap system \
                         /Library/LaunchDaemons/dev.permitlayer.daemon.plist` and check \
                         /Library/Logs/permitlayer/daemon.log",
                        None,
                    )
                );
            }
        }
        _ => {
            // First install (no prior to roll back to) — daemon may
            // be down; nothing we can restore.
            eprint!(
                "{}",
                error_block(
                    "setup.failed_no_rollback",
                    &format!(
                        "setup failed ({cause}) and there was no prior binary to roll back \
                         to (first install)"
                    ),
                    "check /Library/Logs/permitlayer/daemon.log, then re-run \
                     `sudo agentsso setup`",
                    None,
                )
            );
        }
    }
    Err(silent_cli_error("setup failed (see rollback report)"))
}

/// Keep the current version + the single most-recent other version;
/// delete older `agentsso-<semver>` binaries. Best-effort.
#[cfg(target_os = "macos")]
fn gc_old_versions(g: &Glyphs, helper_dir: &Path, current_version: &str) {
    let Ok(entries) = std::fs::read_dir(helper_dir) else {
        return;
    };
    // (semver, path) for every agentsso-<parseable-semver> file.
    let mut versioned: Vec<(semver::Version, PathBuf)> = Vec::new();
    for e in entries.flatten() {
        let path = e.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(ver_str) = name.strip_prefix("agentsso-") else {
            continue;
        };
        // Skip the stable symlink itself and tmp crumbs.
        if ver_str.contains(".tmp.") || ver_str.is_empty() {
            continue;
        }
        if let Ok(v) = semver::Version::parse(ver_str) {
            versioned.push((v, path));
        }
    }
    let Ok(current) = semver::Version::parse(current_version) else {
        return;
    };
    // Sort descending by semver.
    versioned.sort_by(|a, b| b.0.cmp(&a.0));
    // Keep: the current version, plus the highest version that isn't
    // the current one (the "previous" rollback target).
    let mut kept_other = false;
    for (v, path) in &versioned {
        if *v == current {
            continue; // always keep current
        }
        if !kept_other {
            kept_other = true; // keep the most-recent non-current
            continue;
        }
        if std::fs::remove_file(path).is_ok() {
            println!("  {} gc: removed old {}", g.check, path.display());
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_whoami_version_extracts() {
        assert_eq!(
            parse_whoami_version(r#"{"pid":7,"version":"0.3.0-rc.36"}"#),
            Some("0.3.0-rc.36".to_owned())
        );
        assert_eq!(parse_whoami_version(r#"{"pid":7}"#), None);
        assert_eq!(parse_whoami_version("not json"), None);
    }

    #[test]
    fn sha256_file_is_stable_and_distinguishes_content() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        let b = d.path().join("b");
        std::fs::write(&a, b"hello").unwrap();
        std::fs::write(&b, b"hello").unwrap();
        assert_eq!(sha256_file(&a).unwrap(), sha256_file(&b).unwrap());
        std::fs::write(&b, b"world").unwrap();
        assert_ne!(sha256_file(&a).unwrap(), sha256_file(&b).unwrap());
        // Known vector for "hello".
        assert_eq!(
            sha256_file(&a).unwrap(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn atomic_symlink_swap_repoints_and_is_idempotent() {
        let d = tempfile::tempdir().unwrap();
        let v1 = d.path().join("agentsso-0.1.0");
        let v2 = d.path().join("agentsso-0.2.0");
        std::fs::write(&v1, b"one").unwrap();
        std::fs::write(&v2, b"two").unwrap();
        let stable = d.path().join("agentsso");

        atomic_symlink_swap(&v1, &stable, d.path()).unwrap();
        assert_eq!(std::fs::read_link(&stable).unwrap(), v1);
        // Re-point (upgrade) — replaces the existing symlink.
        atomic_symlink_swap(&v2, &stable, d.path()).unwrap();
        assert_eq!(std::fs::read_link(&stable).unwrap(), v2);
        // No tmp crumb left behind.
        assert!(
            !d.path().join(format!("agentsso.tmp.{}", std::process::id())).exists(),
            "swap must not leave a tmp symlink"
        );
    }

    #[test]
    fn gc_keeps_current_and_one_previous() {
        let d = tempfile::tempdir().unwrap();
        for v in ["0.1.0", "0.2.0", "0.3.0", "0.3.0-rc.36"] {
            std::fs::write(d.path().join(format!("agentsso-{v}")), v.as_bytes()).unwrap();
        }
        // A non-versioned file + the stable symlink-name must be
        // untouched.
        std::fs::write(d.path().join("README"), b"x").unwrap();
        std::fs::write(d.path().join("agentsso"), b"sym").unwrap();

        let g = Glyphs { arrow: "->", check: "ok", warn: "!" };
        gc_old_versions(&g, d.path(), "0.3.0");

        assert!(d.path().join("agentsso-0.3.0").exists(), "current kept");
        // Highest non-current is 0.3.0-rc.36? No — 0.3.0 > 0.3.0-rc.36
        // in semver (release > its prerelease). Descending order:
        // 0.3.0, 0.3.0-rc.36, 0.2.0, 0.1.0. Current=0.3.0 skipped;
        // first non-current kept = 0.3.0-rc.36; rest deleted.
        assert!(d.path().join("agentsso-0.3.0-rc.36").exists(), "most-recent non-current kept");
        assert!(!d.path().join("agentsso-0.2.0").exists(), "older deleted");
        assert!(!d.path().join("agentsso-0.1.0").exists(), "older deleted");
        assert!(d.path().join("README").exists(), "non-versioned untouched");
        assert!(d.path().join("agentsso").exists(), "stable symlink-name untouched");
    }
}
