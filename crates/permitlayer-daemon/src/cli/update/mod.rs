//! `agentsso update` — check for updates and apply them in place.
//!
//! Two modes:
//!
//! - **Check-only (default).** `agentsso update` queries
//!   `https://api.github.com/repos/botsdown/permitlayer/releases/latest`
//!   and prints a version-delta summary. No filesystem changes.
//!
//! - **Apply.** `agentsso update --apply` performs the full
//!   orchestrated upgrade: download → minisign verify → extract →
//!   stage `<bin>.new` → stop daemon → atomic swap → run migrations
//!   → re-write autostart artifact (if path drifted) → restart
//!   daemon. State preservation is byte-exact: vault, audit log,
//!   policies, agent registrations, OS-keychain master key are
//!   never touched. Rollback at every failure step restores
//!   `<bin>.old` and respawns the daemon on the old binary.
//!
//! See `_bmad-output/implementation-artifacts/7-5-update-check.md`
//! for the full spec, the strategic decisions documented up-front,
//! and the cross-story fences (Story 7.4 binary-target reuse, Story
//! 7.3 autostart-path-drift detection, Story 7.6 rotate-key
//! coordination).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Args;

use crate::cli::silent_cli_error;
use crate::design::render;
use crate::design::terminal::ColorSupport;
use crate::lifecycle::autostart::{self, AutostartStatus};

mod daemon;
mod diskspace;
mod github;
mod migrations;
mod swap;
mod verify;

use github::ReleaseInfo;
use swap::SwapPaths;

// ── Typed exit-code markers ─────────────────────────────────────────
//
// Mirror Story 7.4 P10+P11's pattern: typed structs (not stringly-
// typed `.context("update_exit_code:N")`) so `main.rs::update_to_
// exit_code` can downcast the chain without colliding with operator-
// visible remediation text.

/// Exit-code 3 marker — resource conflict (brew-services / package-
/// manager-managed). Same semantics as `cli::start`'s exit-3 for a
/// port :3820 conflict and Story 7.4's brew-services refusal.
#[derive(Debug)]
pub(crate) struct UpdateExitCode3;

impl std::fmt::Display for UpdateExitCode3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("update: resource conflict")
    }
}

impl std::error::Error for UpdateExitCode3 {}

/// Exit-code 4 marker — auth / network / signature / disk-space
/// failure. Same semantics class as `permitlayer_oauth::error::OAuthError`'s
/// auth-failure variants surfaced from `cli::connect`.
#[derive(Debug)]
pub(crate) struct UpdateExitCode4;

impl std::fmt::Display for UpdateExitCode4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("update: auth or integrity failure")
    }
}

impl std::error::Error for UpdateExitCode4 {}

/// Exit-code 5 marker — swap, migration, or restart failure (after
/// rollback). Reserved as distinct from auth errors so operators can
/// triage "did the network fail?" vs "did the swap roll back?".
#[derive(Debug)]
pub(crate) struct UpdateExitCode5;

impl std::fmt::Display for UpdateExitCode5 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("update: swap or migration failed (rolled back)")
    }
}

impl std::error::Error for UpdateExitCode5 {}

fn exit3() -> anyhow::Error {
    anyhow::Error::new(UpdateExitCode3).context(crate::cli::SilentCliError)
}

fn exit4() -> anyhow::Error {
    anyhow::Error::new(UpdateExitCode4).context(crate::cli::SilentCliError)
}

fn exit5() -> anyhow::Error {
    anyhow::Error::new(UpdateExitCode5).context(crate::cli::SilentCliError)
}

// ── Glyph helpers (mirror cli::uninstall) ───────────────────────────

struct Glyphs {
    arrow: &'static str,
    check: &'static str,
    warn: &'static str,
}

fn glyphs() -> Glyphs {
    match ColorSupport::detect() {
        ColorSupport::NoColor => Glyphs { arrow: "->", check: "[ok]", warn: "[!]" },
        _ => Glyphs {
            arrow: "\u{2192}", // →
            check: "\u{2713}", // ✓
            warn: "\u{26A0}",  // ⚠
        },
    }
}

// ── CLI args ────────────────────────────────────────────────────────

/// Arguments for `agentsso update`.
///
/// **Review note (P19 / F28 — Auditor):** the spec's AC #8 mentions
/// a `--check-only` flag with `conflicts_with("apply")` "for self-
/// documenting help". That construction doesn't model cleanly in
/// clap (a flag that conflicts with the *absence* of another flag
/// isn't expressible), and check-only is already the default
/// behavior when `--apply` is absent. Help text on `--apply`
/// documents the inversion explicitly.
#[derive(Args, Debug, Default, Clone)]
pub struct UpdateArgs {
    /// Download, verify, and install the latest release. Daemon is
    /// restarted; vault, audit log, policies, agent registrations,
    /// and the OS-keychain master key are preserved. Without this
    /// flag, `agentsso update` is CHECK-ONLY — it reports the
    /// version delta but does NOT download or modify any binary.
    #[arg(long)]
    pub apply: bool,

    /// Skip the interactive confirmation prompt. REQUIRED for
    /// `--apply` from a non-tty context (CI, scripts, pipes).
    #[arg(long)]
    pub yes: bool,

    /// Treat the call as non-interactive: implies `--yes` is
    /// required for `--apply`. Mirrors `cli::uninstall`'s
    /// `--non-interactive` flag.
    #[arg(long)]
    pub non_interactive: bool,
}

// ── Entry point ─────────────────────────────────────────────────────

/// Run the `update` subcommand.
pub async fn run(args: UpdateArgs) -> Result<()> {
    if args.apply { run_apply(args).await } else { run_check_only().await }
}

// ── Check-only flow ─────────────────────────────────────────────────

async fn run_check_only() -> Result<()> {
    let _guards =
        crate::telemetry::init_tracing("info", None, 30).context("tracing init failed")?;

    let current_version = env!("CARGO_PKG_VERSION");

    // Resolve binary target up front. If package-manager-managed,
    // refuse with exit 3 — `agentsso update` (even check-only)
    // should redirect to the package manager so users don't form
    // muscle memory of running our update on a brew install.
    let binary_target = resolve_binary_target_or_print_error()?;
    if let crate::cli::uninstall::binary::BinaryTarget::ManagedByPackageManager {
        manager,
        path,
        remediation,
    } = &binary_target
    {
        eprint!(
            "{}",
            render::error_block(
                "update_managed_externally",
                &format!(
                    "agentsso at {} is managed by {manager}; use that package manager's \
                     upgrade command",
                    path.display()
                ),
                remediation,
                None,
            )
        );
        return Err(exit3());
    }

    // Best-effort audit emission — we have a home dir and an audit
    // store available even when the daemon isn't running.
    let home = super::agentsso_home()?;
    let audit_store = build_audit_store(&home).await.ok();
    emit_check_requested(audit_store.as_deref(), current_version, false).await;

    let release = match github::fetch_latest_release(current_version).await {
        Ok(r) => r,
        Err(e) => {
            eprint!(
                "{}",
                render::error_block(
                    "update_check_failed",
                    &format!("could not query GitHub Releases API: {e}"),
                    "check https://github.com/botsdown/permitlayer/releases manually",
                    None,
                )
            );
            return Err(exit4());
        }
    };

    let latest_version = release.version().to_owned();
    let ord = github::compare_versions(current_version, &latest_version);
    let update_available = matches!(ord, std::cmp::Ordering::Less);
    emit_check_result(
        audit_store.as_deref(),
        current_version,
        &latest_version,
        update_available,
        release.published_at.as_deref(),
    )
    .await;

    let g = glyphs();
    if !update_available {
        // Already at latest (or somehow ahead).
        println!(
            "{} already on the latest release  {} {current_version} (published {})",
            g.arrow,
            g.check,
            release.published_at.as_deref().unwrap_or("unknown")
        );
        return Ok(());
    }

    // Print the version delta + truncated release notes.
    print_check_summary(&release, current_version, &latest_version);
    Ok(())
}

fn print_check_summary(release: &ReleaseInfo, current: &str, latest: &str) {
    let g = glyphs();
    println!();
    println!("{} update available  {} {current} → {latest}", g.arrow, g.check);
    if let Some(name) = &release.name {
        println!("    {name}");
    }
    if let Some(published) = &release.published_at {
        println!("    published: {published}");
    }
    if let Some(body) = &release.body {
        println!();
        for line in body.lines().take(15) {
            println!("    {line}");
        }
        if body.lines().count() > 15 {
            println!("    …");
        }
    }
    println!();
    println!("{} run 'agentsso update --apply' to install", g.arrow);
}

// ── Apply flow ──────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)] // The orchestrator is intentionally linear.
async fn run_apply(args: UpdateArgs) -> Result<()> {
    let _guards =
        crate::telemetry::init_tracing("info", None, 30).context("tracing init failed")?;

    let current_version = env!("CARGO_PKG_VERSION").to_owned();
    let home = super::agentsso_home()?;

    // Resolve binary target. Same refuse-with-exit-3 path as check-
    // only when package-manager-managed.
    let binary_target = resolve_binary_target_or_print_error()?;
    let install_binary_path = match &binary_target {
        crate::cli::uninstall::binary::BinaryTarget::ManagedByPackageManager {
            manager,
            path,
            remediation,
        } => {
            eprint!(
                "{}",
                render::error_block(
                    "update_managed_externally",
                    &format!(
                        "agentsso at {} is managed by {manager}; use that package manager's \
                         upgrade command",
                        path.display()
                    ),
                    remediation,
                    None,
                )
            );
            return Err(exit3());
        }
        crate::cli::uninstall::binary::BinaryTarget::Owned(p) => p.clone(),
    };

    let audit_store = build_audit_store(&home).await.ok();
    emit_check_requested(audit_store.as_deref(), &current_version, true).await;

    // ── Brew-services pre-flight (macOS) ────────────────────────────
    #[cfg(target_os = "macos")]
    if brew_services_managing_agentsso().await {
        eprint!(
            "{}",
            render::error_block(
                "update_brew_services_active",
                "agentsso is being managed by `brew services`. Running `agentsso update --apply` \
                 under this state would conflict with Homebrew's plist at \
                 ~/Library/LaunchAgents/homebrew.mxcl.agentsso.plist.",
                "brew services stop agentsso && agentsso update --apply",
                None,
            )
        );
        return Err(exit3());
    }

    // ── Non-tty / --yes guard ──────────────────────────────────────
    let stdout_is_tty = console::Term::stdout().is_term();
    let interactive = !args.non_interactive && stdout_is_tty;
    if !args.yes && !interactive {
        eprint!(
            "{}",
            render::error_block(
                "update_requires_confirmation",
                "`agentsso update --apply` is destructive (replaces the running binary) \
                 and requires interactive confirmation OR an explicit `--yes` flag",
                "agentsso update --apply --yes",
                None,
            )
        );
        return Err(silent_cli_error("non-interactive update without --yes"));
    }

    // ── Fetch latest release info ───────────────────────────────────
    let release = match github::fetch_latest_release(&current_version).await {
        Ok(r) => r,
        Err(e) => {
            eprint!(
                "{}",
                render::error_block(
                    "update_check_failed",
                    &format!("could not query GitHub Releases API: {e}"),
                    "check https://github.com/botsdown/permitlayer/releases manually",
                    None,
                )
            );
            return Err(exit4());
        }
    };

    let latest_version = release.version().to_owned();
    let ord = github::compare_versions(&current_version, &latest_version);
    let update_available = matches!(ord, std::cmp::Ordering::Less);
    emit_check_result(
        audit_store.as_deref(),
        &current_version,
        &latest_version,
        update_available,
        release.published_at.as_deref(),
    )
    .await;

    if !update_available {
        let g = glyphs();
        println!("{} already up-to-date  {} {current_version} — nothing to do", g.arrow, g.check);
        return Ok(());
    }

    // ── Asset selection ─────────────────────────────────────────────
    let target_triple = current_target_triple();
    let primary_asset = release.asset_for_target(&target_triple).ok_or_else(|| {
        eprint!(
            "{}",
            render::error_block(
                "update_no_asset_for_target",
                &format!(
                    "release {} did not include a binary for target {target_triple}",
                    release.tag_name
                ),
                "check the release page manually or wait for a republish",
                None,
            )
        );
        exit4()
    })?;
    let signature_asset = release.minisig_for(primary_asset).ok_or_else(|| {
        eprint!(
            "{}",
            render::error_block(
                "update_signature_missing",
                &format!(
                    "release {} did not include a `.minisig` for asset {} — refusing to apply",
                    release.tag_name, primary_asset.name
                ),
                "wait for a re-published release with a minisig sidecar",
                None,
            )
        );
        exit4()
    })?;

    // ── Asset-size sanity check ─────────────────────────────────────
    //
    // **Review patch P17 (F32 — Edge):** reject obviously-bogus asset
    // sizes before they defeat the disk-space pre-flight (size: 0
    // would let `need = size * 4 = 0` pass against any free_bytes).
    // 1MB minimum is well below any plausible real `agentsso` binary
    // (the 0.2.1 release is several megabytes compressed).
    const MIN_PLAUSIBLE_ASSET_SIZE: u64 = 1024 * 1024;
    if primary_asset.size < MIN_PLAUSIBLE_ASSET_SIZE {
        eprint!(
            "{}",
            render::error_block(
                "update_asset_size_implausible",
                &format!(
                    "release {} reports asset {} as {} bytes — below the {MIN_PLAUSIBLE_ASSET_SIZE} \
                     byte minimum; refusing to apply (release metadata may be corrupt)",
                    release.tag_name, primary_asset.name, primary_asset.size
                ),
                "check the GitHub release page for asset integrity",
                None,
            )
        );
        return Err(exit4());
    }

    // ── Disk-space pre-flight ───────────────────────────────────────
    let install_dir =
        install_binary_path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("/"));
    if let Some(free_bytes) = diskspace::available_disk_space(&install_dir) {
        let need = primary_asset.size.saturating_mul(4);
        if free_bytes < need {
            eprint!(
                "{}",
                render::error_block(
                    "update_insufficient_disk",
                    &format!(
                        "install dir at {} has {free_bytes} bytes free; need at least {need} \
                         (4× the {} byte download size for staging + backup + slack)",
                        install_dir.display(),
                        primary_asset.size
                    ),
                    "free disk space and re-run `agentsso update --apply`",
                    None,
                )
            );
            return Err(exit4());
        }
    } else {
        tracing::warn!(
            target: "update",
            "could not pre-flight disk space — continuing anyway; swap will fail loudly if disk is full"
        );
    }

    // ── Confirm prompt ──────────────────────────────────────────────
    if !args.yes {
        let manifest = build_apply_manifest(
            &current_version,
            &latest_version,
            &install_binary_path,
            release.published_at.as_deref(),
        );
        println!("{manifest}");

        let join = tokio::task::spawn_blocking(|| {
            dialoguer::Confirm::new().with_prompt("Continue?").default(false).interact()
        })
        .await
        .map_err(|e| anyhow::anyhow!("update confirm join failed: {e}"))?;
        let g = glyphs();
        let confirmed = match join {
            Ok(answer) => answer,
            Err(_) => {
                println!("{} update cancelled  {} prompt aborted", g.arrow, g.check);
                return Ok(());
            }
        };
        if !confirmed {
            println!("{} update cancelled  {} nothing changed", g.arrow, g.check);
            return Ok(());
        }
    }

    let g = glyphs();
    let elapsed_start = Instant::now();

    // From this point on, we audit-emit on success/failure.
    emit_apply_started(
        audit_store.as_deref(),
        &current_version,
        &latest_version,
        &primary_asset.browser_download_url,
    )
    .await;

    // ── Step 5: Download into tempdir ──────────────────────────────
    let tempdir = tempfile::Builder::new().prefix("agentsso-update-").tempdir().map_err(|e| {
        eprint!(
            "{}",
            render::error_block(
                "update_tempdir_failed",
                &format!("could not create tempdir for download: {e}"),
                "check disk space and permissions on $TMPDIR",
                None,
            )
        );
        exit5()
    })?;

    let archive_path = tempdir.path().join(&primary_asset.name);
    let signature_path = tempdir.path().join(&signature_asset.name);

    println!("{} downloading {}", g.arrow, primary_asset.name);
    if let Err(e) = verify::download(&primary_asset.browser_download_url, &archive_path).await {
        eprint!(
            "{}",
            render::error_block(
                "update_download_failed",
                &format!("could not download {}: {e}", primary_asset.browser_download_url),
                "check network connectivity and re-run `agentsso update --apply`",
                None,
            )
        );
        return Err(exit4());
    }

    println!("{} downloading {}", g.arrow, signature_asset.name);
    if let Err(e) = verify::download(&signature_asset.browser_download_url, &signature_path).await {
        eprint!(
            "{}",
            render::error_block(
                "update_signature_download_failed",
                &format!(
                    "could not download signature {}: {e}",
                    signature_asset.browser_download_url
                ),
                "check network connectivity and re-run",
                None,
            )
        );
        return Err(exit4());
    }

    // ── Step 6: Verify signature ───────────────────────────────────
    let info = match verify::verify_minisign(&archive_path, &signature_path) {
        Ok(info) => info,
        Err(e) => {
            eprint!(
                "{}",
                render::error_block(
                    "update_signature_invalid",
                    &format!("minisign verification failed for {}: {e}", primary_asset.name),
                    "the downloaded artifact may be corrupted or tampered with — \
                     do NOT proceed; report at https://github.com/botsdown/permitlayer/issues",
                    None,
                )
            );
            return Err(exit4());
        }
    };
    println!(
        "{} verified signature  {} keyid {} ({})",
        g.arrow, g.check, info.keyid_hex, info.algorithm
    );
    emit_signature_verified(audit_store.as_deref(), &info).await;

    // ── Step 7: Extract archive ────────────────────────────────────
    let extract_dir = tempdir.path().join("extracted");
    std::fs::create_dir_all(&extract_dir).context("create extract dir failed")?;
    let extracted_binary = match verify::extract_targz(&archive_path, &extract_dir) {
        Ok(p) => p,
        Err(e) => {
            eprint!(
                "{}",
                render::error_block(
                    "update_archive_unsafe",
                    &format!("archive extraction failed: {e}"),
                    "report at https://github.com/botsdown/permitlayer/issues",
                    None,
                )
            );
            return Err(exit4());
        }
    };
    println!("{} extracted archive  {} {}", g.arrow, g.check, extracted_binary.display());

    // ── Step 8: Stage `.new` next to current binary ────────────────
    let swap_paths = SwapPaths::from_current(install_binary_path.clone());
    if let Err(e) = swap::stage_new_binary(&extracted_binary, &swap_paths) {
        eprint!(
            "{}",
            render::error_block(
                "update_stage_failed",
                &format!("could not stage new binary at {}: {e}", swap_paths.new.display()),
                "check that the install dir is writable and has free space",
                None,
            )
        );
        return Err(exit5());
    }
    println!("{} staged new binary  {} {}", g.arrow, g.check, swap_paths.new.display());

    // ── Step 9: Stop the daemon ────────────────────────────────────
    let stop_outcome = crate::cli::uninstall::stop_daemon_if_running(&home).await;
    print_step_outcome(&g, &stop_outcome);
    // We continue even on stop-warn — a stuck daemon is precisely
    // what an update-to-fix targets. If the swap fails on Windows
    // because of a still-running daemon, we'll catch that next.

    // ── Step 10: Atomic swap ───────────────────────────────────────
    if let Err(e) = swap::atomic_swap(&swap_paths) {
        eprint!(
            "{}",
            render::error_block(
                "update_swap_failed",
                &format!("atomic swap failed: {e}"),
                "the original binary is still in place; re-run `agentsso update --apply` \
                 once the underlying issue is fixed",
                None,
            )
        );
        // No rollback rename needed — atomic_swap already inverses
        // step A on step B failure. But the daemon may need to be
        // restarted from the original binary.
        let respawn = respawn_old_binary(&swap_paths, &home).await;
        emit_rolled_back(
            audit_store.as_deref(),
            &current_version,
            &latest_version,
            10,
            &format!("atomic_swap failed: {e}"),
            &respawn,
        )
        .await;
        return Err(exit5());
    }
    println!("{} swapped binary  {} {}", g.arrow, g.check, swap_paths.current.display());

    // ── Step 11: Run migrations ────────────────────────────────────
    let migration_outcome =
        match migrations::apply_pending(&home, &current_version, &latest_version).await {
            Ok(o) => o,
            Err(e) => {
                eprint!(
                    "{}",
                    render::error_block(
                        "update_migration_failed",
                        &format!("schema migration failed: {e}"),
                        "rolled back to previous binary; report the migration error at \
                         https://github.com/botsdown/permitlayer/issues",
                        None,
                    )
                );
                let _ = swap::rollback_rename(&swap_paths);
                let respawn = respawn_old_binary(&swap_paths, &home).await;
                emit_rolled_back(
                    audit_store.as_deref(),
                    &current_version,
                    &latest_version,
                    11,
                    &format!("migration failed: {e}"),
                    &respawn,
                )
                .await;
                return Err(exit5());
            }
        };
    println!(
        "{} migrations checked  {} {} migration(s) applied",
        g.arrow,
        g.check,
        migration_outcome.count()
    );
    emit_migrations_checked(
        audit_store.as_deref(),
        &current_version,
        &latest_version,
        &migration_outcome,
    )
    .await;

    // ── Step 12: Re-write autostart artifact if path drifted ───────
    // **P54 (M4):** `daemon_path` is `Option<PathBuf>` — only attempt
    // drift detection when we actually parsed a path. `None` means
    // the artifact was hand-edited or corrupt; we leave that for the
    // operator to fix rather than blowing it away here.
    if let Ok(AutostartStatus::Enabled { daemon_path: Some(daemon_path), .. }) = autostart::status()
        && daemon_path != swap_paths.current
    {
        tracing::info!(
            target: "update",
            old = %daemon_path.display(),
            new = %swap_paths.current.display(),
            "autostart path drift detected — regenerating artifact",
        );
        // Disable + re-enable. Idempotent failure is logged-and-
        // continue — we don't fail the whole update for an
        // autostart re-write failure, but we DO emit a structured
        // audit event so the operator can spot it without grepping
        // the operational log (P16 / review F20 — Blind + Edge).
        let _ = autostart::disable();
        if let Err(e) = autostart::enable() {
            tracing::warn!(
                target: "update",
                error = %e,
                "autostart re-write failed; the update is still valid but autostart \
                 may now point at a stale path"
            );
            emit_autostart_rewrite_failed(
                audit_store.as_deref(),
                &daemon_path,
                &swap_paths.current,
                &e.to_string(),
            )
            .await;
        }
    }

    // ── Step 13: Restart the daemon ────────────────────────────────
    let restart_outcome = match daemon::restart_daemon(&swap_paths.current, &home).await {
        Ok(outcome) => outcome,
        Err(e) => {
            eprint!(
                "{}",
                render::error_block(
                    "update_restart_failed",
                    &format!("could not spawn daemon at {}: {e}", swap_paths.current.display()),
                    "rolled back to previous binary",
                    None,
                )
            );
            let _ = swap::rollback_rename(&swap_paths);
            let respawn = respawn_old_binary(&swap_paths, &home).await;
            emit_rolled_back(
                audit_store.as_deref(),
                &current_version,
                &latest_version,
                13,
                &format!("restart spawn failed: {e}"),
                &respawn,
            )
            .await;
            return Err(exit5());
        }
    };

    if let daemon::RestartOutcome::TimedOut { reason, elapsed_ms } = &restart_outcome {
        eprint!(
            "{}",
            render::error_block(
                "update_restart_timed_out",
                &format!(
                    "daemon at {} did not come up within {elapsed_ms}ms: {reason}",
                    swap_paths.current.display()
                ),
                "rolled back to previous binary; check ~/.agentsso/logs/ for daemon startup errors",
                None,
            )
        );
        let _ = swap::rollback_rename(&swap_paths);
        let respawn = respawn_old_binary(&swap_paths, &home).await;
        emit_rolled_back(
            audit_store.as_deref(),
            &current_version,
            &latest_version,
            13,
            &format!("restart timed out: {reason}"),
            &respawn,
        )
        .await;
        return Err(exit5());
    }

    // ── Step 14: Cleanup + closing line ────────────────────────────
    swap::cleanup_old_binary(&swap_paths);
    // P8 (review F31 — Blind): use `try_into` instead of `as u64`
    // truncation cast on `Duration::as_millis()` (returns u128).
    // Saturate at u64::MAX rather than silently truncate. Practical
    // impact is nil (an update taking >584M years would be the
    // trigger), but the discipline matters.
    let elapsed_ms = u64::try_from(elapsed_start.elapsed().as_millis()).unwrap_or(u64::MAX);
    println!(
        "{} updated {current_version} → {latest_version}  {} daemon restarted in {elapsed_ms}ms",
        g.arrow, g.check
    );
    emit_completed(
        audit_store.as_deref(),
        &current_version,
        &latest_version,
        elapsed_ms,
        migration_outcome.count(),
    )
    .await;

    Ok(())
}

/// Re-spawn the daemon from `swap_paths.current` after a rollback.
/// Outcome surfaced by `respawn_old_binary` so the rollback audit
/// event accurately reflects whether the daemon actually came back
/// up (P7 / review F8 — Edge + Auditor).
#[derive(Debug, Clone)]
enum RespawnOutcome {
    /// Respawn succeeded — old daemon is running on the rolled-back
    /// binary.
    Succeeded,
    /// Respawn failed — operator must intervene (binary missing,
    /// startup timed out, or the spawn itself errored).
    Failed { reason: String },
}

impl RespawnOutcome {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed { .. } => "failed",
        }
    }
}

/// Logged-and-best-effort: if respawn fails the operator sees the
/// rollback error_block + the respawn warning in the logs AND the
/// `update-rolled-back` audit event carries `respawn_outcome` so a
/// future incident triage doesn't have to grep the operational log.
async fn respawn_old_binary(swap_paths: &SwapPaths, home: &Path) -> RespawnOutcome {
    if !swap_paths.current.exists() {
        let reason = format!(
            "binary at {} does not exist — operator must re-install",
            swap_paths.current.display()
        );
        tracing::error!(target: "update", path = %swap_paths.current.display(), "rollback respawn: {reason}");
        return RespawnOutcome::Failed { reason };
    }
    match daemon::restart_daemon(&swap_paths.current, home).await {
        Ok(daemon::RestartOutcome::Running { pid, elapsed_ms }) => {
            tracing::info!(
                target: "update",
                pid,
                elapsed_ms,
                "rollback respawn succeeded"
            );
            RespawnOutcome::Succeeded
        }
        Ok(daemon::RestartOutcome::TimedOut { reason, elapsed_ms }) => {
            tracing::error!(
                target: "update",
                reason = %reason,
                elapsed_ms,
                "rollback respawn timed out — daemon is not running on either binary"
            );
            RespawnOutcome::Failed { reason: format!("respawn timed out: {reason}") }
        }
        Err(e) => {
            let reason = format!("spawn error: {e}");
            tracing::error!(
                target: "update",
                error = %e,
                "rollback respawn FAILED — daemon is not running on either binary"
            );
            RespawnOutcome::Failed { reason }
        }
    }
}

// ── Apply manifest ──────────────────────────────────────────────────

fn build_apply_manifest(
    current: &str,
    latest: &str,
    install_path: &Path,
    published_at: Option<&str>,
) -> String {
    let mut out = String::new();
    out.push('\n');
    out.push_str(&format!("Update agentsso from {current} to {latest}?\n\n"));
    out.push_str(&format!(
        "  • binary at {} will be replaced atomically\n",
        install_path.display()
    ));
    out.push_str("  • the daemon will stop briefly (~5s) and restart on the new binary\n");
    out.push_str(
        "  • vault, audit log, policies, agent registrations, and autostart configuration\n",
    );
    out.push_str("    will be preserved\n");
    if let Some(pub_at) = published_at {
        out.push_str(&format!("  • release published: {pub_at}\n"));
    }
    out
}

// ── Helpers ─────────────────────────────────────────────────────────

fn resolve_binary_target_or_print_error() -> Result<crate::cli::uninstall::binary::BinaryTarget> {
    crate::cli::uninstall::binary::resolve_binary_target().map_err(|e| {
        eprint!(
            "{}",
            render::error_block(
                "update_binary_path_unresolved",
                &format!("could not resolve current binary path: {e}"),
                "check filesystem permissions on /proc/self/exe (Linux) or contact support",
                None,
            )
        );
        exit5()
    })
}

/// Print one teardown-style step outcome line. Reuses the
/// `StepOutcome` shape from `cli::uninstall` for visual consistency
/// with the uninstall flow.
fn print_step_outcome(g: &Glyphs, outcome: &crate::cli::uninstall::StepOutcome) {
    use crate::cli::uninstall::StepOutcome;
    match outcome {
        StepOutcome::Done { step, detail } => {
            println!("{} {step}  {} {detail}", g.arrow, g.check);
        }
        StepOutcome::Skipped { step, reason } => {
            println!("{} {step}  {} {reason}", g.arrow, g.warn);
        }
        StepOutcome::Warned { step, reason, remediation } => {
            eprintln!("{} {step}  {} {reason}", g.arrow, g.warn);
            eprintln!("    remediation: {remediation}");
        }
    }
}

/// Detect the running binary's target triple. Used to pick the
/// right release asset.
fn current_target_triple() -> String {
    // Compose from `cfg` per the values `dist` uses in artifact
    // names: e.g., `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`.
    let arch = std::env::consts::ARCH; // "x86_64" / "aarch64"
    let os = std::env::consts::OS; // "macos" / "linux" / "windows"
    match os {
        "macos" => format!("{arch}-apple-darwin"),
        "linux" => format!("{arch}-unknown-linux-gnu"),
        "windows" => format!("{arch}-pc-windows-msvc"),
        other => format!("{arch}-unknown-{other}"),
    }
}

// ── Brew-services pre-flight ────────────────────────────────────────

#[cfg(target_os = "macos")]
async fn brew_services_managing_agentsso() -> bool {
    use std::time::Duration;

    // **Review patch P21 (F23 — Blind):** async + `tokio::process::Command`
    // with `tokio::time::timeout` instead of std::Command + thread::sleep
    // 100ms poll loop. The previous shape blocked the tokio runtime worker
    // for up to 30s on a slow `brew services list` call (Homebrew startup
    // is occasionally slow on macOS). Now the brew call yields properly.
    let cmd = tokio::process::Command::new("brew")
        .args(["services", "list", "--json"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    let output = match tokio::time::timeout(Duration::from_secs(30), cmd).await {
        Ok(Ok(o)) => o,
        Ok(Err(_)) => return false, // brew not on PATH — proceed.
        Err(_) => return false,     // brew hung past 30s — proceed.
    };
    if !output.status.success() {
        return false;
    }
    crate::lifecycle::autostart::macos::parse_brew_services_active(&output.stdout)
}

// ── Audit emission ──────────────────────────────────────────────────
//
// Audit events use the existing v2 schema with new `event_type`
// strings and structured `extra` fields. No schema bump required:
// `audit/event.rs:30` doc-comment commits to schema_version: u32
// forward-compat for additive fields.

async fn build_audit_store(home: &Path) -> Result<Arc<dyn permitlayer_core::store::AuditStore>> {
    use permitlayer_core::scrub::{ScrubEngine, builtin_rules};
    use permitlayer_core::store::fs::AuditFsStore;

    let scrub_engine = Arc::new(
        ScrubEngine::new(builtin_rules().to_vec())
            .map_err(|e| anyhow::anyhow!("scrub engine creation failed: {e}"))?,
    );
    let audit_dir = home.join("audit");
    let store = AuditFsStore::new(audit_dir, 100_000_000, scrub_engine)
        .map_err(|e| anyhow::anyhow!("audit store creation failed: {e}"))?;
    Ok(Arc::new(store))
}

fn make_event(
    event_type: &str,
    outcome: &str,
    extra: serde_json::Value,
) -> permitlayer_core::audit::event::AuditEvent {
    let mut event = permitlayer_core::audit::event::AuditEvent::new(
        "cli".into(),
        "update".into(),
        String::new(),
        "update".into(),
        outcome.into(),
        event_type.into(),
    );
    event.extra = extra;
    event
}

async fn emit(
    store: Option<&dyn permitlayer_core::store::AuditStore>,
    event: permitlayer_core::audit::event::AuditEvent,
) {
    if let Some(s) = store
        && let Err(e) = s.append(event).await
    {
        tracing::warn!(target: "update", error = %e, "audit emit failed (best-effort)");
    }
}

async fn emit_check_requested(
    store: Option<&dyn permitlayer_core::store::AuditStore>,
    current_version: &str,
    via_apply: bool,
) {
    // **Review patch P6 (F7 — Auditor):** field name matches spec
    // AC #7 verbatim — `requested_channel`, not `channel`. A future
    // auto-update story will set `requested_channel: "auto"` to
    // differentiate. The shorter `channel` name was a drift from
    // the spec; downstream `audit export` consumers depend on the
    // exact field name.
    let extra = serde_json::json!({
        "current_version": current_version,
        "requested_channel": "manual",
        "via_apply": via_apply,
    });
    emit(store, make_event("update-check-requested", "ok", extra)).await;
}

async fn emit_check_result(
    store: Option<&dyn permitlayer_core::store::AuditStore>,
    current_version: &str,
    latest_version: &str,
    update_available: bool,
    published_at: Option<&str>,
) {
    // P6 (review F7): spec AC #7 says `release_published_at`, not
    // the shorter `published_at`. Renamed for downstream-consumer
    // contract.
    let extra = serde_json::json!({
        "current_version": current_version,
        "latest_version": latest_version,
        "update_available": update_available,
        "release_published_at": published_at,
    });
    emit(store, make_event("update-check-result", "ok", extra)).await;
}

async fn emit_apply_started(
    store: Option<&dyn permitlayer_core::store::AuditStore>,
    from_version: &str,
    to_version: &str,
    download_url: &str,
) {
    let extra = serde_json::json!({
        "from_version": from_version,
        "to_version": to_version,
        "download_url": download_url,
    });
    emit(store, make_event("update-apply-started", "ok", extra)).await;
}

async fn emit_signature_verified(
    store: Option<&dyn permitlayer_core::store::AuditStore>,
    info: &verify::MinisigInfo,
) {
    let extra = serde_json::json!({
        "keyid": info.keyid_hex,
        "algorithm": info.algorithm,
    });
    emit(store, make_event("update-signature-verified", "ok", extra)).await;
}

async fn emit_migrations_checked(
    store: Option<&dyn permitlayer_core::store::AuditStore>,
    from_version: &str,
    to_version: &str,
    outcome: &migrations::MigrationOutcome,
) {
    let extra = serde_json::json!({
        "from_version": from_version,
        "to_version": to_version,
        "migrations_applied": outcome.count(),
        "migration_ids": outcome.ids(),
    });
    emit(store, make_event("update-migrations-checked", "ok", extra)).await;
}

async fn emit_completed(
    store: Option<&dyn permitlayer_core::store::AuditStore>,
    from_version: &str,
    to_version: &str,
    elapsed_ms: u64,
    migrations_applied: u32,
) {
    let extra = serde_json::json!({
        "from_version": from_version,
        "to_version": to_version,
        "elapsed_ms": elapsed_ms,
        "migrations_applied": migrations_applied,
    });
    emit(store, make_event("update-completed", "ok", extra)).await;
}

async fn emit_autostart_rewrite_failed(
    store: Option<&dyn permitlayer_core::store::AuditStore>,
    old_path: &Path,
    new_path: &Path,
    failure_reason: &str,
) {
    // P16 (review F20 — Blind + Edge): autostart re-write failure
    // surfaced as a structured audit event so an operator running
    // `agentsso audit` after a successful update can spot a stale
    // autostart artifact without grepping `~/.agentsso/logs/`.
    let extra = serde_json::json!({
        "old_daemon_path": old_path.display().to_string(),
        "new_daemon_path": new_path.display().to_string(),
        "failure_reason": failure_reason,
    });
    emit(store, make_event("update-autostart-rewrite-failed", "error", extra)).await;
}

async fn emit_rolled_back(
    store: Option<&dyn permitlayer_core::store::AuditStore>,
    from_version: &str,
    to_version: &str,
    failure_step: u8,
    failure_reason: &str,
    respawn_outcome: &RespawnOutcome,
) {
    // P7 (review F8 — Edge + Auditor): include the respawn_outcome
    // so the audit event accurately reflects whether the daemon
    // came back up after rollback. Previously, `update-rolled-back`
    // fired BEFORE respawn was attempted; on a respawn failure the
    // log showed "rolled back" with no record that the daemon was
    // actually dead on both binaries.
    let respawn_failure_reason = match respawn_outcome {
        RespawnOutcome::Succeeded => None,
        RespawnOutcome::Failed { reason } => Some(reason.as_str()),
    };
    let extra = serde_json::json!({
        "from_version": from_version,
        "to_version": to_version,
        "failure_step": failure_step,
        "failure_reason": failure_reason,
        "respawn_outcome": respawn_outcome.as_str(),
        "respawn_failure_reason": respawn_failure_reason,
    });
    emit(store, make_event("update-rolled-back", "error", extra)).await;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn current_target_triple_resolves_for_host() {
        let triple = current_target_triple();
        // We can't assert a specific value (varies by host), but
        // we can lock the shape: arch-vendor-os-env (4 dash-separated
        // segments OR 3 for macos's `apple-darwin` shape).
        assert!(triple.contains('-'));
        assert!(triple.starts_with(std::env::consts::ARCH));
    }

    #[test]
    fn typed_exit_markers_implement_error() {
        // Simple roundtrip test — these markers are critical to exit-
        // code routing in main.rs, so lock in their conformance.
        let e: Box<dyn std::error::Error> = Box::new(UpdateExitCode3);
        assert!(e.to_string().contains("resource conflict"));
        let e: Box<dyn std::error::Error> = Box::new(UpdateExitCode4);
        assert!(e.to_string().contains("auth"));
        let e: Box<dyn std::error::Error> = Box::new(UpdateExitCode5);
        assert!(e.to_string().contains("rolled back"));
    }

    #[test]
    fn build_apply_manifest_includes_version_delta() {
        let manifest = build_apply_manifest(
            "0.3.0",
            "0.4.0",
            Path::new("/usr/local/bin/agentsso"),
            Some("2026-04-26T12:00:00Z"),
        );
        assert!(manifest.contains("0.3.0"));
        assert!(manifest.contains("0.4.0"));
        assert!(manifest.contains("/usr/local/bin/agentsso"));
        assert!(manifest.contains("2026-04-26"));
    }

    #[test]
    fn build_apply_manifest_omits_published_at_when_none() {
        let manifest =
            build_apply_manifest("0.3.0", "0.4.0", Path::new("/usr/local/bin/agentsso"), None);
        assert!(!manifest.contains("published"));
    }
}
