//! `agentsso autostart` — manage opt-in autostart at login.
//!
//! Three subcommands:
//! - `agentsso autostart enable` — register the platform-native autostart
//!   artifact (LaunchAgent / systemd user unit / Task Scheduler entry).
//! - `agentsso autostart disable` — remove it. Idempotent.
//! - `agentsso autostart status` — report current state. Always exits 0.
//!
//! See [`crate::lifecycle::autostart`] for the platform implementations,
//! cross-mechanism conflict guardrails (`brew services` on macOS,
//! Story 7.2 install-time `.lnk` on Windows), and the OPT-IN posture.

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::silent_cli_error;
use crate::design::render;
use crate::design::terminal::ColorSupport;
use crate::lifecycle::autostart::{
    self, AutostartError, AutostartStatus, DisableOutcome, EnableOutcome,
};

/// Glyph pair for the step-done line shape.
///
/// **P41 (code review round 4):** Story 7.2's `install.ps1` documented
/// the legacy-`cmd.exe` codepage problem and set
/// `[Console]::OutputEncoding = UTF8` defensively. The daemon CLI runs
/// in many more terminal contexts than the installer (CI logs, SSH
/// sessions through old clients, redirected stdout). Detect color
/// support — when none is reported, the terminal almost certainly
/// can't render arrow + checkmark either, so fall back to ASCII
/// `->` and `[ok]`. Same `ColorSupport::detect()` the rest of the
/// design system uses.
struct StepGlyphs {
    arrow: &'static str,
    check: &'static str,
}

fn step_glyphs() -> StepGlyphs {
    match ColorSupport::detect() {
        ColorSupport::NoColor => StepGlyphs { arrow: "->", check: "[ok]" },
        _ => StepGlyphs { arrow: "\u{2192}", check: "\u{2713}" },
    }
}

/// Arguments for `agentsso autostart`.
#[derive(Args, Debug)]
pub struct AutostartArgs {
    #[command(subcommand)]
    pub command: AutostartCommand,
}

#[derive(Subcommand, Debug)]
pub enum AutostartCommand {
    /// Register the daemon to auto-start at login.
    ///
    /// macOS: writes ~/Library/LaunchAgents/dev.agentsso.daemon.plist.
    /// Linux: writes ~/.config/systemd/user/agentsso.service.
    /// Windows: registers `AgentSSO Daemon` Task Scheduler entry.
    Enable,

    /// Remove the autostart registration. Idempotent.
    Disable,

    /// Report current autostart state. Always exits 0.
    Status,
}

/// Run the `autostart` subcommand. Mirrors the per-subcommand entry-
/// point convention used by `cli::reload::run` etc.
pub async fn run(args: AutostartArgs) -> Result<()> {
    match args.command {
        AutostartCommand::Enable => run_enable(),
        AutostartCommand::Disable => run_disable(),
        AutostartCommand::Status => run_status(),
    }
}

fn run_enable() -> Result<()> {
    let outcome = autostart::enable();
    render_enable_outcome(outcome)
}

/// Shared rendering for an `autostart::enable()` outcome.
///
/// **P12 (code review):** the setup-wizard orchestrator
/// (`cli::setup::run_orchestrator`) used to print autostart errors via
/// raw `eprintln!`, which produced inconsistent UX vs the
/// `agentsso autostart enable` CLI surface (which renders
/// `error_block`s with structured codes). Both call sites now go
/// through this helper for identical error rendering.
///
/// All `Ok` variants emit the same `next: agentsso autostart status`
/// hint (P23 fix — previously only `Registered` did), so the operator
/// always knows where to look next regardless of which arm fired.
pub(crate) fn render_enable_outcome(outcome: Result<EnableOutcome, AutostartError>) -> Result<()> {
    // P30 (code review round 3): match the spec's verbatim
    // `step_done`-styled shape `→ <verb>ing autostart  ✓ <mechanism>`
    // (Story 7.3 AC #1).
    // P41 (code review round 4): glyphs come from `step_glyphs()` so a
    // non-color terminal (legacy Win cmd.exe codepage 437/1252, CI
    // log capture, redirected stdout, OLD SSH clients) gets ASCII
    // `->` + `[ok]` instead of mojibake.
    let g = step_glyphs();
    match outcome {
        Ok(EnableOutcome::Registered { mechanism, artifact_path }) => {
            println!("{} enabling autostart  {} {mechanism}", g.arrow, g.check);
            println!("  artifact: {}", artifact_path.display());
            println!("  next: agentsso autostart status");
            Ok(())
        }
        Ok(EnableOutcome::AlreadyEnabled { artifact_path }) => {
            println!("{} enabling autostart  {} already enabled", g.arrow, g.check);
            println!("  artifact: {}", artifact_path.display());
            println!("  next: agentsso autostart status");
            Ok(())
        }
        Ok(EnableOutcome::MigratedFromStartupShortcut { artifact_path, removed_shortcut }) => {
            // Two step lines: migration first, then enable.
            println!(
                "{} migrating autostart  {} removed Story 7.2 shortcut at {}",
                g.arrow,
                g.check,
                removed_shortcut.display()
            );
            println!("{} enabling autostart  {} task-scheduler", g.arrow, g.check);
            println!("  artifact: {}", artifact_path.display());
            println!("  next: agentsso autostart status");
            Ok(())
        }
        Err(AutostartError::BrewServicesActive) => {
            eprint!(
                "{}",
                render::error_block(
                    "autostart_conflict_brew_services",
                    "Homebrew is already managing agentsso via `brew services start agentsso`. \
                     Running both would double-bind 127.0.0.1:3820.",
                    "brew services stop agentsso && agentsso autostart enable",
                    None,
                )
            );
            Err(silent_cli_error("brew-services conflict on enable"))
        }
        Err(AutostartError::SystemdUnavailable { detail }) => {
            eprint!(
                "{}",
                render::error_block(
                    "autostart_systemd_unavailable",
                    &format!("user-systemd is not available on this host: {detail}"),
                    "fix systemd setup or skip autostart",
                    None,
                )
            );
            Err(silent_cli_error("user-systemd unavailable"))
        }
        Err(AutostartError::UnsupportedPlatform { platform }) => {
            eprint!(
                "{}",
                render::error_block(
                    "autostart_unsupported_platform",
                    &format!("autostart is not implemented on {platform}"),
                    "use the platform's native service manager directly",
                    None,
                )
            );
            Err(silent_cli_error("unsupported platform"))
        }
        Err(AutostartError::ServiceManagerFailed { ref message }) => {
            // P-class addition: surface ServiceManagerFailed with a
            // structured code so the operator can grep for it.
            eprint!(
                "{}",
                render::error_block(
                    "autostart_service_manager_failed",
                    message,
                    "check the platform service manager (launchctl/systemctl/schtasks) directly",
                    None,
                )
            );
            Err(silent_cli_error("service-manager failed during enable"))
        }
        Err(other) => Err(other.into()),
    }
}

fn run_disable() -> Result<()> {
    // P30 + P41: spec AC #2 wording with glyph fallback.
    let g = step_glyphs();
    match autostart::disable() {
        Ok(DisableOutcome::Removed { mechanism, artifact_path }) => {
            println!("{} disabling autostart  {} {mechanism}", g.arrow, g.check);
            println!("  removed: {}", artifact_path.display());
            Ok(())
        }
        Ok(DisableOutcome::RemovedWithShortcut { artifact_path, removed_shortcut }) => {
            println!("{} disabling autostart  {} task-scheduler", g.arrow, g.check);
            println!("  removed: {}", artifact_path.display());
            println!("  removed: {} (leftover Story 7.2 shortcut)", removed_shortcut.display());
            Ok(())
        }
        Ok(DisableOutcome::AlreadyDisabled) => {
            println!("{} disabling autostart  {} already disabled", g.arrow, g.check);
            Ok(())
        }
        Err(AutostartError::UnsupportedPlatform { platform }) => {
            eprint!(
                "{}",
                render::error_block(
                    "autostart_unsupported_platform",
                    &format!("autostart is not implemented on {platform}"),
                    "use the platform's native service manager directly",
                    None,
                )
            );
            Err(silent_cli_error("unsupported platform"))
        }
        Err(other) => Err(other.into()),
    }
}

fn run_status() -> Result<()> {
    // P10 (code review): the subcommand docstring promises "Always exits
    // 0" — honor that contract for ALL error variants, not just
    // UnsupportedPlatform. A status command that exits non-zero on a
    // transient probe failure (e.g., systemd not reachable, broken plist
    // file) breaks scripting that tests for autostart state. Render the
    // unknown state explicitly and exit 0.
    match autostart::status() {
        Ok(AutostartStatus::Disabled) => {
            println!("autostart: disabled");
        }
        Ok(AutostartStatus::Enabled { artifact_path, mechanism, daemon_path }) => {
            println!("autostart: enabled");
            println!("  mechanism:   {mechanism}");
            println!("  artifact:    {}", artifact_path.display());
            println!("  daemon path: {}", daemon_path.display());
        }
        Ok(AutostartStatus::Conflict { detail }) => {
            // Per AC #3: conflict still exits 0 (status is informational,
            // not a check command). Render as a one-line warn so an
            // operator scripting `agentsso autostart status` sees the
            // problem but doesn't break their pipeline.
            println!("autostart: conflict");
            println!("  {detail}");
        }
        Err(AutostartError::UnsupportedPlatform { platform }) => {
            println!("autostart: unsupported on {platform}");
        }
        Err(other) => {
            // Catch-all per AC #3 + P10: never exit non-zero from status.
            println!("autostart: status_unknown");
            println!("  reason: {other}");
        }
    }
    Ok(())
}
