//! The `agentsso` binary — permitlayer's daemon, CLI, and HTTP server.
//!
//! This is the only crate in the workspace that uses `anyhow`. Library
//! crates use concrete `thiserror` error enums.

#![forbid(unsafe_code)]

mod approval;
mod cli;
mod config;
mod design;
mod lifecycle;
mod server;
mod telemetry;

use clap::Parser;
use std::process::ExitCode;

/// permitlayer daemon and CLI.
#[derive(Parser)]
#[command(name = "agentsso", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Start the permitlayer daemon
    Start(cli::start::StartArgs),
    /// Stop the running daemon
    Stop,
    /// Show daemon status
    Status(cli::status::StatusArgs),
    /// Reload configuration (sends SIGHUP)
    Reload,
    /// Set up OAuth for an upstream service (e.g., gmail)
    Setup(cli::setup::SetupArgs),
    /// Manage stored credentials
    Credentials(cli::credentials::CredentialsArgs),
    /// Manage user-facing configuration
    Config(cli::config::ConfigArgs),
    /// Tail the audit log live (historical query ships in Story 5.2)
    Audit(cli::audit::AuditArgs),
    /// Stream the operational log (FR81). Use --verbose/--debug for
    /// verbosity, --follow for live tail. Distinct from `audit` —
    /// operational logs are daemon lifecycle + diagnostic tracing.
    Logs(cli::logs::LogsArgs),
    /// Inspect built-in scrub rules
    Scrub(cli::scrub::ScrubArgs),
    /// Activate the kill switch — blocks all requests with HTTP 403 (FR61)
    Kill(cli::kill::KillArgs),
    /// Deactivate the kill switch and resume normal operation (FR63)
    Resume(cli::resume::ResumeArgs),
    /// Manage agent identities (register/list/remove) — FR47
    Agent(cli::agent::AgentArgs),
    /// List plugin connectors loaded by the daemon (built-in + user-installed) — FR40
    Connectors(cli::connectors::ConnectorsArgs),
    /// Manage opt-in autostart at login (FR7) — enable/disable/status
    Autostart(cli::autostart::AutostartArgs),
    /// Uninstall permitlayer cleanly: stop daemon, remove keychain
    /// entry, autostart, data dir, and binary (FR8). Destructive —
    /// requires interactive confirmation OR --yes.
    Uninstall(cli::uninstall::UninstallArgs),
    /// Check for updates (default) or apply them in place
    /// (`--apply`). Preserves vault, audit log, policies, agent
    /// registrations, and the OS-keychain master key. FR73-76.
    Update(cli::update::UpdateArgs),
    /// Rotate the master encryption key in your OS keychain (FR17).
    /// Re-encrypts every credential under a fresh key; OAuth refresh
    /// tokens persist (no re-consent needed). Agent bearer tokens
    /// are invalidated — agents must re-run `agentsso agent register`.
    /// Destructive — requires interactive confirmation OR --yes.
    /// Daemon must be stopped first (`agentsso stop`).
    RotateKey(cli::rotate_key::RotateKeyArgs),
    /// Abandon an in-flight master-key rotation (Story 7.6b round-2).
    /// Operator escape hatch when rotate-key crashed at phase
    /// pre-previous or pre-primary and the new key bytes were lost.
    /// Clears the keystore's `previous` slot AND removes the
    /// rotation-state marker; refuses if the marker phase is
    /// `committed` (use `agentsso rotate-key` to resume instead).
    KeystoreClearPrevious(cli::rotate_key::keystore_clear_previous::KeystoreClearPreviousArgs),
}

/// Top-level `main` dispatcher.
///
/// Returns [`ExitCode`] rather than `Result<()>` so that
/// `cli::start::run`'s structured [`cli::start::StartError`] can
/// surface operator-facing exit codes (2 for config/bootstrap
/// failures, 3 for resource conflicts) without calling
/// `std::process::exit` from inside the tokio runtime. Destructors
/// run normally on every error path — the PID file at
/// `~/.agentsso/pid` is cleaned up via `PidFile::Drop`, the tracing
/// subscriber's `WorkerGuard` flushes buffered log lines, and the
/// `TcpListener` closes cleanly. Story 1.15 review Decision 1.
///
/// Non-`start` commands use `anyhow::Result` and still map to
/// `ExitCode::FAILURE` (1) on error, matching the pre-1.15 behavior.
#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Start(args)) => match cli::start::run(args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                // Write the operator-facing banner BEFORE the
                // structured tracing write so operators see the
                // remediation advice even if the tracing subscriber
                // is backlogged. `eprint!` not `eprintln!` because
                // the banner already ends in `\n`.
                eprint!("{}", e.render_banner());
                tracing::error!(error = %e, exit_code = e.exit_code(), "daemon startup failed");
                ExitCode::from(e.exit_code())
            }
        },
        Some(Commands::Stop) => anyhow_to_exit_code(cli::stop::run()),
        Some(Commands::Status(args)) => anyhow_to_exit_code(cli::status::run(args).await),
        Some(Commands::Reload) => anyhow_to_exit_code(cli::reload::run().await),
        Some(Commands::Setup(args)) => setup_to_exit_code(cli::setup::run(args).await),
        // `credentials_refresh_to_exit_code` is shape-compatible with
        // `list`/`status` outcomes (the typed-marker downcast is a
        // no-op for those variants). Only `refresh` ever produces
        // `CredentialsRefreshExitCode3`. Story 7.6c.
        Some(Commands::Credentials(args)) => {
            credentials_refresh_to_exit_code(cli::credentials::run(args).await)
        }
        Some(Commands::Config(args)) => anyhow_to_exit_code(cli::config::run(args)),
        Some(Commands::Audit(args)) => anyhow_to_exit_code(cli::audit::run(args).await),
        Some(Commands::Logs(args)) => anyhow_to_exit_code(cli::logs::run(args).await),
        Some(Commands::Scrub(args)) => anyhow_to_exit_code(cli::scrub::run(args)),
        Some(Commands::Kill(args)) => anyhow_to_exit_code(cli::kill::run(args).await),
        Some(Commands::Resume(args)) => anyhow_to_exit_code(cli::resume::run(args).await),
        Some(Commands::Agent(args)) => anyhow_to_exit_code(cli::agent::run(args).await),
        Some(Commands::Connectors(args)) => anyhow_to_exit_code(cli::connectors::run(args).await),
        Some(Commands::Autostart(args)) => anyhow_to_exit_code(cli::autostart::run(args).await),
        Some(Commands::Uninstall(args)) => uninstall_to_exit_code(cli::uninstall::run(args).await),
        Some(Commands::Update(args)) => update_to_exit_code(cli::update::run(args).await),
        Some(Commands::RotateKey(args)) => {
            rotate_key_to_exit_code(cli::rotate_key::run(args).await)
        }
        Some(Commands::KeystoreClearPrevious(args)) => {
            rotate_key_to_exit_code(cli::rotate_key::keystore_clear_previous::run(args).await)
        }
        None => {
            use clap::CommandFactory;
            if let Err(e) = Cli::command().print_help() {
                eprintln!("error: {e}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
    }
}

/// Convert an `anyhow::Result<()>` returned by a non-`start` command
/// into an `ExitCode`, printing the error to stderr on failure.
/// Matches the pre-1.15 `main() -> Result<()>` behavior for those
/// commands — failure exits 1 (`ExitCode::FAILURE`).
///
/// When the error chain contains a [`cli::SilentCliError`] marker,
/// the command has already printed a structured, operator-facing
/// error block to stderr and the generic `error: ...` follow-up
/// line would be a duplicate. In that case we suppress the follow-up
/// line and still return `FAILURE`. Story 5.1 review H2.
fn anyhow_to_exit_code(result: anyhow::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if e.chain().any(|source| source.is::<cli::SilentCliError>()) {
                // Command already printed its error block. Stay silent.
                return ExitCode::FAILURE;
            }
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// `agentsso uninstall`-specific dispatch: same shape as
/// [`anyhow_to_exit_code`] but recognises the
/// `uninstall_exit_code:3` context tag the uninstall flow attaches
/// to its brew-services pre-flight refusal (Story 7.4 AC #8).
///
/// Exit-code conventions per architecture.md:1023 — 3 is the
/// resource-conflict code (the same one `cli::start::run` returns
/// when port :3820 is already bound). Brew-services managing the
/// daemon is morally identical: a different lifecycle owner is
/// already in charge.
fn uninstall_to_exit_code(result: anyhow::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // P10 + P11 (review): typed markers (was: substring scan
            // for "uninstall_exit_code:3" in the error chain — could
            // collide with operator-visible remediation text). We
            // probe via `downcast_ref` instead of `chain().any(is::<T>)`
            // because anyhow's `.context(C)` wraps C in an internal
            // `ContextError<C>` struct that hides the concrete type
            // from a chain-walk's `is::<T>()` check; downcasting
            // through anyhow handles the wrapping correctly.
            let exit_three = e.downcast_ref::<cli::uninstall::UninstallExitCode3>().is_some();
            if e.downcast_ref::<cli::SilentCliError>().is_some()
                || e.chain().any(|s| s.is::<cli::SilentCliError>())
            {
                return if exit_three { ExitCode::from(3) } else { ExitCode::FAILURE };
            }
            eprintln!("error: {e:#}");
            if exit_three { ExitCode::from(3) } else { ExitCode::FAILURE }
        }
    }
}

/// `agentsso update`-specific dispatch: typed markers for exit codes
/// 3 (resource conflict — package-manager-managed binary, brew-
/// services), 4 (auth/integrity — network failure, signature
/// verification failure, archive-unsafe, disk-space), and 5 (swap
/// or migration failure after rollback).
///
/// Same shape as [`uninstall_to_exit_code`] but with three exit-code
/// markers instead of one. Story 7.5 AC #4 + the typed-marker
/// pattern from Story 7.4 P10+P11.
fn update_to_exit_code(result: anyhow::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let exit_three = e.downcast_ref::<cli::update::UpdateExitCode3>().is_some();
            let exit_four = e.downcast_ref::<cli::update::UpdateExitCode4>().is_some();
            let exit_five = e.downcast_ref::<cli::update::UpdateExitCode5>().is_some();
            let resolved_code = if exit_three {
                3
            } else if exit_four {
                4
            } else if exit_five {
                5
            } else {
                1
            };
            if e.downcast_ref::<cli::SilentCliError>().is_some()
                || e.chain().any(|s| s.is::<cli::SilentCliError>())
            {
                return ExitCode::from(resolved_code);
            }
            eprintln!("error: {e:#}");
            ExitCode::from(resolved_code)
        }
    }
}

/// `agentsso rotate-key`-specific dispatch (Story 7.6). Same shape as
/// `update_to_exit_code` — three typed exit-code markers
/// (`RotateKeyExitCode3/4/5`) covering resource-conflict / auth-or-
/// keystore failure / rotation failure. **Architecture note:** this
/// is the third `*_to_exit_code` dispatcher with the same pattern
/// (uninstall + update + rotate-key). The 4th-consumer story should
/// extract a `cli::common::exit_code::dispatch_with_markers` helper —
/// see deferred-work.md cross-story note from Story 7.6.
fn rotate_key_to_exit_code(result: anyhow::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let exit_three = e.downcast_ref::<cli::rotate_key::RotateKeyExitCode3>().is_some();
            let exit_four = e.downcast_ref::<cli::rotate_key::RotateKeyExitCode4>().is_some();
            let exit_five = e.downcast_ref::<cli::rotate_key::RotateKeyExitCode5>().is_some();
            let resolved_code = if exit_three {
                3
            } else if exit_four {
                4
            } else if exit_five {
                5
            } else {
                1
            };
            if e.downcast_ref::<cli::SilentCliError>().is_some()
                || e.chain().any(|s| s.is::<cli::SilentCliError>())
            {
                return ExitCode::from(resolved_code);
            }
            eprintln!("error: {e:#}");
            ExitCode::from(resolved_code)
        }
    }
}

/// `agentsso setup`-specific dispatch (Story 7.6c). Single typed
/// marker (`SetupExitCode3`) covering the daemon-running pre-flight
/// refusal. Mirrors [`rotate_key_to_exit_code`] above.
///
/// **Architecture note:** with this PR there are now four
/// `*_to_exit_code` dispatchers with the same shape (uninstall +
/// update + rotate-key + setup + credentials_refresh). The
/// `cli::common::exit_code::dispatch_with_markers` extraction
/// tracked in deferred-work.md becomes correspondingly more
/// attractive — see Story 7.6c's deferred-work entry.
fn setup_to_exit_code(result: anyhow::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let exit_three = e.downcast_ref::<cli::setup::SetupExitCode3>().is_some();
            let resolved_code = if exit_three { 3 } else { 1 };
            if e.downcast_ref::<cli::SilentCliError>().is_some()
                || e.chain().any(|s| s.is::<cli::SilentCliError>())
            {
                return ExitCode::from(resolved_code);
            }
            eprintln!("error: {e:#}");
            ExitCode::from(resolved_code)
        }
    }
}

/// `agentsso credentials refresh`-specific dispatch (Story 7.6c).
/// Single typed marker (`CredentialsRefreshExitCode3`) covering the
/// daemon-running pre-flight refusal. Same shape as
/// [`setup_to_exit_code`].
///
/// Note: pre-existing `cli_exit::{BUG, MISCONFIG, TRANSIENT}` codes
/// in `cli::credentials` are emitted directly via `std::process::exit`
/// inside `refresh_credentials`, NOT routed through this dispatcher.
/// This dispatcher only needs to surface the new exit-code-3 marker
/// for the pre-flight refusal — the legacy `process::exit` paths
/// short-circuit before the `anyhow::Result` returns to `main`.
fn credentials_refresh_to_exit_code(result: anyhow::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let exit_three =
                e.downcast_ref::<cli::credentials::CredentialsRefreshExitCode3>().is_some();
            let resolved_code = if exit_three { 3 } else { 1 };
            if e.downcast_ref::<cli::SilentCliError>().is_some()
                || e.chain().any(|s| s.is::<cli::SilentCliError>())
            {
                return ExitCode::from(resolved_code);
            }
            eprintln!("error: {e:#}");
            ExitCode::from(resolved_code)
        }
    }
}
