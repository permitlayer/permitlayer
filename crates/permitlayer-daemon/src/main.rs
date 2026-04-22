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
        Some(Commands::Setup(args)) => anyhow_to_exit_code(cli::setup::run(args).await),
        Some(Commands::Credentials(args)) => anyhow_to_exit_code(cli::credentials::run(args).await),
        Some(Commands::Config(args)) => anyhow_to_exit_code(cli::config::run(args)),
        Some(Commands::Audit(args)) => anyhow_to_exit_code(cli::audit::run(args).await),
        Some(Commands::Logs(args)) => anyhow_to_exit_code(cli::logs::run(args).await),
        Some(Commands::Scrub(args)) => anyhow_to_exit_code(cli::scrub::run(args)),
        Some(Commands::Kill(args)) => anyhow_to_exit_code(cli::kill::run(args).await),
        Some(Commands::Resume(args)) => anyhow_to_exit_code(cli::resume::run(args).await),
        Some(Commands::Agent(args)) => anyhow_to_exit_code(cli::agent::run(args).await),
        Some(Commands::Connectors(args)) => anyhow_to_exit_code(cli::connectors::run(args).await),
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
