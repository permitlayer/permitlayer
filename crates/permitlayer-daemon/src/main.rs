//! The `agentsso` binary — permitlayer's daemon, CLI, and HTTP server.
//!
//! This is the only crate in the workspace that uses `anyhow`. Library
//! crates use concrete `thiserror` error enums.

#![forbid(unsafe_code)]

// Story 7.11 review-round-2 Q3: workspace-wide test-seam discipline.
// The daemon's `test-seam` feature transitively enables
// `permitlayer-keystore/test-seam`. See `permitlayer-core::lib.rs`
// for the full rationale.
#[cfg(all(feature = "test-seam", not(debug_assertions)))]
compile_error!(
    "the `test-seam` feature must NOT be enabled in release builds. \
     If you need to run integration tests against this crate, build \
     with `cargo test --features test-seam` (debug profile) instead."
);

mod approval;
mod cli;
mod config;
mod design;
mod lifecycle;
mod repair;
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
    /// Read-only terminal UI: navigable status / agents / policies
    /// console over the loopback control plane (slice 1). Runs as the
    /// operator's UID; no mutations. `q` / Ctrl-C to quit.
    Ui(cli::ui::UiArgs),
    /// Reload configuration (sends SIGHUP)
    Reload,
    /// Manage per-account credential connections (Epic 11, Story 11.13):
    /// `add` runs the OAuth dance and seals a fresh connection;
    /// `list`/`inspect` show connections; `revoke` removes a connection
    /// (record + sealed slots + every binding referencing it). Replaces
    /// the retired `connect <service> --agent` verb (FR23) — bind an
    /// agent to a connection with `agentsso bind` (Story 11.14).
    Connection(cli::connection::ConnectionArgs),
    /// Inspect and validate loaded policies (Story 7.34)
    Policy(cli::policy::PolicyArgs),
    /// Connect ONE agent to ONE Google service in a single command
    /// (UX-overhaul Story 5). Picks the shipped read-only / read-write
    /// policy by the `--read` / `--read-write` flag (the daemon is
    /// headless — no approval, no prompt), auto-creates the agent,
    /// then composes the `connect` OAuth + seal + verify + scope-merge
    /// + rebind + OpenClaw-snippet flow. Idempotent on re-runs.
    Quickstart(cli::quickstart::QuickstartArgs),
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
    /// Install / upgrade / repair the privileged macOS daemon — the
    /// single idempotent root command (UX-overhaul Story 2). Stages
    /// a versioned binary, atomically re-points the stable symlink,
    /// bootstraps, and self-verifies the running daemon's version
    /// over the control plane (rolls back on failure). Replaces
    /// `agentsso service install`.
    Setup(cli::setup::SetupArgs),
    /// Diagnose (and with `--fix` repair the safe subset of) a
    /// privileged macOS install — version drift, stale launchd
    /// registration, symlink topology, managed-policy staleness,
    /// daemon liveness, no-TTY prompt traps, missing daemon binary,
    /// operator-layer compile (UX-overhaul Story 4). `--json` emits a
    /// machine-readable report; `--restart-ok` (inert without
    /// `--fix`) permits daemon-bouncing repairs.
    Doctor(cli::doctor::DoctorArgs),
    /// Manage the daemon as a macOS system service. `install` is now
    /// `agentsso setup` (this verb redirects). `uninstall`
    /// (root-required teardown) + `status` (no-root state report)
    /// remain.
    Service(cli::service::ServiceArgs),
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
    // Story 7.27 review fix: locate the first non-flag arg so the
    // interceptors fire even when global flags (`--verbose`, `--log`,
    // etc.) precede the subcommand. Previous `args().nth(1)` matched
    // only the literal second token, so `agentsso --verbose autostart`
    // bypassed the interceptor and hit clap's "unrecognized" error.
    //
    // Story 7.27 Round-2 review note: this heuristic is correct for
    // the current `Cli` struct because no global flag takes a bare
    // separate-token value (all `Cli` options use either bool flags
    // or `--flag=value` form). If a future flag is added with the
    // shape `--log <value>` (separate-token form), `find` would
    // match the value instead of the subcommand. Switching to
    // `clap::Command::try_get_matches_from_mut` would be more robust
    // but adds parsing cost on every CLI invocation. Re-evaluate if
    // a value-taking global flag is added.
    //
    // Known edge cases (all acceptable as documented):
    //   - `agentsso help autostart` falls through to clap's own
    //     "unrecognized subcommand" rendering (autostart was
    //     removed from `Commands` enum). Operators see clap's
    //     standard error, not the structured migration block —
    //     but the binary's `--help` output also no longer lists
    //     `autostart` so the discovery path is consistent.
    //   - `agentsso autostart status --json`: the interceptor emits
    //     a non-JSON `error_block` on stderr. Legacy script users
    //     of the `autostart status --json` form must migrate to
    //     `agentsso service status` (eventually `--json` flag) or
    //     check exit code 2 (the `autostart.removed` interceptor's
    //     deliberate "loud failure" semantics).
    // Round-3 review fix (R3-C5-P7) doc-only: this heuristic has
    // known limitations the clap-driven full-fidelity parse would
    // handle:
    //   - `agentsso --help autostart` matches `autostart` here and
    //     fires the interceptor BEFORE clap's `--help` rendering.
    //     Operator wanted help; got the autostart-removed error
    //     block. Acceptable: `--help` to find a removed command
    //     should at least surface the removal note.
    //   - `agentsso -- autostart` (conventional end-of-options
    //     marker) matches `autostart` here too. clap would treat
    //     `autostart` as a positional argument, not a subcommand,
    //     so the interceptor's "you removed this subcommand"
    //     message is slightly misleading — but operator intent was
    //     still to invoke autostart, so the message is helpful.
    //   - A future value-taking global flag (`--config /path`)
    //     would cause `find` to return `/path` (no leading `-`),
    //     which won't match `autostart`/`setup` so the interceptor
    //     silently passes through to clap. Worth a clap
    //     `try_get_matches_from` migration if such a flag is
    //     added — but the parsing-cost objection is overblown
    //     (clap parse is microsecond-scale).
    let first_subcommand_arg: Option<String> =
        std::env::args().skip(1).find(|a| !a.starts_with('-'));

    // UX-overhaul Story 2 — `agentsso service install` → `setup`
    // redirect interceptor.
    //
    // `setup` is RECLAIMED as a real subcommand in this story (it is
    // the single idempotent privileged install/upgrade/repair verb;
    // see `cli::setup`). The Story-7.13 `setup`→"removed"→`connect`
    // interceptor is therefore DELETED — `setup` now falls through to
    // clap's dispatch. `service install` is demoted: operators (or
    // scripts) typing it get a loud structured redirect to `setup`
    // (the established "burn the boats" interceptor style, mirroring
    // the `autostart`→removed block below). Runs BEFORE clap parsing.
    //
    // `service install` is TWO tokens; `first_subcommand_arg` is the
    // first non-flag token (`service`). Match the second non-flag
    // token too so `service uninstall` / `service status` are
    // untouched — only `service install` is redirected.
    if first_subcommand_arg.as_deref() == Some("service") {
        let second = std::env::args().skip(1).filter(|a| !a.starts_with('-')).nth(1);
        if second.as_deref() == Some("install") {
            eprint!(
                "{}",
                crate::design::render::error_block(
                    "service.install.redirected",
                    "`agentsso service install` is now `sudo agentsso setup` — the single \
                     idempotent install / upgrade / repair command (versioned-symlink, \
                     self-verifying)",
                    "sudo agentsso setup",
                    None,
                )
            );
            return ExitCode::from(2);
        }
    }

    // Story 7.27 — legacy `agentsso autostart` interceptor.
    //
    // The `autostart` subcommand was replaced by `setup` (one-time
    // install/upgrade/repair) plus `agentsso service uninstall/status`
    // (Sprint Change Proposal 2026-05-10, "burn the boats" direction;
    // `service install` itself was demoted to a redirect in the
    // UX-overhaul epic). Operators (or scripts) still typing
    // `agentsso autostart enable` get a structured remediation block
    // instead of clap's terse "unrecognized subcommand" error.
    if first_subcommand_arg.as_deref() == Some("autostart") {
        eprint!(
            "{}",
            crate::design::render::error_block(
                "autostart.removed",
                "`agentsso autostart` was replaced by `sudo agentsso setup` (install) plus \
                 `agentsso service uninstall/status`",
                "sudo agentsso setup             # one-time install/upgrade/repair, root required\n  \
                 agentsso service status         # report state (no root)\n  \
                 sudo agentsso service uninstall # teardown, root required",
                None,
            )
        );
        return ExitCode::from(2);
    }

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
                // Walk the source chain so the OSStatus from a macOS
                // keychain ACL denial (Plan A) reaches both the compact
                // stdout layer (via `record_error` on the `&dyn Error`
                // field) and the JSON file layer (via the pre-
                // stringified `error_chain` field — JsonVisitor does
                // not walk sources).
                let chain: Vec<String> =
                    std::iter::successors(Some(&e as &(dyn std::error::Error + 'static)), |err| {
                        err.source()
                    })
                    .map(|err| err.to_string())
                    .collect();
                tracing::error!(
                    error = &e as &(dyn std::error::Error + 'static),
                    error_chain = ?chain,
                    exit_code = e.exit_code(),
                    "daemon startup failed",
                );
                ExitCode::from(e.exit_code())
            }
        },
        Some(Commands::Stop) => anyhow_to_exit_code(cli::stop::run()),
        Some(Commands::Status(args)) => anyhow_to_exit_code(cli::status::run(args).await),
        Some(Commands::Ui(args)) => anyhow_to_exit_code(cli::ui::run(args).await),
        Some(Commands::Reload) => anyhow_to_exit_code(cli::reload::run().await),
        // `connection add/list/inspect/revoke` (Story 11.13) share the
        // OAuth/connection exit taxonomy (operator-correctable → 2;
        // system/retry → 3) housed in `cli::oauth_seal`.
        Some(Commands::Connection(args)) => {
            connection_to_exit_code(cli::connection::run(args).await)
        }
        // Quickstart is a stub until Story 11.15 (it errors via
        // `oauth_seal::exit2`), routed through the same exit dispatcher.
        Some(Commands::Quickstart(args)) => {
            connection_to_exit_code(cli::quickstart::run(args).await)
        }
        Some(Commands::Config(args)) => anyhow_to_exit_code(cli::config::run(args)),
        Some(Commands::Policy(args)) => anyhow_to_exit_code(cli::policy::run(args).await),
        Some(Commands::Audit(args)) => anyhow_to_exit_code(cli::audit::run(args).await),
        Some(Commands::Logs(args)) => anyhow_to_exit_code(cli::logs::run(args).await),
        Some(Commands::Scrub(args)) => anyhow_to_exit_code(cli::scrub::run(args)),
        Some(Commands::Kill(args)) => anyhow_to_exit_code(cli::kill::run(args).await),
        Some(Commands::Resume(args)) => anyhow_to_exit_code(cli::resume::run(args).await),
        Some(Commands::Agent(args)) => anyhow_to_exit_code(cli::agent::run(args).await),
        Some(Commands::Connectors(args)) => anyhow_to_exit_code(cli::connectors::run(args).await),
        Some(Commands::Setup(args)) => anyhow_to_exit_code(cli::setup::run(args).await),
        Some(Commands::Doctor(args)) => anyhow_to_exit_code(cli::doctor::run(args).await),
        Some(Commands::Service(args)) => anyhow_to_exit_code(cli::service::run(args).await),
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

/// `agentsso update`-specific dispatch (UX-overhaul Story 3). The
/// command is a read-only drift detector now — no apply/swap path —
/// so the exit-code surface narrowed to two markers:
///
/// - **3** ([`cli::update::UpdateExitCode3`]) — caller asked for the
///   removed `--apply`, or the binary is package-manager-managed;
///   the command redirected to `brew upgrade && sudo agentsso setup`
///   and changed nothing.
/// - **4** ([`cli::update::UpdateExitCode4`]) — actionable
///   non-success: version drift detected, or the latest-release
///   query failed (host is not provably current). Scripts/`doctor`
///   gate on non-zero.
///
/// Same downcast-through-anyhow shape as [`uninstall_to_exit_code`].
fn update_to_exit_code(result: anyhow::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let exit_three = e.downcast_ref::<cli::update::UpdateExitCode3>().is_some();
            let exit_four = e.downcast_ref::<cli::update::UpdateExitCode4>().is_some();
            let resolved_code = if exit_three {
                3
            } else if exit_four {
                4
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

/// `agentsso connection`-specific dispatch (Story 11.13; replaces the
/// retired `connect` dispatcher). Two typed exit-code markers in
/// `cli::oauth_seal` — operator-correctable input → 2; system/retry → 3.
/// Also covers the `quickstart` stub (exit 2 via `oauth_seal::exit2`).
fn connection_to_exit_code(result: anyhow::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let exit_two = e.downcast_ref::<cli::oauth_seal::ConnectExitCode2>().is_some()
                || e.chain().any(|s| s.is::<cli::oauth_seal::ConnectExitCode2>());
            let exit_three = e.downcast_ref::<cli::oauth_seal::ConnectExitCode3>().is_some()
                || e.chain().any(|s| s.is::<cli::oauth_seal::ConnectExitCode3>());
            let resolved_code = if exit_three {
                3
            } else if exit_two {
                2
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
