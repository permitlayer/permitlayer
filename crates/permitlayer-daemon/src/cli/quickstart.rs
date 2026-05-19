//! `agentsso quickstart <service>` — connect ONE agent to ONE Google
//! service in a single command (UX-overhaul Story 5).
//!
//! ## Model (owner-confirmed, final)
//!
//! The daemon is **headless**. There is NO approval, NO prompt-on-write,
//! NO human-in-the-loop. Access is a binary scope capability chosen up
//! front:
//!
//! - `--read`       → bind the agent to the shipped `<svc>-read-only` policy
//! - `--read-write` → bind the agent to the shipped `<svc>-read-write` policy
//!
//! There is no third option, no `none`, no tier name the operator types,
//! and no danger-confirmation string. The legacy `approval-mode` field
//! in shipped policies is dead metadata for this deployment — policies
//! are bound BY NAME and `approval-mode` is ignored.
//!
//! ## Flow
//!
//! 1. Validate the service against the same allowlist `connect` uses.
//! 2. Resolve the access level (flag / interactive selection / hard
//!    error when neither a flag nor a TTY is present — we cannot prompt
//!    with no human present, the same reason approvals do not exist).
//! 3. **Kill-switch gate** (before anything mutating) — a killed daemon
//!    must never leave a registered-but-inert agent behind.
//! 4. **Daemon-reachable gate** — reuse `connect`'s structured
//!    install/start remediation block, plus one steer line pointing at
//!    the single privileged step (`sudo agentsso setup`).
//! 5. Register the agent bound to the resolved policy (the bearer token
//!    is held in memory ONLY — quickstart never writes it anywhere).
//! 6. Drive the existing `connect` orchestration: OAuth, seal, verify,
//!    scope-merge, rebind, and MCP-snippet emission. `connect` owns
//!    the snippet emitter (it hardcodes `"transport":"streamable-http"`
//!    via `cli::openclaw`), so quickstart never re-emits a snippet.
//! 7. Print a plain-language summary of what the agent can now do.
//!
//! ## Reused public seams vs locally-reimplemented private siblings
//!
//! - PUBLIC, reused as-is: `connect::run`, `connect::exit2`,
//!   `connect_uds::require_daemon_running`, `kill::{resolve_control_endpoint,
//!   read_control_token, http_get_via, http_post_json_via}`.
//! - PRIVATE to a sibling, reimplemented locally here with the same
//!   discipline `doctor` used for `sha256_file`: the kill-state probe
//!   (private to `connect.rs`), the register POST (private to
//!   `agent.rs`), and the `Glyphs` helper (private to `doctor`).

use std::io::{IsTerminal, Write};
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use crate::cli::silent_cli_error;
use crate::design::render;

// ── Glyphs (mirror cli::doctor / cli::setup / cli::update) ──────────
//
// Private to each of those modules by design; reimplemented here per
// the "local reimpl of a private sibling" discipline (same as
// doctor's `sha256_file` copy of setup's).

struct Glyphs {
    arrow: &'static str,
    check: &'static str,
}

fn glyphs() -> Glyphs {
    use crate::design::terminal::ColorSupport;
    match ColorSupport::detect() {
        ColorSupport::NoColor => Glyphs { arrow: "->", check: "[ok]" },
        _ => Glyphs {
            arrow: "\u{2192}", // →
            check: "\u{2713}", // ✓
        },
    }
}

// ── Service allowlist ───────────────────────────────────────────────
//
// Same set `connect.rs` uses (`SUPPORTED_SERVICES`); kept as a private
// const here rather than re-exporting connect's private one so the
// two stay independently greppable and a future divergence is loud.

const SUPPORTED_SERVICES: &[&str] = &["gmail", "calendar", "drive"];

fn is_supported_service(service: &str) -> bool {
    SUPPORTED_SERVICES.contains(&service)
}

// ── Access level → shipped policy name ──────────────────────────────

/// The binary access capability. NOT a tier, NOT an approval mode —
/// just "which shipped policy do we bind the agent to".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    ReadWrite,
}

/// Map `(service, write)` to the EXACT shipped policy name.
///
/// No string interpolation — an explicit match so a future bundle
/// rename is a compile/test failure here, not a production
/// `agent.unknown_policy` at register time. The unit tests pin every
/// returned literal against `include_str!("default_policy.toml")`.
fn policy_for(service: &str, write: bool) -> &'static str {
    match (service, write) {
        ("gmail", false) => "gmail-read-only",
        ("gmail", true) => "gmail-read-write",
        ("calendar", false) => "calendar-read-only",
        ("calendar", true) => "calendar-read-write",
        ("drive", false) => "drive-read-only",
        ("drive", true) => "drive-read-write",
        // Unreachable: callers validate `service` against
        // `SUPPORTED_SERVICES` first. Kept total so the fn has no
        // panic path; the empty string would surface as a daemon-side
        // `agent.unknown_policy` (loud) rather than a silent misbind.
        _ => "",
    }
}

/// Parse one interactive selection line into an [`Access`]. `None`
/// means "unrecognized — caller should re-ask once, then default to
/// read". Pure (no I/O) so it is unit-testable.
fn parse_access_line(line: &str) -> Option<Access> {
    match line.trim().to_lowercase().as_str() {
        "" | "1" | "read" => Some(Access::Read),
        "2" | "read-write" | "rw" => Some(Access::ReadWrite),
        _ => None,
    }
}

// ── CLI args ────────────────────────────────────────────────────────

/// Arguments for `agentsso quickstart <service>`.
///
/// `--read` / `--read-write` are mutually exclusive plain flags (clap
/// rejects both). They are NOT a `--tier <enum>` the operator types.
#[derive(Args, Debug)]
pub struct QuickstartArgs {
    /// Service to connect: `gmail`, `calendar`, or `drive`.
    pub service: String,

    /// Bind the agent to the shipped read-only policy for the service
    /// (the agent can READ; writes are denied).
    #[arg(long, conflicts_with = "read_write")]
    pub read: bool,

    /// Bind the agent to the shipped read-write policy for the service
    /// (the agent can READ and WRITE — send/modify/delete — with no
    /// gate; the daemon is headless).
    #[arg(long = "read-write", conflicts_with = "read")]
    pub read_write: bool,

    /// Path to a Google OAuth client JSON file. Forwarded to the
    /// `connect` orchestration; still required for the OAuth step.
    #[arg(long = "oauth-client", value_name = "PATH")]
    pub oauth_client: Option<PathBuf>,

    /// Write the OpenClaw MCP config snippet to this path (forwarded
    /// to `connect`, which owns snippet emission).
    #[arg(long = "mcp-config-out", value_name = "PATH")]
    pub mcp_config_out: Option<PathBuf>,

    /// Agent name to create. Defaults to `<service>-quickstart`.
    #[arg(long)]
    pub agent: Option<String>,

    /// Allow running from an effective-root shell with SUDO_USER set
    /// (forwarded to `connect`). CI / embedded installs only.
    #[arg(long)]
    pub allow_root: bool,

    /// Skip all interactive prompts. Without `--read`/`--read-write`
    /// this is a hard error (we cannot prompt with no human present).
    #[arg(long)]
    pub non_interactive: bool,
}

// ── Run ─────────────────────────────────────────────────────────────

/// Run the `quickstart` subcommand.
pub async fn run(args: QuickstartArgs) -> Result<()> {
    use anyhow::Context as _;

    // Single-shot CLI command — install only the stdout subscriber
    // (mirror connect::run).
    let _guards =
        crate::telemetry::init_tracing("info", None, 30).context("tracing init failed")?;

    let service = args.service.trim().to_lowercase();

    // ── Step 1 — service allowlist ──────────────────────────────────
    if !is_supported_service(&service) {
        eprint!(
            "{}",
            render::error_block(
                "quickstart.unknown_service",
                &format!(
                    "unsupported service '{service}'. Supported services: {}",
                    SUPPORTED_SERVICES.join(", ")
                ),
                &format!(
                    "agentsso quickstart <service> --read | --read-write\n\n  \
                     supported services: {}",
                    SUPPORTED_SERVICES.join(", ")
                ),
                None,
            )
        );
        return Err(crate::cli::connect::exit2());
    }

    // ── Step 2 — resolve the access level ───────────────────────────
    //
    // Precedence: explicit flag → interactive selection → hard error.
    let stdout_is_tty = std::io::stdout().is_terminal();
    let stdin_is_tty = std::io::stdin().is_terminal();
    let interactive = !args.non_interactive && stdin_is_tty && stdout_is_tty;

    let access = if args.read {
        Access::Read
    } else if args.read_write {
        Access::ReadWrite
    } else if interactive {
        prompt_access(&service)
    } else {
        eprint!(
            "{}",
            render::error_block(
                "quickstart.access_unspecified",
                "no access level given and not running interactively",
                "pass --read or --read-write",
                None,
            )
        );
        return Err(crate::cli::connect::exit2());
    };
    let write = matches!(access, Access::ReadWrite);

    let agent_name = args.agent.clone().unwrap_or_else(|| format!("{service}-quickstart"));
    let home = crate::cli::agentsso_home()?;

    tracing::info!(
        home = %home.display(),
        service = %service,
        agent = %agent_name,
        access = ?access,
        "starting quickstart flow"
    );

    // ── Step 3 — kill-switch gate (BEFORE anything mutating) ────────
    //
    // Runs before the daemon-reachable gate so the more-specific
    // `agentsso resume` remediation wins (same ordering connect.rs
    // uses). A killed daemon must never leave a registered-but-inert
    // agent behind, so this MUST precede agent registration.
    probe_kill_state_or_exit().await?;

    // ── Step 4 — daemon-reachable gate ──────────────────────────────
    //
    // `require_daemon_running` already prints the structured
    // install/start block on failure; quickstart adds ONE steer line
    // pointing at the single privileged step.
    let handle = match crate::cli::connect_uds::require_daemon_running(&home).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("\n  the one privileged step is:  sudo agentsso setup");
            // `require_daemon_running` already attached the
            // SilentCliError + ConnectExitCode markers; surface our
            // own internal description but keep the original error in
            // the chain so the exit-code dispatcher still sees them.
            return Err(e.context("quickstart: daemon not reachable"));
        }
    };

    // ── Step 5 — register the agent bound to the resolved policy ────
    let policy = policy_for(&service, write);
    let bearer = register_agent_capture_bearer(&handle, &agent_name, policy, &home).await?;

    // ── Step 6 — drive the existing connect orchestration ───────────
    //
    // connect::run performs OAuth + seal + verify + scope-merge +
    // rebind AND emits the MCP block (its emitter hardcodes
    // `"transport":"streamable-http"` via cli::openclaw). quickstart
    // does NOT re-emit a snippet — that would duplicate/diverge.
    crate::cli::connect::run(crate::cli::connect::ConnectArgs {
        service: service.clone(),
        agent: agent_name.clone(),
        oauth_client: args.oauth_client.clone(),
        non_interactive: args.non_interactive,
        headless: false,
        device_flow: false,
        device_flow_timeout: 120,
        force: false,
        bearer_token: Some(bearer),
        mcp_config_out: args.mcp_config_out.clone(),
        allow_root: args.allow_root,
    })
    .await?;

    // ── Step 7 — plain-language summary ─────────────────────────────
    print_summary(&service, &agent_name, access);

    Ok(())
}

/// Interactive access selection. Plain numbered choice — NOT a y/N,
/// NOT a danger confirmation, no verbatim danger string. Re-asks once
/// on unrecognized input, then defaults to read.
fn prompt_access(service: &str) -> Access {
    use std::io::BufRead;

    let stdin = std::io::stdin();
    for attempt in 0..2 {
        print!(
            "What should this agent be able to do with {service}?  \
             [1] read (default)  [2] read & write: "
        );
        let _ = std::io::stdout().flush();

        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => {
                // EOF mid-prompt — treat as the read default rather
                // than spinning. (The non-interactive hard-error path
                // already covers "no human"; this is the rarer
                // closed-stdin-after-TTY-detect case.)
                return Access::Read;
            }
            Ok(_) => {
                if let Some(a) = parse_access_line(&line) {
                    return a;
                }
                if attempt == 0 {
                    println!("  please answer 1 or 2.");
                }
            }
            Err(_) => return Access::Read,
        }
    }
    Access::Read
}

/// Plain-language post-connect summary. Uses the design `render`
/// primitives + the local `Glyphs` helper (mirror doctor's
/// human-render style).
fn print_summary(service: &str, agent: &str, access: Access) {
    let g = glyphs();
    println!();
    println!("{} quickstart complete", g.arrow);
    println!("    agent:   {agent}");
    println!("    service: {service}");
    match access {
        Access::Read => {
            println!("    {} can READ {service}; writes are denied", g.check);
        }
        Access::ReadWrite => {
            println!("    {} can READ and WRITE {service} (send/modify/delete), no gate", g.check);
        }
    }
    println!(
        "    runs headless — no approval, no prompt; capability is fixed by the \
         access level chosen"
    );
    println!();
}

// ── Locally-reimplemented private siblings ──────────────────────────

/// Local reimplementation of `connect.rs`'s PRIVATE
/// `probe_daemon_kill_state_or_exit` (it cannot be called from here).
///
/// Short-circuits to `Ok(())` (quickstart proceeds) when: no PID file
/// / daemon not running / any probe failure (refused, timeout,
/// non-JSON). Returns `Err` only when the daemon explicitly reports
/// `{"active": true}`. Failing-open on a broken probe is intentional
/// defense-in-depth — exactly mirrors connect.rs's tolerance.
async fn probe_kill_state_or_exit() -> Result<()> {
    use crate::config::{CliOverrides, DaemonConfig};
    use crate::lifecycle::pid::PidFile;

    let config = match DaemonConfig::load(&CliOverrides::default()) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                target: "quickstart",
                error = %e,
                "DaemonConfig::load failed during kill-state probe; proceeding",
            );
            return Ok(());
        }
    };
    let home = &config.paths.home;

    let daemon_running = matches!(PidFile::read(home), Ok(Some(_)))
        && matches!(PidFile::is_daemon_running(home), Ok(true));
    if !daemon_running {
        return Ok(());
    }

    let endpoint = crate::cli::kill::resolve_control_endpoint(&config);
    let probe_deadline = std::time::Duration::from_millis(500);
    let control_token = crate::cli::kill::read_control_token(home);

    let probe_result = tokio::time::timeout(
        probe_deadline,
        crate::cli::kill::http_get_via(&endpoint, "/v1/control/state", control_token.as_deref()),
    )
    .await;

    let body = match probe_result {
        Ok(Ok(body)) => body,
        Ok(Err(e)) => {
            tracing::warn!(
                target: "quickstart",
                error = %e,
                "kill-state probe failed; proceeding",
            );
            return Ok(());
        }
        Err(_elapsed) => {
            tracing::warn!(
                target: "quickstart",
                "kill-state probe timed out; proceeding",
            );
            return Ok(());
        }
    };

    #[derive(serde::Deserialize)]
    struct StateSnapshot {
        active: bool,
    }
    let snapshot: StateSnapshot = match serde_json::from_str(&body) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                target: "quickstart",
                error = %e,
                body = %body,
                "unexpected state response; proceeding",
            );
            return Ok(());
        }
    };

    if snapshot.active {
        eprint!(
            "{}",
            render::error_block(
                "daemon_killed",
                "permitlayer is in kill state \u{2014} quickstart will not connect an \
                 agent that cannot act",
                "agentsso resume",
                None,
            )
        );
        return Err(silent_cli_error("quickstart: daemon in kill state"));
    }

    Ok(())
}

/// Local reimplementation of the `agent.rs` PRIVATE register POST
/// (~the `register_agent` body). Mirrors that flow: POST
/// `/v1/control/agent/register`, parse JSON, render the matching
/// error_block on a non-`ok` status, and on success extract
/// `bearer_token` (the exact field `agent.rs` reads) into memory ONLY
/// — quickstart never writes it.
async fn register_agent_capture_bearer(
    handle: &crate::cli::connect_uds::ConnectControlHandle,
    agent: &str,
    policy: &str,
    home: &std::path::Path,
) -> Result<String> {
    let body = serde_json::json!({
        "name": agent,
        "policy_name": policy,
    })
    .to_string();

    let response = match crate::cli::kill::http_post_json_via(
        &handle.endpoint,
        "/v1/control/agent/register",
        &body,
        handle.control_token.as_deref(),
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(error = %e, "quickstart agent register request failed");
            eprint!(
                "{}",
                render::error_block(
                    "quickstart.register_failed",
                    "could not reach the daemon control plane to register the agent",
                    "agentsso doctor",
                    None,
                )
            );
            return Err(silent_cli_error("quickstart: agent register transport failed"));
        }
    };

    let parsed: serde_json::Value = match serde_json::from_str(&response) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, body = %response, "unexpected register response");
            eprint!(
                "{}",
                render::error_block(
                    "quickstart.register_failed",
                    "the daemon returned an unexpected response to agent register",
                    "agentsso doctor",
                    None,
                )
            );
            return Err(silent_cli_error("quickstart: agent register protocol error"));
        }
    };

    // Nested control-plane auth errors carry a top-level
    // `status:"error"` AND a nested `error.code`; detect them first
    // (same ordering agent.rs uses) so they surface the real cause
    // instead of a useless `agent.unknown_error`.
    if let Some((code, message)) = crate::cli::kill::nested_control_plane_auth_error(&parsed) {
        eprint!(
            "{}",
            render::error_block(&code, &message, crate::cli::kill::CONTROL_AUTH_REMEDIATION, None)
        );
        return Err(silent_cli_error("quickstart: agent register auth rejected"));
    }

    let status = parsed["status"].as_str();
    if status == Some("error") {
        let code = parsed["code"].as_str().unwrap_or("agent.unknown_error").to_owned();
        let message = parsed["message"].as_str().unwrap_or("(no message provided)").to_owned();
        let remediation = match code.as_str() {
            "agent.duplicate_name" => format!("agentsso agent remove {agent}"),
            "agent.unknown_policy" => format!(
                "the shipped policy '{policy}' is missing from {}/policies — run \
                 sudo agentsso setup to restage the managed bundle",
                home.display()
            ),
            _ => "see message above".to_owned(),
        };
        eprint!("{}", render::error_block(&code, &message, &remediation, None));
        return Err(silent_cli_error("quickstart: agent register returned error status"));
    } else if status != Some("ok") {
        tracing::debug!(
            body = %response,
            "unexpected register status: neither 'ok' nor 'error'"
        );
        eprint!(
            "{}",
            render::error_block(
                "quickstart.register_failed",
                "the daemon returned an unrecognized agent-register status",
                "agentsso doctor",
                None,
            )
        );
        return Err(silent_cli_error("quickstart: agent register unknown status"));
    }

    // agent.rs extracts `parsed["bearer_token"]` — match exactly.
    let bearer = parsed["bearer_token"].as_str().unwrap_or("").to_owned();
    if bearer.is_empty() {
        eprint!(
            "{}",
            render::error_block(
                "quickstart.register_failed",
                "the daemon registered the agent but returned no bearer token",
                "agentsso doctor",
                None,
            )
        );
        return Err(silent_cli_error("quickstart: agent register missing bearer token"));
    }
    Ok(bearer)
}

// ── Tests ───────────────────────────────────────────────────────────
//
// This crate is `#![forbid(unsafe_code)]`; `std::env::set_var` is
// unsafe in edition 2024 — NO env-mutating tests. All unit tests are
// pure (no I/O, no env). End-to-end behavior is covered in
// `tests/integration/quickstart_e2e.rs`.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Every `policy_for` return value must be EXACTLY the shipped
    /// policy name AND must appear verbatim as `name = "<literal>"` in
    /// the bundled `default_policy.toml`. A future bundle rename then
    /// breaks the build here, not production.
    #[test]
    fn policy_for_returns_exact_shipped_literals() {
        let bundle = include_str!("default_policy.toml");
        let cases: &[(&str, bool, &str)] = &[
            ("gmail", false, "gmail-read-only"),
            ("gmail", true, "gmail-read-write"),
            ("calendar", false, "calendar-read-only"),
            ("calendar", true, "calendar-read-write"),
            ("drive", false, "drive-read-only"),
            ("drive", true, "drive-read-write"),
        ];
        for (svc, write, expected) in cases {
            assert_eq!(
                policy_for(svc, *write),
                *expected,
                "policy_for({svc}, {write}) literal drifted"
            );
            assert!(
                bundle.contains(&format!("name = \"{expected}\"")),
                "shipped default_policy.toml is missing `name = \"{expected}\"` — \
                 quickstart would mis-bind in production"
            );
        }
    }

    #[test]
    fn service_predicate_accepts_known_rejects_others() {
        for ok in ["gmail", "calendar", "drive"] {
            assert!(is_supported_service(ok), "{ok} should be supported");
        }
        for bad in ["salesforce", "Gmail", "", "drive ", "slack"] {
            assert!(!is_supported_service(bad), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn parse_access_line_maps_read_inputs() {
        for s in ["", "1", "read", "READ", "  read  ", "\n", " 1 "] {
            assert_eq!(parse_access_line(s), Some(Access::Read), "{s:?} → read");
        }
    }

    #[test]
    fn parse_access_line_maps_read_write_inputs() {
        for s in ["2", "read-write", "rw", "RW", "  Read-Write ", " 2 "] {
            assert_eq!(parse_access_line(s), Some(Access::ReadWrite), "{s:?} → read-write");
        }
    }

    #[test]
    fn parse_access_line_rejects_junk() {
        for s in ["3", "yes", "y", "no", "readwrite", "r/w", "delete-everything"] {
            assert_eq!(parse_access_line(s), None, "{s:?} must be unrecognized");
        }
    }

    /// The interactive parser's documented "re-ask once then default
    /// to read on junk" contract, exercised at the pure level: junk →
    /// `None` (caller re-asks), and a second junk → still `None`
    /// (caller defaults to read). This pins the semantics without the
    /// I/O loop.
    #[test]
    fn junk_then_junk_yields_default_read_semantics() {
        assert_eq!(parse_access_line("garbage"), None);
        assert_eq!(parse_access_line("more-garbage"), None);
        // The fallback the loop applies after two misses:
        let fallback = parse_access_line("garbage").unwrap_or(Access::Read);
        assert_eq!(fallback, Access::Read);
    }
}
