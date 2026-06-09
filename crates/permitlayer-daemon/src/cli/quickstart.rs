//! `agentsso quickstart <connector> --agent <name> [--read-write]` — the
//! single-account one-liner (FR5).
//!
//! ## Model (Story 11.15 — composes the Epic-11 primitives)
//!
//! The daemon is **headless** — no approval, no prompt, no
//! human-in-the-loop. Access is a binary capability chosen up front
//! (`--read` default / `--read-write`). Quickstart is the all-in-one verb
//! that COMPOSES the new nouns:
//!
//! 1. **Preflight**: under `--non-interactive` an access flag is required
//!    (`quickstart.access_unspecified`, exit 2); the connector is
//!    validated via the registry (`quickstart.unknown_service`, exit 2);
//!    the kill switch + daemon-reachable gates fire before any mutation.
//! 2. **`connection add`** (reuse [`oauth_seal::oauth_dance_and_seal`]):
//!    mint a ULID, run the OAuth dance, seal the three slots, write the
//!    `ConnectionRecord` (tier from `--read-write`). The connection is
//!    named `<agent>-<connector-bare>` (e.g. `me-gmail`).
//! 3. **Auto-register the agent** if absent (quickstart mints the bearer),
//!    then **`bind`** the agent to the connection at the tier with the
//!    connection name as the selector `--alias`, so `/mcp/<name>`
//!    resolves (reuse the 11.14 control-plane [`post_bind`] client).
//! 4. **Emit** the OpenClaw `/mcp/<name>` snippet (the agent's single
//!    bearer + connection-path addressing). `--mcp-config-out` writes the
//!    snippet to a 0o644 file for cross-user handoff.
//!
//! Ordering is connection-add → bind → snippet. If `bind` fails after the
//! connection is sealed, the connection persists and the operator is told
//! to `bind`/`connection revoke` manually — never a silent half-state.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use crate::cli::oauth_seal;
use crate::design::render;

// ── Access level ────────────────────────────────────────────────────

/// The binary access capability: which OAuth tier the connection
/// requests, and the tier the binding grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    ReadWrite,
}

impl Access {
    /// Tier string for `connection add` / `bind` (`read` | `read-write`).
    fn tier(self) -> &'static str {
        match self {
            Access::Read => "read",
            Access::ReadWrite => "read-write",
        }
    }
    fn is_write(self) -> bool {
        matches!(self, Access::ReadWrite)
    }
}

/// Parse one interactive selection line into an [`Access`]. `None` means
/// "unrecognized — re-ask once, then default to read". Pure (no I/O).
fn parse_access_line(line: &str) -> Option<Access> {
    match line.trim().to_lowercase().as_str() {
        "" | "1" | "read" => Some(Access::Read),
        "2" | "read-write" | "rw" => Some(Access::ReadWrite),
        _ => None,
    }
}

/// Interactive access selection (numbered choice). Re-asks once on
/// unrecognized input, then defaults to read.
fn prompt_access(connector: &str) -> Access {
    use std::io::{BufRead, Write};
    let stdin = std::io::stdin();
    for attempt in 0..2 {
        print!(
            "What should this agent be able to do with {connector}?  \
             [1] read (default)  [2] read & write: "
        );
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => return Access::Read,
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

// ── CLI args ────────────────────────────────────────────────────────

/// Arguments for `agentsso quickstart <connector>`.
///
/// `--read` / `--read-write` are mutually exclusive plain flags (clap
/// rejects both).
#[derive(Args, Debug)]
pub struct QuickstartArgs {
    /// Connector to connect: `gmail`, `calendar`, or `drive` (or the
    /// canonical `google-*` id). Validated against the registry.
    pub service: String,

    /// Request the read-only tier (the default). The agent can READ;
    /// writes are denied by absent scope.
    #[arg(long, conflicts_with = "read_write")]
    pub read: bool,

    /// Request the read-write tier — the OAuth grant includes the write
    /// scopes so the sealed credential can send/modify. The daemon is
    /// headless; there is no per-write gate.
    #[arg(long = "read-write", conflicts_with = "read")]
    pub read_write: bool,

    /// Path to a Google OAuth client JSON file (BYO client).
    #[arg(long = "oauth-client", value_name = "PATH")]
    pub oauth_client: Option<PathBuf>,

    /// Write the OpenClaw MCP config snippet to this path (0o644, for
    /// cross-user handoff).
    #[arg(long = "mcp-config-out", value_name = "PATH")]
    pub mcp_config_out: Option<PathBuf>,

    /// Agent name to create/use. Defaults to `<connector-bare>-quickstart`.
    #[arg(long)]
    pub agent: Option<String>,

    /// Allow running from an effective-root shell with SUDO_USER set.
    #[arg(long)]
    pub allow_root: bool,

    /// Skip all interactive prompts. Without `--read`/`--read-write` this
    /// is a hard error (we cannot prompt with no human present).
    #[arg(long)]
    pub non_interactive: bool,

    /// Use Google OAuth 2.0 device flow (RFC 8628) for the OAuth step.
    #[arg(long)]
    pub device_flow: bool,

    /// Device-flow poll timeout (seconds).
    #[arg(long, default_value = "120", requires = "device_flow")]
    pub device_flow_timeout: u64,

    /// Show the full per-step progress trace.
    #[arg(short = 'v', long)]
    pub verbose: bool,
}

// ── Run ─────────────────────────────────────────────────────────────

/// The bare service selector for a canonical connector id (for the
/// default agent name + connection-name derivation).
fn bare_selector(connector_id: &str) -> &str {
    match connector_id {
        "google-gmail" => "gmail",
        "google-calendar" => "calendar",
        "google-drive" => "drive",
        other => other,
    }
}

/// Run the `quickstart` subcommand: `connection add` → `bind` → snippet.
pub async fn run(args: QuickstartArgs) -> Result<()> {
    use anyhow::Context as _;

    let log_level = if args.verbose { "info" } else { "warn" };
    let _guards =
        crate::telemetry::init_tracing(log_level, None, 30).context("tracing init failed")?;

    #[cfg(unix)]
    {
        let hint = format!("agentsso quickstart {}", args.service);
        crate::cli::root_guard::ensure_not_sudo_root_shell_with(
            "quickstart",
            &hint,
            args.allow_root,
            nix::unistd::geteuid().as_raw(),
            std::env::var("SUDO_USER").ok().as_deref(),
        )?;
    }

    let service = args.service.trim().to_lowercase();

    // ── Preflight 1 — connector validity (registry, FR89) ──────────
    let registry = permitlayer_connectors::ConnectorRegistry::load(Some(
        &permitlayer_core::paths::connectors_dir(
            permitlayer_core::paths::home_override().as_deref(),
        ),
    ))
    .context("connector registry load failed")?;
    let connector = match registry.resolve_selector(&service) {
        Some(c) => c,
        None => {
            let supported = registry.selectors().join(", ");
            eprint!(
                "{}",
                render::error_block(
                    "quickstart.unknown_service",
                    &format!("unsupported service '{service}'. Supported services: {supported}"),
                    &format!(
                        "agentsso quickstart <service> --read | --read-write\n\n  \
                         supported services: {supported}"
                    ),
                    None,
                )
            );
            return Err(oauth_seal::exit2());
        }
    };
    let connector_id = connector.id().to_owned();
    let bare = bare_selector(&connector_id).to_owned();

    // ── Preflight 2 — resolve the access level ─────────────────────
    let stdout_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let stdin_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
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
        return Err(oauth_seal::exit2());
    };

    // Agent name + derived connection name (`<agent>-<connector-bare>`).
    let agent_name = args.agent.clone().unwrap_or_else(|| format!("{bare}-quickstart"));
    let connection_name = format!("{agent_name}-{bare}");
    let home = crate::cli::agentsso_home()?;

    // ── Preflight 3 — kill switch (before any mutation) ────────────
    oauth_seal::probe_daemon_kill_state_or_exit().await?;

    // ── Preflight 4 — daemon-reachable gate ────────────────────────
    let handle = match crate::cli::connect_uds::require_daemon_running(&home).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("\n  the one privileged step is:  sudo agentsso setup");
            return Err(e.context("quickstart: daemon not reachable"));
        }
    };

    // ── Step 1 — connection add (OAuth dance + seal) ───────────────
    let theme = crate::design::theme::Theme::load(&home);
    let oauth_config = oauth_seal::resolve_oauth_client(
        args.oauth_client.as_deref(),
        &connector_id,
        &connection_name,
        &theme,
        interactive,
    )
    .await?;
    let connection_id = permitlayer_credential::ConnectionId::generate();
    let record = oauth_seal::oauth_dance_and_seal(
        &handle,
        oauth_seal::OAuthSealInputs {
            connector: &connector,
            connector_id: &connector_id,
            name: &connection_name,
            read_write: access.is_write(),
            oauth_config,
            connection_id,
            interactive,
            headless: false,
            device_flow: args.device_flow,
            device_flow_timeout: args.device_flow_timeout,
        },
    )
    .await?;

    // ── Step 2 — auto-register the agent (mint bearer) ─────────────
    //
    // The connection is now sealed. From here, a failure leaves the
    // connection in place (the operator is told they can `bind`/`revoke`
    // manually) rather than silently half-completing.
    let bearer = register_agent_capture_bearer(&handle, &agent_name, access.is_write(), &service)
        .await
        .inspect_err(|_e| {
            eprintln!(
                "  note: connection '{}' was sealed but agent registration failed — \
                 the connection persists; re-run quickstart or `agentsso connection revoke {}`.",
                record.name, record.name
            );
        })?;

    // ── Step 3 — bind the agent to the connection ──────────────────
    let req = crate::cli::connect_uds::BindRequest {
        agent: &agent_name,
        connection_id: &record.id.to_string(),
        tier: access.tier(),
        policy: None,
        alias: Some(&connection_name),
    };
    match crate::cli::connect_uds::post_bind(&handle, &req).await {
        Ok(crate::cli::connect_uds::ControlOutcome::Ok(_)) => {}
        Ok(crate::cli::connect_uds::ControlOutcome::Err { status_code, body }) => {
            eprint!(
                "{}",
                render::error_block(
                    "quickstart.bind_failed",
                    &format!(
                        "connection '{}' was sealed but binding agent '{}' failed \
                         (HTTP {status_code}, {}): {}",
                        record.name,
                        agent_name,
                        oauth_seal::sanitize_for_terminal(&body.code),
                        oauth_seal::sanitize_for_terminal(&body.message)
                    ),
                    &format!(
                        "the connection persists; bind manually:  \
                         agentsso bind {agent_name} {connection_name} --grant {}\n  \
                         or remove it:  agentsso connection revoke {connection_name}",
                        access.tier()
                    ),
                    None,
                )
            );
            return Err(oauth_seal::silent_err_for_code(
                "connection.bind_failed",
                "quickstart bind failed",
            ));
        }
        Ok(crate::cli::connect_uds::ControlOutcome::ParseFailure { status_code, .. }) => {
            eprint!(
                "{}",
                render::error_block(
                    "quickstart.bind_failed",
                    &format!(
                        "connection '{}' sealed but bind returned an unparseable response (HTTP {status_code})",
                        record.name
                    ),
                    "verify the daemon is healthy: agentsso status",
                    None,
                )
            );
            return Err(oauth_seal::silent_err_for_code(
                "connection.bind_failed",
                "quickstart bind parse failure",
            ));
        }
        Err(transport_err) => {
            eprint!(
                "{}",
                render::error_block(
                    "quickstart.bind_failed",
                    &format!(
                        "connection '{}' sealed but bind transport failed: {transport_err}",
                        record.name
                    ),
                    "verify the daemon is healthy: agentsso status",
                    None,
                )
            );
            return Err(oauth_seal::silent_err_for_code(
                "connection.bind_failed",
                "quickstart bind transport failure",
            ));
        }
    }

    // ── Step 4 — emit the OpenClaw `/mcp/<name>` snippet ───────────
    let bind_addr =
        crate::cli::kill::load_daemon_config_or_default_with_warn("quickstart openclaw")
            .http
            .bind_addr;
    if !bind_addr.ip().is_loopback() {
        eprintln!(
            "  warn: daemon bound to non-loopback {bind_addr} — the snippet's bearer will travel \
             over the network"
        );
    }
    let snippet = crate::cli::openclaw::build_snippet(&connection_name, &bearer, bind_addr);
    crate::cli::openclaw::emit_snippet(&snippet, args.mcp_config_out.as_deref(), &connection_name)
        .map_err(|e| anyhow::anyhow!("failed to emit MCP snippet: {e}"))?;

    // ── Summary ────────────────────────────────────────────────────
    println!();
    println!(
        "\u{2713} quickstart complete \u{00b7} agent '{}' \u{2192} connection '{}' ({})",
        agent_name,
        connection_name,
        access.tier()
    );
    println!("  address it as /mcp/{connection_name}");
    println!();
    Ok(())
}

/// Register the agent and capture its minted bearer. Returns the bearer
/// on a fresh registration. An already-existing agent is NOT an error
/// (quickstart is idempotent on re-run) — but quickstart needs the bearer
/// to emit the snippet, and a re-registration can't retrieve the old
/// token, so a duplicate is surfaced with the manual remediation.
///
/// `policy` passed to register: post-11.9 the register `--policy` is a
/// validated-but-not-bound relic (authority flows via `bind`); quickstart
/// passes a shipped managed policy name so the register handler's
/// existence check passes. The binding's authority is set by Step 3's
/// `bind` (its alias makes `/mcp/<name>` resolve).
async fn register_agent_capture_bearer(
    handle: &crate::cli::connect_uds::ConnectControlHandle,
    agent: &str,
    write: bool,
    service: &str,
) -> Result<String> {
    let policy = shipped_policy_for(service, write);
    let body = serde_json::json!({ "name": agent, "policy_name": policy }).to_string();

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
            return Err(crate::cli::silent_cli_error(
                "quickstart: agent register transport failed",
            ));
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
            return Err(crate::cli::silent_cli_error("quickstart: agent register protocol error"));
        }
    };

    if let Some((code, message)) = crate::cli::kill::nested_control_plane_auth_error(&parsed) {
        eprint!(
            "{}",
            render::error_block(&code, &message, crate::cli::kill::CONTROL_AUTH_REMEDIATION, None)
        );
        return Err(crate::cli::silent_cli_error("quickstart: agent register auth rejected"));
    }

    let status = parsed["status"].as_str();
    if status == Some("error") {
        let code = parsed["code"].as_str().unwrap_or("agent.unknown_error").to_owned();
        let message = parsed["message"].as_str().unwrap_or("(no message provided)").to_owned();
        let remediation = if code == "agent.duplicate_name" {
            // Quickstart can't retrieve an existing agent's bearer. Surface
            // it as a clean error pointing at the bind+snippet path.
            format!(
                "agent '{agent}' already exists — quickstart can't recover its bearer. \
                 Bind it directly and re-paste your existing bearer:  \
                 agentsso bind {agent} <connection> --grant <tier>"
            )
        } else if code == "agent.unknown_policy" {
            format!(
                "the shipped policy '{policy}' is missing — run `sudo agentsso setup` to restage \
                 the managed bundle"
            )
        } else {
            "see message above".to_owned()
        };
        eprint!("{}", render::error_block(&code, &message, &remediation, None));
        return Err(crate::cli::silent_cli_error("quickstart: agent register returned error"));
    } else if status != Some("ok") {
        tracing::debug!(body = %response, "unexpected register status: neither 'ok' nor 'error'");
        eprint!(
            "{}",
            render::error_block(
                "quickstart.register_failed",
                "the daemon returned an unrecognized agent-register status",
                "agentsso doctor",
                None,
            )
        );
        return Err(crate::cli::silent_cli_error("quickstart: agent register unknown status"));
    }

    let bearer = parsed["bearer_token"].as_str().unwrap_or("").to_owned();
    if bearer.is_empty() {
        eprint!(
            "{}",
            render::error_block(
                "quickstart.register_failed",
                "agent register succeeded but returned no bearer token",
                "agentsso doctor",
                None,
            )
        );
        return Err(crate::cli::silent_cli_error(
            "quickstart: agent register missing bearer token",
        ));
    }
    Ok(bearer)
}

/// Map `(service, write)` to a shipped managed policy name (passed to the
/// register handler's existence check; authority flows via `bind`).
fn shipped_policy_for(service: &str, write: bool) -> &'static str {
    match (service, write) {
        ("gmail", false) => "gmail-read-only",
        ("gmail", true) => "gmail-read-write",
        ("calendar", false) => "calendar-read-only",
        ("calendar", true) => "calendar-read-write",
        ("drive", false) => "drive-read-only",
        ("drive", true) => "drive-read-write",
        // Canonical-id callers (e.g. `google-gmail`): strip the prefix.
        ("google-gmail", false) => "gmail-read-only",
        ("google-gmail", true) => "gmail-read-write",
        ("google-calendar", false) => "calendar-read-only",
        ("google-calendar", true) => "calendar-read-write",
        ("google-drive", false) => "drive-read-only",
        ("google-drive", true) => "drive-read-write",
        _ => "gmail-read-only",
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn shipped_policy_for_returns_exact_shipped_literals() {
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
            assert_eq!(shipped_policy_for(svc, *write), *expected);
            assert!(
                bundle.contains(&format!("name = \"{expected}\"")),
                "shipped default_policy.toml is missing `name = \"{expected}\"`"
            );
        }
    }

    #[test]
    fn bare_selector_strips_google_prefix() {
        assert_eq!(bare_selector("google-gmail"), "gmail");
        assert_eq!(bare_selector("google-calendar"), "calendar");
        assert_eq!(bare_selector("google-drive"), "drive");
        assert_eq!(bare_selector("custom-thing"), "custom-thing");
    }

    #[test]
    fn service_predicate_accepts_known_rejects_others() {
        let registry = permitlayer_connectors::ConnectorRegistry::load(None).unwrap();
        for ok in ["gmail", "calendar", "drive"] {
            assert!(registry.resolve_selector(ok).is_some(), "{ok} should be supported");
        }
        for bad in ["salesforce", "Gmail", "", "drive ", "slack"] {
            assert!(registry.resolve_selector(bad).is_none(), "{bad:?} must be rejected");
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

    #[test]
    fn access_tier_strings() {
        assert_eq!(Access::Read.tier(), "read");
        assert_eq!(Access::ReadWrite.tier(), "read-write");
        assert!(Access::ReadWrite.is_write());
        assert!(!Access::Read.is_write());
    }
}
