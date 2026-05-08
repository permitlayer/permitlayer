//! `agentsso agent register|list|remove` — manage the agent identity
//! registry via the loopback control plane (Story 4.4).
//!
//! Each subcommand sends a single HTTP request to the daemon's
//! `/v1/control/agent/*` endpoints (loopback-only, audit-emitting),
//! parses the JSON response, and renders it via the existing
//! `crate::design::render` primitives so the output inherits color +
//! width adaptation from the rest of the CLI.
//!
//! # Bearer-token discipline
//!
//! `register` is the only command in the entire CLI that displays a
//! plaintext bearer token. The token crosses the loopback wire ONCE
//! (in the `RegisterAgentResponse` body) and is rendered into a
//! one-shot reveal block on stdout. After the command exits, no
//! plaintext exists anywhere except the operator's terminal scrollback.
//! The agent file on disk holds only the Argon2id hash + the HMAC
//! lookup key — both derived values that cannot be used to forge a
//! token without the daemon's master-derived HMAC subkey.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use crate::cli::kill::{
    error_block_daemon_unreachable, error_block_protocol_error, http_get, http_post_json,
    load_daemon_config_or_default_with_warn,
};
use crate::design::render::{TableCell, empty_state, error_block, table};
use crate::design::terminal::{ColorSupport, TableLayout};
use crate::design::theme::Theme;

/// Top-level `agent` subcommand wrapper.
#[derive(Args)]
pub struct AgentArgs {
    #[command(subcommand)]
    pub command: AgentCommand,
}

#[derive(Subcommand)]
pub enum AgentCommand {
    /// Register a new agent identity and mint a bearer token bound to
    /// a policy. The token is displayed once on stdout — copy it
    /// immediately into your agent's `Authorization: Bearer …` header
    /// because it cannot be retrieved later.
    Register(RegisterArgs),
    /// List every registered agent. Never displays bearer tokens.
    List,
    /// Remove an agent. The token is invalidated immediately —
    /// in-flight requests using the old snapshot finish, new requests
    /// return 401.
    Remove(RemoveArgs),
    /// Update an agent's policy binding without rotating its bearer
    /// token (Story 7.11). Use this to extend an agent's scopes —
    /// e.g., switch a Gmail-only agent to a policy that also covers
    /// Calendar — without re-pasting a new token into your MCP-client
    /// config.
    Rebind(RebindArgs),
}

#[derive(Args)]
pub struct RegisterArgs {
    /// Agent name. Lowercase alphanumeric + hyphen, 2–64 chars, no
    /// leading or trailing hyphen.
    pub name: String,
    /// Policy to bind the agent to. Must already exist in
    /// `~/.agentsso/policies/`.
    #[arg(long)]
    pub policy: String,
    /// Output the response as compact JSON to stdout. Mutually exclusive
    /// with --token-out.
    ///
    /// Story 7.17 Task 1: scripted-install path. Pipes safely into `jq`
    /// without parsing pretty-printed human output. The success shape is
    /// `{"status":"ok","name":"...","policy_name":"...","bearer_token":"..."}`;
    /// error shape is `{"status":"error","code":"...","message":"..."}`.
    /// Single-line output (no embedded newlines) so line-oriented
    /// pipelines and JSONL log collectors handle it without a parser.
    #[arg(long, conflicts_with = "token_out")]
    pub json: bool,
    /// Write only the bearer token bytes (no decoration, no trailing
    /// newline) to this path with mode 0o600.
    ///
    /// Story 7.17 Task 1. Owner-only mode: this file holds the same
    /// secret as the in-memory token, so it gets the strictest perms.
    /// For cross-user handoff use `agentsso connect --mcp-config-out`
    /// (Story 7.13) which writes 0o644 by design.
    #[arg(long, value_name = "PATH")]
    pub token_out: Option<PathBuf>,
}

#[derive(Args)]
pub struct RemoveArgs {
    pub name: String,
}

#[derive(Args)]
pub struct RebindArgs {
    /// Name of the agent to rebind.
    pub name: String,
    /// Policy to rebind the agent to. Must already exist in
    /// `~/.agentsso/policies/`.
    #[arg(long)]
    pub policy: String,
}

pub async fn run(args: AgentArgs) -> Result<()> {
    match args.command {
        AgentCommand::Register(a) => register_agent(a).await,
        AgentCommand::List => list_agents().await,
        AgentCommand::Remove(a) => remove_agent(a).await,
        AgentCommand::Rebind(a) => rebind_agent(a).await,
    }
}

// ──────────────────────────────────────────────────────────────────
// Subcommand implementations
// ──────────────────────────────────────────────────────────────────

/// Story 7.17 Task 1.3: typed JSON-render shape for `--json` mode.
///
/// Hand-rolled struct (NOT ad-hoc `serde_json::Value`) so the contract
/// is grep-able and the field set is enforced at compile time. The
/// scripted-install path in `headless-install.yml` pipes `jq -r .bearer_token`
/// over this shape; future field additions are additive.
#[derive(Serialize, Deserialize, Debug)]
struct RegisterResponseJson {
    status: &'static str,
    name: String,
    policy_name: String,
    bearer_token: String,
}

/// Story 7.17 Task 1.5: typed JSON-render shape for `--json` error responses.
///
/// Mirrors the success shape so `jq` callers can branch on `.status`.
#[derive(Serialize, Deserialize, Debug)]
struct RegisterErrorJson {
    status: &'static str,
    code: String,
    message: String,
}

async fn register_agent(args: RegisterArgs) -> Result<()> {
    let config = load_daemon_config_or_default_with_warn("agent register");

    // No PID-file pre-check here. The daemon may be running under a
    // different OS user (intentional architecture: vault-holder runs as
    // a privileged user; agent operators connect over loopback). The
    // PID file lives at the *daemon owner's* `~/.agentsso/` and isn't
    // readable cross-user. Defer the "is the daemon up?" decision to
    // the HTTP call below — the existing `error_block_daemon_unreachable`
    // path renders the same outcome for a single-user user with no
    // daemon running, and works correctly for the cross-user case.
    //
    // Destructive control endpoints (`agent remove`, `kill`, `resume`,
    // `reload`) keep the PID-file gate until the control plane gains
    // proper auth — see deferred-work.md "control-plane authentication".

    // POST the request.
    let body = serde_json::json!({
        "name": args.name,
        "policy_name": args.policy,
    })
    .to_string();
    let bind_addr = config.http.bind_addr;
    let token = crate::cli::kill::read_control_token(&config.paths.home);
    let response = match http_post_json(
        bind_addr,
        "/v1/control/agent/register",
        &body,
        token.as_deref(),
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(error = %e, addr = %bind_addr, "agent register request failed");
            eprint!("{}", error_block_daemon_unreachable("agent register", bind_addr));
            std::process::exit(3);
        }
    };

    // 3. Parse response. Distinguishes ok vs structured error bodies.
    let parsed: serde_json::Value = match serde_json::from_str(&response) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, body = %response, "unexpected agent register response");
            eprint!("{}", error_block_protocol_error());
            std::process::exit(3);
        }
    };
    // Story 7.11 review-round-1 D3: explicit `Some("ok")` positive
    // check. Pre-7.11 the register/list/remove handlers fell through
    // to success on missing/unknown status; D3 lifts the rebind-path
    // discipline to all CLI handlers.
    let status = parsed["status"].as_str();
    if status == Some("error") {
        let code = parsed["code"].as_str().unwrap_or("agent.unknown_error").to_owned();
        let message = parsed["message"].as_str().unwrap_or("(no message provided)").to_owned();
        // Story 7.17 Task 1.5: --json error responses go to stdout (the
        // contract caller is `jq`, which expects machine output on stdout).
        // Human/file paths keep the existing error_block stderr render so
        // operators see the structured remediation block.
        if args.json {
            let payload = RegisterErrorJson { status: "error", code: code.clone(), message };
            // Compact single-line; no `to_string_pretty`.
            match serde_json::to_string(&payload) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    tracing::error!(error = %e, "register --json error serialization failed");
                    eprint!("{}", error_block_protocol_error());
                    std::process::exit(3);
                }
            }
        } else {
            let suggested = match code.as_str() {
                "agent.duplicate_name" => format!("agentsso agent remove {}", args.name),
                "agent.unknown_policy" => {
                    "edit ~/.agentsso/policies/ then `agentsso reload`".to_owned()
                }
                // Story 1.15 removed `agent.no_master_key` — the master
                // key is now eagerly bootstrapped at daemon start, so
                // this code can no longer be emitted by the daemon.
                _ => "see message above".to_owned(),
            };
            eprint!("{}", error_block(&code, &message, &suggested, None));
        }
        // Story 7.11 review-round-2 Q2: route through the shared
        // `agent_control_exit_code` helper so register/list/remove/
        // rebind agree on exit codes for the same error code.
        // Story 7.17 Task 1.5: exit-code mapping is identical across
        // human and --json paths — scripts and humans get the same
        // signal.
        std::process::exit(agent_control_exit_code(&code));
    } else if status != Some("ok") {
        tracing::debug!(
            body = %response,
            "unexpected agent register response: status was neither 'ok' nor 'error'"
        );
        eprint!("{}", error_block_protocol_error());
        std::process::exit(3);
    }

    let name = parsed["name"].as_str().unwrap_or(&args.name).to_owned();
    let policy_name = parsed["policy_name"].as_str().unwrap_or(&args.policy).to_owned();
    let token = parsed["bearer_token"].as_str().unwrap_or("").to_owned();

    if token.is_empty() {
        eprint!("{}", error_block_protocol_error());
        std::process::exit(3);
    }

    // Story 7.17 Task 1.2: branch on render path AFTER name/policy/token
    // extraction. All three paths consume the same source values — there
    // is no parallel-parse drift between them.
    if args.json {
        render_register_json(&name, &policy_name, &token);
    } else if let Some(path) = args.token_out.as_deref() {
        if let Err(e) = render_register_token_file(&name, &policy_name, &token, path) {
            tracing::debug!(error = %e, path = %path.display(), "--token-out write failed");
            let kind = e.kind();
            let (code, msg, remediation) = match kind {
                std::io::ErrorKind::NotFound => (
                    "agent.token_out_parent_missing",
                    format!("parent directory does not exist: {}", path.display()),
                    "create the parent directory or pick a different path".to_owned(),
                ),
                std::io::ErrorKind::InvalidInput => (
                    "agent.token_out_invalid_path",
                    format!("refusing to write token: {e}"),
                    "remove the existing symlink or pick a different path".to_owned(),
                ),
                _ => (
                    "agent.token_out_write_failed",
                    format!("could not write bearer token to {}: {e}", path.display()),
                    "check the parent directory's permissions and disk space".to_owned(),
                ),
            };
            eprint!("{}", error_block(code, &msg, &remediation, None));
            // exit 4 keeps token_out write failures distinct from auth/
            // protocol errors (3) and operator-correctable input (2).
            // Scripts can map exit 4 → "filesystem-side fix needed."
            std::process::exit(4);
        }
    } else {
        render_register_success(&name, &policy_name, &token);
    }
    Ok(())
}

fn render_register_success(name: &str, policy_name: &str, token: &str) {
    // The output is intentionally plain — operators screenshot this
    // line to share with teammates, and ANSI codes hurt the share.
    // Use a single triple-clickable line for the token so it's easy
    // to copy without picking up adjacent whitespace.
    println!();
    println!("✓ agent '{name}' registered → policy '{policy_name}'");
    println!();
    println!("  bearer token (shown once, save it now):");
    println!();
    println!("    {token}");
    println!();
    println!("  set this on your agent's HTTP requests:");
    println!();
    println!("    Authorization: Bearer {token}");
    println!();
    println!("  this token will not be shown again.");
    println!();
}

/// Story 7.17 Task 1.3: emit the success response as compact JSON on a
/// single stdout line.
///
/// `serde_json::to_string` (NOT `to_string_pretty`) is the load-bearing
/// detail — line-oriented pipelines (`while read line; do jq … <<<"$line"; done`)
/// and JSONL collectors (Vector, Fluent Bit) tolerate one record per line
/// only.
fn render_register_json(name: &str, policy_name: &str, token: &str) {
    let payload = RegisterResponseJson {
        status: "ok",
        name: name.to_owned(),
        policy_name: policy_name.to_owned(),
        bearer_token: token.to_owned(),
    };
    match serde_json::to_string(&payload) {
        Ok(s) => println!("{s}"),
        Err(e) => {
            // The struct is owned, primitive-typed, and finite — `to_string`
            // can only fail under serde-internal invariants. If it does we
            // surface a protocol error rather than continue with a phony
            // success.
            tracing::error!(error = %e, "register --json serialization failed");
            eprint!("{}", error_block_protocol_error());
            std::process::exit(3);
        }
    }
}

/// Story 7.17 Task 1.4: write the bearer token bytes (no decoration, no
/// trailing newline) to `path` with mode 0o600 on Unix.
///
/// Stdout receives a confirmation line with the path but **never** the
/// token bytes — the file is the canonical retrieval path and stdout
/// could land in a log file via `tee` or shell redirect.
fn render_register_token_file(
    name: &str,
    policy_name: &str,
    token: &str,
    path: &std::path::Path,
) -> std::io::Result<()> {
    crate::cli::atomic_write::write_atomic_with_mode(path, token.as_bytes(), 0o600)?;
    // Plain stdout — no token bytes. `policy_name` flagged so scripts can
    // confirm the policy bound at register-time without re-querying the
    // daemon.
    println!();
    println!("✓ agent '{name}' registered → policy '{policy_name}'");
    println!("  bearer token written to {} (mode 0o600)", path.display());
    println!();
    Ok(())
}

async fn list_agents() -> Result<()> {
    let config = load_daemon_config_or_default_with_warn("agent list");
    let home = config.paths.home.clone();

    // No PID-file pre-check — see `register_agent` for the rationale.
    // Read-only metadata; safe to defer reachability check to the HTTP
    // call's existing error-block path. `home` is still resolved
    // because it's used by `Theme::load` further down for rendering.

    let bind_addr = config.http.bind_addr;
    let token = crate::cli::kill::read_control_token(&home);
    let response = match http_get(bind_addr, "/v1/control/agent/list", token.as_deref()).await {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(error = %e, addr = %bind_addr, "agent list request failed");
            eprint!("{}", error_block_daemon_unreachable("agent list", bind_addr));
            std::process::exit(3);
        }
    };

    let parsed: serde_json::Value = match serde_json::from_str(&response) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, body = %response, "unexpected agent list response");
            eprint!("{}", error_block_protocol_error());
            std::process::exit(3);
        }
    };
    // Distinguish structured error bodies from the success shape BEFORE
    // reading `agents`. The daemon returns 503 `agent.store_unavailable`
    // (with `status: "error"`) when the backing store is degraded —
    // without this guard the operator would see "no agents registered"
    // and chase a red herring.
    //
    // Story 7.11 review-round-1 D3: explicit Some("ok") discipline.
    // NB: list responses can ALSO take the Plan B
    // `{"error":{"code":"forbidden_*"}}` shape (auth errors), handled
    // immediately below — so the unknown-status branch only fires
    // when neither shape matches.
    let status = parsed["status"].as_str();
    if status == Some("error") {
        let code = parsed["code"].as_str().unwrap_or("agent.unknown_error").to_owned();
        let message = parsed["message"].as_str().unwrap_or("(no message provided)").to_owned();
        let suggested = match code.as_str() {
            "agent.store_unavailable" => {
                "check daemon logs for agent-store errors and verify ~/.agentsso/agents/ permissions"
                    .to_owned()
            }
            _ => "see message above".to_owned(),
        };
        eprint!("{}", error_block(&code, &message, &suggested, None));
        // Story 7.11 review-round-2 Q2: shared exit-code helper.
        std::process::exit(agent_control_exit_code(&code));
    }
    // Plan B: control-plane auth errors come back with a different
    // top-level shape: `{"error":{"code":"forbidden_*", "message":...}}`.
    // Surface them so the operator sees the actual cause instead of a
    // misleading "no agents registered" empty state.
    if let Some(err) = parsed.get("error") {
        let code = err["code"].as_str().unwrap_or("control.unknown_error").to_owned();
        let message = err["message"].as_str().unwrap_or("(no message)").to_owned();
        let suggested = match code.as_str() {
            "forbidden_missing_control_token" | "forbidden_invalid_control_token" => {
                "set AGENTSSO_CONTROL_TOKEN or run as the daemon-owner user. \
                 If you cannot read the daemon's <home>/control.token, ask the operator \
                 to share it explicitly (e.g. via `sudo cat`)."
                    .to_owned()
            }
            _ => "see message above".to_owned(),
        };
        eprint!("{}", error_block(&code, &message, &suggested, None));
        std::process::exit(3);
    }

    // Story 7.11 review-round-1 D3: now that BOTH error shapes are
    // ruled out, require explicit `status: "ok"` before reading
    // `agents`. Anything else is a protocol error.
    if status != Some("ok") {
        tracing::debug!(
            body = %response,
            "unexpected agent list response: status was neither 'ok' nor 'error'"
        );
        eprint!("{}", error_block_protocol_error());
        std::process::exit(3);
    }

    let agents = parsed["agents"].as_array().cloned().unwrap_or_default();
    if agents.is_empty() {
        print!(
            "{}",
            empty_state(
                "no agents registered",
                "register one with:  agentsso agent register <name> --policy=<policy>",
            )
        );
        return Ok(());
    }

    let theme = Theme::load(&home);
    let support = ColorSupport::detect();
    let layout = TableLayout::detect();

    let headers = &["AGENT", "POLICY", "REGISTERED", "LAST SEEN"];
    let rows: Vec<Vec<TableCell>> = agents
        .iter()
        .map(|a| {
            let last_seen =
                a["last_seen_at"].as_str().map(str::to_owned).unwrap_or_else(|| "never".to_owned());
            vec![
                TableCell::Plain(a["name"].as_str().unwrap_or("").to_owned()),
                TableCell::Plain(a["policy_name"].as_str().unwrap_or("").to_owned()),
                TableCell::Plain(a["created_at"].as_str().unwrap_or("").to_owned()),
                TableCell::Plain(last_seen),
            ]
        })
        .collect();

    match table(headers, &rows, layout, &theme, support) {
        Ok(rendered) => print!("{rendered}"),
        Err(e) => {
            tracing::warn!(error = %e, "table render failed — falling back to plain output");
            for a in &agents {
                let last_seen = a["last_seen_at"]
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| "never".to_owned());
                println!(
                    "{}  {}  {}  {}",
                    a["name"].as_str().unwrap_or(""),
                    a["policy_name"].as_str().unwrap_or(""),
                    a["created_at"].as_str().unwrap_or(""),
                    last_seen,
                );
            }
        }
    }

    Ok(())
}

async fn remove_agent(args: RemoveArgs) -> Result<()> {
    let config = load_daemon_config_or_default_with_warn("agent remove");
    let home = config.paths.home.clone();

    // No PID-file pre-check — Plan B's operator-token auth on
    // `/v1/control/*` is the canonical gate.

    let body = serde_json::json!({"name": args.name}).to_string();
    let bind_addr = config.http.bind_addr;
    let token = crate::cli::kill::read_control_token(&home);
    let response = match http_post_json(
        bind_addr,
        "/v1/control/agent/remove",
        &body,
        token.as_deref(),
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(error = %e, addr = %bind_addr, "agent remove request failed");
            eprint!("{}", error_block_daemon_unreachable("agent remove", bind_addr));
            std::process::exit(3);
        }
    };

    let parsed: serde_json::Value = match serde_json::from_str(&response) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, body = %response, "unexpected agent remove response");
            eprint!("{}", error_block_protocol_error());
            std::process::exit(3);
        }
    };

    // Story 7.11 review-round-1 D3: explicit Some("ok") discipline.
    let status = parsed["status"].as_str();
    if status == Some("error") {
        let code = parsed["code"].as_str().unwrap_or("agent.unknown_error").to_owned();
        let message = parsed["message"].as_str().unwrap_or("(no message provided)").to_owned();
        eprint!("{}", error_block(&code, &message, "see message above", None));
        // Story 7.11 review-round-2 Q2: shared exit-code helper.
        std::process::exit(agent_control_exit_code(&code));
    } else if status != Some("ok") {
        tracing::debug!(
            body = %response,
            "unexpected agent remove response: status was neither 'ok' nor 'error'"
        );
        eprint!("{}", error_block_protocol_error());
        std::process::exit(3);
    }

    if parsed["removed"] == true {
        println!("✓ agent '{}' removed", args.name);
    } else {
        println!("agent '{}' was not registered (nothing to remove)", args.name);
        std::process::exit(2);
    }

    Ok(())
}

/// Rebind an agent to a new policy without rotating its bearer token
/// (Story 7.11). The bearer-token-immutable-across-rebind invariant
/// is the load-bearing property — operators can extend an agent's
/// scopes via the policy file + `agent rebind` without touching
/// downstream MCP-client configs.
async fn rebind_agent(args: RebindArgs) -> Result<()> {
    let config = load_daemon_config_or_default_with_warn("agent rebind");
    let home = config.paths.home.clone();

    // Same Plan B operator-token discipline as `agent register` /
    // `agent remove`. Daemon must be running (HTTP call); the
    // `error_block_daemon_unreachable` path renders the right error
    // message if the daemon is down.
    let body = serde_json::json!({
        "name": args.name,
        "policy_name": args.policy,
    })
    .to_string();
    let bind_addr = config.http.bind_addr;
    let token = crate::cli::kill::read_control_token(&home);
    let response = match http_post_json(
        bind_addr,
        "/v1/control/agent/rebind",
        &body,
        token.as_deref(),
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(error = %e, addr = %bind_addr, "agent rebind request failed");
            eprint!("{}", error_block_daemon_unreachable("agent rebind", bind_addr));
            std::process::exit(3);
        }
    };

    let parsed: serde_json::Value = match serde_json::from_str(&response) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, body = %response, "unexpected agent rebind response");
            eprint!("{}", error_block_protocol_error());
            std::process::exit(3);
        }
    };

    // Story 7.11 review-round-1 P4: explicit positive `status == "ok"`
    // check. Pre-existing register/remove handlers fall through to
    // success on missing/unknown status — the rebind path tightens
    // this. Everything that's NOT an explicit "ok" or "error" gets
    // routed to `error_block_protocol_error` rather than silently
    // printing a phony success.
    let status = parsed["status"].as_str();
    if status == Some("error") {
        let code = parsed["code"].as_str().unwrap_or("agent.unknown_error").to_owned();
        let message = parsed["message"].as_str().unwrap_or("(no message provided)").to_owned();
        let suggested = match code.as_str() {
            "agent.unknown_policy" => {
                "edit ~/.agentsso/policies/ then `agentsso reload`".to_owned()
            }
            "agent.not_found" => format!(
                "register the agent first: agentsso agent register {} --policy={}",
                args.name, args.policy
            ),
            "agent.rate_limited" => "wait briefly and retry".to_owned(),
            "agent.registry_reload_failed" => {
                "the agent file was rewritten on disk but the in-memory registry is stale; \
                 run `agentsso reload` to recover"
                    .to_owned()
            }
            _ => "see message above".to_owned(),
        };
        eprint!("{}", error_block(&code, &message, &suggested, None));
        // Story 7.11 review-round-2 Q2: route through the shared
        // `agent_control_exit_code` helper. The earlier round-1 P3
        // hand-rolled this same mapping inline; round-2 promoted it
        // to a shared helper so register/list/remove/rebind agree.
        std::process::exit(agent_control_exit_code(&code));
    } else if status != Some("ok") {
        // Unknown status (missing, null, or anything other than
        // "ok"/"error"). The daemon should never produce this shape,
        // but if it does (network corruption, future schema drift,
        // proxy interposition), fall back to a protocol error rather
        // than printing a phony success block.
        tracing::debug!(
            body = %response,
            "unexpected agent rebind response: status was neither 'ok' nor 'error'"
        );
        eprint!("{}", error_block_protocol_error());
        std::process::exit(3);
    }

    // status == Some("ok") — render success.
    let agent = match parsed.get("agent") {
        Some(a) if a.is_object() => a,
        _ => {
            // Server returned `status: ok` but no `agent` payload.
            // Defense in depth — same bucket as protocol error.
            tracing::debug!(
                body = %response,
                "agent rebind ok-response missing 'agent' field"
            );
            eprint!("{}", error_block_protocol_error());
            std::process::exit(3);
        }
    };
    let name = agent["name"].as_str().unwrap_or(&args.name);
    let policy_name = agent["policy_name"].as_str().unwrap_or(&args.policy);

    // The reassurance-line is operator-facing and required by the
    // story spec (Task 3.3) — it makes the bearer-token-immutable
    // invariant visible at the moment it matters most.
    println!();
    println!("✓ agent '{name}' rebound → policy '{policy_name}'");
    println!("  (bearer token unchanged — your MCP-client config does NOT need to be updated)");
    println!();

    Ok(())
}

/// Story 7.11 review-round-2 Q2: centralized exit-code mapping for
/// `agentsso agent` subcommands (register / list / remove / rebind).
///
/// The contract:
/// - **2** = operator-correctable precondition. The command's target
///   state is wrong (agent missing, policy unknown, name invalid,
///   name already taken). The operator must fix their input and
///   retry. Scripts can map exit 2 → "review the command, don't
///   blindly retry."
/// - **3** = daemon/system error. Transient (rate-limited) or
///   systemic (persist failed, registry reload failed, daemon
///   unreachable). Scripts can map exit 3 → "wait briefly and retry,
///   or escalate if persistent."
///
/// This helper is intentionally scoped to `agent` subcommands.
/// Other CLI surfaces (`start`, `update`, `rotate-key`) have their
/// own exit-code conventions and MUST NOT be routed through this.
/// Story 7.13 (`agentsso connect`) introduces OAuth/browser/provider
/// failure classes that need their own bucket and likewise must not
/// be shoehorned into this taxonomy.
///
/// Codified in response to Story 7.11 round-2 review where
/// `register` and `rebind` were found disagreeing on the exit code
/// for `agent.unknown_policy` (3 vs 2). Single source of truth here.
pub(crate) fn agent_control_exit_code(code: &str) -> i32 {
    match code {
        // Operator-correctable preconditions.
        // Story 7.11 review-round-3 #3: `agent.bad_request` (emitted
        // for malformed JSON / oversized body / unparseable input)
        // belongs in the "fix your input and retry" bucket, NOT
        // "retry later". Scripts mapping exit 3 → retry-with-backoff
        // would loop forever on a malformed payload.
        "agent.not_found"
        | "agent.unknown_policy"
        | "agent.invalid_name"
        | "agent.duplicate_name"
        | "agent.bad_request" => 2,
        // Daemon/system errors (rate_limited, persist_failed,
        // registry_reload_failed, lookup_failed, store_unavailable,
        // internal, unknown). Default 3 keeps unknown future codes
        // in the "retry later" bucket; revisit if a new code
        // surfaces that's clearly operator-correctable.
        _ => 3,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Smoke test: clap can parse `agent register foo --policy=bar`.
    #[derive(Parser)]
    struct CliWrapper {
        #[command(subcommand)]
        cmd: AgentCommand,
    }

    #[test]
    fn clap_parses_register_with_policy_flag() {
        let parsed = CliWrapper::parse_from([
            "agent",
            "register",
            "email-triage",
            "--policy=email-read-only",
        ]);
        match parsed.cmd {
            AgentCommand::Register(r) => {
                assert_eq!(r.name, "email-triage");
                assert_eq!(r.policy, "email-read-only");
            }
            _ => panic!("expected Register variant"),
        }
    }

    #[test]
    fn clap_parses_list_subcommand() {
        let parsed = CliWrapper::parse_from(["agent", "list"]);
        assert!(matches!(parsed.cmd, AgentCommand::List));
    }

    #[test]
    fn clap_parses_remove_subcommand() {
        let parsed = CliWrapper::parse_from(["agent", "remove", "email-triage"]);
        match parsed.cmd {
            AgentCommand::Remove(r) => {
                assert_eq!(r.name, "email-triage");
            }
            _ => panic!("expected Remove variant"),
        }
    }

    #[test]
    fn clap_parses_rebind_with_policy_flag() {
        let parsed = CliWrapper::parse_from([
            "agent",
            "rebind",
            "email-triage",
            "--policy=email-and-calendar",
        ]);
        match parsed.cmd {
            AgentCommand::Rebind(r) => {
                assert_eq!(r.name, "email-triage");
                assert_eq!(r.policy, "email-and-calendar");
            }
            _ => panic!("expected Rebind variant"),
        }
    }

    #[test]
    fn clap_rebind_requires_policy_flag() {
        // `agent rebind <name>` without --policy must fail to parse.
        let result = CliWrapper::try_parse_from(["agent", "rebind", "email-triage"]);
        assert!(result.is_err(), "rebind without --policy must fail clap parse");
    }

    // Story 7.11 review-round-2 Q2: exit-code helper unit tests.
    // Pins the contract so register/list/remove/rebind agree.

    #[test]
    fn agent_control_exit_code_preconditions_map_to_2() {
        for code in &[
            "agent.not_found",
            "agent.unknown_policy",
            "agent.invalid_name",
            "agent.duplicate_name",
        ] {
            assert_eq!(
                agent_control_exit_code(code),
                2,
                "{code} must map to exit code 2 (operator-correctable precondition)"
            );
        }
    }

    #[test]
    fn agent_control_exit_code_bad_request_is_precondition() {
        // Story 7.11 review-round-3 #3: `agent.bad_request` (malformed
        // JSON / oversized body) is operator-correctable input,
        // belongs in exit 2.
        assert_eq!(agent_control_exit_code("agent.bad_request"), 2);
    }

    #[test]
    fn agent_control_exit_code_system_errors_map_to_3() {
        for code in &[
            "agent.rate_limited",
            "agent.persist_failed",
            "agent.registry_reload_failed",
            "agent.lookup_failed",
            "agent.store_unavailable",
            "agent.internal",
            "agent.unknown_error",
        ] {
            assert_eq!(
                agent_control_exit_code(code),
                3,
                "{code} must map to exit code 3 (transient or systemic)"
            );
        }
    }

    #[test]
    fn agent_control_exit_code_unknown_future_codes_default_to_3() {
        // Future error codes that haven't been classified yet land
        // in the "retry later" bucket. This is intentional — we'd
        // rather scripts retry than treat an unknown code as
        // "fix your input."
        assert_eq!(agent_control_exit_code("agent.future_unknown"), 3);
        assert_eq!(agent_control_exit_code(""), 3);
    }

    // ──────────────────────────────────────────────────────────────
    // Story 7.17 Task 1.7: --json and --token-out unit tests
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn register_args_json_flag_parses() {
        let parsed =
            CliWrapper::parse_from(["agent", "register", "ci-test", "--policy=default", "--json"]);
        match parsed.cmd {
            AgentCommand::Register(r) => {
                assert!(r.json);
                assert!(r.token_out.is_none());
            }
            _ => panic!("expected Register variant"),
        }
    }

    #[test]
    fn register_args_token_out_flag_parses() {
        let parsed = CliWrapper::parse_from([
            "agent",
            "register",
            "ci-test",
            "--policy=default",
            "--token-out=/tmp/agent.tok",
        ]);
        match parsed.cmd {
            AgentCommand::Register(r) => {
                assert!(!r.json);
                assert_eq!(r.token_out.as_deref(), Some(std::path::Path::new("/tmp/agent.tok")));
            }
            _ => panic!("expected Register variant"),
        }
    }

    #[test]
    fn register_args_json_and_token_out_are_mutually_exclusive() {
        // Story 7.17 AC #3: clap-level conflict (no runtime check needed).
        let result = CliWrapper::try_parse_from([
            "agent",
            "register",
            "ci-test",
            "--policy=default",
            "--json",
            "--token-out=/tmp/agent.tok",
        ]);
        assert!(result.is_err(), "--json + --token-out must fail clap parse");
    }

    #[test]
    fn register_response_json_serializes_compact_single_line() {
        // Story 7.17 Task 1.7: assert the wire shape pipelines depend on.
        let payload = RegisterResponseJson {
            status: "ok",
            name: "ci-test".to_owned(),
            policy_name: "default".to_owned(),
            bearer_token: "agt_v2_abc".to_owned(),
        };
        let s = serde_json::to_string(&payload).unwrap();
        // Single-line: no embedded newlines.
        assert!(!s.contains('\n'), "compact JSON must be single-line: {s}");
        // No spaces between key and value (the cheap canary for
        // `to_string_pretty` regression).
        assert!(s.contains("\"status\":\"ok\""), "compact JSON must omit key/value spaces: {s}");
        // Round-trips back through the parser as the expected shape.
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["status"], "ok");
        assert_eq!(parsed["name"], "ci-test");
        assert_eq!(parsed["policy_name"], "default");
        assert_eq!(parsed["bearer_token"], "agt_v2_abc");
    }

    #[test]
    fn register_error_json_has_status_error_field() {
        // Story 7.17 Task 1.7: --json error responses have a stable
        // shape `jq` callers can branch on (`.status == "error"`).
        let payload = RegisterErrorJson {
            status: "error",
            code: "agent.duplicate_name".to_owned(),
            message: "agent 'ci-test' already exists".to_owned(),
        };
        let s = serde_json::to_string(&payload).unwrap();
        assert!(!s.contains('\n'));
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["status"], "error");
        assert_eq!(parsed["code"], "agent.duplicate_name");
        assert!(parsed["message"].as_str().unwrap().contains("already exists"));
    }

    #[test]
    fn token_file_writes_bytes_with_no_trailing_newline() {
        // Story 7.17 Task 1.7: --token-out writes raw bytes only — no
        // newline, no decoration. Pipelines reading the file with
        // `cat` or `read -r` get exactly the bearer.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bearer.tok");
        let token = "agt_v2_abc";
        crate::cli::atomic_write::write_atomic_with_mode(&path, token.as_bytes(), 0o600).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes, token.as_bytes());
        assert_eq!(bytes.last(), Some(&b'c')); // no trailing 0x0a
    }

    #[cfg(unix)]
    #[test]
    fn token_file_is_0o600_on_unix() {
        // Story 7.17 Task 1.7: AC #2 contract — owner-only mode.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bearer.tok");
        crate::cli::atomic_write::write_atomic_with_mode(&path, b"agt_v2_x", 0o600).unwrap();
        let md = std::fs::metadata(&path).unwrap();
        let mode = md.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "--token-out file must be 0o600 (owner-only)");
    }
}
