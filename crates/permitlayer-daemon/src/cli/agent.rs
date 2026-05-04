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

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::kill::{
    error_block_daemon_not_running, error_block_daemon_unreachable, error_block_protocol_error,
    http_get, http_post_json, load_daemon_config_or_default_with_warn,
};
use crate::design::render::{TableCell, empty_state, error_block, table};
use crate::design::terminal::{ColorSupport, TableLayout};
use crate::design::theme::Theme;
use crate::lifecycle::pid::PidFile;

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
}

#[derive(Args)]
pub struct RemoveArgs {
    pub name: String,
}

pub async fn run(args: AgentArgs) -> Result<()> {
    match args.command {
        AgentCommand::Register(a) => register_agent(a).await,
        AgentCommand::List => list_agents().await,
        AgentCommand::Remove(a) => remove_agent(a).await,
    }
}

// ──────────────────────────────────────────────────────────────────
// Subcommand implementations
// ──────────────────────────────────────────────────────────────────

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
    let response = match http_post_json(bind_addr, "/v1/control/agent/register", &body).await {
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
    if parsed["status"] == "error" {
        let code = parsed["code"].as_str().unwrap_or("agent.unknown_error").to_owned();
        let message = parsed["message"].as_str().unwrap_or("(no message provided)").to_owned();
        let suggested = match code.as_str() {
            "agent.duplicate_name" => format!("agentsso agent remove {}", args.name),
            "agent.unknown_policy" => {
                "edit ~/.agentsso/policies/ then `agentsso reload`".to_owned()
            }
            // Story 1.15 removed `agent.no_master_key` — the master key
            // is now eagerly bootstrapped at daemon start, so this code
            // can no longer be emitted by the daemon.
            _ => "see message above".to_owned(),
        };
        eprint!("{}", error_block(&code, &message, &suggested, None));
        std::process::exit(if code == "agent.duplicate_name" { 2 } else { 3 });
    }

    let name = parsed["name"].as_str().unwrap_or(&args.name).to_owned();
    let policy_name = parsed["policy_name"].as_str().unwrap_or(&args.policy).to_owned();
    let token = parsed["bearer_token"].as_str().unwrap_or("").to_owned();

    if token.is_empty() {
        eprint!("{}", error_block_protocol_error());
        std::process::exit(3);
    }

    render_register_success(&name, &policy_name, &token);
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

async fn list_agents() -> Result<()> {
    let config = load_daemon_config_or_default_with_warn("agent list");
    let home = config.paths.home.clone();

    // No PID-file pre-check — see `register_agent` for the rationale.
    // Read-only metadata; safe to defer reachability check to the HTTP
    // call's existing error-block path. `home` is still resolved
    // because it's used by `Theme::load` further down for rendering.

    let bind_addr = config.http.bind_addr;
    let response = match http_get(bind_addr, "/v1/control/agent/list").await {
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
    if parsed["status"] == "error" {
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

    if PidFile::read(&home)?.is_none() || !PidFile::is_daemon_running(&home)? {
        eprint!("{}", error_block_daemon_not_running("agent remove"));
        std::process::exit(3);
    }

    let body = serde_json::json!({"name": args.name}).to_string();
    let bind_addr = config.http.bind_addr;
    let response = match http_post_json(bind_addr, "/v1/control/agent/remove", &body).await {
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

    if parsed["status"] == "error" {
        let code = parsed["code"].as_str().unwrap_or("agent.unknown_error").to_owned();
        let message = parsed["message"].as_str().unwrap_or("(no message provided)").to_owned();
        eprint!("{}", error_block(&code, &message, "see message above", None));
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
}
