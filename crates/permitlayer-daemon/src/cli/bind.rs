//! `agentsso bind` / `agentsso unbind` (Epic 11, Story 11.14).
//!
//! A **binding** grants an agent use of a connection at a tier (+ an
//! optional policy and selector alias). One agent → many bindings
//! (amended FR47). Bind/unbind touch ONLY `bindings/<agent>.toml` — never
//! the agent's identity file, so the bearer token is immutable across
//! bind/unbind.
//!
//! ## Routing
//!
//! - `bind` goes through the daemon control plane
//!   (`POST /v1/control/bindings`): the optional `--policy` must be
//!   verified against the daemon's **live compiled `PolicySet`** (the same
//!   authoritative check `agent register --policy` uses), which only the
//!   running daemon holds. The handler validates agent/connection/policy
//!   existence, then writes the binding.
//! - `unbind` is an in-process `BindingStore` op (a pure store delete the
//!   operator CLI can do directly, like `connection list/revoke`) — no
//!   policy check, so no daemon round-trip.

use anyhow::Result;
use clap::Args;

use permitlayer_core::store::connection::ConnectionRecord;

use crate::cli::oauth_seal;
use crate::design::render;

#[derive(Args, Debug)]
pub struct BindArgs {
    /// Agent to grant the connection to. Must already be registered.
    pub agent: String,
    /// Connection to bind: a connection name or its ULID id.
    pub connection: String,
    /// Access tier the binding grants.
    #[arg(long, value_parser = ["read", "read-write"])]
    pub grant: String,
    /// Optional policy further constraining the grant. Must already exist
    /// in the daemon's active policy set (checked before any write).
    #[arg(long)]
    pub policy: Option<String>,
    /// Optional selector alias for path-addressing (`/mcp/<alias>`).
    #[arg(long)]
    pub alias: Option<String>,
}

#[derive(Args, Debug)]
pub struct UnbindArgs {
    /// Agent whose binding to remove.
    pub agent: String,
    /// Connection to unbind: a connection name or its ULID id.
    pub connection: String,
}

// ── control-plane resolve helper ────────────────────────────────────

/// Resolve a `name | id-text` selector to a `ConnectionRecord` via the
/// daemon control plane (Story 11.18 — the operator can't read the
/// root-private store in-process). `Ok(None)` on `connection.not_found`.
async fn resolve_connection_cp(
    handle: &crate::cli::connect_uds::ConnectControlHandle,
    selector: &str,
) -> Result<Option<ConnectionRecord>> {
    match crate::cli::connect_uds::get_connection_record(handle, selector).await {
        Ok(crate::cli::connect_uds::ControlOutcome::Ok(resp)) => Ok(Some(resp.connection)),
        Ok(crate::cli::connect_uds::ControlOutcome::Err { body, .. })
            if body.code == "connection.not_found" =>
        {
            Ok(None)
        }
        Ok(crate::cli::connect_uds::ControlOutcome::Err { status_code, body }) => {
            anyhow::bail!(
                "connection lookup failed (HTTP {status_code}): {}",
                oauth_seal::sanitize_for_terminal(&body.message)
            )
        }
        Ok(crate::cli::connect_uds::ControlOutcome::ParseFailure { status_code, .. }) => {
            anyhow::bail!("connection lookup returned an unparseable response (HTTP {status_code})")
        }
        Err(e) => anyhow::bail!("connection lookup transport error: {e}"),
    }
}

// ── bind ────────────────────────────────────────────────────────────

pub async fn run_bind(args: BindArgs) -> Result<()> {
    use anyhow::Context as _;

    let _guards =
        crate::telemetry::init_tracing("warn", None, 30).context("tracing init failed")?;
    let home = crate::cli::agentsso_home()?;

    // `bind` goes control-plane: the daemon owns the store reads (operator
    // can't read the root-private state dir) AND the optional --policy is
    // checked against the live PolicySet.
    let handle = match crate::cli::connect_uds::require_daemon_running(&home).await {
        Ok(h) => h,
        Err(e) => return Err(e.context("bind: daemon not reachable")),
    };

    // Resolve the connection selector → id via the control plane.
    let Some(connection) = resolve_connection_cp(&handle, &args.connection).await? else {
        eprint!(
            "{}",
            render::error_block(
                "binding.unknown_connection",
                &format!("no connection matching '{}'", args.connection),
                "list connections:  agentsso connection list",
                None,
            )
        );
        return Err(oauth_seal::exit2());
    };

    let req = crate::cli::connect_uds::BindRequest {
        agent: &args.agent,
        connection_id: &connection.id.to_string(),
        tier: &args.grant,
        policy: args.policy.as_deref(),
        alias: args.alias.as_deref(),
    };
    match crate::cli::connect_uds::post_bind(&handle, &req).await {
        Ok(crate::cli::connect_uds::ControlOutcome::Ok(resp)) => {
            println!();
            println!(
                "\u{2713} bound '{}' \u{2192} connection '{}'",
                args.agent, resp.connection_name
            );
            println!("  tier:   {}", resp.tier);
            if let Some(p) = &resp.policy {
                println!("  policy: {p}");
            }
            if let Some(a) = &resp.alias {
                println!("  alias:  {a}  (address it as /mcp/{a})");
            } else {
                println!("  address it as /mcp/{}", resp.connection_name);
            }
            println!();
            Ok(())
        }
        Ok(crate::cli::connect_uds::ControlOutcome::Err { status_code, body }) => {
            let suggested = match body.code.as_str() {
                "binding.duplicate" => "unbind first to change tier/policy/alias",
                "binding.unknown_agent" => {
                    "register the agent first: agentsso agent register <name> --policy <policy>"
                }
                "binding.unknown_connection" => "list connections: agentsso connection list",
                "binding.unknown_policy" => "list policies: agentsso policy list",
                _ => "see message above",
            };
            eprint!(
                "{}",
                render::error_block(
                    &oauth_seal::sanitize_for_terminal(&body.code),
                    &format!(
                        "bind failed (HTTP {status_code}): {}",
                        oauth_seal::sanitize_for_terminal(&body.message)
                    ),
                    suggested,
                    None,
                )
            );
            // Existence failures (`binding.unknown_*`) → exit 2;
            // `binding.duplicate` + `binding.*_failed` → exit 3. The
            // daemon's code drives the mapping via `connection_exit_code`.
            Err(oauth_seal::silent_err_for_code(&body.code, "bind failed"))
        }
        Ok(crate::cli::connect_uds::ControlOutcome::ParseFailure { status_code, .. }) => {
            eprint!(
                "{}",
                render::error_block(
                    "binding.protocol_error",
                    &format!("bind returned an unparseable response (HTTP {status_code})"),
                    "verify the daemon is healthy: agentsso status",
                    None,
                )
            );
            Err(oauth_seal::silent_err_for_code("connection.bind_failed", "bind parse failure"))
        }
        Err(transport_err) => {
            eprint!(
                "{}",
                render::error_block(
                    "binding.daemon_unreachable",
                    &format!("bind transport error: {transport_err}"),
                    "verify the daemon is healthy: agentsso status",
                    None,
                )
            );
            Err(oauth_seal::silent_err_for_code("connection.bind_failed", "bind transport failure"))
        }
    }
}

// ── unbind ──────────────────────────────────────────────────────────

pub async fn run_unbind(args: UnbindArgs) -> Result<()> {
    let home = crate::cli::agentsso_home()?;
    // Story 11.18: connection-resolve + binding removal both go
    // control-plane (the operator can't read/write the root-private state
    // dir). Bearer-immutable: the handler touches only `bindings/<agent>.toml`.
    let handle = match crate::cli::connect_uds::require_daemon_running(&home).await {
        Ok(h) => h,
        Err(e) => return Err(e.context("unbind: daemon not reachable")),
    };
    let Some(connection) = resolve_connection_cp(&handle, &args.connection).await? else {
        eprint!(
            "{}",
            render::error_block(
                "binding.unknown_connection",
                &format!("no connection matching '{}'", args.connection),
                "list connections:  agentsso connection list",
                None,
            )
        );
        return Err(oauth_seal::exit2());
    };

    let req = crate::cli::connect_uds::UnbindRequest {
        agent: &args.agent,
        connection_id: &connection.id.to_string(),
    };
    let removed = match crate::cli::connect_uds::post_unbind(&handle, &req).await {
        Ok(crate::cli::connect_uds::ControlOutcome::Ok(resp)) => resp.removed,
        Ok(crate::cli::connect_uds::ControlOutcome::Err { status_code, body }) => {
            eprint!(
                "{}",
                render::error_block(
                    &oauth_seal::sanitize_for_terminal(&body.code),
                    &format!(
                        "unbind failed (HTTP {status_code}): {}",
                        oauth_seal::sanitize_for_terminal(&body.message)
                    ),
                    "verify the daemon is healthy: agentsso status",
                    None,
                )
            );
            return Err(oauth_seal::silent_err_for_code(
                "connection.unbind_failed",
                "unbind failed",
            ));
        }
        Ok(crate::cli::connect_uds::ControlOutcome::ParseFailure { status_code, .. }) => {
            eprint!(
                "{}",
                render::error_block(
                    "binding.protocol_error",
                    &format!("unbind returned an unparseable response (HTTP {status_code})"),
                    "verify the daemon is healthy: agentsso status",
                    None,
                )
            );
            return Err(oauth_seal::silent_err_for_code(
                "connection.unbind_failed",
                "unbind parse failure",
            ));
        }
        Err(transport_err) => {
            eprint!(
                "{}",
                render::error_block(
                    "binding.daemon_unreachable",
                    &format!("unbind transport error: {transport_err}"),
                    "verify the daemon is healthy: agentsso status",
                    None,
                )
            );
            return Err(oauth_seal::silent_err_for_code(
                "connection.unbind_failed",
                "unbind transport failure",
            ));
        }
    };
    if !removed {
        eprint!(
            "{}",
            render::error_block(
                "binding.not_found",
                &format!("agent '{}' is not bound to connection '{}'", args.agent, connection.name),
                "list the agent's bindings:  agentsso agent bindings <agent>",
                None,
            )
        );
        return Err(oauth_seal::exit2());
    }

    println!();
    println!("\u{2713} unbound '{}' from connection '{}'", args.agent, connection.name);
    println!("  (the agent's bearer token is unchanged)");
    println!();
    Ok(())
}
