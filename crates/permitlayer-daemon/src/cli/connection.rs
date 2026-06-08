//! `agentsso connection add|list|inspect|revoke` (Epic 11, Story 11.13).
//!
//! A **connection** is one upstream account on one connector, identified
//! by a stable ULID. `add` runs the Google OAuth dance and POSTs the
//! tokens to the daemon's seal endpoint under a fresh `ConnectionId`,
//! which seals the three slots (access/refresh/client) and writes the
//! `ConnectionRecord`. `list`/`inspect` read the `ConnectionStore`;
//! `revoke` removes the record, the sealed slots, and every binding that
//! references the connection (so a later `/mcp/<name>` resolves nothing).
//!
//! This supersedes the retired `connect <service> --agent` verb (FR23):
//! creating a credential connection and binding an agent to it are now
//! separate verbs (`connection add` here; `bind` in Story 11.14).

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};

use permitlayer_core::store::connection::{ConnectionRecord, ConnectionStatus, ConnectionTier};
use permitlayer_credential::ConnectionId;

use crate::cli::oauth_seal;
use crate::design::render;

/// Arguments for `agentsso connection <subcommand>`.
#[derive(Args, Debug)]
pub struct ConnectionArgs {
    #[command(subcommand)]
    pub command: ConnectionCommand,
}

#[derive(Subcommand, Debug)]
pub enum ConnectionCommand {
    /// Create a per-account connection: run the OAuth dance and seal a
    /// fresh connection under a new ULID.
    Add(AddArgs),
    /// List every connection (name, connector, account, tier, status).
    List,
    /// Show one connection's full detail incl. granted scopes + the
    /// connector's trust tier.
    Inspect(InspectArgs),
    /// Revoke a connection: remove its record, sealed slots, and every
    /// binding referencing it.
    Revoke(RevokeArgs),
}

#[derive(Args, Debug)]
pub struct AddArgs {
    /// Connector to connect (e.g. `google-gmail`, or the bare `gmail`
    /// alias). Validated against the connector registry (FR89).
    pub connector: String,
    /// Display name / selector for the connection (`/mcp/<name>`).
    /// Defaults to the connector's bare service name.
    #[arg(long)]
    pub name: Option<String>,
    /// Request the connector's read-write tier (default: read tier).
    #[arg(long = "read-write")]
    pub read_write: bool,
    /// Path to a Google OAuth client JSON (BYO client).
    #[arg(long = "oauth-client", value_name = "PATH")]
    pub oauth_client: Option<PathBuf>,
    /// Skip browser launch; print the auth URL and accept a pasted
    /// redirect URL via stdin. Mutually exclusive with `--device-flow`
    /// (the paste flow needs a controlling terminal).
    #[arg(long, conflicts_with = "non_interactive", conflicts_with = "device_flow")]
    pub headless: bool,
    /// Use Google OAuth 2.0 device flow (RFC 8628).
    #[arg(long)]
    pub device_flow: bool,
    /// Device-flow poll timeout (seconds).
    #[arg(long, default_value = "120", requires = "device_flow")]
    pub device_flow_timeout: u64,
    /// Skip all interactive prompts.
    #[arg(long)]
    pub non_interactive: bool,
    /// Allow running from an effective-root shell with SUDO_USER set.
    #[arg(long)]
    pub allow_root: bool,
}

#[derive(Args, Debug)]
pub struct InspectArgs {
    /// Connection name or ULID id.
    pub selector: String,
}

#[derive(Args, Debug)]
pub struct RevokeArgs {
    /// Connection name or ULID id.
    pub selector: String,
}

/// Run the `connection` subcommand.
pub async fn run(args: ConnectionArgs) -> Result<()> {
    match args.command {
        ConnectionCommand::Add(a) => add(a).await,
        ConnectionCommand::List => list().await,
        ConnectionCommand::Inspect(a) => inspect(a).await,
        ConnectionCommand::Revoke(a) => revoke(a).await,
    }
}

// ── add ─────────────────────────────────────────────────────────────

async fn add(args: AddArgs) -> Result<()> {
    use anyhow::Context as _;

    let log_level = "warn";
    let _guards =
        crate::telemetry::init_tracing(log_level, None, 30).context("tracing init failed")?;

    #[cfg(unix)]
    {
        let hint = format!("agentsso connection add {}", args.connector);
        crate::cli::root_guard::ensure_not_sudo_root_shell_with(
            "connection add",
            &hint,
            args.allow_root,
            nix::unistd::geteuid().as_raw(),
            std::env::var("SUDO_USER").ok().as_deref(),
        )?;
    }

    // Validate the connector via the registry (FR89, no closed enum).
    let registry = permitlayer_connectors::ConnectorRegistry::load(Some(
        &permitlayer_core::paths::connectors_dir(
            permitlayer_core::paths::home_override().as_deref(),
        ),
    ))
    .context("connector registry load failed")?;
    let connector = match registry.resolve_selector(&args.connector) {
        Some(c) => c,
        None => {
            let supported = registry.selectors().join(", ");
            eprint!(
                "{}",
                render::error_block(
                    "connection.unknown_connector",
                    &format!("unknown connector '{}'. Supported: {supported}", args.connector),
                    &format!(
                        "agentsso connection add <connector> --name <name>\n\n  supported: {supported}"
                    ),
                    None,
                )
            );
            return Err(oauth_seal::exit2());
        }
    };
    let connector_id = connector.id().to_owned();
    let name = args.name.clone().unwrap_or_else(|| {
        // Default the display name to the bare service selector.
        match connector_id.as_str() {
            "google-gmail" => "gmail",
            "google-calendar" => "calendar",
            "google-drive" => "drive",
            other => other,
        }
        .to_owned()
    });

    let home = crate::cli::agentsso_home()?;

    // Kill-switch gate before any OAuth flow.
    oauth_seal::probe_daemon_kill_state_or_exit().await?;

    // Daemon-reachable gate (the daemon owns the seal/vault writes — and,
    // Story 11.18, the store reads too: the operator can't read the
    // root-private state dir, so the F7 name-check below also goes
    // control-plane).
    let handle = match crate::cli::connect_uds::require_daemon_running(&home).await {
        Ok(h) => h,
        Err(e) => return Err(e.context("connection add: daemon not reachable")),
    };

    // F7 fix: reject a duplicate connection name BEFORE doing any OAuth
    // work. Names are the CLI/`/mcp/<name>` selector; the store keys files
    // on the ULID id and does not enforce name-uniqueness, so two
    // same-named connections would make `inspect`/`bind`/`revoke <name>`
    // resolve nondeterministically (first directory-walk match). Fail fast
    // with an actionable error instead. Resolved daemon-side (Story 11.18).
    match crate::cli::connect_uds::get_connection_record(&handle, &name).await {
        Ok(crate::cli::connect_uds::ControlOutcome::Ok(resp)) => {
            eprint!(
                "{}",
                render::error_block(
                    "connection.duplicate_name",
                    &format!(
                        "a connection named '{name}' already exists (id {}). Connection names \
                         must be unique — they are the `/mcp/<name>` selector.",
                        resp.connection.id
                    ),
                    &format!(
                        "pick a different --name, or inspect/revoke the existing one:\n\n    \
                         agentsso connection inspect {name}\n    \
                         agentsso connection revoke {name}"
                    ),
                    None,
                )
            );
            return Err(oauth_seal::exit2());
        }
        // 404 `connection.not_found` is the happy path here (name is free).
        Ok(crate::cli::connect_uds::ControlOutcome::Err { body, .. })
            if body.code == "connection.not_found" => {}
        // Any other control-plane error or parse/transport failure is a
        // genuine problem — surface it rather than silently proceeding.
        Ok(crate::cli::connect_uds::ControlOutcome::Err { status_code, body }) => {
            eprint!(
                "{}",
                render::error_block(
                    "connection.precheck_failed",
                    &format!(
                        "duplicate-name pre-check failed (HTTP {status_code}): {}",
                        oauth_seal::sanitize_for_terminal(&body.message)
                    ),
                    "verify the daemon is healthy: agentsso status",
                    None,
                )
            );
            return Err(oauth_seal::silent_err_for_code(
                "connection.precheck_failed",
                "name pre-check failed",
            ));
        }
        Ok(crate::cli::connect_uds::ControlOutcome::ParseFailure { status_code, .. }) => {
            eprint!(
                "{}",
                render::error_block(
                    "connection.precheck_failed",
                    &format!(
                        "duplicate-name pre-check returned an unparseable response (HTTP {status_code})"
                    ),
                    "verify the daemon is healthy: agentsso status",
                    None,
                )
            );
            return Err(oauth_seal::silent_err_for_code(
                "connection.precheck_failed",
                "name pre-check parse failure",
            ));
        }
        Err(e) => {
            eprint!(
                "{}",
                render::error_block(
                    "connection.precheck_failed",
                    &format!("duplicate-name pre-check transport error: {e}"),
                    "verify the daemon is healthy: agentsso status",
                    None,
                )
            );
            return Err(oauth_seal::silent_err_for_code(
                "connection.precheck_failed",
                "name pre-check transport failure",
            ));
        }
    }

    let stdout_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let stdin_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
    let interactive = !args.non_interactive && stdin_is_tty && stdout_is_tty;

    let theme = crate::design::theme::Theme::load(&home);
    let oauth_config = oauth_seal::resolve_oauth_client(
        args.oauth_client.as_deref(),
        &connector_id,
        &name,
        &theme,
        interactive,
    )
    .await?;

    // Mint a fresh ULID for this account-scoped connection.
    let connection_id = ConnectionId::generate();

    let record = oauth_seal::oauth_dance_and_seal(
        &handle,
        oauth_seal::OAuthSealInputs {
            connector: &connector,
            connector_id: &connector_id,
            name: &name,
            read_write: args.read_write,
            oauth_config,
            connection_id,
            interactive,
            headless: args.headless,
            device_flow: args.device_flow,
            device_flow_timeout: args.device_flow_timeout,
        },
    )
    .await?;

    let tier_label = match record.tier {
        ConnectionTier::Read => "read",
        ConnectionTier::ReadWrite => "read-write",
    };
    println!();
    println!("\u{2713} connection '{}' created \u{00b7} {}", record.name, record.connector_id);
    println!("  id:      {}", record.id);
    if let Some(hint) = &record.account_hint {
        println!("  account: {hint}");
    }
    println!("  tier:    {tier_label}");

    // Fork 4 / Story 11.12: verify-on-seal via the daemon (the live
    // Google probe needs the daemon's unsealed token; the endpoint keys
    // on the connection id). Best-effort — a verify failure does NOT undo
    // the seal (the credential is durably stored), it only annotates the
    // summary so the operator knows whether the grant actually works.
    let verify_req = crate::cli::connect_uds::CredentialsVerifyRequest::default();
    match crate::cli::connect_uds::post_connection_verify(
        &handle,
        &record.id.to_string(),
        &verify_req,
    )
    .await
    {
        Ok(crate::cli::connect_uds::VerifyOutcome::Body { body, .. }) => {
            if body.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
                let summary = body.get("summary").and_then(|s| s.as_str()).unwrap_or("");
                println!("  verified: {summary}");
            } else {
                let reason = body
                    .get("reason_text")
                    .and_then(|s| s.as_str())
                    .or_else(|| body.get("verify_reason").and_then(|s| s.as_str()))
                    .unwrap_or("verification failed");
                println!(
                    "  warn: connection sealed but verify reported: {}",
                    oauth_seal::sanitize_for_terminal(reason)
                );
            }
        }
        Ok(crate::cli::connect_uds::VerifyOutcome::Err { status_code, body }) => {
            println!(
                "  warn: connection sealed but verify failed (HTTP {status_code}, {}): {}",
                oauth_seal::sanitize_for_terminal(&body.code),
                oauth_seal::sanitize_for_terminal(&body.message)
            );
        }
        Ok(crate::cli::connect_uds::VerifyOutcome::ParseFailure { status_code, .. }) => {
            println!(
                "  warn: connection sealed but verify returned an unparseable response (HTTP {status_code})"
            );
        }
        Err(e) => {
            println!("  warn: connection sealed but verify transport failed: {e}");
        }
    }

    println!();
    // F4 fix: match the real `bind` surface (cli/bind.rs BindArgs) —
    // `connection` is a POSITIONAL and `--grant` is REQUIRED. The prior
    // hint used a nonexistent `--connection` flag + omitted `--grant`, so
    // a copy-paste hit a clap error on the happy path.
    let grant = match record.tier {
        ConnectionTier::ReadWrite => "read-write",
        ConnectionTier::Read => "read",
    };
    println!("  bind an agent to it:  agentsso bind <agent> {} --grant {grant}", record.name);
    println!();
    Ok(())
}

// ── control-plane resolve helper ────────────────────────────────────

/// Resolve a `name | id-text` selector to a `ConnectionRecord` via the
/// daemon control plane (Story 11.18 — the operator can't read the
/// root-private store in-process). `Ok(None)` on a `connection.not_found`
/// 404; any other failure is a hard error rendered to the operator.
async fn resolve_selector_cp(
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

// ── list ────────────────────────────────────────────────────────────

async fn list() -> Result<()> {
    use crate::design::render::{TableCell, table};
    use crate::design::terminal::{ColorSupport, TableLayout};

    let home = crate::cli::agentsso_home()?;
    // Story 11.18: read records via the control plane (daemon runs as root
    // and can read the root-private `connections/` dir).
    let handle = match crate::cli::connect_uds::require_daemon_running(&home).await {
        Ok(h) => h,
        Err(e) => return Err(e.context("connection list: daemon not reachable")),
    };
    let mut connections = match crate::cli::connect_uds::get_connection_records(&handle).await {
        Ok(crate::cli::connect_uds::ControlOutcome::Ok(resp)) => resp.connections,
        Ok(crate::cli::connect_uds::ControlOutcome::Err { status_code, body }) => {
            anyhow::bail!(
                "connection list failed (HTTP {status_code}): {}",
                oauth_seal::sanitize_for_terminal(&body.message)
            )
        }
        Ok(crate::cli::connect_uds::ControlOutcome::ParseFailure { status_code, .. }) => {
            anyhow::bail!("connection list returned an unparseable response (HTTP {status_code})")
        }
        Err(e) => anyhow::bail!("connection list transport error: {e}"),
    };
    connections.sort_by(|a, b| a.name.cmp(&b.name));

    if connections.is_empty() {
        print!(
            "{}",
            render::empty_state(
                "no connections",
                "create one with:  agentsso connection add <connector> --name <name>",
            )
        );
        return Ok(());
    }

    let theme = crate::design::theme::Theme::load(&home);
    let support = ColorSupport::detect();
    let layout = TableLayout::detect();
    let headers = &["NAME", "CONNECTOR", "ACCOUNT", "TIER", "STATUS"];
    let rows: Vec<Vec<TableCell>> = connections
        .iter()
        .map(|r| {
            vec![
                TableCell::Plain(r.name.clone()),
                TableCell::Plain(r.connector_id.clone()),
                TableCell::Plain(r.account_hint.clone().unwrap_or_else(|| "-".to_owned())),
                TableCell::Plain(tier_label(r.tier).to_owned()),
                TableCell::Plain(status_label(r.status).to_owned()),
            ]
        })
        .collect();
    match table(headers, &rows, layout, &theme, support) {
        Ok(rendered) => print!("{rendered}"),
        Err(e) => {
            tracing::error!(error = %e, "connection list table render failed");
            anyhow::bail!("failed to render connection list: {e}");
        }
    }
    Ok(())
}

// ── inspect ─────────────────────────────────────────────────────────

async fn inspect(args: InspectArgs) -> Result<()> {
    let home = crate::cli::agentsso_home()?;
    let handle = match crate::cli::connect_uds::require_daemon_running(&home).await {
        Ok(h) => h,
        Err(e) => return Err(e.context("connection inspect: daemon not reachable")),
    };
    let Some(record) = resolve_selector_cp(&handle, &args.selector).await? else {
        eprint!(
            "{}",
            render::error_block(
                "connection.not_found",
                &format!("no connection matching '{}'", args.selector),
                "list connections:  agentsso connection list",
                None,
            )
        );
        return Err(oauth_seal::exit2());
    };

    // Trust tier (NFR53) comes from the connector registry.
    let trust_tier = permitlayer_connectors::ConnectorRegistry::load(Some(
        &permitlayer_core::paths::connectors_dir(
            permitlayer_core::paths::home_override().as_deref(),
        ),
    ))
    .ok()
    .and_then(|r| r.get(&record.connector_id).map(|c| format!("{:?}", c.trust_tier())))
    .unwrap_or_else(|| "unknown".to_owned());

    println!("connection {}", record.id);
    println!("  name:        {}", record.name);
    println!("  connector:   {}", record.connector_id);
    println!("  trust_tier:  {trust_tier}");
    println!("  account:     {}", record.account_hint.as_deref().unwrap_or("-"));
    println!("  tier:        {}", tier_label(record.tier));
    println!("  status:      {}", status_label(record.status));
    println!("  created_at:  {}", record.created_at.to_rfc3339());
    if record.granted_scopes.is_empty() {
        println!("  scopes:      (none)");
    } else {
        println!("  scopes:");
        for s in &record.granted_scopes {
            println!("    - {s}");
        }
    }
    Ok(())
}

// ── revoke ──────────────────────────────────────────────────────────

async fn revoke(args: RevokeArgs) -> Result<()> {
    let home = crate::cli::agentsso_home()?;
    // Story 11.18: the cascade (record + 3 sealed slots + every binding)
    // runs daemon-side (the operator can't write the root-private stores).
    let handle = match crate::cli::connect_uds::require_daemon_running(&home).await {
        Ok(h) => h,
        Err(e) => return Err(e.context("connection revoke: daemon not reachable")),
    };
    match crate::cli::connect_uds::post_revoke_connection(&handle, &args.selector).await {
        Ok(crate::cli::connect_uds::ControlOutcome::Ok(resp)) => {
            println!();
            println!("\u{2713} connection '{}' revoked", resp.connection_name);
            println!(
                "  sealed credential slots removed, {} binding(s) detached",
                resp.bindings_removed
            );
            println!();
            Ok(())
        }
        Ok(crate::cli::connect_uds::ControlOutcome::Err { body, .. })
            if body.code == "connection.not_found" =>
        {
            eprint!(
                "{}",
                render::error_block(
                    "connection.not_found",
                    &format!("no connection matching '{}'", args.selector),
                    "list connections:  agentsso connection list",
                    None,
                )
            );
            Err(oauth_seal::exit2())
        }
        Ok(crate::cli::connect_uds::ControlOutcome::Err { status_code, body }) => {
            eprint!(
                "{}",
                render::error_block(
                    &oauth_seal::sanitize_for_terminal(&body.code),
                    &format!(
                        "connection revoke failed (HTTP {status_code}): {}",
                        oauth_seal::sanitize_for_terminal(&body.message)
                    ),
                    "verify the daemon is healthy: agentsso status",
                    None,
                )
            );
            Err(oauth_seal::silent_err_for_code("connection.revoke_failed", "revoke failed"))
        }
        Ok(crate::cli::connect_uds::ControlOutcome::ParseFailure { status_code, .. }) => {
            eprint!(
                "{}",
                render::error_block(
                    "connection.revoke_failed",
                    &format!(
                        "connection revoke returned an unparseable response (HTTP {status_code})"
                    ),
                    "verify the daemon is healthy: agentsso status",
                    None,
                )
            );
            Err(oauth_seal::silent_err_for_code("connection.revoke_failed", "revoke parse failure"))
        }
        Err(e) => {
            eprint!(
                "{}",
                render::error_block(
                    "connection.revoke_failed",
                    &format!("connection revoke transport error: {e}"),
                    "verify the daemon is healthy: agentsso status",
                    None,
                )
            );
            Err(oauth_seal::silent_err_for_code(
                "connection.revoke_failed",
                "revoke transport failure",
            ))
        }
    }
}

// ── label helpers ───────────────────────────────────────────────────

fn tier_label(tier: ConnectionTier) -> &'static str {
    match tier {
        ConnectionTier::Read => "read",
        ConnectionTier::ReadWrite => "read-write",
    }
}

fn status_label(status: ConnectionStatus) -> &'static str {
    match status {
        ConnectionStatus::Active => "active",
        ConnectionStatus::Revoked => "revoked",
    }
}
