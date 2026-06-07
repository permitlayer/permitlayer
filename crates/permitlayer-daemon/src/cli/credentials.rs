//! `agentsso credentials list|status|refresh` — display and manage connected
//! service credentials.
//!
//! `list` reads provenance metadata files (`*-meta.json`) from the vault
//! directory and displays them as a table. Does NOT unseal or decrypt anything.
//!
//! `status` shows token validity, time-until-expiry, last refresh timestamp,
//! and scopes per connected service.
//!
//! `refresh` (Story 1.14b AC 4) is an operator escape hatch that performs a
//! single OAuth token refresh for a specific service on demand. Calls the
//! same shared refresh core (`permitlayer_proxy::refresh_flow`) as the
//! proxy's reactive refresh path, so the two code paths emit identical
//! audit-event outcomes.

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Args, Subcommand};
use permitlayer_oauth::metadata::CredentialMeta;

use crate::design::format::format_timestamp;
use crate::design::render::{self, TableCell, table};
use crate::design::terminal::{ColorSupport, TableLayout, styled};
use crate::design::theme::Theme;

/// Story 1.14b code-review m8 fix: distinct CLI exit codes so shell
/// scripts wrapping `agentsso credentials refresh` can branch on the
/// failure category instead of parsing error-block text.
///
/// - `BUG` (1): real bug in permitlayer or unrecoverable internal
///   state. Operator should report it.
/// - `MISCONFIG` (2): user-actionable misconfiguration (no setup,
///   wrong service name, revoked credentials, missing meta file).
///   Shell scripts retry these only after operator intervention.
/// - `TRANSIENT` (75, the BSD `EX_TEMPFAIL` convention): network
///   issue, OAuth provider 5xx, exhaustion. Shell scripts can retry
///   these on a backoff.
mod cli_exit {
    pub const BUG: i32 = 1;
    pub const MISCONFIG: i32 = 2;
    pub const TRANSIENT: i32 = 75;
}

// ── Story 7.6c: typed exit-code marker for the daemon-running
// pre-flight on `credentials refresh` ──────────────────────────────
//
// Same shape as `ConnectExitCode3` in `cli::connect` and
// `RotateKeyExitCode3` in `cli::rotate_key`. Mirrors the typed-marker
// pattern so `main.rs::credentials_refresh_to_exit_code` can downcast
// the chain. Note this marker uses exit code 3 (resource conflict) —
// distinct from the `cli_exit::{BUG, MISCONFIG, TRANSIENT}` codes
// above, which classify *post-refusal* failures during the actual
// refresh flow. The daemon-running refusal is a pre-flight that
// fires before any flow runs.

/// Exit-code 3 marker — resource conflict (daemon running and
/// holding the vault flock; refresh would block indefinitely on
/// `acquire()`).
#[derive(Debug)]
pub(crate) struct CredentialsRefreshExitCode3;

impl std::fmt::Display for CredentialsRefreshExitCode3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("credentials refresh: resource conflict")
    }
}

impl std::error::Error for CredentialsRefreshExitCode3 {}

pub(crate) fn refresh_exit3() -> anyhow::Error {
    anyhow::Error::new(CredentialsRefreshExitCode3).context(crate::cli::SilentCliError)
}

/// Arguments for `agentsso credentials <subcommand>`.
#[derive(Args)]
pub struct CredentialsArgs {
    #[command(subcommand)]
    pub command: CredentialsCommand,
}

/// Available credentials subcommands.
#[derive(Subcommand)]
pub enum CredentialsCommand {
    /// List connected service credentials.
    List,
    /// Show current token validity and scopes for each service.
    Status,
    /// Refresh the OAuth access token for a specific service on demand.
    ///
    /// Use this when you want to pre-refresh a credential before a
    /// long-running job, or to unblock an incident where you suspect
    /// the access token is stale. Do not run while the daemon is
    /// active — credential store and audit log writes may interleave
    /// with the running proxy.
    Refresh(RefreshArgs),
}

/// Arguments for `agentsso credentials refresh <service>`.
#[derive(Args)]
pub struct RefreshArgs {
    /// Service to refresh (`gmail`, `calendar`, or `drive`).
    pub service: String,
}

/// Run the `credentials` subcommand.
pub async fn run(args: CredentialsArgs) -> anyhow::Result<()> {
    match args.command {
        CredentialsCommand::List => list_credentials(),
        CredentialsCommand::Status => status_credentials(),
        CredentialsCommand::Refresh(refresh_args) => refresh_credentials(refresh_args).await,
    }
}

/// List all connected service credentials from metadata files.
fn list_credentials() -> anyhow::Result<()> {
    let vault_dir = vault_dir()?;

    if !vault_dir.exists() {
        print!(
            "{}",
            render::empty_state("no connected services", "connect with:  agentsso setup <service>",)
        );
        return Ok(());
    }

    let mut entries = Vec::new();

    let dir = std::fs::read_dir(&vault_dir)?;
    for entry in dir {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if !name_str.ends_with("-meta.json") {
            continue;
        }

        // Extract service name: "gmail-meta.json" → "gmail"
        let service = name_str.strip_suffix("-meta.json").unwrap_or(&name_str).to_owned();

        match std::fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<CredentialMeta>(&contents) {
                Ok(meta) => entries.push((service, meta)),
                Err(e) => {
                    eprintln!("warning: could not parse {}: {e}", path.display());
                }
            },
            Err(e) => {
                eprintln!("warning: could not read {}: {e}", path.display());
            }
        }
    }

    if entries.is_empty() {
        print!(
            "{}",
            render::empty_state("no connected services", "connect with:  agentsso setup <service>",)
        );
        return Ok(());
    }

    // Sort by service name for consistent output.
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let home = super::agentsso_home().unwrap_or_else(|_| PathBuf::from(".agentsso"));
    let theme = Theme::load(&home);
    let support = ColorSupport::detect();
    let layout = TableLayout::detect();

    let headers = &["SERVICE", "CLIENT TYPE", "SCOPES", "CONNECTED"];
    let rows: Vec<Vec<TableCell>> = entries
        .iter()
        .map(|(service, meta)| {
            let client_type_display = match (meta.client_type.as_str(), &meta.client_source) {
                ("byo", Some(source)) => format!("byo ({source})"),
                (t, _) => t.to_owned(),
            };
            let scopes_display = meta
                .scopes
                .iter()
                .map(|s| s.strip_prefix("https://www.googleapis.com/auth/").unwrap_or(s))
                .collect::<Vec<_>>()
                .join(", ");
            let connected_str =
                if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&meta.connected_at) {
                    format_timestamp(ts.with_timezone(&chrono::Utc))
                } else {
                    meta.connected_at.clone()
                };
            vec![
                TableCell::Plain(service.clone()),
                TableCell::Plain(client_type_display),
                TableCell::Plain(scopes_display),
                TableCell::Plain(connected_str),
            ]
        })
        .collect();

    match table(headers, &rows, layout, &theme, support) {
        Ok(rendered) => print!("{rendered}"),
        Err(e) => {
            tracing::warn!(error = %e, "table render failed — falling back to plain output");
            println!("{:<12}{:<24}{:<44}CONNECTED", "SERVICE", "CLIENT TYPE", "SCOPES");
            for (service, meta) in &entries {
                let client_type_display = match (meta.client_type.as_str(), &meta.client_source) {
                    ("byo", Some(source)) => format!("byo ({source})"),
                    (t, _) => t.to_owned(),
                };
                let scopes_display = meta
                    .scopes
                    .iter()
                    .map(|s| s.strip_prefix("https://www.googleapis.com/auth/").unwrap_or(s))
                    .collect::<Vec<_>>()
                    .join(", ");
                let connected_str =
                    if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&meta.connected_at) {
                        format_timestamp(ts.with_timezone(&chrono::Utc))
                    } else {
                        meta.connected_at.clone()
                    };
                println!(
                    "{:<12}{:<24}{:<44}{}",
                    service, client_type_display, scopes_display, connected_str
                );
            }
        }
    }

    Ok(())
}

/// Show current token validity, time-until-expiry, last refresh, and scopes.
fn status_credentials() -> anyhow::Result<()> {
    let vault_dir = vault_dir()?;

    if !vault_dir.exists() {
        print!(
            "{}",
            render::empty_state("no connected services", "connect with:  agentsso setup <service>",)
        );
        return Ok(());
    }

    let mut entries = Vec::new();

    let dir = std::fs::read_dir(&vault_dir)?;
    for entry in dir {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if !name_str.ends_with("-meta.json") {
            continue;
        }

        let service = name_str.strip_suffix("-meta.json").unwrap_or(&name_str).to_owned();

        let path = entry.path();
        match std::fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<CredentialMeta>(&contents) {
                Ok(meta) => entries.push((service, meta)),
                Err(e) => {
                    eprintln!("warning: could not parse {}: {e}", path.display());
                }
            },
            Err(e) => {
                eprintln!("warning: could not read {}: {e}", path.display());
            }
        }
    }

    if entries.is_empty() {
        print!(
            "{}",
            render::empty_state("no connected services", "connect with:  agentsso setup <service>",)
        );
        return Ok(());
    }

    entries.sort_by(|a, b| a.0.cmp(&b.0));

    // Render through the shared `render::table()` pipeline (the same one
    // `credentials list` uses) so `status` shares the one CLI table
    // idiom — TTY/NO_COLOR-aware, width-adaptive — instead of the old
    // hand-rolled per-credential `println!` column block.
    let home = super::agentsso_home().unwrap_or_else(|_| PathBuf::from(".agentsso"));
    let theme = Theme::load(&home);
    let support = ColorSupport::detect();
    let layout = TableLayout::detect();

    let headers = &["SERVICE", "TOKEN", "CONNECTED", "LAST REFRESH", "SCOPES"];
    let rows: Vec<Vec<TableCell>> = entries
        .iter()
        .map(|(service, meta)| {
            let (validity, time_remaining) = compute_token_validity(meta);
            // Story 1.14b Task 5a: the value has always been
            // `connected_at` (the setup timestamp) — the column header
            // matches the field semantics.
            let connected = if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&meta.connected_at)
            {
                format_timestamp(ts.with_timezone(&chrono::Utc))
            } else {
                meta.connected_at.clone()
            };
            // Story 1.14b Task 5b: "last refresh" is `None` until the
            // refresh flow has updated the meta file. In the old layout
            // the line was omitted entirely; as a table column we render
            // an em-dash placeholder so the column stays aligned.
            let last_refresh: String = meta
                .last_refreshed_at
                .as_ref()
                .map(|raw| {
                    if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(raw) {
                        format_timestamp(ts.with_timezone(&chrono::Utc))
                    } else {
                        raw.clone()
                    }
                })
                .unwrap_or_else(|| "\u{2014}".to_owned());
            let scopes_display = meta
                .scopes
                .iter()
                .map(|s| s.strip_prefix("https://www.googleapis.com/auth/").unwrap_or(s))
                .collect::<Vec<_>>()
                .join(", ");

            vec![
                TableCell::Plain(service.clone()),
                TableCell::Plain(format!("{validity}{time_remaining}")),
                TableCell::Plain(connected),
                TableCell::Plain(last_refresh),
                TableCell::Plain(scopes_display),
            ]
        })
        .collect();

    match table(headers, &rows, layout, &theme, support) {
        Ok(rendered) => print!("{rendered}"),
        Err(e) => {
            tracing::warn!(error = %e, "table render failed — falling back to plain output");
            for row in &rows {
                let cells: Vec<String> = row
                    .iter()
                    .map(|c| match c {
                        TableCell::Plain(s) => s.clone(),
                        other => format!("{other:?}"),
                    })
                    .collect();
                println!("{}", cells.join("  "));
            }
        }
    }

    Ok(())
}

/// Story 1.14b AC 4: `agentsso credentials refresh <service>`.
///
/// Operator escape hatch that performs a single OAuth token refresh
/// for `service` on demand. Calls the shared refresh core
/// (`permitlayer_proxy::refresh_flow::refresh_service`) so the CLI
/// and the proxy emit identical audit outcomes — neither path has
/// its own inline refresh state machine.
///
/// ## Concurrency note (Story 1.14b AC 4, decision 6b)
///
/// This subcommand writes directly to the filesystem credential
/// store and audit log. If `agentsso start` is running in another
/// process, those writes race with the daemon's. `AuditFsStore`
/// rotation logic is NOT process-safe. We deliberately do NOT detect
/// a running daemon — pidfile probing adds failure modes for
/// marginal safety. Instead, we print a warning at startup so the
/// operator understands the risk. A future story can add RPC-through-
/// daemon semantics if the concurrency becomes a real problem.
///
/// ## Audit event field conventions (AC 5)
///
/// CLI-emitted `token-refresh` audit events use these fixed
/// conventions, consistent with the proxy path except where the
/// CLI lacks a meaningful value:
///
/// - `request_id` — freshly-generated ULID per invocation
/// - `agent_id` — literal `"cli"`
/// - `service` — the user-supplied service name
/// - `scope` — literal `""` (operator actions are not scope-bound)
/// - `resource` — literal `"credentials-refresh"` (marks the event
///   as operator-initiated, not API-call-adjacent)
async fn refresh_credentials(args: RefreshArgs) -> anyhow::Result<()> {
    use std::io::Write;

    use permitlayer_core::store::CredentialStore;
    use permitlayer_core::store::fs::{AuditFsStore, CredentialFsStore};
    use permitlayer_proxy::refresh_flow::{self, RefreshFlowError, RefreshOutcome};
    use permitlayer_vault::Vault;

    // ── Story 7.6c: daemon-running pre-flight ──────────────────────
    //
    // `credentials refresh` rewrites the on-disk vault entry. Running
    // it concurrent with a live daemon would race against the
    // daemon's in-memory token cache: the daemon would continue
    // serving requests with the pre-refresh token until restart,
    // and the dual-writer pattern can produce torn-state windows
    // for downstream readers. Refusing here keeps the operator on
    // the documented `stop → refresh → start` sequence.
    //
    // Replaces the old soft `eprintln!` warning ("do not run while
    // daemon is active") with a structured refusal. Mirrors
    // `cli::connect::run`'s Step 2 daemon-running gate and
    // `cli::rotate_key::run` Pre-flight 2 verbatim.
    //
    // Pre-flight runs BEFORE the audit-store carve-out below so a
    // refused-to-run refresh does not emit audit events for an action
    // that did not happen.
    let preflight_home = super::agentsso_home()?;
    let daemon_running = crate::lifecycle::pid::PidFile::is_daemon_running(&preflight_home)
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "PID-file probe failed; treating daemon as running for safety");
            true
        });
    if daemon_running {
        let pid_hint = match crate::lifecycle::pid::PidFile::read(&preflight_home) {
            Ok(Some(pid)) => format!(" (PID {pid})"),
            _ => String::new(),
        };
        eprint!(
            "{}",
            render::error_block(
                "credentials_refresh_daemon_running",
                &format!(
                    "agentsso daemon is running{pid_hint}; credentials refresh rewrites \
                     the vault entry and must not race against a live daemon's token cache."
                ),
                "agentsso stop && agentsso credentials refresh <service>",
                None,
            )
        );
        return Err(refresh_exit3());
    }

    // ── Phase 1: Pre-audit-store carve-out ─────────────────────────
    //
    // Story 1.14b code-review M3: the three failures below CANNOT
    // emit audit events because the audit store cannot exist yet:
    //
    // 1. `validate_service_name` — runs before any I/O. Cheap
    //    rejection of path-traversal / suffix-injection attempts.
    // 2. `agentsso_home()` — needed to find the audit dir itself.
    // 3. `ScrubEngine::new` — required by `AuditFsStore` constructor.
    //
    // These three failures are documented in AC 5 as "infra-not-yet-
    // initialized" exceptions. They are rare (typo, missing $HOME,
    // built-in scrub rules failing to compile = code bug) and the
    // operator sees the error block on stderr regardless. Every
    // failure AFTER `audit_store` is built MUST audit-emit.

    // Validate the service name before touching anything. Rejects
    // path traversal, suffix injection, etc. — same validator the
    // proxy uses on incoming requests.
    if let Err(e) = permitlayer_core::store::validate_service_name(&args.service) {
        eprint!(
            "{}",
            render::error_block(
                "invalid_service",
                &format!("invalid service name: {e}"),
                "agentsso credentials refresh <gmail|calendar|drive>",
                None,
            )
        );
        // m8: typo / bad input is misconfiguration, not a bug.
        std::process::exit(cli_exit::MISCONFIG);
    }
    let service = args.service;

    let home = super::agentsso_home()?;

    let scrub_engine = Arc::new(
        permitlayer_core::scrub::ScrubEngine::new(
            permitlayer_core::scrub::builtin_rules().to_vec(),
        )
        .map_err(|e| anyhow::anyhow!("scrub engine construction failed: {e}"))?,
    );

    // ── Phase 2: Build the audit store ─────────────────────────────
    //
    // Every subsequent failure can now audit-emit. This is the M3
    // pivot point — failures BEFORE this line are pre-audit, after
    // this line are post-audit.

    let audit_dir = home.join("audit");
    let audit_store: Arc<dyn permitlayer_core::store::AuditStore> = Arc::new(
        AuditFsStore::new(audit_dir, 100_000_000, Arc::clone(&scrub_engine))
            .map_err(|e| anyhow::anyhow!("audit store creation failed: {e}"))?,
    );

    // 6c: Construct the audit context for CLI events. Generated
    // BEFORE Phase 3 so every post-audit-store failure can emit a
    // correlated event.
    let request_id = ulid::Ulid::new().to_string();
    let agent_id = "cli";
    let scope = "";
    let resource = "credentials-refresh";

    // ── Phase 3: Vault + credential store + keystore ───────────────
    //
    // Each failure below audit-emits before exiting. The audit store
    // exists; failures here are visible in `agentsso audit --follow`.
    // The audit-emit-then-exit pattern is inlined rather than
    // factored into a helper because Rust closures that capture
    // `audit_store: Arc<dyn AuditStore>` by reference and produce a
    // `Send + 'a` future are awkward to express; the inline form
    // compiles cleanly and is easier to follow.

    let vault_dir = home.join("vault");
    if !vault_dir.exists() {
        emit_cli_token_refresh_audit(
            audit_store.as_ref(),
            &request_id,
            agent_id,
            &service,
            scope,
            resource,
            "no_vault",
            None,
        )
        .await;
        eprint!(
            "{}",
            render::error_block(
                "no_vault",
                "vault directory does not exist — nothing to refresh",
                &format!("agentsso setup {service}"),
                None,
            )
        );
        // m8: no vault is misconfiguration. m2: explicit Drop.
        drop(audit_store);
        std::process::exit(cli_exit::MISCONFIG);
    }

    // Story 7.6c: the prior soft eprintln warning ("do not run while
    // daemon is active") is now superseded by the structured
    // `credentials_refresh_daemon_running` refusal at the top of this
    // function. The warning was a contract; the refusal is enforcement.
    // The vault_dir.exists() carve-out (Story 1.14b code-review n8) is
    // moot because the refusal also fires before vault checks.

    // Keystore → master key → vault.
    let keystore_config = permitlayer_keystore::KeystoreConfig {
        fallback: permitlayer_keystore::FallbackMode::Auto,
        home: home.clone(),
    };
    let keystore = match permitlayer_keystore::default_keystore(&keystore_config) {
        Ok(k) => k,
        Err(e) => {
            emit_cli_token_refresh_audit(
                audit_store.as_ref(),
                &request_id,
                agent_id,
                &service,
                scope,
                resource,
                "keystore_unavailable",
                None,
            )
            .await;
            eprint!(
                "{}",
                render::error_block(
                    "keystore_unavailable",
                    &format!("keystore unavailable (cannot refresh without master key): {e}"),
                    "check OS keychain access or run: agentsso setup <service>",
                    None,
                )
            );
            // m8: locked keychain or missing keystore is
            // misconfiguration (operator needs to unlock or run
            // setup), not a permitlayer bug. m2: explicit Drop.
            drop(audit_store);
            std::process::exit(cli_exit::MISCONFIG);
        }
    };
    let master_key = match keystore.master_key().await {
        Ok(outcome) => outcome.key.into_inner(),
        Err(e) => {
            emit_cli_token_refresh_audit(
                audit_store.as_ref(),
                &request_id,
                agent_id,
                &service,
                scope,
                resource,
                "keystore_unavailable",
                None,
            )
            .await;
            eprint!(
                "{}",
                render::error_block(
                    "keystore_unavailable",
                    &format!("master key unavailable: {e}"),
                    "check OS keychain access or run: agentsso setup <service>",
                    None,
                )
            );
            drop(audit_store);
            std::process::exit(cli_exit::MISCONFIG);
        }
    };

    // Credential store.
    let credential_store: Arc<dyn CredentialStore> = match CredentialFsStore::new(home.clone()) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            emit_cli_token_refresh_audit(
                audit_store.as_ref(),
                &request_id,
                agent_id,
                &service,
                scope,
                resource,
                "store_unavailable",
                None,
            )
            .await;
            eprint!(
                "{}",
                render::error_block(
                    "store_unavailable",
                    &format!("credential store unavailable: {e}"),
                    "check vault directory permissions",
                    None,
                )
            );
            // m8: store creation failure could be permissions
            // (misconfig) or a real bug. Default to BUG so
            // operator investigates — they can override with
            // chmod or whatever the actual cause is.
            drop(audit_store);
            std::process::exit(cli_exit::BUG);
        }
    };
    // Story 7.6a: read the vault's active key_id rather than
    // hardcoding 0. In single-key worlds this is still 0; once 7.6b
    // ships rotation, CLI-side seal sites must stamp the same key_id
    // the daemon writes with, otherwise re-sealed credentials would
    // silently downgrade rotation tracking.
    let active_key_id = super::start::compute_active_key_id(&home.join("vault"));
    let vault = Arc::new(Vault::new(master_key, active_key_id));

    // Flush any buffered stderr before proceeding so the warning is
    // visible even if the refresh itself panics (it won't, but
    // defensive).
    let _ = std::io::stderr().flush();

    // Build the OAuth client resolver closure. The CLI path always
    // uses the production metadata-read path — there's no
    // `oauth_client_overrides` analogue for the CLI because the CLI
    // has no integration-test seam (yet).
    //
    // The resolver reads `{vault_dir}/{service}-meta.json`, dispatches
    // on `client_type`, and constructs a fresh `OAuthClient`. Same
    // logic as `ProxyService::build_oauth_client_for_service` but
    // inlined here to avoid a cross-crate public API surface.
    // Story 1.14b code-review n4 fix: pass the resolver as an
    // unboxed stack closure (matching the proxy's `try_refresh_and_retry`
    // call site at `service.rs::try_refresh_and_retry`). The previous
    // version used `Box<OAuthClientResolver<'_>>` + `&*resolver`,
    // which compiled but was an opaque type annotation and didn't
    // match the proxy's call shape. The shared core takes
    // `&OAuthClientResolver<'_>` = `&dyn Fn + Send + Sync`, and
    // Rust auto-coerces `&impl Fn` into that.
    let vault_dir_for_resolver = vault_dir.clone();
    // Story 7.35: the resolver now unseals the `{service}-client` bundle
    // via the vault instead of re-reading a plaintext client JSON path,
    // so it needs the vault.
    let vault_for_resolver = Arc::clone(&vault);
    let resolver = move |svc: &str| {
        build_oauth_client_for_cli(&vault_for_resolver, &vault_dir_for_resolver, svc)
            .map_err(|detail| RefreshFlowError::MetaInvalid { service: svc.to_owned(), detail })
    };

    // ── Phase 4: Call the shared refresh core ──────────────────────
    //
    // The audit context (request_id, agent_id, scope, resource) was
    // built in Phase 2 above so the post-audit-store failure handlers
    // could reuse it. Every outcome below — success, skipped, all
    // RefreshFlowError variants — emits a token-refresh audit event
    // with the same context, matching the proxy path's audit shape.
    let flow_result =
        refresh_flow::refresh_service(&vault, &credential_store, &vault_dir, &service, &resolver)
            .await;

    // Emit the corresponding audit event and render output. The
    // `emit_cli_token_refresh_audit` helper below encapsulates the
    // manual `AuditEvent` construction — we can't use the proxy's
    // `write_audit` helper because it lives on `ProxyService`, and
    // `emit_persistence_failed_audit` is private to the proxy crate.
    //
    // Story 1.14b code-review m9 fix: success output now uses the
    // theme/render pipeline (`Theme::load` + `styled`) instead of
    // hardcoded ANSI bytes, matching `setup.rs`. Themes apply
    // correctly and color-disabled terminals (NO_COLOR, dumb TTY)
    // get plain text.
    let theme = Theme::load(&home);
    let color_support = ColorSupport::detect();

    match flow_result {
        Ok(outcome @ RefreshOutcome::Refreshed { .. }) => {
            // m6 fix: read the audit-outcome string from the helper
            // rather than hand-typing "success".
            let audit_outcome = outcome.audit_outcome();
            // Destructure for the per-field display logic. We
            // shadow `outcome` since we own it and don't need it
            // again as a whole.
            let RefreshOutcome::Refreshed {
                rotated,
                new_access_bytes: _,
                new_expiry_at,
                last_refreshed_at,
            } = outcome
            else {
                unreachable!("matched on Refreshed pattern above")
            };

            emit_cli_token_refresh_audit(
                audit_store.as_ref(),
                &request_id,
                agent_id,
                &service,
                scope,
                resource,
                audit_outcome,
                Some(serde_json::json!({ "refresh_token_rotated": rotated })),
            )
            .await;

            // m9: themed success output. Mirrors the checkmark idiom
            // used by `setup.rs` for "tokens sealed" success.
            let check = styled("\u{2713}", theme.tokens().accent, color_support);
            let styled_service = styled(&service, theme.tokens().accent, color_support);
            println!("  {check}  {styled_service}  refreshed");

            // m1 fix: use the exact `last_refreshed_at` the meta
            // file was written with (not a fresh `Utc::now()` here,
            // which would drift from the persisted value). If the
            // meta write failed (`last_refreshed_at == None`),
            // surface that explicitly rather than print a
            // misleading value — `agentsso credentials status`
            // will show the OLD timestamp anyway.
            if let Some(persisted) = last_refreshed_at {
                println!("     last refresh: {}", format_timestamp(persisted));
            } else {
                println!(
                    "     last refresh: (meta file write failed — see daemon logs; \
                     `agentsso credentials status` will show stale value)"
                );
            }
            if let Some(expiry) = new_expiry_at {
                println!("     expires at:   {}", format_timestamp(expiry));
            }
            if rotated {
                println!("     note: refresh token also rotated");
            }
            Ok(())
        }
        Ok(outcome @ RefreshOutcome::Skipped) => {
            // m6: outcome string from the helper.
            let audit_outcome = outcome.audit_outcome();
            emit_cli_token_refresh_audit(
                audit_store.as_ref(),
                &request_id,
                agent_id,
                &service,
                scope,
                resource,
                audit_outcome,
                None,
            )
            .await;
            eprint!(
                "{}",
                render::error_block(
                    "no_refresh_token",
                    &format!("no refresh token stored for '{service}' — cannot refresh on demand"),
                    &format!("agentsso setup {service}"),
                    None,
                )
            );
            // m8: missing refresh token is misconfiguration (operator
            // needs to run setup), not a bug.
            //
            // m2: drop the audit_store explicitly before exiting so
            // any pending background work can complete. Today
            // AuditFsStore::append is fully synchronous so this is
            // defense in depth, but it costs nothing and protects
            // against future refactors that might add buffering.
            drop(audit_store);
            std::process::exit(cli_exit::MISCONFIG);
        }
        Err(err) => {
            // Match the proxy's error handling: emit stage-aware
            // audit event for PersistenceFailed, plain audit for all
            // others, then map via the shared `From` impl.
            let outcome = err.audit_outcome();
            let extra = match &err {
                RefreshFlowError::PersistenceFailed { stage, .. } => {
                    Some(serde_json::json!({ "stage": stage.as_str() }))
                }
                _ => None,
            };
            emit_cli_token_refresh_audit(
                audit_store.as_ref(),
                &request_id,
                agent_id,
                &service,
                scope,
                resource,
                outcome,
                extra,
            )
            .await;

            // Render a user-facing error block with a variant-specific
            // remediation. Error message details come from the shared
            // core's `Display` impl (thiserror). Story 1.14b
            // code-review m8 fix: exit code now varies by failure
            // category (BUG / MISCONFIG / TRANSIENT) so wrapping
            // shell scripts can branch on it.
            let (code, remediation, exit_code) = cli_error_code_and_remediation(&err);
            eprint!("{}", render::error_block(code, &format!("{err}"), &remediation, None));
            // m2: explicit Drop before exit (see Skipped arm note).
            drop(audit_store);
            std::process::exit(exit_code);
        }
    }
}

/// Build an `OAuthClient` for a service by reading its metadata file.
///
/// Inlined copy of `ProxyService::build_oauth_client_for_service`
/// without the `oauth_client_overrides` test seam (the CLI has no
/// integration-test harness that needs to inject mock OAuth clients
/// yet). Returns `Err(String)` with a human-readable detail so the
/// caller can wrap it in `RefreshFlowError::MetaInvalid`.
///
/// `pub(crate)` so the control-plane verify handler's 401 self-heal
/// (`server::control::try_self_heal_refresh`) can build the same
/// production resolver the CLI `credentials refresh` path uses.
pub(crate) fn build_oauth_client_for_cli(
    vault: &permitlayer_vault::Vault,
    vault_dir: &std::path::Path,
    service: &str,
) -> Result<Arc<permitlayer_oauth::OAuthClient>, String> {
    use permitlayer_oauth::{GoogleOAuthConfig, OAuthClient};

    let meta_path = vault_dir.join(format!("{service}-meta.json"));
    let meta_contents = std::fs::read_to_string(&meta_path).map_err(|e| {
        format!("could not read metadata for service '{service}' at {}: {e}", meta_path.display())
    })?;
    let meta: CredentialMeta = serde_json::from_str(&meta_contents).map_err(|e| {
        format!("malformed metadata for service '{service}' at {}: {e}", meta_path.display())
    })?;

    let config = match meta.client_type.as_str() {
        "shared-casa" => {
            return Err(format!(
                "metadata for service '{service}' was stored against the removed shared-casa client; re-run `agentsso setup {service} --oauth-client <path>` to migrate"
            ));
        }
        "byo" => {
            // Story 7.35: parity with `ProxyService::build_oauth_client_for_service`.
            // Sealed bundle only; legacy path-based records are rejected
            // with an actionable re-connect message (no plaintext re-read).
            if !meta.client_sealed {
                return Err(format!(
                    "OAuth client for service '{service}' is not sealed (legacy/path-based record). \
                     Re-run: agentsso connect {service} --agent <agent> --oauth-client <path/to/client_secret.json>"
                ));
            }
            let client_service = format!("{service}-client");
            let sealed_path = vault_dir.join(format!("{client_service}.sealed"));
            let bytes = std::fs::read(&sealed_path).map_err(|e| {
                format!(
                    "could not read sealed OAuth client bundle for service '{service}' at {}: {e}",
                    sealed_path.display()
                )
            })?;
            let sealed = permitlayer_core::store::fs::credential_fs::decode_envelope(&bytes)
                .map_err(|e| {
                    format!("corrupt sealed OAuth client bundle for service '{service}': {e}")
                })?;
            // Story 11.8: the vault keys on `(ConnectionId, Slot)`. The
            // `{service}-client` store key stays as-is; the vault unseal
            // derives the base connection + `Slot::Client` from it.
            let (client_connection, client_slot) =
                permitlayer_credential::connection_slot_from_service_key(&client_service);
            let token = vault.unseal(client_connection, client_slot, &sealed).map_err(|e| {
                format!("could not unseal OAuth client bundle for service '{service}': {e}")
            })?;
            GoogleOAuthConfig::from_sealed_bundle_bytes(token.reveal()).map_err(|e| {
                format!("malformed sealed OAuth client bundle for service '{service}': {e}")
            })?
        }
        other => {
            return Err(format!(
                "metadata for service '{service}' has unknown client_type '{other}'"
            ));
        }
    };

    OAuthClient::new(config.client_id().to_owned(), config.client_secret().map(str::to_owned))
        .map(Arc::new)
        .map_err(|e| format!("could not construct OAuth client for service '{service}': {e}"))
}

/// Write a `token-refresh` `AuditEvent` via the shared
/// `AuditStore` trait. Best-effort — logs a warning via `tracing` on
/// failure but does not fail the CLI command.
///
/// Structurally mirrors `ProxyService::write_audit` +
/// `emit_persistence_failed_audit`: accepts an optional `extra` JSON
/// value for the `refresh_token_rotated` (success) or `stage`
/// (persistence_failed) case.
#[allow(clippy::too_many_arguments)]
async fn emit_cli_token_refresh_audit(
    audit_store: &dyn permitlayer_core::store::AuditStore,
    request_id: &str,
    agent_id: &str,
    service: &str,
    scope: &str,
    resource: &str,
    outcome: &str,
    extra: Option<serde_json::Value>,
) {
    use permitlayer_core::audit::event::AuditEvent;

    let mut event = AuditEvent::with_request_id(
        request_id.to_owned(),
        agent_id.to_owned(),
        service.to_owned(),
        scope.to_owned(),
        resource.to_owned(),
        outcome.to_owned(),
        "token-refresh".to_owned(),
    );
    if let Some(e) = extra {
        event.extra = e;
    }
    if let Err(e) = audit_store.append(event).await {
        tracing::warn!(error = %e, "CLI token-refresh audit event write failed (best-effort)");
    }
}

/// Map a `RefreshFlowError` variant to a CLI-flavored `(code,
/// remediation, exit_code)` triple for `render::error_block` and
/// `process::exit`. The `code` field doubles as the `error_code`
/// visible in daemon audit logs; the remediation string is a
/// concrete command the operator should run to recover; the exit
/// code is one of `cli_exit::{BUG, MISCONFIG, TRANSIENT}` per the
/// Story 1.14b code-review m8 policy.
fn cli_error_code_and_remediation(
    err: &permitlayer_proxy::refresh_flow::RefreshFlowError,
) -> (&'static str, String, i32) {
    use permitlayer_proxy::refresh_flow::RefreshFlowError;

    match err {
        RefreshFlowError::CredentialRevoked { service } => {
            ("credential_revoked", format!("agentsso setup {service}"), cli_exit::MISCONFIG)
        }
        RefreshFlowError::Exhausted { service } => (
            "oauth_exhausted",
            format!(
                "check network connectivity, then retry: agentsso credentials refresh {service}"
            ),
            cli_exit::TRANSIENT,
        ),
        // Story 1.14b code-review m4 fix: surface the failing
        // PersistStage in the user-facing remediation. The whole
        // point of the PersistStage enum (Story 1.14a m6 fix) is
        // post-incident debuggability — operators reading the audit
        // log get extra.stage, but the operator running this CLI
        // command was previously seeing only "check vault
        // permissions" with no indication of which persist step
        // broke. Now the stage is in both places.
        RefreshFlowError::PersistenceFailed { service, stage, .. } => (
            "persistence_failed",
            format!(
                "persist stage '{stage}' failed — check vault directory permissions, then retry: agentsso credentials refresh {service}"
            ),
            cli_exit::BUG,
        ),
        RefreshFlowError::MalformedToken { service, .. } => (
            "malformed_token",
            format!(
                "this is a bug — the provider returned non-UTF-8 bytes. re-run: agentsso setup {service}"
            ),
            cli_exit::BUG,
        ),
        RefreshFlowError::StoreReadFailed { service, .. } => (
            "store_read_failed",
            format!(
                "check credential store permissions, then retry: agentsso credentials refresh {service}"
            ),
            cli_exit::BUG,
        ),
        RefreshFlowError::VaultUnsealFailed { service, .. } => (
            "vault_unseal_failed",
            format!("vault tamper or key mismatch — re-run: agentsso setup {service}"),
            cli_exit::BUG,
        ),
        RefreshFlowError::MetaInvalid { service, .. } => (
            "meta_invalid",
            format!("metadata file is corrupt or missing — re-run: agentsso setup {service}"),
            cli_exit::MISCONFIG,
        ),
        RefreshFlowError::UnknownOauthError { service, .. } => (
            "unknown_oauth_error",
            format!(
                "unexpected OAuth error — check daemon logs, then retry: agentsso credentials refresh {service}"
            ),
            cli_exit::BUG,
        ),
    }
}

/// Compute token validity status from metadata.
///
/// Returns `(validity_label, time_remaining_suffix)`.
///
/// Story 1.14b Task 5c: computes `expires_at` from
/// `last_refreshed_at` when it is `Some`, falling back to
/// `connected_at` only when `None` (i.e., pre-refresh credentials or
/// old meta files predating Story 1.14b). This is the actual fix for
/// `deferred-work.md:58` — before this change, refreshed tokens kept
/// showing "expired" long before their actual expiry because the
/// baseline was stuck at the setup timestamp.
fn compute_token_validity(meta: &CredentialMeta) -> (&'static str, String) {
    let Some(expires_in_secs) = meta.expires_in_secs else {
        return ("unknown", String::new());
    };

    // Prefer last_refreshed_at as the baseline when present. This is
    // the load-bearing fix for deferred-work.md:58.
    let baseline_str = meta.last_refreshed_at.as_deref().unwrap_or(&meta.connected_at);
    let Ok(baseline) = chrono::DateTime::parse_from_rfc3339(baseline_str) else {
        return ("unknown", String::new());
    };

    let baseline_utc = baseline.with_timezone(&chrono::Utc);
    let now = chrono::Utc::now();

    // Story 1.14b code-review m5 fix: clamp the baseline to `now` if
    // the meta file's timestamp is in the future. Without this, clock
    // skew (NTP jump, laptop sleep/wake, manually edited meta) would
    // produce a far-future `expires_at` and `compute_token_validity`
    // would return `"valid"` with an absurd "(expires in Nh)" suffix.
    // Clamping degrades gracefully: a refreshed-in-the-future token
    // is treated as "refreshed right now" — so the displayed expiry
    // is the configured token lifetime from the current moment, not
    // garbage.
    let baseline_utc = baseline_utc.min(now);

    // Saturate to i64::MAX to prevent wrap-around on corrupt metadata.
    let secs_i64 = i64::try_from(expires_in_secs).unwrap_or(i64::MAX);
    let expires_at = baseline_utc + chrono::Duration::seconds(secs_i64);

    if now >= expires_at {
        ("expired", String::new())
    } else {
        let remaining = expires_at - now;
        let minutes = remaining.num_minutes();
        if minutes > 60 {
            let hours = remaining.num_hours();
            ("valid", format!(" (expires in {hours}h)"))
        } else {
            ("valid", format!(" (expires in {minutes}m)"))
        }
    }
}

/// Resolve the vault directory path.
fn vault_dir() -> anyhow::Result<PathBuf> {
    let home = super::agentsso_home()?;
    Ok(home.join("vault"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ── Story 1.14b Task 5d: compute_token_validity baseline regression ──

    fn meta_with_last_refreshed(
        connected_at: &str,
        last_refreshed_at: Option<&str>,
        expires_in_secs: Option<u64>,
    ) -> CredentialMeta {
        CredentialMeta {
            client_type: "shared-casa".to_owned(),
            client_source: None,
            client_sealed: false,
            connected_at: connected_at.to_owned(),
            last_refreshed_at: last_refreshed_at.map(str::to_owned),
            scopes: vec!["https://www.googleapis.com/auth/gmail.readonly".to_owned()],
            expires_in_secs,
        }
    }

    #[test]
    fn compute_token_validity_uses_last_refreshed_at_when_present() {
        // Setup time: 2 hours ago. Refresh time: 30 seconds ago. Token
        // expiry: 3600 seconds from baseline. If the function used the
        // OLD behavior (baseline = connected_at), the token would be
        // "expired" (2h > 1h). With the FIX (baseline =
        // last_refreshed_at), the token is "valid" for ~59 more
        // minutes.
        let now = chrono::Utc::now();
        let two_hours_ago = now - chrono::Duration::hours(2);
        let thirty_seconds_ago = now - chrono::Duration::seconds(30);

        let meta = meta_with_last_refreshed(
            &two_hours_ago.to_rfc3339(),
            Some(&thirty_seconds_ago.to_rfc3339()),
            Some(3600),
        );

        let (validity, _remaining) = compute_token_validity(&meta);
        assert_eq!(
            validity, "valid",
            "compute_token_validity must use last_refreshed_at as the baseline when present — \
             without this fix, `deferred-work.md:58` stays open"
        );
    }

    #[test]
    fn compute_token_validity_falls_back_to_connected_at_when_last_refreshed_none() {
        // Legacy meta file: no last_refreshed_at field, connected 30
        // seconds ago, 3600-second expiry. Must report "valid" using
        // connected_at as the baseline.
        let now = chrono::Utc::now();
        let thirty_seconds_ago = now - chrono::Duration::seconds(30);

        let meta = meta_with_last_refreshed(&thirty_seconds_ago.to_rfc3339(), None, Some(3600));

        let (validity, _remaining) = compute_token_validity(&meta);
        assert_eq!(
            validity, "valid",
            "pre-refresh credentials must still compute validity from connected_at"
        );
    }

    #[test]
    fn compute_token_validity_expired_uses_refreshed_baseline() {
        // Story 1.14b code-review n5 fix: previously this fixture had
        // `connected_at = 10s ago` and `last_refreshed_at = 2h ago` —
        // i.e., the token was "refreshed" 2 hours BEFORE it was
        // connected, which is impossible in production. The test
        // still passed because compute_token_validity doesn't enforce
        // the ordering, but the fixture wasn't a believable
        // production scenario. Fixed: connected 3h ago, refreshed
        // 2h ago, with 1h expiry — refreshed-2h-ago with 1h lifetime
        // is expired.
        let now = chrono::Utc::now();
        let three_hours_ago = now - chrono::Duration::hours(3);
        let two_hours_ago = now - chrono::Duration::hours(2);

        let meta = meta_with_last_refreshed(
            &three_hours_ago.to_rfc3339(),
            Some(&two_hours_ago.to_rfc3339()),
            Some(3600),
        );

        let (validity, _remaining) = compute_token_validity(&meta);
        assert_eq!(validity, "expired", "refreshed-2h-ago with 1h expiry must be reported expired");
    }

    #[test]
    fn compute_token_validity_unknown_when_baseline_unparseable() {
        // Story 1.14b code-review n6 fix: cover the
        // baseline-parse-failure → "unknown" branch at
        // `credentials.rs::compute_token_validity` where
        // `chrono::DateTime::parse_from_rfc3339` fails. Previously
        // the only "unknown" test set `expires_in_secs = None`,
        // which short-circuited at the earlier guard before reaching
        // the baseline parse. Now we exercise the parse failure
        // explicitly with a malformed `last_refreshed_at` string and
        // a corrupt `connected_at` fallback.
        let meta = meta_with_last_refreshed(
            "not-a-real-timestamp",
            Some("also-not-a-timestamp"),
            Some(3600),
        );
        let (validity, remaining) = compute_token_validity(&meta);
        assert_eq!(validity, "unknown");
        assert!(remaining.is_empty());
    }

    #[test]
    fn compute_token_validity_clamps_future_baseline_to_now() {
        // Story 1.14b code-review m5 regression test: a baseline in
        // the future (clock skew, NTP jump, edited meta file) used
        // to produce a far-future `expires_at` and a "valid (expires
        // in Nh)" suffix with absurdly large N. The clamp at
        // `credentials.rs::compute_token_validity` now treats a
        // future baseline as "right now", so the displayed expiry
        // is the configured token lifetime from the current moment.
        let now = chrono::Utc::now();
        let one_hour_in_future = now + chrono::Duration::hours(1);

        let meta = meta_with_last_refreshed(
            &one_hour_in_future.to_rfc3339(),
            Some(&one_hour_in_future.to_rfc3339()),
            Some(3600),
        );

        let (validity, remaining) = compute_token_validity(&meta);
        assert_eq!(validity, "valid", "clamped baseline yields valid token");
        // The remaining time should be near 60m (3600s expiry from
        // a "now" baseline), not 120m (3600s expiry from a 1h-future
        // baseline). Tolerate ±2m of test-execution slack.
        assert!(
            remaining.contains("60m") || remaining.contains("59m") || remaining.contains("58m"),
            "expected ~60m remaining (clamped baseline), got: {remaining}"
        );
    }

    #[test]
    fn compute_token_validity_unknown_when_expires_missing() {
        let meta = meta_with_last_refreshed("2026-04-10T12:00:00Z", None, None);
        let (validity, remaining) = compute_token_validity(&meta);
        assert_eq!(validity, "unknown");
        assert!(remaining.is_empty());
    }

    // ── bmad-code-review F10 + F11: Story 7.35 sealed-client coverage
    //    for the CLI refresh path (parity with the proxy) and the
    //    vault namespace-isolation invariant ─────────────────────────

    use permitlayer_vault::Vault;

    const CR_TEST_MASTER_KEY: [u8; 32] = [0x42; 32];

    fn cr_test_vault() -> Vault {
        Vault::new(zeroize::Zeroizing::new(CR_TEST_MASTER_KEY), 0)
    }

    /// Seal a BYO client bundle into `{service}-client.sealed` exactly
    /// as the daemon's seal handler does, then write a matching
    /// `{service}-meta.json`. `client_sealed` controls the meta flag.
    fn cr_seal_byo(vault_dir: &std::path::Path, service: &str, client_sealed: bool) {
        let bundle = serde_json::json!({
            "client_id": "123.apps.googleusercontent.com",
            "client_secret": "GOCSPX-cli-parity-secret",
            "project_id": "cli-parity-proj",
            "v": 1,
        })
        .to_string();
        let token = permitlayer_credential::OAuthToken::from_trusted_bytes(bundle.into_bytes());
        let client_service = format!("{service}-client");
        let (connection, slot) =
            permitlayer_credential::connection_slot_from_service_key(&client_service);
        let sealed = cr_test_vault().seal(connection, slot, &token).unwrap();
        let bytes = permitlayer_core::store::fs::credential_fs::encode_envelope(&sealed);
        std::fs::write(vault_dir.join(format!("{service}-client.sealed")), bytes).unwrap();

        let meta = CredentialMeta {
            client_type: "byo".to_owned(),
            client_source: if client_sealed {
                None
            } else {
                Some("/Users/op/Downloads/client_secret.json".to_owned())
            },
            client_sealed,
            connected_at: "2026-05-16T00:00:00Z".to_owned(),
            last_refreshed_at: None,
            scopes: vec!["https://mail.google.com/".to_owned()],
            expires_in_secs: Some(3599),
        };
        std::fs::write(
            vault_dir.join(format!("{service}-meta.json")),
            serde_json::to_string(&meta).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn cli_build_oauth_client_reconstructs_from_sealed_bundle_not_a_file() {
        // F11 CLI-parity: the CLI refresh path
        // (`build_oauth_client_for_cli`) must unseal `{svc}-client`
        // with NO filesystem read of any client JSON — same contract
        // the proxy's `byo_client_is_reconstructed_from_sealed_bundle_
        // not_a_file` pins for `ProxyService`.
        let dir = tempfile::tempdir().unwrap();
        cr_seal_byo(dir.path(), "gmail", /* client_sealed */ true);
        // No client_secret.json on disk: a path fallback would error.
        let client = build_oauth_client_for_cli(&cr_test_vault(), dir.path(), "gmail")
            .expect("CLI must reconstruct the sealed byo client with no file read");
        // Constructed successfully ⇒ the bundle was unsealed.
        let _ = client; // OAuthClient has no public accessors; success is the assertion.
    }

    #[test]
    fn cli_build_oauth_client_rejects_legacy_non_sealed_no_path_fallback() {
        // F11 CLI-parity: a legacy `client_sealed:false` byo record
        // must be hard-rejected with the actionable re-connect message,
        // never silently re-reading a client JSON — even one sitting
        // right next to the meta.
        let dir = tempfile::tempdir().unwrap();
        cr_seal_byo(dir.path(), "gmail", /* client_sealed */ false);
        std::fs::write(
            dir.path().join("legacy_client_secret.json"),
            r#"{"installed":{"client_id":"x","client_secret":"y"}}"#,
        )
        .unwrap();

        // `OAuthClient` isn't `Debug`, so `expect_err` won't compile.
        let err = match build_oauth_client_for_cli(&cr_test_vault(), dir.path(), "gmail") {
            Ok(_) => panic!("legacy non-sealed record must be rejected, not path-read"),
            Err(e) => e,
        };
        assert!(
            err.contains("not sealed") && err.contains("legacy/path-based"),
            "must explain the record is legacy/non-sealed; got: {err}"
        );
        assert!(
            err.contains("agentsso connect") && err.contains("--oauth-client"),
            "must name the actionable fix (re-run connect); got: {err}"
        );
    }

    #[test]
    fn vault_namespace_isolation_client_bundle_not_cross_unsealable() {
        // F10 (the spec-enumerated AC#7 negative test): the
        // `{service}-client` HKDF subkey MUST be cryptographically
        // distinct from `{service}` and `{service}-refresh`. A bundle
        // sealed under `gmail-client` must NOT unseal under `gmail` or
        // `gmail-refresh` — this is the assertion that proves the
        // per-namespace isolation the whole 7.35 seal design relies on.
        let dir = tempfile::tempdir().unwrap();
        let vault = cr_test_vault();
        let bundle = br#"{"client_id":"x.apps.googleusercontent.com","v":1}"#.to_vec();
        let token = permitlayer_credential::OAuthToken::from_trusted_bytes(bundle);
        // Story 11.8: `connection_slot_from_service_key` maps each
        // service-key string to the same `(ConnectionId, Slot)` the
        // production seal/unseal paths derive, so this preserves the
        // original cross-namespace isolation semantics: `gmail-client`
        // → `(gmail, Client)`, `gmail` → `(gmail, Access)`,
        // `gmail-refresh` → `(gmail, Refresh)`.
        use permitlayer_credential::connection_slot_from_service_key;
        let (client_conn, client_slot) = connection_slot_from_service_key("gmail-client");
        let (access_conn, access_slot) = connection_slot_from_service_key("gmail");
        let (refresh_conn, refresh_slot) = connection_slot_from_service_key("gmail-refresh");
        let sealed = vault.seal(client_conn, client_slot, &token).unwrap();

        // Same vault, wrong slot → AEAD/AAD mismatch → error.
        assert!(
            vault.unseal(access_conn, access_slot, &sealed).is_err(),
            "a gmail-client envelope must NOT unseal under the `gmail` namespace"
        );
        assert!(
            vault.unseal(refresh_conn, refresh_slot, &sealed).is_err(),
            "a gmail-client envelope must NOT unseal under the `gmail-refresh` namespace"
        );
        // Sanity: it DOES unseal under its own namespace.
        assert!(
            vault.unseal(client_conn, client_slot, &sealed).is_ok(),
            "the envelope must unseal under its own `gmail-client` namespace"
        );
        let _ = dir;
    }
}
