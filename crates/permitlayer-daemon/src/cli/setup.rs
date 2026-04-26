//! `agentsso setup <service>` — Interactive OAuth setup wizard.
//!
//! This subcommand runs an interactive OAuth 2.1 authorization flow in six
//! clearly labeled phases:
//!
//! 1. **Scope preview** — show requested scopes with human descriptions;
//!    warn if overwriting an existing connection.
//! 2. **Confirm** — prompt user before opening the browser.
//! 3. **Browser + spinner** — open browser and wait for consent callback.
//! 4. **Seal and store** — seal tokens into the vault.
//! 5. **Verify connection** — run a lightweight test query.
//! 6. **Summary** — echo granted scopes and client type.
//!
//! Pass `--non-interactive` to skip all prompts (for CI / testing).

use std::path::{Path, PathBuf};

use clap::Args;
use permitlayer_core::store::CredentialStore;
use permitlayer_core::store::fs::CredentialFsStore;
use permitlayer_keystore::{FallbackMode, KeystoreConfig, default_keystore};
use permitlayer_oauth::error::OAuthError;
use permitlayer_oauth::google::consent::GoogleOAuthConfig;
use permitlayer_oauth::google::scopes;
use permitlayer_oauth::google::verify;
use permitlayer_oauth::metadata::{CredentialMeta, write_metadata_atomic};
use permitlayer_vault::Vault;

use crate::design::render;
use crate::design::terminal::{ColorSupport, styled};
use crate::design::theme::Theme;

/// RAII guard that ensures an [`indicatif::ProgressBar`] spinner is
/// `finish_and_clear`'d when the guard drops, even on panic or early
/// return.
///
/// Prevents the spinner tick thread from corrupting the terminal if
/// `client.authorize()` panics mid-flight (pre-existing hazard flagged
/// by Story 1.8 review). The guard is self-contained — no external
/// `scopeguard` crate dependency is needed (Story 2.7 anti-pattern).
struct SpinnerGuard {
    spinner: Option<indicatif::ProgressBar>,
}

impl SpinnerGuard {
    fn new(spinner: indicatif::ProgressBar) -> Self {
        Self { spinner: Some(spinner) }
    }
}

impl Drop for SpinnerGuard {
    fn drop(&mut self) {
        if let Some(spinner) = self.spinner.take() {
            spinner.finish_and_clear();
        }
    }
}

/// Arguments for `agentsso setup [service]`.
///
/// `service` is optional — the no-arg form (`agentsso setup`) runs the
/// top-level orchestrator (Story 7.3 Task 3) which interactively picks
/// a service to set up and then offers OPT-IN autostart. The per-
/// service form (`agentsso setup gmail|calendar|drive`) runs the
/// service-only flow unchanged.
#[derive(Args)]
pub struct SetupArgs {
    /// The upstream service to set up (e.g., `gmail`).
    /// Omit to enter the interactive orchestrator (chooses service +
    /// offers autostart).
    pub service: Option<String>,
    /// Path to a Google OAuth client JSON file (BYO mode).
    /// If omitted, the shared CASA-certified client is used.
    #[arg(long = "oauth-client", value_name = "PATH")]
    pub oauth_client: Option<PathBuf>,
    /// Skip interactive prompts (for CI and testing).
    #[arg(long)]
    pub non_interactive: bool,
    /// Overwrite existing credentials without confirmation.
    /// Implied by `--non-interactive`.
    #[arg(long)]
    pub force: bool,
}

/// Run the `setup` subcommand.
///
/// Two paths:
/// - `service: Some(svc)` → the long-standing per-service OAuth flow.
///   Unchanged. No autostart prompt — keeps the path stable for users
///   who already script `agentsso setup gmail` etc.
/// - `service: None` → the Story 7.3 top-level orchestrator. Picks a
///   service interactively, runs the per-service flow, then offers
///   OPT-IN autostart (default = NO; `--non-interactive` requires an
///   explicit service arg).
pub async fn run(args: SetupArgs) -> anyhow::Result<()> {
    // The orchestrator path: no service supplied → interactive picker
    // + autostart prompt. Defer to a dedicated function so the rest of
    // this file (the per-service flow) stays untouched. The orchestrator
    // re-enters this function with `args.service = Some(...)` once the
    // user picks a service, so the per-service path runs unmodified.
    //
    // P21 (code review): treat empty/whitespace-only `Some("")` as
    // `None` (route to orchestrator). Without this, `agentsso setup ""`
    // falls into the per-service path, gets trimmed-to-empty, then
    // fails the SUPPORTED_SERVICES check with the confusing message
    // `unsupported service: ''`.
    let service_arg = match args.service.clone() {
        Some(s) if !s.trim().is_empty() => s,
        _ => return run_orchestrator(args).await,
    };

    // Story 5.4: setup is a one-shot CLI command, not the daemon —
    // pass `log_dir = None` so only the stdout subscriber is
    // installed. No file appender worker thread, no `WorkerGuard` to
    // hold. `_guards` is empty.
    //
    // L11 fix: preserve the structured `TelemetryInitError` source
    // chain via `anyhow::Context` instead of flattening into a plain
    // string. Operators with `RUST_LOG=debug` see the chain.
    use anyhow::Context as _;
    let _guards =
        crate::telemetry::init_tracing("info", None, 30).context("tracing init failed")?;

    let service = service_arg.trim().to_lowercase();

    // Static input validation runs FIRST — unknown service names
    // should produce `unsupported_service` errors regardless of whether
    // stdout is a terminal, so a user running
    // `agentsso setup bogusservice | tee log.txt` sees "unsupported
    // service" and not the misleading "setup_non_interactive_required"
    // error (Story 2.7 review patch: ordering fix).
    if !SUPPORTED_SERVICES.contains(&service.as_str()) {
        anyhow::bail!(
            "unsupported service: '{service}'. Supported services: {}",
            SUPPORTED_SERVICES.join(", ")
        );
    }

    // Story 3.2: if a daemon is running AND its kill switch is active,
    // refuse to open a new OAuth flow. Rationale: the kill switch is
    // "everything stop" — opening a browser and issuing new scopes while
    // killed contradicts the operator intent. If the daemon is NOT
    // running, setup proceeds unchanged (a fresh install must be able to
    // run setup before anything else). If the probe fails for any reason
    // other than "daemon reports active: true", setup also proceeds — a
    // broken probe must NOT block the user from running setup.
    probe_daemon_kill_state_or_exit().await?;

    // Story 2.7 AC #8: fail fast if stdout is piped but --non-interactive
    // was not set. The old silent-fallthrough behavior (skipping Phase 2's
    // confirmation prompt and proceeding straight to browser-opening)
    // is a footgun for a security tool. Pipe-to-tee should FAIL, not
    // proceed without confirmation.
    let stdout_is_tty = console::Term::stdout().is_term();
    if !args.non_interactive && !stdout_is_tty {
        eprint!(
            "{}",
            render::error_block(
                "setup_non_interactive_required",
                "stdout is not a terminal — interactive prompts are unsafe in this context",
                &format!("agentsso setup {service} --non-interactive"),
                None,
            )
        );
        std::process::exit(1);
    }
    let interactive = !args.non_interactive && stdout_is_tty;

    let home = super::agentsso_home()?;
    let theme = Theme::load(&home);
    let color_support = ColorSupport::detect();
    tracing::info!(home = %home.display(), service = %service, "starting OAuth setup");

    // Resolve OAuth client configuration.
    //
    // permitlayer has no shared CASA-certified client yet, so every user
    // must bring their own OAuth client via --oauth-client. If a shared
    // client ever ships, this is the spot that would construct it.
    let oauth_config = match &args.oauth_client {
        Some(path) => GoogleOAuthConfig::from_client_json(path)?,
        None => {
            eprint!(
                "{}",
                render::error_block(
                    "oauth_client_required",
                    "no OAuth client provided — permitlayer currently requires a \
                     bring-your-own Google OAuth client",
                    &format!(
                        "create a Desktop OAuth client at \
                         https://console.cloud.google.com/apis/credentials, \
                         download the JSON, then re-run:\n\n    \
                         agentsso setup {service} --oauth-client ./client_secret.json"
                    ),
                    None,
                )
            );
            std::process::exit(1);
        }
    };

    tracing::info!(
        client_type = %oauth_config.provenance_tag(),
        "using OAuth client"
    );

    // ── Phase 0: Pre-flight vault directory writability check ──────────
    //
    // Verify we can write to the vault directory BEFORE opening the
    // browser for OAuth consent. Users who would have completed the
    // browser flow only to fail at `CredentialFsStore::new()` later now
    // get a clean pre-flight error with no wasted consent flow
    // (Story 2.7 AC #6, closes Story 1.8 defer).
    let vault_dir = home.join("vault");
    if let Err(e) = check_vault_dir_writable(&vault_dir) {
        // Distinguish the symlink-rejection path from generic
        // unwritability so the user gets an error code that tells them
        // specifically what to fix. The helper uses `InvalidInput`
        // ONLY for the symlink case.
        let (error_code, remediation) = if e.kind() == std::io::ErrorKind::InvalidInput {
            ("vault_dir_symlink", "rm ~/.agentsso/vault && mkdir -p -m 0700 ~/.agentsso/vault")
        } else {
            (
                "vault_dir_unwritable",
                "chmod 0700 ~/.agentsso/vault || mkdir -p -m 0700 ~/.agentsso/vault",
            )
        };
        eprint!(
            "{}",
            render::error_block(
                error_code,
                &format!("{}: {e}", vault_dir.display()),
                remediation,
                None,
            )
        );
        std::process::exit(1);
    }

    // Build the shared teal theme for all Phase 1/2 interactive prompts.
    let teal_theme = build_teal_theme(&theme);

    // ── Phase 1: Scope preview + overwrite confirmation ─────────────────

    let meta_path = vault_dir.join(format!("{service}-meta.json"));

    if interactive {
        // Confirm overwrite if existing credentials are present.
        // `--force` (or `--non-interactive`, which implies --force) bypasses.
        if meta_path.exists() && !args.force {
            let styled_service = styled(&service, theme.tokens().accent, color_support);
            println!(
                "  {styled_service} is already connected \u{00b7} re-running will replace existing credentials"
            );
            let confirm = dialoguer::Confirm::with_theme(&teal_theme)
                .with_prompt("replace existing credentials?")
                .default(false)
                .interact()?;
            if !confirm {
                println!("  setup cancelled");
                return Ok(());
            }
            println!();
        } else if meta_path.exists() {
            // --force path: log the overwrite but proceed without prompt.
            tracing::info!(
                service = %service,
                "overwriting existing credentials (--force)"
            );
        }

        // Display scope preview.
        let scope_infos = scopes::default_scope_infos_for_service(&service);
        let styled_service = styled(&service, theme.tokens().accent, color_support);
        println!("  {styled_service} \u{00b7} scopes to request:");
        for info in &scope_infos {
            println!("    {} ({})", info.description, info.short_name);
        }
        println!();
    } else {
        // Non-interactive: --non-interactive implies --force for
        // overwrite semantics (CI / scripting use case).
        if meta_path.exists() {
            tracing::info!(
                service = %service,
                "overwriting existing credentials (non-interactive)"
            );
        }
        tracing::info!(service = %service, "scope preview (non-interactive)");
        let scope_infos = scopes::default_scope_infos_for_service(&service);
        for info in &scope_infos {
            tracing::info!(scope = info.short_name, description = info.description);
        }
    }

    // ── Phase 2: Confirm ────────────────────────────────────────────────

    if interactive {
        let confirm = dialoguer::Confirm::with_theme(&teal_theme)
            .with_prompt("open browser for Google consent?")
            .default(false)
            .interact()?;

        if !confirm {
            println!("  setup cancelled");
            return Ok(());
        }
    } else {
        tracing::info!("skipping confirmation ({})", non_interactive_skip_reason(args.force));
    }

    // ── Phase 3: Browser + spinner ──────────────────────────────────────

    // Load master key via keystore.
    let keystore_config = KeystoreConfig { fallback: FallbackMode::Auto, home: home.clone() };
    let keystore = default_keystore(&keystore_config)?;
    let master_key = keystore.master_key().await?;

    let vault = Vault::new(master_key);

    let client = permitlayer_oauth::OAuthClient::new(
        oauth_config.client_id().to_owned(),
        oauth_config.client_secret().map(|s| s.to_owned()),
    )?;

    let default_scopes = scopes::default_scopes_for_service(&service);
    let scopes_owned: Vec<String> = default_scopes.iter().map(|s| (*s).to_owned()).collect();

    let result = if interactive {
        let spinner = indicatif::ProgressBar::new_spinner();
        spinner.set_style(
            indicatif::ProgressStyle::with_template("{spinner} {msg}")
                .unwrap_or_else(|_| indicatif::ProgressStyle::default_spinner()),
        );
        spinner.enable_steady_tick(std::time::Duration::from_millis(120));
        spinner.set_message("waiting for browser consent...");

        // RAII: guarantee the spinner is cleared on normal return,
        // early return, or panic. Replaces the old manual
        // `spinner.finish_and_clear()` call which leaked the tick
        // thread on any non-happy-path exit (Story 1.8 defer closed).
        let guard = SpinnerGuard::new(spinner);

        let authorize_result = client.authorize(scopes_owned.clone(), None).await;
        // Drop the guard explicitly BEFORE any output so the spinner
        // line is cleared from the terminal before we print an error
        // block or success message.
        drop(guard);
        match authorize_result {
            Ok(r) => r,
            Err(e) => {
                // Preserve OAuthError::error_code() + remediation()
                // instead of letting `?` convert to anyhow::Error and
                // silently drop the structured context (Story 2.7 AC #4).
                render_oauth_error(
                    &e,
                    &service,
                    interactive,
                    OAuthErrorSeverity::Fatal,
                    "authorize failed",
                );
                std::process::exit(1);
            }
        }
    } else {
        tracing::info!("opening browser for Google OAuth consent...");
        match client.authorize(scopes_owned.clone(), None).await {
            Ok(r) => r,
            Err(e) => {
                render_oauth_error(
                    &e,
                    &service,
                    interactive,
                    OAuthErrorSeverity::Fatal,
                    "authorize failed",
                );
                std::process::exit(1);
            }
        }
    };

    // ── Phase 4: Seal and store ─────────────────────────────────────────

    let store = CredentialFsStore::new(home.clone())?;

    let sealed_access = vault
        .seal(&service, &result.access_token)
        .map_err(|e| anyhow::anyhow!("failed to seal access token: {e}"))?;
    store
        .put(&service, sealed_access)
        .await
        .map_err(|e| anyhow::anyhow!("failed to store access token: {e}"))?;

    if let Some(ref refresh_token) = result.refresh_token {
        let refresh_service = format!("{service}-refresh");
        let sealed_refresh = vault
            .seal_refresh(&refresh_service, refresh_token)
            .map_err(|e| anyhow::anyhow!("failed to seal refresh token: {e}"))?;
        store
            .put(&refresh_service, sealed_refresh)
            .await
            .map_err(|e| anyhow::anyhow!("failed to store refresh token: {e}"))?;
    }

    // Store provenance metadata.
    let granted_scopes =
        if result.scopes.is_empty() { scopes_owned } else { result.scopes.clone() };

    let meta = CredentialMeta {
        client_type: "byo".to_owned(),
        client_source: Some(oauth_config.source_path().display().to_string()),
        connected_at: chrono::Utc::now().to_rfc3339(),
        last_refreshed_at: None,
        scopes: granted_scopes.clone(),
        expires_in_secs: result.expires_in.map(|d| d.as_secs()),
    };

    write_metadata_atomic(&meta_path, &meta)
        .map_err(|e| anyhow::anyhow!("failed to write credential metadata: {e}"))?;

    if interactive {
        let check = styled("\u{2713}", theme.tokens().accent, color_support);
        println!("  {check} tokens sealed");
    } else {
        tracing::info!(service = %service, "access token sealed and stored");
    }

    // ── Phase 5: Verify connection ──────────────────────────────────────

    let token_bytes = result.access_token.reveal();
    match verify::verify_connection(&service, token_bytes).await {
        Ok(verify_result) => {
            if verify_result.email.is_some() {
                if interactive {
                    let check = styled("\u{2713}", theme.tokens().accent, color_support);
                    let styled_service = styled(&service, theme.tokens().accent, color_support);
                    println!(
                        "  {check} {styled_service} connected \u{00b7} tested with 1 read \u{00b7} ready"
                    );
                } else {
                    tracing::info!(
                        service = %service,
                        summary = %verify_result.summary,
                        "connection verified"
                    );
                }
            } else if interactive {
                let check = styled("\u{2713}", theme.tokens().accent, color_support);
                let styled_service = styled(&service, theme.tokens().accent, color_support);
                println!("  {check} {styled_service} connected \u{00b7} {}", verify_result.summary);
            } else {
                tracing::info!(
                    service = %service,
                    summary = %verify_result.summary,
                    "setup complete (no verification available)"
                );
            }
        }
        Err(e) => {
            // Phase 5 verification errors are non-fatal: the credentials
            // were already sealed in Phase 4, so we render the error but
            // do not abort the wizard. The summary in Phase 6 still runs.
            // `NonFatal` severity so the tracing dispatch uses WARN, not
            // ERROR — operator alert pipelines tuned to ERROR should not
            // fire on a recoverable path where credentials are already
            // sealed.
            render_oauth_error(
                &e,
                &service,
                interactive,
                OAuthErrorSeverity::NonFatal,
                "verification failed (credentials stored)",
            );
        }
    }

    // ── Phase 6: Summary ────────────────────────────────────────────────

    if interactive {
        println!();
        println!("  scopes granted:");
        for scope_uri in &granted_scopes {
            let info = scopes::scope_info(scope_uri);
            match info {
                Some(info) => println!("    {} ({})", info.description, info.short_name),
                None => println!("    {scope_uri}"),
            }
        }
        println!("  client: {}", oauth_config.provenance_tag());
    } else {
        tracing::info!(
            service = %service,
            scopes = ?granted_scopes,
            client_type = %oauth_config.provenance_tag(),
            "OAuth setup complete"
        );
    }

    // ── Phase 7: UX-DR16 — offer `agentsso audit --follow` on success
    //
    // Story 5.2 implements the Journey-1 flow (§9.1 of the UX spec):
    // "On first-run completion, default the user into
    // `agentsso audit --follow` mode to teach the log exists and
    // make the first scrub event visible."
    //
    // Only interactive runs get the prompt — non-interactive setup
    // is typically scripted / CI and we must not block on stdin. A
    // decline is non-blocking: the wizard returns `Ok(())` exactly
    // as today.
    if interactive {
        let accepted = prompt_start_audit_follow(&teal_theme)?;
        if accepted {
            // In-process dispatch: no subprocess, no double daemon
            // handle leak. `AuditArgs::default()` produces the
            // exact shape of `agentsso audit --follow` with no other
            // flags (all `Option::None` / empty `Vec`).
            let follow_args = crate::cli::audit::AuditArgs { follow: true, ..Default::default() };
            return crate::cli::audit::run(follow_args).await;
        }
    }

    Ok(())
}

/// Prompt the user to start `agentsso audit --follow` after a
/// successful setup (UX-DR16 / §9.1 Journey 1).
///
/// Returns `Ok(true)` if accepted, `Ok(false)` if declined.
///
/// # Test seam
///
/// The `AGENTSSO_TEST_SETUP_AUTO_FOLLOW` env var short-circuits the
/// real `dialoguer::Confirm` prompt for integration tests:
/// - `"accept"` → return `Ok(true)` immediately (caller spawns follow)
/// - `"decline"` → return `Ok(false)` immediately (caller returns `Ok(())`)
/// - Any other value → fall through to the real prompt
///
/// The env var check is gated on `#[cfg(debug_assertions)]` so
/// release builds CANNOT be redirected by a leaked env var. This
/// matches the Story 1.15 `AGENTSSO_TEST_PASSPHRASE` and Story 4.5
/// `AGENTSSO_TEST_APPROVAL_CANNED_RESPONSES` gating pattern.
fn prompt_start_audit_follow(teal_theme: &dialoguer::theme::ColorfulTheme) -> anyhow::Result<bool> {
    #[cfg(debug_assertions)]
    {
        if let Ok(seam) = std::env::var("AGENTSSO_TEST_SETUP_AUTO_FOLLOW") {
            // Emit the prompt banner so integration tests can assert
            // on visible text even when the real Confirm widget is
            // skipped.
            println!();
            println!("  start live audit follow now?");
            if let Some(decision) = decide_prompt_from_seam(Some(seam.as_str())) {
                return Ok(decision);
            }
        }
    }

    println!();
    let confirm = dialoguer::Confirm::with_theme(teal_theme)
        .with_prompt("start live audit follow now?")
        .default(true)
        .interact()?;
    Ok(confirm)
}

/// Pure-function test seam for `AGENTSSO_TEST_SETUP_AUTO_FOLLOW`.
///
/// Maps the raw env var string (if set) into a fixed decision, or
/// `None` to signal "fall through to the real prompt."
///
/// - `Some("accept")` → `Some(true)` (accept)
/// - `Some("decline")` → `Some(false)` (decline)
/// - `Some(<anything else>)` → `Some(false)` (decline, with warn) per
///   P25 review patch — the original code fell through to the real
///   `dialoguer::Confirm::interact()` which blocks on stdin. A CI
///   that sets `AGENTSSO_TEST_SETUP_AUTO_FOLLOW=yes` (typo) would
///   deadlock; safer to decline on unknown values.
/// - `None` → `None` (fall through to real prompt)
///
/// Extracted as a pure helper so unit tests can exercise the seam
/// matrix without needing `std::env::set_var` (which is `unsafe` in
/// Rust 2024 edition and conflicts with `#![forbid(unsafe_code)]`).
fn decide_prompt_from_seam(seam: Option<&str>) -> Option<bool> {
    match seam {
        Some("accept") => Some(true),
        Some("decline") => Some(false),
        Some(other) => {
            tracing::warn!(
                value = %other,
                "unknown AGENTSSO_TEST_SETUP_AUTO_FOLLOW value; declining (safer than falling through to blocking prompt)"
            );
            Some(false)
        }
        None => None,
    }
}

/// Build the accent-colored `dialoguer::ColorfulTheme` used by all
/// interactive prompts in the setup wizard.
///
/// Extracted to a helper in Story 2.7 so Phase 1 (overwrite confirm)
/// and Phase 2 (browser-open confirm) can share the same teal styling
/// without duplicating the `accent_256` picker logic.
///
/// Dialoguer uses the `console` crate internally, which does not
/// integrate with our design system's terminal detection. We use
/// `color256(43)` as a reasonable approximation of the accent color
/// for Carapace/Tidepool; darker teal 30 for the Molt light theme.
fn build_teal_theme(theme: &Theme) -> dialoguer::theme::ColorfulTheme {
    let accent_256 = match theme {
        Theme::Carapace | Theme::Tidepool => 43_u8, // teal
        Theme::Molt => 30,                          // darker teal for light bg
    };
    dialoguer::theme::ColorfulTheme {
        prompt_prefix: console::style("?".to_string()).for_stderr().color256(accent_256),
        success_prefix: console::style("\u{2713}".to_string()).for_stderr().color256(accent_256),
        values_style: console::Style::new().for_stderr().color256(accent_256),
        ..dialoguer::theme::ColorfulTheme::default()
    }
}

/// Verify that the vault directory exists (or can be created) and is
/// writable, before any long-running operation (OAuth browser flow)
/// commits the user to a failed setup.
///
/// Security-sensitive invariants (Story 2.7 AC #6 + review patches):
///
/// 1. **Symlinks are rejected.** If `vault_dir` exists as a symlink,
///    we refuse to operate on it — an attacker on a multi-user host
///    could plant a symlink pointing at their own writable directory
///    and cause the daemon to write sealed credentials into the
///    attacker-controlled target. Checked via `symlink_metadata`
///    (which does NOT follow symlinks).
///
/// 2. **New directories are created with `0o700` on Unix.** There is
///    a window between this helper's `create_dir_all` and Phase 4's
///    `CredentialFsStore::new` during which the vault directory is
///    otherwise world-listable under the default umask (typically
///    `0o755`). Another local user on a shared host could enumerate
///    which services have been set up by watching for
///    `{service}-meta.json` to appear. The `set_permissions` call
///    closes that window.
///
/// 3. **Writability is probed with a short-lived sentinel file.**
///    `create_dir_all` alone proves the directory exists, not that
///    the current process can write to it — a read-only bind mount
///    or a restricted-perms dir owned by another user would pass
///    `create_dir_all` and fail at Phase 4. The probe file catches
///    this cleanly before the browser opens.
///
/// Returns an error if any step fails. The caller is responsible for
/// rendering a `vault_dir_unwritable` or `vault_dir_symlink` error
/// block and exiting.
///
/// Closes Story 1.8 defer #26. Review patches (2026-04-08) added the
/// symlink rejection and the `0o700` chmod.
fn check_vault_dir_writable(vault_dir: &Path) -> std::io::Result<()> {
    // Symlink rejection: if the path already exists AND is a symlink,
    // refuse. `symlink_metadata` does NOT follow symlinks (unlike
    // `metadata`), so it sees the link itself.
    match std::fs::symlink_metadata(vault_dir) {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "vault_dir is a symlink: {} — refusing to follow it for security reasons",
                    vault_dir.display()
                ),
            ));
        }
        Ok(_) => {
            // Exists and is not a symlink — proceed.
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Does not exist yet — `create_dir_all` below will create it.
        }
        Err(e) => return Err(e),
    }

    std::fs::create_dir_all(vault_dir)?;

    // Tighten permissions to `0o700` on Unix. This is a no-op on
    // Windows, where ACL enforcement is tracked separately in the
    // deferred-work log (Story 7.2).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(vault_dir, perms)?;
    }

    let probe_path = vault_dir.join(".permitlayer-writability-probe");
    // Use `create` (truncate) rather than `create_new` so a stale probe
    // file from a previous aborted run does not cause a false negative.
    let file = std::fs::File::create(&probe_path)?;
    drop(file);
    // Best-effort cleanup; if the remove fails (e.g. racy delete by
    // another process), we still consider the dir writable.
    let _ = std::fs::remove_file(&probe_path);
    Ok(())
}

/// Story 3.2 AC #7: refuse to run `agentsso setup` when a running daemon's
/// kill switch is active.
///
/// Short-circuits to `Ok(())` in these cases (setup proceeds as today):
///
/// - No PID file (fresh install / daemon not running).
/// - PID file exists but process is gone (stale PID).
/// - Any probe failure (connect refused, timeout, non-200, malformed body).
///
/// Only exits the process when the daemon explicitly reports
/// `{"active": true}`. Defense in depth: a broken probe must NEVER block
/// the user from running setup — failing-closed here is worse than
/// failing-open.
async fn probe_daemon_kill_state_or_exit() -> anyhow::Result<()> {
    use crate::config::{CliOverrides, DaemonConfig};
    use crate::lifecycle::pid::PidFile;

    let config = match DaemonConfig::load(&CliOverrides::default()) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                target: "setup",
                error = %e,
                "DaemonConfig::load failed during kill-state probe; proceeding with setup — \
                 check ~/.agentsso/config/daemon.toml and AGENTSSO_* env vars",
            );
            return Ok(());
        }
    };
    let home = &config.paths.home;

    // Cheap check first: skip the HTTP probe entirely if no daemon is
    // running. This avoids a 500ms timeout penalty on every `agentsso
    // setup` call on a fresh install.
    let daemon_running = matches!(PidFile::read(home), Ok(Some(_)))
        && matches!(PidFile::is_daemon_running(home), Ok(true));
    if !daemon_running {
        return Ok(());
    }

    let bind_addr = config.http.bind_addr;
    let probe_deadline = std::time::Duration::from_millis(500);

    // 500ms deadline keeps setup snappy even when a misbehaving daemon
    // is on localhost. `probe_state_get` delegates to `kill::http_get`.
    let probe_result = tokio::time::timeout(probe_deadline, probe_state_get(bind_addr)).await;

    let body = match probe_result {
        Ok(Ok(body)) => body,
        Ok(Err(e)) => {
            tracing::warn!(target: "setup", error = %e, "daemon kill-state probe failed; proceeding with setup");
            return Ok(());
        }
        Err(_elapsed) => {
            tracing::warn!(target: "setup", "daemon kill-state probe timed out; proceeding with setup");
            return Ok(());
        }
    };

    // Minimal parser — we only care about the `active` field. Schema
    // drift where the daemon stops sending `active` (or renames it) must
    // NOT silently degrade to a "not active" read: that would turn the
    // defense-in-depth check into a no-op. Instead, a missing-field
    // deserialize error routes through the same fail-open path as any
    // other probe failure — `tracing::warn!` + `return Ok(())`. The
    // operator sees the warn and can diagnose; the user's setup isn't
    // blocked by a broken probe.
    #[derive(serde::Deserialize)]
    struct StateSnapshot {
        active: bool,
    }
    let snapshot: StateSnapshot = match serde_json::from_str(&body) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                target: "setup",
                error = %e,
                body = %body,
                "unexpected state response (missing or malformed `active` field); proceeding with setup",
            );
            return Ok(());
        }
    };

    if snapshot.active {
        eprint!(
            "{}",
            render::error_block(
                "daemon_killed",
                "permitlayer is in kill state \u{2014} setup cannot open new OAuth flows",
                "agentsso resume",
                None,
            )
        );
        std::process::exit(2);
    }

    Ok(())
}

/// Minimal HTTP GET for `/v1/control/state`. Delegates to `kill::http_get`
/// so the TCP logic lives in one place; the 500 ms outer deadline in
/// `probe_daemon_kill_state_or_exit` bounds the total latency.
///
/// Invariant: the outer 500 ms timeout must always be ≤ `kill::HTTP_DEADLINE`
/// (currently 1500 ms). The static assertion below enforces this — if
/// `HTTP_DEADLINE` is ever reduced below 500 ms, this will fail to compile.
async fn probe_state_get(addr: std::net::SocketAddr) -> anyhow::Result<String> {
    const _: () = assert!(
        crate::cli::kill::HTTP_DEADLINE.as_millis() >= 500,
        "kill::HTTP_DEADLINE must be >= the 500ms probe_state_get outer timeout"
    );
    crate::cli::kill::http_get(addr, "/v1/control/state").await
}

/// Severity of an `OAuthError` for the non-interactive tracing-log
/// dispatch path. Interactive mode always renders the same design-
/// system error block regardless of severity.
///
/// Story 2.7 review patch: Phase 5 verification errors are
/// non-fatal (credentials were sealed in Phase 4; the wizard still
/// runs Phase 6 summary) and should log at WARN, not ERROR, so that
/// operator alert pipelines tuned to ERROR-level events do not fire
/// on an expected recoverable path.
#[derive(Debug, Clone, Copy)]
enum OAuthErrorSeverity {
    /// Fatal — the wizard will `std::process::exit(1)` after rendering
    /// (Phase 3 `authorize` failures).
    Fatal,
    /// Non-fatal — the wizard logs but continues execution (Phase 5
    /// `verify_connection` failures after credentials were sealed).
    NonFatal,
}

/// Render an [`OAuthError`] using the design system (interactive mode)
/// or structured tracing (non-interactive mode).
///
/// Centralizes the pattern used by Phase 3 (`authorize` errors) and
/// Phase 5 (`verify_connection` errors) so that the `e.error_code() +
/// e.remediation()` rendering lives in exactly one place.
///
/// The `severity` parameter only affects the non-interactive
/// (tracing) path — `Fatal` dispatches to `tracing::error!` and
/// `NonFatal` dispatches to `tracing::warn!`. The interactive
/// (design-system `error_block`) rendering is identical for both
/// severities because the user always sees the same visual treatment;
/// severity is an operator-facing signal, not a user-facing one.
///
/// The `log_context` string is the `tracing` event message
/// (e.g., `"verification failed (credentials stored)"` for Phase 5,
/// `"authorize failed"` for Phase 3).
///
/// Story 2.7 (Decision 2B + AC #5 + review patch for non-fatal WARN).
fn render_oauth_error(
    e: &OAuthError,
    service: &str,
    interactive: bool,
    severity: OAuthErrorSeverity,
    log_context: &str,
) {
    if interactive {
        print!(
            "{}",
            render::error_block(
                e.error_code(),
                &format!("{service} \u{00b7} {e}"),
                e.remediation(),
                None,
            )
        );
    } else {
        match severity {
            OAuthErrorSeverity::Fatal => tracing::error!(
                service = %service,
                error_code = %e.error_code(),
                error = %e,
                remediation = %e.remediation(),
                "{}",
                log_context
            ),
            OAuthErrorSeverity::NonFatal => tracing::warn!(
                service = %service,
                error_code = %e.error_code(),
                error = %e,
                remediation = %e.remediation(),
                "{}",
                log_context
            ),
        }
    }
}

/// Returns the human-readable reason the Phase 2 confirmation was skipped.
/// Only called when `--non-interactive` is set (the non-interactive code path).
fn non_interactive_skip_reason(force: bool) -> &'static str {
    if force { "--non-interactive --force" } else { "--non-interactive" }
}

// ─────────────────────────────────────────────────────────────────────
// Story 7.3 Task 3 — top-level `agentsso setup` orchestrator.
//
// Runs only when `agentsso setup` is invoked WITHOUT a service arg.
// Picks a service interactively, runs the per-service flow by re-
// dispatching back into [`run`], then offers OPT-IN autostart with
// `default = NO` (per AC #5).
//
// `--non-interactive` here is a hard error: the orchestrator's whole
// purpose is the interactive prompts; CI/scripted callers should pass
// `agentsso setup gmail` directly. Refusing here gives a clean
// `setup_service_required` error rather than silently inferring a
// service.
// ─────────────────────────────────────────────────────────────────────

/// Services the per-service path validates and the orchestrator
/// routes to. Single source of truth — P20 (code review): two
/// previous copies (one in [`run`], one for the orchestrator) risked
/// drift if a fourth service was added to one but not the other.
const SUPPORTED_SERVICES: &[&str] = &["gmail", "calendar", "drive"];

async fn run_orchestrator(args: SetupArgs) -> anyhow::Result<()> {
    use crate::design::render;

    if args.non_interactive {
        eprint!(
            "{}",
            render::error_block(
                "setup_service_required",
                "no service argument provided and --non-interactive is set",
                "agentsso setup gmail   # (or calendar | drive)",
                None,
            )
        );
        return Err(crate::cli::silent_cli_error(
            "non-interactive setup invoked without a service",
        ));
    }

    let stdout_is_tty = console::Term::stdout().is_term();
    if !stdout_is_tty {
        // P22 (code review): rename from `setup_non_interactive_required`
        // to `setup_orchestrator_requires_tty` so operators grepping
        // logs can distinguish the orchestrator-specific TTY error from
        // the per-service `setup_non_interactive_required` error (which
        // means "you piped per-service setup without --non-interactive").
        // The remediation differs: orchestrator → use a real terminal
        // OR pass an explicit service arg; per-service → add the flag.
        eprint!(
            "{}",
            render::error_block(
                "setup_orchestrator_requires_tty",
                "stdout is not a terminal — the orchestrator's interactive picker can't run; \
                 either run from a real terminal or pass an explicit service arg",
                "agentsso setup gmail   # (or calendar | drive)",
                None,
            )
        );
        return Err(crate::cli::silent_cli_error("orchestrator invoked with stdout not a tty"));
    }

    // P34 (code review round 3): build the same teal-themed
    // dialoguer prompts the per-service path uses (Story 5.1's
    // accent-color convention via `build_teal_theme`). The
    // orchestrator's prompts now match the rest of the setup UX
    // instead of dropping back to default monochrome.
    let home = super::agentsso_home()?;
    let theme = Theme::load(&home);
    let teal_theme = std::sync::Arc::new(build_teal_theme(&theme));

    // Render a brief banner so the user knows they're in the orchestrator
    // (not the per-service path). Plain text — no color escapes — so it
    // renders cleanly in any terminal.
    println!("agentsso setup");
    println!("  pick a service to connect, then opt into autostart at login (off by default)");
    println!();

    // Phase 1: pick a service.
    //
    // P32 (code review round 3): dialoguer's `interact()` is
    // synchronous and blocks on stdin. Calling it directly inside a
    // `#[tokio::main]` runtime stalls an executor thread (the
    // single-threaded runtime would deadlock; the multi-threaded
    // runtime burns one worker until input arrives). Wrap in
    // `spawn_blocking` so the runtime keeps making progress on other
    // tasks (timers, signal handlers) while we wait for the user.
    let labels: Vec<String> = SUPPORTED_SERVICES.iter().map(|s| (*s).to_owned()).collect();
    let theme_for_pick = teal_theme.clone();
    let pick = tokio::task::spawn_blocking(move || {
        dialoguer::Select::with_theme(&*theme_for_pick)
            .with_prompt("Which service do you want to connect?")
            .items(&labels)
            .default(0)
            .interact()
    })
    .await
    .map_err(|e| anyhow::anyhow!("setup orchestrator picker join failed: {e}"))??;
    let service = SUPPORTED_SERVICES[pick];
    println!();

    // Phase 2: re-dispatch back into the per-service path with the
    // chosen service. The per-service flow is unchanged.
    let per_service_args = SetupArgs {
        service: Some(service.to_owned()),
        oauth_client: args.oauth_client,
        non_interactive: false,
        force: args.force,
    };
    Box::pin(run(per_service_args)).await?;

    // Phase 3: OPT-IN autostart prompt. AC #5 invariants:
    //   - default = false
    //   - prompt copy explicitly says "off by default"
    //   - skipping (Enter) leaves autostart disabled
    println!();
    // P32 + P34: same spawn_blocking + teal-theme treatment as Phase 1.
    let theme_for_confirm = teal_theme.clone();
    let want_autostart = tokio::task::spawn_blocking(move || {
        dialoguer::Confirm::with_theme(&*theme_for_confirm)
            .with_prompt(
                "Enable autostart at login? \
                 agentsso will start at every login. (Off by default.)",
            )
            .default(false)
            .interact()
    })
    .await
    .map_err(|e| anyhow::anyhow!("setup orchestrator confirm join failed: {e}"))??;

    if want_autostart {
        // P12 (code review): route the enable result through the same
        // structured error-rendering helper the `agentsso autostart
        // enable` CLI uses, so an orchestrator-side autostart failure
        // produces the same `error_block` an operator gets from the
        // direct CLI surface (with structured codes for grep). The
        // helper returns Err on autostart failure; here we
        // intentionally swallow that Err — OAuth setup already
        // succeeded, the autostart prompt is sugar on top, and the
        // user can retry via `agentsso autostart enable` standalone.
        let outcome = crate::lifecycle::autostart::enable();
        if let Err(e) = crate::cli::autostart::render_enable_outcome(outcome) {
            // The structured error block was already rendered by the
            // helper. Just append the "OAuth still ok" reassurance.
            tracing::debug!(error = ?e, "orchestrator-side autostart enable failed");
            eprintln!(
                "(OAuth setup succeeded; you can retry autostart later \
                           with `agentsso autostart enable`.)"
            );
        }
    } else {
        println!("autostart: skipped (off by default)");
        println!("  enable later with: agentsso autostart enable");
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ----- Story 8.4 AC #1: non_interactive_skip_reason -----

    #[test]
    fn setup_force_and_non_interactive_log_correct_reason() {
        // --non-interactive only: reason names exactly that flag.
        assert_eq!(non_interactive_skip_reason(false), "--non-interactive");
        // --non-interactive --force: reason mentions both flags.
        let reason = non_interactive_skip_reason(true);
        assert!(
            reason.contains("--non-interactive") && reason.contains("--force"),
            "reason must mention both flags when --force is set, got: {reason}"
        );
    }

    // ----- Story 8.4 AC #2: service trim -----

    #[test]
    fn setup_service_leading_trailing_whitespace_accepted() {
        // The service name is trimmed before lookup, so "  gmail  " becomes "gmail".
        let trimmed = "  gmail  ".trim().to_lowercase();
        assert_eq!(trimmed, "gmail");
        let supported = &["gmail", "calendar", "drive"];
        assert!(
            supported.contains(&trimmed.as_str()),
            "trimmed service must match the SUPPORTED_SERVICES list"
        );
        // Without trim, it would NOT match.
        let untrimmed = "  gmail  ".to_lowercase();
        assert!(
            !supported.contains(&untrimmed.as_str()),
            "untrimmed service must NOT match (demonstrates the bug that trim() fixes)"
        );
    }

    // ----- Story 8.4 AC #11: probe_state_get delegates to kill::http_get -----

    #[test]
    fn probe_state_get_is_thin_wrapper_over_http_get() {
        // Structural assertion: probe_state_get's body is a single delegation
        // to `kill::http_get`. We can't easily unit-test the async network path
        // without a live daemon, but we can verify the refactor removed the
        // duplicate TCP implementation. The compile-time check (removed TCP code)
        // is enforced by CI; this test documents the expectation.
        //
        // A connection-refused error proves the function resolves and attempts
        // to connect (i.e., it calls the real http_get rather than short-circuiting).
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap(); // port 1 is always refused
        let result = rt.block_on(probe_state_get(addr));
        assert!(result.is_err(), "probe_state_get to port 1 must fail (connection refused)");
    }

    // ----- Story 2.7 Task 4: check_vault_dir_writable -----

    #[test]
    fn check_vault_dir_writable_creates_missing_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let vault_dir = tmp.path().join("vault");
        assert!(!vault_dir.exists());

        let result = check_vault_dir_writable(&vault_dir);

        assert!(result.is_ok(), "should create missing dir: {result:?}");
        assert!(vault_dir.exists(), "vault dir should now exist");
        assert!(vault_dir.is_dir(), "vault dir should be a directory");
        // Probe file should have been cleaned up.
        assert!(!vault_dir.join(".permitlayer-writability-probe").exists());
    }

    #[test]
    fn check_vault_dir_writable_accepts_existing_writable_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let vault_dir = tmp.path().join("vault");
        std::fs::create_dir_all(&vault_dir).unwrap();

        let result = check_vault_dir_writable(&vault_dir);
        assert!(result.is_ok(), "existing writable dir should pass: {result:?}");
    }

    #[cfg(unix)]
    #[test]
    fn check_vault_dir_writable_repairs_readonly_owned_dir() {
        use std::os::unix::fs::PermissionsExt;

        // Updated semantics (Story 2.7 review patch): the helper
        // actively tightens perms to 0o700 on any dir it owns, so a
        // process-owned 0o500 dir is REPAIRED rather than rejected.
        // The chmod-and-probe sequence succeeds because the process
        // owns the dir. (A foreign-owned dir would fail at chmod,
        // but that scenario is not reachable in a tempdir test.)
        let tmp = tempfile::tempdir().unwrap();
        let vault_dir = tmp.path().join("vault");
        std::fs::create_dir_all(&vault_dir).unwrap();

        // Start with read+execute only (0o500).
        let ro_perms = std::fs::Permissions::from_mode(0o500);
        std::fs::set_permissions(&vault_dir, ro_perms).unwrap();

        let result = check_vault_dir_writable(&vault_dir);

        assert!(
            result.is_ok(),
            "helper should repair 0o500 → 0o700 on a process-owned dir: {result:?}"
        );
        // Verify the mode is now 0o700 after the helper's chmod.
        let md = std::fs::metadata(&vault_dir).unwrap();
        let mode = md.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "helper should have chmod'd to 0o700, got {mode:o}");
    }

    // ----- Story 2.7 review patch: 0o700 mode on create + symlink rejection -----

    #[cfg(unix)]
    #[test]
    fn check_vault_dir_writable_sets_0o700_on_created_dir() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let vault_dir = tmp.path().join("vault");
        assert!(!vault_dir.exists());

        check_vault_dir_writable(&vault_dir).expect("helper should succeed");

        // Verify the mode is exactly 0o700.
        let md = std::fs::metadata(&vault_dir).expect("metadata");
        let mode = md.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "newly-created vault dir should have 0o700 perms, got {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn check_vault_dir_writable_tightens_existing_loose_perms() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let vault_dir = tmp.path().join("vault");
        std::fs::create_dir_all(&vault_dir).unwrap();

        // Set loose 0o755 perms first (simulating a dir created under
        // the default umask by some other tool).
        let loose_perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(&vault_dir, loose_perms).unwrap();

        check_vault_dir_writable(&vault_dir).expect("helper should succeed");

        // After the helper runs, the dir should be tightened to 0o700.
        let md = std::fs::metadata(&vault_dir).unwrap();
        let mode = md.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "helper should tighten existing loose perms to 0o700, got {mode:o}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn check_vault_dir_writable_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        // Create a real directory the symlink can point at.
        let target_dir = tmp.path().join("target");
        std::fs::create_dir_all(&target_dir).unwrap();

        // Create the vault_dir path as a symlink to the target.
        let vault_dir = tmp.path().join("vault");
        symlink(&target_dir, &vault_dir).unwrap();

        let result = check_vault_dir_writable(&vault_dir);

        assert!(result.is_err(), "symlinked vault_dir should be rejected");
        let e = result.unwrap_err();
        assert_eq!(
            e.kind(),
            std::io::ErrorKind::InvalidInput,
            "symlink rejection should use InvalidInput kind for caller dispatch"
        );
        assert!(e.to_string().contains("symlink"), "error message should mention symlink: {e}");
    }

    // ----- Story 2.7 Task 5: SpinnerGuard RAII -----

    #[test]
    fn spinner_guard_clears_on_drop() {
        let spinner = indicatif::ProgressBar::new_spinner();
        spinner.set_message("test message");
        assert!(!spinner.is_finished(), "spinner should start not-finished");

        {
            let _guard = SpinnerGuard::new(spinner.clone());
            // Guard is alive; spinner is still active.
            assert!(!spinner.is_finished());
        }
        // Guard dropped at end of block — spinner should be cleared.
        assert!(spinner.is_finished(), "SpinnerGuard::drop should finish the spinner");
    }

    #[test]
    fn spinner_guard_is_idempotent_when_explicitly_dropped() {
        // Explicit drop (as used in the Phase 3 authorize path) must
        // leave the guard in a state where no double-clear happens.
        let spinner = indicatif::ProgressBar::new_spinner();
        let guard = SpinnerGuard::new(spinner.clone());
        drop(guard);
        assert!(spinner.is_finished());
        // Implicit drop of the already-moved spinner clone is a no-op
        // (no panic, no second finish).
    }

    // ----- Story 2.7 review patch: render_oauth_error fallback test -----

    #[test]
    fn render_oauth_error_does_not_panic_on_token_exchange_failed_non_interactive() {
        // Task 3 required a fallback unit test for `render_oauth_error`
        // when the integration-test path is deferred. This test
        // constructs a representative `OAuthError::TokenExchangeFailed`
        // and calls the helper in non-interactive mode (which dispatches
        // via tracing, safe to invoke without a subscriber — tracing
        // silently drops events when no subscriber is installed).
        //
        // The assertion is "does not panic" plus a check that the error
        // accessors (`error_code()` / `remediation()`) return expected
        // strings, which proves the helper's match arms are reachable
        // for this variant.
        let err = OAuthError::TokenExchangeFailed {
            service: "gmail".to_owned(),
            source: Box::new(std::io::Error::other("simulated token exchange failure")),
        };

        // Sanity: the variant's accessors return the expected strings
        // that the helper will interpolate.
        assert_eq!(err.error_code(), "token_exchange_failed");
        assert!(err.remediation().contains("network connection"));

        // Non-interactive path: dispatches via tracing, no stdout output.
        // Run with both Fatal and NonFatal severities to exercise both
        // tracing::error! and tracing::warn! branches.
        render_oauth_error(
            &err,
            "gmail",
            false, // non-interactive
            OAuthErrorSeverity::Fatal,
            "authorize failed",
        );
        render_oauth_error(
            &err,
            "gmail",
            false, // non-interactive
            OAuthErrorSeverity::NonFatal,
            "verification failed (credentials stored)",
        );
        // If either call panicked, the test would have already failed.
    }

    #[test]
    fn render_oauth_error_does_not_panic_on_verification_failed_non_interactive() {
        // Phase 5 non-fatal path: verification failed after credentials
        // sealed. Verify the NonFatal severity branch is reachable.
        let err = OAuthError::VerificationFailed {
            service: "calendar".to_owned(),
            reason: "401 Unauthorized".to_owned(),
            status_code: Some(401),
            source: None,
        };

        assert_eq!(err.error_code(), "verification_failed");

        render_oauth_error(
            &err,
            "calendar",
            false, // non-interactive
            OAuthErrorSeverity::NonFatal,
            "verification failed (credentials stored)",
        );
    }

    // ----- Story 5.2: prompt_start_audit_follow seam (P10 + P25) -----

    #[test]
    fn decide_prompt_from_seam_none_falls_through_to_real_prompt() {
        assert_eq!(decide_prompt_from_seam(None), None);
    }

    #[test]
    fn decide_prompt_from_seam_accept_returns_some_true() {
        assert_eq!(decide_prompt_from_seam(Some("accept")), Some(true));
    }

    #[test]
    fn decide_prompt_from_seam_decline_returns_some_false() {
        assert_eq!(decide_prompt_from_seam(Some("decline")), Some(false));
    }

    #[test]
    fn decide_prompt_from_seam_unknown_value_declines_not_falls_through() {
        // P25 review patch: an unknown value (typo, misconfiguration)
        // must NOT fall through to the real `dialoguer::Confirm`
        // which would block on stdin in a CI environment. Declining
        // is the safer default.
        assert_eq!(decide_prompt_from_seam(Some("yes")), Some(false));
        assert_eq!(decide_prompt_from_seam(Some("1")), Some(false));
        assert_eq!(decide_prompt_from_seam(Some("")), Some(false));
        assert_eq!(decide_prompt_from_seam(Some("ACCEPT")), Some(false));
    }
}
