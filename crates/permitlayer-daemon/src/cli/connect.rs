//! `agentsso connect <service>` — one-verb orchestration of the
//! agent-onboarding journey (Story 7.13).
//!
//! Composes existing primitives into an idempotent state machine:
//!
//! 1. **Pre-flight** — agent exists, service is supported, flags are coherent.
//! 2. **OAuth + seal** — sealed credential present? skip. Else: refuse if
//!    daemon up; run inner OAuth flow (browser or rc.13 paste); seal into vault.
//! 3. **Verify (with retry loop)** — `verify::verify_connection` with up to
//!    5 retries; renders `OAuthError::remediation_owned()` between attempts so
//!    Story 7.12's actionable URLs surface.
//! 4. **Policy edit** — `policy::edit::add_scopes_to_policy` merges granted
//!    scopes into the agent's policy file. No-op when scopes are already
//!    present (idempotent).
//! 5. **Reload** — `POST /v1/control/reload` so the rebind sees the new scopes.
//!    Skipped when Step 4 was a no-op.
//! 6. **Rebind** — `POST /v1/control/agent/rebind` (Story 7.11). Same-policy
//!    rebind is a server-side no-op; CLI logs it as such.
//! 7. **OpenClaw snippet emission** — prints the JSON snippet to stdout
//!    (with copy-paste delimiter block); optionally writes to
//!    `--mcp-config-out <path>` for cross-user / scripted handoff. Connect
//!    does NOT auto-merge into another user's `~/.openclaw/openclaw.json`
//!    — see `cli::openclaw` module docs for the admin/user-split rationale.
//! 8. **Summary** — one block listing each step's outcome.
//!
//! Re-running `connect` with identical args after a successful run is a
//! guaranteed end-to-end no-op: each step detects "already done" and
//! returns "no change". Bearer tokens are NOT rotated (Story 7.11
//! invariant). Policy files are NOT re-written when scopes are already
//! present. The integration tests assert byte-equality of every state-
//! holding file across re-runs.
//!
//! # Replaces `agentsso setup`
//!
//! Story 7.13 deletes `cli/setup.rs` entirely. This file consumes the
//! per-service OAuth-and-seal flow that lived inside `setup.rs::run`
//! (lines 351-619 in the rc.14 archive) and layers Steps 4-7 on top.
//! The `--non-interactive` orchestrator path from setup is dropped:
//! `agentsso connect` always requires an explicit service arg.
//! Operators invoking the legacy `agentsso setup` see a
//! `setup.removed` remediation block from `main.rs`'s top-level
//! interceptor (Task 4 of Story 7.13).

use std::path::{Path, PathBuf};

use clap::Args;
use permitlayer_core::store::CredentialStore;
use permitlayer_core::store::fs::CredentialFsStore;
use permitlayer_keystore::{AclBreakRecoveryMode, FallbackMode, KeystoreConfig, default_keystore};
use permitlayer_oauth::google::consent::GoogleOAuthConfig;
use permitlayer_oauth::google::scopes;
use permitlayer_oauth::google::verify;
use permitlayer_oauth::metadata::{CredentialMeta, write_metadata_atomic};
use permitlayer_vault::Vault;

use crate::design::render;
use crate::design::terminal::{ColorSupport, styled};
use crate::design::theme::Theme;

// Round-1 D1 (re-audit): OAuth-flow rendering helpers factored out of
// this file into `cli::oauth_render`. See module-level docs there.
use super::oauth_render::{
    HEADLESS_PASTE_TIMEOUT_SECS, OAuthErrorSeverity, SpinnerGuard, build_teal_theme,
    check_vault_dir_writable, print_headless_consent_block, read_pasted_redirect_url,
    render_oauth_error,
};

// ──────────────────────────────────────────────────────────────────
// Exit-code marker
// ──────────────────────────────────────────────────────────────────

/// Exit-code 2 marker — operator-correctable input error (unknown
/// agent, unknown service, missing OAuth client).
#[derive(Debug)]
pub(crate) struct ConnectExitCode2;

impl std::fmt::Display for ConnectExitCode2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("connect: operator-correctable input")
    }
}

impl std::error::Error for ConnectExitCode2 {}

pub(crate) fn exit2() -> anyhow::Error {
    anyhow::Error::new(ConnectExitCode2).context(crate::cli::SilentCliError)
}

/// Exit-code 3 marker — resource conflict (e.g., daemon running while
/// connect needs to seal a new credential).
///
/// Mirrors `cli::setup::SetupExitCode3` (which this story removes).
/// `main.rs::connect_to_exit_code` downcasts the chain.
#[derive(Debug)]
pub(crate) struct ConnectExitCode3;

impl std::fmt::Display for ConnectExitCode3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("connect: resource conflict")
    }
}

impl std::error::Error for ConnectExitCode3 {}

pub(crate) fn exit3() -> anyhow::Error {
    anyhow::Error::new(ConnectExitCode3).context(crate::cli::SilentCliError)
}

/// Exit-code dispatch helper for connect-specific error codes.
///
/// Connect has its own taxonomy distinct from `agent_control_exit_code`
/// (Story 7.11 round-2 codex gotcha): connect's error space includes
/// OAuth, browser, provider, and orchestration failures that don't
/// fit the agent CRUD shape.
///
/// - **2 (operator-correctable)**: connect.agent_not_found,
///   connect.unknown_service, connect.invalid_oauth_client,
///   connect.daemon_must_stop, connect.vault_dir_*, connect.non_interactive_required.
/// - **3 (system / retry)**: connect.oauth_failed, connect.verify_failed,
///   connect.policy_edit_failed, connect.reload_failed, connect.rebind_failed,
///   connect.openclaw_failed.
///
/// Used both by the unit tests (mapping table) and by [`silent_err_for_code`]
/// (which produces the right typed marker for `connect_to_exit_code` to
/// downcast). Story 7.13 round-1 P1 wired this in: previously many failure
/// paths used bare `silent_cli_error` which produced exit 1; the spec table
/// in Dev Notes promised 2/3 per code.
pub(crate) fn connect_exit_code(code: &str) -> i32 {
    match code {
        "connect.agent_not_found"
        | "connect.unknown_service"
        | "connect.invalid_oauth_client"
        | "connect.daemon_must_stop"
        | "connect.non_interactive_required"
        | "connect.vault_dir_symlink"
        | "connect.vault_dir_unwritable"
        | "setup.removed" => 2,
        _ => 3,
    }
}

/// Build a silent CLI error tagged with the right exit-code marker for
/// the given operator-facing error code. The `error_block` rendering is
/// the caller's responsibility; this helper attaches ONLY the typed
/// marker so `main.rs::connect_to_exit_code` produces the right exit
/// code.
///
/// Round-1 P1 fix: replaces bare `crate::cli::silent_cli_error(msg)` calls
/// throughout `run` so the spec's exit-code table actually fires at runtime.
pub(crate) fn silent_err_for_code(code: &str, internal_msg: &'static str) -> anyhow::Error {
    let marker_attached = match connect_exit_code(code) {
        2 => anyhow::Error::new(ConnectExitCode2),
        _ => anyhow::Error::new(ConnectExitCode3),
    };
    marker_attached.context(crate::cli::SilentCliError).context(internal_msg)
}

const SUPPORTED_SERVICES: &[&str] = &["gmail", "calendar", "drive"];

/// Resolve device-flow endpoints. Production: Google's hardcoded URLs.
///
/// Story 7.17 Task 3.8: under `#[cfg(debug_assertions)]` builds (i.e.
/// `cargo test`, dev-builds), honor `AGENTSSO_DEVICE_FLOW_DEVICE_CODE_URL`
/// and `AGENTSSO_DEVICE_FLOW_TOKEN_URL` so integration tests can point
/// the polling loop at a mockito server. Release builds compile this
/// branch out — operators cannot accidentally hijack the OAuth flow
/// via env vars.
fn device_flow_endpoints() -> permitlayer_oauth::google::device_flow::DeviceFlowEndpoints {
    #[cfg(debug_assertions)]
    {
        let device_code_override = std::env::var("AGENTSSO_DEVICE_FLOW_DEVICE_CODE_URL").ok();
        let token_override = std::env::var("AGENTSSO_DEVICE_FLOW_TOKEN_URL").ok();
        if device_code_override.is_some() || token_override.is_some() {
            let mut endpoints =
                permitlayer_oauth::google::device_flow::DeviceFlowEndpoints::google();
            if let Some(u) = device_code_override {
                endpoints.device_code = u;
            }
            if let Some(u) = token_override {
                endpoints.token = u;
            }
            return endpoints;
        }
    }
    permitlayer_oauth::google::device_flow::DeviceFlowEndpoints::google()
}

/// Story 3.2 AC #7: refuse to run `agentsso connect` when a running
/// daemon's kill switch is active.
///
/// Short-circuits to `Ok(())` (connect proceeds) in these cases:
/// - No PID file (fresh install / daemon not running).
/// - PID file exists but process is gone (stale PID).
/// - Any probe failure (connect refused, timeout, non-200, malformed body).
///
/// Only exits the process when the daemon explicitly reports
/// `{"active": true}`. Defense in depth: a broken probe must NEVER
/// block the user from running connect — failing-closed here is
/// worse than failing-open.
///
/// Ported verbatim from the legacy `cli/setup.rs::probe_daemon_kill_state_or_exit`
/// (Story 7.13). The `kill_resume_e2e::setup_blocked_when_killed` test
/// was updated to drive this against connect.
async fn probe_daemon_kill_state_or_exit() -> anyhow::Result<()> {
    use crate::config::{CliOverrides, DaemonConfig};
    use crate::lifecycle::pid::PidFile;

    let config = match DaemonConfig::load(&CliOverrides::default()) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                target: "connect",
                error = %e,
                "DaemonConfig::load failed during kill-state probe; proceeding with connect",
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

    let bind_addr = config.http.bind_addr;
    let probe_deadline = std::time::Duration::from_millis(500);
    let control_token = crate::cli::kill::read_control_token(home);

    let probe_result = tokio::time::timeout(
        probe_deadline,
        crate::cli::kill::http_get(bind_addr, "/v1/control/state", control_token.as_deref()),
    )
    .await;

    let body = match probe_result {
        Ok(Ok(body)) => body,
        Ok(Err(e)) => {
            tracing::warn!(target: "connect", error = %e, "kill-state probe failed; proceeding with connect");
            return Ok(());
        }
        Err(_elapsed) => {
            tracing::warn!(target: "connect", "kill-state probe timed out; proceeding with connect");
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
                target: "connect",
                error = %e,
                body = %body,
                "unexpected state response; proceeding with connect"
            );
            return Ok(());
        }
    };

    if snapshot.active {
        eprint!(
            "{}",
            render::error_block(
                "daemon_killed",
                "permitlayer is in kill state \u{2014} connect cannot open new OAuth flows",
                "agentsso resume",
                None,
            )
        );
        return Err(exit2());
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────────
// CLI args
// ──────────────────────────────────────────────────────────────────

/// Arguments for `agentsso connect <service>`.
///
/// Service is REQUIRED — there is no orchestrator path. Operators
/// invoking `agentsso connect` without a service arg get clap's
/// missing-arg error pointing at the supported services.
#[derive(Args, Debug)]
pub struct ConnectArgs {
    /// Service to connect: `gmail`, `calendar`, or `drive`.
    pub service: String,

    /// Agent name. Must already exist (created via
    /// `agentsso agent register <name> --policy <policy>`).
    #[arg(long)]
    pub agent: String,

    /// Path to a Google OAuth client JSON file. Currently required
    /// (no shared CASA-certified client ships yet).
    #[arg(long = "oauth-client", value_name = "PATH")]
    pub oauth_client: Option<PathBuf>,

    /// Skip all interactive prompts. Without `--bearer-token`, Step 7
    /// emits the snippet with a `<REPLACE_WITH_TOKEN>` placeholder.
    #[arg(long)]
    pub non_interactive: bool,

    /// Skip browser launch; print the auth URL and accept the
    /// pasted redirect URL via stdin. Use when SSH'd from a different
    /// machine. Mutually exclusive with `--non-interactive` (the
    /// paste flow needs a controlling terminal).
    #[arg(long, conflicts_with = "non_interactive")]
    pub headless: bool,

    /// Use Google OAuth 2.0 device flow (RFC 8628) for truly headless
    /// boxes with no browser. Story 7.17 Task 3.
    ///
    /// Operator opens the printed URL on any device with a browser
    /// (laptop, phone, kiosk) and types the printed user code.
    /// Polling completes without operator interaction at the target
    /// machine — no SSH-tunneled paste, no `xdg-open` required.
    ///
    /// Requires an OAuth client of type **TV and Limited Input
    /// Device** (separate Google client type from the **Desktop app**
    /// type that scenarios #1 and #2 use). See `docs/user-guide/install.md`.
    ///
    /// Compatible with `--non-interactive` (the canonical scripted-
    /// headless invocation). Mutually exclusive only with `--headless`
    /// (the paste-redirect flow takes a different code path).
    #[arg(long, conflicts_with = "headless")]
    pub device_flow: bool,

    /// Timeout for device-flow polling in seconds. Default 120s.
    /// Hard ceiling at Google's `expires_in` (typically 1800s).
    /// Story 7.17 Task 3.
    #[arg(long, default_value = "120", requires = "device_flow")]
    pub device_flow_timeout: u64,

    /// Overwrite an existing sealed credential without prompting.
    /// Implied by `--non-interactive`.
    #[arg(long)]
    pub force: bool,

    /// Bearer token captured from `agentsso agent register` (used to
    /// build the OpenClaw snippet in Step 7).
    ///
    /// **Prefer `AGENTSSO_BEARER_TOKEN` env var to this flag**: command-line
    /// arguments leak into shell history (`~/.bash_history`,
    /// `~/.zsh_history`) and are visible to other users on the host via
    /// `ps auxww` / `/proc/<pid>/cmdline`. The env var avoids both leaks.
    ///
    /// In interactive mode, omitting both this flag and the env var
    /// prompts via stdin (`dialoguer::Password`, hidden echo). In
    /// `--non-interactive` mode without either, the snippet uses a
    /// `<REPLACE_WITH_TOKEN>` placeholder for downstream substitution.
    #[arg(long)]
    pub bearer_token: Option<String>,

    /// Write the OpenClaw MCP config snippet to this path (in addition
    /// to stdout). Mode 0o644 — intentionally world-readable for
    /// admin → user handoff via shared filesystem (the admin running
    /// connect and the end user running OpenClaw are typically distinct
    /// principals; see `cli::openclaw` module docs).
    #[arg(long = "mcp-config-out", value_name = "PATH")]
    pub mcp_config_out: Option<PathBuf>,
}

// ──────────────────────────────────────────────────────────────────
// Run
// ──────────────────────────────────────────────────────────────────

/// Run the `connect` subcommand.
pub async fn run(args: ConnectArgs) -> anyhow::Result<()> {
    use anyhow::Context as _;

    // Single-shot CLI command — install only the stdout subscriber.
    let _guards =
        crate::telemetry::init_tracing("info", None, 30).context("tracing init failed")?;

    let service = args.service.trim().to_lowercase();

    // Step 1a — service allowlist.
    if !SUPPORTED_SERVICES.contains(&service.as_str()) {
        eprint!(
            "{}",
            render::error_block(
                "connect.unknown_service",
                &format!(
                    "unsupported service '{service}'. Supported services: {}",
                    SUPPORTED_SERVICES.join(", ")
                ),
                &format!(
                    "agentsso connect <service> --agent <name> --oauth-client <path>\n\n  \
                     supported services: {}",
                    SUPPORTED_SERVICES.join(", ")
                ),
                None,
            )
        );
        return Err(exit2());
    }

    // Round-1 P12: when `--headless` is set, the paste-redirect-URL
    // flow needs STDIN to be a TTY (operator types/pastes the URL),
    // not stdout (which can be piped to a log without breaking the
    // flow). For non-headless interactive mode we still need stdout
    // to be a TTY because the design system's prompts render there.
    let stdout_is_tty = console::Term::stdout().is_term();
    let stdin_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
    let needed_tty_present = if args.headless { stdin_is_tty } else { stdout_is_tty };
    if !args.non_interactive && !needed_tty_present {
        let (which, remediation_hint) = if args.headless {
            ("stdin", "run from a terminal that has stdin attached, or drop --headless")
        } else {
            (
                "stdout",
                "pass --non-interactive (and supply --bearer-token + --oauth-client + \
                 AGENTSSO_BEARER_TOKEN), or run from a real terminal",
            )
        };
        eprint!(
            "{}",
            render::error_block(
                "connect.non_interactive_required",
                &format!(
                    "{which} is not a terminal — interactive prompts are unsafe in this context"
                ),
                remediation_hint,
                None,
            )
        );
        // Round-1 P11: was `std::process::exit(1)` which bypasses the
        // tracing WorkerGuard flush AND uses the wrong exit code.
        // `non_interactive_required` is operator-correctable → exit 2.
        return Err(silent_err_for_code(
            "connect.non_interactive_required",
            "required TTY missing and --non-interactive was not set",
        ));
    }
    let interactive = !args.non_interactive && needed_tty_present;

    // Story 3.2 AC #7: block when daemon's kill switch is active.
    // Runs BEFORE the daemon-running gate so the more-specific
    // remediation (`agentsso resume`) wins when applicable.
    probe_daemon_kill_state_or_exit().await?;

    let home = super::agentsso_home()?;
    let theme = Theme::load(&home);
    let color_support = ColorSupport::detect();
    tracing::info!(
        home = %home.display(),
        service = %service,
        agent = %args.agent,
        "starting connect flow"
    );

    // ── Step 1b — agent existence pre-check (AC #5) ────────────────
    //
    // Read the agent file directly via the FS store rather than
    // contacting the daemon. The control plane has no
    // GET /v1/control/agent/<name> endpoint, only `list`, and the
    // agent file is the source of truth anyway. Failing this step
    // produces an operator-actionable error BEFORE any vault touch.
    let agent_policy_name = match resolve_agent_policy_name(&home, &args.agent).await? {
        Some(p) => p,
        None => {
            eprint!(
                "{}",
                render::error_block(
                    "connect.agent_not_found",
                    &format!("agent '{}' not found", args.agent),
                    &format!(
                        "agentsso agent register {} --policy <policy-name>\n\n  \
                         then re-run this command:\n  \
                         agentsso connect {service} --agent {}",
                        args.agent, args.agent
                    ),
                    None,
                )
            );
            return Err(exit2());
        }
    };

    if interactive {
        let styled_service = styled(&service, theme.tokens().accent, color_support);
        let styled_agent = styled(&args.agent, theme.tokens().accent, color_support);
        println!();
        println!("agentsso connect {styled_service} \u{00b7} agent {styled_agent}");
        println!("  policy: {agent_policy_name}");
        println!();
    }

    // ── Step 2 — OAuth + seal (vault-touching phase) ───────────────
    //
    // Round-1 P15 ordering fix: detect credential coverage AND gate
    // daemon-running BEFORE resolving the OAuth client. The previous
    // ordering forced operators who hit the daemon-running gate to
    // first navigate the missing-OAuth-client error — but `agentsso
    // stop` is the actual blocker, so it should be the first thing
    // they see. Resolving the OAuth client is also expensive
    // (interactive prompt) and unnecessary on the credential-skip path.
    let vault_dir = home.join("vault");
    let meta_path = vault_dir.join(format!("{service}-meta.json"));
    let credential_already_present = !args.force && credential_covers_target(&meta_path, &service);

    // Need to seal a new credential? Gate on daemon-running BEFORE
    // any OAuth-client work.
    if !credential_already_present {
        // Round-1 P8: typed daemon-running state distinguishes "known
        // PID" from "running but PID-file unreadable" so the rendered
        // error message no longer says misleading "PID 0".
        let pid_hint = match daemon_running_state(&home) {
            DaemonRunningState::NotRunning => None,
            DaemonRunningState::Running(pid) => Some(format!(" (PID {pid})")),
            DaemonRunningState::RunningUnknownPid => Some(String::new()),
        };
        if let Some(hint) = pid_hint {
            eprint!(
                "{}",
                render::error_block(
                    "connect.daemon_must_stop",
                    &format!(
                        "agentsso daemon is running{hint}; connecting a service \
                         requires sealing a new credential and must not race against a \
                         live daemon."
                    ),
                    &format!(
                        "agentsso stop && agentsso connect {service} --agent {} --oauth-client <path>",
                        args.agent
                    ),
                    None,
                )
            );
            return Err(exit3());
        }
    }

    // `oauth_config` is needed only on the seal path AND for verify's
    // project_id rendering. On the credential-skip path it's None
    // (we never asked the operator for `--oauth-client` because we
    // didn't need to seal). Downstream verify and summary tolerate
    // None — verify renders 7.12's actionable URLs without the
    // `?project=<id>` query param when project_id is unknown.
    let mut oauth_config_opt: Option<GoogleOAuthConfig> = None;

    let granted_scopes: Vec<String> = if credential_already_present {
        if interactive {
            let check = styled("\u{2713}", theme.tokens().accent, color_support);
            println!("  {check} oauth + seal \u{00b7} skipped (credential already present)");
        } else {
            tracing::info!(service = %service, "oauth + seal skipped: credential present");
        }
        // Capture scopes from existing meta for downstream policy merge.
        match std::fs::read_to_string(&meta_path) {
            Ok(text) => match serde_json::from_str::<CredentialMeta>(&text) {
                Ok(m) => m.scopes,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path = %meta_path.display(),
                        "credential meta failed to parse; using default scopes for service"
                    );
                    scopes::default_scopes_for_service(&service)
                        .into_iter()
                        .map(str::to_owned)
                        .collect()
                }
            },
            Err(_) => scopes::default_scopes_for_service(&service)
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }
    } else {
        // Resolve the OAuth client now that the daemon-running gate
        // passed. Same shape as setup.rs had (interactive prompt fallback
        // when `--oauth-client` is absent and we're on a TTY).
        // Validation reads `client_secret.json`; the parsed `project_id`
        // flows into Step 3's verify call.
        // Resolve once, hold by reference for the rest of this block;
        // move into `oauth_config_opt` at the end of the block so the
        // verify + summary code outside the if/else can read it.
        let oauth_config = resolve_oauth_client(&args, &service, &theme, interactive).await?;

        // Phase 0: vault dir writability.
        if let Err(e) = check_vault_dir_writable(&vault_dir) {
            let (code, remediation) = if e.kind() == std::io::ErrorKind::InvalidInput {
                (
                    "connect.vault_dir_symlink",
                    "rm ~/.agentsso/vault && mkdir -p -m 0700 ~/.agentsso/vault",
                )
            } else {
                (
                    "connect.vault_dir_unwritable",
                    "chmod 0700 ~/.agentsso/vault || mkdir -p -m 0700 ~/.agentsso/vault",
                )
            };
            eprint!(
                "{}",
                render::error_block(
                    code,
                    &format!("{}: {e}", vault_dir.display()),
                    remediation,
                    None
                )
            );
            return Err(silent_err_for_code(code, "vault dir unwritable"));
        }

        // Phase 1: scope preview (interactive only).
        let teal_theme = std::sync::Arc::new(build_teal_theme(&theme));

        if interactive {
            if meta_path.exists() && !args.force {
                let styled_service = styled(&service, theme.tokens().accent, color_support);
                println!(
                    "  {styled_service} is already connected \u{00b7} re-running will replace existing credentials"
                );
                let theme_clone = teal_theme.clone();
                let confirm = tokio::task::spawn_blocking(move || {
                    dialoguer::Confirm::with_theme(&*theme_clone)
                        .with_prompt("replace existing credentials?")
                        .default(false)
                        .interact()
                })
                .await
                .map_err(|e| anyhow::anyhow!("connect overwrite-confirm join failed: {e}"))??;
                if !confirm {
                    println!("  connect cancelled");
                    return Ok(());
                }
                println!();
            }
            let scope_infos = scopes::default_scope_infos_for_service(&service);
            let styled_service = styled(&service, theme.tokens().accent, color_support);
            println!("  {styled_service} \u{00b7} scopes to request:");
            for info in &scope_infos {
                println!("    {} ({})", info.description, info.short_name);
            }
            println!();

            // Phase 2: confirm browser open (skipped in headless mode
            // and in device-flow mode — neither opens a local browser).
            if !args.headless && !args.device_flow {
                let theme_clone = teal_theme.clone();
                let confirm = tokio::task::spawn_blocking(move || {
                    dialoguer::Confirm::with_theme(&*theme_clone)
                        .with_prompt("open browser for Google consent?")
                        .default(false)
                        .interact()
                })
                .await
                .map_err(|e| anyhow::anyhow!("connect browser-confirm join failed: {e}"))??;
                if !confirm {
                    println!("  connect cancelled");
                    return Ok(());
                }
            }
        }

        // Phase 3: browser + spinner / headless paste.
        // Story 7.22: `acl_break_recovery: Disabled` preserves the
        // existing passphrase-prompt fallback for non-boot CLI paths.
        // Only `start.rs::ensure_master_key_bootstrapped` opts into
        // `Auto`.
        let keystore_config = KeystoreConfig {
            fallback: FallbackMode::Auto,
            home: home.clone(),
            acl_break_recovery: AclBreakRecoveryMode::Disabled,
        };
        let keystore = default_keystore(&keystore_config)?;
        let master_key = keystore.master_key().await?.key;
        let active_key_id = super::start::compute_active_key_id(&home.join("vault"));
        let vault = Vault::new(master_key, active_key_id);
        let client = permitlayer_oauth::OAuthClient::new(
            oauth_config.client_id().to_owned(),
            oauth_config.client_secret().map(str::to_owned),
        )?;

        let default_scopes = scopes::default_scopes_for_service(&service);
        let scopes_owned: Vec<String> = default_scopes.iter().map(|s| (*s).to_owned()).collect();

        let result = if args.device_flow {
            // Story 7.17 Task 3: Google OAuth 2.0 device flow.
            // Operator opens the printed URL on any device with a
            // browser; this code path never touches the local browser
            // or stdin (paste-redirect lives in the `--headless` arm).
            // Compatible with `--non-interactive` — the splice deliberately
            // lives BEFORE the `interactive` branch.
            tracing::info!(
                timeout_secs = args.device_flow_timeout,
                "running OAuth 2.0 device flow (RFC 8628)"
            );
            // Build a dedicated HTTP client for the device-flow polling
            // loop. Mirrors the `build_verify_client` shape from
            // `permitlayer_oauth::google::verify` (Story 7.12 R3-P26).
            let device_http = match reqwest::Client::builder()
                .user_agent("agentsso/0.1")
                .timeout(std::time::Duration::from_secs(30))
                .read_timeout(std::time::Duration::from_secs(10))
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = %e, "failed to build device-flow http client");
                    return Err(silent_err_for_code(
                        "connect.oauth_failed",
                        "device-flow http client build failed",
                    ));
                }
            };
            let scope_refs: Vec<&str> = scopes_owned.iter().map(String::as_str).collect();
            let endpoints = device_flow_endpoints();
            let device_result = permitlayer_oauth::google::device_flow::run_device_flow(
                &device_http,
                endpoints,
                oauth_config.client_id(),
                &scope_refs,
                Some(std::time::Duration::from_secs(args.device_flow_timeout)),
                &permitlayer_oauth::google::device_flow::SystemClock,
                &permitlayer_oauth::google::device_flow::TokioSleeper,
            )
            .await;
            match device_result {
                Ok(r) => r.into(),
                Err(e) => {
                    render_oauth_error(
                        &e,
                        &service,
                        interactive,
                        OAuthErrorSeverity::Fatal,
                        "device-flow authorize failed",
                    );
                    return Err(silent_err_for_code("connect.oauth_failed", "oauth failed"));
                }
            }
        } else if args.headless {
            tracing::info!("running headless OAuth flow (no callback listener)");
            let r = client
                .authorize_headless(scopes_owned.clone(), |url| async move {
                    print_headless_consent_block(&url);
                    read_pasted_redirect_url().await
                })
                .await;
            match r {
                Ok(r) => r,
                Err(e) => {
                    render_oauth_error(
                        &e,
                        &service,
                        interactive,
                        OAuthErrorSeverity::Fatal,
                        "headless authorize failed",
                    );
                    return Err(silent_err_for_code("connect.oauth_failed", "oauth failed"));
                }
            }
        } else if interactive {
            let spinner = indicatif::ProgressBar::new_spinner();
            spinner.set_style(
                indicatif::ProgressStyle::with_template("{spinner} {msg}")
                    .unwrap_or_else(|_| indicatif::ProgressStyle::default_spinner()),
            );
            spinner.enable_steady_tick(std::time::Duration::from_millis(120));
            spinner.set_message("waiting for browser consent...");
            let guard = SpinnerGuard::new(spinner);
            let r = client.authorize(scopes_owned.clone(), None).await;
            drop(guard);
            match r {
                Ok(r) => r,
                Err(e) => {
                    render_oauth_error(
                        &e,
                        &service,
                        interactive,
                        OAuthErrorSeverity::Fatal,
                        "authorize failed",
                    );
                    return Err(silent_err_for_code("connect.oauth_failed", "oauth failed"));
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
                    return Err(silent_err_for_code("connect.oauth_failed", "oauth failed"));
                }
            }
        };

        // Phase 4: seal + store.
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

        let granted = if result.scopes.is_empty() { scopes_owned } else { result.scopes.clone() };
        let meta = CredentialMeta {
            client_type: "byo".to_owned(),
            client_source: Some(oauth_config.source_path().display().to_string()),
            connected_at: chrono::Utc::now().to_rfc3339(),
            last_refreshed_at: None,
            scopes: granted.clone(),
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

        // Move oauth_config out so the post-block verify + summary code
        // can read its project_id / provenance_tag.
        oauth_config_opt = Some(oauth_config);
        granted
    };

    // ── Step 3 — verify (with retry loop, AC #4) ────────────────────
    //
    // Read the now-sealed credential and probe upstream Google. On a
    // 403 SERVICE_DISABLED / BILLING_DISABLED / SCOPE_INSUFFICIENT
    // (Story 7.12), `remediation_owned()` renders the actionable
    // URL/gcloud command. Up to 5 attempts in interactive mode;
    // first failure exits in --non-interactive mode.
    let project_id_for_verify = oauth_config_opt.as_ref().and_then(|c| c.project_id());
    verify_with_retry(&home, &service, project_id_for_verify, interactive, &args).await?;

    if interactive {
        let check = styled("\u{2713}", theme.tokens().accent, color_support);
        let styled_service = styled(&service, theme.tokens().accent, color_support);
        println!("  {check} {styled_service} verified");
    } else {
        tracing::info!(service = %service, "connection verified");
    }

    // ── Step 4 — policy edit ───────────────────────────────────────
    //
    // Convert granted URIs to short names; merge into the agent's
    // policy file. The `policy::edit::add_scopes_to_policy` helper
    // is idempotent — empty `added` means we don't even touch the file.
    //
    // Round-1 P5: warn loudly when a granted URI is NOT in the
    // `scope_info` allowlist. Without the warn, the credential carries
    // a scope that the policy doesn't list → runtime requests using
    // that scope hit default-deny silently. The operator-actionable
    // remediation is "extend `scopes.rs`" (or accept the deny).
    let mut short_names: Vec<&str> = Vec::with_capacity(granted_scopes.len());
    let mut unmapped: Vec<&str> = Vec::new();
    for uri in &granted_scopes {
        match scopes::uri_to_short_name(uri) {
            Some(short) => short_names.push(short),
            None => unmapped.push(uri.as_str()),
        }
    }
    if !unmapped.is_empty() {
        let joined = unmapped.join(", ");
        if interactive {
            let warn = styled("!", theme.tokens().accent, color_support);
            eprintln!(
                "  {warn} {} granted scope(s) not in policy-mapping table: {joined}",
                unmapped.len()
            );
            eprintln!(
                "    these are sealed in the credential but will hit default-deny at runtime"
            );
            eprintln!("    fix: add them to crates/permitlayer-oauth/src/google/scopes.rs");
        } else {
            tracing::warn!(
                unmapped_scopes = %joined,
                count = unmapped.len(),
                "granted scopes not policy-mappable; sealed in credential but runtime requests will hit default-deny. \
                 remediation: add to permitlayer_oauth::google::scopes::scope_info"
            );
        }
    }

    let policies_dir = home.join("policies");
    let policy_diff = match permitlayer_core::policy::edit::add_scopes_to_policy(
        &policies_dir,
        &agent_policy_name,
        &short_names,
    ) {
        Ok(d) => d,
        Err(e) => {
            eprint!(
                "{}",
                render::error_block(
                    "connect.policy_edit_failed",
                    &format!(
                        "failed to merge granted scopes into policy '{agent_policy_name}': {e}"
                    ),
                    &format!(
                        "inspect ~/.agentsso/policies/{agent_policy_name}.toml and re-run \
                         (or manually add the scopes: {})",
                        short_names.join(", ")
                    ),
                    None,
                )
            );
            return Err(silent_err_for_code("connect.policy_edit_failed", "policy edit failed"));
        }
    };
    let policy_was_modified = !policy_diff.is_no_op();
    if interactive {
        if policy_was_modified {
            let added = policy_diff.added.join(", ");
            let check = styled("\u{2713}", theme.tokens().accent, color_support);
            println!("  {check} policy '{agent_policy_name}' updated \u{00b7} added: {added}");
        } else {
            let check = styled("\u{2713}", theme.tokens().accent, color_support);
            println!(
                "  {check} policy '{agent_policy_name}' \u{00b7} skipped (scopes already present)"
            );
        }
    } else {
        tracing::info!(
            policy = %agent_policy_name,
            added = ?policy_diff.added,
            "policy edit complete"
        );
    }

    // ── Step 5 — reload (only if policy was modified) ──────────────
    if policy_was_modified {
        match post_reload(&home).await {
            Ok(()) => {
                if interactive {
                    let check = styled("\u{2713}", theme.tokens().accent, color_support);
                    println!("  {check} daemon reloaded");
                } else {
                    tracing::info!("daemon reloaded");
                }
            }
            Err(e) => {
                eprint!(
                    "{}",
                    render::error_block(
                        "connect.reload_failed",
                        &format!("failed to reload daemon after policy edit: {e}"),
                        "agentsso reload   # then re-run agentsso connect",
                        None,
                    )
                );
                return Err(silent_err_for_code("connect.reload_failed", "reload failed"));
            }
        }
    } else if interactive {
        let check = styled("\u{2713}", theme.tokens().accent, color_support);
        println!("  {check} reload \u{00b7} skipped (policy unchanged)");
    }

    // ── Step 6 — rebind ────────────────────────────────────────────
    //
    // Re-binding the agent to its own current policy is a server-side
    // no-op (Story 7.11 round-1 P5 short-circuit). We POST anyway so
    // that the agent's `last_seen_at` updates and any registry-cache
    // staleness gets cleared. If the rebind fails we emit a
    // structured error and exit 3.
    match post_rebind(&home, &args.agent, &agent_policy_name).await {
        Ok(()) => {
            if interactive {
                let check = styled("\u{2713}", theme.tokens().accent, color_support);
                println!(
                    "  {check} agent '{}' \u{00b7} bound to policy '{}'",
                    args.agent, agent_policy_name
                );
            } else {
                tracing::info!(agent = %args.agent, policy = %agent_policy_name, "rebind ok");
            }
        }
        Err(e) => {
            // Round-1 P10: switch the remediation on the upstream error
            // code. The default ("retry rebind") is wrong when the
            // failure is `agent.not_found` (concurrent `agent remove`)
            // — rebind will keep failing; the right next step is to
            // re-register the agent.
            let err_str = e.to_string();
            let remediation: &str = if err_str.starts_with("agent.not_found") {
                "agentsso agent register <name> --policy <policy>   # agent was removed; \
                 register fresh"
            } else if err_str.starts_with("agent.unknown_policy") {
                "edit ~/.agentsso/policies/ then `agentsso reload`   # policy missing"
            } else {
                "agentsso agent rebind <name> --policy <policy>   # diagnose, then retry"
            };
            eprint!(
                "{}",
                render::error_block(
                    "connect.rebind_failed",
                    &format!("failed to rebind agent '{}': {e}", args.agent),
                    remediation,
                    None,
                )
            );
            return Err(silent_err_for_code("connect.rebind_failed", "rebind failed"));
        }
    }

    // ── Step 7 — OpenClaw snippet emission ─────────────────────────
    //
    // Resolve the bearer token (flag → AGENTSSO_BEARER_TOKEN env var
    // → interactive Password prompt → placeholder). Emit the snippet
    // to stdout AND optionally write to --mcp-config-out. Connect
    // does NOT auto-merge into the end user's ~/.openclaw config —
    // see cli::openclaw module docs for the admin/user-split rationale.
    emit_openclaw_snippet(&args, &service, interactive, &theme).await?;

    // ── Step 8 — summary ───────────────────────────────────────────
    if interactive {
        println!();
        println!("  scopes granted:");
        for scope_uri in &granted_scopes {
            match scopes::scope_info(scope_uri) {
                Some(info) => println!("    {} ({})", info.description, info.short_name),
                None => println!("    {scope_uri}"),
            }
        }
        if let Some(cfg) = oauth_config_opt.as_ref() {
            println!("  client: {}", cfg.provenance_tag());
        }
        println!();
        println!("  next: hand the snippet above to whoever runs OpenClaw on this machine.");
        println!();
    } else {
        tracing::info!(
            service = %service,
            agent = %args.agent,
            policy = %agent_policy_name,
            scopes = ?granted_scopes,
            "connect complete"
        );
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────────
// Step helpers
// ──────────────────────────────────────────────────────────────────

/// Read the agent file directly via `AgentIdentityFsStore` and return
/// its `policy_name`. Returns `None` if the agent doesn't exist.
async fn resolve_agent_policy_name(home: &Path, name: &str) -> anyhow::Result<Option<String>> {
    use permitlayer_core::store::AgentIdentityStore;

    let store = permitlayer_core::store::fs::AgentIdentityFsStore::new(home.to_path_buf())
        .map_err(|e| anyhow::anyhow!("failed to open agent store: {e}"))?;
    let agent =
        store.get(name).await.map_err(|e| anyhow::anyhow!("failed to read agent '{name}': {e}"))?;
    Ok(agent.map(|a| a.policy_name))
}

/// Result of probing whether a daemon is currently running.
///
/// Round-1 P8: replaces `Option<u32>` where a "running but unknown PID"
/// state was conflated with `Some(0)` and rendered as the misleading
/// "PID 0" in operator-facing messages.
enum DaemonRunningState {
    /// No daemon process is alive (no PID file, or PID file points at
    /// a dead PID).
    NotRunning,
    /// Daemon is running and we read a real PID from the PID file.
    Running(u32),
    /// Daemon is running but the PID file is unreadable / missing /
    /// corrupt — the liveness probe itself reported `true` but we
    /// can't tell the operator which process to act on.
    RunningUnknownPid,
}

/// Probe daemon-running state. Honors the PID file for both liveness
/// (via `is_daemon_running`, which checks process existence) and for
/// the PID hint we render to the operator.
fn daemon_running_state(home: &Path) -> DaemonRunningState {
    if matches!(crate::lifecycle::pid::PidFile::is_daemon_running(home), Ok(true)) {
        match crate::lifecycle::pid::PidFile::read(home) {
            Ok(Some(pid)) => DaemonRunningState::Running(pid),
            _ => DaemonRunningState::RunningUnknownPid,
        }
    } else {
        DaemonRunningState::NotRunning
    }
}

/// Resolve the OAuth client config — same prompt-fallback shape as
/// the legacy `setup.rs` had.
async fn resolve_oauth_client(
    args: &ConnectArgs,
    service: &str,
    theme: &Theme,
    interactive: bool,
) -> anyhow::Result<GoogleOAuthConfig> {
    match &args.oauth_client {
        Some(path) => Ok(GoogleOAuthConfig::from_client_json(path)?),
        None if interactive
            && console::user_attended()
            && std::io::IsTerminal::is_terminal(&std::io::stdin()) =>
        {
            let teal_theme = build_teal_theme(theme);
            let theme_arc = std::sync::Arc::new(teal_theme);
            let theme_for_input = theme_arc.clone();
            let path_str: String = tokio::task::spawn_blocking(move || {
                dialoguer::Input::with_theme(&*theme_for_input)
                    .with_prompt("path to client_secret.json")
                    .interact_text()
            })
            .await??;
            Ok(GoogleOAuthConfig::from_client_json(std::path::Path::new(path_str.trim()))?)
        }
        None => {
            eprint!(
                "{}",
                render::error_block(
                    "connect.invalid_oauth_client",
                    "no OAuth client provided — permitlayer currently requires a \
                     bring-your-own Google OAuth client",
                    &format!(
                        "create a Desktop OAuth client at \
                         https://console.cloud.google.com/apis/credentials, \
                         download the JSON, then re-run:\n\n    \
                         agentsso connect {service} --agent {} --oauth-client ./client_secret.json",
                        args.agent
                    ),
                    None,
                )
            );
            Err(exit2())
        }
    }
}

/// Returns true when an existing credential meta file already covers
/// the service's default scope set — so connect can skip the OAuth
/// flow entirely (idempotent re-run path, AC #2).
fn credential_covers_target(meta_path: &Path, service: &str) -> bool {
    let Ok(text) = std::fs::read_to_string(meta_path) else {
        return false;
    };
    let Ok(meta) = serde_json::from_str::<CredentialMeta>(&text) else {
        return false;
    };
    let needed: std::collections::HashSet<&str> =
        scopes::default_scopes_for_service(service).into_iter().collect();
    let have: std::collections::HashSet<&str> = meta.scopes.iter().map(String::as_str).collect();
    needed.is_subset(&have)
}

/// Run the verify probe with up to 5 retries (interactive) or 1
/// attempt (non-interactive). Renders structured errors on each
/// failure via `OAuthError::remediation_owned()` so Story 7.12's
/// actionable text surfaces.
async fn verify_with_retry(
    home: &Path,
    service: &str,
    project_id: Option<&str>,
    interactive: bool,
    args: &ConnectArgs,
) -> anyhow::Result<()> {
    use std::io::{BufRead as _, Write as _};

    const MAX_ATTEMPTS: usize = 5;
    let max = if interactive { MAX_ATTEMPTS } else { 1 };

    for attempt in 1..=max {
        // Read the access token from the sealed credential each
        // attempt — a long retry loop could outlive a token refresh,
        // and we want the freshest bytes.
        let token = match read_access_token(home, service).await {
            Ok(b) => b,
            Err(e) => {
                eprint!(
                    "{}",
                    render::error_block(
                        "connect.verify_failed",
                        &format!("failed to read sealed credential for {service}: {e}"),
                        &format!(
                            "agentsso credentials list   # confirm credential exists\n  \
                             agentsso connect {service} --agent {}   # or re-run to re-seal",
                            args.agent
                        ),
                        None,
                    )
                );
                return Err(silent_err_for_code(
                    "connect.verify_failed",
                    "verify failed reading credential",
                ));
            }
        };

        match verify::verify_connection(service, token.reveal(), project_id).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                let last_attempt = attempt == max;
                let severity = if last_attempt {
                    OAuthErrorSeverity::Fatal
                } else {
                    OAuthErrorSeverity::NonFatal
                };
                render_oauth_error(&e, service, interactive, severity, "verification failed");

                // Round-1 D2 (re-audit): if the failure is a 401 and we
                // exhausted retries, hint that the access token may
                // have expired during the retry loop. Connect doesn't
                // refresh tokens itself (the daemon is stopped during
                // seal/verify; refresh lives in the daemon's runtime
                // path). The operator's recourse is to re-run connect
                // — Step 2 will skip the OAuth flow because the
                // credential is sealed, AND a fresh access-token
                // exchange happens on re-run.
                if last_attempt && is_unauthorized_after_long_run(&e) && interactive {
                    eprintln!();
                    eprintln!(
                        "  hint: 401 after multiple retries can mean the access token expired"
                    );
                    eprintln!(
                        "        mid-loop. Re-run `agentsso connect {service} --agent {}`;",
                        args.agent
                    );
                    eprintln!("        Step 2 will skip OAuth (credential is sealed) and the next");
                    eprintln!("        verify gets a fresh handshake.");
                    eprintln!();
                }

                if last_attempt {
                    return Err(silent_err_for_code(
                        "connect.verify_failed",
                        "verify failed after retries",
                    ));
                }

                if !interactive {
                    return Err(silent_err_for_code(
                        "connect.verify_failed",
                        "verify failed (non-interactive)",
                    ));
                }

                // Interactive: prompt to retry. A blank line / Enter
                // means "retry"; Ctrl-D / EOF aborts.
                eprint!(
                    "  Press Enter to retry (attempt {}/{}), Ctrl-D to abort: ",
                    attempt + 1,
                    max
                );
                let _ = std::io::stderr().flush();
                // Round-1 P6: wrap the blocking stdin read in a timeout
                // so an AFK operator can't stall the runtime indefinitely.
                // Mirrors `read_pasted_redirect_url` (HEADLESS_PASTE_TIMEOUT_SECS).
                let read_handle =
                    tokio::task::spawn_blocking(|| -> std::io::Result<Option<String>> {
                        let mut line = String::new();
                        let n = std::io::stdin().lock().read_line(&mut line)?;
                        if n == 0 {
                            Ok(None) // EOF — abort
                        } else {
                            Ok(Some(line))
                        }
                    });
                let timed = tokio::time::timeout(
                    std::time::Duration::from_secs(HEADLESS_PASTE_TIMEOUT_SECS),
                    read_handle,
                )
                .await;
                match timed {
                    Ok(Ok(Ok(None))) => {
                        // EOF
                        return Err(silent_err_for_code(
                            "connect.verify_failed",
                            "verify aborted by operator",
                        ));
                    }
                    Ok(Ok(Ok(Some(_)))) => continue,
                    Ok(Ok(Err(e))) => {
                        return Err(anyhow::anyhow!("stdin read failed during verify retry: {e}"));
                    }
                    Ok(Err(join_err)) => {
                        return Err(anyhow::anyhow!(
                            "stdin task panicked during verify retry: {join_err}"
                        ));
                    }
                    Err(_elapsed) => {
                        // Timeout — operator walked away.
                        eprintln!();
                        eprintln!(
                            "  no input within {HEADLESS_PASTE_TIMEOUT_SECS}s; aborting verify retry"
                        );
                        return Err(silent_err_for_code(
                            "connect.verify_failed",
                            "verify aborted by retry-prompt timeout",
                        ));
                    }
                }
            }
        }
    }
    unreachable!("loop terminates via Ok return or Err return inside the for body");
}

/// Round-1 D2 (re-audit): is this verify failure plausibly an expired
/// access token after a long retry loop? Used to surface a re-run
/// hint on the last verify attempt.
///
/// Triggers on `OAuthError::VerificationFailed { status_code: Some(401), .. }`.
fn is_unauthorized_after_long_run(e: &permitlayer_oauth::error::OAuthError) -> bool {
    matches!(
        e,
        permitlayer_oauth::error::OAuthError::VerificationFailed { status_code: Some(401), .. }
    )
}

/// Read and unseal the access token for `service`. The returned
/// `OAuthToken` exposes `reveal() -> &[u8]` for the verify probe.
async fn read_access_token(
    home: &Path,
    service: &str,
) -> anyhow::Result<permitlayer_credential::OAuthToken> {
    // Story 7.22: `acl_break_recovery: Disabled` preserves the
    // existing passphrase-prompt fallback for non-boot CLI paths.
    let keystore_config = KeystoreConfig {
        fallback: FallbackMode::Auto,
        home: home.to_path_buf(),
        acl_break_recovery: AclBreakRecoveryMode::Disabled,
    };
    let keystore = default_keystore(&keystore_config)?;
    let master_key = keystore.master_key().await?.key;
    let active_key_id = super::start::compute_active_key_id(&home.join("vault"));
    let vault = Vault::new(master_key, active_key_id);
    let store = CredentialFsStore::new(home.to_path_buf())?;
    let sealed = store
        .get(service)
        .await
        .map_err(|e| anyhow::anyhow!("failed to load sealed credential for {service}: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("no sealed credential for {service}"))?;
    vault
        .unseal(service, &sealed)
        .map_err(|e| anyhow::anyhow!("failed to unseal credential for {service}: {e}"))
}

/// POST `/v1/control/reload` against the running daemon.
async fn post_reload(home: &Path) -> anyhow::Result<()> {
    let config = crate::cli::kill::load_daemon_config_or_default_with_warn("connect reload");
    let bind_addr = config.http.bind_addr;
    let token = crate::cli::kill::read_control_token(home);
    let response =
        crate::cli::kill::http_post_json(bind_addr, "/v1/control/reload", "{}", token.as_deref())
            .await
            .map_err(|e| anyhow::anyhow!("daemon reload request failed: {e}"))?;
    let parsed: serde_json::Value = serde_json::from_str(&response)
        .map_err(|e| anyhow::anyhow!("malformed reload response: {e} (body: {response})"))?;
    if parsed["status"].as_str() == Some("ok") {
        Ok(())
    } else {
        let msg = parsed["message"].as_str().unwrap_or("reload returned non-ok status").to_owned();
        Err(anyhow::anyhow!(msg))
    }
}

/// POST `/v1/control/agent/rebind` against the running daemon.
async fn post_rebind(home: &Path, agent: &str, policy: &str) -> anyhow::Result<()> {
    let config = crate::cli::kill::load_daemon_config_or_default_with_warn("connect rebind");
    let bind_addr = config.http.bind_addr;
    let token = crate::cli::kill::read_control_token(home);
    let body = serde_json::json!({"name": agent, "policy_name": policy}).to_string();
    let response = crate::cli::kill::http_post_json(
        bind_addr,
        "/v1/control/agent/rebind",
        &body,
        token.as_deref(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("agent rebind request failed: {e}"))?;
    let parsed: serde_json::Value = serde_json::from_str(&response)
        .map_err(|e| anyhow::anyhow!("malformed rebind response: {e} (body: {response})"))?;
    if parsed["status"].as_str() == Some("ok") {
        Ok(())
    } else {
        let code = parsed["code"].as_str().unwrap_or("agent.unknown_error");
        let msg = parsed["message"].as_str().unwrap_or("rebind returned non-ok status");
        Err(anyhow::anyhow!("{code}: {msg}"))
    }
}

/// Resolve the bearer token + emit the OpenClaw snippet (Step 7).
///
/// Resolution order (Round-1 P3 + P4 + P9 hardening):
/// 1. `--bearer-token <T>` flag — value is **trimmed** (flag-passed values
///    from `$(< token.txt)` may carry trailing CRLF; untrimmed they would
///    produce a malformed `Authorization: Bearer <token>\n` header).
/// 2. `AGENTSSO_BEARER_TOKEN` env var — preferred over flag for scripted
///    use, as env vars do NOT land in shell history or `/proc/<pid>/cmdline`.
/// 3. Interactive `dialoguer::Password` prompt — hides the secret from
///    terminal echo + scrollback. Wrapped in `spawn_blocking` (dialoguer is
///    sync) and `tokio::time::timeout` so an AFK operator can't stall the
///    runtime. Empty input → placeholder + warning.
/// 4. `--non-interactive` without env or flag — emit `<REPLACE_WITH_TOKEN>`
///    placeholder + stderr warning.
async fn emit_openclaw_snippet(
    args: &ConnectArgs,
    service: &str,
    interactive: bool,
    theme: &Theme,
) -> anyhow::Result<()> {
    const PROMPT_TIMEOUT_SECS: u64 = 300;

    let bearer_token: String = if let Some(t) = &args.bearer_token {
        // Round-1 P9: trim flag value. `$(< token.txt)` may carry CRLF.
        let trimmed = t.trim().to_owned();
        if trimmed.is_empty() {
            anyhow::bail!("--bearer-token was empty after trim; pass a real token or omit the flag")
        }
        trimmed
    } else if let Ok(env_val) = std::env::var("AGENTSSO_BEARER_TOKEN") {
        // Round-1 P3: env var preferred over flag (no shell-history leak).
        let trimmed = env_val.trim().to_owned();
        if trimmed.is_empty() {
            anyhow::bail!("AGENTSSO_BEARER_TOKEN was set but empty; unset it or set a real token")
        }
        trimmed
    } else if interactive {
        // Round-1 P4: Password prompt (no terminal echo) + timeout.
        let teal_theme = std::sync::Arc::new(build_teal_theme(theme));
        eprintln!();
        eprintln!(
            "  agentsso never persists the bearer token — paste it from `agent register`'s output."
        );
        eprintln!("  (or set AGENTSSO_BEARER_TOKEN before re-running to avoid the prompt)");
        let theme_for_prompt = teal_theme.clone();
        let read_handle = tokio::task::spawn_blocking(move || -> dialoguer::Result<String> {
            dialoguer::Password::with_theme(&*theme_for_prompt)
                .with_prompt("Bearer token")
                .allow_empty_password(true) // empty = placeholder fallback below
                .interact()
        });
        let raw = match tokio::time::timeout(
            std::time::Duration::from_secs(PROMPT_TIMEOUT_SECS),
            read_handle,
        )
        .await
        {
            Ok(Ok(Ok(s))) => s,
            Ok(Ok(Err(e))) => {
                anyhow::bail!("Password prompt failed: {e}")
            }
            Ok(Err(join_err)) => {
                anyhow::bail!("stdin task panicked during token prompt: {join_err}")
            }
            Err(_) => {
                anyhow::bail!(
                    "no bearer token entered within {PROMPT_TIMEOUT_SECS}s; aborting Step 7"
                )
            }
        };
        let trimmed = raw.trim().to_owned();
        if trimmed.is_empty() {
            // Operator hit Enter without typing — treat as "skip the
            // file write but still emit a placeholder snippet to stdout
            // so they can copy the URL/transport shape later".
            eprintln!("  (no token entered; emitting snippet with placeholder)");
            "<REPLACE_WITH_TOKEN>".to_owned()
        } else {
            trimmed
        }
    } else {
        // --non-interactive without --bearer-token or AGENTSSO_BEARER_TOKEN.
        eprintln!(
            "  warn: no --bearer-token in --non-interactive mode; snippet uses <REPLACE_WITH_TOKEN> placeholder"
        );
        eprintln!(
            "        set AGENTSSO_BEARER_TOKEN or pass --bearer-token to inject a real token"
        );
        "<REPLACE_WITH_TOKEN>".to_owned()
    };

    let bind_addr = crate::cli::kill::load_daemon_config_or_default_with_warn("connect openclaw")
        .http
        .bind_addr;

    // Round-1 P14: warn loudly if the daemon is bound to a non-loopback
    // address — the snippet would direct the MCP client to send the
    // bearer over plaintext HTTP. Operators who genuinely want this
    // (e.g., LAN testing) can ignore the warning; operators who didn't
    // realize their bind config was wrong get a chance to notice
    // before pasting the snippet into a config that exposes the token.
    if !bind_addr.ip().is_loopback() {
        eprintln!();
        eprintln!("  warn: daemon is bound to non-loopback address {bind_addr} — the snippet's");
        eprintln!("        Authorization header will travel over plaintext HTTP if the MCP client");
        eprintln!("        connects across the network. Bind to 127.0.0.1 (localhost) unless you");
        eprintln!("        know what you're doing.");
        eprintln!();
    }

    let snippet = super::openclaw::build_snippet(service, &bearer_token, bind_addr);

    if let Err(e) = super::openclaw::emit_snippet(&snippet, args.mcp_config_out.as_deref(), service)
    {
        // Non-fatal: connect's overall exit is still 0 (rebind succeeded).
        eprintln!(
            "  warn: failed to write snippet to {:?}: {e}\n         (the snippet was still printed to stdout above)",
            args.mcp_config_out
        );
    }
    Ok(())
}

// ──────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Test-only wrapper exposing `ConnectArgs` to clap so we can
    /// exercise the parse rules.
    #[derive(clap::Parser, Debug)]
    struct TestCli {
        #[command(subcommand)]
        cmd: TestCmd,
    }

    #[derive(clap::Subcommand, Debug)]
    enum TestCmd {
        Connect(ConnectArgs),
    }

    fn parse(argv: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(argv)
    }

    #[test]
    fn clap_parses_minimal_args() {
        let cli = parse(&["agentsso", "connect", "gmail", "--agent", "me"]).unwrap();
        let TestCmd::Connect(args) = cli.cmd;
        assert_eq!(args.service, "gmail");
        assert_eq!(args.agent, "me");
        assert!(args.oauth_client.is_none());
        assert!(!args.headless);
        assert!(!args.non_interactive);
        assert!(args.bearer_token.is_none());
        assert!(args.mcp_config_out.is_none());
    }

    #[test]
    fn clap_parses_with_oauth_client() {
        let cli = parse(&[
            "agentsso",
            "connect",
            "gmail",
            "--agent",
            "me",
            "--oauth-client",
            "./client.json",
        ])
        .unwrap();
        let TestCmd::Connect(args) = cli.cmd;
        assert_eq!(args.oauth_client.as_deref(), Some(Path::new("./client.json")));
    }

    #[test]
    fn clap_parses_headless() {
        let cli = parse(&["agentsso", "connect", "gmail", "--agent", "me", "--headless"]).unwrap();
        let TestCmd::Connect(args) = cli.cmd;
        assert!(args.headless);
    }

    #[test]
    fn clap_parses_bearer_token_and_mcp_config_out() {
        let cli = parse(&[
            "agentsso",
            "connect",
            "gmail",
            "--agent",
            "me",
            "--bearer-token",
            "agt_v2_me_xxx",
            "--mcp-config-out",
            "/tmp/snippet.json",
        ])
        .unwrap();
        let TestCmd::Connect(args) = cli.cmd;
        assert_eq!(args.bearer_token.as_deref(), Some("agt_v2_me_xxx"));
        assert_eq!(args.mcp_config_out.as_deref(), Some(Path::new("/tmp/snippet.json")));
    }

    #[test]
    fn clap_rejects_headless_with_non_interactive() {
        let err = parse(&[
            "agentsso",
            "connect",
            "gmail",
            "--agent",
            "me",
            "--headless",
            "--non-interactive",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn clap_requires_agent() {
        let err = parse(&["agentsso", "connect", "gmail"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn connect_exit_code_preconditions_map_to_2() {
        for code in [
            "connect.agent_not_found",
            "connect.unknown_service",
            "connect.invalid_oauth_client",
            "connect.daemon_must_stop",
        ] {
            assert_eq!(connect_exit_code(code), 2, "code {code} should be precondition (exit 2)");
        }
    }

    #[test]
    fn connect_exit_code_system_errors_map_to_3() {
        for code in [
            "connect.oauth_failed",
            "connect.verify_failed",
            "connect.policy_edit_failed",
            "connect.reload_failed",
            "connect.rebind_failed",
            "connect.openclaw_failed",
        ] {
            assert_eq!(connect_exit_code(code), 3, "code {code} should be system/retry (exit 3)");
        }
    }

    #[test]
    fn connect_exit_code_unknown_codes_default_to_3() {
        assert_eq!(connect_exit_code("connect.future_unknown"), 3);
        assert_eq!(connect_exit_code("agent.duplicate_name"), 3);
    }

    #[test]
    fn credential_covers_target_returns_false_for_missing_meta() {
        let tmp = tempfile::tempdir().unwrap();
        let meta_path = tmp.path().join("gmail-meta.json");
        assert!(!credential_covers_target(&meta_path, "gmail"));
    }

    #[test]
    fn credential_covers_target_returns_true_when_all_scopes_present() {
        let tmp = tempfile::tempdir().unwrap();
        let meta_path = tmp.path().join("calendar-meta.json");
        let meta = CredentialMeta {
            client_type: "byo".to_owned(),
            client_source: None,
            connected_at: "2026-05-07T00:00:00Z".to_owned(),
            last_refreshed_at: None,
            scopes: vec![
                "https://www.googleapis.com/auth/calendar.readonly".to_owned(),
                "https://www.googleapis.com/auth/calendar.events".to_owned(),
            ],
            expires_in_secs: None,
        };
        std::fs::write(&meta_path, serde_json::to_string(&meta).unwrap()).unwrap();
        assert!(credential_covers_target(&meta_path, "calendar"));
    }

    #[test]
    fn credential_covers_target_returns_false_when_scope_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let meta_path = tmp.path().join("calendar-meta.json");
        let meta = CredentialMeta {
            client_type: "byo".to_owned(),
            client_source: None,
            connected_at: "2026-05-07T00:00:00Z".to_owned(),
            last_refreshed_at: None,
            scopes: vec!["https://www.googleapis.com/auth/calendar.readonly".to_owned()],
            expires_in_secs: None,
        };
        std::fs::write(&meta_path, serde_json::to_string(&meta).unwrap()).unwrap();
        // calendar service requires both readonly + events; only readonly present.
        assert!(!credential_covers_target(&meta_path, "calendar"));
    }
}
