//! `agentsso connect <service>` — one-verb orchestration of the
//! agent-onboarding journey (Story 7.13, daemon-mediated since 7.30).
//!
//! Composes the operator-interactive OAuth dance with a sequence of
//! UDS calls into the daemon control plane. The daemon owns every
//! credential write, every vault touch, every master-key read, and
//! every policy-file edit. The CLI is now a thin orchestrator over:
//!
//! - `GET /v1/control/agent/{name}/policy_name` (agent lookup)
//! - `GET /v1/control/credentials/{service}/meta` (idempotent re-run)
//! - `POST /v1/control/credentials/seal` (token seal + meta write)
//! - `POST /v1/control/credentials/{service}/verify` (Google probe)
//! - `POST /v1/control/policy/{policy_name}/scopes` (merge + reload)
//! - `POST /v1/control/agent/rebind` (existing surface)
//!
//! See `cli/connect_uds.rs` for the typed UDS clients.
//!
//! ## Flow
//!
//! 1. **Pre-flight** — agent exists, service is supported, flags are coherent.
//! 2. **Daemon-must-be-running gate** (Story 7.30 AC #7) — `agentsso connect`
//!    now requires the daemon up because it owns the vault. Three
//!    remediation branches for the failure modes: helper not installed
//!    (`sudo agentsso service install`), helper present but launchd
//!    not-running (`sudo launchctl kickstart`), socket EACCES
//!    (`sudo dseditgroup` group-membership fix).
//! 3. **OAuth + seal** — sealed credential present with covering
//!    scopes? skip. Else: drive the OAuth dance (browser via
//!    Story 7.30 AC #9 fallback / `--headless` paste / `--device-flow`),
//!    then POST plaintext tokens to the daemon's seal endpoint.
//! 4. **Verify (with retry loop)** — POST to the verify endpoint up
//!    to 5 times in interactive mode; render structured Google
//!    failures and daemon-side errors via
//!    `render_verify_error_from_daemon`.
//! 5. **Policy scopes merge** — single POST that returns the diff
//!    AND the `reloaded: bool` discriminator. No separate reload call.
//! 6. **Rebind** — POST `/v1/control/agent/rebind` (Story 7.11). Same-policy
//!    rebind is a server-side no-op; CLI logs it as such.
//! 7. **OpenClaw snippet emission** — prints the JSON snippet to stdout
//!    (with copy-paste delimiter block); optionally writes to
//!    `--mcp-config-out <path>` for cross-user / scripted handoff. Connect
//!    does NOT auto-merge into another user's `~/.openclaw/openclaw.json`
//!    — see `cli::openclaw` module docs for the admin/user-split rationale.
//! 8. **Summary** — one block listing each step's outcome.
//!
//! Re-running `connect` with identical args after a successful run is a
//! guaranteed end-to-end no-op: each daemon endpoint detects "already
//! done" and returns "no change". Bearer tokens are NOT rotated
//! (Story 7.11 invariant). Policy files are NOT re-written when scopes
//! are already present.
//!
//! ## Story 7.30 deviations vs Story 7.13
//!
//! - **Daemon-running gate inverted.** Pre-7.30 connect refused when
//!   the daemon was UP (to prevent seal-races with the refresh path);
//!   post-7.30 it refuses when the daemon is DOWN. The error code is
//!   `connect.daemon_must_run`, replacing the deleted
//!   `connect.daemon_must_stop`. Same exit-2 (operator-correctable).
//! - **Vault-dir writability checks gone from CLI.** The daemon owns
//!   `0700 root:wheel` `/Library/Application Support/permitlayer/vault/`
//!   and surfaces fs failures through `credentials.store_io_failed`.
//!   `connect.vault_dir_symlink` / `_unwritable` error codes deleted.
//! - **Plaintext tokens cross the UDS boundary.** Documented in
//!   ADR-0007: `Zeroizing<String>` on both sides means the heap is
//!   scrubbed on drop; the axum body buffer (`Bytes`) is the
//!   non-zeroizing window during request parse.
//!
//! ## Replaces `agentsso setup`
//!
//! Story 7.13 deleted `cli/setup.rs` entirely. The legacy verb
//! intercepts to `setup.removed` via `main.rs`'s top-level handler.

use std::path::{Path, PathBuf};

use clap::Args;
use permitlayer_oauth::google::consent::GoogleOAuthConfig;
use permitlayer_oauth::google::scopes;

use crate::design::render;
use crate::design::terminal::{ColorSupport, styled};
use crate::design::theme::Theme;

// Round-1 D1 (re-audit): OAuth-flow rendering helpers factored out of
// this file into `cli::oauth_render`. See module-level docs there.
use super::oauth_render::{
    HEADLESS_PASTE_TIMEOUT_SECS, OAuthErrorSeverity, SpinnerGuard, build_teal_theme,
    print_headless_consent_block, read_pasted_redirect_url, render_oauth_error,
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

// Round-3 review verification: `exit3` is intentionally retained as
// the parallel helper to `silent_err_for_code` for the bare-exit-3
// path. All current callers route through `silent_err_for_code(...,
// "agent_lookup_failed")` etc. for the structured-error block; this
// remains as the no-message exit-3 escape valve for future use.
#[allow(dead_code)]
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
///   connect.dangling_policy_binding, connect.unknown_service,
///   connect.invalid_oauth_client, connect.daemon_must_run,
///   connect.non_interactive_required.
/// - **3 (system / retry)**: connect.oauth_failed, connect.seal_failed,
///   connect.verify_failed, connect.policy_edit_failed,
///   connect.rebind_failed, connect.openclaw_failed,
///   connect.agent_lookup_failed, connect.meta_lookup_failed.
///
/// Used both by the unit tests (mapping table) and by [`silent_err_for_code`]
/// (which produces the right typed marker for `connect_to_exit_code` to
/// downcast). Story 7.13 round-1 P1 wired this in: previously many failure
/// paths used bare `silent_cli_error` which produced exit 1; the spec table
/// in Dev Notes promised 2/3 per code.
///
/// Story 7.30 deviation: `connect.daemon_must_stop` (exit 2) is replaced
/// by `connect.daemon_must_run` (exit 2) because the daemon now owns
/// every credential write. `connect.vault_dir_symlink` / `_unwritable`
/// are gone: the daemon owns the vault dir. Round-1 review P34 dropped
/// `connect.reload_failed` from the table — reload-failure now surfaces
/// as `connect.policy_edit_failed` (folded into the single policy/scopes
/// POST). Round-1 review P24 added `connect.dangling_policy_binding`
/// (operator-correctable via `agentsso agent rebind`).
pub(crate) fn connect_exit_code(code: &str) -> i32 {
    match code {
        "connect.agent_not_found"
        | "connect.dangling_policy_binding"
        | "connect.unknown_service"
        | "connect.invalid_oauth_client"
        | "connect.daemon_must_run"
        | "connect.non_interactive_required"
        | "setup.removed" => 2,
        _ => 3,
    }
}

fn default_scope_for_snippet(
    policy_resp: &super::connect_uds::PolicyScopesResponse,
    requested_short_names: &[&str],
) -> Option<String> {
    fn first_matching_policy_scope(policy_scopes: &[String], requested: &[&str]) -> Option<String> {
        policy_scopes.iter().find(|scope| requested.contains(&scope.as_str())).cloned()
    }

    first_matching_policy_scope(&policy_resp.after, requested_short_names)
        .or_else(|| first_matching_policy_scope(&policy_resp.before, requested_short_names))
}

#[cfg(unix)]
fn connect_root_guard_for(
    service: &str,
    agent: &str,
    allow_root: bool,
    effective_uid: u32,
    sudo_user: Option<&str>,
) -> anyhow::Result<()> {
    let connect_hint = format!("agentsso connect {service} --agent {agent}");
    crate::cli::root_guard::ensure_not_sudo_root_shell_with(
        "connect",
        &connect_hint,
        allow_root,
        effective_uid,
        sudo_user,
    )
}

/// Build a silent CLI error tagged with the right exit-code marker for
/// the given operator-facing error code. The `error_block` rendering is
/// the caller's responsibility; this helper attaches ONLY the typed
/// marker so `main.rs::connect_to_exit_code` produces the right exit
/// code.
///
/// Round-1 P1 fix: replaces bare `crate::cli::silent_cli_error(msg)` calls
/// throughout `run` so the spec's exit-code table actually fires at runtime.
/// Round-1 review P36: strip control characters from text we
/// interpolate into operator-facing stderr blocks. Daemon-returned
/// strings (remediation URLs, error messages) cross a trust boundary;
/// without this, a control-char in (e.g.) a forwarded Google response
/// could reposition the operator's cursor or set terminal modes.
///
/// Strategy: keep printable ASCII + common whitespace; replace
/// everything else with U+FFFD. This is intentionally aggressive —
/// our wire-format is JSON which is always UTF-8 printable; anything
/// outside that range is a bug in the producer.
pub(crate) fn sanitize_for_terminal(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii() && (c.is_ascii_graphic() || c == ' ' || c == '\t' || c == '\n') {
                c
            } else if c.is_alphanumeric() || c.is_whitespace() {
                // Allow non-ASCII alphanumerics / common Unicode
                // whitespace — operators in non-English locales
                // shouldn't see U+FFFD splatter on legitimate text.
                c
            } else {
                '\u{FFFD}'
            }
        })
        .collect()
}

/// Story 7.38: the verify probe confirms ONLY that the sealed Google
/// credential can mint an upstream token — it does NOT exercise the
/// agent→daemon→Google bearer chain. The old wording (`gmail verified`)
/// read as end-to-end success and repeatedly misdirected diagnosis when
/// the bearer token in the MCP client was stale/wrong. Scope the claim
/// to exactly what was checked.
///
/// The interactive call site styles the service token separately
/// (color), so the wording is split: the caller prints
/// `<styled service> <VERIFY_SUFFIX>`. This fixed suffix is the only
/// load-bearing string — the snapshot test pins it directly so a
/// deliberate change to operator-facing semantics is a deliberate edit
/// here. (Mirrors the 7.36 `hmac_hit_argon2id_miss_message` pattern of
/// a pure, testable wording unit.)
const VERIFY_SUFFIX: &str = "Google credential verified (upstream token mint OK)";

/// Story 7.38: the post-connect next-steps block must make explicit
/// that verify success does NOT mean the chain works — the bearer token
/// still has to be valid in whatever runs the MCP client. Without this,
/// `gmail verified` + a broken bearer = an operator who believes the
/// connection is healthy and looks everywhere except the token.
pub(crate) fn next_steps_bearer_note() -> &'static str {
    "the bearer token in the snippet must be valid in the MCP client \
     for the agent\u{2192}daemon\u{2192}Google chain to work \u{2014} \
     \"verified\" above only confirms the sealed Google credential"
}

/// Story 7.36 (AC #1): connect's policy rebind preserves the agent's
/// bearer token (Story 7.11 invariant — pinned E2E in
/// `agent_rebind_e2e.rs`). The Angie-2 footgun was an operator who'd
/// re-run connect and then assumed a token problem meant connect had
/// re-issued/orphaned the bearer, chasing the alarming daemon-side
/// "Argon2id verification failed — possible map corruption" log
/// (rewritten in 7.36 AC #2). Surface the invariant at the rebind site
/// so the operator knows connect did NOT touch their deployed bearer
/// and the existing snippet is still valid.
///
/// Pure for string-testing — same extraction pattern as the 7.36
/// `hmac_hit_argon2id_miss_message` daemon-side helper.
pub(crate) fn rebind_bearer_preserved_note() -> &'static str {
    "existing bearer token preserved \u{2014} connect only changed the \
     policy binding; do NOT re-deploy the snippet unless you rotated \
     the agent (\u{0060}agentsso agent rotate\u{0060})"
}

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

    /// Allow connect from an effective-root shell with SUDO_USER set.
    /// Intended only for CI and embedded installs; normal operators should
    /// run this command from their user shell.
    #[arg(long)]
    pub allow_root: bool,
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
    #[cfg(unix)]
    connect_root_guard_for(
        &service,
        &args.agent,
        args.allow_root,
        nix::unistd::geteuid().as_raw(),
        std::env::var("SUDO_USER").ok().as_deref(),
    )?;

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
    // Story 7.33 review fix: load the daemon config so policy
    // remediation points at the daemon's configured paths.home rather
    // than the CLI's env/platform default.
    let daemon_config = crate::cli::kill::load_daemon_config_or_default_with_warn("connect");
    let daemon_home = daemon_config.paths.home.clone();
    let theme = Theme::load(&home);
    let color_support = ColorSupport::detect();
    tracing::info!(
        home = %home.display(),
        service = %service,
        agent = %args.agent,
        "starting connect flow"
    );

    // ── Step 1b — daemon-running gate + agent existence pre-check ──
    //
    // Story 7.30: the connect flow now writes every credential through
    // the daemon control plane (the daemon owns the master key + the
    // `0700 root:wheel` state directory). Require the daemon to be
    // running before going further; if it isn't, render a structured
    // remediation block pointing at the install/start/group steps.
    let control_handle = super::connect_uds::require_daemon_running(&home).await?;

    let agent_policy_name = match super::connect_uds::get_agent_policy_name(
        &control_handle,
        &args.agent,
    )
    .await
    {
        Ok(super::connect_uds::ControlOutcome::Ok(resp)) => resp.policy_name,
        Ok(super::connect_uds::ControlOutcome::Err { status_code, body }) => {
            // 404 → operator-correctable agent-not-found.
            // Round-1 review P33: use silent_err_for_code instead of
            // bare `exit2()` so the typed marker matches the rest of
            // the new flow (consistent with the seal/verify/policy
            // error paths).
            if body.code == "agent.not_found" {
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
                return Err(silent_err_for_code("connect.agent_not_found", "agent not found"));
            }
            // Round-1 review P24: 422 dangling-policy-binding is the
            // daemon-side surface Group 1 P21 added to save the CLI
            // a round-trip discovering the inconsistency via
            // /policy/<dangling>/scopes 404. Map to a dedicated
            // operator-correctable exit-2 with the rebind hint.
            if body.code == "agent.dangling_policy_binding" {
                // Round-3 review P67: sanitize daemon-returned text
                // before printing — defense-in-depth against ANSI/CR/LF
                // ever appearing in a forwarded upstream error.
                eprint!(
                    "{}",
                    render::error_block(
                        "connect.dangling_policy_binding",
                        &format!(
                            "agent '{}' is bound to a policy that doesn't exist in the active set: {}",
                            args.agent,
                            sanitize_for_terminal(&body.message)
                        ),
                        &format!(
                            "agentsso agent rebind {} --policy <new-policy>\n\n  \
                             then re-run this command:\n  \
                             agentsso connect {service} --agent {}",
                            args.agent, args.agent
                        ),
                        None,
                    )
                );
                return Err(silent_err_for_code(
                    "connect.dangling_policy_binding",
                    "agent bound to non-existent policy",
                ));
            }
            // Any other daemon-side error → exit 3.
            // Round-3 review P67: sanitize daemon-returned text.
            eprint!(
                "{}",
                render::error_block(
                    "connect.agent_lookup_failed",
                    &format!(
                        "agent lookup failed (HTTP {status_code}, daemon code {}): {}",
                        sanitize_for_terminal(&body.code),
                        sanitize_for_terminal(&body.message)
                    ),
                    "check the daemon's tracing log and the audit log for the matching request_id",
                    None,
                )
            );
            return Err(silent_err_for_code("connect.agent_lookup_failed", "agent lookup failed"));
        }
        Ok(super::connect_uds::ControlOutcome::ParseFailure { status_code, raw_body }) => {
            // Round-1 review P31: daemon returned an unparseable
            // response. Surface as a distinct diagnostic from
            // transport failure so operators don't think the daemon
            // is down when it actually returned a malformed body.
            return Err(render_parse_failure(
                "connect.agent_lookup_failed",
                "agent lookup",
                status_code,
                &raw_body,
            ));
        }
        Err(transport_err) => {
            eprint!(
                "{}",
                render::error_block(
                    "connect.agent_lookup_failed",
                    &format!("agent lookup transport error: {transport_err}"),
                    "verify the daemon is healthy: agentsso status",
                    None,
                )
            );
            return Err(silent_err_for_code(
                "connect.agent_lookup_failed",
                "agent lookup transport failure",
            ));
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

    // ── Step 2 — OAuth + seal (daemon-mediated phase) ──────────────
    //
    // Story 7.30: the daemon owns the vault, the master key, and every
    // `*.sealed` / `*-meta.json` file. The CLI's job here is:
    //   1. Check whether a credential already exists with covering
    //      scopes (idempotent re-run path) — via UDS.
    //   2. If not, drive the operator-interactive OAuth dance.
    //   3. POST the resulting tokens to the daemon, which seals them
    //      into its vault and writes the meta JSON.
    //
    // The daemon-must-be-running gate already fired in Step 1b above.
    let existing_meta = match super::connect_uds::get_credentials_meta(&control_handle, &service)
        .await
    {
        Ok(super::connect_uds::ControlOutcome::Ok(resp)) => resp,
        Ok(super::connect_uds::ControlOutcome::Err { status_code, body }) => {
            // Round-3 review P67: sanitize daemon-returned text.
            eprint!(
                "{}",
                render::error_block(
                    "connect.meta_lookup_failed",
                    &format!(
                        "credential meta lookup failed (HTTP {status_code}, daemon code {}): {}",
                        sanitize_for_terminal(&body.code),
                        sanitize_for_terminal(&body.message)
                    ),
                    "check the daemon's tracing log for the matching request_id",
                    None,
                )
            );
            return Err(silent_err_for_code(
                "connect.meta_lookup_failed",
                "credential meta lookup failed",
            ));
        }
        Ok(super::connect_uds::ControlOutcome::ParseFailure { status_code, raw_body }) => {
            return Err(render_parse_failure(
                "connect.meta_lookup_failed",
                "credential meta lookup",
                status_code,
                &raw_body,
            ));
        }
        Err(transport_err) => {
            eprint!(
                "{}",
                render::error_block(
                    "connect.meta_lookup_failed",
                    &format!("credential meta transport error: {transport_err}"),
                    "verify the daemon is healthy: agentsso status",
                    None,
                )
            );
            return Err(silent_err_for_code(
                "connect.meta_lookup_failed",
                "credential meta transport failure",
            ));
        }
    };

    let credential_already_present = !args.force
        && existing_meta.exists
        && existing_meta
            .meta
            .as_ref()
            .map(|m| {
                let needed: std::collections::HashSet<&str> =
                    scopes::default_scopes_for_service(&service).into_iter().collect();
                let have: std::collections::HashSet<&str> =
                    m.scopes.iter().map(String::as_str).collect();
                needed.is_subset(&have)
            })
            .unwrap_or(false);

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
        existing_meta.meta.as_ref().map(|m| m.scopes.clone()).unwrap_or_else(|| {
            scopes::default_scopes_for_service(&service).into_iter().map(str::to_owned).collect()
        })
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

        // Story 7.30: vault-dir writability checks moved daemon-side. The
        // daemon owns `0700 root:wheel` `/Library/Application Support/permitlayer/vault/`
        // and surfaces fs failures through `credentials.store_io_failed`
        // on the seal POST. Operator never touches that path directly
        // anymore.

        // Phase 1: scope preview (interactive only).
        let teal_theme = std::sync::Arc::new(build_teal_theme(&theme));

        if interactive {
            if existing_meta.exists && !args.force {
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
        //
        // Story 7.30: the CLI no longer constructs a `Vault` — the
        // daemon owns the master key and the vault. The OAuth dance
        // here only produces plaintext tokens; the seal POST below
        // hands them to the daemon's `credentials_seal_handler`.
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

        // Phase 4: seal via daemon (Story 7.30 AC #3).
        //
        // The CLI hands plaintext tokens to the daemon's
        // `credentials_seal_handler` over UDS. The daemon owns the seal
        // crypto (vault.seal), the disk write (CredentialFsStore::put),
        // and the meta JSON (write_metadata_atomic). The `if_exists`
        // semantics map: `--force` → replace; otherwise → replace too
        // (this branch only fires when the idempotent re-run check
        // above already concluded "we need to seal").
        // Round-1 review P38: scope-resolution priority on empty
        // `result.scopes`. Some OAuth flows return empty `scopes`
        // even on success (Google's behavior varies). If we have
        // existing meta with a wider set than the service default,
        // prefer that — otherwise fall back to default scopes.
        // Without this, `--force` re-run after a granted-scope
        // expansion silently downgrades meta's scope set.
        let granted_scopes_for_seal: Vec<String> = if !result.scopes.is_empty() {
            result.scopes.clone()
        } else if let Some(existing) = existing_meta.meta.as_ref().filter(|m| !m.scopes.is_empty())
        {
            tracing::info!(
                "OAuth result returned empty scopes; using existing meta scopes ({} scope(s)) as fallback",
                existing.scopes.len()
            );
            existing.scopes.clone()
        } else {
            scopes_owned.clone()
        };

        // `access_token` and `refresh_token` are `OAuthToken` /
        // `OAuthRefreshToken` — non-Display, non-Debug. Convert the raw
        // bytes to UTF-8 strings via `reveal()` for the JSON wire body;
        // the seal handler deserializes them into `Zeroizing<String>`.
        //
        // Round-1 review P42: wrap the CLI-side String copies in
        // `Zeroizing<String>` so the heap is scrubbed on drop. Closes
        // the first two of the four CLI-side plaintext windows the
        // Edge Case Hunter flagged. The JSON-body and HTTP-request
        // buffers close further down via the Zeroizing-aware POST
        // helper.
        let access_token_str: zeroize::Zeroizing<String> = zeroize::Zeroizing::new(
            std::str::from_utf8(result.access_token.reveal())
                .map_err(|e| anyhow::anyhow!("access token is not valid UTF-8: {e}"))?
                .to_owned(),
        );
        let refresh_token_str: Option<zeroize::Zeroizing<String>> =
            match result.refresh_token.as_ref() {
                Some(t) => Some(zeroize::Zeroizing::new(
                    std::str::from_utf8(t.reveal())
                        .map_err(|e| anyhow::anyhow!("refresh token is not valid UTF-8: {e}"))?
                        .to_owned(),
                )),
                None => None,
            };
        // Story 7.35: serialize the parsed BYO client bundle and send it
        // to the daemon to be SEALED — instead of sending a filesystem
        // path the proxy would re-read in plaintext on every refresh.
        // Kept in `Zeroizing` (mirrors the access-token handling above)
        // so the transient client_secret-bearing JSON is scrubbed.
        let client_bundle_bytes = oauth_config
            .to_sealed_bundle_bytes()
            .map_err(|e| anyhow::anyhow!("failed to serialize OAuth client bundle: {e}"))?;
        // `.to_vec()` copies out of the `Zeroizing<Vec<u8>>`; the copy
        // is scrubbed on the success path by the `Zeroizing<String>`
        // wrapper below. L1: also scrub it on the
        // `FromUtf8Error`-owns-the-bytes path (effectively unreachable
        // — `serde_json::to_vec` always emits UTF-8 — but the
        // surrounding code is meticulous about plaintext windows).
        let client_bundle_str: zeroize::Zeroizing<String> = zeroize::Zeroizing::new(
            String::from_utf8(client_bundle_bytes.to_vec()).map_err(|e| {
                use zeroize::Zeroize;
                let mut leaked = e.into_bytes();
                leaked.zeroize();
                anyhow::anyhow!("OAuth client bundle is not valid UTF-8")
            })?,
        );
        let seal_req = super::connect_uds::CredentialsSealRequest {
            service: &service,
            agent: &args.agent,
            access_token: access_token_str.as_str(),
            refresh_token: refresh_token_str.as_ref().map(|z| z.as_str()),
            granted_scopes: &granted_scopes_for_seal,
            client_type: "byo",
            client_bundle_json: client_bundle_str.as_str(),
            expires_in_secs: result.expires_in.map(|d| d.as_secs()),
            if_exists: "replace",
        };
        match super::connect_uds::post_credentials_seal(&control_handle, &seal_req).await {
            Ok(super::connect_uds::ControlOutcome::Ok(resp)) => {
                if interactive {
                    let check = styled("\u{2713}", theme.tokens().accent, color_support);
                    if resp.replaced_previous {
                        println!("  {check} tokens sealed (replaced previous)");
                    } else {
                        println!("  {check} tokens sealed");
                    }
                    // Story 7.35: the client JSON is now sealed in the
                    // vault; the daemon no longer reads the original
                    // file at refresh time.
                    //
                    // SECURITY NOTE: only `oauth_config.source_path()`
                    // — the *path* to the original client JSON — is
                    // ever printed here, NEVER the `client_secret`.
                    // Showing the path is REQUIRED by Story 7.35 AC#2
                    // (tell the operator the original file is no longer
                    // needed). CodeQL `rust/cleartext-logging` flags
                    // this because its taint model is not
                    // field-sensitive: any value derived from
                    // `oauth_config` (which also holds the secret)
                    // reaching an output sink trips it, even though
                    // `.source_path()` projects only the non-sensitive
                    // path. Verified false positive (diff-wide sweep:
                    // no oauth_config/client_secret/bundle value
                    // reaches any println!/tracing/eprintln sink) —
                    // dismissed in GitHub code-scanning with this
                    // justification rather than distorting required
                    // operator UX to satisfy an imprecise query.
                    println!(
                        "  {check} client credentials sealed \u{2014} the original {} is no longer",
                        oauth_config.source_path().display()
                    );
                    println!("    needed by the daemon (you may keep or delete it)");
                } else {
                    tracing::info!(
                        service = %service,
                        replaced_previous = resp.replaced_previous,
                        "access token + client bundle sealed via daemon"
                    );
                }
            }
            Ok(super::connect_uds::ControlOutcome::Err { status_code, body }) => {
                // Round-3 review P67: sanitize daemon-returned text.
                eprint!(
                    "{}",
                    render::error_block(
                        "connect.seal_failed",
                        &format!(
                            "credentials seal failed (HTTP {status_code}, daemon code {}): {}",
                            sanitize_for_terminal(&body.code),
                            sanitize_for_terminal(&body.message)
                        ),
                        "check the daemon's tracing log for the matching request_id, then retry",
                        None,
                    )
                );
                return Err(silent_err_for_code("connect.seal_failed", "seal failed"));
            }
            Ok(super::connect_uds::ControlOutcome::ParseFailure { status_code, raw_body }) => {
                return Err(render_parse_failure(
                    "connect.seal_failed",
                    "credentials seal",
                    status_code,
                    &raw_body,
                ));
            }
            Err(transport_err) => {
                eprint!(
                    "{}",
                    render::error_block(
                        "connect.seal_failed",
                        &format!("credentials seal transport error: {transport_err}"),
                        "verify the daemon is healthy: agentsso status",
                        None,
                    )
                );
                return Err(silent_err_for_code("connect.seal_failed", "seal transport failure"));
            }
        }

        // Move oauth_config out so the post-block verify + summary code
        // can read its project_id / provenance_tag.
        oauth_config_opt = Some(oauth_config);
        granted_scopes_for_seal
    };

    // ── Step 3 — verify (with retry loop, AC #4) ────────────────────
    //
    // Read the now-sealed credential and probe upstream Google. On a
    // 403 SERVICE_DISABLED / BILLING_DISABLED / SCOPE_INSUFFICIENT
    // (Story 7.12), `remediation_owned()` renders the actionable
    // URL/gcloud command. Up to 5 attempts in interactive mode;
    // first failure exits in --non-interactive mode.
    let project_id_for_verify = oauth_config_opt.as_ref().and_then(|c| c.project_id());
    verify_with_retry(&control_handle, &service, project_id_for_verify, interactive, &args).await?;

    if interactive {
        let check = styled("\u{2713}", theme.tokens().accent, color_support);
        let styled_service = styled(&service, theme.tokens().accent, color_support);
        // Story 7.38: scope the claim — verify only proves the sealed
        // Google credential mints an upstream token, not the full
        // agent→daemon→Google bearer chain. Service token is styled
        // separately; suffix is shared with `verify_success_line` (and
        // its snapshot test) via `VERIFY_SUFFIX`.
        println!("  {check} {styled_service} {VERIFY_SUFFIX}");
    } else {
        tracing::info!(
            service = %service,
            "google credential verified (upstream token mint ok; bearer chain not exercised)"
        );
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

    // Story 7.30 (Task 10): policy edit + reload move daemon-side. The
    // CLI POSTs the short-name diff to `/v1/control/policy/{name}/scopes`
    // and the daemon owns the file-write + ArcSwap reload. No-op merges
    // surface as `reloaded: false` in the response.
    let scopes_req = super::connect_uds::PolicyScopesRequest { short_names: &short_names };
    let policy_outcome =
        super::connect_uds::post_policy_scopes(&control_handle, &agent_policy_name, &scopes_req)
            .await;
    let policies_dir = crate::cli::agent::policies_dir_remediation(&daemon_home);
    let policy_resp = match policy_outcome {
        Ok(super::connect_uds::ControlOutcome::Ok(resp)) => resp,
        Ok(super::connect_uds::ControlOutcome::Err { status_code, body }) => {
            // Round-3 review P67: sanitize daemon-returned text.
            eprint!(
                "{}",
                render::error_block(
                    "connect.policy_edit_failed",
                    &format!(
                        "policy scope merge failed (HTTP {status_code}, daemon code {}): {}",
                        sanitize_for_terminal(&body.code),
                        sanitize_for_terminal(&body.message)
                    ),
                    // Policy files may use either one-file-per-policy or
                    // multi-policy layouts (e.g. default.toml), so point
                    // operators at the directory rather than inventing a
                    // `<policy>.toml` path. If the daemon's
                    // `policy.reload_failed` surfaced here, `agentsso reload`
                    // retries. Otherwise: inspect the daemon's tracing log
                    // for the parse/IO error and fix the file out-of-band
                    // with sudo.
                    &format!(
                        "agentsso reload   # if the daemon's in-memory \
                         policy set drifted from disk\n\
                         # else: inspect {policies_dir} \
                         (root-only; policies may live inside default.toml) for the underlying issue;\n\
                         # the daemon's tracing log carries the parse/IO error detail.\n\
                         # Scopes requested in this run: {scopes}",
                        policies_dir = policies_dir,
                        scopes = short_names.join(", "),
                    ),
                    None,
                )
            );
            return Err(silent_err_for_code("connect.policy_edit_failed", "policy edit failed"));
        }
        Ok(super::connect_uds::ControlOutcome::ParseFailure { status_code, raw_body }) => {
            return Err(render_parse_failure(
                "connect.policy_edit_failed",
                "policy scope merge",
                status_code,
                &raw_body,
            ));
        }
        Err(transport_err) => {
            eprint!(
                "{}",
                render::error_block(
                    "connect.policy_edit_failed",
                    &format!("policy scope merge transport error: {transport_err}"),
                    "verify the daemon is healthy: agentsso status",
                    None,
                )
            );
            return Err(silent_err_for_code(
                "connect.policy_edit_failed",
                "policy edit transport failure",
            ));
        }
    };
    let default_scope = match default_scope_for_snippet(&policy_resp, &short_names) {
        Some(scope) => scope,
        None => {
            eprint!(
                "{}",
                render::error_block(
                    "connect.policy_scope_missing",
                    &format!("policy '{agent_policy_name}' has no allowlisted scope for {service}"),
                    "edit the daemon policy file to include at least one scope, then run `agentsso reload` and retry",
                    None,
                )
            );
            return Err(silent_err_for_code(
                "connect.policy_scope_missing",
                "policy has no usable default scope",
            ));
        }
    };
    let policy_was_modified = !policy_resp.added.is_empty();
    // Round-1 review P30: detect the disk-edited-but-not-reloaded
    // case explicitly. Daemon emits `policy-scopes-add-partial-failure`
    // audit event on that path; surface an operator-facing warning so
    // they don't think the new scopes are live in memory yet.
    let disk_drift = policy_was_modified && !policy_resp.reloaded;
    if interactive {
        if policy_was_modified {
            let added = policy_resp.added.join(", ");
            let check = styled("\u{2713}", theme.tokens().accent, color_support);
            println!("  {check} policy '{agent_policy_name}' updated \u{00b7} added: {added}");
            if policy_resp.reloaded {
                let check = styled("\u{2713}", theme.tokens().accent, color_support);
                println!("  {check} daemon reloaded");
            } else {
                let warn = styled("!", theme.tokens().accent, color_support);
                eprintln!(
                    "  {warn} policy file updated on disk but daemon has NOT reloaded yet \u{2014} \
                     the new scopes are NOT live until you run `agentsso reload`."
                );
            }
        } else {
            let check = styled("\u{2713}", theme.tokens().accent, color_support);
            println!(
                "  {check} policy '{agent_policy_name}' \u{00b7} skipped (scopes already present)"
            );
            let check = styled("\u{2713}", theme.tokens().accent, color_support);
            println!("  {check} reload \u{00b7} skipped (policy unchanged)");
        }
    } else {
        if disk_drift {
            tracing::warn!(
                policy = %agent_policy_name,
                added = ?policy_resp.added,
                "policy file updated on disk but daemon did not reload — run `agentsso reload` to make the new scopes live",
            );
        }
        tracing::info!(
            policy = %agent_policy_name,
            added = ?policy_resp.added,
            reloaded = policy_resp.reloaded,
            "policy edit complete"
        );
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
                // Story 7.36 AC #1: tell the operator the bearer was
                // NOT touched, so a later token problem isn't misread
                // as connect having orphaned it.
                println!("    {}", rebind_bearer_preserved_note());
            } else {
                tracing::info!(
                    agent = %args.agent,
                    policy = %agent_policy_name,
                    bearer_preserved = true,
                    "rebind ok; bearer token preserved (policy-only change)"
                );
            }
        }
        Err(e) => {
            // Round-1 P10: switch the remediation on the upstream error
            // code. The default ("retry rebind") is wrong when the
            // failure is `agent.not_found` (concurrent `agent remove`)
            // — rebind will keep failing; the right next step is to
            // re-register the agent.
            let err_str = e.to_string();
            let remediation: String = if err_str.starts_with("agent.not_found") {
                "agentsso agent register <name> --policy <policy>   # agent was removed; \
                 register fresh"
                    .to_owned()
            } else if err_str.starts_with("agent.unknown_policy") {
                format!(
                    "{}   # policy missing",
                    crate::cli::agent::policies_dir_remediation(&daemon_config.paths.home)
                )
            } else {
                "agentsso agent rebind <name> --policy <policy>   # diagnose, then retry".to_owned()
            };
            eprint!(
                "{}",
                render::error_block(
                    "connect.rebind_failed",
                    &format!("failed to rebind agent '{}': {e}", args.agent),
                    &remediation,
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
    emit_openclaw_snippet(&args, &service, interactive, &theme, &default_scope).await?;

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
        // Story 7.38: be explicit that verify success ≠ chain works —
        // the bearer token still has to be valid in the MCP client.
        println!("  note: {}", next_steps_bearer_note());
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

/// Run the verify probe with up to 5 retries (interactive) or 1
/// attempt (non-interactive). Renders structured errors on each
/// failure via `OAuthError::remediation_owned()` so Story 7.12's
/// actionable text surfaces.
async fn verify_with_retry(
    control_handle: &super::connect_uds::ConnectControlHandle,
    service: &str,
    project_id: Option<&str>,
    interactive: bool,
    args: &ConnectArgs,
) -> anyhow::Result<()> {
    use std::io::{BufRead as _, Write as _};

    const MAX_ATTEMPTS: usize = 5;
    let max = if interactive { MAX_ATTEMPTS } else { 1 };

    for attempt in 1..=max {
        // Story 7.30: verify probe now lives daemon-side. POST to
        // `/v1/control/credentials/{service}/verify` — the daemon
        // unseals the sealed credential and runs the Google probe.
        // The CLI retains the operator-interactive retry-loop UX
        // ("Press Enter to retry") but no longer touches the vault.
        let verify_req =
            super::connect_uds::CredentialsVerifyRequest { agent: &args.agent, project_id };
        let verify_outcome =
            super::connect_uds::post_credentials_verify(control_handle, service, &verify_req).await;
        let (status_code, body): (u16, serde_json::Value) = match verify_outcome {
            Ok(super::connect_uds::VerifyOutcome::Body { status_code, body }) => {
                (status_code, body)
            }
            Ok(super::connect_uds::VerifyOutcome::Err { status_code, body: err_body }) => {
                // Lift the structured error envelope into a serde
                // Value so render_verify_error_from_daemon sees a
                // uniform shape across the 4xx/5xx daemon-side path
                // and the 200+ok=false Google-side path.
                (
                    status_code,
                    serde_json::json!({
                        "ok": false,
                        "code": err_body.code,
                        "message": err_body.message,
                        "request_id": err_body.request_id,
                    }),
                )
            }
            Ok(super::connect_uds::VerifyOutcome::ParseFailure { status_code, raw_body }) => {
                // Round-1 review P29: parse failures are retry-eligible
                // (the daemon responded, the wire just drifted). Log
                // verbose + continue the retry loop in interactive
                // mode; abort with the parse-failure block in
                // non-interactive.
                tracing::warn!(
                    target: "connect.verify",
                    status_code,
                    raw_excerpt = raw_body.chars().take(256).collect::<String>().as_str(),
                    "verify response body did not parse; attempt {attempt}/{max}",
                );
                if !interactive || attempt == max {
                    return Err(render_parse_failure(
                        "connect.verify_failed",
                        "verify",
                        status_code,
                        &raw_body,
                    ));
                }
                // Interactive + not last attempt → fall through to
                // the retry prompt below by constructing a synthetic
                // "transient parse failure" body that render_verify
                // will surface generically.
                (
                    status_code,
                    serde_json::json!({
                        "ok": false,
                        "code": "verify.body_parse_failed",
                        "message": "daemon response did not parse as JSON",
                    }),
                )
            }
            Err(e) => {
                // Round-1 review P27: transport failure mid-retry.
                // The credential IS already sealed by this point —
                // re-running connect would skip OAuth and retry
                // verify. Surface that hint specifically rather
                // than generic "verify the daemon is healthy".
                eprint!(
                    "{}",
                    render::error_block(
                        "connect.verify_failed",
                        &format!("verify transport error: {e}"),
                        &format!(
                            "the daemon went down or the control plane is unreachable, but the credential IS already sealed.\n  \
                             - check the daemon: `agentsso status`\n  \
                             - if running: re-run `agentsso connect {service} --agent {}` — Step 2 will skip OAuth (credential is sealed) and resume at verify.",
                            args.agent
                        ),
                        None,
                    )
                );
                return Err(silent_err_for_code(
                    "connect.verify_failed",
                    "verify transport failure",
                ));
            }
        };

        // Daemon contract:
        //   - 200 with `ok: true`  → verify succeeded.
        //   - 200 with `ok: false` → structured Google failure
        //     (verify_reason / remediation_url surfaced for retry).
        //   - 4xx/5xx → daemon-side failure (credential missing,
        //     unseal failed, transport to Google failed, etc.).
        if (200..300).contains(&status_code)
            && body.get("ok").and_then(|v| v.as_bool()) == Some(true)
        {
            return Ok(());
        }

        // Build a synthetic verify-error message for render_verify_error.
        let last_attempt = attempt == max;
        let severity =
            if last_attempt { OAuthErrorSeverity::Fatal } else { OAuthErrorSeverity::NonFatal };
        render_verify_error_from_daemon(&body, status_code, service, interactive, severity);

        let status_code_401 = body.get("status_code").and_then(|v| v.as_u64()) == Some(401);
        if last_attempt && status_code_401 && interactive {
            eprintln!();
            eprintln!("  hint: 401 after multiple retries can mean the access token expired");
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
        eprint!("  Press Enter to retry (attempt {}/{}), Ctrl-D to abort: ", attempt + 1, max);
        let _ = std::io::stderr().flush();
        let read_handle = tokio::task::spawn_blocking(|| -> std::io::Result<Option<String>> {
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
                return Err(anyhow::anyhow!("stdin task panicked during verify retry: {join_err}"));
            }
            Err(_elapsed) => {
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
    unreachable!("loop terminates via Ok return or Err return inside the for body");
}

/// Story 7.30: render a verify failure surfaced by the daemon's
/// `credentials_verify_handler`. The daemon returns either:
/// - 200 `{ ok: false, status_code, verify_reason, remediation_url, reason_text }`
///   when Google returned a structured error (SERVICE_DISABLED, etc.)
/// - 4xx/5xx with `{ status: "error", code, message, request_id }`
///   for daemon-side failures (credential not found, unseal failed,
///   transport to Google failed).
///
/// This helper renders whichever shape it gets into the same
/// Round-1 review P31: render a body-parse failure when the daemon
/// returned an unparseable response. Distinct from transport-failure
/// (the request reached the daemon and got a response; the response
/// just didn't match our wire contract). Returns the typed-marker
/// error so `connect_to_exit_code` produces the right exit (3, system
/// error).
fn render_parse_failure(
    code: &'static str,
    operation: &str,
    status_code: u16,
    raw_body: &str,
) -> anyhow::Error {
    // Cap the raw-body excerpt so a huge response doesn't flood
    // stderr; cap is generous enough to show the relevant section
    // of any structured daemon body.
    //
    // Round-3 review P61: walk back to the nearest UTF-8 char boundary
    // before slicing — `&raw_body[..512]` panics if byte 512 falls
    // mid-codepoint (multi-byte UTF-8 in localized daemon error
    // messages, emoji, etc.). `floor_char_boundary` is unstable, so we
    // implement the same with `char_indices().take_while(...).last()`.
    const RAW_BODY_CAP: usize = 512;
    let excerpt = if raw_body.len() > RAW_BODY_CAP {
        let boundary = raw_body
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|i| *i <= RAW_BODY_CAP)
            .last()
            .unwrap_or(0);
        let truncated = &raw_body[..boundary];
        format!("{truncated}... ({total} bytes total)", total = raw_body.len())
    } else {
        raw_body.to_owned()
    };
    eprint!(
        "{}",
        render::error_block(
            code,
            &format!(
                "daemon returned a malformed {operation} response (HTTP {status_code}); \
                 the wire contract between CLI and daemon may have drifted. \
                 Body excerpt: {excerpt}"
            ),
            "check the daemon's tracing log for the request_id, and confirm both CLI and daemon \
             are on the same release (run `agentsso --version` and `agentsso status`)",
            None,
        )
    );
    silent_err_for_code(code, "daemon body parse failed")
}

/// `connect.verify_failed` operator block as the legacy CLI-side
/// `render_oauth_error` produced.
fn render_verify_error_from_daemon(
    body: &serde_json::Value,
    status_code: u16,
    service: &str,
    interactive: bool,
    severity: OAuthErrorSeverity,
) {
    let label = match severity {
        OAuthErrorSeverity::Fatal => "verification failed",
        OAuthErrorSeverity::NonFatal => "verification failed (will retry)",
    };

    // Structured Google-side failure (HTTP 200 + ok=false).
    if (200..300).contains(&status_code) && body.get("ok").and_then(|v| v.as_bool()) == Some(false)
    {
        let reason_text = sanitize_for_terminal(
            body.get("reason_text").and_then(|v| v.as_str()).unwrap_or("(no detail)"),
        );
        let google_status = body.get("status_code").and_then(|v| v.as_u64());
        let verify_reason = body.get("verify_reason").and_then(|v| v.as_str()).unwrap_or("unknown");
        // Round-1 review P36: sanitize daemon-returned URL before
        // interpolating into operator-facing output.
        let remediation_url_owned: Option<String> =
            body.get("remediation_url").and_then(|v| v.as_str()).map(sanitize_for_terminal);
        let remediation_url = remediation_url_owned.as_deref();

        let remediation = match (verify_reason, remediation_url) {
            ("service-disabled", Some(url)) => format!(
                "enable the API in the Google Cloud Console:\n    {url}\n\n  \
                 then re-run: agentsso connect {service}"
            ),
            ("billing-disabled", Some(url)) => format!(
                "enable billing on your GCP project:\n    {url}\n\n  \
                 then re-run: agentsso connect {service}"
            ),
            ("scope-insufficient", _) => format!(
                "re-consent with the required scopes:\n  \
                 agentsso connect {service} --force\n\n  \
                 (existing credentials will be replaced)"
            ),
            (_, Some(url)) => format!("see: {url}"),
            _ => "see the daemon's tracing log + audit log for the verify request_id".to_owned(),
        };
        // Round-1 review P28: dispatch on `interactive` mode. The
        // legacy `render_oauth_error` used the design-system error
        // block for interactive runs and structured tracing for
        // non-interactive (so log pipes see one line per failure,
        // not a multi-line block). The P6 unification accidentally
        // dropped the non-interactive branch; restore it.
        if interactive {
            eprint!(
                "{}",
                render::error_block(
                    "connect.verify_failed",
                    &format!(
                        "{label}: {reason_text} (Google HTTP {}, reason {verify_reason})",
                        google_status.map(|s| s.to_string()).unwrap_or_else(|| "?".to_owned()),
                    ),
                    &remediation,
                    None,
                )
            );
        } else {
            // Single-line tracing entry — log pipes / scripted callers
            // get one structured record per failure.
            let remediation_single_line = remediation.replace('\n', " \\n ");
            match severity {
                OAuthErrorSeverity::Fatal => tracing::error!(
                    service = %service,
                    error_code = "connect.verify_failed",
                    verify_reason = %verify_reason,
                    google_status = ?google_status,
                    remediation = %remediation_single_line,
                    "{label}: {reason_text}"
                ),
                OAuthErrorSeverity::NonFatal => tracing::warn!(
                    service = %service,
                    error_code = "connect.verify_failed",
                    verify_reason = %verify_reason,
                    google_status = ?google_status,
                    remediation = %remediation_single_line,
                    "{label}: {reason_text}"
                ),
            }
        }
        return;
    }

    // Daemon-side failure (4xx/5xx with `{ status: "error", code, message }`).
    // Round-1 review P36: sanitize message in case a future daemon
    // forwards control chars from an upstream error.
    let code = body.get("code").and_then(|v| v.as_str()).unwrap_or("verify.unknown");
    let message = sanitize_for_terminal(
        body.get("message").and_then(|v| v.as_str()).unwrap_or("(no detail)"),
    );
    if interactive {
        eprint!(
            "{}",
            render::error_block(
                "connect.verify_failed",
                &format!("{label}: {message} (HTTP {status_code}, daemon code {code})"),
                "check the daemon's tracing log for the matching request_id",
                None,
            )
        );
    } else {
        match severity {
            OAuthErrorSeverity::Fatal => tracing::error!(
                service = %service,
                error_code = "connect.verify_failed",
                daemon_code = %code,
                http_status = status_code,
                "{label}: {message}"
            ),
            OAuthErrorSeverity::NonFatal => tracing::warn!(
                service = %service,
                error_code = "connect.verify_failed",
                daemon_code = %code,
                http_status = status_code,
                "{label}: {message}"
            ),
        }
    }
}

/// POST `/v1/control/agent/rebind` against the running daemon.
///
/// Story 7.27 Round-2 review fix (P0): dispatches over UDS on macOS
/// via `resolve_control_endpoint(&config)` + `http_post_json_via`.
async fn post_rebind(home: &Path, agent: &str, policy: &str) -> anyhow::Result<()> {
    let config = crate::cli::kill::load_daemon_config_or_default_with_warn("connect rebind");
    let endpoint = crate::cli::kill::resolve_control_endpoint(&config);
    let token = crate::cli::kill::read_control_token(home);
    let body = serde_json::json!({"name": agent, "policy_name": policy}).to_string();
    let response = match crate::cli::kill::http_post_json_via(
        &endpoint,
        "/v1/control/agent/rebind",
        &body,
        token.as_deref(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            // Round-3 review fix (R3-C5-P3): structured endpoint-aware
            // error-block discipline for transport failures (matches
            // the pattern in kill.rs / agent.rs / etc.). Classifies
            // ENOENT/EACCES/ECONNREFUSED so the operator gets a
            // targeted remediation instead of one-size-fits-all.
            tracing::debug!(error = %e, endpoint = %endpoint, "agent rebind transport failure");
            eprint!(
                "{}",
                crate::cli::kill::error_block_daemon_unreachable_endpoint_classified(
                    "agent rebind",
                    &endpoint,
                    Some(&e),
                )
            );
            return Err(silent_err_for_code(
                "agent.rebind_transport_failure",
                "rebind transport failure",
            ));
        }
    };
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
    default_scope: &str,
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

    let snippet = super::openclaw::build_snippet(service, &bearer_token, bind_addr, default_scope);

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
    use crate::cli::connect_uds;
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
        assert!(!args.allow_root);
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
    fn clap_parses_allow_root() {
        let cli =
            parse(&["agentsso", "connect", "gmail", "--agent", "me", "--allow-root"]).unwrap();
        let TestCmd::Connect(args) = cli.cmd;
        assert!(args.allow_root);
    }

    // Story 7.33 review fix: command-level guard coverage. The root-guard
    // helper tests in root_guard.rs pass even if the connect run() call
    // site stops invoking the guard. This test pins the composition of
    // ConnectArgs + the guard so a future refactor can't drop the call.
    #[cfg(unix)]
    #[test]
    fn connect_guard_refuses_root_shell_before_daemon_contact() {
        let result = connect_root_guard_for("gmail", "me", false, 0, Some("testuser"));
        assert!(
            result.is_err(),
            "connect_root_guard_for must refuse root+SUDO_USER before any daemon contact"
        );
    }

    #[cfg(unix)]
    #[test]
    fn connect_guard_allows_root_when_explicitly_requested() {
        let result = connect_root_guard_for("gmail", "me", true, 0, Some("testuser"));
        assert!(
            result.is_ok(),
            "connect_root_guard_for must allow root when --allow-root is passed"
        );
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
            "connect.dangling_policy_binding",
            "connect.unknown_service",
            "connect.invalid_oauth_client",
            "connect.daemon_must_run",
            "connect.non_interactive_required",
        ] {
            assert_eq!(connect_exit_code(code), 2, "code {code} should be precondition (exit 2)");
        }
    }

    /// Round-1 review P34: `connect.reload_failed` dropped — reload
    /// failure now surfaces as `connect.policy_edit_failed` via the
    /// single policy/scopes POST.
    #[test]
    fn connect_exit_code_system_errors_map_to_3() {
        for code in [
            "connect.oauth_failed",
            "connect.seal_failed",
            "connect.verify_failed",
            "connect.policy_edit_failed",
            "connect.rebind_failed",
            "connect.openclaw_failed",
            "connect.agent_lookup_failed",
            "connect.meta_lookup_failed",
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
    fn default_scope_for_snippet_picks_first_requested_scope_in_policy_order() {
        let resp = connect_uds::PolicyScopesResponse {
            policy_name: "calendar-read".to_owned(),
            before: vec!["calendar.readonly".to_owned(), "calendar.events".to_owned()],
            added: Vec::new(),
            after: vec!["calendar.readonly".to_owned(), "calendar.events".to_owned()],
            reloaded: false,
        };

        assert_eq!(
            default_scope_for_snippet(&resp, &["calendar.events", "calendar.readonly"]),
            Some("calendar.readonly".to_owned())
        );
    }

    #[test]
    fn default_scope_for_snippet_ignores_unrelated_policy_scopes_and_empty_policy() {
        let resp = connect_uds::PolicyScopesResponse {
            policy_name: "calendar-read".to_owned(),
            before: Vec::new(),
            added: vec!["calendar.readonly".to_owned()],
            after: vec!["calendar.readonly".to_owned(), "calendar.events".to_owned()],
            reloaded: true,
        };

        assert_eq!(
            default_scope_for_snippet(&resp, &["calendar.events", "calendar.readonly"]),
            Some("calendar.readonly".to_owned())
        );
        assert_eq!(default_scope_for_snippet(&resp, &["drive.readonly"]), None);

        let empty_resp = connect_uds::PolicyScopesResponse {
            policy_name: "gmail-read".to_owned(),
            before: Vec::new(),
            added: Vec::new(),
            after: Vec::new(),
            reloaded: true,
        };

        assert_eq!(default_scope_for_snippet(&empty_resp, &["gmail.readonly"]), None);
        assert_eq!(default_scope_for_snippet(&empty_resp, &[]), None);
    }

    // ── Story 7.38: verify-success wording is scoped, not absolute ──

    #[test]
    fn verify_suffix_scopes_the_claim() {
        // The operator sees `<service> {VERIFY_SUFFIX}` (service is
        // styled separately at the call site).
        let line = format!("gmail {VERIFY_SUFFIX}");
        // AC #1: must NOT be an unqualified "<svc> verified" — that
        // read as end-to-end success and misdirected diagnosis.
        assert_ne!(line, "gmail verified");
        assert!(!line.ends_with(" verified"));
        // It must name *what* was verified (the Google credential),
        // not imply the bearer/chain.
        assert!(line.contains("gmail"));
        assert!(VERIFY_SUFFIX.contains("Google credential verified"));
        assert!(VERIFY_SUFFIX.to_lowercase().contains("token mint"));
        assert!(!VERIFY_SUFFIX.to_lowercase().contains("bearer"));
    }

    #[test]
    fn verify_suffix_pins_exact_wording() {
        // Snapshot pin (AC #3): `VERIFY_SUFFIX` is the exact string the
        // interactive connect path prints after the styled service
        // token — a deliberate change here is a deliberate change to
        // operator-facing semantics.
        assert_eq!(VERIFY_SUFFIX, "Google credential verified (upstream token mint OK)");
    }

    // ── Story 7.36 AC #1: connect surfaces bearer preservation ─────

    #[test]
    fn rebind_bearer_preserved_note_states_bearer_untouched() {
        // AC #1: the operator must be told connect preserved the
        // bearer (so a later token problem isn't misread as connect
        // having orphaned it — the Angie-2 footgun).
        let note = rebind_bearer_preserved_note();
        assert!(note.contains("bearer token preserved"));
        assert!(note.contains("policy"));
        // Must point at the ONE op that does invalidate it, so the
        // operator knows when re-deploying the snippet IS required.
        assert!(note.contains("agentsso agent rotate"));
        // Must NOT imply connect rotated/re-issued anything.
        assert!(!note.to_lowercase().contains("new bearer"));
        assert!(!note.to_lowercase().contains("re-issued"));
    }

    #[test]
    fn next_steps_bearer_note_makes_chain_dependency_explicit() {
        // AC #2: the next-steps block must say the bearer token has to
        // be valid in the MCP client for the chain to work, and that
        // "verified" only covered the sealed Google credential.
        let note = next_steps_bearer_note();
        assert!(note.contains("bearer token"));
        assert!(note.contains("MCP client"));
        assert!(note.contains("chain"));
        assert!(note.contains("sealed Google credential"));
    }
}
