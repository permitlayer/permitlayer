//! Shared OAuth-dance + seal-POST core (Story 11.13).
//!
//! Lifted out of the retired `connect <service> --agent` verb (FR23
//! superseded by `connection add` + `bind`). `connection add` drives the
//! operator-interactive Google OAuth dance here, then POSTs the resulting
//! plaintext tokens to the daemon's reshaped seal endpoint
//! (`connection_id` + `slot` + `connector_id`/`name`/`tier`), which seals
//! them into the vault and writes the `ConnectionRecord`. The CLI never
//! touches the master key or `vault/`.
//!
//! The terminal-rendering helpers (`SpinnerGuard`, headless paste, the
//! OAuth-error renderer) live in `cli::oauth_render` and are reused as-is.

use std::path::Path;

use permitlayer_oauth::google::consent::GoogleOAuthConfig;

use crate::design::render;
use crate::design::theme::Theme;

use super::oauth_render::{
    OAuthErrorSeverity, SpinnerGuard, build_teal_theme, print_headless_consent_block,
    read_pasted_redirect_url, render_oauth_error,
};

// ──────────────────────────────────────────────────────────────────
// Exit-code markers (shared CLI exit taxonomy; lifted from `connect`)
// ──────────────────────────────────────────────────────────────────

/// Exit-code 2 marker — operator-correctable input (unknown connector,
/// missing OAuth client, kill-state, non-interactive-without-access).
#[derive(Debug)]
pub(crate) struct ConnectExitCode2;

impl std::fmt::Display for ConnectExitCode2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("operator-correctable input")
    }
}
impl std::error::Error for ConnectExitCode2 {}

pub(crate) fn exit2() -> anyhow::Error {
    anyhow::Error::new(ConnectExitCode2).context(crate::cli::SilentCliError)
}

/// Exit-code 3 marker — system / retry (OAuth, seal, verify, transport).
#[derive(Debug)]
pub(crate) struct ConnectExitCode3;

impl std::fmt::Display for ConnectExitCode3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("system / retry")
    }
}
impl std::error::Error for ConnectExitCode3 {}

#[allow(dead_code)]
pub(crate) fn exit3() -> anyhow::Error {
    anyhow::Error::new(ConnectExitCode3).context(crate::cli::SilentCliError)
}

/// Map a connection error code to its exit code (2 operator-correctable,
/// 3 system/retry).
pub(crate) fn connection_exit_code(code: &str) -> i32 {
    match code {
        "connection.unknown_connector"
        | "connection.invalid_oauth_client"
        | "connection.daemon_must_run"
        | "connection.not_found"
        | "connection.non_interactive_required" => 2,
        _ => 3,
    }
}

/// Build a silent CLI error tagged with the right exit-code marker for a
/// given operator-facing code. The caller owns the `error_block` render;
/// this attaches only the typed marker so `main.rs` produces the right
/// exit code.
pub(crate) fn silent_err_for_code(code: &str, internal_msg: &'static str) -> anyhow::Error {
    let marker = match connection_exit_code(code) {
        2 => anyhow::Error::new(ConnectExitCode2),
        _ => anyhow::Error::new(ConnectExitCode3),
    };
    marker.context(crate::cli::SilentCliError).context(internal_msg)
}

/// Strip control characters from daemon-returned text before it crosses
/// into operator-facing stderr (keeps printable ASCII + common
/// whitespace; replaces the rest with U+FFFD).
pub(crate) fn sanitize_for_terminal(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\n' || c == '\t' || c == ' ' || (!c.is_control() && c != '\u{7f}') {
                c
            } else {
                '\u{fffd}'
            }
        })
        .collect()
}

// ──────────────────────────────────────────────────────────────────
// OAuth scope / endpoint resolution
// ──────────────────────────────────────────────────────────────────

/// Resolve the OAuth scope URIs to request, keyed off the access level
/// (Story 11.7). The connector def is the single source of truth.
pub(crate) fn requested_scope_uris(
    connector: &permitlayer_connectors::ResolvedConnector,
    read_write: bool,
) -> Vec<&str> {
    let tier = if read_write { "read-write" } else { "read" };
    connector.tier_scope_uris(tier).unwrap_or_default()
}

/// Resolve device-flow endpoints. Production: Google's hardcoded URLs.
/// Debug builds honor `AGENTSSO_DEVICE_FLOW_*_URL` for integration tests.
pub(crate) fn device_flow_endpoints() -> permitlayer_oauth::google::device_flow::DeviceFlowEndpoints
{
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

/// Resolve the BYO Google OAuth client config: explicit `--oauth-client`
/// path, an interactive prompt, or an operator-correctable exit-2 error.
pub(crate) async fn resolve_oauth_client(
    oauth_client: Option<&Path>,
    connector_id: &str,
    name: &str,
    theme: &Theme,
    interactive: bool,
) -> anyhow::Result<GoogleOAuthConfig> {
    match oauth_client {
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
                    "connection.invalid_oauth_client",
                    "no OAuth client provided — permitlayer currently requires a \
                     bring-your-own Google OAuth client",
                    &format!(
                        "create a Desktop OAuth client at \
                         https://console.cloud.google.com/apis/credentials, \
                         download the JSON, then re-run:\n\n    \
                         agentsso connection add {connector_id} --name {name} --oauth-client ./client_secret.json"
                    ),
                    None,
                )
            );
            Err(exit2())
        }
    }
}

/// Refuse to open a new OAuth flow when a running daemon's kill switch is
/// active. Fails OPEN on any probe failure (a broken probe must never
/// block the operator); only an explicit `{"active": true}` exits.
pub(crate) async fn probe_daemon_kill_state_or_exit() -> anyhow::Result<()> {
    use crate::config::{CliOverrides, DaemonConfig};
    use crate::lifecycle::pid::PidFile;

    let config = match DaemonConfig::load(&CliOverrides::default()) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(target: "connection", error = %e, "DaemonConfig::load failed during kill-state probe; proceeding");
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
            tracing::warn!(target: "connection", error = %e, "kill-state probe failed; proceeding");
            return Ok(());
        }
        Err(_elapsed) => {
            tracing::warn!(target: "connection", "kill-state probe timed out; proceeding");
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
            tracing::warn!(target: "connection", error = %e, body = %body, "unexpected state response; proceeding");
            return Ok(());
        }
    };
    if snapshot.active {
        eprint!(
            "{}",
            render::error_block(
                "daemon_killed",
                "permitlayer is in kill state \u{2014} cannot open new OAuth flows",
                "agentsso resume",
                None,
            )
        );
        return Err(exit2());
    }
    Ok(())
}

// ──────────────────────────────────────────────────────────────────
// OAuth dance + seal core
// ──────────────────────────────────────────────────────────────────

/// Inputs to [`oauth_dance_and_seal`].
pub(crate) struct OAuthSealInputs<'a> {
    pub connector: &'a permitlayer_connectors::ResolvedConnector,
    pub connector_id: &'a str,
    pub name: &'a str,
    pub read_write: bool,
    pub oauth_config: GoogleOAuthConfig,
    pub connection_id: permitlayer_credential::ConnectionId,
    pub interactive: bool,
    pub headless: bool,
    pub device_flow: bool,
    pub device_flow_timeout: u64,
}

/// Run the Google OAuth dance for `inputs.connector`, then POST the
/// resulting tokens to the daemon's seal endpoint under
/// `inputs.connection_id`. Returns the persisted `ConnectionRecord` on
/// success. The `error_block` rendering happens here; the caller maps the
/// returned error to an exit code.
pub(crate) async fn oauth_dance_and_seal(
    handle: &super::connect_uds::ConnectControlHandle,
    inputs: OAuthSealInputs<'_>,
) -> anyhow::Result<permitlayer_core::store::connection::ConnectionRecord> {
    let OAuthSealInputs {
        connector,
        connector_id,
        name,
        read_write,
        oauth_config,
        connection_id,
        interactive,
        headless,
        device_flow,
        device_flow_timeout,
    } = inputs;

    let client = permitlayer_oauth::OAuthClient::new(
        oauth_config.client_id().to_owned(),
        oauth_config.client_secret().map(str::to_owned),
    )?;

    let requested_scopes = requested_scope_uris(connector, read_write);
    let scopes_owned: Vec<String> = requested_scopes.iter().map(|s| (*s).to_owned()).collect();

    // Phase: authorize (device-flow / headless-paste / browser).
    let result = if device_flow {
        let device_http = reqwest::Client::builder()
            .user_agent("agentsso/0.1")
            .timeout(std::time::Duration::from_secs(30))
            .read_timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| {
                tracing::error!(error = %e, "failed to build device-flow http client");
                silent_err_for_code(
                    "connection.oauth_failed",
                    "device-flow http client build failed",
                )
            })?;
        let scope_refs: Vec<&str> = scopes_owned.iter().map(String::as_str).collect();
        let endpoints = device_flow_endpoints();
        match permitlayer_oauth::google::device_flow::run_device_flow(
            &device_http,
            endpoints,
            oauth_config.client_id(),
            &scope_refs,
            Some(std::time::Duration::from_secs(device_flow_timeout)),
            &permitlayer_oauth::google::device_flow::SystemClock,
            &permitlayer_oauth::google::device_flow::TokioSleeper,
        )
        .await
        {
            Ok(r) => r.into(),
            Err(e) => {
                render_oauth_error(
                    &e,
                    name,
                    interactive,
                    OAuthErrorSeverity::Fatal,
                    "device-flow authorize failed",
                );
                return Err(silent_err_for_code("connection.oauth_failed", "oauth failed"));
            }
        }
    } else if headless {
        match client
            .authorize_headless(scopes_owned.clone(), |url| async move {
                print_headless_consent_block(&url);
                read_pasted_redirect_url().await
            })
            .await
        {
            Ok(r) => r,
            Err(e) => {
                render_oauth_error(
                    &e,
                    name,
                    interactive,
                    OAuthErrorSeverity::Fatal,
                    "headless authorize failed",
                );
                return Err(silent_err_for_code("connection.oauth_failed", "oauth failed"));
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
                    name,
                    interactive,
                    OAuthErrorSeverity::Fatal,
                    "authorize failed",
                );
                return Err(silent_err_for_code("connection.oauth_failed", "oauth failed"));
            }
        }
    } else {
        match client.authorize(scopes_owned.clone(), None).await {
            Ok(r) => r,
            Err(e) => {
                render_oauth_error(
                    &e,
                    name,
                    interactive,
                    OAuthErrorSeverity::Fatal,
                    "authorize failed",
                );
                return Err(silent_err_for_code("connection.oauth_failed", "oauth failed"));
            }
        }
    };

    // Scope-resolution priority on empty `result.scopes`: fall back to the
    // requested set when Google returns an empty list.
    let granted_scopes_for_seal: Vec<String> =
        if result.scopes.is_empty() { scopes_owned.clone() } else { result.scopes.clone() };

    // Best-effort account hint from a userinfo probe with the freshly
    // obtained plaintext access token (the CLI holds it here, pre-seal).
    let service = match connector_id {
        "google-gmail" => "gmail",
        "google-calendar" => "calendar",
        "google-drive" => "drive",
        _ => "",
    };
    let account_hint: Option<String> = if service.is_empty() {
        None
    } else {
        match permitlayer_oauth::google::verify::verify_connection(
            service,
            result.access_token.reveal(),
            oauth_config.project_id(),
        )
        .await
        {
            Ok(vr) => vr.email,
            Err(_) => None,
        }
    };

    // Convert tokens to UTF-8 for the JSON wire body, scrubbed on drop.
    let access_token_str: zeroize::Zeroizing<String> = zeroize::Zeroizing::new(
        std::str::from_utf8(result.access_token.reveal())
            .map_err(|e| anyhow::anyhow!("access token is not valid UTF-8: {e}"))?
            .to_owned(),
    );
    let refresh_token_str: Option<zeroize::Zeroizing<String>> = match result.refresh_token.as_ref()
    {
        Some(t) => Some(zeroize::Zeroizing::new(
            std::str::from_utf8(t.reveal())
                .map_err(|e| anyhow::anyhow!("refresh token is not valid UTF-8: {e}"))?
                .to_owned(),
        )),
        None => None,
    };
    let client_bundle_bytes = oauth_config
        .to_sealed_bundle_bytes()
        .map_err(|e| anyhow::anyhow!("failed to serialize OAuth client bundle: {e}"))?;
    let client_bundle_str: zeroize::Zeroizing<String> =
        zeroize::Zeroizing::new(String::from_utf8(client_bundle_bytes.to_vec()).map_err(|e| {
            use zeroize::Zeroize;
            let mut leaked = e.into_bytes();
            leaked.zeroize();
            anyhow::anyhow!("OAuth client bundle is not valid UTF-8")
        })?);

    let tier = if read_write { "read-write" } else { "read" };
    let seal_req = super::connect_uds::CredentialsSealRequest {
        connection_id: &connection_id.to_string(),
        connector_id,
        name,
        tier,
        account_hint: account_hint.as_deref(),
        access_token: access_token_str.as_str(),
        refresh_token: refresh_token_str.as_ref().map(|z| z.as_str()),
        granted_scopes: &granted_scopes_for_seal,
        client_type: "byo",
        client_bundle_json: client_bundle_str.as_str(),
        if_exists: "replace",
    };

    match super::connect_uds::post_credentials_seal(handle, &seal_req).await {
        Ok(super::connect_uds::ControlOutcome::Ok(resp)) => Ok(resp.connection),
        Ok(super::connect_uds::ControlOutcome::Err { status_code, body }) => {
            eprint!(
                "{}",
                render::error_block(
                    "connection.seal_failed",
                    &format!(
                        "credential seal failed (HTTP {status_code}, daemon code {}): {}",
                        sanitize_for_terminal(&body.code),
                        sanitize_for_terminal(&body.message)
                    ),
                    "check the daemon's tracing log for the matching request_id",
                    None,
                )
            );
            Err(silent_err_for_code("connection.seal_failed", "credential seal failed"))
        }
        Ok(super::connect_uds::ControlOutcome::ParseFailure { status_code, raw_body }) => {
            eprint!(
                "{}",
                render::error_block(
                    "connection.seal_failed",
                    &format!(
                        "credential seal returned an unparseable response (HTTP {status_code}): {}",
                        sanitize_for_terminal(&raw_body)
                    ),
                    "verify the daemon is healthy: agentsso status",
                    None,
                )
            );
            Err(silent_err_for_code("connection.seal_failed", "credential seal parse failure"))
        }
        Err(transport_err) => {
            eprint!(
                "{}",
                render::error_block(
                    "connection.seal_failed",
                    &format!("credential seal transport error: {transport_err}"),
                    "verify the daemon is healthy: agentsso status",
                    None,
                )
            );
            Err(silent_err_for_code("connection.seal_failed", "credential seal transport failure"))
        }
    }
}
