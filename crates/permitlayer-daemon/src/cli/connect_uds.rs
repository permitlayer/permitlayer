//! UDS client glue for `agentsso connect` (Story 7.30).
//!
//! The connect flow used to read the agent store, vault, and master
//! key directly. Post-7.30 those touchpoints all move daemon-side:
//! - `GET /v1/control/agent/{name}/policy_name` — resolve policy.
//! - `GET /v1/control/credentials/{service}/meta` — idempotent re-run check.
//! - `POST /v1/control/credentials/seal` — seal access/refresh + meta.
//! - `POST /v1/control/credentials/{service}/verify` — verify probe.
//! - `POST /v1/control/policy/{policy_name}/scopes` — merge scopes + reload.
//!
//! This module owns the typed request/response shapes (mirrored from
//! `crates/permitlayer-daemon/src/server/control.rs` Story 7.30
//! endpoint definitions) and the daemon-must-be-running gate that
//! renders structured remediation when the operator hasn't installed
//! or started the daemon yet.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::cli::kill::{
    self, ControlEndpoint, http_get_via, http_get_with_status_via, http_post_json_with_status_via,
};
use crate::config::{CliOverrides, DaemonConfig};
use crate::design::render;
use crate::lifecycle::pid::PidFile;

// ── Daemon-running gate (Story 7.30 AC #7) ─────────────────────────

/// Resolved control-plane handle for the connect flow.
pub(crate) struct ConnectControlHandle {
    pub endpoint: ControlEndpoint,
    pub control_token: Option<String>,
}

/// Verify the daemon is running and the control plane is reachable.
/// Returns a handle the rest of the connect flow uses for UDS calls.
///
/// Failure renders a structured `connect.daemon_must_run` error block
/// with three remediation branches per AC #7:
/// - helper binary missing → `sudo agentsso service install`
/// - helper present but launchd shows not-running → `sudo launchctl kickstart`
/// - socket connect fails with EACCES → group membership remediation
///
/// On Linux/Windows the rc.21 TCP-loopback model is preserved; the
/// remediation surfaces a single "the daemon process isn't reachable"
/// line because the install ladder is different there.
pub(crate) async fn require_daemon_running(
    home: &Path,
) -> Result<ConnectControlHandle, anyhow::Error> {
    let config = DaemonConfig::load(&CliOverrides::default()).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "DaemonConfig::load failed; using defaults for control endpoint");
        DaemonConfig::default()
    });
    let endpoint = kill::resolve_control_endpoint(&config);
    let control_token = kill::read_control_token(home);

    // Liveness probe: try `GET /v1/control/whoami` (a tiny no-state
    // endpoint that requires the control token + loopback). If this
    // succeeds we know the daemon is up AND we can talk to it; both
    // the install-ladder failures and the EACCES-on-socket failure
    // surface here distinct from a daemon that's up but in some
    // weird state.
    let probe = http_get_via(&endpoint, "/v1/control/whoami", control_token.as_deref()).await;
    match probe {
        Ok(_) => Ok(ConnectControlHandle { endpoint, control_token }),
        Err(err) => {
            let pid_state = pid_hint(home);
            render_daemon_must_run(&endpoint, &err, &pid_state);
            Err(crate::cli::connect::silent_err_for_code(
                "connect.daemon_must_run",
                "daemon is not running or control plane unreachable",
            ))
        }
    }
}

/// Render the structured `connect.daemon_must_run` error block.
fn render_daemon_must_run(endpoint: &ControlEndpoint, err: &anyhow::Error, pid_state: &PidHint) {
    let err_str = err.to_string();
    // Best-effort remediation classification. `connect.daemon_must_run`
    // is the umbrella; the remediation text branches inside.
    let remediation = match (endpoint, pid_state) {
        (ControlEndpoint::Uds(sock), _)
            if err_str.contains("No such file or directory") || !sock.exists() =>
        {
            // On macOS, an absent socket usually means the LaunchDaemon
            // was never installed — point at `agentsso service install`.
            "sudo agentsso service install\n\
             \n\
             # The privileged helper binary is not installed (the\n\
             # /var/run/permitlayer/control.sock socket is absent).\n\
             # Once installed, re-run this `agentsso connect` command."
                .to_owned()
        }
        (ControlEndpoint::Uds(_), _) if err_str.contains("Permission denied") => {
            "sudo dseditgroup -o edit -a $(whoami) -t user permitlayer-clients\n\
             # then log out and back in for the new group membership to take effect.\n\
             #\n\
             # Your user is not in the `permitlayer-clients` group, which gates\n\
             # access to the control socket."
                .to_owned()
        }
        (ControlEndpoint::Uds(_), PidHint::Stopped) => {
            "sudo launchctl kickstart -k system/dev.permitlayer.daemon\n\
             \n\
             # The LaunchDaemon is registered but not currently running."
                .to_owned()
        }
        (ControlEndpoint::Uds(_), _) => "sudo agentsso service install   # if not yet installed\n\
             sudo launchctl kickstart -k system/dev.permitlayer.daemon   # if installed but stopped"
            .to_owned(),
        (ControlEndpoint::Tcp(addr), _) => {
            format!(
                "Start the daemon and re-run.\n\
                 \n\
                 # Could not reach the control plane at {addr}.\n\
                 # Linux/Windows: run `agentsso start` (or your service-manager equivalent).\n\
                 # macOS: this codepath should not fire — file a bug if it does."
            )
        }
    };

    eprint!(
        "{}",
        render::error_block(
            "connect.daemon_must_run",
            "agentsso daemon is not running or its control plane is unreachable — \
             `agentsso connect` writes credentials through the daemon and requires it to be up.",
            &remediation,
            None,
        )
    );
}

/// Probe daemon-running state from the PID file. Best-effort hint
/// for remediation rendering; the actual liveness check is the
/// `whoami` probe in `require_daemon_running`.
enum PidHint {
    Stopped,
    Running,
}

fn pid_hint(home: &Path) -> PidHint {
    if matches!(PidFile::is_daemon_running(home), Ok(true)) {
        PidHint::Running
    } else {
        PidHint::Stopped
    }
}

// ── Wire types: mirror server-side response shapes ─────────────────

#[derive(Debug, Deserialize)]
pub(crate) struct AgentPolicyNameResponse {
    pub name: String,
    pub policy_name: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CredentialMetaResponse {
    pub exists: bool,
    pub meta: Option<permitlayer_oauth::metadata::CredentialMeta>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CredentialsSealRequest<'a> {
    pub service: &'a str,
    pub agent: &'a str,
    pub access_token: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<&'a str>,
    pub granted_scopes: &'a [String],
    pub client_type: &'a str,
    pub client_source: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_secs: Option<u64>,
    pub if_exists: &'a str,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CredentialsSealResponse {
    pub sealed: bool,
    pub replaced_previous: bool,
    pub meta: permitlayer_oauth::metadata::CredentialMeta,
}

#[derive(Debug, Serialize)]
pub(crate) struct CredentialsVerifyRequest<'a> {
    pub agent: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CredentialsVerifyOk {
    pub ok: bool, // true here
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CredentialsVerifyStructuredError {
    pub ok: bool, // false here
    pub status_code: Option<u16>,
    pub verify_reason: Option<String>,
    pub remediation_url: Option<String>,
    pub reason_text: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PolicyScopesRequest<'a> {
    pub short_names: &'a [&'a str],
}

#[derive(Debug, Deserialize)]
pub(crate) struct PolicyScopesResponse {
    pub policy_name: String,
    pub before: Vec<String>,
    pub added: Vec<String>,
    pub after: Vec<String>,
    pub reloaded: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ControlErrorBody {
    #[serde(default)]
    pub status: Option<String>,
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub request_id: Option<String>,
}

/// A typed result of any control-plane call: either a 2xx body that
/// parses as `T`, or an HTTP error code paired with the daemon's
/// structured error envelope.
pub(crate) enum ControlOutcome<T> {
    Ok(T),
    Err { status_code: u16, body: ControlErrorBody },
}

fn parse_outcome<T: for<'de> Deserialize<'de>>(
    status_code: u16,
    body_str: &str,
) -> Result<ControlOutcome<T>> {
    if (200..300).contains(&status_code) {
        let parsed: T = serde_json::from_str(body_str)
            .with_context(|| format!("parsing daemon success body: {body_str}"))?;
        Ok(ControlOutcome::Ok(parsed))
    } else {
        let err_body: ControlErrorBody = serde_json::from_str(body_str).with_context(|| {
            format!("parsing daemon error body (HTTP {status_code}): {body_str}")
        })?;
        Ok(ControlOutcome::Err { status_code, body: err_body })
    }
}

// ── Typed call helpers ─────────────────────────────────────────────

pub(crate) async fn get_agent_policy_name(
    handle: &ConnectControlHandle,
    agent: &str,
) -> Result<ControlOutcome<AgentPolicyNameResponse>> {
    let encoded = url_path_encode(agent);
    let path = format!("/v1/control/agent/{encoded}/policy_name");
    let (status, body) =
        http_get_with_status_via(&handle.endpoint, &path, handle.control_token.as_deref()).await?;
    parse_outcome(status, &body)
}

pub(crate) async fn get_credentials_meta(
    handle: &ConnectControlHandle,
    service: &str,
) -> Result<ControlOutcome<CredentialMetaResponse>> {
    let encoded = url_path_encode(service);
    let path = format!("/v1/control/credentials/{encoded}/meta");
    let (status, body) =
        http_get_with_status_via(&handle.endpoint, &path, handle.control_token.as_deref()).await?;
    parse_outcome(status, &body)
}

pub(crate) async fn post_credentials_seal(
    handle: &ConnectControlHandle,
    req: &CredentialsSealRequest<'_>,
) -> Result<ControlOutcome<CredentialsSealResponse>> {
    let body = serde_json::to_string(req).context("serialize seal request")?;
    let (status, response_body) = http_post_json_with_status_via(
        &handle.endpoint,
        "/v1/control/credentials/seal",
        &body,
        handle.control_token.as_deref(),
    )
    .await?;
    parse_outcome(status, &response_body)
}

pub(crate) async fn post_credentials_verify(
    handle: &ConnectControlHandle,
    service: &str,
    req: &CredentialsVerifyRequest<'_>,
) -> Result<(u16, serde_json::Value)> {
    let body = serde_json::to_string(req).context("serialize verify request")?;
    let encoded = url_path_encode(service);
    let path = format!("/v1/control/credentials/{encoded}/verify");
    let (status, response_body) = http_post_json_with_status_via(
        &handle.endpoint,
        &path,
        &body,
        handle.control_token.as_deref(),
    )
    .await?;
    let parsed: serde_json::Value = serde_json::from_str(&response_body)
        .with_context(|| format!("parsing verify response body: {response_body}"))?;
    Ok((status, parsed))
}

pub(crate) async fn post_policy_scopes(
    handle: &ConnectControlHandle,
    policy_name: &str,
    req: &PolicyScopesRequest<'_>,
) -> Result<ControlOutcome<PolicyScopesResponse>> {
    let body = serde_json::to_string(req).context("serialize policy-scopes request")?;
    let encoded = url_path_encode(policy_name);
    let path = format!("/v1/control/policy/{encoded}/scopes");
    let (status, response_body) = http_post_json_with_status_via(
        &handle.endpoint,
        &path,
        &body,
        handle.control_token.as_deref(),
    )
    .await?;
    parse_outcome(status, &response_body)
}

/// Minimal URL path-segment encoder for agent/service/policy names.
///
/// The names that flow through this function have already passed the
/// daemon's allowlist regex (alphanumerics + `-` + `_`), so this is
/// strictly defense-in-depth against future name-shape changes. We
/// percent-encode anything outside `[A-Za-z0-9._-]`.
fn url_path_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_path_encode_passes_safe_chars() {
        assert_eq!(url_path_encode("claude-desktop"), "claude-desktop");
        assert_eq!(url_path_encode("gmail-read-only"), "gmail-read-only");
        assert_eq!(url_path_encode("agent.v1_2"), "agent.v1_2");
    }

    #[test]
    fn url_path_encode_escapes_path_separator_and_whitespace() {
        // `.` is in the safe-char allowlist (it appears in legitimate
        // policy/agent names like `gmail.read-only`), so `..` passes
        // through. The load-bearing traversal guard is escaping `/`
        // and `\\` — the daemon-side allowlist + the URL routing
        // handle the rest.
        assert_eq!(url_path_encode("a/b"), "a%2Fb");
        assert_eq!(url_path_encode("a\\b"), "a%5Cb");
        assert_eq!(url_path_encode("a b"), "a%20b");
        // Whole `../` sequence escapes its `/`.
        assert_eq!(url_path_encode("../etc"), "..%2Fetc");
    }
}
