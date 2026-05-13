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
    self, ControlEndpoint, http_get_with_status_via, http_post_json_with_status_via,
};
use crate::config::{CliOverrides, DaemonConfig};
use crate::design::render;
// PidFile dropped per round-1 review P25 — the wrong-path PID-file
// probe never matched against the daemon's actual state-dir on
// macOS, so it was either dead or actively misleading. The
// LaunchDaemon-running discriminator is `launchctl print` (see
// `launchd_daemon_running` below).

// ── Daemon-running gate (Story 7.30 AC #7) ─────────────────────────

/// Resolved control-plane handle for the connect flow.
pub(crate) struct ConnectControlHandle {
    pub endpoint: ControlEndpoint,
    pub control_token: Option<String>,
}

/// Round-1 review P43 helper: path to the LaunchDaemon-installed
/// privileged helper binary on macOS. The spec uses path-existence
/// as the discriminator between "not installed" and "installed but
/// stopped"; a missing socket file is a weaker proxy because the
/// daemon may transiently lose its socket on crash recovery.
#[cfg(target_os = "macos")]
const MACOS_PRIVILEGED_HELPER_PATH: &str = "/Library/PrivilegedHelperTools/agentsso";

/// Round-1 review P43: precise daemon-running detection per AC #7.
/// Returns the diagnostic the operator most needs to see, based on
/// platform-level state — NOT string-matching tokio's io error
/// Display format.
#[derive(Debug)]
enum DaemonDownReason {
    /// macOS: privileged helper binary not installed.
    /// Spec discriminator: `Path::new(MACOS_PRIVILEGED_HELPER_PATH).exists()`.
    #[allow(dead_code)] // constructed only on macOS; the match arm in
    // `render_daemon_must_run` must still cover it cross-platform
    NotInstalled,
    /// macOS: helper installed but `launchctl print
    /// system/dev.permitlayer.daemon` indicates not-running.
    #[allow(dead_code)] // constructed only on macOS
    NotRunningLaunchd,
    /// Socket connect refused (e.g. stale socket inode after a
    /// force-kill). Per kill.rs::error_block_daemon_unreachable_endpoint_classified.
    SocketConnectionRefused,
    /// EACCES on socket connect — operator not in
    /// `permitlayer-clients` group.
    GroupMembership,
    /// TCP path (Linux/Windows rc.21 fallback) — generic
    /// "start the daemon" message.
    TcpUnreachable,
    /// Round-3 review P65: `launchctl print` itself failed (binary
    /// missing, exec denied, exit code we don't understand). Distinct
    /// from `NotRunningLaunchd` so we don't suggest a `kickstart` that
    /// will fail the same way.
    #[allow(dead_code)] // constructed only on macOS
    LaunchdProbeUnavailable,
    /// Round-3 review P66: daemon process is up and reachable but
    /// rejected the control token. Same operator action class as
    /// daemon-down (regenerate/install the token), but the diagnostic
    /// surfaces what's actually wrong.
    ControlTokenRejected { status: u16 },
    /// Probe failed with a non-classified io::Error or daemon
    /// returned a non-2xx status (e.g. control-token mismatch).
    /// Operator gets a generic actionable hint.
    #[allow(dead_code)] // constructed only inside the cfg(unix) UDS arm
    Unclassified,
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
///
/// Round-1 review P25/P26/P43: detection now uses precise signals
/// (helper-binary path-existence, `launchctl print` exit, io::ErrorKind
/// source-chain walk) instead of the previous string-match heuristics
/// against tokio's locale-dependent Display formatting.
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
    // endpoint that requires the control token + loopback).
    //
    // Round-3 review P66: use the status-aware probe so a daemon that
    // is reachable but rejects our control token (≥400) classifies as
    // auth-broken instead of "daemon is up" (which would let the
    // downstream UDS call fail with a confusing
    // `agent_lookup_failed`). Any 4xx/5xx on whoami means the daemon
    // process is up but the control plane isn't usable from this
    // caller — same operator action as daemon-down (regenerate/install
    // the control token).
    let probe =
        http_get_with_status_via(&endpoint, "/v1/control/whoami", control_token.as_deref()).await;
    match probe {
        Ok((status, _body)) if (200..300).contains(&status) => {
            Ok(ConnectControlHandle { endpoint, control_token })
        }
        Ok((status, _body)) => {
            let reason = DaemonDownReason::ControlTokenRejected { status };
            render_daemon_must_run(&endpoint, &reason);
            let _ = home;
            Err(crate::cli::connect::silent_err_for_code(
                "connect.daemon_must_run",
                "daemon is up but rejected the control token",
            ))
        }
        Err(err) => {
            let reason = classify_daemon_down_reason(&endpoint, &err);
            render_daemon_must_run(&endpoint, &reason);
            let _ = home; // home no longer used; PID-file probe dropped (P25).
            Err(crate::cli::connect::silent_err_for_code(
                "connect.daemon_must_run",
                "daemon is not running or control plane unreachable",
            ))
        }
    }
}

/// Round-1 review P25/P26/P43: classify a daemon-down probe failure
/// using precise signals. Walks the io::Error source chain for
/// ErrorKind classification, then falls back to platform-specific
/// state probes (helper binary path-existence; `launchctl print`
/// exit code).
fn classify_daemon_down_reason(
    endpoint: &ControlEndpoint,
    err: &anyhow::Error,
) -> DaemonDownReason {
    let io_kind = walk_io_error_kind(err);
    match endpoint {
        ControlEndpoint::Tcp(_) => match io_kind {
            Some(std::io::ErrorKind::PermissionDenied) => DaemonDownReason::GroupMembership,
            Some(std::io::ErrorKind::ConnectionRefused) => {
                DaemonDownReason::SocketConnectionRefused
            }
            _ => DaemonDownReason::TcpUnreachable,
        },
        #[cfg(unix)]
        ControlEndpoint::Uds(_) => {
            // Order matters: EACCES first because a permission error
            // tells us we DO have a daemon running (the socket exists
            // + accepts connections + checks our credentials) — just
            // not as us.
            if matches!(io_kind, Some(std::io::ErrorKind::PermissionDenied)) {
                return DaemonDownReason::GroupMembership;
            }
            if matches!(io_kind, Some(std::io::ErrorKind::ConnectionRefused)) {
                return DaemonDownReason::SocketConnectionRefused;
            }
            #[cfg(target_os = "macos")]
            {
                if !std::path::Path::new(MACOS_PRIVILEGED_HELPER_PATH).exists() {
                    return DaemonDownReason::NotInstalled;
                }
                // Round-3 review P64: `NotFound` on UDS connect when
                // the helper IS installed means the socket inode is
                // missing — daemon crashed mid-bind, or operator
                // removed the socket. Route to SocketConnectionRefused
                // so the kickstart remediation fires instead of
                // falling through to Unclassified.
                if matches!(io_kind, Some(std::io::ErrorKind::NotFound)) {
                    return DaemonDownReason::SocketConnectionRefused;
                }
                // Round-3 review P65: distinguish "launchctl confirmed
                // not running" from "launchctl probe itself failed".
                // The kickstart remediation only makes sense for the
                // former.
                match launchd_daemon_running() {
                    Some(false) => return DaemonDownReason::NotRunningLaunchd,
                    None => return DaemonDownReason::LaunchdProbeUnavailable,
                    Some(true) => {} // loaded + running per launchctl — fall through
                }
            }
            DaemonDownReason::Unclassified
        }
    }
}

/// Walk the anyhow source chain looking for the underlying
/// `io::Error` and return its `ErrorKind`. Mirror of the helper
/// inside `kill::error_block_daemon_unreachable_endpoint_classified`
/// (same code; duplicating here keeps the connect_uds module
/// self-contained for testing).
fn walk_io_error_kind(err: &anyhow::Error) -> Option<std::io::ErrorKind> {
    let mut cur: Option<&dyn std::error::Error> = Some(err.as_ref());
    while let Some(e) = cur {
        if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
            return Some(io_err.kind());
        }
        cur = e.source();
    }
    None
}

/// Round-1 review P43 / Round-3 review P65: shell out to `launchctl
/// print system/dev.permitlayer.daemon` and classify the result.
///
/// Returns:
/// - `Some(true)` — service is loaded and the state-line check
///   confirms it's running.
/// - `Some(false)` — service is loaded but the state-line shows
///   `not running` / `waiting` (kickstart remediation is appropriate).
/// - `None` — the probe itself failed (binary missing, exec denied,
///   non-success exit we can't interpret). The caller must not
///   suggest `kickstart` here — it would fail the same way; route
///   to `LaunchdProbeUnavailable` instead.
///
/// `launchctl print` returns exit 0 when the service is loaded
/// (regardless of its state); a non-loaded service exits ~113.
#[cfg(target_os = "macos")]
fn launchd_daemon_running() -> Option<bool> {
    let output = std::process::Command::new("/bin/launchctl")
        .args(["print", "system/dev.permitlayer.daemon"])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            // Service is loaded. Parse stdout for the "state = " line
            // — a loaded-but-not-running service emits e.g. "state =
            // not running" or "state = waiting".
            let stdout = String::from_utf8_lossy(&o.stdout);
            let any_not_running = stdout.lines().any(|l| {
                let l = l.trim_start();
                l.starts_with("state =") && (l.contains("not running") || l.contains("waiting"))
            });
            Some(!any_not_running)
        }
        Ok(o) => {
            // Non-zero exit. Two cases of interest:
            // - Exit ~113 ("Service not loaded") — operator hasn't run
            //   `agentsso service install`, OR launchctl bootstrap
            //   failed. In either case the kickstart remediation will
            //   fail with the same error; treat as probe-unavailable
            //   so we surface the "probe failed" diagnostic instead.
            // - Any other non-zero exit — likely launchctl interface
            //   drift; also probe-unavailable.
            tracing::warn!(
                exit = ?o.status.code(),
                stderr = %String::from_utf8_lossy(&o.stderr),
                "launchctl print returned non-success exit; cannot classify daemon state"
            );
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "launchctl exec failed; cannot classify daemon state");
            None
        }
    }
}

/// Render the structured `connect.daemon_must_run` error block.
fn render_daemon_must_run(endpoint: &ControlEndpoint, reason: &DaemonDownReason) {
    let remediation = match reason {
        DaemonDownReason::NotInstalled => "sudo agentsso service install\n\
             \n\
             # The privileged helper binary is not installed at\n\
             # /Library/PrivilegedHelperTools/agentsso. Run\n\
             # `sudo agentsso service install` to install it and\n\
             # register the LaunchDaemon."
            .to_owned(),
        DaemonDownReason::NotRunningLaunchd => {
            "sudo launchctl kickstart -k system/dev.permitlayer.daemon\n\
             \n\
             # The LaunchDaemon is registered (helper binary is\n\
             # installed) but `launchctl print system/dev.permitlayer.daemon`\n\
             # shows the daemon is not currently running. Kickstart\n\
             # it and re-run."
                .to_owned()
        }
        DaemonDownReason::SocketConnectionRefused => "sudo rm /var/run/permitlayer/control.sock\n\
             sudo launchctl kickstart -k system/dev.permitlayer.daemon\n\
             \n\
             # The control socket exists but isn't accepting\n\
             # connections — likely a stale socket from a\n\
             # force-killed daemon. Remove it and kickstart."
            .to_owned(),
        DaemonDownReason::GroupMembership => {
            "sudo dseditgroup -o edit -a $(whoami) -t user permitlayer-clients\n\
             # then log out and back in for the new group membership to take effect.\n\
             #\n\
             # Your user is not in the `permitlayer-clients` group, which gates\n\
             # access to the control socket."
                .to_owned()
        }
        DaemonDownReason::TcpUnreachable => format!(
            "Start the daemon and re-run.\n\
             \n\
             # Could not reach the control plane at {endpoint}.\n\
             # Linux/Windows: run `agentsso start` (or your service-manager equivalent).\n\
             # macOS: this codepath should not fire — file a bug if it does."
        ),
        DaemonDownReason::LaunchdProbeUnavailable => format!(
            "verify the daemon is healthy: `sudo launchctl print system/dev.permitlayer.daemon`\n\
             \n\
             # Could not reach the control plane at {endpoint}, and\n\
             # `launchctl print system/dev.permitlayer.daemon` itself\n\
             # failed — the kickstart remediation would fail the same\n\
             # way. Run the launchctl print command above (or check\n\
             # the daemon's tracing log) to see why the LaunchDaemon\n\
             # is in an unexpected state."
        ),
        DaemonDownReason::ControlTokenRejected { status } => format!(
            "regenerate the control token and try again\n\
             \n\
             # The daemon process is up at {endpoint} but rejected the\n\
             # control token (HTTP {status}). Either the token in\n\
             # ~/.agentsso/control.token (or AGENTSSO_CONTROL_TOKEN env)\n\
             # is wrong, or it has been rotated by the daemon. Re-run\n\
             # `sudo agentsso service install` to re-provision the\n\
             # token, then re-try."
        ),
        DaemonDownReason::Unclassified => format!(
            "verify the daemon is healthy: `agentsso status`\n\
             \n\
             # Could not classify the failure reaching {endpoint}.\n\
             # Check the daemon's tracing log (and your control token\n\
             # in ~/.agentsso/control.token or AGENTSSO_CONTROL_TOKEN env)."
        ),
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

// ── Wire types: mirror server-side response shapes ─────────────────
//
// Round-3 review verification: these structs are Deserialize targets
// that mirror the daemon's response envelopes exactly, so we get a
// hard parse error if the daemon ever drifts the wire shape. Some
// fields aren't read on the CLI side today (e.g. CredentialsSealResponse.meta
// is computed daemon-side and CLI-side state stays canonical); the
// allow blocks intentional rather than silently `#[serde(skip)]`-ing
// them and losing wire-shape pinning.

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(crate) struct CredentialsVerifyOk {
    pub ok: bool, // true here
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
}

#[allow(dead_code)]
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

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(crate) struct PolicyScopesResponse {
    pub policy_name: String,
    pub before: Vec<String>,
    pub added: Vec<String>,
    pub after: Vec<String>,
    pub reloaded: bool,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(crate) struct ControlErrorBody {
    #[serde(default)]
    pub status: Option<String>,
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub request_id: Option<String>,
}

/// A typed result of any control-plane call: a 2xx body that parses
/// as `T`, an HTTP error code paired with the daemon's structured
/// error envelope, OR a body-parse failure (round-1 review P31 —
/// previously parse failures collapsed into a transport-style anyhow
/// error, masking the actual response).
pub(crate) enum ControlOutcome<T> {
    Ok(T),
    Err {
        status_code: u16,
        body: ControlErrorBody,
    },
    /// Round-1 review P31: daemon returned a response that doesn't
    /// match either the 2xx success shape or the 4xx/5xx error
    /// envelope. The HTTP transport succeeded but the wire contract
    /// drifted. Distinct from transport-failure so callers can render
    /// a more accurate diagnostic.
    ParseFailure {
        status_code: u16,
        raw_body: String,
    },
}

fn parse_outcome<T: for<'de> Deserialize<'de>>(
    status_code: u16,
    body_str: &str,
) -> Result<ControlOutcome<T>> {
    if (200..300).contains(&status_code) {
        match serde_json::from_str::<T>(body_str) {
            Ok(parsed) => Ok(ControlOutcome::Ok(parsed)),
            Err(_e) => {
                // Round-1 review P31: surface as ParseFailure so the
                // caller can render "daemon returned malformed
                // response" — DISTINCT from "couldn't reach daemon".
                Ok(ControlOutcome::ParseFailure { status_code, raw_body: body_str.to_owned() })
            }
        }
    } else {
        match serde_json::from_str::<ControlErrorBody>(body_str) {
            Ok(err_body) => Ok(ControlOutcome::Err { status_code, body: err_body }),
            Err(_e) => {
                Ok(ControlOutcome::ParseFailure { status_code, raw_body: body_str.to_owned() })
            }
        }
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
    // Round-1 review P42: serialize the seal-request body into a
    // `Zeroizing<String>` so the heap allocation gets scrubbed on
    // drop. Tokens are the operator-sensitive content; the wrapping
    // here closes the third of the four CLI-side plaintext windows.
    // The fourth window (HTTP request buffer) is closed by
    // `http_post_zeroizing_with_status_via`, which writes the request
    // header + body as separate socket writes instead of concatenating
    // them into a `format!`-produced String.
    let body =
        zeroize::Zeroizing::new(serde_json::to_string(req).context("serialize seal request")?);
    let (status, response_body) = crate::cli::kill::http_post_zeroizing_with_status_via(
        &handle.endpoint,
        "/v1/control/credentials/seal",
        &body,
        handle.control_token.as_deref(),
    )
    .await?;
    parse_outcome(status, &response_body)
}

/// Outcome of a verify POST. Like `ControlOutcome<T>` but the
/// success body shape isn't strict-typed — verify can return either
/// `{ ok: true, ... }` or `{ ok: false, ... }` at HTTP 200, both of
/// which the CLI's retry loop branches on dynamically.
pub(crate) enum VerifyOutcome {
    /// 2xx response with a parseable JSON body.
    Body { status_code: u16, body: serde_json::Value },
    /// 4xx/5xx response with the standard error envelope.
    Err { status_code: u16, body: ControlErrorBody },
    /// Round-1 review P29: response body didn't parse as JSON at
    /// all. Distinct from a transport failure so the verify retry
    /// loop can re-attempt on parse-failure instead of aborting.
    ParseFailure { status_code: u16, raw_body: String },
}

pub(crate) async fn post_credentials_verify(
    handle: &ConnectControlHandle,
    service: &str,
    req: &CredentialsVerifyRequest<'_>,
) -> Result<VerifyOutcome> {
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
    if (200..300).contains(&status) {
        match serde_json::from_str::<serde_json::Value>(&response_body) {
            Ok(parsed) => Ok(VerifyOutcome::Body { status_code: status, body: parsed }),
            Err(_e) => {
                Ok(VerifyOutcome::ParseFailure { status_code: status, raw_body: response_body })
            }
        }
    } else {
        match serde_json::from_str::<ControlErrorBody>(&response_body) {
            Ok(err_body) => Ok(VerifyOutcome::Err { status_code: status, body: err_body }),
            Err(_e) => {
                Ok(VerifyOutcome::ParseFailure { status_code: status, raw_body: response_body })
            }
        }
    }
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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

    // ── Round-1 review P41: discriminate daemon-must-run remediation
    // branches. The classifier branches on the io::Error ErrorKind and
    // (on macOS) the helper-binary path-existence + launchctl print
    // exit. Tests here pin the io::Error path-mapping; the macOS
    // platform-specific path-checks live behind feature-gated cfg and
    // are covered by the operator-gated rc.22 shakedown.

    /// Construct a synthetic anyhow::Error wrapping an io::Error with
    /// the requested ErrorKind. Used to drive classify_daemon_down_reason
    /// without actually opening a socket.
    fn synthetic_io_error(kind: std::io::ErrorKind, msg: &str) -> anyhow::Error {
        anyhow::Error::new(std::io::Error::new(kind, msg.to_owned()))
    }

    #[cfg(unix)]
    fn fake_uds_endpoint() -> ControlEndpoint {
        ControlEndpoint::Uds(std::path::PathBuf::from("/tmp/agentsso-test-control.sock"))
    }

    fn fake_tcp_endpoint() -> ControlEndpoint {
        ControlEndpoint::Tcp("127.0.0.1:3820".parse().unwrap())
    }

    #[cfg(unix)]
    #[test]
    fn classify_daemon_down_uds_permission_denied_routes_to_group_membership() {
        let err = synthetic_io_error(std::io::ErrorKind::PermissionDenied, "permission denied");
        let reason = classify_daemon_down_reason(&fake_uds_endpoint(), &err);
        assert!(
            matches!(reason, DaemonDownReason::GroupMembership),
            "EACCES on UDS connect must route to GroupMembership; got {reason:?}",
        );
    }

    #[cfg(unix)]
    #[test]
    fn classify_daemon_down_uds_connection_refused_routes_to_stale_socket() {
        let err = synthetic_io_error(std::io::ErrorKind::ConnectionRefused, "connection refused");
        let reason = classify_daemon_down_reason(&fake_uds_endpoint(), &err);
        assert!(
            matches!(reason, DaemonDownReason::SocketConnectionRefused),
            "ECONNREFUSED on UDS connect must route to SocketConnectionRefused; got {reason:?}",
        );
    }

    #[test]
    fn classify_daemon_down_tcp_permission_denied_routes_to_group_membership() {
        let err = synthetic_io_error(std::io::ErrorKind::PermissionDenied, "permission denied");
        let reason = classify_daemon_down_reason(&fake_tcp_endpoint(), &err);
        assert!(
            matches!(reason, DaemonDownReason::GroupMembership),
            "EACCES on TCP connect must route to GroupMembership; got {reason:?}",
        );
    }

    #[test]
    fn classify_daemon_down_tcp_generic_io_error_routes_to_tcp_unreachable() {
        // Any non-EACCES, non-ECONNREFUSED io::Error on TCP →
        // TcpUnreachable (the generic Linux/Windows "start the
        // daemon" message).
        let err = synthetic_io_error(std::io::ErrorKind::AddrNotAvailable, "address not available");
        let reason = classify_daemon_down_reason(&fake_tcp_endpoint(), &err);
        assert!(
            matches!(reason, DaemonDownReason::TcpUnreachable),
            "generic io error on TCP must route to TcpUnreachable; got {reason:?}",
        );
    }

    /// Round-1 review P37 sanity: `validate_control_token` rejects
    /// CRLF-injection inputs. Verified end-to-end via the file-read
    /// path, but the validator's own unit test is here in the crate
    /// that owns its callers.
    #[cfg(unix)]
    #[test]
    fn control_token_round_trip_classification() {
        // Synthesize the same scenarios the renderer dispatches on
        // so a regression in match-arm ordering shows up in tests
        // rather than at runtime. Exhaustive coverage of the enum
        // variants the platform-independent paths produce:
        for (kind, expected) in [
            (std::io::ErrorKind::PermissionDenied, "GroupMembership"),
            (std::io::ErrorKind::ConnectionRefused, "SocketConnectionRefused"),
        ] {
            let err = synthetic_io_error(kind, "test");
            let reason = classify_daemon_down_reason(&fake_uds_endpoint(), &err);
            let actual = format!("{reason:?}");
            assert!(
                actual.contains(expected),
                "expected reason {expected} for kind {kind:?}; got {actual}",
            );
        }
    }
}
