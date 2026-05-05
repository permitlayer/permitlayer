//! `agentsso kill` — activate the daemon's kill switch.
//!
//! Talks to the running daemon via a loopback HTTP POST to
//! `/v1/control/kill`, reads the activation summary, and renders the
//! `KillBanner` to stdout. Exits 3 when the daemon is not running.
//!
//! # NFR6
//!
//! The NFR6 budget is <2s end-to-end wall-clock (CLI invocation → banner
//! render). Budget breakdown (rough, cold cache):
//!
//! - CLI startup: 100-300ms
//! - HTTP connect + write + read: ~5ms on loopback
//! - `KillSwitch::activate`: <1µs
//! - Banner render: ~5-10ms
//!
//! Total expected: ~150-350ms typical. The integration test in
//! `tests/kill_resume_e2e.rs` measures this and asserts `<2000ms`.
//!
//! # Control plane
//!
//! See `docs/adrs/0002-kill-switch-control-plane.md` for the HTTP vs
//! signal vs Unix-socket decision. TL;DR: loopback-only HTTP POST to the
//! main daemon port on a separate axum router carved out of
//! `KillSwitchLayer` so resume still works when killed.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::config::{CliOverrides, DaemonConfig};
use crate::design::kill_banner::{ActivationSummaryView, BannerInputs, render_kill_banner};
use crate::design::render::error_block;
use crate::design::terminal::{ColorSupport, terminal_width};
use crate::design::theme::Theme;

/// HTTP round-trip deadline for the kill POST. Leaves plenty of headroom
/// inside the NFR6 2000ms budget (CLI startup + banner render is well
/// under 500ms on cold cache).
pub(crate) const HTTP_DEADLINE: Duration = Duration::from_millis(1500);

/// Arguments for `agentsso kill`. Empty today — future revisions may add
/// `--reason` to map onto `KillReason` variants beyond `UserInitiated`.
#[derive(clap::Args)]
pub struct KillArgs {}

pub async fn run(_args: KillArgs) -> Result<()> {
    let start = Instant::now();

    let config = load_daemon_config_or_default_with_warn("kill");
    let home = config.paths.home.clone();

    // No PID-file pre-check. Plan B (operator-token auth) replaces
    // the implicit owner-check with a real bearer-style token on
    // `/v1/control/*`. The HTTP path's `error_block_daemon_unreachable`
    // handles the genuine "no daemon" case below.

    // POST /v1/control/kill with the operator token from <home>/control.token
    // (or from AGENTSSO_CONTROL_TOKEN env for cross-user invocation).
    let bind_addr = config.http.bind_addr;
    let token = read_control_token(&home);
    let response_body =
        match http_post_empty_json(bind_addr, "/v1/control/kill", token.as_deref()).await {
            Ok(body) => body,
            Err(e) => {
                tracing::debug!(error = %e, addr = %bind_addr, "kill request failed");
                eprint!("{}", error_block_daemon_unreachable("kill", bind_addr));
                std::process::exit(3);
            }
        };

    // 3. Parse the response.
    let parsed: KillResponseView = match serde_json::from_str(&response_body) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, body = %response_body, "unexpected kill response");
            eprint!("{}", error_block_protocol_error());
            std::process::exit(3);
        }
    };

    // 4. Render the banner. A parse failure is treated as a protocol
    // error (exit 3 + structured error_block), not as an anyhow bubble-up,
    // so the CLI contract in AC #6 holds even when the daemon's schema
    // drifts.
    let activated_at = match chrono::DateTime::parse_from_rfc3339(&parsed.activation.activated_at) {
        Ok(dt) => dt.with_timezone(&chrono::Utc),
        Err(e) => {
            tracing::debug!(
                error = %e,
                activated_at = %parsed.activation.activated_at,
                "daemon returned non-RFC3339 activated_at",
            );
            eprint!("{}", error_block_protocol_error());
            std::process::exit(3);
        }
    };
    let activation_view = ActivationSummaryView {
        tokens_invalidated: parsed.activation.tokens_invalidated,
        activated_at,
        was_already_active: parsed.activation.was_already_active,
        reason: parsed.activation.reason,
    };

    let inputs = BannerInputs {
        activation: &activation_view,
        audit_written: false,
        in_flight_cancelled: None,
        elapsed: start.elapsed(),
        terminal_width: terminal_width(),
    };

    let theme = Theme::load(&home);
    let support = ColorSupport::detect();
    print!("{}", render_kill_banner(&inputs, &theme, support));

    Ok(())
}

// --------------------------------------------------------------------------
// Wire types (daemon-side → CLI deserialize).
//
// We deserialize into plain structs here rather than re-use
// `crate::server::control::KillResponse` because that type is
// `pub(crate) + Serialize`, not `Deserialize`. Adding `Deserialize` to the
// daemon-side type would couple two code paths that don't share data
// ownership. Keeping the CLI deserialize type local means the
// server→client schema contract is the JSON wire format, not a shared
// Rust type.
// --------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct KillResponseView {
    activation: ActivationSummaryWire,
    #[serde(default)]
    #[allow(dead_code)] // we may surface daemon_version in future diagnostics
    daemon_version: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct ActivationSummaryWire {
    tokens_invalidated: usize,
    /// RFC 3339 UTC string from the daemon.
    activated_at: String,
    was_already_active: bool,
    /// Kebab-case kill-reason label from the daemon. Added in Story 3.2
    /// AC #2. Defaults to `"unknown"` when the daemon omits the field (a
    /// pre-3.2 daemon running against a 3.2+ CLI).
    #[serde(default = "default_reason_label")]
    reason: String,
}

fn default_reason_label() -> String {
    "unknown".to_owned()
}

// --------------------------------------------------------------------------
// Shared helpers (HTTP POST + error blocks).
// --------------------------------------------------------------------------

/// Error text for the "daemon_not_running" condition, shaped via
/// `design::render::error_block`.
///
/// **Currently unused in production** — Plan B replaced the PID-file
/// pre-checks that emitted this with the new `forbidden_*` control-
/// token errors. Retained behind `#[allow(dead_code)]` because
/// (a) the unit test below is still meaningful and (b) future CLI
/// commands that legitimately need a same-user PID gate (e.g.,
/// `agentsso stop`, which is owner-scoped by definition) can reuse
/// this without re-introducing the formatter.
#[allow(dead_code)]
pub(crate) fn error_block_daemon_not_running(verb: &str) -> String {
    error_block("daemon_not_running", &format!("no daemon to {verb}"), "agentsso start", None)
}

/// Error text for the "daemon_unreachable" condition (connect/read/write
/// failed or deadline exceeded). The message is deliberately error-agnostic
/// — the underlying cause (ECONNREFUSED, timeout, DNS, etc.) goes to
/// `tracing::debug!` at the call site so operators with `--log-level debug`
/// can diagnose further. The user-facing block stays structured and
/// consistent regardless of the real error.
pub(crate) fn error_block_daemon_unreachable(verb: &str, addr: SocketAddr) -> String {
    // Remediation must be cross-user-safe. `agentsso status` is itself
    // PID-gated against the calling user's home, so a cross-user caller
    // (e.g., `angie` talking to a daemon running as `austinlowry`)
    // would see "daemon not running" from `status` even though the
    // daemon is up. Point at `start` (the genuine no-daemon fix) AND
    // the bind-addr override (the cross-user fix).
    error_block(
        "daemon_unreachable",
        &format!("cannot reach daemon on {addr} (during {verb})"),
        "agentsso start  (or, if the daemon is running under a different user, set AGENTSSO_HTTP__BIND_ADDR=<addr> to match)",
        None,
    )
}

/// Error text for the "daemon_protocol_error" condition (response body is
/// not JSON, or does not match the expected schema).
pub(crate) fn error_block_protocol_error() -> String {
    error_block("daemon_protocol_error", "unexpected response from daemon", "agentsso status", None)
}

/// Read the operator-authentication token for `/v1/control/*` calls.
///
/// Resolution order:
/// 1. `AGENTSSO_CONTROL_TOKEN` env var (cross-user case — operator
///    sets this when calling the daemon owned by another user).
/// 2. `<home>/control.token` (same-user case — daemon owner's CLI
///    reads it from the same home that minted it).
///
/// Returns `None` when neither source has a value. The CLI passes
/// the result through to the HTTP helpers; the daemon will reject
/// with `forbidden_missing_control_token` if no token is sent.
pub(crate) fn read_control_token(home: &std::path::Path) -> Option<String> {
    if let Ok(env) = std::env::var("AGENTSSO_CONTROL_TOKEN") {
        let trimmed = env.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_owned());
        }
    }
    let path = home.join("control.token");
    let content = std::fs::read_to_string(&path).ok()?;
    let trimmed = content.trim();
    if trimmed.is_empty() { None } else { Some(trimmed.to_owned()) }
}

/// Minimal HTTP/1.1 POST `{}` → read full response → extract JSON body.
///
/// Uses raw TCP matching the pattern in `cli/status.rs`. Handles both
/// `Content-Length`-delimited and connection-closed bodies. We control
/// both endpoints (the request and the daemon) and the body is always
/// `Content-Length` small JSON, so we don't implement chunked decoding.
pub(crate) async fn http_post_empty_json(
    addr: SocketAddr,
    path: &str,
    control_token: Option<&str>,
) -> Result<String> {
    http_post_json(addr, path, "{}", control_token).await
}

/// Minimal HTTP/1.1 POST with a caller-supplied JSON body. Used by
/// `cli/agent.rs::register_agent` and `cli/agent.rs::remove_agent`
/// (Story 4.4).
pub(crate) async fn http_post_json(
    addr: SocketAddr,
    path: &str,
    body: &str,
    control_token: Option<&str>,
) -> Result<String> {
    tokio::time::timeout(HTTP_DEADLINE, http_post_json_inner(addr, path, body, control_token))
        .await
        .with_context(|| format!("HTTP POST {path} timed out after {HTTP_DEADLINE:?}"))?
}

async fn http_post_json_inner(
    addr: SocketAddr,
    path: &str,
    body: &str,
    control_token: Option<&str>,
) -> Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut stream =
        TcpStream::connect(addr).await.with_context(|| format!("connect to {addr}"))?;

    let auth_header =
        control_token.map(|t| format!("X-Agentsso-Control: {t}\r\n")).unwrap_or_default();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{auth_header}Connection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.context("write HTTP request")?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.context("read HTTP response")?;
    let response = String::from_utf8_lossy(&response).into_owned();

    extract_body(&response).ok_or_else(|| anyhow::anyhow!("malformed HTTP response"))
}

/// Minimal HTTP/1.1 GET → read full response → extract JSON body.
///
/// Same contract as `http_post_empty_json` but for GETs. Used by
/// `cli/resume.rs` (state probe) and `cli/setup.rs` (kill-state preflight).
pub(crate) async fn http_get(
    addr: SocketAddr,
    path: &str,
    control_token: Option<&str>,
) -> Result<String> {
    tokio::time::timeout(HTTP_DEADLINE, http_get_inner(addr, path, control_token))
        .await
        .with_context(|| format!("HTTP GET {path} timed out after {HTTP_DEADLINE:?}"))?
}

async fn http_get_inner(
    addr: SocketAddr,
    path: &str,
    control_token: Option<&str>,
) -> Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut stream =
        TcpStream::connect(addr).await.with_context(|| format!("connect to {addr}"))?;

    let auth_header =
        control_token.map(|t| format!("X-Agentsso-Control: {t}\r\n")).unwrap_or_default();
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{auth_header}Connection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.context("write HTTP request")?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.context("read HTTP response")?;
    let response = String::from_utf8_lossy(&response).into_owned();

    extract_body(&response).ok_or_else(|| anyhow::anyhow!("malformed HTTP response"))
}

/// Same as [`http_get`] but ALSO returns the HTTP status code so the
/// caller can distinguish 2xx body from a 4xx/5xx error body. Story
/// 5.5 / M4 review patch: `agentsso status --connections` needs this
/// to surface the daemon's `forbidden_not_loopback` block instead of
/// trying to deserialize the error body as a `ConnectionsResponse`.
pub(crate) async fn http_get_with_status(
    addr: SocketAddr,
    path: &str,
    control_token: Option<&str>,
) -> Result<(u16, String)> {
    tokio::time::timeout(HTTP_DEADLINE, http_get_with_status_inner(addr, path, control_token))
        .await
        .with_context(|| format!("HTTP GET {path} timed out after {HTTP_DEADLINE:?}"))?
}

async fn http_get_with_status_inner(
    addr: SocketAddr,
    path: &str,
    control_token: Option<&str>,
) -> Result<(u16, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut stream =
        TcpStream::connect(addr).await.with_context(|| format!("connect to {addr}"))?;

    let auth_header =
        control_token.map(|t| format!("X-Agentsso-Control: {t}\r\n")).unwrap_or_default();
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{auth_header}Connection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.context("write HTTP request")?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.context("read HTTP response")?;
    let response_str = String::from_utf8_lossy(&response).into_owned();

    let status = parse_status_code(&response_str)
        .ok_or_else(|| anyhow::anyhow!("malformed HTTP response status line"))?;
    let body =
        extract_body(&response_str).ok_or_else(|| anyhow::anyhow!("malformed HTTP response"))?;
    Ok((status, body))
}

/// Parse the numeric status code out of an HTTP/1.1 response string
/// of the form `"HTTP/1.1 <code> <reason>\r\n..."`. Returns `None`
/// if the first line is malformed.
fn parse_status_code(response: &str) -> Option<u16> {
    let first_line = response.lines().next()?;
    first_line.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok())
}

/// Extract the JSON body from an HTTP/1.1 response string.
///
/// Splits on the first `\r\n\r\n` and returns whatever comes after. Does
/// not decode chunked encoding — the daemon always uses `Content-Length`
/// for the control endpoints since the JSON bodies are small (<1KB).
fn extract_body(response: &str) -> Option<String> {
    let idx = response.find("\r\n\r\n")?;
    let body = &response[idx + 4..];
    Some(body.trim().to_owned())
}

/// Resolve the agentsso home directory from config (defaults → TOML → env).
///
/// Used by the CLI commands that need to locate the daemon's PID file and
/// vault. Mirrors the helper in `cli/stop.rs` and `cli/reload.rs`.
#[allow(dead_code)] // kept for parity with other CLI modules; resume.rs has its own copy
pub(crate) fn resolve_home() -> PathBuf {
    DaemonConfig::load(&CliOverrides::default()).map(|c| c.paths.home).unwrap_or_else(|_| {
        dirs::home_dir().map(|h| h.join(".agentsso")).unwrap_or_else(|| PathBuf::from(".agentsso"))
    })
}

/// Load `DaemonConfig` with the default overrides, falling back to the
/// built-in default on parse error.
///
/// The silent fallback via `.unwrap_or_default()` hides malformed config
/// files and env parse failures, which then surfaces as a misleading
/// "daemon unreachable" error when the CLI connects to the default port
/// instead of the user's configured one. This helper logs a
/// `tracing::warn!` on the `Err` branch so the config-broken path is
/// auditable in the daemon log (and visible at `--log-level warn`).
///
/// `verb` is the CLI command name ("kill", "resume", "setup") used in the
/// warn message to make the log line easier to grep.
pub(crate) fn load_daemon_config_or_default_with_warn(verb: &str) -> DaemonConfig {
    match DaemonConfig::load(&CliOverrides::default()) {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::warn!(
                target: "cli",
                command = verb,
                error = %e,
                "DaemonConfig::load failed; falling back to defaults — \
                 check ~/.agentsso/config/daemon.toml and AGENTSSO_* env vars",
            );
            DaemonConfig::default()
        }
    }
}

// --------------------------------------------------------------------------
// Tests — unit tests for pure helpers. End-to-end flow is covered by
// `tests/kill_resume_e2e.rs` (subprocess integration).
// --------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn extract_body_simple_response() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 9\r\n\r\n{\"ok\":1}";
        assert_eq!(extract_body(raw).unwrap(), "{\"ok\":1}");
    }

    #[test]
    fn extract_body_no_headers_separator() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n{}";
        // Missing `\r\n\r\n` → None
        assert!(extract_body(raw).is_none());
    }

    #[test]
    fn extract_body_trims_trailing_whitespace() {
        let raw = "HTTP/1.1 200 OK\r\n\r\n{\"ok\":1}\r\n";
        assert_eq!(extract_body(raw).unwrap(), "{\"ok\":1}");
    }

    #[test]
    fn error_block_daemon_not_running_shape() {
        let out = error_block_daemon_not_running("kill");
        assert!(out.contains("daemon_not_running"), "out: {out}");
        assert!(out.contains("no daemon to kill"), "out: {out}");
        assert!(out.contains("run:  agentsso start"), "out: {out}");
    }

    #[test]
    fn error_block_daemon_unreachable_shape() {
        let addr: SocketAddr = "127.0.0.1:3820".parse().unwrap();
        let out = error_block_daemon_unreachable("kill", addr);
        assert!(out.contains("daemon_unreachable"), "out: {out}");
        assert!(out.contains("127.0.0.1:3820"), "out: {out}");
        assert!(out.contains("during kill"), "out: {out}");
        assert!(out.contains("agentsso start"), "out: {out}");
        // Cross-user remediation hint must be present so a caller talking
        // to a daemon owned by a different user has a path forward.
        assert!(out.contains("AGENTSSO_HTTP__BIND_ADDR"), "out: {out}");
    }

    #[test]
    fn error_block_protocol_error_shape() {
        let out = error_block_protocol_error();
        assert!(out.contains("daemon_protocol_error"), "out: {out}");
        assert!(out.contains("unexpected response"), "out: {out}");
    }

    #[test]
    fn deserialize_kill_response_round_trip() {
        let json = r#"{
            "activation": {
                "tokens_invalidated": 3,
                "activated_at": "2026-04-10T12:34:56.789Z",
                "was_already_active": false
            },
            "daemon_version": "0.1.0"
        }"#;
        let parsed: KillResponseView = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.activation.tokens_invalidated, 3);
        assert_eq!(parsed.activation.activated_at, "2026-04-10T12:34:56.789Z");
        assert!(!parsed.activation.was_already_active);
    }
}
