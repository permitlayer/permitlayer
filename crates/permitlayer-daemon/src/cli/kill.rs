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
#[cfg(unix)]
use std::path::Path;
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
    //
    // Story 7.27: dispatch over the platform-appropriate transport.
    // macOS goes through the UDS at
    // `/var/run/permitlayer/control.sock`; Linux + Windows stay on
    // the rc.21 loopback TCP path (their redesigns are 7.18/7.19).
    let endpoint = resolve_control_endpoint(&config);
    let token = read_control_token(&home);
    let response_body =
        match http_post_empty_json_via(&endpoint, "/v1/control/kill", token.as_deref()).await {
            Ok(body) => body,
            Err(e) => {
                tracing::debug!(error = %e, endpoint = %endpoint, "kill request failed");
                // Round-3 review fix (R3-C5-P2): pass the underlying
                // error so the operator-facing block can classify
                // ENOENT/EACCES/ECONNREFUSED and emit a targeted
                // remediation hint (instead of one-size-fits-all
                // "agentsso start" which misleads for the common
                // "not in permitlayer-clients group" case).
                eprint!(
                    "{}",
                    error_block_daemon_unreachable_endpoint_classified("kill", &endpoint, Some(&e),)
                );
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
/// Story 7.27 Round-2 review fix (P2): endpoint-aware variant.
/// Pre-fix, `error_block_daemon_unreachable` took only a
/// `SocketAddr` and hardcoded `unix:/var/run/permitlayer/control.sock`
/// in the macOS hint — wrong under `AGENTSSO_PATHS__HOME=<tmpdir>`
/// (test/dev mode) AND misleading on macOS where the request never
/// touched TCP. This variant uses the actual resolved
/// `ControlEndpoint::Display` impl so the message reflects reality.
pub(crate) fn error_block_daemon_unreachable_endpoint(
    verb: &str,
    endpoint: &ControlEndpoint,
) -> String {
    error_block_daemon_unreachable_endpoint_classified(verb, endpoint, None)
}

/// Round-3 review fix (R3-C5-P2): error-kind-aware variant. The
/// Round-2 `error_block_daemon_unreachable_endpoint` rendered the
/// same generic "agentsso start" remediation regardless of cause:
/// the most common 7.27 misconfig — operator not in
/// `permitlayer-clients` group — produces `EACCES` on UDS connect
/// and gets a misleading "agentsso start" hint that just deepens
/// confusion. This variant accepts an optional underlying
/// `anyhow::Error`, extracts its `io::ErrorKind` when downcastable,
/// and renders one of three branches:
///   - `NotFound`  → daemon not running ("agentsso start")
///   - `PermissionDenied` → not in clients group
///   - `ConnectionRefused` → stale socket inode
///   - anything else → generic fallback (same shape as Round-2).
///
/// Call sites that have the underlying error in scope pass it
/// through; others can call the wrapper above with `None`.
pub(crate) fn error_block_daemon_unreachable_endpoint_classified(
    verb: &str,
    endpoint: &ControlEndpoint,
    cause: Option<&anyhow::Error>,
) -> String {
    let kind = cause.and_then(|e| {
        // Walk the source chain looking for an io::Error.
        let mut cur: Option<&dyn std::error::Error> = Some(e.as_ref());
        while let Some(err) = cur {
            if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
                return Some(io_err.kind());
            }
            cur = err.source();
        }
        None
    });
    let (msg, remediation): (String, &str) = match kind {
        Some(std::io::ErrorKind::NotFound) => (
            format!("daemon not running (during {verb}): no socket at {endpoint}"),
            "start the daemon: `sudo agentsso setup` (one-time install/upgrade/repair), OR `agentsso start` for ad-hoc dev use",
        ),
        Some(std::io::ErrorKind::PermissionDenied) => (
            format!("permission denied reaching daemon at {endpoint} (during {verb})"),
            "add yourself to the permitlayer-clients group: `sudo dseditgroup -o edit -a $USER -t user permitlayer-clients` then log out and back in (group membership is cached per-session)",
        ),
        Some(std::io::ErrorKind::ConnectionRefused) => (
            format!(
                "daemon socket exists at {endpoint} but no listener (during {verb}); likely a stale socket from a force-killed daemon"
            ),
            "remove the stale socket and re-start: `sudo rm /var/run/permitlayer/control.sock && sudo launchctl kickstart -k system/dev.permitlayer.daemon`",
        ),
        _ => (
            format!("cannot reach daemon at {endpoint} (during {verb})"),
            "agentsso start  (or, if the daemon is running under a different user, set AGENTSSO_HTTP__BIND_ADDR=<addr> to match; on macOS the UDS path is fixed)",
        ),
    };
    error_block("daemon_unreachable", &msg, remediation, None)
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
        if validate_control_token(trimmed) {
            return Some(trimmed.to_owned());
        }
    }
    let path = home.join("control.token");
    // Bug 2c: don't silently swallow the read failure. An unreadable
    // token (e.g. macOS `0o600 root:permitlayer-clients` before the
    // cross-user reconcile, or the group-missing fallback) otherwise
    // sends the request unauthenticated with no breadcrumb explaining
    // WHY the operator gets `forbidden_missing_control_token`. `debug`
    // (not `warn`) because the same path is normal on Linux where the
    // env var is the intended channel and the file legitimately lives
    // in a per-user home.
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(
                error = %e,
                path = %path.display(),
                "could not read control.token; sending request unauthenticated \
                 (daemon will reject with forbidden_missing_control_token)"
            );
            return None;
        }
    };
    let trimmed = content.trim();
    if validate_control_token(trimmed) { Some(trimmed.to_owned()) } else { None }
}

/// Operator-facing remediation for a control-plane auth failure
/// (`forbidden_*`). Shared by every `/v1/control/*` CLI consumer so
/// the message is identical across `agent`, `connectors list`, and
/// `policy list`.
pub(crate) const CONTROL_AUTH_REMEDIATION: &str = "set AGENTSSO_CONTROL_TOKEN or run as the daemon-owner user. \
     If you cannot read the daemon's <home>/control.token, ask the operator \
     to share it explicitly (e.g. via `sudo cat`).";

/// Detect the *nested* control-plane auth error shape and return its
/// `(code, message)`.
///
/// The daemon serializes `/v1/control/*` auth rejections via
/// `ControlErrorBody` as
/// `{"status":"error","error":{"code":"forbidden_*","message":...}}`
/// — note it ALSO carries a top-level `"status":"error"`, so a caller
/// that checks the flat shape first (`parsed["status"] == "error"` then
/// `parsed["code"]`) consumes this body, finds no top-level `code`, and
/// reports a useless `*.unknown_error`. Callers must run THIS detector
/// *before* the flat-shape branch and surface the real cause.
///
/// Returns `None` (caller falls through to flat/protocol handling) for:
/// flat agent/connector/policy errors (no nested `error` object), the
/// flat `ConnectorsPayloadTooLargeBody` shape, success bodies, and any
/// nested `error.code` that is not a `forbidden_*` auth code. Only the
/// three `forbidden_*` codes (`forbidden_not_loopback`,
/// `forbidden_missing_control_token`, `forbidden_invalid_control_token`)
/// match — all warrant `CONTROL_AUTH_REMEDIATION`.
pub(crate) fn nested_control_plane_auth_error(
    parsed: &serde_json::Value,
) -> Option<(String, String)> {
    let err = parsed.get("error")?;
    let code = err.get("code")?.as_str()?;
    if !code.starts_with("forbidden_") {
        return None;
    }
    let message = err.get("message").and_then(|m| m.as_str()).unwrap_or("(no message)").to_owned();
    Some((code.to_owned(), message))
}

/// Round-1 review P37: validate a control-token string is safe to
/// embed in an HTTP header. Defends against CRLF-injection
/// (request-smuggling) if the token file ever gets corrupted or
/// tampered with — the token is daemon-minted random bytes today
/// but the file is on the operator's filesystem.
///
/// Acceptance criteria: non-empty, ASCII-only, no CR/LF/NUL, no
/// other control characters. Standard tokens are URL-safe base64
/// which trivially satisfies this; anything else is rejected.
fn validate_control_token(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.bytes().all(|b| {
        // Printable ASCII (0x21..=0x7E) plus we reject space too
        // since tokens shouldn't have whitespace. Excludes CR (0x0D),
        // LF (0x0A), NUL (0x00), and every other control char.
        (0x21..=0x7E).contains(&b)
    })
}

/// Control-plane endpoint — either loopback TCP (rc.21 model, still
/// in use on Linux + Windows in rc.22) or a Unix domain socket (rc.22
/// macOS model per Story 7.27 split-listener AC #2).
///
/// The CLI helpers below dispatch over the right transport based on
/// which variant is present. [`resolve_control_endpoint`] picks the
/// correct one for the current platform + config + override env.
#[derive(Debug, Clone)]
pub(crate) enum ControlEndpoint {
    /// Loopback TCP — rc.21 fallback / Linux + Windows path.
    #[allow(dead_code)] // unreachable on macOS where every CLI uses UDS
    Tcp(SocketAddr),
    /// Unix domain socket — rc.22 macOS path. `cfg(unix)`-gated because
    /// `tokio::net::UnixStream` (used by the dispatch helpers below)
    /// is not available on Windows; the variant has no constructor on
    /// non-Unix anyway since `resolve_control_endpoint` only produces
    /// `Uds(_)` under `target_os = "macos"`.
    #[cfg(unix)]
    #[allow(dead_code)] // unreachable on non-macOS where every CLI uses TCP
    Uds(PathBuf),
}

impl std::fmt::Display for ControlEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(addr) => write!(f, "{addr}"),
            #[cfg(unix)]
            Self::Uds(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

/// Resolve the control-plane endpoint to use for `/v1/control/*` CLI
/// dispatch. On macOS, prefers the UDS path at
/// `permitlayer_core::paths::control_socket_path()` (honoring the
/// `AGENTSSO_PATHS__HOME` test override). On Linux + Windows, returns
/// the configured loopback TCP `bind_addr` (rc.21 model preserved).
///
/// Story 7.27 AC #2: control routes move to UDS on macOS; MCP routes
/// stay on TCP (loopback :3820) for OpenClaw / Claude Desktop /
/// Cursor compatibility.
pub(crate) fn resolve_control_endpoint(config: &DaemonConfig) -> ControlEndpoint {
    #[cfg(target_os = "macos")]
    {
        let _ = config;
        let home_override = permitlayer_core::paths::home_override();
        let sock = permitlayer_core::paths::control_socket_path(home_override.as_deref());
        ControlEndpoint::Uds(sock)
    }
    #[cfg(not(target_os = "macos"))]
    {
        ControlEndpoint::Tcp(config.http.bind_addr)
    }
}

/// Minimal HTTP/1.1 POST `{}` → read full response → extract JSON body.
///
/// Uses raw TCP matching the pattern in `cli/status.rs`. Handles both
/// `Content-Length`-delimited and connection-closed bodies. We control
/// both endpoints (the request and the daemon) and the body is always
/// `Content-Length` small JSON, so we don't implement chunked decoding.
///
/// Story 7.27: superseded by [`http_post_empty_json_via`] which
/// dispatches over UDS on macOS. Retained as a TCP-only convenience
/// wrapper for callers that explicitly need TCP (none in production
/// after 7.27, but the helper stays to keep the test fixtures
/// compiling).
#[allow(dead_code)]
pub(crate) async fn http_post_empty_json(
    addr: SocketAddr,
    path: &str,
    control_token: Option<&str>,
) -> Result<String> {
    http_post_json(addr, path, "{}", control_token).await
}

/// Endpoint-aware POST `{}`. Dispatches over UDS or TCP based on
/// `endpoint`. Story 7.27.
pub(crate) async fn http_post_empty_json_via(
    endpoint: &ControlEndpoint,
    path: &str,
    control_token: Option<&str>,
) -> Result<String> {
    http_post_json_via(endpoint, path, "{}", control_token).await
}

/// Endpoint-aware POST with a caller-supplied JSON body.
pub(crate) async fn http_post_json_via(
    endpoint: &ControlEndpoint,
    path: &str,
    body: &str,
    control_token: Option<&str>,
) -> Result<String> {
    match endpoint {
        ControlEndpoint::Tcp(addr) => http_post_json(*addr, path, body, control_token).await,
        #[cfg(unix)]
        ControlEndpoint::Uds(sock_path) => tokio::time::timeout(
            HTTP_DEADLINE,
            http_post_json_inner_uds(sock_path, path, body, control_token),
        )
        .await
        .with_context(|| format!("HTTP POST {path} (UDS) timed out after {HTTP_DEADLINE:?}"))?,
    }
}

/// Endpoint-aware GET.
pub(crate) async fn http_get_via(
    endpoint: &ControlEndpoint,
    path: &str,
    control_token: Option<&str>,
) -> Result<String> {
    match endpoint {
        ControlEndpoint::Tcp(addr) => http_get(*addr, path, control_token).await,
        #[cfg(unix)]
        ControlEndpoint::Uds(sock_path) => {
            tokio::time::timeout(HTTP_DEADLINE, http_get_inner_uds(sock_path, path, control_token))
                .await
                .with_context(|| {
                    format!("HTTP GET {path} (UDS) timed out after {HTTP_DEADLINE:?}")
                })?
        }
    }
}

/// Endpoint-aware GET that returns the status code alongside the body.
pub(crate) async fn http_get_with_status_via(
    endpoint: &ControlEndpoint,
    path: &str,
    control_token: Option<&str>,
) -> Result<(u16, String)> {
    match endpoint {
        ControlEndpoint::Tcp(addr) => http_get_with_status(*addr, path, control_token).await,
        #[cfg(unix)]
        ControlEndpoint::Uds(sock_path) => tokio::time::timeout(
            HTTP_DEADLINE,
            http_get_with_status_inner_uds(sock_path, path, control_token),
        )
        .await
        .with_context(|| format!("HTTP GET {path} (UDS) timed out after {HTTP_DEADLINE:?}"))?,
    }
}

/// Endpoint-aware POST with a JSON body that returns the status code
/// alongside the body. Story 7.30: the credentials/policy endpoints
/// return structured 4xx/5xx error bodies that callers need to parse
/// alongside the HTTP status — a plain success-or-error result loses
/// information.
pub(crate) async fn http_post_json_with_status_via(
    endpoint: &ControlEndpoint,
    path: &str,
    body: &str,
    control_token: Option<&str>,
) -> Result<(u16, String)> {
    match endpoint {
        ControlEndpoint::Tcp(addr) => {
            http_post_json_with_status(*addr, path, body, control_token).await
        }
        #[cfg(unix)]
        ControlEndpoint::Uds(sock_path) => tokio::time::timeout(
            HTTP_DEADLINE,
            http_post_json_with_status_inner_uds(sock_path, path, body, control_token),
        )
        .await
        .with_context(|| format!("HTTP POST {path} (UDS) timed out after {HTTP_DEADLINE:?}"))?,
    }
}

/// Round-1 review P42: same as `http_post_json_with_status_via` but
/// takes `body: &zeroize::Zeroizing<String>` and writes the request
/// header + body as TWO separate socket writes so the plaintext body
/// is never concatenated into a third heap String alongside the
/// header. Caller's `Zeroizing<String>` scrubs on drop; this helper
/// adds no fresh plaintext heap copies between caller and kernel
/// buffer.
///
/// Used for the credentials-seal POST (plaintext OAuth tokens in the
/// body). All other POSTs use `http_post_json_with_status_via`.
pub(crate) async fn http_post_zeroizing_with_status_via(
    endpoint: &ControlEndpoint,
    path: &str,
    body: &zeroize::Zeroizing<String>,
    control_token: Option<&str>,
) -> Result<(u16, String)> {
    match endpoint {
        ControlEndpoint::Tcp(addr) => tokio::time::timeout(
            HTTP_DEADLINE,
            http_post_zeroizing_with_status_inner_tcp(*addr, path, body, control_token),
        )
        .await
        .with_context(|| format!("HTTP POST {path} (TCP) timed out after {HTTP_DEADLINE:?}"))?,
        #[cfg(unix)]
        ControlEndpoint::Uds(sock_path) => tokio::time::timeout(
            HTTP_DEADLINE,
            http_post_zeroizing_with_status_inner_uds(sock_path, path, body, control_token),
        )
        .await
        .with_context(|| format!("HTTP POST {path} (UDS) timed out after {HTTP_DEADLINE:?}"))?,
    }
}

/// Round-1 review P42 TCP variant: two-write split (header, then
/// plaintext body) so the body never lives in a `format!`-allocated
/// String alongside the header.
async fn http_post_zeroizing_with_status_inner_tcp(
    addr: SocketAddr,
    path: &str,
    body: &zeroize::Zeroizing<String>,
    control_token: Option<&str>,
) -> Result<(u16, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut stream =
        TcpStream::connect(addr).await.with_context(|| format!("connect to {addr}"))?;

    let auth_header =
        control_token.map(|t| format!("X-Agentsso-Control: {t}\r\n")).unwrap_or_default();
    let header = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\n{auth_header}Connection: close\r\n\r\n",
        len = body.len(),
    );
    stream.write_all(header.as_bytes()).await.context("write HTTP request header")?;
    // Body write: borrows the zeroizing String directly. The bytes
    // never get copied into a separate allocation; the kernel
    // socket buffer is the next-hop copy.
    stream.write_all(body.as_bytes()).await.context("write HTTP request body")?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.context("read HTTP response")?;
    let response_str = String::from_utf8_lossy(&response).into_owned();
    let status = parse_status_code(&response_str)
        .ok_or_else(|| anyhow::anyhow!("malformed HTTP response status line"))?;
    let body =
        extract_body(&response_str).ok_or_else(|| anyhow::anyhow!("malformed HTTP response"))?;
    Ok((status, body))
}

/// Round-1 review P42 UDS variant: same two-write split, over a Unix
/// domain socket.
#[cfg(unix)]
async fn http_post_zeroizing_with_status_inner_uds(
    sock_path: &Path,
    path: &str,
    body: &zeroize::Zeroizing<String>,
    control_token: Option<&str>,
) -> Result<(u16, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let mut stream = UnixStream::connect(sock_path)
        .await
        .with_context(|| format!("connect to {}", sock_path.display()))?;

    let auth_header =
        control_token.map(|t| format!("X-Agentsso-Control: {t}\r\n")).unwrap_or_default();
    let header = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {len}\r\n{auth_header}Connection: close\r\n\r\n",
        len = body.len(),
    );
    stream.write_all(header.as_bytes()).await.context("write HTTP request header")?;
    stream.write_all(body.as_bytes()).await.context("write HTTP request body")?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.context("read HTTP response")?;
    let response_str = String::from_utf8_lossy(&response).into_owned();
    let status = parse_status_code(&response_str)
        .ok_or_else(|| anyhow::anyhow!("malformed HTTP response status line"))?;
    let body =
        extract_body(&response_str).ok_or_else(|| anyhow::anyhow!("malformed HTTP response"))?;
    Ok((status, body))
}

#[cfg(unix)]
async fn http_post_json_inner_uds(
    sock_path: &Path,
    path: &str,
    body: &str,
    control_token: Option<&str>,
) -> Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let mut stream = UnixStream::connect(sock_path)
        .await
        .with_context(|| format!("connect to {}", sock_path.display()))?;

    let auth_header =
        control_token.map(|t| format!("X-Agentsso-Control: {t}\r\n")).unwrap_or_default();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{auth_header}Connection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.context("write HTTP request")?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.context("read HTTP response")?;
    let response = String::from_utf8_lossy(&response).into_owned();

    extract_body(&response).ok_or_else(|| anyhow::anyhow!("malformed HTTP response"))
}

#[cfg(unix)]
async fn http_get_inner_uds(
    sock_path: &Path,
    path: &str,
    control_token: Option<&str>,
) -> Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let mut stream = UnixStream::connect(sock_path)
        .await
        .with_context(|| format!("connect to {}", sock_path.display()))?;

    let auth_header =
        control_token.map(|t| format!("X-Agentsso-Control: {t}\r\n")).unwrap_or_default();
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{auth_header}Connection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.context("write HTTP request")?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.context("read HTTP response")?;
    let response = String::from_utf8_lossy(&response).into_owned();

    extract_body(&response).ok_or_else(|| anyhow::anyhow!("malformed HTTP response"))
}

#[cfg(unix)]
async fn http_get_with_status_inner_uds(
    sock_path: &Path,
    path: &str,
    control_token: Option<&str>,
) -> Result<(u16, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let mut stream = UnixStream::connect(sock_path)
        .await
        .with_context(|| format!("connect to {}", sock_path.display()))?;

    let auth_header =
        control_token.map(|t| format!("X-Agentsso-Control: {t}\r\n")).unwrap_or_default();
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{auth_header}Connection: close\r\n\r\n");
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

/// Story 7.30: same as [`http_post_json`] but ALSO returns the HTTP
/// status code so callers can distinguish 2xx success bodies from
/// 4xx/5xx structured error bodies emitted by `agent_error_response`.
pub(crate) async fn http_post_json_with_status(
    addr: SocketAddr,
    path: &str,
    body: &str,
    control_token: Option<&str>,
) -> Result<(u16, String)> {
    tokio::time::timeout(
        HTTP_DEADLINE,
        http_post_json_with_status_inner(addr, path, body, control_token),
    )
    .await
    .with_context(|| format!("HTTP POST {path} timed out after {HTTP_DEADLINE:?}"))?
}

async fn http_post_json_with_status_inner(
    addr: SocketAddr,
    path: &str,
    body: &str,
    control_token: Option<&str>,
) -> Result<(u16, String)> {
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
    let response_str = String::from_utf8_lossy(&response).into_owned();

    let status = parse_status_code(&response_str)
        .ok_or_else(|| anyhow::anyhow!("malformed HTTP response status line"))?;
    let body =
        extract_body(&response_str).ok_or_else(|| anyhow::anyhow!("malformed HTTP response"))?;
    Ok((status, body))
}

#[cfg(unix)]
async fn http_post_json_with_status_inner_uds(
    sock_path: &Path,
    path: &str,
    body: &str,
    control_token: Option<&str>,
) -> Result<(u16, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let mut stream = UnixStream::connect(sock_path)
        .await
        .with_context(|| format!("connect to {}", sock_path.display()))?;

    let auth_header =
        control_token.map(|t| format!("X-Agentsso-Control: {t}\r\n")).unwrap_or_default();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{auth_header}Connection: close\r\n\r\n{body}",
        body.len()
    );
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
    DaemonConfig::load(&CliOverrides::default())
        .map(|c| c.paths.home)
        .unwrap_or_else(|_| permitlayer_core::paths::daemon_state_dir(None))
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
    fn error_block_daemon_unreachable_endpoint_tcp_shape() {
        let addr: SocketAddr = "127.0.0.1:3820".parse().unwrap();
        let endpoint = ControlEndpoint::Tcp(addr);
        let out = error_block_daemon_unreachable_endpoint("kill", &endpoint);
        assert!(out.contains("daemon_unreachable"), "out: {out}");
        assert!(out.contains("127.0.0.1:3820"), "out: {out}");
        assert!(out.contains("during kill"), "out: {out}");
        assert!(out.contains("agentsso start"), "out: {out}");
        // Cross-user remediation hint must be present so a caller talking
        // to a daemon owned by a different user has a path forward.
        assert!(out.contains("AGENTSSO_HTTP__BIND_ADDR"), "out: {out}");
    }

    #[cfg(unix)]
    #[test]
    fn error_block_daemon_unreachable_endpoint_uds_shape() {
        // Story 7.27 Round-2 review fix (P2): UDS endpoint Display
        // is now reflected in the user-facing message, replacing
        // the pre-fix hardcoded `unix:/var/run/permitlayer/
        // control.sock` literal that ignored `AGENTSSO_PATHS__HOME`.
        let endpoint = ControlEndpoint::Uds("/tmp/test/control.sock".into());
        let out = error_block_daemon_unreachable_endpoint("kill", &endpoint);
        assert!(out.contains("daemon_unreachable"), "out: {out}");
        assert!(
            out.contains("/tmp/test/control.sock"),
            "UDS path must appear in operator-facing message; out: {out}"
        );
        assert!(out.contains("during kill"), "out: {out}");
        assert!(out.contains("agentsso start"), "out: {out}");
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

    // --- nested_control_plane_auth_error (Bug 2) -------------------

    #[test]
    fn nested_auth_error_detects_missing_token() {
        // Exact `ControlErrorBody` shape from server/control.rs.
        let v: serde_json::Value = serde_json::from_str(
            r#"{"status":"error","error":{"code":"forbidden_missing_control_token","message":"X-Agentsso-Control header is required on /v1/control/* endpoints"}}"#,
        )
        .unwrap();
        let (code, message) = nested_control_plane_auth_error(&v).unwrap();
        assert_eq!(code, "forbidden_missing_control_token");
        assert!(message.contains("X-Agentsso-Control"), "message: {message}");
    }

    #[test]
    fn nested_auth_error_detects_invalid_token() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"status":"error","error":{"code":"forbidden_invalid_control_token","message":"X-Agentsso-Control token did not match"}}"#,
        )
        .unwrap();
        let (code, _) = nested_control_plane_auth_error(&v).unwrap();
        assert_eq!(code, "forbidden_invalid_control_token");
    }

    #[test]
    fn nested_auth_error_ignores_flat_agent_error() {
        // Flat shape: no nested `error` object → fall through to flat handling.
        let v: serde_json::Value = serde_json::from_str(
            r#"{"status":"error","code":"agent.duplicate_name","message":"already registered","request_id":"r1"}"#,
        )
        .unwrap();
        assert!(nested_control_plane_auth_error(&v).is_none());
    }

    #[test]
    fn nested_auth_error_ignores_flat_payload_too_large() {
        // `ConnectorsPayloadTooLargeBody` is FLAT (no nested `error`).
        let v: serde_json::Value = serde_json::from_str(
            r#"{"status":"error","code":"connectors.payload_too_large","message":"too big","size_bytes":2000000,"limit_bytes":1048576}"#,
        )
        .unwrap();
        assert!(nested_control_plane_auth_error(&v).is_none());
    }

    #[test]
    fn nested_auth_error_ignores_success() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"status":"ok","name":"angie"}"#).unwrap();
        assert!(nested_control_plane_auth_error(&v).is_none());
    }

    #[test]
    fn nested_auth_error_ignores_non_forbidden_nested() {
        // A nested `error` whose code is not `forbidden_*` falls through.
        let v: serde_json::Value = serde_json::from_str(
            r#"{"status":"error","error":{"code":"some.other_error","message":"x"}}"#,
        )
        .unwrap();
        assert!(nested_control_plane_auth_error(&v).is_none());
    }
}
