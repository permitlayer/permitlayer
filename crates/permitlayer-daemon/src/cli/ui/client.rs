//! The single place the TUI touches HTTP. Typed control-plane fetchers
//! over [`crate::cli::kill::http_get_with_status_via`].
//!
//! Every fetch returns a [`FetchOutcome`] so the caller never has to
//! interpret a raw `(u16, String)` or an `anyhow::Error`: connection
//! failures, `forbidden_*`, 5xx, and parse failures each map to a
//! distinct variant the view layer renders verbatim.
//!
//! ## Token handling (security-critical)
//!
//! The control token is read *per fetch* via
//! [`crate::cli::kill::read_control_token`] and dropped at the end of the
//! request — it is never hoisted into long-lived `App` state, never
//! rendered, and never crosses a `tracing`/`format!`-to-log boundary.
//! A TUI is long-lived; a retained plaintext token would sit in process
//! memory for the whole session and land in any core dump.

use crate::cli::kill::{self, ControlEndpoint};

use super::types::{AgentSummary, ListAgentsBody, ListPoliciesBody, PolicyDetailBody, StateBody};

/// The home + endpoint a fetch needs. Cheap to clone; carries no token
/// (the token is re-read per fetch from `home`).
#[derive(Debug, Clone)]
pub struct ControlClient {
    pub home: std::path::PathBuf,
    pub endpoint: ControlEndpoint,
}

/// Outcome of one control-plane GET, already classified for the view
/// layer. `T` is the parsed success body.
#[derive(Debug)]
pub enum FetchOutcome<T> {
    /// 2xx and the body parsed.
    Ok(T),
    /// `connect()` failed — daemon not running / socket missing.
    Unreachable,
    /// Daemon answered but the exchange failed (timeout / IO / malformed
    /// response) — running but misbehaving.
    BadResponse { summary: String },
    /// 403 `forbidden_*` — token missing/unreadable/invalid. Carries the
    /// daemon's `code` (e.g. `forbidden_missing_control_token`).
    Forbidden { code: String },
    /// Any other non-2xx. `code` is the parsed error envelope's `code`
    /// field when present, else a synthetic `http_{status}`.
    HttpError { status: u16, code: String },
    /// 2xx but the body did not parse as the expected shape.
    Parse { summary: String },
}

impl<T> FetchOutcome<T> {
    /// Re-tag a non-`Ok` outcome to a different success type. Used when a
    /// fetch parses into an envelope but hands the caller the inner value
    /// (e.g. `fetch_agents` → `ListAgentsBody.agents`). Panics on `Ok`,
    /// which callers must map themselves.
    fn map_non_ok<U>(self) -> FetchOutcome<U> {
        match self {
            FetchOutcome::Ok(_) => unreachable!("map_non_ok called on Ok"),
            FetchOutcome::Unreachable => FetchOutcome::Unreachable,
            FetchOutcome::BadResponse { summary } => FetchOutcome::BadResponse { summary },
            FetchOutcome::Forbidden { code } => FetchOutcome::Forbidden { code },
            FetchOutcome::HttpError { status, code } => FetchOutcome::HttpError { status, code },
            FetchOutcome::Parse { summary } => FetchOutcome::Parse { summary },
        }
    }
}

impl RawOutcome {
    /// Map a non-`Ok` raw outcome into the matching `FetchOutcome`. Panics
    /// if called on `RawOutcome::Ok` (callers handle the success body
    /// themselves, since JSON vs TOML parsing differs). Centralizes the
    /// non-Ok mapping so `get_json` and `fetch_policy_detail` don't repeat
    /// it.
    fn into_non_ok<T>(self) -> FetchOutcome<T> {
        match self {
            RawOutcome::Ok(_) => unreachable!("into_non_ok called on Ok"),
            RawOutcome::Unreachable => FetchOutcome::Unreachable,
            RawOutcome::BadResponse { summary } => FetchOutcome::BadResponse { summary },
            RawOutcome::Forbidden { code } => FetchOutcome::Forbidden { code },
            RawOutcome::HttpError { status, code } => FetchOutcome::HttpError { status, code },
        }
    }
}

impl ControlClient {
    /// Read the daemon liveness / kill-switch snapshot.
    pub async fn fetch_state(&self) -> FetchOutcome<StateBody> {
        self.get_json("/v1/control/state").await
    }

    /// Read the agent list.
    ///
    /// The daemon returns the `{"status":"ok","agents":[...]}` envelope,
    /// so we parse `ListAgentsBody` and hand back the inner `Vec` —
    /// callers (and the `Fetched::Agents` message) keep working with a
    /// plain `Vec<AgentSummary>`.
    pub async fn fetch_agents(&self) -> FetchOutcome<Vec<AgentSummary>> {
        match self.get_json::<ListAgentsBody>("/v1/control/agent/list").await {
            FetchOutcome::Ok(body) => FetchOutcome::Ok(body.agents),
            other => other.map_non_ok(),
        }
    }

    /// Read the policy list (names + origin + inlined scopes).
    pub async fn fetch_policies(&self) -> FetchOutcome<ListPoliciesBody> {
        self.get_json("/v1/control/policies").await
    }

    /// Read one policy's resolved TOML body.
    pub async fn fetch_policy_detail(&self, name: &str) -> FetchOutcome<PolicyDetailBody> {
        // `name` is an in-memory policy name from the already-fetched
        // list; it contains no path separators or spaces, so it is safe
        // to interpolate into the request path here.
        let path = format!("/v1/control/policies/{name}");
        match self.get_raw(&path).await {
            RawOutcome::Ok(body) => match toml::from_str::<PolicyDetailBody>(&body) {
                Ok(parsed) => FetchOutcome::Ok(parsed),
                Err(e) => FetchOutcome::Parse { summary: parse_summary(&e.to_string()) },
            },
            other => other.into_non_ok(),
        }
    }

    /// Generic JSON GET → parse `T`.
    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> FetchOutcome<T> {
        match self.get_raw(path).await {
            RawOutcome::Ok(body) => match serde_json::from_str::<T>(&body) {
                Ok(parsed) => FetchOutcome::Ok(parsed),
                Err(e) => FetchOutcome::Parse { summary: parse_summary(&e.to_string()) },
            },
            other => other.into_non_ok(),
        }
    }

    /// One GET, classified into transport/status buckets but with the
    /// 2xx body still raw (callers parse JSON vs TOML themselves).
    async fn get_raw(&self, path: &str) -> RawOutcome {
        // Per-fetch token read; the `Option<String>` is dropped when this
        // function returns. Never retained, never logged.
        let token = kill::read_control_token(&self.home);
        let result = kill::http_get_with_status_via(&self.endpoint, path, token.as_deref()).await;

        match result {
            // Distinguish "daemon not running" (connect refused / socket
            // missing → `agentsso start`) from "daemon running but
            // misbehaving" (timeout, mid-request IO error, malformed
            // response). Collapsing both to "unreachable" would tell the
            // operator to start a daemon that is already up.
            Err(e) => {
                if is_connect_failure(&e) {
                    RawOutcome::Unreachable
                } else {
                    RawOutcome::BadResponse { summary: parse_summary(&format!("{e:#}")) }
                }
            }
            Ok((status, body)) if (200..300).contains(&status) => RawOutcome::Ok(body),
            Ok((403, body)) => {
                let code = parse_error_code(&body).unwrap_or_else(|| "forbidden".to_owned());
                RawOutcome::Forbidden { code }
            }
            Ok((status, body)) => {
                let code = parse_error_code(&body).unwrap_or_else(|| format!("http_{status}"));
                RawOutcome::HttpError { status, code }
            }
        }
    }
}

/// Transport-classified GET result with a raw 2xx body.
enum RawOutcome {
    Ok(String),
    /// `connect()` failed — daemon not running / socket missing.
    Unreachable,
    /// Daemon answered the socket but the exchange failed (timeout,
    /// mid-request IO error, or a malformed/unparseable HTTP response).
    /// Distinct from `Unreachable`: the remediation is "check the daemon",
    /// not "start the daemon".
    BadResponse {
        summary: String,
    },
    Forbidden {
        code: String,
    },
    HttpError {
        status: u16,
        code: String,
    },
}

/// Whether an error from the kill.rs HTTP helpers is a connection
/// failure (daemon not running) as opposed to a post-connect failure
/// (timeout / IO / malformed response). Walks the error's source chain
/// for an `io::Error` whose kind indicates the peer could not be reached.
fn is_connect_failure(err: &anyhow::Error) -> bool {
    use std::io::ErrorKind;
    for cause in err.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return matches!(
                io.kind(),
                ErrorKind::ConnectionRefused
                    | ErrorKind::NotFound
                    | ErrorKind::AddrNotAvailable
                    | ErrorKind::ConnectionReset
                    | ErrorKind::PermissionDenied
            );
        }
    }
    false
}

/// Pull a `code` out of an error body. Handles both the nested
/// `forbidden_*` envelope (via the shared kill.rs detector) and the flat
/// `{"code": ...}` shape used by agent/policy errors.
fn parse_error_code(body: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(body).ok()?;
    if let Some((code, _msg)) = kill::nested_control_plane_auth_error(&parsed) {
        return Some(code);
    }
    parsed.get("code").and_then(|c| c.as_str()).map(|s| s.to_owned())
}

/// Truncate a parser error to a single short line for the footer.
///
/// Truncation is at a UTF-8 char boundary, not a raw byte index: parser
/// error messages can echo non-ASCII input (a policy value, a garbled
/// daemon response), and slicing `&s[..120]` mid-codepoint would panic.
fn parse_summary(raw: &str) -> String {
    let first_line = raw.lines().next().unwrap_or(raw);
    const MAX: usize = 120;
    if first_line.len() > MAX {
        // Largest char boundary <= MAX. (Avoids the unstable
        // `str::floor_char_boundary`.)
        let end = (0..=MAX).rev().find(|&i| first_line.is_char_boundary(i)).unwrap_or(0);
        format!("{}…", &first_line[..end])
    } else {
        first_line.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_error_code_nested_forbidden() {
        let body = r#"{"status":"error","error":{"code":"forbidden_missing_control_token","message":"no token"}}"#;
        assert_eq!(parse_error_code(body).as_deref(), Some("forbidden_missing_control_token"));
    }

    #[test]
    fn parse_error_code_flat() {
        let body = r#"{"status":"error","code":"policy.not_found","message":"nope"}"#;
        assert_eq!(parse_error_code(body).as_deref(), Some("policy.not_found"));
    }

    #[test]
    fn parse_error_code_absent() {
        assert_eq!(parse_error_code("not json"), None);
        assert_eq!(parse_error_code("{}"), None);
    }

    #[test]
    fn parse_summary_truncates() {
        let long = "x".repeat(200);
        let s = parse_summary(&long);
        assert!(s.ends_with('…'));
        assert!(s.len() <= 124);
    }

    #[test]
    fn parse_summary_first_line_only() {
        assert_eq!(parse_summary("line one\nline two"), "line one");
    }
}
