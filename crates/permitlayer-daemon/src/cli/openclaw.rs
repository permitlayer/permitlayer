//! OpenClaw MCP-config snippet emission — Story 7.13.
//!
//! `agentsso connect <service>` ends by emitting an OpenClaw MCP-
//! client-config snippet so the operator can configure their MCP
//! client (OpenClaw, Claude Desktop, Cursor, etc.) to route requests
//! through permitlayer.
//!
//! # Admin → user handoff
//!
//! On a typical PermitLayer install the **machine admin** runs
//! `agentsso connect` (sealing credentials, editing policies, binding
//! agents) and the **end user** runs the MCP client. These are
//! distinct principals on the same machine; the admin's home is not
//! readable by the end user, and vice versa.
//!
//! Connect therefore does **not** attempt to auto-discover or write
//! the end user's `~/.openclaw/openclaw.json`. Instead Step 7
//! emits the snippet via this module — printed to stdout (so the
//! admin can copy it from their terminal or capture it in a script)
//! and optionally written to a file at an admin-specified path
//! (`--mcp-config-out`) for cross-user handoff via shared filesystem.
//!
//! The end user runs `openclaw mcp set` themselves with the snippet
//! they received.
//!
//! # Snippet shape
//!
//! Matches the rc.13 OpenClaw MCP-server config shape:
//!
//! ```json
//! {
//!   "transport": "streamable-http",
//!   "url": "http://127.0.0.1:3820/mcp/<service>",
//!   "headers": {
//!     "Authorization": "Bearer <token>"
//!   }
//! }
//! ```
//!
//! The wrapping `mcpServers` key + the entry's name (e.g.,
//! `permitlayer-gmail`) are the operator's responsibility — the
//! emitted JSON is just the value at that nested entry.
//!
//! ## No client scope header on the `/mcp` path
//!
//! The snippet carries NO `x-agentsso-scope` header. On the MCP tool-
//! dispatch path (`/mcp/<service>`) the daemon derives each tool's
//! required scope server-side (e.g. `messages.send` → `gmail.send`) and
//! evaluates that against the agent's policy; it never reads a client
//! scope header. A single static header could only ever name one scope,
//! so it cannot express a read-write agent (which spans
//! readonly/send/compose/modify) and was silently ignored anyway.
//! Emitting it implied — falsely — that one scope governs every call,
//! which led operators to hand-build multiple per-scope MCP entries.
//!
//! (The REST `/v1/tools/<service>` path is different: it DOES require an
//! `x-agentsso-scope` header per request. That path is not what this
//! snippet targets.)

use std::io::{self, Write as _};
use std::net::SocketAddr;
use std::path::Path;

/// Build the JSON snippet for an MCP client to connect to permitlayer
/// for `service`, authenticating with `bearer_token`.
///
/// Pure function — no I/O. The returned `serde_json::Value` is
/// shaped to drop directly into an MCP-client config under
/// `mcpServers.permitlayer-<service>`.
///
/// The snippet carries no `x-agentsso-scope` header — MCP tool dispatch
/// derives the required scope per-tool server-side (see module docs).
pub(crate) fn build_snippet(
    service: &str,
    bearer_token: &str,
    addr: SocketAddr,
) -> serde_json::Value {
    serde_json::json!({
        "transport": "streamable-http",
        "url": format!("http://{}/mcp/{}", addr, service),
        "headers": {
            "Authorization": format!("Bearer {}", bearer_token),
        },
    })
}

/// Print the snippet to stdout (always) AND optionally write it to a
/// file at the admin-specified path.
///
/// Stdout output is wrapped in a delimiter block so the operator can
/// visually identify the copy-paste boundary. The file output is
/// pure JSON (no delimiters) so it's directly consumable by
/// `openclaw mcp set`, `jq`, or scripted tooling.
///
/// # Cross-user handoff
///
/// The file path is written with mode `0o644` (intentionally world-
/// readable). The admin/user split (see module-level docs) means
/// the end user — running OpenClaw — is a distinct UID from the
/// admin running `agentsso connect`. A `0o600` snippet would be
/// readable only by the admin and useless to the end user. The
/// snippet only contains the bearer token, which is no more
/// sensitive at-rest at `--mcp-config-out` than it will be at-rest
/// in the end user's `~/.openclaw/openclaw.json`. The admin chooses
/// the path; if they need stricter perms they can chmod after.
pub(crate) fn emit_snippet(
    snippet: &serde_json::Value,
    mcp_config_out: Option<&Path>,
    service: &str,
) -> io::Result<()> {
    // Stable pretty-print so admins reading the snippet on stdout
    // see one field per line.
    let body_with_bearer = serde_json::to_string_pretty(snippet)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Round-1 P13: when stdout is piped (e.g. `agentsso connect ... | tee log`),
    // the bearer header lands unredacted in the log file. Redact the
    // stdout copy when stdout is NOT a terminal AND `mcp_config_out`
    // was supplied (the operator has another way to retrieve the real
    // bearer). When `mcp_config_out` is absent, we leave the bearer in
    // stdout because that's the operator's only retrieval path —
    // they must accept the log-leak risk explicitly. Always-redact-on-
    // piped would silently break the no-config-out flow.
    let stdout_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let redact_stdout = !stdout_is_tty && mcp_config_out.is_some();
    let stdout_body =
        if redact_stdout { redact_bearer(&body_with_bearer) } else { body_with_bearer.clone() };

    // Stream split (clig.dev): the JSON snippet is machine payload → it
    // goes to STDOUT as bare, fence-free JSON so `agentsso connect … |
    // jq` and `… > config.json` Just Work. The human-facing labels
    // ("copy this into …", entry-name hint, redaction note) are chrome →
    // STDERR. Pre-fix this was a single `### … ###`-fenced block on
    // stdout, which (a) was unreadable and (b) made the stdout copy
    // un-parseable as JSON.
    //
    // The labels are only useful to a human at a terminal; when stdout is
    // piped the consumer wants pure JSON and the labels would be noise,
    // but stderr is the right channel either way (it never pollutes the
    // piped stdout), so we always emit them to stderr.
    let mut stderr = io::stderr().lock();
    writeln!(stderr)?;
    writeln!(
        stderr,
        "  Paste into your MCP client (e.g. ~/.openclaw/openclaw.json) as \"permitlayer-{service}\":"
    )?;
    if redact_stdout {
        writeln!(
            stderr,
            "  (bearer redacted on piped stdout \u{2014} the real token is in --mcp-config-out)"
        )?;
    }
    writeln!(stderr)?;
    drop(stderr);

    // The payload: bare JSON on stdout, nothing else.
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{stdout_body}")?;
    drop(stdout);

    // Optional file write — always uses the un-redacted body (the file
    // is the canonical handoff path; permissions are admin-controlled
    // via the path they chose, not by us).
    if let Some(path) = mcp_config_out {
        write_snippet_atomic(path, body_with_bearer.as_bytes()).map_err(|e| {
            io::Error::new(e.kind(), format!("failed to write snippet to {}: {e}", path.display()))
        })?;
    }

    Ok(())
}

/// Replace the value of `Authorization: Bearer <X>` with a placeholder.
/// Round-1 P13 helper.
fn redact_bearer(body: &str) -> String {
    // The snippet has shape `"Authorization": "Bearer <token>"`. Match
    // the JSON-encoded form and replace conservatively. We do NOT
    // substring-match `agt_v2_` to avoid a future-token-format gotcha.
    // serde_json serialization is stable for this struct; the regex-
    // free string replace is sufficient.
    if let Some(start) = body.find("\"Authorization\":")
        && let Some(open) = body[start..].find("\"Bearer ")
    {
        // `open` is the offset of the opening quote of the value
        // (`"Bearer …"`) relative to `start`. `abs_open` is its absolute
        // index — the opening quote itself, NOT one past it.
        //
        // Bug fix (CLI output consistency pass): the previous code set
        // `abs_open = start + open + 1` and then copied `body[..abs_open]`
        // (which INCLUDED the opening `"`) before pushing a fresh
        // `"Bearer …"`, producing a doubled quote (`""Bearer …`) that
        // made the redacted stdout body INVALID JSON. The old unit test
        // only substring-checked the placeholder, so it never caught it.
        // Now `abs_open` points AT the opening quote so the prefix copy
        // stops just before it and the replacement re-emits exactly one.
        let abs_open = start + open; // position of the opening quote
        // Find the value's closing quote (skip the opening quote).
        let after_open = abs_open + 1;
        if let Some(close_rel) = body[after_open..].find('"') {
            let abs_close = after_open + close_rel;
            let mut out = String::with_capacity(body.len());
            out.push_str(&body[..abs_open]);
            out.push_str("\"Bearer <REDACTED_FOR_PIPED_STDOUT>\"");
            out.push_str(&body[abs_close + 1..]);
            return out;
        }
    }
    body.to_owned()
}

/// Atomic same-directory tempfile + rename, mode 0o644 on Unix.
///
/// 0o644 (not 0o600) because the admin/user split means the end user
/// running OpenClaw is a different UID from the admin running this
/// command (see module-level docs).
///
/// Story 7.17 Task 1.4 factored the underlying mechanism into
/// [`crate::cli::atomic_write::write_atomic_with_mode`] so
/// `agent register --token-out` (mode 0o600) shares the same
/// tempfile-then-rename plus parent-must-exist plus refuse-existing-symlink
/// contract.
fn write_snippet_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    crate::cli::atomic_write::write_atomic_with_mode(path, bytes, 0o644)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn snippet_has_streamable_http_transport() {
        let addr: SocketAddr = "127.0.0.1:3820".parse().unwrap();
        let snippet = build_snippet("gmail", "agt_v2_test_xxx", addr);
        assert_eq!(snippet["transport"], "streamable-http");
    }

    #[test]
    fn snippet_url_includes_service_path() {
        let addr: SocketAddr = "127.0.0.1:3820".parse().unwrap();
        let snippet = build_snippet("calendar", "agt_v2_test_xxx", addr);
        assert_eq!(snippet["url"], "http://127.0.0.1:3820/mcp/calendar");
    }

    #[test]
    fn snippet_authorization_header_uses_bearer_prefix() {
        let addr: SocketAddr = "127.0.0.1:3820".parse().unwrap();
        let snippet = build_snippet("drive", "agt_v2_alice_secret", addr);
        assert_eq!(snippet["headers"]["Authorization"], "Bearer agt_v2_alice_secret");
    }

    #[test]
    fn snippet_omits_scope_header_on_mcp_path() {
        // RC2: the `/mcp` path derives each tool's scope server-side and
        // NEVER reads a client scope header. A single static
        // `x-agentsso-scope` header can't express a read-write agent
        // (readonly/send/compose/modify) and was silently ignored — emitting
        // it falsely implied one scope governs every call, which pushed
        // operators into hand-building per-scope MCP entries.
        //
        // This INVERTS the old Story 10.8 "header must never be absent"
        // guard: the correct structural defense is that we never hand-build
        // the MCP entry and never imply a client scope. Do NOT re-add the
        // header here.
        let addr: SocketAddr = "127.0.0.1:3820".parse().unwrap();
        for bearer in ["agt_v2_alice_secret", "<PASTE_YOUR_EXISTING_BEARER_TOKEN>"] {
            let snippet = build_snippet("gmail", bearer, addr);
            assert!(
                snippet["headers"].get("x-agentsso-scope").is_none(),
                "the MCP snippet must NOT carry a client scope header (bearer={bearer})"
            );
        }
    }

    #[test]
    fn snippet_round_trips_through_serde_json() {
        let addr: SocketAddr = "127.0.0.1:3820".parse().unwrap();
        let snippet = build_snippet("gmail", "tok", addr);
        let s = serde_json::to_string(&snippet).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["transport"], "streamable-http");
    }

    #[test]
    fn redact_bearer_replaces_token_with_placeholder() {
        let body = r#"{
  "transport": "streamable-http",
  "url": "http://127.0.0.1:3820/mcp/gmail",
  "headers": {
    "Authorization": "Bearer agt_v2_alice_supersecret"
  }
}"#;
        let redacted = redact_bearer(body);
        assert!(!redacted.contains("agt_v2_alice_supersecret"), "{redacted}");
        assert!(redacted.contains("<REDACTED_FOR_PIPED_STDOUT>"), "{redacted}");
        // Other fields preserved.
        assert!(redacted.contains("streamable-http"));
        assert!(redacted.contains("http://127.0.0.1:3820/mcp/gmail"));
    }

    #[test]
    fn redacted_snippet_body_is_still_valid_json() {
        // Stream-split contract (CLI output consistency pass): the
        // snippet body emitted on stdout — redacted or not — must remain
        // bare, parseable JSON now that the `### … ###` fences and the
        // human labels moved to stderr. A consumer doing
        // `agentsso connect … | jq` or `… > config.json` relies on this.
        let addr: SocketAddr = "127.0.0.1:3820".parse().unwrap();
        let snippet = build_snippet("gmail", "agt_v2_alice_supersecret", addr);
        let pretty = serde_json::to_string_pretty(&snippet).unwrap();
        let redacted = redact_bearer(&pretty);
        // Both the un-redacted and the redacted stdout copies parse.
        let parsed_plain: serde_json::Value = serde_json::from_str(&pretty).unwrap();
        let parsed_redacted: serde_json::Value = serde_json::from_str(&redacted).unwrap();
        assert_eq!(parsed_plain["transport"], "streamable-http");
        assert_eq!(parsed_redacted["transport"], "streamable-http");
        assert_eq!(
            parsed_redacted["headers"]["Authorization"],
            "Bearer <REDACTED_FOR_PIPED_STDOUT>"
        );
    }

    #[test]
    fn redact_bearer_no_op_when_no_authorization_field() {
        let body = r#"{ "foo": "bar" }"#;
        assert_eq!(redact_bearer(body), body);
    }

    #[test]
    fn write_atomic_creates_file_with_expected_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("snippet.json");
        let payload = b"{\"ok\":true}";
        write_snippet_atomic(&path, payload).unwrap();
        let read = std::fs::read(&path).unwrap();
        assert_eq!(read, payload);
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_uses_0o644_perms() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("snippet.json");
        write_snippet_atomic(&path, b"{}").unwrap();
        let md = std::fs::metadata(&path).unwrap();
        let mode = md.permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "snippet file should be 0o644 for cross-user readability");
    }

    #[test]
    fn write_atomic_errors_when_parent_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does-not-exist").join("snippet.json");
        let err = write_snippet_atomic(&path, b"{}").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
