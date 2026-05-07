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
//!   "headers": { "Authorization": "Bearer <token>" }
//! }
//! ```
//!
//! The wrapping `mcpServers` key + the entry's name (e.g.,
//! `permitlayer-gmail`) are the operator's responsibility — the
//! emitted JSON is just the value at that nested entry.

use std::io::{self, Write as _};
use std::net::SocketAddr;
use std::path::Path;

/// Build the JSON snippet for an MCP client to connect to permitlayer
/// for `service`, authenticating with `bearer_token`.
///
/// Pure function — no I/O. The returned `serde_json::Value` is
/// shaped to drop directly into an MCP-client config under
/// `mcpServers.permitlayer-<service>`.
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

    // Always write to stdout in a delimited block.
    let mut stdout = io::stdout().lock();
    writeln!(stdout)?;
    writeln!(
        stdout,
        "### copy this into your MCP client config (e.g. ~/.openclaw/openclaw.json) ###"
    )?;
    writeln!(stdout, "### entry name suggestion: \"permitlayer-{service}\" ###")?;
    if redact_stdout {
        writeln!(
            stdout,
            "### NOTE: bearer redacted because stdout is piped — real token in --mcp-config-out ###"
        )?;
    }
    writeln!(stdout)?;
    writeln!(stdout, "{stdout_body}")?;
    writeln!(stdout)?;
    writeln!(stdout, "### end ###")?;
    writeln!(stdout)?;
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
        let abs_open = start + open + 1; // position of opening quote
        // Find the next unescaped closing quote.
        let after_open = abs_open + 1; // skip the opening quote
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
fn write_snippet_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("snippet path has no parent dir: {}", path.display()),
        )
    })?;
    if !parent.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("parent dir does not exist: {}", parent.display()),
        ));
    }

    // Story 7.13 round-1 P7: refuse to overwrite a symlink. `tempfile::persist`'s
    // `rename(2)` would replace the symlink with a regular file (the link target
    // file remains untouched), silently breaking admin workflows that symlink
    // shared snippet paths to git-tracked locations. If the path doesn't exist
    // yet we proceed normally; only existing-symlink is rejected.
    if let Ok(md) = std::fs::symlink_metadata(path)
        && md.file_type().is_symlink()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("--mcp-config-out path is a symlink (refusing to follow): {}", path.display()),
        ));
    }

    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o644);
        std::fs::set_permissions(tmp.path(), perms)?;
    }

    tmp.persist(path).map_err(|e| e.error)?;
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
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
