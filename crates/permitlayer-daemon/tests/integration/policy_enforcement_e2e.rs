//! Integration test: PolicyLayer middleware enforces policy evaluation
//! from inside the post-Story-4.4 chain.
//!
//! Story 4.3 originally added this test against the single-policy
//! shortcut heuristic in `resolve_policy_name`. Story 4.4 deleted that
//! heuristic and moved bearer-token → policy resolution into the new
//! agent identity registry, which means an unauthenticated request now
//! 401s at AuthLayer BEFORE reaching PolicyLayer. This test now pins
//! the post-4.4 behavior:
//!
//! - Without an `Authorization: Bearer <token>` header, every request
//!   to a service path returns 401 `auth.missing_token`.
//! - Health/control endpoints continue to bypass auth.
//!
//! End-to-end coverage of the register → auth → policy lifecycle with
//! real bearer tokens lives in `agent_registry_e2e.rs` (Story 4.4).

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::common::agentsso_bin;

/// Deterministic test master key so the daemon's `try_build_agent_runtime`
/// short-circuits past the real OS keychain lookup. Without this, a dev
/// machine's `cargo test --workspace` run triggers a macOS `SecurityAgent`
/// dialog asking for the login keychain password — documented in the
/// Story 4.4 code-review Review Findings (2026-04-13). Keep in sync with
/// `agent_registry_e2e.rs::TEST_MASTER_KEY_HEX`.
const TEST_MASTER_KEY_HEX: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Story 7.7: zero-port + marker-read.
fn start_daemon(home: &std::path::Path) -> (std::process::Child, u16) {
    let mut child = Command::new(agentsso_bin())
        .arg("start")
        .arg("--bind-addr")
        .arg("127.0.0.1:0")
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .env("AGENTSSO_TEST_MASTER_KEY_HEX", TEST_MASTER_KEY_HEX)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start daemon");
    let port = crate::common::wait_for_bound_addr(&mut child, Duration::from_secs(10)).port();
    (child, port)
}

fn wait_for_health(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(mut stream) = std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(100),
        ) {
            let _ = stream.write_all(
                format!(
                    "GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            );
            let mut buf = Vec::new();
            let _ = stream.read_to_end(&mut buf);
            let response = String::from_utf8_lossy(&buf);
            if response.contains("\"healthy\"") {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Send an HTTP GET with optional headers and return (status_code, body).
fn http_get(port: u16, path: &str, extra_headers: &[(&str, &str)]) -> (u16, String) {
    let mut stream = std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_secs(2),
    )
    .expect("failed to connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let mut headers =
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n");
    for (key, val) in extra_headers {
        headers.push_str(&format!("{key}: {val}\r\n"));
    }
    headers.push_str("\r\n");

    stream.write_all(headers.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let raw = String::from_utf8_lossy(&buf).to_string();
    let status = raw.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
    let body = raw.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    (status, body)
}

/// Restrictive policy: allows gmail.readonly on any resource.
const RESTRICTIVE_POLICY: &str = r#"
[[policies]]
name = "gmail-readonly"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
"#;

#[test]
fn unauthenticated_service_request_returns_401_missing_token() {
    // Post-Story-4.4: AuthLayer runs BEFORE PolicyLayer and rejects
    // any request to a service path without a valid `Authorization:
    // Bearer <token>` header. PolicyLayer never sees the request, so
    // the deny path is `auth.missing_token`, not `policy.denied`.
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();

    let policies_dir = home.path().join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();
    std::fs::write(policies_dir.join("default.toml"), RESTRICTIVE_POLICY).unwrap();

    let (mut daemon, port) = start_daemon(home.path());

    assert!(
        wait_for_health(port, Duration::from_secs(5)),
        "daemon should boot with restrictive policy"
    );

    // --- Test 1: any tool path without Authorization → 401 ---
    let (status, body) = http_get(
        port,
        "/v1/tools/gmail/users/me/messages",
        &[("x-agentsso-scope", "gmail.modify")],
    );
    assert_eq!(status, 401, "should require auth, body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["error"]["code"], "auth.missing_token");
    assert!(json["error"]["request_id"].is_string(), "request_id should be present");
    assert!(
        json["error"]["remediation"].as_str().unwrap().contains("agentsso agent register"),
        "remediation should mention agent register"
    );

    // --- Test 2: a different scope still 401s — auth runs first ---
    let (status, body) = http_get(
        port,
        "/v1/tools/gmail/users/me/messages",
        &[("x-agentsso-scope", "gmail.readonly")],
    );
    assert_eq!(status, 401, "auth runs before policy regardless of scope, body: {body}");

    // --- Test 3: health endpoint bypasses auth ---
    let (status, _) = http_get(port, "/v1/health", &[]);
    assert_eq!(status, 200, "health endpoint should always pass through");

    daemon.kill().unwrap();
    let _ = daemon.wait();
}

#[test]
fn empty_policies_directory_still_returns_401_unauthenticated() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();

    let policies_dir = home.path().join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();

    let (mut daemon, port) = start_daemon(home.path());

    assert!(
        wait_for_health(port, Duration::from_secs(5)),
        "daemon should boot with empty policies"
    );

    // Any unauthenticated tool-path request → 401, not policy.denied.
    let (status, body) =
        http_get(port, "/v1/tools/gmail/users/me", &[("x-agentsso-scope", "gmail.readonly")]);
    assert_eq!(status, 401, "should require auth, body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["error"]["code"], "auth.missing_token");

    daemon.kill().unwrap();
    let _ = daemon.wait();
}
