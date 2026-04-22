//! End-to-end integration tests for `agentsso connectors list` and
//! the `GET /v1/control/connectors` control-plane endpoint.
//!
//! Boots the real `agentsso` binary, then:
//! - (AC #16 + #28) runs `agentsso connectors list` as a subprocess
//!   and verifies stdout contains the three built-in rows.
//! - (AC #17) runs `agentsso connectors list --json` and verifies
//!   the output parses as valid JSON with the expected shape.
//! - (AC #18) makes a direct HTTP request to
//!   `GET /v1/control/connectors` over loopback and verifies the
//!   response + the non-loopback 403 path is covered by the
//!   in-process control-plane tests at
//!   `server/control.rs::tests::connectors_handler_rejects_non_loopback`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::common::{agentsso_bin, free_port};

const TEST_MASTER_KEY_HEX: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn start_daemon(home: &std::path::Path, port: u16) -> Child {
    Command::new(agentsso_bin())
        .arg("start")
        .arg("--bind-addr")
        .arg(format!("127.0.0.1:{port}"))
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .env("AGENTSSO_TEST_MASTER_KEY_HEX", TEST_MASTER_KEY_HEX)
        .env("AGENTSSO_PLUGINS__WARN_ON_FIRST_LOAD", "false")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start daemon")
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

fn run_cli(home: &std::path::Path, port: u16, args: &[&str]) -> (i32, String, String) {
    let output = Command::new(agentsso_bin())
        .args(args)
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .env("AGENTSSO_HTTP__BIND_ADDR", format!("127.0.0.1:{port}"))
        .env("NO_COLOR", "1") // keep terminal theming out of the assertion strings
        .env("AGENTSSO_TEST_MASTER_KEY_HEX", TEST_MASTER_KEY_HEX)
        .output()
        .expect("failed to run agentsso CLI");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    (code, stdout, stderr)
}

fn http_get(port: u16, path: &str) -> (u16, String) {
    let mut stream = std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_secs(2),
    )
    .expect("failed to connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let raw = String::from_utf8_lossy(&buf).to_string();
    let status = raw.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
    let body = raw.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    (status, body)
}

// ---------- AC #28 ----------

#[test]
fn end_to_end_list_returns_three_builtins() {
    let tmp = tempfile::TempDir::new().unwrap();
    let port = free_port();
    let mut child = start_daemon(tmp.path(), port);
    let healthy = wait_for_health(port, Duration::from_secs(10));
    if !healthy {
        let _ = child.kill();
        panic!("daemon did not become healthy in time");
    }

    let (code, stdout, stderr) = run_cli(tmp.path(), port, &["connectors", "list"]);

    // Clean up BEFORE asserting so a failure doesn't leak the
    // subprocess.
    let _ = child.kill();
    let _ = child.wait();

    assert_eq!(code, 0, "connectors list must exit 0; stdout=<<<{stdout}>>> stderr=<<<{stderr}>>>");
    // Header row is always present.
    assert!(stdout.contains("CONNECTOR"));
    assert!(stdout.contains("VERSION"));
    assert!(stdout.contains("TRUST"));
    // All three built-in names present.
    assert!(stdout.contains("google-gmail"), "google-gmail must be in output: <<<{stdout}>>>");
    assert!(stdout.contains("google-calendar"));
    assert!(stdout.contains("google-drive"));
    // AC #28 strengthened: exactly 3 data rows + 1 header row.
    // Non-empty lines only (the rendered table may or may not have
    // a trailing blank). Pinning the exact count catches duplicate-
    // emit regressions and stray debug output.
    let non_empty_lines = stdout.lines().filter(|l| !l.trim().is_empty()).count();
    assert_eq!(
        non_empty_lines, 4,
        "expected exactly header + 3 rows; got {non_empty_lines}; stdout=<<<{stdout}>>>"
    );
    // Output must end on a newline (spec requires "empty trailing
    // line"; we treat a trailing newline as satisfying that).
    assert!(stdout.ends_with('\n'), "output must end with a newline; stdout=<<<{stdout}>>>");
}

// AC #16 empty-registry rendering: covered by the unit test
// `empty_registry_renders_empty_state` added alongside the rewritten
// `cli/connectors.rs` — the CLI binary crate can reach the design
// helpers directly; integration tests cannot `use crate::`, so this
// assertion lives at the unit level.

// ---------- AC #17 ----------

#[test]
fn list_json_mode_parses_as_valid_json() {
    let tmp = tempfile::TempDir::new().unwrap();
    let port = free_port();
    let mut child = start_daemon(tmp.path(), port);
    let healthy = wait_for_health(port, Duration::from_secs(10));
    if !healthy {
        let _ = child.kill();
        panic!("daemon did not become healthy");
    }

    let (code, stdout, stderr) = run_cli(tmp.path(), port, &["connectors", "list", "--json"]);
    let _ = child.kill();
    let _ = child.wait();

    assert_eq!(code, 0, "--json must exit 0; stderr=<<<{stderr}>>>");
    let json: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("--json output must parse as JSON: {e}; body=<<<{stdout}>>>"));
    let arr = json["connectors"].as_array().expect("connectors array");
    assert_eq!(arr.len(), 3);
    for entry in arr {
        // Required fields that the CLI's Rust-side parse relies on.
        assert!(entry.get("name").is_some());
        assert!(entry.get("version").is_some());
        assert!(entry.get("trust_tier").is_some());
        assert!(entry.get("scopes").is_some());
        assert!(entry.get("source_sha256_hex").is_some());
        // `source` must NOT be on the wire (AR29-analogous — no
        // transporting plugin bytes over the control plane).
        assert!(entry.get("source").is_none(), "source must not appear in JSON output: {entry}");
    }
}

// ---------- AC #18 control endpoint direct ----------

#[test]
fn control_endpoint_returns_registry() {
    let tmp = tempfile::TempDir::new().unwrap();
    let port = free_port();
    let mut child = start_daemon(tmp.path(), port);
    let healthy = wait_for_health(port, Duration::from_secs(10));
    if !healthy {
        let _ = child.kill();
        panic!("daemon did not become healthy");
    }
    let (status, body) = http_get(port, "/v1/control/connectors");
    let _ = child.kill();
    let _ = child.wait();

    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|e| {
        panic!("control endpoint body must parse as JSON: {e}; body=<<<{body}>>>")
    });
    let arr = json["connectors"].as_array().expect("connectors array");
    assert_eq!(arr.len(), 3);
    assert!(json["daemon_version"].is_string());
}
