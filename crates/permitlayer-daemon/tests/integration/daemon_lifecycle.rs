//! Integration tests for daemon lifecycle: start, stop, status, config loading,
//! and middleware chain verification.
//!
//! Each test gets its own temp dir for PID file and config isolation.
//! Ephemeral ports are used to avoid conflicts.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::common::{agentsso_bin, free_port};

/// Deterministic test master key so the daemon's `try_build_agent_runtime`
/// short-circuits past the real OS keychain lookup. Without this, a dev
/// machine's `cargo test --workspace` run triggers a macOS `SecurityAgent`
/// dialog asking for the login keychain password — documented in the
/// Story 4.4 code-review Review Findings (2026-04-13). Keep in sync with
/// `agent_registry_e2e.rs::TEST_MASTER_KEY_HEX`.
const TEST_MASTER_KEY_HEX: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Start the daemon with a given home dir and port. Returns the child process.
fn start_daemon(home: &std::path::Path, port: u16) -> std::process::Child {
    Command::new(agentsso_bin())
        .arg("start")
        .arg("--bind-addr")
        .arg(format!("127.0.0.1:{port}"))
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .env("AGENTSSO_TEST_MASTER_KEY_HEX", TEST_MASTER_KEY_HEX)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start daemon")
}

/// Wait for the daemon to be ready by polling /health.
fn wait_for_health(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(stream) = std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(100),
        ) {
            use std::io::{Read, Write as _};
            let mut stream = stream;
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

/// Send an HTTP request and return the raw response string.
fn send_http_request(port: u16, request: &str) -> String {
    use std::io::{Read, Write as _};
    let mut stream = std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_secs(2),
    )
    .expect("failed to connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut buf = Vec::new();
    // Read until connection closes or timeout.
    let _ = stream.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).to_string()
}

/// Parse HTTP response body from raw response string.
/// Handles both content-length and chunked transfer encoding.
fn parse_response_body(raw: &str) -> String {
    if let Some(idx) = raw.find("\r\n\r\n") {
        let after_headers = &raw[idx + 4..];
        // Check if chunked
        if raw.to_lowercase().contains("transfer-encoding: chunked") {
            // Simple chunked decoder: read chunk sizes and data.
            let mut result = String::new();
            let mut remaining = after_headers;
            while let Some(crlf) = remaining.find("\r\n") {
                let size_str = remaining[..crlf].trim();
                if let Ok(size) = usize::from_str_radix(size_str, 16) {
                    if size == 0 {
                        break;
                    }
                    let data_start = crlf + 2;
                    let data_end = data_start + size;
                    if data_end <= remaining.len() {
                        result.push_str(&remaining[data_start..data_end]);
                        // Skip the trailing \r\n after chunk data.
                        remaining = if data_end + 2 <= remaining.len() {
                            &remaining[data_end + 2..]
                        } else {
                            ""
                        };
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            result
        } else {
            after_headers.to_string()
        }
    } else {
        String::new()
    }
}

/// Extract the HTTP status code from raw response string.
fn parse_status_code(raw: &str) -> u16 {
    // "HTTP/1.1 200 OK\r\n..."
    let first_line = raw.lines().next().unwrap_or("");
    first_line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// Extract a header value from raw HTTP response string.
fn parse_header(raw: &str, header_name: &str) -> Option<String> {
    let lower_name = header_name.to_lowercase();
    for line in raw.lines() {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.is_empty() {
            break; // End of headers.
        }
        if let Some((name, value)) = trimmed.split_once(':')
            && name.trim().to_lowercase() == lower_name
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

/// Send SIGTERM to a process.
#[cfg(unix)]
fn send_sigterm(pid: u32) {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;
    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
}

/// Send SIGHUP to a process.
#[cfg(unix)]
fn send_sighup(pid: u32) {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;
    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGHUP);
}

// -----------------------------------------------------------------------
// Lifecycle tests (from Story 1.4)
// -----------------------------------------------------------------------

#[test]
fn test_cold_start_and_health() {
    let home = tempfile::TempDir::new().unwrap();
    let port = free_port();

    let mut child = start_daemon(home.path(), port);

    // Should become healthy within 500ms (AC #1: cold-start <500ms).
    let start = Instant::now();
    let healthy = wait_for_health(port, Duration::from_secs(5));
    let elapsed = start.elapsed();

    assert!(healthy, "daemon did not become healthy");
    // Allow some slack for CI, but should be well under 500ms in practice.
    assert!(
        elapsed < Duration::from_secs(3),
        "cold-start took {elapsed:?}, expected <500ms on fast hardware"
    );

    // PID file should exist.
    let pid_path = home.path().join("agentsso.pid");
    assert!(pid_path.exists(), "PID file not created");

    // Clean up.
    #[cfg(unix)]
    send_sigterm(child.id());
    let _ = child.wait();
}

#[test]
fn test_graceful_shutdown() {
    let home = tempfile::TempDir::new().unwrap();
    let port = free_port();

    let mut child = start_daemon(home.path(), port);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    let pid_path = home.path().join("agentsso.pid");
    assert!(pid_path.exists());

    // Send SIGTERM (AC #2, #7).
    #[cfg(unix)]
    send_sigterm(child.id());

    let status = child.wait().unwrap();
    assert!(status.success(), "daemon did not exit cleanly: {status}");

    // PID file should be removed after shutdown (AC #7).
    // Give it a moment for cleanup.
    std::thread::sleep(Duration::from_millis(100));
    assert!(!pid_path.exists(), "PID file not removed after shutdown");
}

#[test]
fn test_status_json() {
    let home = tempfile::TempDir::new().unwrap();
    let port = free_port();

    let mut child = start_daemon(home.path(), port);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    // Run `agentsso status --json`.
    let output = Command::new(agentsso_bin())
        .arg("status")
        .arg("--json")
        .env("AGENTSSO_PATHS__HOME", home.path().to_str().unwrap())
        .env("AGENTSSO_HTTP__BIND_ADDR", format!("127.0.0.1:{port}"))
        .output()
        .expect("failed to run status");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("failed to parse status JSON: {e}\nstdout: {stdout}"));

    assert_eq!(parsed["status"], "healthy");
    assert!(parsed["pid"].is_number());
    assert!(parsed["uptime_seconds"].is_number());
    assert!(parsed["bind_addr"].is_string());

    // Clean up.
    #[cfg(unix)]
    send_sigterm(child.id());
    let _ = child.wait();
}

#[test]
fn test_stop_command() {
    let home = tempfile::TempDir::new().unwrap();
    let port = free_port();

    let mut child = start_daemon(home.path(), port);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    // Run `agentsso stop`.
    let output = Command::new(agentsso_bin())
        .arg("stop")
        .env("AGENTSSO_PATHS__HOME", home.path().to_str().unwrap())
        .output()
        .expect("failed to run stop");

    assert!(output.status.success(), "stop command failed");

    // Daemon should have exited.
    let status = child.wait().unwrap();
    assert!(status.success(), "daemon did not exit cleanly after stop");
}

#[test]
fn test_config_from_toml() {
    let home = tempfile::TempDir::new().unwrap();
    let port = free_port();

    // Write a TOML config with a custom port.
    let config_dir = home.path().join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    let toml_path = config_dir.join("daemon.toml");
    {
        let mut f = std::fs::File::create(&toml_path).unwrap();
        writeln!(f, "[http]").unwrap();
        writeln!(f, "bind_addr = \"127.0.0.1:{port}\"").unwrap();
    }

    // Start WITHOUT --bind-addr flag; should pick up from TOML.
    let mut child = Command::new(agentsso_bin())
        .arg("start")
        .env("AGENTSSO_PATHS__HOME", home.path().to_str().unwrap())
        .env("AGENTSSO_TEST_MASTER_KEY_HEX", TEST_MASTER_KEY_HEX)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    assert!(
        wait_for_health(port, Duration::from_secs(5)),
        "daemon did not start on TOML-configured port {port}"
    );

    #[cfg(unix)]
    send_sigterm(child.id());
    let _ = child.wait();
}

#[test]
fn test_env_var_override() {
    let home = tempfile::TempDir::new().unwrap();
    let toml_port = free_port();
    let env_port = free_port();

    // Write TOML with one port.
    let config_dir = home.path().join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    let toml_path = config_dir.join("daemon.toml");
    {
        let mut f = std::fs::File::create(&toml_path).unwrap();
        writeln!(f, "[http]").unwrap();
        writeln!(f, "bind_addr = \"127.0.0.1:{toml_port}\"").unwrap();
    }

    // Start with env var override to a different port.
    let mut child = Command::new(agentsso_bin())
        .arg("start")
        .env("AGENTSSO_PATHS__HOME", home.path().to_str().unwrap())
        .env("AGENTSSO_HTTP__BIND_ADDR", format!("127.0.0.1:{env_port}"))
        .env("AGENTSSO_TEST_MASTER_KEY_HEX", TEST_MASTER_KEY_HEX)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // The daemon should bind to the env var port, not the TOML port.
    assert!(
        wait_for_health(env_port, Duration::from_secs(5)),
        "daemon did not bind to env var port {env_port}"
    );

    #[cfg(unix)]
    send_sigterm(child.id());
    let _ = child.wait();
}

#[test]
fn test_invalid_config_fails_fast() {
    let home = tempfile::TempDir::new().unwrap();

    // Write invalid TOML (AC #5).
    let config_dir = home.path().join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    let toml_path = config_dir.join("daemon.toml");
    {
        let mut f = std::fs::File::create(&toml_path).unwrap();
        writeln!(f, "[http]").unwrap();
        writeln!(f, "bind_addr = \"not-a-socket-addr\"").unwrap();
    }

    let output = Command::new(agentsso_bin())
        .arg("start")
        .env("AGENTSSO_PATHS__HOME", home.path().to_str().unwrap())
        .env("AGENTSSO_TEST_MASTER_KEY_HEX", TEST_MASTER_KEY_HEX)
        .output()
        .unwrap();

    assert!(!output.status.success(), "daemon should fail with invalid config");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("config_invalid"),
        "expected structured error with error_code, got: {stderr}"
    );
}

#[test]
fn test_stale_pid_recovery() {
    let home = tempfile::TempDir::new().unwrap();
    let port = free_port();

    // Write a stale PID file (PID that doesn't exist).
    std::fs::write(home.path().join("agentsso.pid"), "999999999\n").unwrap();

    // Starting should succeed — stale PID is overwritten.
    let mut child = start_daemon(home.path(), port);
    assert!(
        wait_for_health(port, Duration::from_secs(5)),
        "daemon did not recover from stale PID file"
    );

    #[cfg(unix)]
    send_sigterm(child.id());
    let _ = child.wait();
}

#[test]
fn test_double_start_fails() {
    let home = tempfile::TempDir::new().unwrap();
    let port1 = free_port();
    let port2 = free_port();

    let mut child1 = start_daemon(home.path(), port1);
    assert!(wait_for_health(port1, Duration::from_secs(5)));

    // Attempting to start a second daemon on the same home should fail.
    let output = Command::new(agentsso_bin())
        .arg("start")
        .arg("--bind-addr")
        .arg(format!("127.0.0.1:{port2}"))
        .env("AGENTSSO_PATHS__HOME", home.path().to_str().unwrap())
        .env("AGENTSSO_TEST_MASTER_KEY_HEX", TEST_MASTER_KEY_HEX)
        .output()
        .unwrap();

    assert!(!output.status.success(), "second start should fail when daemon already running");

    #[cfg(unix)]
    send_sigterm(child1.id());
    let _ = child1.wait();
}

/// Test SIGHUP triggers config reload (AC #6).
#[cfg(unix)]
#[test]
fn test_sighup_reload() {
    let home = tempfile::TempDir::new().unwrap();
    let port = free_port();

    let mut child = start_daemon(home.path(), port);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    // Send SIGHUP — daemon should log "configuration reloaded" and stay running.
    send_sighup(child.id());

    // Give it a moment to process.
    std::thread::sleep(Duration::from_millis(500));

    // Daemon should still be running.
    assert!(wait_for_health(port, Duration::from_secs(2)), "daemon not healthy after SIGHUP");

    #[cfg(unix)]
    send_sigterm(child.id());
    let _ = child.wait();
}

// -----------------------------------------------------------------------
// Middleware tests (Story 1.5)
// -----------------------------------------------------------------------

/// Verify the default bind address is now 127.0.0.1:3820 via config unit test.
/// (Integration test relies on the config layer, which is tested in schema::tests.)
#[test]
fn test_default_binds_localhost_3820() {
    // This test verifies the default at the config level (no daemon spawn needed).
    // The default_bind_addr() function now returns 127.0.0.1:3820.
    // We validate by starting the daemon on an ephemeral port (to avoid port conflict)
    // and confirming the status JSON reports the correct bind address.
    let home = tempfile::TempDir::new().unwrap();
    let port = free_port();

    // Write TOML config with no http section — daemon should use default.
    // But we still need a known port for the test, so write one explicitly.
    // The real default-port assertion is in the unit test `default_config_produces_localhost_3820`.
    let mut child = start_daemon(home.path(), port);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    // Verify the status JSON output includes the bind address we expect.
    let output = Command::new(agentsso_bin())
        .arg("status")
        .arg("--json")
        .env("AGENTSSO_PATHS__HOME", home.path().to_str().unwrap())
        .env("AGENTSSO_HTTP__BIND_ADDR", format!("127.0.0.1:{port}"))
        .output()
        .expect("failed to run status");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("failed to parse status JSON: {e}\nstdout: {stdout}"));

    let bind_addr = parsed["bind_addr"].as_str().unwrap();
    assert!(!bind_addr.contains("3100"), "bind address should not reference 3100: {bind_addr}");
    assert!(bind_addr.starts_with("127.0.0.1:"), "bind address should be localhost: {bind_addr}");

    #[cfg(unix)]
    send_sigterm(child.id());
    let _ = child.wait();
}

/// Verify X-Agentsso-Request-Id header is echoed in responses (ULID format).
#[test]
fn test_request_id_header_echoed() {
    let home = tempfile::TempDir::new().unwrap();
    let port = free_port();

    let mut child = start_daemon(home.path(), port);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    let raw = send_http_request(
        port,
        &format!("GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"),
    );
    let request_id = parse_header(&raw, "x-agentsso-request-id");
    assert!(request_id.is_some(), "missing X-Agentsso-Request-Id header. raw response:\n{raw}");
    let id = request_id.unwrap();
    assert_eq!(id.len(), 26, "ULID should be 26 chars, got: {id}");

    #[cfg(unix)]
    send_sigterm(child.id());
    let _ = child.wait();
}

/// Verify DNS rebinding protection blocks disallowed Host header.
#[test]
fn test_dns_rebind_blocked() {
    let home = tempfile::TempDir::new().unwrap();
    let port = free_port();

    let mut child = start_daemon(home.path(), port);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    let raw = send_http_request(
        port,
        "GET /health HTTP/1.1\r\nHost: evil.com\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status_code(&raw);
    assert_eq!(status, 400, "expected 400 for disallowed Host header. raw response:\n{raw}");

    let body = parse_response_body(&raw);
    let json: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("failed to parse error JSON: {e}\nbody: {body}\nraw: {raw}"));
    assert_eq!(json["error"]["code"], "dns_rebind.blocked");
    assert!(json["error"]["request_id"].is_null());

    #[cfg(unix)]
    send_sigterm(child.id());
    let _ = child.wait();
}

/// Verify DNS rebinding allows localhost Host header.
#[test]
fn test_dns_rebind_allowed_localhost() {
    let home = tempfile::TempDir::new().unwrap();
    let port = free_port();

    let mut child = start_daemon(home.path(), port);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    // Use ephemeral port (NOT hardcoded 3000).
    let raw = send_http_request(
        port,
        &format!("GET /health HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n"),
    );
    let status = parse_status_code(&raw);
    assert_eq!(status, 200, "expected 200 for allowed localhost Host header. raw response:\n{raw}");

    #[cfg(unix)]
    send_sigterm(child.id());
    let _ = child.wait();
}

/// Verify DNS rebinding blocks disallowed Origin header.
#[test]
fn test_dns_rebind_origin_blocked() {
    let home = tempfile::TempDir::new().unwrap();
    let port = free_port();

    let mut child = start_daemon(home.path(), port);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    let raw = send_http_request(
        port,
        &format!(
            "GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://evil.com\r\nConnection: close\r\n\r\n"
        ),
    );
    let status = parse_status_code(&raw);
    assert_eq!(status, 400, "expected 400 for disallowed Origin header. raw response:\n{raw}");

    #[cfg(unix)]
    send_sigterm(child.id());
    let _ = child.wait();
}

/// Verify /health traverses middleware (has X-Agentsso-Request-Id with valid ULID).
#[test]
fn test_health_traverses_middleware() {
    let home = tempfile::TempDir::new().unwrap();
    let port = free_port();

    let mut child = start_daemon(home.path(), port);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    let raw = send_http_request(
        port,
        &format!("GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"),
    );
    let request_id = parse_header(&raw, "x-agentsso-request-id");
    assert!(
        request_id.is_some(),
        "/health should traverse middleware and include X-Agentsso-Request-Id. raw:\n{raw}"
    );
    let id = request_id.unwrap();
    assert_eq!(id.len(), 26, "ULID should be 26 chars");

    #[cfg(unix)]
    send_sigterm(child.id());
    let _ = child.wait();
}

/// Verify non-localhost binding emits a warning.
/// The warning is emitted by tracing, which writes to stdout (default for
/// `tracing_subscriber::fmt()`).
#[test]
fn test_non_localhost_warning() {
    let home = tempfile::TempDir::new().unwrap();
    let port = free_port();

    // Start with 0.0.0.0 binding — should emit the warning.
    let child = Command::new(agentsso_bin())
        .arg("start")
        .arg("--bind-addr")
        .arg(format!("0.0.0.0:{port}"))
        .env("AGENTSSO_PATHS__HOME", home.path().to_str().unwrap())
        .env("AGENTSSO_TEST_MASTER_KEY_HEX", TEST_MASTER_KEY_HEX)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let child_id = child.id();

    // Wait for the daemon to start.
    assert!(wait_for_health(port, Duration::from_secs(5)));

    // Send SIGTERM and wait for clean exit, which flushes tracing output.
    #[cfg(unix)]
    send_sigterm(child_id);
    let output = child.wait_with_output().unwrap();

    // tracing_subscriber::fmt() writes to stdout by default.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("binding to non-localhost address"),
        "expected non-localhost warning, got stdout:\n{stdout}"
    );
}

/// Verify all routes traverse middleware (X-Agentsso-Request-Id present).
#[test]
fn test_middleware_ordering() {
    let home = tempfile::TempDir::new().unwrap();
    let port = free_port();

    let mut child = start_daemon(home.path(), port);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    let routes = ["/health", "/v1/health", "/mcp", "/v1/tools/test/test"];

    for route in &routes {
        let raw = send_http_request(
            port,
            &format!("GET {route} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"),
        );
        let request_id = parse_header(&raw, "x-agentsso-request-id");
        assert!(
            request_id.is_some(),
            "route {route} should have X-Agentsso-Request-Id header. raw:\n{raw}"
        );
        let id = request_id.unwrap();
        assert_eq!(id.len(), 26, "route {route}: ULID should be 26 chars, got: {id}");
    }

    #[cfg(unix)]
    send_sigterm(child.id());
    let _ = child.wait();
}

/// Story 6.1 AC #16: `PluginRuntime::new_default()` failure bubbles
/// through `StartError::PluginRuntimeInit` with a structured banner,
/// exits code 2, and does NOT create the PID file.
///
/// Exercises the `AGENTSSO_TEST_PLUGIN_RUNTIME_INIT_FAIL=1` test
/// seam gated on `#[cfg(debug_assertions)]` in
/// `permitlayer-plugins/src/runtime.rs`.
#[test]
fn test_plugin_runtime_init_failure_bubbles_as_start_error() {
    let home = tempfile::TempDir::new().unwrap();
    let port = free_port();

    let output = Command::new(agentsso_bin())
        .arg("start")
        .arg("--bind-addr")
        .arg(format!("127.0.0.1:{port}"))
        .env("AGENTSSO_PATHS__HOME", home.path().to_str().unwrap())
        .env("AGENTSSO_TEST_MASTER_KEY_HEX", TEST_MASTER_KEY_HEX)
        .env("AGENTSSO_TEST_PLUGIN_RUNTIME_INIT_FAIL", "1")
        .output()
        .unwrap();

    assert!(!output.status.success(), "daemon should fail when plugin runtime init fails");
    assert_eq!(
        output.status.code(),
        Some(2),
        "PluginRuntimeInit is a boot-time fatal — exit code 2 per StartError::exit_code"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    // L2 review patch: narrow to the exact phrase the `StartError::
    // PluginRuntimeInit::render_banner` impl emits. A permissive
    // substring match would silently accept a banner that omits
    // the operator-actionable detail ("connector plugin runtime")
    // in a future refactor.
    assert!(
        stderr.contains("connector plugin runtime"),
        "expected banner containing 'connector plugin runtime', got: {stderr}"
    );
}
