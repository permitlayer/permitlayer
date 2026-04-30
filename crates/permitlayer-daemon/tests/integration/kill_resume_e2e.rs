//! End-to-end subprocess integration tests for `agentsso kill` /
//! `agentsso resume`, the loopback control endpoints, and (Story 3.3)
//! the audit narrative that a kill incident produces.
//!
//! Spawns a real daemon subprocess, drives the CLI (also as a subprocess),
//! and asserts HTTP round trips against both the main middleware chain
//! (where `/health` is expected to be blocked while killed) and the
//! carved-out control endpoints (where `POST /v1/control/resume` must keep
//! working while killed). Story 3.3 adds audit-narrative tests that parse
//! `<home>/audit/<today>.jsonl` directly and assert the three new event
//! types appear with matching request_ids and timestamp ordering.
//!
//! This file is intentionally self-contained — the subprocess helpers are
//! copied from `daemon_lifecycle.rs` rather than extracted into
//! `tests/common/mod.rs`, to avoid touching the Epic-2-flagged dedup
//! concern under story scope. Extraction is deferred to a future
//! test-infra story.
//!
//! # Known flakiness under `cargo test --workspace` default parallelism
//!
//! This file contains 13 subprocess tests, each of which spawns its own
//! `agentsso start` child process. Under `cargo test --workspace` with
//! default `--test-threads` (= number of CPU cores), the parallel
//! subprocess spawn pressure can cause 1-in-N runs to fail with
//! `assertion failed: wait_for_health(port, Duration::from_secs(5))` —
//! a daemon didn't complete its startup sequence inside the 5s health
//! poll window because other tests were hammering the CPU / fs at the
//! same time. The failing test is non-deterministic (different test
//! each run). Running in isolation or with `--test-threads=4` is
//! reliable.
//!
//! The root fix is test-harness isolation (extracting the subprocess
//! helpers into `tests/common/mod.rs` and either serializing the
//! spawn-heavy tests via `serial_test` or running them in separate
//! integration binaries). Deferred.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::common::agentsso_bin;

// --------------------------------------------------------------------------
// Subprocess harness — copied from daemon_lifecycle.rs.
// --------------------------------------------------------------------------

/// Deterministic test master key so the daemon's `try_build_agent_runtime`
/// short-circuits past the real OS keychain lookup. Keep in sync with
/// `agent_registry_e2e.rs::TEST_MASTER_KEY_HEX`.
const TEST_MASTER_KEY_HEX: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Story 7.7: zero-port + marker-read.
fn start_daemon(home: &std::path::Path) -> (Child, u16) {
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
        if let Ok(mut stream) = TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(100),
        ) {
            stream.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
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

fn send_http_request(port: u16, request: &str) -> String {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_secs(2),
    )
    .expect("failed to connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut buf = Vec::new();
    // Propagate read errors via `.expect()` — a silent `let _` here would
    // hide timeouts / connection resets and turn real IO failures into
    // downstream "parse_status_code got 0" assertion failures with no
    // diagnostic. We want to see the root cause.
    stream.read_to_end(&mut buf).expect("read HTTP response (connection reset or read timeout)");
    String::from_utf8_lossy(&buf).to_string()
}

fn parse_status_code(raw: &str) -> u16 {
    let first_line = raw.lines().next().unwrap_or("");
    first_line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn parse_response_body(raw: &str) -> String {
    if let Some(idx) = raw.find("\r\n\r\n") {
        raw[idx + 4..].trim().to_string()
    } else {
        String::new()
    }
}

fn parse_header(raw: &str, name: &str) -> Option<String> {
    let lower = name.to_lowercase();
    for line in raw.lines() {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.is_empty() {
            break;
        }
        if let Some((n, v)) = trimmed.split_once(':')
            && n.trim().to_lowercase() == lower
        {
            return Some(v.trim().to_string());
        }
    }
    None
}

#[cfg(unix)]
fn send_sigterm(pid: u32) {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;
    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
}

/// RAII wrapper that always SIGTERMs the subprocess on drop.
struct DaemonGuard {
    child: Option<Child>,
}

impl DaemonGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            #[cfg(unix)]
            send_sigterm(child.id());
            // Give it a moment to exit gracefully, then force-kill if still alive.
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) => {
                        if Instant::now() > deadline {
                            let _ = child.kill();
                            let _ = child.wait();
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => {
                        let _ = child.kill();
                        return;
                    }
                }
            }
        }
    }
}

// --------------------------------------------------------------------------
// Subprocess CLI drivers.
// --------------------------------------------------------------------------

struct CliOutput {
    status: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run_cli(home: &std::path::Path, port: u16, args: &[&str]) -> CliOutput {
    let output = Command::new(agentsso_bin())
        .args(args)
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .env("AGENTSSO_HTTP__BIND_ADDR", format!("127.0.0.1:{port}"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run CLI subprocess");
    CliOutput {
        status: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn get_health(port: u16) -> String {
    send_http_request(
        port,
        &format!("GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"),
    )
}

fn post_control(port: u16, path: &str) -> String {
    let body = "{}";
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    send_http_request(port, &request)
}

fn get_control(port: u16, path: &str) -> String {
    send_http_request(
        port,
        &format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"),
    )
}

// --------------------------------------------------------------------------
// Tests.
// --------------------------------------------------------------------------

#[test]
fn kill_then_resume_round_trip() {
    let home = tempfile::TempDir::new().unwrap();
    let (child, port) = start_daemon(home.path());
    let _guard = DaemonGuard::new(child);
    assert!(wait_for_health(port, Duration::from_secs(5)), "daemon did not become healthy");

    // 1. /health returns 200 before kill.
    let raw = get_health(port);
    assert_eq!(parse_status_code(&raw), 200, "pre-kill /health must be 200: {raw}");

    // 2. Run `agentsso kill`.
    let out = run_cli(home.path(), port, &["kill"]);
    assert_eq!(out.status, Some(0), "kill exit should be 0; stderr={}", out.stderr);
    assert!(
        out.stdout.contains("DAEMON KILLED"),
        "missing banner header in kill stdout: {}",
        out.stdout
    );
    assert!(
        out.stdout.contains("resume with:  agentsso resume"),
        "missing resume hint in kill stdout: {}",
        out.stdout
    );

    // 3. /health returns 403 + daemon_killed while killed.
    let raw = get_health(port);
    assert_eq!(parse_status_code(&raw), 403, "post-kill /health must be 403: {raw}");
    let body = parse_response_body(&raw);
    assert!(body.contains("\"daemon_killed\""), "body missing daemon_killed: {body}");

    // 4. Run `agentsso resume`.
    let out = run_cli(home.path(), port, &["resume"]);
    assert_eq!(out.status, Some(0), "resume exit should be 0; stderr={}", out.stderr);
    assert!(
        out.stdout.contains("daemon resumed") || out.stdout.contains("RESUMED"),
        "missing resume banner in stdout: {}",
        out.stdout
    );

    // 5. /health returns 200 again after resume.
    let raw = get_health(port);
    assert_eq!(parse_status_code(&raw), 200, "post-resume /health must be 200: {raw}");
}

#[test]
fn kill_respects_nfr6_budget() {
    let home = tempfile::TempDir::new().unwrap();
    let (child, port) = start_daemon(home.path());
    let _guard = DaemonGuard::new(child);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    // Warm-up: a throwaway CLI invocation pays the cold-cache subprocess
    // spawn cost (dyld + binary load + cargo artifact linking) so it
    // doesn't contaminate the first timed iteration below. Without this,
    // on slow/contended CI runners the first kill can exceed the 2000ms
    // budget purely due to cold-start overhead, not NFR6 regression.
    // `--help` exits cleanly without touching the daemon.
    let _ = run_cli(home.path(), port, &["--help"]);

    // Run kill 3 times, each preceded by a resume so the daemon is in the
    // "not yet killed" state and the full activation happens. Assert all
    // three complete within the NFR6 2000ms budget.
    for i in 0..3 {
        // Ensure daemon is running (not killed) before measuring.
        if i > 0 {
            let out = run_cli(home.path(), port, &["resume"]);
            assert_eq!(out.status, Some(0), "resume failed: {}", out.stderr);
        }

        let started = Instant::now();
        let out = run_cli(home.path(), port, &["kill"]);
        let elapsed = started.elapsed();
        assert_eq!(out.status, Some(0), "kill iteration {i} failed: {}", out.stderr);
        assert!(
            elapsed < Duration::from_secs(2),
            "NFR6 violation on iteration {i}: kill took {elapsed:?} (>2s budget)"
        );
    }
}

#[test]
fn kill_is_idempotent() {
    let home = tempfile::TempDir::new().unwrap();
    let (child, port) = start_daemon(home.path());
    let _guard = DaemonGuard::new(child);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    let out = run_cli(home.path(), port, &["kill"]);
    assert_eq!(out.status, Some(0), "first kill: {}", out.stderr);
    assert!(out.stdout.contains("DAEMON KILLED"), "first kill missing full banner: {}", out.stdout);

    // Second kill should exit 0 and render the idempotent short form.
    let out = run_cli(home.path(), port, &["kill"]);
    assert_eq!(out.status, Some(0), "second kill: {}", out.stderr);
    assert!(
        out.stdout.contains("already in kill state") || out.stdout.contains("idempotent"),
        "second kill missing idempotent signal: {}",
        out.stdout
    );
}

#[test]
fn resume_is_idempotent() {
    let home = tempfile::TempDir::new().unwrap();
    let (child, port) = start_daemon(home.path());
    let _guard = DaemonGuard::new(child);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    // Fresh daemon — never killed. Resume should be a no-op.
    let out = run_cli(home.path(), port, &["resume"]);
    assert_eq!(out.status, Some(0), "resume: {}", out.stderr);
    assert!(
        out.stdout.contains("nothing to resume") || out.stdout.contains("not in kill state"),
        "resume missing nothing-to-resume signal: {}",
        out.stdout
    );

    // Second resume — still a no-op.
    let out = run_cli(home.path(), port, &["resume"]);
    assert_eq!(out.status, Some(0));
}

#[test]
fn kill_when_no_daemon_exits_3() {
    let home = tempfile::TempDir::new().unwrap();
    // No daemon spawned: the CLI exits 3 before ever opening a TCP
    // connection. A literal placeholder port is fine.
    let port: u16 = 1;

    // No daemon running.
    let out = run_cli(home.path(), port, &["kill"]);
    assert_eq!(out.status, Some(3), "expected exit 3, got {:?}; stderr={}", out.status, out.stderr);
    assert!(
        out.stderr.contains("daemon_not_running"),
        "stderr missing daemon_not_running: {}",
        out.stderr
    );
}

#[test]
fn resume_when_no_daemon_exits_3() {
    let home = tempfile::TempDir::new().unwrap();
    let port: u16 = 1;

    let out = run_cli(home.path(), port, &["resume"]);
    assert_eq!(out.status, Some(3), "expected exit 3, got {:?}; stderr={}", out.status, out.stderr);
    assert!(
        out.stderr.contains("daemon_not_running"),
        "stderr missing daemon_not_running: {}",
        out.stderr
    );
}

// NOTE: the FR62 "vault untouched across kill" assertion moved to an
// in-process unit test at `crates/permitlayer-daemon/src/server/control.rs`
// (`kill_handler_does_not_touch_any_file_under_home`). The previous
// subprocess-based version in this file would have needed either a real
// sealed-vault blob (out of scope) or a keystore-fallback override
// (doesn't exist today) to avoid the macOS Keychain prompt path that
// `try_build_proxy_service` triggers when `vault/` is present. The
// in-process assertion is strictly sharper — it drives the real kill
// handler against a real temp home and asserts the full subtree is
// byte-identical afterwards — without needing a running daemon or any
// subprocess plumbing. See `server/control.rs` for the assertion.

#[test]
fn control_resume_bypasses_kill_middleware() {
    let home = tempfile::TempDir::new().unwrap();
    let (child, port) = start_daemon(home.path());
    let _guard = DaemonGuard::new(child);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    // Kill via direct POST (not via CLI) so we isolate the test to the
    // control endpoint behavior.
    let raw = post_control(port, "/v1/control/kill");
    assert_eq!(parse_status_code(&raw), 200, "control kill must be 200: {raw}");

    // /health is now blocked.
    let raw = get_health(port);
    assert_eq!(parse_status_code(&raw), 403, "post-kill /health must be 403");

    // But /v1/control/resume must still reach the handler.
    let raw = post_control(port, "/v1/control/resume");
    assert_eq!(
        parse_status_code(&raw),
        200,
        "control resume must not be blocked by KillSwitchLayer: {raw}"
    );
    let body = parse_response_body(&raw);
    assert!(
        body.contains("\"deactivation\""),
        "control resume body must contain deactivation field: {body}"
    );
    assert!(
        !body.contains("\"daemon_killed\""),
        "control resume leaked daemon_killed body: {body}"
    );

    // And /health recovers.
    let raw = get_health(port);
    assert_eq!(parse_status_code(&raw), 200, "post-resume /health must be 200");
}

#[test]
fn main_endpoints_still_blocked_while_killed() {
    let home = tempfile::TempDir::new().unwrap();
    let (child, port) = start_daemon(home.path());
    let _guard = DaemonGuard::new(child);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    assert_eq!(parse_status_code(&post_control(port, "/v1/control/kill")), 200);

    for path in ["/health", "/v1/health", "/mcp"] {
        let raw = send_http_request(
            port,
            &format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"),
        );
        let code = parse_status_code(&raw);
        assert_eq!(code, 403, "{path} must return 403 while killed, got {code}: {raw}");
        let body = parse_response_body(&raw);
        assert!(body.contains("\"daemon_killed\""), "{path} missing daemon_killed: {body}");
    }

    // Content-Type assertion (Story 3.1 review patch: LOW — integration
    // tests should verify the header shape is identical across endpoints).
    let raw = get_health(port);
    assert_eq!(
        parse_header(&raw, "content-type").as_deref(),
        Some("application/json"),
        "Content-Type must be application/json: {raw}"
    );
}

#[test]
fn control_state_endpoint_reports_active_while_killed() {
    let home = tempfile::TempDir::new().unwrap();
    let (child, port) = start_daemon(home.path());
    let _guard = DaemonGuard::new(child);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    assert_eq!(parse_status_code(&post_control(port, "/v1/control/kill")), 200);

    let raw = get_control(port, "/v1/control/state");
    assert_eq!(parse_status_code(&raw), 200);
    let body = parse_response_body(&raw);
    assert!(body.contains("\"active\":true"), "state must report active=true: {body}");
    assert!(body.contains("\"activated_at\""), "state missing activated_at: {body}");
}

#[test]
fn setup_blocked_when_killed() {
    let home = tempfile::TempDir::new().unwrap();
    let (child, port) = start_daemon(home.path());
    let _guard = DaemonGuard::new(child);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    assert_eq!(parse_status_code(&post_control(port, "/v1/control/kill")), 200);

    // Run `agentsso setup gmail --non-interactive` — it should be blocked
    // by the kill-state probe before any OAuth flow starts.
    let out = run_cli(home.path(), port, &["setup", "gmail", "--non-interactive"]);
    assert_eq!(
        out.status,
        Some(2),
        "expected setup to exit 2 when daemon killed, got {:?}; stderr={}",
        out.status,
        out.stderr
    );
    assert!(
        out.stderr.contains("daemon_killed"),
        "setup stderr missing daemon_killed: {}",
        out.stderr
    );
    assert!(
        out.stderr.contains("agentsso resume"),
        "setup stderr missing resume hint: {}",
        out.stderr
    );
}

/// Probe the control-state endpoint as a loopback peer. Sanity check that
/// the content-type + schema look right.
#[test]
fn control_state_endpoint_content_type_is_json() {
    let home = tempfile::TempDir::new().unwrap();
    let (child, port) = start_daemon(home.path());
    let _guard = DaemonGuard::new(child);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    let raw = get_control(port, "/v1/control/state");
    assert_eq!(parse_status_code(&raw), 200);
    assert_eq!(
        parse_header(&raw, "content-type").as_deref(),
        Some("application/json"),
        "state endpoint must return application/json: {raw}"
    );
}

// --------------------------------------------------------------------------
//
// Story 3.3: audit narrative during kill incident.
//
// --------------------------------------------------------------------------
//
// These tests reconstruct the FR64 incident narrative from the audit
// JSONL file directly. They spawn a real daemon, run `agentsso kill`,
// fire N requests that should be 403'd, run `agentsso resume`, then
// parse `<home>/audit/<today>.jsonl` and assert the three new Story 3.3
// event types appear in the expected order with matching fields.

/// Parse every non-blank line in `<home>/audit/*.jsonl` as a
/// `serde_json::Value`. Ignores malformed lines (they shouldn't happen,
/// but the test is a forensic reader not a schema enforcer).
/// Story 7.7 Phase 4b: parse an ISO-8601 timestamp like
/// `2026-04-30T15:14:48.092Z` into wall-clock milliseconds since the
/// Unix epoch, falling back to `0` on parse failure (the per-test
/// invariant catches truly empty strings; a bad-but-not-empty string
/// that parses to 0 will fail the ordering check loudly).
fn parse_iso8601_ms(s: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(s).map(|dt| dt.timestamp_millis()).unwrap_or(0)
}

fn read_audit_events(home: &std::path::Path) -> Vec<serde_json::Value> {
    let audit_dir = home.join("audit");
    let mut out = Vec::new();
    if !audit_dir.exists() {
        return out;
    }
    let mut paths: Vec<_> = std::fs::read_dir(&audit_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("jsonl"))
        .collect();
    paths.sort();
    for path in paths {
        let contents = std::fs::read_to_string(&path).unwrap();
        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                out.push(v);
            }
        }
    }
    out
}

/// Wait up to `timeout` for at least `expected_count` events matching
/// `event_type` to land in the audit log. The audit writes from
/// `KillSwitchLayer::call` are fire-and-forget via `tokio::spawn`, so
/// we need a short poll loop to let the spawned tasks finish their
/// `append().await` and `fsync()` before reading the file.
fn wait_for_audit_events(
    home: &std::path::Path,
    event_type: &str,
    expected_count: usize,
    timeout: Duration,
) -> Vec<serde_json::Value> {
    let deadline = Instant::now() + timeout;
    loop {
        let events = read_audit_events(home);
        let matching: Vec<_> = events
            .into_iter()
            .filter(|e| e.get("event_type").and_then(|v| v.as_str()) == Some(event_type))
            .collect();
        if matching.len() >= expected_count {
            return matching;
        }
        if Instant::now() > deadline {
            return matching; // Return partial results; caller asserts count.
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn kill_resume_audit_narrative() {
    let home = tempfile::TempDir::new().unwrap();
    let (child, port) = start_daemon(home.path());
    let _guard = DaemonGuard::new(child);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    // 1. Kill via the CLI.
    let out = run_cli(home.path(), port, &["kill"]);
    assert_eq!(out.status, Some(0), "kill: {}", out.stderr);
    assert!(out.stdout.contains("DAEMON KILLED"), "missing banner: {}", out.stdout);

    // 2. Issue 3 blocked requests against /v1/tools/gmail/*.
    for _ in 0..3 {
        let raw = send_http_request(
            port,
            &format!(
                "GET /v1/tools/gmail/users/me/profile HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
            ),
        );
        assert_eq!(parse_status_code(&raw), 403, "expected 403: {raw}");
        let body = parse_response_body(&raw);
        assert!(body.contains("daemon_killed"), "body missing daemon_killed: {body}");
    }

    // 3. Resume via the CLI.
    let out = run_cli(home.path(), port, &["resume"]);
    assert_eq!(out.status, Some(0), "resume: {}", out.stderr);

    // Drop the guard explicitly so the daemon exits cleanly and flushes
    // its audit buffer before we read the file. The guard goes out of
    // scope at the end of the function anyway, but doing it explicitly
    // makes the timeline unambiguous.
    drop(_guard);
    // Give the daemon a brief moment to finalize the fsync'd audit file.
    std::thread::sleep(Duration::from_millis(100));

    // 4. Read and parse the audit narrative.
    let activated = wait_for_audit_events(home.path(), "kill-activated", 1, Duration::from_secs(2));
    assert_eq!(activated.len(), 1, "expected 1 kill-activated event");

    let blocked =
        wait_for_audit_events(home.path(), "kill-blocked-request", 3, Duration::from_secs(2));
    assert_eq!(blocked.len(), 3, "expected 3 kill-blocked-request events");

    let resumed = wait_for_audit_events(home.path(), "kill-resumed", 1, Duration::from_secs(2));
    assert_eq!(resumed.len(), 1, "expected 1 kill-resumed event");

    // 5. Assert narrative ordering via timestamp comparison.
    let all_events = read_audit_events(home.path());
    let kill_narrative: Vec<&serde_json::Value> = all_events
        .iter()
        .filter(|e| {
            matches!(
                e.get("event_type").and_then(|v| v.as_str()),
                Some("kill-activated") | Some("kill-blocked-request") | Some("kill-resumed")
            )
        })
        .collect();

    // Extract timestamps as strings — lexicographic order on ISO 8601
    // with Z suffix matches chronological order for all sensible values.
    let timestamps: Vec<&str> = kill_narrative
        .iter()
        .map(|e| e.get("timestamp").and_then(|v| v.as_str()).unwrap_or(""))
        .collect();

    // Story 7.7 Phase 4b: Windows `chrono::Utc::now()` is backed by
    // `GetSystemTimeAsFileTime`, which has 15.6ms default resolution.
    // The three concurrent `kill-blocked-request` events are
    // generated on different tokio task threads and each call
    // `Utc::now()` independently — within a single Windows tick,
    // wall-clock-adjacent calls can return values that don't preserve
    // submission order. Allow up to 20ms inversion on Windows
    // (well above the 15.6ms tick, well below any failure mode that
    // would mask a real seconds-scale ordering bug). Unix gets
    // microsecond-resolution monotonic time and stays strict.
    const TIMESTAMP_INVERSION_TOLERANCE_MS: i64 = if cfg!(windows) { 20 } else { 0 };
    for i in 1..timestamps.len() {
        let prev_ms = parse_iso8601_ms(timestamps[i - 1]);
        let curr_ms = parse_iso8601_ms(timestamps[i]);
        assert!(
            curr_ms + TIMESTAMP_INVERSION_TOLERANCE_MS >= prev_ms,
            "audit events must be in timestamp order (±{}ms on Windows); {} > {}",
            TIMESTAMP_INVERSION_TOLERANCE_MS,
            timestamps[i - 1],
            timestamps[i],
        );
    }

    // 6. The first event must be kill-activated, the last must be kill-resumed.
    assert_eq!(
        kill_narrative[0].get("event_type").and_then(|v| v.as_str()),
        Some("kill-activated"),
        "first kill event must be kill-activated",
    );
    assert_eq!(
        kill_narrative.last().unwrap().get("event_type").and_then(|v| v.as_str()),
        Some("kill-resumed"),
        "last kill event must be kill-resumed",
    );

    // 7. Each kill-blocked-request must have a unique request_id.
    let mut blocked_request_ids: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    for event in &blocked {
        let request_id = event.get("request_id").and_then(|v| v.as_str()).unwrap_or("").to_owned();
        assert!(!request_id.is_empty(), "request_id missing: {event}");
        assert!(
            blocked_request_ids.insert(request_id.clone()),
            "duplicate request_id {request_id} in kill-blocked-request events",
        );
    }

    // 7a. Story 3.3 review finding from Acceptance Auditor: AC #7 clause
    // 11 asks for an explicit assertion that the kill-activated and
    // kill-resumed events carry distinct request_ids. After the
    // HIGH #2 patch plumbed RequestTraceLayer into the control router,
    // each handler call gets a fresh ULID from the trace layer, so
    // the distinctness is mathematically guaranteed — but the assertion
    // locks in the invariant against future regressions.
    let activated_request_id =
        activated[0].get("request_id").and_then(|v| v.as_str()).unwrap_or("");
    let resumed_request_id = resumed[0].get("request_id").and_then(|v| v.as_str()).unwrap_or("");
    assert!(!activated_request_id.is_empty(), "activated request_id missing");
    assert!(!resumed_request_id.is_empty(), "resumed request_id missing");
    assert_ne!(
        activated_request_id, resumed_request_id,
        "kill-activated and kill-resumed must carry distinct request_ids (AC #7 clause 11)",
    );

    // 8. kill-activated fields.
    let activated = &activated[0];
    assert_eq!(activated["agent_id"], "system");
    assert_eq!(activated["service"], "permitlayer");
    assert_eq!(activated["scope"], "-");
    assert_eq!(activated["resource"], "kill-switch");
    assert_eq!(activated["outcome"], "ok");
    assert_eq!(activated["extra"]["cause"], "user-initiated");
    assert_eq!(activated["extra"]["tokens_invalidated"], 0);
    assert_eq!(activated["extra"]["in_flight_cancelled"], 0);
    assert_eq!(activated["extra"]["was_already_active"], false);

    // 9. kill-resumed fields.
    let resumed = &resumed[0];
    assert_eq!(resumed["agent_id"], "system");
    assert_eq!(resumed["service"], "permitlayer");
    assert_eq!(resumed["outcome"], "ok");
    let duration = resumed["extra"]["duration_killed_seconds"].as_u64().unwrap();
    // Sub-second test wall clock rounds to 0.
    assert_eq!(duration, 0);
    assert_eq!(resumed["extra"]["was_already_inactive"], false);

    // 10. Each kill-blocked-request has the expected per-request shape.
    for event in &blocked {
        assert_eq!(event["agent_id"], "unknown", "agent_id sentinel");
        assert_eq!(event["service"], "gmail");
        assert_eq!(event["scope"], "-");
        assert_eq!(event["resource"], "/v1/tools/gmail/users/me/profile");
        assert_eq!(event["outcome"], "denied");
        assert_eq!(event["extra"]["error_code"], "daemon_killed");
        assert_eq!(event["extra"]["method"], "GET");
    }
}

#[test]
fn kill_blocked_request_logs_even_for_health_probes() {
    let home = tempfile::TempDir::new().unwrap();
    let (child, port) = start_daemon(home.path());
    let _guard = DaemonGuard::new(child);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    // Kill, then probe /health twice.
    let out = run_cli(home.path(), port, &["kill"]);
    assert_eq!(out.status, Some(0));

    for _ in 0..2 {
        let raw = get_health(port);
        assert_eq!(parse_status_code(&raw), 403);
    }

    drop(_guard);
    std::thread::sleep(Duration::from_millis(100));

    let blocked =
        wait_for_audit_events(home.path(), "kill-blocked-request", 2, Duration::from_secs(2));
    assert_eq!(blocked.len(), 2, "expected 2 kill-blocked-request events for health probes");
    for event in &blocked {
        assert_eq!(event["service"], "-", "health probe service must be '-'");
        assert_eq!(event["resource"], "/health");
    }
}
