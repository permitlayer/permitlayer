//! End-to-end integration tests for `agentsso status --connections`
//! and `--watch` (Story 5.5 — FR83).
//!
//! Boots the real `agentsso` binary against an ephemeral home, exercises
//! the new `/v1/control/connections` endpoint via the CLI, and verifies
//! the table render + flag-validation paths.
//!
//! # Master key seam
//!
//! `AGENTSSO_TEST_MASTER_KEY_HEX=<64 hex>` short-circuits the OS
//! keychain bootstrap (Story 4.4 review trap — without this seam, daemon
//! spawning hangs on a macOS keychain dialog when run interactively).
//! Same constant + spawn pattern as `tests/agent_registry_e2e.rs`.

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::common::{agentsso_bin, free_port};

const TEST_MASTER_KEY_HEX: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// RAII guard wrapping the daemon `Child` so that any test panic
/// between `start_daemon` and the function exit still reaps the
/// process cleanly. Without this, `Child::Drop` on Unix doesn't
/// reap, leaving zombie agentsso processes that hold the test home
/// dir's PID file lock and break subsequent runs.
///
/// Test functions bind the returned guard as `_daemon` so the
/// compiler doesn't warn about an unused variable but its lifetime
/// (and thus the cleanup) extends to the end of the function.
///
/// **L1 review patch.**
struct DaemonHandle(Option<Child>);

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn start_daemon(home: &std::path::Path, port: u16) -> DaemonHandle {
    let child = Command::new(agentsso_bin())
        .arg("start")
        .arg("--bind-addr")
        .arg(format!("127.0.0.1:{port}"))
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .env("AGENTSSO_TEST_MASTER_KEY_HEX", TEST_MASTER_KEY_HEX)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start daemon");
    DaemonHandle(Some(child))
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

fn http_request(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> (u16, String) {
    let mut stream = std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_secs(2),
    )
    .expect("failed to connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let body_str = body.unwrap_or("");
    let mut req =
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n");
    if body.is_some() {
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body_str.len()
        ));
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    if !body_str.is_empty() {
        req.push_str(body_str);
    }

    stream.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let raw = String::from_utf8_lossy(&buf).to_string();
    let status = raw.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
    let body = raw.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    (status, body)
}

fn http_get_loopback(port: u16, path: &str, headers: &[(&str, &str)]) -> (u16, String) {
    http_request(port, "GET", path, headers, None)
}

fn http_post_loopback(
    port: u16,
    path: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> (u16, String) {
    http_request(port, "POST", path, headers, Some(body))
}

const SINGLE_POLICY_TOML: &str = r#"
[[policies]]
name = "policy-readonly"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
"#;

fn seed_single_policy(home: &std::path::Path) {
    let policies_dir = home.join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();
    std::fs::write(policies_dir.join("readonly.toml"), SINGLE_POLICY_TOML).unwrap();
}

/// Register an agent via the loopback control endpoint and return the
/// minted bearer token. Panics on any failure — this helper is on the
/// happy path of every test that exercises the tracker.
fn register_agent(port: u16, name: &str, policy: &str) -> String {
    let body = serde_json::json!({"name": name, "policy_name": policy}).to_string();
    let (status, resp_body) = http_post_loopback(port, "/v1/control/agent/register", &body, &[]);
    assert_eq!(status, 200, "agent register should succeed for {name}: {resp_body}");
    let parsed: serde_json::Value = serde_json::from_str(&resp_body).unwrap();
    parsed["bearer_token"].as_str().unwrap().to_owned()
}

/// Run `agentsso status` with the supplied flags as a subprocess,
/// returning `(exit_code, stdout, stderr)`. Sets `NO_COLOR=1` so
/// stdout assertions don't have to strip ANSI escapes.
fn run_status_cli(home: &std::path::Path, port: u16, args: &[&str]) -> (i32, String, String) {
    let output = Command::new(agentsso_bin())
        .arg("status")
        .args(args)
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .env("NO_COLOR", "1")
        // Override the default bind addr so the CLI talks to the test
        // daemon's port (the daemon was spawned with --bind-addr).
        .env("AGENTSSO_HTTP__BIND_ADDR", format!("127.0.0.1:{port}"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run agentsso status");
    let exit = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (exit, stdout, stderr)
}

// ── Tests ─────────────────────────────────────────────────────────

#[test]
fn connections_endpoint_returns_empty_on_fresh_boot() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_single_policy(home.path());
    let port = free_port();
    let _daemon = start_daemon(home.path(), port);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    let (status, body) = http_get_loopback(port, "/v1/control/connections", &[]);
    assert_eq!(status, 200, "endpoint must respond 200 on fresh boot: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json["connections"].is_array());
    assert_eq!(json["connections"].as_array().unwrap().len(), 0);
    assert!(json["generated_at"].as_str().unwrap().ends_with('Z'));
}

#[test]
fn status_connections_renders_empty_state() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_single_policy(home.path());
    let port = free_port();
    let _daemon = start_daemon(home.path(), port);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    let (exit, stdout, _stderr) = run_status_cli(home.path(), port, &["--connections"]);
    assert_eq!(exit, 0, "status --connections must exit 0 with empty tracker");
    assert!(stdout.contains("no agents connected yet"), "missing empty-state line: {stdout:?}");
    assert!(
        stdout.contains("agentsso agent register <name>"),
        "missing populate-command hint: {stdout:?}"
    );
    assert!(
        !stdout.contains("AGENT  "),
        "empty state must NOT render the AGENT header: {stdout:?}"
    );
}

#[test]
fn status_connections_renders_table_after_request() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_single_policy(home.path());
    let port = free_port();
    let _daemon = start_daemon(home.path(), port);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    let token = register_agent(port, "test-agent", "policy-readonly");

    // Fire one authenticated request through the proxy. The upstream
    // handler will return some non-2xx because credentials aren't
    // configured, but `ConnTrackLayer` runs BEFORE policy/upstream so
    // the tracker entry lands either way.
    let (_status, _body) = http_get_loopback(
        port,
        "/v1/tools/gmail/users/me/messages",
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", "gmail.readonly")],
    );

    let (exit, stdout, _stderr) = run_status_cli(home.path(), port, &["--connections"]);
    assert_eq!(exit, 0, "status --connections must exit 0 after a request");
    assert!(stdout.contains("test-agent"), "table must include the agent name: {stdout:?}");
    assert!(stdout.contains("AGENT"), "table must render the header row: {stdout:?}");
    assert!(stdout.contains("1 agents connected"), "footer must report 1: {stdout:?}");
}

#[test]
fn status_connections_json_emits_valid_json() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_single_policy(home.path());
    let port = free_port();
    let _daemon = start_daemon(home.path(), port);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    let token = register_agent(port, "json-agent", "policy-readonly");
    let (_status, _body) = http_get_loopback(
        port,
        "/v1/tools/gmail/users/me/messages",
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", "gmail.readonly")],
    );

    let (exit, stdout, _stderr) = run_status_cli(home.path(), port, &["--connections", "--json"]);
    assert_eq!(exit, 0, "status --connections --json must exit 0");
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("--json output must be valid JSON");
    let rows = json["connections"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "json output must include the recorded agent");
    assert_eq!(rows[0]["agent_name"], "json-agent");
    assert!(json["generated_at"].as_str().unwrap().ends_with('Z'));
}

#[test]
fn status_watch_without_connections_rejected() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_single_policy(home.path());
    let port = free_port();
    let _daemon = start_daemon(home.path(), port);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    let (exit, stdout, stderr) = run_status_cli(home.path(), port, &["--watch"]);
    assert_ne!(exit, 0, "--watch alone must fail");
    assert!(stderr.contains("invalid_flag_combination"), "stderr must explain: {stderr:?}");
    assert!(
        stderr.contains("--watch requires --connections"),
        "stderr must include hint: {stderr:?}"
    );
    assert!(stdout.is_empty(), "stdout must be empty on rejection: {stdout:?}");
}

#[test]
fn status_watch_with_json_rejected() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_single_policy(home.path());
    let port = free_port();
    let _daemon = start_daemon(home.path(), port);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    let (exit, stdout, stderr) =
        run_status_cli(home.path(), port, &["--connections", "--watch", "--json"]);
    assert_ne!(exit, 0, "--watch + --json must fail");
    assert!(stderr.contains("invalid_flag_combination"), "stderr must explain: {stderr:?}");
    assert!(
        stderr.contains("--watch and --json cannot be combined"),
        "stderr must include hint: {stderr:?}"
    );
    assert!(stdout.is_empty(), "stdout must be empty on rejection: {stdout:?}");
}

#[test]
fn status_connections_no_daemon_returns_3() {
    // No daemon spawned. The PID guard at the top of `cli::status::run`
    // exits 3 with "daemon not running".
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();

    let port = free_port(); // unused by the CLI when there's no daemon, but bind-addr env still gets resolved.
    let (exit, _stdout, stderr) = run_status_cli(home.path(), port, &["--connections"]);
    assert_eq!(exit, 3, "no-daemon path must exit 3");
    assert!(stderr.contains("daemon not running"), "stderr must explain: {stderr:?}");
}

#[test]
fn status_help_mentions_new_flags() {
    // No daemon required — clap prints help without dispatching.
    let output = Command::new(agentsso_bin())
        .arg("status")
        .arg("--help")
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run agentsso status --help");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(stdout.contains("--connections"), "help must mention --connections: {stdout}");
    assert!(stdout.contains("--watch"), "help must mention --watch: {stdout}");
    assert!(stdout.contains("--json"), "help must still mention --json: {stdout}");
}

#[test]
fn health_active_connections_reflects_tracker_count() {
    // Verify the AC #5 invariant end-to-end: `/health` reports the
    // tracker's live count, not the pre-Story-5.5 hardcoded 0.
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_single_policy(home.path());
    let port = free_port();
    let _daemon = start_daemon(home.path(), port);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    // Fresh boot → zero.
    let (_, body) = http_get_loopback(port, "/health", &[]);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["active_connections"], 0, "fresh boot should report 0: {body}");

    // Register + fire one request → one entry.
    let token = register_agent(port, "health-agent", "policy-readonly");
    let (_status, _body) = http_get_loopback(
        port,
        "/v1/tools/gmail/users/me/messages",
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", "gmail.readonly")],
    );

    let (_, body) = http_get_loopback(port, "/health", &[]);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["active_connections"], 1, "after one request should report 1: {body}");
}

#[test]
fn status_watch_redraws_at_least_twice_then_clean_exits_on_kill() {
    // Boot the daemon, spawn `status --connections --watch` as a
    // subprocess, let it run for ~5s, then kill it. Asserts the table
    // header appeared at least twice in captured stdout — proves the
    // 2s redraw loop fired more than once.
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_single_policy(home.path());
    let port = free_port();
    let _daemon = start_daemon(home.path(), port);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    // Seed at least one entry so the table has a row to redraw.
    let token = register_agent(port, "watch-agent", "policy-readonly");
    let (_status, _body) = http_get_loopback(
        port,
        "/v1/tools/gmail/users/me/messages",
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", "gmail.readonly")],
    );

    let mut child = Command::new(agentsso_bin())
        .arg("status")
        .arg("--connections")
        .arg("--watch")
        .env("AGENTSSO_PATHS__HOME", home.path().to_str().unwrap())
        .env("AGENTSSO_HTTP__BIND_ADDR", format!("127.0.0.1:{port}"))
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn watch subprocess");

    // ~5s = ~3 ticks at 2s interval (immediate first tick + 2 follow-ups).
    std::thread::sleep(Duration::from_secs(5));

    // SIGKILL path — the companion test below exercises the SIGINT
    // (Ctrl-C) arm of the watch loop's `tokio::select!`; this test
    // asserts the process doesn't hang on hard-kill cleanup and that
    // the redraw count is what we expect.
    let _ = child.kill();
    let output = child.wait_with_output().expect("watch subprocess wait failed");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();

    let header_hits = stdout.matches("AGENT").count();
    assert!(
        header_hits >= 2,
        "watch must redraw the table ≥2 times in 5s; saw {header_hits} (stdout: {stdout:?})"
    );
}

#[test]
#[cfg(unix)]
fn status_watch_sigint_exits_zero_with_clean_teardown() {
    // M1 review patch: the prior watch e2e test only exercised SIGKILL,
    // which bypasses the `tokio::signal::ctrl_c()` arm of the watch
    // loop's `select!` entirely. This test sends SIGINT (the signal
    // Ctrl-C produces) and asserts (a) the process exits with code 0,
    // (b) the trailing newline that lets the shell prompt land cleanly
    // appears in stdout, (c) the redraw fired at least once before
    // SIGINT — proving the loop ran AND the ctrl_c arm fired AND the
    // exit was clean. The cursor-show ANSI escape (`\x1b[?25h`) is
    // gated on `stdout().is_terminal()` (M3) — since the test pipes
    // stdout, it's correctly suppressed and we don't assert on it
    // here. The unit test path covers the TTY emit.
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_single_policy(home.path());
    let port = free_port();
    let _daemon = start_daemon(home.path(), port);
    assert!(wait_for_health(port, Duration::from_secs(5)));

    let token = register_agent(port, "sigint-agent", "policy-readonly");
    let (_status, _body) = http_get_loopback(
        port,
        "/v1/tools/gmail/users/me/messages",
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", "gmail.readonly")],
    );

    let child = Command::new(agentsso_bin())
        .arg("status")
        .arg("--connections")
        .arg("--watch")
        .env("AGENTSSO_PATHS__HOME", home.path().to_str().unwrap())
        .env("AGENTSSO_HTTP__BIND_ADDR", format!("127.0.0.1:{port}"))
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn watch subprocess");

    let child_pid = child.id();

    // Let the loop fire at least once (immediate first tick).
    std::thread::sleep(Duration::from_millis(500));

    // Send SIGINT — the watch loop's `tokio::signal::ctrl_c()` arm
    // should fire, print a trailing newline, and return Ok(()).
    let _ = kill(Pid::from_raw(child_pid as i32), Signal::SIGINT);

    let output = child.wait_with_output().expect("watch subprocess wait failed");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();

    assert_eq!(
        output.status.code(),
        Some(0),
        "SIGINT must exit with code 0 (got {:?}); stdout={stdout:?}",
        output.status.code()
    );
    let header_hits = stdout.matches("AGENT").count();
    assert!(
        header_hits >= 1,
        "loop must have redrawn at least once before SIGINT; saw {header_hits} headers in {stdout:?}"
    );
    // Trailing newline from the ctrl_c arm's `println!()`.
    assert!(
        stdout.ends_with('\n'),
        "stdout must end with the trailing newline from the ctrl_c arm; got {stdout:?}"
    );
}
