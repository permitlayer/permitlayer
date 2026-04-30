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

use crate::common::agentsso_bin;

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

/// Start the daemon with `--bind-addr 127.0.0.1:0`, then read the
/// OS-assigned port from the daemon's `AGENTSSO_BOUND_ADDR=<addr>`
/// stdout marker (emitted by `cli/start.rs:2168`). Returns the guard,
/// resolved port, and daemon PID for `assert_daemon_pid_matches`.
///
/// Story 7.7 register-then-auth flake mitigation: zero-port avoids
/// the `free_port()` TOCTOU race entirely.
fn start_daemon_zero_port(home: &std::path::Path) -> (DaemonHandle, u16, u32) {
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
    let pid = child.id();

    let stdout =
        child.stdout.take().expect("child.stdout must be Stdio::piped() for marker reading");
    let mut reader = std::io::BufReader::new(stdout);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    let mut port: Option<u16> = None;
    use std::io::BufRead;
    while Instant::now() < deadline {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => panic!("daemon stdout closed before AGENTSSO_BOUND_ADDR marker"),
            Ok(_) => {
                if let Some(rest) = line.trim_end().strip_prefix("AGENTSSO_BOUND_ADDR=") {
                    let addr: std::net::SocketAddr = rest
                        .parse()
                        .unwrap_or_else(|e| panic!("malformed AGENTSSO_BOUND_ADDR={rest:?}: {e}"));
                    port = Some(addr.port());
                    break;
                }
            }
            Err(e) => panic!("error reading daemon stdout: {e}"),
        }
    }
    let port = port.expect("timed out waiting for AGENTSSO_BOUND_ADDR marker on daemon stdout");

    std::thread::spawn(move || {
        let _ = std::io::copy(&mut reader, &mut std::io::sink());
    });

    (DaemonHandle(Some(child)), port, pid)
}

/// Fire one authenticated proxy request to seed a tracker entry for
/// `agent_name`, then poll `/v1/control/connections` until that
/// specific agent name appears, or panic with a self-diagnosing dump.
///
/// **Why this helper exists.** The earlier `wait_for_connection_recorded`
/// pattern silently masked three different failure modes as a single
/// `tracker did not record the request within Ns` panic:
///   1. The proxied request returned 401 `auth.invalid_token` — the
///      register-then-auth flake captured by Story 7.7 Phase 4a
///      (`2bf572b`). The request never reached `ConnTrackLayer` because
///      `AuthLayer` rejected it.
///   2. The TCP read timed out (`http_request` swallows read errors and
///      returns `status == 0`) — the request never completed end-to-end.
///   3. The request reached `ConnTrackLayer`, recorded synchronously
///      via `DashMap::entry`, but the snapshot at `/v1/control/connections`
///      didn't see it under sufficient delay (genuinely the case the
///      original deadline guarded — if this is what we're seeing,
///      something deeper is wrong than just timing).
///
/// **What the production middleware actually does.** Contrary to the
/// previous comment ("ConnTrackLayer's DashMap insert can lag the
/// response"), `ConnTrackService::call` records *synchronously* before
/// forwarding to the inner service (`conn_track.rs:107-109`), and
/// `ConnTracker::record_request` uses `DashMap::entry` which holds the
/// shard write-lock for the full lookup-or-create
/// (`conn_tracker.rs:151-185`). There is no async insert path. The
/// previous helper's comment was wrong — the real risk is auth /
/// request scheduling under CI load, which this helper now diagnoses
/// rather than retries.
///
/// On the originally-failing path (`status_watch_sigint_exits_zero_with_clean_teardown`
/// hitting `tracker did not record the request within 5s` on
/// macos-15-intel in CI run 25189312574), the previous helper provided
/// no evidence to distinguish (1)/(2)/(3). This helper makes the next
/// failure self-diagnosing.
fn seed_tracked_connection_or_dump(
    port: u16,
    daemon_pid: u32,
    home: &std::path::Path,
    token: &str,
    agent_name: &str,
    scope: &str,
) {
    // 1. Fire the proxied request. Don't discard the status/body — they
    //    are the first piece of forensic evidence.
    let (proxy_status, proxy_body) = http_get_loopback(
        port,
        "/v1/tools/gmail/users/me/messages",
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", scope)],
    );

    // 2. Refuse to proceed on the auth-flake signature. The helper's
    //    job is to seed a tracker entry; if the auth lookup didn't see
    //    the just-registered agent, the request never reached
    //    `ConnTrackLayer`. Pretending otherwise wastes the poll budget
    //    and mints a misleading panic message.
    if proxy_status == 401 && proxy_body.contains("auth.invalid_token") {
        dump_and_panic(
            "AUTH-FLAKE pre-tracker (401 auth.invalid_token)",
            port,
            daemon_pid,
            home,
            token,
            agent_name,
            proxy_status,
            &proxy_body,
        );
    }

    // 3. Refuse to proceed on a TCP read failure. `http_request` swallows
    //    read errors and returns `status == 0` with empty body — that
    //    means the daemon socket connect succeeded but the response read
    //    hit the 5s timeout or a connection reset. The request may or
    //    may not have reached `ConnTrackLayer`; we can't tell without
    //    the response status. Dump and bail rather than poll.
    if proxy_status == 0 {
        dump_and_panic(
            "PROXY-REQUEST-TIMEOUT-OR-RESET (status=0; http_request swallowed a read error)",
            port,
            daemon_pid,
            home,
            token,
            agent_name,
            proxy_status,
            &proxy_body,
        );
    }

    // 4. Poll `/v1/control/connections` looking for the specific agent
    //    we just seeded. Polling for "any non-empty array" used to
    //    permit false positives from leftover state on shared-port
    //    runs; with zero-port + PID-match (Story 7.7) that's no longer
    //    a vector, but the per-agent check is still the correct
    //    invariant — the tracker has THIS agent's entry, not just SOME
    //    entry.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let (status, body) = http_get_loopback(port, "/v1/control/connections", &[]);
        if status == 200
            && let Ok(json) = serde_json::from_str::<serde_json::Value>(&body)
            && let Some(arr) = json.get("connections").and_then(|c| c.as_array())
            && arr
                .iter()
                .any(|conn| conn.get("agent_name").and_then(|v| v.as_str()) == Some(agent_name))
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // 5. Tracker poll exhausted. By now we've ruled out the auth-flake
    //    and a fully-failed proxy request, so the question becomes
    //    "where between `ConnTrackLayer::call` and the snapshot read
    //    did this go?" — capture every relevant piece of state.
    dump_and_panic(
        "TRACKER-EMPTY-FOR-AGENT (proxy returned successfully but tracker has no entry for the seeded agent within 5s)",
        port,
        daemon_pid,
        home,
        token,
        agent_name,
        proxy_status,
        &proxy_body,
    );
}

/// Forensic-dump panic helper for `seed_tracked_connection_or_dump`.
///
/// Captures every piece of state that distinguishes the candidate
/// failure modes: was the proxy response 401? did the tracker see this
/// agent? does the registry know about the agent? is the daemon the
/// one we spawned? are the on-disk agent files what we expect?
///
/// 8 args is genuinely the right shape — each is independent forensic
/// state and bundling them in a struct would be theater. Allow the
/// clippy lint locally.
#[allow(clippy::too_many_arguments)]
#[track_caller]
fn dump_and_panic(
    failure_kind: &str,
    port: u16,
    daemon_pid: u32,
    home: &std::path::Path,
    token: &str,
    agent_name: &str,
    proxy_status: u16,
    proxy_body: &str,
) -> ! {
    let (conn_status, conn_body) = http_get_loopback(port, "/v1/control/connections", &[]);
    let (list_status, list_body) = http_get_loopback(port, "/v1/control/agent/list", &[]);
    let (whoami_status, whoami_body) = http_get_loopback(port, "/v1/control/whoami", &[]);
    let (health_status, health_body) = http_get_loopback(port, "/health", &[]);

    let agents_dir = home.join("agents");
    let mut on_disk: Vec<String> = Vec::new();
    match std::fs::read_dir(&agents_dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?").to_owned();
                let content =
                    std::fs::read_to_string(&path).unwrap_or_else(|e| format!("<read error: {e}>"));
                let truncated: String = content.chars().take(500).collect();
                on_disk.push(format!("  {name}: {truncated}"));
            }
        }
        Err(e) => {
            on_disk.push(format!("  <unable to read {}: {e}>", agents_dir.display()));
        }
    }
    if on_disk.is_empty() {
        on_disk.push(format!("  <{} is empty>", agents_dir.display()));
    }
    let token_prefix: String = token.chars().take(12).collect();

    panic!(
        "TRACKER-FLAKE-DUMP ({failure_kind}):\n\
         seeded_agent_name={agent_name}\n\
         daemon_pid={daemon_pid}\n\
         port={port}\n\
         token_first_12={token_prefix}\n\
         proxy_response: status={proxy_status} body={proxy_body}\n\
         /v1/control/connections: status={conn_status} body={conn_body}\n\
         /v1/control/agent/list: status={list_status} body={list_body}\n\
         /v1/control/whoami: status={whoami_status} body={whoami_body}\n\
         /health: status={health_status} body={health_body}\n\
         on-disk agents/ contents:\n{}\n",
        on_disk.join("\n"),
    );
}

/// Story 7.7 register-then-auth flake guard: hit `/v1/control/whoami`
/// and assert the daemon's reported `pid` matches the spawned child
/// PID.
///
/// **Story 7.7 P19**: probes `/v1/control/whoami` (loopback-gated)
/// rather than `/health` because `/health` no longer exposes PID
/// (it leaked daemon identity to LAN peers under `0.0.0.0` binds).
fn assert_daemon_pid_matches(port: u16, expected_pid: u32) {
    let (status, body) = http_get_loopback(port, "/v1/control/whoami", &[]);
    assert_eq!(status, 200, "/v1/control/whoami should return 200, got {status}: {body}");
    let json: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("/v1/control/whoami response not JSON: {e}\nbody: {body}"));
    let reported_pid = json
        .get("pid")
        .and_then(|p| p.as_u64())
        .unwrap_or_else(|| panic!("/v1/control/whoami response missing numeric pid field: {body}"));
    let expected_pid = u64::from(expected_pid);
    assert_eq!(
        reported_pid, expected_pid,
        "free_port TOCTOU: /v1/control/whoami on port {port} reported pid {reported_pid} \
         but our spawned daemon is pid {expected_pid}. Another test's daemon stole this \
         port between free_port() pre-allocation and our daemon's bind."
    );
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
    let (_daemon, port, daemon_pid) = start_daemon_zero_port(home.path());
    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, daemon_pid);

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
    let (_daemon, port, daemon_pid) = start_daemon_zero_port(home.path());
    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, daemon_pid);

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
    let (_daemon, port, daemon_pid) = start_daemon_zero_port(home.path());
    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, daemon_pid);

    let token = register_agent(port, "test-agent", "policy-readonly");

    // Fire one authenticated request through the proxy and confirm the
    // tracker has THIS agent's entry. `seed_tracked_connection_or_dump`
    // distinguishes auth-flake (401), proxy-timeout (status=0), and
    // tracker-empty failures with a forensic dump on miss — see its
    // doc comment for the candidate-cause mapping.
    seed_tracked_connection_or_dump(
        port,
        daemon_pid,
        home.path(),
        &token,
        "test-agent",
        "gmail.readonly",
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
    let (_daemon, port, daemon_pid) = start_daemon_zero_port(home.path());
    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, daemon_pid);

    let token = register_agent(port, "json-agent", "policy-readonly");
    seed_tracked_connection_or_dump(
        port,
        daemon_pid,
        home.path(),
        &token,
        "json-agent",
        "gmail.readonly",
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
    let (_daemon, port, daemon_pid) = start_daemon_zero_port(home.path());
    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, daemon_pid);

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
    let (_daemon, port, daemon_pid) = start_daemon_zero_port(home.path());
    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, daemon_pid);

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

    // No daemon: the CLI exits 3 before any port is used, but `bind-addr`
    // env still gets resolved into a string. A literal placeholder port
    // is fine; we are NOT going to bind it anywhere.
    let port: u16 = 1;
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
    //
    // Story 7.7 review patch (2026-04-29): macos-15-intel surfaces
    // intermittent failures where the post-request `/health` poll
    // reports `active_connections == 0` instead of `1`. Initial
    // hypothesis (tracker decrement-on-disconnect race) was refuted
    // by reading conn_track.rs — the tracker has NO decrement path;
    // entries persist for `idle_timeout_secs` (default 300s) and are
    // removed only by background sweep. The likely actual cause is
    // that the proxied request below failed at AuthLayer (401), so
    // ConnTrackLayer never recorded the AgentId and the DashMap
    // stayed empty. The previous version of this test discarded the
    // proxied response status and surfaced auth failures only as a
    // downstream `active_connections == 0` mismatch — confusing.
    //
    // The assertion below now PINS the proxied response to "not
    // auth.invalid_token" so the next macos-15-intel failure tells
    // us unambiguously whether it's auth (Story 7.7 register-then-
    // auth flake) or tracker (genuine bug we'd need to investigate).
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_single_policy(home.path());
    // Story 7.7: zero-port + PID match avoids the `free_port()` TOCTOU
    // window. The 401-cascade described above is downstream of the
    // wrong daemon answering on our port; PID match catches that
    // upstream of the request loop.
    let (_daemon, port, daemon_pid) = start_daemon_zero_port(home.path());
    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, daemon_pid);

    // Fresh boot → zero.
    let (_, body) = http_get_loopback(port, "/health", &[]);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["active_connections"], 0, "fresh boot should report 0: {body}");

    // Register + fire one request → one entry.
    let token = register_agent(port, "health-agent", "policy-readonly");
    let (status, body) = http_get_loopback(
        port,
        "/v1/tools/gmail/users/me/messages",
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", "gmail.readonly")],
    );
    // Pre-condition: the request reached at least the policy layer.
    // If THIS assert fires (status == 401), the proxied request
    // never made it past AuthLayer → ConnTrackLayer didn't record →
    // the active_connections check below would spuriously fail.
    // Surfacing the auth result here makes the test self-diagnosing.
    let auth_failure_body = if status == 401 { Some(body.clone()) } else { None };
    assert!(
        auth_failure_body.is_none(),
        "auth-flake guard: proxied request returned 401 BEFORE the tracker recorded — \
         this is the Story 7.7 register-then-auth visibility race. \
         The active_connections=0 symptom below is downstream of this. \
         Response body: {}",
        auth_failure_body.unwrap_or_default()
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
    let (_daemon, port, daemon_pid) = start_daemon_zero_port(home.path());
    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, daemon_pid);

    // Seed at least one entry so the table has a row to redraw.
    let token = register_agent(port, "watch-agent", "policy-readonly");
    seed_tracked_connection_or_dump(
        port,
        daemon_pid,
        home.path(),
        &token,
        "watch-agent",
        "gmail.readonly",
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
    let (_daemon, port, daemon_pid) = start_daemon_zero_port(home.path());
    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, daemon_pid);

    let token = register_agent(port, "sigint-agent", "policy-readonly");
    seed_tracked_connection_or_dump(
        port,
        daemon_pid,
        home.path(),
        &token,
        "sigint-agent",
        "gmail.readonly",
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
