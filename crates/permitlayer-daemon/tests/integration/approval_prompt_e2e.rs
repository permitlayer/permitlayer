//! End-to-end integration test for Story 4.5 approval prompt dispatch.
//!
//! Boots the real `agentsso` binary in a subprocess with the
//! `AGENTSSO_TEST_APPROVAL_CANNED_RESPONSES` env var pre-seeded so
//! the daemon's `build_approval_service` wires a `CannedPromptReader`
//! into a real `CliApprovalService` — the full mpsc serializer +
//! always/never cache pipeline, just with the `dialoguer` prompt
//! replaced by a canned-response shim.
//!
//! This mirrors the test-seam pattern Story 4.4 established with
//! `AGENTSSO_TEST_MASTER_KEY_HEX` and covers the matrix from Task 9
//! of Story 4.5's spec:
//!
//! - `granted` → request passes, audit `approval-granted
//!   outcome_detail=operator-y`
//! - `denied` → 403 `policy.approval_required`, audit
//!   `approval-denied outcome_detail=operator-n`
//! - `always` → request passes + cache populated, second request
//!   served from cache without consuming a new canned outcome
//! - `never` → 403 + cache populated, second request cached deny
//! - `force_timeout_ms` → 403, audit `approval-timeout
//!   outcome_detail=timeout-Ns`
//! - `force_no_tty` → 503, audit `approval-timeout outcome_detail=no-tty`
//! - `auto-approve-reads` → request passes without touching the
//!   approval service at all
//! - reload clears cache → SIGHUP (or `POST /v1/control/reload`)
//!   clears the always/never cache so a cached decision no longer
//!   fires on the next request

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::common::agentsso_bin;

const TEST_MASTER_KEY_HEX: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// RAII guard for daemon subprocesses spawned by these tests.
///
/// On drop, kills the child and waits for it to exit. This guarantees
/// that even if a test assertion fails mid-test (which unwinds the
/// stack and skips the manual `daemon.kill().unwrap()` line), the
/// subprocess is reaped before the next test runs. Without this, a
/// failing test would leak a daemon holding its port, and the next
/// test would fail with "address in use" or wait_for_health timeout.
struct DaemonGuard {
    child: Option<Child>,
    /// Captured `stderr` handle, used by tests that need to read the
    /// startup banner. Taken via [`DaemonGuard::take_stderr`].
    stderr: Option<std::process::ChildStderr>,
}

impl DaemonGuard {
    /// Drop and return the captured stderr handle. After this call,
    /// `take_stderr` returns `None`.
    fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        self.stderr.take()
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Start the daemon with `--bind-addr 127.0.0.1:0`, then read the
/// OS-assigned port from the daemon's `AGENTSSO_BOUND_ADDR=<addr>`
/// stdout marker (emitted by `cli/start.rs:2168`). Returns the guard,
/// the resolved port, and the daemon's PID — the PID is used by
/// `assert_pid_matches` to detect a stray foreign daemon answering on
/// the same port.
///
/// The marker emit is on stdout via `println!`; we hand stdout off to
/// a background thread that drains the rest into `io::sink()` so the
/// daemon never blocks on a full pipe.
///
/// Story 7.7 register-then-auth flake mitigation: replaces the
/// `free_port()` pre-allocation pattern, which has a TOCTOU window
/// where another nextest worker can grab the freed port before our
/// daemon's `bind`. With zero-port the OS assigns a port atomically
/// with the daemon's actual `bind`, eliminating the race.
fn start_daemon_with_env_zero_port(
    home: &std::path::Path,
    extra_env: &[(&str, &str)],
) -> (DaemonGuard, u16, u32) {
    let mut cmd = Command::new(agentsso_bin());
    cmd.arg("start")
        .arg("--bind-addr")
        .arg("127.0.0.1:0")
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .env("AGENTSSO_TEST_MASTER_KEY_HEX", TEST_MASTER_KEY_HEX)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("failed to start daemon");
    let pid = child.id();
    let stderr = child.stderr.take();

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

    // Drain the rest of stdout to /dev/null in a background thread so
    // the daemon never blocks on a full kernel pipe.
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut reader, &mut std::io::sink());
    });

    (DaemonGuard { child: Some(child), stderr }, port, pid)
}

/// Story 7.7 register-then-auth flake guard: hit `/v1/control/whoami`
/// and assert the daemon's reported `pid` matches the spawned child
/// PID. If a stray foreign daemon (from another nextest worker) is
/// answering on our port — the only surviving live hypothesis after
/// the `free_port()` TOCTOU analysis — this fires loudly with both
/// PIDs instead of cascading into a confusing 401-on-fresh-token
/// failure.
///
/// **Story 7.7 P19**: probes `/v1/control/whoami` (loopback-gated)
/// rather than `/health` because `/health` no longer exposes PID
/// (it leaked daemon identity to LAN peers under `0.0.0.0` binds).
fn assert_daemon_pid_matches(port: u16, home: &std::path::Path, expected_pid: u32) {
    let ctl = crate::common::read_test_control_token(home);
    let (status, body) = crate::common::http_request_control(
        home,
        port,
        "GET",
        "/v1/control/whoami",
        None,
        &[("X-Agentsso-Control", ctl.as_str())],
    );
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
        Duration::from_secs(30),
    )
    .expect("failed to connect");
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();

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
    stream.read_to_end(&mut buf).expect("failed to read HTTP response from daemon");
    let raw = String::from_utf8_lossy(&buf).to_string();
    // Use expect (not unwrap_or(0)) so a malformed response surfaces a
    // diagnostic message instead of presenting as `status == 0` and
    // failing later with a confusing assertion.
    let status =
        raw.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or_else(|| {
            panic!("malformed HTTP response from daemon (could not parse status line): {raw:?}")
        });
    let body = raw.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    (status, body)
}

fn http_get(port: u16, path: &str, headers: &[(&str, &str)]) -> (u16, String) {
    http_request(port, "GET", path, headers, None)
}

#[allow(dead_code)] // retained for ad-hoc test additions
fn http_post(port: u16, path: &str, body: &str, headers: &[(&str, &str)]) -> (u16, String) {
    http_request(port, "POST", path, headers, Some(body))
}

const POLICY_PROMPT_TOML: &str = r#"
[[policies]]
name = "policy-prompt"
scopes = ["gmail.modify"]
resources = ["*"]
approval-mode = "prompt"
"#;

const POLICY_PROMPT_WITH_READS_TOML: &str = r#"
[[policies]]
name = "policy-prompt-reads"
scopes = ["gmail.readonly", "gmail.modify"]
resources = ["*"]
approval-mode = "prompt"
auto-approve-reads = true
"#;

const POLICY_GMAIL_READONLY_TOML: &str = r#"
[[policies]]
name = "gmail-read-only"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
"#;

fn seed_prompt_policy(home: &std::path::Path) {
    let policies_dir = home.join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();
    std::fs::write(policies_dir.join("prompt.toml"), POLICY_PROMPT_TOML).unwrap();
}

/// UX-overhaul Story 1: `gmail-read-only` is now a **managed**
/// (product) policy shipped in the bundle the daemon writes to
/// `policies-managed/` on every boot. Re-seeding an identically-named
/// policy into the OPERATOR layer is now an unmarked cross-layer
/// collision → the daemon fail-closes and refuses to boot (by
/// design). So this no longer writes a file: agents binding to
/// `gmail-read-only` resolve it from the managed layer. Kept as a
/// named no-op so the call sites still read intentionally ("this
/// test exercises an agent on the gmail-read-only policy") and
/// `POLICY_GMAIL_READONLY_TOML` documents what the managed bundle
/// provides.
fn seed_gmail_readonly_policy(_home: &std::path::Path) {
    // Intentionally empty — the managed layer provides
    // `gmail-read-only`. See doc comment above.
    let _ = POLICY_GMAIL_READONLY_TOML;
}

fn seed_prompt_with_reads_policy(home: &std::path::Path) {
    let policies_dir = home.join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();
    std::fs::write(policies_dir.join("prompt.toml"), POLICY_PROMPT_WITH_READS_TOML).unwrap();
}

/// Seed BOTH a prompt-mode Gmail policy AND an auto-mode Calendar
/// policy so one daemon can dispatch two approval modes in parallel.
/// Used by the Story 8.6 AC #4 test to demonstrate that auto-mode
/// requests never touch the approval service while a concurrent
/// prompt-mode request consumes a canned response.
fn seed_prompt_and_auto_policies(home: &std::path::Path) {
    const POLICY_AUTO_CAL_TOML: &str = r#"
[[policies]]
name = "policy-auto-cal"
scopes = ["calendar.readonly", "calendar.events"]
resources = ["*"]
approval-mode = "auto"
"#;
    let policies_dir = home.join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();
    std::fs::write(policies_dir.join("prompt.toml"), POLICY_PROMPT_TOML).unwrap();
    std::fs::write(policies_dir.join("auto.toml"), POLICY_AUTO_CAL_TOML).unwrap();
}

/// Full OAuth URIs for the gmail read-write tier, used so a request's
/// `gmail.modify` / `gmail.readonly` short name passes the proxy's
/// `tier ∩ granted_scopes` gate (Story 11.10). Mirrors the
/// `google-gmail` connector def's `[scopes]` map.
const GMAIL_RW_URIS: &[&str] = &[
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.modify",
];
const GMAIL_RO_URIS: &[&str] = &["https://www.googleapis.com/auth/gmail.readonly"];
const CALENDAR_RW_URIS: &[&str] = &[
    "https://www.googleapis.com/auth/calendar.readonly",
    "https://www.googleapis.com/auth/calendar.events",
];

/// Story 11.10: seed a `gmail` connection (read-write tier so both
/// `gmail.readonly` and `gmail.modify` pass the tier gate) + a binding
/// for `agent` carrying `policy`, plus a sealed access token so a
/// PolicyLayer-granted request can proceed through the service's tier
/// gate to dispatch. The connection `name = "gmail"` matches the
/// `/v1/tools/gmail/...` selector.
fn seed_gmail_binding(home: &std::path::Path, agent: &str, policy: &str) {
    crate::common::seed_connection_and_binding(
        home,
        agent,
        "google-gmail",
        "gmail",
        crate::common::SeedTier::ReadWrite,
        GMAIL_RW_URIS,
        Some(policy),
        None,
        TEST_MASTER_KEY_HEX,
        Some(b"ya29.test-access-token"),
    );
}

fn register_agent(port: u16, home: &std::path::Path, name: &str, policy: &str) -> String {
    let body = serde_json::json!({"name": name, "policy_name": policy}).to_string();
    let ctl = crate::common::read_test_control_token(home);
    let (status, resp_body) = crate::common::http_post_control(
        home,
        port,
        "/v1/control/agent/register",
        &body,
        &[("X-Agentsso-Control", ctl.as_str()), ("Content-Type", "application/json")],
    );
    assert_eq!(status, 200, "register should succeed: {resp_body}");
    let parsed: serde_json::Value = serde_json::from_str(&resp_body).unwrap();
    parsed["bearer_token"].as_str().unwrap().to_owned()
}

fn seal_gmail_credential(
    port: u16,
    home: &std::path::Path,
    connection_id: permitlayer_credential::ConnectionId,
) {
    let ctl = crate::common::read_test_control_token(home);
    // Story 11.12: the seal request keys on a real `connection_id` +
    // `connector_id`/`name`/`tier`; it seals the slots AND writes the
    // ConnectionRecord. The BYO client bundle is sealed into the Client slot.
    let client_bundle_json = serde_json::json!({
        "client_id": "123.apps.googleusercontent.com",
        "client_secret": "GOCSPX-test-client-secret",
        "project_id": "test-project",
        "v": 1,
    })
    .to_string();
    let body = serde_json::json!({
        "connection_id": connection_id.to_string(),
        "connector_id": "google-gmail",
        "name": "gmail",
        "tier": "read",
        "access_token": "ya29.test-access-token",
        "refresh_token": "1//test-refresh-token",
        "granted_scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
        "client_type": "byo",
        "client_bundle_json": client_bundle_json,
        "expires_in_secs": 3600,
        "if_exists": "replace"
    })
    .to_string();
    let (status, resp_body) = crate::common::http_post_control(
        home,
        port,
        "/v1/control/credentials/seal",
        &body,
        &[("X-Agentsso-Control", ctl.as_str()), ("Content-Type", "application/json")],
    );
    assert_eq!(status, 200, "credential seal should succeed: {resp_body}");
}

fn mcp_initialize_request() -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {
                "name": "approval-prompt-e2e",
                "version": "0.1.0"
            }
        }
    })
    .to_string()
}

/// Poll the audit directory for a JSON line matching `predicate`.
fn wait_for_audit_event(
    audit_dir: &std::path::Path,
    predicate: impl Fn(&serde_json::Value) -> bool,
    timeout: Duration,
) -> Option<serde_json::Value> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if audit_dir.exists()
            && let Ok(read) = std::fs::read_dir(audit_dir)
        {
            for entry in read.flatten() {
                if entry.path().extension().and_then(|e| e.to_str()) != Some("jsonl") {
                    continue;
                }
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    for line in content.lines() {
                        if let Ok(event) = serde_json::from_str::<serde_json::Value>(line)
                            && predicate(&event)
                        {
                            return Some(event);
                        }
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

/// Wait for an audit event matching `predicate`, or panic with a forensic
/// audit-dir dump.
///
/// **Why this wrapper exists.** The audit dispatcher
/// (`crates/permitlayer-core/src/audit/dispatcher.rs:120`) is fire-and-track:
/// `dispatch().await` returns once the producer-edge semaphore permit is held,
/// before the spawned write task has done any I/O. The HTTP response is sent
/// before the JSONL line is durable. Audit-polling tests like the ones in this
/// file race that gap and intermittently flake on hosted runners (macOS-14,
/// Linux, Windows) — the event sometimes appears 30-60s after the request
/// completes when the runner is heavily loaded.
///
/// The mitigation pattern ships in two parts:
/// 1. **60s timeout** — comfortably above the observed 30-40s outliers, well
///    below any failure mode that would mask a real product regression.
/// 2. **Forensic audit-dir dump on miss** — every JSONL file body is included
///    in the panic message so the next CI failure surfaces the actual events
///    that landed (with whatever divergent fields they have) instead of just
///    "didn't appear in N seconds." This is what catches "did the event land
///    with the wrong outcome_detail?" vs. "did it just not land?"
///
/// Origin: Story 7.7 cross-platform CI (the original 60s + dump pattern was
/// inlined at this file's `always_canned_response_populates_cache_second_request_served_from_cache`).
/// Rolled out across the family during the v0.3.0-rc.2 release cycle when
/// other tests in this file started hitting the same flake on Windows
/// (CI run 25187061552).
///
/// **Do not change the production dispatcher contract** — `JoinSet`-based
/// fire-and-track is intentional (Story 8.2 D1 / `dispatcher.rs:24-30`):
/// switching to `mpsc → single-consumer` would re-serialize all audit writes
/// through one point and undo the design. The right durability barrier in
/// production is `drain()` on shutdown; the right durability barrier in tests
/// is this helper.
#[track_caller]
fn assert_audit_event_or_dump(
    audit_dir: &std::path::Path,
    predicate: impl Fn(&serde_json::Value) -> bool,
    timeout: Duration,
    not_found_message: &str,
) -> serde_json::Value {
    if let Some(event) = wait_for_audit_event(audit_dir, predicate, timeout) {
        return event;
    }
    let mut audit_events = Vec::new();
    if audit_dir.exists() {
        for entry in std::fs::read_dir(audit_dir).into_iter().flatten().flatten() {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                audit_events.push(format!("=== {} ===\n{content}", entry.path().display()));
            }
        }
    }
    panic!(
        "{not_found_message} (waited {timeout:?}). Audit dir contents:\n{}",
        audit_events.join("\n\n")
    );
}

/// Positive contract for "PolicyLayer allowed this request through."
///
/// Once PolicyLayer allows a request, it is forwarded to the upstream
/// Google proxy — which, in these tests, has no real OAuth credentials
/// and therefore returns a non-policy error (401/4xx/5xx from the
/// upstream shape). The contract is NOT "request succeeded" but "the
/// request reached the upstream boundary without being rejected by
/// PolicyLayer."
///
/// A rejected request manifests as:
///   - HTTP 403 with `error.code` starting `policy.`
///   - HTTP 503 `policy.approval_unavailable` when approval wiring is broken
///
/// Anything else is on the far side of the policy boundary.
///
/// Story 8.6 P13 refactor — replaces the earlier
/// `assert_ne!(status, 403); assert_ne!(status, 503)` pattern which
/// only asserted a negative contract.
#[track_caller]
fn assert_policy_allowed(status: u16, body: &str, context: &str) {
    let json: serde_json::Value = serde_json::from_str(body).unwrap_or(serde_json::Value::Null);
    let code = json["error"]["code"].as_str().unwrap_or("");

    // A policy rejection either manifests as 403 + `policy.*` code, or
    // as 503 `policy.approval_unavailable`. Assert neither shape is
    // present. The body-code check is the load-bearing half — 403
    // from an upstream that rejects a bad token without a `policy.*`
    // code would not be a policy rejection, while a `policy.denied`
    // at a different status would be.
    let is_policy_reject = (status == 403 && code.starts_with("policy.")) || status == 503;
    assert!(
        !is_policy_reject,
        "{context}: PolicyLayer rejected request (status={status}, code={code:?}, body={body})"
    );

    // Defense-in-depth: any status reporting a `policy.*` code is
    // suspect regardless of the numeric status.
    assert!(
        !code.starts_with("policy."),
        "{context}: request produced policy.* error code (status={status}, code={code:?}, body={body})"
    );
}

// ──────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────

#[test]
fn granted_canned_response_allows_request_and_writes_approval_granted_audit() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_prompt_policy(home.path());
    let (_daemon, port, daemon_pid) = start_daemon_with_env_zero_port(
        home.path(),
        &[("AGENTSSO_TEST_APPROVAL_CANNED_RESPONSES", "allow")],
    );

    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, home.path(), daemon_pid);

    let token = register_agent(port, home.path(), "test-agent", "policy-prompt");
    seed_gmail_binding(home.path(), "test-agent", "policy-prompt");

    let (status, body) = http_get(
        port,
        "/v1/tools/gmail/users/me",
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", "gmail.modify")],
    );

    assert_policy_allowed(status, &body, "granted outcome");

    // Audit event for the approval-granted path.
    let audit_dir = home.path().join("audit");
    assert_audit_event_or_dump(
        &audit_dir,
        |e| {
            e["event_type"] == "approval-granted"
                && e["extra"]["outcome_detail"] == "operator-y"
                && e["extra"]["cached"] == false
        },
        Duration::from_secs(60),
        "expected approval-granted audit event with outcome_detail=operator-y",
    );
}

#[test]
fn denied_canned_response_returns_403_and_writes_approval_denied_audit() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_prompt_policy(home.path());
    let (_daemon, port, daemon_pid) = start_daemon_with_env_zero_port(
        home.path(),
        &[("AGENTSSO_TEST_APPROVAL_CANNED_RESPONSES", "deny")],
    );

    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, home.path(), daemon_pid);

    let token = register_agent(port, home.path(), "test-agent", "policy-prompt");
    seed_gmail_binding(home.path(), "test-agent", "policy-prompt");

    let (status, body) = http_get(
        port,
        "/v1/tools/gmail/users/me",
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", "gmail.modify")],
    );
    assert_eq!(status, 403, "denied outcome should 403: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["error"]["code"], "policy.approval_required");

    let audit_dir = home.path().join("audit");
    assert_audit_event_or_dump(
        &audit_dir,
        |e| {
            e["event_type"] == "approval-denied"
                && e["extra"]["outcome_detail"] == "operator-n"
                && e["extra"]["cached"] == false
        },
        Duration::from_secs(60),
        "expected approval-denied audit event with outcome_detail=operator-n",
    );
}

#[test]
fn always_canned_response_populates_cache_second_request_served_from_cache() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_prompt_policy(home.path());
    // Seed just one "always" decision. If the cache works, the
    // second request is served from the cache and does NOT consume
    // the next canned outcome (which there isn't — empty queue → Aborted
    // → Denied — so a missing cache would turn the second request into 403).
    let (_daemon, port, daemon_pid) = start_daemon_with_env_zero_port(
        home.path(),
        &[("AGENTSSO_TEST_APPROVAL_CANNED_RESPONSES", "always")],
    );

    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, home.path(), daemon_pid);

    let token = register_agent(port, home.path(), "test-agent", "policy-prompt");
    seed_gmail_binding(home.path(), "test-agent", "policy-prompt");

    // First request consumes the "always" canned decision.
    let (status1, body1) = http_get(
        port,
        "/v1/tools/gmail/users/me",
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", "gmail.modify")],
    );
    assert_policy_allowed(status1, &body1, "first request via always");

    // Second identical request — if cache hit fires, this passes too.
    // If cache misses, the queue is empty → Aborted → Denied → 403.
    let (status2, body2) = http_get(
        port,
        "/v1/tools/gmail/users/me",
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", "gmail.modify")],
    );
    assert_policy_allowed(status2, &body2, "second request via cache hit");

    // Audit: the second request emitted `approval-granted cached=true
    // outcome_detail=operator-a-cached`. See `assert_audit_event_or_dump`
    // doc comment for why audit-polling assertions in this file use 60s
    // + forensic dump.
    let audit_dir = home.path().join("audit");
    assert_audit_event_or_dump(
        &audit_dir,
        |e| {
            e["event_type"] == "approval-granted"
                && e["extra"]["outcome_detail"] == "operator-a-cached"
                && e["extra"]["cached"] == true
        },
        Duration::from_secs(60),
        "expected approval-granted cached=true event from second (cache-hit) request",
    );
}

#[test]
fn never_canned_response_populates_cache_second_request_cached_deny() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_prompt_policy(home.path());
    let (_daemon, port, daemon_pid) = start_daemon_with_env_zero_port(
        home.path(),
        &[("AGENTSSO_TEST_APPROVAL_CANNED_RESPONSES", "never")],
    );

    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, home.path(), daemon_pid);

    let token = register_agent(port, home.path(), "test-agent", "policy-prompt");
    seed_gmail_binding(home.path(), "test-agent", "policy-prompt");

    let (status1, _) = http_get(
        port,
        "/v1/tools/gmail/users/me",
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", "gmail.modify")],
    );
    assert_eq!(status1, 403, "never outcome 403 on first request");

    let (status2, body2) = http_get(
        port,
        "/v1/tools/gmail/users/me",
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", "gmail.modify")],
    );
    assert_eq!(status2, 403, "never cache hit 403 on second request: {body2}");
    let json2: serde_json::Value = serde_json::from_str(&body2).unwrap();
    assert_eq!(json2["error"]["code"], "policy.approval_required");

    // Audit: cached deny emitted on the second request.
    let audit_dir = home.path().join("audit");
    assert_audit_event_or_dump(
        &audit_dir,
        |e| {
            e["event_type"] == "approval-denied"
                && e["extra"]["outcome_detail"] == "operator-never-cached"
                && e["extra"]["cached"] == true
        },
        Duration::from_secs(60),
        "expected approval-denied cached=true event from never-cache hit",
    );
}

#[test]
fn timeout_outcome_returns_403_approval_timeout_via_force_timeout_env() {
    // Force the reader to sleep 2s while the approval timeout is 1s.
    // The tokio::select! arm in handle_one_prompt races the sleep
    // against the blocking reader and fires the Timeout branch.
    let home = tempfile::tempdir().unwrap();
    let config_dir = home.path().join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    // Seed a 1-second approval timeout via daemon.toml.
    std::fs::write(config_dir.join("daemon.toml"), "[approval]\ntimeout_seconds = 1\n").unwrap();
    seed_prompt_policy(home.path());

    let (_daemon, port, daemon_pid) = start_daemon_with_env_zero_port(
        home.path(),
        &[("AGENTSSO_TEST_APPROVAL_FORCE_TIMEOUT_MS", "2000")],
    );

    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, home.path(), daemon_pid);

    let token = register_agent(port, home.path(), "test-agent", "policy-prompt");
    seed_gmail_binding(home.path(), "test-agent", "policy-prompt");

    let (status, body) = http_get(
        port,
        "/v1/tools/gmail/users/me",
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", "gmail.modify")],
    );
    assert_eq!(status, 403, "timeout should 403: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    // Story 4.5 review: timeouts get a distinct error code from
    // operator denials so agents can implement smart retry.
    assert_eq!(json["error"]["code"], "policy.approval_timeout");

    let audit_dir = home.path().join("audit");
    assert_audit_event_or_dump(
        &audit_dir,
        |e| {
            e["event_type"] == "approval-timeout"
                && e["extra"]["outcome_detail"].as_str().is_some_and(|s| s.starts_with("timeout-"))
        },
        Duration::from_secs(60),
        "expected approval-timeout event",
    );
}

#[test]
fn unavailable_no_tty_returns_503_approval_unavailable() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_prompt_policy(home.path());
    let (mut daemon, port, daemon_pid) = start_daemon_with_env_zero_port(
        home.path(),
        &[("AGENTSSO_TEST_APPROVAL_FORCE_NO_TTY", "1")],
    );

    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, home.path(), daemon_pid);

    // Story 4.5 Task 10.2: assert the literal startup banner text is
    // emitted to stderr. Read up to ~4 KB from the captured stderr
    // pipe (non-blocking via a 200ms read timeout) so the test does
    // not hang if the banner is missing.
    let mut stderr_buf = vec![0u8; 4096];
    let stderr_text = if let Some(mut stderr) = daemon.take_stderr() {
        // Spawn a thread to read stderr with a soft deadline. The
        // banner is printed during startup, well before wait_for_health
        // returns, so there is content waiting in the pipe.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let n = stderr.read(&mut stderr_buf).unwrap_or(0);
            stderr_buf.truncate(n);
            let _ = tx.send(String::from_utf8_lossy(&stderr_buf).to_string());
        });
        rx.recv_timeout(Duration::from_secs(30)).unwrap_or_default()
    } else {
        String::new()
    };
    assert!(
        stderr_text.contains("approval: prompts disabled (no TTY)"),
        "expected no-TTY startup banner on stderr; saw: {stderr_text:?}"
    );

    let token = register_agent(port, home.path(), "test-agent", "policy-prompt");
    seed_gmail_binding(home.path(), "test-agent", "policy-prompt");

    let (status, body) = http_get(
        port,
        "/v1/tools/gmail/users/me",
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", "gmail.modify")],
    );
    assert_eq!(status, 503, "no-tty should 503: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["error"]["code"], "policy.approval_unavailable");

    let audit_dir = home.path().join("audit");
    // Story 4.5 review: Unavailable now emits its own event type
    // (matching the HTTP error code) instead of being conflated with
    // approval-timeout. Operators grepping for `approval-unavailable`
    // in audit.jsonl find these events directly.
    assert_audit_event_or_dump(
        &audit_dir,
        |e| e["event_type"] == "approval-unavailable" && e["extra"]["outcome_detail"] == "no-tty",
        Duration::from_secs(60),
        "expected approval-unavailable outcome_detail=no-tty event",
    );
}

#[test]
fn auto_approve_reads_bypasses_approval_service_for_readonly_scope() {
    // Policy has approval-mode=prompt + auto-approve-reads=true.
    // Readonly scope should bypass the approval service entirely —
    // verified by the fact that the daemon is started with an empty
    // canned queue but the request still succeeds. (If the short-circuit
    // failed, the empty canned queue would mean the request falls through
    // to a real prompt → CannedPromptReader pops nothing → returns
    // Aborted → fail-closed Denied → 403.)
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_prompt_with_reads_policy(home.path());
    let (_daemon, port, daemon_pid) = start_daemon_with_env_zero_port(
        home.path(),
        &[("AGENTSSO_TEST_APPROVAL_CANNED_RESPONSES", "")],
    );

    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, home.path(), daemon_pid);

    let token = register_agent(port, home.path(), "test-agent", "policy-prompt-reads");
    seed_gmail_binding(home.path(), "test-agent", "policy-prompt-reads");

    let (status, body) = http_get(
        port,
        "/v1/tools/gmail/users/me",
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", "gmail.readonly")],
    );
    assert_policy_allowed(status, &body, "readonly scope bypasses approval prompt");

    // Audit: the short-circuit emits `approval-granted
    // outcome_detail=auto-approve-reads cached=false`.
    //
    // Story 4.5 review: `cached=false` is the corrected semantics — the
    // auto-approve-reads short-circuit never touches the always/never
    // session cache, so claiming `cached=true` would conflate "cache
    // hit" with "policy-level rule bypass" and corrupt downstream
    // analytics. The `outcome_detail = "auto-approve-reads"` sentinel
    // is the unique discriminator.
    let audit_dir = home.path().join("audit");
    assert_audit_event_or_dump(
        &audit_dir,
        |e| {
            e["event_type"] == "approval-granted"
                && e["extra"]["outcome_detail"] == "auto-approve-reads"
                && e["extra"]["cached"] == false
        },
        Duration::from_secs(60),
        "expected approval-granted outcome_detail=auto-approve-reads cached=false audit event",
    );
}

#[test]
fn reload_clears_approval_cache() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_prompt_policy(home.path());
    // Canned list: one always, then a deny. Without reload, the
    // second request hits the cache and is allowed. After reload,
    // the cache is cleared and the second request consumes the deny.
    //
    // Story 7.7: zero-port + PID match closes the `free_port()`
    // TOCTOU window that surfaced as the "agent is not registered"
    // 401 on macos-15-intel. The daemon binds atomically on port 0,
    // emits `AGENTSSO_BOUND_ADDR=` on stdout, and we assert /health
    // PID matches our spawned child PID before any auth call.
    let (_daemon, port, daemon_pid) = start_daemon_with_env_zero_port(
        home.path(),
        &[("AGENTSSO_TEST_APPROVAL_CANNED_RESPONSES", "always,deny")],
    );

    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, home.path(), daemon_pid);

    let token = register_agent(port, home.path(), "test-agent", "policy-prompt");
    seed_gmail_binding(home.path(), "test-agent", "policy-prompt");

    // First request: always → populates cache, should allow.
    let (status1, body1) = http_get(
        port,
        "/v1/tools/gmail/users/me",
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", "gmail.modify")],
    );
    assert_policy_allowed(status1, &body1, "first request populates cache via always");

    // POST /v1/control/reload to clear the cache.
    let ctl_for_reload = crate::common::read_test_control_token(home.path());
    let (reload_status, reload_body) = crate::common::http_post_control(
        home.path(),
        port,
        "/v1/control/reload",
        "",
        &[("X-Agentsso-Control", ctl_for_reload.as_str()), ("Content-Type", "application/json")],
    );
    assert_eq!(reload_status, 200, "reload should succeed: {reload_body}");

    // Second request after reload: cache was cleared, so this
    // consumes the next canned outcome (deny) → 403.
    let (status2, body2) = http_get(
        port,
        "/v1/tools/gmail/users/me",
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", "gmail.modify")],
    );
    assert_eq!(
        status2, 403,
        "after reload, cache cleared, second request consumes canned deny: {body2}"
    );
    let json2: serde_json::Value = serde_json::from_str(&body2).unwrap();
    assert_eq!(json2["error"]["code"], "policy.approval_required");
}

/// Story 8.6 AC #4 — two approval policies side-by-side on one
/// daemon, with concurrent requests. The auto-mode request must
/// complete without ever consuming a canned prompt response, while
/// the prompt-mode request must produce the expected
/// `approval-granted` audit event.
///
/// Seeds two policies (`policy-prompt` prompt-mode, `policy-auto-cal`
/// auto-mode) and fires two parallel requests against different
/// agent identities. The canned queue holds exactly one `allow`; a
/// mis-implementation where auto-mode fell through to the prompt
/// path would either (a) consume the allow and leave the prompt
/// request stalled, or (b) exhaust the queue and 503 both requests.
/// Correct behavior is: auto-mode never touches the queue, prompt
/// request consumes the single allow, no `approval-*` event appears
/// for the auto-mode agent.
#[test]
fn auto_mode_dispatches_without_prompt_in_parallel_with_prompt_policy() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_prompt_and_auto_policies(home.path());
    let (_daemon, port, daemon_pid) = start_daemon_with_env_zero_port(
        home.path(),
        &[("AGENTSSO_TEST_APPROVAL_CANNED_RESPONSES", "allow")],
    );

    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, home.path(), daemon_pid);

    let prompt_token = register_agent(port, home.path(), "prompt-agent", "policy-prompt");
    seed_gmail_binding(home.path(), "prompt-agent", "policy-prompt");
    let auto_token = register_agent(port, home.path(), "auto-agent", "policy-auto-cal");
    // auto-agent → calendar connection (read tier covers `calendar.events`)
    // + binding carrying `policy-auto-cal`. The connection `name =
    // "calendar"` matches the `/v1/tools/calendar/...` selector.
    crate::common::seed_connection_and_binding(
        home.path(),
        "auto-agent",
        "google-calendar",
        "calendar",
        crate::common::SeedTier::Read,
        CALENDAR_RW_URIS,
        Some("policy-auto-cal"),
        None,
        TEST_MASTER_KEY_HEX,
        Some(b"ya29.test-calendar-token"),
    );

    // Dispatch both requests in parallel. `std::thread::spawn` suffices —
    // the test's http client is blocking, and the two agents route
    // through different policies so there is no cross-request state.
    let prompt_handle = std::thread::spawn(move || {
        http_get(
            port,
            "/v1/tools/gmail/users/me",
            &[
                ("authorization", &format!("Bearer {prompt_token}")),
                ("x-agentsso-scope", "gmail.modify"),
            ],
        )
    });
    let auto_handle = std::thread::spawn(move || {
        http_get(
            port,
            "/v1/tools/calendar/users/me/calendarList",
            &[
                ("authorization", &format!("Bearer {auto_token}")),
                ("x-agentsso-scope", "calendar.events"),
            ],
        )
    });

    let (prompt_status, prompt_body) = prompt_handle.join().unwrap();
    let (auto_status, auto_body) = auto_handle.join().unwrap();

    // Neither request may hit the policy-rejection path. Upstream
    // errors (no real Google creds) are expected and OK.
    assert_policy_allowed(prompt_status, &prompt_body, "parallel prompt request");
    assert_policy_allowed(auto_status, &auto_body, "parallel auto request");

    let audit_dir = home.path().join("audit");

    // Prompt-mode agent MUST produce an approval-granted event.
    assert_audit_event_or_dump(
        &audit_dir,
        |e| {
            e["event_type"] == "approval-granted"
                && e["agent_id"] == "prompt-agent"
                && e["extra"]["outcome_detail"] == "operator-y"
        },
        Duration::from_secs(60),
        "expected approval-granted event for prompt-agent (outcome_detail=operator-y)",
    );

    // Auto-mode agent MUST NOT produce any `approval-*` event. The
    // auto dispatch short-circuits before the approval service is
    // consulted, so no approval-granted / approval-denied /
    // approval-unavailable / approval-timeout event exists.
    let auto_approval_event = wait_for_audit_event(
        &audit_dir,
        |e| {
            e["agent_id"] == "auto-agent"
                && e["event_type"].as_str().is_some_and(|s| s.starts_with("approval-"))
        },
        Duration::from_millis(500),
    );
    assert!(
        auto_approval_event.is_none(),
        "auto-mode must not emit any approval-* event; got {auto_approval_event:?}"
    );
}

// ------------------------------------------------------------------
// Story 8.7: approval-timeout hot-reload + stub-detection.
// ------------------------------------------------------------------

/// Story 8.7 AC #8. End-to-end proof that editing
/// `[approval] timeout_seconds` in `daemon.toml` and firing
/// `POST /v1/control/reload` updates the atomic that `PolicyLayer`
/// reads per-request, without restarting the daemon.
///
/// The original daemon is booted with `timeout_seconds = 30` and the
/// `force_timeout = 2000ms` env-var seam. After reload the new
/// `timeout_seconds = 2` flows into the atomic; the force-timeout env
/// stays at 2000ms, so the per-request timeout race is:
/// `tokio::select! { sleep(2) <-> reader.sleep(2000ms) }`. The
/// approval-timeout path fires first, returning 403
/// `policy.approval_timeout` in well under the pre-reload 30s. The
/// assertion caps walltime at 5 seconds — far below 30s but well above
/// the ~2s expected value, buying CI-jitter headroom.
#[test]
fn approval_timeout_updates_via_sighup_without_restart() {
    let home = tempfile::tempdir().unwrap();
    let config_dir = home.path().join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    // Start with a large timeout so the pre-reload behavior would
    // trivially exceed the 5s post-reload bound if the atomic wasn't
    // updated.
    std::fs::write(config_dir.join("daemon.toml"), "[approval]\ntimeout_seconds = 30\n").unwrap();
    seed_prompt_policy(home.path());

    let (_daemon, port, daemon_pid) = start_daemon_with_env_zero_port(
        home.path(),
        &[("AGENTSSO_TEST_APPROVAL_FORCE_TIMEOUT_MS", "2500")],
    );

    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, home.path(), daemon_pid);

    let token = register_agent(port, home.path(), "test-agent", "policy-prompt");
    seed_gmail_binding(home.path(), "test-agent", "policy-prompt");

    // Swap the config to a 2-second timeout and hit the HTTP reload.
    std::fs::write(config_dir.join("daemon.toml"), "[approval]\ntimeout_seconds = 2\n").unwrap();
    let ctl_for_reload = crate::common::read_test_control_token(home.path());
    let (reload_status, reload_body) = crate::common::http_post_control(
        home.path(),
        port,
        "/v1/control/reload",
        "",
        &[("X-Agentsso-Control", ctl_for_reload.as_str()), ("Content-Type", "application/json")],
    );
    assert_eq!(reload_status, 200, "reload should succeed: {reload_body}");

    // Fire the prompt-required request and measure walltime.
    let t0 = Instant::now();
    let (status, body) = http_get(
        port,
        "/v1/tools/gmail/users/me",
        &[("authorization", &format!("Bearer {token}")), ("x-agentsso-scope", "gmail.modify")],
    );
    let elapsed = t0.elapsed();

    assert_eq!(status, 403, "post-reload timeout should 403: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["error"]["code"], "policy.approval_timeout");
    // Upper bound far under the pre-reload 30s timeout but well above
    // the ~2s expected value (the force-timeout reader sleeps 2.5s, so
    // the 2s approval-timeout fires first).
    assert!(
        elapsed < Duration::from_secs(5),
        "post-reload timeout walltime should be well under 5s; got {elapsed:?}"
    );
}

/// Story 7.32 regression guard: an empty post-boot vault directory is
/// not enough to warn operators anymore. Boot creates vault/ as part
/// of normal daemon setup; only a sealed credential should trigger a
/// proxy rebuild attempt.
///
/// The old Story 8.7 behavior warned on directory existence alone,
/// which turned fresh installs into noisy "restart daemon" diagnostics.
#[test]
fn reload_does_not_warn_on_empty_post_boot_vault() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    // Deliberately do NOT create `vault/` — forces the daemon into
    // the 501-stub branch at boot.
    assert!(!home.path().join("vault").exists());

    let (_daemon, port, daemon_pid) = start_daemon_with_env_zero_port(home.path(), &[]);
    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, home.path(), daemon_pid);

    // Create an empty `vault/` after boot. This is not sufficient for
    // proxy activation and should not emit the stale-stub diagnostic.
    std::fs::create_dir_all(home.path().join("vault")).unwrap();

    let ctl_for_reload = crate::common::read_test_control_token(home.path());
    let (status, body) = crate::common::http_post_control(
        home.path(),
        port,
        "/v1/control/reload",
        "",
        &[("X-Agentsso-Control", ctl_for_reload.as_str()), ("Content-Type", "application/json")],
    );
    assert_eq!(status, 200, "reload should succeed: {body}");

    let audit_dir = home.path().join("audit");
    let event = wait_for_audit_event(
        &audit_dir,
        |e| {
            e["event_type"] == "config-reload-stub-detected"
                && e["extra"]["vault_present"] == true
                && e["extra"]["proxy_service_active"] == false
        },
        Duration::from_secs(1),
    );
    assert!(event.is_none(), "empty post-boot vault should not emit stale-stub audit: {event:?}");
}

#[test]
fn mcp_initialize_succeeds_after_credential_seal_without_restart() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_gmail_readonly_policy(home.path());
    assert!(!home.path().join("vault").exists(), "test must boot through the stub-only proxy path");

    let (_daemon, port, daemon_pid) = start_daemon_with_env_zero_port(home.path(), &[]);
    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, home.path(), daemon_pid);

    let bearer = register_agent(port, home.path(), "openclaw", "gmail-read-only");
    let auth_header = format!("Bearer {bearer}");
    let init_body = mcp_initialize_request();
    let headers = [
        ("authorization", auth_header.as_str()),
        ("x-agentsso-scope", "gmail.readonly"),
        ("accept", "application/json, text/event-stream"),
    ];

    let (stub_status, stub_body) = http_post(port, "/mcp/gmail", &init_body, &headers);
    assert_eq!(
        stub_status, 501,
        "before credentials are sealed, /mcp/gmail should still be the stub route: {stub_body}"
    );
    let stub_json: serde_json::Value =
        serde_json::from_str(&stub_body).expect("stub response body should be JSON");
    assert_eq!(stub_json["error"]["code"], "route.not_implemented");
    assert!(
        stub_json["error"]["available_routes"]
            .as_array()
            .expect("available_routes should be an array")
            .iter()
            .any(|route| route == "/mcp/gmail"),
        "stub response should list the post-7.32 Gmail route: {stub_body}"
    );

    // Story 11.12/11.13: seal under a real minted ULID via the reshaped
    // seal endpoint (which also writes the ConnectionRecord named
    // "gmail"). Then seed the agent→connection BINDING under the SAME id
    // so the proxy authz path (bearer → agent → binding → connection)
    // resolves on `/mcp/gmail`.
    let gmail_conn_id = permitlayer_credential::ConnectionId::generate();
    seal_gmail_credential(port, home.path(), gmail_conn_id);
    crate::common::seed_connection_and_binding_with_id(
        home.path(),
        "openclaw",
        gmail_conn_id,
        "google-gmail",
        "gmail",
        crate::common::SeedTier::Read,
        GMAIL_RO_URIS,
        Some("gmail-read-only"),
        None,
    );

    let ctl_for_reload = crate::common::read_test_control_token(home.path());
    let (reload_status, reload_body) = crate::common::http_post_control(
        home.path(),
        port,
        "/v1/control/reload",
        "",
        &[("X-Agentsso-Control", ctl_for_reload.as_str()), ("Content-Type", "application/json")],
    );
    assert_eq!(reload_status, 200, "reload should activate proxy routes: {reload_body}");
    assert_daemon_pid_matches(port, home.path(), daemon_pid);

    let (mcp_status, mcp_body) = http_post(port, "/mcp/gmail", &init_body, &headers);
    assert_eq!(
        mcp_status, 200,
        "after credential seal + reload, /mcp/gmail initialize should succeed without restart: {mcp_body}"
    );
    assert!(
        mcp_body.contains("protocolVersion") && mcp_body.contains("serverInfo"),
        "initialize response should include MCP server info: {mcp_body}"
    );
}

#[test]
fn first_connection_seal_activates_proxy_without_manual_reload() {
    // Operator-flow regression guard (review 2026-06-08): on a freshly-
    // booted daemon (no credentials at boot → stub /mcp routes), the FIRST
    // `connection add` seal must activate the proxy ON ITS OWN — without a
    // manual `agentsso reload`. The seal handler now calls
    // `activate_proxy_routes_if_ready`; this proves it end-to-end.
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_gmail_readonly_policy(home.path());
    assert!(!home.path().join("vault").exists(), "test must boot through the stub-only proxy path");

    let (_daemon, port, daemon_pid) = start_daemon_with_env_zero_port(home.path(), &[]);
    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, home.path(), daemon_pid);

    let bearer = register_agent(port, home.path(), "openclaw", "gmail-read-only");
    let auth_header = format!("Bearer {bearer}");
    let init_body = mcp_initialize_request();
    let headers = [
        ("authorization", auth_header.as_str()),
        ("x-agentsso-scope", "gmail.readonly"),
        ("accept", "application/json, text/event-stream"),
    ];

    // Before any seal: stub route (proxy not active).
    let (stub_status, _stub_body) = http_post(port, "/mcp/gmail", &init_body, &headers);
    assert_eq!(stub_status, 501, "pre-seal /mcp/gmail should be the stub route");

    // Seal the first connection + its binding — but DO NOT call reload.
    let gmail_conn_id = permitlayer_credential::ConnectionId::generate();
    seal_gmail_credential(port, home.path(), gmail_conn_id);
    crate::common::seed_connection_and_binding_with_id(
        home.path(),
        "openclaw",
        gmail_conn_id,
        "google-gmail",
        "gmail",
        crate::common::SeedTier::Read,
        GMAIL_RO_URIS,
        Some("gmail-read-only"),
        None,
    );

    // No reload! The seal handler must have already activated the proxy.
    let (mcp_status, mcp_body) = http_post(port, "/mcp/gmail", &init_body, &headers);
    assert_daemon_pid_matches(port, home.path(), daemon_pid); // same daemon — no restart
    assert_eq!(
        mcp_status, 200,
        "the seal alone must activate the proxy (no manual reload): {mcp_body}"
    );
    assert!(
        mcp_body.contains("protocolVersion") && mcp_body.contains("serverInfo"),
        "initialize response should include MCP server info: {mcp_body}"
    );
}

#[test]
fn unknown_route_returns_json_body() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_gmail_readonly_policy(home.path());

    let (_daemon, port, daemon_pid) = start_daemon_with_env_zero_port(home.path(), &[]);
    assert!(wait_for_health(port, Duration::from_secs(5)));
    assert_daemon_pid_matches(port, home.path(), daemon_pid);

    let bearer = register_agent(port, home.path(), "openclaw", "gmail-read-only");
    let auth_header = format!("Bearer {bearer}");
    let headers = [
        ("authorization", auth_header.as_str()),
        ("x-agentsso-scope", "gmail.readonly"),
        ("accept", "application/json, text/event-stream"),
        ("content-type", "application/json"),
    ];
    let (status, body) = http_post(port, "/mcp", "{}", &headers);
    assert_eq!(status, 404, "bare /mcp should be a JSON 404 after 7.32: {body}");
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("unknown route response body should be JSON");
    assert_eq!(json["error"]["code"], "route.not_found");
    assert!(
        json["error"]["request_id"].as_str().is_some_and(|id| id.len() == 26),
        "404 route response should include a ULID request_id: {body}"
    );
    assert!(
        json["error"]["available_routes"]
            .as_array()
            .expect("available_routes should be an array")
            .iter()
            .any(|route| route == "/mcp/gmail"),
        "404 route response should list available MCP routes: {body}"
    );
}
