//! End-to-end integration test for the Story 4.4 agent identity registry.
//!
//! Boots the real `agentsso` binary in a subprocess against an
//! ephemeral home directory, then exercises the full
//! register → authenticate → policy-evaluation → remove lifecycle via
//! HTTP. Mirrors the harness pattern from `policy_enforcement_e2e.rs`
//! and `kill_resume_e2e.rs`.
//!
//! # Master key seam
//!
//! The daemon's bearer-token validation requires a master-derived HMAC
//! subkey. In production this comes from the OS keychain (provisioned
//! by `cli::start::ensure_master_key_bootstrapped` at daemon boot —
//! Story 1.15 moved this from lazy-via-setup to eager-at-start).
//! For tests we set `AGENTSSO_TEST_MASTER_KEY_HEX=<64 hex chars>` to
//! short-circuit `ensure_master_key_bootstrapped` and return a
//! deterministic master key without touching the keychain. The seam
//! is `#[cfg(debug_assertions)]`-gated so release builds compile it
//! out entirely — see `cli::start::ensure_master_key_bootstrapped`
//! for the full set of `AGENTSSO_TEST_*` seams.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use crate::common::{
    DaemonTestConfig, assert_daemon_pid_matches, start_daemon as start_daemon_common,
    wait_for_health,
};

// Story 8.8b round-1 review: this file used to define its own
// private `start_daemon` (with `AGENTSSO_TEST_MASTER_KEY_HEX`
// inlined) and its own `wait_for_health(port, timeout)`. Both are
// now provided by `crate::common`. Local helpers retained below
// are file-specific (header-aware HTTP, `wait_for_audit_event`)
// and have no canonical equivalent yet.

/// Spawn the daemon for this test file's pattern: short-circuit the
/// keystore via `AGENTSSO_TEST_MASTER_KEY_HEX` (Story 4.4 boot
/// dependency on a master-derived agent-lookup subkey), bind to
/// `port`, point at `home`. Returns the canonical [`DaemonHandle`]
/// so each test gets Drop-kill-on-panic for free.
fn start_daemon(home: &std::path::Path) -> crate::common::DaemonHandle {
    start_daemon_common(DaemonTestConfig {
        // Story 7.7: `port: 0` lets the OS assign atomically with bind;
        // `start_daemon_common` reads the actual port from the daemon's
        // `AGENTSSO_BOUND_ADDR=` stdout marker and stores it on
        // `DaemonHandle.port`.
        port: 0,
        home: home.to_path_buf(),
        // `set_test_master_key: true` (default) wires
        // `AGENTSSO_TEST_MASTER_KEY_HEX` to the canonical
        // `common::TEST_MASTER_KEY_HEX` constant.
        ..Default::default()
    })
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

const TWO_POLICY_TOML_A: &str = r#"
[[policies]]
name = "policy-readonly"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
"#;

const TWO_POLICY_TOML_B: &str = r#"
[[policies]]
name = "policy-write"
scopes = ["gmail.modify"]
resources = ["*"]
approval-mode = "auto"
"#;

fn seed_two_policies(home: &std::path::Path) {
    let policies_dir = home.join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();
    std::fs::write(policies_dir.join("readonly.toml"), TWO_POLICY_TOML_A).unwrap();
    std::fs::write(policies_dir.join("write.toml"), TWO_POLICY_TOML_B).unwrap();
}

/// Register an agent via the loopback control endpoint and return the
/// minted bearer token. Panics on any failure — the test is hard-fail
/// on the happy path because every assertion downstream depends on it.
fn register_agent(port: u16, name: &str, policy: &str) -> String {
    let body = serde_json::json!({"name": name, "policy_name": policy}).to_string();
    let (status, resp_body) = http_post_loopback(port, "/v1/control/agent/register", &body, &[]);
    assert_eq!(
        status, 200,
        "agent register should succeed for {name} → {policy}, got {status}: {resp_body}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&resp_body).unwrap();
    assert_eq!(parsed["status"], "ok");
    let token = parsed["bearer_token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("agt_v2_"), "bearer token must use the agt_v2_ prefix: {token}");
    token
}

fn remove_agent(port: u16, name: &str) -> bool {
    let body = serde_json::json!({"name": name}).to_string();
    let (status, resp_body) = http_post_loopback(port, "/v1/control/agent/remove", &body, &[]);
    assert_eq!(status, 200, "agent remove should succeed for {name}, got {status}: {resp_body}");
    let parsed: serde_json::Value = serde_json::from_str(&resp_body).unwrap();
    parsed["removed"].as_bool().unwrap_or(false)
}

fn list_agents(port: u16) -> serde_json::Value {
    let (status, resp_body) = http_get_loopback(port, "/v1/control/agent/list", &[]);
    assert_eq!(status, 200, "agent list should succeed, got {status}: {resp_body}");
    serde_json::from_str(&resp_body).unwrap()
}

#[test]
fn full_register_auth_policy_lifecycle() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_two_policies(home.path());

    let daemon = start_daemon(home.path());
    let port = daemon.port;

    assert!(wait_for_health(port), "daemon should boot with two policies");
    assert_daemon_pid_matches(&daemon);

    // 1. Register two agents bound to different policies.
    let token_readonly = register_agent(port, "readonly-agent", "policy-readonly");
    let token_write = register_agent(port, "write-agent", "policy-write");

    // 2. Authenticated request matching the readonly agent's scope:
    //    PolicyLayer ALLOWS the request through. Without upstream
    //    credentials the proxy then returns a downstream error, but
    //    the critical assertion is that the response is NOT a
    //    `policy.denied` body and NOT a `auth.invalid_token` body.
    let (_status, body) = http_get_loopback(
        port,
        "/v1/tools/gmail/users/me/messages",
        &[
            ("authorization", &format!("Bearer {token_readonly}")),
            ("x-agentsso-scope", "gmail.readonly"),
        ],
    );
    let json: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let code = json["error"]["code"].as_str().unwrap_or("");
    assert_ne!(code, "policy.denied", "PolicyLayer should allow gmail.readonly: {body}");
    assert_ne!(code, "auth.invalid_token", "auth should accept the registered token: {body}");
    assert_ne!(code, "auth.missing_token");

    // 3. Same readonly agent attempts a `gmail.modify` request →
    //    PolicyLayer denies with `policy.denied` and the policy_name
    //    of the readonly policy.
    let (status, body) = http_get_loopback(
        port,
        "/v1/tools/gmail/users/me/messages",
        &[
            ("authorization", &format!("Bearer {token_readonly}")),
            ("x-agentsso-scope", "gmail.modify"),
        ],
    );
    assert_eq!(status, 403, "scope deny should fire: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["error"]["code"], "policy.denied");
    assert_eq!(json["error"]["policy_name"], "policy-readonly");
    assert_eq!(json["error"]["denied_scope"], "gmail.modify");

    // 4. The write agent CAN do `gmail.modify` — same path, different
    //    token → PolicyLayer routes to a different policy.
    let (_status, body) = http_get_loopback(
        port,
        "/v1/tools/gmail/users/me/messages",
        &[
            ("authorization", &format!("Bearer {token_write}")),
            ("x-agentsso-scope", "gmail.modify"),
        ],
    );
    let json: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let code = json["error"]["code"].as_str().unwrap_or("");
    assert_ne!(code, "policy.denied", "write agent should allow gmail.modify: {body}");

    // 5. Bogus token → 401 invalid_token (NOT policy.denied — auth runs first).
    let (status, body) = http_get_loopback(
        port,
        "/v1/tools/gmail/users/me/messages",
        &[
            ("authorization", "Bearer agt_v2_garbageDoesNotMatchAnyAgent"),
            ("x-agentsso-scope", "gmail.readonly"),
        ],
    );
    assert_eq!(status, 401, "bogus token should 401: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["error"]["code"], "auth.invalid_token");

    // 6. No header → 401 missing_token.
    let (status, body) = http_get_loopback(port, "/v1/tools/gmail/users/me/messages", &[]);
    assert_eq!(status, 401, "missing header should 401: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["error"]["code"], "auth.missing_token");

    // 7. Health endpoint bypasses auth even with no Authorization.
    let (status, _) = http_get_loopback(port, "/v1/health", &[]);
    assert_eq!(status, 200, "health endpoint must bypass auth");

    // 8. List shows both agents and never leaks the bearer token or
    //    its hash.
    let listing = list_agents(port);
    let agents = listing["agents"].as_array().unwrap();
    assert_eq!(agents.len(), 2);
    let raw = serde_json::to_string(&listing).unwrap();
    assert!(!raw.contains(&token_readonly), "list output must not leak the readonly token");
    assert!(!raw.contains(&token_write), "list output must not leak the write token");
    assert!(!raw.contains("argon2"), "list output must not leak the Argon2id hash material");

    // 9. Remove the readonly agent → its token stops working.
    let removed = remove_agent(port, "readonly-agent");
    assert!(removed, "remove should report removed=true");
    let (status, body) = http_get_loopback(
        port,
        "/v1/tools/gmail/users/me/messages",
        &[
            ("authorization", &format!("Bearer {token_readonly}")),
            ("x-agentsso-scope", "gmail.readonly"),
        ],
    );
    assert_eq!(status, 401, "removed agent's token must 401: {body}");

    // The write agent's token is unaffected.
    let (status, body) = http_get_loopback(
        port,
        "/v1/tools/gmail/users/me/messages",
        &[
            ("authorization", &format!("Bearer {token_write}")),
            ("x-agentsso-scope", "gmail.modify"),
        ],
    );
    assert_ne!(status, 401, "write token must still authenticate: {body}");

    // 10. Audit assertion: the agent-auth-denied event from step 5
    //     (bogus token) was written with the correct token_prefix.
    //     Use a firm assertion (Story 4.3 review MED #3 lesson).
    //     Story 7.6b round-1 review: TOKEN_PREFIX_AUDIT_LEN shrunk
    //     8 → 7 (was leaking the first letter of the agent name).
    //     Expected prefix is now the literal version-prefix `agt_v2_`.
    let audit_dir = home.path().join("audit");
    let found = wait_for_audit_event(
        &audit_dir,
        |event| {
            event["event_type"] == "agent-auth-denied"
                && event["extra"]["token_prefix"] == "agt_v2_"
        },
        Duration::from_secs(2),
    );
    assert!(
        found.is_some(),
        "expected an agent-auth-denied audit event with token_prefix='agt_v2_'"
    );

    // DaemonHandle Drop SIGKILLs on scope exit; explicit graceful
    // shutdown is unnecessary for these tests (none of them assert
    // on captured stdout/stderr after shutdown).
    drop(daemon);
}

#[test]
fn register_with_unknown_policy_returns_422() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_two_policies(home.path());

    let daemon = start_daemon(home.path());
    let port = daemon.port;

    assert!(wait_for_health(port));
    assert_daemon_pid_matches(&daemon);

    let body = serde_json::json!({"name": "agent1", "policy_name": "nonexistent"}).to_string();
    let (status, resp_body) = http_post_loopback(port, "/v1/control/agent/register", &body, &[]);
    assert_eq!(status, 422, "unknown policy should be 422, body: {resp_body}");
    let parsed: serde_json::Value = serde_json::from_str(&resp_body).unwrap();
    assert_eq!(parsed["status"], "error");
    assert_eq!(parsed["code"], "agent.unknown_policy");

    // DaemonHandle Drop SIGKILLs on scope exit; explicit graceful
    // shutdown is unnecessary for these tests (none of them assert
    // on captured stdout/stderr after shutdown).
    drop(daemon);
}

#[test]
fn register_duplicate_name_returns_409() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_two_policies(home.path());

    let daemon = start_daemon(home.path());
    let port = daemon.port;

    assert!(wait_for_health(port));
    assert_daemon_pid_matches(&daemon);

    let _token = register_agent(port, "duplicate-test", "policy-readonly");
    let body =
        serde_json::json!({"name": "duplicate-test", "policy_name": "policy-readonly"}).to_string();
    let (status, resp_body) = http_post_loopback(port, "/v1/control/agent/register", &body, &[]);
    assert_eq!(status, 409, "duplicate name should be 409, body: {resp_body}");
    let parsed: serde_json::Value = serde_json::from_str(&resp_body).unwrap();
    assert_eq!(parsed["code"], "agent.duplicate_name");

    // DaemonHandle Drop SIGKILLs on scope exit; explicit graceful
    // shutdown is unnecessary for these tests (none of them assert
    // on captured stdout/stderr after shutdown).
    drop(daemon);
}

/// Poll the audit directory for a JSON line matching `predicate`.
fn wait_for_audit_event(
    audit_dir: &std::path::Path,
    predicate: impl Fn(&serde_json::Value) -> bool,
    timeout: Duration,
) -> Option<serde_json::Value> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if audit_dir.exists() {
            for entry in std::fs::read_dir(audit_dir).ok()?.flatten() {
                if entry.path().extension().and_then(|e| e.to_str()) != Some("jsonl") {
                    continue;
                }
                let content = std::fs::read_to_string(entry.path()).ok()?;
                for line in content.lines() {
                    if let Ok(event) = serde_json::from_str::<serde_json::Value>(line)
                        && predicate(&event)
                    {
                        return Some(event);
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

/// Cross-user / cross-home `agentsso agent register` works.
///
/// Pins the architectural property "any caller on loopback who can reach
/// the daemon's bind address may register an agent" by simulating the
/// "different OS user" scenario without actually needing two real users:
///
/// - Daemon home: `home_daemon` (tempdir A) — daemon writes its PID file
///   here.
/// - Caller home: `home_caller` (tempdir B) — the CLI is invoked with
///   `AGENTSSO_PATHS__HOME=<home_caller>`, so its config-loader thinks
///   it's a different user with no PID file in its own home.
/// - The CLI is told the daemon's bind address via
///   `AGENTSSO_HTTP__BIND_ADDR`.
///
/// Pre-this-fix, the CLI's PID-file pre-check would short-circuit with
/// `daemon_not_running` because `home_caller/agentsso.pid` doesn't
/// exist. Post-fix, the PID short-circuit is gone for `register`, so
/// the HTTP call proceeds and succeeds.
///
/// `#[cfg(unix)]`-gated only because Windows `cmd.env_clear()` plus
/// Winsock interactions in the larger subprocess matrix have been
/// flake-prone (see `kill_resume_e2e.rs::setup_blocked_when_killed`);
/// the change being tested is platform-independent.
#[cfg(unix)]
#[test]
fn agent_register_works_cross_home() {
    use std::process::Command;

    let home_daemon = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home_daemon.path().join("config")).unwrap();
    seed_two_policies(home_daemon.path());

    let daemon = start_daemon(home_daemon.path());
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon should boot");

    // Caller's home is a *separate* tempdir with NO PID file.
    let home_caller = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home_caller.path().join("policies")).unwrap();

    let bind_addr = format!("127.0.0.1:{port}");
    let output = Command::new(crate::common::agentsso_bin())
        .env_clear()
        .envs(crate::common::forward_windows_required_env())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home_caller.path())
        .env("AGENTSSO_PATHS__HOME", home_caller.path())
        .env("AGENTSSO_HTTP__BIND_ADDR", &bind_addr)
        .arg("agent")
        .arg("register")
        .arg("cross-home-agent")
        .arg("--policy")
        .arg("policy-readonly")
        .output()
        .expect("failed to spawn agentsso agent register");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(0),
        "register should succeed cross-home (the daemon under home_daemon serves loopback). \
         exit={:?}\nstdout={stdout}\nstderr={stderr}",
        output.status.code(),
    );
    assert!(stdout.contains("cross-home-agent"), "expected agent name in stdout; stdout={stdout}",);
    assert!(stdout.contains("agt_v2_"), "expected bearer token in stdout; stdout={stdout}",);
    // Negative pin: must NOT have rendered the pre-fix `daemon_not_running` banner
    // just because the caller's home had no PID file.
    assert!(
        !stderr.contains("daemon_not_running"),
        "daemon_not_running should not fire for cross-home register; stderr={stderr}",
    );
}
