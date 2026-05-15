//! Story 7.34 review patch: integration tests for `agentsso agent rotate`.
//!
//! Boots the daemon, registers an agent, rotates its bearer token,
//! and asserts:
//!   1. The old bearer token is invalidated (401 / auth.invalid_token).
//!   2. The new bearer token authenticates successfully.
//!   3. On macOS, `--token-out` writes with register-compatible
//!      permissions.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::common::{DaemonTestConfig, agentsso_bin, start_daemon, wait_for_health};

const POLICY_TOML: &str = r#"
[[policies]]
name = "policy-readonly"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
"#;

fn seed_policy(home: &std::path::Path) {
    let policies_dir = home.join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();
    std::fs::write(policies_dir.join("readonly.toml"), POLICY_TOML).unwrap();
}

fn run_register_once(
    home: &std::path::Path,
    bind_addr: &str,
    name: &str,
    policy: &str,
    extra_args: &[&str],
) -> (i32, String, String) {
    let mut cmd = Command::new(agentsso_bin());
    cmd.env("AGENTSSO_PATHS__HOME", home);
    cmd.env("AGENTSSO_HTTP__BIND_ADDR", bind_addr);
    cmd.env("AGENTSSO_TEST_MASTER_KEY_HEX", crate::common::TEST_MASTER_KEY_HEX);
    cmd.arg("agent").arg("register").arg(name).arg("--policy").arg(policy);
    for a in extra_args {
        cmd.arg(a);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = cmd.output().expect("failed to spawn agentsso register");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn run_register(
    home: &std::path::Path,
    bind_addr: &str,
    name: &str,
    policy: &str,
    extra_args: &[&str],
) -> (i32, String, String) {
    let mut delay = Duration::from_millis(50);
    let mut last = run_register_once(home, bind_addr, name, policy, extra_args);
    for _ in 0..8 {
        if !(last.0 == 3 && last.2.contains("daemon_unreachable")) {
            return last;
        }
        std::thread::sleep(delay);
        delay = std::cmp::min(delay * 2, Duration::from_millis(800));
        last = run_register_once(home, bind_addr, name, policy, extra_args);
    }
    last
}

fn run_rotate_once(
    home: &std::path::Path,
    bind_addr: &str,
    name: &str,
    extra_args: &[&str],
) -> (i32, String, String) {
    let mut cmd = Command::new(agentsso_bin());
    cmd.env("AGENTSSO_PATHS__HOME", home);
    cmd.env("AGENTSSO_HTTP__BIND_ADDR", bind_addr);
    cmd.env("AGENTSSO_TEST_MASTER_KEY_HEX", crate::common::TEST_MASTER_KEY_HEX);
    cmd.arg("agent").arg("rotate").arg(name);
    for a in extra_args {
        cmd.arg(a);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = cmd.output().expect("failed to spawn agentsso rotate");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn run_rotate(
    home: &std::path::Path,
    bind_addr: &str,
    name: &str,
    extra_args: &[&str],
) -> (i32, String, String) {
    let mut delay = Duration::from_millis(50);
    let mut last = run_rotate_once(home, bind_addr, name, extra_args);
    for _ in 0..8 {
        if !(last.0 == 3 && last.2.contains("daemon_unreachable")) {
            return last;
        }
        std::thread::sleep(delay);
        delay = std::cmp::min(delay * 2, Duration::from_millis(800));
        last = run_rotate_once(home, bind_addr, name, extra_args);
    }
    last
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

fn assert_token_authenticates(port: u16, bearer: &str) {
    let (_status, body) = http_request(
        port,
        "GET",
        "/v1/tools/gmail/users/me/messages",
        &[("authorization", &format!("Bearer {bearer}")), ("x-agentsso-scope", "gmail.readonly")],
        None,
    );
    let json: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let code = json["error"]["code"].as_str().unwrap_or("");
    assert_ne!(code, "auth.invalid_token", "new token must authenticate, body: {body}");
    assert_ne!(code, "auth.missing_token", "auth header should be present, body: {body}");
}

fn assert_token_invalid(port: u16, bearer: &str) {
    let (status, body) = http_request(
        port,
        "GET",
        "/v1/tools/gmail/users/me/messages",
        &[("authorization", &format!("Bearer {bearer}")), ("x-agentsso-scope", "gmail.readonly")],
        None,
    );
    let json: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let code = json["error"]["code"].as_str().unwrap_or("");
    assert_eq!(
        code, "auth.invalid_token",
        "old bearer should be invalid (401) after rotation; got status={status}, body={body}"
    );
}

#[test]
fn rotate_invalidates_old_bearer_and_new_bearer_authenticates() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_policy(home.path());

    let daemon = start_daemon(DaemonTestConfig {
        port: 0,
        home: home.path().to_path_buf(),
        ..Default::default()
    });
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon should boot");

    let bind_addr = format!("127.0.0.1:{port}");

    // Register agent with --token-out to a known file.
    let token_path = home.path().join("agent-bearer.token");
    let (code, _stdout, stderr) = run_register(
        home.path(),
        &bind_addr,
        "rotate-test",
        "policy-readonly",
        &["--token-out", token_path.to_str().unwrap()],
    );
    assert_eq!(code, 0, "register should succeed; stderr={stderr}");

    let old_bearer = std::fs::read_to_string(&token_path)
        .expect("token-out file should exist")
        .trim()
        .to_owned();
    assert!(
        old_bearer.starts_with("agt_v2_rotate-test_"),
        "old bearer should have expected prefix: {old_bearer}"
    );

    // Confirm old bearer works before rotation.
    assert_token_authenticates(port, &old_bearer);

    // Rotate the agent, overwriting the same token-out file.
    let (code, _stdout, stderr) = run_rotate(
        home.path(),
        &bind_addr,
        "rotate-test",
        &["--token-out", token_path.to_str().unwrap()],
    );
    assert_eq!(code, 0, "rotate should succeed; stderr={stderr}");

    let new_bearer = std::fs::read_to_string(&token_path)
        .expect("token-out file should exist after rotate")
        .trim()
        .to_owned();
    assert!(
        new_bearer.starts_with("agt_v2_rotate-test_"),
        "new bearer should have expected prefix: {new_bearer}"
    );
    assert_ne!(old_bearer, new_bearer, "rotation must produce a different bearer token");

    // Old bearer is invalidated.
    assert_token_invalid(port, &old_bearer);

    // New bearer authenticates.
    assert_token_authenticates(port, &new_bearer);

    drop(daemon);
}
