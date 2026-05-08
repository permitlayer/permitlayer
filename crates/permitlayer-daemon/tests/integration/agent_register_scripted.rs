//! Story 7.17 Task 1.8 — integration tests for the scripted-install
//! `agent register --json` and `--token-out` flags.
//!
//! Boots the daemon, runs the real `agentsso agent register` binary
//! with the new flags, and validates the bearer token works for
//! authenticated requests. The registry stores a token *hash* (not
//! plaintext) so we cannot byte-compare against the on-disk agent file —
//! the only way to confirm the token "works" is to issue an
//! authenticated request and assert PolicyLayer routes through.
//!
//! Codex review 3 fix: prior draft asserted plaintext-equality with the
//! registry, which is not how Story 4.4 / 7.6b stores it. This test
//! validates the wire shape AND the resulting token via behavior, not
//! storage equality.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::common::{
    DaemonTestConfig, agentsso_bin, start_daemon as start_daemon_common, wait_for_health,
};

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

fn start_daemon(home: &std::path::Path) -> crate::common::DaemonHandle {
    start_daemon_common(DaemonTestConfig {
        port: 0,
        home: home.to_path_buf(),
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

/// Run `agentsso agent register <name> --policy <policy> [extra_args]`
/// against the live daemon. Returns (exit_code, stdout, stderr).
fn run_register(
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
    let output = cmd.output().expect("failed to spawn agentsso");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Hit a tools endpoint with the bearer; assert PolicyLayer routes
/// through (i.e., not `auth.invalid_token` and not `auth.missing_token`).
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
    assert_ne!(code, "auth.invalid_token", "registered token must authenticate, body: {body}");
    assert_ne!(code, "auth.missing_token", "auth header should be present, body: {body}");
}

#[test]
fn register_json_emits_compact_single_line_with_bearer_that_authenticates() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_policy(home.path());

    let daemon = start_daemon(home.path());
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon did not boot");

    let bind_addr = format!("127.0.0.1:{port}");
    let (code, stdout, stderr) =
        run_register(home.path(), &bind_addr, "ci-test", "policy-readonly", &["--json"]);
    assert_eq!(code, 0, "register --json should exit 0; stderr={stderr}");

    // Compact single-line: no embedded newline before the trailing one,
    // no pretty-print indentation.
    let trimmed = stdout.trim_end_matches('\n');
    assert!(!trimmed.contains('\n'), "JSON output must be single-line: {trimmed}");
    assert!(!trimmed.contains("  "), "compact JSON must not contain indentation: {trimmed}");

    let parsed: serde_json::Value =
        serde_json::from_str(trimmed).expect("--json output must parse as JSON");
    assert_eq!(parsed["status"], "ok");
    assert_eq!(parsed["name"], "ci-test");
    assert_eq!(parsed["policy_name"], "policy-readonly");
    let bearer = parsed["bearer_token"].as_str().expect("bearer_token field present");
    assert!(
        bearer.starts_with("agt_v2_"),
        "bearer must be agt_v2_-prefixed (Story 7.6b): {bearer}"
    );

    // The token actually works — Codex review 3 fix.
    assert_token_authenticates(port, bearer);
}

#[test]
fn register_token_out_writes_owner_only_file_with_no_trailing_newline() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_policy(home.path());

    let daemon = start_daemon(home.path());
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon did not boot");

    let token_dir = tempfile::tempdir().unwrap();
    let token_path = token_dir.path().join("bearer.tok");

    let bind_addr = format!("127.0.0.1:{port}");
    let token_path_arg = format!("--token-out={}", token_path.display());
    let (code, stdout, stderr) =
        run_register(home.path(), &bind_addr, "ci-test", "policy-readonly", &[&token_path_arg]);
    assert_eq!(code, 0, "register --token-out should exit 0; stderr={stderr}");

    // Stdout has the confirmation line but NOT the token bytes.
    assert!(stdout.contains("bearer token written to"), "missing confirmation line: {stdout}");

    let bytes = std::fs::read(&token_path).expect("token file should exist");
    let bearer = String::from_utf8(bytes.clone()).expect("token bytes are utf8");
    assert!(bearer.starts_with("agt_v2_"), "file must hold a real bearer: {bearer}");
    assert!(!bearer.ends_with('\n'), "no trailing newline: {bearer:?}");
    assert!(
        !stdout.contains(&bearer),
        "token bytes must NOT appear on stdout (would defeat owner-only file)"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let md = std::fs::metadata(&token_path).unwrap();
        let mode = md.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "--token-out file must be 0o600");
    }

    // The on-disk token authenticates against the daemon.
    assert_token_authenticates(port, bearer.trim());
}

#[test]
fn register_json_and_token_out_together_fail_with_clap_conflict() {
    // Story 7.17 AC #3: clap-level conflict. The daemon does not need
    // to be running for clap to reject the args.
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();

    let token_path = home.path().join("bearer.tok");
    let mut cmd = Command::new(agentsso_bin());
    cmd.env("AGENTSSO_PATHS__HOME", home.path());
    cmd.arg("agent")
        .arg("register")
        .arg("ci-test")
        .arg("--policy=default")
        .arg("--json")
        .arg(format!("--token-out={}", token_path.display()));
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = cmd.output().expect("failed to spawn agentsso");

    // clap exits 2 on argument-parse errors.
    assert_eq!(output.status.code(), Some(2), "clap conflict must exit 2");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--json") || stderr.contains("--token-out"),
        "clap should name the conflicting flag, got: {stderr}"
    );
}

#[test]
fn register_json_error_response_has_status_error_field() {
    // Story 7.17 Task 1.8 test 4: --json error path. Trigger via
    // unknown policy (the easiest deterministic failure on a fresh
    // daemon — no policies have been seeded).
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    // Intentionally NOT seeding any policy file.
    std::fs::create_dir_all(home.path().join("policies")).unwrap();

    let daemon = start_daemon(home.path());
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon did not boot");

    let bind_addr = format!("127.0.0.1:{port}");
    let (code, stdout, _stderr) =
        run_register(home.path(), &bind_addr, "ci-test", "policy-does-not-exist", &["--json"]);
    // unknown_policy → exit 2 (operator-correctable, agent_control_exit_code).
    assert_eq!(code, 2, "unknown policy must exit 2");

    let trimmed = stdout.trim_end_matches('\n');
    assert!(!trimmed.is_empty(), "--json error must still emit a JSON line on stdout");
    let parsed: serde_json::Value =
        serde_json::from_str(trimmed).expect("error JSON must parse: {trimmed}");
    assert_eq!(parsed["status"], "error");
    assert_eq!(parsed["code"], "agent.unknown_policy");
    assert!(!parsed["message"].as_str().unwrap().is_empty());
}
