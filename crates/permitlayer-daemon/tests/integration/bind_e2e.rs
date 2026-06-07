//! End-to-end tests for `agentsso bind` / `unbind` / `agent bindings`
//! (Epic 11, Story 11.14).
//!
//! `bind` routes through the daemon control plane (the optional
//! `--policy` is checked against the live `PolicySet`), so these tests
//! boot the real daemon. The connection to bind to is seeded directly on
//! disk (`seed_connection_only`) — but the BINDING itself is created via
//! the REAL `bind` verb. `unbind` / `agent bindings` are in-process store
//! ops the CLI does directly.

use std::process::Command;

use crate::common::{
    DaemonHandle, DaemonTestConfig, SeedTier, TEST_MASTER_KEY_HEX, agentsso_bin, http_post_control,
    read_test_control_token, seed_connection_only, start_daemon as start_daemon_common,
    wait_for_health,
};

const GMAIL_RO_URI: &str = "https://www.googleapis.com/auth/gmail.readonly";

/// A `[[policies]]` file the daemon compiles at boot (so `bind --policy`
/// can verify against the live PolicySet).
const POLICY_TOML: &str = r#"
[[policies]]
name = "gmail-read"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
"#;

fn seed_policy(home: &std::path::Path) {
    let dir = home.join("policies");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("gmail-read.toml"), POLICY_TOML).unwrap();
}

fn start_daemon(home: &std::path::Path) -> DaemonHandle {
    start_daemon_common(DaemonTestConfig {
        port: 0,
        home: home.to_path_buf(),
        ..Default::default()
    })
}

fn register_agent(port: u16, home: &std::path::Path, name: &str) {
    let body = serde_json::json!({ "name": name, "policy_name": "gmail-read" }).to_string();
    let ctl = read_test_control_token(home);
    let headers = [("X-Agentsso-Control", ctl.as_str()), ("Content-Type", "application/json")];
    let (status, resp_body) =
        http_post_control(home, port, "/v1/control/agent/register", &body, &headers);
    assert_eq!(status, 200, "agent register {name} should succeed: {resp_body}");
}

/// Run an `agentsso` CLI subcommand against the running daemon.
fn run_cli(home: &std::path::Path, port: u16, args: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(agentsso_bin())
        .args(args)
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .env("AGENTSSO_HTTP__BIND_ADDR", format!("127.0.0.1:{port}"))
        .env("AGENTSSO_TEST_MASTER_KEY_HEX", TEST_MASTER_KEY_HEX)
        .output()
        .expect("spawn agentsso CLI");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Read an agent's on-disk identity file bytes (for the bearer-immutability
/// assertion). Returns `(token_hash, lookup_key_hex)`.
fn read_agent_identity_fields(home: &std::path::Path, agent: &str) -> (String, String) {
    let path = home.join("agents").join(format!("{agent}.toml"));
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read agent file {}: {e}", path.display()));
    let parsed: toml::Value = toml::from_str(&raw).expect("agent toml parses");
    let token_hash = parsed.get("token_hash").and_then(|v| v.as_str()).unwrap().to_owned();
    let lookup = parsed.get("lookup_key_hex").and_then(|v| v.as_str()).unwrap().to_owned();
    (token_hash, lookup)
}

#[test]
fn bind_then_agent_bindings_then_unbind_lifecycle() {
    let home = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_policy(home.path());
    let daemon = start_daemon(home.path());
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon should boot");

    register_agent(port, home.path(), "chuck");
    seed_connection_only(
        home.path(),
        "google-gmail",
        "chuck-gmail",
        SeedTier::Read,
        &[GMAIL_RO_URI],
    );

    // bind (with a valid policy + alias).
    let (status, out, stderr) = run_cli(
        home.path(),
        port,
        &[
            "bind",
            "chuck",
            "chuck-gmail",
            "--grant",
            "read",
            "--policy",
            "gmail-read",
            "--alias",
            "cg",
        ],
    );
    assert_eq!(status, Some(0), "bind should succeed; stderr={stderr}");
    assert!(out.contains("chuck-gmail"), "bind output names the connection: {out}");

    // agent bindings lists it with tier + policy + alias.
    let (status, out, stderr) = run_cli(home.path(), port, &["agent", "bindings", "chuck"]);
    assert_eq!(status, Some(0), "agent bindings should succeed; stderr={stderr}");
    assert!(out.contains("chuck-gmail"), "bindings list shows the connection: {out}");
    assert!(out.contains("read"), "bindings list shows the tier: {out}");
    assert!(out.contains("gmail-read"), "bindings list shows the policy: {out}");
    assert!(out.contains("cg"), "bindings list shows the alias: {out}");

    // unbind removes it.
    let (status, _out, stderr) = run_cli(home.path(), port, &["unbind", "chuck", "chuck-gmail"]);
    assert_eq!(status, Some(0), "unbind should succeed; stderr={stderr}");

    // agent bindings is now empty.
    let (status, out, _stderr) = run_cli(home.path(), port, &["agent", "bindings", "chuck"]);
    assert_eq!(status, Some(0));
    assert!(
        out.to_lowercase().contains("no bindings") || !out.contains("chuck-gmail"),
        "bindings should be empty after unbind: {out}"
    );

    drop(daemon);
}

#[test]
fn agent_holds_multiple_bindings_fr47() {
    let home = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_policy(home.path());
    let daemon = start_daemon(home.path());
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon should boot");

    register_agent(port, home.path(), "chuck");
    seed_connection_only(
        home.path(),
        "google-gmail",
        "chuck-gmail",
        SeedTier::ReadWrite,
        &[GMAIL_RO_URI],
    );
    seed_connection_only(
        home.path(),
        "google-gmail",
        "austin-gmail",
        SeedTier::Read,
        &[GMAIL_RO_URI],
    );

    let (s1, _o1, e1) =
        run_cli(home.path(), port, &["bind", "chuck", "chuck-gmail", "--grant", "read-write"]);
    assert_eq!(s1, Some(0), "first bind should succeed; stderr={e1}");
    let (s2, _o2, e2) =
        run_cli(home.path(), port, &["bind", "chuck", "austin-gmail", "--grant", "read"]);
    assert_eq!(s2, Some(0), "second bind should succeed; stderr={e2}");

    // Both bindings listed (one agent → many bindings, FR47).
    let (status, out, stderr) = run_cli(home.path(), port, &["agent", "bindings", "chuck"]);
    assert_eq!(status, Some(0), "agent bindings should succeed; stderr={stderr}");
    assert!(out.contains("chuck-gmail"), "lists chuck-gmail: {out}");
    assert!(out.contains("austin-gmail"), "lists austin-gmail: {out}");

    drop(daemon);
}

#[test]
fn bind_duplicate_is_rejected_unbind_first() {
    let home = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_policy(home.path());
    let daemon = start_daemon(home.path());
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon should boot");

    register_agent(port, home.path(), "chuck");
    seed_connection_only(
        home.path(),
        "google-gmail",
        "chuck-gmail",
        SeedTier::Read,
        &[GMAIL_RO_URI],
    );

    let (s1, _o1, e1) =
        run_cli(home.path(), port, &["bind", "chuck", "chuck-gmail", "--grant", "read"]);
    assert_eq!(s1, Some(0), "first bind should succeed; stderr={e1}");

    let (s2, _o2, stderr) =
        run_cli(home.path(), port, &["bind", "chuck", "chuck-gmail", "--grant", "read"]);
    assert_eq!(s2, Some(3), "duplicate bind is a conflict → exit 3; stderr={stderr}");
    assert!(
        stderr.contains("binding.duplicate") || stderr.contains("already bound"),
        "duplicate bind should name the conflict: {stderr}"
    );

    drop(daemon);
}

#[test]
fn bind_with_nonexistent_policy_rejected_before_write() {
    let home = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_policy(home.path());
    let daemon = start_daemon(home.path());
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon should boot");

    register_agent(port, home.path(), "chuck");
    seed_connection_only(
        home.path(),
        "google-gmail",
        "chuck-gmail",
        SeedTier::Read,
        &[GMAIL_RO_URI],
    );

    let (status, _out, stderr) = run_cli(
        home.path(),
        port,
        &["bind", "chuck", "chuck-gmail", "--grant", "read", "--policy", "no-such-policy"],
    );
    assert_eq!(status, Some(2), "unknown policy → exit 2; stderr={stderr}");
    assert!(
        stderr.contains("binding.unknown_policy") || stderr.contains("not found"),
        "should name the unknown-policy rejection: {stderr}"
    );

    // No binding was written (rejected before the store touch): the
    // bindings file must not exist for this agent.
    let binding_file = home.path().join("bindings/chuck.toml");
    assert!(!binding_file.exists(), "no binding file should be written on a policy-rejected bind");

    drop(daemon);
}

#[test]
fn bind_to_missing_connection_errors_cleanly() {
    let home = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_policy(home.path());
    let daemon = start_daemon(home.path());
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon should boot");

    register_agent(port, home.path(), "chuck");
    // No connection seeded.
    let (status, _out, stderr) =
        run_cli(home.path(), port, &["bind", "chuck", "ghost-gmail", "--grant", "read"]);
    assert_eq!(status, Some(2), "missing connection → exit 2; stderr={stderr}");
    assert!(
        stderr.contains("unknown_connection") || stderr.contains("no connection"),
        "should name the missing-connection error: {stderr}"
    );

    drop(daemon);
}

#[test]
fn bind_and_unbind_are_bearer_immutable() {
    // AC#4: bind + unbind touch ONLY bindings/<agent>.toml — the agent's
    // token_hash + lookup_key_hex are byte-identical pre/post.
    let home = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_policy(home.path());
    let daemon = start_daemon(home.path());
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon should boot");

    register_agent(port, home.path(), "chuck");
    seed_connection_only(
        home.path(),
        "google-gmail",
        "chuck-gmail",
        SeedTier::Read,
        &[GMAIL_RO_URI],
    );

    let before = read_agent_identity_fields(home.path(), "chuck");

    let (s1, _o1, e1) =
        run_cli(home.path(), port, &["bind", "chuck", "chuck-gmail", "--grant", "read"]);
    assert_eq!(s1, Some(0), "bind should succeed; stderr={e1}");
    let after_bind = read_agent_identity_fields(home.path(), "chuck");
    assert_eq!(before, after_bind, "bind must NOT touch the agent's token_hash/lookup_key_hex");

    let (s2, _o2, e2) = run_cli(home.path(), port, &["unbind", "chuck", "chuck-gmail"]);
    assert_eq!(s2, Some(0), "unbind should succeed; stderr={e2}");
    let after_unbind = read_agent_identity_fields(home.path(), "chuck");
    assert_eq!(before, after_unbind, "unbind must NOT touch the agent's token_hash/lookup_key_hex");

    drop(daemon);
}

#[test]
fn bind_to_missing_agent_errors_cleanly() {
    let home = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_policy(home.path());
    let daemon = start_daemon(home.path());
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon should boot");

    // Agent NOT registered; connection exists.
    seed_connection_only(
        home.path(),
        "google-gmail",
        "chuck-gmail",
        SeedTier::Read,
        &[GMAIL_RO_URI],
    );
    let (status, _out, stderr) =
        run_cli(home.path(), port, &["bind", "ghost", "chuck-gmail", "--grant", "read"]);
    assert_eq!(status, Some(2), "missing agent → exit 2; stderr={stderr}");
    assert!(
        stderr.contains("unknown_agent") || stderr.contains("not registered"),
        "should name the missing-agent error: {stderr}"
    );

    drop(daemon);
}
