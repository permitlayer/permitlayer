//! End-to-end tests for Plan B (operator-token authentication on
//! `/v1/control/*`). Pin the regression: a CLI invocation against
//! the daemon's control endpoints must carry a valid
//! `X-Agentsso-Control` header (or an equivalent `AGENTSSO_CONTROL_TOKEN`
//! env var); a missing or wrong token is rejected with a structured
//! `forbidden_*` error code.
//!
//! These tests drive the *real* `agentsso` CLI as a subprocess against
//! a real spawned daemon. The daemon mints `<home>/control.token` at
//! startup. Same-user CLI reads the file directly; cross-user CLI uses
//! the env var.

// Every test in this file is `#[cfg(unix)]`-gated (subprocess CLI
// drives + env-clear plumbing + Winsock interactions are flake-prone
// on Windows). Gating the helpers too keeps `cargo clippy --all-targets
// --all-features -D warnings` happy on Windows where nothing in this
// module gets called.
#![cfg(unix)]

use std::process::Command;
use std::time::Duration;

use crate::common::{
    DaemonTestConfig, agentsso_bin, forward_windows_required_env, read_test_control_token,
    start_daemon, wait_for_health,
};

/// Spawn `agentsso <args>` with the given env overrides. Inherit a
/// minimal env and explicitly clear `AGENTSSO_CONTROL_TOKEN` so the
/// CLI's same-user fallback path (read from `<home>/control.token`)
/// is exercised by default.
fn run_cli_against_daemon(
    home: &std::path::Path,
    bind_addr: &str,
    extra_env: &[(&str, &str)],
    args: &[&str],
) -> std::process::Output {
    let mut cmd = Command::new(agentsso_bin());
    cmd.env_clear()
        .envs(forward_windows_required_env())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("AGENTSSO_PATHS__HOME", home)
        .env("AGENTSSO_HTTP__BIND_ADDR", bind_addr)
        .args(args);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to spawn agentsso CLI")
}

const POLICY_TOML: &str = r#"
[[policies]]
name = "test-policy"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
"#;

fn seed_policy(home: &std::path::Path) {
    let policies_dir = home.join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();
    std::fs::write(policies_dir.join("test.toml"), POLICY_TOML).unwrap();
}

/// **Happy path.** CLI reads the daemon's local `<home>/control.token`,
/// sends it as `X-Agentsso-Control`, daemon accepts, command succeeds.
#[test]
fn control_command_succeeds_with_token() {
    let home = tempfile::tempdir().unwrap();
    seed_policy(home.path());
    let daemon = start_daemon(DaemonTestConfig {
        port: 0,
        home: home.path().to_path_buf(),
        ..Default::default()
    });
    assert!(wait_for_health(daemon.port), "daemon should boot");
    let bind_addr = format!("127.0.0.1:{}", daemon.port);

    // Same-user path: don't set AGENTSSO_CONTROL_TOKEN; CLI reads from
    // <home>/control.token directly.
    let out = run_cli_against_daemon(home.path(), &bind_addr, &[], &["agent", "list"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "agent list should succeed with same-user token. exit={:?}\nstdout={stdout}\nstderr={stderr}",
        out.status.code(),
    );
    assert!(
        !stderr.contains("forbidden_missing_control_token"),
        "stderr leaked missing-token error: {stderr}"
    );
}

/// **Missing token.** CLI in a fresh home with no `control.token` file
/// and no env var. Daemon under different home; CLI exits 3 with the
/// `daemon_unreachable` error block (the underlying HTTP response is
/// 403 `forbidden_missing_control_token`, which the CLI's existing
/// error path renders as a generic "unreachable" block — that's a
/// minor UX improvement for a follow-up).
#[test]
fn control_command_fails_without_token() {
    let home_daemon = tempfile::tempdir().unwrap();
    seed_policy(home_daemon.path());
    let daemon = start_daemon(DaemonTestConfig {
        port: 0,
        home: home_daemon.path().to_path_buf(),
        ..Default::default()
    });
    assert!(wait_for_health(daemon.port), "daemon should boot");
    let bind_addr = format!("127.0.0.1:{}", daemon.port);

    // Cross-home: CLI under a fresh home with NO control.token file,
    // no env var. Should fail.
    let home_caller = tempfile::tempdir().unwrap();
    let out = run_cli_against_daemon(home_caller.path(), &bind_addr, &[], &["agent", "list"]);
    assert_ne!(
        out.status.code(),
        Some(0),
        "agent list should fail with no token: exit={:?}",
        out.status.code(),
    );
}

/// **Wrong token.** CLI sets a syntactically-valid but mismatched
/// `AGENTSSO_CONTROL_TOKEN`. Daemon rejects with
/// `forbidden_invalid_control_token`.
#[test]
fn control_command_fails_with_wrong_token() {
    let home_daemon = tempfile::tempdir().unwrap();
    seed_policy(home_daemon.path());
    let daemon = start_daemon(DaemonTestConfig {
        port: 0,
        home: home_daemon.path().to_path_buf(),
        ..Default::default()
    });
    assert!(wait_for_health(daemon.port), "daemon should boot");
    let bind_addr = format!("127.0.0.1:{}", daemon.port);

    let home_caller = tempfile::tempdir().unwrap();
    let bogus = "agt_ctl_definitelynotthistokenagt_ctl_thisistotallywrongLLLLL";
    let out = run_cli_against_daemon(
        home_caller.path(),
        &bind_addr,
        &[("AGENTSSO_CONTROL_TOKEN", bogus)],
        &["agent", "list"],
    );
    assert_ne!(
        out.status.code(),
        Some(0),
        "agent list should fail with wrong token: exit={:?}",
        out.status.code(),
    );
}

/// **Cross-user via env var.** CLI under a different home reads the
/// daemon-owner's `control.token` (via the operator's `sudo cat` or
/// equivalent in real life) and exports it as `AGENTSSO_CONTROL_TOKEN`.
/// Should work.
#[test]
fn control_command_works_cross_home_via_env_var() {
    let home_daemon = tempfile::tempdir().unwrap();
    seed_policy(home_daemon.path());
    let daemon = start_daemon(DaemonTestConfig {
        port: 0,
        home: home_daemon.path().to_path_buf(),
        ..Default::default()
    });
    assert!(wait_for_health(daemon.port), "daemon should boot");
    let bind_addr = format!("127.0.0.1:{}", daemon.port);

    // Read the daemon-owner's token.
    let token = read_test_control_token(home_daemon.path());

    let home_caller = tempfile::tempdir().unwrap();
    let out = run_cli_against_daemon(
        home_caller.path(),
        &bind_addr,
        &[("AGENTSSO_CONTROL_TOKEN", token.as_str())],
        &["agent", "list"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "agent list should succeed with explicit env var. exit={:?}\nstdout={stdout}\nstderr={stderr}",
        out.status.code(),
    );
    assert!(
        !stderr.contains("forbidden_missing_control_token"),
        "stderr leaked missing-token error: {stderr}"
    );
    assert!(
        !stderr.contains("forbidden_invalid_control_token"),
        "stderr leaked invalid-token error: {stderr}"
    );

    // Wait briefly for the slow Drop. Drives `daemon` out of scope.
    drop(daemon);

    // Sleep briefly so the daemon's exit is observable and any
    // pending audit writes complete before the next test starts.
    std::thread::sleep(Duration::from_millis(100));
}

/// **Token persists across daemon restart.** Codex review caught this
/// as a real ops concern — auto-rotating on every restart breaks
/// cron jobs and other automation. This test pins the persistence
/// invariant: shut down the daemon, restart, the token file content
/// is byte-identical.
#[test]
fn control_token_persists_across_daemon_restart() {
    let home = tempfile::tempdir().unwrap();
    seed_policy(home.path());

    // First boot: daemon mints fresh token.
    let daemon = start_daemon(DaemonTestConfig {
        port: 0,
        home: home.path().to_path_buf(),
        ..Default::default()
    });
    assert!(wait_for_health(daemon.port), "first daemon should boot");
    let token_first = read_test_control_token(home.path());
    drop(daemon); // SIGKILL on Drop.
    std::thread::sleep(Duration::from_millis(200));

    // Second boot under same home: daemon must read the existing token.
    let daemon2 = start_daemon(DaemonTestConfig {
        port: 0,
        home: home.path().to_path_buf(),
        ..Default::default()
    });
    assert!(wait_for_health(daemon2.port), "second daemon should boot");
    let token_second = read_test_control_token(home.path());
    drop(daemon2);

    assert_eq!(
        token_first, token_second,
        "control token must persist across daemon restarts (Codex review finding #6 — \
         rotating on restart would break ops automation)",
    );
}
