//! Story 7.17 Task 3.8 — `agentsso connect <service> --device-flow`
//! integration tests.
//!
//! The CI-light tests (always run) cover the clap argument grammar
//! and exit-code mapping for paths that don't require the OS keychain
//! or a sealed credential.
//!
//! The `#[ignore]`-gated tests cover the full polling-loop end-to-end
//! against a mockito-served Google `device/code` + `token` endpoint.
//! These are gated because `agentsso connect`'s keystore lookup hits
//! the real macOS Keychain / Linux Secret Service on most dev boxes,
//! and the existing daemon-only `AGENTSSO_TEST_MASTER_KEY_HEX` seam
//! does not extend to the connect codepath. Run them locally with:
//!
//! ```sh
//! cargo nextest run -p permitlayer-daemon --features test-seam \
//!   device_flow_e2e --run-ignored only
//! ```
//!
//! The shipped CI workflow in `.github/workflows/headless-install.yml`
//! covers the live-binary path on macOS-14 with a fully wired keychain
//! (Story 7.17 Task 5.2 documents what that workflow does and does
//! NOT validate).

use std::process::{Command, Stdio};

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

const FAKE_OAUTH_CLIENT_JSON: &str = r#"{
    "installed": {
        "client_id": "device-flow-test-client.apps.googleusercontent.com",
        "client_secret": "GOCSPX-test-secret",
        "project_id": "test-project"
    }
}"#;

fn seed_policy(home: &std::path::Path) {
    let policies_dir = home.join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();
    std::fs::write(policies_dir.join("readonly.toml"), POLICY_TOML).unwrap();
}

fn write_oauth_client(home: &std::path::Path) -> std::path::PathBuf {
    let path = home.join("client_secret_device.json");
    std::fs::write(&path, FAKE_OAUTH_CLIENT_JSON).unwrap();
    path
}

// ──────────────────────────────────────────────────────────────────
// CI-light tests — run on every PR.
// ──────────────────────────────────────────────────────────────────

#[test]
fn device_flow_and_headless_are_mutually_exclusive() {
    // AC #5: clap-level conflict on `connection add` (Story 11.13
    // repoint of the device-flow flags off the retired `connect` verb).
    let home = tempfile::tempdir().unwrap();
    let oauth_client = write_oauth_client(home.path());
    let output = Command::new(agentsso_bin())
        .args([
            "connection",
            "add",
            "google-gmail",
            "--name",
            "x",
            "--oauth-client",
            oauth_client.to_str().unwrap(),
            "--device-flow",
            "--headless",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run connection add");
    assert_eq!(output.status.code(), Some(2), "clap conflict must exit 2");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--device-flow") || stderr.contains("--headless"),
        "stderr should name the conflicting flag: {stderr}"
    );
}

#[test]
fn device_flow_timeout_requires_device_flow_flag() {
    // `--device-flow-timeout` without `--device-flow` is meaningless;
    // clap should reject it (`requires` attribute on `connection add`).
    let home = tempfile::tempdir().unwrap();
    let oauth_client = write_oauth_client(home.path());
    let output = Command::new(agentsso_bin())
        .args([
            "connection",
            "add",
            "google-gmail",
            "--name",
            "x",
            "--oauth-client",
            oauth_client.to_str().unwrap(),
            "--device-flow-timeout",
            "60",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run connection add");
    assert_eq!(output.status.code(), Some(2), "clap requires-violation must exit 2");
}

#[test]
fn device_flow_with_non_interactive_is_accepted_by_clap() {
    // `--device-flow` MUST coexist with `--non-interactive` (the
    // canonical scripted-headless invocation). With no daemon running in
    // this test home, the daemon-must-run gate fires AFTER clap, exiting
    // 2 — proving clap accepted the flag combo.
    let home = tempfile::tempdir().unwrap();
    let oauth_client = write_oauth_client(home.path());
    let output = Command::new(agentsso_bin())
        .env("AGENTSSO_PATHS__HOME", home.path())
        .args([
            "connection",
            "add",
            "google-gmail",
            "--name",
            "x",
            "--oauth-client",
            oauth_client.to_str().unwrap(),
            "--device-flow",
            "--non-interactive",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run connection add");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Reaching the daemon-must-run gate proves clap accepted the combo.
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("connection.daemon_must_run"),
        "should reach the daemon-must-run gate, not a clap conflict; stderr={stderr}"
    );
    assert!(
        !stderr.contains("cannot be used with"),
        "clap should not have rejected the flag combo; stderr={stderr}"
    );
}

// ──────────────────────────────────────────────────────────────────
// Heavyweight E2E tests — gated #[ignore] because they require the
// keystore and a sealed credential path. Run locally via `--run-ignored
// only`.
// ──────────────────────────────────────────────────────────────────

/// Register an agent against the live daemon via `agentsso agent
/// register --json`, then stop the daemon (so the connect command's
/// daemon-must-stop gate passes). Returns the bearer.
#[allow(dead_code)] // Used only by `#[ignore]` tests.
fn register_agent_then_stop_daemon(home: &std::path::Path) -> String {
    let daemon = start_daemon_common(DaemonTestConfig {
        port: 0,
        home: home.to_path_buf(),
        ..Default::default()
    });
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon did not boot");

    let bind_addr = format!("127.0.0.1:{port}");
    let output = Command::new(agentsso_bin())
        .env("AGENTSSO_PATHS__HOME", home)
        .env("AGENTSSO_HTTP__BIND_ADDR", &bind_addr)
        .env("AGENTSSO_TEST_MASTER_KEY_HEX", crate::common::TEST_MASTER_KEY_HEX)
        .args(["agent", "register", "test-agent", "--policy", "policy-readonly", "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run agent register");
    assert_eq!(
        output.status.code(),
        Some(0),
        "agent register failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim_end_matches('\n')).unwrap();
    let bearer = parsed["bearer_token"].as_str().unwrap().to_owned();

    drop(daemon);
    bearer
}

#[allow(dead_code)] // Used only by `#[ignore]` tests.
fn run_connect_device_flow(
    home: &std::path::Path,
    oauth_client: &std::path::Path,
    device_code_url: &str,
    token_url: &str,
    timeout_secs: u64,
) -> (Option<i32>, String, String) {
    let output = Command::new(agentsso_bin())
        .env("AGENTSSO_PATHS__HOME", home)
        .env("AGENTSSO_TEST_MASTER_KEY_HEX", crate::common::TEST_MASTER_KEY_HEX)
        .env("AGENTSSO_DEVICE_FLOW_DEVICE_CODE_URL", device_code_url)
        .env("AGENTSSO_DEVICE_FLOW_TOKEN_URL", token_url)
        .args([
            "connect",
            "gmail",
            "--agent",
            "test-agent",
            "--oauth-client",
            oauth_client.to_str().unwrap(),
            "--device-flow",
            "--device-flow-timeout",
            &timeout_secs.to_string(),
            "--non-interactive",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run connect --device-flow");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[ignore = "requires keystore access; run with --run-ignored only on a dev box"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_flow_timeout_returns_exit_3_with_named_error() {
    let mut server = mockito::Server::new_async().await;
    let _device = server
        .mock("POST", "/device/code")
        .with_status(200)
        .with_body(
            r#"{"device_code":"dc","user_code":"AAAA-BBBB","verification_url":"https://example.test/verify","expires_in":1800,"interval":1}"#,
        )
        .create_async()
        .await;
    let _pending = server
        .mock("POST", "/token")
        .with_status(400)
        .with_body(r#"{"error":"authorization_pending"}"#)
        .expect_at_least(1)
        .create_async()
        .await;

    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_policy(home.path());
    let oauth_client = write_oauth_client(home.path());
    let _bearer = register_agent_then_stop_daemon(home.path());

    let (status, stdout, stderr) = run_connect_device_flow(
        home.path(),
        &oauth_client,
        &format!("{}/device/code", server.url()),
        &format!("{}/token", server.url()),
        1, // 1-second timeout — fires before any conceivable consent
    );

    assert_eq!(
        status,
        Some(3),
        "device-flow timeout should exit 3 (oauth_failed); stderr={stderr}"
    );
    assert!(stdout.contains("AAAA-BBBB"), "stdout should contain the user code: {stdout}");
    assert!(
        stdout.contains("https://example.test/verify"),
        "stdout should contain the verification URL: {stdout}"
    );
    assert!(
        stderr.contains("device_flow_timeout") || stderr.contains("DeviceFlowTimeout"),
        "stderr should name DeviceFlowTimeout: {stderr}"
    );
}

#[ignore = "requires keystore access; run with --run-ignored only on a dev box"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_flow_renders_verification_block_before_polling() {
    let mut server = mockito::Server::new_async().await;
    let _device = server
        .mock("POST", "/device/code")
        .with_status(200)
        .with_body(
            r#"{"device_code":"dc","user_code":"WXYZ-1234","verification_url":"https://example.test/print-me","expires_in":600,"interval":1}"#,
        )
        .create_async()
        .await;
    let _denied = server
        .mock("POST", "/token")
        .with_status(400)
        .with_body(r#"{"error":"access_denied"}"#)
        .create_async()
        .await;

    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    seed_policy(home.path());
    let oauth_client = write_oauth_client(home.path());
    let _bearer = register_agent_then_stop_daemon(home.path());

    let (status, stdout, stderr) = run_connect_device_flow(
        home.path(),
        &oauth_client,
        &format!("{}/device/code", server.url()),
        &format!("{}/token", server.url()),
        30,
    );

    assert_eq!(status, Some(3), "access_denied should exit 3 (oauth_failed); stderr={stderr}");
    assert!(
        stdout.contains("WXYZ-1234"),
        "stdout MUST render the user code before polling errors: {stdout}"
    );
    assert!(
        stdout.contains("https://example.test/print-me"),
        "stdout MUST render the verification URL before polling errors: {stdout}"
    );
    assert!(
        stderr.contains("device_code_denied")
            || stderr.contains("DeviceCodeDenied")
            || stderr.contains("denied consent"),
        "stderr should name DeviceCodeDenied: {stderr}"
    );
}
