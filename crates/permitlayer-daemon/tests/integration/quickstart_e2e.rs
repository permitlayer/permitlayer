//! End-to-end integration tests for `agentsso quickstart <service>`
//! (UX-overhaul Story 5).
//!
//! The model under test (owner-confirmed, final): the daemon is
//! headless — there is NO approval, NO prompt-on-write, NO
//! human-in-the-loop. `quickstart` picks the shipped `<svc>-read-only`
//! / `<svc>-read-write` policy by the `--read` / `--read-write` flag,
//! auto-creates the agent bound to that policy, then drives the
//! existing `connect` orchestration (OAuth + seal + verify +
//! scope-merge + rebind + snippet emission).
//!
//! Like `connect_e2e.rs`, the full happy path (real Google OAuth) is
//! out of CI scope. These tests cover every observable surface that
//! does NOT need a real authorize:
//!
//! - `quickstart --help` is a real clap subcommand (exit 0).
//! - unknown service → `quickstart.unknown_service` exit 2.
//! - no daemon → the reused `connect.daemon_must_run` block + the
//!   `sudo agentsso setup` steer line, exit 2, failure.
//! - `--non-interactive` with NO access flag →
//!   `quickstart.access_unspecified` exit 2 (no agent created).
//! - daemon up + `--read` → agent `<svc>-quickstart` is registered and
//!   bound to `<svc>-read-only` (asserted via `/v1/control/agent/list`)
//!   BEFORE connect's OAuth stage (proving register+bind happens
//!   first). Same for `--read-write` → `<svc>-read-write`.
//!
//! The crate is `#![forbid(unsafe_code)]`; `std::env::set_var` is
//! unsafe in edition 2024, so env is set on the spawned CHILD only
//! (`Command::env`), never on the test process. The pure logic
//! (`policy_for`, the access-line parser, the service predicate) is
//! unit-tested in-crate (`cli/quickstart.rs` `#[cfg(test)]`).

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::common::{
    DaemonTestConfig, agentsso_bin, http_request_control, read_test_control_token, start_daemon,
    wait_for_health,
};

/// Poll `/v1/control/whoami` until the control plane actually ANSWERS
/// (200), not merely until its socket file exists.
///
/// `start_daemon` waits for the control socket *file* to appear and
/// `wait_for_health` waits for HTTP `/health` — but neither guarantees
/// the daemon is yet accepting+serving `/v1/control/*` requests. The
/// `quickstart` child's first action is a control-plane register POST;
/// if it lands in that startup window it fails fast with
/// `quickstart.register_failed` (transport error). On loaded macOS
/// runners that window is wide enough to lose deterministically (the
/// real cause behind the old `observed binding: None` flake). Probing
/// `whoami` to a 200 before spawning the child closes the window.
fn wait_for_control_ready(home: &std::path::Path, port: u16) -> bool {
    let token = read_test_control_token(home);
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        let (status, _) = http_request_control(
            home,
            port,
            "GET",
            "/v1/control/whoami",
            None,
            &[("X-Agentsso-Control", token.as_str())],
        );
        if status == 200 {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Run `agentsso <args>` against `home` (no running daemon expected),
/// capturing exit code + stdout + stderr.
fn run_cli(home: &std::path::Path, args: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(agentsso_bin())
        .args(args)
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run agentsso CLI");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

// --------------------------------------------------------------------------
// (a) `quickstart --help` is a real subcommand.
// --------------------------------------------------------------------------

#[test]
fn quickstart_help_lists_subcommand_and_exits_zero() {
    let home = tempfile::TempDir::new().unwrap();
    let (status, stdout, stderr) = run_cli(home.path(), &["quickstart", "--help"]);
    assert_eq!(status, Some(0), "`quickstart --help` should exit 0; stderr={stderr}");
    assert!(
        stdout.contains("--read") && stdout.contains("--read-write"),
        "help should document the --read / --read-write access flags: {stdout}"
    );
    // The headless model forbids an approval/tier *mechanism*: there
    // must be no `--tier` flag and no approval-mode option. (The doc
    // text legitimately uses the word "approval" to state there is
    // NONE — "no approval, no prompt" — so a bare substring scan for
    // "approval" would be a false positive. Assert on the flag surface
    // instead.)
    assert!(
        !stdout.contains("--tier"),
        "help must NOT expose a `--tier` flag — access is the binary --read/--read-write \
         capability: {stdout}"
    );
    assert!(
        !stdout.to_lowercase().contains("approval-mode")
            && !stdout.to_lowercase().contains("--approve"),
        "help must NOT expose any approval-mode option — the daemon is headless: {stdout}"
    );
}

#[test]
fn quickstart_appears_in_top_level_help() {
    let home = tempfile::TempDir::new().unwrap();
    let (status, stdout, _stderr) = run_cli(home.path(), &["--help"]);
    assert_eq!(status, Some(0));
    assert!(stdout.contains("quickstart"), "top-level help should list `quickstart`: {stdout}");
}

// --------------------------------------------------------------------------
// (b) unknown service → `quickstart.unknown_service` exit 2.
// --------------------------------------------------------------------------

#[test]
fn quickstart_unknown_service_exits_2() {
    let home = tempfile::TempDir::new().unwrap();
    let (status, _stdout, stderr) =
        run_cli(home.path(), &["quickstart", "salesforce", "--read", "--non-interactive"]);
    assert_eq!(status, Some(2), "unknown service should exit 2; stderr={stderr}");
    assert!(
        stderr.contains("quickstart.unknown_service"),
        "stderr should name `quickstart.unknown_service`: {stderr}"
    );
}

// --------------------------------------------------------------------------
// (c) no daemon → reused `connect.daemon_must_run` block + the
//     `sudo agentsso setup` steer line, FAILURE.
// --------------------------------------------------------------------------

#[test]
fn quickstart_without_daemon_fails_with_must_run_and_setup_steer() {
    let home = tempfile::TempDir::new().unwrap();
    let (status, _stdout, stderr) =
        run_cli(home.path(), &["quickstart", "gmail", "--read", "--non-interactive"]);

    // `require_daemon_running` failure is operator-correctable → exit 2
    // (it attaches the `ConnectExitCode2` marker). Story 11.13 re-keyed
    // the error code to `connection.daemon_must_run`.
    assert_eq!(status, Some(2), "no daemon → exit 2; stderr={stderr}");
    assert!(
        stderr.contains("connection.daemon_must_run"),
        "stderr should carry the `connection.daemon_must_run` block: {stderr}"
    );
    assert!(
        stderr.contains("sudo agentsso setup"),
        "stderr should carry the single-privileged-step steer line: {stderr}"
    );

    // No agent artifacts written (the gate fires before registration).
    let agents_dir = home.path().join("agents");
    if agents_dir.exists() {
        let entries: Vec<_> =
            std::fs::read_dir(&agents_dir).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        for e in entries {
            let name = e.file_name();
            let name = name.to_string_lossy();
            assert!(
                !name.ends_with(".toml"),
                "agents dir should not contain agent files before the daemon gate: {name}"
            );
        }
    }
}

// --------------------------------------------------------------------------
// (d) `--non-interactive` with NO access flag →
//     `quickstart.access_unspecified` exit 2, no agent created.
// --------------------------------------------------------------------------

#[test]
fn quickstart_non_interactive_without_access_flag_errors() {
    let home = tempfile::TempDir::new().unwrap();
    let (status, _stdout, stderr) =
        run_cli(home.path(), &["quickstart", "gmail", "--non-interactive"]);
    assert_eq!(status, Some(2), "no access flag + non-interactive → exit 2; stderr={stderr}");
    assert!(
        stderr.contains("quickstart.access_unspecified"),
        "stderr should name `quickstart.access_unspecified`: {stderr}"
    );
    assert!(
        stderr.contains("--read") && stderr.contains("--read-write"),
        "remediation should point at the two access flags: {stderr}"
    );
    // The access gate fires before the daemon gate / registration: no
    // agent files, and stderr must NOT mention the daemon-running block.
    assert!(
        !stderr.contains("daemon_must_run"),
        "access gate must fire before the daemon gate: {stderr}"
    );
}

#[test]
fn quickstart_read_and_read_write_are_mutually_exclusive() {
    let home = tempfile::TempDir::new().unwrap();
    let (status, _stdout, stderr) = run_cli(
        home.path(),
        &["quickstart", "gmail", "--read", "--read-write", "--non-interactive"],
    );
    assert_eq!(status, Some(2), "clap conflict → exit 2; stderr={stderr}");
    assert!(
        stderr.contains("--read") || stderr.contains("--read-write"),
        "stderr should name the conflicting flag: {stderr}"
    );
}

#[test]
fn quickstart_headless_and_device_flow_are_mutually_exclusive() {
    let home = tempfile::TempDir::new().unwrap();
    let (status, _stdout, stderr) =
        run_cli(home.path(), &["quickstart", "gmail", "--read", "--headless", "--device-flow"]);
    assert_eq!(status, Some(2), "clap conflict → exit 2; stderr={stderr}");
    assert!(
        stderr.contains("--headless") || stderr.contains("--device-flow"),
        "stderr should name the conflicting flag: {stderr}"
    );
}

/// `--headless` must actually reach `OAuthSealInputs` (a clap-accept
/// test alone would pass with the flag parsed but never wired — the
/// exact bug class this flag's introduction fixes). EOF on stdin is
/// the headless paste flow's documented cancel path, so the run fails
/// without any Google round-trip — but ONLY the headless branch prints
/// the paste-consent block first. Asserting on that block proves the
/// flag propagated through quickstart into the OAuth dance.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quickstart_headless_flag_reaches_oauth_dance() {
    let home = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    let daemon = start_daemon(DaemonTestConfig {
        port: 0,
        home: home.path().to_path_buf(),
        ..Default::default()
    });
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon did not become healthy");
    assert!(wait_for_control_ready(home.path(), port), "daemon control plane did not become ready");

    let oauth_client = write_fake_oauth_client(home.path());
    let home_path = home.path().to_path_buf();
    let (status, stderr) = tokio::task::spawn_blocking(move || {
        let output = Command::new(agentsso_bin())
            .args([
                "quickstart",
                "gmail",
                "--read",
                "--headless",
                "--oauth-client",
                oauth_client.to_str().unwrap(),
            ])
            .env("AGENTSSO_PATHS__HOME", home_path.to_str().unwrap())
            .env("AGENTSSO_HTTP__BIND_ADDR", format!("127.0.0.1:{port}"))
            .env("AGENTSSO_TEST_MASTER_KEY_HEX", crate::common::TEST_MASTER_KEY_HEX)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("spawn agentsso quickstart --headless");
        (output.status.code(), String::from_utf8_lossy(&output.stderr).into_owned())
    })
    .await
    .expect("join quickstart child");

    assert!(
        stderr.contains("Paste redirect URL"),
        "headless paste prompt must render — the flag did not reach the OAuth dance: {stderr}"
    );
    assert_ne!(status, Some(0), "EOF on stdin is a cancel — the run must not succeed");
}

fn write_fake_oauth_client(home: &std::path::Path) -> std::path::PathBuf {
    // Valid-shape Google "installed app" client JSON — `resolve_oauth_client`
    // parses it so the device-flow dance can use its client_id.
    let path = home.join("client_secret.json");
    std::fs::write(
        &path,
        r#"{
            "installed": {
                "client_id": "quickstart-test-client.apps.googleusercontent.com",
                "client_secret": "GOCSPX-quickstart-test-secret",
                "project_id": "quickstart-test-project"
            }
        }"#,
    )
    .unwrap();
    path
}

/// Story 11.15: drive the FULL quickstart flow (connection add → register
/// → bind → snippet) to completion using a mock device-flow OAuth server
/// (debug builds honor `AGENTSSO_DEVICE_FLOW_*_URL`), then assert the
/// composed primitives produced a `ConnectionRecord` named
/// `<agent>-<connector>` at the right tier AND a binding for the agent.
///
/// This INVERTS the old "register-before-OAuth" causality: the repointed
/// quickstart does `connection add` (OAuth) FIRST, so the connection +
/// binding only exist after the dance completes — which the mock device-
/// flow lets happen deterministically in CI without real Google.
///
/// macOS bind-poll flake: under nextest load the daemon/CLI round-trips
/// can be slow. This is a known timing flake (NOT a regression — see
/// project_quickstart_e2e_macos_timing_flake); if it recurs, re-run the
/// suite (e.g. `cargo nextest run --retries 2` at the runner level — the
/// test body itself wires no retry).
async fn assert_quickstart_creates_connection_and_binding(connector: &str, write: bool) {
    let mut server = mockito::Server::new_async().await;
    let _device = server
        .mock("POST", "/device/code")
        .with_status(200)
        .with_body(
            r#"{"device_code":"dc","user_code":"AAAA-BBBB","verification_url":"https://example.test/verify","expires_in":1800,"interval":1}"#,
        )
        .expect_at_least(1)
        .create_async()
        .await;
    let _token = server
        .mock("POST", "/token")
        .with_status(200)
        .with_body(
            r#"{"access_token":"ya29.quickstart-fake","refresh_token":"1//quickstart-fake","expires_in":3600,"scope":"https://www.googleapis.com/auth/gmail.readonly"}"#,
        )
        .expect_at_least(1)
        .create_async()
        .await;

    let home = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    let daemon = start_daemon(DaemonTestConfig {
        port: 0,
        home: home.path().to_path_buf(),
        ..Default::default()
    });
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon did not become healthy");
    assert!(wait_for_control_ready(home.path(), port), "daemon control plane did not become ready");

    let oauth_client = write_fake_oauth_client(home.path());
    let agent = "me";
    let bare = connector; // gmail/calendar/drive — bare selectors here
    let expected_connection = format!("{agent}-{bare}");
    let expected_tier = if write { "read-write" } else { "read" };
    let access_flag = if write { "--read-write" } else { "--read" };

    // Run quickstart to completion (subprocess; blocking call inside the
    // async test — the mockito server runs in the background).
    let device_code_url = format!("{}/device/code", server.url());
    let token_url = format!("{}/token", server.url());
    let home_path = home.path().to_path_buf();
    let oauth_client_path = oauth_client.clone();
    let connector_owned = connector.to_owned();
    let (status, _stdout, stderr) = tokio::task::spawn_blocking(move || {
        let output = Command::new(agentsso_bin())
            .args([
                "quickstart",
                &connector_owned,
                access_flag,
                "--agent",
                "me",
                "--non-interactive",
                "--device-flow",
                "--device-flow-timeout",
                "30",
                "--oauth-client",
                oauth_client_path.to_str().unwrap(),
            ])
            .env("AGENTSSO_PATHS__HOME", home_path.to_str().unwrap())
            .env("AGENTSSO_HTTP__BIND_ADDR", format!("127.0.0.1:{port}"))
            .env("AGENTSSO_TEST_MASTER_KEY_HEX", crate::common::TEST_MASTER_KEY_HEX)
            .env("AGENTSSO_DEVICE_FLOW_DEVICE_CODE_URL", &device_code_url)
            .env("AGENTSSO_DEVICE_FLOW_TOKEN_URL", &token_url)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("spawn quickstart");
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    })
    .await
    .unwrap();

    assert_eq!(status, Some(0), "quickstart should complete (exit 0); stderr={stderr}");

    // Assert via the daemon control plane (the operator-observable surface):
    // the connection appears in `connection list` and the agent's binding
    // in `agent bindings`. Reading the on-disk stores would also work, but
    // the CLI surface is the contract.
    let conn_list = run_cli_capture(home.path(), port, &["connection", "list"]);
    assert!(
        conn_list.contains(&expected_connection),
        "connection list should show `{expected_connection}`: {conn_list}"
    );

    let bindings = run_cli_capture(home.path(), port, &["agent", "bindings", agent]);
    assert!(
        bindings.contains(&expected_connection),
        "agent bindings should list connection `{expected_connection}`: {bindings}"
    );
    assert!(
        bindings.contains(expected_tier),
        "agent bindings should show tier `{expected_tier}`: {bindings}"
    );

    drop(daemon);
}

/// Run an `agentsso` CLI subcommand against the running daemon and return
/// its stdout (panicking on a non-zero exit).
fn run_cli_capture(home: &std::path::Path, port: u16, args: &[&str]) -> String {
    let output = Command::new(agentsso_bin())
        .args(args)
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .env("AGENTSSO_HTTP__BIND_ADDR", format!("127.0.0.1:{port}"))
        .env("AGENTSSO_TEST_MASTER_KEY_HEX", crate::common::TEST_MASTER_KEY_HEX)
        .output()
        .expect("spawn agentsso CLI");
    assert_eq!(
        output.status.code(),
        Some(0),
        "`agentsso {}` should exit 0; stderr={}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quickstart_calendar_read_creates_connection_and_binding() {
    assert_quickstart_creates_connection_and_binding("calendar", false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quickstart_gmail_read_write_creates_connection_and_binding() {
    assert_quickstart_creates_connection_and_binding("gmail", true).await;
}
