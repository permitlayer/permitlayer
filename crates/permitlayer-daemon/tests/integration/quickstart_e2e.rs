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

use std::io::{Read, Write};
#[cfg(not(target_os = "macos"))]
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::common::{DaemonTestConfig, agentsso_bin, start_daemon, wait_for_health};

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
    // (it attaches connect's ConnectExitCode2 marker, same as
    // `connect_without_daemon_exits_2_with_must_run_block`).
    assert_eq!(status, Some(2), "no daemon → exit 2; stderr={stderr}");
    assert!(
        stderr.contains("connect.daemon_must_run"),
        "stderr should reuse connect's `connect.daemon_must_run` block: {stderr}"
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
        !stderr.contains("connect.daemon_must_run"),
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

// --------------------------------------------------------------------------
// (e)/(f) daemon up — agent is registered + bound to the resolved
// policy BEFORE connect's OAuth stage.
//
// connect's non-interactive OAuth stage spins a local callback server
// that waits up to 120s for a redirect that never comes (no real
// Google round-trip in CI). Rather than block the suite for 2 minutes
// per case, we spawn quickstart, poll `/v1/control/agent/list` until
// the agent appears bound to the expected policy (proving register +
// bind completed AND the flow advanced into connect's OAuth stage),
// then terminate the child. This asserts exactly the spec contract —
// register+bind happens first — without the wall-clock hang.
// --------------------------------------------------------------------------

/// Issue `GET /v1/control/agent/list` and return the parsed JSON. On
/// macOS control routes are UDS-only (Story 7.27); elsewhere TCP
/// loopback. The token is read from `<home>/control.token`.
fn agent_list(home: &std::path::Path, port: u16) -> serde_json::Value {
    let token = std::fs::read_to_string(home.join("control.token"))
        .expect("control.token readable")
        .trim()
        .to_owned();
    let request = format!(
        "GET /v1/control/agent/list HTTP/1.1\r\nHost: localhost\r\n\
         X-Agentsso-Control: {token}\r\nConnection: close\r\n\r\n"
    );

    let raw = {
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::net::UnixStream;
            let _ = port;
            let sock = home.join("run").join("control.sock");
            let mut stream = UnixStream::connect(&sock)
                .unwrap_or_else(|e| panic!("connect UDS at {}: {e}", sock.display()));
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).expect("read agent list over UDS");
            String::from_utf8_lossy(&buf).into_owned()
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = home;
            let mut stream = TcpStream::connect_timeout(
                &format!("127.0.0.1:{port}").parse().unwrap(),
                Duration::from_secs(2),
            )
            .expect("connect daemon TCP");
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            let mut buf = Vec::new();
            let _ = stream.read_to_end(&mut buf);
            String::from_utf8_lossy(&buf).into_owned()
        }
    };

    let body = raw.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("").trim();
    serde_json::from_str(body)
        .unwrap_or_else(|e| panic!("agent list body not JSON: {e}; raw={raw}"))
}

/// Poll the agent list until `agent` appears bound to `expected_policy`,
/// or the deadline elapses. Returns the matched binding's policy name.
fn wait_for_agent_bound(
    home: &std::path::Path,
    port: u16,
    agent: &str,
    expected_policy: &str,
) -> Option<String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let list = agent_list(home, port);
        if let Some(agents) = list.get("agents").and_then(|a| a.as_array()) {
            for a in agents {
                if a.get("name").and_then(|n| n.as_str()) == Some(agent) {
                    let pol = a
                        .get("policy_name")
                        .and_then(|p| p.as_str())
                        .unwrap_or_default()
                        .to_owned();
                    assert_eq!(
                        pol, expected_policy,
                        "agent {agent} must be bound to {expected_policy}, got {pol}"
                    );
                    return Some(pol);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    None
}

fn write_fake_oauth_client(home: &std::path::Path) -> std::path::PathBuf {
    // Valid-shape Google "installed app" client JSON — connect's
    // `resolve_oauth_client` parses it successfully so the flow
    // advances PAST register+bind into the OAuth stage (where it
    // would block on the never-arriving redirect; we kill it there).
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

#[cfg(unix)]
fn terminate(child: &mut std::process::Child) {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;
    let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM);
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(not(unix))]
fn terminate(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn assert_quickstart_registers_then_oauth(service: &str, write: bool) {
    let home = tempfile::TempDir::new().unwrap();
    let daemon = start_daemon(DaemonTestConfig {
        port: 0,
        home: home.path().to_path_buf(),
        ..Default::default()
    });
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon did not become healthy");

    let oauth_client = write_fake_oauth_client(home.path());
    let agent = format!("{service}-quickstart");
    let expected_policy =
        if write { format!("{service}-read-write") } else { format!("{service}-read-only") };
    let access_flag = if write { "--read-write" } else { "--read" };

    let mut child = Command::new(agentsso_bin())
        .args([
            "quickstart",
            service,
            access_flag,
            "--non-interactive",
            "--oauth-client",
            oauth_client.to_str().unwrap(),
        ])
        .env("AGENTSSO_PATHS__HOME", home.path().to_str().unwrap())
        .env("AGENTSSO_HTTP__BIND_ADDR", format!("127.0.0.1:{port}"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn quickstart");

    // Register+bind must complete (and the flow must advance into
    // connect's OAuth stage, which is where the child now blocks).
    let bound = wait_for_agent_bound(home.path(), port, &agent, &expected_policy);

    terminate(&mut child);
    drop(daemon);

    assert_eq!(
        bound,
        Some(expected_policy.clone()),
        "quickstart must register `{agent}` bound to `{expected_policy}` BEFORE \
         connect's OAuth stage"
    );
}

#[test]
fn quickstart_calendar_read_registers_calendar_read_only_then_oauth() {
    assert_quickstart_registers_then_oauth("calendar", false);
}

#[test]
fn quickstart_gmail_read_write_registers_gmail_read_write_then_oauth() {
    assert_quickstart_registers_then_oauth("gmail", true);
}
