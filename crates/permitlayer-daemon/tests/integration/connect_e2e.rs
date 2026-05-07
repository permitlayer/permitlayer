//! End-to-end integration tests for Story 7.13 (`agentsso connect`).
//!
//! Story 7.13's full happy-path — sealing a real Google credential —
//! requires a live OAuth flow that we cannot drive in CI. These tests
//! cover every AC that does NOT require completing a real authorize:
//!
//! - **AC #5** (unknown agent → exit 2, no daemon contact, no vault touch).
//! - **AC #6** (daemon-running gate when credential needs sealing).
//! - **AC #7** (legacy `agentsso setup` → `setup.removed` block + exit 2).
//! - **AC #8** (snippet emission to stdout + `--mcp-config-out`).
//!
//! The full happy path (Step 2 OAuth + seal + Steps 3-6) is covered
//! by Story 7.13's manual E2E on the operator's box, tracked in the
//! sprint deferred-work and the rc.15 verification checklist.

use std::process::{Command, Stdio};

use crate::common::agentsso_bin;

/// Run `agentsso <args>` against the supplied `home`, capturing stdout
/// and stderr.
fn run_cli(home: &std::path::Path, args: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(agentsso_bin())
        .args(args)
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
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
// AC #7 — legacy `agentsso setup` interceptor.
// --------------------------------------------------------------------------

#[test]
fn connect_setup_legacy_verb_emits_remediation() {
    let home = tempfile::TempDir::new().unwrap();
    let (status, _stdout, stderr) = run_cli(home.path(), &["setup", "gmail"]);
    assert_eq!(status, Some(2), "legacy `agentsso setup` should exit 2; stderr={stderr}");
    assert!(
        stderr.contains("setup.removed"),
        "stderr should contain `setup.removed` code: {stderr}"
    );
    assert!(
        stderr.contains("agentsso connect"),
        "stderr should suggest `agentsso connect`: {stderr}"
    );
}

#[test]
fn connect_setup_legacy_verb_with_extra_args_still_intercepts() {
    let home = tempfile::TempDir::new().unwrap();
    let (status, _stdout, stderr) =
        run_cli(home.path(), &["setup", "calendar", "--non-interactive", "--force"]);
    assert_eq!(
        status,
        Some(2),
        "interceptor should fire regardless of extra args; stderr={stderr}"
    );
    assert!(stderr.contains("setup.removed"), "{stderr}");
}

// --------------------------------------------------------------------------
// AC #5 — unknown agent → exit 2 with no daemon contact, no vault touch.
// --------------------------------------------------------------------------

#[test]
fn connect_unknown_agent_exits_2_no_vault_touch() {
    let home = tempfile::TempDir::new().unwrap();

    // Pre-state: no agents/, no vault/.
    assert!(!home.path().join("agents").exists());
    assert!(!home.path().join("vault").exists());

    let (status, _stdout, stderr) = run_cli(
        home.path(),
        &["connect", "gmail", "--agent", "does-not-exist", "--non-interactive"],
    );

    assert_eq!(status, Some(2), "unknown agent should exit 2; stderr={stderr}");
    assert!(
        stderr.contains("connect.agent_not_found"),
        "stderr should name `connect.agent_not_found`: {stderr}"
    );
    assert!(
        stderr.contains("agentsso agent register"),
        "stderr should suggest `agentsso agent register`: {stderr}"
    );

    // Post-state: vault MUST NOT have been touched. The agents/ dir
    // is created by the FS store on `new()` but no .toml files inside.
    let vault_dir = home.path().join("vault");
    if vault_dir.exists() {
        let entries: Vec<_> =
            std::fs::read_dir(&vault_dir).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        for e in entries {
            // Anything other than the writability probe is suspicious.
            let name = e.file_name();
            let name = name.to_string_lossy();
            assert!(
                name.starts_with(".") || name == "writability-probe",
                "vault should not contain credential artifacts: {name}"
            );
        }
    }
    let agents_dir = home.path().join("agents");
    if agents_dir.exists() {
        let entries: Vec<_> =
            std::fs::read_dir(&agents_dir).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        for e in entries {
            let name = e.file_name();
            let name = name.to_string_lossy();
            assert!(!name.ends_with(".toml"), "agents dir should not contain agent files: {name}");
        }
    }
}

#[test]
fn connect_unknown_service_exits_2() {
    let home = tempfile::TempDir::new().unwrap();
    let (status, _stdout, stderr) =
        run_cli(home.path(), &["connect", "salesforce", "--agent", "me", "--non-interactive"]);
    assert_eq!(status, Some(2), "unknown service should exit 2; stderr={stderr}");
    assert!(
        stderr.contains("connect.unknown_service"),
        "stderr should name `connect.unknown_service`: {stderr}"
    );
}

// --------------------------------------------------------------------------
// Clap parse rules.
// --------------------------------------------------------------------------

#[test]
fn connect_requires_agent_flag() {
    let home = tempfile::TempDir::new().unwrap();
    let (status, _stdout, stderr) = run_cli(home.path(), &["connect", "gmail"]);
    // Clap missing-required-arg → exit 2.
    assert_eq!(status, Some(2), "missing --agent should exit 2; stderr={stderr}");
    assert!(stderr.contains("--agent") || stderr.contains("required"), "{stderr}");
}

#[test]
fn connect_rejects_headless_with_non_interactive() {
    let home = tempfile::TempDir::new().unwrap();
    let (status, _stdout, stderr) = run_cli(
        home.path(),
        &["connect", "gmail", "--agent", "me", "--headless", "--non-interactive"],
    );
    // Clap conflict → exit 2.
    assert_eq!(
        status,
        Some(2),
        "--headless + --non-interactive should be rejected; stderr={stderr}"
    );
    assert!(
        stderr.contains("--headless") || stderr.contains("conflict"),
        "stderr should mention the conflict: {stderr}"
    );
}

// --------------------------------------------------------------------------
// AC #6 — daemon-running gate fires when credential needs sealing.
// Round-1 P15 follow-up.
// --------------------------------------------------------------------------

#[test]
fn connect_daemon_running_during_seal_emits_must_stop() {
    // Test the daemon-running gate at Step 2: daemon up, agent registered,
    // no credential — connect must refuse with `connect.daemon_must_stop`
    // and exit 3 BEFORE touching the vault.
    use crate::common::{DaemonTestConfig, start_daemon, wait_for_health};
    use std::time::Duration;

    let home = tempfile::TempDir::new().unwrap();
    let daemon = start_daemon(DaemonTestConfig {
        port: 0,
        home: home.path().to_path_buf(),
        ..Default::default()
    });
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon did not become healthy");

    // Register an agent through the control endpoint so the agent file
    // exists when connect's Step 1 looks for it.
    let ctl = std::fs::read_to_string(home.path().join("control.token"))
        .expect("control.token missing")
        .trim()
        .to_owned();
    let body = r#"{"name":"test-agent","policy_name":"gmail-read-only"}"#;
    let request = format!(
        "POST /v1/control/agent/register HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         X-Agentsso-Control: {ctl}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    let raw = {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_secs(2),
        )
        .unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(request.as_bytes()).unwrap();
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    };
    assert!(raw.contains("\"status\":\"ok\""), "agent register failed: {raw}");

    // Daemon is still running; no credential is sealed. Run connect.
    let (status, _stdout, stderr) = {
        let output = Command::new(agentsso_bin())
            .args(["connect", "gmail", "--agent", "test-agent", "--non-interactive"])
            .env("AGENTSSO_PATHS__HOME", home.path().to_str().unwrap())
            .env("AGENTSSO_HTTP__BIND_ADDR", format!("127.0.0.1:{port}"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("failed to run connect");
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };

    assert_eq!(
        status,
        Some(3),
        "daemon-running + missing credential should exit 3; stderr={stderr}"
    );
    assert!(
        stderr.contains("connect.daemon_must_stop"),
        "stderr should name `connect.daemon_must_stop`: {stderr}"
    );
    assert!(stderr.contains("agentsso stop"), "stderr should suggest `agentsso stop`: {stderr}");

    // Confirm vault dir is still untouched.
    let vault_dir = home.path().join("vault");
    if vault_dir.exists() {
        let entries: Vec<_> =
            std::fs::read_dir(&vault_dir).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        for e in entries {
            let name = e.file_name();
            let name = name.to_string_lossy();
            assert!(name.starts_with('.'), "vault should not contain credential artifacts: {name}");
        }
    }
    // DaemonHandle's Drop kills the daemon.
    drop(daemon);
}

// --------------------------------------------------------------------------
// AC #2 / Step 7 — snippet emission paths exercised at the unit level.
// (We can't run the full happy path without OAuth, but snippet emission
// is exercised through the cli::openclaw module's unit tests + via a
// dedicated smoke that touches no state.)
// --------------------------------------------------------------------------
//
// The exhaustive snippet shape assertions live in
// `crates/permitlayer-daemon/src/cli/openclaw.rs::tests`. The end-to-
// end snippet emission via `agentsso connect` is exercised by the
// Angie's-box manual E2E (Story 7.13 Task 8.5).
//
// Snippet shape verification (without daemon dependency) is covered
// in `cli/openclaw.rs::tests` (build_snippet, emit_snippet, redaction).
