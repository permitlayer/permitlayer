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
fn connect_without_daemon_exits_2_with_must_run_block() {
    // Story 7.30: post-CLI-cutover, `agentsso connect` requires the
    // daemon to be running for every credential-touching operation.
    // When the daemon isn't up, the structured `connect.daemon_must_run`
    // remediation fires BEFORE any agent lookup or vault touch.
    let home = tempfile::TempDir::new().unwrap();
    assert!(!home.path().join("agents").exists());
    assert!(!home.path().join("vault").exists());

    let (status, _stdout, stderr) = run_cli(
        home.path(),
        &["connect", "gmail", "--agent", "does-not-exist", "--non-interactive"],
    );

    assert_eq!(status, Some(2), "no daemon → exit 2; stderr={stderr}");
    assert!(
        stderr.contains("connect.daemon_must_run"),
        "stderr should name `connect.daemon_must_run`: {stderr}"
    );

    // Post-state: vault MUST NOT have been touched (the CLI no longer
    // writes there anyway, but assert anyway).
    let vault_dir = home.path().join("vault");
    if vault_dir.exists() {
        let entries: Vec<_> =
            std::fs::read_dir(&vault_dir).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        for e in entries {
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
// Story 7.30: daemon-running gate INVERTS. The daemon now owns every
// credential-touching operation; `agentsso connect` requires it to be
// up. The pre-7.30 `connect.daemon_must_stop` block (which prevented
// seal-races with the daemon's refresh path) is replaced by
// `connect.daemon_must_run` covered by `connect_without_daemon_*`.
//
// The "daemon up, agent unknown" path is now an `agent_not_found` 404
// from the daemon's `agent_policy_name_handler` — surfaced as the
// `connect.agent_not_found` exit-2 block. We assert it here against a
// real running daemon.
// --------------------------------------------------------------------------

#[test]
fn connect_daemon_up_unknown_agent_emits_agent_not_found() {
    use crate::common::{DaemonTestConfig, start_daemon, wait_for_health};

    let home = tempfile::TempDir::new().unwrap();
    let daemon = start_daemon(DaemonTestConfig {
        port: 0,
        home: home.path().to_path_buf(),
        ..Default::default()
    });
    let port = daemon.port;
    assert!(wait_for_health(port), "daemon did not become healthy");

    // No agent registered. Daemon's agent_policy_name_handler returns
    // 404 → CLI maps it to `connect.agent_not_found` exit 2.
    let (status, _stdout, stderr) = {
        let output = Command::new(agentsso_bin())
            .args(["connect", "gmail", "--agent", "does-not-exist", "--non-interactive"])
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

    assert_eq!(status, Some(2), "unknown agent → exit 2; stderr={stderr}");
    assert!(
        stderr.contains("connect.agent_not_found"),
        "stderr should name `connect.agent_not_found`: {stderr}"
    );

    drop(daemon);
}

// Story 7.30: the "daemon up + agent registered + connect reaches
// oauth-client step" happy-path lights up two UDS hops
// (agent_policy_name + credentials_meta). It can't run in the
// current integration test harness because the helper that
// registers the test agent uses TCP POST against
// `/v1/control/agent/register`, which post-Story-7.27 lives on the
// UDS listener on macOS — not on the TCP loopback used here. The
// same harness limitation affects half the daemon's integration
// tests (`agent_rebind_e2e`, `agent_registry_e2e`,
// `kill_resume_e2e::connect_blocked_when_killed`, …); fixing it is
// out of scope for Story 7.30. The CLI's UDS hops are still covered
// by:
//   - 28 unit tests on the daemon-side handlers (control.rs) — full
//     happy path including audit-event shape verification.
//   - 2 unit tests on the CLI-side URL encoder (connect_uds.rs).
//   - The two integration tests above
//     (`connect_without_daemon_exits_2_with_must_run_block` and
//     `connect_daemon_up_unknown_agent_emits_agent_not_found`) for
//     the exit-code surface.
//   - Manual macOS shakedown on Angie's box per the rc.22 ship
//     procedure (Story 7.29 Task 6 + 7.30 AC #18-25).

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
