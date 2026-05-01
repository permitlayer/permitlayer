//! Story 7.6c — `agentsso setup` daemon-running pre-flight tests.
//!
//! Pins the four behavioral claims of the pre-flight at
//! `crates/permitlayer-daemon/src/cli/setup.rs::run`:
//!
//! 1. **daemon running** → exit 3 with `setup_daemon_running` banner.
//! 2. **stale PID file** (PID points at a dead process) → setup
//!    proceeds (exit code != 3, no banner).
//! 3. **no PID file** → setup proceeds (exit code != 3, no banner).
//! 4. **corrupt PID file** (non-numeric content) → fail-closed branch
//!    fires → exit 3 with banner. Pins the load-bearing fail-closed
//!    posture documented in the pre-flight body.
//!
//! Tests 2/3/4 do not need a real daemon — they manipulate the PID
//! file directly. Test 1 uses `std::process::id()` (the test runner's
//! own PID) as a guaranteed-alive PID, which is enough to make
//! `PidFile::is_daemon_running` return `true`. This keeps the tests
//! deterministic and fast (no daemon spawn, no port allocation, no
//! Argon2id master-key bootstrap).

use std::process::{Command, Stdio};

use crate::common::agentsso_bin;

/// Spawn `agentsso setup gmail --oauth-client <fixture>` as a
/// subprocess against `home` and return the captured `Output`.
///
/// The fixture path doesn't need to be a valid OAuth client JSON —
/// the pre-flight runs BEFORE the JSON is read, so the test outcome
/// depends only on the PID-file state, not on whether OAuth could
/// theoretically complete.
fn run_setup(home: &std::path::Path) -> std::process::Output {
    let mut cmd = Command::new(agentsso_bin());
    cmd.env_clear()
        .envs(crate::common::forward_windows_required_env())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home.to_str().unwrap())
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .arg("setup")
        .arg("gmail")
        .arg("--oauth-client")
        .arg("/nonexistent-fixture/client_secret.json")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.output().expect("failed to spawn agentsso setup")
}

/// Write a PID file containing the given PID at `home/agentsso.pid`.
fn write_pid_file(home: &std::path::Path, pid: u32) {
    std::fs::write(home.join("agentsso.pid"), format!("{pid}\n")).expect("write PID file fixture");
}

/// Write a PID file with non-numeric content at `home/agentsso.pid`.
fn write_corrupt_pid_file(home: &std::path::Path) {
    std::fs::write(home.join("agentsso.pid"), b"not-a-number\n")
        .expect("write corrupt PID file fixture");
}

/// Test 1 — daemon running → exit 3 with `setup_daemon_running` banner.
///
/// We use `std::process::id()` as a guaranteed-live PID instead of
/// spawning a real daemon. This makes the test fully deterministic:
/// no port allocation, no master-key bootstrap, no health-poll race.
///
/// `#[cfg(not(windows))]` because the Windows liveness probe via
/// `tasklist` has known cross-process-self-spawn fragility under
/// nextest (deferred-work.md:910 / Story 7.7 Phase 4b notes). The
/// Unix `kill(pid, 0)` path is fully reliable.
#[test]
#[cfg(not(windows))]
fn setup_refuses_exit3_when_daemon_running() {
    let home = tempfile::tempdir().unwrap();
    write_pid_file(home.path(), std::process::id());

    let output = run_setup(home.path());

    assert_eq!(
        output.status.code(),
        Some(3),
        "expected exit 3 (daemon running), got {:?}; stderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("setup_daemon_running"),
        "stderr should name the refusal code; got:\n{stderr}"
    );
    assert!(
        stderr.contains("agentsso stop"),
        "stderr should include the stop-daemon remediation; got:\n{stderr}"
    );
}

/// Test 2 — stale PID file (PID does not point to a live process)
/// MUST NOT cause refusal. The fail-closed branch fires only on
/// probe ERROR, not on probe success-with-false.
#[test]
fn setup_does_not_refuse_with_stale_pid_file() {
    let home = tempfile::tempdir().unwrap();
    // PID 999_999_999 is well outside macOS / Linux / Windows PID
    // ranges (kern.maxproc on macOS caps around 1e5; Linux PID_MAX
    // defaults to 4_194_304 = 2^22). Guaranteed dead.
    write_pid_file(home.path(), 999_999_999);

    let output = run_setup(home.path());

    // Setup will fail with exit code 1 for an unrelated reason
    // (unreadable OAuth client JSON, since the fixture path doesn't
    // exist). The behavioral claim is "exit code != 3" — the
    // pre-flight did NOT fire.
    assert_ne!(
        output.status.code(),
        Some(3),
        "stale PID file must NOT cause refusal; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("setup_daemon_running"),
        "stale PID file must not produce the daemon-running banner; got:\n{stderr}"
    );
}

/// Test 3 — no PID file at all (fresh install) MUST NOT cause refusal.
#[test]
fn setup_does_not_refuse_when_no_pid_file() {
    let home = tempfile::tempdir().unwrap();

    let output = run_setup(home.path());

    assert_ne!(
        output.status.code(),
        Some(3),
        "missing PID file must NOT cause refusal; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("setup_daemon_running"),
        "missing PID file must not produce the daemon-running banner; got:\n{stderr}"
    );
}

/// Test 4 — corrupt PID file (non-numeric content) MUST trigger the
/// fail-closed branch and refuse. This pins the load-bearing
/// fail-closed posture: probing returns `Err(InvalidPidFile)`, the
/// `unwrap_or_else` block treats it as "daemon running for safety".
#[test]
fn setup_refuses_when_pid_file_corrupt() {
    let home = tempfile::tempdir().unwrap();
    write_corrupt_pid_file(home.path());

    let output = run_setup(home.path());

    assert_eq!(
        output.status.code(),
        Some(3),
        "corrupt PID file must trigger fail-closed refusal, got {:?}; stderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("setup_daemon_running"),
        "fail-closed branch must use the same banner as a real running daemon; got:\n{stderr}"
    );
}
