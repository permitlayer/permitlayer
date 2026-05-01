//! Story 7.6c — `agentsso credentials refresh` daemon-running pre-flight tests.
//!
//! Symmetric to `setup_daemon_conflict.rs` for the refresh path.
//!
//! 1. **daemon running** → exit 3 with
//!    `credentials_refresh_daemon_running` banner.
//! 2. **no PID file** → refresh proceeds (exit code != 3, no banner).
//!
//! We don't repeat the stale-PID and corrupt-PID tests here — they
//! exercise the same `PidFile::is_daemon_running` code path covered
//! by `setup_daemon_conflict.rs`. The 7.6c contract is: setup and
//! refresh share the pre-flight body verbatim, so testing each
//! branch on both sides would be redundant. The two tests here pin
//! the wiring (refresh routes through `credentials_refresh_to_exit_code`,
//! the marker downcasts correctly, the banner code matches).

use std::process::{Command, Stdio};

use crate::common::agentsso_bin;

fn run_credentials_refresh(home: &std::path::Path) -> std::process::Output {
    let mut cmd = Command::new(agentsso_bin());
    cmd.env_clear()
        .envs(crate::common::forward_windows_required_env())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home.to_str().unwrap())
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .arg("credentials")
        .arg("refresh")
        .arg("gmail")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.output().expect("failed to spawn agentsso credentials refresh")
}

// Only callers of `write_pid_file` are the cfg-gated daemon-running
// test below. Gate the helper too so Windows builds (where the test
// is excluded) don't trip `-D dead_code`.
#[cfg(not(windows))]
fn write_pid_file(home: &std::path::Path, pid: u32) {
    std::fs::write(home.join("agentsso.pid"), format!("{pid}\n")).expect("write PID file fixture");
}

#[test]
#[cfg(not(windows))]
fn credentials_refresh_refuses_exit3_when_daemon_running() {
    let home = tempfile::tempdir().unwrap();
    write_pid_file(home.path(), std::process::id());

    let output = run_credentials_refresh(home.path());

    assert_eq!(
        output.status.code(),
        Some(3),
        "expected exit 3 (daemon running), got {:?}; stderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("credentials_refresh_daemon_running"),
        "stderr should name the refusal code; got:\n{stderr}"
    );
    assert!(
        stderr.contains("agentsso stop"),
        "stderr should include the stop-daemon remediation; got:\n{stderr}"
    );
}

#[test]
fn credentials_refresh_does_not_refuse_when_no_pid_file() {
    let home = tempfile::tempdir().unwrap();

    let output = run_credentials_refresh(home.path());

    // Refresh will exit non-zero for a different reason (no vault
    // exists, no credentials seeded). The behavioral claim is
    // "exit code != 3" — the pre-flight did NOT fire.
    assert_ne!(
        output.status.code(),
        Some(3),
        "missing PID file must NOT cause refusal; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("credentials_refresh_daemon_running"),
        "missing PID file must not produce the daemon-running banner; got:\n{stderr}"
    );
}
