//! Story 5.4 AC #10 — log/audit path isolation test.
//!
//! Asserts the architectural invariant from NFR45: operational logs
//! (`~/.agentsso/logs/daemon.log`) and audit logs
//! (`~/.agentsso/audit/YYYY-MM-DD.jsonl`) are separate streams. A
//! message written via `tracing::info!`/`warn!`/etc. MUST NOT appear
//! in the audit log, and an `AuditEvent` written via `AuditStore::
//! append` MUST NOT appear in the operational log.
//!
//! We verify this by (1) spawning the daemon with a hermetic
//! master-key seam (Story 4.4 precedent), (2) waiting for startup,
//! (3) stopping the daemon, (4) inspecting both file paths for
//! cross-contamination.

// Both integration tests in this file are gated `cfg(not(windows))`
// (Winsock 10106 / nextest concurrency on Windows hosted runners);
// gate the helpers + imports they consume to match.
#[cfg(not(windows))]
use std::io::{Read, Write};
#[cfg(not(windows))]
use std::net::TcpStream;
#[cfg(not(windows))]
use std::process::{Command, Stdio};
#[cfg(not(windows))]
use std::time::{Duration, Instant};

/// Poll raw-HTTP `/health` up to `timeout`. Returns `true` when the
/// daemon responds with its healthy body. Matches the pattern in
/// `master_key_bootstrap_e2e.rs::wait_for_health` (convention: no
/// `reqwest` in e2e, keeps the subprocess test hermetic).
#[cfg(not(windows))]
fn wait_for_health(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(mut stream) = TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(100),
        ) {
            let _ = stream.write_all(
                format!(
                    "GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            );
            let mut buf = Vec::new();
            let _ = stream.read_to_end(&mut buf);
            let response = String::from_utf8_lossy(&buf);
            if response.contains("\"healthy\"") {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Spawn the daemon with the test master-key seam + bind to an
/// ephemeral port. Returns (child, home) — caller is responsible for
/// killing + cleanup.
#[cfg(not(windows))]
fn spawn_test_daemon() -> Option<(std::process::Child, tempfile::TempDir, u16)> {
    // Only run on debug builds; release builds compile out the
    // `AGENTSSO_TEST_MASTER_KEY_HEX` seam.
    if !cfg!(debug_assertions) {
        return None;
    }
    let home = tempfile::tempdir().unwrap();
    // Story 7.7: zero-port — the daemon binds atomically and emits the
    // OS-assigned port on stdout via `AGENTSSO_BOUND_ADDR=`.
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentsso"))
        .arg("start")
        .arg("--bind-addr")
        .arg("127.0.0.1:0")
        .env_clear()
        .envs(crate::common::forward_windows_required_env())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env("AGENTSSO_PATHS__HOME", home.path().as_os_str())
        .env("AGENTSSO_TEST_MASTER_KEY_HEX", "0042".repeat(16)) // 32 bytes of hex
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agentsso start");
    let port =
        crate::common::wait_for_bound_addr(&mut child, std::time::Duration::from_secs(10)).port();
    Some((child, home, port))
}

/// Cfg-gated to `not(windows)`: hosted Windows runners under
/// nextest contention occasionally hit Winsock transient bind
/// failures (`os error 10106 — service provider could not be
/// loaded or initialized`). The test contract (logs and audit
/// files are at distinct paths) is OS-agnostic and validated on
/// Linux + macOS; the Winsock-flake is an infrastructure-level
/// Windows runner issue that needs separate handling (bind retry
/// in the daemon's TCP binder, or nextest concurrency limit on
/// Windows).
#[cfg(not(windows))]
#[test]
fn log_and_audit_files_are_distinct_paths() {
    let Some((mut child, home, port)) = spawn_test_daemon() else {
        eprintln!("skipping: release build — test seam compiled out");
        return;
    };

    // Wait for daemon to be healthy (up to 10s).
    let healthy = wait_for_health(port, Duration::from_secs(10));
    // Always send SIGTERM to the child regardless of health — the
    // tempdir's Drop cleans up on panic too, but the subprocess would
    // otherwise linger.
    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        let pid = child.id();
        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
    }
    // Wait for exit.
    let _ = child.wait();

    if !healthy {
        // M16 fix: panic on unhealthy boot rather than silent-skip.
        // A skip here reduces CI signal to zero when the test matters
        // most (flaky environment). If this is flaky on CI we escalate
        // to `#[ignore]` with a tracking issue rather than silently
        // degrade the invariant check.
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            use std::io::Read;
            let _ = pipe.read_to_string(&mut stderr);
        }
        panic!("daemon did not become healthy within 10s: {stderr}");
    }

    // The two expected paths.
    let log_file = home.path().join("logs").join("daemon.log");
    let audit_dir = home.path().join("audit");

    // Operational log file must exist.
    assert!(log_file.exists(), "expected operational log at {}", log_file.display());
    let log_content = std::fs::read_to_string(&log_file).unwrap();

    // Log must be non-empty (startup banner lives here).
    assert!(!log_content.is_empty(), "operational log must not be empty");

    // Log must contain the boot signal.
    assert!(
        log_content.contains("daemon starting"),
        "operational log must contain startup banner: content-head={}",
        &log_content.chars().take(300).collect::<String>()
    );

    // Audit log MAY or may not exist (no agent-initiated requests
    // happened in this test). The invariant we check is content
    // isolation, not existence.
    if audit_dir.exists() {
        for entry in std::fs::read_dir(&audit_dir).unwrap().flatten() {
            let audit_content = std::fs::read_to_string(entry.path()).unwrap_or_default();
            // The tracing startup banner message must NOT appear in
            // any audit file.
            assert!(
                !audit_content.contains("daemon starting"),
                "audit log leaked operational event: {}",
                audit_content
            );
        }
    }
}

/// Cfg-gated to `not(windows)`: same Winsock 10106 / nextest-
/// concurrency rationale as `log_and_audit_files_are_distinct_paths`
/// in this file. The log-shape contract is OS-agnostic; verified
/// on Linux + macOS.
#[cfg(not(windows))]
#[test]
fn operational_log_contains_json_per_line_shape() {
    let Some((mut child, home, port)) = spawn_test_daemon() else {
        eprintln!("skipping: release build — test seam compiled out");
        return;
    };
    let healthy = wait_for_health(port, Duration::from_secs(10));

    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        let pid = child.id();
        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
    }
    let _ = child.wait();

    if !healthy {
        // M16 fix: panic on unhealthy boot, same reasoning as
        // `log_and_audit_files_are_distinct_paths`.
        panic!("daemon did not become healthy within 10s");
    }

    let log_file = home.path().join("logs").join("daemon.log");
    assert!(log_file.exists(), "log file must exist");
    let content = std::fs::read_to_string(&log_file).unwrap();
    assert!(!content.is_empty(), "log file must contain the startup banner");

    // Every non-empty line must parse as JSON.
    let mut lines_tested = 0;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| {
            panic!("log line must be valid JSON (shape contract): {e}\nline: {line}")
        });
        assert!(parsed.get("timestamp").is_some(), "line must have timestamp: {line}");
        assert!(parsed.get("level").is_some(), "line must have level: {line}");
        lines_tested += 1;
    }
    assert!(lines_tested > 0, "expected at least one JSON log line");
}

/// L15 fix: renamed and narrowed to reflect what the test actually
/// verifies — that `<REDACTED>` markers produced by the
/// `RedactingWriter` survive end-to-end through the `agentsso logs`
/// CLI pipeline without further transformation. The PIPELINE
/// invariant: once a redacted line is on disk, the reader renders it
/// as-is with the marker intact.
///
/// Actual redaction behavior (raw-token → marker) is covered
/// exhaustively by `telemetry::filter::tests` (24 positive+negative
/// pattern tests) plus the `redacting_writer_round_trip_agt_v1_token`
/// test in `telemetry::tests`. Those exercise the subscriber-layer
/// redactor directly and do not need a daemon boot.
/// Cfg-gated to `not(windows)`: same Winsock 10106 / nextest-
/// concurrency rationale as the other tests in this file. Coverage
/// for the redaction subscriber-layer behavior is preserved by
/// `telemetry::filter::tests` and
/// `telemetry::tests::redacting_writer_round_trip_agt_v1_token`
/// which run on every platform (no daemon boot required).
#[cfg(not(windows))]
#[test]
fn redacted_marker_survives_end_to_end_through_logs_pipeline() {
    let home = tempfile::tempdir().unwrap();
    let log_dir = home.path().join("logs");
    std::fs::create_dir_all(&log_dir).unwrap();
    let log_file = log_dir.join("daemon.log");
    // Seed a line with the marker the subscriber would have produced
    // after redaction. If the CLI path ever inadvertently
    // post-processes this content, the assertion fails.
    let mut f = std::fs::File::create(&log_file).unwrap();
    writeln!(
        f,
        r#"{{"timestamp":"2026-04-16T14:30:00Z","level":"INFO","target":"t","fields":{{"message":"bearer agt_v1_<REDACTED> seen"}}}}"#
    )
    .unwrap();
    drop(f);

    let output = Command::new(env!("CARGO_BIN_EXE_agentsso"))
        .arg("logs")
        .arg("--no-pager")
        .env("AGENTSSO_PATHS__HOME", home.path().as_os_str())
        .env("NO_COLOR", "1")
        .output()
        .expect("run agentsso logs");
    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("<REDACTED>"), "redacted marker must propagate: {stdout}");
    // And confirm nothing added a raw-token pattern that the CLI
    // would have had to undo to produce.
    assert!(
        !stdout.contains("agt_v1_secret") && !stdout.contains("agt_v1_raw"),
        "no raw token must appear in CLI output: {stdout}"
    );
}
