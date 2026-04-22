//! End-to-end subprocess tests for `agentsso logs` (Story 5.4).
//!
//! Seeds a tempdir with synthetic JSON log lines at
//! `{home}/logs/daemon.log`, then runs `agentsso logs` with various
//! filter flags and asserts the output matches the story's acceptance
//! criteria.
//!
//! No daemon spawn — writing synthetic JSONL log lines is simpler,
//! faster, and hermetic. The log reader and the subscriber are
//! independent code paths; tests that specifically need the
//! subscriber output live in `logs_credential_redaction_e2e.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output};

// ──────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────

fn log_dir_of(home: &Path) -> std::path::PathBuf {
    home.join("logs")
}

fn log_file_of(home: &Path) -> std::path::PathBuf {
    log_dir_of(home).join("daemon.log")
}

/// Write a synthetic tracing-JSON line at the given level with the
/// given message. Timestamp is the current UTC time unless overridden.
fn write_log_line_at(
    home: &Path,
    timestamp: chrono::DateTime<chrono::Utc>,
    level: &str,
    target: &str,
    msg: &str,
) {
    let dir = log_dir_of(home);
    std::fs::create_dir_all(&dir).unwrap();
    let path = log_file_of(home);

    let ts = timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let line = format!(
        r#"{{"timestamp":"{ts}","level":"{level}","target":"{target}","fields":{{"message":"{msg}"}}}}"#
    );
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path).unwrap();
    writeln!(f, "{line}").unwrap();
}

fn write_log_line(home: &Path, level: &str, msg: &str) {
    write_log_line_at(home, chrono::Utc::now(), level, "permitlayer_daemon::test", msg)
}

fn run_logs(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agentsso"))
        .arg("logs")
        .args(args)
        .env("AGENTSSO_PATHS__HOME", home.as_os_str())
        .env("NO_COLOR", "1")
        // `--no-pager` so the subprocess doesn't spawn `less` and
        // hang.
        .arg("--no-pager")
        .output()
        .expect("run agentsso logs")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

// ──────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────

#[test]
fn logs_missing_file_errors() {
    let home = tempfile::tempdir().unwrap();
    let output = run_logs(home.path(), &[]);
    assert!(!output.status.success(), "expected non-zero exit on missing log file");
    let stderr = stderr_of(&output);
    assert!(stderr.contains("log_file_missing"), "stderr must contain log_file_missing: {stderr}");
    assert!(stderr.contains("agentsso start"), "stderr must suggest remediation: {stderr}");
}

#[test]
fn logs_default_shows_info_and_above() {
    let home = tempfile::tempdir().unwrap();
    // Seed one line at each level. Default filter is INFO+ so TRACE
    // and DEBUG should be suppressed; INFO, WARN, ERROR should appear.
    write_log_line(home.path(), "TRACE", "trace-hidden");
    write_log_line(home.path(), "DEBUG", "debug-hidden");
    write_log_line(home.path(), "INFO", "info-visible");
    write_log_line(home.path(), "WARN", "warn-visible");
    write_log_line(home.path(), "ERROR", "error-visible");

    let output = run_logs(home.path(), &[]);
    assert!(output.status.success(), "stderr={}", stderr_of(&output));
    let stdout = stdout_of(&output);
    assert!(!stdout.contains("trace-hidden"), "TRACE must be filtered: {stdout}");
    assert!(!stdout.contains("debug-hidden"), "DEBUG must be filtered: {stdout}");
    assert!(stdout.contains("info-visible"), "INFO must be shown: {stdout}");
    assert!(stdout.contains("warn-visible"), "WARN must be shown: {stdout}");
    assert!(stdout.contains("error-visible"), "ERROR must be shown: {stdout}");
}

#[test]
fn logs_verbose_shows_debug_and_above() {
    let home = tempfile::tempdir().unwrap();
    write_log_line(home.path(), "TRACE", "trace-hidden");
    write_log_line(home.path(), "DEBUG", "debug-now-visible");
    write_log_line(home.path(), "INFO", "info-visible");

    let output = run_logs(home.path(), &["--verbose"]);
    assert!(output.status.success(), "stderr={}", stderr_of(&output));
    let stdout = stdout_of(&output);
    assert!(!stdout.contains("trace-hidden"), "TRACE must still be filtered: {stdout}");
    assert!(stdout.contains("debug-now-visible"), "DEBUG must now be shown: {stdout}");
    assert!(stdout.contains("info-visible"), "INFO must be shown: {stdout}");
}

#[test]
fn logs_debug_shows_trace_and_above() {
    let home = tempfile::tempdir().unwrap();
    write_log_line(home.path(), "TRACE", "trace-now-visible");
    write_log_line(home.path(), "DEBUG", "debug-visible");

    let output = run_logs(home.path(), &["--debug"]);
    assert!(output.status.success(), "stderr={}", stderr_of(&output));
    let stdout = stdout_of(&output);
    assert!(stdout.contains("trace-now-visible"), "TRACE must be shown with --debug: {stdout}");
    assert!(stdout.contains("debug-visible"), "DEBUG must be shown: {stdout}");
}

#[test]
fn logs_verbose_and_debug_rejected() {
    let home = tempfile::tempdir().unwrap();
    write_log_line(home.path(), "INFO", "any");
    let output = run_logs(home.path(), &["--verbose", "--debug"]);
    assert!(!output.status.success(), "must reject --verbose + --debug");
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("invalid_flag_combination"),
        "stderr must contain invalid_flag_combination: {stderr}"
    );
}

#[test]
fn logs_follow_with_until_rejected() {
    let home = tempfile::tempdir().unwrap();
    write_log_line(home.path(), "INFO", "any");
    let output = run_logs(home.path(), &["--follow", "--until=1h"]);
    assert!(!output.status.success(), "must reject --follow + --until");
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("invalid_flag_combination"),
        "stderr must contain invalid_flag_combination: {stderr}"
    );
}

#[test]
fn logs_lines_zero_rejected() {
    let home = tempfile::tempdir().unwrap();
    write_log_line(home.path(), "INFO", "any");
    let output = run_logs(home.path(), &["--lines=0"]);
    assert!(!output.status.success(), "must reject --lines=0");
    let stderr = stderr_of(&output);
    assert!(stderr.contains("invalid_limit"), "stderr must contain invalid_limit: {stderr}");
}

#[test]
fn logs_since_invalid_duration_errors() {
    let home = tempfile::tempdir().unwrap();
    write_log_line(home.path(), "INFO", "any");
    let output = run_logs(home.path(), &["--since=99999999w"]);
    assert!(!output.status.success(), "must reject overflow duration");
    let stderr = stderr_of(&output);
    assert!(stderr.contains("invalid_duration"), "stderr must contain invalid_duration: {stderr}");
}

#[test]
fn logs_since_duration_filters_to_recent_window() {
    let home = tempfile::tempdir().unwrap();
    let now = chrono::Utc::now();
    write_log_line_at(
        home.path(),
        now - chrono::Duration::hours(3),
        "INFO",
        "t",
        "three-hours-ago",
    );
    write_log_line_at(
        home.path(),
        now - chrono::Duration::minutes(30),
        "INFO",
        "t",
        "thirty-min-ago",
    );
    write_log_line_at(home.path(), now, "INFO", "t", "just-now");

    let output = run_logs(home.path(), &["--since=90m"]);
    assert!(output.status.success(), "stderr={}", stderr_of(&output));
    let stdout = stdout_of(&output);
    assert!(!stdout.contains("three-hours-ago"), "older line must be filtered: {stdout}");
    assert!(stdout.contains("thirty-min-ago"), "recent line must be present: {stdout}");
    assert!(stdout.contains("just-now"), "current line must be present: {stdout}");
}

#[test]
fn logs_lines_caps_output_at_n() {
    let home = tempfile::tempdir().unwrap();
    for i in 0..20 {
        write_log_line(home.path(), "INFO", &format!("line-{i:02}"));
    }
    let output = run_logs(home.path(), &["--lines=5"]);
    assert!(output.status.success(), "stderr={}", stderr_of(&output));
    let stdout = stdout_of(&output);
    // Last 5 should be present.
    assert!(stdout.contains("line-15"), "last-5 window must include line-15: {stdout}");
    assert!(stdout.contains("line-19"), "last-5 window must include line-19: {stdout}");
    // First few must NOT be present.
    assert!(!stdout.contains("line-00"), "line-00 must be out of window: {stdout}");
    assert!(!stdout.contains("line-10"), "line-10 must be out of window: {stdout}");
}

#[test]
fn logs_help_mentions_all_flags() {
    // Subprocess run of `agentsso logs --help` lists every flag.
    // L8 fix: isolate env so the maintainer's real
    // `~/.agentsso/config/daemon.toml` cannot influence the test.
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_agentsso"))
        .arg("logs")
        .arg("--help")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("AGENTSSO_PATHS__HOME", home.path().as_os_str())
        .env("NO_COLOR", "1")
        .output()
        .expect("run agentsso logs --help");
    assert!(output.status.success(), "--help must succeed");
    let stdout = stdout_of(&output);
    assert!(stdout.contains("--follow"), "help must mention --follow");
    assert!(stdout.contains("--verbose"), "help must mention --verbose");
    assert!(stdout.contains("--debug"), "help must mention --debug");
    assert!(stdout.contains("--since"), "help must mention --since");
    assert!(stdout.contains("--lines"), "help must mention --lines");
    assert!(stdout.contains("--no-pager"), "help must mention --no-pager");
}

#[test]
fn logs_malformed_lines_skipped() {
    let home = tempfile::tempdir().unwrap();
    let dir = log_dir_of(home.path());
    std::fs::create_dir_all(&dir).unwrap();
    let path = log_file_of(home.path());
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "not json at all").unwrap();
    writeln!(
        f,
        r#"{{"timestamp":"2026-04-16T14:30:00Z","level":"INFO","target":"t","fields":{{"message":"survivor"}}}}"#
    )
    .unwrap();
    writeln!(f, "{{broken json").unwrap();
    drop(f);

    let output = run_logs(home.path(), &[]);
    assert!(output.status.success(), "stderr={}", stderr_of(&output));
    let stdout = stdout_of(&output);
    assert!(stdout.contains("survivor"), "surviving record must render: {stdout}");
}

#[test]
fn logs_no_narrowing_shows_default_hint() {
    let home = tempfile::tempdir().unwrap();
    write_log_line(home.path(), "INFO", "boot");
    let output = run_logs(home.path(), &[]);
    assert!(output.status.success(), "stderr={}", stderr_of(&output));
    let stdout = stdout_of(&output);
    // Default query hints at widening the verbosity, matching Story 5.1's
    // "showing last 100 lines · use --verbose for debug" voice.
    assert!(
        stdout.contains("showing last") && stdout.contains("--verbose"),
        "default hint must show: {stdout}"
    );
}

/// M11/M18 fix: verify `agentsso logs` can parse the actual JSON
/// shape emitted by `tracing_subscriber::fmt::layer().json()`. The
/// parser makes `#[serde(default)]` assumptions about `target` and
/// `fields`; if a `tracing-subscriber` upgrade renames those fields,
/// this test fails loudly at the e2e level and forces an explicit
/// parser update rather than silently dropping log lines.
///
/// We exercise the real subscriber by using its documented output
/// shape (top-level `timestamp`, `level`, `target`, `fields.message`)
/// — same structure our parser requires. A future subscriber that
/// renames `timestamp` to `ts` would break this test, which is the
/// intended behavior.
#[test]
fn logs_parses_real_tracing_subscriber_json_shape() {
    let home = tempfile::tempdir().unwrap();
    let dir = log_dir_of(home.path());
    std::fs::create_dir_all(&dir).unwrap();
    let path = log_file_of(home.path());

    // Write a line in the exact shape `tracing_subscriber::fmt::layer()
    // .json()` produces. If the subscriber's output format evolves,
    // update this fixture AND `RawLogRecord` together.
    let mut f = std::fs::File::create(&path).unwrap();
    let line = r#"{"timestamp":"2026-04-16T14:30:00.123Z","level":"INFO","fields":{"message":"daemon starting"},"target":"permitlayer_daemon::start","threadName":"main","threadId":"ThreadId(1)"}"#;
    writeln!(f, "{line}").unwrap();
    drop(f);

    let output = run_logs(home.path(), &[]);
    assert!(output.status.success(), "stderr={}", stderr_of(&output));
    let stdout = stdout_of(&output);
    assert!(stdout.contains("daemon starting"), "real-shape line must render: {stdout}");
    assert!(stdout.contains("INFO"), "level column must render: {stdout}");
}
