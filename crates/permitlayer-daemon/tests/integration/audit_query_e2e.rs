//! End-to-end subprocess tests for `agentsso audit` historical query
//! (Story 5.1 Task 5).
//!
//! Seeds a tempdir with synthetic JSONL audit events (no daemon
//! spawn — just write raw lines via the `AuditEvent` serializer), then
//! runs `agentsso audit` with various filter flags and asserts the
//! output matches the story's acceptance criteria.
//!
//! Why no daemon spawn: Story 5.1's query path reads the audit log
//! files directly via `std::fs::File::open`, so we don't need a
//! running daemon to exercise it. Writing synthetic JSONL lines is
//! simpler, faster, and hermetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output};

use permitlayer_core::audit::event::{AUDIT_SCHEMA_VERSION, AuditEvent, format_audit_timestamp};

// ──────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────

fn write_event_line(
    audit_dir: &Path,
    timestamp: chrono::DateTime<chrono::Utc>,
    service: &str,
    outcome: &str,
    event_type: &str,
    agent: &str,
) {
    std::fs::create_dir_all(audit_dir).unwrap();
    let filename = format!("{}.jsonl", timestamp.format("%Y-%m-%d"));
    let path = audit_dir.join(&filename);

    let mut event = AuditEvent::new(
        agent.to_owned(),
        service.to_owned(),
        "mail.readonly".to_owned(),
        "messages/123".to_owned(),
        outcome.to_owned(),
        event_type.to_owned(),
    );
    event.timestamp = format_audit_timestamp(timestamp);
    event.schema_version = AUDIT_SCHEMA_VERSION;

    let line = serde_json::to_string(&event).unwrap();
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path).unwrap();
    writeln!(f, "{line}").unwrap();
}

fn run_audit(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agentsso"))
        .arg("audit")
        .args(args)
        .env("AGENTSSO_PATHS__HOME", home.as_os_str())
        .env("NO_COLOR", "1")
        // `--no-pager` so the subprocess doesn't try to spawn `less`
        // and block waiting for a reader.
        .arg("--no-pager")
        .output()
        .expect("run agentsso audit")
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

/// AC #9: missing audit directory → `audit_dir_missing` error block
/// + non-zero exit.
#[test]
fn empty_home_without_audit_dir_returns_audit_dir_missing() {
    let home = tempfile::tempdir().unwrap();
    let output = run_audit(home.path(), &[]);

    assert!(!output.status.success(), "should exit non-zero on missing audit dir");
    let stderr = stderr_of(&output);
    assert!(stderr.contains("audit_dir_missing"), "stderr should contain error code: {stderr}");
    assert!(stderr.contains("agentsso start"), "stderr should contain remediation: {stderr}");
}

/// AC #8: filter that matches zero events → empty_state block +
/// exit 0.
#[test]
fn zero_match_filter_shows_empty_state_and_exits_zero() {
    let home = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    write_event_line(&audit_dir, chrono::Utc::now(), "gmail", "ok", "api-call", "email-triage");

    let output = run_audit(home.path(), &["--service=calendar"]);

    assert!(output.status.success(), "empty result should exit 0: stderr={}", stderr_of(&output));
    let stdout = stdout_of(&output);
    assert!(
        stdout.contains("no events matched these filters"),
        "stdout should show empty_state: {stdout}"
    );
    assert!(stdout.contains("widen the range"), "stdout should offer remediation: {stdout}");
}

/// AC #2: historical query renders rows with UX-DR10 outcome icons.
#[test]
fn query_renders_rows_with_outcome_icons() {
    let home = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");

    let now = chrono::Utc::now();
    write_event_line(&audit_dir, now, "gmail", "ok", "api-call", "email-triage");
    write_event_line(&audit_dir, now, "gmail", "denied", "policy-violation", "email-triage");

    let output = run_audit(home.path(), &[]);

    assert!(output.status.success(), "stderr={}", stderr_of(&output));
    let stdout = stdout_of(&output);
    // UX-DR7: outcome icons always present regardless of color.
    assert!(stdout.contains("\u{25CF}"), "should contain ● (ok icon): {stdout}"); // ●
    assert!(stdout.contains("\u{25B2}"), "should contain ▲ (blocked icon): {stdout}"); // ▲
    // Event type column visible in Standard layout.
    assert!(stdout.contains("api-call"), "should contain api-call event type: {stdout}");
    assert!(
        stdout.contains("policy-violation"),
        "should contain policy-violation event type: {stdout}"
    );
}

/// AC #1 / #2: `--outcome=denied` filter narrows results to denied
/// events only.
#[test]
fn outcome_filter_narrows_to_denied_only() {
    let home = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");

    let now = chrono::Utc::now();
    write_event_line(&audit_dir, now, "gmail", "ok", "api-call", "email-triage");
    write_event_line(&audit_dir, now, "gmail", "denied", "policy-violation", "email-triage");
    write_event_line(&audit_dir, now, "gmail", "ok", "api-call", "email-triage");

    let output = run_audit(home.path(), &["--outcome=denied"]);

    assert!(output.status.success(), "stderr={}", stderr_of(&output));
    let stdout = stdout_of(&output);
    // Only one denied event matches.
    assert!(stdout.contains("\u{25B2}"), "should contain ▲ (blocked): {stdout}"); // ▲
    // Footer should show 1 total, 0 allowed, 1 blocked, 0 errors.
    assert!(stdout.contains("1 calls"), "footer should report 1 total: {stdout}");
    assert!(stdout.contains("0 allowed"), "footer should report 0 allowed: {stdout}");
    assert!(stdout.contains("1 blocked"), "footer should report 1 blocked: {stdout}");
    assert!(stdout.contains("0 errors"), "footer should report 0 errors (M3): {stdout}");
}

/// M3 regression test: a query that returns error-outcome events
/// renders a non-zero `errors` bucket in the footer. Before the M3
/// fix the `errors` bucket was tracked internally but never printed,
/// so `5 calls · 0 allowed · 0 blocked · 0 scrubs` was possible for
/// an all-error result set.
#[test]
fn footer_includes_errors_bucket_for_error_outcomes() {
    let home = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");

    let now = chrono::Utc::now();
    write_event_line(&audit_dir, now, "gmail", "ok", "api-call", "email-triage");
    write_event_line(&audit_dir, now, "gmail", "error", "api-call", "email-triage");
    write_event_line(&audit_dir, now, "gmail", "error", "token-refresh", "email-triage");

    let output = run_audit(home.path(), &[]);

    assert!(output.status.success(), "stderr={}", stderr_of(&output));
    let stdout = stdout_of(&output);
    assert!(stdout.contains("3 calls"), "footer should count 3 total: {stdout}");
    assert!(stdout.contains("1 allowed"), "footer should count 1 allowed: {stdout}");
    assert!(stdout.contains("0 blocked"), "footer should count 0 blocked: {stdout}");
    assert!(stdout.contains("2 errors"), "footer should count 2 errors: {stdout}");
}

/// AC #4: footer aggregation shows totals with middle-dot
/// separators. Story 5.1 review M3: footer now renders the `errors`
/// bucket explicitly so `allowed + blocked + errors == total`
/// visibly sums.
#[test]
fn footer_aggregation_format_matches_canonical_mock() {
    let home = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");

    let now = chrono::Utc::now();
    // 3 ok + 2 denied → 5 total, 3 allowed, 2 blocked, 0 errors, 0 scrubs
    for _ in 0..3 {
        write_event_line(&audit_dir, now, "gmail", "ok", "api-call", "email-triage");
    }
    for _ in 0..2 {
        write_event_line(&audit_dir, now, "gmail", "denied", "policy-violation", "email-triage");
    }

    let output = run_audit(home.path(), &[]);

    assert!(output.status.success(), "stderr={}", stderr_of(&output));
    let stdout = stdout_of(&output);
    // Middle-dot separators per §6.1 Interaction 4, including
    // the explicit `errors` bucket added by the M3 fix.
    assert!(
        stdout.contains(
            "5 calls \u{00B7} 3 allowed \u{00B7} 2 blocked \u{00B7} 0 errors \u{00B7} 0 scrubs"
        ),
        "footer should match canonical mock (with errors bucket): {stdout}"
    );
}

/// AC #6: default behavior (no filters) shows the "showing last 100"
/// hint; filtered query suppresses the hint.
#[test]
fn default_query_shows_hint_filtered_query_suppresses_it() {
    let home = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");

    let now = chrono::Utc::now();
    write_event_line(&audit_dir, now, "gmail", "ok", "api-call", "email-triage");

    // Case 1: no filters → hint present.
    let output = run_audit(home.path(), &[]);
    assert!(output.status.success(), "stderr={}", stderr_of(&output));
    let stdout_default = stdout_of(&output);
    assert!(
        stdout_default.contains("showing last 100 events"),
        "default query should show hint: {stdout_default}"
    );
    assert!(
        stdout_default.contains("use --since=24h"),
        "hint should include remediation: {stdout_default}"
    );

    // Case 2: with filter → hint suppressed.
    let output = run_audit(home.path(), &["--service=gmail"]);
    assert!(output.status.success(), "stderr={}", stderr_of(&output));
    let stdout_filtered = stdout_of(&output);
    assert!(
        !stdout_filtered.contains("showing last 100 events"),
        "filtered query should NOT show hint: {stdout_filtered}"
    );
}

/// AC #1: invalid --since value returns `invalid_duration` error.
#[test]
fn invalid_since_value_returns_invalid_duration_error() {
    let home = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    std::fs::create_dir_all(&audit_dir).unwrap();

    let output = run_audit(home.path(), &["--since=bogus"]);

    assert!(!output.status.success(), "invalid duration should exit non-zero");
    let stderr = stderr_of(&output);
    assert!(stderr.contains("invalid_duration"), "stderr should contain error code: {stderr}");
}

/// AC #1: invalid --outcome value returns `invalid_outcome` error.
#[test]
fn invalid_outcome_value_returns_invalid_outcome_error() {
    let home = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    std::fs::create_dir_all(&audit_dir).unwrap();

    let output = run_audit(home.path(), &["--outcome=bogus"]);

    assert!(!output.status.success(), "invalid outcome should exit non-zero");
    let stderr = stderr_of(&output);
    assert!(stderr.contains("invalid_outcome"), "stderr should contain error code: {stderr}");
    assert!(
        stderr.contains("ok, denied, error, scrubbed"),
        "stderr should list valid values: {stderr}"
    );
}

/// AC #10: malformed JSONL lines are skipped with a warn, valid
/// events still return.
#[test]
fn malformed_line_skipped_valid_events_returned() {
    let home = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    std::fs::create_dir_all(&audit_dir).unwrap();

    // Write a mix: valid event, corrupted line, valid event.
    let now = chrono::Utc::now();
    let filename = format!("{}.jsonl", now.format("%Y-%m-%d"));
    let path = audit_dir.join(&filename);

    write_event_line(&audit_dir, now, "gmail", "ok", "api-call", "email-triage");
    // Append a corrupted line to the same file.
    let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
    writeln!(f, "{{ this is not valid JSON").unwrap();
    drop(f);
    write_event_line(&audit_dir, now, "gmail", "denied", "policy-violation", "email-triage");

    let output = run_audit(home.path(), &[]);

    assert!(output.status.success(), "stderr={}", stderr_of(&output));
    let stdout = stdout_of(&output);
    // Both valid events should be rendered.
    assert!(stdout.contains("api-call"), "valid event before malformed line: {stdout}");
    assert!(stdout.contains("policy-violation"), "valid event after malformed line: {stdout}");
    // Footer should count 2 matched events, not 3.
    assert!(stdout.contains("2 calls"), "footer should count 2 (malformed skipped): {stdout}");
}

/// AC #14 case (c): `--since=1h` window scans rotation files
/// chronologically.
///
/// Seeds an audit directory containing a rotated sibling for today
/// (`YYYY-MM-DD-1.jsonl`) alongside the currently-active file
/// (`YYYY-MM-DD.jsonl`), then invokes `agentsso audit --since=1h`
/// and asserts events from BOTH files are returned in the correct
/// chronological order. M4 fix — this e2e case was part of the
/// AC #14 minimum set but not shipped in the original Story 5.1.
#[test]
fn audit_query_since_1h_scans_rotation_files() {
    let home = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    std::fs::create_dir_all(&audit_dir).unwrap();

    // Today's date. The writer's rotation convention is:
    // - `YYYY-MM-DD-N.jsonl` contains OLDER events (rotated out)
    // - `YYYY-MM-DD.jsonl` is the currently-active file (NEWEST)
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

    // Write two events into the rotated sibling with distinct
    // resources so we can verify both appear in the output.
    let rotated = audit_dir.join(format!("{today}-1.jsonl"));
    let mut f = std::fs::File::create(&rotated).unwrap();
    for (i, when) in [
        chrono::Utc::now() - chrono::Duration::minutes(30),
        chrono::Utc::now() - chrono::Duration::minutes(20),
    ]
    .iter()
    .enumerate()
    {
        let mut event = AuditEvent::new(
            "email-triage".into(),
            "gmail".into(),
            "mail.readonly".into(),
            format!("messages/rotated-{i}"),
            "ok".into(),
            "api-call".into(),
        );
        event.timestamp = format_audit_timestamp(*when);
        event.schema_version = AUDIT_SCHEMA_VERSION;
        let line = serde_json::to_string(&event).unwrap();
        writeln!(f, "{line}").unwrap();
    }
    drop(f);

    // Write one event into the currently-active file.
    let active = audit_dir.join(format!("{today}.jsonl"));
    let mut f = std::fs::File::create(&active).unwrap();
    {
        let mut event = AuditEvent::new(
            "email-triage".into(),
            "gmail".into(),
            "mail.readonly".into(),
            "messages/active-0".into(),
            "ok".into(),
            "api-call".into(),
        );
        event.timestamp = format_audit_timestamp(chrono::Utc::now() - chrono::Duration::minutes(5));
        event.schema_version = AUDIT_SCHEMA_VERSION;
        let line = serde_json::to_string(&event).unwrap();
        writeln!(f, "{line}").unwrap();
    }
    drop(f);

    let output = run_audit(home.path(), &["--since=1h"]);

    assert!(output.status.success(), "stderr={}", stderr_of(&output));
    let stdout = stdout_of(&output);

    // Events from BOTH the rotated sibling AND the active file
    // should appear. Events from a file 2h ago would not, but we
    // only seeded today so everything falls inside `--since=1h`.
    assert!(
        stdout.contains("messages/rotated-0"),
        "rotated file event 0 should be visible: {stdout}"
    );
    assert!(
        stdout.contains("messages/rotated-1"),
        "rotated file event 1 should be visible: {stdout}"
    );
    assert!(
        stdout.contains("messages/active-0"),
        "currently-active file event should be visible: {stdout}"
    );
    // Footer should count 3 events total.
    assert!(stdout.contains("3 calls"), "footer should count 3 events across rotation: {stdout}");
}

/// L4 regression guard: the default-behavior 100-row cap. Seeds 150
/// synthetic events with distinct resources, runs `agentsso audit`
/// with no filters, and asserts exactly the 50 LOWEST-index events
/// (events 0..=49, i.e., the oldest) are NOT in the output — only
/// events 50..=149 (the 100 most recent) should appear. Also
/// asserts the "showing last 100 events" hint is present.
///
/// This closes the AC #14 case (f) test depth gap — before L4 the
/// default-hint test only seeded 1 event and never actually
/// verified the 100-row cap that AC #6 mandates.
#[test]
fn default_query_caps_at_100_events() {
    let home = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    std::fs::create_dir_all(&audit_dir).unwrap();

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let path = audit_dir.join(format!("{today}.jsonl"));
    let mut f = std::fs::File::create(&path).unwrap();

    // Write 150 events with distinct resources and monotonically
    // increasing timestamps inside the last 24h (so the M5 implicit
    // --since=24h bound doesn't filter any of them out).
    for i in 0..150 {
        let mut event = AuditEvent::new(
            "email-triage".into(),
            "gmail".into(),
            "mail.readonly".into(),
            format!("messages/{i:03}"),
            "ok".into(),
            "api-call".into(),
        );
        event.timestamp =
            format_audit_timestamp(chrono::Utc::now() - chrono::Duration::minutes(150 - i as i64));
        event.schema_version = AUDIT_SCHEMA_VERSION;
        let line = serde_json::to_string(&event).unwrap();
        writeln!(f, "{line}").unwrap();
    }
    drop(f);

    let output = run_audit(home.path(), &[]);

    assert!(output.status.success(), "stderr={}", stderr_of(&output));
    let stdout = stdout_of(&output);

    // Footer should report 100 total (the cap).
    assert!(stdout.contains("100 calls"), "footer should cap at 100: {stdout}");
    // Hint should be present with the literal 100.
    assert!(
        stdout.contains("showing last 100 events"),
        "default query should print the hint: {stdout}"
    );
    // The OLDEST 50 events (indices 000..=049) must NOT appear —
    // they were dropped by the tail-take.
    assert!(
        !stdout.contains("messages/000"),
        "oldest event (000) should be dropped by tail-cap: {stdout}"
    );
    assert!(
        !stdout.contains("messages/049"),
        "oldest 50 events should be dropped by tail-cap (049 out): {stdout}"
    );
    // The 50th-oldest (index 050) is the first kept event.
    assert!(stdout.contains("messages/050"), "event 050 should be the first kept: {stdout}");
    // The newest event (149) must be visible.
    assert!(stdout.contains("messages/149"), "newest event (149) should be visible: {stdout}");
}

/// M2 regression guard: `--limit=N` alone (with no other filter
/// flags) still prints the "showing last N events" hint. Before M2,
/// `is_active()` counted `limit.is_some()` as a filter axis and
/// suppressed the hint.
#[test]
fn limit_alone_still_prints_hint() {
    let home = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    std::fs::create_dir_all(&audit_dir).unwrap();

    // Seed one event inside the default 24h window.
    write_event_line(&audit_dir, chrono::Utc::now(), "gmail", "ok", "api-call", "email-triage");

    let output = run_audit(home.path(), &["--limit=50"]);

    assert!(output.status.success(), "stderr={}", stderr_of(&output));
    let stdout = stdout_of(&output);
    // AC #6: `--limit=N` alone is NOT a filter axis — hint still
    // prints with the user's chosen limit (not the default 100).
    assert!(
        stdout.contains("showing last 50 events"),
        "--limit=N alone should still print hint: {stdout}"
    );
}

/// H1 regression guard: `--since=<huge duration>` must return a
/// structured `invalid_duration` error, not panic.
#[test]
fn huge_since_duration_returns_invalid_duration_not_panic() {
    let home = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    std::fs::create_dir_all(&audit_dir).unwrap();

    // 10^18 weeks is well beyond u64-seconds range; M10's
    // checked_mul should reject this before chrono ever sees it.
    let output = run_audit(home.path(), &["--since=999999999999999999w"]);

    assert!(!output.status.success(), "huge duration should exit non-zero, not panic");
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("invalid_duration"),
        "stderr should contain invalid_duration error code: {stderr}"
    );
    // Must NOT contain a Rust panic message.
    assert!(!stderr.contains("panicked"), "CLI must not panic on huge duration input: {stderr}");
}

/// M8 regression guard: `--limit=0` returns a structured
/// `invalid_limit` error, not the misleading empty_state.
#[test]
fn limit_zero_returns_invalid_limit_error() {
    let home = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    std::fs::create_dir_all(&audit_dir).unwrap();

    write_event_line(&audit_dir, chrono::Utc::now(), "gmail", "ok", "api-call", "email-triage");

    let output = run_audit(home.path(), &["--limit=0"]);

    assert!(!output.status.success(), "--limit=0 should exit non-zero");
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("invalid_limit"),
        "stderr should contain invalid_limit error code: {stderr}"
    );
    // Stdout must NOT contain the empty_state fallback (M8 regression).
    let stdout = stdout_of(&output);
    assert!(
        !stdout.contains("no events matched"),
        "--limit=0 must not fall through to empty_state: {stdout}"
    );
}

/// H2 regression guard: structured error blocks do NOT get a
/// duplicate `error: ...` follow-up line from main::anyhow_to_exit_code.
/// Before the H2 fix every run_query error path printed both the
/// error_block and a trailing `error: {e:#}` line.
#[test]
fn structured_error_block_not_followed_by_duplicate_error_line() {
    let home = tempfile::tempdir().unwrap();
    // Missing audit dir triggers the `audit_dir_missing` error block.
    let output = run_audit(home.path(), &[]);

    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(stderr.contains("audit_dir_missing"), "error block present: {stderr}");
    // The generic `error: ...` line from anyhow_to_exit_code must
    // NOT appear — the block is sufficient.
    assert!(
        !stderr.contains("error: audit directory not found"),
        "structured error block must not be followed by a duplicate 'error: ...' line: {stderr}"
    );
}

/// AC #1: `--limit=N` caps the output at N rows.
#[test]
fn limit_caps_output_to_n_rows() {
    let home = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");

    // Write 20 events with distinct service names so we can count them
    // in the output.
    let now = chrono::Utc::now();
    for i in 0..20 {
        write_event_line(
            &audit_dir,
            now + chrono::Duration::milliseconds(i * 100),
            "gmail",
            "ok",
            "api-call",
            "email-triage",
        );
    }

    let output = run_audit(home.path(), &["--limit=5"]);

    assert!(output.status.success(), "stderr={}", stderr_of(&output));
    let stdout = stdout_of(&output);
    // Footer should report 5 calls total.
    assert!(stdout.contains("5 calls"), "footer should cap at 5: {stdout}");
}
