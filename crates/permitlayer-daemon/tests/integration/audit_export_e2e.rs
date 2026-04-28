//! End-to-end subprocess tests for `agentsso audit --export=<path>`
//! (Story 5.3).
//!
//! Same hermetic pattern as `tests/audit_query_e2e.rs`: seed a tempdir
//! with synthetic JSONL audit events (no daemon spawn — just write raw
//! lines via the `AuditEvent` serializer), then run `agentsso audit
//! --export=...` and assert the written artifact matches the story's
//! acceptance criteria.
//!
//! The e2e file is deliberately NOT sharing a `tests/common/mod.rs`
//! with `audit_query_e2e.rs` / `audit_follow.rs` — the Epic 3 retro
//! action item to extract shared test helpers has been deferred
//! across Stories 4.4, 4.5, 5.1, and 5.2. Story 5.3 continues the
//! pattern rather than landing a test-infra refactor as a side
//! effect.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output};

use permitlayer_core::audit::event::{AUDIT_SCHEMA_VERSION, AuditEvent, format_audit_timestamp};

// ──────────────────────────────────────────────────────────────────
// Helpers (mirrors audit_query_e2e.rs:26-90)
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

/// Same as `write_event_line` but allows overriding `resource` and
/// `agent_id` directly — needed for CSV quoting tests (commas,
/// embedded quotes).
fn write_event_with_overrides(
    audit_dir: &Path,
    timestamp: chrono::DateTime<chrono::Utc>,
    service: &str,
    resource: &str,
    agent_id: &str,
) {
    std::fs::create_dir_all(audit_dir).unwrap();
    let filename = format!("{}.jsonl", timestamp.format("%Y-%m-%d"));
    let path = audit_dir.join(&filename);

    let mut event = AuditEvent::new(
        agent_id.to_owned(),
        service.to_owned(),
        "mail.readonly".to_owned(),
        resource.to_owned(),
        "ok".to_owned(),
        "api-call".to_owned(),
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

/// AC #4: JSON export is an array of full event objects, filter
/// vocabulary matches query path.
#[test]
fn export_json_contains_filtered_events_only() {
    let home = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    let now = chrono::Utc::now();

    write_event_line(&audit_dir, now, "gmail", "ok", "api-call", "email-triage");
    write_event_line(&audit_dir, now, "gmail", "denied", "policy-violation", "email-triage");
    write_event_line(&audit_dir, now, "calendar", "ok", "api-call", "calendar-bot");
    write_event_line(&audit_dir, now, "calendar", "ok", "api-call", "calendar-bot");
    write_event_line(&audit_dir, now, "gmail", "ok", "api-call", "email-triage");

    let dest = out_dir.path().join("out.json");
    let output = run_audit(home.path(), &["--export", dest.to_str().unwrap(), "--service=gmail"]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));

    let content = std::fs::read_to_string(&dest).unwrap();
    let events: Vec<AuditEvent> = serde_json::from_str(&content).unwrap();
    assert_eq!(events.len(), 3, "expected 3 gmail events after filter");
    assert!(events.iter().all(|e| e.service == "gmail"));
}

/// AC #5: CSV has header row + CRLF-terminated data rows in the fixed
/// 10-column order.
#[test]
fn export_csv_contains_header_plus_rows() {
    let home = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    let now = chrono::Utc::now();

    write_event_line(&audit_dir, now, "gmail", "ok", "api-call", "email-triage");
    write_event_line(&audit_dir, now, "calendar", "denied", "policy-violation", "calendar-bot");

    let dest = out_dir.path().join("out.csv");
    let output = run_audit(home.path(), &["--export", dest.to_str().unwrap()]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));

    let content = std::fs::read_to_string(&dest).unwrap();
    assert!(
        content.starts_with(
            "timestamp,request_id,agent_id,service,scope,resource,outcome,event_type,schema_version,extra_json\r\n"
        ),
        "expected canonical header row, got: {content}"
    );
    // 1 header + 2 data rows = 3 CRLF terminators.
    assert_eq!(content.matches("\r\n").count(), 3);
}

/// AC #5: RFC 4180 quoting for commas and embedded quotes.
#[test]
fn export_csv_handles_commas_and_quotes_in_fields() {
    let home = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    let now = chrono::Utc::now();

    write_event_with_overrides(&audit_dir, now, "gmail", "msg,with,comma", r#"quoted "name""#);

    let dest = out_dir.path().join("out.csv");
    let output = run_audit(home.path(), &["--export", dest.to_str().unwrap()]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));

    // Read back via the same csv crate and verify field-level round-trip.
    let mut reader = csv::ReaderBuilder::new().has_headers(true).from_path(&dest).unwrap();
    let records: Vec<csv::StringRecord> = reader.records().map(|r| r.unwrap()).collect();
    assert_eq!(records.len(), 1);
    let row = &records[0];
    assert_eq!(&row[2], r#"quoted "name""#, "agent_id round-trip");
    assert_eq!(&row[5], "msg,with,comma", "resource round-trip");
}

/// AC #3: JSON format inferred from `.json` extension.
#[test]
fn export_format_inferred_from_json_extension() {
    let home = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    write_event_line(&audit_dir, chrono::Utc::now(), "gmail", "ok", "api-call", "agent");

    let dest = out_dir.path().join("out.json");
    let output = run_audit(home.path(), &["--export", dest.to_str().unwrap()]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));

    let content = std::fs::read_to_string(&dest).unwrap();
    assert!(content.starts_with("[\n"), "expected JSON array from .json ext, got: {content}");
    // Must parse as JSON.
    let _: Vec<AuditEvent> = serde_json::from_str(&content).unwrap();
}

/// AC #3: CSV format inferred from `.csv` extension.
#[test]
fn export_format_inferred_from_csv_extension() {
    let home = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    write_event_line(&audit_dir, chrono::Utc::now(), "gmail", "ok", "api-call", "agent");

    let dest = out_dir.path().join("out.csv");
    let output = run_audit(home.path(), &["--export", dest.to_str().unwrap()]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));

    let content = std::fs::read_to_string(&dest).unwrap();
    assert!(content.starts_with("timestamp,"), "expected CSV header from .csv ext, got: {content}");
    assert!(content.contains("\r\n"), "expected CRLF terminator");
}

/// AC #3: ambiguous extension (not .json/.csv) without `--format` is
/// an error, no file created.
#[test]
fn export_format_ambiguous_extension_errors() {
    let home = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    write_event_line(&audit_dir, chrono::Utc::now(), "gmail", "ok", "api-call", "agent");

    let dest = out_dir.path().join("incident.log");
    let output = run_audit(home.path(), &["--export", dest.to_str().unwrap()]);
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("export_format_ambiguous"),
        "expected export_format_ambiguous in stderr: {stderr}"
    );
    assert!(!dest.exists(), "no file should be created on format error");
}

/// AC #7: overwrite refused without `--force`; existing file
/// unchanged; exit non-zero.
#[test]
fn export_refuses_overwrite_without_force() {
    let home = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    write_event_line(&audit_dir, chrono::Utc::now(), "gmail", "ok", "api-call", "agent");

    let dest = out_dir.path().join("out.json");
    std::fs::write(&dest, b"old content").unwrap();

    let output = run_audit(home.path(), &["--export", dest.to_str().unwrap()]);
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("export_destination_exists"),
        "expected export_destination_exists in stderr: {stderr}"
    );
    assert!(stderr.contains("--force"), "remediation should mention --force: {stderr}");
    // File still contains the old content.
    let content = std::fs::read_to_string(&dest).unwrap();
    assert_eq!(content, "old content", "existing file must not be touched");
}

/// AC #7: `--force` allows overwrite; old content replaced.
#[test]
fn export_overwrites_with_force() {
    let home = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    write_event_line(&audit_dir, chrono::Utc::now(), "gmail", "ok", "api-call", "agent");

    let dest = out_dir.path().join("out.json");
    std::fs::write(&dest, b"old content").unwrap();

    let output = run_audit(home.path(), &["--export", dest.to_str().unwrap(), "--force"]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));

    let content = std::fs::read_to_string(&dest).unwrap();
    assert!(
        content.starts_with("[\n"),
        "expected new JSON array after --force overwrite, got: {content}"
    );
    assert!(!content.contains("old content"));
}

/// AC #2: `--export` + `--follow` is rejected at argument
/// validation; no file created; exit non-zero.
#[test]
fn export_follow_combination_rejected() {
    let home = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    write_event_line(&audit_dir, chrono::Utc::now(), "gmail", "ok", "api-call", "agent");

    let dest = out_dir.path().join("out.json");
    let output = run_audit(home.path(), &["--export", dest.to_str().unwrap(), "--follow"]);
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("invalid_flag_combination"),
        "expected invalid_flag_combination in stderr: {stderr}"
    );
    // H2 regression lock: no duplicate `error:` trailer.
    let error_prefix_count = stderr.matches("error: ").count();
    assert!(
        error_prefix_count == 0 || error_prefix_count == 1,
        "duplicate error trailer detected: {stderr}"
    );
    assert!(!dest.exists(), "no file should be created on flag-combo error");
}

/// AC #10: filter that matches zero events still writes a file
/// (empty JSON array) and exits 0.
#[test]
fn export_empty_result_writes_empty_array() {
    let home = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    write_event_line(&audit_dir, chrono::Utc::now(), "gmail", "ok", "api-call", "agent");

    let dest = out_dir.path().join("out.json");
    let output =
        run_audit(home.path(), &["--export", dest.to_str().unwrap(), "--service=nonexistent"]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));

    let content = std::fs::read_to_string(&dest).unwrap();
    assert_eq!(content, "[]\n", "empty filter result should write []\\n");

    let stdout = stdout_of(&output);
    assert!(stdout.contains("exported 0 events"), "summary should say 0 events, got: {stdout}");
}

/// AC #13: missing audit dir error fires before any file is created.
#[test]
fn export_missing_audit_dir_errors() {
    let home = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    // Deliberately no `audit/` subdir.

    let dest = out_dir.path().join("out.json");
    let output = run_audit(home.path(), &["--export", dest.to_str().unwrap()]);
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(stderr.contains("audit_dir_missing"), "expected audit_dir_missing: {stderr}");
    assert!(stderr.contains("agentsso start"), "expected remediation text: {stderr}");
    assert!(!dest.exists(), "no export file should be created on missing audit dir");
}

/// AC #6: success summary line format (regex).
#[test]
fn export_summary_line_format() {
    let home = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    let now = chrono::Utc::now();
    for _ in 0..3 {
        write_event_line(&audit_dir, now, "gmail", "ok", "api-call", "agent");
    }

    let dest = out_dir.path().join("out.json");
    let output = run_audit(home.path(), &["--export", dest.to_str().unwrap()]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));

    let stdout = stdout_of(&output);
    // 2-space indent + "exported N events" + " → " (U+2192) + path + " (size)"
    assert!(stdout.starts_with("  exported "), "expected 2-space indent: {stdout:?}");
    assert!(stdout.contains("\u{2192}"), "expected → arrow (U+2192): {stdout:?}");
    assert!(stdout.contains("events"), "expected 'events' word: {stdout:?}");
    // Size should appear in parens with a unit (B / KB / MB / GB / TB).
    let re_ok = stdout.contains(" B)\n")
        || stdout.contains(" KB)\n")
        || stdout.contains(" MB)\n")
        || stdout.contains(" GB)\n")
        || stdout.contains(" TB)\n");
    assert!(re_ok, "expected size with IEC unit in parens: {stdout:?}");
}

/// AC #6: summary line's byte count reflects the actual on-disk
/// size (using the same `format_bytes` IEC formatter as the rest of
/// the daemon). We seed a zero-event export so the file is tiny and
/// the byte form renders as `(3 B)` (exactly `[]\n`).
#[test]
fn export_summary_line_size_matches_disk() {
    let home = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    // Seed one event we'll filter out, so the export file is the
    // empty-array form (3 bytes: `[`, `]`, `\n`).
    write_event_line(&audit_dir, chrono::Utc::now(), "gmail", "ok", "api-call", "agent");

    let dest = out_dir.path().join("out.json");
    let output = run_audit(home.path(), &["--export", dest.to_str().unwrap(), "--service=nothing"]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));

    let actual_bytes = std::fs::metadata(&dest).unwrap().len();
    assert_eq!(actual_bytes, 3, "empty-array JSON is exactly `[]\\n`");
    let stdout = stdout_of(&output);
    assert!(stdout.contains("(3 B)"), "summary should contain exact '(3 B)' form, got: {stdout:?}");
    assert!(
        stdout.contains("exported 0 events"),
        "summary should say 'exported 0 events', got: {stdout:?}"
    );
}

/// AC #1: invalid `--format` value is rejected; no file created.
#[test]
fn export_invalid_format_value_errors() {
    let home = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    write_event_line(&audit_dir, chrono::Utc::now(), "gmail", "ok", "api-call", "agent");

    let dest = out_dir.path().join("out.txt");
    let output = run_audit(home.path(), &["--export", dest.to_str().unwrap(), "--format=xml"]);
    assert!(!output.status.success());
    // clap catches invalid --format values at the parse boundary;
    // the specific stderr text is clap-generated, not our
    // error_block, but it must mention the invalid value and the
    // allowed choices.
    let stderr = stderr_of(&output);
    assert!(stderr.contains("xml") || stderr.contains("invalid value"));
    assert!(
        stderr.contains("json") && stderr.contains("csv"),
        "stderr should mention valid values json/csv: {stderr}"
    );
    assert!(!dest.exists(), "no file should be created on invalid --format");
}

/// AC #9: filter vocabulary (`--limit`) caps exported count.
#[test]
fn export_respects_limit_filter() {
    let home = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    let now = chrono::Utc::now();
    for _ in 0..20 {
        write_event_line(&audit_dir, now, "gmail", "ok", "api-call", "agent");
    }

    let dest = out_dir.path().join("out.json");
    let output = run_audit(home.path(), &["--export", dest.to_str().unwrap(), "--limit=5"]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));

    let content = std::fs::read_to_string(&dest).unwrap();
    let events: Vec<AuditEvent> = serde_json::from_str(&content).unwrap();
    assert_eq!(events.len(), 5, "--limit=5 should cap at 5 events");
}

/// AC #1 + Story 5.1 filter-error parity: `--limit=0` is rejected
/// with the existing `invalid_limit` error block.
#[test]
fn export_invalid_filter_errors_match_query_path() {
    let home = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    write_event_line(&audit_dir, chrono::Utc::now(), "gmail", "ok", "api-call", "agent");

    let dest = out_dir.path().join("out.json");
    let output = run_audit(home.path(), &["--export", dest.to_str().unwrap(), "--limit=0"]);
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(stderr.contains("invalid_limit"), "expected Story 5.1 invalid_limit error: {stderr}");
    assert!(!dest.exists(), "no file should be created on filter error");
}

/// AC #4: JSON export preserves non-null `extra` fields (v2 scrub
/// events + policy metadata round-trip).
#[test]
fn export_json_preserves_non_null_extra() {
    use permitlayer_core::audit::event::AuditEvent;

    let home = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let audit_dir = home.path().join("audit");
    std::fs::create_dir_all(&audit_dir).unwrap();

    let mut event = AuditEvent::new(
        "agent".into(),
        "gmail".into(),
        "mail.send".into(),
        "messages/send".into(),
        "denied".into(),
        "policy-violation".into(),
    );
    event.timestamp = format_audit_timestamp(chrono::Utc::now());
    event.extra = serde_json::json!({
        "policy_id": "p-default",
        "rule_id": "no-forward",
    });
    let filename = format!("{}.jsonl", chrono::Utc::now().format("%Y-%m-%d"));
    let path = audit_dir.join(&filename);
    let line = serde_json::to_string(&event).unwrap();
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path).unwrap();
    writeln!(f, "{line}").unwrap();

    let dest = out_dir.path().join("out.json");
    let output = run_audit(home.path(), &["--export", dest.to_str().unwrap()]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));

    let events: Vec<AuditEvent> =
        serde_json::from_str(&std::fs::read_to_string(&dest).unwrap()).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].extra["policy_id"], "p-default");
    assert_eq!(events[0].extra["rule_id"], "no-forward");
}
