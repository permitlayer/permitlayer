#![allow(dead_code)]
//! Append-only setup journal at
//! `<daemon_log_dir>/setup-journal.log`.
//!
//! Forensic trail of every setup step. Complements `daemon.log`
//! (operational state) — this file is one line per setup decision
//! / action / outcome, so a future operator (or future-self
//! debugging an Apple launchctl wording change) can reconstruct
//! what actually happened across a setup run.
//!
//! Format: `<UTC-isotime> step=<event> result=<ok|warn|fail> <k>=<v>...`
//!
//! File opened with `O_APPEND` (POSIX-atomic multi-writer append).
//! Created with mode `0o640 root:wheel` if absent (matches the
//! existing daemon log mode; the file goes in the same dir as
//! `daemon.log` so the existing 0750 root:wheel parent works).
//!
//! Story 10.2 wires this in at each step of the setup flow.
//! Story 10.1 ships the primitive plus unit tests.

use std::io::Write as _;
use std::path::Path;

use super::fs_repair::open_append_with_mode;

/// Outcome classification for a journal entry.
#[derive(Debug, Clone, Copy)]
pub(crate) enum JournalResult {
    Ok,
    Warn,
    Fail,
}

impl JournalResult {
    fn as_str(self) -> &'static str {
        match self {
            JournalResult::Ok => "ok",
            JournalResult::Warn => "warn",
            JournalResult::Fail => "fail",
        }
    }
}

/// Append one line to the setup journal.
///
/// The journal lives at `<daemon_log_dir(Some(home))>/setup-journal.log`.
/// Each call produces one line; `fields` is rendered as
/// space-separated `key=value` pairs after the standard
/// `<isotime> step=<event> result=<result>` prefix.
///
/// Format the timestamp with literal colons (`%Y-%m-%dT%H:%M:%SZ`)
/// for RFC 3339 readability — the journal is operator-facing log
/// content, not a FS name (cf. `repair::archive` where snapshot
/// dirs strip colons for portability).
///
/// **Field escaping:** `=`, space, newline, and backslash are
/// percent-escaped (`\xNN`) in both keys and values so a hostile or
/// careless field cannot inject a fake journal line. The forensic
/// trail's integrity depends on one-event-per-line.
///
/// **Per-call `sync_all` is intentional**, not an oversight. The
/// journal is the forensic record of *what setup did before it
/// crashed*. Batching the fsync would lose that durability
/// guarantee: a crash between `write_all` and a batched fsync would
/// leave the log claiming the next step started when the prior
/// step's record wasn't on disk yet. Story 10.2 wires this in at
/// ~14 setup sites; the fsync cost is acceptable (setup runs once
/// per install, not in a hot loop) and the durability invariant is
/// what makes the journal useful for post-mortems.
pub(crate) fn record(
    home: &Path,
    event: &str,
    result: JournalResult,
    fields: &[(&str, &str)],
) -> std::io::Result<()> {
    let log_dir = permitlayer_core::paths::daemon_log_dir(Some(home));
    // Best-effort dir create (the daemon's normal startup creates it
    // with the right mode, but during setup the dir may not yet
    // exist if this is the very first run). Set 0o750 explicitly so
    // a setup-first-touch doesn't inherit umask defaults (typically
    // 0755) and leak the log dir's presence to non-root readers.
    if !log_dir.exists() {
        std::fs::create_dir_all(&log_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o750));
        }
    }
    let path = log_dir.join("setup-journal.log");
    let mut file = open_append_with_mode(&path, 0o640)?;

    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    let mut line = format!("{} step={} result={}", now, escape_field(event), result.as_str());
    for (k, v) in fields {
        line.push(' ');
        line.push_str(&escape_field(k));
        line.push('=');
        line.push_str(&escape_field(v));
    }
    line.push('\n');
    file.write_all(line.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

/// Percent-escape characters that would break the
/// `<key>=<value>` space-separated line format:
/// `=` (delimiter), ` ` (separator), `\n` (line break), `\\`
/// (escape sentinel itself).
fn escape_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\x5c"),
            '=' => out.push_str("\\x3d"),
            ' ' => out.push_str("\\x20"),
            '\n' => out.push_str("\\x0a"),
            '\r' => out.push_str("\\x0d"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn record_appends_one_line_per_call() {
        let home = tempfile::tempdir().unwrap();
        record(home.path(), "test_event", JournalResult::Ok, &[("k1", "v1")]).unwrap();
        record(home.path(), "another_event", JournalResult::Warn, &[("k2", "v2"), ("k3", "v3")])
            .unwrap();
        let log = home.path().join("logs/setup-journal.log");
        let contents = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("step=test_event result=ok k1=v1"));
        assert!(lines[1].contains("step=another_event result=warn k2=v2 k3=v3"));
    }

    #[test]
    fn record_creates_parent_dir_if_absent() {
        let home = tempfile::tempdir().unwrap();
        // No logs/ subdir pre-created.
        record(home.path(), "first_event", JournalResult::Ok, &[]).unwrap();
        assert!(home.path().join("logs").is_dir());
        assert!(home.path().join("logs/setup-journal.log").is_file());
    }

    #[test]
    fn record_format_has_iso8601_prefix_with_colons() {
        let home = tempfile::tempdir().unwrap();
        record(home.path(), "fmt_check", JournalResult::Fail, &[]).unwrap();
        let log = home.path().join("logs/setup-journal.log");
        let contents = std::fs::read_to_string(&log).unwrap();
        // Should start with YYYY-MM-DDTHH:MM:SSZ (literal colons).
        let line = contents.lines().next().unwrap();
        // 20 chars: 4-2-2 date + T + 2:2:2 time + Z = 20 chars total.
        let prefix = &line[..20];
        // Loose shape check.
        assert_eq!(prefix.chars().filter(|&c| c == '-').count(), 2, "expected 2 dashes in date");
        assert_eq!(prefix.chars().filter(|&c| c == ':').count(), 2, "expected 2 colons in time");
        assert!(prefix.ends_with('Z'), "expected Z suffix");
    }

    #[test]
    fn record_result_variants_format_correctly() {
        assert_eq!(JournalResult::Ok.as_str(), "ok");
        assert_eq!(JournalResult::Warn.as_str(), "warn");
        assert_eq!(JournalResult::Fail.as_str(), "fail");
    }

    #[test]
    fn escape_field_escapes_delimiter_chars() {
        // Plain ASCII passes through.
        assert_eq!(escape_field("simple"), "simple");
        // Each of the delimiter chars is percent-escaped.
        assert_eq!(escape_field("a=b"), "a\\x3db");
        assert_eq!(escape_field("a b"), "a\\x20b");
        assert_eq!(escape_field("a\nb"), "a\\x0ab");
        assert_eq!(escape_field("a\\b"), "a\\x5cb");
    }

    #[test]
    fn record_escapes_injection_attempt_in_field_value() {
        let home = tempfile::tempdir().unwrap();
        // A value that would otherwise inject a fake log line.
        let malicious = "innocent\nstep=fake result=ok";
        record(home.path(), "real_step", JournalResult::Ok, &[("msg", malicious)]).unwrap();
        let log = home.path().join("logs/setup-journal.log");
        let contents = std::fs::read_to_string(&log).unwrap();
        // Exactly one line in the file — the injection was neutralized.
        assert_eq!(contents.lines().count(), 1, "injection produced extra lines: {contents:?}");
        // The escaped sequence appears in the value position.
        assert!(contents.contains("msg=innocent\\x0astep\\x3dfake"));
    }

    #[cfg(unix)]
    #[test]
    fn record_sets_log_dir_mode_to_0o750_on_first_touch() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        // No logs/ subdir pre-created — record() creates it.
        record(home.path(), "first_event", JournalResult::Ok, &[]).unwrap();
        let log_dir = home.path().join("logs");
        let mode = std::fs::metadata(&log_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o750, "log dir mode should be 0o750 on first-touch");
    }
}
