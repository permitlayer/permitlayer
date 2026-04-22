//! Shared audit log reader for `agentsso audit` (Story 5.1), `audit
//! --follow` (Story 5.2), and `audit export` (Story 5.3).
//!
//! # Why this lives in `permitlayer-core`
//!
//! The reader is the shared primitive all three Epic 5 audit
//! commands consume. Putting it in `permitlayer-core` (not
//! `permitlayer-daemon`) lets Stories 5.2 and 5.3 import it without
//! reaching back into the daemon binary, matching the Story 1.15
//! `bootstrap_from_keystore` split pattern (testable core in core,
//! orchestration in daemon).
//!
//! # What this module does NOT do
//!
//! - **Does NOT re-scrub audit content.** `AuditFsWriter::scrub_event`
//!   (Story 2.4) scrubs every string field and the entire `extra`
//!   blob BEFORE writing. The reader MUST trust the written form —
//!   re-scrubbing would risk double-replacement of `<REDACTED_*>`
//!   placeholders and waste CPU. This invariant is locked in by a
//!   unit test asserting no `scrub` imports.
//! - **Does NOT take the `AuditFsStore` writer lock.** Out-of-process
//!   reader: the `agentsso audit` CLI runs as a separate process from
//!   the daemon. `O_APPEND` atomically positions the write offset at
//!   end-of-file before each kernel write call, preventing two concurrent
//!   writers from overlapping. Per-line `fsync` ensures each line is fully
//!   durable before the next write begins. The reader's line-at-a-time
//!   serde parse silently skips partial JSON lines. Together these give
//!   the "whole lines or EOF" property — the mechanism is `fsync` plus
//!   reader resilience, not `O_APPEND` alone.
//! - **Does NOT build an index or secondary data structure.** A
//!   streaming `BufReader` pass meets the <1s implicit bar on a
//!   30-minute window. If profiling ever demands indexing, it's a
//!   separate story.
//!
//! # File enumeration and rotation
//!
//! The writer rotates files by renaming the active `YYYY-MM-DD.jsonl`
//! to `YYYY-MM-DD-N.jsonl` when it exceeds `max_file_bytes`, then
//! opens a fresh `YYYY-MM-DD.jsonl`. N increments monotonically. This
//! means **for a given date, the NON-suffixed file is always the
//! newest**. The reader sorts files in chronological order as:
//!
//! ```text
//! [2026-04-13-1.jsonl, 2026-04-13-2.jsonl, 2026-04-13.jsonl,
//!  2026-04-14-1.jsonl, 2026-04-14.jsonl]
//! ```
//!
//! Unit test `file_enumeration_sorts_rotations_correctly` locks
//! this ordering in.

use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, NaiveDate, Utc};

use crate::audit::event::AuditEvent;

// ──────────────────────────────────────────────────────────────────
// Errors
// ──────────────────────────────────────────────────────────────────

/// Errors returned by [`AuditReader::query`] and helpers.
///
/// Parse errors on individual JSONL lines are NOT represented here —
/// they are logged via `tracing::warn!` and skipped (Story 2.6
/// precedent). A single corrupted line in a 90-day retention window
/// must not kill the query.
#[derive(Debug, thiserror::Error)]
pub enum AuditReaderError {
    /// The audit directory does not exist. Typically the daemon has
    /// never run; the remediation is `agentsso start`.
    #[error("audit directory not found at {path}")]
    AuditDirMissing { path: PathBuf },

    /// A filesystem I/O error while enumerating or reading files.
    /// The `path` field names the file/directory that failed, since
    /// a bare `std::io::Error` carries no path context and operator
    /// debugging needs the "which file?" answer.
    #[error("audit reader I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl AuditReaderError {
    fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io { path: path.into(), source }
    }
}

/// Error returned by [`parse_duration`] when the grammar does not
/// match.
#[derive(Debug, thiserror::Error)]
pub enum DurationParseError {
    /// Empty string.
    #[error("duration string is empty")]
    Empty,
    /// Integer part failed to parse.
    #[error("invalid numeric value in duration: {0}")]
    InvalidNumber(String),
    /// Suffix is not one of `s|m|h|d|w`.
    #[error("unknown duration suffix '{0}' — valid: s, m, h, d, w")]
    UnknownSuffix(char),
    /// Missing suffix entirely.
    #[error("duration '{0}' is missing a unit suffix (s|m|h|d|w)")]
    MissingSuffix(String),
    /// Numeric value overflows `u64` seconds when multiplied by the
    /// unit factor. Defensive — practical values never hit this, but
    /// combined with chrono's panicking `Sub<Duration>` it matters.
    #[error("duration '{0}' is out of range")]
    OutOfRange(String),
}

// ──────────────────────────────────────────────────────────────────
// Filter
// ──────────────────────────────────────────────────────────────────

/// Filter predicates applied to audit events during
/// [`AuditReader::query`].
///
/// Repeatable flags like `--service=gmail --service=calendar` become
/// `Vec<String>` where non-empty means "match any of these" (OR
/// within). Different axes are AND-combined (`service=gmail AND
/// outcome=denied`). An empty `Vec` means "no filter on this axis"
/// (matches everything).
#[derive(Debug, Default, Clone)]
pub struct AuditFilter {
    /// Start of time range. `None` = no lower bound.
    pub since: Option<DateTime<Utc>>,
    /// End of time range. `None` = no upper bound (no "now" clamp;
    /// future-dated events are included if they somehow exist).
    pub until: Option<DateTime<Utc>>,
    /// Filter by `service` field. Empty = no filter.
    pub services: Vec<String>,
    /// Filter by `agent_id` field. Empty = no filter.
    pub agents: Vec<String>,
    /// Filter by `outcome` field. Empty = no filter. Valid values:
    /// `ok`, `denied`, `error`, `scrubbed`, `already-active`,
    /// `already-inactive`.
    pub outcomes: Vec<String>,
    /// Filter by `event_type` field. Empty = no filter.
    pub event_types: Vec<String>,
    /// Maximum events to return. `None` = unlimited.
    pub limit: Option<usize>,
}

impl AuditFilter {
    /// Build an empty filter (matches everything, no limit).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return `true` if any filter axis is active (non-empty list or
    /// `Some` time bound). Used by the caller to decide whether to
    /// suppress the "showing last 100 events" hint.
    ///
    /// **`limit` is intentionally NOT a filter axis** per AC #6:
    /// "If no filter flag is passed AND `--limit` is passed, respect
    /// `--limit` but still print the hint." `--limit=50` alone caps
    /// display but doesn't narrow the *meaning* of the query.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.since.is_some()
            || self.until.is_some()
            || !self.services.is_empty()
            || !self.agents.is_empty()
            || !self.outcomes.is_empty()
            || !self.event_types.is_empty()
    }

    /// Evaluate the row-level predicate on a single event. Returns
    /// `true` if the event matches all active filter axes.
    ///
    /// Promoted to `pub` in Story 5.2 so `cli::audit_follow` can apply
    /// the same filter predicate to events arriving through the
    /// `notify` watcher. `AuditReader::query` still calls this
    /// internally for historical queries.
    pub fn matches(&self, event: &AuditEvent) -> bool {
        // Timestamp comparison. Parse once; on parse failure the
        // event fails the since/until check silently (this is a
        // "garbage in, not counted" posture, not an error).
        //
        // L19 consistency note: the writer enforces strict RFC 3339
        // via `format_audit_timestamp`, so malformed timestamps
        // normally never surface. If a tampered or migrated file
        // has near-RFC3339 timestamps (space instead of T, etc.),
        // those events are visible in untimed queries but dropped
        // once a time bound is set. This is the "trust the writer"
        // posture; changing it would require the reader to re-parse
        // every timestamp regardless of filter and is out of scope.
        if self.since.is_some() || self.until.is_some() {
            let Ok(ts) = DateTime::parse_from_rfc3339(&event.timestamp) else {
                return false;
            };
            let ts_utc = ts.with_timezone(&Utc);
            if let Some(since) = self.since
                && ts_utc < since
            {
                return false;
            }
            if let Some(until) = self.until
                && ts_utc > until
            {
                return false;
            }
        }

        if !self.services.is_empty() && !self.services.iter().any(|s| s == &event.service) {
            return false;
        }
        if !self.agents.is_empty() && !self.agents.iter().any(|a| a == &event.agent_id) {
            return false;
        }
        if !self.outcomes.is_empty() && !self.outcomes.iter().any(|o| o == &event.outcome) {
            return false;
        }
        if !self.event_types.is_empty() && !self.event_types.iter().any(|t| t == &event.event_type)
        {
            return false;
        }

        true
    }
}

// ──────────────────────────────────────────────────────────────────
// File enumeration
// ──────────────────────────────────────────────────────────────────

/// Parsed components of an audit log filename.
///
/// The writer produces two shapes:
/// - `YYYY-MM-DD.jsonl` — the currently-active file (no suffix)
/// - `YYYY-MM-DD-N.jsonl` — a rotated-out file, N increments monotonically
#[derive(Debug, Clone, Eq, PartialEq)]
struct AuditFilename {
    date: NaiveDate,
    /// Rotation suffix. `None` = active file (NEWEST for this date).
    /// `Some(N)` = rotated-out (OLDER than Some(N+1) and older than None).
    suffix: Option<u32>,
    path: PathBuf,
}

impl AuditFilename {
    /// Parse a filename into date + optional rotation suffix. Returns
    /// `None` if the filename doesn't match `YYYY-MM-DD[-N].jsonl`.
    fn parse(path: PathBuf) -> Option<Self> {
        let name = path.file_name()?.to_str()?.to_owned();
        let stem = name.strip_suffix(".jsonl")?;

        // Split into date part + optional -N suffix.
        // Date prefix is always exactly 10 chars (YYYY-MM-DD).
        if stem.len() < 10 {
            return None;
        }
        let (date_str, rest) = stem.split_at(10);
        let date = NaiveDate::parse_from_str(date_str, "%Y-%m-%d").ok()?;

        let suffix = if rest.is_empty() {
            None
        } else {
            // Must be `-N` where N is a non-negative integer.
            let num_str = rest.strip_prefix('-')?;
            Some(num_str.parse::<u32>().ok()?)
        };

        Some(Self { date, suffix, path })
    }
}

/// Sort audit filenames in chronological order (oldest first).
///
/// For a given date, rotated files (`Some(1)`, `Some(2)`, ...) are
/// older than the active file (`None`). This matches the writer's
/// rotation semantics: when the active file fills, it's renamed to
/// the next `-N` suffix and a fresh active file is opened, so older
/// events always end up in lower-suffix files and newer events in
/// the active (unsuffixed) file.
fn sort_audit_filenames(files: &mut [AuditFilename]) {
    files.sort_by(|a, b| {
        a.date.cmp(&b.date).then_with(|| match (a.suffix, b.suffix) {
            // Rotated files compare by their N values (lower is older).
            (Some(n), Some(m)) => n.cmp(&m),
            // Rotated (Some) is older than active (None) for the same date.
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            // Two active files for the same date shouldn't exist, but
            // treat as equal rather than panic.
            (None, None) => std::cmp::Ordering::Equal,
        })
    });
}

// ──────────────────────────────────────────────────────────────────
// Reader
// ──────────────────────────────────────────────────────────────────

/// Streaming reader for the audit log directory.
///
/// Opens files read-only and parses JSONL line-by-line. Does NOT
/// coordinate with the writer — see the module-level docs for the
/// `O_APPEND` + `fsync` concurrency model.
#[derive(Debug, Clone)]
pub struct AuditReader {
    audit_dir: PathBuf,
}

impl AuditReader {
    /// Construct a reader for the given audit directory. Typically
    /// `~/.agentsso/audit/`. The directory is NOT checked for
    /// existence at construction time — the check happens in
    /// [`query`], so the caller can distinguish "directory missing"
    /// from "directory exists but empty".
    ///
    /// [`query`]: Self::query
    #[must_use]
    pub fn new(audit_dir: impl Into<PathBuf>) -> Self {
        Self { audit_dir: audit_dir.into() }
    }

    /// Enumerate relevant `.jsonl` files in the audit directory,
    /// filter by date range (when `filter.since`/`filter.until` is
    /// set), and return them in chronological order (oldest first).
    ///
    /// File-level date filtering is the "don't scan 90 days for a
    /// 1h query" optimization — a file whose date is strictly before
    /// `since.date()` or strictly after `until.date()` is dropped
    /// without being opened.
    ///
    /// Per-entry I/O errors are logged via `tracing::warn!` and
    /// skipped (matching the writer-side `sweep_retention` posture at
    /// `writer.rs`); only the top-level `read_dir` failure is fatal.
    ///
    /// # Errors
    ///
    /// Returns [`AuditReaderError::AuditDirMissing`] if the audit
    /// directory does not exist, or [`AuditReaderError::Io`] if the
    /// directory itself cannot be opened.
    fn enumerate_files(
        &self,
        filter: &AuditFilter,
    ) -> Result<Vec<AuditFilename>, AuditReaderError> {
        if !self.audit_dir.exists() {
            return Err(AuditReaderError::AuditDirMissing { path: self.audit_dir.clone() });
        }

        let read_dir = std::fs::read_dir(&self.audit_dir)
            .map_err(|e| AuditReaderError::io(&self.audit_dir, e))?;
        let mut files: Vec<AuditFilename> = Vec::new();

        for entry in read_dir {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    // M7: match the writer's sweep_retention posture —
                    // a single unreadable dirent (stale inode, EACCES,
                    // concurrent delete) must not kill the whole query.
                    tracing::warn!(
                        audit_dir = %self.audit_dir.display(),
                        error = %e,
                        "skipping unreadable audit dir entry"
                    );
                    continue;
                }
            };
            let path = entry.path();
            if let Some(file) = AuditFilename::parse(path) {
                // File-level date filter. An active file (suffix=None)
                // is always included in its own date's window.
                if let Some(since) = filter.since
                    && file.date < since.date_naive()
                {
                    continue;
                }
                if let Some(until) = filter.until
                    && file.date > until.date_naive()
                {
                    continue;
                }
                files.push(file);
            }
        }

        sort_audit_filenames(&mut files);
        Ok(files)
    }

    /// Stream audit events from one file, applying the row-level
    /// predicates. Parse errors are skipped with a `tracing::warn!`.
    ///
    /// Returns `Ok(true)` if the file was read, `Ok(false)` if the
    /// file has vanished since enumeration (the writer rotated it out
    /// from under us — see M6 TOCTOU handling in `query`). Line-level
    /// I/O errors (invalid UTF-8, truncated reads) are logged and
    /// skipped; they do not abort the file read.
    fn read_file_filtered(
        &self,
        file: &AuditFilename,
        filter: &AuditFilter,
        out: &mut Vec<AuditEvent>,
    ) -> Result<bool, AuditReaderError> {
        use std::io::{BufRead, BufReader};

        let f = match std::fs::File::open(&file.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // M6: TOCTOU. Between our `enumerate_files` read_dir
                // and this open, the writer may have rotated the
                // active file (`rename(today.jsonl, today-N.jsonl)`).
                // Signal "vanished" to the caller so it can
                // re-enumerate once.
                tracing::debug!(
                    file = %file.path.display(),
                    "audit file vanished between enumerate and open (rotation race)"
                );
                return Ok(false);
            }
            Err(e) => {
                return Err(AuditReaderError::io(&file.path, e));
            }
        };
        let reader = BufReader::new(f);

        for (line_num, line_result) in reader.lines().enumerate() {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    // L7: `BufRead::lines` on invalid UTF-8 may
                    // return Err and continue, or stop — either way,
                    // log and keep going. Subsequent valid lines
                    // continue to surface via the iterator.
                    tracing::warn!(
                        file = %file.path.display(),
                        line = line_num + 1,
                        error = %e,
                        "skipping audit line: read error"
                    );
                    continue;
                }
            };

            // Skip blank lines (e.g., trailing newline at EOF).
            if line.trim().is_empty() {
                continue;
            }

            let event: AuditEvent = match serde_json::from_str(&line) {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(
                        file = %file.path.display(),
                        line = line_num + 1,
                        error = %e,
                        "skipping malformed audit line"
                    );
                    continue;
                }
            };

            if !filter.matches(&event) {
                continue;
            }

            out.push(event);
        }

        Ok(true)
    }

    /// Run the full query: enumerate files, apply filters, return
    /// matching events in chronological order.
    ///
    /// # Algorithm
    ///
    /// 1. Enumerate files, apply file-level date filter (dropping
    ///    files strictly outside `[since.date(), until.date()]`).
    /// 2. Read each file line-by-line. Collect every event that
    ///    matches all row-level predicates.
    /// 3. If `filter.limit` is set and the total match count exceeds
    ///    it, drain the head to keep the last `limit` events — the
    ///    most recent `limit` matches in chronological order.
    ///
    /// This is a collect-then-take-tail design, NOT a streaming
    /// early-termination. For Story 5.1's default `--limit=100` on a
    /// time-bounded window this is fine; for pathological
    /// `--limit=100` on an unbounded 90-day retention with millions
    /// of events, every match is still read into memory before the
    /// tail is taken. A streaming ring buffer would be more memory-
    /// efficient but complicates the file-level filter and error
    /// handling; deferred to a future story if profiling demands it.
    ///
    /// # Rotation races (M6)
    ///
    /// The writer and reader are separate processes; the writer can
    /// rotate `today.jsonl` → `today-N.jsonl` between our
    /// `enumerate_files` and per-file open. If a file vanishes during
    /// the read loop (open returns `NotFound`), we re-enumerate once
    /// and re-read the delta — any file we have NOT yet read is
    /// re-opened, but files we already finished are skipped to avoid
    /// double-counting across rotations.
    ///
    /// # Errors
    ///
    /// Returns [`AuditReaderError::AuditDirMissing`] when the audit
    /// directory does not exist, or [`AuditReaderError::Io`] on any
    /// fatal filesystem I/O failure (directory open, file open with
    /// non-NotFound kind). Malformed JSONL lines, invalid-UTF-8
    /// reads, and rotation races are logged and handled silently.
    pub fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditEvent>, AuditReaderError> {
        let mut files = self.enumerate_files(filter)?;
        let mut all_matches: Vec<AuditEvent> = Vec::new();
        let mut already_read: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
        let mut retries_left = 1_u8;

        'outer: loop {
            for file in &files {
                if already_read.contains(&file.path) {
                    continue;
                }
                let read_ok = self.read_file_filtered(file, filter, &mut all_matches)?;
                if !read_ok {
                    // File vanished. Retry enumeration once to pick
                    // up the rotated sibling(s).
                    if retries_left > 0 {
                        retries_left -= 1;
                        files = self.enumerate_files(filter)?;
                        continue 'outer;
                    }
                    // Retry budget exhausted: skip the vanished file
                    // and continue with the rest. The lost file's
                    // events are reflected in a `debug!` from
                    // `read_file_filtered`.
                    continue;
                }
                already_read.insert(file.path.clone());
            }
            break;
        }

        if let Some(limit) = filter.limit
            && all_matches.len() > limit
        {
            // Take the tail: last `limit` events.
            let tail_start = all_matches.len() - limit;
            all_matches.drain(0..tail_start);
        }

        Ok(all_matches)
    }
}

// ──────────────────────────────────────────────────────────────────
// Scrub count helper (ported from cli/audit.rs)
// ──────────────────────────────────────────────────────────────────

/// Extract the total scrub count for an audit event, handling both
/// v1 and v2 schema shapes.
///
/// - **v1** (pre-Story 2.6): `extra.scrub_events` is a flat
///   `{rule: count}` map.
/// - **v2** (Story 2.6+): `extra.scrub_events` is
///   `{"summary": {rule: count, ...}, "samples": [ScrubSample, ...]}`
///   where `summary` preserves the v1 counts.
///
/// Returns `0` if `scrub_events` is absent or cannot be interpreted
/// as either shape. Never panics on malformed input.
///
/// Ported from `crates/permitlayer-daemon/src/cli/audit.rs` so
/// Stories 5.1/5.2/5.3 share one implementation. The original copy
/// in `cli/audit.rs` delegates here.
#[must_use]
pub fn scrub_count_for(event: &AuditEvent) -> u64 {
    let Some(scrub_events) = event.extra.get("scrub_events") else {
        return 0;
    };

    // v2 nested shape: { "summary": { rule: count, ... }, "samples": [...] }
    if event.schema_version >= 2 {
        return scrub_events
            .get("summary")
            .and_then(|s| s.as_object())
            .map(|obj| obj.values().filter_map(serde_json::Value::as_u64).sum::<u64>())
            .unwrap_or(0);
    }

    // v1 flat shape: { "scrub_events": { rule: count, ... } }
    // Defensive: also tolerate v1 events written with the v2 shape.
    if let Some(summary) = scrub_events.get("summary").and_then(|s| s.as_object()) {
        return summary.values().filter_map(serde_json::Value::as_u64).sum();
    }
    scrub_events
        .as_object()
        .map(|obj| obj.values().filter_map(serde_json::Value::as_u64).sum::<u64>())
        .unwrap_or(0)
}

// ──────────────────────────────────────────────────────────────────
// Duration parser (for --since / --until)
// ──────────────────────────────────────────────────────────────────

/// Parse a duration string like `30m`, `24h`, `7d`, `2w` into a
/// [`std::time::Duration`].
///
/// # Grammar
///
/// `<N>(s|m|h|d|w)` where N is a non-negative integer.
/// - `s` = seconds
/// - `m` = minutes (NOT months)
/// - `h` = hours
/// - `d` = days (24 × 3600 seconds)
/// - `w` = weeks (7 × 24 × 3600 seconds)
///
/// Rejects: empty strings, fractional N (`1.5h` → error), combined
/// units (`1h30m` → error), months/years (no `M`, no `y` — 90-day
/// retention means those are always out of range), unknown
/// suffixes.
///
/// # Errors
///
/// Returns [`DurationParseError`] on any grammar violation.
pub fn parse_duration(s: &str) -> Result<Duration, DurationParseError> {
    let Some(last) = s.chars().next_back() else {
        return Err(DurationParseError::Empty);
    };
    if !last.is_ascii_alphabetic() {
        return Err(DurationParseError::MissingSuffix(s.to_owned()));
    }
    let num_str = &s[..s.len() - last.len_utf8()];
    let n: u64 =
        num_str.parse().map_err(|_| DurationParseError::InvalidNumber(num_str.to_owned()))?;
    // M10: checked_mul (not saturating_mul) so overflow surfaces as
    // OutOfRange instead of silently clamping to u64::MAX and then
    // interacting badly with chrono's panicking DateTime - Duration
    // operator downstream. Practical values never hit this ceiling.
    let secs = match last {
        's' => n,
        'm' => n.checked_mul(60).ok_or_else(|| DurationParseError::OutOfRange(s.to_owned()))?,
        'h' => n.checked_mul(3600).ok_or_else(|| DurationParseError::OutOfRange(s.to_owned()))?,
        'd' => n.checked_mul(86_400).ok_or_else(|| DurationParseError::OutOfRange(s.to_owned()))?,
        'w' => {
            n.checked_mul(604_800).ok_or_else(|| DurationParseError::OutOfRange(s.to_owned()))?
        }
        c => return Err(DurationParseError::UnknownSuffix(c)),
    };
    Ok(Duration::from_secs(secs))
}

// ──────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::audit::event::AUDIT_SCHEMA_VERSION;
    use std::io::Write;
    use tempfile::TempDir;

    // ── File enumeration ─────────────────────────────────────────

    #[test]
    fn audit_filename_parses_active_file() {
        let f = AuditFilename::parse(PathBuf::from("2026-04-14.jsonl")).unwrap();
        assert_eq!(f.date, NaiveDate::from_ymd_opt(2026, 4, 14).unwrap());
        assert_eq!(f.suffix, None);
    }

    #[test]
    fn audit_filename_parses_rotated_file() {
        let f = AuditFilename::parse(PathBuf::from("2026-04-14-3.jsonl")).unwrap();
        assert_eq!(f.date, NaiveDate::from_ymd_opt(2026, 4, 14).unwrap());
        assert_eq!(f.suffix, Some(3));
    }

    #[test]
    fn audit_filename_rejects_non_jsonl() {
        assert!(AuditFilename::parse(PathBuf::from("2026-04-14.json")).is_none());
    }

    #[test]
    fn audit_filename_rejects_bad_date() {
        assert!(AuditFilename::parse(PathBuf::from("not-a-date.jsonl")).is_none());
    }

    #[test]
    fn audit_filename_rejects_short_name() {
        assert!(AuditFilename::parse(PathBuf::from("short.jsonl")).is_none());
    }

    #[test]
    fn audit_filename_rejects_non_integer_suffix() {
        assert!(AuditFilename::parse(PathBuf::from("2026-04-14-abc.jsonl")).is_none());
    }

    #[test]
    fn file_enumeration_sorts_rotations_correctly() {
        // Unordered input exercising every case:
        // - two dates
        // - rotated files (Some) and the active file (None)
        // - the non-suffixed file is newer than ANY rotated file for the same date
        let base = PathBuf::from("/audit");
        let mut files = vec![
            AuditFilename {
                date: NaiveDate::from_ymd_opt(2026, 4, 14).unwrap(),
                suffix: None,
                path: base.join("2026-04-14.jsonl"),
            },
            AuditFilename {
                date: NaiveDate::from_ymd_opt(2026, 4, 14).unwrap(),
                suffix: Some(1),
                path: base.join("2026-04-14-1.jsonl"),
            },
            AuditFilename {
                date: NaiveDate::from_ymd_opt(2026, 4, 14).unwrap(),
                suffix: Some(2),
                path: base.join("2026-04-14-2.jsonl"),
            },
            AuditFilename {
                date: NaiveDate::from_ymd_opt(2026, 4, 13).unwrap(),
                suffix: None,
                path: base.join("2026-04-13.jsonl"),
            },
        ];
        sort_audit_filenames(&mut files);
        // Expected chronological (oldest first):
        //   2026-04-13 (active — only file for that date)
        //   2026-04-14-1 (oldest rotation for 04-14)
        //   2026-04-14-2 (next rotation)
        //   2026-04-14 (active = newest)
        let names: Vec<&str> =
            files.iter().map(|f| f.path.file_name().unwrap().to_str().unwrap()).collect();
        assert_eq!(
            names,
            vec![
                "2026-04-13.jsonl",
                "2026-04-14-1.jsonl",
                "2026-04-14-2.jsonl",
                "2026-04-14.jsonl"
            ]
        );
    }

    // ── Filter predicates ────────────────────────────────────────

    fn sample_event(overrides: impl FnOnce(&mut AuditEvent)) -> AuditEvent {
        let mut event = AuditEvent::new(
            "agent-1".into(),
            "gmail".into(),
            "mail.readonly".into(),
            "messages/123".into(),
            "ok".into(),
            "api-call".into(),
        );
        overrides(&mut event);
        event
    }

    #[test]
    fn empty_filter_matches_everything() {
        let filter = AuditFilter::new();
        let event = sample_event(|_| {});
        assert!(filter.matches(&event));
    }

    #[test]
    fn filter_is_active_flag() {
        assert!(!AuditFilter::new().is_active());
        let mut f = AuditFilter::new();
        f.services.push("gmail".into());
        assert!(f.is_active());
        // M2 regression guard: `--limit` alone is NOT a filter axis
        // per AC #6 ("If no filter flag is passed AND `--limit` is
        // passed, respect `--limit` but still print the hint").
        let mut f = AuditFilter::new();
        f.limit = Some(10);
        assert!(!f.is_active(), "limit alone must not count as a filter axis");
        // Time bounds DO count as filter axes.
        let mut f = AuditFilter::new();
        f.since = Some(Utc::now() - chrono::Duration::hours(1));
        assert!(f.is_active());
    }

    #[test]
    fn filter_service_or_within_list() {
        let mut filter = AuditFilter::new();
        filter.services = vec!["gmail".into(), "calendar".into()];
        assert!(filter.matches(&sample_event(|e| e.service = "gmail".into())));
        assert!(filter.matches(&sample_event(|e| e.service = "calendar".into())));
        assert!(!filter.matches(&sample_event(|e| e.service = "drive".into())));
    }

    #[test]
    fn filter_axes_are_and_combined() {
        let mut filter = AuditFilter::new();
        filter.services = vec!["gmail".into()];
        filter.outcomes = vec!["denied".into()];
        assert!(filter.matches(&sample_event(|e| {
            e.service = "gmail".into();
            e.outcome = "denied".into();
        })));
        assert!(!filter.matches(&sample_event(|e| {
            e.service = "gmail".into();
            e.outcome = "ok".into();
        })));
        assert!(!filter.matches(&sample_event(|e| {
            e.service = "calendar".into();
            e.outcome = "denied".into();
        })));
    }

    #[test]
    fn filter_since_excludes_old_events() {
        let since = Utc::now() - chrono::Duration::hours(1);
        let mut filter = AuditFilter::new();
        filter.since = Some(since);
        let old_event = sample_event(|e| {
            e.timestamp = crate::audit::event::format_audit_timestamp(
                Utc::now() - chrono::Duration::hours(2),
            );
        });
        let recent_event = sample_event(|_| {});
        assert!(!filter.matches(&old_event));
        assert!(filter.matches(&recent_event));
    }

    #[test]
    fn filter_until_excludes_future_events() {
        let until = Utc::now() - chrono::Duration::hours(1);
        let mut filter = AuditFilter::new();
        filter.until = Some(until);
        let old_event = sample_event(|e| {
            e.timestamp = crate::audit::event::format_audit_timestamp(
                Utc::now() - chrono::Duration::hours(2),
            );
        });
        let recent_event = sample_event(|_| {});
        assert!(filter.matches(&old_event));
        assert!(!filter.matches(&recent_event));
    }

    #[test]
    fn filter_agent() {
        let mut filter = AuditFilter::new();
        filter.agents = vec!["alice".into()];
        assert!(filter.matches(&sample_event(|e| e.agent_id = "alice".into())));
        assert!(!filter.matches(&sample_event(|e| e.agent_id = "bob".into())));
    }

    #[test]
    fn filter_outcome() {
        let mut filter = AuditFilter::new();
        filter.outcomes = vec!["denied".into()];
        assert!(filter.matches(&sample_event(|e| e.outcome = "denied".into())));
        assert!(!filter.matches(&sample_event(|e| e.outcome = "ok".into())));
    }

    #[test]
    fn filter_event_type() {
        let mut filter = AuditFilter::new();
        filter.event_types = vec!["policy-violation".into()];
        assert!(filter.matches(&sample_event(|e| e.event_type = "policy-violation".into())));
        assert!(!filter.matches(&sample_event(|e| e.event_type = "api-call".into())));
    }

    // ── scrub_count_for v1/v2 fallback ───────────────────────────

    #[test]
    fn scrub_count_for_handles_v1_schema() {
        let mut event = sample_event(|_| {});
        event.schema_version = 1;
        event.extra = serde_json::json!({
            "scrub_events": {
                "otp": 2,
                "email": 1,
            }
        });
        assert_eq!(scrub_count_for(&event), 3);
    }

    #[test]
    fn scrub_count_for_handles_v2_schema() {
        let mut event = sample_event(|_| {});
        event.schema_version = 2;
        event.extra = serde_json::json!({
            "scrub_events": {
                "summary": {
                    "otp": 2,
                    "email": 1,
                },
                "samples": [],
            }
        });
        assert_eq!(scrub_count_for(&event), 3);
    }

    #[test]
    fn scrub_count_for_returns_zero_when_absent() {
        let event = sample_event(|_| {});
        assert_eq!(scrub_count_for(&event), 0);
    }

    #[test]
    fn scrub_count_for_tolerates_v1_written_with_v2_shape() {
        // Defensive: a v1 event that happens to have the v2 shape
        // (e.g., schema_version not bumped on all code paths).
        let mut event = sample_event(|_| {});
        event.schema_version = 1;
        event.extra = serde_json::json!({
            "scrub_events": {
                "summary": { "otp": 5 },
                "samples": [],
            }
        });
        assert_eq!(scrub_count_for(&event), 5);
    }

    // ── parse_duration ────────────────────────────────────────────

    #[test]
    fn parse_duration_accepts_all_suffixes() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(30 * 60));
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(24 * 3600));
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(7 * 86_400));
        assert_eq!(parse_duration("2w").unwrap(), Duration::from_secs(2 * 604_800));
    }

    #[test]
    fn parse_duration_accepts_zero() {
        assert_eq!(parse_duration("0s").unwrap(), Duration::from_secs(0));
        assert_eq!(parse_duration("0m").unwrap(), Duration::from_secs(0));
    }

    #[test]
    fn parse_duration_rejects_empty() {
        assert!(matches!(parse_duration(""), Err(DurationParseError::Empty)));
    }

    #[test]
    fn parse_duration_rejects_missing_suffix() {
        assert!(matches!(parse_duration("30"), Err(DurationParseError::MissingSuffix(_))));
    }

    #[test]
    fn parse_duration_rejects_fractional() {
        assert!(matches!(parse_duration("1.5h"), Err(DurationParseError::InvalidNumber(_))));
    }

    #[test]
    fn parse_duration_rejects_combined_units() {
        // "1h30m" → num_str = "1h30", parse::<u64> fails
        assert!(matches!(parse_duration("1h30m"), Err(DurationParseError::InvalidNumber(_))));
    }

    #[test]
    fn parse_duration_rejects_unknown_suffix() {
        assert!(matches!(parse_duration("30y"), Err(DurationParseError::UnknownSuffix('y'))));
        assert!(matches!(parse_duration("30M"), Err(DurationParseError::UnknownSuffix('M'))));
    }

    // ── End-to-end query with a temp directory ───────────────────

    fn write_event_line(file: &mut std::fs::File, event: &AuditEvent) {
        let line = serde_json::to_string(event).unwrap();
        writeln!(file, "{line}").unwrap();
    }

    fn make_event(
        timestamp: DateTime<Utc>,
        service: &str,
        outcome: &str,
        event_type: &str,
    ) -> AuditEvent {
        let mut e = AuditEvent::new(
            "agent-1".into(),
            service.into(),
            "mail.readonly".into(),
            "messages/123".into(),
            outcome.into(),
            event_type.into(),
        );
        e.timestamp = crate::audit::event::format_audit_timestamp(timestamp);
        e
    }

    #[test]
    fn query_empty_directory_returns_empty() {
        let dir = TempDir::new().unwrap();
        let reader = AuditReader::new(dir.path());
        let result = reader.query(&AuditFilter::new()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn query_missing_directory_returns_audit_dir_missing() {
        let reader = AuditReader::new("/nonexistent/agentsso/audit");
        let err = reader.query(&AuditFilter::new()).unwrap_err();
        assert!(matches!(err, AuditReaderError::AuditDirMissing { .. }));
    }

    #[test]
    fn query_streams_events_across_rotation_files() {
        let dir = TempDir::new().unwrap();

        // Write a rotated file (older events).
        let rotated = dir.path().join("2026-04-14-1.jsonl");
        let mut f = std::fs::File::create(&rotated).unwrap();
        write_event_line(
            &mut f,
            &make_event(Utc::now() - chrono::Duration::minutes(30), "gmail", "ok", "api-call"),
        );

        // Write the active file (newer events).
        let active = dir.path().join("2026-04-14.jsonl");
        let mut f = std::fs::File::create(&active).unwrap();
        write_event_line(
            &mut f,
            &make_event(
                Utc::now() - chrono::Duration::minutes(5),
                "gmail",
                "denied",
                "policy-violation",
            ),
        );

        let reader = AuditReader::new(dir.path());
        let events = reader.query(&AuditFilter::new()).unwrap();

        assert_eq!(events.len(), 2, "should include both files");
        // Chronological order: rotated (older) first, then active (newer).
        assert_eq!(events[0].outcome, "ok");
        assert_eq!(events[1].outcome, "denied");
    }

    #[test]
    fn query_malformed_line_skipped_with_warn() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("2026-04-14.jsonl");
        let mut f = std::fs::File::create(&file).unwrap();
        // Valid line
        write_event_line(&mut f, &make_event(Utc::now(), "gmail", "ok", "api-call"));
        // Malformed line
        writeln!(f, "{{ this is not valid JSON").unwrap();
        // Another valid line
        write_event_line(&mut f, &make_event(Utc::now(), "gmail", "denied", "api-call"));

        let reader = AuditReader::new(dir.path());
        let events = reader.query(&AuditFilter::new()).unwrap();
        assert_eq!(events.len(), 2, "malformed line must be skipped, valid lines returned");
    }

    #[test]
    fn query_filter_outcome_narrows_results() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("2026-04-14.jsonl");
        let mut f = std::fs::File::create(&file).unwrap();
        write_event_line(&mut f, &make_event(Utc::now(), "gmail", "ok", "api-call"));
        write_event_line(&mut f, &make_event(Utc::now(), "gmail", "denied", "policy-violation"));
        write_event_line(&mut f, &make_event(Utc::now(), "gmail", "ok", "api-call"));

        let mut filter = AuditFilter::new();
        filter.outcomes = vec!["denied".into()];

        let reader = AuditReader::new(dir.path());
        let events = reader.query(&filter).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, "denied");
    }

    #[test]
    fn query_limit_returns_most_recent_tail() {
        let dir = TempDir::new().unwrap();
        // Use today's date so the file-level date filter doesn't
        // reject it regardless of calendar time.
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let file = dir.path().join(format!("{today}.jsonl"));
        let mut f = std::fs::File::create(&file).unwrap();
        // Write 5 events in chronological order with DISTINCT
        // resources so we can assert which 3 were returned.
        for i in 0..5 {
            let mut e = make_event(
                Utc::now() - chrono::Duration::minutes(5 - i),
                "gmail",
                "ok",
                "api-call",
            );
            e.resource = format!("messages/{i}");
            write_event_line(&mut f, &e);
        }

        let mut filter = AuditFilter::new();
        filter.limit = Some(3);

        let reader = AuditReader::new(dir.path());
        let events = reader.query(&filter).unwrap();
        assert_eq!(events.len(), 3);
        // L14 fix: actually verify the tail selection returned the
        // 3 MOST RECENT events (indices 2, 3, 4), not the first 3
        // or an arbitrary set.
        let resources: Vec<String> = events.iter().map(|e| e.resource.clone()).collect();
        assert_eq!(
            resources,
            vec!["messages/2".to_string(), "messages/3".to_string(), "messages/4".to_string()],
            "limit must return the tail (most recent events), not the head"
        );
    }

    #[test]
    fn parse_duration_rejects_overflow_weeks() {
        // M10 regression guard: u64::MAX weeks overflows the
        // week-to-seconds multiplication. Before the checked_mul
        // fix, this saturated silently to u64::MAX seconds, which
        // then cascaded into chrono panics downstream.
        let result = parse_duration(&format!("{}w", u64::MAX));
        assert!(matches!(result, Err(DurationParseError::OutOfRange(_))));
    }

    #[test]
    fn parse_duration_rejects_overflow_days() {
        // 2^63 days overflows the days-to-seconds multiplication.
        let result = parse_duration("9999999999999999999d");
        // Either InvalidNumber (parse::<u64> fails) or OutOfRange —
        // both are correct rejections.
        assert!(matches!(
            result,
            Err(DurationParseError::OutOfRange(_)) | Err(DurationParseError::InvalidNumber(_))
        ));
    }

    #[test]
    fn query_since_filters_at_file_level() {
        let dir = TempDir::new().unwrap();

        // An old file from 30 days ago — should be skipped entirely.
        let old_date = Utc::now().date_naive() - chrono::Duration::days(30);
        let old_file = dir.path().join(format!("{}.jsonl", old_date.format("%Y-%m-%d")));
        let mut f = std::fs::File::create(&old_file).unwrap();
        write_event_line(
            &mut f,
            &make_event(Utc::now() - chrono::Duration::days(30), "gmail", "ok", "api-call"),
        );

        // Today's file with a recent event.
        let today_file = dir.path().join(format!("{}.jsonl", Utc::now().format("%Y-%m-%d")));
        let mut f = std::fs::File::create(&today_file).unwrap();
        write_event_line(&mut f, &make_event(Utc::now(), "gmail", "ok", "api-call"));

        let mut filter = AuditFilter::new();
        filter.since = Some(Utc::now() - chrono::Duration::hours(1));

        let reader = AuditReader::new(dir.path());
        let events = reader.query(&filter).unwrap();
        assert_eq!(events.len(), 1, "old file must be skipped by file-level date filter");
    }

    // ── Zero-import invariant (AC #11) ───────────────────────────

    #[test]
    fn reader_module_does_not_import_scrub_engine() {
        // Compile-time structural check: scan only for actual `use`
        // statements that pull in the scrub engine. This is stricter
        // than a free-text grep (which would false-positive on this
        // test's own assertion message) and it mirrors what a real
        // Rust import looks like. If the reader ever imports the
        // scrub engine, either this test fails OR it needs updating
        // — either way, the change surfaces in review.
        //
        // Story 2.4 invariant: audit content is scrubbed at WRITE
        // time by `AuditFsWriter::scrub_event`. Re-scrubbing at read
        // time would risk double-replacement of `<REDACTED_*>`
        // placeholders and waste CPU.
        let source = include_str!("reader.rs");
        for line in source.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("use ") {
                assert!(
                    !trimmed.contains("scrub"),
                    "reader.rs must not `use` anything from the scrub module: {trimmed}"
                );
            }
        }
    }

    // Also guard against accidental re-export that would let callers
    // reach in via `permitlayer_core::audit::reader::ScrubEngine`.
    #[test]
    fn reader_schema_version_constant_still_matches() {
        // Sanity check that AUDIT_SCHEMA_VERSION is still at v2 — if
        // a future schema bump lands (v3), scrub_count_for needs a
        // new branch and this test fails loud so the dev remembers
        // to update the fallback.
        assert_eq!(AUDIT_SCHEMA_VERSION, 2);
    }
}
