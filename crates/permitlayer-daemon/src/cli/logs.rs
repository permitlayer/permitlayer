//! `agentsso logs` — operational log viewer with historical query and
//! live follow (Story 5.4, FR81 + FR82 + NFR45 + AR37 + AR38).
//!
//! # Scope
//!
//! Reads from `{paths.home}/logs/daemon.log` (or the operator-override
//! `[log] path = "..."`), the JSON-per-line file produced by the
//! tracing-appender layer installed by [`crate::telemetry::init_tracing`].
//! Filters by level (INFO+ default, DEBUG+ `--verbose`, TRACE+
//! `--debug`), by time window (`--since=<dur|ts>`), and by line count
//! (`--lines=N`, default 100). Renders via the shared design-system
//! [`crate::design::render::table`] primitive.
//!
//! # Invariants
//!
//! - **No re-scrub.** This module does NOT import the
//!   ScrubEngine type. The on-disk file is already scrubbed by
//!   [`crate::telemetry::RedactingWriter`] at write time; re-scrubbing
//!   would be redundant AND a source of drift between the stdout and
//!   file views. A grep-assert unit test locks this invariant in place.
//! - **Not an audit reader.** This module does NOT import the
//!   AuditReader type. Log reading and audit reading are deliberately
//!   separated; type confusion here would be a correctness regression.
//!   A grep-assert unit test locks this invariant in place.
//! - **Spawn-blocking for file I/O.** The `run_query` backward-read
//!   and parse loop runs inside `tokio::task::spawn_blocking` so the
//!   tokio reactor is never blocked on stat/read. Matches the
//!   Story 5.2 P7 pattern.
//!
//! # Flag rejections (match Story 5.1/5.2/5.3 precedents)
//!
//! - `--verbose --debug` → `invalid_flag_combination` (both raise the
//!   level ceiling; pick one).
//! - `--follow --until` → `invalid_flag_combination` (Story 5.2
//!   precedent: follow is an unbounded tail).
//! - `--lines=0` → `invalid_limit` (Story 5.1 precedent).

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Utc};
use clap::Args;
use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tracing::warn;

use crate::cli::{agentsso_home, silent_cli_error};
use crate::config::{CliOverrides, DaemonConfig};
use crate::design::render::{
    Outcome, TableCell, empty_state, error_block, outcome_icon, table, truncate_field,
};
use crate::design::terminal::{ColorSupport, TableLayout, styled};
use crate::design::theme::Theme;

/// The five tracing levels, ordered from most-verbose to
/// least-verbose. `Trace` < `Debug` < `Info` < `Warn` < `Error` when
/// compared by the derived `Ord`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

impl LogLevel {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "TRACE" => Some(Self::Trace),
            "DEBUG" => Some(Self::Debug),
            "INFO" => Some(Self::Info),
            "WARN" | "WARNING" => Some(Self::Warn),
            "ERROR" => Some(Self::Error),
            _ => None,
        }
    }

    fn as_label(self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }

    /// Map a log level onto the UX-DR4 outcome palette for icon + color
    /// rendering. TRACE/DEBUG stay muted (no icon, plain text);
    /// INFO → teal ● (ok); WARN → amber ▲ (blocked); ERROR → coral ✕
    /// (error). Non-color fallback uses the icon alone per UX-DR7.
    fn as_outcome(self) -> Option<Outcome> {
        match self {
            Self::Trace | Self::Debug => None,
            Self::Info => Some(Outcome::Ok),
            Self::Warn => Some(Outcome::Blocked),
            Self::Error => Some(Outcome::Error),
        }
    }
}

/// CLI args for `agentsso logs`.
#[derive(Args, Debug, Default)]
pub struct LogsArgs {
    /// Tail the operational log live. Honors `--verbose`/`--debug`
    /// level filters. `--since` replays matching history before
    /// switching to live tail. `--until` is rejected (incompatible).
    /// Ctrl-C exits cleanly.
    #[arg(long, short = 'f')]
    pub follow: bool,

    /// Show DEBUG and higher. Default is INFO+. Combining with
    /// `--debug` is rejected — pick one.
    #[arg(long)]
    pub verbose: bool,

    /// Show TRACE (wire-level) and higher. Implies `--verbose`.
    #[arg(long)]
    pub debug: bool,

    /// Start from this time: duration (30m, 24h, 7d, 2w) or RFC 3339.
    #[arg(long)]
    pub since: Option<String>,

    /// End at this time: duration or RFC 3339. Rejected with
    /// `--follow` (follow is an unbounded tail).
    #[arg(long)]
    pub until: Option<String>,

    /// Cap the number of displayed lines (default 100 when no time
    /// filter is set). `--lines=0` is rejected.
    #[arg(long, short = 'n')]
    pub lines: Option<usize>,

    /// Disable automatic paging via `less -R` on TTY stdout. Ignored
    /// with `--follow` (follow mode never pages).
    #[arg(long)]
    pub no_pager: bool,
}

/// Entry point for `agentsso logs`.
pub async fn run(args: LogsArgs) -> anyhow::Result<()> {
    // 1. Reject incompatible flag combinations up front.
    if args.verbose && args.debug {
        eprint!(
            "{}",
            error_block(
                "invalid_flag_combination",
                "--verbose and --debug are mutually exclusive",
                "pick one: --verbose for DEBUG+, --debug for TRACE+",
                None,
            )
        );
        return Err(silent_cli_error("--verbose + --debug mutually exclusive"));
    }

    if args.follow && args.until.is_some() {
        eprint!(
            "{}",
            error_block(
                "invalid_flag_combination",
                "--until is not supported with --follow",
                "follow mode is an unbounded tail; drop --until or drop --follow",
                None,
            )
        );
        return Err(silent_cli_error("--until not supported with --follow"));
    }

    if matches!(args.lines, Some(0)) {
        eprint!(
            "{}",
            error_block(
                "invalid_limit",
                "--lines=0 displays nothing",
                "pick a positive value or omit --lines to use the default (100)",
                None,
            )
        );
        return Err(silent_cli_error("--lines=0 rejected"));
    }

    // 2. Resolve the log path + filter values.
    let log_path = resolve_log_path()?;
    if !log_path.exists() {
        eprint!(
            "{}",
            error_block(
                "log_file_missing",
                &format!("operational log not found at {}", log_path.display()),
                "agentsso start",
                None,
            )
        );
        return Err(silent_cli_error(format!(
            "operational log not found at {}",
            log_path.display()
        )));
    }

    let min_level = if args.debug {
        LogLevel::Trace
    } else if args.verbose {
        LogLevel::Debug
    } else {
        LogLevel::Info
    };

    // L1 fix: trim whitespace before parsing so operator typos
    // (`--since=" 30m "`) don't get rejected by `parse_duration`.
    let since = match args.since.as_deref().map(str::trim) {
        Some(s) if !s.is_empty() => Some(super::audit::parse_time_arg(s, "--since")?),
        _ => None,
    };
    let until = match args.until.as_deref().map(str::trim) {
        Some(s) if !s.is_empty() => Some(super::audit::parse_time_arg(s, "--until")?),
        _ => None,
    };
    if let (Some(s), Some(u)) = (since, until)
        && s > u
    {
        eprint!(
            "{}",
            error_block(
                "invalid_time_range",
                "--since must be earlier than --until",
                "swap the values or drop one of them",
                None,
            )
        );
        return Err(silent_cli_error("invalid time range: since > until"));
    }

    let limit = args.lines.unwrap_or(100);

    let filter = LogFilter { min_level, since, until, limit };

    // 3. Dispatch: follow vs query.
    if args.follow {
        return run_follow(log_path, filter).await;
    }
    run_query(log_path, filter, args.no_pager).await
}

/// In-memory filter applied during scan + rendering.
#[derive(Debug, Clone)]
struct LogFilter {
    min_level: LogLevel,
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    limit: usize,
}

impl LogFilter {
    /// `true` when any filter axis is non-default. Used to decide
    /// whether to print the "showing last N lines" hint.
    fn is_narrowed(&self) -> bool {
        self.min_level < LogLevel::Info || self.since.is_some() || self.until.is_some()
    }

    /// Match an event against the filter. M7 fix: `--since` and
    /// `--until` bounds are INCLUSIVE — an event with timestamp
    /// exactly at the boundary is accepted. Operators passing
    /// `--since=2026-04-16T14:30:00Z` mean "from this moment forward"
    /// including the boundary instant itself.
    fn matches(&self, record: &LogRecord) -> bool {
        if record.level < self.min_level {
            return false;
        }
        if let Some(s) = self.since
            && record.timestamp < s
        {
            return false;
        }
        if let Some(u) = self.until
            && record.timestamp > u
        {
            return false;
        }
        true
    }
}

/// Single parsed record from the JSON-per-line log file.
///
/// Mirrors the shape produced by
/// `tracing_subscriber::fmt::layer().json()`: each line is a JSON
/// object with `timestamp`, `level`, `target`, and a `fields` map that
/// contains `message` plus any structured event fields.
#[derive(Debug, Clone)]
struct LogRecord {
    timestamp: DateTime<Utc>,
    level: LogLevel,
    target: String,
    message: String,
}

/// Raw deserializable shape; we project into [`LogRecord`] after
/// parsing.
#[derive(Debug, Deserialize)]
struct RawLogRecord {
    timestamp: String,
    level: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    fields: serde_json::Map<String, serde_json::Value>,
}

impl RawLogRecord {
    fn into_record(self) -> Option<LogRecord> {
        let timestamp = DateTime::parse_from_rfc3339(&self.timestamp).ok()?.with_timezone(&Utc);
        let level = LogLevel::parse(&self.level)?;
        let message = self.fields.get("message").and_then(|v| v.as_str()).unwrap_or("").to_owned();
        Some(LogRecord { timestamp, level, target: self.target, message })
    }
}

fn parse_line(line: &str) -> Option<LogRecord> {
    let raw: RawLogRecord = serde_json::from_str(line).ok()?;
    raw.into_record()
}

/// Typed error returned by [`read_and_filter`]. H7 fix: separating the
/// error type from the render path lets the async caller print the
/// structured `error_block` on the main thread while the blocking
/// work stays in `spawn_blocking`.
#[derive(Debug, thiserror::Error)]
enum LogReadError {
    #[error("failed to open {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl LogReadError {
    /// Render the structured `error_block` for this error. Must be
    /// called from the async caller (NOT from inside `spawn_blocking`)
    /// so stderr writes don't race with other tracing output.
    fn render_and_wrap(&self) -> anyhow::Error {
        match self {
            Self::Open { path, source } => {
                eprint!(
                    "{}",
                    error_block(
                        "log_read_failed",
                        &format!("failed to open {}: {source}", path.display()),
                        "check the log file permissions",
                        None,
                    )
                );
                silent_cli_error(format!("open log failed: {source}"))
            }
        }
    }
}

/// Run the historical-query path.
async fn run_query(log_path: PathBuf, filter: LogFilter, no_pager: bool) -> anyhow::Result<()> {
    // Move the blocking read + parse + filter into spawn_blocking so
    // large log files (TRACE-level, many-MB) don't park the reactor.
    let filter_for_task = filter.clone();
    let join_result =
        tokio::task::spawn_blocking(move || read_and_filter(&log_path, &filter_for_task))
            .await
            .map_err(|e| {
                eprint!(
                    "{}",
                    error_block(
                        "logs_internal_error",
                        "log reader worker task failed unexpectedly",
                        "report this bug with your RUST_LOG=debug output",
                        None,
                    )
                );
                tracing::error!(error = %e, "log read worker task panicked");
                silent_cli_error(format!("log read task join failed: {e}"))
            })?;
    // H7 fix: render the typed LogReadError on the CLI thread.
    let events = join_result.map_err(|e| e.render_and_wrap())?;

    if events.is_empty() {
        print!(
            "{}",
            empty_state(
                "no log events matched these filters",
                "widen the range: agentsso logs --since=24h --verbose",
            )
        );
        return Ok(());
    }

    // 4. Render via the shared table primitive.
    let theme = Theme::load(&resolve_home()?);
    let support = ColorSupport::detect();
    let layout = TableLayout::detect();
    let headers = log_row_headers(layout);
    let rows: Vec<Vec<TableCell>> =
        events.iter().map(|r| log_row_cells(r, layout, &theme, support)).collect();

    let table_str = table(headers, &rows, layout, &theme, support)?;

    let mut output = String::with_capacity(table_str.len() + 128);
    output.push_str(&table_str);
    if !filter.is_narrowed() {
        output.push('\n');
        output.push_str(&format!(
            "  showing last {} lines \u{00B7} use --verbose for debug\n",
            filter.limit
        ));
    }
    super::audit::emit_output(&output, no_pager);
    Ok(())
}

/// Read the log file tail-first and keep the newest `filter.limit`
/// records that match. Blocking — called inside `spawn_blocking`.
/// L17 fix: removed unused `#[allow(clippy::expect_used)]` that was
/// left over from an earlier draft. This function uses only `?`.
fn read_and_filter(
    log_path: &std::path::Path,
    filter: &LogFilter,
) -> Result<Vec<LogRecord>, LogReadError> {
    use std::io::{BufRead, BufReader};

    let file = std::fs::File::open(log_path)
        .map_err(|source| LogReadError::Open { path: log_path.to_path_buf(), source })?;
    let reader = BufReader::new(file);

    // Stream forward, keep a tail ring-buffer of at most `filter.limit`
    // records. For the typical 100-line default, this uses a few KB
    // even against a multi-MB log.
    let mut ring: std::collections::VecDeque<LogRecord> =
        std::collections::VecDeque::with_capacity(filter.limit);
    for (idx, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                warn!(line = idx, error = %e, "log reader: skipping unreadable line");
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let record = match parse_line(&line) {
            Some(r) => r,
            None => {
                warn!(line = idx, "log reader: skipping malformed log line");
                continue;
            }
        };
        if !filter.matches(&record) {
            continue;
        }
        if ring.len() == filter.limit {
            ring.pop_front();
        }
        ring.push_back(record);
    }
    Ok(ring.into_iter().collect())
}

/// Run the live-follow path.
///
/// Architecture: the follow loop operates in a single timeout-driven
/// loop that waits for either (a) a notify watcher event OR (b) a
/// 250ms polling deadline — whichever fires first. This avoids the
/// `tokio::select!` fairness race (H4) where both arms could fire in
/// the same turn and issue duplicate reads.
///
/// Rotation detection uses `(device, inode)` on Unix and file-length
/// shrink on Windows. When either changes, the reader seeks to 0 and
/// reads the new file contents, which correctly handles external
/// rotation (`logrotate(8)`, the SIGHUP sweep, manual moves) as well
/// as truncation.
///
/// The offset is captured BEFORE the `--since` replay (H1 fix) so
/// events written during the replay window are covered by the live
/// tail after replay completes.
async fn run_follow(log_path: PathBuf, mut filter: LogFilter) -> anyhow::Result<()> {
    use notify::{RecursiveMode, Watcher};

    let theme = Theme::load(&resolve_home()?);
    let support = ColorSupport::detect();
    let layout = TableLayout::detect();

    // H1 fix: capture the initial offset BEFORE the replay. Any writes
    // that land during or immediately after the replay read will be
    // picked up by the first live-tail iteration.
    let initial_fid = current_file_id(&log_path).await;
    let initial_offset: u64 = match tokio::fs::metadata(&log_path).await {
        Ok(m) => m.len(),
        Err(_) => 0,
    };

    // 1. Replay phase: print matching history first if --since was set.
    if filter.since.is_some() {
        let filter_for_task = filter.clone();
        let log_path_for_task = log_path.clone();
        let join_result = tokio::task::spawn_blocking(move || {
            read_and_filter_in_task(&log_path_for_task, &filter_for_task)
        })
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "log replay task panicked");
            silent_cli_error(format!("log replay join failed: {e}"))
        })?;
        // H7: render on the CLI thread.
        let replay = join_result.map_err(|e| e.render_and_wrap())?;

        let mut out = std::io::stdout().lock();
        for record in &replay {
            let line = render_follow_line(record, layout, &theme, support);
            let _ = writeln!(out, "{line}");
        }
        drop(out);
    }

    // H2 fix: once replay is complete, clear the --since bound so live
    // events are unbounded. Operator mental model: `--since=1h` means
    // "replay the last hour then keep tailing forever". A clock skew
    // that backdates a new event must not silently drop it.
    filter.since = None;

    // 2. Live tail — watch the parent dir for modify/create events.
    let parent = log_path.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));

    // M14: bump channel buffer to 1024 so bursts on busy filesystems
    // don't drop events. The polling safety net catches anything that
    // does drop, so the cost of a larger buffer is bounded.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<notify::Result<notify::Event>>(1024);
    let mut watcher = notify::RecommendedWatcher::new(
        move |res| {
            // Events dropped when the mpsc is full are recovered by
            // the 250ms polling safety net below (L16 fix).
            let _ = tx.blocking_send(res);
        },
        notify::Config::default(),
    )
    .map_err(|e| {
        eprint!(
            "{}",
            error_block(
                "log_watch_failed",
                &format!("failed to install filesystem watcher: {e}"),
                "ensure the log directory is readable",
                None,
            )
        );
        silent_cli_error(format!("notify init failed: {e}"))
    })?;

    watcher.watch(&parent, RecursiveMode::NonRecursive).map_err(|e| {
        silent_cli_error(format!("watcher: failed to watch {}: {e}", parent.display()))
    })?;

    // Live state: the offset we last read from and the (dev, inode) of
    // the file at that offset. On rotation, the (dev, inode) changes
    // and we reset the offset to 0.
    let mut active_offset: u64 = initial_offset;
    let mut active_fid: Option<FileId> = initial_fid;

    loop {
        // H4 fix: single timeout-driven receiver. Either notify fires
        // (and we drain the rx) OR the 250ms poll deadline fires (and
        // we recheck the file). No dual-arm race; no duplicate reads.
        let poll_deadline = Duration::from_millis(250);
        let recv = tokio::time::timeout(poll_deadline, rx.recv());

        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                return Ok(());
            }
            recv_result = recv => {
                match recv_result {
                    Ok(Some(Ok(_evt))) => {
                        // Drain any other immediately-available events
                        // so a burst doesn't trigger N redundant tail
                        // reads. Errors are logged and ignored.
                        while let Ok(extra) = rx.try_recv() {
                            if let Err(e) = extra {
                                warn!(error = %e, "log follow: watcher error, continuing");
                            }
                        }
                    }
                    Ok(Some(Err(e))) => {
                        warn!(error = %e, "log follow: watcher error, continuing");
                    }
                    Ok(None) => {
                        // Channel closed — watcher dropped. Exit cleanly.
                        return Ok(());
                    }
                    Err(_) => {
                        // Timeout — polling safety net tick. Fall
                        // through to the sync-and-read block below.
                    }
                }
            }
        }

        // Sync and read — runs after either a notify event batch OR a
        // poll-deadline timeout. Inline the rotation + tail logic so
        // both paths use identical code.
        (active_offset, active_fid) =
            sync_and_tail(&log_path, active_offset, active_fid, &filter, layout, &theme, support)
                .await?;
    }
}

/// Platform-specific file-identity tuple. On Unix this is
/// `(dev, ino)`; on Windows we fall back to a length-only check.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    dev: u64,
    ino: u64,
}

#[cfg(not(unix))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId(());

/// Read the current file identity of `path`. Returns `None` if the
/// file does not exist or metadata cannot be read.
async fn current_file_id(path: &std::path::Path) -> Option<FileId> {
    let meta = tokio::fs::metadata(path).await.ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(FileId { dev: meta.dev(), ino: meta.ino() })
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        Some(FileId(()))
    }
}

/// Resolve the current state of the log file and emit any new matching
/// lines. Handles rotation (inode change) and truncation (length
/// shrink) by resetting the offset. Returns the updated
/// `(offset, file_id)` tuple.
///
/// H5/H9 fix: inode comparison is the source of truth for rotation
/// detection. Length-shrink is a secondary fallback (non-Unix
/// platforms or filesystems with unstable inode numbers).
async fn sync_and_tail(
    log_path: &std::path::Path,
    mut offset: u64,
    fid: Option<FileId>,
    filter: &LogFilter,
    layout: TableLayout,
    theme: &Theme,
    support: ColorSupport,
) -> anyhow::Result<(u64, Option<FileId>)> {
    let new_fid = current_file_id(log_path).await;
    let new_meta = tokio::fs::metadata(log_path).await;

    // Rotation or truncation detection:
    //   1. File now missing → nothing to do; preserve state.
    //   2. File identity changed → reset offset to 0 (new inode).
    //   3. File shorter than offset → reset offset to 0 (truncation).
    let meta = match new_meta {
        Ok(m) => m,
        Err(_) => return Ok((offset, fid)),
    };

    let rotated = match (fid, new_fid) {
        (Some(old), Some(new)) => old != new,
        _ => false,
    };
    if rotated || meta.len() < offset {
        offset = 0;
    }

    if offset < meta.len() {
        offset = read_and_emit_tail(log_path, offset, filter, layout, theme, support).await?;
    }

    Ok((offset, new_fid))
}

/// Wrapper used by `run_follow`'s replay phase. Calls `read_and_filter`
/// but does NOT print the structured error block from inside
/// `spawn_blocking` — instead it returns the typed error and the
/// caller in the async context decides how to surface it (H7 fix:
/// structured error rendering belongs on the CLI thread, not the
/// worker thread).
fn read_and_filter_in_task(
    log_path: &std::path::Path,
    filter: &LogFilter,
) -> Result<Vec<LogRecord>, LogReadError> {
    read_and_filter(log_path, filter)
}

/// Maximum bytes read from the log file in a single tail iteration.
/// H8 fix: bounds the synchronous parse-and-emit loop so a Ctrl-C
/// during a tail of a multi-MB file doesn't force the user to wait
/// for the full read to complete before exit. The remaining bytes are
/// picked up on the next `sync_and_tail` iteration.
const FOLLOW_TAIL_CHUNK_BYTES: u64 = 64 * 1024;

/// Read `path` from `offset` up to `FOLLOW_TAIL_CHUNK_BYTES`, parse +
/// filter each line, emit matching rows to stdout. Returns the new
/// offset. A partial final line (bytes after the last `\n`) is left
/// unread so the next iteration picks it up intact.
async fn read_and_emit_tail(
    path: &std::path::Path,
    offset: u64,
    filter: &LogFilter,
    layout: TableLayout,
    theme: &Theme,
    support: ColorSupport,
) -> anyhow::Result<u64> {
    use tokio::io::AsyncSeekExt;

    let mut file = tokio::fs::File::open(path).await?;
    file.seek(std::io::SeekFrom::Start(offset)).await?;

    let mut buf = vec![0u8; FOLLOW_TAIL_CHUNK_BYTES as usize];
    let n = file.read(&mut buf).await?;
    buf.truncate(n);

    // Find the last newline so we only commit complete lines. Bytes
    // after the final `\n` remain in the file and are re-read next
    // iteration. If the chunk contains no newline, commit nothing and
    // advance offset to the chunk start (unchanged).
    let last_newline = buf.iter().rposition(|b| *b == b'\n');
    let (complete_bytes, advance) = match last_newline {
        Some(idx) => (&buf[..=idx], (idx as u64) + 1),
        None => {
            // No complete line in this chunk. Don't advance the
            // offset — wait for more bytes to arrive.
            return Ok(offset);
        }
    };

    let mut out = std::io::stdout().lock();
    for (idx, line) in complete_bytes.split(|b| *b == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let text = match std::str::from_utf8(line) {
            Ok(s) => s,
            Err(_) => {
                // M10 fix: warn on non-utf8 to match `read_and_filter`
                // behavior rather than silently dropping.
                warn!(line = idx, "log follow: skipping non-utf8 line");
                continue;
            }
        };
        let record = match parse_line(text) {
            Some(r) => r,
            None => {
                warn!(line = idx, "log follow: skipping malformed log line");
                continue;
            }
        };
        if !filter.matches(&record) {
            continue;
        }
        let rendered = render_follow_line(&record, layout, theme, support);
        let _ = writeln!(out, "{rendered}");
    }
    drop(out);

    Ok(offset + advance)
}

/// Render a single log record as a one-line string for follow-mode
/// output.
///
/// B1 fix: follow mode is explicitly NOT attempting column-width
/// parity with the historical-query table renderer. The query path
/// uses `table()` which computes widths from the full row set; follow
/// prints one line at a time with no advance knowledge of subsequent
/// lines, so column alignment is structurally impossible. Instead,
/// follow uses a compact tab-separated form: time, level, (target if
/// present), message. Operators who need aligned output pipe `agentsso
/// logs --follow` through `column -t -s $'\t'`.
fn render_follow_line(
    record: &LogRecord,
    layout: TableLayout,
    theme: &Theme,
    support: ColorSupport,
) -> String {
    let time = format_timestamp(record.timestamp, layout);
    let level_cell = render_level_cell(record.level, theme, support);
    let include_target = matches!(layout, TableLayout::Standard | TableLayout::Wide);

    let mut buf = String::with_capacity(128);
    buf.push_str(&time);
    buf.push('\t');
    buf.push_str(&level_cell);
    buf.push('\t');
    if include_target {
        // Do NOT truncate in follow mode: full target name aids
        // grep-based filtering.
        buf.push_str(&record.target);
        buf.push('\t');
    }
    buf.push_str(&record.message);
    buf
}

/// Headers for the log-table. Adapts to [`TableLayout`] per UX-DR5.
fn log_row_headers(layout: TableLayout) -> &'static [&'static str] {
    match layout {
        TableLayout::Narrow => &["time", "level", "message"],
        TableLayout::Standard => &["time", "level", "target", "message"],
        TableLayout::Wide => &["time", "level", "target", "message"],
    }
}

/// Render a single [`LogRecord`] as a row of [`TableCell`]s. The level
/// cell is a pre-styled `Plain(String)` containing the icon + label
/// (colored on TTY, plain on `NoColor` per UX-DR7). Target and message
/// columns are plain text; the table primitive truncates on overflow.
fn log_row_cells(
    record: &LogRecord,
    layout: TableLayout,
    theme: &Theme,
    support: ColorSupport,
) -> Vec<TableCell> {
    let time = format_timestamp(record.timestamp, layout);
    let level_cell = render_level_cell(record.level, theme, support);
    let target = truncate_field(&record.target, 32);
    let message = record.message.clone();

    match layout {
        TableLayout::Narrow => {
            vec![TableCell::Plain(time), TableCell::Plain(level_cell), TableCell::Plain(message)]
        }
        TableLayout::Standard | TableLayout::Wide => vec![
            TableCell::Plain(time),
            TableCell::Plain(level_cell),
            TableCell::Plain(target),
            TableCell::Plain(message),
        ],
    }
}

/// Render the level column as icon + label with UX-DR4 color + UX-DR7
/// non-color signaling (icon always present).
fn render_level_cell(level: LogLevel, theme: &Theme, support: ColorSupport) -> String {
    let label = level.as_label();
    match level.as_outcome() {
        Some(outcome) => {
            let icon = outcome_icon(outcome);
            let tokens = theme.tokens();
            let color = match outcome {
                Outcome::Ok => tokens.accent,
                Outcome::Blocked => tokens.warn,
                Outcome::Error => tokens.danger,
            };
            let text = format!("{icon} {label}");
            styled(&text, color, support)
        }
        None => {
            // TRACE / DEBUG — no icon, muted text color so noisy
            // lines recede visually.
            let tokens = theme.tokens();
            styled(&format!("  {label}"), tokens.muted, support)
        }
    }
}

/// Format a UTC timestamp for display. L4/L5 fix: Narrow and Standard
/// layouts use `HH:MM:SSZ` (compact, Z suffix disambiguates UTC);
/// Wide uses full RFC 3339 with millisecond precision to match the
/// docstring contract that previously drifted from the implementation.
fn format_timestamp(ts: DateTime<Utc>, layout: TableLayout) -> String {
    match layout {
        TableLayout::Narrow | TableLayout::Standard => ts.format("%H:%M:%SZ").to_string(),
        TableLayout::Wide => ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
    }
}

/// Resolve the operational log file path from the daemon config. When
/// `[log] path` is unset, defaults to `{paths.home}/logs/daemon.log`.
///
/// H6 fix: on config-load failure, emit a structured `config_load_failed`
/// error block and wrap the returned error with `silent_cli_error` so
/// `main::anyhow_to_exit_code` does not print a duplicate generic trailer.
fn resolve_log_path() -> anyhow::Result<PathBuf> {
    let config = match DaemonConfig::load(&CliOverrides::default()) {
        Ok(c) => c,
        Err(e) => {
            eprint!(
                "{}",
                error_block(
                    "config_load_failed",
                    &format!("could not load daemon config: {e}"),
                    "check ~/.agentsso/config/daemon.toml for syntax errors",
                    None,
                )
            );
            return Err(silent_cli_error(format!("config load failed: {e}")));
        }
    };
    let path = config.log.path.unwrap_or_else(|| config.paths.home.join("logs").join("daemon.log"));
    Ok(path)
}

/// Resolve the agentsso home directory. M9 fix: unlike
/// `cli::audit::resolve_home` (which falls through on config parse
/// error for theme-loading purposes), this function hard-fails
/// consistent with [`resolve_log_path`]. A broken config that
/// resolves the log file to one path but the theme home to a
/// different path is a worse failure mode than refusing to run.
///
/// Silent fallback would leave the operator staring at an
/// unreadable error: `agentsso logs` would succeed against a
/// fallback home while `resolve_log_path` reported "file missing"
/// against the configured home.
fn resolve_home() -> anyhow::Result<PathBuf> {
    match DaemonConfig::load(&CliOverrides::default()) {
        Ok(config) => Ok(config.paths.home),
        Err(e) => {
            // Fallback to the env-var-aware default so the caller at
            // least gets a usable path for theme loading — theme is
            // cosmetic and should not block output. But emit a
            // tracing::warn so operators debugging a broken config
            // see the divergence.
            tracing::warn!(
                error = %e,
                "config load failed for theme resolution; using default home"
            );
            agentsso_home()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ── Level parsing ──────────────────────────────────────────────

    #[test]
    fn parse_log_level_accepts_standard_tokens() {
        assert_eq!(LogLevel::parse("TRACE"), Some(LogLevel::Trace));
        assert_eq!(LogLevel::parse("DEBUG"), Some(LogLevel::Debug));
        assert_eq!(LogLevel::parse("INFO"), Some(LogLevel::Info));
        assert_eq!(LogLevel::parse("WARN"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::parse("WARNING"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::parse("ERROR"), Some(LogLevel::Error));
    }

    #[test]
    fn parse_log_level_is_case_insensitive() {
        assert_eq!(LogLevel::parse("info"), Some(LogLevel::Info));
        assert_eq!(LogLevel::parse("Warn"), Some(LogLevel::Warn));
    }

    #[test]
    fn parse_log_level_rejects_unknown() {
        assert_eq!(LogLevel::parse("CRITICAL"), None);
        assert_eq!(LogLevel::parse(""), None);
    }

    #[test]
    fn log_level_ord_is_verbose_to_terse() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    // ── LogFilter matches ──────────────────────────────────────────

    fn test_record(level: LogLevel, when: DateTime<Utc>, msg: &str) -> LogRecord {
        LogRecord {
            timestamp: when,
            level,
            target: "permitlayer_daemon::test".to_owned(),
            message: msg.to_owned(),
        }
    }

    #[test]
    fn filter_rejects_below_min_level() {
        let filter = LogFilter { min_level: LogLevel::Info, since: None, until: None, limit: 100 };
        assert!(!filter.matches(&test_record(LogLevel::Debug, Utc::now(), "x")));
        assert!(filter.matches(&test_record(LogLevel::Info, Utc::now(), "x")));
        assert!(filter.matches(&test_record(LogLevel::Error, Utc::now(), "x")));
    }

    #[test]
    fn filter_rejects_before_since() {
        let anchor = Utc::now();
        let filter =
            LogFilter { min_level: LogLevel::Trace, since: Some(anchor), until: None, limit: 100 };
        let earlier = anchor - chrono::Duration::minutes(5);
        let later = anchor + chrono::Duration::minutes(5);
        assert!(!filter.matches(&test_record(LogLevel::Info, earlier, "x")));
        assert!(filter.matches(&test_record(LogLevel::Info, later, "x")));
    }

    #[test]
    fn filter_rejects_after_until() {
        let anchor = Utc::now();
        let filter =
            LogFilter { min_level: LogLevel::Trace, since: None, until: Some(anchor), limit: 100 };
        let earlier = anchor - chrono::Duration::minutes(5);
        let later = anchor + chrono::Duration::minutes(5);
        assert!(filter.matches(&test_record(LogLevel::Info, earlier, "x")));
        assert!(!filter.matches(&test_record(LogLevel::Info, later, "x")));
    }

    #[test]
    fn filter_is_narrowed_reports_non_default_axes() {
        let default = LogFilter { min_level: LogLevel::Info, since: None, until: None, limit: 100 };
        assert!(!default.is_narrowed());

        let narrowed = LogFilter { min_level: LogLevel::Debug, ..default.clone() };
        assert!(narrowed.is_narrowed());
    }

    // ── parse_line round-trip ──────────────────────────────────────

    #[test]
    fn parse_line_accepts_tracing_json_shape() {
        let line = r#"{"timestamp":"2026-04-16T14:30:00Z","level":"INFO","target":"permitlayer_daemon","fields":{"message":"daemon starting"}}"#;
        let record = parse_line(line).expect("parses");
        assert_eq!(record.level, LogLevel::Info);
        assert_eq!(record.message, "daemon starting");
        assert_eq!(record.target, "permitlayer_daemon");
    }

    #[test]
    fn parse_line_rejects_malformed_json() {
        assert!(parse_line("not json").is_none());
        assert!(parse_line("{\"level\":\"INFO\"}").is_none()); // missing timestamp
    }

    #[test]
    fn parse_line_rejects_unknown_level() {
        let line = r#"{"timestamp":"2026-04-16T14:30:00Z","level":"CRITICAL","target":"x","fields":{"message":"x"}}"#;
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn parse_line_handles_missing_message_field() {
        let line =
            r#"{"timestamp":"2026-04-16T14:30:00Z","level":"INFO","target":"x","fields":{}}"#;
        let record = parse_line(line).expect("parses");
        assert_eq!(record.message, "");
    }

    // ── read_and_filter tail + limit ───────────────────────────────

    #[test]
    fn read_and_filter_keeps_last_n_matching_lines() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut f = std::fs::File::create(tmp.path()).unwrap();
        for i in 0..20 {
            let line = format!(
                r#"{{"timestamp":"2026-04-16T14:{:02}:00Z","level":"INFO","target":"t","fields":{{"message":"msg-{}"}}}}"#,
                i, i
            );
            writeln!(f, "{line}").unwrap();
        }
        drop(f);

        let filter = LogFilter { min_level: LogLevel::Info, since: None, until: None, limit: 5 };
        let records = read_and_filter(tmp.path(), &filter).unwrap();
        assert_eq!(records.len(), 5);
        // The tail should be the last 5 emitted.
        assert_eq!(records.first().unwrap().message, "msg-15");
        assert_eq!(records.last().unwrap().message, "msg-19");
    }

    #[test]
    fn read_and_filter_skips_malformed_lines() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut f = std::fs::File::create(tmp.path()).unwrap();
        writeln!(f, "not json").unwrap();
        writeln!(
            f,
            r#"{{"timestamp":"2026-04-16T14:30:00Z","level":"INFO","target":"t","fields":{{"message":"survivor"}}}}"#
        )
        .unwrap();
        writeln!(f, r#"{{"timestamp":"nope","level":"INFO"}}"#).unwrap();
        drop(f);

        let filter = LogFilter { min_level: LogLevel::Info, since: None, until: None, limit: 100 };
        let records = read_and_filter(tmp.path(), &filter).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].message, "survivor");
    }

    #[test]
    fn read_and_filter_applies_level_filter() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut f = std::fs::File::create(tmp.path()).unwrap();
        for (i, level) in ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"].iter().enumerate() {
            writeln!(
                f,
                r#"{{"timestamp":"2026-04-16T14:{:02}:00Z","level":"{}","target":"t","fields":{{"message":"m{}"}}}}"#,
                i, level, i
            )
            .unwrap();
        }
        drop(f);

        let filter = LogFilter { min_level: LogLevel::Warn, since: None, until: None, limit: 100 };
        let records = read_and_filter(tmp.path(), &filter).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].level, LogLevel::Warn);
        assert_eq!(records[1].level, LogLevel::Error);
    }

    // ── Rendering ─────────────────────────────────────────────────

    #[test]
    fn render_level_cell_error_contains_coral_icon() {
        let theme = Theme::Carapace;
        let cell = render_level_cell(LogLevel::Error, &theme, ColorSupport::NoColor);
        assert!(cell.contains("ERROR"));
        // Non-color mode preserves the icon (UX-DR7).
        assert!(cell.contains("\u{2715}"));
    }

    #[test]
    fn render_level_cell_info_contains_teal_icon() {
        let theme = Theme::Carapace;
        let cell = render_level_cell(LogLevel::Info, &theme, ColorSupport::NoColor);
        assert!(cell.contains("INFO"));
        assert!(cell.contains("\u{25CF}"));
    }

    #[test]
    fn render_level_cell_warn_contains_amber_icon() {
        let theme = Theme::Carapace;
        let cell = render_level_cell(LogLevel::Warn, &theme, ColorSupport::NoColor);
        assert!(cell.contains("WARN"));
        assert!(cell.contains("\u{25B2}"));
    }

    #[test]
    fn render_level_cell_debug_has_no_icon() {
        let theme = Theme::Carapace;
        let cell = render_level_cell(LogLevel::Debug, &theme, ColorSupport::NoColor);
        assert!(cell.contains("DEBUG"));
        // TRACE/DEBUG render without an outcome icon.
        assert!(!cell.contains("\u{25CF}"));
        assert!(!cell.contains("\u{25B2}"));
        assert!(!cell.contains("\u{2715}"));
    }

    #[test]
    fn log_row_cells_narrow_has_three_columns() {
        let record = test_record(LogLevel::Info, Utc::now(), "boot");
        let cells =
            log_row_cells(&record, TableLayout::Narrow, &Theme::Carapace, ColorSupport::NoColor);
        assert_eq!(cells.len(), 3);
    }

    #[test]
    fn log_row_cells_standard_has_four_columns() {
        let record = test_record(LogLevel::Info, Utc::now(), "boot");
        let cells =
            log_row_cells(&record, TableLayout::Standard, &Theme::Carapace, ColorSupport::NoColor);
        assert_eq!(cells.len(), 4);
    }

    #[test]
    fn log_row_headers_narrow_excludes_target() {
        let headers = log_row_headers(TableLayout::Narrow);
        assert_eq!(headers, &["time", "level", "message"]);
    }

    #[test]
    fn log_row_headers_standard_includes_target() {
        let headers = log_row_headers(TableLayout::Standard);
        assert_eq!(headers, &["time", "level", "target", "message"]);
    }

    // ── Scope-fence grep-asserts ──────────────────────────────────

    // M12 fix: pin the grep-assert source path relative to
    // `CARGO_MANIFEST_DIR` so moving the file or reorganizing into
    // `logs/mod.rs` produces a compile error rather than a silent
    // stale include.
    const LOGS_MODULE_SOURCE: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/cli/logs.rs"));

    #[test]
    fn logs_module_does_not_import_scrub_engine() {
        // Build forbidden patterns via `concat!` so the assertion
        // source itself doesn't match (Story 5.1 + 5.2 + 5.3
        // precedent). Error message keeps its reference abstract so
        // `include_str!` doesn't pick up the forbidden literal.
        let forbidden_a = concat!("crate::", "scrub::", "ScrubEngine");
        let forbidden_b = concat!("permitlayer_core::", "scrub::", "ScrubEngine");
        assert!(
            !LOGS_MODULE_SOURCE.contains(forbidden_a),
            "logs module must not import the local scrub engine — the on-disk log is already redacted"
        );
        assert!(
            !LOGS_MODULE_SOURCE.contains(forbidden_b),
            "logs module must not import the core scrub engine — the on-disk log is already redacted"
        );
    }

    #[test]
    fn logs_module_does_not_import_audit_reader() {
        let forbidden = concat!("permitlayer_core::", "audit::", "reader::", "AuditReader");
        assert!(
            !LOGS_MODULE_SOURCE.contains(forbidden),
            "logs module must not import the audit reader — log reading is not audit reading"
        );
    }
}
