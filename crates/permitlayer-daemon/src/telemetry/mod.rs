//! Tracing subscriber setup for the `agentsso` daemon and CLI.
//!
//! # Story 5.4 architecture: dual-subscriber
//!
//! `init_tracing` composes two `tracing_subscriber::fmt` layers behind
//! a single `tracing_subscriber::registry`:
//!
//! 1. **Stdout layer** — compact human-readable output, wrapped through
//!    [`filter::redact_sensitive_patterns`] via [`RedactingWriter`],
//!    filtered by the user-provided `EnvFilter` (honors `[log] level`
//!    and `RUST_LOG`). This is the terminal stream operators see when
//!    running the daemon in the foreground.
//! 2. **File layer** (only when `log_dir` is `Some(_)`) — JSON
//!    line-per-event output via
//!    [`tracing_appender::rolling::RollingFileAppender`] configured
//!    with `Rotation::NEVER` and a stable `daemon.log` filename,
//!    wrapped in a `tracing_appender::non_blocking` worker thread, ALSO
//!    wrapped through [`RedactingWriter`]. This layer is pinned to
//!    `LevelFilter::TRACE` so the on-disk file captures every event
//!    regardless of the stdout filter. `agentsso logs --debug` can
//!    retroactively surface lines that the terminal filter hid.
//!    (L14 fix: docstring previously claimed `rolling::daily` which
//!    was misleading — the daemon does NOT perform in-process
//!    rotation; retention management is via the out-of-band
//!    [`sweep_rotated_logs`] helper called at boot + SIGHUP.)
//!
//! Both layers receive the same event stream; each filters
//! independently. Neither path can leak credentials independently
//! because both wrap through the shared `RedactingWriter`.
//!
//! # Worker-guard lifetime
//!
//! `tracing_appender::non_blocking` returns a `(NonBlocking,
//! WorkerGuard)` pair. Dropping the guard flushes and shuts down the
//! worker thread synchronously, so the caller MUST hold every returned
//! guard for the lifetime of the daemon process or trailing log lines
//! are silently lost. [`init_tracing`] returns a `Vec<WorkerGuard>`
//! that `cli::start::run` binds until process exit. Passing
//! `log_dir = None` (e.g., from `cli::setup::run`) produces an empty
//! `Vec` — stdout is synchronous, no worker thread to flush.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

pub mod filter;

/// Result of [`init_tracing`] including every [`WorkerGuard`] that
/// must be held until process exit. The guards are dropped in the
/// order they appear in the `Vec`; dropping them flushes and shuts
/// down the tracing-appender worker thread.
///
/// Empty when `log_dir` is `None` (stdout-only mode used by one-shot
/// CLI commands like `agentsso setup`).
pub type TelemetryGuards = Vec<WorkerGuard>;

/// Errors returned by [`init_tracing`]. Converted to
/// `cli::start::StartError::TelemetryInit` at the boot callsite.
#[derive(Debug, Error)]
pub enum TelemetryInitError {
    /// Could not create the operational log directory at the
    /// configured path (permissions, missing parent, read-only
    /// filesystem). Wraps the underlying `std::io::Error`.
    #[error("failed to create operational log directory at {path}: {source}")]
    LogDirCreate {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    /// The global tracing subscriber was already initialized. Happens
    /// when a test harness pre-installs a subscriber. Not expected on
    /// the production boot path.
    #[error("tracing subscriber already initialized: {0}")]
    SubscriberInit(String),
}

/// Initialize the `tracing` subscriber with the given log level
/// directive and (optionally) a daily-rotating file appender rooted
/// at `log_dir`.
///
/// Returns a `Vec<WorkerGuard>` that the caller MUST hold for the
/// lifetime of the process (typically as a local binding in
/// `cli::start::run` named `_guards`). Dropping the guards flushes
/// the non-blocking writer's queue and shuts down the worker thread
/// so trailing log lines reach disk before exit.
///
/// Must be called exactly once per process, as early as possible in
/// daemon startup (after config load, before any other operations).
/// M1 fix: integration tests that need a subscriber installed should
/// install their own (via `tracing_subscriber::fmt()` directly) rather
/// than calling this function — calling twice returns
/// [`TelemetryInitError::SubscriberInit`] on the second call.
///
/// # Parameters
///
/// - `level`: the `EnvFilter` directive applied to the stdout layer
///   (e.g., `"info"`, `"debug,permitlayer_proxy=trace"`). The file
///   layer is pinned to `LevelFilter::TRACE` regardless so the on-disk
///   record captures everything.
/// - `log_dir`: when `Some(path)`, enable the file appender at
///   `path/daemon.log` with daily rotation. When `None`, only the
///   stdout subscriber is installed (used by one-shot CLI commands
///   like `agentsso setup`).
/// - `_retention_days`: accepted for API symmetry with
///   [`sweep_rotated_logs`]; retention is enforced by the boot-time
///   sweep, not by the appender itself. The parameter is named
///   underscore-prefixed to document this.
pub fn init_tracing(
    level: &str,
    log_dir: Option<&Path>,
    _retention_days: u32,
) -> Result<TelemetryGuards, TelemetryInitError> {
    let env_filter = EnvFilter::try_new(level).unwrap_or_else(|_| {
        eprintln!("warning: invalid log level {level:?}, falling back to \"info\"");
        EnvFilter::new("info")
    });

    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_writer(RedactingWriterFactory::<StdoutSink>::new())
        .compact()
        .with_filter(env_filter);

    let mut guards: TelemetryGuards = Vec::new();

    // File layer is conditional so one-shot CLI commands that pass
    // `log_dir = None` avoid spinning up a worker thread for an
    // output no one will read.
    match log_dir {
        Some(dir) => {
            ensure_log_dir(dir)?;
            // Use `Rotation::NEVER` with a stable filename — the live
            // file is always at `<dir>/daemon.log` so `agentsso logs`
            // has a predictable path to open.
            //
            // M5 note: tracing-appender does NOT rotate in this mode.
            // The retention sweep ([`sweep_rotated_logs`]) collects
            // files matching `daemon.log.*` at boot + SIGHUP; those
            // date-suffixed files only exist if an external tool
            // (`logrotate(8)`, ops-team script) renamed the live file.
            // In a pure out-of-the-box deployment with no external
            // rotator, the live `daemon.log` grows unboundedly and
            // `retention_days` is a no-op. This is a deliberate Tier-1
            // simplification — the operational stream is diagnostic
            // churn, not a compliance artifact, and the audit log
            // (which DOES need rotation per NFR44) has its own
            // rotator in `permitlayer-core::store::fs::audit_fs`.
            // Upgrading the operational stream to daemon-internal
            // rotation is tracked as a follow-up if disk growth proves
            // problematic in the field.
            let file_appender = tracing_appender::rolling::RollingFileAppender::builder()
                .rotation(tracing_appender::rolling::Rotation::NEVER)
                .filename_prefix("daemon")
                .filename_suffix("log")
                .build(dir)
                .map_err(|e| TelemetryInitError::LogDirCreate {
                    path: dir.to_path_buf(),
                    source: io::Error::other(e.to_string()),
                })?;
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            guards.push(guard);

            let file_layer = tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_writer(RedactingWriterFactory::<NonBlockingSink>::from_non_blocking(
                    non_blocking,
                ))
                .json()
                .with_filter(LevelFilter::TRACE);

            tracing_subscriber::registry()
                .with(stdout_layer)
                .with(file_layer)
                .try_init()
                .map_err(|e| TelemetryInitError::SubscriberInit(e.to_string()))?;
        }
        None => {
            tracing_subscriber::registry()
                .with(stdout_layer)
                .try_init()
                .map_err(|e| TelemetryInitError::SubscriberInit(e.to_string()))?;
        }
    }

    Ok(guards)
}

/// Ensure `dir` exists and (on Unix) has mode `0700`. Matches the
/// audit directory permissions discipline at architecture.md:1062.
fn ensure_log_dir(dir: &Path) -> Result<(), TelemetryInitError> {
    std::fs::create_dir_all(dir)
        .map_err(|source| TelemetryInitError::LogDirCreate { path: dir.to_path_buf(), source })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best-effort: set 0o700 on the directory. If chmod fails
        // (filesystem doesn't support Unix permissions, e.g. FAT32),
        // emit a warn and continue — the daemon must boot even on
        // exotic filesystems used by some Linux /tmp configurations.
        //
        // M2 note: this uses `eprintln!` NOT `tracing::warn!` because
        // `ensure_log_dir` runs inside `init_tracing` BEFORE the
        // subscriber is installed — a `tracing::warn!` here would be
        // silently dropped. Post-init paths (e.g. `sweep_rotated_logs`)
        // use `tracing::warn!` which is correctly routed through the
        // installed subscriber.
        if let Ok(metadata) = std::fs::metadata(dir) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o700);
            if let Err(e) = std::fs::set_permissions(dir, perms) {
                eprintln!("warning: could not set 0o700 on log directory {}: {e}", dir.display());
            }
        }
    }
    Ok(())
}

/// Sweep rotated operational log files older than `retention_days`.
///
/// Matches any file in `log_dir` whose name starts with `daemon.log.`
/// (the date-suffixed rotation produced by
/// `tracing_appender::rolling::daily`). Returns the count of files
/// unlinked.
///
/// Called from `cli::start::run` at boot AND from the SIGHUP reload
/// handler (`server::sighup::reload_loop`). Never called on the write
/// path — a per-write `readdir+stat+unlink` would be catastrophic for
/// per-request tracing volumes.
pub fn sweep_rotated_logs(log_dir: &Path, retention_days: u32) -> io::Result<usize> {
    if !log_dir.exists() {
        return Ok(0);
    }

    // M4 fix: clamp `retention_days` defensively to match
    // `LogConfig::validated` even when callers bypass it. Prevents
    // an absurd value (u32::MAX) from saturating cutoff to UNIX_EPOCH
    // and silently disabling the sweep.
    let retention_days = retention_days.clamp(1, 365);
    let retention_secs = u64::from(retention_days).saturating_mul(24 * 60 * 60);
    let cutoff = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(retention_secs))
        .unwrap_or(std::time::UNIX_EPOCH);

    let mut removed = 0;
    for entry in std::fs::read_dir(log_dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "log retention sweep: skipping unreadable dirent");
                continue;
            }
        };
        let path = entry.path();
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        // Only sweep rotated files. The live `daemon.log` is preserved.
        if !file_name.starts_with("daemon.log.") {
            continue;
        }

        // M3 fix: on metadata failure, warn-and-skip rather than
        // falling back to `now` (which would make `mtime < cutoff`
        // always false and preserve the file forever). Skipping means
        // the file survives THIS sweep; the next sweep retries.
        let mtime = match entry.metadata().and_then(|m| m.modified()) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "log retention sweep: metadata failed, skipping file"
                );
                continue;
            }
        };
        if mtime < cutoff {
            match std::fs::remove_file(&path) {
                Ok(()) => removed += 1,
                Err(e) => tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "log retention sweep: failed to unlink rotated file",
                ),
            }
        }
    }

    Ok(removed)
}

// ---------------------------------------------------------------------------
// Sensitive-pattern wrapping writers
// ---------------------------------------------------------------------------

/// Generic sink trait implemented by the two writer backends the
/// dual-subscriber uses: `io::Stdout` and
/// `tracing_appender::non_blocking::NonBlocking`. Abstracts over the
/// backend so [`RedactingWriter`] only has to know how to write a
/// scrubbed byte slice.
pub trait WriterSink: Write + Send + 'static {}

/// Thin newtype around `io::Stdout` so the trait impl doesn't collide
/// with downstream crates.
pub struct StdoutSink(io::Stdout);

impl Write for StdoutSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl WriterSink for StdoutSink {}

/// Wrapper around `tracing_appender::non_blocking::NonBlocking` so the
/// non-blocking appender participates in the `WriterSink` trait.
pub struct NonBlockingSink(tracing_appender::non_blocking::NonBlocking);

impl Write for NonBlockingSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl WriterSink for NonBlockingSink {}

/// `MakeWriter` factory parameterized over the sink type. Produces a
/// [`RedactingWriter`] that scrubs each write through
/// [`filter::redact_sensitive_patterns`] before forwarding to the
/// inner sink.
///
/// The factory owns a handle used to build new [`WriterSink`]s on
/// every event — for stdout, a fresh `io::stdout()` handle; for the
/// non-blocking appender, a clone of the `NonBlocking` sender.
pub struct RedactingWriterFactory<S> {
    make_sink: std::sync::Arc<dyn Fn() -> S + Send + Sync + 'static>,
}

impl<S: WriterSink> RedactingWriterFactory<S> {
    fn new_from_closure(make_sink: impl Fn() -> S + Send + Sync + 'static) -> Self {
        Self { make_sink: std::sync::Arc::new(make_sink) }
    }
}

impl RedactingWriterFactory<StdoutSink> {
    /// Build a factory wrapping `io::stdout()`.
    pub(crate) fn new() -> Self {
        Self::new_from_closure(|| StdoutSink(io::stdout()))
    }
}

impl RedactingWriterFactory<NonBlockingSink> {
    /// Build a factory wrapping the given `NonBlocking` appender
    /// handle. The `NonBlocking` handle is clonable (internally it is
    /// a `Sender` into a bounded channel), so every event gets a
    /// fresh clone.
    pub(crate) fn from_non_blocking(
        non_blocking: tracing_appender::non_blocking::NonBlocking,
    ) -> Self {
        Self::new_from_closure(move || NonBlockingSink(non_blocking.clone()))
    }
}

impl<'a, S: WriterSink> MakeWriter<'a> for RedactingWriterFactory<S> {
    type Writer = RedactingWriter<S>;
    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter { inner: (self.make_sink)() }
    }
}

/// `io::Write` wrapper that scans each write for sensitive patterns
/// via [`filter::redact_sensitive_patterns`] and forwards the scrubbed
/// buffer to the inner sink.
///
/// The `write` method returns the ORIGINAL buffer length to satisfy
/// the `Write` contract — callers see their logical bytes as fully
/// written even though the physical sink received a (possibly
/// shorter) scrubbed buffer.
pub struct RedactingWriter<S: Write> {
    inner: S,
}

impl<S: Write> Write for RedactingWriter<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let scrubbed = filter::redact_sensitive_patterns(buf);
        self.inner.write_all(&scrubbed)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Test-only `WriterSink` that collects written bytes in memory.
    struct VecSink(Arc<Mutex<Vec<u8>>>);
    impl Write for VecSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl WriterSink for VecSink {}

    #[test]
    fn redacting_writer_round_trip_agt_v1_token() {
        let buf: Vec<u8> = Vec::new();
        let mut w = RedactingWriter { inner: buf };
        let input = b"inflight agt_v1_secretBody123 end";
        let n = w.write(input).unwrap();
        assert_eq!(n, input.len());
        assert_eq!(w.inner, b"inflight agt_v1_<REDACTED> end".to_vec());
    }

    #[test]
    fn redacting_writer_preserves_non_sensitive_lines() {
        let buf: Vec<u8> = Vec::new();
        let mut w = RedactingWriter { inner: buf };
        let input = b"daemon starting on 127.0.0.1:3820";
        w.write_all(input).unwrap();
        assert_eq!(w.inner, input.to_vec());
    }

    #[test]
    fn factory_make_writer_rewraps_inner_sink() {
        let collected: Arc<Mutex<Vec<u8>>> = Arc::default();
        let inner = Arc::clone(&collected);
        let factory: RedactingWriterFactory<VecSink> =
            RedactingWriterFactory::new_from_closure(move || VecSink(Arc::clone(&inner)));
        let mut writer = <RedactingWriterFactory<VecSink> as MakeWriter<'_>>::make_writer(&factory);
        writer.write_all(b"token=agt_v1_abc end").unwrap();
        assert_eq!(&*collected.lock().unwrap(), b"token=agt_v1_<REDACTED> end");
    }

    #[test]
    fn ensure_log_dir_creates_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("logs");
        assert!(!dir.exists());
        ensure_log_dir(&dir).unwrap();
        assert!(dir.exists());
        assert!(dir.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn ensure_log_dir_sets_0700_unix() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("logs");
        ensure_log_dir(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn sweep_rotated_logs_returns_zero_when_dir_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("no-such-dir");
        assert_eq!(sweep_rotated_logs(&missing, 30).unwrap(), 0);
    }

    #[test]
    fn sweep_rotated_logs_preserves_live_daemon_log() {
        let tmp = tempfile::tempdir().unwrap();
        let live = tmp.path().join("daemon.log");
        std::fs::write(&live, b"live\n").unwrap();
        assert_eq!(sweep_rotated_logs(tmp.path(), 30).unwrap(), 0);
        // Live file still present.
        assert!(live.exists());
    }

    #[test]
    fn sweep_rotated_logs_keeps_recent_rotations() {
        let tmp = tempfile::tempdir().unwrap();
        let recent = tmp.path().join("daemon.log.2030-01-01");
        std::fs::write(&recent, b"recent\n").unwrap();
        // Default retention 30 days; a brand-new file should survive.
        assert_eq!(sweep_rotated_logs(tmp.path(), 30).unwrap(), 0);
        assert!(recent.exists());
    }

    #[cfg(unix)]
    #[test]
    fn sweep_rotated_logs_removes_files_older_than_retention() {
        // M6 fix: set mtime to `now - 40 days` (rather than the
        // literal epoch) so the test is resilient to APFS/NFS
        // filesystems that may clamp or reject ancient timestamps.
        // 40 days is safely past the 30-day retention default yet
        // still inside any plausible filesystem's timestamp range.
        use nix::sys::stat::{UtimensatFlags, utimensat};
        use nix::sys::time::TimeSpec;

        let tmp = tempfile::tempdir().unwrap();
        let ancient = tmp.path().join("daemon.log.ancient");
        std::fs::write(&ancient, b"ancient\n").unwrap();

        let now_secs =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let forty_days_ago = now_secs.saturating_sub(40 * 24 * 60 * 60);
        let past = TimeSpec::new(forty_days_ago as i64, 0);
        utimensat(None, &ancient, &past, &past, UtimensatFlags::FollowSymlink).unwrap();

        assert_eq!(sweep_rotated_logs(tmp.path(), 30).unwrap(), 1);
        assert!(!ancient.exists());
    }
}
