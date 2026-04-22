//! `agentsso audit --follow` — live-tail the audit log with filters and
//! rolling-window rate anomaly hints.
//!
//! # Story 5.2 rewrite
//!
//! Before Story 5.2 the follow path lived inline in `cli/audit.rs` as a
//! 250 ms polling scaffold inherited from Story 1.9: `follow_loop`
//! opened today's JSONL file at `SeekFrom::End(0)`, slept 250 ms
//! between reads, and never reacted to rotation or UTC midnight
//! rollover (deferred-work.md:91 — "`follow_loop` calls blocking
//! std::io on the tokio reactor"; :92 — "`follow_loop` never reopens
//! the file after rotation or daily rollover"). Both items were
//! explicitly tagged "Story 5.2's turf" when the Story 5.1 scope
//! fence put them off.
//!
//! Story 5.2 closes both by swapping the poll loop for a
//! `notify`-based filesystem watcher. A [`notify::RecommendedWatcher`]
//! watches the audit **directory** (not a single file) so rename and
//! create events fire on rotation (`YYYY-MM-DD.jsonl` →
//! `YYYY-MM-DD-1.jsonl` at 100 MB per writer.rs:247-314) AND on UTC
//! midnight rollover (the writer opens a new `YYYY-MM-DD.jsonl` for
//! the new date). Events ship from the sync `notify` callback into
//! the async task via a `tokio::sync::mpsc::unbounded_channel`. No
//! polling, no blocking I/O on the tokio reactor.
//!
//! # What this path owns
//!
//! - The `notify` watcher setup, event pump, and file-offset tracking
//! - Rotation / rollover detection and re-resolution of the active file
//! - Historical replay via [`AuditReader::query`] when `--since` is set
//! - Row-level filter application (reusing Story 5.1's
//!   [`AuditFilter::matches`])
//! - Row rendering via the Story 5.1 `design::render::table` +
//!   `audit_row_cells` path (visual parity with historical query)
//! - v2 scrub-sample rendering (preserved unchanged from Story 1.9 /
//!   2.4 / 2.6 — the DoS-hardened `sample_is_renderable` + the
//!   existing `render_scrub_inline` branch live here now)
//! - Rolling-window per-service rate anomaly detection via
//!   [`crate::cli::audit_anomaly::AnomalyDetector`]
//! - Clean Ctrl-C shutdown (watcher drop triggers `inotify_rm_watch` /
//!   FSEvents cleanup)
//!
//! # What this path does NOT own
//!
//! - Historical query rendering (Story 5.1 — `cli::audit::run_query`)
//! - `AuditReader` primitive itself (Story 5.1 — `permitlayer_core::audit::reader`)
//! - Scrub engine (Story 2.1-2.4 — reader MUST NOT re-scrub)
//! - Audit log writer / rotation / retention (Story 1.9 —
//!   `permitlayer_core::audit::writer`)

use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use notify::{EventKind, RecursiveMode, Watcher};
use permitlayer_core::audit::event::AuditEvent;
use permitlayer_core::audit::reader::{AuditFilter, AuditReader};
use permitlayer_core::scrub::ScrubSample;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::signal;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};
use tracing::warn;

use crate::cli::audit::{AuditArgs, build_filter_from_args, resolve_audit_dir, resolve_home};
use crate::cli::audit_anomaly::AnomalyDetector;
use crate::cli::silent_cli_error;
use crate::config::{CliOverrides, DaemonConfig};
use crate::design::render::{audit_row_cells, audit_row_headers, empty_state, error_block, table};
use crate::design::scrub_inline::render_scrub_inline;
use crate::design::terminal::{ColorSupport, TableLayout};
use crate::design::theme::Theme;

/// Entry point for the `--follow` path, dispatched from
/// [`crate::cli::audit::run`] when `args.follow` is set.
///
/// Validates filter flags, rejects `--until + --follow`, resolves the
/// audit directory, optionally replays historical events via
/// `AuditReader::query` when `--since` is set, then spawns the
/// `notify`-based watcher task and races it against `ctrl_c` in a
/// `tokio::select!`. Returns `Ok(())` on clean Ctrl-C exit or
/// `Err(SilentCliError)` on validation failure (the structured error
/// block is already printed to stderr via `design::render::error_block`
/// so `main::anyhow_to_exit_code` suppresses the duplicate trailing
/// `error: ...` line per the Story 5.1 H2 fix).
pub async fn run_follow(args: AuditArgs) -> anyhow::Result<()> {
    // AC #5: `--until` is meaningless with `--follow` because the live
    // tail has no upper time bound. Reject BEFORE the watcher is
    // constructed so the error block fires once, cleanly, without a
    // half-opened watcher.
    if args.until.is_some() {
        eprint!(
            "{}",
            error_block(
                "invalid_flag_combination",
                "--until is not supported with --follow",
                "drop --until or use a historical query instead",
                None,
            )
        );
        return Err(silent_cli_error("--until not supported with --follow"));
    }

    // AC #3: reuse the Story 5.1 filter builder verbatim so every
    // validation rule stays in lockstep across historical and follow
    // paths. `build_filter_from_args` handles --since/--outcome/--limit
    // parsing AND prints the error block on failure, so any error
    // returned from here is already in SilentCliError shape.
    let filter = build_filter_from_args(&args)?;

    // Resolve audit dir. If it doesn't exist, the daemon has never
    // run — print the friendly empty-state block and exit cleanly
    // rather than waiting forever for a directory that may never
    // appear. Matches the Story 1.9 empty_state UX preserved in
    // `tests/audit_follow.rs::audit_follow_prints_empty_state_when_no_file`.
    let audit_dir = resolve_audit_dir()?;
    if !audit_dir.exists() {
        print!(
            "{}",
            empty_state("no audit events yet for today", "start the daemon: agentsso start")
        );
        return Ok(());
    }

    let theme = Theme::load(&resolve_home()?);
    let support = ColorSupport::detect();
    let layout = TableLayout::detect();

    // AC #4: --since replay-then-follow. If the user asked for the
    // last N minutes/hours/days, run the historical query first to
    // fill in the back-context, then switch to the live tail. No
    // visual separator between replay and live — the stream is
    // conceptually one continuous flow.
    //
    // If a replay write sees EPIPE (e.g. the user piped into
    // `head -1`), bail out immediately — the watcher never armed
    // so there's nothing to drop and we return `Ok(())` for the
    // same "clean broken-pipe exit" UX AC #14 requires.
    let mut seen_request_ids: HashSet<String> = HashSet::new();
    // P28: skip replay entirely when `--since=0s` (or any parsed
    // since that resolves to a time >= now). A naïve user typing
    // `--follow --since=0s` expects "just tail from now," not a
    // full-directory enumeration. This also bounds the replay path
    // when the writer happens to have a future-dated clock skew.
    let replay_needed = match filter.since {
        Some(since) => since < chrono::Utc::now(),
        None => false,
    };
    if replay_needed {
        // P7: `AuditReader::query` is synchronous std::fs I/O. Offload
        // to a blocking thread so the tokio reactor isn't parked for
        // seconds on a 100 MB replay.
        let audit_dir_owned = audit_dir.clone();
        let filter_owned = filter.clone();
        let query_result = tokio::task::spawn_blocking(move || {
            AuditReader::new(&audit_dir_owned).query(&filter_owned)
        })
        .await;
        match query_result {
            Ok(Ok(events)) => {
                for event in &events {
                    match emit_row(event, layout, &theme, support) {
                        WriteStatus::Ok => {}
                        WriteStatus::BrokenPipe => return Ok(()),
                        WriteStatus::Fatal(kind) => {
                            eprint!(
                                "{}",
                                error_block(
                                    "stdout_write_failed",
                                    &format!("replay write failed: {kind:?}"),
                                    "check stdout is writable",
                                    None,
                                )
                            );
                            return Err(silent_cli_error(format!(
                                "replay stdout write failed: {kind:?}"
                            )));
                        }
                    }
                    seen_request_ids.insert(event.request_id.clone());
                }
            }
            Ok(Err(e)) => {
                // Non-fatal: replay failed but live tail can still
                // proceed. Log and continue. If the audit dir is
                // missing we already bailed above, so any error here
                // is something unusual.
                warn!(error = %e, "replay query failed; continuing to live tail");
            }
            Err(join_err) => {
                // spawn_blocking join failed (usually panic in the
                // blocking thread). Continue to live tail and log.
                warn!(error = %join_err, "replay task join failed; continuing to live tail");
            }
        }
    }

    // Load anomaly detector config from DaemonConfig. A parse error
    // at this point should fall back to defaults rather than abort
    // the follow command — the CLI is a user-facing tool, not the
    // daemon hot path, and a bad anomaly threshold must never block
    // operators from watching the audit log.
    let anomaly_cfg = match DaemonConfig::load(&CliOverrides::default()) {
        Ok(cfg) => cfg.audit.anomaly,
        Err(_) => crate::config::schema::AnomalyConfig::default(),
    }
    .validated();

    let detector = AnomalyDetector::new(anomaly_cfg);

    // Build the notify watcher. The watcher thread runs a sync
    // callback; we bridge it into the async world via an unbounded
    // mpsc channel. The watcher binding MUST outlive the select!
    // below — dropping the watcher closes the channel and the
    // receiver task ends naturally. This is also how Ctrl-C exits
    // cleanly: select picks the ctrl_c branch, returns from the
    // function, the watcher drops, inotify_rm_watch fires.
    let (event_tx, event_rx) = unbounded_channel::<notify::Result<notify::Event>>();
    let watcher_result = notify::recommended_watcher(move |res| {
        // Closure is FnMut; send errors mean the receiver was dropped
        // (shutdown). Ignore them — the task is going away anyway.
        let _ = event_tx.send(res);
    });
    let mut watcher = match watcher_result {
        Ok(w) => w,
        Err(e) => {
            eprint!(
                "{}",
                error_block(
                    "watcher_init_failed",
                    &format!("cannot construct filesystem watcher: {e}"),
                    "check that inotify/FSEvents is available on this system",
                    None,
                )
            );
            return Err(silent_cli_error(format!("notify watcher init failed: {e}")));
        }
    };

    if let Err(e) = watcher.watch(&audit_dir, RecursiveMode::NonRecursive) {
        eprint!(
            "{}",
            error_block(
                "watcher_watch_failed",
                &format!("cannot watch audit directory: {e}"),
                "check that the audit directory is readable",
                None,
            )
        );
        return Err(silent_cli_error(format!("notify watch() failed: {e}")));
    }

    // Spawn the async event pump. It owns the receiver half.
    let follow_state = FollowState::new(audit_dir.clone(), filter, layout, theme, support);
    // P8 review patch: spawn the watcher task via `tokio::spawn` and
    // handle `JoinError::is_panic()` so a panic inside emit_row /
    // audit_row_cells / render_scrub_inline surfaces as a structured
    // SilentCliError instead of a raw panic trace. The watcher still
    // drops cleanly via scope unwind, but the operator sees a Story
    // 1.15-consistent error block.
    //
    // `tokio::spawn` requires `'static` futures, so we move the
    // detector + seen_request_ids into the spawned task. The return
    // path from the spawned task is an `anyhow::Result<()>` which
    // we unwrap through the JoinError.
    let watcher_handle =
        tokio::spawn(async move { follow_state.run(event_rx, detector, seen_request_ids).await });
    tokio::select! {
        res = watcher_handle => match res {
            Ok(inner) => inner,
            Err(join_err) if join_err.is_panic() => {
                let msg = panic_msg_from_join_err(join_err);
                eprint!(
                    "{}",
                    error_block(
                        "follow_panicked",
                        &format!("follow stream panicked: {msg}"),
                        "retry with a narrower filter, or report at https://github.com/botsdown/permitlayer/issues",
                        None,
                    )
                );
                Err(silent_cli_error(format!("follow stream panicked: {msg}")))
            }
            Err(join_err) => {
                // Cancelled (shouldn't happen outside select abort)
                // or other non-panic JoinError.
                Err(silent_cli_error(format!("follow task join failed: {join_err}")))
            }
        },
        _ = signal::ctrl_c() => {
            // Trailing newline so the shell prompt lands cleanly.
            println!();
            // `watcher` drops here via scope end → inotify_rm_watch.
            // The spawned watcher_handle will also be dropped as
            // select! exits, which aborts the task.
            Ok(())
        }
    }
}

/// Extract a human-readable message from a [`tokio::task::JoinError`]
/// that represents a panic. Falls back to a generic label when the
/// payload isn't a `&str` or `String`.
fn panic_msg_from_join_err(join_err: tokio::task::JoinError) -> String {
    match join_err.try_into_panic() {
        Ok(payload) => {
            if let Some(s) = payload.downcast_ref::<&'static str>() {
                (*s).to_owned()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "<non-string panic payload>".to_owned()
            }
        }
        Err(_) => "<panic payload unavailable>".to_owned(),
    }
}

/// State held across the watcher event loop: tracks the currently
/// active audit file, its byte offset, the filter, and the render
/// context. Everything the watcher task needs in one place.
///
/// # Rotation identity
///
/// `active_file` holds the path string, but path equality is not
/// enough to detect rotation. The daemon's writer rotates by
/// renaming `YYYY-MM-DD.jsonl` → `YYYY-MM-DD-1.jsonl` and opening a
/// fresh `YYYY-MM-DD.jsonl`, so before-and-after the same-path check
/// sees two DIFFERENT files at the identical path. To catch the
/// rotation even when the path string doesn't change, we also track
/// `(inode, dev)` from [`MetadataExt`] on Unix. A new file at the
/// same path has a new inode; the offset resets to 0.
///
/// On non-Unix platforms (`#[cfg(not(unix))]`), we fall back to a
/// simpler "if file metadata changed, reset offset" heuristic using
/// `file_len < active_offset` as the rotation signal, which is less
/// robust but sufficient for the current CI matrix (macOS + Linux).
///
/// [`MetadataExt`]: std::os::unix::fs::MetadataExt
struct FollowState {
    audit_dir: PathBuf,
    filter: AuditFilter,
    layout: TableLayout,
    theme: Theme,
    support: ColorSupport,
    active_file: Option<PathBuf>,
    active_offset: u64,
    /// Unix inode of the currently-tracked active file. `None` on
    /// non-Unix platforms or before the first `refresh_active_file`.
    #[cfg(unix)]
    active_ino: Option<u64>,
    /// Unix device ID of the currently-tracked active file. Paired
    /// with `active_ino` so cross-device renames still round-trip.
    #[cfg(unix)]
    active_dev: Option<u64>,
}

impl FollowState {
    fn new(
        audit_dir: PathBuf,
        filter: AuditFilter,
        layout: TableLayout,
        theme: Theme,
        support: ColorSupport,
    ) -> Self {
        Self {
            audit_dir,
            filter,
            layout,
            theme,
            support,
            active_file: None,
            active_offset: 0,
            #[cfg(unix)]
            active_ino: None,
            #[cfg(unix)]
            active_dev: None,
        }
    }

    async fn run(
        mut self,
        mut rx: UnboundedReceiver<notify::Result<notify::Event>>,
        mut detector: AnomalyDetector,
        mut seen_request_ids: HashSet<String>,
    ) -> anyhow::Result<()> {
        // Resolve the initial active file and seek to end-of-file so
        // we don't re-stream pre-existing content on startup. If there
        // is no file yet (brand-new audit dir), sit and wait for the
        // first Create event — follow mode is legitimately "watch and
        // wait" in that case.
        self.refresh_active_file(true).await;

        // P9 review patch: count consecutive notify::Result errors so
        // the follow loop bails on persistent filesystem-watch failure
        // (IN_Q_OVERFLOW, ENOSPC on inotify, audit dir rmdir'd). Before
        // the fix, the loop just `continue`d indefinitely without ever
        // exiting `rx.recv()`, so the user saw no output and no error.
        const CONSECUTIVE_ERROR_LIMIT: u32 = 10;
        let mut consecutive_errors: u32 = 0;

        // P11 review patch: `seen_request_ids` is a belt-and-braces
        // dedupe for the narrow race window between "replay finished"
        // and "watcher armed." That window is milliseconds, not the
        // lifetime of the follow session. After the first successful
        // `read_new_bytes` pass the watcher has taken over, so we
        // clear the set to bound memory. Before this fix, replay
        // events whose request_ids never appear in the live tail
        // stayed in the HashSet forever — a memory leak of
        // thousands of entries on a long-running `--since=24h` follow.
        let mut first_read_done = false;

        while let Some(event_result) = rx.recv().await {
            let event = match event_result {
                Ok(e) => {
                    consecutive_errors = 0;
                    e
                }
                Err(err) => {
                    consecutive_errors += 1;
                    warn!(
                        error = %err,
                        consecutive = consecutive_errors,
                        "notify watcher error"
                    );
                    if consecutive_errors >= CONSECUTIVE_ERROR_LIMIT {
                        eprint!(
                            "{}",
                            error_block(
                                "watcher_unrecoverable",
                                &format!(
                                    "filesystem watcher failed {CONSECUTIVE_ERROR_LIMIT} times in a row (last: {err})"
                                ),
                                "check disk space, inotify limits, and that the audit directory still exists",
                                None,
                            )
                        );
                        return Err(silent_cli_error(format!(
                            "notify watcher exceeded error limit ({CONSECUTIVE_ERROR_LIMIT}); last: {err}"
                        )));
                    }
                    continue;
                }
            };

            // P9: detect audit-dir deletion and bail. A Remove event
            // on the audit_dir itself means the operator ran
            // `rm -rf ~/.agentsso/audit` while follow was running —
            // the inotify watch is dead, no further events will fire,
            // and the process would otherwise hang forever.
            if matches!(event.kind, EventKind::Remove(_))
                && event.paths.iter().any(|p| p == &self.audit_dir)
            {
                eprint!(
                    "{}",
                    error_block(
                        "audit_dir_removed",
                        "audit directory was removed while follow was running",
                        "run: agentsso start",
                        None,
                    )
                );
                return Err(silent_cli_error("audit directory removed mid-stream"));
            }

            // We don't try to match the event's paths against our
            // active file — platform path normalization (macOS
            // `/var` ↔ `/private/var`) makes strict equality
            // fragile, and FSEvents often delivers coarse
            // `Event::Any` / `Event::Other` that carry no useful
            // kind discriminator.
            //
            // Instead, on any non-access event in the watched
            // directory, we unconditionally: (a) re-resolve today's
            // active file (handles rotation and midnight rollover),
            // and (b) read any new bytes from whatever active file
            // is now tracked. Both operations are idempotent:
            // re-resolve is a no-op if the path hasn't changed, and
            // `read_new_bytes` returns early if the file length
            // hasn't advanced. The cost of an unnecessary pass is
            // one stat() syscall.
            if matches!(event.kind, EventKind::Access(_)) {
                // Access events cannot indicate new writes; skip to
                // avoid hammering the file on every read by the
                // daemon's writer side.
                continue;
            }
            self.refresh_active_file(false).await;
            // AC #14 + P2 review patch: if any write through
            // emit_row/emit_hint sees EPIPE (the reader half of stdout
            // closed) OR a fatal non-transient error, bail the watcher
            // loop. EPIPE exits cleanly with `Ok(())`; a fatal error
            // surfaces an operator-visible structured error.
            match self.read_new_bytes(&mut seen_request_ids, &mut detector).await {
                WriteStatus::Ok => {}
                WriteStatus::BrokenPipe => {
                    // Reader closed — dropping the watcher via the
                    // outer `tokio::select!` triggers inotify_rm_watch
                    // cleanup on the way out.
                    return Ok(());
                }
                WriteStatus::Fatal(kind) => {
                    eprint!(
                        "{}",
                        error_block(
                            "stdout_write_failed",
                            &format!("follow stream write failed: {kind:?}"),
                            "check stdout is writable (disk space, pipe target, tty state)",
                            None,
                        )
                    );
                    return Err(silent_cli_error(format!(
                        "follow stream stdout write failed: {kind:?}"
                    )));
                }
            }
            // P11: after the first successful read pass, the
            // replay-to-watcher handoff window has definitely closed.
            // Drop the dedupe set so it doesn't accumulate forever.
            if !first_read_done {
                first_read_done = true;
                seen_request_ids.clear();
                seen_request_ids.shrink_to_fit();
            }
        }

        Ok(())
    }

    /// Re-resolve today's active audit file.
    ///
    /// When `seek_to_end` is true (initial call), the new file is
    /// opened and the offset is set to its current length so we only
    /// see future writes. When false (post-rotation), the new file
    /// is opened at offset 0 — it is freshly-created by the writer
    /// so its content is "what happened after rotation" which IS the
    /// live tail from the user's perspective.
    ///
    /// # Rotation detection (P1 fix)
    ///
    /// On Unix, compares `(inode, dev)` from `stat(2)` against the
    /// tracked `(active_ino, active_dev)`. When the writer renames
    /// `YYYY-MM-DD.jsonl` → `YYYY-MM-DD-1.jsonl` and opens a fresh
    /// `YYYY-MM-DD.jsonl`, the path equality check would short-circuit
    /// and leave `active_offset` stale, silently dropping post-rotation
    /// events when the pre-rotation offset was non-zero. With the
    /// inode check, a new file at the same path triggers a reset to
    /// offset 0 so the post-rotation content is read from the start.
    async fn refresh_active_file(&mut self, seek_to_end: bool) {
        // Story 8.2: snapshot `Utc::now()` ONCE per refresh so the
        // filename derivation and any subsequent rotation-check logic
        // in this iteration use the same date.
        let now = chrono::Utc::now();
        let today = today_filename(now);
        let candidate = self.audit_dir.join(&today);

        // Story 5.2 review patch P14: use async try_exists to avoid
        // blocking stat on the tokio reactor.
        let exists = tokio::fs::try_exists(&candidate).await.unwrap_or(false);
        if !exists {
            // No active file yet. If we had one, clear it; we'll
            // pick up a new file when a Create event fires.
            self.active_file = None;
            self.active_offset = 0;
            #[cfg(unix)]
            {
                self.active_ino = None;
                self.active_dev = None;
            }
            return;
        }

        // Stat the candidate once; use the metadata for both the
        // rotation-identity check and (on seek_to_end) the initial
        // offset.
        let meta = match tokio::fs::metadata(&candidate).await {
            Ok(m) => m,
            Err(e) => {
                warn!(path = %candidate.display(), error = %e, "metadata() failed for candidate file");
                return;
            }
        };

        // Rotation identity check — see P1.
        #[cfg(unix)]
        let (new_ino, new_dev) = {
            use std::os::unix::fs::MetadataExt;
            (Some(meta.ino()), Some(meta.dev()))
        };

        // Same path? Decide whether this is truly the same file.
        if self.active_file.as_ref() == Some(&candidate) {
            #[cfg(unix)]
            {
                // On Unix: same path + same (ino, dev) means no
                // rotation happened; keep the current offset.
                if self.active_ino == new_ino && self.active_dev == new_dev {
                    return;
                }
                // Same path but different inode → rotation happened.
                // Reset to the start of the new file so no post-
                // rotation bytes are lost. Log at debug level so an
                // operator tracing rotation can see the swap.
                tracing::debug!(
                    path = %candidate.display(),
                    old_ino = ?self.active_ino,
                    new_ino = ?new_ino,
                    "active file inode changed — treating as rotation"
                );
                self.active_offset = 0;
                self.active_ino = new_ino;
                self.active_dev = new_dev;
                return;
            }
            #[cfg(not(unix))]
            {
                // Non-Unix fallback: same path is treated as same
                // file. Rotation detection falls back to the
                // `file_len < active_offset` reset in read_new_bytes.
                return;
            }
        }

        // Different path → new file, switch and set offset per policy.
        let offset = if seek_to_end {
            meta.len()
        } else {
            // Post-rotation: read from the start of the new active
            // file, since everything in it is new.
            0
        };

        self.active_file = Some(candidate);
        self.active_offset = offset;
        #[cfg(unix)]
        {
            self.active_ino = new_ino;
            self.active_dev = new_dev;
        }
    }

    /// Read from `active_offset` to end-of-file, parse each newline
    /// delimited JSONL record, filter via `AuditFilter`, and render
    /// matching events through the design-system row pipeline. Also
    /// hands each matching event to the anomaly detector and prints
    /// the hint when a spike fires.
    ///
    /// Returns [`WriteStatus::BrokenPipe`] if any write through
    /// `emit_row` / `emit_hint` sees EPIPE; the caller uses that as
    /// the signal to exit the watcher loop cleanly.
    async fn read_new_bytes(
        &mut self,
        seen_request_ids: &mut HashSet<String>,
        detector: &mut AnomalyDetector,
    ) -> WriteStatus {
        let Some(ref active_file) = self.active_file else {
            return WriteStatus::Ok;
        };
        let active_file = active_file.clone();

        let mut file = match tokio::fs::File::open(&active_file).await {
            Ok(f) => f,
            Err(e) => {
                // File vanished mid-stream (e.g., rotated just now).
                // refresh_active_file will re-resolve on the next
                // watcher event; nothing to do here.
                warn!(path = %active_file.display(), error = %e, "open() failed in read_new_bytes");
                return WriteStatus::Ok;
            }
        };

        let file_len = match file.metadata().await {
            Ok(m) => m.len(),
            Err(e) => {
                warn!(path = %active_file.display(), error = %e, "metadata() failed in read_new_bytes");
                return WriteStatus::Ok;
            }
        };

        if file_len < self.active_offset {
            // File shrank — rotation or truncation. Re-seek to zero.
            self.active_offset = 0;
        }

        if file_len == self.active_offset {
            // No new data.
            return WriteStatus::Ok;
        }

        if let Err(e) = file.seek(std::io::SeekFrom::Start(self.active_offset)).await {
            warn!(error = %e, "seek() failed in read_new_bytes");
            return WriteStatus::Ok;
        }

        // P12 review patch: cap per-pass read at READ_CHUNK_BYTES so a
        // paused watcher waking up on a near-full 100 MB audit file
        // doesn't burst-allocate 100 MB on the tokio executor.
        // Anything beyond the chunk is picked up on the next event
        // (the watcher will keep firing as long as file_len is
        // advancing, or we'll catch up on the next natural tick).
        //
        // `usize::try_from` bounds the `as usize` cast against 32-bit
        // overflow — the daemon targets 64-bit but being defensive
        // here costs nothing.
        const READ_CHUNK_BYTES: u64 = 1_048_576; // 1 MiB
        let available = file_len - self.active_offset;
        let to_read_u64 = available.min(READ_CHUNK_BYTES);
        let to_read = usize::try_from(to_read_u64).unwrap_or(usize::MAX);

        let mut new_bytes = Vec::with_capacity(to_read);
        let mut take = (&mut file).take(to_read_u64);
        if let Err(e) = take.read_to_end(&mut new_bytes).await {
            warn!(error = %e, "read_to_end() failed in read_new_bytes");
            return WriteStatus::Ok;
        }

        // Track how far into `new_bytes` we consumed via complete
        // lines; if the tail ends mid-line, leave the partial
        // fragment unread (seek back to before it on the next pass).
        //
        // P26 review patch: collapsed the redundant `cursor` +
        // `last_complete_end` pair into a single `consumed` index.
        // The two always advanced in lockstep; one variable is
        // clearer and removes a footgun if future code ever tried
        // to diverge them.
        let mut consumed: usize = 0;
        let mut status = WriteStatus::Ok;
        while let Some(nl) = memchr_newline(&new_bytes[consumed..]) {
            let line_end = consumed + nl;
            let line_bytes = &new_bytes[consumed..line_end];
            consumed = line_end + 1; // past the '\n'

            // Parse + filter + render.
            let line_str = match std::str::from_utf8(line_bytes) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "invalid UTF-8 in audit line; skipping");
                    continue;
                }
            };
            let event: AuditEvent = match serde_json::from_str(line_str) {
                Ok(ev) => ev,
                Err(e) => {
                    warn!(error = %e, "failed to parse audit line; skipping");
                    continue;
                }
            };

            // Replay-dedupe: if --since replay already rendered this
            // event's request_id, skip it here. Belt-and-braces guard
            // for the narrow window between "replay finished" and
            // "watcher armed" where the writer could have appended
            // an event whose timestamp predates our replay cutoff.
            //
            // P11/M3: use `contains` rather than `remove` so the
            // dedupe is idempotent. The set is cleared in bulk by
            // FollowState::run after the first read pass closes the
            // handoff window — freeing per-entry removes here just
            // re-creates the asymmetric "first match drops, second
            // match passes through" bug Edge Case M3 flagged.
            if seen_request_ids.contains(&event.request_id) {
                continue;
            }

            if !self.filter.matches(&event) {
                continue;
            }

            status = emit_row(&event, self.layout, &self.theme, self.support);
            if status.should_exit_loop() {
                break;
            }

            // Feed the anomaly detector.
            if let Some(hint) = detector.observe(&event, Instant::now()) {
                status = emit_hint(&hint, &self.theme, self.support);
                if status.should_exit_loop() {
                    break;
                }
            }
        }

        // Advance offset past the last complete line consumed. Any
        // partial fragment after `consumed` stays unread and will be
        // picked up on the next pass.
        self.active_offset += consumed as u64;
        status
    }
}

/// Find the next `\n` byte in `bytes`, returning its position or
/// `None` if no newline is present.
fn memchr_newline(bytes: &[u8]) -> Option<usize> {
    bytes.iter().position(|&b| b == b'\n')
}

/// Drop the first `\n`-delimited line from `s`, returning whatever
/// follows the first newline (even if that remainder lacks a trailing
/// newline of its own).
///
/// Used by [`emit_row`] to strip the header line that
/// `design::render::table` always emits. Follow-mode is a continuous
/// flow — repeating the schema on every event would saturate the
/// stream with static chrome (and also breaks visual parity with the
/// `tail -f` mental model).
///
/// P3 review patch: replaces the previous `s.find('\n')` match which
/// had a dead `nl < s.len()` guard (always true when `find` returned
/// `Some`) and silently dropped the data row when the input had no
/// trailing newline. Now delegates to [`str::split_once`] which gives
/// the correct semantics uniformly:
///
/// - Input `"a\nb\nc\n"` → `"b\nc\n"` (header stripped, body + newlines preserved)
/// - Input `"header\ndata"` → `"data"` (body preserved without trailing newline)
/// - Input `"a\n"` → `""` (header-only, no data)
/// - Input `""` → `""`
/// - Input `"nolinebreak"` → `""` (no newline to split on)
fn strip_header_line(s: &str) -> String {
    s.split_once('\n').map(|(_header, rest)| rest.to_owned()).unwrap_or_default()
}

/// Return value from [`emit_row`] and [`emit_hint`].
///
/// Classifies the outcome of a stdout write:
/// - `Ok` — write succeeded, or failed with a transient error
///   ([`std::io::ErrorKind::Interrupted`], [`WouldBlock`]) where a
///   retry on the next iteration is legitimate.
/// - `BrokenPipe` — the reader half of the pipe has closed (EPIPE);
///   the caller must exit the watcher loop cleanly with `Ok(())`.
/// - `Fatal` — a non-recoverable write error that is not EPIPE
///   ([`StorageFull`], [`UnexpectedEof`], [`ConnectionAborted`],
///   etc.). The caller should emit an operator-facing error and exit
///   the loop via `silent_cli_error`.
///
/// This is a P2 review patch. Before the fix, `from_io_result`
/// collapsed every non-BrokenPipe error into `Ok`, causing the
/// follow loop to spin forever writing to a dead sink on ENOSPC /
/// EIO / network-fs failures. The new classification bails cleanly
/// on any terminal error.
///
/// [`WouldBlock`]: std::io::ErrorKind::WouldBlock
/// [`StorageFull`]: std::io::ErrorKind::StorageFull
/// [`UnexpectedEof`]: std::io::ErrorKind::UnexpectedEof
/// [`ConnectionAborted`]: std::io::ErrorKind::ConnectionAborted
#[must_use]
enum WriteStatus {
    Ok,
    BrokenPipe,
    Fatal(std::io::ErrorKind),
}

impl WriteStatus {
    fn from_io_result(result: std::io::Result<()>) -> Self {
        use std::io::ErrorKind::*;
        match result {
            Ok(()) => Self::Ok,
            // Transient — retry on next iteration.
            Err(e) if e.kind() == Interrupted || e.kind() == WouldBlock => Self::Ok,
            // Reader closed — exit loop cleanly via `Ok(())`.
            Err(e) if e.kind() == BrokenPipe => Self::BrokenPipe,
            // Everything else is terminal: ENOSPC, EIO, network-fs
            // failure, etc. The loop must bail and the operator must
            // see a structured error.
            Err(e) => Self::Fatal(e.kind()),
        }
    }

    /// Returns `true` if the caller should exit the watcher loop.
    fn should_exit_loop(&self) -> bool {
        matches!(self, Self::BrokenPipe | Self::Fatal(_))
    }
}

/// Render a single event through the design-system row pipeline and
/// then (if the event carries v2 scrub samples) the inline-scrub
/// renderer. Shared between replay and live-tail paths so the two
/// renderers cannot drift.
///
/// Live-tail rendering elides the header row that `design::render::table`
/// would otherwise emit per-row — follow mode is a continuous flow
/// of data, not a rebuilt schema per event. The caller is responsible
/// for emitting the header once at startup if desired (see
/// `emit_header`).
///
/// Returns [`WriteStatus::BrokenPipe`] when the reader half of stdout
/// has closed (e.g. `agentsso audit --follow | head -5` exits after 5
/// lines). The watcher loop uses this signal to bail out cleanly
/// instead of spinning on a dead pipe — see AC #14.
fn emit_row(
    event: &AuditEvent,
    layout: TableLayout,
    theme: &Theme,
    support: ColorSupport,
) -> WriteStatus {
    // Render via the Story 5.1 design-system primitive, then strip
    // the header line (the first \n-delimited line) so follow mode
    // shows only data rows. The primitive's column widths are
    // derived from header text AND cell widths, so stripping the
    // header line does NOT affect data-row alignment.
    let headers = audit_row_headers(layout);
    let cells = audit_row_cells(event, layout);
    let full = match table(headers, &[cells], layout, theme, support) {
        Ok(s) => s,
        Err(e) => {
            // P24 review patch: surface a visible placeholder to
            // operators so a single broken event doesn't silently
            // disappear from the stream. tracing is off by default,
            // so the warn! alone is invisible.
            warn!(error = %e, "failed to render audit row; skipping");
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "  [row_render_failed: {kind}]", kind = e);
            let _ = out.flush();
            return WriteStatus::Ok;
        }
    };
    let row_str = strip_header_line(&full);

    // Locked stdout with EPIPE detection. When the reader half closes
    // (e.g. `agentsso audit --follow | head`), `write!` returns
    // `BrokenPipe`. We surface that through `WriteStatus` so the
    // watcher loop can bail cleanly on the next iteration.
    let mut out = std::io::stdout().lock();
    let mut status = WriteStatus::from_io_result(write!(out, "{}", row_str).map(|_| ()));
    if status.should_exit_loop() {
        return status;
    }

    // Scrub sample rendering (preserved unchanged from Story 2.4 /
    // 2.6). v2+ events can carry scrub_events.samples which the
    // ScrubInline component renders beneath the row. The DoS-hardened
    // `sample_is_renderable` guard prevents bounds-invalid samples
    // from panicking the loop.
    if event.schema_version >= 2
        && let Some(samples_arr) = event
            .extra
            .get("scrub_events")
            .and_then(|se| se.get("samples"))
            .and_then(|s| s.as_array())
        && !samples_arr.is_empty()
    {
        for sample_value in samples_arr {
            match serde_json::from_value::<ScrubSample>(sample_value.clone()) {
                Ok(sample) => {
                    if !sample_is_renderable(&sample) {
                        warn!(
                            rule = %sample.rule,
                            snippet_len = sample.snippet.len(),
                            placeholder_offset = sample.placeholder_offset,
                            placeholder_len = sample.placeholder_len,
                            "scrub sample has invalid offsets; skipping"
                        );
                        continue;
                    }
                    let res = write!(out, "{}", render_scrub_inline(&sample, theme, support));
                    status = WriteStatus::from_io_result(res.map(|_| ()));
                    if status.should_exit_loop() {
                        return status;
                    }
                }
                Err(e) => {
                    warn!(error = %e, "malformed scrub sample in audit line; skipping");
                }
            }
        }
    }

    WriteStatus::from_io_result(out.flush())
}

/// Render an anomaly hint line on its own row between events. Returns
/// [`WriteStatus::BrokenPipe`] on EPIPE so the watcher loop can bail.
fn emit_hint(
    hint: &crate::cli::audit_anomaly::AnomalyHint,
    theme: &Theme,
    support: ColorSupport,
) -> WriteStatus {
    let line = crate::cli::audit_anomaly::format_hint(hint, theme, support);
    let mut out = std::io::stdout().lock();
    let write_status = WriteStatus::from_io_result(writeln!(out, "{line}").map(|_| ()));
    if write_status.should_exit_loop() {
        return write_status;
    }
    WriteStatus::from_io_result(out.flush())
}

/// Returns `true` if a deserialized `ScrubSample` has valid byte-offset
/// bounds for `render_scrub_inline` / `fit_snippet` to slice safely.
///
/// Checks (Story 2.6 review patch — preserved here across the Story
/// 5.2 refactor):
/// 1. `placeholder_offset + placeholder_len` does not overflow and
///    fits inside `snippet.len()`.
/// 2. Both boundaries land on UTF-8 char boundaries.
/// 3. The placeholder span is non-empty (otherwise the renderer
///    produces a zero-width highlight that the arrow math can't
///    locate).
///
/// Bounds-invalid samples come from corrupted audit files or hostile
/// local actors editing JSONL by hand; the follow loop MUST reject
/// them without panicking.
fn sample_is_renderable(sample: &ScrubSample) -> bool {
    let Some(end) = sample.placeholder_offset.checked_add(sample.placeholder_len) else {
        return false;
    };
    if end > sample.snippet.len() {
        return false;
    }
    if sample.placeholder_len == 0 {
        return false;
    }
    sample.snippet.is_char_boundary(sample.placeholder_offset)
        && sample.snippet.is_char_boundary(end)
}

/// Returns the expected filename for today's audit file, e.g.
/// `2026-04-15.jsonl`. Matches the writer's `writer.rs` rotation
/// naming convention.
///
/// Story 8.2 P15 fix: accepts the caller's `now` snapshot rather than
/// reading `chrono::Utc::now()` internally. Pre-Story-8.2, the
/// follow-mode rotation-check loop could read the clock twice at
/// midnight (once here, once for the rotation check) and disagree —
/// leading to a "file not found" race when the daemon rotated the
/// YYYY-MM-DD file just as the follower's `Utc::now()` ticked forward.
fn today_filename(now: chrono::DateTime<chrono::Utc>) -> String {
    format!("{}.jsonl", now.format("%Y-%m-%d"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ----- sample_is_renderable bounds checks (Story 2.6 review patch) -----

    fn valid_sample() -> ScrubSample {
        ScrubSample {
            rule: "otp-6digit".into(),
            snippet: "Your verification code is <REDACTED_OTP>".into(),
            placeholder_offset: 26,
            placeholder_len: 14,
        }
    }

    #[test]
    fn sample_is_renderable_accepts_valid() {
        assert!(sample_is_renderable(&valid_sample()));
    }

    #[test]
    fn sample_is_renderable_rejects_offset_past_end() {
        let mut s = valid_sample();
        s.placeholder_offset = 9999;
        assert!(!sample_is_renderable(&s));
    }

    #[test]
    fn sample_is_renderable_rejects_len_past_end() {
        let mut s = valid_sample();
        s.placeholder_len = 9999;
        assert!(!sample_is_renderable(&s));
    }

    #[test]
    fn sample_is_renderable_rejects_offset_plus_len_overflow() {
        let mut s = valid_sample();
        s.placeholder_offset = usize::MAX;
        s.placeholder_len = 1;
        assert!(!sample_is_renderable(&s));
    }

    #[test]
    fn sample_is_renderable_rejects_zero_placeholder_len() {
        let mut s = valid_sample();
        s.placeholder_len = 0;
        assert!(!sample_is_renderable(&s));
    }

    #[test]
    fn sample_is_renderable_rejects_mid_codepoint_boundary() {
        // 4-byte emoji at offset 0 — placeholder_offset=1 lands mid-codepoint.
        let snippet = "\u{1F600}some text".to_string();
        let s = ScrubSample {
            rule: "custom".into(),
            snippet,
            placeholder_offset: 1,
            placeholder_len: 2,
        };
        assert!(!sample_is_renderable(&s));
    }

    // ----- today_filename -----

    #[test]
    fn today_filename_has_jsonl_extension_and_expected_length() {
        let name = today_filename(chrono::Utc::now());
        assert!(name.ends_with(".jsonl"));
        assert_eq!(name.len(), "YYYY-MM-DD.jsonl".len());
    }

    // Story 8.2 P15 fix: inject the snapshot and verify the name is
    // derived from the argument, not the wall clock.
    #[test]
    fn today_filename_uses_injected_snapshot() {
        let fixed = chrono::DateTime::parse_from_rfc3339("2026-04-19T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(today_filename(fixed), "2026-04-19.jsonl");
    }

    // ----- memchr_newline -----

    #[test]
    fn memchr_newline_finds_first_newline() {
        assert_eq!(memchr_newline(b"abc\ndef"), Some(3));
    }

    #[test]
    fn memchr_newline_returns_none_on_no_newline() {
        assert_eq!(memchr_newline(b"abc"), None);
    }

    #[test]
    fn memchr_newline_on_empty_returns_none() {
        assert_eq!(memchr_newline(b""), None);
    }

    // ----- strip_header_line -----

    #[test]
    fn strip_header_line_removes_first_line() {
        assert_eq!(strip_header_line("header\ndata\n"), "data\n");
    }

    #[test]
    fn strip_header_line_header_only_returns_empty() {
        assert_eq!(strip_header_line("header\n"), "");
    }

    #[test]
    fn strip_header_line_empty_input_returns_empty() {
        assert_eq!(strip_header_line(""), "");
    }

    #[test]
    fn strip_header_line_multiple_data_rows_preserved() {
        assert_eq!(strip_header_line("h\n1\n2\n3\n"), "1\n2\n3\n");
    }

    #[test]
    fn strip_header_line_no_newline_returns_empty() {
        assert_eq!(strip_header_line("nolinebreak"), "");
    }

    #[test]
    fn strip_header_line_data_without_trailing_newline_preserved() {
        // P3 review patch: the old `find('\n')` path silently dropped
        // the data when `table()` returned something without a
        // trailing newline. `split_once` preserves the remainder
        // intact.
        assert_eq!(strip_header_line("header\ndata"), "data");
    }

    // ----- P19: malformed v2 event regression (Story 2.6 DoS hardening) -----

    fn malformed_v2_event(placeholder_offset: usize, placeholder_len: usize) -> AuditEvent {
        let mut event = AuditEvent::new(
            "test-agent".into(),
            "gmail".into(),
            "mail.readonly".into(),
            "messages/1".into(),
            "ok".into(),
            "api-call".into(),
        );
        event.schema_version = 2;
        event.extra = serde_json::json!({
            "scrub_events": {
                "summary": { "otp-6digit": 1 },
                "samples": [{
                    "rule": "otp-6digit",
                    "snippet": "short",
                    "placeholder_offset": placeholder_offset,
                    "placeholder_len": placeholder_len,
                }]
            }
        });
        event
    }

    #[test]
    fn emit_row_does_not_panic_on_out_of_bounds_sample() {
        // Story 2.6 review patch regression: a malformed v2 scrub
        // sample with placeholder_offset > snippet.len() must not
        // panic the follow loop. The sample_is_renderable guard
        // catches it before `render_scrub_inline` gets unchecked
        // byte-sliced indices.
        let event = malformed_v2_event(9999, 14);
        let _status =
            emit_row(&event, TableLayout::Standard, &Theme::Carapace, ColorSupport::NoColor);
    }

    #[test]
    fn emit_row_does_not_panic_on_mid_codepoint_offset() {
        // placeholder_offset lands mid-UTF-8-codepoint. The guard
        // rejects the sample before unchecked slicing happens.
        let mut event = AuditEvent::new(
            "a".into(),
            "gmail".into(),
            "mail.readonly".into(),
            "m/abc".into(),
            "ok".into(),
            "api-call".into(),
        );
        event.schema_version = 2;
        event.extra = serde_json::json!({
            "scrub_events": {
                "summary": { "otp-6digit": 1 },
                "samples": [{
                    "rule": "otp-6digit",
                    "snippet": "\u{1F600}abc",
                    "placeholder_offset": 1, // mid-codepoint
                    "placeholder_len": 2,
                }]
            }
        });
        let _status =
            emit_row(&event, TableLayout::Standard, &Theme::Carapace, ColorSupport::NoColor);
    }

    #[test]
    fn emit_row_does_not_panic_on_zero_placeholder_len() {
        let event = malformed_v2_event(0, 0);
        let _status =
            emit_row(&event, TableLayout::Standard, &Theme::Carapace, ColorSupport::NoColor);
    }

    // ----- P18: scrub-before-log invariant enforcement -----

    #[test]
    fn audit_follow_module_does_not_import_scrub_engine() {
        // Story 2.4 scrub-before-log invariant + Story 5.2 AC #12:
        // the follow-mode reader MUST NOT re-scrub audit content.
        // Re-scrubbing would risk double-replacement of `<REDACTED_*>`
        // placeholders and waste CPU. Mirrors the Story 5.1
        // `reader_does_not_import_scrub_engine` test adapted for the
        // new module.
        //
        // NB: the forbidden patterns are built via `concat!` so this
        // test's own source doesn't match itself under
        // `include_str!`.
        let src = include_str!("audit_follow.rs");
        let forbidden_crate = concat!("use crate::", "scrub::", "ScrubEngine");
        let forbidden_core = concat!("use permitlayer_core::", "scrub::", "ScrubEngine");
        let forbidden_path = concat!("Scrub", "Engine", "::");
        assert!(
            !src.contains(forbidden_crate),
            "audit_follow must not import crate::scrub engine (Story 2.4 invariant)"
        );
        assert!(
            !src.contains(forbidden_core),
            "audit_follow must not import permitlayer_core scrub engine"
        );
        assert!(
            !src.contains(forbidden_path),
            "audit_follow must not reference the scrub-engine qualified path"
        );
    }

    // ----- run_follow argument validation -----

    #[tokio::test]
    async fn run_follow_rejects_until_flag_with_silent_cli_error() {
        // --until is explicitly rejected in the follow path BEFORE
        // any watcher is constructed. This test asserts the error
        // path wraps a SilentCliError so `main::anyhow_to_exit_code`
        // suppresses the duplicate generic error trailer.
        let args = AuditArgs { follow: true, until: Some("1h".into()), ..Default::default() };
        let err = run_follow(args).await.unwrap_err();
        assert!(
            err.chain().any(|source| source.is::<crate::cli::SilentCliError>()),
            "expected SilentCliError in error chain, got: {err:?}"
        );
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("--until"),
            "error description should mention --until: {rendered}"
        );
    }
}
