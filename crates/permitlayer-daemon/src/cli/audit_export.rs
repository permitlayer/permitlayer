//! `agentsso audit --export=<path>` — write a filtered event set to
//! JSON or CSV in a single command.
//!
//! # Story 5.3
//!
//! Third consumer of the shared
//! [`permitlayer_core::audit::reader::AuditReader`] primitive. Reuses
//! [`super::audit::build_filter_from_args`] (promoted to `pub(super)`
//! by Story 5.2) so the filter vocabulary is identical to query and
//! follow mode. Reuses the Story 5.2 `spawn_blocking` pattern for the
//! `AuditReader::query` read and the serialize-and-write step, so a
//! 24h export of a busy deployment never blocks the tokio reactor.
//!
//! The scrub invariant from Story 2.4 is preserved: this module does
//! NOT import `ScrubEngine`. A grep-assert unit test enforces that.
//! The exported artifact contains exactly the `<REDACTED_*>`
//! placeholders the writer produced at audit-write time.
//!
//! # Write contract
//!
//! The write path is a single function, [`persist_atomic`], that owns
//! the full contract:
//!
//! 1. **Temp file** — created via `tempfile::NamedTempFile::new_in
//!    (dest.parent())` so the atomic rename stays within one
//!    filesystem (`EXDEV` otherwise falls back to non-atomic
//!    copy+unlink).
//! 2. **Write** — caller-provided serializer writes into a
//!    `BufWriter`; the inner writer is extracted via
//!    `BufWriter::into_inner()?` so a disk-full during the implicit
//!    drop-flush surfaces as an error, not silent data loss.
//! 3. **fsync file** — `sync_all()` on the temp handle, pushing data
//!    + metadata to persistent storage.
//! 4. **Atomic rename** — `persist_noclobber(dest)` when `!force`
//!    fails atomically (POSIX `renameat2(RENAME_NOREPLACE)` on
//!    Linux; `link(2)`+`unlink` on macOS — NFS-safe, stronger than
//!    `O_EXCL`). `persist(dest)` when `force` replaces the
//!    destination atomically.
//! 5. **fsync parent dir** — on Unix, open the parent directory and
//!    `sync_all()` it. Without this, a power failure between rename
//!    and writeback can lose the directory entry on ext4 /
//!    `data=ordered`, XFS, and similar. Windows' `MoveFileEx` is
//!    transactional and does not need this step.
//! 6. **Measure** — `dest.metadata()?.len()` is the authoritative
//!    byte count reported by the success summary.
//!
//! A panic, SIGKILL, or any I/O failure anywhere in steps 1-4 leaves
//! the destination untouched and the temp file auto-unlinked by
//! `NamedTempFile::Drop`. A concurrent process that wins the race to
//! create `dest` while `--force` is not set fails `persist_noclobber`
//! with `PersistError` → structured `export_destination_exists` error
//! block, preserving the contract "without `--force`, never clobber".
//!
//! # Validation layer
//!
//! [`validate_destination`] is an **advisory pre-flight**. It prints
//! friendly structured error blocks for the common ergonomic failure
//! modes (destination exists without `--force`, destination is a
//! directory, parent missing, parent not writable) so operators hit
//! them BEFORE the 500 ms audit-log read. Correctness does not depend
//! on validation running — [`persist_atomic`] is the single source
//! of truth and catches concurrent-creator races via
//! `persist_noclobber`.

#[cfg(unix)]
use std::fs::File;
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use permitlayer_core::audit::event::AuditEvent;
use permitlayer_core::audit::reader::{AuditReader, AuditReaderError};

use super::audit::{AuditArgs, build_filter_from_args, resolve_audit_dir};
use super::silent_cli_error;
use crate::design::format::{format_bytes, format_count};
use crate::design::render::error_block;

/// Format of the on-disk export artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExportFormat {
    /// Single JSON document: array of `AuditEvent` objects. Pretty-
    /// printed with 2-space indent, trailing newline.
    Json,
    /// RFC 4180 CSV: header row + one row per event, CRLF terminator.
    /// 10 columns: timestamp, request_id, agent_id, service, scope,
    /// resource, outcome, event_type, schema_version, extra_json.
    Csv,
}

/// Entry point for `agentsso audit --export=<path>`.
pub async fn run_export(args: AuditArgs) -> anyhow::Result<()> {
    // Precondition: caller (`cli::audit::run`) dispatches here only
    // when `args.export.is_some()`. A `None` here means an internal
    // invariant has broken — log loudly and fail fast.
    let dest = args.export.clone().ok_or_else(|| {
        tracing::error!("run_export called without --export set — internal invariant violation");
        debug_assert!(args.export.is_some(), "run_export requires --export");
        silent_cli_error("run_export called without --export set")
    })?;

    // 1. Resolve format (clap already validated --format values, but
    //    double-check for programmatic callers; also handle extension
    //    inference with the friendly ambiguous-extension error).
    let format = resolve_format(&dest, args.format.as_deref())?;

    // 2. Advisory destination pre-flight — surfaces friendly error
    //    blocks for common ergonomic failures BEFORE we read the
    //    audit log. Not load-bearing for correctness.
    validate_destination(&dest, args.force)?;

    // 3. Build the filter (reuses Story 5.1 logic + error wording).
    //    Ordered AFTER destination validation but BEFORE audit-dir
    //    existence / I/O — invalid flags fire before any filesystem
    //    read (Dev Notes § "Ordering of validation errors").
    let filter = build_filter_from_args(&args)?;

    // H4: apply an implicit `--since=24h` time bound when no filter
    // axis was set. Without this, an `agentsso audit --export=out.json`
    // with no flags reads the full 90-day retention into RAM — a
    // foot-gun on busy deployments. Matches the query path's
    // default-safety posture at `cli/audit.rs::run_query`. If the
    // operator DID pass any filter (`--service`, `--since`, etc.),
    // respect their intent and don't bound further.
    let mut effective_filter = filter.clone();
    if !filter.is_active() && effective_filter.since.is_none() {
        effective_filter.since = Some(chrono::Utc::now() - chrono::Duration::hours(24));
    }

    // 4. Resolve audit dir. Missing-dir handling is unified: the
    //    `AuditReader::query` call inside the blocking task surfaces
    //    `AuditReaderError::AuditDirMissing` with the same wording
    //    as the Story 5.1 query path.
    let audit_dir = resolve_audit_dir()?;

    // 5. Single blocking task owns both the query and the write.
    //    Avoids a second await point; matches Story 5.2's P7
    //    pattern. Structured error blocks are printed from the
    //    blocking thread (stderr is process-wide).
    let force = args.force;
    let (event_count, bytes_written) =
        tokio::task::spawn_blocking(move || -> anyhow::Result<(usize, u64)> {
            let events =
                AuditReader::new(&audit_dir).query(&effective_filter).map_err(|e| match &e {
                    AuditReaderError::AuditDirMissing { path } => {
                        eprint!(
                            "{}",
                            error_block(
                                "audit_dir_missing",
                                &format!("audit directory not found at {}", path.display()),
                                "agentsso start",
                                None,
                            )
                        );
                        silent_cli_error(format!("audit directory not found at {}", path.display()))
                    }
                    AuditReaderError::Io { path, source } => {
                        eprint!(
                            "{}",
                            error_block(
                                "audit_io_error",
                                &format!(
                                    "failed to read audit log at {}: {source}",
                                    path.display()
                                ),
                                "check ~/.agentsso/audit/ permissions",
                                None,
                            )
                        );
                        silent_cli_error(format!("audit I/O error at {}: {source}", path.display()))
                    }
                })?;

            let count = events.len();
            let bytes = persist_atomic(&dest, force, |writer| match format {
                ExportFormat::Json => serialize_json(&events, writer),
                ExportFormat::Csv => serialize_csv(&events, writer),
            })?;
            Ok((count, bytes))
        })
        .await
        .map_err(|join_err| {
            eprint!(
                "{}",
                error_block(
                    "export_internal_error",
                    "export worker task failed unexpectedly",
                    "report this bug with RUST_LOG=debug output",
                    None,
                )
            );
            tracing::error!(error = %join_err, "spawn_blocking join failed for export");
            silent_cli_error(format!("export join failed: {join_err}"))
        })??;

    // 6. Zero-event warn to stderr (AC #10). Exit status is still 0
    //    because absence-of-activity is a legitimate forensic
    //    artifact.
    if event_count == 0 {
        tracing::warn!("export matched zero events (empty artifact written)");
    }

    // 7. Success summary on stdout (AC #6).
    print_summary(
        event_count as u64,
        args.export.as_deref().unwrap_or(Path::new("")),
        bytes_written,
    );
    Ok(())
}

/// Resolve the parent directory of an export destination path,
/// normalizing the empty-parent case (relative filename with no
/// directory component) to `.`.
fn export_parent(dest: &Path) -> &Path {
    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    if parent.as_os_str().is_empty() { Path::new(".") } else { parent }
}

/// Resolve the export format from the `--format` override (if set)
/// or from the destination path's file extension.
///
/// Explicit `--format=json|csv` always wins over extension inference.
/// When `--format` is absent and the extension is ambiguous (not
/// `.json` or `.csv`, case-insensitive), returns a structured
/// `export_format_ambiguous` error block.
fn resolve_format(path: &Path, override_: Option<&str>) -> anyhow::Result<ExportFormat> {
    if let Some(fmt) = override_ {
        // clap's `value_parser = ["json", "csv"]` already gates this,
        // but double-check for programmatic callers (e.g., unit
        // tests) that bypass clap. Case-insensitive match per AC #3.
        return match fmt.to_ascii_lowercase().as_str() {
            "json" => Ok(ExportFormat::Json),
            "csv" => Ok(ExportFormat::Csv),
            other => {
                eprint!(
                    "{}",
                    error_block(
                        "invalid_format",
                        &format!("'{other}' is not a valid export format"),
                        "valid formats: json, csv",
                        None,
                    )
                );
                Err(silent_cli_error(format!("invalid --format value: {other}")))
            }
        };
    }

    // Infer from extension (case-insensitive: .JSON / .Csv both work).
    let ext = path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("json") => Ok(ExportFormat::Json),
        Some("csv") => Ok(ExportFormat::Csv),
        _ => {
            eprint!(
                "{}",
                error_block(
                    "export_format_ambiguous",
                    &format!("cannot infer export format from path: {}", path.display()),
                    "pass --format=json or --format=csv, or use a .json/.csv extension",
                    None,
                )
            );
            Err(silent_cli_error("ambiguous export format"))
        }
    }
}

/// Advisory pre-flight validation of the export destination.
///
/// Fires friendly structured error blocks for the common ergonomic
/// failure modes BEFORE the 500 ms audit-log read. **NOT** load-
/// bearing for correctness — [`persist_atomic`] is the single source
/// of truth for the write contract, including the no-clobber race
/// defense via `persist_noclobber`.
///
/// Probes:
/// 1. `dest` is not an existing directory (persist would fail with
///    EISDIR later).
/// 2. `dest` is not a symlink (symlinks — including broken ones —
///    would be replaced by `rename`, not followed). Requires
///    `--force` to replace.
/// 3. Parent directory exists (friendly `mkdir -p` remediation).
/// 4. Parent directory is writable (via Unix `access(W_OK)` or
///    `OpenOptions::create_new` probe on Windows — no leftover probe
///    file in the destination dir).
/// 5. `dest` does not already exist as a regular file, unless
///    `--force` is set.
fn validate_destination(dest: &Path, force: bool) -> anyhow::Result<()> {
    let parent = export_parent(dest);

    // Parent must exist. Checked first so the remediation is
    // "create the directory" rather than "file permission".
    if !parent.exists() {
        eprint!(
            "{}",
            error_block(
                "export_parent_missing",
                &format!("parent directory does not exist: {}", parent.display()),
                &format!("create the directory first: mkdir -p {}", parent.display()),
                None,
            )
        );
        return Err(silent_cli_error(format!(
            "export parent directory missing: {}",
            parent.display()
        )));
    }

    // Parent must be a directory. Catches `--export=some-file/out.json`
    // where `some-file` exists but is a regular file.
    if !parent.is_dir() {
        eprint!(
            "{}",
            error_block(
                "export_parent_missing",
                &format!("parent is not a directory: {}", parent.display()),
                "choose a path whose parent is a directory",
                None,
            )
        );
        return Err(silent_cli_error(format!(
            "export parent is not a directory: {}",
            parent.display()
        )));
    }

    // `symlink_metadata` does NOT follow symlinks, so we can
    // distinguish "dest is a regular file", "dest is a symlink",
    // and "dest is a directory" explicitly.
    match dest.symlink_metadata() {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_dir() {
                eprint!(
                    "{}",
                    error_block(
                        "export_destination_is_directory",
                        &format!("destination is a directory, not a file: {}", dest.display()),
                        "specify a file path (e.g., incident.json) instead of a directory",
                        None,
                    )
                );
                return Err(silent_cli_error(format!(
                    "export destination is a directory: {}",
                    dest.display()
                )));
            }
            if ft.is_symlink() && !force {
                eprint!(
                    "{}",
                    error_block(
                        "export_destination_exists",
                        &format!("destination is a symlink: {}", dest.display()),
                        "use --force to replace the symlink, or choose a different path",
                        None,
                    )
                );
                return Err(silent_cli_error(format!(
                    "export destination is a symlink: {}",
                    dest.display()
                )));
            }
            // Regular file (or symlink-with-force): fall through to
            // the force check below.
            if !force {
                eprint!(
                    "{}",
                    error_block(
                        "export_destination_exists",
                        &format!("file already exists: {}", dest.display()),
                        "use --force to overwrite, or choose a different path",
                        None,
                    )
                );
                return Err(silent_cli_error(format!(
                    "export destination exists without --force: {}",
                    dest.display()
                )));
            }
            // Force + existing regular file: OK. Log at info level
            // for operator visibility AFTER the write succeeds in
            // persist_atomic.
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Fresh destination, no existing file to worry about.
            // Fall through to the writability probe.
        }
        Err(e) => {
            // Some other error on symlink_metadata (permission
            // denied on the path, bad OS string, etc.). Surface it.
            eprint!(
                "{}",
                error_block(
                    "export_parent_not_writable",
                    &format!("cannot stat destination: {}: {e}", dest.display()),
                    "check path and parent directory permissions",
                    None,
                )
            );
            return Err(silent_cli_error(format!(
                "export destination stat failed for {}: {e}",
                dest.display()
            )));
        }
    }

    // Probe parent writability without leaving a file behind.
    if let Err(e) = probe_parent_writable(parent) {
        eprint!(
            "{}",
            error_block(
                "export_parent_not_writable",
                &format!("cannot write to directory: {}", parent.display()),
                "check directory permissions or choose a writable path",
                None,
            )
        );
        return Err(silent_cli_error(format!(
            "export parent not writable {}: {e}",
            parent.display()
        )));
    }

    Ok(())
}

/// Probe whether `parent` is writable by the current process without
/// leaving a file behind.
///
/// On Unix we use `faccessat(W_OK)` via `libc::access` — no file
/// created, no `notify` watcher noise. On Windows we fall back to a
/// single `create_new` probe with a deterministic hidden filename
/// that we unlink immediately; the alternative is `GetFileAttributes`
/// which doesn't tell us about ACLs.
fn probe_parent_writable(parent: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use nix::unistd::{AccessFlags, access};
        match access(parent, AccessFlags::W_OK) {
            Ok(()) => Ok(()),
            Err(errno) => Err(io::Error::from_raw_os_error(errno as i32)),
        }
    }
    #[cfg(not(unix))]
    {
        // Windows fallback: create + unlink a deterministic probe
        // file. Minor filesystem churn in exchange for correct ACL
        // semantics.
        use std::process;
        let probe = parent.join(format!(".agentsso-export-probe.{}", process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&probe) {
            Ok(_file) => {
                let _ = std::fs::remove_file(&probe);
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // Another process's probe collided — still proves
                // writability.
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

/// The single source of truth for the export write contract.
///
/// Writes bytes produced by `serialize` to `dest` atomically. The
/// callback receives a `&mut dyn Write` backed by a `BufWriter` over
/// the temp file; serializers should NOT flush or fsync — this
/// function owns the drop-flush + fsync + persist dance.
///
/// Contract:
/// - On success: `dest` contains the serialized bytes; no temp
///   siblings remain; parent-directory fsync has been called on Unix.
/// - On any failure (serialize, flush, fsync, persist_noclobber
///   collision, etc.): `dest` is either untouched (fresh write) or
///   contains the PREVIOUS contents (if `force` was set and the
///   failure occurred after the temp-file write but before persist).
///   Temp siblings are unlinked by `NamedTempFile::Drop`.
/// - When `!force` and a concurrent process creates `dest` between
///   validation and `persist_noclobber`, the error is the same
///   `export_destination_exists` structured block the user would see
///   if the file existed at validation time. No silent clobber.
///
/// Returns the destination file's size in bytes (via
/// `dest.metadata()`), which is the authoritative byte count
/// reported by the success summary line.
fn persist_atomic<F>(dest: &Path, force: bool, serialize: F) -> anyhow::Result<u64>
where
    F: FnOnce(&mut dyn Write) -> anyhow::Result<()>,
{
    let parent = export_parent(dest);

    // 1. Create the temp file in the destination's parent directory.
    //    Same filesystem = atomic rename in step 4.
    let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(|e| {
        eprint!(
            "{}",
            error_block(
                "export_write_failed",
                &format!("failed to create temp file in {}: {e}", parent.display()),
                "check parent directory permissions and disk space",
                None,
            )
        );
        silent_cli_error(format!("temp file creation failed in {}: {e}", parent.display()))
    })?;

    // 2. Hand the caller a BufWriter over the temp file's handle.
    //    We use `into_inner` (not drop) to surface any late flush
    //    error that a plain `drop(BufWriter)` would swallow.
    //
    //    Scoped so the BufWriter is fully consumed before we fsync
    //    the underlying fd.
    {
        // `as_file_mut` gives us a `&mut File`. BufWriter<&mut File>
        // is `Sized` and `Write`; its `into_inner` returns the
        // `&mut File` after a final checked flush.
        let inner = temp.as_file_mut();
        let mut writer = BufWriter::new(inner);
        serialize(&mut writer)?;
        // `into_inner` calls flush and returns `Err` if flush fails —
        // closes the "disk fills between checked flush() and drop"
        // hazard that a plain `drop(writer)` would swallow.
        writer.into_inner().map_err(|e| {
            let io_err = e.into_error();
            eprint!(
                "{}",
                error_block(
                    "export_write_failed",
                    &format!("failed to flush export buffer: {io_err}"),
                    "check disk space",
                    None,
                )
            );
            silent_cli_error(format!("export buffer flush failed: {io_err}"))
        })?;
    }

    // 3. fsync the file — data + metadata to persistent storage.
    temp.as_file().sync_all().map_err(|e| {
        eprint!(
            "{}",
            error_block(
                "export_write_failed",
                &format!("fsync failed: {e}"),
                "check disk space and filesystem health",
                None,
            )
        );
        silent_cli_error(format!("export fsync failed: {e}"))
    })?;

    // 4. Atomic rename. `persist_noclobber` fails with
    //    `PersistError` if `dest` exists (NFS-safe atomic-create-
    //    or-fail via `link(2)`+unlink on macOS, `renameat2
    //    (RENAME_NOREPLACE)` on recent Linux). `persist` replaces
    //    atomically when `--force` was set.
    if force {
        temp.persist(dest).map_err(|persist_err| {
            let io_err = persist_err.error;
            eprint!(
                "{}",
                error_block(
                    "export_write_failed",
                    &format!("failed to rename temp file onto {}: {io_err}", dest.display()),
                    "check parent directory permissions and free space",
                    None,
                )
            );
            silent_cli_error(format!("persist failed for {}: {io_err}", dest.display()))
        })?;
    } else {
        temp.persist_noclobber(dest).map_err(|persist_err| {
            let io_err = persist_err.error;
            if io_err.kind() == io::ErrorKind::AlreadyExists {
                // Concurrent writer created `dest` between our
                // advisory validation and this atomic rename. Use
                // the same error code as the validation layer so
                // the operator sees a consistent message regardless
                // of where the race was caught.
                eprint!(
                    "{}",
                    error_block(
                        "export_destination_exists",
                        &format!("file already exists: {}", dest.display()),
                        "use --force to overwrite, or choose a different path",
                        None,
                    )
                );
                silent_cli_error(format!(
                    "export destination created concurrently: {}",
                    dest.display()
                ))
            } else {
                eprint!(
                    "{}",
                    error_block(
                        "export_write_failed",
                        &format!("failed to atomically create {}: {io_err}", dest.display()),
                        "check parent directory permissions and free space",
                        None,
                    )
                );
                silent_cli_error(format!(
                    "persist_noclobber failed for {}: {io_err}",
                    dest.display()
                ))
            }
        })?;
    }

    // 5. fsync the parent directory so the rename itself is durable.
    //    A power failure between the rename (step 4) and writeback
    //    can lose the new directory entry on ext4/`data=ordered`,
    //    XFS, and similar. Windows' MoveFileEx is transactional —
    //    no parent fsync needed. Best-effort on Unix: a failure
    //    here means the data reached disk but the directory entry
    //    might not have, so we surface it rather than lying about
    //    durability.
    #[cfg(unix)]
    fsync_parent_dir(parent).map_err(|e| {
        eprint!(
            "{}",
            error_block(
                "export_write_failed",
                &format!("parent-directory fsync failed: {e}"),
                "check disk space and filesystem health",
                None,
            )
        );
        silent_cli_error(format!("parent dir fsync failed for {}: {e}", parent.display()))
    })?;

    // Log the overwrite AFTER it actually happened (M12 fix).
    if force {
        tracing::info!(
            path = %dest.display(),
            "overwrote existing export file (--force)"
        );
    }

    // 6. Measure the final destination file size. Using
    //    `dest.metadata()` (not `temp.as_file().metadata()`) reads
    //    from the post-persist path, which is what the operator
    //    will see via `ls -l`. Fail loudly on metadata error rather
    //    than silently reporting `0 B`.
    let bytes = dest.metadata().map(|m| m.len()).map_err(|e| {
        eprint!(
            "{}",
            error_block(
                "export_write_failed",
                &format!("failed to read {} metadata after write: {e}", dest.display()),
                "check file permissions; the write itself succeeded",
                None,
            )
        );
        silent_cli_error(format!("metadata read failed for persisted {}: {e}", dest.display()))
    })?;

    Ok(bytes)
}

/// fsync a directory (Unix only) to make a prior `rename` durable.
#[cfg(unix)]
fn fsync_parent_dir(parent: &Path) -> io::Result<()> {
    let dir = File::open(parent)?;
    dir.sync_all()
}

// ────────────────────────────────────────────────────────────────
// Serializers — thin closures that write into the BufWriter handed
// out by `persist_atomic`. They do NOT flush or fsync; `persist_
// atomic` owns the drop-flush + fsync + persist contract.
// ────────────────────────────────────────────────────────────────

/// Serialize `events` into `writer` as a pretty-printed JSON array
/// followed by a trailing newline.
fn serialize_json(events: &[AuditEvent], writer: &mut dyn Write) -> anyhow::Result<()> {
    serde_json::to_writer_pretty(&mut *writer, events).map_err(|e| {
        eprint!(
            "{}",
            error_block(
                "export_write_failed",
                &format!("failed to serialize events to JSON: {e}"),
                "report this bug",
                None,
            )
        );
        silent_cli_error(format!("json serialize failed: {e}"))
    })?;
    writer.write_all(b"\n").map_err(|e| {
        eprint!(
            "{}",
            error_block(
                "export_write_failed",
                &format!("failed to write trailing newline: {e}"),
                "check disk space",
                None,
            )
        );
        silent_cli_error(format!("json trailing newline failed: {e}"))
    })?;
    Ok(())
}

/// CSV column names in the order they are written to the header row.
///
/// `extra_json` maps to `AuditEvent::extra` (a `serde_json::Value`).
/// The schema-drift test `audit_csv_columns_match_audit_event_fields`
/// asserts this constant stays in sync with the `AuditEvent` struct.
pub(crate) const AUDIT_CSV_COLUMNS: &[&str] = &[
    "timestamp",
    "request_id",
    "agent_id",
    "service",
    "scope",
    "resource",
    "outcome",
    "event_type",
    "schema_version",
    "extra_json",
];

/// Serialize `events` into `writer` as RFC 4180 CSV with a 10-column
/// header and CRLF row terminators.
///
/// Columns (in order): `timestamp`, `request_id`, `agent_id`,
/// `service`, `scope`, `resource`, `outcome`, `event_type`,
/// `schema_version`, `extra_json`. The `extra_json` column
/// serializes `event.extra` (a `serde_json::Value`) via
/// `serde_json::to_string` — null extras render as the literal
/// string `null`. The `csv` crate handles RFC 4180 quoting of
/// commas / quotes / line breaks automatically.
fn serialize_csv(events: &[AuditEvent], writer: &mut dyn Write) -> anyhow::Result<()> {
    let mut csv_writer = csv::WriterBuilder::new()
        .terminator(csv::Terminator::CRLF)
        .has_headers(false) // we write headers manually to pin order
        .from_writer(writer);

    csv_writer.write_record(AUDIT_CSV_COLUMNS).map_err(|e| {
        eprint!(
            "{}",
            error_block(
                "export_write_failed",
                &format!("failed to write CSV header: {e}"),
                "check disk space",
                None,
            )
        );
        silent_cli_error(format!("csv header write failed: {e}"))
    })?;

    for event in events {
        let schema_ver = event.schema_version.to_string();
        // `serde_json::to_string` on `serde_json::Value` is
        // infallible in practice — `Value`'s `Serialize` impl never
        // returns an error. A `debug_assert!` locks the invariant:
        // if a future change swaps `extra`'s type to something
        // fallible, debug builds + CI trip on the first row. In
        // release we fall back to the JSON literal `null`, which
        // round-trips through `serde_json::from_str` and keeps the
        // CSV column valid — better than emitting the empty string
        // or panicking mid-export.
        let extra_json = match serde_json::to_string(&event.extra) {
            Ok(s) => s,
            Err(e) => {
                debug_assert!(false, "serde_json::Value serialization should be infallible: {e}");
                tracing::error!(error = %e, "unexpected serialization failure on event.extra");
                "null".to_owned()
            }
        };

        csv_writer
            .write_record([
                &event.timestamp,
                &event.request_id,
                &event.agent_id,
                &event.service,
                &event.scope,
                &event.resource,
                &event.outcome,
                &event.event_type,
                &schema_ver,
                &extra_json,
            ])
            .map_err(|e| {
                eprint!(
                    "{}",
                    error_block(
                        "export_write_failed",
                        &format!("failed to write CSV row: {e}"),
                        "check disk space",
                        None,
                    )
                );
                silent_cli_error(format!("csv row write failed: {e}"))
            })?;
    }

    // Drop the csv writer so its inner BufWriter wrapping is
    // consumed and any remaining bytes flush into the underlying
    // writer. `into_inner` would also work; both paths go through
    // `persist_atomic`'s `BufWriter::into_inner` which catches
    // flush errors.
    csv_writer.flush().map_err(|e| {
        eprint!(
            "{}",
            error_block(
                "export_write_failed",
                &format!("failed to flush CSV buffer: {e}"),
                "check disk space",
                None,
            )
        );
        silent_cli_error(format!("csv flush failed: {e}"))
    })?;
    Ok(())
}

/// Print the success summary line to stdout.
///
/// Format: `  exported {N} events → {path} ({size})`
/// - 2-space leading indent (matches `AuditFooter` convention)
/// - `format_count` thousand-separators (UX-DR18)
/// - U+2192 Rightwards Arrow (single char, not `->`)
/// - `format_bytes` KB/MB/GB units (matches `design/format.rs`;
///   NOT IEC's KiB/MiB — UX spec choice)
/// - Trailing newline
fn print_summary(count: u64, path: &Path, bytes: u64) {
    println!(
        "  exported {} events \u{2192} {} ({})",
        format_count(count),
        path.display(),
        format_bytes(bytes),
    );
}

// ──────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use permitlayer_core::audit::event::AuditEvent;

    // ----- resolve_format -----

    #[test]
    fn resolve_format_json_extension() {
        let fmt = resolve_format(Path::new("out.json"), None).unwrap();
        assert_eq!(fmt, ExportFormat::Json);
    }

    #[test]
    fn resolve_format_csv_extension() {
        let fmt = resolve_format(Path::new("out.csv"), None).unwrap();
        assert_eq!(fmt, ExportFormat::Csv);
    }

    #[test]
    fn resolve_format_uppercase_json_extension() {
        let fmt = resolve_format(Path::new("OUT.JSON"), None).unwrap();
        assert_eq!(fmt, ExportFormat::Json);
    }

    #[test]
    fn resolve_format_mixed_case_csv_extension() {
        let fmt = resolve_format(Path::new("Out.Csv"), None).unwrap();
        assert_eq!(fmt, ExportFormat::Csv);
    }

    #[test]
    fn resolve_format_override_wins_over_extension() {
        // Extension says .json, but override says csv — override wins.
        let fmt = resolve_format(Path::new("incident.json"), Some("csv")).unwrap();
        assert_eq!(fmt, ExportFormat::Csv);
    }

    #[test]
    fn resolve_format_override_case_insensitive() {
        let fmt = resolve_format(Path::new("x.json"), Some("CSV")).unwrap();
        assert_eq!(fmt, ExportFormat::Csv);
    }

    #[test]
    fn resolve_format_unknown_extension_without_override_errors() {
        let err = resolve_format(Path::new("incident.log"), None).unwrap_err();
        assert!(err.chain().any(|s| s.is::<crate::cli::SilentCliError>()));
    }

    #[test]
    fn resolve_format_no_extension_without_override_errors() {
        let err = resolve_format(Path::new("incident"), None).unwrap_err();
        assert!(err.chain().any(|s| s.is::<crate::cli::SilentCliError>()));
    }

    #[test]
    fn resolve_format_invalid_override_errors() {
        let err = resolve_format(Path::new("out.json"), Some("xml")).unwrap_err();
        assert!(err.chain().any(|s| s.is::<crate::cli::SilentCliError>()));
    }

    // ----- validate_destination -----

    #[test]
    fn validate_destination_missing_parent_errors() {
        let dest = Path::new("/definitely-does-not-exist/deeper/still/out.json");
        let err = validate_destination(dest, false).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("parent directory missing") || msg.contains("export parent"),
            "expected parent-missing error, got: {msg}"
        );
    }

    #[test]
    fn validate_destination_existing_file_without_force_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.json");
        std::fs::write(&dest, b"pre-existing").unwrap();
        let err = validate_destination(&dest, false).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("exists without --force") || msg.contains("destination"),
            "expected destination-exists error, got: {msg}"
        );
    }

    #[test]
    fn validate_destination_existing_file_with_force_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.json");
        std::fs::write(&dest, b"old").unwrap();
        // force=true should allow overwrite.
        validate_destination(&dest, true).unwrap();
    }

    #[test]
    fn validate_destination_fresh_path_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("fresh.json");
        validate_destination(&dest, false).unwrap();
    }

    #[test]
    fn validate_destination_directory_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let dir_as_dest = tmp.path().to_path_buf();
        let err = validate_destination(&dir_as_dest, true).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("directory") || msg.contains("destination is a directory"),
            "expected directory error, got: {msg}"
        );
    }

    /// M1 — Parent-not-writable probe via `chmod 0o500` fires
    /// `export_parent_not_writable`. Unix-only.
    #[cfg(unix)]
    #[test]
    fn validate_destination_parent_not_writable_errors() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path();
        // chmod 0o500 — read+execute but NOT write for the owner.
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o500)).unwrap();

        let dest = parent.join("out.json");
        let err = validate_destination(&dest, false).unwrap_err();
        let msg = format!("{err:#}");

        // Restore permissions so tempdir cleanup works.
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            msg.contains("export parent not writable") || msg.contains("parent not writable"),
            "expected parent-not-writable error, got: {msg}"
        );
    }

    /// M8 — Broken-symlink destination without --force is rejected
    /// (would be replaced, not followed). Unix-only.
    #[cfg(unix)]
    #[test]
    fn validate_destination_broken_symlink_without_force_errors() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.json");
        symlink("/nonexistent-target-for-test", &dest).unwrap();
        let err = validate_destination(&dest, false).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("symlink") || msg.contains("destination"),
            "expected symlink error, got: {msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn validate_destination_broken_symlink_with_force_succeeds() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.json");
        symlink("/nonexistent-target-for-test", &dest).unwrap();
        // --force should accept replacing the symlink.
        validate_destination(&dest, true).unwrap();
    }

    /// Probe path cleanliness: `validate_destination` must not
    /// leave any sibling artifacts in the parent directory on Unix
    /// (access(2) is side-effect-free).
    #[cfg(unix)]
    #[test]
    fn validate_destination_leaves_no_sibling_on_unix() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("fresh.json");
        validate_destination(&dest, false).unwrap();

        let entries: Vec<String> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(entries.is_empty(), "probe should not leave any siblings; found: {entries:?}");
    }

    // ----- persist_atomic (integration-level — exercises write
    // contract via the closure-based API) -----

    fn event_for_test(service: &str, outcome: &str, event_type: &str) -> AuditEvent {
        AuditEvent::new(
            "test-agent".into(),
            service.into(),
            "mail.readonly".into(),
            "messages/1".into(),
            outcome.into(),
            event_type.into(),
        )
    }

    fn write_json(events: &[AuditEvent], dest: &Path, force: bool) -> anyhow::Result<u64> {
        persist_atomic(dest, force, |w| serialize_json(events, w))
    }

    fn write_csv(events: &[AuditEvent], dest: &Path, force: bool) -> anyhow::Result<u64> {
        persist_atomic(dest, force, |w| serialize_csv(events, w))
    }

    #[test]
    fn json_writes_valid_array_of_events() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.json");
        let events = vec![
            event_for_test("gmail", "ok", "api-call"),
            event_for_test("calendar", "denied", "policy-violation"),
            event_for_test("drive", "scrubbed", "api-call"),
        ];
        let bytes = write_json(&events, &dest, false).unwrap();
        assert!(bytes > 0);

        let content = std::fs::read_to_string(&dest).unwrap();
        assert!(content.starts_with("[\n"));
        assert!(content.ends_with("]\n"));
        let parsed: Vec<AuditEvent> = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].service, "gmail");
        assert_eq!(parsed[1].outcome, "denied");
        assert_eq!(parsed[2].event_type, "api-call");
    }

    #[test]
    fn json_preserves_non_null_extra() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.json");
        let mut event = event_for_test("gmail", "ok", "api-call");
        event.extra = serde_json::json!({"policy_id": "p-123", "count": 42});
        let events = vec![event];
        write_json(&events, &dest, false).unwrap();

        let parsed: Vec<AuditEvent> =
            serde_json::from_str(&std::fs::read_to_string(&dest).unwrap()).unwrap();
        assert_eq!(parsed[0].extra["policy_id"], "p-123");
        assert_eq!(parsed[0].extra["count"], 42);
    }

    #[test]
    fn json_elides_null_extra() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.json");
        let event = event_for_test("gmail", "ok", "api-call");
        assert!(event.extra.is_null());
        write_json(&[event], &dest, false).unwrap();

        // M10 — parse the JSON and check for the absence of the
        // `extra` key at the object level, not a substring match.
        let parsed: Vec<serde_json::Value> =
            serde_json::from_str(&std::fs::read_to_string(&dest).unwrap()).unwrap();
        assert_eq!(parsed.len(), 1);
        let obj = parsed[0].as_object().expect("event is an object");
        assert!(!obj.contains_key("extra"), "null extra should be elided from object: {obj:?}");
    }

    #[test]
    fn json_empty_events_writes_empty_array() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.json");
        let bytes = write_json(&[], &dest, false).unwrap();
        let content = std::fs::read_to_string(&dest).unwrap();
        assert_eq!(content, "[]\n", "empty input should produce [] + newline");
        assert_eq!(bytes, 3, "expected 3 bytes (`[`, `]`, `\\n`); got {bytes}");
    }

    #[test]
    fn json_overwrites_existing_with_force() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.json");
        std::fs::write(&dest, b"old content").unwrap();
        write_json(&[event_for_test("gmail", "ok", "api-call")], &dest, true).unwrap();

        let content = std::fs::read_to_string(&dest).unwrap();
        assert!(content.starts_with("[\n"), "expected JSON array after overwrite, got: {content}");
        assert!(!content.contains("old content"));
    }

    /// D1 (Option D) — `persist_noclobber` fails atomically when
    /// `dest` exists and `--force` is not set. This is the primary
    /// write-contract defense against the TOCTOU race between
    /// `validate_destination` and `persist`. Proof that correctness
    /// does not rely on validation alone: we bypass validate entirely
    /// here and write directly via `persist_atomic(force=false)` to
    /// a pre-existing file.
    #[test]
    fn persist_atomic_noclobber_fails_on_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.json");
        std::fs::write(&dest, b"pre-existing content that must survive").unwrap();

        let err =
            write_json(&[event_for_test("gmail", "ok", "api-call")], &dest, false).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("export destination created concurrently") || msg.contains("destination"),
            "expected no-clobber error, got: {msg}"
        );

        // The original content must survive — no silent overwrite.
        let content = std::fs::read_to_string(&dest).unwrap();
        assert_eq!(content, "pre-existing content that must survive");
    }

    #[test]
    fn json_no_temp_file_sibling_on_success() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.json");
        write_json(&[event_for_test("gmail", "ok", "api-call")], &dest, false).unwrap();

        // M10 — exact-match assertion rather than substring filter.
        let entries: Vec<String> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(entries, vec!["out.json".to_owned()]);
    }

    /// H6 — atomicity failure-path test: when write-time I/O fails,
    /// the destination does not exist and no temp siblings remain.
    /// Uses chmod 0o500 on the parent directory AFTER validate_
    /// destination would have succeeded (we skip validate and go
    /// straight to persist_atomic to exercise the failure).
    #[cfg(unix)]
    #[test]
    fn json_temp_file_cleaned_on_io_error() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path();
        let dest = parent.join("out.json");

        // Remove write permission on the parent AFTER we've set up
        // the scenario — this simulates a chmod-during-write.
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o500)).unwrap();

        let result = write_json(&[event_for_test("gmail", "ok", "api-call")], &dest, false);

        // Restore permissions so tempdir cleanup succeeds.
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Write must have failed.
        assert!(result.is_err(), "expected write failure when parent is read-only");

        // Destination must not exist (no partial artifact).
        assert!(!dest.exists(), "destination should not exist after failed write");

        // No temp-file siblings may remain.
        let entries: Vec<String> = std::fs::read_dir(parent)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(
            entries.iter().all(|n| !n.starts_with(".tmp")),
            "no temp siblings should remain after failure; got: {entries:?}"
        );
    }

    // ----- serialize_csv -----

    #[test]
    fn csv_writes_header_plus_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.csv");
        let events = vec![
            event_for_test("gmail", "ok", "api-call"),
            event_for_test("calendar", "denied", "policy-violation"),
        ];
        write_csv(&events, &dest, false).unwrap();

        let content = std::fs::read(&dest).unwrap();
        let as_str = String::from_utf8(content).unwrap();
        assert!(as_str.starts_with("timestamp,request_id,agent_id,service,scope,resource,outcome,event_type,schema_version,extra_json\r\n"));
        assert_eq!(as_str.matches("\r\n").count(), 3, "1 header + 2 data rows = 3 CRLF");
        assert!(as_str.ends_with("\r\n"));
    }

    #[test]
    fn csv_quotes_fields_with_commas() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.csv");
        let mut event = event_for_test("gmail", "ok", "api-call");
        event.resource = "msg,with,comma".to_owned();
        write_csv(&[event], &dest, false).unwrap();

        let content = std::fs::read_to_string(&dest).unwrap();
        assert!(content.contains("\"msg,with,comma\""), "expected quoted field: {content}");
    }

    #[test]
    fn csv_escapes_embedded_double_quotes() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.csv");
        let mut event = event_for_test("gmail", "ok", "api-call");
        event.agent_id = r#"he said "hi""#.to_owned();
        write_csv(&[event], &dest, false).unwrap();

        let content = std::fs::read_to_string(&dest).unwrap();
        assert!(
            content.contains(r#""he said ""hi""""#),
            "expected RFC 4180 escaped quotes: {content}"
        );
    }

    #[test]
    fn csv_extra_json_column_null_for_null_extra() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.csv");
        let event = event_for_test("gmail", "ok", "api-call");
        assert!(event.extra.is_null());
        write_csv(&[event], &dest, false).unwrap();

        let content = std::fs::read_to_string(&dest).unwrap();
        assert!(content.ends_with(",null\r\n"), "expected null literal in extra column: {content}");
    }

    #[test]
    fn csv_extra_json_column_serializes_non_null_extra() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.csv");
        let mut event = event_for_test("gmail", "ok", "api-call");
        event.extra = serde_json::json!({"k": "v"});
        write_csv(&[event], &dest, false).unwrap();

        let content = std::fs::read_to_string(&dest).unwrap();
        // L4 — rewritten comment: the `csv` crate quotes this field
        // because the serialized JSON (`{"k":"v"}`) contains `"`
        // characters. Commas are absent in this specific test input.
        assert!(
            content.contains(r#""{""k"":""v""}""#),
            "expected quoted-and-escaped extra_json column: {content}"
        );
    }

    #[test]
    fn csv_empty_events_writes_header_only() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.csv");
        let bytes = write_csv(&[], &dest, false).unwrap();

        let content = std::fs::read_to_string(&dest).unwrap();
        assert_eq!(
            content,
            "timestamp,request_id,agent_id,service,scope,resource,outcome,event_type,schema_version,extra_json\r\n"
        );
        // L5 — the exact on-disk byte count matches the string
        // length (no hidden padding / BOM). Actual byte count is
        // 99: 9 + 1 + 10 + 1 + 8 + 1 + 7 + 1 + 5 + 1 + 8 + 1 + 7 +
        // 1 + 10 + 1 + 14 + 1 + 10 + 2 = 99.
        assert_eq!(bytes, content.len() as u64);
        assert_eq!(bytes, 99);
    }

    #[test]
    fn csv_roundtrips_via_csv_reader() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.csv");
        let mut event = event_for_test("gmail", "ok", "api-call");
        event.resource = "msg,with,comma".to_owned();
        event.agent_id = r#"quoted "name""#.to_owned();
        write_csv(&[event.clone()], &dest, false).unwrap();

        let mut reader = csv::ReaderBuilder::new().has_headers(true).from_path(&dest).unwrap();
        let headers = reader.headers().unwrap().clone();
        assert_eq!(&headers[0], "timestamp");
        assert_eq!(&headers[9], "extra_json");

        let records: Vec<csv::StringRecord> = reader.records().map(|r| r.unwrap()).collect();
        assert_eq!(records.len(), 1);
        let row = &records[0];
        assert_eq!(&row[2], r#"quoted "name""#, "agent_id round-trip");
        assert_eq!(&row[5], "msg,with,comma", "resource round-trip");
        assert_eq!(&row[3], "gmail", "service round-trip");
        assert_eq!(&row[6], "ok", "outcome round-trip");
    }

    #[test]
    fn csv_overwrites_existing_with_force() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.csv");
        std::fs::write(&dest, b"old,content\r\n").unwrap();
        write_csv(&[event_for_test("gmail", "ok", "api-call")], &dest, true).unwrap();

        let content = std::fs::read_to_string(&dest).unwrap();
        assert!(content.starts_with("timestamp,"), "expected CSV header after overwrite");
        assert!(!content.contains("old,content"));
    }

    // ----- print_summary smoke test -----

    #[test]
    fn summary_prints_without_panic() {
        let path = Path::new("test.json");
        print_summary(412, path, 187 * 1024);
    }

    // ----- Invariant tests -----

    /// AC #11: the export module must NOT re-scrub at read time.
    /// Story 2.4 scrub-before-log invariant. Forbidden literals
    /// built via `concat!` so the assertion source itself doesn't
    /// match.
    #[test]
    fn audit_export_module_does_not_import_scrub_engine() {
        let src = include_str!("audit_export.rs");
        let forbidden_crate = concat!("use crate::scr", "ub::Scrub", "Engine");
        let forbidden_core = concat!("use permitlayer_core::scr", "ub::Scrub", "Engine");
        let forbidden_call = concat!("Scrub", "Engine::scrub");
        assert!(
            !src.contains(forbidden_crate),
            "audit_export must NOT import the scrub engine from crate::scrub"
        );
        assert!(
            !src.contains(forbidden_core),
            "audit_export must NOT import the scrub engine from permitlayer_core::scrub"
        );
        assert!(!src.contains(forbidden_call), "audit_export must NOT invoke scrub at read time");
    }

    /// AC #12: blocking work is wrapped in `spawn_blocking`.
    #[test]
    fn spawn_blocking_is_used_in_export_path() {
        let src = include_str!("audit_export.rs");
        let count = src.matches("spawn_blocking").count();
        assert!(count >= 1, "export path must wrap AuditReader::query + write in spawn_blocking");
    }

    /// M2 — fsync-before-persist ordering is preserved. Grep-assert
    /// that `sync_all` appears in the source before `persist(` (for
    /// the force path) and `persist_noclobber(` (for the no-force
    /// path). Prevents a regression that reorders the write contract.
    #[test]
    fn write_fsyncs_before_persist() {
        let src = include_str!("audit_export.rs");
        let sync_pos = src.find(".sync_all()").expect("sync_all must be called in persist_atomic");
        let persist_pos = src.find(".persist(").expect("persist must be called in persist_atomic");
        let noclobber_pos = src
            .find(".persist_noclobber(")
            .expect("persist_noclobber must be called in persist_atomic");
        assert!(
            sync_pos < persist_pos,
            "sync_all must come before persist in source order (fsync before rename)"
        );
        assert!(
            sync_pos < noclobber_pos,
            "sync_all must come before persist_noclobber in source order"
        );
    }

    /// Story 5.3 correctness-refactor invariant: the no-force write
    /// path MUST call `persist_noclobber`, not `persist`. This is
    /// the structural fix that honors AC #7's TOCTOU-defense
    /// mandate without relying on the advisory `validate_destination`
    /// check.
    #[test]
    fn no_force_path_uses_persist_noclobber() {
        let src = include_str!("audit_export.rs");
        assert!(
            src.contains(".persist_noclobber("),
            "non-force write path must use persist_noclobber for TOCTOU defense"
        );
    }

    /// The parent-directory fsync closes the durability window
    /// between `rename` and writeback on ext4/XFS under
    /// `data=ordered`. Unix-only (Windows `MoveFileEx` is
    /// transactional).
    #[test]
    fn parent_dir_fsync_invoked_on_unix() {
        let src = include_str!("audit_export.rs");
        assert!(
            src.contains("fsync_parent_dir"),
            "parent-directory fsync must be called after persist"
        );
    }

    // ----- Story 8.4 AC #12: resolve_export_parent (export_parent) edge case -----

    #[test]
    fn resolve_export_parent_returns_cwd_for_rootless_path() {
        // A path with no parent component (bare filename) should return ".".
        let bare = Path::new("output.json");
        let parent = export_parent(bare);
        assert_eq!(parent, Path::new("."), "bare filename must resolve to current directory");
    }

    #[test]
    fn resolve_export_parent_returns_actual_parent_for_nested_path() {
        let nested = Path::new("/tmp/audit/output.json");
        let parent = export_parent(nested);
        assert_eq!(parent, Path::new("/tmp/audit"));
    }

    // ----- schema-drift guard (AC #9 — Story 8.5) -----

    #[test]
    fn audit_csv_columns_match_audit_event_fields() {
        // Guard 1: column count stays at 10.
        assert_eq!(
            AUDIT_CSV_COLUMNS.len(),
            10,
            "AUDIT_CSV_COLUMNS must have exactly 10 entries — one per AuditEvent field"
        );

        // Guard 2: every named AuditEvent field appears in the column list.
        // `extra_json` is the CSV alias for `AuditEvent::extra`. Because `extra` has
        // `skip_serializing_if = "is_null"`, we populate it with a non-null value so
        // it appears in the serialized keys and can be asserted below.
        let mut event = AuditEvent::new(
            "agent".to_owned(),
            "gmail".to_owned(),
            "gmail.readonly".to_owned(),
            "*".to_owned(),
            "ok".to_owned(),
            "api-call".to_owned(),
        );
        event.extra = serde_json::json!({"sentinel": true});

        let json_val = serde_json::to_value(&event).expect("AuditEvent must serialize");
        let json_keys: std::collections::HashSet<&str> = json_val
            .as_object()
            .expect("AuditEvent serializes to a JSON object")
            .keys()
            .map(String::as_str)
            .collect();

        // Guard 3: reverse direction — every AuditEvent JSON key maps to a CSV column.
        // `extra` in JSON → `extra_json` in the column list; account for that alias.
        // This catches a new field added to AuditEvent without a matching column addition.
        let csv_keys_normalized: std::collections::HashSet<&str> = AUDIT_CSV_COLUMNS
            .iter()
            .map(|col| if *col == "extra_json" { "extra" } else { col })
            .collect();
        for key in &json_keys {
            assert!(
                csv_keys_normalized.contains(key),
                "AuditEvent JSON key '{key}' has no corresponding column in AUDIT_CSV_COLUMNS; \
                 did you add a field to AuditEvent without adding a CSV column?"
            );
        }

        // Every column name must match a JSON key — except `extra_json` which maps to `extra`.
        for col in AUDIT_CSV_COLUMNS {
            let expected_key = if *col == "extra_json" { "extra" } else { col };
            assert!(
                json_keys.contains(expected_key),
                "CSV column '{col}' maps to JSON key '{expected_key}' but that key is not present \
                 in the serialized AuditEvent; did you add a field to AuditEvent without updating \
                 AUDIT_CSV_COLUMNS?"
            );
        }
    }
}
