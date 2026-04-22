//! Append-only JSONL audit log writer with date/size-based rotation.
//!
//! Every audit event is scrubbed before serialization (scrub-before-log
//! invariant). The writer holds an `Arc<ScrubEngine>` shared with the
//! proxy response path.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::audit::event::AuditEvent;
use crate::scrub::ScrubEngine;
use crate::store::error::StoreError;

/// Manages append-only JSONL audit log files with rotation.
///
/// All string fields of every [`AuditEvent`] are scrubbed through
/// [`ScrubEngine::scrub()`] before JSONL serialization.
pub struct AuditFsWriter {
    audit_dir: PathBuf,
    /// Size threshold for rotation (default 100MB).
    max_file_bytes: u64,
    /// Currently open file handle + its date string + current size.
    current: Option<OpenFileState>,
    /// Shared scrub engine for scrub-before-log invariant.
    scrub_engine: Arc<ScrubEngine>,
    /// Story 8.2 F39: cached per-date last-used rotation suffix, so
    /// back-to-back rotations during an incident don't re-scan the
    /// whole audit directory. `None` = no rotation has happened for
    /// the current date yet; on the first rotation we scan the
    /// directory once and seed this cache.
    last_rotation: Option<(String, u64)>,
}

struct OpenFileState {
    file: File,
    date: String,
    path: PathBuf,
    bytes_written: u64,
}

impl AuditFsWriter {
    /// Minimum allowed value for `max_file_bytes` to prevent degenerate
    /// rotation (every append triggers a rename).
    const MIN_MAX_FILE_BYTES: u64 = 1024;

    /// Create a new writer. Creates `audit_dir` with `0o700` permissions
    /// if it doesn't exist. `max_file_bytes` is clamped to at least 1024.
    pub fn new(
        audit_dir: PathBuf,
        max_file_bytes: u64,
        scrub_engine: Arc<ScrubEngine>,
    ) -> Result<Self, StoreError> {
        create_audit_dir(&audit_dir)?;
        Ok(Self {
            audit_dir,
            max_file_bytes: max_file_bytes.max(Self::MIN_MAX_FILE_BYTES),
            current: None,
            scrub_engine,
            last_rotation: None,
        })
    }

    /// Scrub sensitive content from audit event fields before serialization.
    ///
    /// Clones the event and scrubs user-facing string fields. System-generated
    /// fields (`timestamp`, `request_id`, `schema_version`) are not scrubbed.
    fn scrub_event(&self, event: &AuditEvent) -> AuditEvent {
        let scrub = |s: &str| -> String { self.scrub_engine.scrub(s).output };

        let extra = if event.extra.is_null() {
            serde_json::Value::Null
        } else {
            match serde_json::to_string(&event.extra) {
                Ok(json_str) => {
                    let scrubbed_str = self.scrub_engine.scrub(&json_str).output;
                    match serde_json::from_str(&scrubbed_str) {
                        Ok(val) => val,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "scrubbed extra field produced invalid JSON, using original"
                            );
                            event.extra.clone()
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "failed to serialize extra field for scrubbing, using original"
                    );
                    event.extra.clone()
                }
            }
        };

        AuditEvent {
            timestamp: event.timestamp.clone(),
            request_id: event.request_id.clone(),
            agent_id: scrub(&event.agent_id),
            service: scrub(&event.service),
            scope: scrub(&event.scope),
            resource: scrub(&event.resource),
            outcome: scrub(&event.outcome),
            event_type: scrub(&event.event_type),
            schema_version: event.schema_version,
            extra,
        }
    }

    /// Append an audit event as a single JSONL line with fsync.
    ///
    /// All string fields are scrubbed before serialization (scrub-before-log invariant).
    pub fn append(&mut self, event: &AuditEvent) -> Result<(), StoreError> {
        self.append_at(chrono::Utc::now(), event)
    }

    /// Append an audit event using the provided `now` snapshot for all
    /// date-routing decisions (Story 8.2 F14 fix).
    ///
    /// Pre-Story-8.2 `append()` read `chrono::Utc::now()` at the top of
    /// the function AND again inside `open_file_for_date` / rotation
    /// logic. At midnight the two reads could land on different dates,
    /// routing the event into the wrong file. This helper takes `now`
    /// as an argument so the test suite can inject a deterministic
    /// snapshot via `append_at(fake_now, event)`. `append()` above is
    /// the thin public wrapper that threads `Utc::now()` through.
    ///
    /// All string fields are scrubbed before serialization (scrub-before-log invariant).
    pub(crate) fn append_at(
        &mut self,
        now: DateTime<Utc>,
        event: &AuditEvent,
    ) -> Result<(), StoreError> {
        let today = now.format("%Y-%m-%d").to_string();

        // Check if we need a new file (no file open, date changed, or size exceeded).
        let needs_new_file = match &self.current {
            None => true,
            Some(state) => state.date != today,
        };

        if needs_new_file {
            self.current = None; // Close previous file by dropping it.
            self.open_file_for_date(&today)?;
        }

        // Check size-based rotation (must happen after date check).
        if let Some(state) = &self.current
            && state.bytes_written >= self.max_file_bytes
        {
            self.rotate_current_file()?;
        }

        // Scrub all string fields before serialization (scrub-before-log invariant).
        let scrubbed = self.scrub_event(event);

        // Serialize and write.
        let json_line =
            serde_json::to_string(&scrubbed).map_err(|e| StoreError::AuditWriteFailed {
                reason: "JSON serialization failed".into(),
                source: Some(Box::new(e)),
            })?;

        let line = format!("{json_line}\n");
        let line_bytes = line.as_bytes();

        let state = self.current.as_mut().ok_or_else(|| StoreError::AuditWriteFailed {
            reason: "no open audit file".into(),
            source: None,
        })?;

        state.file.write_all(line_bytes).map_err(|e| StoreError::AuditWriteFailed {
            reason: format!("write to {} failed", state.path.display()),
            source: Some(Box::new(e)),
        })?;

        state.file.sync_all().map_err(|e| StoreError::AuditWriteFailed {
            reason: format!("fsync on {} failed", state.path.display()),
            source: Some(Box::new(e)),
        })?;

        state.bytes_written += line_bytes.len() as u64;

        Ok(())
    }

    /// Scan `audit_dir` for files older than `retention_days` and delete them.
    /// Returns the count of deleted files. Skips the currently-open file and
    /// continues past individual delete failures (logging each).
    pub fn sweep_retention(&self, retention_days: u32) -> Result<u32, StoreError> {
        let cutoff =
            chrono::Utc::now().date_naive() - chrono::Duration::days(i64::from(retention_days));
        let mut deleted = 0u32;

        // Path of the currently-open file, if any — skip it during sweep.
        let current_path = self.current.as_ref().map(|s| s.path.clone());

        let entries =
            std::fs::read_dir(&self.audit_dir).map_err(|e| StoreError::AuditWriteFailed {
                reason: format!("failed to read audit directory {}", self.audit_dir.display()),
                source: Some(Box::new(e)),
            })?;

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(error = %e, "skipping unreadable directory entry during retention sweep");
                    continue;
                }
            };

            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if !name_str.ends_with(".jsonl") {
                continue;
            }

            // Parse date from first 10 characters: YYYY-MM-DD
            if name_str.len() < 10 {
                continue;
            }
            let date_str = &name_str[..10];
            let Ok(file_date) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") else {
                continue;
            };

            if file_date < cutoff {
                let path = entry.path();

                // Never delete the file the writer currently has open.
                if current_path.as_ref() == Some(&path) {
                    tracing::warn!(path = %path.display(), "skipping currently-open audit file during retention sweep");
                    continue;
                }

                tracing::info!(path = %path.display(), date = %file_date, "deleting expired audit file");
                if let Err(e) = std::fs::remove_file(&path) {
                    tracing::warn!(path = %path.display(), error = %e, "failed to delete expired audit file, skipping");
                    continue;
                }
                deleted += 1;
            }
        }

        Ok(deleted)
    }

    fn open_file_for_date(&mut self, date: &str) -> Result<(), StoreError> {
        let path = self.audit_dir.join(format!("{date}.jsonl"));

        let file = open_append_file(&path)?;

        // Get current file size for accurate byte tracking.
        let metadata = file.metadata().map_err(|e| StoreError::AuditWriteFailed {
            reason: format!("failed to stat {}", path.display()),
            source: Some(Box::new(e)),
        })?;

        self.current = Some(OpenFileState {
            file,
            date: date.to_owned(),
            path,
            bytes_written: metadata.len(),
        });

        Ok(())
    }

    fn rotate_current_file(&mut self) -> Result<(), StoreError> {
        // Take ownership of current state.
        let state = self.current.take().ok_or_else(|| StoreError::AuditRotationFailed {
            reason: "no file open for rotation".into(),
            source: None,
        })?;

        // Drop the file handle before rename.
        drop(state.file);

        // Story 8.2 F39: use the cached rotation suffix when available
        // to avoid re-scanning the whole audit directory on every
        // rotation during an incident. Seed the cache on the first
        // rotation for a given date.
        //
        // Story 8.2 review fix D2: if the wall clock has stepped
        // backwards (NTP adjust), the cached suffix can be LOWER than
        // the real on-disk max — `std::fs::rename` would silently
        // overwrite a prior rotation's file. Guard: if the candidate
        // rotated path already exists, invalidate the cache and
        // rescan.
        let mut next_suffix = self.next_rotation_suffix(&state.date)?;
        let mut rotated_name = format!("{}-{next_suffix}.jsonl", state.date);
        let mut rotated_path = self.audit_dir.join(&rotated_name);
        if rotated_path.exists() {
            tracing::warn!(
                date = %state.date,
                cached_next_suffix = next_suffix,
                "rotation target already exists — cache is stale (likely clock step-back); forcing rescan"
            );
            self.last_rotation = None;
            next_suffix = self.scan_for_max_suffix(&state.date)? + 1;
            rotated_name = format!("{}-{next_suffix}.jsonl", state.date);
            rotated_path = self.audit_dir.join(&rotated_name);
        }

        std::fs::rename(&state.path, &rotated_path).map_err(|e| {
            StoreError::AuditRotationFailed {
                reason: format!(
                    "rename {} → {} failed",
                    state.path.display(),
                    rotated_path.display()
                ),
                source: Some(Box::new(e)),
            }
        })?;

        tracing::info!(
            from = %state.path.display(),
            to = %rotated_path.display(),
            "rotated audit log file"
        );

        // Update the rotation cache so the NEXT rotation for this
        // date increments without re-scanning.
        self.last_rotation = Some((state.date.clone(), next_suffix));

        // Open a fresh file for the same date.
        self.open_file_for_date(&state.date)?;

        Ok(())
    }

    /// Returns the next rotation suffix for `date`, using a cached
    /// counter when one exists (F39 fix). On cache miss, scans the
    /// audit directory once to find the maximum existing suffix.
    ///
    /// Story 8.2 review fix F14: overflow on `u64::MAX + 1` is
    /// defensively guarded with `checked_add`. Hitting the cap is
    /// physically unreachable (u64::MAX rotations per day) but the
    /// check is one line of insurance against corrupted filenames.
    fn next_rotation_suffix(&self, date: &str) -> Result<u64, StoreError> {
        if let Some((cached_date, last_suffix)) = &self.last_rotation
            && cached_date == date
        {
            return last_suffix.checked_add(1).ok_or_else(|| StoreError::AuditRotationFailed {
                reason: "rotation suffix overflowed u64::MAX".into(),
                source: None,
            });
        }
        // Cache miss — scan the directory.
        let max_existing = self.scan_for_max_suffix(date)?;
        max_existing.checked_add(1).ok_or_else(|| StoreError::AuditRotationFailed {
            reason: "rotation suffix overflowed u64::MAX".into(),
            source: None,
        })
    }

    /// Scan the audit directory for the maximum existing rotation
    /// suffix for `date`. O(n) in the directory size; called at most
    /// once per date thanks to `last_rotation` caching.
    fn scan_for_max_suffix(&self, date: &str) -> Result<u64, StoreError> {
        let prefix = format!("{date}-");
        let mut max_suffix: u64 = 0;

        let entries =
            std::fs::read_dir(&self.audit_dir).map_err(|e| StoreError::AuditWriteFailed {
                reason: format!(
                    "failed to scan audit dir for rotation: {}",
                    self.audit_dir.display()
                ),
                source: Some(Box::new(e)),
            })?;

        for entry in entries {
            let entry = entry.map_err(|e| StoreError::AuditWriteFailed {
                reason: "failed to read directory entry".into(),
                source: Some(Box::new(e)),
            })?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if let Some(rest) = name_str.strip_prefix(&prefix)
                && let Some(num_str) = rest.strip_suffix(".jsonl")
                && let Ok(n) = num_str.parse::<u64>()
            {
                max_suffix = max_suffix.max(n);
            }
        }

        Ok(max_suffix)
    }
}

/// Open or create a file with O_APPEND semantics and 0o600 permissions.
fn open_append_file(path: &Path) -> Result<File, StoreError> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let file = opts.open(path).map_err(|e| StoreError::AuditWriteFailed {
        reason: format!("failed to open {}", path.display()),
        source: Some(Box::new(e)),
    })?;

    Ok(file)
}

/// Create the audit directory with `0o700` permissions on Unix.
fn create_audit_dir(dir: &Path) -> Result<(), StoreError> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| StoreError::AuditWriteFailed {
            reason: format!("failed to create parent dirs for {}", dir.display()),
            source: Some(Box::new(e)),
        })?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        match std::fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                use std::os::unix::fs::PermissionsExt;
                let meta =
                    std::fs::symlink_metadata(dir).map_err(|e| StoreError::AuditWriteFailed {
                        reason: format!("failed to stat audit dir {}", dir.display()),
                        source: Some(Box::new(e)),
                    })?;
                if !meta.is_dir() {
                    return Err(StoreError::AuditWriteFailed {
                        reason: format!(
                            "audit path exists but is not a directory: {}",
                            dir.display()
                        ),
                        source: None,
                    });
                }
                let mut perms = meta.permissions();
                perms.set_mode(0o700);
                if let Err(e) = std::fs::set_permissions(dir, perms) {
                    tracing::warn!(path = %dir.display(), error = %e, "failed to tighten audit dir permissions");
                }
            }
            Err(e) => {
                return Err(StoreError::AuditWriteFailed {
                    reason: format!("failed to create audit dir {}", dir.display()),
                    source: Some(Box::new(e)),
                });
            }
        }
    }

    #[cfg(not(unix))]
    {
        match std::fs::create_dir(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let meta =
                    std::fs::symlink_metadata(dir).map_err(|e| StoreError::AuditWriteFailed {
                        reason: format!("failed to stat audit dir {}", dir.display()),
                        source: Some(Box::new(e)),
                    })?;
                if !meta.is_dir() {
                    return Err(StoreError::AuditWriteFailed {
                        reason: format!(
                            "audit path exists but is not a directory: {}",
                            dir.display()
                        ),
                        source: None,
                    });
                }
            }
            Err(e) => {
                return Err(StoreError::AuditWriteFailed {
                    reason: format!("failed to create audit dir {}", dir.display()),
                    source: Some(Box::new(e)),
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::audit::event::AuditEvent;
    use crate::scrub::{ScrubEngine, builtin_rules};
    use tempfile::TempDir;

    fn test_scrub_engine() -> Arc<ScrubEngine> {
        Arc::new(ScrubEngine::new(builtin_rules().to_vec()).expect("builtin rules must compile"))
    }

    fn test_event() -> AuditEvent {
        AuditEvent::new(
            "agent-1".into(),
            "gmail".into(),
            "mail.readonly".into(),
            "*".into(),
            "ok".into(),
            "api-call".into(),
        )
    }

    #[test]
    fn append_creates_file() {
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("audit");
        let mut writer =
            AuditFsWriter::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap();

        writer.append(&test_event()).unwrap();

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let file_path = audit_dir.join(format!("{today}.jsonl"));
        assert!(file_path.exists(), "audit file should exist");

        let content = std::fs::read_to_string(&file_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1);

        // Verify it's valid JSON.
        let _: AuditEvent = serde_json::from_str(lines[0]).unwrap();
    }

    #[test]
    fn append_increments_size() {
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("audit");
        let mut writer =
            AuditFsWriter::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap();

        writer.append(&test_event()).unwrap();
        let size_after_one = writer.current.as_ref().unwrap().bytes_written;

        writer.append(&test_event()).unwrap();
        let size_after_two = writer.current.as_ref().unwrap().bytes_written;

        assert!(size_after_two > size_after_one);
    }

    #[test]
    fn size_rotation_renames_correctly() {
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("audit");
        // Set a tiny threshold so rotation triggers quickly.
        let mut writer = AuditFsWriter::new(audit_dir.clone(), 50, test_scrub_engine()).unwrap();

        // Write events until rotation happens.
        for _ in 0..10 {
            writer.append(&test_event()).unwrap();
        }

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

        // Should have at least one rotated file.
        let entries: Vec<_> = std::fs::read_dir(&audit_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();

        let rotated = entries.iter().filter(|n| n.starts_with(&format!("{today}-"))).count();
        assert!(rotated >= 1, "expected at least one rotated file, got entries: {entries:?}");

        // Current file should still exist.
        assert!(
            entries.contains(&format!("{today}.jsonl")),
            "current file should exist: {entries:?}"
        );
    }

    #[test]
    fn multiple_rotations_produce_incrementing_suffixes() {
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("audit");
        let mut writer = AuditFsWriter::new(audit_dir.clone(), 10, test_scrub_engine()).unwrap();

        // Write many events to force multiple rotations.
        for _ in 0..50 {
            writer.append(&test_event()).unwrap();
        }

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let entries: Vec<String> = std::fs::read_dir(&audit_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();

        // Check that suffixes are incrementing.
        let mut suffixes: Vec<u32> = entries
            .iter()
            .filter_map(|n| {
                n.strip_prefix(&format!("{today}-"))
                    .and_then(|rest| rest.strip_suffix(".jsonl"))
                    .and_then(|num| num.parse().ok())
            })
            .collect();
        suffixes.sort();

        assert!(suffixes.len() >= 2, "expected at least 2 rotations, got: {suffixes:?}");
        // Verify they start at 1 and are incrementing.
        for (i, &suffix) in suffixes.iter().enumerate() {
            assert_eq!(suffix, (i as u32) + 1, "suffixes should be incrementing: {suffixes:?}");
        }
    }

    #[test]
    fn sweep_deletes_old_files() {
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("audit");
        let writer =
            AuditFsWriter::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap();

        // Create files with old dates.
        let old_date = (chrono::Utc::now().date_naive() - chrono::Duration::days(100))
            .format("%Y-%m-%d")
            .to_string();
        let recent_date = chrono::Utc::now().format("%Y-%m-%d").to_string();

        std::fs::write(audit_dir.join(format!("{old_date}.jsonl")), "old\n").unwrap();
        std::fs::write(audit_dir.join(format!("{old_date}-1.jsonl")), "old rotated\n").unwrap();
        std::fs::write(audit_dir.join(format!("{recent_date}.jsonl")), "recent\n").unwrap();

        let deleted = writer.sweep_retention(90).unwrap();
        assert_eq!(deleted, 2);
        assert!(!audit_dir.join(format!("{old_date}.jsonl")).exists());
        assert!(!audit_dir.join(format!("{old_date}-1.jsonl")).exists());
        assert!(audit_dir.join(format!("{recent_date}.jsonl")).exists());
    }

    #[test]
    fn sweep_preserves_recent_files() {
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("audit");
        let writer =
            AuditFsWriter::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap();

        let recent = chrono::Utc::now().format("%Y-%m-%d").to_string();
        std::fs::write(audit_dir.join(format!("{recent}.jsonl")), "recent\n").unwrap();

        let deleted = writer.sweep_retention(90).unwrap();
        assert_eq!(deleted, 0);
        assert!(audit_dir.join(format!("{recent}.jsonl")).exists());
    }

    #[test]
    fn sweep_preserves_file_at_exact_boundary() {
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("audit");
        let writer =
            AuditFsWriter::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap();

        // File dated exactly `retention_days` ago should be preserved (strict less-than).
        let boundary_date = (chrono::Utc::now().date_naive() - chrono::Duration::days(90))
            .format("%Y-%m-%d")
            .to_string();
        let old_date = (chrono::Utc::now().date_naive() - chrono::Duration::days(91))
            .format("%Y-%m-%d")
            .to_string();

        std::fs::write(audit_dir.join(format!("{boundary_date}.jsonl")), "boundary\n").unwrap();
        std::fs::write(audit_dir.join(format!("{old_date}.jsonl")), "old\n").unwrap();

        let deleted = writer.sweep_retention(90).unwrap();
        assert_eq!(deleted, 1, "only the 91-day-old file should be deleted");
        assert!(
            audit_dir.join(format!("{boundary_date}.jsonl")).exists(),
            "file at exact boundary should be preserved"
        );
        assert!(!audit_dir.join(format!("{old_date}.jsonl")).exists());
    }

    #[test]
    fn date_rollover_creates_new_file() {
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("audit");
        let mut writer =
            AuditFsWriter::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap();

        // Write to a "yesterday" file by manually setting up state.
        let yesterday = (chrono::Utc::now().date_naive() - chrono::Duration::days(1))
            .format("%Y-%m-%d")
            .to_string();
        let yesterday_path = audit_dir.join(format!("{yesterday}.jsonl"));
        std::fs::write(&yesterday_path, "").unwrap();

        // Simulate the writer having an open file for yesterday.
        writer.current = Some(OpenFileState {
            file: std::fs::OpenOptions::new().append(true).open(&yesterday_path).unwrap(),
            date: yesterday.clone(),
            path: yesterday_path.clone(),
            bytes_written: 0,
        });

        // Append should detect date change and open a new file for today.
        writer.append(&test_event()).unwrap();

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        assert_ne!(today, yesterday);
        assert!(
            audit_dir.join(format!("{today}.jsonl")).exists(),
            "today's file should exist after date rollover"
        );
        assert!(yesterday_path.exists(), "yesterday's file should remain on disk");
        assert_eq!(
            writer.current.as_ref().unwrap().date,
            today,
            "writer should now be on today's date"
        );
    }

    #[test]
    fn max_file_bytes_clamped_to_minimum() {
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("audit");
        let writer = AuditFsWriter::new(audit_dir, 0, test_scrub_engine()).unwrap();
        assert_eq!(writer.max_file_bytes, AuditFsWriter::MIN_MAX_FILE_BYTES);
    }

    #[cfg(unix)]
    #[test]
    fn audit_dir_mode_is_0700() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("audit");
        let _writer =
            AuditFsWriter::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap();
        let mode = std::fs::metadata(&audit_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn audit_file_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("audit");
        let mut writer =
            AuditFsWriter::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap();
        writer.append(&test_event()).unwrap();

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let file_path = audit_dir.join(format!("{today}.jsonl"));
        let mode = std::fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    // --- Scrub-before-log tests (Story 2.4) ---

    #[test]
    fn scrub_event_redacts_otp_in_resource_field() {
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("audit");
        let mut writer =
            AuditFsWriter::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap();

        let mut event = test_event();
        event.resource = "messages/123 code is 456789".into();
        writer.append(&event).unwrap();

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let content = std::fs::read_to_string(audit_dir.join(format!("{today}.jsonl"))).unwrap();
        let line = content.lines().next().unwrap();

        assert!(
            line.contains("<REDACTED_OTP>"),
            "audit line should contain <REDACTED_OTP>: {line}"
        );
        assert!(!line.contains("456789"), "audit line must NOT contain raw OTP: {line}");
    }

    #[test]
    fn scrub_event_redacts_jwt_in_extra_field() {
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("audit");
        let mut writer =
            AuditFsWriter::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap();

        let mut event = test_event();
        // JWT-shaped: three dot-separated base64url segments
        event.extra = serde_json::json!({
            "snippet": "token is eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        });
        writer.append(&event).unwrap();

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let content = std::fs::read_to_string(audit_dir.join(format!("{today}.jsonl"))).unwrap();
        let line = content.lines().next().unwrap();

        assert!(
            line.contains("<REDACTED_JWT>"),
            "audit line should contain <REDACTED_JWT>: {line}"
        );
        assert!(
            !line.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
            "audit line must NOT contain raw JWT: {line}"
        );
    }

    #[test]
    fn scrub_event_clean_event_unchanged() {
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("audit");
        let mut writer =
            AuditFsWriter::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap();

        let event = test_event();
        writer.append(&event).unwrap();

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let content = std::fs::read_to_string(audit_dir.join(format!("{today}.jsonl"))).unwrap();
        let line = content.lines().next().unwrap();

        // Deserialize and verify fields are unchanged.
        let written: AuditEvent = serde_json::from_str(line).unwrap();
        assert_eq!(written.agent_id, "agent-1");
        assert_eq!(written.service, "gmail");
        assert_eq!(written.scope, "mail.readonly");
        assert_eq!(written.resource, "*");
        assert_eq!(written.outcome, "ok");
        assert_eq!(written.event_type, "api-call");
    }

    #[test]
    fn scrub_event_preserves_system_fields() {
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("audit");
        let engine = test_scrub_engine();
        let writer = AuditFsWriter::new(audit_dir, 100 * 1024 * 1024, Arc::clone(&engine)).unwrap();

        let event = test_event();
        let scrubbed = writer.scrub_event(&event);

        // System fields are passed through unchanged.
        assert_eq!(scrubbed.timestamp, event.timestamp);
        assert_eq!(scrubbed.request_id, event.request_id);
        assert_eq!(scrubbed.schema_version, event.schema_version);
    }

    // --- Story 2.6: v2 scrub_events payload survives scrub-before-log round-trip ---

    #[test]
    fn scrub_samples_in_extra_survive_audit_writer_scrub() {
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("audit");
        let mut writer =
            AuditFsWriter::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap();

        // Build a v2-shape extra where samples are ALREADY scrubbed by the
        // proxy service (placeholders in place). The writer's scrub pass
        // must be a no-op on this payload.
        let mut event = test_event();
        event.extra = serde_json::json!({
            "scrub_events": {
                "summary": { "otp-6digit": 1 },
                "samples": [
                    {
                        "rule": "otp-6digit",
                        "snippet": "Your verification code is <REDACTED_OTP>",
                        "placeholder_offset": 26,
                        "placeholder_len": 14
                    }
                ]
            }
        });
        writer.append(&event).unwrap();

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let content = std::fs::read_to_string(audit_dir.join(format!("{today}.jsonl"))).unwrap();
        let written: AuditEvent = serde_json::from_str(content.lines().next().unwrap()).unwrap();

        // Shape preserved: {summary, samples}
        let scrub_events = &written.extra["scrub_events"];
        assert_eq!(scrub_events["summary"]["otp-6digit"], 1);
        let samples = scrub_events["samples"].as_array().unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0]["rule"], "otp-6digit");
        assert_eq!(samples[0]["snippet"], "Your verification code is <REDACTED_OTP>");
        assert_eq!(samples[0]["placeholder_offset"], 26);
        assert_eq!(samples[0]["placeholder_len"], 14);
    }

    // ── Story 8.2: single-snapshot midnight rollover (F14) ─────────

    #[test]
    fn midnight_rollover_uses_single_timestamp_snapshot() {
        // AC #12: `append_at(now, event)` must route the event to the
        // file named for `now`'s date, using the SAME snapshot for both
        // the date-comparison and the file-opening decision. Prior to
        // Story 8.2, `append()` called `chrono::Utc::now()` twice — once
        // at the top and once inside `open_file_for_date` — and at
        // midnight the two reads could disagree.
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("audit");
        let mut writer =
            AuditFsWriter::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap();

        // Inject a specific UTC timestamp just before midnight.
        let eve =
            DateTime::parse_from_rfc3339("2026-04-18T23:59:59.999Z").unwrap().with_timezone(&Utc);
        writer.append_at(eve, &test_event()).unwrap();
        assert!(
            audit_dir.join("2026-04-18.jsonl").exists(),
            "event at 23:59:59 should land in 2026-04-18.jsonl"
        );
    }

    // ── Story 8.2: rotation suffix cache (F39) ─────────────────────

    #[test]
    fn rotation_suffix_cached_avoids_rescan() {
        // AC #7: after the first rotation for a date, the cached
        // `last_rotation` counter increments without a fresh `read_dir`.
        // We assert this structurally via `next_rotation_suffix` returning
        // the cached value + 1 even after we pollute the directory with
        // extra files that a fresh scan would pick up.
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("audit");
        let mut writer =
            AuditFsWriter::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap();

        let date = "2026-04-19";
        // Seed the cache as if we had just rotated to suffix 3.
        writer.last_rotation = Some((date.to_owned(), 3));

        // Create a decoy file with a HIGHER suffix. If the writer
        // re-scanned the directory, it would pick up 99 + 1 = 100.
        // With the cache intact, it returns 3 + 1 = 4.
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::write(audit_dir.join(format!("{date}-99.jsonl")), b"").unwrap();

        let next = writer.next_rotation_suffix(date).unwrap();
        assert_eq!(next, 4, "cached counter must skip the directory scan; got {next} (expected 4)");
    }

    #[test]
    fn rotation_suffix_cache_miss_scans_directory() {
        // Companion to the test above: when the cache doesn't match the
        // requested date (different date or no cache entry), fall back
        // to scanning the directory.
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("audit");
        let writer =
            AuditFsWriter::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap();

        let date = "2026-04-19";
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::write(audit_dir.join(format!("{date}-5.jsonl")), b"").unwrap();
        std::fs::write(audit_dir.join(format!("{date}-7.jsonl")), b"").unwrap();

        let next = writer.next_rotation_suffix(date).unwrap();
        assert_eq!(next, 8, "cache-miss path should find max 7, return 8");
    }

    #[test]
    fn midnight_rollover_routes_second_event_to_new_file() {
        // AC #12 companion: a SECOND append_at with the next day's
        // timestamp rolls to a new file. The previous day's file is
        // preserved (not re-opened).
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("audit");
        let mut writer =
            AuditFsWriter::new(audit_dir.clone(), 100 * 1024 * 1024, test_scrub_engine()).unwrap();

        let eve =
            DateTime::parse_from_rfc3339("2026-04-18T23:59:59.999Z").unwrap().with_timezone(&Utc);
        let dawn =
            DateTime::parse_from_rfc3339("2026-04-19T00:00:00.001Z").unwrap().with_timezone(&Utc);

        writer.append_at(eve, &test_event()).unwrap();
        writer.append_at(dawn, &test_event()).unwrap();

        let eve_file = audit_dir.join("2026-04-18.jsonl");
        let dawn_file = audit_dir.join("2026-04-19.jsonl");
        assert!(eve_file.exists());
        assert!(dawn_file.exists());

        let eve_lines =
            std::fs::read_to_string(&eve_file).unwrap().lines().filter(|l| !l.is_empty()).count();
        let dawn_lines =
            std::fs::read_to_string(&dawn_file).unwrap().lines().filter(|l| !l.is_empty()).count();
        assert_eq!(eve_lines, 1, "eve file must have exactly 1 event");
        assert_eq!(dawn_lines, 1, "dawn file must have exactly 1 event");
    }
}
