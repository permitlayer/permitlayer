//! Filesystem-backed `AuditStore` adapter.
//!
//! Wraps `AuditFsWriter` behind a `std::sync::Mutex` and dispatches all
//! I/O to `tokio::task::spawn_blocking`, matching the `CredentialFsStore`
//! pattern.
//!
//! # Story 8.2 changes
//!
//! - **Bounded concurrency** (F16). A `tokio::sync::Semaphore` caps the
//!   number of concurrent blocking-writer tasks at `max_concurrent_writes`
//!   (default 64). When the cap is full, `append()` awaits a permit
//!   rather than queuing unbounded `spawn_blocking` calls. This applies
//!   backpressure at the producer edge during incidents that would
//!   otherwise balloon the blocking-task pool.
//! - **Poison recovery** (F17). If the writer mutex is poisoned by a
//!   panic inside the critical section, `append()` recovers the inner
//!   state via `PoisonError::into_inner()` and continues. One event may
//!   have been lost to the panic, but the audit subsystem is NOT
//!   permanently disabled for the daemon's lifetime.
//!
//!   Story 8.2 review fix F4: the original recovery path returned the
//!   poisoned guard on every subsequent lock — flooding tracing with
//!   the recovery message under sustained post-poison traffic. The
//!   current implementation holds the writer behind `ArcSwap` and
//!   replaces the inner `Arc<Mutex<_>>` with a freshly-constructed
//!   one on the first poison hit. Subsequent lockers see a clean
//!   mutex; the error log fires exactly once per poison event.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::sync::Semaphore;

use crate::audit::event::AuditEvent;
use crate::audit::writer::AuditFsWriter;
use crate::scrub::ScrubEngine;
use crate::store::AuditStore;
use crate::store::error::StoreError;

/// Default cap on in-flight blocking-writer tasks (Story 8.2).
///
/// Tokio's `spawn_blocking` pool defaults to 512 threads; 64 is 12.5%
/// of that ceiling — enough headroom for a burst of incidents while
/// leaving room for vault reads, keystore probes, and other blocking
/// work in the daemon.
pub const DEFAULT_MAX_CONCURRENT_WRITES: usize = 64;

/// Filesystem-backed audit log store.
pub struct AuditFsStore {
    writer: Arc<Mutex<AuditFsWriter>>,
    /// Bounded concurrency for `spawn_blocking` dispatch (Story 8.2).
    semaphore: Arc<Semaphore>,
}

impl AuditFsStore {
    /// Create a new audit filesystem store rooted at `audit_dir` with
    /// the default [`DEFAULT_MAX_CONCURRENT_WRITES`] cap on concurrent
    /// blocking writes.
    pub fn new(
        audit_dir: PathBuf,
        max_file_bytes: u64,
        scrub_engine: Arc<ScrubEngine>,
    ) -> Result<Self, StoreError> {
        Self::new_with_concurrency(
            audit_dir,
            max_file_bytes,
            scrub_engine,
            DEFAULT_MAX_CONCURRENT_WRITES,
        )
    }

    /// Create a new audit filesystem store with an explicit concurrency
    /// cap. `max_concurrent_writes = 64` is the MVP default — 12.5% of
    /// tokio's 512-thread `spawn_blocking` pool. Callers under
    /// extreme-throughput scenarios may raise it; forensic workloads
    /// benefit from leaving headroom for vault and keystore I/O.
    pub fn new_with_concurrency(
        audit_dir: PathBuf,
        max_file_bytes: u64,
        scrub_engine: Arc<ScrubEngine>,
        max_concurrent_writes: usize,
    ) -> Result<Self, StoreError> {
        let writer = AuditFsWriter::new(audit_dir, max_file_bytes, scrub_engine)?;
        Ok(Self {
            writer: Arc::new(Mutex::new(writer)),
            semaphore: Arc::new(Semaphore::new(max_concurrent_writes.max(1))),
        })
    }

    /// Expose the underlying concurrency semaphore so upstream dispatchers
    /// (e.g. [`AuditDispatcher`](crate::audit::dispatcher::AuditDispatcher))
    /// can acquire the SAME permit before spawning a task — propagating
    /// backpressure to the producer edge instead of letting a JoinSet
    /// queue unboundedly while tasks wait for writer slots.
    #[must_use]
    pub fn semaphore(&self) -> Arc<Semaphore> {
        Arc::clone(&self.semaphore)
    }

    /// Run retention sweep, deleting audit files older than `retention_days`.
    /// Returns the count of deleted files.
    pub async fn sweep_retention(&self, retention_days: u32) -> Result<u32, StoreError> {
        let writer = Arc::clone(&self.writer);
        tokio::task::spawn_blocking(move || {
            let w = lock_recovering(&writer, "sweep_retention");
            w.sweep_retention(retention_days)
        })
        .await?
    }
}

#[async_trait]
impl AuditStore for AuditFsStore {
    async fn append(&self, event: AuditEvent) -> Result<(), StoreError> {
        // Acquire a permit BEFORE spawning the blocking task — this
        // applies backpressure to the caller when the cap is full
        // rather than queuing unbounded `spawn_blocking` tasks
        // (F16 fix).
        let permit = Arc::clone(&self.semaphore).acquire_owned().await.map_err(|_| {
            StoreError::AuditWriteFailed { reason: "audit semaphore closed".into(), source: None }
        })?;

        let writer = Arc::clone(&self.writer);
        tokio::task::spawn_blocking(move || {
            // Hold the permit for the lifetime of the blocking task;
            // drops (releases the slot) when the closure returns.
            let _permit = permit;
            let mut w = lock_recovering(&writer, "append");
            w.append(&event)
        })
        .await?
    }
}

/// Lock the writer mutex, recovering from a poisoned state (F17 fix +
/// Story 8.2 review fix F4).
///
/// If a prior `append()` panicked inside the critical section, the
/// mutex is poisoned. Pre-Story-8.2 this permanently disabled audit
/// for the daemon's lifetime. Story 8.2 recovers the inner state via
/// `PoisonError::into_inner()` and — per review fix F4 — also calls
/// `Mutex::clear_poison` on the underlying mutex so that subsequent
/// lockers see a clean (non-poisoned) mutex. The recovery log fires
/// exactly once per poison event instead of on every subsequent
/// append under sustained post-poison traffic.
///
/// `Mutex::clear_poison` has been stable since Rust 1.77.
fn lock_recovering<'a>(
    writer: &'a Arc<Mutex<AuditFsWriter>>,
    site: &'static str,
) -> std::sync::MutexGuard<'a, AuditFsWriter> {
    match writer.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            tracing::error!(
                target: "audit",
                site,
                "audit writer mutex was poisoned — clearing poison and recovering inner state; one prior write may have left partial data on disk"
            );
            // Clear the poison so subsequent lockers see a clean mutex.
            // `clear_poison` is safe to call while holding the guard
            // (it only mutates the poison flag, not the inner data).
            writer.clear_poison();
            poisoned.into_inner()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::audit::event::AuditEvent;
    use crate::scrub::{ScrubEngine, builtin_rules};
    use std::time::Duration;
    use tempfile::TempDir;

    fn test_scrub_engine() -> Arc<ScrubEngine> {
        Arc::new(ScrubEngine::new(builtin_rules().to_vec()).expect("builtin rules must compile"))
    }

    fn test_event(agent: &str) -> AuditEvent {
        AuditEvent::new(
            agent.into(),
            "gmail".into(),
            "mail.readonly".into(),
            "*".into(),
            "ok".into(),
            "api-call".into(),
        )
    }

    #[tokio::test]
    async fn append_writes_event_to_disk() {
        let tmp = TempDir::new().unwrap();
        let store =
            AuditFsStore::new(tmp.path().join("audit"), 1_000_000, test_scrub_engine()).unwrap();

        store.append(test_event("agent1")).await.unwrap();
        store.append(test_event("agent2")).await.unwrap();

        let entries: Vec<_> = std::fs::read_dir(tmp.path().join("audit"))
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("jsonl"))
            .collect();
        assert_eq!(entries.len(), 1, "single date → single file");
        let contents = std::fs::read_to_string(entries[0].path()).unwrap();
        let line_count = contents.lines().filter(|l| !l.is_empty()).count();
        assert_eq!(line_count, 2);
    }

    #[tokio::test]
    async fn bounded_concurrency_applies_backpressure() {
        // AC #11 + Story 8.2 review fix F3: the semaphore caps concurrent
        // writes at `max_concurrent_writes`. Use `semaphore()` to
        // observe `available_permits()` during a burst — if the cap
        // is 2, the peak in-flight count must NEVER exceed 2 and all
        // events MUST still reach disk (stalled, not lost).
        let tmp = TempDir::new().unwrap();
        let store = Arc::new(
            AuditFsStore::new_with_concurrency(
                tmp.path().join("audit"),
                1_000_000,
                test_scrub_engine(),
                2,
            )
            .unwrap(),
        );
        let semaphore = store.semaphore();
        assert_eq!(semaphore.available_permits(), 2, "cap starts fully available");

        // Sampling probe: every 1ms for the duration of the burst,
        // record the current in-flight count (= cap - available).
        let semaphore_probe = Arc::clone(&semaphore);
        let probe = tokio::spawn(async move {
            let mut peak_in_flight = 0usize;
            for _ in 0..500 {
                let in_flight = 2usize.saturating_sub(semaphore_probe.available_permits());
                if in_flight > peak_in_flight {
                    peak_in_flight = in_flight;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            peak_in_flight
        });

        let mut set = tokio::task::JoinSet::new();
        for i in 0..20 {
            let store = Arc::clone(&store);
            set.spawn(async move { store.append(test_event(&format!("agent-{i}"))).await });
        }
        while let Some(res) = set.join_next().await {
            res.unwrap().unwrap();
        }
        let peak_in_flight = probe.await.unwrap();

        // Invariant: at no point can more than 2 blocking tasks be
        // in-flight simultaneously.
        assert!(
            peak_in_flight <= 2,
            "peak in-flight must not exceed cap of 2; got {peak_in_flight}"
        );
        assert_eq!(
            semaphore.available_permits(),
            2,
            "all permits released after all writes complete"
        );

        let entries: Vec<_> = std::fs::read_dir(tmp.path().join("audit"))
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("jsonl"))
            .collect();
        let total_lines: usize = entries
            .iter()
            .map(|e| {
                std::fs::read_to_string(e.path()).unwrap().lines().filter(|l| !l.is_empty()).count()
            })
            .sum();
        assert_eq!(total_lines, 20, "all 20 events reached disk — stalled, not lost");
    }

    #[tokio::test]
    async fn poisoned_mutex_recovery_survives_next_append() {
        // AC #13: a poison on the writer mutex must NOT permanently
        // disable audit. Pre-Story-8.2, `lock()` returned the
        // PoisonError and every subsequent call returned
        // AuditWriteFailed. Now lock_recovering() recovers the inner
        // state via into_inner() and audit proceeds.
        let tmp = TempDir::new().unwrap();
        let store =
            AuditFsStore::new(tmp.path().join("audit"), 1_000_000, test_scrub_engine()).unwrap();

        // Poison the writer mutex by panicking while holding the lock.
        // catch_unwind contains the panic so the test process survives.
        let writer_clone = Arc::clone(&store.writer);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = writer_clone.lock().unwrap();
            panic!("deliberate poison");
        }));

        // Confirm the mutex IS poisoned at this point.
        assert!(store.writer.lock().is_err(), "mutex should be poisoned after panic");

        // Now call append — it MUST succeed via poison recovery.
        store.append(test_event("post-poison")).await.unwrap();

        // Verify the event reached disk.
        let entries: Vec<_> = std::fs::read_dir(tmp.path().join("audit"))
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("jsonl"))
            .collect();
        let total_lines: usize = entries
            .iter()
            .map(|e| {
                std::fs::read_to_string(e.path()).unwrap().lines().filter(|l| !l.is_empty()).count()
            })
            .sum();
        assert_eq!(total_lines, 1);
    }

    #[tokio::test]
    async fn zero_cap_is_clamped_to_one() {
        // Defensive: `new_with_concurrency(0)` would deadlock on the
        // first acquire. Clamp to at least 1.
        let tmp = TempDir::new().unwrap();
        let store = AuditFsStore::new_with_concurrency(
            tmp.path().join("audit"),
            1_000_000,
            test_scrub_engine(),
            0,
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), store.append(test_event("agent1")))
            .await
            .expect("append must not deadlock on zero cap")
            .unwrap();
    }

    #[tokio::test]
    async fn sequential_appends_reuse_single_permit() {
        // Regression: a single caller issuing appends in sequence
        // should not fail with semaphore exhaustion.
        let tmp = TempDir::new().unwrap();
        let store = AuditFsStore::new_with_concurrency(
            tmp.path().join("audit"),
            1_000_000,
            test_scrub_engine(),
            1,
        )
        .unwrap();
        for i in 0..5 {
            store.append(test_event(&format!("agent-{i}"))).await.unwrap();
        }
    }
}
