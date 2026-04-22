//! Daemon-owned fire-and-track audit dispatcher (Story 8.2).
//!
//! Replaces the fire-and-forget `tokio::spawn(async move { store.append(...) })`
//! pattern at every middleware audit-write site. The dispatcher owns a
//! [`tokio::task::JoinSet`] so the daemon shutdown sequence can explicitly
//! drain in-flight audit writes before the hard 30-second deadline fires —
//! the scenario where audit durability matters most (kill switch incident,
//! SIGTERM under load) is the exact scenario where fire-and-forget tasks
//! are orphaned.
//!
//! # Shape
//!
//! - [`AuditDispatcher::dispatch`] is an `async` fn: acquires a permit on
//!   the shared semaphore BEFORE spawning so backpressure propagates to
//!   the caller instead of queuing unbounded tasks. Under normal load
//!   the acquire is non-blocking; under a flood the caller awaits.
//!   Best-effort on the write itself — audit failures log a `tracing::warn!`.
//! - [`AuditDispatcher::drain`] awaits all outstanding tasks or times out.
//!   Called from the daemon shutdown spine between the graceful-shutdown
//!   notify and the 30-second hard deadline.
//! - [`AuditDispatcher::none`] constructs a no-op dispatcher for tests
//!   and for daemon configurations where audit is structurally absent.
//!
//! # Why `JoinSet` over `mpsc → writer task`
//!
//! Both solve the drop-on-shutdown problem. `JoinSet` is simpler when each
//! spawned unit is independent (the `AuditFsStore`'s internal
//! `Arc<Mutex<_>>` already serializes at the writer boundary). An `mpsc`
//! channel with a single consumer would re-serialize writes and re-introduce
//! the exact bottleneck `spawn_blocking` exists to avoid.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::audit::event::AuditEvent;
use crate::store::AuditStore;

/// Report returned by [`AuditDispatcher::drain`].
#[derive(Debug, Default, Clone, Copy)]
pub struct DrainReport {
    /// Tasks that completed within the drain timeout.
    pub drained: usize,
    /// Tasks still in flight when the drain timeout expired.
    pub timed_out: usize,
}

/// Fire-and-track audit dispatcher.
///
/// Cloning the `Arc<AuditDispatcher>` is cheap; all clones share the same
/// owned [`JoinSet`] and the same underlying [`AuditStore`].
pub struct AuditDispatcher {
    store: Option<Arc<dyn AuditStore>>,
    tasks: Mutex<JoinSet<()>>,
    /// Shared backpressure semaphore (Story 8.2 review fix D1). When
    /// `Some`, [`AuditDispatcher::dispatch`] acquires a permit BEFORE
    /// spawning the blocking task — propagating backpressure to the
    /// producer edge instead of letting the JoinSet queue unboundedly
    /// under a flood. In production this is the same `Arc<Semaphore>`
    /// exposed by [`AuditFsStore::semaphore`](crate::store::fs::AuditFsStore::semaphore)
    /// so the two layers share a single cap.
    ///
    /// `None` is used only by [`AuditDispatcher::none`] (disabled audit)
    /// and by [`AuditDispatcher::for_tests_unbounded`] for unit tests
    /// that exercise dispatch semantics without a writer-side cap.
    semaphore: Option<Arc<Semaphore>>,
}

impl AuditDispatcher {
    /// Construct a dispatcher wrapping a store with a shared backpressure
    /// semaphore.
    ///
    /// Pass the semaphore from [`AuditFsStore::semaphore`](crate::store::fs::AuditFsStore::semaphore)
    /// so producer (dispatcher) and consumer (writer) share one cap. A
    /// flood stalls at the dispatcher's `dispatch().await` instead of
    /// ballooning the JoinSet.
    #[must_use]
    pub fn new(store: Arc<dyn AuditStore>, semaphore: Arc<Semaphore>) -> Self {
        Self { store: Some(store), tasks: Mutex::new(JoinSet::new()), semaphore: Some(semaphore) }
    }

    /// Construct a no-op dispatcher. Convenience for tests and for daemon
    /// configurations where audit is structurally absent. `dispatch` is
    /// a silent no-op.
    #[must_use]
    pub fn none() -> Self {
        Self { store: None, tasks: Mutex::new(JoinSet::new()), semaphore: None }
    }

    /// Test-only: construct a dispatcher with a store but NO backpressure
    /// semaphore. Behavior matches pre-Story-8.2: unbounded queuing.
    /// Intended for unit tests that inspect dispatch semantics in
    /// isolation from the writer-side cap.
    #[doc(hidden)]
    #[must_use]
    pub fn for_tests_unbounded(store: Arc<dyn AuditStore>) -> Self {
        Self { store: Some(store), tasks: Mutex::new(JoinSet::new()), semaphore: None }
    }

    /// Fire-and-track dispatch: acquire a shared permit, then spawn the
    /// audit write into the owned [`JoinSet`]. Awaiting this future
    /// yields to the runtime when the concurrency cap is full — the
    /// caller is the point where backpressure is applied (Story 8.2
    /// review fix D1).
    ///
    /// Best-effort on the write itself: if `store.append` returns an
    /// error, the spawned task logs a `tracing::warn!` and terminates.
    ///
    /// When the dispatcher was constructed with [`AuditDispatcher::none`],
    /// this is a silent no-op.
    ///
    /// NOTE on drain races: if `drain()` has taken the JoinSet by the
    /// time this function spawns, the new task lands on the replacement
    /// JoinSet that `drain()` does not await. In practice this is safe
    /// because `drain()` is only called from the daemon shutdown spine
    /// AFTER axum has stopped accepting new connections — no middleware
    /// call path reaches this method once `drain()` has started.
    pub async fn dispatch(&self, event: AuditEvent) {
        let Some(store) = self.store.clone() else {
            return;
        };

        // Acquire a shared permit BEFORE spawning (producer-edge
        // backpressure). Closed-semaphore errors are unreachable in
        // practice — nothing calls `Semaphore::close` on this handle.
        let permit = if let Some(sem) = self.semaphore.as_ref() {
            match Arc::clone(sem).acquire_owned().await {
                Ok(p) => Some(p),
                Err(_) => {
                    tracing::warn!(
                        target: "audit",
                        "audit semaphore closed — dropping event"
                    );
                    return;
                }
            }
        } else {
            None
        };

        // Lock is held only long enough to push a future onto the JoinSet;
        // no `.await` while the mutex is locked.
        let mut tasks = match self.tasks.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::error!(
                    target: "audit",
                    "audit dispatcher JoinSet mutex was poisoned — recovering inner state"
                );
                poisoned.into_inner()
            }
        };
        tasks.spawn(async move {
            // Keep the permit alive for the lifetime of the store.append
            // call so the cap reflects truly in-flight work.
            let _permit = permit;
            if let Err(e) = store.append(event).await {
                tracing::warn!(error = %e, "audit write failed (best-effort)");
            }
        });
    }

    /// Await all outstanding dispatches or time out.
    ///
    /// Called from the daemon shutdown sequence AFTER the graceful-shutdown
    /// notify fires and BEFORE the hard 30-second drain deadline.
    ///
    /// ## Drain semantics (Story 8.2 review fix F1)
    ///
    /// `drain()` takes the current `JoinSet` out of the dispatcher at
    /// call time; any [`AuditDispatcher::dispatch`] that spawns AFTER
    /// this point lands on a fresh replacement `JoinSet` that this
    /// drain will NOT await. This is safe in the production shutdown
    /// sequence because `drain()` is called AFTER axum's
    /// `with_graceful_shutdown` has finished draining connections, so
    /// no middleware call path is live to dispatch new events. The
    /// replacement `JoinSet` is aborted on dispatcher drop.
    ///
    /// Calling `drain()` twice is idempotent for the second call:
    /// it takes whatever has been dispatched since the first call.
    pub async fn drain(&self, timeout: Duration) -> DrainReport {
        // Snapshot the JoinSet out of the Mutex so we can `.await` without
        // holding the lock. A new empty JoinSet takes its place.
        let mut tasks = {
            let mut guard = match self.tasks.lock() {
                Ok(g) => g,
                Err(poisoned) => {
                    tracing::error!(
                        target: "audit",
                        "audit dispatcher JoinSet mutex was poisoned at drain — recovering"
                    );
                    poisoned.into_inner()
                }
            };
            std::mem::take(&mut *guard)
        };

        let mut drained = 0usize;

        let drain_all = async {
            while let Some(join_result) = tasks.join_next().await {
                if let Err(e) = join_result {
                    tracing::warn!(error = %e, "audit dispatch task join error during drain");
                }
                drained += 1;
            }
        };

        let timed_out;
        tokio::select! {
            () = drain_all => {
                timed_out = 0;
            }
            () = tokio::time::sleep(timeout) => {
                // Sweep any tasks that completed in the race window between
                // the last `join_next()` poll and the timeout firing —
                // otherwise they'd be counted as `timed_out` even though
                // their write reached disk (Story 8.2 review fix F7).
                while let Some(join_result) = tasks.try_join_next() {
                    if let Err(e) = join_result {
                        tracing::warn!(error = %e, "audit dispatch task join error during drain");
                    }
                    drained += 1;
                }
                timed_out = tasks.len();
                // Abort the rest — they're orphaned under the deadline.
                tasks.abort_all();
            }
        }

        DrainReport { drained, timed_out }
    }
}

impl std::fmt::Debug for AuditDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditDispatcher")
            .field("store", &self.store.as_ref().map(|_| "<dyn AuditStore>"))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::audit::event::AuditEvent;
    use crate::store::error::StoreError;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn sample_event() -> AuditEvent {
        AuditEvent::new(
            "agent-1".into(),
            "gmail".into(),
            "mail.readonly".into(),
            "*".into(),
            "ok".into(),
            "api-call".into(),
        )
    }

    struct CountingStore {
        count: Arc<AtomicUsize>,
        delay_ms: u64,
    }

    #[async_trait]
    impl AuditStore for CountingStore {
        async fn append(&self, _event: AuditEvent) -> Result<(), StoreError> {
            if self.delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
            }
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn dispatch_then_drain_completes_all() {
        let count = Arc::new(AtomicUsize::new(0));
        let store: Arc<dyn AuditStore> =
            Arc::new(CountingStore { count: Arc::clone(&count), delay_ms: 0 });
        let dispatcher = AuditDispatcher::for_tests_unbounded(store);

        for _ in 0..10 {
            dispatcher.dispatch(sample_event()).await;
        }

        let report = dispatcher.drain(Duration::from_secs(5)).await;
        assert_eq!(report.drained, 10);
        assert_eq!(report.timed_out, 0);
        assert_eq!(count.load(Ordering::SeqCst), 10);
    }

    #[tokio::test]
    async fn drain_timeout_reports_partial() {
        let count = Arc::new(AtomicUsize::new(0));
        let store: Arc<dyn AuditStore> =
            Arc::new(CountingStore { count: Arc::clone(&count), delay_ms: 500 });
        let dispatcher = AuditDispatcher::for_tests_unbounded(store);

        for _ in 0..5 {
            dispatcher.dispatch(sample_event()).await;
        }

        // Timeout well below the 500ms delay so tasks are still in flight.
        let report = dispatcher.drain(Duration::from_millis(50)).await;
        assert!(
            report.timed_out > 0,
            "expected some tasks to be still in-flight at 50ms, got {report:?}"
        );
        assert!(report.drained + report.timed_out == 5);
    }

    #[tokio::test]
    async fn dispatch_with_none_store_is_noop() {
        let dispatcher = AuditDispatcher::none();
        // Should not panic, should not spawn anything.
        for _ in 0..100 {
            dispatcher.dispatch(sample_event()).await;
        }
        let report = dispatcher.drain(Duration::from_secs(1)).await;
        assert_eq!(report.drained, 0);
        assert_eq!(report.timed_out, 0);
    }

    #[tokio::test]
    async fn drop_is_safe_when_not_drained() {
        let count = Arc::new(AtomicUsize::new(0));
        let store: Arc<dyn AuditStore> =
            Arc::new(CountingStore { count: Arc::clone(&count), delay_ms: 100 });
        {
            let dispatcher = AuditDispatcher::for_tests_unbounded(store);
            dispatcher.dispatch(sample_event()).await;
            // Dispatcher goes out of scope here with a task still in flight.
            // JoinSet's Drop aborts remaining tasks — no panic, no leak.
        }
        // Brief wait to show the test process survives the drop.
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Story 8.2 review fix D1: dispatcher-level backpressure via shared
    // semaphore. Under a flood, `dispatch().await` stalls rather than
    // queuing unbounded tasks in the JoinSet.
    #[tokio::test]
    async fn dispatch_applies_backpressure_when_semaphore_full() {
        let count = Arc::new(AtomicUsize::new(0));
        let store: Arc<dyn AuditStore> =
            Arc::new(CountingStore { count: Arc::clone(&count), delay_ms: 100 });
        // Cap of 2 → only 2 dispatches can be in-flight concurrently.
        let semaphore = Arc::new(Semaphore::new(2));
        let dispatcher = AuditDispatcher::new(store, Arc::clone(&semaphore));

        // Fire 3 dispatches. The first 2 get permits immediately; the
        // 3rd must await. Verify by checking available_permits after
        // the first two spawn (their permits are moved into the spawned
        // tasks; semaphore should show 0 free).
        dispatcher.dispatch(sample_event()).await;
        dispatcher.dispatch(sample_event()).await;
        assert_eq!(
            semaphore.available_permits(),
            0,
            "both permits must be held by in-flight tasks"
        );

        // A 3rd dispatch must eventually complete once a permit frees.
        dispatcher.dispatch(sample_event()).await;
        let report = dispatcher.drain(Duration::from_secs(2)).await;
        assert_eq!(report.drained, 3);
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }
}
