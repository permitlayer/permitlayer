//! In-process per-agent connection tracker (Story 5.5 — FR83).
//!
//! Backs `agentsso status --connections` (and `--watch`) by recording
//! per-request observations from `ConnTrackLayer` middleware into a
//! lock-free [`dashmap::DashMap`]. The map is keyed by [`ConnId`] —
//! `(agent_name, first_seen)` — which produces a stable identifier for
//! an agent's contiguous active session, naturally re-keyed when the
//! agent goes idle past the configured timeout and reappears.
//!
//! # Why a sliding window, not a counter
//!
//! Reusing [`crate::cli::audit_anomaly::RateWindow`] (60 minute-buckets
//! with hybrid-divisor cold-start smoothing) sidesteps the
//! cancellation-correctness traps Story 4.4 review found in
//! `KillSwitch::tokens` (decrement-on-Drop is fragile when a response
//! future is cancelled mid-flight). It also answers the question
//! operators are actually asking — "is this agent doing things?" —
//! rather than the misleading "0 in-flight right now" that a strict
//! counter would report between requests.
//!
//! # Why `(agent_name, first_seen)` as the key
//!
//! A UUID would require minting + storing a per-request ID in
//! middleware. The tuple is stable for the duration of an active
//! window, derives trivially from `record_request` inputs, and the
//! "two requests within 1-second resolution collide and merge into one
//! entry" property is the desired behavior — that *is* the same
//! session.
//!
//! # Sweep model
//!
//! [`ConnTracker::sweep_idle`] is called both (a) by a background task
//! spawned in `cli/start.rs::run` on a 60s tick and (b) by
//! `connections_handler` before `snapshot()` so even a daemon that
//! never receives a status query can't grow without bound. axum 0.7 /
//! hyper 1 do not expose a per-connection lifecycle event accessible
//! to middleware, so sweep-on-tick + sweep-on-read is the cleanest
//! pattern available.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use dashmap::DashMap;

use crate::cli::audit_anomaly::RateWindow;

/// Stable identifier for an agent's active session.
///
/// Equality is `(agent_name, first_seen)` — same agent reappearing
/// after [`ConnTracker::idle_timeout`] mints a new `ConnId` because
/// the prior `ConnInfo` (and its `first_seen` anchor) has been swept.
#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub struct ConnId {
    pub agent_name: String,
    pub first_seen: DateTime<Utc>,
}

/// Per-active-agent state.
///
/// Cloned on `snapshot()` (DashMap iteration cannot expose references
/// outside its lock); the `RateWindow` clone is a 60-element `[u64;
/// 60]` array + two `Instant`s, so the cost is bounded and
/// independent of how many requests have been observed.
///
/// # Wall-clock vs monotonic-clock fields
///
/// `connected_since` and `last_request_at` (`DateTime<Utc>`) are for
/// *display only* — operators see them in the table.
/// `last_request_at_mono` (`Instant`) is the load-bearing field for
/// staleness decisions (H2 review patch). Wall clock is unsafe for
/// staleness because NTP correction or manual `date` adjustments can
/// jump it backward (locking entries as live forever) or forward
/// (wiping every active session mid-flight). The monotonic clock is
/// immune to both. The two are tracked independently so the display
/// stays meaningful while the internal logic stays correct.
#[derive(Clone, Debug)]
pub struct ConnInfo {
    pub agent_name: String,
    pub policy_name: String,
    pub connected_since: DateTime<Utc>,
    pub last_request_at: DateTime<Utc>,
    /// Monotonic timestamp of the most recent observation. Used by
    /// [`ConnTracker::record_request`] and [`ConnTracker::sweep_idle`]
    /// for clock-skew-immune staleness decisions. NEVER serialized to
    /// the wire (no `serde::Serialize` derive on `Instant` anyway).
    pub last_request_at_mono: Instant,
    pub request_window: RateWindow,
    pub total_requests: u64,
}

/// Lock-free in-process connection tracker.
///
/// All public methods take `&self`; concurrency is handled by
/// `DashMap`'s sharded RwLocks. The middleware writer
/// (`record_request`) is on the request hot path; readers
/// (`snapshot`, `count`, `sweep_idle`) run on the control endpoint
/// and the background sweep task.
///
/// # Why we key by `agent_name` not `ConnId`
///
/// At most one active session exists per agent name at any time
/// (sessions are defined by their idle gaps, not by overlapping
/// concurrent windows). Keying by `agent_name` lets
/// [`DashMap::entry`] handle the "lookup-or-create" atomically,
/// closing the lost-update race that exists in any
/// `find()`-then-`insert()` pattern. The `ConnId` (the
/// `(agent_name, first_seen)` tuple) is still part of the public API
/// — it's the stable identifier for an active session — but it's
/// reconstructed from the live `ConnInfo` on read rather than being
/// the map key.
pub struct ConnTracker {
    inner: DashMap<String, ConnInfo>,
    idle_timeout: Duration,
}

impl ConnTracker {
    /// Construct a new tracker with the given idle-eviction window.
    /// Wrap the result in `Arc` for sharing across middleware,
    /// `AppState`, and the control router.
    #[must_use]
    pub fn new(idle_timeout: Duration) -> Self {
        Self { inner: DashMap::new(), idle_timeout }
    }

    /// Record one observation. Called from `ConnTrackLayer` middleware
    /// on every request that has an `AgentId` extension.
    ///
    /// Atomic via [`DashMap::entry`]: lookup-or-create runs under the
    /// shard lock, so concurrent observations of the same agent name
    /// cannot lose updates. If the existing entry is stale (older
    /// than `idle_timeout` measured against the **monotonic** clock —
    /// H2 review patch), it is reset in place — same map slot, new
    /// `first_seen` anchor — which keeps the operation atomic, and
    /// emits a `tracing::debug!` so the session-reset has a forensic
    /// trail (H3 review patch).
    ///
    /// **L7 review patch:** empty `agent_name` is a no-op; the tracker
    /// represents per-agent activity, and an empty key would corrupt
    /// the table even though `validate_agent_name` already rejects
    /// such names at the auth boundary today.
    ///
    /// **H4 review patch:** the non-stale `Entry::Occupied` arm now
    /// refreshes `policy_name` when the incoming value is non-empty,
    /// so a registry-reload race that initially saw an empty string
    /// can recover on a subsequent observation.
    ///
    /// Returns the resolved `ConnId` so the caller can correlate (used
    /// in tests; the production middleware ignores the return value).
    pub fn record_request(
        &self,
        agent_name: &str,
        policy_name: &str,
        now_wall: DateTime<Utc>,
        now_mono: Instant,
    ) -> ConnId {
        use dashmap::Entry;

        // L7: defense-in-depth — an empty agent_name would key an
        // entry on `""` and produce a row with no agent name in the
        // operator table. AuthLayer's validate_agent_name rejects
        // empty names today, but a future caller (or a test that
        // hand-rolls AgentId) shouldn't be able to corrupt the table.
        if agent_name.is_empty() {
            return ConnId { agent_name: String::new(), first_seen: now_wall };
        }

        // `DashMap::entry` holds the shard write-lock for the whole
        // match arm — concurrent observations of the same agent name
        // serialize through this critical section, so increments
        // cannot race-overwrite each other.
        match self.inner.entry(agent_name.to_owned()) {
            Entry::Occupied(mut occ) => {
                // H2: staleness measured on the monotonic clock so
                // backward NTP corrections can't lock entries as live
                // and forward jumps can't wipe sessions mid-flight.
                let stale = now_mono.saturating_duration_since(occ.get().last_request_at_mono)
                    > self.idle_timeout;
                if stale {
                    // Reset the session in place — same map key, new
                    // anchor. The previous session has aged out; a
                    // sweep would have removed it on the next tick.
                    // H3: emit a debug-level forensic trail so the
                    // operator-visible "total_requests=1" right after
                    // a long quiet period is auditable.
                    let prior_total = occ.get().total_requests;
                    let prior_connected_since = occ.get().connected_since;
                    let mut window = RateWindow::new(now_mono);
                    window.record(now_mono);
                    let info = occ.get_mut();
                    info.policy_name = policy_name.to_owned();
                    info.connected_since = now_wall;
                    info.last_request_at = now_wall;
                    info.last_request_at_mono = now_mono;
                    info.request_window = window;
                    info.total_requests = 1;
                    tracing::debug!(
                        agent = %agent_name,
                        prior_session_started_at = %prior_connected_since,
                        prior_session_total_requests = prior_total,
                        "conn_tracker: stale-reset (new session anchor)"
                    );
                } else {
                    let info = occ.get_mut();
                    info.last_request_at = now_wall;
                    info.last_request_at_mono = now_mono;
                    info.total_requests = info.total_requests.saturating_add(1);
                    info.request_window.record(now_mono);
                    // H4: refresh policy_name if a registry-reload
                    // race during the initial vacant insert produced
                    // an empty string. Don't blank a non-empty value
                    // on a second-best lookup result.
                    if !policy_name.is_empty() && info.policy_name.is_empty() {
                        info.policy_name = policy_name.to_owned();
                    }
                }
                ConnId { agent_name: agent_name.to_owned(), first_seen: occ.get().connected_since }
            }
            Entry::Vacant(vac) => {
                let mut window = RateWindow::new(now_mono);
                window.record(now_mono);
                let info = ConnInfo {
                    agent_name: agent_name.to_owned(),
                    policy_name: policy_name.to_owned(),
                    connected_since: now_wall,
                    last_request_at: now_wall,
                    last_request_at_mono: now_mono,
                    request_window: window,
                    total_requests: 1,
                };
                let inserted = vac.insert(info);
                ConnId { agent_name: agent_name.to_owned(), first_seen: inserted.connected_since }
            }
        }
    }

    /// Drop entries whose monotonic `last_request_at_mono` is older
    /// than `idle_timeout`. Returns the number of entries the retain
    /// predicate actually removed.
    ///
    /// **H2 review patch:** sweep uses the monotonic clock for the
    /// same clock-skew-immunity reasons as `record_request`.
    ///
    /// **Story 8.6 AC #6:** counts removals inside the retain closure
    /// via an `AtomicUsize` rather than diffing `len()` before/after.
    /// `DashMap::retain` returns `()` in dashmap 6.x, so the old
    /// `before.saturating_sub(self.inner.len())` pattern undercounted
    /// whenever a concurrent `record_request` inserted a fresh entry
    /// between the `len()` snapshots. The returned value is now a
    /// tight upper bound on actual removals, independent of concurrent
    /// insertions. (See `deferred-work.md` L10 / Story 5.5 review.)
    pub fn sweep_idle(&self, now_mono: Instant) -> usize {
        let timeout = self.idle_timeout;
        let removed = AtomicUsize::new(0);
        self.inner.retain(|_, v| {
            let keep = now_mono.saturating_duration_since(v.last_request_at_mono) <= timeout;
            if !keep {
                removed.fetch_add(1, Ordering::Relaxed);
            }
            keep
        });
        removed.load(Ordering::Relaxed)
    }

    /// Number of currently-tracked connections. Cheap (`DashMap::len`).
    pub fn count(&self) -> usize {
        self.inner.len()
    }

    /// Snapshot all current entries, sorted by `connected_since` DESC
    /// (most-recent session first — matches the audit-follow row
    /// order operators are used to).
    pub fn snapshot(&self) -> Vec<ConnInfo> {
        let mut rows: Vec<ConnInfo> = self.inner.iter().map(|e| e.value().clone()).collect();
        rows.sort_by(|a, b| b.connected_since.cmp(&a.connected_since));
        rows
    }
}

/// Type alias used by `ConnTrackLayer` (defined in `permitlayer-proxy`)
/// via the `ConnTrackerSink` trait. Re-exported so the daemon's
/// `start.rs` and the proxy crate share the same `Arc<ConnTracker>`
/// shape without the proxy crate importing `dashmap`.
#[allow(dead_code)] // Held by AppState/ControlState; used by health + connections handlers.
pub type SharedConnTracker = Arc<ConnTracker>;

/// Adapter that bridges the proxy crate's
/// [`permitlayer_proxy::middleware::ConnTrackerSink`] trait to this
/// crate's [`ConnTracker`] (which depends on `dashmap` and chrono).
/// Resolves the agent's `policy_name` from the registry on each
/// observation so the middleware itself stays clock- and
/// registry-free.
///
/// If the agent has been removed from the registry between
/// authentication and connection-tracking (rare race window during
/// `agentsso agent remove`), the policy name is recorded as the
/// empty string — the entry is still tracked so operators see the
/// orphaned activity in the connections table.
pub struct ConnTrackerAdapter {
    tracker: Arc<ConnTracker>,
    registry: Arc<permitlayer_core::agent::AgentRegistry>,
}

impl ConnTrackerAdapter {
    #[must_use]
    pub fn new(
        tracker: Arc<ConnTracker>,
        registry: Arc<permitlayer_core::agent::AgentRegistry>,
    ) -> Self {
        Self { tracker, registry }
    }
}

impl permitlayer_proxy::middleware::ConnTrackerSink for ConnTrackerAdapter {
    fn record(&self, agent_name: &str) {
        let policy_name = self
            .registry
            .snapshot()
            .get_by_name(agent_name)
            .map(|i| i.policy_name.clone())
            .unwrap_or_default();
        let _ = self.tracker.record_request(
            agent_name,
            &policy_name,
            chrono::Utc::now(),
            std::time::Instant::now(),
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::sync::Arc;
    use std::thread;

    fn now_pair() -> (DateTime<Utc>, Instant) {
        (Utc::now(), Instant::now())
    }

    #[test]
    fn record_request_creates_entry_on_first_call() {
        let tracker = ConnTracker::new(Duration::from_secs(60));
        let (wall, mono) = now_pair();
        let id = tracker.record_request("agent-a", "default", wall, mono);
        assert_eq!(id.agent_name, "agent-a");
        assert_eq!(tracker.count(), 1);
        let snap = tracker.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].total_requests, 1);
        assert_eq!(snap[0].policy_name, "default");
    }

    #[test]
    fn record_request_updates_existing_entry_within_window() {
        let tracker = ConnTracker::new(Duration::from_secs(60));
        let (wall1, mono1) = now_pair();
        let id1 = tracker.record_request("agent-a", "default", wall1, mono1);
        // Same wall-clock instant + monotonic instant — should land in
        // the same session.
        let id2 = tracker.record_request("agent-a", "default", wall1, mono1);
        assert_eq!(id1, id2);
        assert_eq!(tracker.count(), 1);
        assert_eq!(tracker.snapshot()[0].total_requests, 2);
    }

    #[test]
    fn record_request_mints_new_conn_id_after_idle_timeout() {
        let tracker = ConnTracker::new(Duration::from_secs(60));
        let (wall1, mono1) = now_pair();
        let id1 = tracker.record_request("agent-a", "default", wall1, mono1);

        // Sweep first to clear the stale entry, then re-record. (In
        // production the background task does the sweep; here we
        // simulate it directly so we can assert the new `ConnId`.)
        let wall2 = wall1 + chrono::Duration::seconds(120);
        let mono2 = mono1 + Duration::from_secs(120);
        let removed = tracker.sweep_idle(mono2);
        assert_eq!(removed, 1);
        let id2 = tracker.record_request("agent-a", "default", wall2, mono2);

        assert_ne!(id1, id2);
        assert_eq!(tracker.count(), 1);
        assert_eq!(tracker.snapshot()[0].total_requests, 1);
    }

    #[test]
    fn sweep_idle_removes_entries_past_timeout() {
        let tracker = ConnTracker::new(Duration::from_secs(60));
        let (wall, mono) = now_pair();
        tracker.record_request("agent-a", "default", wall, mono);
        tracker.record_request(
            "agent-b",
            "default",
            wall + chrono::Duration::seconds(30),
            mono + Duration::from_secs(30),
        );
        // Sweep at T+90s: agent-a is 90s stale (>60s timeout), agent-b
        // is 60s stale (== timeout, kept).
        let removed = tracker.sweep_idle(mono + Duration::from_secs(90));
        assert_eq!(removed, 1);
        assert_eq!(tracker.count(), 1);
        assert_eq!(tracker.snapshot()[0].agent_name, "agent-b");
    }

    #[test]
    fn sweep_idle_keeps_recent_entries() {
        let tracker = ConnTracker::new(Duration::from_secs(60));
        let (wall, mono) = now_pair();
        tracker.record_request("agent-a", "default", wall, mono);
        let removed = tracker.sweep_idle(mono + Duration::from_secs(30));
        assert_eq!(removed, 0);
        assert_eq!(tracker.count(), 1);
    }

    /// Story 8.6 AC #6 — the counted-removal return must be exact when
    /// a second thread is concurrently inserting fresh entries.
    /// Regression guard for Story 5.5 L10 (`deferred-work.md:38`): the
    /// pre-fix `before.saturating_sub(self.inner.len())` undercounted
    /// under contention because an insert between the two `len()` calls
    /// cancelled out a real removal in the diff. An upper-bound-only
    /// assertion (`<=`) passes for both the buggy and the fixed impl
    /// since saturating_sub can only undercount; distinguishing the
    /// two requires the strict equality after draining.
    ///
    /// A `Barrier` forces the inserter and the sweep loop to start
    /// concurrently, so the interleaving is actually exercised rather
    /// than trivially happening-before the inserter starts running.
    #[test]
    fn sweep_idle_count_stable_under_concurrent_insertion() {
        use std::sync::Barrier;

        // Pre-seed 20 stale entries so there's something to remove.
        let idle_timeout = Duration::from_secs(60);
        let tracker = Arc::new(ConnTracker::new(idle_timeout));
        let (wall, mono) = now_pair();
        let stale_count = 20usize;
        for i in 0..stale_count {
            tracker.record_request(&format!("stale-{i}"), "default", wall, mono);
        }

        // Sweep at T+120s: every pre-seeded entry is past the 60s
        // timeout. Fresh inserts happening during the sweep use a
        // forward-advanced `mono` so they are NOT stale and must
        // survive the retain predicate.
        let sweep_mono = mono + Duration::from_secs(120);

        // Barrier makes the inserter and sweep-loop start at the same
        // instant. Without it the inserter's spawn overhead could
        // happen-before the first sweep, leaving no real concurrency
        // to observe.
        let barrier = Arc::new(Barrier::new(2));

        let inserter_tracker = Arc::clone(&tracker);
        let inserter_barrier = Arc::clone(&barrier);
        let inserter = thread::spawn(move || {
            inserter_barrier.wait();
            for i in 0..100 {
                inserter_tracker.record_request(
                    &format!("fresh-{i}"),
                    "default",
                    wall + chrono::Duration::seconds(120),
                    sweep_mono,
                );
            }
        });

        barrier.wait();

        let mut total_returned = 0usize;
        for _ in 0..10 {
            total_returned += tracker.sweep_idle(sweep_mono);
            thread::yield_now();
        }

        inserter.join().unwrap();

        // Final drain: any stale entries the inserter-race pushed
        // across shard boundaries during the 10-sweep window must be
        // reaped here. The AtomicUsize-counted return value sums to
        // EXACTLY `stale_count` — not just `<= stale_count` — because
        // (a) every stale key is eventually visited by retain, and
        // (b) the counter is incremented on each `false` return
        // independently of concurrent inserts on other keys. The
        // pre-fix impl (`before.saturating_sub(len())`) cannot reach
        // equality under contention — concurrent inserts inflate
        // `len()` during the retain pass and deflate the subtraction.
        total_returned += tracker.sweep_idle(sweep_mono);

        assert_eq!(
            total_returned, stale_count,
            "exact-count invariant violated: total_returned={total_returned}, stale_count={stale_count}"
        );

        // None of the 100 fresh entries should have been swept —
        // they're all at `sweep_mono`, i.e. not stale relative to
        // the sweep horizon.
        let live_fresh = tracker.count();
        assert_eq!(live_fresh, 100, "all 100 fresh entries must survive; got {live_fresh}");
    }

    #[test]
    fn count_returns_live_size() {
        let tracker = ConnTracker::new(Duration::from_secs(60));
        assert_eq!(tracker.count(), 0);
        let (wall, mono) = now_pair();
        tracker.record_request("agent-a", "default", wall, mono);
        assert_eq!(tracker.count(), 1);
        tracker.record_request("agent-b", "default", wall, mono);
        assert_eq!(tracker.count(), 2);
    }

    #[test]
    fn snapshot_returns_clones_sorted_by_connected_since_desc() {
        let tracker = ConnTracker::new(Duration::from_secs(300));
        let (wall, mono) = now_pair();
        tracker.record_request("first", "p", wall, mono);
        tracker.record_request(
            "second",
            "p",
            wall + chrono::Duration::seconds(10),
            mono + Duration::from_secs(10),
        );
        tracker.record_request(
            "third",
            "p",
            wall + chrono::Duration::seconds(20),
            mono + Duration::from_secs(20),
        );
        let snap = tracker.snapshot();
        assert_eq!(snap.len(), 3);
        // Most-recent first.
        assert_eq!(snap[0].agent_name, "third");
        assert_eq!(snap[1].agent_name, "second");
        assert_eq!(snap[2].agent_name, "first");
    }

    #[test]
    fn concurrent_record_request_no_lost_updates() {
        let tracker = Arc::new(ConnTracker::new(Duration::from_secs(300)));
        let (wall, mono) = now_pair();
        let mut handles = Vec::new();
        for _ in 0..16 {
            let t = Arc::clone(&tracker);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    t.record_request("hot-agent", "default", wall, mono);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // All 16 * 1000 = 16,000 increments should land on the SAME
        // entry (same wall-clock anchor → same ConnId).
        assert_eq!(tracker.count(), 1);
        assert_eq!(tracker.snapshot()[0].total_requests, 16_000);
    }

    // ── H2: monotonic-clock staleness immune to wall-clock skew ────

    #[test]
    fn record_request_staleness_uses_monotonic_clock_not_wall_clock() {
        // Simulate a backward NTP correction: the wall clock jumps
        // BACKWARD by 2 hours between request 1 and request 2, but
        // the monotonic clock advances normally by 1 second. The
        // entry must NOT be treated as stale (the prior `> timeout`
        // wall-clock check would have produced a NEGATIVE delta and
        // returned false anyway, but the new mono-clock check is
        // explicit about why).
        let tracker = ConnTracker::new(Duration::from_secs(60));
        let wall1 = chrono::Utc.with_ymd_and_hms(2026, 4, 16, 14, 0, 0).unwrap();
        let mono1 = Instant::now();
        tracker.record_request("agent-a", "default", wall1, mono1);

        // Wall jumps backward by 2h; monotonic advances by 1s.
        let wall2 = wall1 - chrono::Duration::hours(2);
        let mono2 = mono1 + Duration::from_secs(1);
        tracker.record_request("agent-a", "default", wall2, mono2);

        // Same session — total_requests bumped to 2, NOT reset to 1.
        assert_eq!(tracker.count(), 1);
        assert_eq!(
            tracker.snapshot()[0].total_requests,
            2,
            "backward wall-clock skew must NOT trigger a stale-reset"
        );
    }

    #[test]
    fn record_request_forward_wall_skew_does_not_wipe_session() {
        // Forward wall-clock jump >idle_timeout: prior wall-clock
        // logic would have triggered stale-reset; monotonic logic
        // sees only 1s of real elapsed time and keeps the session.
        let tracker = ConnTracker::new(Duration::from_secs(60));
        let wall1 = chrono::Utc.with_ymd_and_hms(2026, 4, 16, 14, 0, 0).unwrap();
        let mono1 = Instant::now();
        tracker.record_request("agent-a", "default", wall1, mono1);

        let wall2 = wall1 + chrono::Duration::hours(2); // FORWARD jump
        let mono2 = mono1 + Duration::from_secs(1);
        tracker.record_request("agent-a", "default", wall2, mono2);

        assert_eq!(tracker.count(), 1);
        assert_eq!(
            tracker.snapshot()[0].total_requests,
            2,
            "forward wall-clock skew must NOT trigger a stale-reset"
        );
    }

    // ── H4: registry-reload race recovery ──────────────────────────

    #[test]
    fn record_request_refreshes_empty_policy_name_on_subsequent_call() {
        // First call: registry race produces empty policy_name.
        // Second call: registry has recovered, real policy_name on
        // wire. Existing entry must adopt the new value.
        let tracker = ConnTracker::new(Duration::from_secs(60));
        let (wall, mono) = now_pair();
        tracker.record_request("agent-a", "", wall, mono);
        assert_eq!(tracker.snapshot()[0].policy_name, "");

        tracker.record_request("agent-a", "policy-readonly", wall, mono);
        assert_eq!(
            tracker.snapshot()[0].policy_name,
            "policy-readonly",
            "non-empty policy_name on later call must overwrite an earlier empty one"
        );
    }

    #[test]
    fn record_request_does_not_blank_policy_name_on_later_empty() {
        // Inverse: if the registry already populated the policy_name
        // and a later observation arrives with an empty string (e.g.
        // race window during agent-remove), keep the existing value.
        let tracker = ConnTracker::new(Duration::from_secs(60));
        let (wall, mono) = now_pair();
        tracker.record_request("agent-a", "policy-readonly", wall, mono);
        tracker.record_request("agent-a", "", wall, mono);
        assert_eq!(
            tracker.snapshot()[0].policy_name,
            "policy-readonly",
            "later empty policy_name must NOT blank a known good value"
        );
    }

    // ── L7: empty agent_name guard ─────────────────────────────────

    #[test]
    fn record_request_empty_agent_name_is_noop() {
        let tracker = ConnTracker::new(Duration::from_secs(60));
        let (wall, mono) = now_pair();
        let id = tracker.record_request("", "default", wall, mono);
        assert_eq!(id.agent_name, "");
        assert_eq!(tracker.count(), 0, "empty agent_name must NOT create a tracker entry");
    }
}
