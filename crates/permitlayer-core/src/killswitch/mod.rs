//! Kill switch — sovereign off-button for the daemon.
//!
//! When the kill switch is active, every HTTP request is rejected with
//! `daemon_killed` / HTTP 403 by `KillSwitchLayer` in `permitlayer-proxy`,
//! and every scoped token in the in-memory registry is marked invalid.
//! Activation broadcasts a `KillEvent::Activated` message so in-flight
//! request handlers can observe the kill and cancel themselves (Story 3.2).
//!
//! This module holds only the state machine and its public API. The tower
//! layer that enforces the state lives in `permitlayer-proxy::middleware::kill`;
//! the CLI commands that toggle the state ship in Story 3.2; the audit
//! events for kill/resume ship in Story 3.3.
//!
//! # Concurrency model
//!
//! - `active: AtomicBool` — toggled by `activate()` / `deactivate()` via
//!   `Ordering::Release`, observed by `is_active()` via `Ordering::Acquire`.
//!   The release/acquire pair guarantees that a reader observing
//!   `active == true` also observes every token-invalidation write that
//!   happened-before the activation.
//! - `registry: std::sync::Mutex<HashMap<TokenId, TokenInfo>>` — a plain
//!   `std::sync::Mutex` rather than `tokio::sync::Mutex` or `dashmap`.
//!   Registrations and lookups are microsecond-scale pure-memory ops;
//!   the mutex is never held across `.await` points.
//! - `notifier: tokio::sync::broadcast::Sender<KillEvent>` — fan-out
//!   channel for activation/resume events with capacity 64. Zero
//!   subscribers is a valid runtime state (the CLI may not have wired
//!   up a receiver yet); `send()` errors are swallowed.
//! - `activated_at: Mutex<Option<DateTime<Utc>>>` — carries the exact
//!   activation timestamp the proxy middleware needs for the response
//!   body. Stored separately from the atomic flag because an
//!   `AtomicU64` timestamp would add complexity without benefit: the
//!   field is only read by the error-building path, which already
//!   takes a mutex-sized hit.
//!
//! # Idempotency
//!
//! `activate()` and `deactivate()` are both idempotent. A second
//! `activate()` on an already-active switch is a no-op — no broadcast,
//! no re-iteration of the registry, `ActivationSummary.was_already_active
//! == true`. This matches the epic AC #3 requirement that
//! `agentsso kill` can be run twice safely.
//!
//! # Token lifecycle
//!
//! Tokens enter the registry via `register_token()` when the proxy
//! issues a scoped token (Story 3.2 or later wires this call — Story 3.1
//! only defines the registry). `invalidate_token()` marks a specific
//! token invalid without removing it (post-incident forensics). On
//! activation, every token in the registry is invalidated in a single
//! locked pass. **Deactivation does NOT re-validate previously-invalidated
//! tokens** — this is a deliberate security invariant (operators must
//! re-issue tokens after `agentsso resume`, not inherit dangling ones).

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{DateTime, Utc};
use tokio::sync::broadcast;

/// Errors produced by the kill switch module.
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KillSwitchError {
    /// A `TokenId` was constructed from an empty string. Token IDs must
    /// be non-empty so they can unambiguously identify a scoped token
    /// in the registry.
    #[error("token id must not be empty")]
    InvalidTokenId,

    /// `register_token` was called while the kill switch was active.
    /// Registering a new token during a kill state would create a
    /// dangling token that survives the next `deactivate()` call
    /// (violating the "once invalidated, stays invalidated" security
    /// invariant). Callers must wait for `is_active() == false` — or
    /// re-issue the token after resume — before retrying.
    #[error("cannot register token: kill switch is active")]
    RegisterWhileActive,
}

/// Identifier for a scoped token tracked by the kill switch registry.
///
/// Constructed only via [`TokenId::new`], which rejects empty strings.
/// Clone is cheap (single `String` clone); `Hash` + `Eq` make it usable
/// as a `HashMap` key without friction.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct TokenId(String);

impl TokenId {
    /// Construct a new `TokenId` from any string-like input.
    ///
    /// Returns `Err(KillSwitchError::InvalidTokenId)` if the input is empty.
    pub fn new(value: impl Into<String>) -> Result<Self, KillSwitchError> {
        let s: String = value.into();
        if s.is_empty() {
            return Err(KillSwitchError::InvalidTokenId);
        }
        Ok(Self(s))
    }

    /// Borrow the underlying string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Metadata for a scoped token in the registry.
///
/// `invalidated` is an `AtomicBool` so `activate()` can flip every token
/// in the registry to invalid under the single registry mutex without
/// needing to re-lock per token for a write. Not `Clone` — the
/// `AtomicBool` makes clone-equality semantics subtle, and callers that
/// need a snapshot should construct a fresh value instead.
#[derive(Debug)]
#[non_exhaustive]
pub struct TokenInfo {
    /// Agent identity this token was issued to.
    pub agent_id: String,
    /// Upstream service the token authorizes (e.g. `"gmail"`).
    pub service: String,
    /// OAuth scope the token authorizes.
    pub scope: String,
    /// When the token was issued (RFC 3339 UTC).
    pub issued_at: DateTime<Utc>,
    /// Invalidation flag. Set to `true` when the registry is flushed
    /// by `activate()` or by a targeted `invalidate_token()`.
    pub invalidated: AtomicBool,
}

impl TokenInfo {
    /// Construct a fresh `TokenInfo` in the valid state.
    #[must_use]
    pub fn new(
        agent_id: impl Into<String>,
        service: impl Into<String>,
        scope: impl Into<String>,
        issued_at: DateTime<Utc>,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            service: service.into(),
            scope: scope.into(),
            issued_at,
            invalidated: AtomicBool::new(false),
        }
    }
}

/// Why the kill switch was activated.
///
/// Extended via `#[non_exhaustive]` so later stories can add variants
/// (e.g. `PolicyTripwire`, `VaultCorruption`) without breaking downstream
/// match sites. Story 3.1 only ships the user-initiated variant.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum KillReason {
    /// User ran `agentsso kill` (the only MVP kill path).
    UserInitiated,
}

/// Broadcast event emitted on activation or resume.
///
/// Subscribers get the event via `KillSwitch::subscribe()`. Missing a
/// message because no subscribers were wired yet is a valid runtime
/// state: `send()` errors are swallowed by `activate()`/`deactivate()`.
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum KillEvent {
    /// Kill switch flipped from inactive → active.
    Activated {
        /// RFC 3339 UTC activation timestamp.
        at: DateTime<Utc>,
        /// Why the activation happened.
        reason: KillReason,
    },
    /// Kill switch flipped from active → inactive.
    Resumed {
        /// RFC 3339 UTC resume timestamp.
        at: DateTime<Utc>,
    },
}

/// Return value from [`KillSwitch::activate`].
///
/// Story 3.2's `KillBanner` UI component reads `tokens_invalidated`
/// (for the "N tokens invalidated" line), `activated_at` (for the
/// banner timestamp), and `was_already_active` (to suppress the
/// confirmation banner on double-activation).
#[derive(Debug, Clone, Copy)]
pub struct ActivationSummary {
    /// Number of tokens marked invalid by this activation. Always `0`
    /// when `was_already_active == true` (idempotent no-op).
    pub tokens_invalidated: usize,
    /// When the activation was observed (RFC 3339 UTC).
    pub activated_at: DateTime<Utc>,
    /// Whether the switch was already active when this call was made.
    pub was_already_active: bool,
}

/// Return value from [`KillSwitch::deactivate`].
#[derive(Debug, Clone, Copy)]
pub struct DeactivationSummary {
    /// When the resume was observed (RFC 3339 UTC).
    pub resumed_at: DateTime<Utc>,
    /// Whether the switch was already inactive when this call was made.
    pub was_already_inactive: bool,
}

/// The kill-switch state machine.
///
/// Owns the atomic flag, the in-memory scoped-token registry, the
/// activation timestamp, and the broadcast channel. Typically held
/// as `Arc<KillSwitch>` and cloned into every middleware / CLI
/// consumer that needs to read or toggle the state.
///
/// # Lock hierarchy
///
/// There are three mutexes on `KillSwitch`, acquired in this strict
/// order to prevent deadlock:
///
/// 1. `transition` — held for the entire duration of `activate()` /
///    `deactivate()`. Serializes state transitions so the
///    `(active, activated_at, registry flush, broadcast)` tuple
///    updates atomically. Fast readers (`is_active()`,
///    `is_token_valid()`, `activated_at()`) do NOT take this lock —
///    they read through the atomic + per-field mutexes directly.
/// 2. `registry` — held for per-call read/write on the token map.
///    Never held across a `.await` point.
/// 3. `activated_at_guard` — held for per-call read/write on the
///    activation timestamp.
///
/// Within `activate()`/`deactivate()` the order of acquisition after
/// `transition` is: update `active` → write `activated_at_guard` →
/// flush `registry` → broadcast. Readers that touch only one field
/// at a time see monotonically consistent state; readers that touch
/// multiple fields (e.g. middleware reading `is_active()` then
/// `activated_at()`) may see an intermediate value during a
/// transition, which is tolerated by the middleware's
/// `unwrap_or_else(Utc::now)` fallback.
pub struct KillSwitch {
    active: AtomicBool,
    registry: Mutex<HashMap<TokenId, TokenInfo>>,
    activated_at_guard: Mutex<Option<DateTime<Utc>>>,
    notifier: broadcast::Sender<KillEvent>,
    /// Serializes `activate()` / `deactivate()` so the full state
    /// transition (`active` flip, `activated_at` store, registry
    /// flush, broadcast) happens as one unit. Without this, concurrent
    /// `activate() + deactivate()` calls could emit events in the
    /// wrong causal order (`Resumed` before `Activated`) or leave
    /// `(active=false, activated_at=Some)` observable.
    transition: Mutex<()>,
}

impl std::fmt::Debug for KillSwitch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // IMPORTANT: Debug is invoked by panic messages, tracing span
        // fields, and assert!/debug_assert! on Self. std::sync::Mutex
        // is non-reentrant, so any path that formats `KillSwitch`
        // while already holding one of its mutexes will deadlock.
        //
        // We read through `try_lock()` ONLY. On contention we emit a
        // placeholder rather than blocking. `active` is an atomic
        // (no lock needed).
        let active = self.active.load(Ordering::Acquire);
        let token_count: Box<dyn std::fmt::Debug> = match self.registry.try_lock() {
            Ok(g) => Box::new(g.len()),
            Err(_) => Box::new("<locked>"),
        };
        let activated_at: Box<dyn std::fmt::Debug> = match self.activated_at_guard.try_lock() {
            Ok(g) => Box::new(*g),
            Err(_) => Box::new("<locked>"),
        };
        f.debug_struct("KillSwitch")
            .field("active", &active)
            .field("token_count", &token_count)
            .field("activated_at", &activated_at)
            .finish()
    }
}

impl Default for KillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

impl KillSwitch {
    /// Create a fresh kill switch in the inactive state with an empty
    /// token registry and a broadcast channel of capacity 64.
    #[must_use]
    pub fn new() -> Self {
        let (notifier, _keep_alive_rx) = broadcast::channel(64);
        // Drop the held receiver. `broadcast::channel` requires at
        // least one receiver at construction time, but the kill switch
        // doesn't need to consume its own events — subscribers are
        // wired externally via `subscribe()`. Dropping the receiver is
        // safe: the channel stays open as long as the `Sender` is alive.
        drop(_keep_alive_rx);
        Self {
            active: AtomicBool::new(false),
            registry: Mutex::new(HashMap::new()),
            activated_at_guard: Mutex::new(None),
            notifier,
            transition: Mutex::new(()),
        }
    }

    /// Return `true` if the kill switch is active.
    ///
    /// Uses `Ordering::Acquire` so an observer that sees `true` also
    /// observes every token-invalidation write that happened-before
    /// `activate()` published the flip.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// Return the timestamp the switch most recently became active,
    /// or `None` if it is currently inactive.
    #[must_use]
    pub fn activated_at(&self) -> Option<DateTime<Utc>> {
        let guard = match self.activated_at_guard.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!(
                    target: "killswitch",
                    "activated_at mutex was poisoned; recovering"
                );
                poisoned.into_inner()
            }
        };
        *guard
    }

    /// Register a scoped token in the in-memory registry.
    ///
    /// # Kill-state rejection
    ///
    /// Returns `Err(KillSwitchError::RegisterWhileActive)` if the kill
    /// switch is active. Registering a new token while killed would
    /// create a dangling token that survives the next `deactivate()`
    /// call, violating the "once invalidated, stays invalidated"
    /// security invariant. Callers must re-issue the token after
    /// `agentsso resume`.
    ///
    /// # Collision handling
    ///
    /// If a token with the same id already exists in the registry,
    /// the existing entry's `invalidated` flag is PRESERVED — the new
    /// `TokenInfo` adopts the old token's invalidation state. This
    /// prevents a targeted `invalidate_token()` from being silently
    /// reversed by a subsequent re-registration. If the previous
    /// token was invalidated, the new one is inserted as invalidated
    /// too; if the previous was valid, the new one is valid.
    ///
    /// The replacement is otherwise "last writer wins" for the
    /// metadata fields (`agent_id`, `service`, `scope`, `issued_at`).
    pub fn register_token(&self, id: TokenId, info: TokenInfo) -> Result<(), KillSwitchError> {
        if self.is_active() {
            return Err(KillSwitchError::RegisterWhileActive);
        }
        let mut guard = match self.registry.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!(
                    target: "killswitch",
                    "registry mutex was poisoned; recovering"
                );
                poisoned.into_inner()
            }
        };
        // Preserve the previous invalidation state on collision.
        // This closes the "overwrite resurrects an invalidated token"
        // attack discovered in Story 3.1 code review.
        let preserved_invalidated = guard
            .get(&id)
            .map(|existing| existing.invalidated.load(Ordering::Acquire))
            .unwrap_or(false);
        if preserved_invalidated {
            info.invalidated.store(true, Ordering::Release);
        }
        guard.insert(id, info);
        Ok(())
    }

    /// Mark a specific token invalid without removing it.
    ///
    /// Returns `true` if the token existed in the registry, `false`
    /// otherwise. Does not remove the entry (post-incident forensics).
    pub fn invalidate_token(&self, id: &TokenId) -> bool {
        let guard = match self.registry.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!(
                    target: "killswitch",
                    "registry mutex was poisoned; recovering"
                );
                poisoned.into_inner()
            }
        };
        if let Some(info) = guard.get(id) {
            info.invalidated.store(true, Ordering::Release);
            true
        } else {
            false
        }
    }

    /// Return `true` if the token is present AND not invalidated AND
    /// the kill switch is not active.
    ///
    /// The short-circuit on `is_active()` is the load-bearing
    /// security invariant — a token is invalid in kill state even if
    /// it was never registered.
    #[must_use]
    pub fn is_token_valid(&self, id: &TokenId) -> bool {
        if self.is_active() {
            return false;
        }
        let guard = match self.registry.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!(
                    target: "killswitch",
                    "registry mutex was poisoned; recovering"
                );
                poisoned.into_inner()
            }
        };
        guard.get(id).is_some_and(|info| !info.invalidated.load(Ordering::Acquire))
    }

    /// Number of tokens currently in the registry (valid + invalid).
    #[must_use]
    pub fn token_count(&self) -> usize {
        let guard = match self.registry.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!(
                    target: "killswitch",
                    "registry mutex was poisoned; recovering"
                );
                poisoned.into_inner()
            }
        };
        guard.len()
    }

    /// Subscribe to the broadcast channel to observe future
    /// `KillEvent::Activated` / `KillEvent::Resumed` messages.
    ///
    /// Messages published before the subscription are NOT replayed.
    /// Receivers that lag more than 64 messages behind will get
    /// `RecvError::Lagged(n)` — that is a normal error condition, not
    /// a bug.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<KillEvent> {
        self.notifier.subscribe()
    }

    /// Flip the switch to active, invalidate every registered token,
    /// record the activation timestamp, and broadcast `KillEvent::Activated`.
    ///
    /// Idempotent: a second activation on an already-active switch is
    /// a no-op — no broadcast, no re-iteration of the registry, and
    /// `ActivationSummary.was_already_active == true`.
    ///
    /// # Transition atomicity
    ///
    /// The entire transition (`active` flip → `activated_at` store →
    /// registry flush → broadcast) runs under the `transition` mutex
    /// so that concurrent `activate()`/`deactivate()` calls serialize
    /// properly. Without this, an interleaved
    /// `activate() → deactivate()` could produce impossible states
    /// like `(active=false, activated_at=Some(stale))` or broadcast
    /// events in the wrong causal order (`Resumed` before
    /// `Activated`). Fast readers (`is_active()`, `is_token_valid()`)
    /// do not take this lock — they read through the atomic directly.
    pub fn activate(&self, reason: KillReason) -> ActivationSummary {
        let _transition_guard = self.acquire_transition();
        let now = Utc::now();

        // Atomic swap captures both the "was already active" signal
        // and the "am active now" commit. Using `Release` semantics
        // so any observer that sees `true` via `Acquire` also sees
        // the invalidation writes below.
        let was_already_active = self.active.swap(true, Ordering::Release);

        if was_already_active {
            return ActivationSummary {
                tokens_invalidated: 0,
                activated_at: now,
                was_already_active: true,
            };
        }

        // Store the activation timestamp under the transition lock
        // so readers that observe `active == true` can subsequently
        // observe a fresh `activated_at` after the transition
        // completes. Between the atomic flip and this store, a
        // reader may see `Some(stale)` from a previous cycle (cleared
        // by the matching deactivate) or `None` if this is the first
        // activation — the middleware handles both via
        // `unwrap_or_else(Utc::now)` as defense-in-depth.
        {
            let mut guard = match self.activated_at_guard.lock() {
                Ok(g) => g,
                Err(poisoned) => {
                    tracing::warn!(
                        target: "killswitch",
                        "activated_at mutex was poisoned; recovering"
                    );
                    poisoned.into_inner()
                }
            };
            *guard = Some(now);
        }

        // Flush the registry — flip every token's invalidated flag.
        let tokens_invalidated = {
            let guard = match self.registry.lock() {
                Ok(g) => g,
                Err(poisoned) => {
                    tracing::warn!(
                        target: "killswitch",
                        "registry mutex was poisoned; recovering"
                    );
                    poisoned.into_inner()
                }
            };
            let mut count = 0usize;
            for info in guard.values() {
                // Skip already-invalidated tokens so the count
                // reflects only the tokens this activation newly
                // invalidated. A previously-targeted invalidation
                // via `invalidate_token()` does not double-count.
                if !info.invalidated.swap(true, Ordering::Release) {
                    count += 1;
                }
            }
            count
        };

        // Broadcast — receiver count of 0 is a normal runtime state
        // (Story 3.2 wires the receiver), so `send()` errors are
        // swallowed. The `let _ =` is deliberate; `.unwrap()` would
        // violate the workspace `unwrap_used = deny` clippy gate.
        let _ = self.notifier.send(KillEvent::Activated { at: now, reason });

        ActivationSummary { tokens_invalidated, activated_at: now, was_already_active: false }
    }

    /// Flip the switch to inactive, clear the activation timestamp,
    /// and broadcast `KillEvent::Resumed`.
    ///
    /// Idempotent: a second deactivation on an already-inactive switch
    /// is a no-op — no broadcast, `DeactivationSummary.was_already_inactive
    /// == true`.
    ///
    /// **Does not re-validate previously-invalidated tokens.** This is
    /// a deliberate security invariant: operators must re-issue scoped
    /// tokens after `agentsso resume` rather than inherit dangling ones.
    ///
    /// Transition atomicity is provided by the same `transition` mutex
    /// used by [`activate`](Self::activate) — see that method's docs.
    pub fn deactivate(&self) -> DeactivationSummary {
        let _transition_guard = self.acquire_transition();
        let now = Utc::now();
        let was_active = self.active.swap(false, Ordering::Release);

        if !was_active {
            return DeactivationSummary { resumed_at: now, was_already_inactive: true };
        }

        // Clear the stored activation timestamp.
        {
            let mut guard = match self.activated_at_guard.lock() {
                Ok(g) => g,
                Err(poisoned) => {
                    tracing::warn!(
                        target: "killswitch",
                        "activated_at mutex was poisoned; recovering"
                    );
                    poisoned.into_inner()
                }
            };
            *guard = None;
        }

        let _ = self.notifier.send(KillEvent::Resumed { at: now });

        DeactivationSummary { resumed_at: now, was_already_inactive: false }
    }

    /// Acquire the transition mutex, recovering from poisoning by
    /// extracting the inner guard and logging a warning. The guard
    /// carries no state — it is a pure mutual-exclusion token — so
    /// poisoning has no data-corruption risk.
    fn acquire_transition(&self) -> std::sync::MutexGuard<'_, ()> {
        match self.transition.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!(
                    target: "killswitch",
                    "transition mutex was poisoned; recovering"
                );
                poisoned.into_inner()
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;
    use tokio::sync::broadcast::error::TryRecvError;

    assert_impl_all!(KillSwitch: Send, Sync);

    fn sample_token(service: &str) -> (TokenId, TokenInfo) {
        let id = TokenId::new(format!("tok-{service}-abc")).unwrap();
        let info = TokenInfo::new("agent-1", service, format!("{service}.readonly"), Utc::now());
        (id, info)
    }

    #[test]
    fn new_is_inactive_and_empty() {
        let switch = KillSwitch::new();
        assert!(!switch.is_active());
        assert_eq!(switch.token_count(), 0);
        assert!(switch.activated_at().is_none());
    }

    #[test]
    fn register_and_lookup_token() {
        let switch = KillSwitch::new();
        let (id, info) = sample_token("gmail");
        switch.register_token(id.clone(), info).expect("register while inactive");
        assert_eq!(switch.token_count(), 1);
        assert!(switch.is_token_valid(&id));
    }

    #[test]
    fn invalidate_nonexistent_returns_false() {
        let switch = KillSwitch::new();
        let unknown = TokenId::new("nope").unwrap();
        assert!(!switch.invalidate_token(&unknown));
    }

    #[test]
    fn targeted_invalidation_marks_token_invalid() {
        let switch = KillSwitch::new();
        let (id, info) = sample_token("calendar");
        switch.register_token(id.clone(), info).expect("register while inactive");
        assert!(switch.is_token_valid(&id));

        assert!(switch.invalidate_token(&id));
        assert!(!switch.is_token_valid(&id));
    }

    #[tokio::test]
    async fn activate_flips_flag_and_broadcasts() {
        let switch = KillSwitch::new();
        let (id, info) = sample_token("drive");
        switch.register_token(id.clone(), info).expect("register while inactive");

        let mut rx = switch.subscribe();

        let summary = switch.activate(KillReason::UserInitiated);
        assert!(switch.is_active());
        assert!(!switch.is_token_valid(&id));
        assert_eq!(summary.tokens_invalidated, 1);
        assert!(!summary.was_already_active);

        let event = rx.recv().await.expect("receiver should get the activation event");
        match event {
            KillEvent::Activated { reason, .. } => {
                assert_eq!(reason, KillReason::UserInitiated);
            }
            other => panic!("expected Activated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn activate_is_idempotent() {
        let switch = KillSwitch::new();
        let (id, info) = sample_token("gmail");
        switch.register_token(id, info).expect("register while inactive");

        let mut rx = switch.subscribe();

        let first = switch.activate(KillReason::UserInitiated);
        assert!(!first.was_already_active);
        assert_eq!(first.tokens_invalidated, 1);

        let second = switch.activate(KillReason::UserInitiated);
        assert!(second.was_already_active);
        assert_eq!(second.tokens_invalidated, 0);

        // Exactly ONE broadcast message should be present despite
        // two activate() calls. Yield once to let the broadcast task
        // deliver, then try_recv.
        tokio::task::yield_now().await;
        let first_event = rx.try_recv().expect("first activation should broadcast");
        assert!(matches!(first_event, KillEvent::Activated { .. }));
        assert_eq!(
            rx.try_recv(),
            Err(TryRecvError::Empty),
            "second activate() must not re-broadcast"
        );
    }

    #[tokio::test]
    async fn deactivate_after_activate() {
        let switch = KillSwitch::new();
        let mut rx = switch.subscribe();

        switch.activate(KillReason::UserInitiated);
        let summary = switch.deactivate();
        assert!(!switch.is_active());
        assert!(!summary.was_already_inactive);

        // Drain both messages in order.
        let first = rx.recv().await.unwrap();
        assert!(matches!(first, KillEvent::Activated { .. }));
        let second = rx.recv().await.unwrap();
        assert!(matches!(second, KillEvent::Resumed { .. }));
    }

    #[test]
    fn deactivate_is_idempotent() {
        let switch = KillSwitch::new();
        let first = switch.deactivate();
        assert!(first.was_already_inactive);

        switch.activate(KillReason::UserInitiated);
        let second = switch.deactivate();
        assert!(!second.was_already_inactive);

        let third = switch.deactivate();
        assert!(third.was_already_inactive);
    }

    #[test]
    fn deactivate_does_not_revalidate_tokens() {
        let switch = KillSwitch::new();
        let (id, info) = sample_token("gmail");
        switch.register_token(id.clone(), info).expect("register while inactive");

        switch.activate(KillReason::UserInitiated);
        assert!(!switch.is_token_valid(&id));

        switch.deactivate();
        assert!(
            !switch.is_token_valid(&id),
            "once invalidated, a token must stay invalidated across deactivate() — security invariant"
        );
    }

    #[test]
    fn token_id_rejects_empty_string() {
        let err = TokenId::new("").unwrap_err();
        assert!(matches!(err, KillSwitchError::InvalidTokenId));
    }

    #[test]
    fn token_id_accepts_non_empty() {
        let id = TokenId::new("01HTEST").unwrap();
        assert_eq!(id.as_str(), "01HTEST");
    }

    #[test]
    fn activated_at_tracks_activate_and_deactivate() {
        let switch = KillSwitch::new();
        assert!(switch.activated_at().is_none());

        let before = Utc::now();
        switch.activate(KillReason::UserInitiated);
        let first = switch.activated_at().expect("should be Some after activate");
        assert!(first >= before, "activated_at must be >= now at activation time");

        switch.deactivate();
        assert!(switch.activated_at().is_none(), "deactivate must clear activated_at");

        // Re-activation yields a later timestamp.
        std::thread::sleep(std::time::Duration::from_millis(2));
        switch.activate(KillReason::UserInitiated);
        let second = switch.activated_at().expect("should be Some after re-activate");
        assert!(second > first, "re-activation should update the timestamp");
    }

    #[tokio::test]
    async fn concurrent_register_does_not_deadlock() {
        use std::sync::Arc;
        let switch = Arc::new(KillSwitch::new());
        let mut handles = Vec::new();
        for worker in 0..8 {
            let s = Arc::clone(&switch);
            handles.push(tokio::task::spawn_blocking(move || {
                for i in 0..100 {
                    let id = TokenId::new(format!("w{worker}-tok{i}")).unwrap();
                    let info = TokenInfo::new("agent-1", "gmail", "gmail.readonly", Utc::now());
                    s.register_token(id, info).expect("register while inactive");
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(switch.token_count(), 800);
    }

    // ----- Code review patches (2026-04-11) -----

    /// Review finding #1 (HIGH): `register_token` must reject when
    /// the kill switch is active, so a dangling token can't survive
    /// the next `deactivate()` call.
    #[test]
    fn register_token_fails_while_active() {
        let switch = KillSwitch::new();
        switch.activate(KillReason::UserInitiated);

        let (id, info) = sample_token("gmail");
        let err = switch.register_token(id, info).expect_err("must reject during kill");
        assert_eq!(err, KillSwitchError::RegisterWhileActive);
        assert_eq!(switch.token_count(), 0, "no token should have been inserted");
    }

    /// Review finding #1 (HIGH): re-registering a previously
    /// invalidated token must preserve the `invalidated` flag so a
    /// targeted `invalidate_token()` can't be silently reversed by a
    /// subsequent `register_token()` call with the same id.
    #[test]
    fn register_token_preserves_invalidated_state_on_collision() {
        let switch = KillSwitch::new();
        let id = TokenId::new("tok-collision").unwrap();

        let first_info = TokenInfo::new("agent-1", "gmail", "gmail.readonly", Utc::now());
        switch.register_token(id.clone(), first_info).expect("first register");
        assert!(switch.is_token_valid(&id));

        // Targeted invalidation.
        assert!(switch.invalidate_token(&id));
        assert!(!switch.is_token_valid(&id));

        // Re-register with the same id. The new TokenInfo is fresh
        // (invalidated = false), but register_token must preserve
        // the previous invalidation state.
        let second_info = TokenInfo::new("agent-2", "drive", "drive.readonly", Utc::now());
        switch.register_token(id.clone(), second_info).expect("second register while inactive");

        assert!(
            !switch.is_token_valid(&id),
            "re-registering an invalidated token must preserve its invalidated flag"
        );
    }

    /// Review finding #2 (HIGH): concurrent `activate()` and
    /// `deactivate()` must not produce impossible observable states
    /// like `(active=false, activated_at=Some)`, and broadcast events
    /// must arrive in causal order. The `transition` mutex serializes
    /// the pair.
    #[tokio::test]
    async fn concurrent_activate_deactivate_preserves_consistency() {
        use std::sync::Arc;
        let switch = Arc::new(KillSwitch::new());

        // Kick off N pairs of concurrent activate/deactivate calls
        // from different tasks. The final state must be one of the
        // four legal observable pairs:
        //   (active=false, activated_at=None)  — the "quiescent" state
        //   (active=true,  activated_at=Some)  — killed and published
        // Any of the other two pairs would prove the race exists.
        let mut handles = Vec::new();
        for _ in 0..32 {
            let s = Arc::clone(&switch);
            handles.push(tokio::task::spawn_blocking(move || {
                s.activate(KillReason::UserInitiated);
            }));
            let s = Arc::clone(&switch);
            handles.push(tokio::task::spawn_blocking(move || {
                s.deactivate();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        // Sample the final state and check the invariant.
        let is_active = switch.is_active();
        let at = switch.activated_at();
        match (is_active, at.is_some()) {
            (false, false) | (true, true) => { /* legal */ }
            (false, true) => panic!(
                "IMPOSSIBLE STATE: active=false but activated_at={:?} — race between activate/deactivate",
                at
            ),
            (true, false) => {
                // Brief window during activation between the atomic
                // flip and the timestamp store is tolerated by the
                // middleware's Utc::now() fallback — but only if the
                // transition lock is held and no other transition
                // can have already finished. Since we await ALL
                // handles before sampling, no transition is in flight
                // at the sample point, so this state is impossible.
                panic!("active=true but activated_at=None after all transitions settled");
            }
        }
    }

    /// Review finding #7 (LOW): explicit positive-pair test for the
    /// "is_active implies token invalid" invariant, covered
    /// implicitly by `activate_flips_flag_and_broadcasts` but spec
    /// Task 1 asked for a dedicated test by name.
    #[test]
    fn is_active_implies_token_invalid() {
        let switch = KillSwitch::new();
        let (id, info) = sample_token("gmail");
        switch.register_token(id.clone(), info).expect("register while inactive");

        assert!(switch.is_token_valid(&id), "baseline: token is valid before kill");

        switch.activate(KillReason::UserInitiated);
        assert!(switch.is_active());
        assert!(
            !switch.is_token_valid(&id),
            "is_active == true implies every registered token is invalid"
        );
    }
}
