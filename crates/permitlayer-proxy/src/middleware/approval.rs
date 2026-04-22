//! Approval service trait (Story 4.5).
//!
//! This module defines the abstraction `PolicyLayer` uses to block on a
//! human-in-the-loop decision when `PolicySet::evaluate` returns
//! `Decision::Prompt`. The production implementor is
//! `permitlayer_daemon::approval::CliApprovalService`, which renders a
//! `dialoguer::Select` prompt on the daemon's controlling terminal.
//!
//! # Dependency direction
//!
//! `permitlayer-proxy` declares the trait, the request/outcome types,
//! and the fail-closed `AlwaysDenyApprovalService` default — but it
//! contains **no terminal I/O**. Terminal ownership lives in
//! `permitlayer-daemon::approval`. This keeps the proxy crate free of
//! stdio concerns and keeps `permitlayer-core` free of both (ADR 0002).
//!
//! # Outcome taxonomy
//!
//! [`ApprovalOutcome`] has eight variants so the cache-hit path is a
//! first-class signal rather than an out-of-band side channel. The two
//! `*Cached` variants let `PolicyLayer` stamp `cached = true` on audit
//! events without any bookkeeping.
//!
//! # Serialization invariant
//!
//! Any implementor that wraps a TTY MUST serialize concurrent
//! `request_approval` calls — stdin is shared mutable state and two
//! awaited readers would race. The production `CliApprovalService`
//! satisfies this via an mpsc channel that feeds a single prompt task.

use std::time::Duration;

use async_trait::async_trait;

/// Input to [`ApprovalService::request_approval`].
///
/// Carries the request identity, the policy/rule that fired the prompt,
/// and the timeout the caller wants applied. The timeout is
/// request-scoped (rather than trait-level) so per-policy timeout
/// overrides can be added in a future story without changing the
/// constructor surface of every implementor.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    /// Request ID from `RequestTraceLayer`, threaded through for audit
    /// correlation (Story 3.3 retro pattern #3).
    pub request_id: String,
    /// Agent identifier stamped by `AuthLayer`.
    pub agent_id: String,
    /// Derived upstream service name (`gmail`, `calendar`, `drive`, `-`).
    pub service: String,
    /// The OAuth scope the request targets.
    pub scope: String,
    /// The resource identifier the request targets, when one applies.
    pub resource: Option<String>,
    /// Policy that produced the `Decision::Prompt` outcome.
    pub policy_name: String,
    /// Stable string ID of the rule that fired the prompt. Either a
    /// rule-level ID or the well-known `"default-prompt-approval-mode"`
    /// for policy-level `approval-mode = "prompt"` fall-through.
    pub rule_id: String,
    /// Maximum time the caller will wait for the operator's decision.
    pub timeout: Duration,
}

/// Outcome of an approval request.
///
/// `#[non_exhaustive]` so future variants (e.g., `OperatorDeferred` for
/// an out-of-band approval queue) can be added without a breaking
/// change. Callers MUST have a wildcard arm.
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum ApprovalOutcome {
    /// Operator approved this single request (`y`).
    Granted,
    /// Operator approved this request AND asked to remember the
    /// decision for all future requests matching the same
    /// `(policy_name, rule_id)` in the current session (`a`).
    AlwaysAllowThisSession { rule_id: String },
    /// Cached hit on a prior `AlwaysAllowThisSession` decision. The
    /// operator was not prompted.
    AlwaysAllowCached { rule_id: String },
    /// Operator denied this single request (`n`).
    Denied,
    /// Operator denied this request AND asked to remember the
    /// denial for all future requests matching the same
    /// `(policy_name, rule_id)` in the current session (`never`).
    NeverAllow { rule_id: String },
    /// Cached hit on a prior `NeverAllow` decision. The operator was
    /// not prompted.
    NeverAllowCached { rule_id: String },
    /// Operator did not respond within the configured timeout.
    Timeout,
    /// The approval service is structurally unable to prompt (no
    /// controlling TTY, daemon shutting down, reader thread panicked).
    Unavailable,
}

impl ApprovalOutcome {
    /// Returns `true` when the outcome should let the request proceed.
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(
            self,
            Self::Granted | Self::AlwaysAllowThisSession { .. } | Self::AlwaysAllowCached { .. }
        )
    }

    /// Returns `true` when the outcome came from the session cache
    /// (no interactive prompt was shown).
    #[must_use]
    pub fn is_cached(&self) -> bool {
        matches!(self, Self::AlwaysAllowCached { .. } | Self::NeverAllowCached { .. })
    }
}

/// Abstraction over the mechanism that surfaces an
/// `Decision::Prompt` outcome to a human operator.
///
/// Implementors MUST:
/// - Be `Send + Sync + 'static` so `Arc<dyn ApprovalService>` can be
///   shared across tower service clones.
/// - Serialize concurrent calls if they touch shared TTY state.
/// - Return [`ApprovalOutcome::Unavailable`] (not block indefinitely)
///   when the underlying prompt surface is gone.
#[async_trait]
pub trait ApprovalService: Send + Sync + 'static {
    /// Block the caller until the operator decides (or times out).
    async fn request_approval(&self, req: ApprovalRequest) -> ApprovalOutcome;

    /// Drop all remembered `AlwaysAllowThisSession` / `NeverAllow`
    /// decisions. Called from the SIGHUP reload path so policy edits
    /// take immediate effect.
    ///
    /// Synchronous because the underlying primitive is a `DashMap` /
    /// `Mutex<HashMap>` clear with no await points. Making it async
    /// would force the SIGHUP handler into an async context for no
    /// benefit.
    fn clear_caches(&self);

    /// Short static identifier used by startup logs to distinguish the
    /// three modes (`cli-tty`, `no-tty`, `test-canned`). Override in
    /// implementors; default is the generic `"approval-service"`.
    fn describe(&self) -> &'static str {
        "approval-service"
    }
}

// ──────────────────────────────────────────────────────────────────
// Built-in implementors
// ──────────────────────────────────────────────────────────────────

/// Fail-closed approval service used by unit tests and as the default
/// when no real implementor is wired up.
///
/// Every `request_approval` call returns
/// [`ApprovalOutcome::Unavailable`] synchronously. Matches the
/// production `NoTtyApprovalService` semantics — `PolicyLayer` treats
/// `Unavailable` as HTTP 503 `policy.approval_unavailable`.
#[derive(Debug, Default)]
pub struct AlwaysDenyApprovalService;

impl AlwaysDenyApprovalService {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ApprovalService for AlwaysDenyApprovalService {
    async fn request_approval(&self, _req: ApprovalRequest) -> ApprovalOutcome {
        ApprovalOutcome::Unavailable
    }

    fn clear_caches(&self) {
        // No state to clear.
    }

    fn describe(&self) -> &'static str {
        "always-deny"
    }
}

/// Test-only approval service that pops canned outcomes off a queue.
///
/// Each call to `request_approval` consumes the next
/// [`ApprovalOutcome`] from the provided `VecDeque`. When the queue is
/// empty, returns [`ApprovalOutcome::Unavailable`] so under-specified
/// tests fail closed instead of hanging. The `always_cache` /
/// `never_cache` remembered decisions are tracked just like
/// `CliApprovalService` so tests can verify cache semantics without
/// requiring a live TTY.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct MockApprovalService {
    decisions: std::sync::Mutex<std::collections::VecDeque<ApprovalOutcome>>,
    always_cache: std::sync::Mutex<std::collections::HashSet<(String, String)>>,
    never_cache: std::sync::Mutex<std::collections::HashSet<(String, String)>>,
    call_count: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl MockApprovalService {
    /// Build a mock that pops outcomes off the supplied queue in order.
    #[must_use]
    pub fn with_decisions(decisions: Vec<ApprovalOutcome>) -> Self {
        Self {
            decisions: std::sync::Mutex::new(decisions.into_iter().collect()),
            always_cache: std::sync::Mutex::new(std::collections::HashSet::new()),
            never_cache: std::sync::Mutex::new(std::collections::HashSet::new()),
            call_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Number of times `request_approval` has been invoked.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.call_count.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Remaining canned outcomes in the queue.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.decisions.lock().map(|q| q.len()).unwrap_or(0)
    }
}

#[cfg(test)]
#[async_trait]
impl ApprovalService for MockApprovalService {
    async fn request_approval(&self, req: ApprovalRequest) -> ApprovalOutcome {
        self.call_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let key = (req.policy_name.clone(), req.rule_id.clone());

        // Consult caches first (mirrors CliApprovalService semantics).
        if self.never_cache.lock().map(|c| c.contains(&key)).unwrap_or(false) {
            return ApprovalOutcome::NeverAllowCached { rule_id: req.rule_id };
        }
        if self.always_cache.lock().map(|c| c.contains(&key)).unwrap_or(false) {
            return ApprovalOutcome::AlwaysAllowCached { rule_id: req.rule_id };
        }

        // Pop the next canned outcome.
        let outcome = self
            .decisions
            .lock()
            .ok()
            .and_then(|mut q| q.pop_front())
            .unwrap_or(ApprovalOutcome::Unavailable);

        // Populate caches on first-seen always/never responses.
        match &outcome {
            ApprovalOutcome::AlwaysAllowThisSession { .. } => {
                if let Ok(mut c) = self.always_cache.lock() {
                    c.insert(key);
                }
            }
            ApprovalOutcome::NeverAllow { .. } => {
                if let Ok(mut c) = self.never_cache.lock() {
                    c.insert(key);
                }
            }
            _ => {}
        }
        outcome
    }

    fn clear_caches(&self) {
        if let Ok(mut c) = self.always_cache.lock() {
            c.clear();
        }
        if let Ok(mut c) = self.never_cache.lock() {
            c.clear();
        }
    }

    fn describe(&self) -> &'static str {
        "mock"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn sample_req(policy: &str, rule: &str) -> ApprovalRequest {
        ApprovalRequest {
            request_id: "req-1".to_owned(),
            agent_id: "test-agent".to_owned(),
            service: "gmail".to_owned(),
            scope: "gmail.modify".to_owned(),
            resource: None,
            policy_name: policy.to_owned(),
            rule_id: rule.to_owned(),
            timeout: Duration::from_secs(30),
        }
    }

    #[tokio::test]
    async fn always_deny_returns_unavailable() {
        let svc = AlwaysDenyApprovalService::new();
        let outcome = svc.request_approval(sample_req("p", "r")).await;
        assert_eq!(outcome, ApprovalOutcome::Unavailable);
        assert_eq!(svc.describe(), "always-deny");
        svc.clear_caches(); // no panic
    }

    #[tokio::test]
    async fn mock_returns_canned_outcomes_in_order() {
        let svc = MockApprovalService::with_decisions(vec![
            ApprovalOutcome::Granted,
            ApprovalOutcome::Denied,
            ApprovalOutcome::Timeout,
        ]);
        assert_eq!(svc.request_approval(sample_req("p", "r1")).await, ApprovalOutcome::Granted);
        assert_eq!(svc.request_approval(sample_req("p", "r2")).await, ApprovalOutcome::Denied);
        assert_eq!(svc.request_approval(sample_req("p", "r3")).await, ApprovalOutcome::Timeout);
        assert_eq!(svc.call_count(), 3);
        assert_eq!(svc.remaining(), 0);
    }

    #[tokio::test]
    async fn mock_empty_queue_returns_unavailable() {
        let svc = MockApprovalService::with_decisions(vec![]);
        let outcome = svc.request_approval(sample_req("p", "r")).await;
        assert_eq!(outcome, ApprovalOutcome::Unavailable);
    }

    #[tokio::test]
    async fn mock_populates_always_cache_on_always_outcome() {
        let svc = MockApprovalService::with_decisions(vec![
            ApprovalOutcome::AlwaysAllowThisSession { rule_id: "r".to_owned() },
            // The second call should NOT consume this — it should hit the cache first.
            ApprovalOutcome::Denied,
        ]);
        let first = svc.request_approval(sample_req("p", "r")).await;
        assert!(matches!(first, ApprovalOutcome::AlwaysAllowThisSession { .. }));
        let second = svc.request_approval(sample_req("p", "r")).await;
        assert!(matches!(second, ApprovalOutcome::AlwaysAllowCached { .. }));
        // The Denied outcome should still be in the queue.
        assert_eq!(svc.remaining(), 1);
    }

    #[tokio::test]
    async fn mock_populates_never_cache_on_never_outcome() {
        let svc = MockApprovalService::with_decisions(vec![
            ApprovalOutcome::NeverAllow { rule_id: "r".to_owned() },
            ApprovalOutcome::Granted,
        ]);
        let first = svc.request_approval(sample_req("p", "r")).await;
        assert!(matches!(first, ApprovalOutcome::NeverAllow { .. }));
        let second = svc.request_approval(sample_req("p", "r")).await;
        assert!(matches!(second, ApprovalOutcome::NeverAllowCached { .. }));
        assert_eq!(svc.remaining(), 1);
    }

    #[tokio::test]
    async fn mock_cache_is_policy_rule_scoped() {
        // A cache hit on (policy-A, rule-X) does NOT match (policy-B, rule-X).
        let svc = MockApprovalService::with_decisions(vec![
            ApprovalOutcome::AlwaysAllowThisSession { rule_id: "rule-x".to_owned() },
            ApprovalOutcome::Denied,
        ]);
        assert!(matches!(
            svc.request_approval(sample_req("policy-A", "rule-x")).await,
            ApprovalOutcome::AlwaysAllowThisSession { .. }
        ));
        // Different policy → cache miss → consumes next canned outcome.
        assert_eq!(
            svc.request_approval(sample_req("policy-B", "rule-x")).await,
            ApprovalOutcome::Denied
        );
    }

    #[tokio::test]
    async fn mock_clear_caches_empties_both() {
        let svc = MockApprovalService::with_decisions(vec![
            ApprovalOutcome::AlwaysAllowThisSession { rule_id: "r".to_owned() },
            ApprovalOutcome::NeverAllow { rule_id: "r2".to_owned() },
            ApprovalOutcome::Granted,
        ]);
        let _ = svc.request_approval(sample_req("p", "r")).await;
        let _ = svc.request_approval(sample_req("p", "r2")).await;
        svc.clear_caches();
        // Next call for rule "r" should consume the Granted outcome
        // rather than hit the (cleared) always cache.
        let outcome = svc.request_approval(sample_req("p", "r")).await;
        assert_eq!(outcome, ApprovalOutcome::Granted);
    }

    #[test]
    fn outcome_is_allow_true_for_granted_and_always() {
        assert!(ApprovalOutcome::Granted.is_allow());
        assert!(ApprovalOutcome::AlwaysAllowThisSession { rule_id: "r".to_owned() }.is_allow());
        assert!(ApprovalOutcome::AlwaysAllowCached { rule_id: "r".to_owned() }.is_allow());
    }

    #[test]
    fn outcome_is_allow_false_for_denied_timeout_unavailable_never() {
        assert!(!ApprovalOutcome::Denied.is_allow());
        assert!(!ApprovalOutcome::NeverAllow { rule_id: "r".to_owned() }.is_allow());
        assert!(!ApprovalOutcome::NeverAllowCached { rule_id: "r".to_owned() }.is_allow());
        assert!(!ApprovalOutcome::Timeout.is_allow());
        assert!(!ApprovalOutcome::Unavailable.is_allow());
    }

    #[test]
    fn outcome_is_cached_true_only_for_cached_variants() {
        assert!(ApprovalOutcome::AlwaysAllowCached { rule_id: "r".to_owned() }.is_cached());
        assert!(ApprovalOutcome::NeverAllowCached { rule_id: "r".to_owned() }.is_cached());
        assert!(!ApprovalOutcome::Granted.is_cached());
        assert!(!ApprovalOutcome::AlwaysAllowThisSession { rule_id: "r".to_owned() }.is_cached());
        assert!(!ApprovalOutcome::Denied.is_cached());
        assert!(!ApprovalOutcome::NeverAllow { rule_id: "r".to_owned() }.is_cached());
        assert!(!ApprovalOutcome::Timeout.is_cached());
        assert!(!ApprovalOutcome::Unavailable.is_cached());
    }
}
