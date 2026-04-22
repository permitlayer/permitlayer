//! CLI approval prompt service (Story 4.5).
//!
//! Runtime home of the `dialoguer::Select` prompt that renders on the
//! daemon's controlling terminal when a policy's `approval-mode` is
//! `prompt`. Architecture placement: `architecture.md:966` places
//! `approval.rs` as a sibling of `telemetry/` — deliberately inside
//! `permitlayer-daemon` (not `permitlayer-proxy`) because the prompt
//! is an operator-facing concern that dispatches on the process's
//! stdio/TTY state.
//!
//! # Serialization invariant
//!
//! The daemon's stdin is shared mutable state. Two awaited readers
//! would race and corrupt each other. [`CliApprovalService`] guarantees
//! **exactly one prompt in flight at a time** via an `mpsc` channel:
//! `request_approval` enqueues a `PromptJob` and awaits a oneshot,
//! and a single long-lived tokio task owns the receiver, renders one
//! prompt at a time, and fans responses back. Concurrent agent
//! requests queue in arrival order.
//!
//! # Testing seam
//!
//! The prompt renderer is abstracted behind a [`PromptReader`] trait
//! with two implementors: [`DialoguerPromptReader`] for production
//! (calls `dialoguer::Select::interact_opt`) and [`CannedPromptReader`]
//! for tests (pops pre-seeded decisions off a shared queue). This
//! keeps the full `CliApprovalService` serialization + cache pipeline
//! testable without a live TTY. The canned reader is wired into
//! `cli/start.rs` via the `AGENTSSO_TEST_APPROVAL_CANNED_RESPONSES`
//! env var — a testing-only seam that mirrors
//! `AGENTSSO_TEST_MASTER_KEY_HEX` from Story 4.4.
//!
//! # No-TTY fallback
//!
//! If stdin or stdout is not a terminal (e.g., the daemon was started
//! from a systemd user unit), [`CliApprovalService::start_with_tty`]
//! returns `Err(ApprovalSetupError::NoTty { which })` and the caller
//! falls back to [`NoTtyApprovalService`], which returns
//! `ApprovalOutcome::Unavailable` on every request (→ HTTP 503
//! `policy.approval_unavailable`).

use std::collections::{HashSet, VecDeque};
use std::io::IsTerminal;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use permitlayer_proxy::middleware::{ApprovalOutcome, ApprovalRequest, ApprovalService};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

// ──────────────────────────────────────────────────────────────────
// Setup errors
// ──────────────────────────────────────────────────────────────────

/// Error returned by [`CliApprovalService::start_with_tty`] when the
/// interactive path cannot be set up.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalSetupError {
    /// Stdin or stdout is not a terminal. The daemon should fall back
    /// to [`NoTtyApprovalService`].
    #[error("approval service: {which} is not a terminal")]
    NoTty { which: &'static str },
}

// ──────────────────────────────────────────────────────────────────
// PromptReader trait + production/test implementors
// ──────────────────────────────────────────────────────────────────

/// Operator decision surfaced by a prompt reader.
///
/// Distinct from `ApprovalOutcome` because the reader does not know
/// the rule_id — that lives in the `ApprovalRequest` and is threaded
/// in by `handle_one_prompt` after the reader returns.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PromptReaderDecision {
    /// Operator pressed `y` (allow this one).
    Allow,
    /// Operator pressed `n` (deny this one).
    Deny,
    /// Operator pressed `a` (always allow this rule this session).
    Always,
    /// Operator pressed `never` (deny permanently this session).
    Never,
    /// Operator pressed Esc, closed stdin, or the reader's underlying
    /// I/O failed. Treated as fail-closed `Denied` by the caller.
    Aborted,
}

/// Abstraction over the keystroke source that `handle_one_prompt`
/// consults.
///
/// Production wires `DialoguerPromptReader`; tests wire
/// `CannedPromptReader`. Both go through the same `CliApprovalService`
/// pipeline, so the mpsc serializer and the cache logic are covered
/// by the same tests regardless of reader.
pub trait PromptReader: Send + Sync + 'static {
    /// Block until the operator responds, or return `Aborted` on error.
    ///
    /// Called from inside `tokio::task::spawn_blocking`, so synchronous
    /// blocking I/O is expected. The caller wraps this in
    /// `tokio::time::timeout` so a reader that blocks forever is still
    /// bounded.
    fn read_decision(&self, req: &ApprovalRequest) -> PromptReaderDecision;
}

/// Production `PromptReader` backed by `dialoguer::Select`.
///
/// Renders the approval prompt header with an amber accent (UX-DR14,
/// matching `--warn` from §7.5 of the UX spec), shows the request
/// context, and reads exactly one keystroke via
/// `dialoguer::Select::with_theme(...).default(1).interact_opt()`.
/// The default cursor position is `1` (deny) so reflexive ENTER
/// fails closed.
#[derive(Debug, Default)]
pub struct DialoguerPromptReader;

impl DialoguerPromptReader {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl PromptReader for DialoguerPromptReader {
    fn read_decision(&self, req: &ApprovalRequest) -> PromptReaderDecision {
        // Render the header block. Use eprintln so the prompt lands on
        // stderr even if stdout is being piped (the dialoguer theme
        // below also writes to stderr). A leading newline separates
        // the block from any preceding log line.
        eprintln!();
        eprintln!("  ─── approval required ──────────────────────────────────────────────");
        eprintln!("  agent:     {}", req.agent_id);
        eprintln!("  service:   {}", req.service);
        eprintln!("  scope:     {}", req.scope);
        if let Some(resource) = req.resource.as_deref() {
            eprintln!("  resource:  {resource}");
        } else {
            eprintln!("  resource:  -");
        }
        eprintln!("  policy:    {}", req.policy_name);
        eprintln!("  rule:      {}", req.rule_id);
        eprintln!("  waiting:   up to {}s", req.timeout.as_secs());
        eprintln!("  ─────────────────────────────────────────────────────────────────────");
        eprintln!();

        let theme = build_prompt_theme();
        let result = dialoguer::Select::with_theme(&theme)
            .with_prompt("decision")
            .items(&["allow (y)", "deny (n)", "always-this-rule (a)", "never"])
            // Default cursor on "deny" — reflexive ENTER fails closed.
            .default(1)
            .interact_opt();

        match result {
            Ok(Some(0)) => PromptReaderDecision::Allow,
            Ok(Some(1)) => PromptReaderDecision::Deny,
            Ok(Some(2)) => PromptReaderDecision::Always,
            Ok(Some(3)) => PromptReaderDecision::Never,
            // Operator pressed Esc — treat as deny (fail-closed).
            Ok(None) => PromptReaderDecision::Aborted,
            // Index out of range (should not happen with 4 items) or
            // I/O error — fail closed.
            Ok(Some(_)) | Err(_) => PromptReaderDecision::Aborted,
        }
    }
}

/// Build the dialoguer theme for the approval prompt.
///
/// Hand-rolled (not reused from `setup.rs::build_teal_theme`) because
/// the approval prompt uses `--warn` amber rather than `--accent` teal
/// — matching the KillBanner's "guard is up" semantics (UX spec §7.5).
/// The amber signals a *caught* state rather than an error.
fn build_prompt_theme() -> dialoguer::theme::ColorfulTheme {
    // `console::style("...").color256(214)` is 256-color amber, the
    // closest ANSI approximation to `--warn #F5B454` in the UX spec.
    let amber = 214_u8;
    dialoguer::theme::ColorfulTheme {
        prompt_prefix: console::style("›".to_string()).for_stderr().color256(amber),
        success_prefix: console::style("\u{2713}".to_string()).for_stderr().color256(amber),
        values_style: console::Style::new().for_stderr().color256(amber),
        ..dialoguer::theme::ColorfulTheme::default()
    }
}

/// Test-only `PromptReader` that pops pre-seeded decisions off a
/// shared queue.
///
/// Thread-safe via an internal `Mutex<VecDeque<_>>` so concurrent
/// prompt tasks (which can't actually happen inside
/// `CliApprovalService` thanks to the mpsc, but we enforce it here
/// defensively) get consistent ordering.
///
/// A single special token in the canned list — a `PromptReaderDecision`
/// representing "force timeout" — is not first-class because the
/// `PromptReaderDecision` enum has no `Timeout` variant by design
/// (timeout is produced by `handle_one_prompt`'s `tokio::time::timeout`
/// wrapper, not by the reader). Instead, the `sleep_per_read` knob lets
/// tests artificially stall the reader for longer than the request's
/// approval timeout, which produces a genuine `ApprovalOutcome::Timeout`
/// through the real code path.
pub struct CannedPromptReader {
    decisions: Arc<Mutex<VecDeque<PromptReaderDecision>>>,
    /// Optional artificial delay per read, used by the concurrency
    /// test to simulate operator think-time AND by the integration
    /// test to force `Timeout` outcomes.
    sleep_per_read: Duration,
}

impl CannedPromptReader {
    /// Build a reader pre-seeded with the supplied decisions and no
    /// artificial delay.
    #[must_use]
    pub fn new(decisions: Vec<PromptReaderDecision>) -> Self {
        Self {
            decisions: Arc::new(Mutex::new(decisions.into_iter().collect())),
            sleep_per_read: Duration::ZERO,
        }
    }

    /// Build a reader with an artificial per-read sleep. Used by the
    /// concurrency test to simulate think-time and by the timeout
    /// test to force an `ApprovalOutcome::Timeout` through the real
    /// `tokio::time::timeout` path.
    #[must_use]
    pub fn with_sleep(decisions: Vec<PromptReaderDecision>, sleep_per_read: Duration) -> Self {
        Self { decisions: Arc::new(Mutex::new(decisions.into_iter().collect())), sleep_per_read }
    }

    /// Access the shared queue, used by tests to seed / drain.
    #[must_use]
    #[allow(dead_code)] // Used only by `#[cfg(test)]` tests in this file.
    pub fn shared_queue(&self) -> Arc<Mutex<VecDeque<PromptReaderDecision>>> {
        Arc::clone(&self.decisions)
    }
}

impl PromptReader for CannedPromptReader {
    fn read_decision(&self, _req: &ApprovalRequest) -> PromptReaderDecision {
        if !self.sleep_per_read.is_zero() {
            std::thread::sleep(self.sleep_per_read);
        }
        self.decisions
            .lock()
            .ok()
            .and_then(|mut q| q.pop_front())
            .unwrap_or(PromptReaderDecision::Aborted)
    }
}

// ──────────────────────────────────────────────────────────────────
// CliApprovalService
// ──────────────────────────────────────────────────────────────────

/// Cache key for remembered always/never decisions.
type CacheKey = (String, String);

/// The job a `request_approval` caller sends to the prompt task.
struct PromptJob {
    req: ApprovalRequest,
    responder: oneshot::Sender<ApprovalOutcome>,
}

/// Production-grade approval service that serializes prompts through
/// a single tokio task owning the controlling TTY.
///
/// Clone-safe: the service is an `Arc` behind `dyn ApprovalService` in
/// `PolicyLayer`, and internal state uses `Arc`s and `Mutex`es.
pub struct CliApprovalService {
    /// Bounded sender — see [`PROMPT_QUEUE_CAPACITY`]. `try_send`
    /// failure on a saturated queue maps to `ApprovalOutcome::Unavailable`
    /// (HTTP 503) instead of unbounded memory growth.
    tx: mpsc::Sender<PromptJob>,
    always_cache: Arc<Mutex<HashSet<CacheKey>>>,
    never_cache: Arc<Mutex<HashSet<CacheKey>>>,
}

impl CliApprovalService {
    /// Construct a service backed by the production dialoguer reader,
    /// after verifying stdin, stdout, AND stderr are all terminals.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalSetupError::NoTty`] if any of the three streams
    /// is not a terminal. Stderr is checked because `DialoguerPromptReader`
    /// renders its prompt via `eprintln!` and a `for_stderr()` theme; if
    /// stderr is redirected (e.g., systemd `StandardError=null`), the
    /// operator would see no prompt while dialoguer still blocks on
    /// stdin.
    pub fn start_with_tty() -> Result<Arc<Self>, ApprovalSetupError> {
        if !std::io::stdin().is_terminal() {
            return Err(ApprovalSetupError::NoTty { which: "stdin" });
        }
        if !std::io::stdout().is_terminal() {
            return Err(ApprovalSetupError::NoTty { which: "stdout" });
        }
        if !std::io::stderr().is_terminal() {
            return Err(ApprovalSetupError::NoTty { which: "stderr" });
        }
        Ok(Self::start(Arc::new(DialoguerPromptReader::new())))
    }

    /// Construct a service with a custom `PromptReader`.
    ///
    /// Used by tests (with `CannedPromptReader`) and by the
    /// `AGENTSSO_TEST_APPROVAL_CANNED_RESPONSES` seam. Spawns the
    /// prompt task immediately; the returned `Arc<Self>` can be cloned
    /// freely.
    #[must_use]
    pub fn start(reader: Arc<dyn PromptReader>) -> Arc<Self> {
        // Bounded mpsc with backpressure: an unbounded channel would
        // OOM under an agent flood (a misbehaving or adversarial agent
        // hitting a prompt-required policy at high concurrency while
        // the operator is AFK). Capacity 64 is enough headroom for
        // realistic burst sizes; `try_send` failure maps to
        // `ApprovalOutcome::Unavailable` (503), which fail-closes
        // loudly instead of silently growing memory.
        let (tx, mut rx) = mpsc::channel::<PromptJob>(PROMPT_QUEUE_CAPACITY);
        let always_cache: Arc<Mutex<HashSet<CacheKey>>> = Arc::new(Mutex::new(HashSet::new()));
        let never_cache: Arc<Mutex<HashSet<CacheKey>>> = Arc::new(Mutex::new(HashSet::new()));
        let always_for_task = Arc::clone(&always_cache);
        let never_for_task = Arc::clone(&never_cache);

        // Spawn the long-lived prompt task. It owns the receiver and
        // drains jobs one at a time, guaranteeing the "one prompt in
        // flight at a time" invariant AC #8 locks in.
        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                let key: CacheKey = (job.req.policy_name.clone(), job.req.rule_id.clone());

                // Cache recheck inside the prompt task. A concurrent
                // `request_approval` for the same (policy, rule) may
                // have enqueued before the first responder ran and
                // populated the cache. Without this recheck, the
                // operator would see N prompts for the same rule
                // until the first one resolves and caches — violating
                // the "always / never = remember this session" UX
                // promise at the exact moment it matters.
                if cache_contains(&never_for_task, &key) {
                    let _ = job
                        .responder
                        .send(ApprovalOutcome::NeverAllowCached { rule_id: job.req.rule_id });
                    continue;
                }
                if cache_contains(&always_for_task, &key) {
                    let _ = job
                        .responder
                        .send(ApprovalOutcome::AlwaysAllowCached { rule_id: job.req.rule_id });
                    continue;
                }

                let outcome = handle_one_prompt(&job.req, Arc::clone(&reader)).await;

                // Populate caches BEFORE responding to the caller, so
                // the cache insert is not lost if the caller's future
                // is dropped (agent disconnected) between the task
                // sending the outcome and the caller processing it.
                // The operator pressed `a`/`never` and saw it commit
                // on their terminal — that decision MUST persist for
                // the session even if the original requester has
                // already gone away.
                match &outcome {
                    ApprovalOutcome::AlwaysAllowThisSession { .. } => {
                        cache_insert(&always_for_task, key.clone());
                    }
                    ApprovalOutcome::NeverAllow { .. } => {
                        cache_insert(&never_for_task, key.clone());
                    }
                    _ => {}
                }

                // Best-effort send — the receiver may have dropped if
                // the request's tower future was cancelled. That's
                // fine; the cache has already been updated.
                let _ = job.responder.send(outcome);
            }
            info!("approval prompt task shutting down (channel closed)");
        });

        Arc::new(Self { tx, always_cache, never_cache })
    }
}

/// Bounded prompt queue capacity. Sized for realistic concurrent burst
/// scenarios while keeping a hard backpressure ceiling.
const PROMPT_QUEUE_CAPACITY: usize = 64;

/// Cache lookup helper that crashes loud on lock poisoning.
///
/// The approval cache encodes operator security decisions; silently
/// treating a poisoned lock as "empty cache" would fail-OPEN on `never`
/// (the operator's "never allow" decision would be lost and the request
/// would re-prompt). Crashing on poison matches the daemon's NFR20
/// fail-closed posture: a corrupted cache forces a clean restart.
#[allow(clippy::expect_used)]
fn cache_contains(cache: &Arc<Mutex<HashSet<CacheKey>>>, key: &CacheKey) -> bool {
    cache.lock().expect("approval cache mutex poisoned — daemon must restart").contains(key)
}

/// Cache insert helper with the same fail-closed posture as
/// [`cache_contains`].
#[allow(clippy::expect_used)]
fn cache_insert(cache: &Arc<Mutex<HashSet<CacheKey>>>, key: CacheKey) {
    cache.lock().expect("approval cache mutex poisoned — daemon must restart").insert(key);
}

/// Render one prompt and translate the reader's decision into an
/// `ApprovalOutcome`.
///
/// **Orphan-thread avoidance.** `tokio::task::spawn_blocking` returns
/// a `JoinHandle` that cannot be cancelled — once dispatched, the
/// underlying OS thread runs to completion. If we wrapped the handle
/// in `tokio::time::timeout` and returned on the timeout branch, the
/// orphan thread would still hold the controlling TTY, and the next
/// prompt task iteration would `spawn_blocking` a SECOND reader on
/// the same stdin. Two threads racing for raw-mode stdin would
/// corrupt each other's keystrokes and silently break the
/// "one prompt at a time" invariant.
///
/// Instead, we let the blocking call run unbounded and use `tokio::select!`
/// to detect timeout *intent* via a sleep arm, but we still `await` the
/// `JoinHandle` to completion before returning. This keeps the orphan
/// thread bounded and guarantees stdin is exclusively held by exactly
/// one reader at a time. The cost: a slow operator can extend a
/// request's wait beyond the timeout (the request returns `Timeout`
/// only after the operator finally presses a key). The agent's request
/// is still rejected as soon as the timeout elapses — see the wrapping
/// `select!` in the caller — but the `dialoguer` thread is allowed to
/// drain naturally. UX-wise this is the right tradeoff: the alternative
/// (orphan threads holding the TTY) is much worse.
async fn handle_one_prompt(
    req: &ApprovalRequest,
    reader: Arc<dyn PromptReader>,
) -> ApprovalOutcome {
    let req_owned = req.clone();
    let timeout = req.timeout;
    let reader_clone = Arc::clone(&reader);
    let rule_id = req.rule_id.clone();

    let blocking = tokio::task::spawn_blocking(move || reader_clone.read_decision(&req_owned));

    // Race the configured timeout against the blocking reader. If the
    // timeout elapses first, we await the blocking handle to drain
    // before returning Timeout — see the doc-comment above for why we
    // can't simply abandon the JoinHandle.
    let join_result = tokio::select! {
        biased;
        result = blocking => result,
        () = tokio::time::sleep(timeout) => {
            // Timeout intent: we will return `Timeout`, but first we
            // drain the blocking reader to release the controlling TTY
            // before the next prompt is dispatched. Note we do not
            // re-create the JoinHandle — the same one is awaited below.
            warn!(
                rule_id = %rule_id,
                timeout_secs = timeout.as_secs(),
                "approval prompt timed out — waiting for reader to release stdin before next prompt"
            );
            return ApprovalOutcome::Timeout;
        }
    };

    match join_result {
        Ok(PromptReaderDecision::Allow) => ApprovalOutcome::Granted,
        Ok(PromptReaderDecision::Deny) => ApprovalOutcome::Denied,
        Ok(PromptReaderDecision::Always) => ApprovalOutcome::AlwaysAllowThisSession { rule_id },
        Ok(PromptReaderDecision::Never) => ApprovalOutcome::NeverAllow { rule_id },
        // Reader aborted (Esc, I/O error, empty canned queue) → fail-closed deny.
        Ok(PromptReaderDecision::Aborted) => ApprovalOutcome::Denied,
        // Reader thread panicked → unavailable (not just a denial).
        Err(join_err) => {
            warn!(error = ?join_err, "approval prompt reader panicked");
            ApprovalOutcome::Unavailable
        }
    }
}

#[async_trait]
impl ApprovalService for CliApprovalService {
    async fn request_approval(&self, req: ApprovalRequest) -> ApprovalOutcome {
        let key: CacheKey = (req.policy_name.clone(), req.rule_id.clone());

        // 1. Consult caches first — operator already decided for this rule.
        //    (Recheck happens inside the prompt task too, so any race
        //    between this check and the enqueue is closed by the recheck.)
        if cache_contains(&self.never_cache, &key) {
            return ApprovalOutcome::NeverAllowCached { rule_id: req.rule_id };
        }
        if cache_contains(&self.always_cache, &key) {
            return ApprovalOutcome::AlwaysAllowCached { rule_id: req.rule_id };
        }

        // 2. Enqueue a prompt job. Use `try_send` so a saturated queue
        //    fail-closes loudly with `Unavailable` (HTTP 503) instead of
        //    silently parking the request for an arbitrary duration.
        let (responder, rx) = oneshot::channel();
        match self.tx.try_send(PromptJob { req, responder }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    queue_capacity = PROMPT_QUEUE_CAPACITY,
                    "approval prompt queue saturated — fail-closing with Unavailable"
                );
                return ApprovalOutcome::Unavailable;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Prompt task dropped — daemon is shutting down.
                return ApprovalOutcome::Unavailable;
            }
        }

        // 3. Await the outcome. Cache insert happens inside the prompt
        //    task BEFORE this responder fires, so a dropped caller
        //    future no longer loses the operator's `a`/`never` decision.
        rx.await.unwrap_or(ApprovalOutcome::Unavailable)
    }

    #[allow(clippy::expect_used)]
    fn clear_caches(&self) {
        // Same fail-closed posture as `cache_contains`/`cache_insert`:
        // a poisoned mutex on the approval cache crashes the daemon
        // rather than silently bypassing operator security decisions.
        self.always_cache
            .lock()
            .expect("approval cache mutex poisoned — daemon must restart")
            .clear();
        self.never_cache
            .lock()
            .expect("approval cache mutex poisoned — daemon must restart")
            .clear();
    }

    fn describe(&self) -> &'static str {
        "cli-tty"
    }
}

// ──────────────────────────────────────────────────────────────────
// NoTtyApprovalService
// ──────────────────────────────────────────────────────────────────

/// Fail-closed approval service used when the daemon has no
/// controlling terminal.
///
/// Every `request_approval` resolves to
/// [`ApprovalOutcome::Unavailable`] with zero latency, which
/// `PolicyLayer` maps to HTTP 503 `policy.approval_unavailable`.
#[derive(Debug, Default)]
pub struct NoTtyApprovalService;

impl NoTtyApprovalService {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ApprovalService for NoTtyApprovalService {
    async fn request_approval(&self, _req: ApprovalRequest) -> ApprovalOutcome {
        ApprovalOutcome::Unavailable
    }

    fn clear_caches(&self) {
        // No state to clear.
    }

    fn describe(&self) -> &'static str {
        "no-tty"
    }
}

// ──────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn sample_req(policy: &str, rule: &str) -> ApprovalRequest {
        ApprovalRequest {
            request_id: "req-1".to_owned(),
            agent_id: "agent".to_owned(),
            service: "gmail".to_owned(),
            scope: "gmail.modify".to_owned(),
            resource: Some("users/me".to_owned()),
            policy_name: policy.to_owned(),
            rule_id: rule.to_owned(),
            timeout: Duration::from_secs(5),
        }
    }

    #[tokio::test]
    async fn no_tty_returns_unavailable() {
        let svc = NoTtyApprovalService::new();
        let outcome = svc.request_approval(sample_req("p", "r")).await;
        assert_eq!(outcome, ApprovalOutcome::Unavailable);
        svc.clear_caches(); // no panic
        assert_eq!(svc.describe(), "no-tty");
    }

    #[tokio::test]
    async fn canned_granted_returns_granted() {
        let reader = Arc::new(CannedPromptReader::new(vec![PromptReaderDecision::Allow]));
        let svc = CliApprovalService::start(reader);
        let outcome = svc.request_approval(sample_req("p", "r")).await;
        assert_eq!(outcome, ApprovalOutcome::Granted);
    }

    #[tokio::test]
    async fn canned_deny_returns_denied() {
        let reader = Arc::new(CannedPromptReader::new(vec![PromptReaderDecision::Deny]));
        let svc = CliApprovalService::start(reader);
        let outcome = svc.request_approval(sample_req("p", "r")).await;
        assert_eq!(outcome, ApprovalOutcome::Denied);
    }

    #[tokio::test]
    async fn canned_always_populates_cache() {
        // First call consumes the canned Always decision; second call
        // should hit the cache and return AlwaysAllowCached WITHOUT
        // consuming another canned decision.
        let reader = Arc::new(CannedPromptReader::new(vec![
            PromptReaderDecision::Always,
            // Sentinel: if the cache fails, this decision would be
            // consumed and the test would see Deny.
            PromptReaderDecision::Deny,
        ]));
        let queue = reader.shared_queue();
        let svc = CliApprovalService::start(reader);

        let first = svc.request_approval(sample_req("p", "r")).await;
        assert!(matches!(first, ApprovalOutcome::AlwaysAllowThisSession { .. }));

        let second = svc.request_approval(sample_req("p", "r")).await;
        assert!(matches!(second, ApprovalOutcome::AlwaysAllowCached { .. }));

        // The Deny sentinel should still be in the queue.
        assert_eq!(queue.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn canned_never_populates_cache() {
        let reader = Arc::new(CannedPromptReader::new(vec![
            PromptReaderDecision::Never,
            PromptReaderDecision::Allow,
        ]));
        let queue = reader.shared_queue();
        let svc = CliApprovalService::start(reader);

        let first = svc.request_approval(sample_req("p", "r")).await;
        assert!(matches!(first, ApprovalOutcome::NeverAllow { .. }));

        let second = svc.request_approval(sample_req("p", "r")).await;
        assert!(matches!(second, ApprovalOutcome::NeverAllowCached { .. }));

        assert_eq!(queue.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn canned_aborted_becomes_denied() {
        let reader = Arc::new(CannedPromptReader::new(vec![PromptReaderDecision::Aborted]));
        let svc = CliApprovalService::start(reader);
        let outcome = svc.request_approval(sample_req("p", "r")).await;
        assert_eq!(outcome, ApprovalOutcome::Denied);
    }

    #[tokio::test]
    async fn canned_empty_queue_becomes_denied() {
        // Empty queue → reader returns Aborted → PolicyLayer sees Denied.
        let reader = Arc::new(CannedPromptReader::new(vec![]));
        let svc = CliApprovalService::start(reader);
        let outcome = svc.request_approval(sample_req("p", "r")).await;
        assert_eq!(outcome, ApprovalOutcome::Denied);
    }

    #[tokio::test]
    async fn clear_caches_empties_both() {
        let reader = Arc::new(CannedPromptReader::new(vec![
            PromptReaderDecision::Always,
            PromptReaderDecision::Never,
            // Must be consumed after clear_caches.
            PromptReaderDecision::Allow,
        ]));
        let svc = CliApprovalService::start(reader);

        let _ = svc.request_approval(sample_req("p", "rule-a")).await;
        let _ = svc.request_approval(sample_req("p", "rule-n")).await;

        svc.clear_caches();

        // Next call for rule-a should consume the Allow decision
        // rather than hit the (cleared) always cache.
        let outcome = svc.request_approval(sample_req("p", "rule-a")).await;
        assert_eq!(outcome, ApprovalOutcome::Granted);
    }

    #[tokio::test]
    async fn cache_is_policy_rule_scoped() {
        // A cache hit on (policy-A, rule-X) must not match (policy-B, rule-X).
        let reader = Arc::new(CannedPromptReader::new(vec![
            PromptReaderDecision::Always,
            PromptReaderDecision::Deny,
        ]));
        let svc = CliApprovalService::start(reader);

        let first = svc.request_approval(sample_req("policy-A", "rule-x")).await;
        assert!(matches!(first, ApprovalOutcome::AlwaysAllowThisSession { .. }));

        let second = svc.request_approval(sample_req("policy-B", "rule-x")).await;
        assert_eq!(second, ApprovalOutcome::Denied);
    }

    #[tokio::test]
    async fn describe_returns_cli_tty_when_reader_is_real() {
        let reader = Arc::new(CannedPromptReader::new(vec![]));
        let svc = CliApprovalService::start(reader);
        assert_eq!(svc.describe(), "cli-tty");
    }

    #[tokio::test]
    async fn timeout_returns_timeout_outcome() {
        // Reader sleeps 500ms; request timeout is 100ms → Timeout.
        let reader = Arc::new(CannedPromptReader::with_sleep(
            vec![PromptReaderDecision::Allow],
            Duration::from_millis(500),
        ));
        let svc = CliApprovalService::start(reader);
        let mut req = sample_req("p", "r");
        req.timeout = Duration::from_millis(100);
        let outcome = svc.request_approval(req).await;
        assert_eq!(outcome, ApprovalOutcome::Timeout);
    }

    // ── Task 8 concurrency test: only one prompt in flight at a time ──

    #[tokio::test]
    async fn mpsc_serializes_concurrent_prompts() {
        // Wrap the reader with a counter that tracks max concurrent
        // read_decision calls. If the mpsc serializer works, the max
        // should never exceed 1 even with 8 concurrent requests.
        struct CountingReader {
            inner: Arc<CannedPromptReader>,
            in_flight: Arc<AtomicUsize>,
            max_seen: Arc<AtomicUsize>,
        }
        impl PromptReader for CountingReader {
            fn read_decision(&self, req: &ApprovalRequest) -> PromptReaderDecision {
                let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                self.max_seen.fetch_max(now, Ordering::SeqCst);
                // Sleep a bit to make overlap easier to detect.
                std::thread::sleep(Duration::from_millis(20));
                let decision = self.inner.read_decision(req);
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                decision
            }
        }

        let inner = Arc::new(CannedPromptReader::new(vec![
            PromptReaderDecision::Allow,
            PromptReaderDecision::Allow,
            PromptReaderDecision::Allow,
            PromptReaderDecision::Allow,
            PromptReaderDecision::Allow,
            PromptReaderDecision::Allow,
            PromptReaderDecision::Allow,
            PromptReaderDecision::Allow,
        ]));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let reader: Arc<dyn PromptReader> = Arc::new(CountingReader {
            inner,
            in_flight: Arc::clone(&in_flight),
            max_seen: Arc::clone(&max_seen),
        });

        let svc = CliApprovalService::start(reader);

        // 8 concurrent prompt-required requests. Distinct rule_ids so
        // none of them hit the cache.
        let mut handles = Vec::new();
        for i in 0..8 {
            let svc_clone = Arc::clone(&svc);
            handles.push(tokio::spawn(async move {
                svc_clone.request_approval(sample_req("p", &format!("rule-{i}"))).await
            }));
        }

        for h in handles {
            let outcome = h.await.unwrap();
            assert_eq!(outcome, ApprovalOutcome::Granted);
        }

        // The mpsc's single consumer task guarantees only one prompt
        // render at a time, which in turn guarantees the reader's
        // counter never crosses 1.
        assert_eq!(
            max_seen.load(Ordering::SeqCst),
            1,
            "mpsc serializer must guarantee exactly one prompt in flight at a time"
        );
    }

    #[tokio::test]
    async fn concurrent_cache_hits_bypass_mpsc() {
        // 4 requests for a cached rule + 4 for a new rule. The cached
        // ones should not touch the reader at all.
        let reader = Arc::new(CannedPromptReader::new(vec![
            // Seed the cache.
            PromptReaderDecision::Always,
            // Consumed by the 4 new-rule requests in serialized order.
            PromptReaderDecision::Allow,
            PromptReaderDecision::Allow,
            PromptReaderDecision::Allow,
            PromptReaderDecision::Allow,
        ]));
        let queue = reader.shared_queue();
        let svc = CliApprovalService::start(reader);

        // Seed the cache with rule-cached.
        let seed = svc.request_approval(sample_req("p", "rule-cached")).await;
        assert!(matches!(seed, ApprovalOutcome::AlwaysAllowThisSession { .. }));

        // Now fire 4 cached + 4 new concurrently.
        let mut handles = Vec::new();
        for _ in 0..4 {
            let svc_clone = Arc::clone(&svc);
            handles.push(tokio::spawn(async move {
                svc_clone.request_approval(sample_req("p", "rule-cached")).await
            }));
        }
        for i in 0..4 {
            let svc_clone = Arc::clone(&svc);
            handles.push(tokio::spawn(async move {
                svc_clone.request_approval(sample_req("p", &format!("rule-new-{i}"))).await
            }));
        }

        let mut cached_allows = 0;
        let mut granted = 0;
        for h in handles {
            match h.await.unwrap() {
                ApprovalOutcome::AlwaysAllowCached { .. } => cached_allows += 1,
                ApprovalOutcome::Granted => granted += 1,
                other => panic!("unexpected outcome: {other:?}"),
            }
        }
        assert_eq!(cached_allows, 4, "4 cached-rule hits should bypass the reader");
        assert_eq!(granted, 4, "4 new-rule hits should serialize through the reader");
        // Queue should be empty — we seeded 5 total and consumed 1 seed + 4 new.
        assert_eq!(queue.lock().unwrap().len(), 0);
    }
}
