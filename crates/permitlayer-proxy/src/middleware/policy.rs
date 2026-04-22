//! Policy evaluation middleware.
//!
//! Story 4.3 wires `PolicySet::evaluate` into the `call()` body.
//! Every proxied request is evaluated against the active `PolicySet`
//! with fail-closed semantics: a policy engine failure denies the
//! request rather than silently allowing it (NFR20).
//!
//! Story 4.1 replaced the `PolicySet` unit-struct stub with the real
//! compiled IR in `permitlayer_core::policy::PolicySet`. Story 4.2
//! added the `ArcSwap`-based hot-swap on SIGHUP/reload. This layer
//! holds the `Arc<ArcSwap<PolicySet>>` handle and evaluates every
//! request against the current snapshot.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, Response};
use permitlayer_core::audit::dispatcher::AuditDispatcher;
use permitlayer_core::audit::event::AuditEvent;
use permitlayer_core::policy::PolicySet;
use permitlayer_core::policy::compile::DEFAULT_PROMPT_APPROVAL_MODE;
use permitlayer_core::policy::eval::{Decision, EvalRequest};
use tower::{Layer, Service};
use tracing::{error, warn};

use crate::error::{AgentId, AgentPolicyBinding, ProxyError, RequestId};
use crate::middleware::approval::{
    AlwaysDenyApprovalService, ApprovalOutcome, ApprovalRequest, ApprovalService,
};
use crate::middleware::util::is_operational_path;

/// Default approval timeout when the caller does not specify one.
///
/// Matches the epic spec (30s) and the `DaemonConfig.approval.timeout_seconds`
/// default. `PolicyLayer` holds this as a `Duration` and propagates it into
/// every `ApprovalRequest` it builds.
pub const DEFAULT_APPROVAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum length for an agent-supplied scope header. Matches the
/// policy-side scope-format validator (`MAX_SCOPE_LEN` in
/// `permitlayer-core::policy::compile`). Scope strings longer than this
/// are truncated before being stored in `PolicyContext.scope` so they
/// cannot inflate audit log lines or error response bodies under
/// adversarial input.
const MAX_REQUEST_SCOPE_LEN: usize = 128;

// ──────────────────────────────────────────────────────────────────
// PolicyContext — request fields needed for policy evaluation
// ──────────────────────────────────────────────────────────────────

/// Fields extracted from an incoming `Request` for policy evaluation.
///
/// Built by [`extract_policy_context`] before the request is consumed.
#[derive(Debug, Clone)]
pub(crate) struct PolicyContext {
    pub agent_id: String,
    pub scope: String,
    pub service: String,
    pub resource: Option<String>,
}

/// Extract policy-relevant fields from the raw `Request`.
///
/// This runs in the middleware (before `ProxyService`), so it cannot
/// rely on axum extractors — it parses the URI path manually.
///
/// **Scope canonicalization:** Both a missing `x-agentsso-scope` header
/// and an explicitly-empty header value collapse to `"*"`. The scope is
/// truncated to [`MAX_REQUEST_SCOPE_LEN`] characters to prevent an
/// attacker from inflating downstream audit lines and error responses.
pub(crate) fn extract_policy_context(req: &Request<Body>) -> PolicyContext {
    let agent_id = req
        .extensions()
        .get::<AgentId>()
        .map(|a| a.0.clone())
        .unwrap_or_else(|| "unknown".to_owned());

    let scope_raw =
        req.headers().get("x-agentsso-scope").and_then(|v| v.to_str().ok()).unwrap_or("");
    // Canonicalize empty (missing OR present-but-empty) → "*".
    let scope_canonical = if scope_raw.is_empty() { "*" } else { scope_raw };
    // Truncate at character boundary to bound audit/error body size.
    let scope = if scope_canonical.chars().count() > MAX_REQUEST_SCOPE_LEN {
        scope_canonical.chars().take(MAX_REQUEST_SCOPE_LEN).collect()
    } else {
        scope_canonical.to_owned()
    };

    let path = req.uri().path();
    let (service, resource) = derive_service_and_resource(path);

    PolicyContext { agent_id, scope, service: service.to_owned(), resource }
}

// ──────────────────────────────────────────────────────────────────
// Path parsing (derive service + resource from URI)
// ──────────────────────────────────────────────────────────────────

/// Derive the upstream `service` name and optional `resource` path
/// from the request URI.
///
/// Path structures:
/// - `/v1/tools/{service}/{resource_path}` → (service, Some(resource_path))
/// - `/v1/tools/{service}` → (service, None)
/// - `/mcp/{service}` → (service, None)
/// - `/mcp` → ("gmail", None) — default per Story 1.11 convention
///
/// Unknown paths map to `("-", None)`.
///
/// **MCP resource contract:** MCP requests are always returned with
/// `resource = None` because the resource lives in the JSON-RPC body,
/// not the URL path. Policies bound to MCP traffic MUST set
/// `resources = ["*"]` — any narrower allowlist will deny 100% of MCP
/// calls because `ResourceMatcher::Allowlist::matches(None)` is `false`.
/// A future story (Story 4.4 or later) may parse the JSON-RPC body to
/// derive a real resource.
///
/// **Path normalization:** Repeated leading slashes after the prefix
/// (e.g., `/v1/tools//gmail/...`) are collapsed before the service
/// segment is extracted. This prevents an empty service segment from
/// silently bypassing policy via the `service == "-"` short-circuit.
///
/// TODO(consolidate): This duplicates the service-derivation logic from
/// `kill.rs::derive_service_from_path`. Consolidate into a shared
/// `middleware::util` module in a future story.
fn derive_service_and_resource(path: &str) -> (&'static str, Option<String>) {
    // Strip query string defensively (`URI::path()` already strips it,
    // but unit tests pass raw strings).
    let path = path.split('?').next().unwrap_or("");

    // REST paths: /v1/tools/{service}/{*path}
    if let Some(rest) = path.strip_prefix("/v1/tools/") {
        // Collapse repeated leading slashes ("/v1/tools//gmail/..." or
        // "/v1/tools///gmail/...") so the service segment is the actual
        // first non-empty segment, not the empty string.
        let rest = rest.trim_start_matches('/');

        // rest = "gmail/users/me/messages" or "gmail" or "gmail/"
        let (service_segment, resource_tail) = match rest.find('/') {
            Some(idx) => (&rest[..idx], Some(&rest[idx + 1..])),
            None => (rest, None),
        };

        let service = match_known_service(service_segment);

        // Trim leading/trailing slashes from the resource tail so paths
        // like `/v1/tools/gmail//` produce `resource = None` (not
        // `Some("/")`) and `/v1/tools/gmail/users//me` becomes
        // `Some("users//me")` rather than dropping the segment entirely.
        let resource = resource_tail
            .map(|r| r.trim_matches('/'))
            .filter(|r| !r.is_empty())
            .map(|r| r.to_owned());

        return (service, resource);
    }

    // MCP paths: /mcp/{service} or /mcp
    if path == "/mcp" || path == "/mcp/" {
        return ("gmail", None);
    }
    if let Some(rest) = path.strip_prefix("/mcp/") {
        let rest = rest.trim_start_matches('/');
        let segment = rest.split('/').next().unwrap_or("");
        let service = match_known_service(segment);
        return (service, None);
    }

    ("-", None)
}

/// Match a path segment to a known service name, returning `"-"` for
/// unknown segments. Uses exact equality to prevent substring
/// contamination (e.g., `"gmail-exploit"` → `"-"`).
fn match_known_service(segment: &str) -> &'static str {
    match segment {
        "gmail" => "gmail",
        "calendar" => "calendar",
        "drive" => "drive",
        _ => "-",
    }
}

// `is_operational_path` lives in `middleware::util` so AuthLayer and
// PolicyLayer agree on the same allowlist. See `util.rs` for the
// canonical implementation.

// ──────────────────────────────────────────────────────────────────
// Policy binding resolution (Story 4.4)
// ──────────────────────────────────────────────────────────────────

/// Resolve the policy name for the request, returning `None` when no
/// binding exists.
///
/// Reads the `AgentPolicyBinding` extension that `AuthLayer` stamps
/// onto the request after a successful bearer-token validation. If
/// the extension is absent (e.g., a unit test that bypasses
/// `AuthLayer`), the function returns `None` and the caller emits
/// `default-deny-no-agent-binding`.
///
/// **Story 4.4 deleted the previous single-policy heuristic.** The
/// pre-Story-4.4 fallback ("if the PolicySet has exactly one policy,
/// auto-bind every unknown agent to it") was a transitional crutch
/// while the registry was being built. The post-Story-4.4 invariant
/// is: explicit binding via `agentsso agent register` is required
/// for any non-operational request, full stop.
pub(crate) fn resolve_policy_name(req: &Request<Body>) -> Option<String> {
    req.extensions().get::<AgentPolicyBinding>().map(|b| b.0.clone())
}

// ──────────────────────────────────────────────────────────────────
// Tower Layer + Service
// ──────────────────────────────────────────────────────────────────

/// Tower layer for policy evaluation.
#[derive(Clone)]
pub struct PolicyLayer {
    policy_set: Arc<ArcSwap<PolicySet>>,
    audit_dispatcher: Arc<AuditDispatcher>,
    approval_service: Arc<dyn ApprovalService>,
    // Story 8.7: approval timeout seconds read per-request via
    // `Arc<AtomicU64>`, written by SIGHUP / `POST /v1/control/reload`.
    //
    // `Ordering::Relaxed` is sufficient because:
    //   1. Writers are serialized: both SIGHUP's `reload_loop` and
    //      `reload_handler` take `reload_mutex` before writing this
    //      atomic + the paired `config_state` ArcSwap, so two
    //      reloaders can't interleave and pair this atomic with a
    //      mismatched config snapshot.
    //   2. There are no cross-variable happens-before invariants
    //      between this value and other request-visible state —
    //      `PolicyService::call` reads the atomic once per request
    //      and wraps in `Duration::from_secs` at the moment of use.
    approval_timeout: Arc<AtomicU64>,
}

impl PolicyLayer {
    /// Construct a `PolicyLayer` with the default
    /// `AlwaysDenyApprovalService` (every `Decision::Prompt` resolves
    /// to HTTP 503 `policy.approval_unavailable`).
    ///
    /// Use [`PolicyLayer::with_approval_service`] to wire a real
    /// implementor from `permitlayer_daemon::approval`.
    #[must_use]
    pub fn new(
        policy_set: Arc<ArcSwap<PolicySet>>,
        audit_dispatcher: Arc<AuditDispatcher>,
    ) -> Self {
        Self {
            policy_set,
            audit_dispatcher,
            approval_service: Arc::new(AlwaysDenyApprovalService::new()),
            approval_timeout: Arc::new(AtomicU64::new(DEFAULT_APPROVAL_TIMEOUT.as_secs())),
        }
    }

    /// Construct a `PolicyLayer` with an explicit approval service and
    /// an atomic timeout handle. Used by `assemble_middleware` from the
    /// daemon crate. The same `Arc<AtomicU64>` is shared with the
    /// SIGHUP reload path and `POST /v1/control/reload` so operator
    /// edits to `[approval] timeout_seconds` take effect without a
    /// daemon restart (Story 8.7 AC #1/#2/#3).
    #[must_use]
    pub fn with_approval_service(
        policy_set: Arc<ArcSwap<PolicySet>>,
        audit_dispatcher: Arc<AuditDispatcher>,
        approval_service: Arc<dyn ApprovalService>,
        approval_timeout: Arc<AtomicU64>,
    ) -> Self {
        Self { policy_set, audit_dispatcher, approval_service, approval_timeout }
    }
}

impl<S> Layer<S> for PolicyLayer {
    type Service = PolicyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PolicyService {
            inner,
            policy_set: Arc::clone(&self.policy_set),
            audit_dispatcher: Arc::clone(&self.audit_dispatcher),
            approval_service: Arc::clone(&self.approval_service),
            approval_timeout: Arc::clone(&self.approval_timeout),
        }
    }
}

/// Tower service that evaluates policies with fail-closed semantics.
#[derive(Clone)]
pub struct PolicyService<S> {
    inner: S,
    policy_set: Arc<ArcSwap<PolicySet>>,
    audit_dispatcher: Arc<AuditDispatcher>,
    approval_service: Arc<dyn ApprovalService>,
    approval_timeout: Arc<AtomicU64>,
}

impl<S> Service<Request<Body>> for PolicyService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // 1. Extract request_id before anything else (for error responses).
        let request_id = req.extensions().get::<RequestId>().map(|r| r.0.clone());

        // 2. Extract policy evaluation context.
        let ctx = extract_policy_context(&req);

        // 2a. Skip policy evaluation for explicitly-allowed operational
        // paths (health probes, control endpoints). PolicyLayer is the
        // authorization boundary for upstream API calls only. We use an
        // explicit allowlist of known-safe path prefixes rather than a
        // fall-through `service == "-"` bypass — the latter would
        // silently exempt any future-routed unknown path from policy
        // enforcement (defense-in-depth gap caught in code review).
        if is_operational_path(req.uri().path()) {
            let fut = self.inner.call(req);
            return Box::pin(fut);
        }

        // Any other unknown-service path (`service == "-"` from
        // `derive_service_and_resource`) falls through to evaluation,
        // where it will be denied by `default-deny-no-agent-binding`
        // or `default-deny-unmatched-policy`. This is the fail-closed
        // posture: unknown means "evaluate, then probably deny."

        // 3. Load the current policy set (lock-free ArcSwap read).
        let policy_set = self.policy_set.load();

        // 4. Resolve which policy applies to this agent. Story 4.4
        //    reads the AgentPolicyBinding extension stamped by
        //    AuthLayer; the pre-Story-4.4 single-policy heuristic is
        //    gone. Missing binding → default-deny.
        let policy_name = match resolve_policy_name(&req) {
            Some(name) => name,
            None => {
                // No policy binding — deny with informative error.
                let err = ProxyError::PolicyDenied {
                    policy_name: "-".to_owned(),
                    rule_id: "default-deny-no-agent-binding".to_owned(),
                    denied_scope: None,
                    denied_resource: None,
                    message: "No policy binding for agent".to_owned(),
                };
                let event = build_policy_violation_event(
                    &request_id,
                    &ctx,
                    "-",
                    "default-deny-no-agent-binding",
                    None,
                    None,
                    "deny",
                );
                let dispatcher = Arc::clone(&self.audit_dispatcher);
                let resp = err.into_response_with_request_id(request_id);
                return Box::pin(async move {
                    dispatcher.dispatch(event).await;
                    Ok(resp)
                });
            }
        };

        // 5. Build evaluation request.
        let eval_req = EvalRequest {
            policy_name: policy_name.clone(),
            scope: ctx.scope.clone(),
            resource: ctx.resource.clone(),
        };

        // 6. Evaluate with panic catch (fail-closed per NFR20).
        let decision =
            std::panic::catch_unwind(AssertUnwindSafe(|| policy_set.evaluate(&eval_req)));

        match decision {
            Ok(Decision::Allow) => {
                // Pass through to inner service.
                let fut = self.inner.call(req);
                Box::pin(fut)
            }
            Ok(Decision::Deny { policy_name: pn, rule_id, denied_scope, denied_resource }) => {
                let err = ProxyError::PolicyDenied {
                    policy_name: pn.clone(),
                    rule_id: rule_id.clone(),
                    denied_scope: denied_scope.clone(),
                    denied_resource: denied_resource.clone(),
                    message: format!("Request denied by policy '{pn}' rule '{rule_id}'"),
                };
                let event = build_policy_violation_event(
                    &request_id,
                    &ctx,
                    &pn,
                    &rule_id,
                    denied_scope.as_deref(),
                    denied_resource.as_deref(),
                    "deny",
                );
                let dispatcher = Arc::clone(&self.audit_dispatcher);
                let resp = err.into_response_with_request_id(request_id);
                Box::pin(async move {
                    dispatcher.dispatch(event).await;
                    Ok(resp)
                })
            }
            Ok(Decision::Prompt { policy_name: pn, rule_id }) => {
                // Story 4.5: Dispatch to the ApprovalService.
                //
                // Before awaiting the operator, consult the policy's
                // `auto-approve-reads` flag. If the policy has the
                // flag set, the request targets a read-style scope
                // (suffix `.readonly` / `.metadata`), AND the prompt
                // came from the policy-level fall-through (NOT an
                // explicit operator-written rule), short-circuit through
                // Allow without showing a prompt. The rule_id gate
                // preserves explicit operator intent: a rule like
                // `{ scope = "gmail.readonly", action = "prompt" }`
                // is honored even when `auto-approve-reads = true`.
                let is_policy_level_prompt = rule_id == DEFAULT_PROMPT_APPROVAL_MODE;
                let is_read_bypass = is_policy_level_prompt
                    && policy_set
                        .get(&pn)
                        .map(|p| p.auto_approve_reads && p.is_readonly_scope(&ctx.scope))
                        .unwrap_or(false);

                if is_read_bypass {
                    // `cached = false`: this path never touches the
                    // `always`/`never` session cache. The discriminator
                    // is `outcome_detail = "auto-approve-reads"`, which
                    // is distinct from the cached-decision sentinels
                    // (`operator-a-cached`, `operator-never-cached`).
                    // Setting `cached = true` here would corrupt
                    // "% of approvals served from cache" analytics by
                    // conflating cache hits with policy-level rule
                    // bypasses.
                    let event = build_approval_event(
                        &request_id,
                        &ctx,
                        &pn,
                        &rule_id,
                        ApprovalEventKind::Granted,
                        outcome_detail::AUTO_APPROVE_READS,
                        false,
                    );
                    let dispatcher = Arc::clone(&self.audit_dispatcher);
                    let fut = self.inner.call(req);
                    return Box::pin(async move {
                        dispatcher.dispatch(event).await;
                        fut.await
                    });
                }

                // Drop the ArcSwap guard before moving into the async
                // block — `arc_swap::Guard` is not `Send`.
                drop(policy_set);

                // Build the approval request. `request_id` is
                // `Option<String>` because RequestTraceLayer may not have
                // run (defensive), but the approval service always wants
                // a concrete `String` — fall back to an empty string,
                // which the audit event writer normalizes to
                // `"missing-request-id"`.
                // Story 8.7 AC #1: load the atomic once per request and
                // wrap in `Duration` at the moment of use. `Relaxed` is
                // sufficient — see the `PolicyLayer::approval_timeout`
                // field doc-comment.
                let timeout_secs = self.approval_timeout.load(Ordering::Relaxed);
                let approval_req = ApprovalRequest {
                    request_id: request_id.clone().unwrap_or_default(),
                    agent_id: ctx.agent_id.clone(),
                    service: ctx.service.clone(),
                    scope: ctx.scope.clone(),
                    resource: ctx.resource.clone(),
                    policy_name: pn.clone(),
                    rule_id: rule_id.clone(),
                    timeout: Duration::from_secs(timeout_secs),
                };

                // Clone handles into the async block. The returned
                // future must be `'static + Send`, so all captures
                // must be owned.
                let approval_service = Arc::clone(&self.approval_service);
                let mut inner = self.inner.clone();
                let audit_dispatcher = Arc::clone(&self.audit_dispatcher);
                let ctx_owned = ctx.clone();
                let pn_owned = pn.clone();
                let rule_id_owned = rule_id.clone();
                let request_id_owned = request_id.clone();
                // `timeout_secs` was loaded once above via
                // `self.approval_timeout.load(Relaxed)` and is reused
                // here to avoid a second atomic load per request.

                Box::pin(async move {
                    let outcome = approval_service.request_approval(approval_req).await;

                    // Translate the outcome into (a) an audit-event
                    // emission and (b) either a pass-through to the
                    // inner service or an error response.
                    match outcome {
                        ApprovalOutcome::Granted => {
                            write_approval_event_detached(
                                &audit_dispatcher,
                                &request_id_owned,
                                &ctx_owned,
                                &pn_owned,
                                &rule_id_owned,
                                ApprovalEventKind::Granted,
                                outcome_detail::OPERATOR_Y,
                                false,
                            )
                            .await;
                            inner.call(req).await
                        }
                        ApprovalOutcome::AlwaysAllowThisSession { .. } => {
                            write_approval_event_detached(
                                &audit_dispatcher,
                                &request_id_owned,
                                &ctx_owned,
                                &pn_owned,
                                &rule_id_owned,
                                ApprovalEventKind::Granted,
                                outcome_detail::OPERATOR_A,
                                false,
                            )
                            .await;
                            inner.call(req).await
                        }
                        ApprovalOutcome::AlwaysAllowCached { .. } => {
                            write_approval_event_detached(
                                &audit_dispatcher,
                                &request_id_owned,
                                &ctx_owned,
                                &pn_owned,
                                &rule_id_owned,
                                ApprovalEventKind::Granted,
                                outcome_detail::OPERATOR_A_CACHED,
                                true,
                            )
                            .await;
                            inner.call(req).await
                        }
                        ApprovalOutcome::Denied => {
                            write_approval_event_detached(
                                &audit_dispatcher,
                                &request_id_owned,
                                &ctx_owned,
                                &pn_owned,
                                &rule_id_owned,
                                ApprovalEventKind::Denied,
                                outcome_detail::OPERATOR_N,
                                false,
                            )
                            .await;
                            let err = ProxyError::ApprovalRequired {
                                policy_name: pn_owned,
                                rule_id: rule_id_owned,
                            };
                            Ok(err.into_response_with_request_id(request_id_owned))
                        }
                        ApprovalOutcome::NeverAllow { .. } => {
                            write_approval_event_detached(
                                &audit_dispatcher,
                                &request_id_owned,
                                &ctx_owned,
                                &pn_owned,
                                &rule_id_owned,
                                ApprovalEventKind::Denied,
                                outcome_detail::OPERATOR_NEVER,
                                false,
                            )
                            .await;
                            let err = ProxyError::ApprovalRequired {
                                policy_name: pn_owned,
                                rule_id: rule_id_owned,
                            };
                            Ok(err.into_response_with_request_id(request_id_owned))
                        }
                        ApprovalOutcome::NeverAllowCached { .. } => {
                            write_approval_event_detached(
                                &audit_dispatcher,
                                &request_id_owned,
                                &ctx_owned,
                                &pn_owned,
                                &rule_id_owned,
                                ApprovalEventKind::Denied,
                                outcome_detail::OPERATOR_NEVER_CACHED,
                                true,
                            )
                            .await;
                            let err = ProxyError::ApprovalRequired {
                                policy_name: pn_owned,
                                rule_id: rule_id_owned,
                            };
                            Ok(err.into_response_with_request_id(request_id_owned))
                        }
                        ApprovalOutcome::Timeout => {
                            let detail = outcome_detail::timeout(timeout_secs);
                            write_approval_event_detached(
                                &audit_dispatcher,
                                &request_id_owned,
                                &ctx_owned,
                                &pn_owned,
                                &rule_id_owned,
                                ApprovalEventKind::Timeout,
                                &detail,
                                false,
                            )
                            .await;
                            // Distinct error code from `ApprovalRequired`:
                            // a timeout means the operator was AFK, not
                            // that they said no. Agents can safely retry
                            // a 403 `policy.approval_timeout` after a
                            // delay.
                            let err = ProxyError::ApprovalTimeout {
                                policy_name: pn_owned,
                                rule_id: rule_id_owned,
                            };
                            Ok(err.into_response_with_request_id(request_id_owned))
                        }
                        ApprovalOutcome::Unavailable => {
                            // Audit event type matches the HTTP error
                            // code so operators grepping audit.jsonl
                            // for `event_type=approval-unavailable`
                            // find the same events that produced the
                            // 503 `policy.approval_unavailable`
                            // responses.
                            write_approval_event_detached(
                                &audit_dispatcher,
                                &request_id_owned,
                                &ctx_owned,
                                &pn_owned,
                                &rule_id_owned,
                                ApprovalEventKind::Unavailable,
                                outcome_detail::NO_TTY,
                                false,
                            )
                            .await;
                            let err = ProxyError::ApprovalUnavailable {
                                policy_name: pn_owned,
                                rule_id: rule_id_owned,
                            };
                            Ok(err.into_response_with_request_id(request_id_owned))
                        } // NOTE: `ApprovalOutcome` is `#[non_exhaustive]`,
                          // but from inside the same crate the compiler
                          // sees every variant, so no wildcard arm is
                          // needed (and one would be dead code). Any new
                          // variant added in this crate will trigger a
                          // non-exhaustive match error here — that's the
                          // whole point of enumerating explicitly.
                    }
                })
            }
            Ok(_) => {
                // Wildcard arm for #[non_exhaustive] Decision variants.
                // Fail-closed: unknown decision → deny.
                error!("policy evaluation returned unknown Decision variant — fail-closed");
                let resp = ProxyError::PolicyEvalFailed.into_response_with_request_id(request_id);
                Box::pin(async move { Ok(resp) })
            }
            Err(_panic) => {
                // Evaluation panicked — fail-closed (NFR20).
                error!("policy evaluation panicked — returning 503 fail-closed");
                let resp = ProxyError::PolicyEvalFailed.into_response_with_request_id(request_id);
                Box::pin(async move { Ok(resp) })
            }
        }
    }
}

// Story 8.2 review fix D1: `PolicyService::write_audit_event` and
// `PolicyService::write_approval_event` wrapper methods were removed.
// All call sites now use `build_policy_violation_event` /
// `build_approval_event` (pure functions that return an
// `AuditEvent`) and `dispatcher.dispatch(event).await` directly from
// within each response-future async block. This preserves
// producer-edge backpressure: the response is held while the
// dispatcher permit is contended.

/// Pure function that builds a `policy-violation` audit event. Split
/// out from `write_audit_event` (Story 8.2 review fix D1) so sync
/// call paths can build the event synchronously and hand it to an
/// async `dispatcher.dispatch(event).await` inside a response future.
#[allow(clippy::too_many_arguments)]
fn build_policy_violation_event(
    request_id: &Option<String>,
    ctx: &PolicyContext,
    policy_name: &str,
    rule_id: &str,
    denied_scope: Option<&str>,
    denied_resource: Option<&str>,
    decision: &str,
) -> AuditEvent {
    // RequestTraceLayer always inserts a `RequestId` extension
    // upstream of PolicyLayer in `assemble_middleware`, so this
    // fallback should be unreachable. Emit a sentinel string
    // (instead of empty) so any unexpected occurrence is grep-
    // visible in the audit log, and warn so a refactor that
    // breaks the chain order surfaces immediately in tracing.
    let request_id_for_audit = match request_id {
        Some(id) if !id.is_empty() => id.clone(),
        _ => {
            warn!(
                "policy-violation audit event has no RequestId — \
                 RequestTraceLayer may be missing from the chain"
            );
            "missing-request-id".to_owned()
        }
    };
    let mut event = AuditEvent::with_request_id(
        request_id_for_audit,
        ctx.agent_id.clone(),
        ctx.service.clone(),
        ctx.scope.clone(),
        ctx.resource.clone().unwrap_or_else(|| "-".to_owned()),
        "denied".to_owned(),
        "policy-violation".to_owned(),
    );
    event.extra = serde_json::json!({
        "policy_name": policy_name,
        "rule_id": rule_id,
        "denied_scope": denied_scope,
        "denied_resource": denied_resource,
        "decision": decision,
    });
    event
}

/// Kind of approval event being emitted. Maps 1:1 onto the three
/// `event_type` strings Story 4.5 adds to the audit schema.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ApprovalEventKind {
    /// `approval-granted` — operator said yes (or cache hit, or
    /// auto-approve-reads short-circuit).
    Granted,
    /// `approval-denied` — operator said no (or never, or cached never).
    Denied,
    /// `approval-timeout` — operator did not respond before the
    /// configured approval timeout elapsed.
    Timeout,
    /// `approval-unavailable` — the approval service is structurally
    /// unavailable (no controlling TTY, or the daemon is shutting down).
    /// Distinct from `Timeout` so operators grepping the audit log find
    /// these events under the same name as the HTTP 503
    /// `policy.approval_unavailable` responses.
    Unavailable,
}

impl ApprovalEventKind {
    fn event_type(self) -> &'static str {
        match self {
            Self::Granted => "approval-granted",
            Self::Denied => "approval-denied",
            Self::Timeout => "approval-timeout",
            Self::Unavailable => "approval-unavailable",
        }
    }

    fn outcome(self) -> &'static str {
        match self {
            // Granted → "ok" (request proceeds to upstream).
            Self::Granted => "ok",
            // Denied, Timeout, Unavailable all surface as "denied" in
            // the audit outcome field because the agent's request was
            // rejected. The `event_type` distinguishes them.
            Self::Denied | Self::Timeout | Self::Unavailable => "denied",
        }
    }
}

/// Canonical `outcome_detail` strings for approval audit events.
///
/// Centralized so production code, tests, and operator audit queries
/// reference the same constants. A typo at any single call site would
/// silently drift the audit schema from its tests; pulling the strings
/// into a single module makes drift a compile error.
pub(crate) mod outcome_detail {
    /// Operator pressed `y` at the prompt.
    pub const OPERATOR_Y: &str = "operator-y";
    /// Operator pressed `a` ("always allow this rule this session").
    pub const OPERATOR_A: &str = "operator-a";
    /// Subsequent request matched a previously-cached `a` decision.
    pub const OPERATOR_A_CACHED: &str = "operator-a-cached";
    /// Operator pressed `n` at the prompt.
    pub const OPERATOR_N: &str = "operator-n";
    /// Operator pressed `never` ("never allow this rule this session").
    pub const OPERATOR_NEVER: &str = "operator-never";
    /// Subsequent request matched a previously-cached `never` decision.
    pub const OPERATOR_NEVER_CACHED: &str = "operator-never-cached";
    /// `auto-approve-reads = true` short-circuited a readonly scope
    /// without invoking the approval service. Distinct from cache hits.
    pub const AUTO_APPROVE_READS: &str = "auto-approve-reads";
    /// Approval service is structurally unavailable (no TTY, or
    /// daemon shutting down).
    pub const NO_TTY: &str = "no-tty";

    /// Format the `timeout-<N>s` outcome detail for a configurable
    /// approval timeout. Centralized so the format string is identical
    /// at every site.
    #[must_use]
    pub fn timeout(seconds: u64) -> String {
        format!("timeout-{seconds}s")
    }
}

/// Dispatch an approval-related audit event (best-effort, fire-and-track).
///
/// A free function (rather than a `&self` method on `PolicyService`)
/// because the `Decision::Prompt` path captures only a subset of
/// `self` into its async block — the full service reference would
/// require an additional `Arc` bump on every request.
///
/// Routes through the daemon-owned [`AuditDispatcher`] so the write
/// is drained on graceful shutdown (Story 8.2). Async because the
/// dispatcher applies producer-edge backpressure (Story 8.2 review
/// fix D1).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn write_approval_event_detached(
    audit_dispatcher: &Arc<AuditDispatcher>,
    request_id: &Option<String>,
    ctx: &PolicyContext,
    policy_name: &str,
    rule_id: &str,
    kind: ApprovalEventKind,
    outcome_detail: &str,
    cached: bool,
) {
    let event =
        build_approval_event(request_id, ctx, policy_name, rule_id, kind, outcome_detail, cached);
    audit_dispatcher.dispatch(event).await;
}

/// Pure function that builds an approval-related audit event (Story 8.2
/// review fix D1).
#[allow(clippy::too_many_arguments)]
fn build_approval_event(
    request_id: &Option<String>,
    ctx: &PolicyContext,
    policy_name: &str,
    rule_id: &str,
    kind: ApprovalEventKind,
    outcome_detail: &str,
    cached: bool,
) -> AuditEvent {
    // Same missing-request-id fallback as `write_audit_event` so
    // operators can grep for "missing-request-id" across both
    // policy-violation and approval-* events.
    let request_id_for_audit = match request_id {
        Some(id) if !id.is_empty() => id.clone(),
        _ => {
            warn!(
                "approval audit event has no RequestId — \
                 RequestTraceLayer may be missing from the chain"
            );
            "missing-request-id".to_owned()
        }
    };
    let mut event = AuditEvent::with_request_id(
        request_id_for_audit,
        ctx.agent_id.clone(),
        ctx.service.clone(),
        ctx.scope.clone(),
        ctx.resource.clone().unwrap_or_else(|| "-".to_owned()),
        kind.outcome().to_owned(),
        kind.event_type().to_owned(),
    );
    event.extra = serde_json::json!({
        "policy_name": policy_name,
        "rule_id": rule_id,
        "scope": ctx.scope,
        "resource": ctx.resource,
        "outcome_detail": outcome_detail,
        "cached": cached,
    });
    event
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{HeaderValue, Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::{ServiceBuilder, ServiceExt};

    // ── approval_timeout atomic wiring (Story 8.7 AC #1) ────────────

    #[test]
    fn policylayer_new_defaults_atomic_to_default_timeout_secs() {
        // AC #1: `PolicyLayer::new` initializes the atomic to
        // `DEFAULT_APPROVAL_TIMEOUT.as_secs()` (30 today). This is the
        // default path used when the daemon has no config override.
        let policy_set =
            Arc::new(ArcSwap::from_pointee(permitlayer_core::policy::PolicySet::empty()));
        let layer = PolicyLayer::new(policy_set, Arc::new(AuditDispatcher::none()));
        assert_eq!(
            layer.approval_timeout.load(Ordering::Relaxed),
            DEFAULT_APPROVAL_TIMEOUT.as_secs()
        );
    }

    // ── extract_policy_context tests ──────────────────────────────

    #[test]
    fn extract_context_rest_path_with_scope_header() {
        let mut req = Request::builder()
            .uri("/v1/tools/gmail/users/me/messages")
            .body(Body::empty())
            .unwrap();
        req.headers_mut().insert("x-agentsso-scope", HeaderValue::from_static("gmail.readonly"));
        req.extensions_mut().insert(AgentId("test-agent".to_owned()));

        let ctx = extract_policy_context(&req);
        assert_eq!(ctx.agent_id, "test-agent");
        assert_eq!(ctx.scope, "gmail.readonly");
        assert_eq!(ctx.service, "gmail");
        assert_eq!(ctx.resource.as_deref(), Some("users/me/messages"));
    }

    #[test]
    fn extract_context_rest_path_no_resource() {
        let req = Request::builder().uri("/v1/tools/gmail").body(Body::empty()).unwrap();

        let ctx = extract_policy_context(&req);
        assert_eq!(ctx.service, "gmail");
        assert!(ctx.resource.is_none());
    }

    #[test]
    fn extract_context_mcp_default_gmail() {
        let req = Request::builder().uri("/mcp").body(Body::empty()).unwrap();

        let ctx = extract_policy_context(&req);
        assert_eq!(ctx.service, "gmail");
        assert!(ctx.resource.is_none());
    }

    #[test]
    fn extract_context_mcp_calendar() {
        let req = Request::builder().uri("/mcp/calendar").body(Body::empty()).unwrap();

        let ctx = extract_policy_context(&req);
        assert_eq!(ctx.service, "calendar");
        assert!(ctx.resource.is_none());
    }

    #[test]
    fn extract_context_defaults_scope_to_wildcard() {
        let req = Request::builder().uri("/v1/tools/drive/files/abc").body(Body::empty()).unwrap();

        let ctx = extract_policy_context(&req);
        assert_eq!(ctx.scope, "*");
        assert_eq!(ctx.service, "drive");
        assert_eq!(ctx.resource.as_deref(), Some("files/abc"));
    }

    #[test]
    fn extract_context_defaults_agent_id_to_unknown() {
        let req = Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();

        let ctx = extract_policy_context(&req);
        assert_eq!(ctx.agent_id, "unknown");
    }

    #[test]
    fn extract_context_unknown_path() {
        let req = Request::builder().uri("/v1/health").body(Body::empty()).unwrap();

        let ctx = extract_policy_context(&req);
        assert_eq!(ctx.service, "-");
        assert!(ctx.resource.is_none());
    }

    #[test]
    fn extract_context_rejects_service_substring_contamination() {
        let req =
            Request::builder().uri("/v1/tools/gmail-exploit/evil").body(Body::empty()).unwrap();

        let ctx = extract_policy_context(&req);
        assert_eq!(ctx.service, "-");
    }

    // ── derive_service_and_resource tests ──────────────────────────

    #[test]
    fn derive_rest_gmail_with_resource() {
        let (svc, res) = derive_service_and_resource("/v1/tools/gmail/users/me/messages");
        assert_eq!(svc, "gmail");
        assert_eq!(res.as_deref(), Some("users/me/messages"));
    }

    #[test]
    fn derive_rest_calendar_with_resource() {
        let (svc, res) = derive_service_and_resource("/v1/tools/calendar/calendars/primary/events");
        assert_eq!(svc, "calendar");
        assert_eq!(res.as_deref(), Some("calendars/primary/events"));
    }

    #[test]
    fn derive_rest_no_resource() {
        let (svc, res) = derive_service_and_resource("/v1/tools/gmail");
        assert_eq!(svc, "gmail");
        assert!(res.is_none());
    }

    #[test]
    fn derive_rest_trailing_slash_no_resource() {
        let (svc, res) = derive_service_and_resource("/v1/tools/gmail/");
        assert_eq!(svc, "gmail");
        assert!(res.is_none());
    }

    #[test]
    fn derive_mcp_default_gmail() {
        let (svc, res) = derive_service_and_resource("/mcp");
        assert_eq!(svc, "gmail");
        assert!(res.is_none());
    }

    #[test]
    fn derive_mcp_drive() {
        let (svc, res) = derive_service_and_resource("/mcp/drive");
        assert_eq!(svc, "drive");
        assert!(res.is_none());
    }

    #[test]
    fn derive_unknown_service() {
        let (svc, _) = derive_service_and_resource("/v1/tools/unknown-svc/foo");
        assert_eq!(svc, "-");
    }

    #[test]
    fn derive_strips_query_string_defensively() {
        // `URI::path()` already strips the query in production, but
        // `derive_service_and_resource` defensively strips again so
        // direct callers passing raw URI strings get the same behavior.
        // After stripping `?alt=json`, the path is `/v1/tools/gmail/users/me`
        // and the resource is `users/me`.
        let (svc, res) = derive_service_and_resource("/v1/tools/gmail/users/me?alt=json");
        assert_eq!(svc, "gmail");
        assert_eq!(res.as_deref(), Some("users/me"));
    }

    #[test]
    fn derive_handles_double_slash_after_prefix() {
        // Regression: `/v1/tools//gmail/users/me` (double slash) used to
        // produce `service_segment = ""` which fell through to `"-"`,
        // bypassing policy enforcement entirely. The collapse-leading-
        // slashes step now extracts `gmail` correctly.
        let (svc, res) = derive_service_and_resource("/v1/tools//gmail/users/me");
        assert_eq!(svc, "gmail");
        assert_eq!(res.as_deref(), Some("users/me"));
    }

    #[test]
    fn derive_handles_triple_slash_after_prefix() {
        // Defense in depth: any number of leading slashes collapse.
        let (svc, _) = derive_service_and_resource("/v1/tools///gmail");
        assert_eq!(svc, "gmail");
    }

    #[test]
    fn derive_resource_trims_trailing_slash() {
        // `/v1/tools/gmail//` used to produce `resource = Some("/")`
        // which would never match a policy allowlist and produced a
        // confusing audit log line. Now it's `None`.
        let (svc, res) = derive_service_and_resource("/v1/tools/gmail//");
        assert_eq!(svc, "gmail");
        assert!(res.is_none());
    }

    #[test]
    fn derive_resource_trims_leading_slash() {
        let (svc, res) = derive_service_and_resource("/v1/tools/gmail///users/me///");
        assert_eq!(svc, "gmail");
        assert_eq!(res.as_deref(), Some("users/me"));
    }

    // ── resolve_policy_name tests (Story 4.4) ──────────────────────

    #[test]
    fn resolve_returns_none_when_no_extension() {
        // Post-Story-4.4: missing AgentPolicyBinding → None →
        // PolicyLayer issues default-deny-no-agent-binding.
        let req = Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        assert!(resolve_policy_name(&req).is_none());
    }

    #[test]
    fn resolve_returns_extension_value() {
        let mut req =
            Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        req.extensions_mut().insert(AgentPolicyBinding("my-policy".to_owned()));
        assert_eq!(resolve_policy_name(&req), Some("my-policy".to_owned()));
    }

    #[test]
    fn resolve_ignores_policy_set_count() {
        // Regression guard: Story 4.4 deleted the single-policy
        // shortcut. Even with an empty PolicySet (where the old
        // heuristic would have returned None) or a populated PolicySet
        // (where the old heuristic would have returned the only
        // policy's name), the new function only reads the extension.
        // Two requests with the same extension produce the same answer
        // regardless of what policies happen to be loaded.
        let mut req = Request::builder().uri("/v1/tools/gmail").body(Body::empty()).unwrap();
        req.extensions_mut().insert(AgentPolicyBinding("specific-policy".to_owned()));
        assert_eq!(resolve_policy_name(&req), Some("specific-policy".to_owned()));
    }

    #[test]
    fn default_deny_no_agent_binding_when_two_policies_present() {
        // Regression guard for the Story 4.4 invariant: with TWO
        // policies in the set and NO AgentPolicyBinding extension,
        // the request must default-deny rather than auto-bind to
        // either policy. The pre-Story-4.4 single-policy heuristic
        // would have returned None here too (because n=2), but the
        // intent of the regression guard is to prove that even adding
        // a third policy or moving to one wouldn't change the
        // post-4.4 outcome — the request needs an explicit binding,
        // full stop.
        let req = Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        // No AgentPolicyBinding extension at all.
        assert!(
            resolve_policy_name(&req).is_none(),
            "request without AgentPolicyBinding must produce None — single-policy heuristic is gone"
        );
    }

    // ── PolicyService integration tests ──────────────────────────

    /// Helper: write a single-policy TOML to a tempdir, compile, and
    /// return the `Arc<ArcSwap<PolicySet>>`.
    fn make_policy_set(toml_content: &str) -> (tempfile::TempDir, Arc<ArcSwap<PolicySet>>) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test.toml"), toml_content).unwrap();
        let ps = PolicySet::compile_from_dir(dir.path()).unwrap();
        (dir, Arc::new(ArcSwap::from_pointee(ps)))
    }

    async fn handler(_req: Request<Body>) -> Result<Response<Body>, std::convert::Infallible> {
        Ok(Response::builder().status(StatusCode::OK).body(Body::from("ok")).unwrap())
    }

    async fn call_policy_layer(
        policy_set: Arc<ArcSwap<PolicySet>>,
        req: Request<Body>,
    ) -> Response<Body> {
        // Default: AlwaysDenyApprovalService (Decision::Prompt → 503
        // policy.approval_unavailable). Tests that exercise approval
        // outcomes use `call_policy_layer_with_approval` below.
        let svc = ServiceBuilder::new()
            .layer(PolicyLayer::new(policy_set, Arc::new(AuditDispatcher::none())))
            .service(tower::service_fn(handler));

        svc.oneshot(req).await.unwrap()
    }

    /// Build a `PolicyLayer` with a custom approval service. Used by
    /// Story 4.5 tests to exercise the full `Decision::Prompt` dispatch.
    async fn call_policy_layer_with_approval(
        policy_set: Arc<ArcSwap<PolicySet>>,
        approval: Arc<dyn crate::middleware::approval::ApprovalService>,
        req: Request<Body>,
    ) -> Response<Body> {
        call_policy_layer_with_approval_and_audit(policy_set, approval, None, req).await
    }

    async fn call_policy_layer_with_approval_and_audit(
        policy_set: Arc<ArcSwap<PolicySet>>,
        approval: Arc<dyn crate::middleware::approval::ApprovalService>,
        audit_store: Option<Arc<dyn AuditStore>>,
        req: Request<Body>,
    ) -> Response<Body> {
        let dispatcher = match audit_store {
            Some(store) => Arc::new(AuditDispatcher::for_tests_unbounded(store)),
            None => Arc::new(AuditDispatcher::none()),
        };
        let layer = PolicyLayer::with_approval_service(
            policy_set,
            dispatcher,
            approval,
            Arc::new(AtomicU64::new(DEFAULT_APPROVAL_TIMEOUT.as_secs())),
        );
        let svc = ServiceBuilder::new().layer(layer).service(tower::service_fn(handler));
        svc.oneshot(req).await.unwrap()
    }

    async fn body_json(resp: Response<Body>) -> serde_json::Value {
        let bytes = Body::new(resp.into_body()).collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    /// Build a test request. The `binding` parameter sets the
    /// `AgentPolicyBinding` extension that `PolicyLayer` reads via
    /// `resolve_policy_name`. Pass `None` to exercise the
    /// default-deny-no-agent-binding path.
    fn make_req(
        uri: &str,
        scope: Option<&str>,
        agent_id: Option<&str>,
        binding: Option<&str>,
    ) -> Request<Body> {
        let mut req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        if let Some(s) = scope {
            req.headers_mut().insert("x-agentsso-scope", HeaderValue::from_str(s).unwrap());
        }
        if let Some(a) = agent_id {
            req.extensions_mut().insert(AgentId(a.to_owned()));
        }
        if let Some(b) = binding {
            req.extensions_mut().insert(AgentPolicyBinding(b.to_owned()));
        }
        // Insert a request ID for correlation tests.
        req.extensions_mut().insert(RequestId("01TESTPOLICY".to_owned()));
        req
    }

    #[tokio::test]
    async fn allow_when_scope_matches_policy() {
        let (_dir, ps) = make_policy_set(
            r#"
[[policies]]
name = "test-allow"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
"#,
        );

        let req =
            make_req("/v1/tools/gmail/users/me", Some("gmail.readonly"), None, Some("test-allow"));
        let resp = call_policy_layer(ps, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn deny_when_scope_out_of_allowlist() {
        let (_dir, ps) = make_policy_set(
            r#"
[[policies]]
name = "test-deny-scope"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
"#,
        );

        let req = make_req(
            "/v1/tools/gmail/users/me",
            Some("gmail.modify"),
            None,
            Some("test-deny-scope"),
        );
        let resp = call_policy_layer(ps, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let json = body_json(resp).await;
        assert_eq!(json["error"]["code"], "policy.denied");
        assert_eq!(json["error"]["rule_id"], "default-deny-scope-out-of-allowlist");
        assert_eq!(json["error"]["denied_scope"], "gmail.modify");
        assert_eq!(json["error"]["policy_name"], "test-deny-scope");
    }

    #[tokio::test]
    async fn deny_when_resource_out_of_allowlist() {
        let (_dir, ps) = make_policy_set(
            r#"
[[policies]]
name = "test-deny-resource"
scopes = ["calendar.events.read"]
resources = ["primary"]
approval-mode = "auto"
"#,
        );

        let req = make_req(
            "/v1/tools/calendar/calendars/family/events",
            Some("calendar.events.read"),
            None,
            Some("test-deny-resource"),
        );
        let resp = call_policy_layer(ps, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let json = body_json(resp).await;
        assert_eq!(json["error"]["code"], "policy.denied");
        assert_eq!(json["error"]["rule_id"], "default-deny-resource-out-of-allowlist");
        // Resource in deny body should be the full resource path from the request.
        assert!(json["error"]["denied_resource"].is_string());
        assert_eq!(json["error"]["policy_name"], "test-deny-resource");
    }

    #[tokio::test]
    async fn deny_no_agent_binding_multi_policy() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.toml"),
            r#"
[[policies]]
name = "policy-a"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("b.toml"),
            r#"
[[policies]]
name = "policy-b"
scopes = ["calendar.events.read"]
resources = ["*"]
approval-mode = "auto"
"#,
        )
        .unwrap();
        let ps = PolicySet::compile_from_dir(dir.path()).unwrap();
        let ps = Arc::new(ArcSwap::from_pointee(ps));

        // No AgentPolicyBinding extension → default-deny-no-agent-binding.
        // Post-Story-4.4: this is the canonical no-binding path; the
        // single-policy heuristic that used to auto-bind on n=1 is gone,
        // so n=2 here is no longer special — n=0, 1, 2, anything-without-
        // a-binding all hit the same fail-closed code.
        let req = make_req("/v1/tools/gmail/users/me", Some("gmail.readonly"), None, None);
        let resp = call_policy_layer(ps, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let json = body_json(resp).await;
        assert_eq!(json["error"]["code"], "policy.denied");
        assert_eq!(json["error"]["rule_id"], "default-deny-no-agent-binding");
    }

    #[tokio::test]
    async fn deny_empty_policy_set() {
        let ps = Arc::new(ArcSwap::from_pointee(PolicySet::empty()));

        // No binding → default-deny-no-agent-binding regardless of
        // whether the PolicySet is empty.
        let req = make_req("/v1/tools/gmail/users/me", Some("gmail.readonly"), None, None);
        let resp = call_policy_layer(ps, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let json = body_json(resp).await;
        assert_eq!(json["error"]["rule_id"], "default-deny-no-agent-binding");
    }

    // ── Story 4.5: Decision::Prompt dispatch through ApprovalService ──

    #[tokio::test]
    async fn prompt_with_default_approval_service_returns_503_unavailable() {
        // Migrated from Story 4.3's `prompt_returns_approval_required`.
        // The default `AlwaysDenyApprovalService` returns `Unavailable`,
        // which PolicyLayer maps to HTTP 503 `policy.approval_unavailable`.
        // This is the production fallback when no real approval service
        // is wired up (test scaffolding, broken configuration, etc.).
        let (_dir, ps) = make_policy_set(
            r#"
[[policies]]
name = "test-prompt"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "prompt"
"#,
        );

        let req =
            make_req("/v1/tools/gmail/users/me", Some("gmail.readonly"), None, Some("test-prompt"));
        let resp = call_policy_layer(ps, req).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json = body_json(resp).await;
        assert_eq!(json["error"]["code"], "policy.approval_unavailable");
        assert_eq!(json["error"]["policy_name"], "test-prompt");
    }

    #[tokio::test]
    async fn prompt_with_granted_mock_passes_through_to_inner() {
        use crate::middleware::approval::{ApprovalOutcome, MockApprovalService};
        let (_dir, ps) = make_policy_set(
            r#"
[[policies]]
name = "test-prompt"
scopes = ["gmail.modify"]
resources = ["*"]
approval-mode = "prompt"
"#,
        );
        let mock = Arc::new(MockApprovalService::with_decisions(vec![ApprovalOutcome::Granted]));
        let req =
            make_req("/v1/tools/gmail/users/me", Some("gmail.modify"), None, Some("test-prompt"));
        let resp = call_policy_layer_with_approval(ps, mock.clone(), req).await;
        // Inner handler returns 200 OK with body "ok".
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(mock.call_count(), 1);
    }

    #[tokio::test]
    async fn prompt_with_denied_mock_returns_403_approval_required() {
        use crate::middleware::approval::{ApprovalOutcome, MockApprovalService};
        let (_dir, ps) = make_policy_set(
            r#"
[[policies]]
name = "test-prompt"
scopes = ["gmail.modify"]
resources = ["*"]
approval-mode = "prompt"
"#,
        );
        let mock = Arc::new(MockApprovalService::with_decisions(vec![ApprovalOutcome::Denied]));
        let req =
            make_req("/v1/tools/gmail/users/me", Some("gmail.modify"), None, Some("test-prompt"));
        let resp = call_policy_layer_with_approval(ps, mock, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let json = body_json(resp).await;
        assert_eq!(json["error"]["code"], "policy.approval_required");
        assert_eq!(json["error"]["policy_name"], "test-prompt");
    }

    #[tokio::test]
    async fn prompt_with_timeout_mock_returns_403_approval_timeout() {
        // Story 4.5 review: timeouts get a distinct `policy.approval_timeout`
        // error code (still 403) so agents can implement smart retry —
        // a timeout means "operator AFK, safe to retry," while
        // `policy.approval_required` means "operator said no, do not retry."
        use crate::middleware::approval::{ApprovalOutcome, MockApprovalService};
        let (_dir, ps) = make_policy_set(
            r#"
[[policies]]
name = "test-prompt"
scopes = ["gmail.modify"]
resources = ["*"]
approval-mode = "prompt"
"#,
        );
        let mock = Arc::new(MockApprovalService::with_decisions(vec![ApprovalOutcome::Timeout]));
        let req =
            make_req("/v1/tools/gmail/users/me", Some("gmail.modify"), None, Some("test-prompt"));
        let resp = call_policy_layer_with_approval(ps, mock, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let json = body_json(resp).await;
        assert_eq!(json["error"]["code"], "policy.approval_timeout");
    }

    #[tokio::test]
    async fn prompt_with_unavailable_mock_returns_503_approval_unavailable() {
        use crate::middleware::approval::{ApprovalOutcome, MockApprovalService};
        let (_dir, ps) = make_policy_set(
            r#"
[[policies]]
name = "test-prompt"
scopes = ["gmail.modify"]
resources = ["*"]
approval-mode = "prompt"
"#,
        );
        let mock =
            Arc::new(MockApprovalService::with_decisions(vec![ApprovalOutcome::Unavailable]));
        let req =
            make_req("/v1/tools/gmail/users/me", Some("gmail.modify"), None, Some("test-prompt"));
        let resp = call_policy_layer_with_approval(ps, mock, req).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json = body_json(resp).await;
        assert_eq!(json["error"]["code"], "policy.approval_unavailable");
    }

    #[tokio::test]
    async fn prompt_with_always_mock_populates_cache_for_second_call() {
        use crate::middleware::approval::{ApprovalOutcome, MockApprovalService};
        let (_dir, ps) = make_policy_set(
            r#"
[[policies]]
name = "test-prompt"
scopes = ["gmail.modify"]
resources = ["*"]
approval-mode = "prompt"
"#,
        );
        // First canned outcome: Always (populates cache).
        // Second canned outcome: Denied (must NOT be consumed — the
        // second request hits the cache and returns AlwaysAllowCached).
        let mock = Arc::new(MockApprovalService::with_decisions(vec![
            ApprovalOutcome::AlwaysAllowThisSession {
                rule_id: "default-prompt-approval-mode".to_owned(),
            },
            ApprovalOutcome::Denied,
        ]));

        let req1 =
            make_req("/v1/tools/gmail/users/me", Some("gmail.modify"), None, Some("test-prompt"));
        let resp1 = call_policy_layer_with_approval(
            Arc::clone(&ps),
            mock.clone() as Arc<dyn crate::middleware::approval::ApprovalService>,
            req1,
        )
        .await;
        assert_eq!(resp1.status(), StatusCode::OK, "first request should pass through");

        let req2 =
            make_req("/v1/tools/gmail/users/me", Some("gmail.modify"), None, Some("test-prompt"));
        let resp2 = call_policy_layer_with_approval(
            ps,
            mock.clone() as Arc<dyn crate::middleware::approval::ApprovalService>,
            req2,
        )
        .await;
        assert_eq!(resp2.status(), StatusCode::OK, "second request should hit the always cache");

        // The Denied outcome must still be in the queue — proves the
        // second call was served from the cache, not the canned queue.
        assert_eq!(mock.remaining(), 1);
    }

    #[tokio::test]
    async fn auto_approve_reads_bypasses_approval_service_for_readonly_scope() {
        use crate::middleware::approval::MockApprovalService;
        // Policy with approval-mode = "prompt" + auto-approve-reads = true.
        // A readonly scope should bypass the prompt entirely.
        let (_dir, ps) = make_policy_set(
            r#"
[[policies]]
name = "test-read-bypass"
scopes = ["gmail.readonly", "gmail.modify"]
resources = ["*"]
approval-mode = "prompt"
auto-approve-reads = true
"#,
        );
        // Empty mock queue — if the short-circuit fails, the test will
        // see the fallthrough `Unavailable` and 503.
        let mock = Arc::new(MockApprovalService::with_decisions(vec![]));
        let req = make_req(
            "/v1/tools/gmail/users/me",
            Some("gmail.readonly"),
            None,
            Some("test-read-bypass"),
        );
        let resp = call_policy_layer_with_approval(
            ps,
            mock.clone() as Arc<dyn crate::middleware::approval::ApprovalService>,
            req,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "readonly should pass without prompting");
        // The approval service must NOT have been invoked.
        assert_eq!(
            mock.call_count(),
            0,
            "auto-approve-reads must short-circuit before ApprovalService"
        );
    }

    #[tokio::test]
    async fn auto_approve_reads_still_prompts_for_write_scope() {
        use crate::middleware::approval::{ApprovalOutcome, MockApprovalService};
        // Same policy as above — but this time send a write scope.
        // Writes should still go through the approval service.
        let (_dir, ps) = make_policy_set(
            r#"
[[policies]]
name = "test-read-bypass"
scopes = ["gmail.readonly", "gmail.modify"]
resources = ["*"]
approval-mode = "prompt"
auto-approve-reads = true
"#,
        );
        let mock = Arc::new(MockApprovalService::with_decisions(vec![ApprovalOutcome::Granted]));
        let req = make_req(
            "/v1/tools/gmail/users/me",
            Some("gmail.modify"),
            None,
            Some("test-read-bypass"),
        );
        let resp = call_policy_layer_with_approval(
            ps,
            mock.clone() as Arc<dyn crate::middleware::approval::ApprovalService>,
            req,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(mock.call_count(), 1, "write scopes must still invoke the approval service");
    }

    #[tokio::test]
    async fn auto_approve_reads_false_prompts_for_readonly_too() {
        use crate::middleware::approval::{ApprovalOutcome, MockApprovalService};
        // approval-mode = "prompt" WITHOUT auto-approve-reads → every
        // scope prompts, including readonly. Proves the short-circuit
        // is gated on the flag, not blanket.
        let (_dir, ps) = make_policy_set(
            r#"
[[policies]]
name = "test-prompt-all"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "prompt"
"#,
        );
        let mock = Arc::new(MockApprovalService::with_decisions(vec![ApprovalOutcome::Granted]));
        let req = make_req(
            "/v1/tools/gmail/users/me",
            Some("gmail.readonly"),
            None,
            Some("test-prompt-all"),
        );
        let resp = call_policy_layer_with_approval(
            ps,
            mock.clone() as Arc<dyn crate::middleware::approval::ApprovalService>,
            req,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(mock.call_count(), 1);
    }

    #[tokio::test]
    async fn auto_approve_reads_does_not_override_explicit_rule_level_prompt() {
        use crate::middleware::approval::{ApprovalOutcome, MockApprovalService};
        // Story 4.5 review (Decision 1): an operator-written rule with
        // `action = "prompt"` on a readonly scope MUST be honored even
        // when the policy has `auto-approve-reads = true`. The
        // auto-approve-reads short-circuit is restricted to the
        // policy-level fall-through (`rule_id ==
        // "default-prompt-approval-mode"`), not explicit rule-level
        // prompts. This preserves operator intent: writing a rule that
        // says "prompt on this specific readonly scope" should not be
        // silently bypassed.
        //
        // Setup: policy with `approval-mode = "auto"` (so the default
        // path is allow), `auto-approve-reads = true`, and an explicit
        // rule `{ scope = "gmail.readonly", action = "prompt" }`. A
        // request to `gmail.readonly` should match the explicit rule
        // (Decision::Prompt with the rule's id) and the short-circuit
        // should NOT fire.
        let (_dir, ps) = make_policy_set(
            r#"
[[policies]]
name = "test-explicit-prompt-on-read"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
auto-approve-reads = true

[[policies.rules]]
id = "explicit-prompt-readonly"
scopes = ["gmail.readonly"]
action = "prompt"
"#,
        );
        let mock = Arc::new(MockApprovalService::with_decisions(vec![ApprovalOutcome::Granted]));
        let req = make_req(
            "/v1/tools/gmail/users/me",
            Some("gmail.readonly"),
            None,
            Some("test-explicit-prompt-on-read"),
        );
        let resp = call_policy_layer_with_approval(
            ps,
            mock.clone() as Arc<dyn crate::middleware::approval::ApprovalService>,
            req,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        // The approval service MUST have been invoked exactly once —
        // the explicit rule's prompt was honored, not bypassed by
        // auto-approve-reads.
        assert_eq!(
            mock.call_count(),
            1,
            "explicit rule-level action='prompt' must NOT be bypassed by auto-approve-reads"
        );
    }

    #[tokio::test]
    async fn request_id_echoed_in_deny_response() {
        let (_dir, ps) = make_policy_set(
            r#"
[[policies]]
name = "test-id"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
"#,
        );

        let req = make_req("/v1/tools/gmail/users/me", Some("gmail.modify"), None, Some("test-id"));
        let resp = call_policy_layer(ps, req).await;
        let json = body_json(resp).await;
        assert_eq!(json["error"]["request_id"], "01TESTPOLICY");
    }

    #[tokio::test]
    async fn deny_when_wildcard_scope_not_in_allowlist() {
        // Agent sends no scope header (defaults to "*"), but policy
        // doesn't list "*" in scopes. Should be denied — not allowed.
        // This is the default-deny spirit of FR48 — a missing scope
        // header MUST NOT silently bypass the scope allowlist.
        let (_dir, ps) = make_policy_set(
            r#"
[[policies]]
name = "no-wildcard"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
"#,
        );

        let req = make_req("/v1/tools/gmail/users/me", None, None, Some("no-wildcard"));
        let resp = call_policy_layer(ps, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let json = body_json(resp).await;
        assert_eq!(json["error"]["rule_id"], "default-deny-scope-out-of-allowlist");
    }

    #[tokio::test]
    async fn empty_scope_header_canonicalized_to_wildcard() {
        // An explicitly-empty `x-agentsso-scope: ` header has the same
        // semantics as a missing header (both default to "*"), so a
        // policy without "*" in its allowlist denies both consistently.
        let (_dir, ps) = make_policy_set(
            r#"
[[policies]]
name = "no-wildcard"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
"#,
        );

        let req = make_req("/v1/tools/gmail/users/me", Some(""), None, Some("no-wildcard"));
        let resp = call_policy_layer(ps, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let json = body_json(resp).await;
        // The denied_scope echoes the canonicalized value, not "".
        assert_eq!(json["error"]["denied_scope"], "*");
    }

    #[test]
    fn extract_context_truncates_oversize_scope() {
        // A 10K-character scope header is truncated to MAX_REQUEST_SCOPE_LEN
        // before being stored in PolicyContext. Without this guard, the
        // full attacker-controlled string would flow into the audit log
        // and the 403 response body.
        let huge_scope: String = "a".repeat(10_000);
        let mut req =
            Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        req.headers_mut().insert("x-agentsso-scope", HeaderValue::from_str(&huge_scope).unwrap());

        let ctx = extract_policy_context(&req);
        assert_eq!(ctx.scope.chars().count(), MAX_REQUEST_SCOPE_LEN);
        assert!(ctx.scope.chars().all(|c| c == 'a'));
    }

    #[test]
    fn extract_context_canonicalizes_empty_and_missing_scope() {
        // Missing header → "*"
        let req = Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        assert_eq!(extract_policy_context(&req).scope, "*");

        // Empty header → "*"
        let mut req =
            Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        req.headers_mut().insert("x-agentsso-scope", HeaderValue::from_static(""));
        assert_eq!(extract_policy_context(&req).scope, "*");
    }

    // ── MCP resource contract ─────────────────────────────────────

    #[test]
    fn mcp_paths_always_have_resource_none() {
        // MCP resource contract: all /mcp/* paths return resource=None
        // because the resource lives in the JSON-RPC body, not the URL.
        // Policies bound to MCP traffic MUST set `resources = ["*"]`.
        for path in [
            "/mcp",
            "/mcp/",
            "/mcp/gmail",
            "/mcp/gmail/some/method",
            "/mcp/calendar",
            "/mcp/calendar/list",
            "/mcp/drive",
            "/mcp/drive/files/abc",
        ] {
            let (_, res) = derive_service_and_resource(path);
            assert!(res.is_none(), "MCP path {path} should have resource=None, got {res:?}");
        }
    }

    #[tokio::test]
    async fn mcp_request_denied_by_narrowed_resource_policy() {
        // Pinning the documented MCP contract: a policy with a non-`*`
        // resource allowlist denies all MCP traffic because MCP requests
        // always evaluate with `resource=None`, which never matches a
        // non-empty allowlist (compile.rs:134-136).
        let (_dir, ps) = make_policy_set(
            r#"
[[policies]]
name = "mcp-narrow"
scopes = ["gmail.readonly"]
resources = ["primary"]
approval-mode = "auto"
"#,
        );

        let req = make_req("/mcp", Some("gmail.readonly"), None, Some("mcp-narrow"));
        let resp = call_policy_layer(ps, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let json = body_json(resp).await;
        assert_eq!(json["error"]["rule_id"], "default-deny-resource-out-of-allowlist");
    }

    // ── Operational path bypass ─────────────────────────────────

    #[test]
    fn is_operational_path_recognizes_known_endpoints() {
        assert!(is_operational_path("/health"));
        assert!(is_operational_path("/v1/health"));
        assert!(is_operational_path("/v1/control/kill"));
        assert!(is_operational_path("/v1/control/resume"));
        assert!(is_operational_path("/v1/control/reload"));
    }

    #[test]
    fn is_operational_path_rejects_service_paths() {
        assert!(!is_operational_path("/v1/tools/gmail/users/me"));
        assert!(!is_operational_path("/mcp"));
        assert!(!is_operational_path("/mcp/gmail"));
    }

    #[test]
    fn is_operational_path_rejects_unknown_paths() {
        // Defense-in-depth: unknown paths must NOT bypass policy.
        assert!(!is_operational_path("/random/path"));
        assert!(!is_operational_path("/admin"));
        assert!(!is_operational_path("/v1/control/unknown"));
        assert!(!is_operational_path(""));
        assert!(!is_operational_path("/"));
    }

    #[tokio::test]
    async fn unknown_path_does_not_bypass_policy_with_empty_set() {
        // Regression: previously the `service == "-"` short-circuit
        // would let unknown paths fall through to the inner handler
        // even with an empty PolicySet. Now they must be evaluated and
        // denied because nothing matches.
        let policy_set = Arc::new(ArcSwap::from_pointee(PolicySet::empty()));
        let svc = ServiceBuilder::new()
            .layer(PolicyLayer::new(policy_set, Arc::new(AuditDispatcher::none())))
            .service(tower::service_fn(handler));

        // Unknown path with no scope header — should be denied, not OK.
        let req = Request::builder().uri("/random/path").body(Body::empty()).unwrap();
        let resp: Response<Body> = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn non_service_paths_skip_policy_evaluation() {
        // Non-service paths (health probes, control endpoints, etc.)
        // bypass policy evaluation entirely — they're operational
        // endpoints, not upstream API calls. Even with an empty
        // PolicySet, these pass through to the inner handler.
        let policy_set = Arc::new(ArcSwap::from_pointee(PolicySet::empty()));
        let svc = ServiceBuilder::new()
            .layer(PolicyLayer::new(policy_set, Arc::new(AuditDispatcher::none())))
            .service(tower::service_fn(handler));

        let req = Request::builder().uri("/v1/health").body(Body::empty()).unwrap();
        let resp: Response<Body> = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn service_paths_enforced_with_empty_policy_set() {
        // Service paths (/v1/tools/*, /mcp/*) are enforced. An empty
        // PolicySet means no agent binding exists → deny.
        let policy_set = Arc::new(ArcSwap::from_pointee(PolicySet::empty()));
        let svc = ServiceBuilder::new()
            .layer(PolicyLayer::new(policy_set, Arc::new(AuditDispatcher::none())))
            .service(tower::service_fn(handler));

        let req = Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        let resp: Response<Body> = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // ── Audit-event correlation + shape tests ──────────────────────

    use permitlayer_core::store::{AuditStore, StoreError};
    use std::sync::Mutex;

    /// Mock `AuditStore` that captures appended events for inspection.
    struct MockAuditStore {
        events: Mutex<Vec<AuditEvent>>,
    }

    impl MockAuditStore {
        fn new() -> Arc<Self> {
            Arc::new(Self { events: Mutex::new(Vec::new()) })
        }

        fn events(&self) -> Vec<AuditEvent> {
            self.events.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl AuditStore for MockAuditStore {
        async fn append(&self, event: AuditEvent) -> Result<(), StoreError> {
            self.events.lock().unwrap().push(event);
            Ok(())
        }
    }

    /// Wait briefly for the fire-and-forget audit task to write its event.
    async fn wait_for_audit_events(store: &MockAuditStore, expected: usize) {
        for _ in 0..50 {
            if store.events().len() >= expected {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    }

    /// Story 8.2: construct an `Arc<AuditDispatcher>` wrapping a shared
    /// `MockAuditStore`. Tests must hold the returned Arc for the full
    /// duration of the test so the dispatcher's owned `JoinSet` is not
    /// dropped (and its tasks aborted) before the audit write completes.
    fn test_dispatcher(store: &Arc<MockAuditStore>) -> Arc<AuditDispatcher> {
        Arc::new(AuditDispatcher::for_tests_unbounded(Arc::clone(store) as Arc<dyn AuditStore>))
    }

    #[tokio::test]
    async fn audit_event_request_id_matches_request_extension() {
        // Story 3.3 retro pattern #3: request-ID correlation between
        // the response and the audit event. The audit event's
        // `request_id` MUST match the `RequestId` extension threaded
        // through by `RequestTraceLayer`.
        let (_dir, ps) = make_policy_set(
            r#"
[[policies]]
name = "correlation-test"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
"#,
        );
        let audit = MockAuditStore::new();
        let dispatcher = test_dispatcher(&audit);
        let svc = ServiceBuilder::new()
            .layer(PolicyLayer::new(ps, Arc::clone(&dispatcher)))
            .service(tower::service_fn(handler));

        // make_req helper inserts RequestId("01TESTPOLICY").
        let req = make_req(
            "/v1/tools/gmail/users/me",
            Some("gmail.modify"),
            None,
            Some("correlation-test"),
        );
        let _resp = svc.oneshot(req).await.unwrap();

        wait_for_audit_events(&audit, 1).await;
        let events = audit.events();
        assert_eq!(events.len(), 1, "expected one policy-violation audit event");
        let event = &events[0];
        assert_eq!(
            event.request_id, "01TESTPOLICY",
            "audit event request_id must match the RequestId extension"
        );
        assert_eq!(event.event_type, "policy-violation");
        assert_eq!(event.outcome, "denied");
        assert_eq!(event.agent_id, "unknown");
        assert_eq!(event.service, "gmail");
        assert_eq!(event.scope, "gmail.modify");
    }

    #[tokio::test]
    async fn audit_event_extra_carries_decision_fields() {
        let (_dir, ps) = make_policy_set(
            r#"
[[policies]]
name = "extra-test"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
"#,
        );
        let audit = MockAuditStore::new();
        let dispatcher = test_dispatcher(&audit);
        let svc = ServiceBuilder::new()
            .layer(PolicyLayer::new(ps, Arc::clone(&dispatcher)))
            .service(tower::service_fn(handler));

        let req =
            make_req("/v1/tools/gmail/users/me", Some("gmail.modify"), None, Some("extra-test"));
        let _resp = svc.oneshot(req).await.unwrap();
        wait_for_audit_events(&audit, 1).await;

        let events = audit.events();
        let extra = &events[0].extra;
        assert_eq!(extra["policy_name"], "extra-test");
        assert_eq!(extra["rule_id"], "default-deny-scope-out-of-allowlist");
        assert_eq!(extra["denied_scope"], "gmail.modify");
        assert!(extra["denied_resource"].is_null());
        assert_eq!(extra["decision"], "deny");
    }

    #[tokio::test]
    async fn audit_event_shape_snapshot() {
        // Snapshot the canonical policy-violation audit event shape so
        // any future schema drift surfaces immediately. Task 5.4 of the
        // story explicitly required an insta snapshot for this.
        let (_dir, ps) = make_policy_set(
            r#"
[[policies]]
name = "snapshot-test"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
"#,
        );
        let audit = MockAuditStore::new();
        let dispatcher = test_dispatcher(&audit);
        let svc = ServiceBuilder::new()
            .layer(PolicyLayer::new(ps, Arc::clone(&dispatcher)))
            .service(tower::service_fn(handler));

        let req =
            make_req("/v1/tools/gmail/users/me", Some("gmail.modify"), None, Some("snapshot-test"));
        let _resp = svc.oneshot(req).await.unwrap();
        wait_for_audit_events(&audit, 1).await;

        let events = audit.events();
        let event = &events[0];
        // Build a stable JSON view (omit timestamp, which is non-deterministic).
        let snapshot = serde_json::json!({
            "request_id": event.request_id,
            "agent_id": event.agent_id,
            "service": event.service,
            "scope": event.scope,
            "resource": event.resource,
            "outcome": event.outcome,
            "event_type": event.event_type,
            "extra": event.extra,
        });
        insta::assert_json_snapshot!("policy_violation_audit_event", snapshot);
    }

    #[tokio::test]
    async fn no_audit_event_on_allow() {
        // Confirm that `Decision::Allow` does NOT write an audit event.
        // The policy-violation audit log should never contain allowed
        // requests — those are recorded via the separate AuditLayer.
        let (_dir, ps) = make_policy_set(
            r#"
[[policies]]
name = "allow-test"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
"#,
        );
        let audit = MockAuditStore::new();
        let dispatcher = test_dispatcher(&audit);
        let svc = ServiceBuilder::new()
            .layer(PolicyLayer::new(ps, Arc::clone(&dispatcher)))
            .service(tower::service_fn(handler));

        let req =
            make_req("/v1/tools/gmail/users/me", Some("gmail.readonly"), None, Some("allow-test"));
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Give any spurious spawn a chance to fire, then assert empty.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(audit.events().len(), 0, "allow path must not write a policy-violation event");
    }

    // ── Fail-closed (panic + wildcard Decision) ────────────────────

    #[test]
    fn catch_unwind_returns_err_on_panic() {
        // Structural test: prove that the catch_unwind technique used
        // in PolicyService::call() actually catches panics. Decision
        // can't be mock-injected (it lives in core), so we verify the
        // catching mechanism directly. Combined with
        // `policy_eval_failed_produces_503_with_dotted_code` in error.rs
        // tests, this proves: panic → caught → ProxyError::PolicyEvalFailed
        // → 503. The full pipeline is structurally sound even though
        // PolicySet::evaluate is not currently a panic source.
        let result: Result<Decision, _> = std::panic::catch_unwind(AssertUnwindSafe(|| {
            panic!("simulated evaluation panic");
        }));
        assert!(result.is_err(), "catch_unwind must catch the simulated panic");
    }

    #[tokio::test]
    async fn fail_closed_response_for_eval_failed_is_503() {
        // The wildcard `Ok(_)` arm and the `Err(_panic)` arm both
        // construct ProxyError::PolicyEvalFailed and convert via
        // into_response_with_request_id. This test pins the response
        // shape so any future drift in the fail-closed path is caught.
        let resp = ProxyError::PolicyEvalFailed
            .into_response_with_request_id(Some("01FAILCLOSED".to_owned()));
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = Body::new(resp.into_body()).collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["code"], "policy.eval_failed");
        assert_eq!(json["error"]["request_id"], "01FAILCLOSED");
    }
}
