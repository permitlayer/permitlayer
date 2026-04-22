//! Authentication middleware (Story 4.4).
//!
//! Validates `Authorization: Bearer <token>` against the in-memory
//! agent registry, populates `AgentId` + `AgentPolicyBinding` request
//! extensions on success, and returns HTTP 401 fail-closed on missing
//! or invalid tokens.
//!
//! # Hot path discipline
//!
//! Per the dual-index design (see
//! `docs/adrs/0003-agent-identity-token-lookup.md` and the
//! `permitlayer-core::agent::registry` module docs), token validation
//! is two steps:
//!
//! 1. **HMAC index lookup (~1 µs)**: compute
//!    `HMAC-SHA-256(daemon_lookup_key, plaintext_token)` and look up
//!    the snapshot's `by_lookup_key` map. O(1).
//! 2. **Argon2id verification (~100 ms)**: verify the inbound token
//!    against the matched agent's stored hash. Defense in depth — even
//!    if an attacker corrupts the in-memory map (architecturally
//!    impossible without process compromise) they still cannot forge
//!    a token without computing a valid Argon2id round-trip.
//!
//! Step 2 is unavoidable per request (it's the security-critical
//! check), but it only fires on a hit, not on every agent. The hot
//! path is therefore O(1) HMAC + O(1) verify, not O(n × verify).
//!
//! # Audit events
//!
//! Auth failures emit `agent-auth-denied` audit events with
//! request-ID correlation (Story 3.3 retro pattern #3). The events
//! carry a `token_prefix` (first 8 characters of the inbound token,
//! or `null` if shorter) for grep-correlation in incident response —
//! NEVER the full token. Writes are fire-and-forget via `tokio::spawn`
//! to avoid blocking the request hot path on the audit store.

use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{Request, Response};
use permitlayer_core::agent::{
    AgentRegistry, LOOKUP_KEY_BYTES, compute_lookup_key, hash_token, verify_token,
};
use permitlayer_core::audit::dispatcher::AuditDispatcher;
use permitlayer_core::audit::event::AuditEvent;
use permitlayer_core::store::AgentIdentityStore;
use tower::{Layer, Service};
use tracing::warn;
use zeroize::Zeroizing;

use crate::error::{AgentId, AgentPolicyBinding, ProxyError, RequestId};
use crate::middleware::util::is_operational_path;

/// Hard cap on inbound bearer-token length, in bytes (Story 4.4).
///
/// Legitimate `agt_v1_*` tokens are exactly 50 characters. We accept
/// up to 256 chars to leave room for a future format rotation
/// (`agt_v2_*`) without changing this constant. Beyond 256, the
/// request is rejected before any HMAC computation — defense against
/// an attacker sending megabytes in the Authorization header to
/// inflate the audit log via `token_prefix`.
pub const MAX_BEARER_TOKEN_LEN: usize = 256;

/// Number of characters of the inbound bearer token to capture in the
/// `agent-auth-denied` audit event for grep correlation. The first 8
/// characters of an `agt_v1_*` token are `agt_v1_<one>` — enough to
/// distinguish a misconfigured agent from a typo from a stolen token,
/// not enough to reverse-engineer the credential.
pub const TOKEN_PREFIX_AUDIT_LEN: usize = 8;

// ──────────────────────────────────────────────────────────────────
// Tower Layer + Service
// ──────────────────────────────────────────────────────────────────

/// Tower layer for bearer-token authentication.
///
/// The HMAC subkey is held as `Arc<Zeroizing<[u8; 32]>>` so the backing
/// allocation is scrubbed when the last reference drops (daemon
/// shutdown) and `Clone` on the layer is a cheap `Arc` bump rather than
/// a 32-byte memcpy. This mirrors `ControlState.agent_lookup_key` —
/// both production copies of the subkey MUST be `Zeroizing`-wrapped so
/// freed memory is never handed back to the allocator cleartext.
#[derive(Clone)]
pub struct AuthLayer {
    registry: Arc<AgentRegistry>,
    daemon_lookup_key: Arc<Zeroizing<[u8; LOOKUP_KEY_BYTES]>>,
    agent_store: Option<Arc<dyn AgentIdentityStore>>,
    audit_dispatcher: Arc<AuditDispatcher>,
}

impl AuthLayer {
    /// Construct an `AuthLayer` with the runtime registry, the master-
    /// derived HMAC subkey, a `last_seen_at` store handle, and the
    /// daemon-owned audit dispatcher (Story 8.2).
    ///
    /// `agent_store` is `Option<>` because the daemon boots successfully
    /// even when the agents directory is unavailable — the layer
    /// degrades gracefully (auth still works, the `last_seen_at`
    /// touch silently skips). Pass `AuditDispatcher::none()` to
    /// disable audit-event writes for the same degraded-mode reason.
    ///
    /// The caller owns the `Arc<Zeroizing<_>>` and is expected to share
    /// the same subkey Arc across the middleware and the control plane
    /// (see `cli/start.rs::run`); this ensures there is exactly one
    /// backing allocation for the subkey bytes across the daemon.
    #[must_use]
    pub fn new(
        registry: Arc<AgentRegistry>,
        daemon_lookup_key: Arc<Zeroizing<[u8; LOOKUP_KEY_BYTES]>>,
        agent_store: Option<Arc<dyn AgentIdentityStore>>,
        audit_dispatcher: Arc<AuditDispatcher>,
    ) -> Self {
        Self { registry, daemon_lookup_key, agent_store, audit_dispatcher }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            registry: Arc::clone(&self.registry),
            daemon_lookup_key: Arc::clone(&self.daemon_lookup_key),
            agent_store: self.agent_store.clone(),
            audit_dispatcher: Arc::clone(&self.audit_dispatcher),
        }
    }
}

/// Tower service that validates bearer tokens against the agent registry.
#[derive(Clone)]
pub struct AuthService<S> {
    inner: S,
    registry: Arc<AgentRegistry>,
    daemon_lookup_key: Arc<Zeroizing<[u8; LOOKUP_KEY_BYTES]>>,
    agent_store: Option<Arc<dyn AgentIdentityStore>>,
    audit_dispatcher: Arc<AuditDispatcher>,
}

impl<S> Service<Request<Body>> for AuthService<S>
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

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        // 1. Extract request_id (for error responses + audit correlation).
        let request_id = req.extensions().get::<RequestId>().map(|r| r.0.clone());

        // 2. Operational paths bypass auth entirely (health probes,
        //    control plane, the agent CRUD routes themselves — see the
        //    `is_operational_path` allowlist for the source of truth).
        if is_operational_path(req.uri().path()) {
            let fut = self.inner.call(req);
            return Box::pin(fut);
        }

        // 3. Extract the Authorization header into an owned String so
        //    we can mutate request extensions later without colliding
        //    with the header borrow.
        let token_owned: Option<String> = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|s| s.trim().to_owned());

        let token_str = match token_owned {
            Some(t) => t,
            None => {
                // Story 8.2 review fix D1: `dispatch` is async — await
                // inside the response future so backpressure propagates
                // to the caller instead of queuing unbounded tasks.
                let dispatcher = Arc::clone(&self.audit_dispatcher);
                let request_id_for_audit = request_id.clone();
                let resp = ProxyError::AuthMissingToken.into_response_with_request_id(request_id);
                return Box::pin(async move {
                    write_auth_denied_event(
                        &dispatcher,
                        &request_id_for_audit,
                        "missing_token",
                        None,
                    )
                    .await;
                    Ok(resp)
                });
            }
        };

        // 4. Length cap defense — reject obviously-overlong tokens
        //    BEFORE computing HMAC. An attacker sending megabytes in
        //    the Authorization header would otherwise inflate audit
        //    lines via the (truncated) prefix capture.
        if token_str.is_empty() || token_str.len() > MAX_BEARER_TOKEN_LEN {
            let prefix = audit_token_prefix(&token_str);
            let dispatcher = Arc::clone(&self.audit_dispatcher);
            let request_id_for_audit = request_id.clone();
            let prefix_for_audit = prefix.clone();
            let resp = ProxyError::AuthInvalidToken { token_prefix: prefix }
                .into_response_with_request_id(request_id);
            return Box::pin(async move {
                write_auth_denied_event(
                    &dispatcher,
                    &request_id_for_audit,
                    "invalid_token",
                    prefix_for_audit,
                )
                .await;
                Ok(resp)
            });
        }

        // 5. HMAC lookup (~1 µs, synchronous — no point spawning).
        //    On miss we still pay ~100 ms of dummy Argon2id work
        //    inside spawn_blocking before returning 401, so an
        //    attacker cannot distinguish "unknown agent" from "known
        //    agent, wrong token" via response-latency timing.
        // Auto-deref chains through Arc → Zeroizing → [u8; 32] to
        // match compute_lookup_key's `&[u8; LOOKUP_KEY_BYTES]`.
        let lookup_key = compute_lookup_key(&self.daemon_lookup_key, token_str.as_bytes());
        let snapshot = self.registry.snapshot();
        let matched_agent = snapshot.lookup_by_key(&lookup_key).cloned();

        // Clone everything the async block needs up front — `self`
        // and `req` both cross the await boundary.
        let agent_store = self.agent_store.clone();
        let audit_dispatcher = Arc::clone(&self.audit_dispatcher);
        let inner_clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner_clone);

        Box::pin(async move {
            let agent = match matched_agent {
                Some(a) => a,
                None => {
                    // Miss path: pay a dummy Argon2id verify so the
                    // miss and the hit-and-fail paths take the same
                    // ~100 ms. Token bytes copied in; result ignored.
                    // Skipped on the extreme edge where the static
                    // dummy hash failed to initialize — a tracing
                    // error is emitted by `dummy_argon2id_hash` in
                    // that case.
                    if let Some(dummy_hash) = dummy_argon2id_hash() {
                        let token_bytes = token_str.as_bytes().to_vec();
                        let _ = tokio::task::spawn_blocking(move || {
                            verify_token(&token_bytes, dummy_hash)
                        })
                        .await;
                    }

                    let prefix = audit_token_prefix(&token_str);
                    write_auth_denied_event(
                        &audit_dispatcher,
                        &request_id,
                        "invalid_token",
                        prefix.clone(),
                    )
                    .await;
                    let resp = ProxyError::AuthInvalidToken { token_prefix: prefix }
                        .into_response_with_request_id(request_id);
                    return Ok(resp);
                }
            };

            // 6. Defense-in-depth Argon2id verification (~100 ms).
            //    The HMAC index lookup alone is not authoritative —
            //    the on-disk Argon2id hash is the canonical record.
            //    Even if the in-memory map is corrupted, this step
            //    blocks token forgery. Runs on a blocking worker so
            //    the tokio runtime is not stalled by the ~100 ms
            //    Argon2id CPU burn.
            let token_bytes = token_str.as_bytes().to_vec();
            let agent_hash = agent.token_hash.clone();
            let verified =
                tokio::task::spawn_blocking(move || verify_token(&token_bytes, &agent_hash))
                    .await
                    .unwrap_or(false);

            if !verified {
                warn!(
                    agent_name = %agent.name(),
                    "HMAC lookup hit but Argon2id verification failed — possible map corruption or hash drift"
                );
                let prefix = audit_token_prefix(&token_str);
                write_auth_denied_event(
                    &audit_dispatcher,
                    &request_id,
                    "invalid_token",
                    prefix.clone(),
                )
                .await;
                let resp = ProxyError::AuthInvalidToken { token_prefix: prefix }
                    .into_response_with_request_id(request_id);
                return Ok(resp);
            }

            // 7. Success: stamp extensions, fire-and-forget last_seen_at update.
            let agent_name = agent.name().to_owned();
            let policy_name = agent.policy_name.clone();
            req.extensions_mut().insert(AgentId(agent_name.clone()));
            req.extensions_mut().insert(AgentPolicyBinding(policy_name));

            if let Some(store) = agent_store {
                let mut updated = agent;
                updated.last_seen_at = Some(chrono::Utc::now());
                let agent_name_for_log = agent_name.clone();
                tokio::spawn(async move {
                    if let Err(e) = store.touch_last_seen(updated).await {
                        warn!(
                            agent_name = %agent_name_for_log,
                            error = %e,
                            "best-effort touch_last_seen failed (auth still succeeded)"
                        );
                    }
                });
            }

            inner.call(req).await
        })
    }
}

/// Dispatch an `agent-auth-denied` audit event (best-effort, fire-and-track
/// through [`AuditDispatcher`]).
///
/// `reason` ∈ {`"missing_token"`, `"invalid_token"`}. The
/// `token_prefix` carries the first 8 characters of the inbound
/// token (or `None` if shorter than 8 chars or absent entirely)
/// for grep-correlation. Never the full token.
///
/// Story 8.2 review fix D1: async because the dispatcher applies
/// backpressure at the producer edge. Callers `.await` to yield
/// when the concurrency cap is full.
async fn write_auth_denied_event(
    audit_dispatcher: &AuditDispatcher,
    request_id: &Option<String>,
    reason: &str,
    token_prefix: Option<String>,
) {
    let request_id_for_audit = match request_id {
        Some(id) if !id.is_empty() => id.clone(),
        _ => {
            warn!(
                "agent-auth-denied audit event has no RequestId — \
                 RequestTraceLayer may be missing from the chain"
            );
            "missing-request-id".to_owned()
        }
    };

    // Audit event shape follows the kill-switch convention:
    // service="permitlayer", scope="-", resource=<action>. Matches
    // `agent-registered`/`agent-removed` in server::control. See the
    // Story 4.4 review triage (audit shape consolidation).
    let mut event = AuditEvent::with_request_id(
        request_id_for_audit,
        "unknown".to_owned(),
        "permitlayer".to_owned(),
        "-".to_owned(),
        "auth".to_owned(),
        "denied".to_owned(),
        "agent-auth-denied".to_owned(),
    );
    event.extra = serde_json::json!({
        "reason": reason,
        "token_prefix": token_prefix,
    });

    audit_dispatcher.dispatch(event).await;
}

/// Precomputed Argon2id hash used to pay a constant-time ~100 ms CPU
/// burn on the HMAC-miss path. This closes the timing oracle that
/// would otherwise let an attacker distinguish "unknown agent" (~1 µs)
/// from "known agent, wrong token" (~100 ms) via response latency.
/// See Story 4.4 review patch A2.
///
/// Returns `Option<&'static str>` rather than `&'static str` because
/// Argon2id hash generation is fallible (`argon2::password_hash::Error`).
/// On the astronomically unlikely initialization failure, the miss path
/// skips the dummy verify and returns a 401 immediately — the timing
/// oracle is temporarily re-opened, but the alternative is panicking
/// on every miss, which is worse. A `tracing::error!` signals the
/// failure so the operator can investigate.
static DUMMY_ARGON2ID_HASH: OnceLock<Option<String>> = OnceLock::new();

fn dummy_argon2id_hash() -> Option<&'static str> {
    DUMMY_ARGON2ID_HASH
        .get_or_init(|| match hash_token(b"permitlayer-timing-oracle-dummy-v1") {
            Ok(phc) => Some(phc),
            Err(e) => {
                warn!(error = %e, "dummy Argon2id hash generation failed — timing oracle mitigation disabled");
                None
            }
        })
        .as_deref()
}

/// Capture the first [`TOKEN_PREFIX_AUDIT_LEN`] characters of `token`
/// for the audit-event `token_prefix` field. Returns `None` if the
/// token is shorter than the cutoff (so the audit log doesn't carry
/// useless near-full short tokens).
///
/// Operates on character boundaries via a single `chars()` pass so a
/// non-ASCII Authorization header can't be sliced mid-codepoint AND
/// we don't walk the entire (possibly 256-char) token twice.
#[must_use]
fn audit_token_prefix(token: &str) -> Option<String> {
    let mut prefix = String::with_capacity(TOKEN_PREFIX_AUDIT_LEN * 4);
    let mut count = 0;
    for c in token.chars() {
        if count >= TOKEN_PREFIX_AUDIT_LEN {
            break;
        }
        prefix.push(c);
        count += 1;
    }
    if count < TOKEN_PREFIX_AUDIT_LEN { None } else { Some(prefix) }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{HeaderValue, Request, StatusCode};
    use chrono::Utc;
    use http_body_util::BodyExt;
    use permitlayer_core::agent::{
        AgentIdentity, AgentRegistry, generate_bearer_token_bytes, hash_token, lookup_key_to_hex,
    };
    use permitlayer_core::store::AuditStore;
    use std::sync::Mutex;
    use tower::{ServiceBuilder, ServiceExt};

    /// In-memory `AuditStore` for tests that need to inspect emitted events.
    #[derive(Default, Clone)]
    struct MockAuditStore {
        events: Arc<Mutex<Vec<AuditEvent>>>,
    }

    impl MockAuditStore {
        fn events(&self) -> Vec<AuditEvent> {
            self.events.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl AuditStore for MockAuditStore {
        async fn append(
            &self,
            event: AuditEvent,
        ) -> Result<(), permitlayer_core::store::StoreError> {
            self.events.lock().unwrap().push(event);
            Ok(())
        }
    }

    use permitlayer_core::store::test_seams::MockAgentStore;

    /// Build a test fixture: a registry containing one agent with a
    /// known plaintext token, plus a fake daemon lookup key.
    fn fixture(name: &str, policy: &str) -> (Arc<AgentRegistry>, [u8; LOOKUP_KEY_BYTES], String) {
        let plaintext = generate_bearer_token_bytes();
        let token_string = format!("agt_v1_{}", base64_url(&plaintext));
        let daemon_key = [0x42u8; LOOKUP_KEY_BYTES];
        let lookup_key = compute_lookup_key(&daemon_key, token_string.as_bytes());
        let hash = hash_token(token_string.as_bytes()).unwrap();
        let agent = AgentIdentity::new(
            name.to_owned(),
            policy.to_owned(),
            hash,
            lookup_key_to_hex(&lookup_key),
            Utc::now(),
            None,
        )
        .unwrap();
        let registry = Arc::new(AgentRegistry::new(vec![agent]));
        (registry, daemon_key, token_string)
    }

    /// Tiny URL-safe base64 (no padding) encoder. The agent CLI will
    /// use the `base64` crate; tests use a hand-rolled minimal version
    /// to avoid pulling the dep into the proxy crate's dev-deps.
    fn base64_url(bytes: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        let mut i = 0;
        while i + 3 <= bytes.len() {
            let n =
                ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
            out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
            out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
            out.push(CHARS[((n >> 6) & 0x3f) as usize] as char);
            out.push(CHARS[(n & 0x3f) as usize] as char);
            i += 3;
        }
        if i + 2 == bytes.len() {
            let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
            out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
            out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
            out.push(CHARS[((n >> 6) & 0x3f) as usize] as char);
        } else if i + 1 == bytes.len() {
            let n = (bytes[i] as u32) << 16;
            out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
            out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
        }
        out
    }

    async fn handler(req: Request<Body>) -> Result<Response<Body>, std::convert::Infallible> {
        // Sniff the extensions so the test can confirm AuthLayer
        // populated them. Echo the agent name and policy in the body.
        let agent_id = req.extensions().get::<AgentId>().map(|a| a.0.clone()).unwrap_or_default();
        let policy =
            req.extensions().get::<AgentPolicyBinding>().map(|p| p.0.clone()).unwrap_or_default();
        let body = format!("{agent_id}|{policy}");
        Ok(Response::builder().status(StatusCode::OK).body(Body::from(body)).unwrap())
    }

    #[allow(clippy::type_complexity)]
    fn build_layer_only_service(
        registry: Arc<AgentRegistry>,
        daemon_key: [u8; LOOKUP_KEY_BYTES],
        audit_store: Option<Arc<dyn permitlayer_core::store::AuditStore>>,
    ) -> impl Service<
        Request<Body>,
        Response = Response<Body>,
        Error = std::convert::Infallible,
        Future = std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Response<Body>, std::convert::Infallible>>
                    + Send,
            >,
        >,
    > + Clone {
        let (svc, _dispatcher) = build_layer_with_dispatcher(registry, daemon_key, audit_store);
        svc
    }

    /// Story 8.2: tests that inspect audit events need to hold the
    /// dispatcher in scope so the `JoinSet` isn't dropped (and tasks
    /// aborted) before the write completes. This helper returns the
    /// dispatcher handle alongside the service; tests can then
    /// `dispatcher.drain(...).await` before reading the audit store.
    #[allow(clippy::type_complexity)]
    fn build_layer_with_dispatcher(
        registry: Arc<AgentRegistry>,
        daemon_key: [u8; LOOKUP_KEY_BYTES],
        audit_store: Option<Arc<dyn permitlayer_core::store::AuditStore>>,
    ) -> (
        impl Service<
            Request<Body>,
            Response = Response<Body>,
            Error = std::convert::Infallible,
            Future = std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<Response<Body>, std::convert::Infallible>,
                        > + Send,
                >,
            >,
        > + Clone,
        Arc<AuditDispatcher>,
    ) {
        let dispatcher = match audit_store {
            Some(store) => Arc::new(AuditDispatcher::for_tests_unbounded(store)),
            None => Arc::new(AuditDispatcher::none()),
        };
        let svc = ServiceBuilder::new()
            .layer(AuthLayer::new(
                registry,
                Arc::new(Zeroizing::new(daemon_key)),
                None,
                Arc::clone(&dispatcher),
            ))
            .service(tower::service_fn(handler));
        (svc, dispatcher)
    }

    // ── happy path ─────────────────────────────────────────────────

    #[tokio::test]
    async fn valid_bearer_token_populates_extensions() {
        let (registry, daemon_key, token) = fixture("email-triage", "email-read-only");
        let svc = build_layer_only_service(registry, daemon_key, None);
        let mut req =
            Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        req.headers_mut()
            .insert("authorization", HeaderValue::from_str(&format!("Bearer {token}")).unwrap());
        let resp: Response<Body> = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(body_str, "email-triage|email-read-only");
    }

    // ── 401 paths ──────────────────────────────────────────────────

    #[tokio::test]
    async fn missing_authorization_header_returns_401_missing_token() {
        let (registry, daemon_key, _token) = fixture("agent1", "default");
        let svc = build_layer_only_service(registry, daemon_key, None);
        let req = Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        let resp: Response<Body> = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "auth.missing_token");
    }

    #[tokio::test]
    async fn malformed_bearer_header_returns_401_missing_token() {
        let (registry, daemon_key, _token) = fixture("agent1", "default");
        let svc = build_layer_only_service(registry, daemon_key, None);
        let mut req =
            Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        // Wrong scheme (Basic instead of Bearer).
        req.headers_mut().insert("authorization", HeaderValue::from_static("Basic dXNlcjpwYXNz"));
        let resp: Response<Body> = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "auth.missing_token");
    }

    #[tokio::test]
    async fn unknown_bearer_token_returns_401_invalid_token() {
        let (registry, daemon_key, _token) = fixture("agent1", "default");
        let svc = build_layer_only_service(registry, daemon_key, None);
        let mut req =
            Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        req.headers_mut()
            .insert("authorization", HeaderValue::from_static("Bearer agt_v1_garbageDoesNotMatch"));
        let resp: Response<Body> = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "auth.invalid_token");
        // Token prefix MUST NOT leak into the error body.
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(!body_str.contains("agt_v1_g"));
    }

    #[tokio::test]
    async fn empty_bearer_token_returns_401_invalid_token() {
        let (registry, daemon_key, _token) = fixture("agent1", "default");
        let svc = build_layer_only_service(registry, daemon_key, None);
        let mut req =
            Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        req.headers_mut().insert("authorization", HeaderValue::from_static("Bearer "));
        let resp: Response<Body> = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "auth.invalid_token");
    }

    #[tokio::test]
    async fn oversized_bearer_token_returns_401_invalid_token() {
        let (registry, daemon_key, _token) = fixture("agent1", "default");
        let svc = build_layer_only_service(registry, daemon_key, None);
        let mut req =
            Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        let oversized = format!("Bearer {}", "a".repeat(MAX_BEARER_TOKEN_LEN + 1));
        req.headers_mut().insert("authorization", HeaderValue::from_str(&oversized).unwrap());
        let resp: Response<Body> = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "auth.invalid_token");
    }

    // ── operational bypass ─────────────────────────────────────────

    #[tokio::test]
    async fn operational_path_bypasses_auth() {
        let (registry, daemon_key, _token) = fixture("agent1", "default");
        let svc = build_layer_only_service(registry, daemon_key, None);
        let req = Request::builder().uri("/health").body(Body::empty()).unwrap();
        let resp: Response<Body> = svc.oneshot(req).await.unwrap();
        // No Authorization header but the route is operational → 200.
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn control_plane_paths_bypass_auth() {
        let (registry, daemon_key, _token) = fixture("agent1", "default");
        let svc = build_layer_only_service(registry, daemon_key, None);
        for path in [
            "/v1/control/kill",
            "/v1/control/resume",
            "/v1/control/state",
            "/v1/control/agent/register",
            "/v1/control/agent/list",
            "/v1/control/agent/remove",
        ] {
            let svc = svc.clone();
            let req = Request::builder().uri(path).body(Body::empty()).unwrap();
            let resp: Response<Body> = svc.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "operational path {path} should bypass auth");
        }
    }

    // ── audit events ───────────────────────────────────────────────

    #[tokio::test]
    async fn missing_token_writes_agent_auth_denied_event_with_request_id_correlation() {
        let (registry, daemon_key, _token) = fixture("agent1", "default");
        let mock_store = MockAuditStore::default();
        let store: Arc<dyn AuditStore> = Arc::new(mock_store.clone());
        let (svc, dispatcher) =
            build_layer_with_dispatcher(registry, daemon_key, Some(Arc::clone(&store)));
        let mut req =
            Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        req.extensions_mut().insert(RequestId("01TESTREQ".to_owned()));
        let _resp: Response<Body> = svc.oneshot(req).await.unwrap();
        let _ = dispatcher.drain(std::time::Duration::from_secs(2)).await;
        let events = mock_store.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "agent-auth-denied");
        assert_eq!(events[0].outcome, "denied");
        assert_eq!(events[0].request_id, "01TESTREQ");
        assert_eq!(events[0].extra["reason"], "missing_token");
        assert!(events[0].extra["token_prefix"].is_null());
    }

    #[tokio::test]
    async fn invalid_token_writes_agent_auth_denied_event_with_token_prefix() {
        let (registry, daemon_key, _token) = fixture("agent1", "default");
        let mock_store = MockAuditStore::default();
        let store: Arc<dyn AuditStore> = Arc::new(mock_store.clone());
        let (svc, dispatcher) =
            build_layer_with_dispatcher(registry, daemon_key, Some(Arc::clone(&store)));
        let mut req =
            Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        req.extensions_mut().insert(RequestId("01TESTBAD".to_owned()));
        req.headers_mut()
            .insert("authorization", HeaderValue::from_static("Bearer agt_v1_garbage"));
        let _resp: Response<Body> = svc.oneshot(req).await.unwrap();
        let _ = dispatcher.drain(std::time::Duration::from_secs(2)).await;
        let events = mock_store.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "agent-auth-denied");
        assert_eq!(events[0].extra["reason"], "invalid_token");
        // First 8 chars of "agt_v1_garbage" → "agt_v1_g".
        assert_eq!(events[0].extra["token_prefix"], "agt_v1_g");
    }

    #[tokio::test]
    async fn short_invalid_token_omits_token_prefix() {
        // Token shorter than 8 chars → token_prefix is null (don't
        // bother capturing a near-full short token).
        let (registry, daemon_key, _token) = fixture("agent1", "default");
        let mock_store = MockAuditStore::default();
        let store: Arc<dyn AuditStore> = Arc::new(mock_store.clone());
        let (svc, dispatcher) =
            build_layer_with_dispatcher(registry, daemon_key, Some(Arc::clone(&store)));
        let mut req =
            Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        req.extensions_mut().insert(RequestId("01TESTSHORT".to_owned()));
        req.headers_mut().insert("authorization", HeaderValue::from_static("Bearer abc"));
        let _resp: Response<Body> = svc.oneshot(req).await.unwrap();
        let _ = dispatcher.drain(std::time::Duration::from_secs(2)).await;
        let events = mock_store.events();
        assert_eq!(events.len(), 1);
        assert!(events[0].extra["token_prefix"].is_null());
    }

    #[tokio::test]
    async fn valid_token_writes_no_audit_event() {
        let (registry, daemon_key, token) = fixture("agent1", "default");
        let mock_store = MockAuditStore::default();
        let store: Arc<dyn AuditStore> = Arc::new(mock_store.clone());
        let svc = build_layer_only_service(registry, daemon_key, Some(Arc::clone(&store)));
        let mut req =
            Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        req.headers_mut()
            .insert("authorization", HeaderValue::from_str(&format!("Bearer {token}")).unwrap());
        let _resp: Response<Body> = svc.oneshot(req).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let events = mock_store.events();
        assert_eq!(events.len(), 0, "successful auth must not write an audit event");
    }

    #[tokio::test]
    async fn audit_event_uses_missing_request_id_sentinel_when_extension_absent() {
        let (registry, daemon_key, _token) = fixture("agent1", "default");
        let mock_store = MockAuditStore::default();
        let store: Arc<dyn AuditStore> = Arc::new(mock_store.clone());
        let (svc, dispatcher) =
            build_layer_with_dispatcher(registry, daemon_key, Some(Arc::clone(&store)));
        // Note: NO RequestId extension inserted — production has
        // RequestTraceLayer ahead of AuthLayer; the test exercises the
        // defensive sentinel path.
        let req = Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        let _resp: Response<Body> = svc.oneshot(req).await.unwrap();
        let _ = dispatcher.drain(std::time::Duration::from_secs(2)).await;
        let events = mock_store.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].request_id, "missing-request-id");
    }

    // ── audit_token_prefix unit tests ─────────────────────────────

    #[test]
    fn audit_token_prefix_captures_first_8_chars_when_long_enough() {
        assert_eq!(audit_token_prefix("agt_v1_garbage"), Some("agt_v1_g".to_owned()));
    }

    #[test]
    fn audit_token_prefix_returns_none_when_too_short() {
        assert_eq!(audit_token_prefix(""), None);
        assert_eq!(audit_token_prefix("abc"), None);
        assert_eq!(audit_token_prefix("1234567"), None);
    }

    #[test]
    fn audit_token_prefix_handles_non_ascii_safely() {
        // 🦀 is one char (4 bytes UTF-8). The prefix must take 8 chars,
        // not 8 bytes — slicing mid-codepoint would panic.
        let token = "🦀🦀🦀🦀🦀🦀🦀🦀🦀";
        let prefix = audit_token_prefix(token);
        assert!(prefix.is_some());
        assert_eq!(prefix.unwrap().chars().count(), 8);
    }

    // ── touch_last_seen integration ───────────────────────────────

    #[tokio::test]
    async fn successful_auth_calls_touch_last_seen_when_agent_store_present() {
        let (registry, daemon_key, token) = fixture("agent1", "default");
        let mock_agent_store = MockAgentStore::default();
        let agent_store: Arc<dyn AgentIdentityStore> = Arc::new(mock_agent_store.clone());

        let layer = AuthLayer::new(
            registry,
            Arc::new(Zeroizing::new(daemon_key)),
            Some(Arc::clone(&agent_store)),
            Arc::new(AuditDispatcher::none()),
        );
        let svc = ServiceBuilder::new().layer(layer).service(tower::service_fn(handler));

        let mut req =
            Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        req.headers_mut()
            .insert("authorization", HeaderValue::from_str(&format!("Bearer {token}")).unwrap());
        let _resp: Response<Body> = svc.oneshot(req).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let touched = mock_agent_store.touched.lock().unwrap();
        assert_eq!(touched.len(), 1);
        assert_eq!(touched[0], "agent1");
    }
}
