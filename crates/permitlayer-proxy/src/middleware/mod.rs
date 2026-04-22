//! Tower middleware layers for the permitlayer proxy.
//!
//! Execution order (outermost → innermost):
//! `DnsRebind → Trace → KillSwitch → Auth → AgentIdentity → ConnTrack → Policy → Audit → handler`
//!
//! The chain is assembled in one place via [`assemble_middleware`] so
//! the daemon's `start.rs` and the ordering-invariant tests both use
//! the same builder. Any change to layer order here must be reflected
//! in the ordering test (`ordering_tests` module below).

pub mod agent_identity;
pub mod approval;
pub mod audit;
pub mod auth;
pub mod conn_track;
pub mod dns_rebind;
pub mod kill;
pub mod policy;
pub mod trace;
pub mod util;

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use arc_swap::ArcSwap;
use tower::ServiceBuilder;
use tower::layer::util::{Identity, Stack};

use permitlayer_core::killswitch::KillSwitch;

pub use agent_identity::AgentIdentityLayer;
pub use approval::{AlwaysDenyApprovalService, ApprovalOutcome, ApprovalRequest, ApprovalService};
pub use audit::AuditLayer;
pub use auth::AuthLayer;
pub use conn_track::{ConnTrackLayer, ConnTrackerSink};
pub use dns_rebind::DnsRebindLayer;
pub use kill::KillSwitchLayer;
pub use permitlayer_core::policy::PolicySet;
pub use policy::PolicyLayer;
pub use trace::RequestTraceLayer;

/// The concrete type of the assembled middleware stack returned by
/// [`assemble_middleware`].
///
/// # Stack nesting vs runtime order
///
/// `ServiceBuilder::layer(X)` calls `Stack::new(X, self.layer)`, which
/// makes `X` the INNER field of the new stack — but `Stack::layer(service)`
/// applies inner first and outer last (`outer.layer(inner.layer(service))`),
/// so the INNER field ends up wrapping the service CLOSEST, i.e. runs
/// LAST at runtime. Combined with the tower doc guarantee that "layers
/// that are added first will be called with the request first," this
/// means:
///
/// - `ServiceBuilder::new().layer(A).layer(B).layer(C)` produces a
///   runtime chain of `A → B → C → service` (A sees the request first).
/// - In the nested `Stack<Inner, Outer>` type, the LAST-added layer
///   (`C`) is the outermost `Inner` field, the next-to-last (`B`) is
///   the next level, and the FIRST-added (`A`) is innermost, buried
///   closest to `Identity`.
///
/// So to get the architecture-pinned runtime order:
///   `DnsRebind → Trace → KillSwitch → Auth → AgentIdentity → ConnTrack → Policy → Audit → handler`
/// we add DnsRebind FIRST (outermost runtime) and Audit LAST (innermost
/// runtime), and the resulting `Stack` nests with `AuditLayer` at the
/// TOP and `DnsRebindLayer` at the BOTTOM of the nested expression.
pub type MiddlewareStack = ServiceBuilder<
    Stack<
        AuditLayer,
        Stack<
            PolicyLayer,
            Stack<
                ConnTrackLayer,
                Stack<
                    AgentIdentityLayer,
                    Stack<
                        AuthLayer,
                        Stack<
                            KillSwitchLayer,
                            Stack<RequestTraceLayer, Stack<DnsRebindLayer, Identity>>,
                        >,
                    >,
                >,
            >,
        >,
    >,
>;

/// Assemble the canonical middleware chain.
///
/// Execution order (outermost → innermost, i.e., the order layers
/// observe a request as it flows through):
///
/// 1. `DnsRebindLayer` — rejects malformed Host/Origin headers (HTTP
///    400). Runs OUTSIDE the kill switch because DNS rebinding is a
///    transport-level concern — telling an attacker the daemon is
///    killed just leaks state.
/// 2. `RequestTraceLayer` — generates a ULID request ID, inserts it
///    into request extensions, and echoes it in the response header.
///    Runs before `KillSwitchLayer` so the `daemon_killed` response
///    body can include the request ID.
/// 3. `KillSwitchLayer` — short-circuits with HTTP 403 `daemon_killed`
///    when the kill switch is active. First authorization-relevant
///    layer in the chain — no `AuthLayer`/`PolicyLayer`/`AuditLayer`
///    work happens while killed.
/// 4. `AuthLayer` — validates bearer tokens (currently a stub
///    pass-through; real enforcement lands in Story 4.4).
/// 5. `AgentIdentityLayer` — maps the bearer token to an `AgentId`.
/// 6. `PolicyLayer` — evaluates the request against the active
///    `PolicySet` (currently a stub allow-all; real engine in Story 4.2).
/// 7. `AuditLayer` — emits the `api-call` audit event.
/// 8. Terminal handler — the axum router / proxy service.
///
/// See the `ordering_tests` module at the bottom of this file for the
/// executable assertions that lock this order.
///
/// `audit_dispatcher` is passed into `KillSwitchLayer`, `AuthLayer`, and
/// `PolicyLayer` for the `kill-blocked-request`, `agent-auth-denied`,
/// and `policy-violation` audit-event write paths. An
/// `AuditDispatcher::none()` silences audit writes for every layer —
/// the response still fires, but no forensic log line is emitted.
/// Story 8.2 replaced the prior `Option<Arc<dyn AuditStore>>` +
/// `tokio::spawn` fire-and-forget pattern with the daemon-owned
/// dispatcher so `start.rs` can drain in-flight audit writes on
/// graceful shutdown.
///
/// Story 4.4 added the `agent_registry`, `agent_lookup_key`, and
/// `agent_store` parameters needed by `AuthLayer`'s real bearer-token
/// validation path. `agent_lookup_key` is an `Arc<Zeroizing<_>>` so
/// the same backing allocation is shared with `ControlState` and is
/// scrubbed on daemon shutdown rather than handed back to the
/// allocator cleartext.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn assemble_middleware(
    kill_switch: Arc<KillSwitch>,
    policy_set: Arc<ArcSwap<PolicySet>>,
    // Story 8.7 AC #5: DNS allowlist lives behind an `ArcSwap` so a
    // future `[dns] allowlist = [...]` reload can hot-swap the
    // contents without rebuilding the tower stack. The layer reads it
    // per-request via `ArcSwap::load`.
    dns_allowlist: Arc<ArcSwap<Vec<String>>>,
    audit_dispatcher: Arc<permitlayer_core::audit::dispatcher::AuditDispatcher>,
    agent_registry: Arc<permitlayer_core::agent::AgentRegistry>,
    agent_lookup_key: Arc<zeroize::Zeroizing<[u8; permitlayer_core::agent::LOOKUP_KEY_BYTES]>>,
    agent_store: Option<Arc<dyn permitlayer_core::store::AgentIdentityStore>>,
    approval_service: Arc<dyn ApprovalService>,
    // Story 8.7 AC #2: approval timeout is now an atomic (seconds)
    // shared with the SIGHUP / `POST /v1/control/reload` paths. Each
    // request loads it via `Ordering::Relaxed` — see
    // `permitlayer_proxy::middleware::policy::PolicyLayer`.
    approval_timeout: Arc<AtomicU64>,
    conn_tracker: Arc<dyn ConnTrackerSink>,
) -> MiddlewareStack {
    // Tower's ServiceBuilder doc guarantee: "Layers that are added
    // first will be called with the request first." So we add the
    // OUTERMOST layer (DnsRebind) FIRST and the INNERMOST (Audit) LAST.
    // This is OPPOSITE to the order used by the pre-Story-3.1
    // `start.rs` inline chain, which had the order reversed (Audit
    // first, DnsRebind last) — that chain was runtime-backwards and
    // not caught because no test pitted two layers against each other
    // in a way that would have exposed the bug. Story 3.1 fixes the
    // order AND locks it in with the `ordering_tests` module below.
    //
    // Runtime execution order (outermost → innermost):
    //   DnsRebind → Trace → KillSwitch → Auth → AgentIdentity → ConnTrack → Policy → Audit → handler
    //
    // Story 5.5 wedges `ConnTrackLayer` between `AgentIdentityLayer`
    // (which guarantees `AgentId` is on the request) and `PolicyLayer`
    // (so policy-rejected requests are still recorded — operators
    // want visibility into agents that are *trying* things).
    ServiceBuilder::new()
        .layer(DnsRebindLayer::new(dns_allowlist))
        .layer(RequestTraceLayer::new())
        .layer(KillSwitchLayer::new(kill_switch, Arc::clone(&audit_dispatcher)))
        .layer(AuthLayer::new(
            agent_registry,
            agent_lookup_key,
            agent_store,
            Arc::clone(&audit_dispatcher),
        ))
        .layer(AgentIdentityLayer::new())
        .layer(ConnTrackLayer::new(conn_tracker))
        .layer(PolicyLayer::with_approval_service(
            policy_set,
            audit_dispatcher,
            approval_service,
            approval_timeout,
        ))
        .layer(AuditLayer::new())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod ordering_tests {
    //! Executable assertions for the middleware chain order.
    //!
    //! # Defense in depth
    //!
    //! This module locks the layer order via THREE independent checks:
    //!
    //! 1. **Compile-time type equality** — the canonical
    //!    `MiddlewareStack` type alias is compared against a
    //!    hand-constructed `CanonicalOrderType` via
    //!    `static_assertions::assert_type_eq_all!`. Any reorder of
    //!    `.layer()` calls in `assemble_middleware` changes the return
    //!    type and fails this assertion at compile time. This closes
    //!    the spec gap that runtime tests couldn't detect stub-layer
    //!    transpositions (pre-Story-3.1, Auth/AgentIdentity/Policy/Audit
    //!    were all pass-throughs so swapping any two of them would
    //!    pass every runtime test).
    //! 2. **Runtime observable behavior** — five tests below drive
    //!    requests through the real chain and assert on response
    //!    signals that differ based on layer order.
    //! 3. **Single source of truth** — the daemon's `start.rs` and
    //!    these tests both call `assemble_middleware`. A future
    //!    refactor that builds the chain elsewhere bypasses these
    //!    tests, so `start.rs` must keep calling this helper.
    //!
    //!
    //! Epic 2 retrospective critical prep item for Story 3.1:
    //!
    //! > Verify tower middleware layer ordering can be asserted in a
    //! > test, not just documented. If the kill switch isn't first,
    //! > the story's core invariant is undetectable.
    //!
    //! This module locks in two things:
    //!
    //! 1. **`assemble_middleware` is the single source of truth.** The
    //!    daemon's `start.rs` and these tests both call the same
    //!    function. Any future refactor that builds the chain
    //!    elsewhere will either use this helper OR bypass it (and
    //!    these tests won't fire), so start.rs must keep calling this
    //!    helper. A separate test in `crates/permitlayer-daemon`
    //!    covers the wiring side.
    //!
    //! 2. **Order-sensitive invariants are tested via observable
    //!    behavior**, not by inspecting the tower type. The test cases
    //!    exercise the chain with real requests and assert on
    //!    status/body + request-extension breadcrumbs.
    //!
    //! Approach: a terminal service that records request extensions
    //! (proving all "insert-extension" layers ran) and returns 200
    //! OK. Then request-level assertions cover the "short-circuit"
    //! layers (DnsRebind and KillSwitch).
    //!
    //! **Note on AuthLayer/PolicyLayer:** both are pass-through stubs
    //! today (real enforcement lands in Stories 4.2 / 4.4). We can't
    //! assert "KillSwitch runs before Auth" via a 401-vs-403 test
    //! because Auth never returns 401. Instead, we rely on the kill
    //! switch firing before the terminal reaches 200, which
    //! structurally proves KillSwitch sits somewhere in the inner
    //! chain. The explicit ordering vs Auth/Policy is defended by
    //! the `assemble_middleware` helper's stable type signature
    //! (`MiddlewareStack`) — any reorder changes the nested `Stack`
    //! structure and triggers a compile error at the call site.

    use super::*;
    use axum::body::Body;
    use axum::http::{HeaderValue, Request, Response, StatusCode};
    use http_body_util::BodyExt;
    use permitlayer_core::killswitch::{KillReason, KillSwitch};
    use static_assertions::assert_type_eq_all;
    use tower::{Service, ServiceExt};

    use crate::error::RequestId;

    // ------------------------------------------------------------
    //
    // Compile-time layer-order pin.
    //
    // ------------------------------------------------------------
    //
    // `CanonicalOrderType` is the single source of truth for the
    // middleware chain nesting. `assemble_middleware()` returns
    // `MiddlewareStack`, which MUST equal `CanonicalOrderType`. Any
    // reorder of `.layer()` calls in `assemble_middleware` OR any
    // drift in the `MiddlewareStack` type alias triggers a compile
    // error on the `assert_type_eq_all!` below.
    //
    // Runtime execution order (outermost → innermost):
    //
    //   DnsRebind → Trace → KillSwitch → Auth → AgentIdentity → ConnTrack → Policy → Audit → handler
    //
    // Stack nesting (innermost at Rust type TOP, because
    // `ServiceBuilder::layer(X)` puts the new layer in the `Inner`
    // field of a `Stack<Inner, Outer>`, and runtime order is
    // outer-wraps-inner per `Stack::layer()`'s impl):
    type CanonicalOrderType = ServiceBuilder<
        Stack<
            AuditLayer,
            Stack<
                PolicyLayer,
                Stack<
                    ConnTrackLayer,
                    Stack<
                        AgentIdentityLayer,
                        Stack<
                            AuthLayer,
                            Stack<
                                KillSwitchLayer,
                                Stack<RequestTraceLayer, Stack<DnsRebindLayer, Identity>>,
                            >,
                        >,
                    >,
                >,
            >,
        >,
    >;

    assert_type_eq_all!(MiddlewareStack, CanonicalOrderType);

    /// Build a canonical chain with all defaults, wrapping a terminal
    /// handler that returns 200 with the captured `RequestId` as the
    /// body (proves `RequestTraceLayer` ran before the terminal).
    async fn terminal_handler(
        req: Request<Body>,
    ) -> Result<Response<Body>, std::convert::Infallible> {
        let request_id = req
            .extensions()
            .get::<RequestId>()
            .map(|r| r.0.clone())
            .unwrap_or_else(|| "MISSING".to_owned());
        Ok(Response::builder().status(StatusCode::OK).body(Body::from(request_id)).unwrap())
    }

    fn build_chain(
        kill_switch: Arc<KillSwitch>,
    ) -> impl Service<
        Request<Body>,
        Response = Response<Body>,
        Error = std::convert::Infallible,
        Future = impl Send,
    > + Clone {
        // Use a single permissive policy so PolicyLayer allows requests
        // through (Story 4.3 enforces real evaluation; an empty
        // PolicySet would deny everything and break these ordering-only
        // tests). PolicySet compiles its IR into memory at load time
        // (Story 4.1 invariant: "no TOML parsing in the hot path"), so
        // the tempdir can be dropped immediately after `compile_from_dir`
        // returns — the in-memory `PolicySet` does not reference the
        // source files. This avoids the tempdir-leak hazard from using
        // `std::mem::forget` to artificially extend the dir's lifetime.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("permissive.toml"),
            r#"
[[policies]]
name = "ordering-test"
scopes = ["gmail.readonly", "gmail.modify", "calendar.events.read", "drive.readonly"]
resources = ["*"]
approval-mode = "auto"
"#,
        )
        .unwrap();
        let ps = PolicySet::compile_from_dir(dir.path()).unwrap();
        // Explicit drop documents that compile_from_dir is fully owning.
        drop(dir);
        let policy_set = Arc::new(ArcSwap::from_pointee(ps));
        let dns_allowlist: Arc<ArcSwap<Vec<String>>> =
            Arc::new(ArcSwap::from_pointee(vec!["localhost".to_owned(), "127.0.0.1".to_owned()]));
        // Ordering tests don't exercise audit writes — pass None.
        // The agent registry is empty (no agents registered), so any
        // tool-route request would 401 — but the ordering tests use
        // operational paths (`/v1/health`, etc.) that bypass auth via
        // the `is_operational_path` allowlist.
        let agent_registry = Arc::new(permitlayer_core::agent::AgentRegistry::new(vec![]));
        let agent_lookup_key =
            Arc::new(zeroize::Zeroizing::new([0u8; permitlayer_core::agent::LOOKUP_KEY_BYTES]));
        let approval_service: Arc<dyn ApprovalService> = Arc::new(AlwaysDenyApprovalService::new());
        // Story 5.5: ordering tests use operational paths only, so the
        // tracker is never invoked — a no-op sink suffices and keeps
        // the test free of a dashmap/daemon dependency.
        struct NoopSink;
        impl ConnTrackerSink for NoopSink {
            fn record(&self, _agent_name: &str) {}
        }
        let conn_tracker: Arc<dyn ConnTrackerSink> = Arc::new(NoopSink);
        let middleware = assemble_middleware(
            kill_switch,
            policy_set,
            dns_allowlist,
            Arc::new(permitlayer_core::audit::dispatcher::AuditDispatcher::none()),
            agent_registry,
            agent_lookup_key,
            None,
            approval_service,
            Arc::new(AtomicU64::new(30)),
            conn_tracker,
        );
        middleware.service(tower::service_fn(terminal_handler))
    }

    fn req_with_host(path: &str, host: &str) -> Request<Body> {
        let mut req = Request::builder().uri(path).body(Body::empty()).unwrap();
        req.headers_mut().insert("host", HeaderValue::from_str(host).unwrap());
        req
    }

    async fn body_json(resp: Response<Body>) -> serde_json::Value {
        let bytes = Body::new(resp.into_body()).collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    async fn body_text(resp: Response<Body>) -> String {
        let bytes = Body::new(resp.into_body()).collect().await.unwrap().to_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn happy_path_reaches_terminal_with_request_id() {
        // Case E: kill switch inactive + valid host + valid path →
        // terminal handler runs AND sees a RequestId in extensions.
        // Proves RequestTraceLayer runs before the terminal.
        let switch = Arc::new(KillSwitch::new());
        let svc = build_chain(switch);
        let req = req_with_host("/v1/health", "localhost");
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_text(resp).await;
        // ULID is 26 chars
        assert_eq!(body.len(), 26, "terminal should echo the 26-char ULID RequestId");
        assert_ne!(body, "MISSING");
    }

    #[tokio::test]
    async fn dns_rebind_blocks_regardless_of_kill_state() {
        // Case A + Case B combined: DnsRebindLayer is OUTSIDE
        // KillSwitchLayer. An attacker using a rebinding host gets
        // `dns_rebind.blocked` regardless of whether the switch is
        // active. This is deliberate information hygiene — telling
        // the attacker the daemon is killed would leak state.
        let switch_inactive = Arc::new(KillSwitch::new());
        let svc = build_chain(Arc::clone(&switch_inactive));
        let req = req_with_host("/v1/health", "evil.com");
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert_eq!(json["error"]["code"], "dns_rebind.blocked");

        let switch_active = Arc::new(KillSwitch::new());
        switch_active.activate(KillReason::UserInitiated);
        let svc = build_chain(switch_active);
        let req = req_with_host("/v1/health", "evil.com");
        let resp = svc.oneshot(req).await.unwrap();
        // DNS rebind fires BEFORE kill switch, so the response is 400
        // dns_rebind.blocked, NOT 403 daemon_killed.
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "DnsRebindLayer must run outside KillSwitchLayer — attacker using bad host sees 400, not 403"
        );
        let json = body_json(resp).await;
        assert_eq!(json["error"]["code"], "dns_rebind.blocked");
    }

    #[tokio::test]
    async fn kill_switch_blocks_without_reaching_terminal() {
        // Case C-adapted: kill switch active + valid host + valid path
        // → 403 daemon_killed, terminal handler NOT reached. This
        // proves KillSwitchLayer sits between RequestTraceLayer
        // (outer) and the terminal handler (inner). The terminal
        // handler would return body length 26 (ULID echo); a kill
        // switch rejection returns the structured error body instead.
        let switch = Arc::new(KillSwitch::new());
        switch.activate(KillReason::UserInitiated);
        let svc = build_chain(switch);
        let req = req_with_host("/v1/health", "localhost");
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let json = body_json(resp).await;
        assert_eq!(json["error"]["code"], "daemon_killed");
        assert_eq!(json["error"]["resume_instructions"], "run: agentsso resume");
        // RequestId was inserted by the trace layer BEFORE kill
        // switch rejection, so it appears in the error body.
        assert!(
            json["error"]["request_id"].is_string(),
            "KillSwitchLayer must run after RequestTraceLayer so the 403 body echoes request_id"
        );
    }

    #[tokio::test]
    async fn kill_switch_blocks_regardless_of_auth_header() {
        // Case D-adapted: kill switch active + Authorization header
        // present → still 403 daemon_killed. Even though AuthLayer is
        // a pass-through stub today (Story 4.4 will add real
        // enforcement), this test proves the kill switch short-circuit
        // runs before Auth/Policy layers would get a chance to
        // observe the request. Future: when AuthLayer enforces, flip
        // a variant with a deliberately-invalid bearer token and
        // assert the response is STILL 403 daemon_killed (not 401).
        let switch = Arc::new(KillSwitch::new());
        switch.activate(KillReason::UserInitiated);
        let svc = build_chain(switch);
        let mut req = req_with_host("/v1/tools/gmail/messages", "127.0.0.1");
        req.headers_mut()
            .insert("authorization", HeaderValue::from_static("Bearer definitely-invalid"));
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let json = body_json(resp).await;
        assert_eq!(json["error"]["code"], "daemon_killed");
    }

    #[tokio::test]
    async fn resume_restores_terminal_reachability() {
        // Round-trip: activate → observe 403 → deactivate → observe
        // 200 again. Proves the full kill/resume cycle works end-to-
        // end through the assembled chain. The terminal handler
        // should be reachable again AFTER deactivate.
        let switch = Arc::new(KillSwitch::new());
        let svc = build_chain(Arc::clone(&switch));

        // Inactive → 200
        {
            let req = req_with_host("/v1/health", "localhost");
            let resp = svc.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        // Active → 403
        switch.activate(KillReason::UserInitiated);
        {
            let req = req_with_host("/v1/health", "localhost");
            let resp = svc.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }

        // Resumed → 200
        switch.deactivate();
        {
            let req = req_with_host("/v1/health", "localhost");
            let resp = svc.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }
}
