//! End-to-end integration tests for the kill switch middleware.
//!
//! Story 3.1 AC #5: the `daemon_killed` response body is byte-for-byte
//! identical across every transport — MCP, REST, health, and the 501
//! stub branch that fires when no credentials are configured. This
//! test file proves that invariant by building the canonical router
//! via `assemble_middleware` + a stub terminal handler (no
//! `ProxyService`, no real credentials, no subprocess plumbing) and
//! exercising it with `tower::ServiceExt::oneshot`.
//!
//! The in-process router matches the 501 stub branch of `start.rs`
//! (the branch that fires when `try_build_proxy_service` returns
//! `None` because the user hasn't run `agentsso setup` yet). That
//! branch is the minimal reproducer for AC #5: even with zero
//! credentials configured, the kill switch still blocks every
//! endpoint with the `daemon_killed` body.
//!
//! Subprocess-based testing is deferred: Story 3.2 will ship the
//! `agentsso kill` CLI command, and once it exists, a real
//! `setup → start → kill → resume → audit` smoke test can be added
//! to `scripts/smoke-test.sh` per the Epic 2 retrospective action
//! item #5.

use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{any, get};
use axum::{Json, Router};
use http_body_util::BodyExt;
use serde::Serialize;
use tower::ServiceExt;

use permitlayer_core::killswitch::{KillReason, KillSwitch};
use permitlayer_proxy::middleware::{
    AlwaysDenyApprovalService, ApprovalService, ConnTrackerSink, PolicySet, assemble_middleware,
};

/// No-op `ConnTrackerSink` for tests that drive the middleware chain
/// directly. Operational paths bypass the tracker, but the layer still
/// needs an `Arc<dyn ConnTrackerSink>` to be constructed.
struct NoopConnTracker;
impl ConnTrackerSink for NoopConnTracker {
    fn record(&self, _agent_name: &str) {}
}

#[derive(Serialize)]
struct HealthStub {
    status: &'static str,
}

async fn health_handler() -> Json<HealthStub> {
    Json(HealthStub { status: "healthy" })
}

async fn not_implemented_handler() -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

/// Build a router that mirrors the 501 stub branch of `start.rs` —
/// real health endpoints + 501 stubs for the tool routes. Applies the
/// canonical middleware chain via `assemble_middleware`.
fn build_stub_router(kill_switch: Arc<KillSwitch>) -> Router {
    let policy_set = Arc::new(ArcSwap::from_pointee(PolicySet::empty()));
    let dns_allowlist: Arc<ArcSwap<Vec<String>>> =
        Arc::new(ArcSwap::from_pointee(vec!["127.0.0.1".to_owned(), "localhost".to_owned()]));

    // Story 3.3: the test doesn't exercise kill-blocked-request audit
    // writes (that's covered directly in kill.rs unit tests), so pass
    // `None` for the audit store.
    //
    // Story 4.4: this test only hits operational paths (health probes
    // + 501 stubs that aren't on the auth-required allowlist), so an
    // empty agent registry + zero lookup key is sufficient.
    let agent_registry = Arc::new(permitlayer_core::agent::AgentRegistry::new(vec![]));
    // Story 4.5: operational paths (/health, /v1/health) bypass the
    // PolicyLayer anyway, so the approval service is never called.
    // A fail-closed AlwaysDeny is appropriate here.
    let approval_service: Arc<dyn ApprovalService> = Arc::new(AlwaysDenyApprovalService::new());
    let middleware = assemble_middleware(
        kill_switch,
        policy_set,
        dns_allowlist,
        Arc::new(permitlayer_core::audit::dispatcher::AuditDispatcher::none()),
        agent_registry,
        Arc::new(zeroize::Zeroizing::new([0u8; permitlayer_core::agent::LOOKUP_KEY_BYTES])),
        None,
        approval_service,
        Arc::new(std::sync::atomic::AtomicU64::new(30)),
        Arc::new(NoopConnTracker) as Arc<dyn ConnTrackerSink>,
    );

    Router::new()
        .route("/health", get(health_handler))
        .route("/v1/health", get(health_handler))
        .route("/mcp", get(not_implemented_handler).post(not_implemented_handler))
        .route("/mcp/calendar", get(not_implemented_handler).post(not_implemented_handler))
        .route("/mcp/drive", get(not_implemented_handler).post(not_implemented_handler))
        .route("/v1/tools/{service}/{*path}", any(not_implemented_handler))
        .layer(middleware)
}

fn req(path: &str) -> Request<Body> {
    let mut r = Request::builder().uri(path).body(Body::empty()).unwrap();
    r.headers_mut().insert("host", HeaderValue::from_static("127.0.0.1:3820"));
    r
}

fn post_req(path: &str) -> Request<Body> {
    let mut r = Request::builder().method("POST").uri(path).body(Body::empty()).unwrap();
    r.headers_mut().insert("host", HeaderValue::from_static("127.0.0.1:3820"));
    r
}

async fn body_json(resp: Response<Body>) -> serde_json::Value {
    let bytes = Body::new(resp.into_body()).collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

/// Assert the error body matches the `daemon_killed` contract:
/// `code == "daemon_killed"`, `resume_instructions == "run: agentsso resume"`,
/// `activated_at` is an RFC 3339 string with `Z` suffix, `request_id` is
/// present (proves `RequestTraceLayer` ran before the kill switch).
fn assert_daemon_killed_body(json: &serde_json::Value) {
    assert_eq!(json["error"]["code"], "daemon_killed", "json was: {json}");
    assert_eq!(json["error"]["resume_instructions"], "run: agentsso resume", "json was: {json}");
    let activated_at = json["error"]["activated_at"]
        .as_str()
        .unwrap_or_else(|| panic!("activated_at missing or non-string: {json}"));
    assert!(
        activated_at.ends_with('Z'),
        "activated_at must use Z suffix (audit log format): {activated_at}"
    );
    chrono::DateTime::parse_from_rfc3339(activated_at)
        .unwrap_or_else(|e| panic!("activated_at not RFC 3339: {activated_at} ({e})"));
    assert!(
        json["error"]["request_id"].is_string(),
        "request_id must be present (proves RequestTraceLayer ran before KillSwitchLayer): {json}"
    );
}

#[tokio::test]
async fn kill_active_blocks_health() {
    // AC #5: /health is blocked — even operator probes see the
    // kill state, which is deliberate (they're an operator signal,
    // not an uptime heartbeat).
    let switch = Arc::new(KillSwitch::new());
    switch.activate(KillReason::UserInitiated);
    let router = build_stub_router(Arc::clone(&switch));

    let resp = router.oneshot(req("/health")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = body_json(resp).await;
    assert_daemon_killed_body(&json);
}

#[tokio::test]
async fn kill_active_blocks_v1_health() {
    let switch = Arc::new(KillSwitch::new());
    switch.activate(KillReason::UserInitiated);
    let router = build_stub_router(Arc::clone(&switch));

    let resp = router.oneshot(req("/v1/health")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = body_json(resp).await;
    assert_daemon_killed_body(&json);
}

#[tokio::test]
async fn kill_active_blocks_mcp_stub() {
    // Kill active + POST /mcp (which would return 501 normally
    // because no ProxyService is configured) → still 403
    // daemon_killed. Proves the kill switch fires BEFORE the
    // terminal handler, even when the terminal is a 501 stub.
    let switch = Arc::new(KillSwitch::new());
    switch.activate(KillReason::UserInitiated);
    let router = build_stub_router(Arc::clone(&switch));

    let resp = router.oneshot(post_req("/mcp")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = body_json(resp).await;
    assert_daemon_killed_body(&json);
}

#[tokio::test]
async fn kill_active_blocks_mcp_calendar_stub() {
    let switch = Arc::new(KillSwitch::new());
    switch.activate(KillReason::UserInitiated);
    let router = build_stub_router(Arc::clone(&switch));

    let resp = router.oneshot(post_req("/mcp/calendar")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = body_json(resp).await;
    assert_daemon_killed_body(&json);
}

#[tokio::test]
async fn kill_active_blocks_rest_tool_route() {
    let switch = Arc::new(KillSwitch::new());
    switch.activate(KillReason::UserInitiated);
    let router = build_stub_router(Arc::clone(&switch));

    let resp = router.oneshot(req("/v1/tools/gmail/users/me/profile")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = body_json(resp).await;
    assert_daemon_killed_body(&json);
}

#[tokio::test]
async fn kill_active_identical_body_across_endpoints() {
    // AC #5: the status code, `Content-Type` header, and response
    // body JSON shape are identical across all four endpoint types
    // (health, MCP, MCP sub-service, REST tool route). Per-request
    // fields (`request_id`, `activated_at`) are per-request and
    // stripped before structural comparison — but BEFORE stripping,
    // each must be asserted present and non-null so a regression
    // that drops one of them on a specific endpoint cannot silently
    // pass this test.
    let switch = Arc::new(KillSwitch::new());
    switch.activate(KillReason::UserInitiated);

    /// (status_code, content_type_header, body_json).
    async fn fetch(
        switch: Arc<KillSwitch>,
        r: Request<Body>,
    ) -> (StatusCode, Option<String>, serde_json::Value) {
        let router = build_stub_router(switch);
        let resp = router.oneshot(r).await.unwrap();
        let status = resp.status();
        let content_type =
            resp.headers().get("content-type").map(|v| v.to_str().unwrap().to_owned());
        let json = body_json(resp).await;
        (status, content_type, json)
    }

    let probes = [
        ("GET /health", fetch(Arc::clone(&switch), req("/health")).await),
        ("GET /v1/health", fetch(Arc::clone(&switch), req("/v1/health")).await),
        ("POST /mcp", fetch(Arc::clone(&switch), post_req("/mcp")).await),
        (
            "GET /v1/tools/gmail/messages",
            fetch(Arc::clone(&switch), req("/v1/tools/gmail/messages")).await,
        ),
    ];

    // Per-endpoint invariants.
    for (label, (status, content_type, body)) in probes.iter() {
        assert_eq!(*status, StatusCode::FORBIDDEN, "{label}: expected 403");

        let ct = content_type.as_deref().unwrap_or_else(|| {
            panic!("{label}: missing Content-Type header on kill-switch 403 response")
        });
        assert!(
            ct.starts_with("application/json"),
            "{label}: expected Content-Type: application/json*, got {ct}"
        );

        // Validate the full daemon_killed contract on each body
        // BEFORE stripping per-request fields.
        assert_daemon_killed_body(body);
    }

    // Per-request fields (`request_id`, `activated_at`) are
    // asserted present above via `assert_daemon_killed_body`. Strip
    // them so the remaining keys + values can be compared as JSON
    // equality.
    let mut stripped_bodies: Vec<serde_json::Value> =
        probes.iter().map(|(_, (_, _, body))| body.clone()).collect();
    for body in stripped_bodies.iter_mut() {
        let error = body.get_mut("error").unwrap().as_object_mut().unwrap();
        error.remove("request_id");
        error.remove("activated_at");
    }

    // All four stripped bodies must now be structurally equal.
    let first = &stripped_bodies[0];
    for (i, body) in stripped_bodies.iter().enumerate().skip(1) {
        let label = probes[i].0;
        assert_eq!(
            body, first,
            "{label}: kill-switch body diverged from /health after stripping per-request fields. \
             first: {first}, {label}: {body}"
        );
    }

    // Sanity check the shared body has the daemon_killed shape.
    assert_eq!(first["error"]["code"], "daemon_killed");
    assert_eq!(first["error"]["resume_instructions"], "run: agentsso resume");
}

#[tokio::test]
async fn kill_inactive_passes_through_health() {
    // Sanity: with the switch inactive, /health returns 200 + the
    // stub body. Proves the middleware isn't misbehaving when the
    // switch is off.
    let switch = Arc::new(KillSwitch::new());
    let router = build_stub_router(Arc::clone(&switch));

    let resp = router.oneshot(req("/health")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "healthy");
}

#[tokio::test]
async fn kill_active_then_resume_restores_health() {
    // Full activate → 403 → deactivate → 200 cycle through the
    // assembled router. Proves the kill/resume round-trip works
    // end-to-end, not just at the unit level.
    let switch = Arc::new(KillSwitch::new());

    // Inactive: 200
    {
        let router = build_stub_router(Arc::clone(&switch));
        let resp = router.oneshot(req("/health")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Active: 403 daemon_killed
    switch.activate(KillReason::UserInitiated);
    {
        let router = build_stub_router(Arc::clone(&switch));
        let resp = router.oneshot(req("/health")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let json = body_json(resp).await;
        assert_daemon_killed_body(&json);
    }

    // Resumed: 200 again
    switch.deactivate();
    {
        let router = build_stub_router(Arc::clone(&switch));
        let resp = router.oneshot(req("/health")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
