//! Kill-switch middleware.
//!
//! When the [`KillSwitch`] is active, all requests are rejected with
//! HTTP 403 and the `daemon_killed` body shape defined in [`crate::error`].
//! The layer short-circuits BEFORE `AuthLayer`, `AgentIdentityLayer`,
//! `PolicyLayer`, and `AuditLayer` — no authorization-relevant
//! middleware runs when the switch is active.
//!
//! # Layer position
//!
//! The story 3.1 AC #2 pins the chain order at:
//!
//! ```text
//! DnsRebindLayer → RequestTraceLayer → KillSwitchLayer →
//!     AuthLayer → AgentIdentityLayer → PolicyLayer → AuditLayer → handler
//! ```
//!
//! `DnsRebindLayer` deliberately runs OUTSIDE the kill switch: DNS
//! rebinding is a transport-level concern (rejecting malformed Host
//! headers before the request reaches any permitlayer logic), while
//! the kill switch is an authorization-level concern. An attacker
//! using a rebinding host is told `dns_rebind.blocked` regardless of
//! kill state — this is deliberate information hygiene, not a bypass.
//!
//! `RequestTraceLayer` runs before `KillSwitchLayer` so the 403 body
//! echoes the `request_id` (ULID) operators use to correlate the
//! rejection with their `agentsso kill` invocation.

use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{Request, Response};
use chrono::{DateTime, Utc};
use tower::{Layer, Service};

use permitlayer_core::audit::dispatcher::AuditDispatcher;
use permitlayer_core::audit::event::{AuditEvent, format_audit_timestamp};
use permitlayer_core::killswitch::KillSwitch;

use crate::error::{ProxyError, RequestId};

/// Tower layer for the kill switch.
#[derive(Clone)]
pub struct KillSwitchLayer {
    switch: Arc<KillSwitch>,
    /// Owned audit dispatcher (Story 8.2). Replaces the pre-Story-8.2
    /// `Option<Arc<dyn AuditStore>>` + fire-and-forget `tokio::spawn`
    /// pattern. A dispatcher constructed with `AuditDispatcher::none()`
    /// silently drops audit writes — matches the previous `None` store
    /// semantics without changing the middleware shape.
    audit_dispatcher: Arc<AuditDispatcher>,
}

impl KillSwitchLayer {
    #[must_use]
    pub fn new(switch: Arc<KillSwitch>, audit_dispatcher: Arc<AuditDispatcher>) -> Self {
        Self { switch, audit_dispatcher }
    }
}

impl<S> Layer<S> for KillSwitchLayer {
    type Service = KillSwitchService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        KillSwitchService {
            inner,
            switch: Arc::clone(&self.switch),
            audit_dispatcher: Arc::clone(&self.audit_dispatcher),
        }
    }
}

/// Tower service that enforces the kill switch.
#[derive(Clone)]
pub struct KillSwitchService<S> {
    inner: S,
    switch: Arc<KillSwitch>,
    audit_dispatcher: Arc<AuditDispatcher>,
}

impl<S> Service<Request<Body>> for KillSwitchService<S>
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
        // Fail-closed readiness: when the kill switch is active, the
        // layer is ALWAYS ready regardless of inner backpressure.
        // Without this short-circuit, an inner layer that returns
        // `Poll::Pending` (e.g. a future rate limiter in Story 4.4)
        // would stall the kill-switch rejection until the inner was
        // ready — violating the "daemon is killed → reject
        // immediately" invariant. `call()` still enforces the
        // rejection; `poll_ready` just unblocks the call path.
        if self.switch.is_active() {
            return Poll::Ready(Ok(()));
        }
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        if self.switch.is_active() {
            let request_id = req.extensions().get::<RequestId>().map(|r| r.0.clone());

            // Read the activation timestamp. In the normal path this is
            // `Some(t)` because `activate()` stores the timestamp before
            // publishing the atomic `active=true` flag. The `None` branch
            // fires only in the race window where we observed
            // `is_active() == true` but the switch was concurrently
            // deactivated and `activated_at` was cleared. A
            // `tracing::warn!` makes this invariant violation auditable
            // — the 403 response still carries a fallback timestamp
            // (`Utc::now()`) so the client gets a coherent reply, but
            // the audit event distinguishes the race from a legitimate
            // activation. The `activated_at_observed` flag propagates
            // into the audit helper so the log line clearly marks the
            // fallback origin.
            let (activated_at, activated_at_observed) = match self.switch.activated_at() {
                Some(t) => (t, true),
                None => {
                    tracing::warn!(
                        target: "kill",
                        "is_active() was true but activated_at() returned None — race with deactivate; falling back to Utc::now() for the 403 response and audit event",
                    );
                    (chrono::Utc::now(), false)
                }
            };

            // Story 8.2: fire-and-track through the owned AuditDispatcher
            // so daemon shutdown can drain in-flight audit writes. Previously
            // a bare `tokio::spawn` dropped the JoinHandle; now the dispatcher
            // owns the JoinSet and `start.rs` awaits it on SIGTERM.
            let method = req.method().as_str().to_owned();
            let uri = req.uri().clone();

            // Distinguish "no Host header" (None → sentinel "-")
            // from "Host header with invalid UTF-8" (Some(Err) →
            // sentinel "<non-utf8>") so forensic investigators can
            // tell an HTTP/1.0 probe from a malformed attack probe.
            // `unwrap_or_default()` collapsed both to empty string,
            // losing the distinction.
            let host = match req.headers().get(axum::http::header::HOST) {
                None => "-".to_owned(),
                Some(value) => match value.to_str() {
                    Ok(s) => s.to_owned(),
                    Err(_) => "<non-utf8>".to_owned(),
                },
            };

            let request_id_for_audit =
                request_id.clone().unwrap_or_else(|| ulid::Ulid::new().to_string());
            let event = build_kill_blocked_event(
                request_id_for_audit,
                &uri,
                &method,
                &host,
                activated_at,
                activated_at_observed,
            );

            // Story 8.2 review fix D1: `dispatch` is async (acquires a
            // shared backpressure permit before spawning). Await inside
            // the response future so the 403 is held while the permit
            // is contended — producer-edge backpressure. Under normal
            // load the acquire is a fast non-blocking path.
            let dispatcher = Arc::clone(&self.audit_dispatcher);
            let response = ProxyError::KillSwitchActive { activated_at }
                .into_response_with_request_id(request_id);
            return Box::pin(async move {
                dispatcher.dispatch(event).await;
                Ok(response)
            });
        }
        let fut = self.inner.call(req);
        Box::pin(fut)
    }
}

/// Build a `kill-blocked-request` audit event. Pure function —
/// called from `KillSwitchService::call` and handed to
/// `AuditDispatcher::dispatch`, which owns the actual write.
///
/// `activated_at_observed` is `true` when the timestamp came from
/// `KillSwitch::activated_at()` (the normal path), `false` when it
/// fell back to `Utc::now()` because the switch was concurrently
/// deactivated (the race documented in `KillSwitchService::call`).
/// The flag propagates into `extra.activated_at_observed` so forensic
/// investigators can distinguish a real activation timestamp from a
/// fallback.
#[allow(clippy::too_many_arguments)]
fn build_kill_blocked_event(
    request_id: String,
    uri: &axum::http::Uri,
    method: &str,
    host: &str,
    activated_at: DateTime<Utc>,
    activated_at_observed: bool,
) -> AuditEvent {
    let path = uri.path();
    let service = derive_service_from_path(path);
    let resource = truncate_to_chars(path, 256);

    let mut event = AuditEvent::with_request_id(
        request_id,
        // Agent identity is unresolved at this point in the middleware
        // chain — `AgentIdentityLayer` runs AFTER `KillSwitchLayer` per
        // Story 3.1's compile-time ordering pin. Use the `"unknown"`
        // sentinel, which is identical to what `AgentIdentityLayer`
        // would have stamped had it run (its current impl is a stub
        // that always inserts `AgentId("unknown")`). Epic 4's real
        // identity extraction is the fix.
        "unknown".to_owned(),
        service.to_owned(),
        "-".to_owned(),
        resource,
        "denied".to_owned(),
        "kill-blocked-request".to_owned(),
    );
    event.extra = serde_json::json!({
        "error_code": "daemon_killed",
        "activated_at": format_audit_timestamp(activated_at),
        "activated_at_observed": activated_at_observed,
        "method": method,
        "host": host,
    });
    event
}

/// Derive the `service` audit field from the request URI path.
///
/// The path is inspected before any query string. Unknown paths (health
/// probes, control endpoints, anything unrecognized) map to `"-"` — a
/// deliberate not-applicable sentinel that reads cleanly in grep output.
///
/// This is a pure function with no allocation on the hot path (returns
/// `&'static str`). Extend the match when adding new upstream services.
fn derive_service_from_path(path: &str) -> &'static str {
    // Strip query string defensively. In production this split is a no-op
    // because `http::Uri::path()` has already stripped the query, but the
    // helper is also called from unit tests that pass raw strings. Adding
    // trivial defensive parsing keeps the test call path working and
    // prevents future refactors that introduce a direct-string caller
    // from silently matching the wrong prefix.
    let path = path.split('?').next().unwrap_or("");

    // Use `match_segment` instead of bare `starts_with` to avoid
    // substring contamination — `starts_with("/v1/tools/gmail")` would
    // match `/v1/tools/gmail-exploit/evil` and misattribute the audit
    // event. `match_segment(p, "/v1/tools/gmail")` returns true only
    // when `p` is exactly that prefix OR starts with `prefix + "/"`.
    if match_segment(path, "/v1/tools/gmail") {
        "gmail"
    } else if match_segment(path, "/v1/tools/calendar") {
        "calendar"
    } else if match_segment(path, "/v1/tools/drive") {
        "drive"
    } else if match_segment(path, "/mcp/calendar") {
        "calendar"
    } else if match_segment(path, "/mcp/drive") {
        "drive"
    } else if path == "/mcp" || path == "/mcp/" {
        // The default `/mcp` route is wired to the Gmail MCP service
        // in `start.rs` (Story 1.11 convention). Only the exact `/mcp`
        // (with or without trailing slash) maps to gmail — any other
        // `/mcp/...` subpath that didn't match `calendar` or `drive`
        // above is an unknown subservice and maps to `-`, not gmail,
        // to avoid misattributing load during incidents. NOTE: the
        // `/mcp → gmail` hardcode assumes Story 1.11's routing
        // convention and will misattribute if a future config rebinds
        // `/mcp` to a different service. Flagged in deferred-work.md
        // for a future routing-derivation refactor.
        "gmail"
    } else {
        "-"
    }
}

/// Return `true` if `path` exactly equals `prefix` or begins with
/// `prefix + "/"`. This is the "path segment match" that rejects
/// substring contamination like `/v1/tools/gmail-exploit` from matching
/// `/v1/tools/gmail`.
fn match_segment(path: &str, prefix: &str) -> bool {
    if path == prefix {
        return true;
    }
    if let Some(rest) = path.strip_prefix(prefix) {
        return rest.starts_with('/');
    }
    false
}

/// Truncate a string to `max_chars` characters, appending `\u{2026}` (…)
/// if truncated. Operates on Unicode scalar values, not bytes — safe
/// against UTF-8 boundary hazards.
fn truncate_to_chars(text: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let char_count = text.chars().count();
    if char_count <= max_chars {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(max_chars - 1).collect();
    out.push('\u{2026}');
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use permitlayer_core::killswitch::KillReason;
    use tower::{ServiceBuilder, ServiceExt};

    async fn ok_handler(req: Request<Body>) -> Result<Response<Body>, std::convert::Infallible> {
        let _ = req;
        Ok(Response::builder().status(StatusCode::OK).body(Body::from("ok")).unwrap())
    }

    #[tokio::test]
    async fn pass_through_when_inactive() {
        let switch = Arc::new(KillSwitch::new());
        let svc = ServiceBuilder::new()
            .layer(KillSwitchLayer::new(switch, Arc::new(AuditDispatcher::none())))
            .service(tower::service_fn(ok_handler));

        let req = Request::builder().uri("/health").body(Body::empty()).unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn returns_403_daemon_killed_when_active() {
        let switch = Arc::new(KillSwitch::new());
        switch.activate(KillReason::UserInitiated);

        let svc = ServiceBuilder::new()
            .layer(KillSwitchLayer::new(Arc::clone(&switch), Arc::new(AuditDispatcher::none())))
            .service(tower::service_fn(ok_handler));

        let req = Request::builder().uri("/health").body(Body::empty()).unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let body = resp.into_body();
        let bytes = Body::new(body).collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(json["error"]["code"], "daemon_killed");
        assert_eq!(json["error"]["resume_instructions"], "run: agentsso resume");
        assert!(json["error"]["activated_at"].is_string());
        let activated_at = json["error"]["activated_at"].as_str().unwrap();
        assert!(activated_at.ends_with('Z'), "activated_at must use Z suffix");
    }

    #[tokio::test]
    async fn deactivation_restores_pass_through() {
        let switch = Arc::new(KillSwitch::new());
        switch.activate(KillReason::UserInitiated);
        switch.deactivate();

        let svc = ServiceBuilder::new()
            .layer(KillSwitchLayer::new(switch, Arc::new(AuditDispatcher::none())))
            .service(tower::service_fn(ok_handler));

        let req = Request::builder().uri("/health").body(Body::empty()).unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Review finding #6 (LOW): when the kill switch is active,
    /// `poll_ready` must return `Ready(Ok)` immediately regardless
    /// of inner backpressure. Without this, a future inner layer
    /// that returns `Pending` (e.g. Story 4.4 rate limiter) would
    /// stall kill-switch rejections until inner was ready.
    #[tokio::test]
    async fn poll_ready_short_circuits_when_active() {
        use std::sync::Mutex;
        use std::task::{Poll, Waker};

        /// Inner service that is ALWAYS `Pending` in `poll_ready`.
        /// Stores the latest waker so the test can verify it was
        /// never woken.
        #[derive(Clone)]
        struct AlwaysPending {
            last_waker: Arc<Mutex<Option<Waker>>>,
        }

        impl tower::Service<Request<Body>> for AlwaysPending {
            type Response = Response<Body>;
            type Error = std::convert::Infallible;
            type Future = std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
            >;

            fn poll_ready(
                &mut self,
                cx: &mut std::task::Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                *self.last_waker.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            }

            fn call(&mut self, _req: Request<Body>) -> Self::Future {
                panic!("call() should never run when inner is perpetually Pending");
            }
        }

        let switch = Arc::new(KillSwitch::new());
        switch.activate(KillReason::UserInitiated);

        let inner = AlwaysPending { last_waker: Arc::new(Mutex::new(None)) };
        let mut svc = KillSwitchLayer::new(Arc::clone(&switch), Arc::new(AuditDispatcher::none()))
            .layer(inner);

        // poll_ready must return Ready(Ok) DESPITE the perpetually-
        // Pending inner, because the kill switch is active.
        let poll_result = futures_poll_once(&mut svc).await;
        match poll_result {
            Poll::Ready(Ok(())) => { /* expected */ }
            Poll::Ready(Err(_)) => panic!("poll_ready returned error"),
            Poll::Pending => panic!(
                "poll_ready was Pending despite active kill switch — fail-closed invariant broken"
            ),
        }

        // call() then produces the 403 daemon_killed response.
        let req = Request::builder().uri("/health").body(Body::empty()).unwrap();
        let resp = svc.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// Helper that drives a Service's `poll_ready` exactly once and
    /// returns the result. Used by the backpressure short-circuit
    /// test above.
    async fn futures_poll_once<S>(svc: &mut S) -> std::task::Poll<Result<(), S::Error>>
    where
        S: tower::Service<Request<Body>>,
    {
        std::future::poll_fn(|cx| std::task::Poll::Ready(svc.poll_ready(cx))).await
    }

    // ---------------------------------------------------------------------
    //
    // Story 3.3: `derive_service_from_path` + `truncate_to_chars` helpers.
    //
    // ---------------------------------------------------------------------

    #[test]
    fn derive_service_from_path_gmail_rest() {
        assert_eq!(derive_service_from_path("/v1/tools/gmail/users/me/profile"), "gmail");
        assert_eq!(derive_service_from_path("/v1/tools/gmail"), "gmail");
    }

    #[test]
    fn derive_service_from_path_calendar_rest() {
        assert_eq!(
            derive_service_from_path("/v1/tools/calendar/calendars/primary/events"),
            "calendar"
        );
    }

    #[test]
    fn derive_service_from_path_drive_rest() {
        assert_eq!(derive_service_from_path("/v1/tools/drive/files/abc"), "drive");
    }

    #[test]
    fn derive_service_from_path_mcp_gmail_default() {
        assert_eq!(derive_service_from_path("/mcp"), "gmail");
        assert_eq!(derive_service_from_path("/mcp/"), "gmail");
    }

    #[test]
    fn derive_service_from_path_mcp_calendar() {
        assert_eq!(derive_service_from_path("/mcp/calendar"), "calendar");
        assert_eq!(derive_service_from_path("/mcp/calendar/some-method"), "calendar");
    }

    #[test]
    fn derive_service_from_path_mcp_drive() {
        assert_eq!(derive_service_from_path("/mcp/drive"), "drive");
    }

    /// Regression for the substring-contamination bug caught in
    /// Story 3.3's code review: `starts_with("/v1/tools/gmail")` used
    /// to match `/v1/tools/gmail-exploit/evil` and misattribute
    /// forensic events. The fix uses `match_segment` which requires
    /// either exact equality or a `/` separator after the prefix.
    #[test]
    fn derive_service_from_path_rejects_substring_contamination() {
        // Similar prefixes that should NOT match the short service name:
        assert_eq!(derive_service_from_path("/v1/tools/gmail-exploit/evil"), "-");
        assert_eq!(derive_service_from_path("/v1/tools/gmail_old"), "-");
        assert_eq!(derive_service_from_path("/v1/tools/gmailtypo/users"), "-");
        assert_eq!(derive_service_from_path("/v1/tools/calendarother"), "-");
        assert_eq!(derive_service_from_path("/v1/tools/drive-beta/file"), "-");
        assert_eq!(derive_service_from_path("/mcp/calendar-v2"), "-");
        assert_eq!(derive_service_from_path("/mcpfoo"), "-");
        // But the exact prefixes still match:
        assert_eq!(derive_service_from_path("/v1/tools/gmail"), "gmail");
        assert_eq!(derive_service_from_path("/v1/tools/gmail/"), "gmail");
        assert_eq!(derive_service_from_path("/mcp"), "gmail");
        assert_eq!(derive_service_from_path("/mcp/"), "gmail");
    }

    #[test]
    fn match_segment_requires_exact_or_slash_boundary() {
        assert!(match_segment("/v1/tools/gmail", "/v1/tools/gmail"));
        assert!(match_segment("/v1/tools/gmail/", "/v1/tools/gmail"));
        assert!(match_segment("/v1/tools/gmail/users", "/v1/tools/gmail"));
        assert!(!match_segment("/v1/tools/gmail-old", "/v1/tools/gmail"));
        assert!(!match_segment("/v1/tools/gmailer", "/v1/tools/gmail"));
        assert!(!match_segment("", "/v1/tools/gmail"));
        assert!(!match_segment("/", "/v1/tools/gmail"));
    }

    #[test]
    fn derive_service_from_path_health_is_dash() {
        assert_eq!(derive_service_from_path("/health"), "-");
        assert_eq!(derive_service_from_path("/v1/health"), "-");
    }

    #[test]
    fn derive_service_from_path_control_is_dash() {
        // Control endpoints never actually hit KillSwitchLayer (they're
        // carved out of the main router per Story 3.2's ADR 0001), but
        // cover them for defensive completeness.
        assert_eq!(derive_service_from_path("/v1/control/kill"), "-");
        assert_eq!(derive_service_from_path("/v1/control/resume"), "-");
    }

    #[test]
    fn derive_service_from_path_unknown_is_dash() {
        assert_eq!(derive_service_from_path("/"), "-");
        assert_eq!(derive_service_from_path(""), "-");
        assert_eq!(derive_service_from_path("/random/path"), "-");
    }

    #[test]
    fn derive_service_from_path_strips_query_string() {
        assert_eq!(derive_service_from_path("/v1/tools/gmail/users/me?alt=json"), "gmail");
    }

    #[test]
    fn truncate_to_chars_leaves_short_text_untouched() {
        assert_eq!(truncate_to_chars("hello", 10), "hello");
        assert_eq!(truncate_to_chars("hello", 5), "hello");
    }

    #[test]
    fn truncate_to_chars_appends_ellipsis_when_truncated() {
        assert_eq!(truncate_to_chars("helloworld", 5), "hell\u{2026}");
    }

    #[test]
    fn truncate_to_chars_zero_width_returns_empty() {
        assert_eq!(truncate_to_chars("anything", 0), "");
    }

    #[test]
    fn truncate_to_chars_unicode_safe() {
        // Each char is a 3-byte UTF-8 code point; truncating by bytes
        // would be a catastrophe. Char-count truncation is correct.
        let s = "日本語テスト";
        let out = truncate_to_chars(s, 3);
        assert_eq!(out.chars().count(), 3);
        assert!(out.ends_with('\u{2026}'));
    }

    // ---------------------------------------------------------------------
    //
    // Story 3.3: kill-blocked-request audit write end-to-end.
    //
    // Uses a real `AuditFsStore` in a tempdir. The
    // `returns_403_with_audit_write` test drives a request through the
    // full `KillSwitchService::call` path with an active switch and an
    // audit store attached, then waits for the spawned audit task to
    // complete before reading the audit file.
    // ---------------------------------------------------------------------

    use permitlayer_core::scrub::{ScrubEngine, builtin_rules};
    use permitlayer_core::store::AuditStore;
    use permitlayer_core::store::fs::AuditFsStore;

    fn build_audit_store(home: &std::path::Path) -> Arc<dyn AuditStore> {
        let scrub_engine = Arc::new(ScrubEngine::new(builtin_rules().to_vec()).unwrap());
        let audit_dir = home.join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        Arc::new(AuditFsStore::new(audit_dir, 100_000_000, scrub_engine).unwrap())
    }

    fn read_audit_events(
        home: &std::path::Path,
    ) -> Vec<permitlayer_core::audit::event::AuditEvent> {
        let audit_dir = home.join("audit");
        let mut out = Vec::new();
        if !audit_dir.exists() {
            return out;
        }
        let mut paths: Vec<_> = std::fs::read_dir(&audit_dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("jsonl"))
            .collect();
        paths.sort();
        for path in paths {
            let contents = std::fs::read_to_string(&path).unwrap();
            for line in contents.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                out.push(serde_json::from_str(line).unwrap());
            }
        }
        out
    }

    #[tokio::test]
    async fn kill_blocked_request_writes_audit_event() {
        let home = tempfile::TempDir::new().unwrap();
        let store = build_audit_store(home.path());
        let switch = Arc::new(KillSwitch::new());
        switch.activate(KillReason::UserInitiated);

        // Story 8.2: hold the dispatcher in scope so its owned JoinSet
        // stays alive after `svc.oneshot` consumes the service; otherwise
        // the spawned audit task is aborted with the JoinSet's Drop.
        let dispatcher = Arc::new(AuditDispatcher::for_tests_unbounded(Arc::clone(&store)));

        let svc = ServiceBuilder::new()
            .layer(KillSwitchLayer::new(Arc::clone(&switch), Arc::clone(&dispatcher)))
            .service(tower::service_fn(ok_handler));

        let req = Request::builder()
            .method("GET")
            .uri("/v1/tools/gmail/users/me/profile")
            .header("host", "127.0.0.1:3820")
            .body(Body::empty())
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Drain the dispatcher explicitly so the audit write reaches
        // disk before we inspect the file (replaces the pre-Story-8.2
        // yield-and-poll loop).
        let _ = dispatcher.drain(std::time::Duration::from_secs(2)).await;

        let events = read_audit_events(home.path());
        let blocked: Vec<_> =
            events.iter().filter(|e| e.event_type == "kill-blocked-request").collect();
        assert_eq!(
            blocked.len(),
            1,
            "expected 1 kill-blocked-request event, got {}",
            blocked.len()
        );

        let event = blocked[0];
        assert_eq!(event.agent_id, "unknown");
        assert_eq!(event.service, "gmail");
        assert_eq!(event.scope, "-");
        assert_eq!(event.resource, "/v1/tools/gmail/users/me/profile");
        assert_eq!(event.outcome, "denied");
        assert_eq!(event.extra["error_code"], "daemon_killed");
        assert_eq!(event.extra["method"], "GET");
        assert_eq!(event.extra["host"], "127.0.0.1:3820");
        let activated_at = event.extra["activated_at"].as_str().unwrap();
        assert!(activated_at.ends_with('Z'));
    }

    #[tokio::test]
    async fn kill_blocked_request_health_probe_has_dash_service() {
        let home = tempfile::TempDir::new().unwrap();
        let store = build_audit_store(home.path());
        let switch = Arc::new(KillSwitch::new());
        switch.activate(KillReason::UserInitiated);

        let dispatcher = Arc::new(AuditDispatcher::for_tests_unbounded(Arc::clone(&store)));
        let svc = ServiceBuilder::new()
            .layer(KillSwitchLayer::new(Arc::clone(&switch), Arc::clone(&dispatcher)))
            .service(tower::service_fn(ok_handler));

        let req = Request::builder()
            .method("GET")
            .uri("/health")
            .header("host", "localhost")
            .body(Body::empty())
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let _ = dispatcher.drain(std::time::Duration::from_secs(2)).await;

        let events = read_audit_events(home.path());
        let blocked: Vec<_> =
            events.iter().filter(|e| e.event_type == "kill-blocked-request").collect();
        assert_eq!(blocked.len(), 1);
        let event = blocked[0];
        assert_eq!(event.service, "-", "health probe must map to `-` service");
        assert_eq!(event.resource, "/health");
    }

    #[tokio::test]
    async fn kill_blocked_request_no_audit_store_skips_write() {
        // Regression: when audit_store is None, the 403 still fires
        // and nothing panics.
        let switch = Arc::new(KillSwitch::new());
        switch.activate(KillReason::UserInitiated);

        let svc = ServiceBuilder::new()
            .layer(KillSwitchLayer::new(Arc::clone(&switch), Arc::new(AuditDispatcher::none())))
            .service(tower::service_fn(ok_handler));

        let req =
            Request::builder().uri("/v1/tools/gmail/users/me/profile").body(Body::empty()).unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // No audit store → no audit file → nothing to assert except no panic.
    }
}
