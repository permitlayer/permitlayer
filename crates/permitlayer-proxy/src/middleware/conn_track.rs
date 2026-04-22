//! Per-request connection-tracking middleware (Story 5.5 — FR83).
//!
//! Reads the `AgentId` extension that `AuthLayer` populates and
//! forwards each observation to a [`ConnTrackerSink`] (the daemon's
//! `ConnTracker`, behind a trait so this crate stays free of
//! `dashmap`).
//!
//! # Position in the chain
//!
//! Wedged between `AgentIdentityLayer` and `PolicyLayer`:
//!
//! ```text
//! DnsRebind → Trace → KillSwitch → Auth → AgentIdentity → ConnTrack → Policy → Audit → handler
//! ```
//!
//! - **After Auth/AgentIdentity** so `AgentId` is on the request.
//!   Unauthenticated *non-operational* requests (bad/expired/missing bearer
//!   token on proxy paths) are rejected at `AuthLayer` and **never reach
//!   `ConnTrackLayer`** — so only *authenticated* agents appear in the
//!   tracker. Operational paths (`/health`, `/v1/control/*`) bypass `AuthLayer`
//!   and short-circuit inside `ConnTrackLayer` before any `AgentId` read.
//! - **Before Policy** so we record authenticated agents that are *trying*
//!   things, including those whose requests are subsequently denied at
//!   policy time. This matches the audit log's per-attempt accounting and
//!   what operators expect when they wonder "is this agent doing things?"
//!
//! # No response-path work
//!
//! `record` fires on entry only. The tracker uses a sliding window
//! (60-bucket per-minute history) rather than a request-counter, so
//! there is no decrement-on-drop path that can race with response
//! cancellation. See `server::conn_tracker::ConnTracker` for the
//! rationale.

use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{Request, Response};
use tower::{Layer, Service};

use crate::error::AgentId;
use crate::middleware::util::is_operational_path;

/// Trait the daemon's `ConnTracker` implements so this crate doesn't
/// depend on `dashmap` or the daemon's wall-clock semantics. The
/// middleware sees only the per-request observation point.
pub trait ConnTrackerSink: Send + Sync + 'static {
    /// Record one observation for `agent_name`. The tracker provides
    /// its own wall-clock + monotonic-clock readings — the middleware
    /// stays clock-free so the sink can use synthetic clocks in tests.
    fn record(&self, agent_name: &str);
}

/// Tower layer that records each request's `AgentId` to a
/// [`ConnTrackerSink`].
#[derive(Clone)]
pub struct ConnTrackLayer {
    sink: Arc<dyn ConnTrackerSink>,
}

impl ConnTrackLayer {
    #[must_use]
    pub fn new(sink: Arc<dyn ConnTrackerSink>) -> Self {
        Self { sink }
    }
}

impl<S> Layer<S> for ConnTrackLayer {
    type Service = ConnTrackService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ConnTrackService { inner, sink: Arc::clone(&self.sink) }
    }
}

/// Tower service that observes `AgentId` and forwards the request.
#[derive(Clone)]
pub struct ConnTrackService<S> {
    inner: S,
    sink: Arc<dyn ConnTrackerSink>,
}

impl<S> Service<Request<Body>> for ConnTrackService<S>
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
        // Operational paths (`/health`, `/v1/health`, `/v1/control/*`)
        // bypass auth and therefore have no `AgentId`. Skip the
        // observation cleanly — the tracker is for agent-attributed
        // requests only.
        if is_operational_path(req.uri().path()) {
            return Box::pin(self.inner.call(req));
        }
        if let Some(agent_id) = req.extensions().get::<AgentId>() {
            self.sink.record(&agent_id.0);
        }
        Box::pin(self.inner.call(req))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use std::sync::Mutex;
    use tower::{ServiceBuilder, ServiceExt};

    /// Test sink that records every observed agent name.
    struct VecSink {
        observed: Mutex<Vec<String>>,
    }

    impl VecSink {
        fn new() -> Arc<Self> {
            Arc::new(Self { observed: Mutex::new(Vec::new()) })
        }
        fn observed(&self) -> Vec<String> {
            self.observed.lock().unwrap().clone()
        }
    }

    impl ConnTrackerSink for VecSink {
        fn record(&self, agent_name: &str) {
            self.observed.lock().unwrap().push(agent_name.to_owned());
        }
    }

    async fn handler(_req: Request<Body>) -> Result<Response<Body>, std::convert::Infallible> {
        Ok(Response::builder().status(StatusCode::OK).body(Body::from("inner-body")).unwrap())
    }

    #[tokio::test]
    async fn conn_track_passes_through_when_no_agent_id() {
        let sink = VecSink::new();
        let svc = ServiceBuilder::new()
            .layer(ConnTrackLayer::new(Arc::clone(&sink) as Arc<dyn ConnTrackerSink>))
            .service(tower::service_fn(handler));
        // /health is operational → no AgentId expected, no observation.
        let req = Request::builder().uri("/health").body(Body::empty()).unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(sink.observed().is_empty());
    }

    #[tokio::test]
    async fn conn_track_records_when_agent_id_present() {
        let sink = VecSink::new();
        let svc = ServiceBuilder::new()
            .layer(ConnTrackLayer::new(Arc::clone(&sink) as Arc<dyn ConnTrackerSink>))
            .service(tower::service_fn(handler));
        let mut req =
            Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        req.extensions_mut().insert(AgentId("test-agent".to_owned()));
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(sink.observed(), vec!["test-agent".to_owned()]);
    }

    #[tokio::test]
    async fn conn_track_does_not_block_response_path() {
        let sink = VecSink::new();
        let svc = ServiceBuilder::new()
            .layer(ConnTrackLayer::new(Arc::clone(&sink) as Arc<dyn ConnTrackerSink>))
            .service(tower::service_fn(handler));
        let mut req =
            Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        req.extensions_mut().insert(AgentId("test-agent".to_owned()));
        let resp = svc.oneshot(req).await.unwrap();
        let bytes = Body::new(resp.into_body()).collect().await.unwrap().to_bytes();
        // The inner service's body must reach the caller unchanged.
        assert_eq!(&bytes[..], b"inner-body");
    }
}
