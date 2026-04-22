//! Agent identity middleware (no-op pass-through after Story 4.4).
//!
//! Story 4.4 moved real bearer-token → `AgentId` resolution into
//! `AuthLayer` (which runs immediately upstream of this layer in the
//! pinned middleware chain). This layer is therefore a pass-through
//! today — but it stays in the chain on purpose:
//!
//! - **Removing it would break the Story 3.1 compile-time
//!   `assert_type_eq_all!` ordering test.** The `MiddlewareStack`
//!   type alias has `AgentIdentityLayer` baked in; deleting the layer
//!   would change the alias and fail the static assertion.
//! - **It is a documentation seam** for any future story that wants
//!   to decorate `AgentId` with derived metadata (group membership,
//!   tenant, etc.) without touching `AuthLayer`'s authentication
//!   responsibility.
//! - **Defense in depth**: the `debug_assert!` in `call()` fires in
//!   debug builds if a future refactor moves `AgentIdentityLayer`
//!   ahead of `AuthLayer`, catching the chain-order regression
//!   immediately rather than waiting for a production miss.
//!
//! In release builds the `debug_assert!` compiles out and the layer
//! is the cheapest possible pass-through.

use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{Request, Response};
use tower::{Layer, Service};

use crate::error::AgentId;
use crate::middleware::util::is_operational_path;

/// Tower layer that asserts the `AgentId` extension is present (in
/// debug builds) and otherwise passes the request through unchanged.
#[derive(Clone, Default)]
pub struct AgentIdentityLayer;

impl AgentIdentityLayer {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for AgentIdentityLayer {
    type Service = AgentIdentityService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AgentIdentityService { inner }
    }
}

/// Tower service that documents the AuthLayer → AgentIdentityLayer
/// contract via a debug-only assertion.
#[derive(Clone)]
pub struct AgentIdentityService<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for AgentIdentityService<S>
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
        // Debug-only contract assertion: AuthLayer must populate AgentId
        // before the request reaches AgentIdentityLayer for any
        // non-operational path. Operational paths bypass auth and
        // therefore have no AgentId. The assert compiles out in
        // release builds.
        debug_assert!(
            req.extensions().get::<AgentId>().is_some() || is_operational_path(req.uri().path()),
            "AuthLayer must populate AgentId before AgentIdentityLayer for non-operational paths"
        );

        let fut = self.inner.call(req);
        Box::pin(fut)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::{ServiceBuilder, ServiceExt};

    async fn handler(_req: Request<Body>) -> Result<Response<Body>, std::convert::Infallible> {
        Ok(Response::builder().status(StatusCode::OK).body(Body::from("ok")).unwrap())
    }

    #[tokio::test]
    async fn passes_through_with_agent_id_extension() {
        let svc = ServiceBuilder::new()
            .layer(AgentIdentityLayer::new())
            .service(tower::service_fn(handler));
        let mut req =
            Request::builder().uri("/v1/tools/gmail/users/me").body(Body::empty()).unwrap();
        req.extensions_mut().insert(AgentId("test-agent".to_owned()));
        let resp: Response<Body> = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn passes_through_operational_path_without_agent_id() {
        let svc = ServiceBuilder::new()
            .layer(AgentIdentityLayer::new())
            .service(tower::service_fn(handler));
        // No AgentId in extensions, but the path is operational so
        // the debug_assert is satisfied (AND short-circuits via the
        // is_operational_path check).
        let req = Request::builder().uri("/health").body(Body::empty()).unwrap();
        let resp: Response<Body> = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
