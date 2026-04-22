//! Audit middleware (stub).
//!
//! Logs request/response metadata at TRACE level. Does NOT write to audit file
//! yet — that lands in Story 1.9.

use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{Request, Response};
use tower::{Layer, Service};

use crate::error::RequestId;

/// Tower layer for audit logging.
#[derive(Clone, Default)]
pub struct AuditLayer;

impl AuditLayer {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for AuditLayer {
    type Service = AuditService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuditService { inner }
    }
}

/// Tower service that logs audit events at TRACE level (stub).
#[derive(Clone)]
pub struct AuditService<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for AuditService<S>
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
        let request_id =
            req.extensions().get::<RequestId>().map(|r| r.0.clone()).unwrap_or_default();
        let method = req.method().to_string();
        let path = req.uri().path().to_owned();

        tracing::trace!(
            request_id = %request_id,
            method = %method,
            path = %path,
            "audit: request entering handler"
        );

        // Clone first, then swap: the polled-ready instance is used for the
        // call, and the fresh clone takes its place (tower Service contract).
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let fut = async move {
            let result = inner.call(req).await;
            match &result {
                Ok(resp) => {
                    tracing::trace!(
                        request_id = %request_id,
                        status = resp.status().as_u16(),
                        "audit: response leaving handler"
                    );
                }
                Err(_) => {
                    tracing::trace!(
                        request_id = %request_id,
                        "audit: handler returned error"
                    );
                }
            }
            result
        };
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

    #[tokio::test]
    async fn pass_through() {
        async fn handler(req: Request<Body>) -> Result<Response<Body>, std::convert::Infallible> {
            let _ = req;
            Ok(Response::builder().status(StatusCode::OK).body(Body::from("ok")).unwrap())
        }

        let svc =
            ServiceBuilder::new().layer(AuditLayer::new()).service(tower::service_fn(handler));

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp: Response<Body> = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
