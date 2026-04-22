//! Request tracing middleware.
//!
//! Generates a ULID request ID per request, opens a tracing span, inserts the
//! ID into request extensions, and echoes it in the `X-Agentsso-Request-Id`
//! response header.

use std::task::{Context, Poll};
use std::time::Instant;

use axum::body::Body;
use axum::http::{Request, Response};
use tower::{Layer, Service};
use tracing::Instrument;

use crate::error::RequestId;

/// Tower layer that wraps services with request tracing.
#[derive(Clone, Default)]
pub struct RequestTraceLayer;

impl RequestTraceLayer {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for RequestTraceLayer {
    type Service = RequestTraceService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestTraceService { inner }
    }
}

/// Tower service that traces each request with a ULID.
#[derive(Clone)]
pub struct RequestTraceService<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for RequestTraceService<S>
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
        let request_id = ulid::Ulid::new().to_string();
        let start = Instant::now();

        // Insert request_id into extensions for downstream middleware.
        req.extensions_mut().insert(RequestId(request_id.clone()));

        let span = tracing::info_span!(
            "request",
            request_id = %request_id,
            agent_id = "unknown",
            service = "unknown",
            scope = "unknown",
            method = %req.method(),
            path = %req.uri().path(),
        );

        // Swap self.inner with a clone so the polled-ready instance is the
        // one we actually call (tower Service contract).
        // Clone first, then swap: the polled-ready instance is used for the
        // call, and the fresh clone takes its place (tower Service contract).
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let fut = async move {
            let result = inner.call(req).await;
            let elapsed = start.elapsed();
            tracing::info!(duration_ms = elapsed.as_millis() as u64, "request completed");
            match result {
                Ok(mut response) => {
                    #[allow(clippy::expect_used)]
                    let header_value =
                        request_id.parse().expect("static invariant: ULID is valid header value");
                    response.headers_mut().insert("x-agentsso-request-id", header_value);
                    Ok(response)
                }
                Err(e) => Err(e),
            }
        }
        .instrument(span);
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
    use tracing_test::traced_test;

    async fn ok_handler(req: Request<Body>) -> Result<Response<Body>, std::convert::Infallible> {
        let _ = req;
        Ok(Response::builder().status(StatusCode::OK).body(Body::from("ok")).unwrap())
    }

    #[tokio::test]
    #[traced_test]
    async fn ulid_generated_and_header_echoed() {
        let svc = ServiceBuilder::new()
            .layer(RequestTraceLayer::new())
            .service(tower::service_fn(ok_handler));

        let req = Request::builder().uri("/health").body(Body::empty()).unwrap();

        let resp: Response<Body> = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let header = resp
            .headers()
            .get("x-agentsso-request-id")
            .expect("missing X-Agentsso-Request-Id header");
        let id_str = header.to_str().unwrap();
        // ULID is 26 characters, uppercase alphanumeric.
        assert_eq!(id_str.len(), 26, "ULID should be 26 chars: {id_str}");

        // Verify span fields are present in tracing output.
        assert!(logs_contain("request"));
        assert!(logs_contain("agent_id"));
        assert!(logs_contain("request completed"));
    }

    #[tokio::test]
    async fn request_id_in_extensions() {
        // Verify the inner service can read RequestId from extensions.
        async fn check_extension(
            req: Request<Body>,
        ) -> Result<Response<Body>, std::convert::Infallible> {
            let ext = req.extensions().get::<RequestId>();
            assert!(ext.is_some(), "RequestId not in extensions");
            let id = &ext.unwrap().0;
            assert_eq!(id.len(), 26);
            Ok(Response::builder().status(StatusCode::OK).body(Body::from("ok")).unwrap())
        }

        let svc = ServiceBuilder::new()
            .layer(RequestTraceLayer::new())
            .service(tower::service_fn(check_extension));

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp: Response<Body> = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
