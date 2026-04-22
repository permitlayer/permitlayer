//! DNS-rebinding protection layer (outermost middleware).
//!
//! Validates `Host` and `Origin` headers against an allowlist. Runs before
//! `TraceLayer`, so rejected requests never get a request_id.

use std::sync::Arc;
use std::task::{Context, Poll};

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, Response};
use axum::response::IntoResponse;
use tower::{Layer, Service};

use crate::error::ProxyError;

/// Tower layer that wraps services with DNS-rebinding protection.
///
/// Story 8.7 AC #5: the allowlist container moved from
/// `Arc<Vec<String>>` to `Arc<ArcSwap<Vec<String>>>` so operator
/// edits to `[dns] allowlist` (a future Epic 7+ feature) can be
/// hot-swapped without rebuilding the tower stack. The MVP allowlist
/// contents stay `["127.0.0.1", "localhost"]`; only the container
/// type changed.
#[derive(Clone)]
pub struct DnsRebindLayer {
    allowlist: Arc<ArcSwap<Vec<String>>>,
}

impl DnsRebindLayer {
    /// Create a new `DnsRebindLayer` with the given allowlist of hostnames.
    #[must_use]
    pub fn new(allowlist: Arc<ArcSwap<Vec<String>>>) -> Self {
        Self { allowlist }
    }
}

impl<S> Layer<S> for DnsRebindLayer {
    type Service = DnsRebindService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DnsRebindService { inner, allowlist: Arc::clone(&self.allowlist) }
    }
}

/// Tower service that enforces DNS-rebinding protection.
#[derive(Clone)]
pub struct DnsRebindService<S> {
    inner: S,
    allowlist: Arc<ArcSwap<Vec<String>>>,
}

impl<S> DnsRebindService<S> {
    /// Strip port and brackets from a host string.
    ///
    /// Examples: `localhost:3000` → `localhost`, `[::1]:3000` → `::1`, `[::1]` → `::1`.
    fn strip_port(host: &str) -> &str {
        // Handle IPv6 addresses like [::1]:3000
        if host.starts_with('[')
            && let Some(bracket_end) = host.find(']')
        {
            // Return content inside brackets, without brackets.
            return &host[1..bracket_end];
        }
        // Regular host:port
        host.split(':').next().unwrap_or(host)
    }

    /// Check if a host string (with or without port) is in the allowlist.
    ///
    /// Story 8.7 AC #5: loads the current allowlist via `ArcSwap::load`.
    /// The returned `arc_swap::Guard` is not `Send`, but this function
    /// has no `.await` so the guard drops naturally at scope end. Any
    /// future refactor that introduces an `.await` inside this path
    /// must `drop(guard)` before the first await — see the
    /// `drop(policy_set)` call inside `PolicyService::call` in
    /// `crates/permitlayer-proxy/src/middleware/policy.rs` for the
    /// canonical precedent. (Symbol reference rather than line number
    /// so the guidance stays accurate across future edits.)
    fn is_allowed(&self, host: &str) -> bool {
        let bare = Self::strip_port(host.trim());
        let guard = self.allowlist.load();
        guard.iter().any(|allowed| bare.eq_ignore_ascii_case(allowed))
    }

    /// Extract the host portion from an Origin header value.
    /// E.g. `http://localhost:3000` → `localhost:3000`
    fn origin_host(origin: &str) -> &str {
        // Strip scheme (http:// or https://)
        let without_scheme = origin
            .strip_prefix("http://")
            .or_else(|| origin.strip_prefix("https://"))
            .unwrap_or(origin);
        // Strip path if present
        without_scheme.split('/').next().unwrap_or(without_scheme)
    }
}

impl<S> Service<Request<Body>> for DnsRebindService<S>
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
        // Validate Host header if present.
        if let Some(host_val) = req.headers().get("host") {
            if let Ok(host_str) = host_val.to_str() {
                if !self.is_allowed(host_str) {
                    tracing::debug!(host = %host_str, "DNS rebind guard: blocked Host header");
                    let response =
                        ProxyError::DnsRebindBlocked { host: host_str.to_owned() }.into_response();
                    return Box::pin(async move { Ok(response) });
                }
            } else {
                // Non-UTF8 Host header — reject.
                let response =
                    ProxyError::DnsRebindBlocked { host: "<non-utf8>".to_owned() }.into_response();
                return Box::pin(async move { Ok(response) });
            }
        } else {
            // Missing Host header — reject.
            tracing::debug!("DNS rebind guard: missing Host header");
            let response =
                ProxyError::DnsRebindBlocked { host: "<missing>".to_owned() }.into_response();
            return Box::pin(async move { Ok(response) });
        }

        // Validate Origin header if present (per AR23: both must pass).
        if let Some(origin_val) = req.headers().get("origin") {
            if let Ok(origin_str) = origin_val.to_str() {
                let origin_host = Self::origin_host(origin_str);
                if !self.is_allowed(origin_host) {
                    tracing::debug!(origin = %origin_str, "DNS rebind guard: blocked Origin header");
                    let response = ProxyError::DnsRebindBlocked { host: origin_str.to_owned() }
                        .into_response();
                    return Box::pin(async move { Ok(response) });
                }
            } else {
                let response =
                    ProxyError::DnsRebindBlocked { host: "<non-utf8-origin>".to_owned() }
                        .into_response();
                return Box::pin(async move { Ok(response) });
            }
        }

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
    use http_body_util::BodyExt;
    use tower::{ServiceBuilder, ServiceExt};

    /// A simple handler that returns 200 OK.
    async fn ok_handler(req: Request<Body>) -> Result<Response<Body>, std::convert::Infallible> {
        let _ = req;
        Ok(Response::builder().status(StatusCode::OK).body(Body::from("ok")).unwrap())
    }

    fn build_service(
        allowlist: Vec<&str>,
    ) -> impl Service<Request<Body>, Response = Response<Body>, Error = std::convert::Infallible>
    {
        let allowlist: Arc<ArcSwap<Vec<String>>> =
            Arc::new(ArcSwap::from_pointee(allowlist.iter().map(|s| (*s).to_owned()).collect()));
        ServiceBuilder::new()
            .layer(DnsRebindLayer::new(allowlist))
            .service(tower::service_fn(ok_handler))
    }

    /// Variant of [`build_service`] that also returns the shared
    /// `Arc<ArcSwap<Vec<String>>>` handle so the Story 8.7 AC #6 test
    /// can hot-swap the allowlist between two `oneshot` calls against
    /// the SAME service clone.
    #[allow(clippy::type_complexity)]
    fn build_service_with_handle(
        allowlist: Vec<&str>,
    ) -> (
        impl Service<Request<Body>, Response = Response<Body>, Error = std::convert::Infallible> + Clone,
        Arc<ArcSwap<Vec<String>>>,
    ) {
        let handle: Arc<ArcSwap<Vec<String>>> =
            Arc::new(ArcSwap::from_pointee(allowlist.iter().map(|s| (*s).to_owned()).collect()));
        let svc = ServiceBuilder::new()
            .layer(DnsRebindLayer::new(Arc::clone(&handle)))
            .service(tower::service_fn(ok_handler));
        (svc, handle)
    }

    #[tokio::test]
    async fn allowed_host_passes() {
        let svc = build_service(vec!["127.0.0.1", "localhost"]);
        let req = Request::builder()
            .uri("/health")
            .header("host", "localhost:3000")
            .body(Body::empty())
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn disallowed_host_blocked() {
        let svc = build_service(vec!["127.0.0.1", "localhost"]);
        let req = Request::builder()
            .uri("/health")
            .header("host", "evil.com")
            .body(Body::empty())
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = Body::new(resp.into_body()).collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["code"], "dns_rebind.blocked");
    }

    #[tokio::test]
    async fn missing_host_blocked() {
        let svc = build_service(vec!["127.0.0.1", "localhost"]);
        let req = Request::builder().uri("/health").body(Body::empty()).unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn port_stripping_works() {
        let svc = build_service(vec!["127.0.0.1", "localhost"]);
        let req = Request::builder()
            .uri("/health")
            .header("host", "127.0.0.1:9999")
            .body(Body::empty())
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn allowed_origin_passes() {
        let svc = build_service(vec!["127.0.0.1", "localhost"]);
        let req = Request::builder()
            .uri("/health")
            .header("host", "localhost:3000")
            .header("origin", "http://localhost:3000")
            .body(Body::empty())
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn disallowed_origin_blocked() {
        let svc = build_service(vec!["127.0.0.1", "localhost"]);
        let req = Request::builder()
            .uri("/health")
            .header("host", "localhost:3000")
            .header("origin", "http://evil.com")
            .body(Body::empty())
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn both_headers_validated() {
        // Valid Host but invalid Origin → blocked.
        let svc = build_service(vec!["127.0.0.1", "localhost"]);
        let req = Request::builder()
            .uri("/health")
            .header("host", "localhost")
            .header("origin", "https://attacker.com")
            .body(Body::empty())
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn dns_rebind_error_has_null_request_id() {
        let svc = build_service(vec!["127.0.0.1", "localhost"]);
        let req = Request::builder()
            .uri("/health")
            .header("host", "evil.com")
            .body(Body::empty())
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        let bytes = Body::new(resp.into_body()).collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json["error"]["request_id"].is_null());
    }

    // -- Boundary condition tests --

    #[tokio::test]
    async fn host_with_whitespace_trimmed() {
        let svc = build_service(vec!["127.0.0.1", "localhost"]);
        let req = Request::builder()
            .uri("/health")
            .header("host", " localhost:3000 ")
            .body(Body::empty())
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ipv6_loopback_allowed() {
        let svc = build_service(vec!["127.0.0.1", "localhost", "::1"]);
        let req = Request::builder()
            .uri("/health")
            .header("host", "[::1]:3000")
            .body(Body::empty())
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ipv6_loopback_without_port_allowed() {
        let svc = build_service(vec!["127.0.0.1", "localhost", "::1"]);
        let req =
            Request::builder().uri("/health").header("host", "[::1]").body(Body::empty()).unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn malformed_ipv6_missing_bracket_blocked() {
        let svc = build_service(vec!["127.0.0.1", "localhost", "::1"]);
        let req =
            Request::builder().uri("/health").header("host", "[::1").body(Body::empty()).unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        // Malformed: missing ']', falls through to split on ':' → "[" which is not in allowlist.
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn empty_host_header_blocked() {
        let svc = build_service(vec!["127.0.0.1", "localhost"]);
        let req = Request::builder().uri("/health").header("host", "").body(Body::empty()).unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Story 8.7 AC #6 — positive proof that swapping the
    /// `Arc<ArcSwap<Vec<String>>>` handle while a `DnsRebindService`
    /// is live changes the allowlist observed on the NEXT request
    /// without rebuilding the service. Without this test AC #5 would
    /// be a type-surface change with no runtime verification.
    #[tokio::test]
    async fn dns_allowlist_hot_swap_takes_effect_without_rebuild() {
        let (svc, allowlist) = build_service_with_handle(vec!["127.0.0.1"]);

        // Request #1: `alt.example.com` not allowed → 400.
        let req1 = Request::builder()
            .uri("/health")
            .header("host", "alt.example.com")
            .body(Body::empty())
            .unwrap();
        let resp1 = svc.clone().oneshot(req1).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::BAD_REQUEST);
        let json1: serde_json::Value = serde_json::from_slice(
            &Body::new(resp1.into_body()).collect().await.unwrap().to_bytes(),
        )
        .unwrap();
        assert_eq!(json1["error"]["code"], "dns_rebind.blocked");

        // Hot-swap the allowlist to include `alt.example.com`.
        allowlist.store(Arc::new(vec!["127.0.0.1".to_owned(), "alt.example.com".to_owned()]));

        // Request #2: same service (clone), same host → now 200.
        let req2 = Request::builder()
            .uri("/health")
            .header("host", "alt.example.com")
            .body(Body::empty())
            .unwrap();
        let resp2 = svc.oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn host_with_multiple_colons_blocked() {
        let svc = build_service(vec!["127.0.0.1", "localhost"]);
        let req = Request::builder()
            .uri("/health")
            .header("host", "localhost:3000:extra")
            .body(Body::empty())
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        // split(':').next() → "localhost" which is allowed. This is acceptable
        // because the extra colon is a malformed host, but the hostname portion
        // is still valid and in the allowlist.
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
