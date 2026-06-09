//! HTTP client for dispatching requests to upstream Google APIs.

use std::time::Duration;

use axum::body::Bytes;
use axum::http::{HeaderMap, Method};
use url::Url;

use crate::error::ProxyError;

/// Default maximum upstream response body size for the JSON/MCP path
/// (10 MiB). Caps memory on the fully-buffered response read.
pub const MAX_RESPONSE_BODY: usize = 10 * 1024 * 1024;

/// Maximum upstream response body for the attachment-fetch path (50 MiB).
/// Gmail attachment `data` is base64 (~33% inflation), so this bounds a
/// raw attachment of roughly ~37 MiB. The bytes are decoded and written
/// to disk server-side (never streamed through an MCP text result), so
/// the larger cap does not enlarge any model-visible payload.
pub const MAX_ATTACHMENT_BODY: usize = 50 * 1024 * 1024;

/// Response from an upstream API call.
#[derive(Debug)]
pub struct UpstreamResponse {
    /// HTTP status code from upstream.
    pub status: u16,
    /// Response headers from upstream.
    pub headers: HeaderMap,
    /// Response body bytes.
    pub body: Bytes,
}

/// HTTP client for dispatching requests to upstream APIs.
///
/// Wraps a shared `reqwest::Client` with connection pooling, rustls-tls,
/// and configured timeouts. Maps upstream errors to `ProxyError` variants.
pub struct UpstreamClient {
    client: reqwest::Client,
}

impl UpstreamClient {
    /// Create a new upstream client.
    ///
    /// Configures: connect timeout (10s), request timeout (30s), rustls-tls.
    ///
    /// Story 11.5: the client no longer holds a hardcoded `base_urls`
    /// map. The upstream base URL + host allowlist are resolved from the
    /// connector definition (`UpstreamSpec`) by the caller and passed to
    /// [`Self::dispatch`].
    pub fn new() -> Result<Self, ProxyError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .use_rustls_tls()
            .build()
            .map_err(|e| ProxyError::Internal {
                message: format!("failed to build HTTP client: {e}"),
            })?;

        Ok(Self { client })
    }

    /// Construct an `UpstreamClient` wrapping a caller-supplied
    /// `reqwest::Client`.
    ///
    /// Story 11.5: replaces the deleted `with_client_and_urls` — it
    /// carries no base URLs (those come from the connector def now), only
    /// the HTTP client. Used by integration tests that need a client
    /// without `new()`'s 10s/30s timeouts (e.g. `start_paused` tests
    /// whose virtualized clock would otherwise trip a real connect
    /// timeout at virtual-time zero).
    #[must_use]
    pub fn from_client(client: reqwest::Client) -> Self {
        Self { client }
    }

    /// Dispatch a request to the upstream API.
    ///
    /// Joins `path` onto the connector-resolved `base_url`, sets the
    /// `Authorization: Bearer` header, and forwards the request.
    /// `service` is the bare service label used only for error/audit
    /// attribution. `guard` carries the connector's host allowlist + trust
    /// tier + the `allow_private_upstream` escape hatch; the per-call
    /// resolved-host SSRF re-check (Story 11.6, FR91/NFR52) runs on the
    /// joined URL before any bytes leave the process.
    #[allow(clippy::too_many_arguments)] // HTTP dispatch: full request shape + body cap.
    pub async fn dispatch(
        &self,
        service: &str,
        base_url: &Url,
        guard: &super::ssrf_guard::UpstreamGuard<'_>,
        path: &str,
        method: Method,
        headers: HeaderMap,
        body: Bytes,
        access_token: &str,
        max_body: usize,
    ) -> Result<UpstreamResponse, ProxyError> {
        let url = base_url.join(path).map_err(|e| ProxyError::Internal {
            message: format!("invalid upstream URL path '{path}': {e}"),
        })?;

        // FR91/NFR52: re-check the RESOLVED host against the connector's
        // allowlist (+ host-installed range/scheme rules) — fail closed.
        super::ssrf_guard::check_upstream(
            service,
            &url,
            guard.allowed_hosts,
            guard.trust_tier,
            guard.allow_private_upstream,
        )?;

        let reqwest_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
            .map_err(|e| ProxyError::Internal { message: format!("invalid HTTP method: {e}") })?;

        let mut request =
            self.client.request(reqwest_method, url).bearer_auth(access_token).body(body);

        // Forward headers (excluding hop-by-hop and auth headers which are set by us).
        for (name, value) in &headers {
            let name_str = name.as_str();
            if name_str != "host"
                && name_str != "authorization"
                && name_str != "content-length"
                && name_str != "transfer-encoding"
                && name_str != "accept-encoding"
            {
                request = request.header(name_str, value);
            }
        }

        let response = request.send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                ProxyError::UpstreamUnreachable {
                    service: service.to_owned(),
                    message: e.to_string(),
                    retry_after_seconds: 30,
                }
            } else {
                ProxyError::Internal { message: format!("upstream request failed: {e}") }
            }
        })?;

        let status = response.status().as_u16();

        // Handle 429 rate limit.
        if status == 429 {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_owned());
            return Err(ProxyError::UpstreamRateLimited {
                service: service.to_owned(),
                retry_after,
            });
        }

        // Handle 5xx server errors.
        if status >= 500 {
            // F11: Truncate 5xx body to avoid leaking internal API details.
            let body_text = response.text().await.unwrap_or_default();
            let truncated = if body_text.len() > 512 {
                format!("{}...(truncated)", &body_text[..512])
            } else {
                body_text
            };
            return Err(ProxyError::UpstreamServerError {
                service: service.to_owned(),
                status,
                message: truncated,
            });
        }

        let resp_headers = convert_headers(response.headers());
        // F7: Cap response body size to prevent OOM on large upstream responses.
        // `max_body` is the caller-supplied ceiling (MAX_RESPONSE_BODY for the
        // JSON/MCP path; MAX_ATTACHMENT_BODY for the attachment-fetch path).
        let content_length = response.content_length().unwrap_or(0);
        if content_length > max_body as u64 {
            return Err(ProxyError::Internal {
                message: format!(
                    "upstream response body too large: {content_length} bytes (max {max_body})"
                ),
            });
        }
        let resp_body = response.bytes().await.map_err(|e| ProxyError::Internal {
            message: format!("failed to read upstream response body: {e}"),
        })?;
        if resp_body.len() > max_body {
            return Err(ProxyError::Internal {
                message: format!(
                    "upstream response body too large: {} bytes (max {max_body})",
                    resp_body.len()
                ),
            });
        }

        Ok(UpstreamResponse { status, headers: resp_headers, body: resp_body })
    }
}

/// Convert reqwest headers to axum HeaderMap.
fn convert_headers(reqwest_headers: &reqwest::header::HeaderMap) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in reqwest_headers {
        let name_str = name.as_str();
        // Strip hop-by-hop and framing headers — the body has already been
        // fully read, so transfer-encoding / content-encoding / content-length
        // from upstream would conflict with axum's own response framing.
        if name_str == "transfer-encoding"
            || name_str == "content-encoding"
            || name_str == "content-length"
            || name_str == "connection"
        {
            continue;
        }
        if let Ok(name) = axum::http::header::HeaderName::from_bytes(name_str.as_bytes())
            && let Ok(value) = axum::http::header::HeaderValue::from_bytes(value.as_bytes())
        {
            headers.append(name, value);
        }
    }
    headers
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn test_client() -> UpstreamClient {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        UpstreamClient { client }
    }

    /// Allowlist a base URL's own host (the real flow's invariant — a
    /// connector's `allowed_hosts` contains its `base_url` host, validated
    /// at load). The mock server runs on `127.0.0.1:PORT`, so the test
    /// allowlist must contain that host for the SSRF guard (11.6) to pass.
    fn allow_host_of(base: &Url) -> Vec<String> {
        vec![base.host_str().expect("base has host").to_owned()]
    }

    /// A BuiltIn guard allowlisting the given base URL's host.
    fn builtin_guard(hosts: &[String]) -> super::super::ssrf_guard::UpstreamGuard<'_> {
        super::super::ssrf_guard::UpstreamGuard {
            allowed_hosts: hosts,
            trust_tier: permitlayer_connectors::TrustTier::BuiltIn,
            allow_private_upstream: false,
        }
    }

    #[tokio::test]
    async fn successful_dispatch() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/gmail/v1/users/me/messages")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"messages":[]}"#)
            .create_async()
            .await;

        let client = test_client();
        let base = Url::parse(&format!("{}/gmail/v1/", server.url())).unwrap();
        let result = client
            .dispatch(
                "gmail",
                &base,
                &builtin_guard(&allow_host_of(&base)),
                "users/me/messages",
                Method::GET,
                HeaderMap::new(),
                Bytes::new(),
                "test-token",
                MAX_RESPONSE_BODY,
            )
            .await;

        let resp = result.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, r#"{"messages":[]}"#.as_bytes());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn upstream_429_returns_rate_limited() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/gmail/v1/users/me/messages")
            .with_status(429)
            .with_header("retry-after", "60")
            .create_async()
            .await;

        let client = test_client();
        let base = Url::parse(&format!("{}/gmail/v1/", server.url())).unwrap();
        let result = client
            .dispatch(
                "gmail",
                &base,
                &builtin_guard(&allow_host_of(&base)),
                "users/me/messages",
                Method::GET,
                HeaderMap::new(),
                Bytes::new(),
                "test-token",
                MAX_RESPONSE_BODY,
            )
            .await;

        match result {
            Err(ProxyError::UpstreamRateLimited { service, retry_after }) => {
                assert_eq!(service, "gmail");
                assert_eq!(retry_after.as_deref(), Some("60"));
            }
            other => panic!("expected UpstreamRateLimited, got {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn upstream_500_returns_server_error() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/gmail/v1/users/me/messages")
            .with_status(500)
            .with_body("internal error")
            .create_async()
            .await;

        let client = test_client();
        let base = Url::parse(&format!("{}/gmail/v1/", server.url())).unwrap();
        let result = client
            .dispatch(
                "gmail",
                &base,
                &builtin_guard(&allow_host_of(&base)),
                "users/me/messages",
                Method::GET,
                HeaderMap::new(),
                Bytes::new(),
                "test-token",
                MAX_RESPONSE_BODY,
            )
            .await;

        match result {
            Err(ProxyError::UpstreamServerError { service, status, .. }) => {
                assert_eq!(service, "gmail");
                assert_eq!(status, 500);
            }
            other => panic!("expected UpstreamServerError, got {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn dns_failure_returns_unreachable() {
        let base = Url::parse("https://nonexistent.invalid.local/gmail/v1/").unwrap();
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let upstream = UpstreamClient { client };

        let result = upstream
            .dispatch(
                "gmail",
                &base,
                &builtin_guard(&allow_host_of(&base)),
                "users/me/messages",
                Method::GET,
                HeaderMap::new(),
                Bytes::new(),
                "test-token",
                MAX_RESPONSE_BODY,
            )
            .await;

        match result {
            Err(ProxyError::UpstreamUnreachable { service, retry_after_seconds, .. }) => {
                assert_eq!(service, "gmail");
                assert_eq!(retry_after_seconds, 30);
            }
            other => panic!("expected UpstreamUnreachable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn invalid_path_join_returns_internal_error() {
        // Story 11.5: with the base_urls map gone, the former
        // "unknown service" error class is replaced by a base_url-join
        // failure. A base_url that cannot be a base (no host) makes the
        // join fail with a typed Internal error rather than a panic.
        let base = Url::parse("mailto:nobody@example.com").unwrap();
        let client = test_client();
        // `mailto:` has no host; the join fails before the SSRF guard runs,
        // so the guard's allowlist is irrelevant — use a literal to avoid
        // calling `allow_host_of` on a hostless URL.
        let result = client
            .dispatch(
                "gmail",
                &base,
                &builtin_guard(&["example.com".to_owned()]),
                "path",
                Method::GET,
                HeaderMap::new(),
                Bytes::new(),
                "token",
                MAX_RESPONSE_BODY,
            )
            .await;
        assert!(matches!(result, Err(ProxyError::Internal { .. })));
    }

    #[tokio::test]
    async fn structured_error_json_for_upstream_unreachable() {
        let err = ProxyError::UpstreamUnreachable {
            service: "gmail".to_owned(),
            message: "connection timed out".to_owned(),
            retry_after_seconds: 30,
        };
        assert_eq!(err.status_code(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.error_code(), "upstream.unreachable");

        let response = err.into_response_with_request_id(Some("01TEST".to_owned()));
        assert_eq!(response.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);

        let body = axum::body::Body::new(response.into_body());
        let bytes = http_body_util::BodyExt::collect(body).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["code"], "upstream.unreachable");
        assert_eq!(json["error"]["upstream_service"], "gmail");
        assert_eq!(json["error"]["retry_after_seconds"], 30);
        assert!(json["error"]["remediation"].is_string());
    }

    #[test]
    fn builtin_defs_carry_todays_base_urls() {
        // Story 11.5: the hardcoded base_urls map is gone; the built-in
        // connector defs are the source of truth. Pin that they still
        // carry today's upstream URLs (the values the deleted map held).
        let defs = permitlayer_connectors::builtin_connector_defs().unwrap();
        let url_of = |id: &str| {
            defs.iter()
                .find(|d| d.connector.id == id)
                .map(|d| d.upstream.base_url.as_str().to_owned())
                .unwrap()
        };
        assert_eq!(url_of("google-gmail"), "https://gmail.googleapis.com/gmail/v1/");
        assert_eq!(url_of("google-calendar"), "https://www.googleapis.com/calendar/v3/");
        assert_eq!(url_of("google-drive"), "https://www.googleapis.com/drive/v3/");
    }

    #[tokio::test]
    async fn calendar_dispatch_hits_correct_upstream() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/calendar/v3/users/me/calendarList")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"items":[]}"#)
            .create_async()
            .await;

        let upstream = test_client();
        let base = Url::parse(&format!("{}/calendar/v3/", server.url())).unwrap();
        let result = upstream
            .dispatch(
                "calendar",
                &base,
                &builtin_guard(&allow_host_of(&base)),
                "users/me/calendarList",
                Method::GET,
                HeaderMap::new(),
                Bytes::new(),
                "test-token",
                MAX_RESPONSE_BODY,
            )
            .await;

        let resp = result.unwrap();
        assert_eq!(resp.status, 200);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn drive_dispatch_hits_correct_upstream() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/drive/v3/files")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"files":[]}"#)
            .create_async()
            .await;

        let upstream = test_client();
        let base = Url::parse(&format!("{}/drive/v3/", server.url())).unwrap();
        let result = upstream
            .dispatch(
                "drive",
                &base,
                &builtin_guard(&allow_host_of(&base)),
                "files",
                Method::GET,
                HeaderMap::new(),
                Bytes::new(),
                "test-token",
                MAX_RESPONSE_BODY,
            )
            .await;

        let resp = result.unwrap();
        assert_eq!(resp.status, 200);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn post_tool_path_joins_onto_base_url() {
        // AC #3: a POST tool path template joins correctly.
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/gmail/v1/users/me/messages/send")
            .with_status(200)
            .with_body(r#"{"id":"x"}"#)
            .create_async()
            .await;
        let client = test_client();
        let base = Url::parse(&format!("{}/gmail/v1/", server.url())).unwrap();
        let result = client
            .dispatch(
                "gmail",
                &base,
                &builtin_guard(&allow_host_of(&base)),
                "users/me/messages/send",
                Method::POST,
                HeaderMap::new(),
                Bytes::from_static(b"{}"),
                "test-token",
                MAX_RESPONSE_BODY,
            )
            .await;
        assert_eq!(result.unwrap().status, 200);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn structured_error_json_for_rate_limited() {
        let err = ProxyError::UpstreamRateLimited {
            service: "gmail".to_owned(),
            retry_after: Some("60".to_owned()),
        };
        assert_eq!(err.status_code(), axum::http::StatusCode::TOO_MANY_REQUESTS);

        let response = err.into_response_with_request_id(None);
        assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get("retry-after").unwrap().to_str().unwrap(), "60");
    }
}
