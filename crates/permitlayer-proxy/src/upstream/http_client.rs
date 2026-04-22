//! HTTP client for dispatching requests to upstream Google APIs.

use std::collections::HashMap;
use std::time::Duration;

use axum::body::Bytes;
use axum::http::{HeaderMap, Method};
use url::Url;

use crate::error::ProxyError;

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
    base_urls: HashMap<String, Url>,
}

impl UpstreamClient {
    /// Create a new upstream client.
    ///
    /// Configures: connect timeout (10s), request timeout (30s), rustls-tls.
    /// Registers base URLs for Gmail, Calendar, and Drive.
    pub fn new() -> Result<Self, ProxyError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .use_rustls_tls()
            .build()
            .map_err(|e| ProxyError::Internal {
                message: format!("failed to build HTTP client: {e}"),
            })?;

        let mut base_urls = HashMap::new();
        #[allow(clippy::expect_used)]
        {
            let gmail_url = Url::parse("https://gmail.googleapis.com/gmail/v1/")
                .expect("hardcoded URL is valid");
            base_urls.insert("gmail".to_owned(), gmail_url);

            let calendar_url = Url::parse("https://www.googleapis.com/calendar/v3/")
                .expect("hardcoded URL is valid");
            base_urls.insert("calendar".to_owned(), calendar_url);

            let drive_url =
                Url::parse("https://www.googleapis.com/drive/v3/").expect("hardcoded URL is valid");
            base_urls.insert("drive".to_owned(), drive_url);
        }

        Ok(Self { client, base_urls })
    }

    /// Create an upstream client with a custom reqwest client and base URLs.
    ///
    /// Used in tests and integration wiring to inject custom base URLs.
    pub fn with_client_and_urls(client: reqwest::Client, base_urls: HashMap<String, Url>) -> Self {
        Self { client, base_urls }
    }

    /// Dispatch a request to the upstream API.
    ///
    /// Builds the full upstream URL from the service's base URL and the path,
    /// sets the `Authorization: Bearer` header, and forwards the request.
    pub async fn dispatch(
        &self,
        service: &str,
        path: &str,
        method: Method,
        headers: HeaderMap,
        body: Bytes,
        access_token: &str,
    ) -> Result<UpstreamResponse, ProxyError> {
        let base_url = self.base_urls.get(service).ok_or_else(|| ProxyError::Internal {
            message: format!("no upstream URL configured for service '{service}'"),
        })?;

        let url = base_url.join(path).map_err(|e| ProxyError::Internal {
            message: format!("invalid upstream URL path '{path}': {e}"),
        })?;

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

        /// Maximum upstream response body size (10 MB, matching request limit).
        const MAX_RESPONSE_BODY: usize = 10 * 1024 * 1024;

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
        let content_length = response.content_length().unwrap_or(0);
        if content_length > MAX_RESPONSE_BODY as u64 {
            return Err(ProxyError::Internal {
                message: format!(
                    "upstream response body too large: {content_length} bytes (max {MAX_RESPONSE_BODY})"
                ),
            });
        }
        let resp_body = response.bytes().await.map_err(|e| ProxyError::Internal {
            message: format!("failed to read upstream response body: {e}"),
        })?;
        if resp_body.len() > MAX_RESPONSE_BODY {
            return Err(ProxyError::Internal {
                message: format!(
                    "upstream response body too large: {} bytes (max {MAX_RESPONSE_BODY})",
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

    fn test_client(base_url: &str) -> UpstreamClient {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let mut base_urls = HashMap::new();
        base_urls.insert("gmail".to_owned(), Url::parse(base_url).unwrap());

        UpstreamClient::with_client_and_urls(client, base_urls)
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

        let client = test_client(&format!("{}/gmail/v1/", server.url()));
        let result = client
            .dispatch(
                "gmail",
                "users/me/messages",
                Method::GET,
                HeaderMap::new(),
                Bytes::new(),
                "test-token",
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

        let client = test_client(&format!("{}/gmail/v1/", server.url()));
        let result = client
            .dispatch(
                "gmail",
                "users/me/messages",
                Method::GET,
                HeaderMap::new(),
                Bytes::new(),
                "test-token",
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

        let client = test_client(&format!("{}/gmail/v1/", server.url()));
        let result = client
            .dispatch(
                "gmail",
                "users/me/messages",
                Method::GET,
                HeaderMap::new(),
                Bytes::new(),
                "test-token",
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
        let mut base_urls = HashMap::new();
        base_urls.insert(
            "gmail".to_owned(),
            Url::parse("https://nonexistent.invalid.local/gmail/v1/").unwrap(),
        );
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let upstream = UpstreamClient::with_client_and_urls(client, base_urls);

        let result = upstream
            .dispatch(
                "gmail",
                "users/me/messages",
                Method::GET,
                HeaderMap::new(),
                Bytes::new(),
                "test-token",
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
    async fn unknown_service_returns_error() {
        let client = test_client("http://localhost:1234/");
        let result = client
            .dispatch("unknown", "path", Method::GET, HeaderMap::new(), Bytes::new(), "token")
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
    fn new_client_has_calendar_base_url() {
        let client = UpstreamClient::new().unwrap();
        let url = client.base_urls.get("calendar").expect("calendar URL should exist");
        assert_eq!(url.as_str(), "https://www.googleapis.com/calendar/v3/");
    }

    #[test]
    fn new_client_has_drive_base_url() {
        let client = UpstreamClient::new().unwrap();
        let url = client.base_urls.get("drive").expect("drive URL should exist");
        assert_eq!(url.as_str(), "https://www.googleapis.com/drive/v3/");
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

        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let mut base_urls = HashMap::new();
        base_urls.insert(
            "calendar".to_owned(),
            Url::parse(&format!("{}/calendar/v3/", server.url())).unwrap(),
        );
        let upstream = UpstreamClient::with_client_and_urls(client, base_urls);

        let result = upstream
            .dispatch(
                "calendar",
                "users/me/calendarList",
                Method::GET,
                HeaderMap::new(),
                Bytes::new(),
                "test-token",
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

        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let mut base_urls = HashMap::new();
        base_urls.insert(
            "drive".to_owned(),
            Url::parse(&format!("{}/drive/v3/", server.url())).unwrap(),
        );
        let upstream = UpstreamClient::with_client_and_urls(client, base_urls);

        let result = upstream
            .dispatch("drive", "files", Method::GET, HeaderMap::new(), Bytes::new(), "test-token")
            .await;

        let resp = result.unwrap();
        assert_eq!(resp.status, 200);
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
