//! Proxy response type: wraps the upstream API response for return to
//! the agent.

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

/// The response from an upstream API call, ready to be returned to the agent.
#[derive(Debug)]
pub struct ProxyResponse {
    /// HTTP status code from upstream.
    pub status: StatusCode,
    /// Response headers from upstream.
    pub headers: HeaderMap,
    /// Response body bytes from upstream.
    pub body: Bytes,
}

impl IntoResponse for ProxyResponse {
    fn into_response(self) -> Response {
        let mut builder = Response::builder().status(self.status);
        if let Some(headers) = builder.headers_mut() {
            headers.extend(self.headers);
        }
        builder.body(axum::body::Body::from(self.body)).unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(axum::body::Body::empty())
                .unwrap_or_default()
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn proxy_response_roundtrip_to_axum_response() {
        let mut headers = HeaderMap::new();
        headers.insert("x-custom", "value".parse().unwrap());

        let proxy_resp = ProxyResponse {
            status: StatusCode::OK,
            headers,
            body: Bytes::from(r#"{"data":"test"}"#),
        };

        let response = proxy_resp.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("x-custom").unwrap(), "value");

        let body_bytes =
            axum::body::Body::new(response.into_body()).collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes, r#"{"data":"test"}"#.as_bytes());
    }

    #[test]
    fn empty_body_response() {
        let proxy_resp = ProxyResponse {
            status: StatusCode::NO_CONTENT,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        };
        let response = proxy_resp.into_response();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
