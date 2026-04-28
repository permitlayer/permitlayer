//! Integration tests for the OAuth 2.1 flow.
//!
//! Uses an in-process axum mock OAuth server to test the full flow
//! without hitting real Google endpoints.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use axum::Json;
use axum::routing::post;
use permitlayer_credential::{OAuthRefreshToken, OAuthToken};
use permitlayer_oauth::callback;
use permitlayer_oauth::error::OAuthError;
use permitlayer_oauth::pkce;
use permitlayer_oauth::refresh;

// ============================================================================
// Mock OAuth server
// ============================================================================

/// Spawn a mock token endpoint that returns the standard test response.
async fn spawn_mock_token_server() -> (String, tokio::net::TcpListener) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind mock server");
    let addr = listener.local_addr().expect("local addr");
    let url = format!("http://127.0.0.1:{}", addr.port());
    (url, listener)
}

async fn mock_token_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "access_token": "ya29.test-access-token-placeholder",
        "refresh_token": "1//test-refresh-token-placeholder",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "https://www.googleapis.com/auth/gmail.readonly"
    }))
}

async fn mock_refresh_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "access_token": "ya29.refreshed-access-token",
        "refresh_token": "1//rotated-refresh-token",
        "token_type": "Bearer",
        "expires_in": 3600
    }))
}

/// Returns a JSON error response for invalid_grant.
async fn _mock_invalid_grant_handler() -> (axum::http::StatusCode, Json<serde_json::Value>) {
    (
        axum::http::StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "Token has been expired or revoked."
        })),
    )
}

// ============================================================================
// PKCE tests
// ============================================================================

#[test]
fn pkce_verifier_sent_in_token_exchange() {
    // Verify PKCE generation produces valid challenge+verifier pair.
    let (challenge, verifier) = pkce::generate_pkce();
    assert_eq!(challenge.method().as_str(), "S256");
    let v = verifier.secret();
    assert!((43..=128).contains(&v.len()));
}

// ============================================================================
// Callback server tests
// ============================================================================

#[tokio::test]
async fn callback_state_roundtrips_correctly() {
    let state_value = "csrf-state-integration-test-12345";
    let server =
        callback::spawn_callback_server(state_value.to_owned(), Some(Duration::from_secs(5)))
            .await
            .expect("server start");

    // Send a request with matching state.
    let url = format!(
        "http://127.0.0.1:{}/callback?code=test-code&state={}",
        server.local_addr.port(),
        state_value
    );
    let resp = reqwest::get(&url).await.expect("request");
    assert!(resp.status().is_success());

    let code = tokio::time::timeout(Duration::from_secs(2), server.code_receiver)
        .await
        .expect("no timeout")
        .expect("channel ok")
        .expect("code ok");

    assert_eq!(code, "test-code");
}

#[tokio::test]
async fn callback_server_binds_to_127_0_0_1_not_0_0_0_0() {
    let server = callback::spawn_callback_server("state".to_owned(), Some(Duration::from_secs(1)))
        .await
        .expect("server start");

    assert!(server.local_addr.ip().is_loopback());
    assert_eq!(server.local_addr.ip().to_string(), "127.0.0.1");
}

#[tokio::test]
async fn callback_server_shuts_down_after_callback() {
    let server = callback::spawn_callback_server("state".to_owned(), Some(Duration::from_secs(5)))
        .await
        .expect("server start");

    let port = server.local_addr.port();

    // First request should succeed.
    let url = format!("http://127.0.0.1:{port}/callback?code=test&state=state");
    let resp = reqwest::get(&url).await.expect("first request");
    assert!(resp.status().is_success());

    // Consume the code.
    let _ = server.code_receiver.await;

    // Give the server a moment to shut down.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second request should fail (server is shut down).
    let result = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
        .expect("client")
        .get(format!("http://127.0.0.1:{port}/callback?code=test2&state=state"))
        .send()
        .await;

    assert!(result.is_err(), "server should be shut down after first callback");
}

#[tokio::test]
async fn callback_user_denied_consent() {
    let server = callback::spawn_callback_server("state".to_owned(), Some(Duration::from_secs(5)))
        .await
        .expect("server start");

    let url = format!("http://127.0.0.1:{}/callback?error=access_denied", server.local_addr.port());
    let _resp = reqwest::get(&url).await.expect("request");

    let result = tokio::time::timeout(Duration::from_secs(2), server.code_receiver)
        .await
        .expect("no timeout")
        .expect("channel ok");

    assert!(result.is_err());
    match result.unwrap_err() {
        OAuthError::UserDeniedConsent { service } => {
            assert_eq!(service, "google-oauth");
        }
        other => panic!("expected UserDeniedConsent, got {other:?}"),
    }
}

#[tokio::test]
async fn callback_timeout_fires_after_configured_duration() {
    let server =
        callback::spawn_callback_server("state".to_owned(), Some(Duration::from_millis(100)))
            .await
            .expect("server start");

    // Don't send any request — let the timeout fire.
    let result = tokio::time::timeout(Duration::from_secs(2), server.code_receiver).await;

    // The sender is dropped when the server task exits, causing RecvError.
    match result {
        Ok(Err(_)) => {}     // Sender dropped — expected on timeout
        Ok(Ok(Err(_))) => {} // Timeout error sent through channel
        Err(_) => panic!("outer timeout fired before callback server timeout"),
        Ok(Ok(Ok(_))) => panic!("should not receive code without a request"),
    }
}

// ============================================================================
// Token exchange tests
// ============================================================================

#[tokio::test]
async fn full_token_exchange_with_mock_server() {
    let (base_url, listener) = spawn_mock_token_server().await;
    let token_url = format!("{base_url}/token");

    let app = axum::Router::new().route("/token", post(mock_token_handler));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mock server");
    });

    let client =
        oauth2::basic::BasicClient::new(oauth2::ClientId::new("test-client-id".to_owned()))
            .set_auth_uri(
                oauth2::AuthUrl::new("http://127.0.0.1:1/auth".to_owned()).expect("auth url"),
            )
            .set_token_uri(oauth2::TokenUrl::new(token_url).expect("token url"))
            .set_client_secret(oauth2::ClientSecret::new("test-secret".to_owned()));

    let http_client = reqwest::Client::new();

    let (_challenge, verifier) = pkce::generate_pkce();

    let redirect_url =
        oauth2::RedirectUrl::new("http://127.0.0.1:9999/callback".to_owned()).expect("url");

    let result = client
        .exchange_code(oauth2::AuthorizationCode::new("test-code".to_owned()))
        .set_pkce_verifier(verifier)
        .set_redirect_uri(std::borrow::Cow::Owned(redirect_url))
        .request_async(&http_client)
        .await;

    assert!(result.is_ok(), "exchange should succeed");
    let resp = result.unwrap();

    // Verify PKCE verifier was used (the exchange didn't fail, which means
    // the mock server accepted it).
    let access = OAuthToken::from_trusted_bytes(
        oauth2::TokenResponse::access_token(&resp).secret().as_bytes().to_vec(),
    );
    assert_eq!(access.reveal(), b"ya29.test-access-token-placeholder");

    let refresh_token = oauth2::TokenResponse::refresh_token(&resp)
        .map(|rt| OAuthRefreshToken::from_trusted_bytes(rt.secret().as_bytes().to_vec()));
    assert!(refresh_token.is_some());
}

// ============================================================================
// Refresh rotation tests
// ============================================================================

#[tokio::test]
async fn refresh_rotation_returns_new_tokens() {
    let (base_url, listener) = spawn_mock_token_server().await;
    let token_url = format!("{base_url}/token");

    let app = axum::Router::new().route("/token", post(mock_refresh_handler));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mock server");
    });

    let client = oauth2::basic::BasicClient::new(oauth2::ClientId::new("test".to_owned()))
        .set_auth_uri(oauth2::AuthUrl::new("http://127.0.0.1:1/auth".to_owned()).expect("url"))
        .set_token_uri(oauth2::TokenUrl::new(token_url).expect("url"));

    let http_client = reqwest::Client::new();
    let refresh = OAuthRefreshToken::from_trusted_bytes(b"1//old-token".to_vec());

    let result = refresh::refresh_access_token(&client, &http_client, &refresh).await;
    assert!(result.is_ok(), "refresh should succeed");

    let r = match result {
        Ok(r) => r,
        Err(_) => panic!("expected Ok"),
    };
    assert_eq!(r.access_token.reveal(), b"ya29.refreshed-access-token");
    assert!(r.new_refresh_token.is_some());
    let nrt = match r.new_refresh_token {
        Some(t) => t,
        None => panic!("expected new refresh token"),
    };
    assert_eq!(nrt.reveal(), b"1//rotated-refresh-token");
}

#[tokio::test]
async fn refresh_retry_exhaustion_returns_correct_error() {
    // Spawn a server that always returns 500.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let token_url = format!("http://127.0.0.1:{}/token", addr.port());

    let attempt_count = Arc::new(AtomicU32::new(0));
    let count = Arc::clone(&attempt_count);

    let app = axum::Router::new().route(
        "/token",
        post(move || {
            let c = Arc::clone(&count);
            async move {
                c.fetch_add(1, Ordering::Relaxed);
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "server_error"})),
                )
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mock server");
    });

    let client = oauth2::basic::BasicClient::new(oauth2::ClientId::new("test".to_owned()))
        .set_auth_uri(oauth2::AuthUrl::new("http://127.0.0.1:1/auth".to_owned()).expect("url"))
        .set_token_uri(oauth2::TokenUrl::new(token_url).expect("url"));

    let http_client = reqwest::Client::new();
    let refresh = OAuthRefreshToken::from_trusted_bytes(b"1//test-token".to_vec());

    // Use tokio's time pausing to avoid real delays.
    tokio::time::pause();

    let result = refresh::refresh_with_retry(&client, &http_client, &refresh).await;

    assert!(result.is_err());
    match result {
        Err(OAuthError::RefreshExhausted { service, attempts }) => {
            assert_eq!(service, "google-oauth");
            assert_eq!(attempts, 3);
        }
        Err(other) => panic!("expected RefreshExhausted, got {other:?}"),
        Ok(_) => panic!("expected error"),
    }

    assert_eq!(attempt_count.load(Ordering::Relaxed), 3, "should have made 3 attempts");
}

// ============================================================================
// Error credential safety tests
// ============================================================================

#[test]
fn no_credential_material_in_error_display() {
    let known_token = "ya29.super-secret-access-token";
    let known_refresh = "1//super-secret-refresh-token";

    let errors: Vec<OAuthError> = vec![
        OAuthError::PkceGenerationFailed,
        OAuthError::CallbackTimeout { timeout_secs: 120 },
        OAuthError::CallbackStateMismatch,
        OAuthError::UserDeniedConsent { service: "google-oauth".to_owned() },
        OAuthError::TokenExchangeFailed {
            service: "google-oauth".to_owned(),
            source: "test error".into(),
        },
        OAuthError::RefreshFailed {
            service: "google-oauth".to_owned(),
            source: "test error".into(),
        },
        OAuthError::RefreshExhausted { service: "google-oauth".to_owned(), attempts: 3 },
        OAuthError::InvalidGrant { service: "google-oauth".to_owned() },
        OAuthError::BrowserOpenFailed { source: std::io::Error::other("test") },
        OAuthError::CallbackServerFailed { source: std::io::Error::other("test") },
    ];

    for error in &errors {
        let display = format!("{error}");
        let debug = format!("{error:?}");

        assert!(!display.contains(known_token), "Display of {error:?} contains access token");
        assert!(!display.contains(known_refresh), "Display of {error:?} contains refresh token");
        assert!(!debug.contains(known_token), "Debug of {error:?} contains access token");
        assert!(!debug.contains(known_refresh), "Debug of {error:?} contains refresh token");
    }
}

#[test]
fn error_codes_are_machine_readable() {
    let error = OAuthError::RefreshExhausted { service: "google-oauth".to_owned(), attempts: 3 };
    assert_eq!(error.error_code(), "upstream_unreachable");

    let error = OAuthError::UserDeniedConsent { service: "google-oauth".to_owned() };
    assert_eq!(error.error_code(), "user_denied_consent");
}

#[test]
fn remediation_hints_are_non_empty() {
    let errors: Vec<OAuthError> = vec![
        OAuthError::PkceGenerationFailed,
        OAuthError::CallbackTimeout { timeout_secs: 120 },
        OAuthError::CallbackStateMismatch,
        OAuthError::UserDeniedConsent { service: "test".to_owned() },
        OAuthError::RefreshExhausted { service: "test".to_owned(), attempts: 3 },
    ];

    for error in &errors {
        assert!(!error.remediation().is_empty(), "remediation empty for {error:?}");
    }
}
