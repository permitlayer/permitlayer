//! Ephemeral loopback HTTP server for the OAuth callback.
//!
//! Spawns a single-request axum server bound to `127.0.0.1:0` (ephemeral
//! port). The server receives the authorization code from Google's redirect,
//! validates the CSRF `state` parameter, sends the code through a oneshot
//! channel, and shuts down immediately.
//!
//! # Key constraints
//!
//! - Binds to `127.0.0.1` literal, NEVER `localhost` (Google requirement, AR66).
//! - Uses `tokio::net::TcpListener` (axum 0.8 requires the tokio variant).
//! - Single-request lifecycle: shuts down after receiving one request.
//! - Timeout: if no callback arrives within the configured duration, shuts
//!   down with a `CallbackTimeout` error.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use tokio::sync::{Notify, oneshot};
use url::Url;

use subtle::ConstantTimeEq;

use crate::error::OAuthError;

/// Default timeout for the callback server (seconds).
const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// Query parameters expected on the callback URL.
#[derive(serde::Deserialize)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Shared state for the callback handler.
struct CallbackState {
    expected_state: String,
    code_tx: std::sync::Mutex<Option<oneshot::Sender<Result<String, OAuthError>>>>,
    shutdown: Arc<Notify>,
}

/// Result of spawning the callback server.
pub struct CallbackServer {
    /// The redirect URI to pass to the OAuth authorization request.
    /// Format: `http://127.0.0.1:{port}/callback`
    pub redirect_uri: Url,
    /// Receiver for the authorization code (or error).
    pub code_receiver: oneshot::Receiver<Result<String, OAuthError>>,
    /// The local address the server is bound to.
    pub local_addr: SocketAddr,
}

/// Spawn an ephemeral callback server for the OAuth redirect.
///
/// Returns the redirect URI and a receiver for the authorization code.
/// The server shuts down after receiving one request or after `timeout`.
pub async fn spawn_callback_server(
    expected_state: String,
    timeout: Option<Duration>,
) -> Result<CallbackServer, OAuthError> {
    let timeout = timeout.unwrap_or(Duration::from_secs(DEFAULT_TIMEOUT_SECS));

    // Bind to 127.0.0.1:0 — MUST use tokio's TcpListener for axum 0.8.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| OAuthError::CallbackServerFailed { source: e })?;
    let local_addr =
        listener.local_addr().map_err(|e| OAuthError::CallbackServerFailed { source: e })?;

    // Construct redirect URI: http://127.0.0.1:{port}/callback
    // NEVER use `localhost` literal (AR66, Google requirement).
    let redirect_uri = Url::parse(&format!("http://127.0.0.1:{}/callback", local_addr.port()))
        .map_err(|_| OAuthError::CallbackServerFailed {
            source: std::io::Error::other("failed to construct redirect URI"),
        })?;

    let (code_tx, code_rx) = oneshot::channel();
    let shutdown = Arc::new(Notify::new());

    let state = Arc::new(CallbackState {
        expected_state,
        code_tx: std::sync::Mutex::new(Some(code_tx)),
        shutdown: Arc::clone(&shutdown),
    });

    let app =
        axum::Router::new().route("/callback", get(handle_callback)).with_state(Arc::clone(&state));

    let shutdown_clone = Arc::clone(&shutdown);
    let timeout_secs = timeout.as_secs();

    tokio::spawn(async move {
        let server = axum::serve(listener, app).with_graceful_shutdown(async move {
            shutdown_clone.notified().await;
        });

        // Race the server against the timeout.
        tokio::select! {
            result = server.into_future() => {
                if let Err(e) = result {
                    tracing::error!(error = %e, "callback server error");
                }
            }
            () = tokio::time::sleep(timeout) => {
                tracing::warn!(timeout_secs, "callback server timed out waiting for OAuth redirect");
                // Send timeout error through the channel before the task exits,
                // so the receiver gets an explicit error instead of a RecvError.
                #[allow(clippy::expect_used)]
                if let Some(tx) = state
                    .code_tx
                    .lock()
                    .expect("static invariant: lock not poisoned")
                    .take()
                {
                    let _ = tx.send(Err(OAuthError::CallbackTimeout { timeout_secs }));
                }
            }
        }
    });

    Ok(CallbackServer { redirect_uri, code_receiver: code_rx, local_addr })
}

/// Handle the OAuth callback GET request.
async fn handle_callback(
    State(state): State<Arc<CallbackState>>,
    Query(params): Query<CallbackParams>,
) -> Html<String> {
    let result = process_callback(&state, &params);
    let is_ok = result.is_ok();

    // Send the result through the oneshot channel.
    #[allow(clippy::expect_used)]
    if let Some(tx) = state.code_tx.lock().expect("static invariant: lock not poisoned").take() {
        // Ignore send error — receiver may have been dropped (timeout race).
        let _ = tx.send(result);
    }

    // Signal shutdown after handling the request.
    state.shutdown.notify_one();

    if is_ok {
        Html("<html><body><h1>Authentication successful!</h1><p>You can close this tab.</p></body></html>".to_owned())
    } else {
        Html("<html><body><h1>Authentication failed</h1><p>Please check the terminal for details.</p></body></html>".to_owned())
    }
}

/// Validate callback parameters and extract the authorization code.
fn process_callback(state: &CallbackState, params: &CallbackParams) -> Result<String, OAuthError> {
    // Check for error parameter (e.g., user denied consent).
    if let Some(error) = &params.error {
        if error == "access_denied" {
            return Err(OAuthError::UserDeniedConsent { service: "google-oauth".to_owned() });
        }
        return Err(OAuthError::TokenExchangeFailed {
            service: "google-oauth".to_owned(),
            source: Box::new(std::io::Error::other(format!(
                "OAuth provider returned error: {error}"
            ))),
        });
    }

    // Validate state parameter (CSRF protection).
    // Constant-time comparison to prevent timing side-channels on the CSRF token.
    let callback_state = params.state.as_deref().ok_or(OAuthError::CallbackStateMismatch)?;
    if callback_state.as_bytes().ct_eq(state.expected_state.as_bytes()).unwrap_u8() != 1 {
        return Err(OAuthError::CallbackStateMismatch);
    }

    // Extract authorization code.
    params.code.clone().ok_or_else(|| OAuthError::TokenExchangeFailed {
        service: "google-oauth".to_owned(),
        source: Box::new(std::io::Error::other("callback missing 'code' parameter")),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn callback_server_binds_to_loopback() {
        let server = spawn_callback_server("test-state".to_owned(), Some(Duration::from_secs(5)))
            .await
            .expect("server should start");

        // Must bind to 127.0.0.1, NOT 0.0.0.0 or localhost.
        assert!(
            server.local_addr.ip().is_loopback(),
            "must bind to loopback: got {}",
            server.local_addr.ip()
        );
        assert!(
            server.redirect_uri.as_str().contains("127.0.0.1"),
            "redirect URI must use 127.0.0.1 literal: {}",
            server.redirect_uri
        );
        assert!(
            !server.redirect_uri.as_str().contains("localhost"),
            "redirect URI must NOT contain localhost: {}",
            server.redirect_uri
        );
    }

    #[tokio::test]
    async fn callback_extracts_code_on_valid_state() {
        let server =
            spawn_callback_server("csrf-token-123".to_owned(), Some(Duration::from_secs(5)))
                .await
                .expect("server should start");

        let url = format!(
            "http://127.0.0.1:{}/callback?code=auth-code-xyz&state=csrf-token-123",
            server.local_addr.port()
        );
        let resp = reqwest::get(&url).await.expect("request should succeed");
        assert!(resp.status().is_success());

        let code = tokio::time::timeout(Duration::from_secs(2), server.code_receiver)
            .await
            .expect("should not timeout")
            .expect("channel should not be dropped")
            .expect("should be Ok");

        assert_eq!(code, "auth-code-xyz");
    }

    #[tokio::test]
    async fn callback_rejects_state_mismatch() {
        let server =
            spawn_callback_server("expected-state".to_owned(), Some(Duration::from_secs(5)))
                .await
                .expect("server should start");

        let url = format!(
            "http://127.0.0.1:{}/callback?code=auth-code&state=wrong-state",
            server.local_addr.port()
        );
        let _resp = reqwest::get(&url).await.expect("request should succeed");

        let result = tokio::time::timeout(Duration::from_secs(2), server.code_receiver)
            .await
            .expect("should not timeout")
            .expect("channel should not be dropped");

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OAuthError::CallbackStateMismatch));
    }

    #[tokio::test]
    async fn callback_handles_user_denied_consent() {
        let server = spawn_callback_server("state-123".to_owned(), Some(Duration::from_secs(5)))
            .await
            .expect("server should start");

        let url =
            format!("http://127.0.0.1:{}/callback?error=access_denied", server.local_addr.port());
        let _resp = reqwest::get(&url).await.expect("request should succeed");

        let result = tokio::time::timeout(Duration::from_secs(2), server.code_receiver)
            .await
            .expect("should not timeout")
            .expect("channel should not be dropped");

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OAuthError::UserDeniedConsent { .. }));
    }

    #[tokio::test]
    async fn callback_timeout_fires() {
        let server = spawn_callback_server("state".to_owned(), Some(Duration::from_millis(100)))
            .await
            .expect("server should start");

        // Don't send a request — let it timeout.
        let result = tokio::time::timeout(Duration::from_secs(2), server.code_receiver).await;
        // The receiver will be dropped when the server task exits after timeout.
        // The channel will error (RecvError) because the sender is dropped.
        match result {
            Ok(Ok(Err(_))) => {} // Timeout error sent through channel
            Ok(Err(_)) => {}     // Sender dropped (expected on timeout)
            Err(_) => panic!("outer timeout fired before callback server timeout"),
            Ok(Ok(Ok(_))) => panic!("should not receive a code without a request"),
        }
    }

    #[test]
    fn process_callback_missing_code_returns_error() {
        let state = CallbackState {
            expected_state: "state".to_owned(),
            code_tx: std::sync::Mutex::new(None),
            shutdown: Arc::new(Notify::new()),
        };
        let params = CallbackParams { code: None, state: Some("state".to_owned()), error: None };
        let result = process_callback(&state, &params);
        assert!(result.is_err());
    }

    #[test]
    fn process_callback_missing_state_returns_mismatch() {
        let state = CallbackState {
            expected_state: "state".to_owned(),
            code_tx: std::sync::Mutex::new(None),
            shutdown: Arc::new(Notify::new()),
        };
        let params = CallbackParams { code: Some("code".to_owned()), state: None, error: None };
        let result = process_callback(&state, &params);
        assert!(matches!(result, Err(OAuthError::CallbackStateMismatch)));
    }
}
