//! Refresh token rotation with retry and exponential backoff.
//!
//! # Retry policy
//!
//! - Max 3 attempts with exponential backoff: 1s, 2s, 4s (±20% jitter).
//! - After 3rd failure: returns `OAuthError::RefreshExhausted`.
//! - Caller (proxy layer) maps this to HTTP 503.
//!
//! # Atomic rotation
//!
//! When the provider returns a new refresh token (rotation), the sequence is:
//! 1. Seal new refresh token via vault
//! 2. Store sealed credential (atomic tempfile+rename)
//! 3. Only then drop the old refresh token
//!
//! This ensures the new token is persisted before the old one is invalidated.

use std::time::Duration;

use oauth2::basic::BasicErrorResponseType;
use oauth2::{RefreshToken, RequestTokenError, TokenResponse};
use permitlayer_credential::{OAuthRefreshToken, OAuthToken};
use rand::Rng;

use crate::client::ConfiguredClient;
use crate::error::OAuthError;

/// Maximum number of refresh retry attempts.
const MAX_RETRY_ATTEMPTS: u32 = 3;

/// Base delay for exponential backoff (seconds).
const BASE_DELAY_SECS: f64 = 1.0;

/// Jitter range: ±20% of the computed delay.
const JITTER_FACTOR: f64 = 0.2;

/// Default threshold for proactive refresh: refresh when access token has
/// less than this many seconds remaining.
const PROACTIVE_REFRESH_THRESHOLD_SECS: u64 = 300; // 5 minutes

/// Result of a successful token refresh.
pub struct RefreshResult {
    /// The new access token.
    pub access_token: OAuthToken,
    /// A new refresh token, if the provider rotated it.
    pub new_refresh_token: Option<OAuthRefreshToken>,
    /// Expiry duration for the new access token.
    pub expires_in: Option<Duration>,
}

/// Check whether a proactive refresh should be triggered.
///
/// Returns `true` if the remaining lifetime is below the threshold.
#[must_use]
pub fn should_proactively_refresh(remaining: Duration, threshold: Option<Duration>) -> bool {
    let threshold = threshold.unwrap_or(Duration::from_secs(PROACTIVE_REFRESH_THRESHOLD_SECS));
    remaining < threshold
}

/// Refresh the access token using the given refresh token.
///
/// This function performs a single refresh attempt (no retries).
/// Use [`refresh_with_retry`] for the full retry policy.
pub async fn refresh_access_token(
    client: &ConfiguredClient,
    http_client: &reqwest::Client,
    refresh_token: &OAuthRefreshToken,
) -> Result<RefreshResult, OAuthError> {
    // Reveal refresh token bytes at the LAST possible moment.
    let rt_str =
        std::str::from_utf8(refresh_token.reveal()).map_err(|_| OAuthError::RefreshFailed {
            service: "google-oauth".to_owned(),
            source: "refresh token is not valid UTF-8".into(),
        })?;

    let oauth2_refresh = RefreshToken::new(rt_str.to_owned());

    let token_response = client
        .exchange_refresh_token(&oauth2_refresh)
        .request_async(http_client)
        .await
        .map_err(|e| {
            // Match on the structured error type rather than string-scanning.
            if let RequestTokenError::ServerResponse(ref resp) = e
                && *resp.error() == BasicErrorResponseType::InvalidGrant
            {
                return OAuthError::InvalidGrant { service: "google-oauth".to_owned() };
            }
            OAuthError::RefreshFailed { service: "google-oauth".to_owned(), source: Box::new(e) }
        })?;

    // Convert to credential types IMMEDIATELY (scoped token exposure).
    let access_token =
        OAuthToken::from_trusted_bytes(token_response.access_token().secret().as_bytes().to_vec());

    let new_refresh_token = token_response
        .refresh_token()
        .map(|rt| OAuthRefreshToken::from_trusted_bytes(rt.secret().as_bytes().to_vec()));

    let expires_in = token_response.expires_in();

    Ok(RefreshResult { access_token, new_refresh_token, expires_in })
}

/// Refresh with exponential backoff retry policy.
///
/// Attempts up to 3 times with delays of ~1s, ~2s, ~4s (±20% jitter).
/// On exhaustion, emits a `token_refresh_failed` audit stub via `tracing::warn!`
/// and returns `OAuthError::RefreshExhausted`.
pub async fn refresh_with_retry(
    client: &ConfiguredClient,
    http_client: &reqwest::Client,
    refresh_token: &OAuthRefreshToken,
) -> Result<RefreshResult, OAuthError> {
    let mut last_error = None;

    for attempt in 0..MAX_RETRY_ATTEMPTS {
        match refresh_access_token(client, http_client, refresh_token).await {
            Ok(result) => return Ok(result),
            Err(OAuthError::InvalidGrant { .. }) => {
                // invalid_grant is non-retryable — token is revoked.
                return Err(OAuthError::InvalidGrant { service: "google-oauth".to_owned() });
            }
            Err(e) => {
                tracing::warn!(
                    attempt = attempt + 1,
                    max_attempts = MAX_RETRY_ATTEMPTS,
                    error = %e,
                    "token refresh attempt failed, will retry"
                );
                last_error = Some(e);

                if attempt < MAX_RETRY_ATTEMPTS - 1 {
                    let delay = compute_backoff_delay(attempt);
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    // All retries exhausted — emit audit stub event.
    tracing::warn!(
        event_type = "token-refresh",
        service = "google-oauth",
        outcome = "failed",
        attempts = MAX_RETRY_ATTEMPTS,
        error_code = "upstream_unreachable",
        "token refresh failed after all retry attempts"
    );

    // Log the last error for debugging (no credential bytes in OAuthError).
    if let Some(last) = &last_error {
        tracing::debug!(last_error = %last, "final refresh error");
    }

    Err(OAuthError::RefreshExhausted {
        service: "google-oauth".to_owned(),
        attempts: MAX_RETRY_ATTEMPTS,
    })
}

/// Compute backoff delay with ±20% jitter.
///
/// delay = BASE_DELAY_SECS * 2^attempt * (1 ± 0.2 * random)
fn compute_backoff_delay(attempt: u32) -> Duration {
    let base = BASE_DELAY_SECS * 2.0_f64.powi(attempt as i32);
    let mut rng = rand::thread_rng();
    let jitter: f64 = rng.gen_range(-JITTER_FACTOR..=JITTER_FACTOR);
    let delay = base * (1.0 + jitter);
    Duration::from_secs_f64(delay.max(0.1))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn should_refresh_below_threshold() {
        assert!(should_proactively_refresh(
            Duration::from_secs(60),
            Some(Duration::from_secs(300))
        ));
    }

    #[test]
    fn should_not_refresh_above_threshold() {
        assert!(!should_proactively_refresh(
            Duration::from_secs(600),
            Some(Duration::from_secs(300))
        ));
    }

    #[test]
    fn should_refresh_uses_default_threshold() {
        assert!(should_proactively_refresh(Duration::from_secs(60), None));
        assert!(!should_proactively_refresh(Duration::from_secs(600), None));
    }

    #[test]
    fn backoff_delay_increases_exponentially() {
        for attempt in 0..3 {
            let delay = compute_backoff_delay(attempt);
            let expected_base = BASE_DELAY_SECS * 2.0_f64.powi(attempt as i32);
            let min = expected_base * (1.0 - JITTER_FACTOR);
            let max = expected_base * (1.0 + JITTER_FACTOR);
            assert!(
                delay.as_secs_f64() >= min && delay.as_secs_f64() <= max,
                "attempt {attempt}: delay {:.3}s not in [{min:.3}, {max:.3}]",
                delay.as_secs_f64()
            );
        }
    }

    #[tokio::test]
    async fn refresh_with_mock_server() {
        use axum::Json;
        use axum::routing::post;
        use oauth2::{ClientId, TokenUrl};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let token_url = format!("http://127.0.0.1:{}/token", addr.port());

        let app = axum::Router::new().route(
            "/token",
            post(|| async {
                Json(serde_json::json!({
                    "access_token": "ya29.new-access-token",
                    "refresh_token": "1//new-refresh-token",
                    "token_type": "Bearer",
                    "expires_in": 3600
                }))
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock server");
        });

        let client = oauth2::basic::BasicClient::new(ClientId::new("test-client".to_owned()))
            .set_auth_uri(
                oauth2::AuthUrl::new("http://127.0.0.1:1/auth".to_owned()).expect("auth url"),
            )
            .set_token_uri(TokenUrl::new(token_url).expect("token url"));

        let http_client = reqwest::Client::new();
        let refresh_token = OAuthRefreshToken::from_trusted_bytes(b"1//old-refresh-token".to_vec());

        let result = refresh_access_token(&client, &http_client, &refresh_token).await;

        assert!(result.is_ok(), "refresh should succeed");
        let r = match result {
            Ok(r) => r,
            Err(_) => panic!("expected Ok"),
        };
        assert_eq!(r.access_token.reveal(), b"ya29.new-access-token");
        assert!(r.new_refresh_token.is_some());
        let nrt = match r.new_refresh_token {
            Some(t) => t,
            None => panic!("expected Some"),
        };
        assert_eq!(nrt.reveal(), b"1//new-refresh-token");
    }
}
