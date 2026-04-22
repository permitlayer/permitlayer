//! Post-consent verification via lightweight read-only test queries.
//!
//! After sealing OAuth tokens, the setup wizard calls [`verify_connection`]
//! to confirm the grant actually works end-to-end. This module lives in
//! `permitlayer-oauth` (not in the daemon) because it is part of the OAuth
//! domain — verifying that the grant produced usable tokens.
//!
//! # Privacy (Story 2.7 Decision 2B)
//!
//! Google API error responses can include user-identifying content:
//! email addresses in `invalid_grant` messages, account IDs, internal
//! service tokens. We DO NOT include the raw error body in the
//! user-facing `reason` field of [`OAuthError::VerificationFailed`] — a
//! failed-setup screenshot shared for troubleshooting would otherwise
//! leak that content. Instead, the body is emitted via
//! `tracing::debug!` under a `permitlayer_oauth::google::verify`
//! target, so operators who need diagnostics can opt in with
//! `RUST_LOG=debug permitlayer_oauth=debug` while normal users see
//! only a status-code-level message.

use crate::error::OAuthError;

/// Gmail profile API endpoint.
const GMAIL_PROFILE_URL: &str = "https://gmail.googleapis.com/gmail/v1/users/me/profile";
/// Calendar list API endpoint (lightweight read-only check).
const CALENDAR_LIST_URL: &str =
    "https://www.googleapis.com/calendar/v3/users/me/calendarList?maxResults=1";
/// Drive about API endpoint (lightweight read-only check).
const DRIVE_ABOUT_URL: &str = "https://www.googleapis.com/drive/v3/about?fields=user";

/// Build the shared `reqwest::Client` used by every `verify_*` function.
///
/// Connection pool, TLS context, user-agent, and timeout settings are
/// constructed exactly once per call. Wraps any build failure as
/// [`OAuthError::VerificationFailed`].
fn build_verify_client(service: &str) -> Result<reqwest::Client, OAuthError> {
    reqwest::Client::builder()
        .user_agent("agentsso/0.1")
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| OAuthError::VerificationFailed {
            service: service.to_owned(),
            reason: "failed to build HTTP client".to_owned(),
            status_code: None,
            source: Some(Box::new(e)),
        })
}

/// Join a base URL with a path, producing a slash-safe URL.
///
/// Handles all four combinations of trailing / leading slashes on
/// `base` and `path`:
///
/// | base         | path  | result      |
/// |--------------|-------|-------------|
/// | `http://x`   | `foo` | `http://x/foo` |
/// | `http://x`   | `/foo`| `http://x/foo` |
/// | `http://x/`  | `foo` | `http://x/foo` |
/// | `http://x/`  | `/foo`| `http://x/foo` |
///
/// We manually normalize rather than using `url::Url::join` because
/// the latter has surprising semantics when the base lacks a trailing
/// slash (it treats the last path segment as a "file" and replaces it),
/// which does not match the caller's intent here (base is always a
/// host, path is always a route).
fn join_verify_url(base: &str, path: &str) -> String {
    let base_trimmed = base.trim_end_matches('/');
    let path_trimmed = path.trim_start_matches('/');
    format!("{base_trimmed}/{path_trimmed}")
}

/// Log a non-2xx verify response body at DEBUG level without exposing
/// it to the user-facing error.
///
/// **Privacy (Story 2.7 Decision 2B):** Google API error responses can
/// contain user email addresses (in `invalid_grant` messages), account
/// IDs, internal service tokens, and other user-identifying content.
/// This helper consumes the body, logs it via `tracing::debug!`, and
/// returns nothing — the body is NEVER included in the `OAuthError`
/// returned to the caller, so a failed-setup screenshot shared for
/// troubleshooting does not leak that content. Operators who need
/// forensics can opt in with `RUST_LOG=debug permitlayer_oauth=debug`.
async fn log_verify_error_body(response: reqwest::Response, service: &str, status_code: u16) {
    match response.text().await {
        Ok(body) => {
            tracing::debug!(
                service,
                status_code,
                body_len = body.len(),
                body = %body,
                "verify response body (contains potentially sensitive Google API content — \
                 not included in user-facing error)"
            );
        }
        Err(e) => {
            tracing::debug!(
                service,
                status_code,
                error = %e,
                "failed to read verify response body"
            );
        }
    }
}

/// Result of a post-consent verification query.
#[derive(Debug)]
#[must_use]
pub struct VerifyResult {
    /// Human-readable summary of what was verified (e.g., "email: user@example.com").
    pub summary: String,
    /// Verified email address if available (e.g., from gmail.users.getProfile).
    pub email: Option<String>,
}

/// Run a lightweight read-only verification query for the given service.
///
/// Uses the access token directly (before sealing) to confirm the OAuth
/// grant actually works end-to-end. Returns structured error on failure.
pub async fn verify_connection(
    service: &str,
    access_token: &[u8],
) -> Result<VerifyResult, OAuthError> {
    verify_connection_with_url(service, access_token, None).await
}

/// Internal implementation that accepts an optional base URL override for testing.
async fn verify_connection_with_url(
    service: &str,
    access_token: &[u8],
    base_url: Option<&str>,
) -> Result<VerifyResult, OAuthError> {
    match service {
        "gmail" => verify_gmail(access_token, base_url).await,
        "calendar" => verify_calendar(access_token, base_url).await,
        "drive" => verify_drive(access_token, base_url).await,
        _ => Ok(VerifyResult { summary: "no verification available".to_owned(), email: None }),
    }
}

async fn verify_gmail(
    access_token: &[u8],
    base_url: Option<&str>,
) -> Result<VerifyResult, OAuthError> {
    let token_str =
        std::str::from_utf8(access_token).map_err(|e| OAuthError::VerificationFailed {
            service: "gmail".to_owned(),
            reason: "access token is not valid UTF-8".to_owned(),
            status_code: None,
            source: Some(Box::new(e)),
        })?;

    if token_str.is_empty() {
        return Err(OAuthError::VerificationFailed {
            service: "gmail".to_owned(),
            reason: "access token is empty".to_owned(),
            status_code: None,
            source: None,
        });
    }

    let url = match base_url {
        Some(base) => join_verify_url(base, "gmail/v1/users/me/profile"),
        None => GMAIL_PROFILE_URL.to_owned(),
    };

    let client = build_verify_client("gmail")?;

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {token_str}"))
        .send()
        .await
        .map_err(|e| OAuthError::VerificationFailed {
            service: "gmail".to_owned(),
            reason: format!("request failed: {e}"),
            status_code: None,
            source: Some(Box::new(e)),
        })?;

    let status = response.status();
    if !status.is_success() {
        let status_code = status.as_u16();
        // Privacy (Story 2.7 Decision 2B): log body at DEBUG, never in user-facing error.
        log_verify_error_body(response, "gmail", status_code).await;
        return Err(OAuthError::VerificationFailed {
            service: "gmail".to_owned(),
            reason: format!("{status_code} {}", status.canonical_reason().unwrap_or("unknown")),
            status_code: Some(status_code),
            source: None,
        });
    }

    let json: serde_json::Value =
        response.json().await.map_err(|e| OAuthError::VerificationFailed {
            service: "gmail".to_owned(),
            reason: "failed to parse profile response".to_owned(),
            status_code: None,
            source: Some(Box::new(e)),
        })?;

    let email = json.get("emailAddress").and_then(|v| v.as_str()).map(|s| s.to_owned());

    let summary = match &email {
        Some(addr) => format!("email: {addr}"),
        None => "profile retrieved (no email in response)".to_owned(),
    };

    Ok(VerifyResult { summary, email })
}

async fn verify_calendar(
    access_token: &[u8],
    base_url: Option<&str>,
) -> Result<VerifyResult, OAuthError> {
    let token_str =
        std::str::from_utf8(access_token).map_err(|e| OAuthError::VerificationFailed {
            service: "calendar".to_owned(),
            reason: "access token is not valid UTF-8".to_owned(),
            status_code: None,
            source: Some(Box::new(e)),
        })?;

    if token_str.is_empty() {
        return Err(OAuthError::VerificationFailed {
            service: "calendar".to_owned(),
            reason: "access token is empty".to_owned(),
            status_code: None,
            source: None,
        });
    }

    let url = match base_url {
        Some(base) => join_verify_url(base, "calendar/v3/users/me/calendarList?maxResults=1"),
        None => CALENDAR_LIST_URL.to_owned(),
    };

    let client = build_verify_client("calendar")?;

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {token_str}"))
        .send()
        .await
        .map_err(|e| OAuthError::VerificationFailed {
            service: "calendar".to_owned(),
            reason: format!("request failed: {e}"),
            status_code: None,
            source: Some(Box::new(e)),
        })?;

    let status = response.status();
    if !status.is_success() {
        let status_code = status.as_u16();
        // Privacy (Story 2.7 Decision 2B): log body at DEBUG, never in user-facing error.
        log_verify_error_body(response, "calendar", status_code).await;
        return Err(OAuthError::VerificationFailed {
            service: "calendar".to_owned(),
            reason: format!("{status_code} {}", status.canonical_reason().unwrap_or("unknown")),
            status_code: Some(status_code),
            source: None,
        });
    }

    let json: serde_json::Value =
        response.json().await.map_err(|e| OAuthError::VerificationFailed {
            service: "calendar".to_owned(),
            reason: "failed to parse calendarList response".to_owned(),
            status_code: None,
            source: Some(Box::new(e)),
        })?;

    let calendar_count = json.get("items").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);

    Ok(VerifyResult { summary: format!("{calendar_count} calendar(s) accessible"), email: None })
}

async fn verify_drive(
    access_token: &[u8],
    base_url: Option<&str>,
) -> Result<VerifyResult, OAuthError> {
    let token_str =
        std::str::from_utf8(access_token).map_err(|e| OAuthError::VerificationFailed {
            service: "drive".to_owned(),
            reason: "access token is not valid UTF-8".to_owned(),
            status_code: None,
            source: Some(Box::new(e)),
        })?;

    if token_str.is_empty() {
        return Err(OAuthError::VerificationFailed {
            service: "drive".to_owned(),
            reason: "access token is empty".to_owned(),
            status_code: None,
            source: None,
        });
    }

    let url = match base_url {
        Some(base) => join_verify_url(base, "drive/v3/about?fields=user"),
        None => DRIVE_ABOUT_URL.to_owned(),
    };

    let client = build_verify_client("drive")?;

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {token_str}"))
        .send()
        .await
        .map_err(|e| OAuthError::VerificationFailed {
            service: "drive".to_owned(),
            reason: format!("request failed: {e}"),
            status_code: None,
            source: Some(Box::new(e)),
        })?;

    let status = response.status();
    if !status.is_success() {
        let status_code = status.as_u16();
        // Privacy (Story 2.7 Decision 2B): log body at DEBUG, never in user-facing error.
        log_verify_error_body(response, "drive", status_code).await;
        return Err(OAuthError::VerificationFailed {
            service: "drive".to_owned(),
            reason: format!("{status_code} {}", status.canonical_reason().unwrap_or("unknown")),
            status_code: Some(status_code),
            source: None,
        });
    }

    let json: serde_json::Value =
        response.json().await.map_err(|e| OAuthError::VerificationFailed {
            service: "drive".to_owned(),
            reason: "failed to parse about response".to_owned(),
            status_code: None,
            source: Some(Box::new(e)),
        })?;

    let email = json
        .get("user")
        .and_then(|u| u.get("emailAddress"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());

    let display_name = json
        .get("user")
        .and_then(|u| u.get("displayName"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let summary = match &email {
        Some(addr) => format!("drive: {display_name} ({addr})"),
        None => format!("drive: {display_name}"),
    };

    Ok(VerifyResult { summary, email })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn gmail_successful_profile() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/gmail/v1/users/me/profile")
            .match_header("Authorization", "Bearer test-token-123")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"emailAddress": "test@example.com", "messagesTotal": 42}"#)
            .create_async()
            .await;

        let result = verify_connection_with_url("gmail", b"test-token-123", Some(&server.url()))
            .await
            .expect("verification should succeed");

        assert_eq!(result.email, Some("test@example.com".to_owned()));
        assert_eq!(result.summary, "email: test@example.com");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn gmail_401_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/gmail/v1/users/me/profile")
            .with_status(401)
            .with_body(r#"{"error": {"code": 401, "message": "Invalid Credentials"}}"#)
            .create_async()
            .await;

        let err = verify_connection_with_url("gmail", b"bad-token", Some(&server.url()))
            .await
            .expect_err("should fail with 401");

        assert_eq!(err.error_code(), "verification_failed");
        match &err {
            OAuthError::VerificationFailed { status_code, service, .. } => {
                assert_eq!(*status_code, Some(401));
                assert_eq!(service, "gmail");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn gmail_403_forbidden() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/gmail/v1/users/me/profile")
            .with_status(403)
            .with_body(r#"{"error": {"code": 403, "message": "Forbidden"}}"#)
            .create_async()
            .await;

        let err = verify_connection_with_url("gmail", b"token", Some(&server.url()))
            .await
            .expect_err("should fail with 403");

        match &err {
            OAuthError::VerificationFailed { status_code, .. } => {
                assert_eq!(*status_code, Some(403));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn unknown_service_passthrough() {
        let result = verify_connection_with_url("notion", b"token", None)
            .await
            .expect("unknown service should return Ok");

        assert_eq!(result.summary, "no verification available");
        assert!(result.email.is_none());
    }

    #[tokio::test]
    async fn network_timeout() {
        // Use a URL that will refuse connection quickly.
        let err = verify_connection_with_url("gmail", b"token", Some("http://127.0.0.1:1"))
            .await
            .expect_err("should fail with connection error");

        assert_eq!(err.error_code(), "verification_failed");
    }

    #[tokio::test]
    async fn gmail_empty_token_rejected() {
        let err = verify_connection_with_url("gmail", b"", None)
            .await
            .expect_err("empty token should be rejected");

        assert_eq!(err.error_code(), "verification_failed");
        match &err {
            OAuthError::VerificationFailed { reason, .. } => {
                assert!(reason.contains("empty"), "reason should mention empty: {reason}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn calendar_successful_verification() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/calendar/v3/users/me/calendarList?maxResults=1")
            .match_header("Authorization", "Bearer cal-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"kind":"calendar#calendarList","items":[{"id":"primary","summary":"My Calendar"}]}"#,
            )
            .create_async()
            .await;

        let result = verify_connection_with_url("calendar", b"cal-token", Some(&server.url()))
            .await
            .expect("calendar verification should succeed");

        assert_eq!(result.summary, "1 calendar(s) accessible");
        assert!(result.email.is_none());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn calendar_401_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/calendar/v3/users/me/calendarList?maxResults=1")
            .with_status(401)
            .with_body(r#"{"error":{"code":401}}"#)
            .create_async()
            .await;

        let err = verify_connection_with_url("calendar", b"bad-token", Some(&server.url()))
            .await
            .expect_err("should fail with 401");

        match &err {
            OAuthError::VerificationFailed { status_code, service, .. } => {
                assert_eq!(*status_code, Some(401));
                assert_eq!(service, "calendar");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn drive_successful_verification() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/drive/v3/about?fields=user")
            .match_header("Authorization", "Bearer drive-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"user":{"displayName":"Test User","emailAddress":"test@example.com"}}"#)
            .create_async()
            .await;

        let result = verify_connection_with_url("drive", b"drive-token", Some(&server.url()))
            .await
            .expect("drive verification should succeed");

        assert_eq!(result.email, Some("test@example.com".to_owned()));
        assert_eq!(result.summary, "drive: Test User (test@example.com)");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn drive_403_forbidden() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/drive/v3/about?fields=user")
            .with_status(403)
            .with_body(r#"{"error":{"code":403}}"#)
            .create_async()
            .await;

        let err = verify_connection_with_url("drive", b"token", Some(&server.url()))
            .await
            .expect_err("should fail with 403");

        match &err {
            OAuthError::VerificationFailed { status_code, service, .. } => {
                assert_eq!(*status_code, Some(403));
                assert_eq!(service, "drive");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
        mock.assert_async().await;
    }

    // ----- Story 2.7: shared helpers + privacy-safe body logging -----

    #[test]
    fn build_verify_client_returns_configured_client() {
        // Smoke test: the helper must produce a client without error and
        // propagate the service name into the error path if it ever fails.
        let client = build_verify_client("gmail").expect("client builds");
        // The client is opaque; we just verify it exists and can be used.
        // A deeper assertion (user-agent, timeout) would require a mock
        // server request — covered by the existing success-path tests.
        drop(client);
    }

    #[test]
    fn join_verify_url_handles_trailing_slash_on_base() {
        // The four base/path slash combinations must all produce the
        // same output.
        let expected = "http://example.com/gmail/v1/users/me/profile";
        assert_eq!(join_verify_url("http://example.com", "gmail/v1/users/me/profile"), expected);
        assert_eq!(join_verify_url("http://example.com", "/gmail/v1/users/me/profile"), expected);
        assert_eq!(join_verify_url("http://example.com/", "gmail/v1/users/me/profile"), expected);
        assert_eq!(join_verify_url("http://example.com/", "/gmail/v1/users/me/profile"), expected);
    }

    #[test]
    fn join_verify_url_preserves_query_string_in_path() {
        // Query strings must survive the normalization so the calendar
        // URL's `?maxResults=1` parameter is not dropped.
        let joined = join_verify_url(
            "http://example.com/",
            "calendar/v3/users/me/calendarList?maxResults=1",
        );
        assert_eq!(joined, "http://example.com/calendar/v3/users/me/calendarList?maxResults=1");
    }

    #[tokio::test]
    async fn gmail_verify_error_body_never_leaks_into_reason() {
        // Privacy regression test (Story 2.7 Decision 2B): a Google
        // error response containing user-identifying content must NOT
        // appear in the user-facing `OAuthError::VerificationFailed.reason`
        // field. The body goes to `tracing::debug!` only.
        //
        // This fixture body mimics a real Google `invalid_grant` error
        // which would normally include an email address — the test
        // uses a sentinel string `"SENSITIVE_EMAIL_alice@example.com"`
        // that is unambiguous to search for.
        let mut server = mockito::Server::new_async().await;
        let sensitive_marker = "SENSITIVE_EMAIL_alice@example.com";
        let body =
            format!(r#"{{"error":"invalid_grant","error_description":"{sensitive_marker}"}}"#);
        let mock = server
            .mock("GET", "/gmail/v1/users/me/profile")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(&body)
            .create_async()
            .await;

        let err = verify_connection_with_url("gmail", b"leaked-token", Some(&server.url()))
            .await
            .expect_err("should fail with 401");

        match &err {
            OAuthError::VerificationFailed { reason, status_code, service, source } => {
                // The status code IS in the user-facing reason (that's safe).
                assert_eq!(*status_code, Some(401));
                assert_eq!(service, "gmail");
                assert!(reason.contains("401"), "reason should contain status code: {reason}");
                // CRITICAL: the Google error body must NOT be in `reason`.
                assert!(
                    !reason.contains(sensitive_marker),
                    "Story 2.7 Decision 2B PRIVACY REGRESSION: \
                     Google response body leaked into user-facing OAuthError.reason. \
                     reason={reason}, sensitive_marker={sensitive_marker}"
                );
                // Also check it didn't sneak into the canonical status text.
                assert!(!reason.contains("alice@example.com"));
                // Story 2.7 review patch: lock the `source: None` invariant
                // on 4xx/5xx paths. A future refactor that wraps the
                // reqwest error into `source` would re-leak the body via
                // `std::error::Error::source()` chain traversal in
                // operator log pipelines. Assert the source is None.
                assert!(
                    source.is_none(),
                    "Story 2.7 review patch PRIVACY REGRESSION: \
                     4xx/5xx verify failure carries a `source` error, which \
                     could leak the response body via error-chain traversal. \
                     source={source:?}"
                );
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn calendar_verify_error_body_never_leaks_into_reason() {
        // Same privacy assertion as the gmail test, for the calendar path.
        let mut server = mockito::Server::new_async().await;
        let sensitive_marker = "SENSITIVE_CALENDAR_OWNER_bob@example.com";
        let body = format!(r#"{{"error":{{"code":403,"message":"{sensitive_marker}"}}}}"#);
        let mock = server
            .mock("GET", "/calendar/v3/users/me/calendarList?maxResults=1")
            .with_status(403)
            .with_body(&body)
            .create_async()
            .await;

        let err = verify_connection_with_url("calendar", b"token", Some(&server.url()))
            .await
            .expect_err("should fail with 403");

        match &err {
            OAuthError::VerificationFailed { reason, status_code, source, .. } => {
                assert_eq!(*status_code, Some(403));
                assert!(reason.contains("403"));
                assert!(
                    !reason.contains(sensitive_marker),
                    "calendar body leaked into reason: {reason}"
                );
                // Story 2.7 review patch: lock source = None on 4xx/5xx.
                assert!(
                    source.is_none(),
                    "calendar 4xx/5xx carries a source error (potential body leak): {source:?}"
                );
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn drive_verify_error_body_never_leaks_into_reason() {
        // Same privacy assertion as the gmail/calendar tests, for drive.
        let mut server = mockito::Server::new_async().await;
        let sensitive_marker = "SENSITIVE_DRIVE_USER_carol@example.com";
        let body = format!(r#"{{"error":{{"code":401,"message":"{sensitive_marker}"}}}}"#);
        let mock = server
            .mock("GET", "/drive/v3/about?fields=user")
            .with_status(401)
            .with_body(&body)
            .create_async()
            .await;

        let err = verify_connection_with_url("drive", b"token", Some(&server.url()))
            .await
            .expect_err("should fail with 401");

        match &err {
            OAuthError::VerificationFailed { reason, status_code, source, .. } => {
                assert_eq!(*status_code, Some(401));
                assert!(reason.contains("401"));
                assert!(
                    !reason.contains(sensitive_marker),
                    "drive body leaked into reason: {reason}"
                );
                // Story 2.7 review patch: lock source = None on 4xx/5xx.
                assert!(
                    source.is_none(),
                    "drive 4xx/5xx carries a source error (potential body leak): {source:?}"
                );
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn verify_with_trailing_slash_base_url_produces_no_double_slash() {
        // Regression test for the `verify_*` trailing-slash issue:
        // a base_url like `http://mock/` must not produce `//gmail/...`
        // in the constructed URL. mockito::Server::url() returns
        // without a trailing slash, so we manually append one.
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/gmail/v1/users/me/profile")
            .with_status(200)
            .with_body(r#"{"emailAddress":"test@example.com"}"#)
            .create_async()
            .await;

        let trailing_base = format!("{}/", server.url());
        let result =
            verify_connection_with_url("gmail", b"tok", Some(&trailing_base)).await.unwrap();
        assert_eq!(result.email, Some("test@example.com".to_owned()));
        mock.assert_async().await;
    }
}
