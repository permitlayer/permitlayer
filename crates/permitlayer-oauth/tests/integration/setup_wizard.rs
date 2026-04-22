//! Integration tests for Story 1.8: setup wizard components.
//!
//! Tests scope info, verification module, and error variant behavior.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use permitlayer_oauth::OAuthError;
use permitlayer_oauth::google::scopes;
use permitlayer_oauth::google::verify;

// ── Scope info tests ────────────────────────────────────────────────

#[test]
fn scope_info_for_all_default_gmail_scopes() {
    let infos = scopes::default_scope_infos_for_service("gmail");
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].uri, scopes::GMAIL_READONLY);
    assert_eq!(infos[0].short_name, "gmail.readonly");
    assert_eq!(infos[0].description, "Read your email messages and settings");
}

#[test]
fn scope_info_returns_none_for_unknown_uri() {
    assert!(scopes::scope_info("https://example.com/fake.scope").is_none());
}

#[test]
fn default_scope_infos_for_calendar() {
    let infos = scopes::default_scope_infos_for_service("calendar");
    assert_eq!(infos.len(), 2);
    assert_eq!(infos[0].short_name, "calendar.readonly");
    assert_eq!(infos[1].short_name, "calendar.events");
}

#[test]
fn default_scope_infos_for_drive() {
    let infos = scopes::default_scope_infos_for_service("drive");
    assert_eq!(infos.len(), 2);
    assert_eq!(infos[0].short_name, "drive.readonly");
    assert_eq!(infos[1].short_name, "drive.file");
}

// ── VerificationFailed error tests ──────────────────────────────────

#[test]
fn verification_failed_error_code() {
    let err = OAuthError::VerificationFailed {
        service: "gmail".to_owned(),
        reason: "401 Unauthorized".to_owned(),
        status_code: Some(401),
        source: None,
    };
    assert_eq!(err.error_code(), "verification_failed");
}

#[test]
fn verification_failed_remediation() {
    let err = OAuthError::VerificationFailed {
        service: "gmail".to_owned(),
        reason: "test".to_owned(),
        status_code: None,
        source: None,
    };
    let remediation = err.remediation();
    assert!(
        remediation.contains("Credentials are stored"),
        "remediation should mention stored credentials: {remediation}"
    );
}

#[test]
fn verification_failed_display() {
    let err = OAuthError::VerificationFailed {
        service: "gmail".to_owned(),
        reason: "403 Forbidden".to_owned(),
        status_code: Some(403),
        source: None,
    };
    let display = format!("{err}");
    assert!(display.contains("gmail"));
    assert!(display.contains("403 Forbidden"));
}

// ── Verification module integration tests ───────────────────────────
// Note: mock-based gmail verification (success, 401, 403, timeout) is
// thoroughly covered in the unit tests in verify.rs. Integration tests
// here focus on the public API contract.

#[tokio::test]
async fn verify_unknown_service_returns_ok() {
    let result = verify::verify_connection("unknown_service", b"any-token")
        .await
        .expect("unknown service should return Ok");

    assert_eq!(result.summary, "no verification available");
    assert!(result.email.is_none());
}

#[tokio::test]
async fn verify_calendar_empty_token_rejected() {
    let err = verify::verify_connection("calendar", b"")
        .await
        .expect_err("empty token should be rejected");

    assert_eq!(err.error_code(), "verification_failed");
}

#[tokio::test]
async fn verify_drive_empty_token_rejected() {
    let err =
        verify::verify_connection("drive", b"").await.expect_err("empty token should be rejected");

    assert_eq!(err.error_code(), "verification_failed");
}
