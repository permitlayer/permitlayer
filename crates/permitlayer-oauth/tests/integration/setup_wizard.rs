//! Integration tests for Story 1.8: setup wizard components.
//!
//! Tests scope info, verification module, and error variant behavior.

use permitlayer_oauth::OAuthError;
use permitlayer_oauth::error::VerifyReason;
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
        verify_reason: None,
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
        verify_reason: None,
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
        verify_reason: None,
        source: None,
    };
    let display = format!("{err}");
    assert!(display.contains("gmail"));
    assert!(display.contains("403 Forbidden"));
}

// ── Story 7.12: remediation_owned() for VerifyReason variants ──────

fn verify_failed_with(vr: VerifyReason) -> OAuthError {
    OAuthError::VerificationFailed {
        service: "calendar".to_owned(),
        reason: "403 Forbidden".to_owned(),
        status_code: Some(403),
        verify_reason: Some(vr),
        source: None,
    }
}

#[test]
fn service_disabled_with_project_renders_url_and_gcloud() {
    let err = verify_failed_with(VerifyReason::ServiceDisabled {
        service: "calendar.googleapis.com".to_owned(),
        project: Some("my-project".to_owned()),
        also_billing_disabled: false,
    });
    let text = err.remediation_owned();
    assert!(
        text.contains(
            "https://console.cloud.google.com/apis/library/calendar.googleapis.com?project=my-project"
        ),
        "missing console URL with project: {text}"
    );
    assert!(
        text.contains("gcloud services enable calendar.googleapis.com --project my-project"),
        "missing gcloud command: {text}"
    );
    assert!(text.contains("Calendar API"), "missing friendly name: {text}");
}

#[test]
fn service_disabled_without_project_omits_query_param() {
    let err = verify_failed_with(VerifyReason::ServiceDisabled {
        service: "drive.googleapis.com".to_owned(),
        project: None,
        also_billing_disabled: false,
    });
    let text = err.remediation_owned();
    // URL must end at the canonical service name with no `?project=` tail.
    assert!(
        text.contains("https://console.cloud.google.com/apis/library/drive.googleapis.com"),
        "missing bare URL: {text}"
    );
    assert!(!text.contains("?project="), "URL should omit ?project= when project is None: {text}");
    assert!(
        text.contains("gcloud services enable drive.googleapis.com"),
        "missing gcloud command: {text}"
    );
    assert!(
        !text.contains("--project"),
        "gcloud should omit --project when project is None: {text}"
    );
}

#[test]
fn service_disabled_unknown_api_falls_back_to_raw_name() {
    let err = verify_failed_with(VerifyReason::ServiceDisabled {
        service: "future.googleapis.com".to_owned(),
        project: Some("p1".to_owned()),
        also_billing_disabled: false,
    });
    let text = err.remediation_owned();
    // Unknown service: no friendly name; raw service identifier appears
    // throughout the URL + gcloud command.
    assert!(text.contains("future.googleapis.com"), "missing raw name: {text}");
    assert!(
        text.contains(
            "https://console.cloud.google.com/apis/library/future.googleapis.com?project=p1"
        ),
        "missing URL: {text}"
    );
}

#[test]
fn billing_disabled_renders_billing_url_with_project() {
    let err = verify_failed_with(VerifyReason::BillingDisabled {
        project: Some("my-project".to_owned()),
    });
    let text = err.remediation_owned();
    assert!(
        text.contains("https://console.cloud.google.com/billing?project=my-project"),
        "missing billing URL with project: {text}"
    );
    assert!(text.to_lowercase().contains("billing"), "should mention billing: {text}");
}

#[test]
fn billing_disabled_without_project_omits_query_param() {
    let err = verify_failed_with(VerifyReason::BillingDisabled { project: None });
    let text = err.remediation_owned();
    assert!(
        text.contains("https://console.cloud.google.com/billing"),
        "missing billing URL: {text}"
    );
    assert!(!text.contains("?project="), "URL should omit ?project= when project is None: {text}");
}

#[test]
fn scope_insufficient_with_scopes_lists_them() {
    let err = verify_failed_with(VerifyReason::ScopeInsufficient {
        missing_scopes: vec![
            "https://www.googleapis.com/auth/calendar.events".to_owned(),
            "https://www.googleapis.com/auth/drive.readonly".to_owned(),
        ],
        also_service_disabled: None,
        also_billing_disabled: false,
    });
    let text = err.remediation_owned();
    assert!(text.contains("calendar.events"), "missing scope #1: {text}");
    assert!(text.contains("drive.readonly"), "missing scope #2: {text}");
}

#[test]
fn scope_insufficient_without_scopes_falls_back() {
    let err = verify_failed_with(VerifyReason::ScopeInsufficient {
        missing_scopes: vec![],
        also_service_disabled: None,
        also_billing_disabled: false,
    });
    let text = err.remediation_owned();
    assert!(
        text.to_lowercase().contains("missing scopes"),
        "should mention missing scopes: {text}"
    );
    // Empty-vec branch must not panic and must produce sensible text;
    // exact wording is implementation-defined but should hint at re-running.
}

#[test]
fn verification_failed_other_falls_back_to_static() {
    // P9 round-1 review: strengthened from `contains` to `Cow::Borrowed`
    // equality. The pre-fix assertion would have passed even when
    // `Other` allocated a `Cow::Owned` duplicate of the static text;
    // P8 fixed the allocation, P9 fixes the test to lock the contract.
    let err = verify_failed_with(VerifyReason::Other);
    assert_eq!(err.remediation_owned(), std::borrow::Cow::Borrowed(err.remediation()));
}

#[test]
fn verification_failed_none_falls_back_to_static() {
    let err = OAuthError::VerificationFailed {
        service: "gmail".to_owned(),
        reason: "401 Unauthorized".to_owned(),
        status_code: Some(401),
        verify_reason: None,
        source: None,
    };
    assert_eq!(err.remediation_owned(), std::borrow::Cow::Borrowed(err.remediation()));
}

#[test]
fn unrelated_error_variants_unchanged_by_remediation_owned() {
    let err = OAuthError::PkceGenerationFailed;
    // remediation_owned must delegate to remediation for static variants;
    // the borrowed Cow points at the same static string.
    assert_eq!(err.remediation_owned(), std::borrow::Cow::Borrowed(err.remediation()));
}

// ── Verification module integration tests ───────────────────────────
// Note: mock-based gmail verification (success, 401, 403, timeout) is
// thoroughly covered in the unit tests in verify.rs. Integration tests
// here focus on the public API contract.

#[tokio::test]
async fn verify_unknown_service_returns_ok() {
    let result = verify::verify_connection("unknown_service", b"any-token", None)
        .await
        .expect("unknown service should return Ok");

    assert_eq!(result.summary, "no verification available");
    assert!(result.email.is_none());
}

#[tokio::test]
async fn verify_calendar_empty_token_rejected() {
    let err = verify::verify_connection("calendar", b"", None)
        .await
        .expect_err("empty token should be rejected");

    assert_eq!(err.error_code(), "verification_failed");
}

#[tokio::test]
async fn verify_drive_empty_token_rejected() {
    let err = verify::verify_connection("drive", b"", None)
        .await
        .expect_err("empty token should be rejected");

    assert_eq!(err.error_code(), "verification_failed");
}
