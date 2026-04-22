//! Integration tests for Google OAuth client configuration (Story 1.7).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use permitlayer_oauth::google::consent::GoogleOAuthConfig;
use permitlayer_oauth::google::scopes;
use permitlayer_oauth::metadata::CredentialMeta;

// ── GoogleOAuthConfig tests ──────────────────────────────────────────

#[test]
fn from_client_json_parses_installed_app_fixture() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-fixtures/google-oauth/installed-app.json");

    let config = GoogleOAuthConfig::from_client_json(&fixture).unwrap();
    assert_eq!(config.client_id(), "test-byo-client-id.apps.googleusercontent.com");
    assert_eq!(config.client_secret(), Some("GOCSPX-test-fixture-secret"));
}

#[test]
fn from_client_json_byo_provenance_tag() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-fixtures/google-oauth/installed-app.json");

    let config = GoogleOAuthConfig::from_client_json(&fixture).unwrap();
    let tag = config.provenance_tag();
    assert!(tag.starts_with("byo:"), "provenance tag should start with 'byo:': {tag}");
    assert!(tag.contains("installed-app.json"), "tag should contain source filename: {tag}");
}

#[test]
fn from_client_json_missing_file_returns_read_error() {
    let path = PathBuf::from("/nonexistent/path/client.json");
    let err = GoogleOAuthConfig::from_client_json(&path).unwrap_err();
    assert_eq!(err.error_code(), "client_json_read_failed");
}

#[test]
fn from_client_json_malformed_json_returns_invalid_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.json");
    std::fs::write(&path, "not valid json {{{").unwrap();

    let err = GoogleOAuthConfig::from_client_json(&path).unwrap_err();
    assert_eq!(err.error_code(), "client_json_invalid");
}

#[test]
fn from_client_json_missing_client_id_returns_invalid_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.json");
    std::fs::write(&path, r#"{"installed": {"project_id": "test"}}"#).unwrap();

    let err = GoogleOAuthConfig::from_client_json(&path).unwrap_err();
    assert_eq!(err.error_code(), "client_json_invalid");
    let msg = format!("{err}");
    assert!(msg.contains("client_id"), "error should mention client_id: {msg}");
}

#[test]
fn from_client_json_wrong_structure_returns_invalid_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.json");
    std::fs::write(&path, r#"{"desktop": {"client_id": "test"}}"#).unwrap();

    let err = GoogleOAuthConfig::from_client_json(&path).unwrap_err();
    assert_eq!(err.error_code(), "client_json_invalid");
    let msg = format!("{err}");
    assert!(
        msg.contains("installed") || msg.contains("web"),
        "error should mention expected keys: {msg}"
    );
}

// ── Scope tests ──────────────────────────────────────────────────────

#[test]
fn gmail_default_scopes() {
    let scopes = scopes::default_scopes_for_service("gmail");
    assert_eq!(scopes, vec![scopes::GMAIL_READONLY]);
}

#[test]
fn calendar_default_scopes() {
    let scopes = scopes::default_scopes_for_service("calendar");
    assert_eq!(scopes, vec![scopes::CALENDAR_READONLY, scopes::CALENDAR_EVENTS]);
}

#[test]
fn drive_default_scopes() {
    let scopes = scopes::default_scopes_for_service("drive");
    assert_eq!(scopes, vec![scopes::DRIVE_READONLY, scopes::DRIVE_FILE]);
}

#[test]
fn unknown_service_returns_empty_scopes() {
    let scopes = scopes::default_scopes_for_service("slack");
    assert!(scopes.is_empty());
}

// ── CredentialMeta tests ─────────────────────────────────────────────

#[test]
fn credential_meta_roundtrip_shared_casa() {
    let meta = CredentialMeta {
        client_type: "shared-casa".to_owned(),
        client_source: None,
        connected_at: "2026-04-06T12:00:00Z".to_owned(),
        last_refreshed_at: None,
        scopes: vec!["https://www.googleapis.com/auth/gmail.readonly".to_owned()],
        expires_in_secs: Some(3600),
    };

    let json = serde_json::to_string(&meta).unwrap();
    let deserialized: CredentialMeta = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.client_type, "shared-casa");
    assert!(deserialized.client_source.is_none());
}

#[test]
fn credential_meta_roundtrip_byo() {
    let meta = CredentialMeta {
        client_type: "byo".to_owned(),
        client_source: Some("./my-client.json".to_owned()),
        connected_at: "2026-04-06T12:00:00Z".to_owned(),
        last_refreshed_at: None,
        scopes: vec![
            "https://www.googleapis.com/auth/gmail.readonly".to_owned(),
            "https://www.googleapis.com/auth/gmail.modify".to_owned(),
        ],
        expires_in_secs: None,
    };

    let json = serde_json::to_string(&meta).unwrap();
    let deserialized: CredentialMeta = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.client_type, "byo");
    assert_eq!(deserialized.client_source.as_deref(), Some("./my-client.json"));
    assert_eq!(deserialized.scopes.len(), 2);
}

// ── Error display safety ─────────────────────────────────────────────

#[test]
fn error_display_does_not_contain_credentials() {
    let err = permitlayer_oauth::OAuthError::ClientJsonReadFailed {
        path: PathBuf::from("/tmp/client.json"),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
    };
    let display = format!("{err}");
    let debug = format!("{err:?}");

    // These should NOT contain any token material.
    assert!(!display.contains("secret"), "Display should not contain secrets: {display}");
    assert!(!debug.contains("GOCSPX"), "Debug should not contain client secrets: {debug}");
}

#[test]
fn new_error_variants_have_remediation_and_error_code() {
    let err1 = permitlayer_oauth::OAuthError::ClientJsonReadFailed {
        path: PathBuf::from("/tmp/test.json"),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
    };
    assert!(!err1.remediation().is_empty());
    assert_eq!(err1.error_code(), "client_json_read_failed");

    let err2 = permitlayer_oauth::OAuthError::ClientJsonInvalid {
        path: PathBuf::from("/tmp/test.json"),
        reason: "missing client_id".to_owned(),
    };
    assert!(!err2.remediation().is_empty());
    assert_eq!(err2.error_code(), "client_json_invalid");
}
