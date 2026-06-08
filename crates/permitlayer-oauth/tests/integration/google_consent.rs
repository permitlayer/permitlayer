//! Integration tests for Google OAuth client configuration (Story 1.7).

use std::path::PathBuf;

use permitlayer_oauth::google::consent::GoogleOAuthConfig;
use permitlayer_oauth::google::scopes;

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
//
// Story 11.7: the per-service scope *data* (`default_scopes_for_service`
// / `read_write_scopes_for_service` / `scopes_for_access`) moved out of
// `scopes.rs` into the connector defs. The byte-identical-scope-set
// regression pin now lives in `permitlayer-connectors`
// (`registry::tests::tier_scope_uris_pin_to_legacy_scope_sets`), which
// asserts the same gmail read-write = readonly+send+compose+modify
// contract this file used to cover. `scopes.rs` keeps only the provider-
// generic display metadata (`scope_info` / `uri_to_short_name`), exercised
// by its own unit tests.

#[test]
fn scope_info_round_trips_for_known_uris() {
    // The display-metadata surface `scopes.rs` retains: a granted URI maps
    // to its policy short name + a human description.
    let info = scopes::scope_info(scopes::GMAIL_SEND).expect("gmail.send has scope_info");
    assert_eq!(info.short_name, "gmail.send");
    assert!(!info.description.is_empty());
    assert_eq!(scopes::uri_to_short_name(scopes::GMAIL_READONLY), Some("gmail.readonly"));
    assert!(scopes::scope_info("https://example.com/unknown").is_none());
}

// (CredentialMeta serde round-trip tests removed in Story 11.16 — the
// `-meta.json` provenance type was deleted; the ConnectionRecord is the
// provenance now, tested in permitlayer-core's connection_fs.rs.)

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
