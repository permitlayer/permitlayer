//! Integration tests for the `credentials status` subcommand.
//!
//! Verifies output formatting for both the "has credentials" and
//! "no credentials" states.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

use tempfile::TempDir;

use crate::common::agentsso_bin;

#[test]
fn credentials_status_with_no_credentials_shows_empty_message() {
    let home = TempDir::new().unwrap();
    let output = Command::new(agentsso_bin())
        .args(["credentials", "status"])
        .env("AGENTSSO_PATHS__HOME", home.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("no connected services"),
        "expected 'no connected services' in output, got: {stdout}"
    );
}

#[test]
fn credentials_status_with_valid_meta_shows_service_info() {
    let home = TempDir::new().unwrap();
    let vault_dir = home.path().join("vault");
    std::fs::create_dir_all(&vault_dir).unwrap();

    // Write a mock gmail-meta.json with valid data.
    let meta = serde_json::json!({
        "client_type": "shared-casa",
        "connected_at": "2026-04-06T10:00:00Z",
        "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
        "expires_in_secs": 3600
    });
    std::fs::write(vault_dir.join("gmail-meta.json"), serde_json::to_string_pretty(&meta).unwrap())
        .unwrap();

    let output = Command::new(agentsso_bin())
        .args(["credentials", "status"])
        .env("AGENTSSO_PATHS__HOME", home.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain the service name and scope.
    assert!(stdout.contains("gmail"), "expected 'gmail' in output, got: {stdout}");
    assert!(
        stdout.contains("gmail.readonly"),
        "expected 'gmail.readonly' in output, got: {stdout}"
    );
    // Story 1.14b Task 5a renamed the misleading `refreshed:` label
    // to `connected:` because the field was always `connected_at`,
    // not `last_refreshed_at`. Both the label and its value should
    // appear in the output.
    assert!(stdout.contains("connected:"), "expected 'connected:' in output, got: {stdout}");
    // Story 1.14b Task 5b: when `last_refreshed_at` is None (as in
    // this fixture), the `last refresh:` line must be absent.
    assert!(
        !stdout.contains("last refresh:"),
        "pre-refresh credentials must not show a 'last refresh:' line, got: {stdout}"
    );
    // Token will be expired (connected_at is in the past relative to now + expires_in_secs).
    assert!(
        stdout.contains("token:") || stdout.contains("expired") || stdout.contains("valid"),
        "expected token status in output, got: {stdout}"
    );
}

/// Story 1.14b Task 5b + 5c regression: a meta file WITH
/// `last_refreshed_at` should show the `last refresh:` line AND
/// compute validity from the refresh baseline, not the setup time.
#[test]
fn credentials_status_shows_last_refresh_line_when_refreshed() {
    let home = TempDir::new().unwrap();
    let vault_dir = home.path().join("vault");
    std::fs::create_dir_all(&vault_dir).unwrap();

    // Setup was 2 days ago; refresh was 30 seconds ago. With a
    // 24-hour expiry, the token is valid for ~24 more hours. Old
    // behavior (baseline = connected_at) would report `expired` —
    // this is the deferred-work.md:58 regression gate.
    //
    // Story 1.14b code-review n7 fix: bumped expires_in_secs from
    // 3600 (1h) to 86400 (24h) to add CI slack. The previous test
    // would have flaked on a CI machine that took >59 minutes to
    // launch the test binary; now it has 24 hours of headroom.
    let now = chrono::Utc::now();
    let two_days_ago = (now - chrono::Duration::days(2)).to_rfc3339();
    let thirty_seconds_ago = (now - chrono::Duration::seconds(30)).to_rfc3339();

    let meta = serde_json::json!({
        "client_type": "shared-casa",
        "connected_at": two_days_ago,
        "last_refreshed_at": thirty_seconds_ago,
        "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
        "expires_in_secs": 86400
    });
    std::fs::write(vault_dir.join("gmail-meta.json"), serde_json::to_string_pretty(&meta).unwrap())
        .unwrap();

    let output = Command::new(agentsso_bin())
        .args(["credentials", "status"])
        .env("AGENTSSO_PATHS__HOME", home.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("connected:"), "expected 'connected:' line, got: {stdout}");
    assert!(
        stdout.contains("last refresh:"),
        "expected 'last refresh:' line when last_refreshed_at is Some, got: {stdout}"
    );
    assert!(
        stdout.contains("valid"),
        "compute_token_validity must report 'valid' using last_refreshed_at as the baseline \
         (fix for deferred-work.md:58), got: {stdout}"
    );
    assert!(
        !stdout.contains("expired"),
        "refreshed-30s-ago token must not report 'expired' (deferred-work.md:58 regression), \
         got: {stdout}"
    );
}
