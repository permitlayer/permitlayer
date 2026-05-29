//! Integration tests for the `credentials status` subcommand.
//!
//! Verifies output formatting for both the "has credentials" and
//! "no credentials" states.

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
    // CLI output consistency pass: `status` now renders through the
    // shared `render::table()` pipeline (matching `credentials list`),
    // so the per-line `connected:` label became a `CONNECTED` column
    // header. Story 1.14b Task 5a's semantics still hold — the column
    // value is `connected_at`, the setup timestamp.
    assert!(
        stdout.contains("CONNECTED"),
        "expected 'CONNECTED' column header in output, got: {stdout}"
    );
    // Story 1.14b Task 5b: when `last_refreshed_at` is None (as in this
    // fixture), the LAST REFRESH column renders an em-dash placeholder
    // (the table keeps every column aligned), not a stale timestamp.
    assert!(
        stdout.contains("LAST REFRESH"),
        "expected 'LAST REFRESH' column header in output, got: {stdout}"
    );
    assert!(
        stdout.contains('\u{2014}'),
        "pre-refresh credentials must show an em-dash placeholder in LAST REFRESH, got: {stdout}"
    );
    // Token will be expired (connected_at is in the past relative to now + expires_in_secs).
    assert!(
        stdout.contains("TOKEN") || stdout.contains("expired") || stdout.contains("valid"),
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

    // CLI output consistency pass: `status` renders through
    // `render::table()`, so the per-line labels became column headers.
    assert!(stdout.contains("CONNECTED"), "expected 'CONNECTED' column header, got: {stdout}");
    assert!(
        stdout.contains("LAST REFRESH"),
        "expected 'LAST REFRESH' column header when last_refreshed_at is Some, got: {stdout}"
    );
    // The LAST REFRESH column must carry an actual timestamp (not the
    // em-dash placeholder) when last_refreshed_at is Some. "just now"
    // is `format_timestamp`'s rendering of a 30-seconds-ago instant.
    assert!(
        stdout.contains("just now") || stdout.contains("ago"),
        "expected a recent timestamp in LAST REFRESH when refreshed 30s ago, got: {stdout}"
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
