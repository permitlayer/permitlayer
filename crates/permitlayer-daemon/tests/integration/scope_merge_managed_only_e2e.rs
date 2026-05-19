//! Integration test: the C1 fix — `POST /v1/control/policy/<name>/scopes`
//! succeeds as a NO-OP when the target policy exists ONLY in the
//! managed (shipped) layer and the requested scopes are already a
//! subset of that policy's scopes.
//!
//! ## Why this test exists
//!
//! `agentsso quickstart gmail` (default `--read`) binds the agent to
//! the managed-only `gmail-read-only` policy. connect's scope-merge
//! step then POSTs the granted scopes to
//! `/v1/control/policy/gmail-read-only/scopes`. On a CLEAN install the
//! operator `policies/` dir is empty (the product bundle lives in the
//! sibling `policies-managed/`, never seeded into the operator layer).
//! Before the C1 fix the handler scanned the operator dir only →
//! `PolicyFileNotFound` → HTTP error → connect treated it as FATAL →
//! `quickstart` failed AFTER the user completed OAuth. The existing
//! `quickstart_e2e` SIGTERMs the child before scope-merge, so that
//! blindness is exactly why C1 shipped.
//!
//! This test boots a real daemon with an EMPTY operator dir (the
//! managed bundle is rewritten on every boot, Story 1), then drives
//! the scope-merge endpoint directly with the read-only tier's exact
//! scopes and asserts: HTTP 200, a no-op result (`added == []`,
//! `reloaded == false`), and that NO operator-layer file was created
//! (Option B: the managed bundle stays the single source of truth).
//! It also asserts the negative: requesting a scope the managed
//! policy lacks is a clear error (no silent grant).
//!
//! macOS control routes are UDS-only (Story 7.27); elsewhere TCP
//! loopback. `crate::common::http_post_control` handles both.

use crate::common::{
    DaemonTestConfig, http_post_control, read_test_control_token, start_daemon, wait_for_health,
};

/// Boot a daemon with an empty operator policy dir. The managed
/// bundle (`policies-managed/default.toml`) is written by the daemon
/// on boot, so `gmail-read-only` resolves managed-only — exactly the
/// clean-install shape `quickstart` hits.
fn boot_clean_daemon(home: &std::path::Path) -> crate::common::DaemonHandle {
    // Operator dir intentionally NOT created/seeded — clean install.
    let daemon =
        start_daemon(DaemonTestConfig { port: 0, home: home.to_path_buf(), ..Default::default() });
    assert!(wait_for_health(daemon.port), "daemon did not become healthy");
    daemon
}

#[test]
fn managed_only_subset_scope_merge_is_a_successful_noop() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    let daemon = boot_clean_daemon(home.path());
    let port = daemon.port;
    let ctl = read_test_control_token(home.path());

    // connect for a quickstart `--read` bind requests exactly the
    // managed `gmail-read-only` tier's scopes.
    let (status, body) = http_post_control(
        home.path(),
        port,
        "/v1/control/policy/gmail-read-only/scopes",
        r#"{"short_names":["gmail.readonly","gmail.metadata"]}"#,
        &[("X-Agentsso-Control", ctl.as_str())],
    );
    assert_eq!(status, 200, "managed-only subset scope-merge must succeed (C1) — body: {body}");
    let json: serde_json::Value =
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("non-JSON body {body:?}: {e}"));
    assert_eq!(json["policy_name"], "gmail-read-only");
    assert_eq!(
        json["added"].as_array().map(Vec::len),
        Some(0),
        "no scopes should be added (pure no-op) — body: {body}"
    );
    assert_eq!(json["reloaded"], false, "a no-op merge must not trigger a reload — body: {body}");

    // Option B: the managed bundle stays the single source of truth —
    // NO operator-layer file was created by the no-op.
    let operator_dir = home.path().join("policies");
    let operator_empty = !operator_dir.exists()
        || std::fs::read_dir(&operator_dir).map(|mut d| d.next().is_none()).unwrap_or(true);
    assert!(operator_empty, "operator policies/ dir must remain empty (no seeded copy)");
}

#[test]
fn managed_policy_missing_scope_is_a_loud_error_not_silent_grant() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    let daemon = boot_clean_daemon(home.path());
    let port = daemon.port;
    let ctl = read_test_control_token(home.path());

    // Ask the read-only tier for a WRITE scope it does not allow.
    // This must NOT silently grant — there is no operator file to
    // extend and Option B forbids seeding one.
    let (status, body) = http_post_control(
        home.path(),
        port,
        "/v1/control/policy/gmail-read-only/scopes",
        r#"{"short_names":["gmail.send"]}"#,
        &[("X-Agentsso-Control", ctl.as_str())],
    );
    assert_ne!(
        status, 200,
        "requesting a scope the managed policy lacks must fail loudly, not 200 — body: {body}"
    );

    // And still no operator file materialized.
    let operator_dir = home.path().join("policies");
    let operator_empty = !operator_dir.exists()
        || std::fs::read_dir(&operator_dir).map(|mut d| d.next().is_none()).unwrap_or(true);
    assert!(operator_empty, "a rejected over-broad request must not create an operator file");
}
