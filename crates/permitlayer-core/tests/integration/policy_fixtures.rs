//! Integration test: compile the worked `default.toml` fixture and
//! snapshot-test its decisions for canonical requests.
//!
//! This file is the compile-time gate on the policy examples shipped
//! under `test-fixtures/policies/`. If someone edits `default.toml`
//! in a way that changes the behavior of any of the canonical
//! requests below, the snapshot review will catch it.
//!
//! Decision category mapping (headless model — no prompt):
//!   read-allow                    → `decision_gmail_read_allowed`
//!   out-of-scope-deny (as impl'd) → `decision_gmail_write_denied`
//!                                   (default-deny, scope absent)
//!   write-allow (read-write tier) → `decision_calendar_write_allowed`
//!   unknown-resource-deny         → `decision_drive_other_resource_denied`
//!   unmatched-policy-default-deny → `decision_unknown_policy_default_denies`
//!
//! UX-overhaul: the daemon is HEADLESS — there is no `prompt`
//! disposition in the shipped bundle/fixture (it could only 503 on a
//! headless daemon). The former `decision_calendar_write_prompts`
//! snapshot is replaced by `decision_calendar_write_allowed`: a
//! `-read-write` tier auto-grants the write scope. The legacy
//! `calendar-prompt-on-write` example policy was deleted with the
//! `prompt` purge; the unknown-resource-deny category now exercises
//! `drive-research-scope-restricted` (which scopes to one folder ID).

use std::path::PathBuf;

use permitlayer_core::policy::{EvalRequest, PolicyCompileError, PolicySet};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("test-fixtures")
        .join("policies")
}

fn load_default_policy_set() -> PolicySet {
    let path = fixture_root().join("default.toml");
    let text = std::fs::read_to_string(&path).expect("default.toml fixture must exist");
    PolicySet::compile_from_str(&text, &path).expect("default.toml must compile cleanly")
}

#[test]
fn default_fixture_compiles() {
    let set = load_default_policy_set();
    // Six per-service tier policies plus two retained originals
    // (gmail-read-only + drive-research-scope-restricted). The legacy
    // `calendar-prompt-on-write` example was deleted with the
    // headless `prompt`-purge → 8 policies total.
    assert_eq!(set.len(), 8);
    // Retained originals.
    assert!(set.get("gmail-read-only").is_some());
    assert!(set.get("drive-research-scope-restricted").is_some());
    assert!(
        set.get("calendar-prompt-on-write").is_none(),
        "the legacy prompt-on-write example must NOT ship — the daemon is headless"
    );
    // Per-service read-only / read-write tiers.
    for name in [
        "gmail-read-write",
        "calendar-read-only",
        "calendar-read-write",
        "drive-read-only",
        "drive-read-write",
        "gmail-read-only-tier",
    ] {
        assert!(set.get(name).is_some(), "tier policy {name} must be present");
    }
}

#[test]
fn decision_gmail_read_allowed() {
    let set = load_default_policy_set();
    let decision = set.evaluate(&EvalRequest {
        policy_name: "gmail-read-only".to_owned(),
        scope: "gmail.readonly".to_owned(),
        resource: None,
    });
    insta::assert_json_snapshot!("gmail_read_allowed", decision);
}

#[test]
fn decision_gmail_write_denied() {
    let set = load_default_policy_set();
    let decision = set.evaluate(&EvalRequest {
        policy_name: "gmail-read-only".to_owned(),
        scope: "gmail.modify".to_owned(),
        resource: None,
    });
    insta::assert_json_snapshot!("gmail_write_denied", decision);
}

#[test]
fn decision_calendar_write_allowed() {
    // Headless model: the `-read-write` tier auto-grants the write
    // scope (no prompt — `prompt` would only 503 on a headless
    // daemon and is purged from the shipped bundle/fixture).
    let set = load_default_policy_set();
    let decision = set.evaluate(&EvalRequest {
        policy_name: "calendar-read-write".to_owned(),
        scope: "calendar.events".to_owned(),
        resource: Some("primary".to_owned()),
    });
    insta::assert_json_snapshot!("calendar_write_allowed", decision);
}

#[test]
fn decision_drive_other_resource_denied() {
    // `drive-research-scope-restricted` scopes to exactly the
    // `research-shared` folder ID; any other resource is denied by
    // the resource allowlist (unknown-resource-deny category).
    let set = load_default_policy_set();
    let decision = set.evaluate(&EvalRequest {
        policy_name: "drive-research-scope-restricted".to_owned(),
        scope: "drive.readonly".to_owned(),
        resource: Some("some-other-folder".to_owned()),
    });
    insta::assert_json_snapshot!("drive_other_resource_denied", decision);
}

#[test]
fn decision_unknown_policy_default_denies() {
    let set = load_default_policy_set();
    let decision = set.evaluate(&EvalRequest {
        policy_name: "nope".to_owned(),
        scope: "gmail.readonly".to_owned(),
        resource: None,
    });
    insta::assert_json_snapshot!("unknown_policy_default_denies", decision);
}

#[test]
fn invalid_empty_scopes_fixture_is_rejected() {
    let path = fixture_root().join("invalid").join("empty-scopes.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    let err = PolicySet::compile_from_str(&text, &path).unwrap_err();
    assert!(matches!(err, PolicyCompileError::EmptyScopesAllowlist { .. }));
}

#[test]
fn invalid_duplicate_rule_ids_fixture_is_rejected() {
    let path = fixture_root().join("invalid").join("duplicate-rule-ids.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    let err = PolicySet::compile_from_str(&text, &path).unwrap_err();
    assert!(matches!(err, PolicyCompileError::DuplicateRuleId { .. }));
}

#[test]
fn invalid_unknown_top_level_key_fixture_is_rejected() {
    let path = fixture_root().join("invalid").join("unknown-top-level-key.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    let err = PolicySet::compile_from_str(&text, &path).unwrap_err();
    assert!(matches!(err, PolicyCompileError::Parse { .. }));
}

#[test]
fn invalid_bogus_approval_mode_fixture_is_rejected() {
    let path = fixture_root().join("invalid").join("bogus-approval-mode.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    let err = PolicySet::compile_from_str(&text, &path).unwrap_err();
    assert!(matches!(err, PolicyCompileError::Parse { .. }));
}

#[test]
fn invalid_uppercase_scope_fixture_is_rejected() {
    let path = fixture_root().join("invalid").join("uppercase-scope.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    let err = PolicySet::compile_from_str(&text, &path).unwrap_err();
    assert!(matches!(err, PolicyCompileError::InvalidScopeFormat { .. }));
}
