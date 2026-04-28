//! Integration test: compile the worked `default.toml` fixture and
//! snapshot-test its decisions for canonical requests.
//!
//! This file is the compile-time gate on the policy examples shipped
//! under `test-fixtures/policies/`. If someone edits `default.toml`
//! in a way that changes the behavior of any of the canonical
//! requests below, the snapshot review will catch it.
//!
//! AC #9 decision category mapping (Story 4.1):
//!   read-allow                    → `decision_gmail_read_allowed`
//!   out-of-scope-deny (as impl'd) → `decision_gmail_write_denied`
//!                                   (rule-deny, not scope-deny — see Note)
//!   write-prompt                  → `decision_calendar_write_prompts`
//!   unknown-resource-deny         → `decision_calendar_other_resource_denied`
//!   unmatched-policy-default-deny → `decision_unknown_policy_default_denies`
//!
//! Note: AC #9's literal text lists "out-of-scope-deny" but the
//! `default.toml` fixture ships `gmail_write_denied` as an explicit
//! rule-deny for the `gmail.modify` scope rather than a scope-allowlist
//! miss. Spirit of the AC is met (five decision categories × five
//! snapshots); the label drift is cosmetic. Tracked (and now closed)
//! in `deferred-work.md:119` by Story 8.6 AC #7.

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
    assert_eq!(set.len(), 3);
    assert!(set.get("gmail-read-only").is_some());
    assert!(set.get("calendar-prompt-on-write").is_some());
    assert!(set.get("drive-research-scope-restricted").is_some());
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
fn decision_calendar_write_prompts() {
    let set = load_default_policy_set();
    let decision = set.evaluate(&EvalRequest {
        policy_name: "calendar-prompt-on-write".to_owned(),
        scope: "calendar.events".to_owned(),
        resource: Some("primary".to_owned()),
    });
    insta::assert_json_snapshot!("calendar_write_prompts", decision);
}

#[test]
fn decision_calendar_other_resource_denied() {
    let set = load_default_policy_set();
    let decision = set.evaluate(&EvalRequest {
        policy_name: "calendar-prompt-on-write".to_owned(),
        scope: "calendar.events".to_owned(),
        resource: Some("family".to_owned()),
    });
    insta::assert_json_snapshot!("calendar_other_resource_denied", decision);
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
