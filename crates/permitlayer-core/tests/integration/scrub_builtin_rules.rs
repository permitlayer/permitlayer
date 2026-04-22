//! Integration tests for the built-in scrub rule pack.
//!
//! Validates that `builtin_rules()` produces a functional, stable, unique
//! rule set that detects all 8 placeholder types.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use permitlayer_core::scrub::{ScrubEngine, builtin_rules};

/// Build an engine with the full built-in rule set.
fn engine() -> ScrubEngine {
    ScrubEngine::new(builtin_rules().to_vec()).expect("builtin rules should produce a valid engine")
}

/// Composite input containing one of each sensitive type.
/// Note: the JWT is NOT preceded by "Bearer" so it exercises the JWT rule independently.
fn composite_input() -> &'static str {
    concat!(
        "Email from john.doe@example.com: ",
        "Your verification code is 123456. ",
        "Reset your password: https://accounts.google.com/reset/password?token=abc123. ",
        "Authorization: Bearer abc123def456ghi789jkl012mno345pqr. ",
        "Refresh token: eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6. ",
        "Call (555) 123-4567. ",
        "SSN: 123-45-6789. ",
        "Visa card 4111111111111111.",
    )
}

#[test]
fn all_placeholder_types_appear() {
    let r = engine().scrub(composite_input());

    assert!(r.output.contains("<REDACTED_EMAIL>"), "missing email redaction: {}", r.output);
    assert!(r.output.contains("<REDACTED_OTP>"), "missing OTP redaction: {}", r.output);
    assert!(
        r.output.contains("<REDACTED_RESET_LINK>"),
        "missing reset-link redaction: {}",
        r.output
    );
    assert!(r.output.contains("<REDACTED_BEARER>"), "missing bearer redaction: {}", r.output);
    assert!(r.output.contains("<REDACTED_JWT>"), "missing JWT redaction: {}", r.output);
    assert!(r.output.contains("<REDACTED_PHONE>"), "missing phone redaction: {}", r.output);
    assert!(r.output.contains("<REDACTED_SSN>"), "missing SSN redaction: {}", r.output);
    assert!(r.output.contains("<REDACTED_CC>"), "missing CC redaction: {}", r.output);
}

#[test]
fn no_original_sensitive_content_in_output() {
    let r = engine().scrub(composite_input());

    assert!(!r.output.contains("john.doe@example.com"), "email leaked: {}", r.output);
    assert!(!r.output.contains("123456"), "OTP leaked: {}", r.output);
    assert!(!r.output.contains("123-45-6789"), "SSN leaked: {}", r.output);
}

#[test]
fn builtin_rules_stable_nonempty() {
    let rules = builtin_rules();
    assert!(!rules.is_empty(), "builtin_rules() must return at least one rule");
    // Run twice to verify stability
    let rules2 = builtin_rules();
    assert_eq!(rules.len(), rules2.len(), "builtin_rules() length must be stable");
    for (a, b) in rules.iter().zip(rules2.iter()) {
        assert_eq!(a.name, b.name, "builtin_rules() names must be stable");
    }
}

#[test]
fn no_duplicate_rule_names() {
    let rules = builtin_rules();
    let mut names: Vec<&str> = rules.iter().map(|r| r.name.as_str()).collect();
    names.sort();
    let orig_len = names.len();
    names.dedup();
    assert_eq!(names.len(), orig_len, "duplicate rule names found in builtin_rules()");
}

#[test]
fn all_rules_have_literals() {
    for rule in builtin_rules() {
        assert!(
            !rule.literals.is_empty(),
            "rule '{}' must have at least one literal for the two-pass engine",
            rule.name
        );
    }
}

#[test]
fn clean_input_passes_through() {
    let input = "This is a perfectly normal email body with no sensitive content whatsoever.";
    let r = engine().scrub(input);
    assert!(r.is_clean(), "clean input should produce zero matches");
    assert_eq!(r.output, input);
}
