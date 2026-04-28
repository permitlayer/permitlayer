//! Integration tests for [`permitlayer_plugins::scope_allowlist`]
//! (Story 6.4 AC #18).

use permitlayer_plugins::{ALLOWED_SCOPES, is_allowed};

#[test]
fn allowlist_covers_built_in_scopes() {
    // AC #18: every scope declared by a built-in connector placeholder
    // must be in the allowlist — otherwise the freshly-scaffolded
    // template would fail `connectors test` if it copied those
    // scopes.
    for scope in [
        "gmail.readonly",
        "gmail.metadata",
        "gmail.search",
        "gmail.modify",
        "gmail.send",
        "calendar.readonly",
        "calendar.events",
        "drive.readonly",
        "drive.file",
        "example.readonly",
    ] {
        assert!(is_allowed(scope), "built-in scope `{scope}` must be in allowlist");
        assert!(ALLOWED_SCOPES.contains(&scope), "ALLOWED_SCOPES must contain `{scope}` literally");
    }
}

#[test]
fn is_allowed_rejects_unknown() {
    assert!(!is_allowed("notion.read"));
    assert!(!is_allowed("linear.issue.read"));
    assert!(!is_allowed("random.unreviewed"));
}

#[test]
fn is_allowed_rejects_empty() {
    assert!(!is_allowed(""));
}
