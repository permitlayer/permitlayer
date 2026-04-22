//! Curated allowlist of OAuth scope identifiers known to permitlayer's
//! policy engine as of this release.
//!
//! `agentsso connectors test` (Story 6.4) emits a **non-blocking**
//! warning when a connector declares a scope outside this list. The
//! warning is a developer-feedback signal, not a security gate:
//!
//! - Connectors with out-of-allowlist scopes still **load** (the
//!   Story 6.3 loader does not consult this list).
//! - The **policy engine** (Story 4.x) enforces its own per-policy
//!   `scopes = [...]` allowlist at request time — that is the real
//!   authorization gate.
//!
//! The allowlist exists because epics.md:1755 commits us to a future
//! marketplace-review step: "publication to the connector marketplace
//! will require the scope to be reviewed." Until that marketplace
//! ships, this static list is the review-pass proxy. Extend it when
//! a new scope passes review.

/// Ordered static list of every scope identifier currently marked
/// "reviewed." Iteration order is source order; callers that need
/// lexical ordering should sort a clone.
///
/// **Extending this list:** add new entries in the module doc order
/// (built-ins grouped first, third-party additions in chronological
/// review order). Do NOT remove entries — once reviewed, a scope is
/// reviewed forever (removing would silently start warning on
/// already-shipped connectors).
pub const ALLOWED_SCOPES: &[&str] = &[
    // Google Gmail (Epic 2: built-in Gmail connector)
    "gmail.readonly",
    "gmail.metadata",
    "gmail.search",
    "gmail.modify",
    "gmail.send",
    // Google Calendar (Epic 2: built-in Calendar connector)
    "calendar.readonly",
    "calendar.events",
    "calendar.events.readonly",
    // Google Drive (Epic 2: built-in Drive connector)
    "drive.readonly",
    "drive.file",
    "drive.metadata",
    // Scaffolder default — always allowed so the freshly-scaffolded
    // template passes `connectors test` without any edits.
    "example.readonly",
];

/// Returns `true` if `scope` is present in [`ALLOWED_SCOPES`].
///
/// Empty strings, whitespace-only strings, and any case-differing
/// variants return `false` — the match is exact, byte-for-byte.
pub fn is_allowed(scope: &str) -> bool {
    ALLOWED_SCOPES.contains(&scope)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_is_non_empty_and_has_no_duplicates() {
        assert!(!ALLOWED_SCOPES.is_empty());
        let mut sorted: Vec<&&str> = ALLOWED_SCOPES.iter().collect();
        sorted.sort();
        for pair in sorted.windows(2) {
            assert_ne!(pair[0], pair[1], "duplicate scope in allowlist: {}", pair[0]);
        }
    }

    #[test]
    fn is_allowed_accepts_known_scope() {
        assert!(is_allowed("gmail.readonly"));
        assert!(is_allowed("drive.readonly"));
        assert!(is_allowed("calendar.events"));
        assert!(is_allowed("example.readonly"));
    }

    #[test]
    fn is_allowed_rejects_unknown_scope() {
        assert!(!is_allowed("notion.read"));
        assert!(!is_allowed("jira.read"));
        assert!(!is_allowed("slack.post"));
    }

    #[test]
    fn is_allowed_rejects_empty_and_whitespace() {
        assert!(!is_allowed(""));
        assert!(!is_allowed(" "));
        assert!(!is_allowed("\t"));
    }

    #[test]
    fn is_allowed_is_case_sensitive() {
        assert!(is_allowed("gmail.readonly"));
        assert!(!is_allowed("GMAIL.READONLY"));
        assert!(!is_allowed("Gmail.Readonly"));
    }
}
