//! Google API scope constants, per-service defaults, and human-readable
//! scope metadata for the setup wizard.

// Gmail scopes
pub const GMAIL_READONLY: &str = "https://www.googleapis.com/auth/gmail.readonly";
/// Metadata-only Gmail scope (headers + labels, NO message body).
///
/// Narrower than [`GMAIL_READONLY`]. Reconciled in Story 9.1: this scope
/// has shipped in the `gmail-read-only` policy fixture and the plugin
/// `scope_allowlist` ("reviewed scopes") since the initial public release
/// (`23774ed`), but `scopes.rs` never carried a constant/`scope_info`
/// row for it — so the fixture loaded structurally yet mapped to no
/// metadata. This adds the missing constant + `scope_info` entry to make
/// `scopes.rs` coherent with the long-standing fixture + allowlist. It is
/// deliberately in the gmail connector's `[scopes]` vocab but in **no
/// access tier** (no metadata-only grant tier was ever wired, and Story
/// 9.1 exposes no metadata-only tool — see story Dev Notes / Task 7).
/// Story 11.7 moved the tier sets into the connector defs.
pub const GMAIL_METADATA: &str = "https://www.googleapis.com/auth/gmail.metadata";
pub const GMAIL_MODIFY: &str = "https://www.googleapis.com/auth/gmail.modify";
pub const GMAIL_SEND: &str = "https://www.googleapis.com/auth/gmail.send";
/// Draft compose/manage scope (Story 9.2). Google's `users.drafts.*`
/// (create/update/send) accept `gmail.compose` as their minimum — NOT
/// `gmail.send` (verified against Google's REST reference 2026-05-17:
/// `users.drafts.send` accepts mail.google.com / gmail.modify /
/// gmail.compose only). Like the other write scopes it is in the gmail
/// connector's `read-write` tier but not its `read` tier — the write tier
/// is a policy choice, not a default OAuth grant (same rule as 9.1's
/// `GMAIL_METADATA`). Story 11.7 moved the tier sets into the connector
/// defs.
pub const GMAIL_COMPOSE: &str = "https://www.googleapis.com/auth/gmail.compose";

// Calendar scopes
pub const CALENDAR_READONLY: &str = "https://www.googleapis.com/auth/calendar.readonly";
pub const CALENDAR_EVENTS: &str = "https://www.googleapis.com/auth/calendar.events";

// Drive scopes
pub const DRIVE_READONLY: &str = "https://www.googleapis.com/auth/drive.readonly";
pub const DRIVE_FILE: &str = "https://www.googleapis.com/auth/drive.file";

/// Human-readable scope metadata for display in the setup wizard.
#[derive(Debug, Clone)]
#[must_use]
pub struct ScopeInfo {
    /// Full OAuth scope URI.
    pub uri: &'static str,
    /// Short name (e.g., "gmail.readonly").
    pub short_name: &'static str,
    /// Human-readable description shown to user before consent.
    pub description: &'static str,
}

/// Look up human-readable metadata for an OAuth scope URI.
///
/// Returns `None` for unrecognized scope URIs.
#[must_use]
pub fn scope_info(scope_uri: &str) -> Option<ScopeInfo> {
    match scope_uri {
        GMAIL_READONLY => Some(ScopeInfo {
            uri: GMAIL_READONLY,
            short_name: "gmail.readonly",
            description: "Read your email messages and settings",
        }),
        GMAIL_METADATA => Some(ScopeInfo {
            uri: GMAIL_METADATA,
            short_name: "gmail.metadata",
            description: "Read email metadata (headers and labels) but not message bodies",
        }),
        GMAIL_MODIFY => Some(ScopeInfo {
            uri: GMAIL_MODIFY,
            short_name: "gmail.modify",
            description: "Read, send, and manage your email",
        }),
        GMAIL_SEND => Some(ScopeInfo {
            uri: GMAIL_SEND,
            short_name: "gmail.send",
            description: "Send email on your behalf",
        }),
        GMAIL_COMPOSE => Some(ScopeInfo {
            uri: GMAIL_COMPOSE,
            short_name: "gmail.compose",
            description: "Create, update, and send drafts on your behalf",
        }),
        CALENDAR_READONLY => Some(ScopeInfo {
            uri: CALENDAR_READONLY,
            short_name: "calendar.readonly",
            description: "View your calendar events",
        }),
        CALENDAR_EVENTS => Some(ScopeInfo {
            uri: CALENDAR_EVENTS,
            short_name: "calendar.events",
            description: "View and edit your calendar events",
        }),
        DRIVE_READONLY => Some(ScopeInfo {
            uri: DRIVE_READONLY,
            short_name: "drive.readonly",
            description: "View files in your Google Drive",
        }),
        DRIVE_FILE => Some(ScopeInfo {
            uri: DRIVE_FILE,
            short_name: "drive.file",
            description: "View and manage files created by this app",
        }),
        _ => None,
    }
}

// Story 11.7: per-service scope *set* resolution
// (`default_scopes_for_service` / `read_write_scopes_for_service` /
// `scopes_for_access` and their `ScopeInfo` wrappers) moved out of
// `scopes.rs` into the connector defs — the registry is now the single
// source of truth for "which scopes does this access tier grant". The
// daemon CLI resolves the tier→URI set via
// `ResolvedConnector::tier_scope_uris`, then maps each URI through
// `scope_info` below for the consent display. `scopes.rs` keeps only the
// provider-generic display metadata + the scope constants.

/// Story 7.13: convert a granted OAuth scope URI to its policy-file
/// short name.
///
/// Policy TOML files store short names (e.g., `"gmail.readonly"`),
/// not full URIs. This helper maps a granted scope URI like
/// `"https://www.googleapis.com/auth/gmail.readonly"` to the policy-
/// shape short name. Returns `None` for URIs we don't know about
/// (the caller — `agentsso connect`'s policy-merge step — must skip
/// those rather than write an unparseable scope into a policy file).
#[must_use]
pub fn uri_to_short_name(scope_uri: &str) -> Option<&'static str> {
    scope_info(scope_uri).map(|info| info.short_name)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // Story 11.7: per-service scope-*set* tests moved to
    // `permitlayer-connectors` (`tier_scope_uris_pin_to_legacy_scope_sets`).
    // What remains here is the provider-generic `scope_info` /
    // `uri_to_short_name` display surface `scopes.rs` still owns.

    #[test]
    fn each_known_scope_has_info() {
        let all_scopes = [
            GMAIL_READONLY,
            GMAIL_METADATA,
            GMAIL_MODIFY,
            GMAIL_SEND,
            GMAIL_COMPOSE,
            CALENDAR_READONLY,
            CALENDAR_EVENTS,
            DRIVE_READONLY,
            DRIVE_FILE,
        ];
        for uri in all_scopes {
            let info = scope_info(uri);
            assert!(info.is_some(), "scope_info should return Some for {uri}");
            let info = info.unwrap();
            assert_eq!(info.uri, uri);
            assert!(!info.short_name.is_empty());
            assert!(!info.description.is_empty());
        }
    }

    #[test]
    fn unknown_scope_returns_none() {
        assert!(scope_info("https://example.com/unknown.scope").is_none());
    }

    /// Story 9.1 Task 7 reconciliation: `gmail.metadata` shipped in the
    /// `gmail-read-only` fixture + plugin scope_allowlist since the initial
    /// public release but had no `scope_info` row. It must still resolve.
    /// (Whether it appears in any access tier is now the connector defs'
    /// concern — it deliberately appears in `[scopes]` but no tier.)
    #[test]
    fn gmail_metadata_scope_is_reconciled() {
        let info = scope_info(GMAIL_METADATA);
        assert!(info.is_some(), "gmail.metadata must resolve after Story 9.1 reconciliation");
        let info = info.unwrap();
        assert_eq!(info.uri, "https://www.googleapis.com/auth/gmail.metadata");
        assert_eq!(info.short_name, "gmail.metadata");
        assert!(!info.description.is_empty());
        assert_eq!(uri_to_short_name(GMAIL_METADATA), Some("gmail.metadata"));
    }

    /// Story 9.2: `gmail.compose` resolves (drafts create/update/send
    /// minimum scope — verified against Google's REST reference; NOT
    /// `gmail.send`).
    #[test]
    fn gmail_compose_reconciled() {
        let info = scope_info(GMAIL_COMPOSE);
        assert!(info.is_some(), "gmail.compose must resolve (Story 9.2)");
        let info = info.unwrap();
        assert_eq!(info.uri, "https://www.googleapis.com/auth/gmail.compose");
        assert_eq!(info.short_name, "gmail.compose");
        assert!(!info.description.is_empty());
        assert_eq!(uri_to_short_name(GMAIL_COMPOSE), Some("gmail.compose"));
    }

    #[test]
    fn uri_to_short_name_round_trips_for_known_scopes() {
        assert_eq!(uri_to_short_name(GMAIL_READONLY), Some("gmail.readonly"));
        assert_eq!(uri_to_short_name(CALENDAR_EVENTS), Some("calendar.events"));
        assert_eq!(uri_to_short_name(DRIVE_FILE), Some("drive.file"));
    }

    #[test]
    fn uri_to_short_name_returns_none_for_unknown() {
        assert_eq!(uri_to_short_name("https://example.com/some.unknown.scope"), None);
    }
}
