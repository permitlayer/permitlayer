//! Google API scope constants, per-service defaults, and human-readable
//! scope metadata for the setup wizard.

// Gmail scopes
pub const GMAIL_READONLY: &str = "https://www.googleapis.com/auth/gmail.readonly";
pub const GMAIL_MODIFY: &str = "https://www.googleapis.com/auth/gmail.modify";
pub const GMAIL_SEND: &str = "https://www.googleapis.com/auth/gmail.send";

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

/// Return `ScopeInfo` entries for a service's default scopes.
#[must_use]
pub fn default_scope_infos_for_service(service: &str) -> Vec<ScopeInfo> {
    default_scopes_for_service(service).into_iter().filter_map(scope_info).collect()
}

/// Return the default scope set for a given service name.
///
/// Unknown services return an empty vec (the caller decides whether
/// that is an error).
#[must_use]
pub fn default_scopes_for_service(service: &str) -> Vec<&'static str> {
    match service {
        "gmail" => vec![GMAIL_READONLY],
        "calendar" => vec![CALENDAR_READONLY, CALENDAR_EVENTS],
        "drive" => vec![DRIVE_READONLY, DRIVE_FILE],
        _ => vec![],
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn gmail_returns_readonly_scope() {
        let scopes = default_scopes_for_service("gmail");
        assert_eq!(scopes, vec![GMAIL_READONLY]);
    }

    #[test]
    fn calendar_returns_readonly_and_events_scopes() {
        let scopes = default_scopes_for_service("calendar");
        assert_eq!(scopes, vec![CALENDAR_READONLY, CALENDAR_EVENTS]);
    }

    #[test]
    fn drive_returns_readonly_and_file_scopes() {
        let scopes = default_scopes_for_service("drive");
        assert_eq!(scopes, vec![DRIVE_READONLY, DRIVE_FILE]);
    }

    #[test]
    fn unknown_service_returns_empty() {
        let scopes = default_scopes_for_service("unknown");
        assert!(scopes.is_empty());
    }

    #[test]
    fn each_known_scope_has_info() {
        let all_scopes = [
            GMAIL_READONLY,
            GMAIL_MODIFY,
            GMAIL_SEND,
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

    #[test]
    fn default_scope_infos_for_gmail() {
        let infos = default_scope_infos_for_service("gmail");
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].short_name, "gmail.readonly");
        assert_eq!(infos[0].description, "Read your email messages and settings");
    }

    #[test]
    fn default_scope_infos_for_unknown_service() {
        let infos = default_scope_infos_for_service("unknown");
        assert!(infos.is_empty());
    }
}
