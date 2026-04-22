use serde::{Deserialize, Serialize};

/// Format a `DateTime<Utc>` as the canonical audit timestamp string.
///
/// Uses `%Y-%m-%dT%H:%M:%S%.3fZ` — RFC 3339 UTC with millisecond
/// precision and a literal `Z` suffix. This is the single source of
/// truth for audit timestamp formatting across the workspace; both
/// `permitlayer-daemon::server::control` and
/// `permitlayer-proxy::middleware::kill` consume this helper instead
/// of rolling their own copies. Using `.to_rfc3339()` is NOT
/// equivalent — it emits `+00:00` rather than `Z` and breaks
/// operator grep-correlation between the daemon's audit log and any
/// other timestamped source in the workspace.
#[must_use]
pub fn format_audit_timestamp(ts: chrono::DateTime<chrono::Utc>) -> String {
    ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Current audit event schema version. Bump on breaking changes.
///
/// # Version history
///
/// - **v1** (Epic 1): baseline schema with `extra.scrub_events` as a flat
///   `{rule_name: count}` map.
/// - **v2** (Story 2.6, 2026-04): `extra.scrub_events` restructured to
///   `{"summary": {rule: count, ...}, "samples": [ScrubSample, ...]}` to
///   support inline rendering of scrub events (the `ScrubInline` CLI
///   component). `summary` preserves the v1 counts; `samples` carries
///   pre-scrubbed contextual snippets for display. Reader code should
///   gate sample extraction on `schema_version >= 2`.
pub const AUDIT_SCHEMA_VERSION: u32 = 2;

/// A single audit log entry. Serialized as one JSONL line.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AuditEvent {
    /// RFC 3339 UTC with millisecond precision, Z suffix.
    pub timestamp: String,
    /// ULID request identifier (lexicographically sortable).
    pub request_id: String,
    /// Agent identity string.
    pub agent_id: String,
    /// Service name (e.g., "gmail").
    pub service: String,
    /// OAuth scope used.
    pub scope: String,
    /// Resource accessed (e.g., "messages/123" or "*").
    pub resource: String,
    /// Outcome: `"ok"`, `"denied"`, `"error"`, `"scrubbed"`, or the
    /// kill-switch-specific idempotent outcomes `"already-active"` and
    /// `"already-inactive"` (Story 3.3) emitted by `kill-activated` /
    /// `kill-resumed` events when the operator invoked kill/resume on
    /// a daemon that was already in the target state. Downstream
    /// grep-based audit consumers should match on all six.
    pub outcome: String,
    /// Kebab-case event type: "api-call", "token-refresh",
    /// "policy-violation", "scrub-event", "kill-activated".
    pub event_type: String,
    /// Schema version for forward compatibility.
    pub schema_version: u32,
    /// Extensible fields for future use (policy details, scrub counts, etc.).
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub extra: serde_json::Value,
}

impl AuditEvent {
    /// Create a new audit event with auto-populated timestamp, request_id,
    /// and schema_version.
    #[must_use]
    pub fn new(
        agent_id: String,
        service: String,
        scope: String,
        resource: String,
        outcome: String,
        event_type: String,
    ) -> Self {
        Self::with_request_id(
            ulid::Ulid::new().to_string(),
            agent_id,
            service,
            scope,
            resource,
            outcome,
            event_type,
        )
    }

    /// Create a new audit event with an explicit request_id (for correlating
    /// with proxy request traces).
    #[must_use]
    pub fn with_request_id(
        request_id: String,
        agent_id: String,
        service: String,
        scope: String,
        resource: String,
        outcome: String,
        event_type: String,
    ) -> Self {
        Self {
            timestamp: format_audit_timestamp(chrono::Utc::now()),
            request_id,
            agent_id,
            service,
            scope,
            resource,
            outcome,
            event_type,
            schema_version: AUDIT_SCHEMA_VERSION,
            extra: serde_json::Value::Null,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn serialize_deserialize_roundtrip() {
        let event = AuditEvent::new(
            "agent-1".into(),
            "gmail".into(),
            "mail.readonly".into(),
            "messages/123".into(),
            "ok".into(),
            "api-call".into(),
        );
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.agent_id, "agent-1");
        assert_eq!(deserialized.service, "gmail");
        assert_eq!(deserialized.scope, "mail.readonly");
        assert_eq!(deserialized.resource, "messages/123");
        assert_eq!(deserialized.outcome, "ok");
        assert_eq!(deserialized.event_type, "api-call");
        assert_eq!(deserialized.schema_version, AUDIT_SCHEMA_VERSION);
    }

    #[test]
    fn schema_version_matches_const() {
        let event = AuditEvent::new(
            "a".into(),
            "s".into(),
            "sc".into(),
            "r".into(),
            "ok".into(),
            "api-call".into(),
        );
        assert_eq!(event.schema_version, AUDIT_SCHEMA_VERSION);
    }

    #[test]
    fn event_type_is_kebab_case() {
        let valid_types =
            ["api-call", "token-refresh", "policy-violation", "scrub-event", "kill-activated"];
        for event_type in valid_types {
            assert!(
                event_type.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "event_type '{event_type}' is not kebab-case"
            );
        }
    }

    #[test]
    fn timestamp_is_rfc3339_with_z_suffix() {
        let event = AuditEvent::new(
            "a".into(),
            "s".into(),
            "sc".into(),
            "r".into(),
            "ok".into(),
            "api-call".into(),
        );
        assert!(event.timestamp.ends_with('Z'), "timestamp must end with Z: {}", event.timestamp);
        // Verify it parses as valid RFC 3339
        chrono::DateTime::parse_from_rfc3339(&event.timestamp)
            .expect("timestamp must parse as RFC 3339");
    }

    #[test]
    fn extra_null_is_omitted_from_json() {
        let event = AuditEvent::new(
            "a".into(),
            "s".into(),
            "sc".into(),
            "r".into(),
            "ok".into(),
            "api-call".into(),
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("\"extra\""), "null extra should be omitted: {json}");
    }

    #[test]
    fn extra_present_when_non_null() {
        let mut event = AuditEvent::new(
            "a".into(),
            "s".into(),
            "sc".into(),
            "r".into(),
            "ok".into(),
            "api-call".into(),
        );
        event.extra = serde_json::json!({"policy_id": "p-123"});
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"extra\""), "non-null extra should appear: {json}");
        let deserialized: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.extra["policy_id"], "p-123");
    }
}
