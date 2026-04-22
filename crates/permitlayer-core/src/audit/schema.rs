//! Snapshot test for the audit event JSON schema.
//!
//! The `insta` snapshot guards against accidental schema changes (NFR43).
//! Any field addition, removal, or rename will fail this test, forcing
//! a conscious `cargo insta review` to accept the change.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use crate::audit::event::{AUDIT_SCHEMA_VERSION, AuditEvent};

    #[test]
    fn audit_event_json_schema_snapshot() {
        // Canonical event with deterministic values for snapshot stability.
        let event = AuditEvent {
            timestamp: "2026-01-15T10:30:45.123Z".into(),
            request_id: "01JQXK5V7R000000000000000".into(),
            agent_id: "agent-test-001".into(),
            service: "gmail".into(),
            scope: "mail.readonly".into(),
            resource: "messages/abc123".into(),
            outcome: "ok".into(),
            event_type: "api-call".into(),
            schema_version: AUDIT_SCHEMA_VERSION,
            extra: serde_json::Value::Null,
        };
        insta::assert_json_snapshot!("audit_event_v2", event);
    }

    // ---------------------------------------------------------------------
    //
    // Story 3.3: snapshot tests for the three new kill-switch event types.
    //
    // These events are v2-compatible — `event_type` is a free-form String
    // and `extra` is `serde_json::Value`, so new event types add zero
    // schema pressure. A v2 reader that doesn't understand the event_type
    // will simply render it as a generic v2 event (Story 5.2's follow-up
    // audit reader UX).
    //
    // ---------------------------------------------------------------------

    fn kill_activated_canonical() -> AuditEvent {
        let mut event = AuditEvent {
            timestamp: "2026-04-11T18:54:48.832Z".into(),
            request_id: "01JQXK5V7R000000000000001".into(),
            agent_id: "system".into(),
            service: "permitlayer".into(),
            scope: "-".into(),
            resource: "kill-switch".into(),
            outcome: "ok".into(),
            event_type: "kill-activated".into(),
            schema_version: AUDIT_SCHEMA_VERSION,
            extra: serde_json::Value::Null,
        };
        event.extra = serde_json::json!({
            "activated_at": "2026-04-11T18:54:48.832Z",
            "cause": "user-initiated",
            "tokens_invalidated": 0,
            "in_flight_cancelled": 0,
            "was_already_active": false,
        });
        event
    }

    fn kill_resumed_canonical() -> AuditEvent {
        let mut event = AuditEvent {
            timestamp: "2026-04-11T18:54:48.859Z".into(),
            request_id: "01JQXK5V7R000000000000002".into(),
            agent_id: "system".into(),
            service: "permitlayer".into(),
            scope: "-".into(),
            resource: "kill-switch".into(),
            outcome: "ok".into(),
            event_type: "kill-resumed".into(),
            schema_version: AUDIT_SCHEMA_VERSION,
            extra: serde_json::Value::Null,
        };
        event.extra = serde_json::json!({
            "resumed_at": "2026-04-11T18:54:48.859Z",
            "duration_killed_seconds": 0,
            "was_already_inactive": false,
        });
        event
    }

    fn kill_blocked_request_canonical() -> AuditEvent {
        let mut event = AuditEvent {
            timestamp: "2026-04-11T18:54:48.840Z".into(),
            request_id: "01JQXK5V7R000000000000003".into(),
            agent_id: "unknown".into(),
            service: "gmail".into(),
            scope: "-".into(),
            resource: "/v1/tools/gmail/users/me/profile".into(),
            outcome: "denied".into(),
            event_type: "kill-blocked-request".into(),
            schema_version: AUDIT_SCHEMA_VERSION,
            extra: serde_json::Value::Null,
        };
        event.extra = serde_json::json!({
            "error_code": "daemon_killed",
            "activated_at": "2026-04-11T18:54:48.832Z",
            "method": "GET",
            "host": "127.0.0.1:3820",
        });
        event
    }

    #[test]
    fn kill_activated_event_v2_schema_snapshot() {
        insta::assert_json_snapshot!("kill_activated_v2", kill_activated_canonical());
    }

    #[test]
    fn kill_resumed_event_v2_schema_snapshot() {
        insta::assert_json_snapshot!("kill_resumed_v2", kill_resumed_canonical());
    }

    #[test]
    fn kill_blocked_request_event_v2_schema_snapshot() {
        insta::assert_json_snapshot!("kill_blocked_request_v2", kill_blocked_request_canonical());
    }

    /// Reader-side fallback discipline (Epic 2 retro / Story 2.6):
    /// hand-craft raw JSON bytes for each new event type and assert that
    /// a v2 reader can deserialize them into `AuditEvent` cleanly. This
    /// proves the new event types are v2-compatible without needing a
    /// v3 schema bump.
    ///
    /// **Load-bearing:** if a future change accidentally breaks v2
    /// compatibility (e.g., by adding a required non-optional field to
    /// `AuditEvent`), this test fails loudly.
    #[test]
    fn v2_reader_accepts_kill_event_types_without_schema_bump() {
        let cases = [
            // kill-activated — hand-crafted, not round-tripped
            r#"{
                "timestamp": "2026-04-11T18:54:48.832Z",
                "request_id": "01JQXK5V7R000000000000001",
                "agent_id": "system",
                "service": "permitlayer",
                "scope": "-",
                "resource": "kill-switch",
                "outcome": "ok",
                "event_type": "kill-activated",
                "schema_version": 2,
                "extra": {
                    "activated_at": "2026-04-11T18:54:48.832Z",
                    "cause": "user-initiated",
                    "tokens_invalidated": 3,
                    "in_flight_cancelled": 0,
                    "was_already_active": false
                }
            }"#,
            // kill-resumed
            r#"{
                "timestamp": "2026-04-11T18:54:48.859Z",
                "request_id": "01JQXK5V7R000000000000002",
                "agent_id": "system",
                "service": "permitlayer",
                "scope": "-",
                "resource": "kill-switch",
                "outcome": "ok",
                "event_type": "kill-resumed",
                "schema_version": 2,
                "extra": {
                    "resumed_at": "2026-04-11T18:54:48.859Z",
                    "duration_killed_seconds": 12,
                    "was_already_inactive": false
                }
            }"#,
            // kill-blocked-request
            r#"{
                "timestamp": "2026-04-11T18:54:48.840Z",
                "request_id": "01JQXK5V7R000000000000003",
                "agent_id": "unknown",
                "service": "gmail",
                "scope": "-",
                "resource": "/v1/tools/gmail/users/me/profile",
                "outcome": "denied",
                "event_type": "kill-blocked-request",
                "schema_version": 2,
                "extra": {
                    "error_code": "daemon_killed",
                    "activated_at": "2026-04-11T18:54:48.832Z",
                    "method": "GET",
                    "host": "127.0.0.1:3820"
                }
            }"#,
        ];
        for (i, json) in cases.iter().enumerate() {
            let event: AuditEvent = serde_json::from_str(json)
                .unwrap_or_else(|e| panic!("case {i} failed to deserialize: {e}\njson: {json}"));
            assert_eq!(event.schema_version, 2);
            // Sanity check: extra is present and non-null.
            assert!(!event.extra.is_null(), "case {i}: extra should not be null for kill events");
        }
    }

    /// Round-trip test: each event type must survive serialize →
    /// deserialize with all fields intact, including the `extra`
    /// `serde_json::Value` shape.
    #[test]
    fn kill_activated_event_round_trips() {
        let event = kill_activated_canonical();
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.event_type, "kill-activated");
        assert_eq!(deserialized.agent_id, "system");
        assert_eq!(deserialized.service, "permitlayer");
        assert_eq!(deserialized.scope, "-");
        assert_eq!(deserialized.resource, "kill-switch");
        assert_eq!(deserialized.outcome, "ok");
        assert_eq!(deserialized.extra["cause"], "user-initiated");
        assert_eq!(deserialized.extra["tokens_invalidated"], 0);
        assert_eq!(deserialized.extra["in_flight_cancelled"], 0);
        assert_eq!(deserialized.extra["was_already_active"], false);
        assert_eq!(deserialized.extra["activated_at"], "2026-04-11T18:54:48.832Z");
    }

    #[test]
    fn kill_resumed_event_round_trips() {
        let event = kill_resumed_canonical();
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.event_type, "kill-resumed");
        assert_eq!(deserialized.agent_id, "system");
        assert_eq!(deserialized.extra["duration_killed_seconds"], 0);
        assert_eq!(deserialized.extra["was_already_inactive"], false);
    }

    #[test]
    fn kill_blocked_request_event_round_trips() {
        let event = kill_blocked_request_canonical();
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.event_type, "kill-blocked-request");
        assert_eq!(deserialized.agent_id, "unknown");
        assert_eq!(deserialized.service, "gmail");
        assert_eq!(deserialized.resource, "/v1/tools/gmail/users/me/profile");
        assert_eq!(deserialized.outcome, "denied");
        assert_eq!(deserialized.extra["error_code"], "daemon_killed");
        assert_eq!(deserialized.extra["method"], "GET");
        assert_eq!(deserialized.extra["host"], "127.0.0.1:3820");
    }
}
