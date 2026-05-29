//! `#[derive(Deserialize)]` mirrors of the `/v1/control/*` response
//! bodies the read-only TUI consumes.
//!
//! The on-wire structs in `server/control.rs` are `pub(crate)` +
//! `Serialize`-only, so — exactly as `cli/agent.rs` and `cli/policy.rs`
//! already do — we mirror only the fields the UI renders. The mirrors
//! are deliberately *loose* (no `deny_unknown_fields`): a future daemon
//! that adds a field must not break an older `agentsso ui`.

use serde::Deserialize;

/// `GET /v1/control/state` — daemon liveness + kill-switch snapshot.
///
/// Mirrors `server::control::StateResponse`. Note `activated_at` is the
/// *kill-switch* activation time, NOT daemon start — there is no uptime
/// field in the control API (see the plan's "Status header" note).
#[derive(Debug, Clone, Deserialize)]
pub struct StateBody {
    pub active: bool,
    /// Kill-switch activation timestamp. Parsed from the wire for fidelity
    /// (and covered by the round-trip test) but not yet rendered — the
    /// header shows only the `active` state in slice 1.
    #[serde(default)]
    #[allow(dead_code)]
    pub activated_at: Option<String>,
    pub token_count: usize,
    pub daemon_version: String,
}

/// One element of `GET /v1/control/agent/list`.
///
/// Mirrors `server::control::AgentSummary`. `policy_name` is already
/// here — the TUI does NOT make a per-agent `policy_name` fetch.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentSummary {
    pub name: String,
    pub policy_name: String,
    pub created_at: String,
    #[serde(default)]
    pub last_seen_at: Option<String>,
}

/// One element of the `policies` array in `GET /v1/control/policies`.
///
/// Mirrors `server::control::PolicyListEntry`. `scopes` is inlined here,
/// so the agent detail pane resolves an agent's scopes via an in-memory
/// `policy_name -> scopes` lookup with no extra HTTP.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyListEntry {
    pub name: String,
    /// Filesystem path the policy was loaded from (NOT a managed/operator
    /// enum — slice 1 renders it as-is).
    pub origin: String,
    pub scopes: Vec<String>,
}

/// Envelope of `GET /v1/control/policies`.
#[derive(Debug, Clone, Deserialize)]
pub struct ListPoliciesBody {
    pub policies: Vec<PolicyListEntry>,
}

/// `GET /v1/control/policies/{name}` success body — TOML text, a
/// `[[policies]]` array with a single entry. Mirrors the relevant subset
/// of `permitlayer_core::policy::schema::TomlPolicyFile` / `TomlPolicy`.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyDetailBody {
    pub policies: Vec<PolicyDetail>,
}

/// One `[[policies]]` entry in the policy-detail TOML.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyDetail {
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub resources: Vec<String>,
    #[serde(rename = "approval-mode", default)]
    pub approval_mode: Option<String>,
    #[serde(default)]
    pub rules: Vec<PolicyDetailRule>,
}

/// One `[[policies.rules]]` entry, rendered compactly as `id → action`.
///
/// Per-rule `scopes`/`resources` overrides exist in the wire TOML but are
/// not surfaced in slice 1's compact detail; loose deserialize ignores
/// them. Add them back here if a future slice renders per-rule overrides.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyDetailRule {
    pub id: String,
    #[serde(default)]
    pub action: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn state_body_parses_minimal() {
        let body = r#"{"active":false,"token_count":3,"daemon_version":"1.0.0"}"#;
        let s: StateBody = serde_json::from_str(body).unwrap();
        assert!(!s.active);
        assert_eq!(s.token_count, 3);
        assert_eq!(s.daemon_version, "1.0.0");
        assert!(s.activated_at.is_none());
    }

    #[test]
    fn state_body_ignores_unknown_fields() {
        // A future daemon adding `uptime_secs` must not break an older UI.
        let body = r#"{"active":true,"activated_at":"2026-05-28T00:00:00Z","token_count":1,"daemon_version":"1.1.0","uptime_secs":42}"#;
        let s: StateBody = serde_json::from_str(body).unwrap();
        assert!(s.active);
        assert_eq!(s.activated_at.as_deref(), Some("2026-05-28T00:00:00Z"));
    }

    #[test]
    fn agent_list_parses() {
        let body = r#"[{"name":"calendar-bot","policy_name":"calendar-ro","created_at":"2026-05-01T00:00:00Z","last_seen_at":null}]"#;
        let agents: Vec<AgentSummary> = serde_json::from_str(body).unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].policy_name, "calendar-ro");
        assert!(agents[0].last_seen_at.is_none());
    }

    #[test]
    fn policies_list_parses() {
        let body = r#"{"status":"ok","policies":[{"name":"calendar-ro","origin":"/etc/agentsso/policies/managed/calendar-ro.toml","scopes":["https://www.googleapis.com/auth/calendar.readonly"]}]}"#;
        let list: ListPoliciesBody = serde_json::from_str(body).unwrap();
        assert_eq!(list.policies.len(), 1);
        assert_eq!(list.policies[0].scopes.len(), 1);
    }

    #[test]
    fn policy_detail_toml_parses() {
        let toml_text = r#"
[[policies]]
name = "calendar-ro"
scopes = ["https://www.googleapis.com/auth/calendar.readonly"]
resources = ["*"]
approval-mode = "auto"

[[policies.rules]]
id = "allow-reads"
action = "allow"
"#;
        let detail: PolicyDetailBody = toml::from_str(toml_text).unwrap();
        assert_eq!(detail.policies.len(), 1);
        let p = &detail.policies[0];
        assert_eq!(p.name, "calendar-ro");
        assert_eq!(p.approval_mode.as_deref(), Some("auto"));
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.rules[0].id, "allow-reads");
    }
}
