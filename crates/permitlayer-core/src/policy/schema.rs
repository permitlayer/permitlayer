//! TOML schema types for policy files.
//!
//! These types are the raw deserialization target — they match the
//! user-facing TOML byte-for-byte. `compile.rs` walks the parsed tree
//! and produces the runtime `PolicySet` IR. Keep semantics OUT of
//! this file; it should be pure `#[derive(serde::Deserialize)]` shape.
//!
//! # Conventions
//!
//! - Every struct sets `#[serde(deny_unknown_fields)]` so typos in
//!   user TOML fail loudly rather than being silently ignored. This
//!   is the fail-fast half of AC #2.
//! - Keys are kebab-case in TOML (AR28) but `snake_case` in Rust,
//!   bridged per-field via `#[serde(rename = "kebab-name")]`.
//! - Enums use `#[serde(rename_all = "kebab-case")]` + lowercase
//!   string discriminants — TOML users write `approval-mode = "auto"`,
//!   not `ApprovalMode::Auto`.

use serde::Deserialize;

/// Top-level deserialization target for a single `*.toml` file.
///
/// A file MUST contain at least one `[[policies]]` entry; the empty
/// case surfaces as [`super::PolicyCompileError::EmptyPoliciesArray`]
/// during compile, not a parser rejection here.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TomlPolicyFile {
    /// Array of `[[policies]]` table entries.
    pub policies: Vec<TomlPolicy>,
}

/// One `[[policies]]` entry.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TomlPolicy {
    /// Stable identifier used to bind agents to this policy
    /// (see Epic 4 Story 4.4). Must be unique within the entire
    /// `~/.agentsso/policies/` directory.
    pub name: String,

    /// Scope allowlist. Any OAuth scope NOT listed here is denied
    /// by the default-deny fallback (FR48). An empty allowlist
    /// surfaces as `EmptyScopesAllowlist` during compile — if you
    /// really want "deny everything" use `approval-mode = "deny"`
    /// with an explicit rule.
    pub scopes: Vec<String>,

    /// Resource allowlist. `["*"]` means "match any resource".
    /// Explicit values match exactly (`["primary"]` matches only
    /// the primary calendar). Glob syntax is deferred to a future
    /// story per Story 4.1 Dev Notes (§Resource matcher design).
    pub resources: Vec<String>,

    /// Default approval disposition for requests that match the
    /// policy's scope/resource allowlists but do not match any
    /// explicit rule.
    #[serde(rename = "approval-mode")]
    pub approval_mode: TomlApprovalMode,

    /// Per-rule overrides. Rules are evaluated in declaration order;
    /// the first rule whose scopes AND resources match wins.
    #[serde(default)]
    pub rules: Vec<TomlRule>,

    /// Positive-framed flag (AR28): when true, all rules whose
    /// scope overrides are empty or absent and whose action is
    /// `prompt` are upgraded to `allow` for requests where the
    /// scope matches a read-style scope (ends in `.readonly` or
    /// `.metadata`).
    ///
    /// Story 4.1 stores the flag but does not yet consume it in
    /// the evaluator — Story 4.5 (approval prompts) owns the
    /// runtime behavior. The flag is schema-validated here so the
    /// field is not an "unknown key" trigger.
    #[serde(rename = "auto-approve-reads", default)]
    pub auto_approve_reads: bool,
}

/// Approval dispositions available at the policy and rule level.
///
/// These values appear verbatim in user-written TOML:
/// `approval-mode = "auto"` / `"prompt"` / `"deny"`.
#[derive(Debug, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TomlApprovalMode {
    /// Request is allowed without prompting the operator.
    Auto,
    /// Request is blocked pending an operator decision (Story 4.5).
    Prompt,
    /// Request is denied unconditionally. HTTP 403 `policy_violation`.
    Deny,
}

/// One `[[policies.rules]]` entry.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TomlRule {
    /// Stable string identifier. Appears in HTTP 403 response bodies
    /// so operators can grep their policy file for it (UX-DR21).
    /// Must be unique within the enclosing policy.
    pub id: String,

    /// If present, overrides the policy-level scope allowlist for
    /// matching purposes. Absent means "inherit the policy's scopes".
    #[serde(default)]
    pub scopes: Option<Vec<String>>,

    /// If present, overrides the policy-level resource allowlist.
    #[serde(default)]
    pub resources: Option<Vec<String>>,

    /// What happens when this rule matches. Narrower than policy-level
    /// approval mode because a rule exists to carve an exception out
    /// of the policy defaults.
    pub action: TomlRuleAction,
}

/// Rule-level actions. Superset of `TomlApprovalMode` so rules can
/// express explicit `allow` (which the policy-level field cannot —
/// a policy's default is either auto, prompt, or deny, not allow).
#[derive(Debug, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TomlRuleAction {
    /// Explicitly allow requests matching this rule (used to carve
    /// exceptions out of an otherwise prompt/deny policy).
    Allow,
    /// Explicitly block and require operator approval.
    Prompt,
    /// Explicitly deny. Takes precedence over any broader allow.
    Deny,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_policy() {
        let src = r#"
            [[policies]]
            name = "gmail-read-only"
            scopes = ["gmail.readonly"]
            resources = ["*"]
            approval-mode = "auto"
        "#;
        let parsed: TomlPolicyFile = toml::from_str(src).unwrap();
        assert_eq!(parsed.policies.len(), 1);
        let p = &parsed.policies[0];
        assert_eq!(p.name, "gmail-read-only");
        assert_eq!(p.scopes, vec!["gmail.readonly".to_string()]);
        assert_eq!(p.resources, vec!["*".to_string()]);
        assert_eq!(p.approval_mode, TomlApprovalMode::Auto);
        assert!(p.rules.is_empty());
        assert!(!p.auto_approve_reads);
    }

    #[test]
    fn parses_policy_with_rules() {
        let src = r#"
            [[policies]]
            name = "calendar-prompt-on-write"
            scopes = ["calendar.readonly", "calendar.events"]
            resources = ["primary"]
            approval-mode = "prompt"
            auto-approve-reads = true

            [[policies.rules]]
            id = "deny-delete-events"
            action = "deny"

            [[policies.rules]]
            id = "allow-read-events"
            scopes = ["calendar.readonly"]
            action = "allow"
        "#;
        let parsed: TomlPolicyFile = toml::from_str(src).unwrap();
        assert_eq!(parsed.policies.len(), 1);
        let p = &parsed.policies[0];
        assert!(p.auto_approve_reads);
        assert_eq!(p.rules.len(), 2);
        assert_eq!(p.rules[0].id, "deny-delete-events");
        assert_eq!(p.rules[0].action, TomlRuleAction::Deny);
        assert!(p.rules[0].scopes.is_none());
        assert_eq!(p.rules[1].id, "allow-read-events");
        assert_eq!(p.rules[1].action, TomlRuleAction::Allow);
        assert_eq!(p.rules[1].scopes.as_deref(), Some(&["calendar.readonly".to_string()][..]));
    }

    #[test]
    fn parses_multiple_policies_in_one_file() {
        let src = r#"
            [[policies]]
            name = "a"
            scopes = ["x.read"]
            resources = ["*"]
            approval-mode = "auto"

            [[policies]]
            name = "b"
            scopes = ["y.read"]
            resources = ["*"]
            approval-mode = "deny"
        "#;
        let parsed: TomlPolicyFile = toml::from_str(src).unwrap();
        assert_eq!(parsed.policies.len(), 2);
        assert_eq!(parsed.policies[0].name, "a");
        assert_eq!(parsed.policies[1].approval_mode, TomlApprovalMode::Deny);
    }

    #[test]
    fn parses_empty_policies_array() {
        // Structurally valid TOML — semantic rejection happens in compile.
        let src = "policies = []";
        let parsed: TomlPolicyFile = toml::from_str(src).unwrap();
        assert!(parsed.policies.is_empty());
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        let src = r#"
            policies = []
            extra = "oops"
        "#;
        let err = toml::from_str::<TomlPolicyFile>(src).unwrap_err();
        assert!(err.to_string().contains("extra"), "error: {err}");
    }

    #[test]
    fn rejects_unknown_policy_key() {
        let src = r#"
            [[policies]]
            name = "a"
            scopes = ["x.read"]
            resources = ["*"]
            approval-mode = "auto"
            description = "oops"
        "#;
        let err = toml::from_str::<TomlPolicyFile>(src).unwrap_err();
        assert!(err.to_string().contains("description"), "error: {err}");
    }

    #[test]
    fn rejects_unknown_rule_key() {
        let src = r#"
            [[policies]]
            name = "a"
            scopes = ["x.read"]
            resources = ["*"]
            approval-mode = "auto"

            [[policies.rules]]
            id = "r1"
            action = "deny"
            description = "oops"
        "#;
        let err = toml::from_str::<TomlPolicyFile>(src).unwrap_err();
        assert!(err.to_string().contains("description"), "error: {err}");
    }

    #[test]
    fn rejects_uppercase_approval_mode() {
        let src = r#"
            [[policies]]
            name = "a"
            scopes = ["x.read"]
            resources = ["*"]
            approval-mode = "AUTO"
        "#;
        let err = toml::from_str::<TomlPolicyFile>(src).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("auto"), "error: {err}");
    }

    #[test]
    fn rejects_bogus_approval_mode_variant() {
        let src = r#"
            [[policies]]
            name = "a"
            scopes = ["x.read"]
            resources = ["*"]
            approval-mode = "maybe"
        "#;
        let err = toml::from_str::<TomlPolicyFile>(src).unwrap_err();
        assert!(err.to_string().contains("maybe"), "error: {err}");
    }

    #[test]
    fn rejects_snake_case_approval_mode_key() {
        // AR28 mandates kebab-case — snake_case is rejected by serde
        // because the Rust-side field uses `#[serde(rename = "approval-mode")]`.
        let src = r#"
            [[policies]]
            name = "a"
            scopes = ["x.read"]
            resources = ["*"]
            approval_mode = "auto"
        "#;
        let err = toml::from_str::<TomlPolicyFile>(src).unwrap_err();
        // `deny_unknown_fields` reports it as an unknown key; good enough.
        assert!(err.to_string().contains("approval_mode"), "error: {err}");
    }

    #[test]
    fn rejects_missing_required_policy_fields() {
        // Missing `resources`.
        let src = r#"
            [[policies]]
            name = "a"
            scopes = ["x.read"]
            approval-mode = "auto"
        "#;
        let err = toml::from_str::<TomlPolicyFile>(src).unwrap_err();
        assert!(err.to_string().contains("resources"), "error: {err}");
    }

    #[test]
    fn rejects_missing_rule_id() {
        let src = r#"
            [[policies]]
            name = "a"
            scopes = ["x.read"]
            resources = ["*"]
            approval-mode = "auto"

            [[policies.rules]]
            action = "deny"
        "#;
        let err = toml::from_str::<TomlPolicyFile>(src).unwrap_err();
        assert!(err.to_string().contains("id"), "error: {err}");
    }

    #[test]
    fn auto_approve_reads_defaults_to_false() {
        let src = r#"
            [[policies]]
            name = "a"
            scopes = ["x.read"]
            resources = ["*"]
            approval-mode = "auto"
        "#;
        let parsed: TomlPolicyFile = toml::from_str(src).unwrap();
        assert!(!parsed.policies[0].auto_approve_reads);
    }

    #[test]
    fn rule_action_prompt_roundtrips() {
        let src = r#"
            [[policies]]
            name = "a"
            scopes = ["x.read"]
            resources = ["*"]
            approval-mode = "auto"

            [[policies.rules]]
            id = "r1"
            action = "prompt"
        "#;
        let parsed: TomlPolicyFile = toml::from_str(src).unwrap();
        assert_eq!(parsed.policies[0].rules[0].action, TomlRuleAction::Prompt);
    }
}
