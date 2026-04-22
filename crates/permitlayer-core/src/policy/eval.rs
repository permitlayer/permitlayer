//! Evaluation inputs and outputs.
//!
//! The `PolicySet::evaluate` implementation itself lives in `compile.rs`
//! (next to the IR it walks). This file owns the public contract the
//! caller sees: the request shape [`EvalRequest`], the decision shape
//! [`Decision`], and the approval-mode enum [`ApprovalMode`] that
//! Stories 4.3 and 4.5 switch on.
//!
//! These types are deliberately free of `permitlayer-proxy` — the
//! dependency direction rule (`proxy → core`, never reverse) forbids
//! `permitlayer-core` from knowing what a `ProxyRequest` is. Story 4.3
//! will add the adapter inside `permitlayer_proxy::middleware::policy`.

/// Input to [`super::PolicySet::evaluate`].
///
/// The caller (Story 4.3's `PolicyLayer`) builds this from the
/// authenticated request: it already knows which policy the agent
/// is bound to (via Story 4.4's identity registry), which scope the
/// request targets, and which resource — if any — it touches.
#[derive(Debug, Clone)]
pub struct EvalRequest {
    /// The policy this agent is bound to. Resolved by Story 4.4's
    /// agent-identity registry before policy evaluation. Owned
    /// `String` (not `&str`) because Story 4.4 will produce it from
    /// a registry lookup, not a zero-copy header slice.
    pub policy_name: String,
    /// The OAuth scope the request targets (e.g., `gmail.readonly`).
    pub scope: String,
    /// The resource identifier the request targets, when one applies
    /// (e.g., `primary` for the primary calendar). `None` means the
    /// request has no resource dimension to evaluate.
    pub resource: Option<String>,
}

/// Outcome of a policy evaluation.
///
/// `#[non_exhaustive]` so Stories 4.2-4.5 can add variants (e.g., a
/// `RateLimit` variant for Epic 5's per-policy rate limits) without
/// a breaking change. Callers must have a wildcard arm.
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize)]
#[non_exhaustive]
#[serde(tag = "decision", rename_all = "lowercase")]
pub enum Decision {
    /// Request passes policy evaluation. The caller should continue
    /// down the middleware chain.
    Allow,

    /// Request is blocked and a human operator must approve it
    /// before it can proceed. Story 4.5 builds the TTY prompt that
    /// consumes this variant.
    Prompt {
        /// Name of the policy that produced the prompt decision.
        policy_name: String,
        /// Stable string ID of the rule that triggered the prompt,
        /// or `"default-prompt-approval-mode"` if the decision came
        /// from the policy-level `approval-mode = "prompt"` default.
        rule_id: String,
    },

    /// Request is denied. The caller (Story 4.3's `PolicyLayer`)
    /// returns HTTP 403 with a body built from these fields.
    Deny {
        /// Name of the policy that produced the denial.
        policy_name: String,
        /// Stable string ID of the rule that produced the denial.
        /// Default-deny fallbacks use one of these well-known IDs:
        /// - `"default-deny-unmatched-policy"` — agent bound to a
        ///   policy name that is not present in the `PolicySet`.
        /// - `"default-deny-scope-out-of-allowlist"` — scope not
        ///   listed in the policy's `scopes = [...]` allowlist.
        /// - `"default-deny-resource-out-of-allowlist"` — resource
        ///   not listed in the policy's `resources = [...]` allowlist.
        rule_id: String,
        /// The scope that was denied, when the denial was scope-driven.
        denied_scope: Option<String>,
        /// The resource that was denied, when the denial was resource-driven.
        denied_resource: Option<String>,
    },
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Prompt { policy_name, rule_id } => {
                write!(f, "prompt policy={policy_name} rule={rule_id}")
            }
            Self::Deny { policy_name, rule_id, denied_scope, denied_resource } => {
                write!(f, "deny policy={policy_name} rule={rule_id}")?;
                if let Some(s) = denied_scope {
                    write!(f, " scope={s}")?;
                }
                if let Some(r) = denied_resource {
                    write!(f, " resource={r}")?;
                }
                Ok(())
            }
        }
    }
}

/// Policy-level approval disposition, as compiled into the IR.
///
/// This is the compiled counterpart to `schema::TomlApprovalMode` — it
/// lives here (rather than `schema.rs`) because the IR consumes it but
/// not the schema layer. Story 4.5 consumes the `Prompt` variant at
/// runtime to decide whether to show a TTY prompt.
#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalMode {
    /// Auto-approve everything the rules and allowlists let through.
    Auto,
    /// Prompt the operator for every fall-through request.
    Prompt,
    /// Deny every fall-through request. A policy-wide deny stance is
    /// almost always wrong — most use cases want `Auto` with explicit
    /// deny rules — but the variant exists so `approval-mode = "deny"`
    /// in TOML round-trips faithfully.
    Deny,
}

impl From<super::schema::TomlApprovalMode> for ApprovalMode {
    fn from(v: super::schema::TomlApprovalMode) -> Self {
        match v {
            super::schema::TomlApprovalMode::Auto => Self::Auto,
            super::schema::TomlApprovalMode::Prompt => Self::Prompt,
            super::schema::TomlApprovalMode::Deny => Self::Deny,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn decision_display_allow() {
        assert_eq!(Decision::Allow.to_string(), "allow");
    }

    #[test]
    fn decision_display_prompt() {
        let d = Decision::Prompt { policy_name: "p".to_owned(), rule_id: "r".to_owned() };
        assert_eq!(d.to_string(), "prompt policy=p rule=r");
    }

    #[test]
    fn decision_display_deny_full() {
        let d = Decision::Deny {
            policy_name: "p".to_owned(),
            rule_id: "r".to_owned(),
            denied_scope: Some("gmail.modify".to_owned()),
            denied_resource: Some("primary".to_owned()),
        };
        assert_eq!(d.to_string(), "deny policy=p rule=r scope=gmail.modify resource=primary");
    }

    #[test]
    fn decision_display_deny_scope_only() {
        let d = Decision::Deny {
            policy_name: "p".to_owned(),
            rule_id: "r".to_owned(),
            denied_scope: Some("gmail.modify".to_owned()),
            denied_resource: None,
        };
        assert_eq!(d.to_string(), "deny policy=p rule=r scope=gmail.modify");
    }

    #[test]
    fn approval_mode_from_toml() {
        use super::super::schema::TomlApprovalMode;
        assert_eq!(ApprovalMode::from(TomlApprovalMode::Auto), ApprovalMode::Auto);
        assert_eq!(ApprovalMode::from(TomlApprovalMode::Prompt), ApprovalMode::Prompt);
        assert_eq!(ApprovalMode::from(TomlApprovalMode::Deny), ApprovalMode::Deny);
    }
}
