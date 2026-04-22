//! Errors produced by the policy compile pipeline.
//!
//! Every structural or semantic defect in a `~/.agentsso/policies/*.toml`
//! file surfaces through `PolicyCompileError`. The daemon renders this to
//! a multi-line diagnostic at startup (fail-fast per FR15), so every
//! variant carries enough context — file path and (when the parser
//! provides it) line number — to point a human editor at the exact
//! location that needs fixing.
//!
//! `toml::de::Error` is carried via `#[source]` rather than stringified,
//! so downstream callers can still walk the error chain if they need the
//! raw parser detail.

use std::path::PathBuf;

/// Defects detected while loading and compiling a policy TOML file.
///
/// The daemon fails fast on any of these at startup. Every variant is
/// constructed at a single call site inside `compile.rs` or `schema.rs`
/// — grep for the variant name to find the site that produces it.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum PolicyCompileError {
    /// Filesystem error reading a policy file or the policies directory.
    ///
    /// Typically surfaces for permission problems (`~/.agentsso/policies`
    /// not readable by the daemon user) or vanished files (a file listed
    /// by `read_dir` but deleted before we could `read_to_string` it).
    #[error("failed to read policy file {path}")]
    Io {
        /// The file or directory that failed the read.
        path: PathBuf,
        /// The underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The policies directory path exists but points at something that
    /// is not a directory (a regular file or a symlink to a file).
    ///
    /// This is distinct from `Io` because the OS-level error produced
    /// by `read_dir` on a non-directory path is cryptic ("Not a
    /// directory (os error 20)"); the dedicated variant lets the
    /// renderer emit a clearer fix hint.
    #[error("policies path {path} is not a directory")]
    NotADirectory {
        /// The path that was expected to be a directory.
        path: PathBuf,
    },

    /// TOML failed to parse or deserialize into the schema types.
    ///
    /// `line` is populated from `toml::de::Error::span()` when the
    /// parser reports a span. `message` is the parser's own description
    /// of the defect. The rendered diagnostic is `path:line: message`.
    #[error("{path}: parse error: {message}")]
    Parse {
        /// The file that contained the invalid TOML.
        path: PathBuf,
        /// 1-based line number of the error, if the parser reported a span.
        line: Option<usize>,
        /// Human-readable reason — the parser's own message.
        message: String,
    },

    /// A policy file parsed successfully but contained zero `[[policies]]`
    /// entries. Empty files are almost certainly a mistake; flag them.
    #[error("{path}: contains zero [[policies]] entries")]
    EmptyPoliciesArray {
        /// The file that held the empty array.
        path: PathBuf,
    },

    /// Two policies in different files share the same `name`. Policy
    /// names are the public identifier agents are bound to — duplicates
    /// would make agent-to-policy mapping ambiguous.
    #[error("duplicate policy name {name:?}: first defined in {first}, redefined in {second}")]
    DuplicatePolicyName {
        /// The duplicated name.
        name: String,
        /// The file that first declared the name.
        first: PathBuf,
        /// The file that redeclared it.
        second: PathBuf,
    },

    /// Two `[[policies]]` entries within a single TOML file share the
    /// same `name`. Distinct from `DuplicatePolicyName` which covers
    /// the cross-file case.
    #[error("duplicate policy name {name:?} defined twice in {path}")]
    DuplicatePolicyNameInFile {
        /// The duplicated name.
        name: String,
        /// The file that contains both definitions.
        path: PathBuf,
    },

    /// Two rules within a single policy share the same `id`. Rule IDs
    /// appear verbatim in HTTP 403 response bodies (UX-DR21), so they
    /// MUST be unique within a policy — otherwise clients cannot tell
    /// which rule denied them.
    #[error("duplicate rule id {rule_id:?} in policy {policy:?} ({path})")]
    DuplicateRuleId {
        /// The policy that contained the duplicate rule.
        policy: String,
        /// The rule ID that was repeated.
        rule_id: String,
        /// The file that held the policy.
        path: PathBuf,
    },

    /// A policy shipped with an empty `scopes = []` allowlist. An empty
    /// allowlist denies every scope, which is certainly a mistake (the
    /// policy couldn't allow anything). If you really mean default-deny,
    /// use `approval-mode = "deny"` explicitly.
    #[error("policy {policy:?} has empty scopes allowlist ({path})")]
    EmptyScopesAllowlist {
        /// The offending policy name.
        policy: String,
        /// The file that held the policy.
        path: PathBuf,
    },

    /// A policy shipped with an empty `resources = []` allowlist.
    /// Symmetric to `EmptyScopesAllowlist`: every request would be
    /// denied with `default-deny-resource-out-of-allowlist`. Almost
    /// certainly a mistake. Use `resources = ["*"]` for "any resource".
    #[error("policy {policy:?} has empty resources allowlist ({path})")]
    EmptyResourcesAllowlist {
        /// The offending policy name.
        policy: String,
        /// The file that held the policy.
        path: PathBuf,
    },

    /// A rule shipped with an empty `scopes = []` override. The rule
    /// would never match (every scope lookup would miss the empty
    /// set), making it dead code. Operators meaning "inherit policy
    /// scopes" should omit the key entirely.
    #[error(
        "rule {rule_id:?} in policy {policy:?} has empty scopes override (would never match) ({path})"
    )]
    EmptyRuleScopesOverride {
        /// The enclosing policy name.
        policy: String,
        /// The rule ID.
        rule_id: String,
        /// The file that held the policy.
        path: PathBuf,
    },

    /// A rule shipped with an empty `resources = []` override. Same
    /// reasoning as `EmptyRuleScopesOverride`: the rule would never
    /// match. Use `resources = ["*"]` for "match any resource" or
    /// omit the key to inherit the policy's resource allowlist.
    #[error(
        "rule {rule_id:?} in policy {policy:?} has empty resources override (would never match) ({path})"
    )]
    EmptyRuleResourcesOverride {
        /// The enclosing policy name.
        policy: String,
        /// The rule ID.
        rule_id: String,
        /// The file that held the policy.
        path: PathBuf,
    },

    /// A rule's `scopes = [...]` override contains a scope that is NOT
    /// in the enclosing policy's scope allowlist. Without this check
    /// a rule with `action = "allow"` could silently widen the policy
    /// (defeat FR48 default-deny).
    #[error(
        "rule {rule_id:?} in policy {policy:?} references scope {scope:?} that is not in the policy scope allowlist ({path})"
    )]
    RuleScopeWidensPolicyAllowlist {
        /// The enclosing policy name.
        policy: String,
        /// The rule ID.
        rule_id: String,
        /// The offending scope that is not in the policy allowlist.
        scope: String,
        /// The file that held the policy.
        path: PathBuf,
    },

    /// A rule's `resources = [...]` override contains a resource that
    /// is NOT in the enclosing policy's resource allowlist (and the
    /// policy is not a wildcard). Symmetric to
    /// `RuleScopeWidensPolicyAllowlist`.
    ///
    /// Checked only when the policy uses an explicit `Allowlist`.
    /// Policy-level `resources = ["*"]` allows any rule resource to
    /// pass through this check (the policy is already wide open).
    #[error(
        "rule {rule_id:?} in policy {policy:?} references resource {resource:?} that is not in the policy resource allowlist ({path})"
    )]
    RuleResourceWidensPolicyAllowlist {
        /// The enclosing policy name.
        policy: String,
        /// The rule ID.
        rule_id: String,
        /// The offending resource that is not in the policy allowlist.
        resource: String,
        /// The file that held the policy.
        path: PathBuf,
    },

    /// A rule (or policy) later in the evaluation order is fully
    /// shadowed by an earlier rule. The later rule can never fire,
    /// which is almost always a mistake — either an ordering bug or
    /// a typo on the earlier rule's scopes/resources.
    ///
    /// Emitted only when the shadow is total (both scopes AND
    /// resources of the later rule are subsets of the earlier rule's
    /// effective match set). Partial overlaps are not flagged.
    #[error(
        "rule {later_rule_id:?} in policy {policy:?} is fully shadowed by earlier rule {earlier_rule_id:?} ({path})"
    )]
    ShadowedRule {
        /// The enclosing policy name.
        policy: String,
        /// The earlier rule that shadows.
        earlier_rule_id: String,
        /// The later rule that is unreachable.
        later_rule_id: String,
        /// The file that held the policy.
        path: PathBuf,
    },

    /// A policy file starts with a UTF-8 BOM (`\xEF\xBB\xBF`).
    ///
    /// TOML parsers do not strip the BOM and instead emit a cryptic
    /// parse error. Detecting the BOM before the TOML parser runs
    /// lets the daemon emit a clear remediation pointing at the
    /// editor's "UTF-8 without BOM" encoding setting.
    #[error("policy file starts with a UTF-8 BOM; save without BOM: {path}")]
    BomDetected {
        /// The file that contained the BOM.
        path: PathBuf,
    },

    /// A scope string failed the structural validator (see
    /// `compile::validate_scope_format`). Scopes must be non-empty,
    /// lowercase alphanumeric + `.` or `-`, max 128 chars, no leading
    /// or trailing separator.
    #[error("scope {scope:?} in policy {policy:?} is not a valid scope identifier ({path})")]
    InvalidScopeFormat {
        /// The offending scope string.
        scope: String,
        /// The policy that contained it.
        policy: String,
        /// The file that held the policy.
        path: PathBuf,
    },

    /// A policy or rule scope allowlist contains the same scope twice.
    /// Silently deduping is correct behavior for a `HashSet`, but
    /// almost always indicates an operator typo — flag it.
    #[error("policy {policy:?} lists scope {scope:?} more than once ({path})")]
    DuplicateScopeInAllowlist {
        /// The offending policy name.
        policy: String,
        /// The duplicated scope string.
        scope: String,
        /// The file that held the policy.
        path: PathBuf,
    },

    /// A resources allowlist mixes `"*"` (the wildcard) with explicit
    /// resource entries. The implementation folds this to
    /// `ResourceMatcher::All`, silently discarding the explicit
    /// entries — almost always not what the operator intended.
    #[error(
        "policy {policy:?} mixes the wildcard resource {wildcard:?} with explicit resources ({path})"
    )]
    MixedWildcardAndExplicitResources {
        /// The offending policy name.
        policy: String,
        /// The wildcard marker (always `"*"` today).
        wildcard: String,
        /// The file that held the policy.
        path: PathBuf,
    },
}

impl PolicyCompileError {
    /// Tag name of the current variant. Used by the
    /// `variant_tag_covers_every_variant` test to force a compile
    /// error whenever a new variant is added without updating the
    /// downstream `render_policy_error` renderer in
    /// `permitlayer-daemon::cli::start`.
    ///
    /// The match here is intentionally same-crate and therefore
    /// NOT subject to the `#[non_exhaustive]` wildcard requirement:
    /// the compiler will refuse to build `permitlayer-core` until
    /// every variant is listed. Reviewers adding a new variant MUST
    /// update both this function and the daemon's renderer.
    #[must_use]
    pub fn variant_tag(&self) -> &'static str {
        match self {
            Self::Io { .. } => "Io",
            Self::NotADirectory { .. } => "NotADirectory",
            Self::Parse { .. } => "Parse",
            Self::EmptyPoliciesArray { .. } => "EmptyPoliciesArray",
            Self::DuplicatePolicyName { .. } => "DuplicatePolicyName",
            Self::DuplicatePolicyNameInFile { .. } => "DuplicatePolicyNameInFile",
            Self::DuplicateRuleId { .. } => "DuplicateRuleId",
            Self::EmptyScopesAllowlist { .. } => "EmptyScopesAllowlist",
            Self::EmptyResourcesAllowlist { .. } => "EmptyResourcesAllowlist",
            Self::EmptyRuleScopesOverride { .. } => "EmptyRuleScopesOverride",
            Self::EmptyRuleResourcesOverride { .. } => "EmptyRuleResourcesOverride",
            Self::RuleScopeWidensPolicyAllowlist { .. } => "RuleScopeWidensPolicyAllowlist",
            Self::RuleResourceWidensPolicyAllowlist { .. } => "RuleResourceWidensPolicyAllowlist",
            Self::ShadowedRule { .. } => "ShadowedRule",
            Self::BomDetected { .. } => "BomDetected",
            Self::InvalidScopeFormat { .. } => "InvalidScopeFormat",
            Self::DuplicateScopeInAllowlist { .. } => "DuplicateScopeInAllowlist",
            Self::MixedWildcardAndExplicitResources { .. } => "MixedWildcardAndExplicitResources",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Forces a compile error when a new `PolicyCompileError` variant
    /// is added without also updating `variant_tag` (and, transitively,
    /// the daemon's `render_policy_error` renderer).
    ///
    /// Exhaustiveness is enforced at compile time by the `match self`
    /// in `variant_tag`, which is same-crate and therefore sees every
    /// variant despite the `#[non_exhaustive]` attribute. This test
    /// builds one instance of every variant and counts the unique
    /// tags — the assertion reminds the reviewer to audit the daemon
    /// renderer when the variant count changes.
    #[test]
    fn variant_tag_covers_every_variant() {
        let samples: Vec<PolicyCompileError> = vec![
            PolicyCompileError::Io {
                path: PathBuf::from("/x"),
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            },
            PolicyCompileError::NotADirectory { path: PathBuf::from("/x") },
            PolicyCompileError::Parse {
                path: PathBuf::from("/x"),
                line: None,
                message: "m".to_owned(),
            },
            PolicyCompileError::EmptyPoliciesArray { path: PathBuf::from("/x") },
            PolicyCompileError::DuplicatePolicyName {
                name: "n".to_owned(),
                first: PathBuf::from("/a"),
                second: PathBuf::from("/b"),
            },
            PolicyCompileError::DuplicatePolicyNameInFile {
                name: "n".to_owned(),
                path: PathBuf::from("/x"),
            },
            PolicyCompileError::DuplicateRuleId {
                policy: "p".to_owned(),
                rule_id: "r".to_owned(),
                path: PathBuf::from("/x"),
            },
            PolicyCompileError::EmptyScopesAllowlist {
                policy: "p".to_owned(),
                path: PathBuf::from("/x"),
            },
            PolicyCompileError::EmptyResourcesAllowlist {
                policy: "p".to_owned(),
                path: PathBuf::from("/x"),
            },
            PolicyCompileError::EmptyRuleScopesOverride {
                policy: "p".to_owned(),
                rule_id: "r".to_owned(),
                path: PathBuf::from("/x"),
            },
            PolicyCompileError::EmptyRuleResourcesOverride {
                policy: "p".to_owned(),
                rule_id: "r".to_owned(),
                path: PathBuf::from("/x"),
            },
            PolicyCompileError::RuleScopeWidensPolicyAllowlist {
                policy: "p".to_owned(),
                rule_id: "r".to_owned(),
                scope: "s".to_owned(),
                path: PathBuf::from("/x"),
            },
            PolicyCompileError::RuleResourceWidensPolicyAllowlist {
                policy: "p".to_owned(),
                rule_id: "r".to_owned(),
                resource: "r".to_owned(),
                path: PathBuf::from("/x"),
            },
            PolicyCompileError::ShadowedRule {
                policy: "p".to_owned(),
                earlier_rule_id: "a".to_owned(),
                later_rule_id: "b".to_owned(),
                path: PathBuf::from("/x"),
            },
            PolicyCompileError::BomDetected { path: PathBuf::from("/x") },
            PolicyCompileError::InvalidScopeFormat {
                scope: "s".to_owned(),
                policy: "p".to_owned(),
                path: PathBuf::from("/x"),
            },
            PolicyCompileError::DuplicateScopeInAllowlist {
                policy: "p".to_owned(),
                scope: "s".to_owned(),
                path: PathBuf::from("/x"),
            },
            PolicyCompileError::MixedWildcardAndExplicitResources {
                policy: "p".to_owned(),
                wildcard: "*".to_owned(),
                path: PathBuf::from("/x"),
            },
        ];
        let tags: std::collections::HashSet<&'static str> =
            samples.iter().map(PolicyCompileError::variant_tag).collect();
        assert_eq!(
            tags.len(),
            samples.len(),
            "variant_tag produced duplicate tags — check the match in variant_tag"
        );
        // If the cardinality drifts here, the reviewer adding a new
        // variant needs to: (1) add the variant to `samples` above,
        // (2) add the variant to `variant_tag`, (3) add a dedicated
        // arm to `render_policy_error` in permitlayer-daemon.
        assert_eq!(tags.len(), 18, "update this count when adding/removing variants");
    }
}
