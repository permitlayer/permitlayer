//! Load-time validation of a [`ConnectorDef`] (FR90).
//!
//! Story 11.1 parses a `connector.toml` into a typed model; this
//! module enforces the *semantic* invariants the type system can't:
//! every tool/tier scope must be in the connector's own `[scopes]`
//! vocabulary, the upstream `base_url` host must be in `allowed_hosts`,
//! the declared id must match the directory/expected id, methods must
//! be a known HTTP verb, and the id charset/length is bounded.
//!
//! A def that fails validation is refused at load: built-ins fail the
//! test suite (a ship-time bug), host-installed defs are skipped-and-
//! warned by the registry (Story 11.3) so one bad third-party connector
//! never takes down the daemon.

use crate::def::ConnectorDef;

/// A connector definition failed load-time validation.
///
/// Each variant names the offending connector id plus the specific
/// field/scope/value, so the registry's skip-and-warn log (and the
/// built-in test failures) point straight at the problem.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    /// The `[connector].id` did not match the directory / expected id.
    #[error("connector id mismatch: def declares `{declared}` but was loaded as `{expected}`")]
    IdMismatch {
        /// id from `[connector].id`.
        declared: String,
        /// id derived from the directory / built-in table.
        expected: String,
    },

    /// The id is empty, too long, or contains disallowed characters.
    #[error("connector `{id}`: invalid id (must be 2..=64 chars of [a-z0-9-_])")]
    InvalidId {
        /// The offending id.
        id: String,
    },

    /// `allowed_hosts` is empty — there is no permissive default
    /// (FR91/NFR52): a connector with no allowlist can reach nothing.
    #[error("connector `{id}`: [upstream].allowed_hosts must be non-empty")]
    EmptyAllowedHosts {
        /// The connector id.
        id: String,
    },

    /// The `base_url` host is not in `allowed_hosts`.
    #[error("connector `{id}`: base_url host `{host}` is not in allowed_hosts {allowed:?}")]
    BaseUrlHostNotAllowed {
        /// The connector id.
        id: String,
        /// The resolved base_url host.
        host: String,
        /// The declared allowlist.
        allowed: Vec<String>,
    },

    /// `base_url` has no host component at all (e.g. a relative URL).
    #[error("connector `{id}`: base_url has no host")]
    BaseUrlNoHost {
        /// The connector id.
        id: String,
    },

    /// A `[[tools]].required_scope` is not present in `[scopes]` (FR90).
    #[error("connector `{id}`: tool `{tool}` requires scope `{scope}` which is not in [scopes]")]
    ToolScopeNotInVocab {
        /// The connector id.
        id: String,
        /// The offending tool name.
        tool: String,
        /// The scope short-name not found in `[scopes]`.
        scope: String,
    },

    /// A tier bundle lists a scope not present in `[scopes]`.
    #[error("connector `{id}`: tier `{tier}` lists scope `{scope}` which is not in [scopes]")]
    TierScopeNotInVocab {
        /// The connector id.
        id: String,
        /// The offending tier name.
        tier: String,
        /// The scope short-name not found in `[scopes]`.
        scope: String,
    },

    /// A tool declares an unknown HTTP method.
    #[error("connector `{id}`: tool `{tool}` has unknown HTTP method `{method}`")]
    UnknownMethod {
        /// The connector id.
        id: String,
        /// The offending tool name.
        tool: String,
        /// The unrecognized method string.
        method: String,
    },
}

/// HTTP methods a connector tool may declare.
const KNOWN_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE"];

/// Validate a connector id's charset and length: 2..=64 chars of
/// lowercase alphanumeric, `-`, or `_`. Mirrors the plugin loader's
/// `validate_metadata` name rule so built-in and host-installed
/// connectors share one id discipline.
fn id_is_valid(id: &str) -> bool {
    let len = id.chars().count();
    (2..=64).contains(&len)
        && id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// Validate a [`ConnectorDef`] against its expected id (FR90 + the
/// structural invariants the parser can't enforce).
///
/// `expected_id` is the id the loader assigned this def — the
/// directory name for host-installed connectors, or the embed-table
/// id for built-ins. A def whose `[connector].id` disagrees is
/// rejected ([`ValidationError::IdMismatch`]) so a connector can't
/// masquerade as another by living in the wrong directory.
///
/// # Errors
///
/// Returns the first [`ValidationError`] encountered. Checks run in a
/// stable order (id → allowed_hosts → base_url → tools → tiers →
/// methods) so the error a connector author sees is deterministic.
pub fn validate_def(def: &ConnectorDef, expected_id: &str) -> Result<(), ValidationError> {
    let id = def.connector.id.as_str();

    if !id_is_valid(id) {
        return Err(ValidationError::InvalidId { id: id.to_owned() });
    }

    if id != expected_id {
        return Err(ValidationError::IdMismatch {
            declared: id.to_owned(),
            expected: expected_id.to_owned(),
        });
    }

    if def.upstream.allowed_hosts.is_empty() {
        return Err(ValidationError::EmptyAllowedHosts { id: id.to_owned() });
    }

    let host = def
        .upstream
        .base_url
        .host_str()
        .ok_or_else(|| ValidationError::BaseUrlNoHost { id: id.to_owned() })?;
    if !def.upstream.allowed_hosts.iter().any(|h| h == host) {
        return Err(ValidationError::BaseUrlHostNotAllowed {
            id: id.to_owned(),
            host: host.to_owned(),
            allowed: def.upstream.allowed_hosts.clone(),
        });
    }

    for tool in &def.tools {
        if !def.scopes.contains_key(&tool.required_scope) {
            return Err(ValidationError::ToolScopeNotInVocab {
                id: id.to_owned(),
                tool: tool.name.clone(),
                scope: tool.required_scope.clone(),
            });
        }
        let method = tool.method.to_ascii_uppercase();
        if !KNOWN_METHODS.contains(&method.as_str()) {
            return Err(ValidationError::UnknownMethod {
                id: id.to_owned(),
                tool: tool.name.clone(),
                method: tool.method.clone(),
            });
        }
    }

    for (tier, bundle) in &def.tiers {
        for scope in bundle.scopes() {
            if !def.scopes.contains_key(scope) {
                return Err(ValidationError::TierScopeNotInVocab {
                    id: id.to_owned(),
                    tier: tier.clone(),
                    scope: scope.clone(),
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const VALID: &str = r#"
[connector]
id = "good-conn"
display_name = "Good"
version = "1.0.0"
trust_tier = "host-installed"

[auth]
flavor = "oauth2"
auth_url = "https://accounts.example.com/auth"
token_url = "https://accounts.example.com/token"

[upstream]
base_url = "https://api.example.com/v1/"
allowed_hosts = ["api.example.com"]

[scopes]
"thing.read" = "https://api.example.com/auth/thing.read"
"thing.write" = "https://api.example.com/auth/thing.write"

[tiers]
read = ["thing.read"]
read-write = ["thing.read", "thing.write"]

[[tools]]
name = "thing.list"
required_scope = "thing.read"
method = "GET"
path = "things"

[[tools]]
name = "thing.create"
required_scope = "thing.write"
method = "POST"
path = "things"
"#;

    fn parse(s: &str) -> ConnectorDef {
        ConnectorDef::from_toml_str(s).expect("fixture parses")
    }

    #[test]
    fn valid_def_passes() {
        assert!(validate_def(&parse(VALID), "good-conn").is_ok());
    }

    #[test]
    fn id_mismatch_rejected() {
        let err = validate_def(&parse(VALID), "different-id").unwrap_err();
        assert_eq!(
            err,
            ValidationError::IdMismatch {
                declared: "good-conn".to_owned(),
                expected: "different-id".to_owned()
            }
        );
    }

    #[test]
    fn invalid_id_charset_rejected() {
        let toml = VALID.replace("id = \"good-conn\"", "id = \"Bad ID!\"");
        let err = validate_def(&parse(&toml), "Bad ID!").unwrap_err();
        assert!(matches!(err, ValidationError::InvalidId { .. }));
    }

    #[test]
    fn tool_scope_not_in_vocab_rejected_naming_scope_and_id() {
        // FR90.
        let toml =
            VALID.replace("required_scope = \"thing.read\"", "required_scope = \"thing.absent\"");
        let err = validate_def(&parse(&toml), "good-conn").unwrap_err();
        match err {
            ValidationError::ToolScopeNotInVocab { id, tool, scope } => {
                assert_eq!(id, "good-conn");
                assert_eq!(tool, "thing.list");
                assert_eq!(scope, "thing.absent");
            }
            other => panic!("expected ToolScopeNotInVocab, got {other:?}"),
        }
    }

    #[test]
    fn base_url_host_not_in_allowed_hosts_rejected() {
        let toml = VALID.replace(
            "allowed_hosts = [\"api.example.com\"]",
            "allowed_hosts = [\"other.example.com\"]",
        );
        let err = validate_def(&parse(&toml), "good-conn").unwrap_err();
        assert!(matches!(err, ValidationError::BaseUrlHostNotAllowed { .. }));
    }

    #[test]
    fn empty_allowed_hosts_rejected() {
        let toml = VALID.replace("allowed_hosts = [\"api.example.com\"]", "allowed_hosts = []");
        let err = validate_def(&parse(&toml), "good-conn").unwrap_err();
        assert_eq!(err, ValidationError::EmptyAllowedHosts { id: "good-conn".to_owned() });
    }

    #[test]
    fn tier_scope_not_in_vocab_rejected() {
        let toml = VALID.replace("read = [\"thing.read\"]", "read = [\"thing.ghost\"]");
        let err = validate_def(&parse(&toml), "good-conn").unwrap_err();
        match err {
            ValidationError::TierScopeNotInVocab { tier, scope, .. } => {
                assert_eq!(tier, "read");
                assert_eq!(scope, "thing.ghost");
            }
            other => panic!("expected TierScopeNotInVocab, got {other:?}"),
        }
    }

    #[test]
    fn unknown_method_rejected() {
        let toml = VALID.replace("method = \"GET\"", "method = \"FETCH\"");
        let err = validate_def(&parse(&toml), "good-conn").unwrap_err();
        assert!(matches!(err, ValidationError::UnknownMethod { .. }));
    }

    #[test]
    fn all_three_builtins_validate() {
        for def in crate::builtin_connector_defs().expect("builtins parse") {
            let id = def.connector.id.clone();
            validate_def(&def, &id).unwrap_or_else(|e| panic!("built-in {id} must validate: {e}"));
        }
    }
}
