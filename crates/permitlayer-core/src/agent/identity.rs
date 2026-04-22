//! `AgentIdentity` — the on-disk + in-memory record for one registered agent.
//!
//! This file owns three things:
//!
//! 1. [`AgentIdentity`] — the canonical, validated record. Constructed
//!    only via `AgentIdentityRaw::into_validated` so the agent name is
//!    guaranteed to satisfy the path-traversal-safe allowlist.
//! 2. [`AgentIdentityRaw`] — the serde mirror used for TOML round-trip.
//!    Identical layout, no validation. Tests and the fs adapter
//!    serialize this type and then immediately validate.
//! 3. [`validate_agent_name`] — the public allowlist validator. Mirrors
//!    `validate_service_name` exactly so future readers see one pattern
//!    and one rationale, not two.
//!
//! # No plaintext discipline
//!
//! `AgentIdentity` carries the Argon2id PHC string and the hex-encoded
//! HMAC lookup key — both derived values. Plaintext token bytes never
//! reach this struct. The `AgentBearerToken` non-`Debug` discipline in
//! `permitlayer-credential` enforces the boundary on the other side.
//!
//! # Why a hex-encoded lookup key
//!
//! The lookup key is 32 bytes of HMAC-SHA-256 output. TOML can encode
//! it as either a base64 string or a hex string; we pick hex because
//! `serde_json` already serializes audit events with hex byte strings
//! and operators benefit from exactly one canonical encoding for
//! cryptographic material in `~/.agentsso/`. The cost is +33% disk
//! footprint vs base64 — irrelevant for a 64-char-vs-44-char field.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Errors returned by [`validate_agent_name`].
///
/// `Display` carries the offending input verbatim — agent names never
/// contain credential material, so echoing them in operator-facing
/// errors is safe.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AgentNameError {
    /// The name violates the allowlist (length, character set, or
    /// leading/trailing hyphen).
    #[error("agent name '{input}' does not match allowlist pattern")]
    Invalid {
        /// The invalid input. Safe to echo — agent names never contain
        /// credential material.
        input: String,
    },
}

/// Minimum agent name length. Same as `validate_service_name`.
const MIN_AGENT_NAME_LEN: usize = 2;
/// Maximum agent name length. Same as `validate_service_name` — caps
/// `agents/<name>.toml` path length at `len("agents/") + 64 + len(".toml") = 75`,
/// well under any platform's `PATH_MAX`.
const MAX_AGENT_NAME_LEN: usize = 64;

/// Validate an agent name against the path-traversal-safe allowlist.
///
/// Pattern: `^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$` — lowercase alphanumeric
/// `+ -`, 2–64 chars, no leading/trailing hyphen. This subset is
/// structurally path-traversal-safe (no `.`, no `/`, no NUL bytes,
/// no `..` sequences — any attempt fails the character-set check
/// before the string can become a filesystem path).
///
/// **Why duplicate `validate_service_name`?** Service names live under
/// `vault/<service>.sealed`; agent names live under `agents/<name>.toml`.
/// They share the same character-set requirement but they validate
/// different namespaces, so collapsing them into one function would
/// create a confusing dependency where the policy/credential side has
/// to import an "agent" identifier validator. Keep them parallel and
/// document the duplication here.
///
/// # Errors
///
/// Returns [`AgentNameError::Invalid`] on any violation.
pub fn validate_agent_name(s: &str) -> Result<(), AgentNameError> {
    let len = s.len();
    if !(MIN_AGENT_NAME_LEN..=MAX_AGENT_NAME_LEN).contains(&len) {
        return Err(AgentNameError::Invalid { input: s.to_owned() });
    }
    let bytes = s.as_bytes();
    if !is_alnum_lower(bytes[0]) || !is_alnum_lower(bytes[len - 1]) {
        return Err(AgentNameError::Invalid { input: s.to_owned() });
    }
    for &b in bytes {
        if !is_alnum_lower(b) && b != b'-' {
            return Err(AgentNameError::Invalid { input: s.to_owned() });
        }
    }
    Ok(())
}

#[inline]
fn is_alnum_lower(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

/// A registered agent identity — the canonical, validated record.
///
/// Constructed only via [`AgentIdentityRaw::into_validated`] so the
/// `name` field is guaranteed to satisfy [`validate_agent_name`]. All
/// other fields are caller-provided and trusted.
///
/// # Field discipline
///
/// - `name` — validated identifier. Used as the on-disk filename
///   (`agents/<name>.toml`) and the audit-log `agent_id` field.
/// - `policy_name` — the policy this agent is bound to. NOT validated
///   against the active `PolicySet` here — that check happens at
///   register time in the daemon control handler.
/// - `token_hash` — Argon2id PHC string from `argon2::PasswordHasher`.
///   At-rest defense for the on-disk file.
/// - `lookup_key_hex` — 64-char hex (32 bytes) HMAC-SHA-256 output.
///   The runtime O(1) index key. **NOT a secret on its own** — an
///   attacker who steals only this value cannot use it to authenticate
///   because the daemon's HMAC subkey is required to *produce* the
///   lookup key from a plaintext token. But it IS predictable from
///   `(daemon_subkey, plaintext)`, so don't expose it in audit logs or
///   error responses. The agent file itself is mode 0o600 in a 0o700
///   directory.
/// - `created_at` / `last_seen_at` — RFC 3339 UTC timestamps. The
///   `last_seen_at` field is updated best-effort by `AuthLayer` on
///   every successful authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(into = "AgentIdentityRaw", try_from = "AgentIdentityRaw")]
pub struct AgentIdentity {
    /// Validated agent name (path-traversal-safe).
    name: String,
    /// Policy this agent is bound to.
    pub policy_name: String,
    /// Argon2id PHC-string hash of the bearer token. The salt is
    /// embedded in the PHC string per RFC 9106 § 4.
    pub token_hash: String,
    /// Hex-encoded 32-byte HMAC-SHA-256 lookup key. See module docs
    /// for the dual-index rationale.
    pub lookup_key_hex: String,
    /// Registration timestamp (RFC 3339 UTC, millisecond precision).
    pub created_at: DateTime<Utc>,
    /// Most recent successful authentication timestamp. `None` until
    /// the agent's bearer token is first presented.
    pub last_seen_at: Option<DateTime<Utc>>,
}

impl AgentIdentity {
    /// Borrowed access to the validated name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Construct an `AgentIdentity` directly. The name is validated;
    /// any failure surfaces as [`AgentNameError`].
    ///
    /// This is the canonical constructor for tests and the fs adapter.
    /// The serde path goes through [`AgentIdentityRaw::into_validated`],
    /// which calls this internally.
    ///
    /// # Errors
    ///
    /// Returns [`AgentNameError::Invalid`] if `name` violates the
    /// allowlist.
    pub fn new(
        name: String,
        policy_name: String,
        token_hash: String,
        lookup_key_hex: String,
        created_at: DateTime<Utc>,
        last_seen_at: Option<DateTime<Utc>>,
    ) -> Result<Self, AgentNameError> {
        validate_agent_name(&name)?;
        Ok(Self { name, policy_name, token_hash, lookup_key_hex, created_at, last_seen_at })
    }
}

/// On-disk TOML mirror of [`AgentIdentity`]. Identical fields, no
/// validation. The serde adapter on `AgentIdentity` round-trips
/// through this type so the validation gate runs exactly once on every
/// deserialization path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentityRaw {
    pub name: String,
    pub policy_name: String,
    pub token_hash: String,
    pub lookup_key_hex: String,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<DateTime<Utc>>,
}

impl AgentIdentityRaw {
    /// Validate and lift to [`AgentIdentity`].
    ///
    /// # Errors
    ///
    /// Returns [`AgentNameError::Invalid`] if `name` violates the
    /// allowlist.
    pub fn into_validated(self) -> Result<AgentIdentity, AgentNameError> {
        AgentIdentity::new(
            self.name,
            self.policy_name,
            self.token_hash,
            self.lookup_key_hex,
            self.created_at,
            self.last_seen_at,
        )
    }
}

impl From<AgentIdentity> for AgentIdentityRaw {
    fn from(v: AgentIdentity) -> Self {
        Self {
            name: v.name,
            policy_name: v.policy_name,
            token_hash: v.token_hash,
            lookup_key_hex: v.lookup_key_hex,
            created_at: v.created_at,
            last_seen_at: v.last_seen_at,
        }
    }
}

impl TryFrom<AgentIdentityRaw> for AgentIdentity {
    type Error = AgentNameError;

    fn try_from(value: AgentIdentityRaw) -> Result<Self, Self::Error> {
        value.into_validated()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn fake_identity(name: &str) -> AgentIdentity {
        AgentIdentity::new(
            name.to_owned(),
            "default".to_owned(),
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".to_owned(),
            "0".repeat(64),
            Utc::now(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn validate_accepts_valid_names() {
        assert!(validate_agent_name("gmail").is_ok());
        assert!(validate_agent_name("email-triage").is_ok());
        assert!(validate_agent_name("a1").is_ok());
        assert!(validate_agent_name("a--b").is_ok());
        let sixty_four = "a".repeat(64);
        assert!(validate_agent_name(&sixty_four).is_ok());
    }

    #[test]
    fn validate_rejects_too_short() {
        assert!(validate_agent_name("").is_err());
        assert!(validate_agent_name("a").is_err());
    }

    #[test]
    fn validate_rejects_too_long() {
        let sixty_five = "a".repeat(65);
        assert!(validate_agent_name(&sixty_five).is_err());
    }

    #[test]
    fn validate_rejects_uppercase() {
        assert!(validate_agent_name("Gmail").is_err());
        assert!(validate_agent_name("Triage").is_err());
    }

    #[test]
    fn validate_rejects_disallowed_chars() {
        assert!(validate_agent_name("agent_one").is_err());
        assert!(validate_agent_name("agent.one").is_err());
        assert!(validate_agent_name("agent/one").is_err());
        assert!(validate_agent_name("agent one").is_err());
    }

    #[test]
    fn validate_rejects_path_traversal() {
        assert!(validate_agent_name("..").is_err());
        assert!(validate_agent_name("../etc").is_err());
        assert!(validate_agent_name("a\0b").is_err());
    }

    #[test]
    fn validate_rejects_leading_or_trailing_hyphen() {
        assert!(validate_agent_name("-leading").is_err());
        assert!(validate_agent_name("trailing-").is_err());
        assert!(validate_agent_name("-a-").is_err());
    }

    #[test]
    fn agent_identity_constructor_validates_name() {
        let bad = AgentIdentity::new(
            "Bad-Name".to_owned(),
            "default".to_owned(),
            "h".to_owned(),
            "0".repeat(64),
            Utc::now(),
            None,
        );
        assert!(bad.is_err());
    }

    #[test]
    fn toml_round_trip_preserves_fields() {
        let original = fake_identity("email-triage");
        let toml_str = toml::to_string_pretty(&original).unwrap();
        let parsed: AgentIdentity = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.name(), "email-triage");
        assert_eq!(parsed.policy_name, "default");
    }

    #[test]
    fn toml_deserialize_rejects_invalid_name() {
        // Construct a raw TOML with an invalid name and confirm the
        // try_from gate refuses it.
        let toml_str = r#"
name = "Bad-Name"
policy_name = "default"
token_hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA"
lookup_key_hex = "0000000000000000000000000000000000000000000000000000000000000000"
created_at = "2026-04-12T00:00:00Z"
"#;
        let result: Result<AgentIdentity, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn last_seen_at_defaults_to_none_and_is_omitted_when_none() {
        let id = fake_identity("agent1");
        let toml_str = toml::to_string_pretty(&id).unwrap();
        // Round-trip with omitted field should still parse.
        assert!(!toml_str.contains("last_seen_at"));
        let parsed: AgentIdentity = toml::from_str(&toml_str).unwrap();
        assert!(parsed.last_seen_at.is_none());
    }
}
