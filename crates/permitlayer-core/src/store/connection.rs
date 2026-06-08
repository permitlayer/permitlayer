//! `ConnectionStore` — the persistence trait for **Connections** (Epic 11,
//! Story 11.9).
//!
//! A [`ConnectionRecord`] is the non-secret metadata for ONE connection:
//! one upstream account on one connector, identified by a stable
//! [`ConnectionId`] (ULID). The sealed credential material lives in the
//! [`CredentialStore`](crate::store::CredentialStore) keyed on
//! `(ConnectionId, Slot)`; this store holds only the routing/display
//! metadata.
//!
//! # No secrets here
//!
//! A `ConnectionRecord` carries NO ciphertext, no tokens, no client
//! secret — only the connector id, a mutable display name, the actual
//! granted scopes, an account hint, the requested tier, status, and a
//! creation timestamp. Renaming a connection therefore never touches the
//! sealed bytes (the crypto keys on the id, not the name — Story 11.8).

use std::fmt;

use chrono::{DateTime, Utc};
use permitlayer_credential::ConnectionId;
use serde::{Deserialize, Serialize};

use crate::store::error::StoreError;

/// A connection's account hint — the Google account identity captured at
/// `connection add` time (typically the account email), used so an
/// operator can tell *which* account a connection authenticated as when
/// two connections share one connector.
///
/// # Why a newtype
///
/// The email is **PII the operator already holds** (they just consented
/// as that account) and is never a secret — but it is still the one field
/// on an otherwise non-sensitive [`ConnectionRecord`] worth not echoing in
/// full to a terminal. Rather than rely on every print site remembering to
/// mask it, the masking is enforced **at the type boundary**: `Display`
/// and `Debug` always emit the masked form (`ag•••@gmail.com`), so it is
/// structurally impossible to `println!`/`format!`/log the full value by
/// accident. Code that genuinely needs the raw value — the `--json` output
/// path, the serde wire/disk format, equality — uses [`AccountHint::reveal`]
/// or serde explicitly, which reads as a deliberate choice at the call
/// site.
///
/// Serialization is transparent: an `AccountHint` serializes and
/// deserializes as the bare inner string, so on-disk TOML and the control
/// plane / `--json` wire format are byte-identical to a plain `String`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccountHint(String);

impl AccountHint {
    /// Wrap a raw account-hint string.
    #[must_use]
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// The full, unmasked value. Naming it `reveal` makes every raw-value
    /// read an explicit, greppable decision (the `--json` path, tests).
    #[must_use]
    pub fn reveal(&self) -> &str {
        &self.0
    }

    /// The masked rendering used by `Display`/`Debug`.
    ///
    /// - `local@domain` → first ≤2 chars of `local` + `•••` + `@domain`
    ///   (`agentssotest@gmail.com` → `ag•••@gmail.com`). A `local` of ≤2
    ///   chars is fully masked so length is not leaked (`ab@x.com` →
    ///   `•••@x.com`).
    /// - No `@` (not email-shaped) → first ≤2 chars + `•••`
    ///   (`account-123` → `ac•••`), so an opaque hint is never echoed whole.
    /// - Empty → empty.
    #[must_use]
    pub fn masked(&self) -> String {
        if self.0.is_empty() {
            return String::new();
        }
        let mask_prefix = |s: &str| -> String {
            let prefix: String = s.chars().take(2).collect();
            if s.chars().count() > 2 {
                format!("{prefix}\u{2022}\u{2022}\u{2022}")
            } else {
                "\u{2022}\u{2022}\u{2022}".to_owned()
            }
        };
        match self.0.split_once('@') {
            Some((local, domain)) if !domain.is_empty() => {
                format!("{}@{domain}", mask_prefix(local))
            }
            _ => mask_prefix(&self.0),
        }
    }
}

/// Masked. Never emits the raw value — see [`AccountHint::reveal`] for the
/// deliberate unmasked path.
impl fmt::Display for AccountHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.masked())
    }
}

/// Masked. Keeps the raw value out of `{:?}` logs / panic messages too.
impl fmt::Debug for AccountHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccountHint({})", self.masked())
    }
}

impl From<String> for AccountHint {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// The tier a connection's token was requested at (Story 11.9). This is
/// the *requested* tier recorded at `connection add` time; the actual
/// authority a tool gets is `tier ∩ granted_scopes ∩ policy` resolved at
/// request time (Story 11.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionTier {
    /// Read-only access.
    Read,
    /// Read + write access.
    ReadWrite,
}

/// Lifecycle status of a connection (Story 11.9). `connection revoke`
/// (Story 11.13) flips an `Active` record to `Revoked` and removes its
/// sealed slots + bindings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionStatus {
    /// The connection is usable.
    Active,
    /// The connection has been revoked; no credential should resolve.
    Revoked,
}

/// Non-secret metadata for one connection (Story 11.9).
///
/// Persisted as `connections/<id>.toml`. The `id` is both the record
/// identity and the filename stem. `name` is a mutable display alias used
/// for path-addressing (`/mcp/<name>`); renaming it never re-seals the
/// credential (Story 11.8 AC — crypto keys on `id`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionRecord {
    /// Stable ULID identity (also the filename stem). Serialized as the
    /// 26-char Crockford text form.
    #[serde(with = "connection_id_serde")]
    pub id: ConnectionId,
    /// Connector registry id this connection belongs to (e.g.
    /// `"google-gmail"`).
    pub connector_id: String,
    /// Mutable display name / selector alias (validated allowlist).
    pub name: String,
    /// Account hint captured at add-time from userinfo (e.g. the email).
    /// Populated by `connection add` (Story 11.13); 11.9 round-trips it.
    /// [`AccountHint`] masks on `Display`/`Debug`; serde is transparent so
    /// the on-disk/wire form is the bare string.
    #[serde(default)]
    pub account_hint: Option<AccountHint>,
    /// The actual OAuth scopes the sealed token carries.
    #[serde(default)]
    pub granted_scopes: Vec<String>,
    /// The tier requested at add-time.
    pub tier: ConnectionTier,
    /// Creation timestamp (RFC 3339 UTC).
    pub created_at: DateTime<Utc>,
    /// Lifecycle status.
    pub status: ConnectionStatus,
}

/// Serde adapter rendering a [`ConnectionId`] as its canonical 26-char
/// ULID text form (and parsing it back), so the on-disk TOML is
/// human-readable and matches the credential filename stem.
mod connection_id_serde {
    use permitlayer_credential::ConnectionId;
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(id: &ConnectionId, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&id.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<ConnectionId, D::Error> {
        let s = String::deserialize(d)?;
        ConnectionId::from_ulid_str(&s)
            .ok_or_else(|| D::Error::custom(format!("invalid ULID '{s}'")))
    }
}

/// Persist [`ConnectionRecord`]s keyed by [`ConnectionId`] (Story 11.9).
///
/// Implementations MUST mirror [`AgentIdentityStore`](crate::store::AgentIdentityStore):
/// atomic-write (tempfile → fsync → rename → fsync parent dir), `0o600`
/// files in a `0o700` dir, `Ok(None)`/`Ok(false)` on absent, skip-and-warn
/// on malformed entries during `list`, and dir-absent → empty list.
#[async_trait::async_trait]
pub trait ConnectionStore: Send + Sync {
    /// Persist (create or overwrite) a connection record. Overwrite is
    /// allowed — a rename or status flip rewrites the same `id` file.
    async fn put(&self, record: ConnectionRecord) -> Result<(), StoreError>;

    /// Retrieve a connection by id. `Ok(None)` if absent.
    async fn get(&self, id: ConnectionId) -> Result<Option<ConnectionRecord>, StoreError>;

    /// List every persisted connection. Order is implementation-defined.
    async fn list(&self) -> Result<Vec<ConnectionRecord>, StoreError>;

    /// Remove a connection record. `Ok(true)` if a file was deleted,
    /// `Ok(false)` if none existed. Does NOT cascade to sealed slots or
    /// bindings — the `connection revoke` caller (Story 11.13) orchestrates
    /// that across the three stores.
    async fn remove(&self, id: ConnectionId) -> Result<bool, StoreError>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod account_hint_tests {
    use super::AccountHint;

    #[test]
    fn display_masks_typical_email_keeping_prefix_and_domain() {
        assert_eq!(
            AccountHint::new("alpha@example.com").to_string(),
            "al\u{2022}\u{2022}\u{2022}@example.com"
        );
        // A real `@gmail.com` domain case proves Gmail masking; the local
        // part is a non-human service handle, not a person's name.
        assert_eq!(
            AccountHint::new("agentssotest@gmail.com").to_string(),
            "ag\u{2022}\u{2022}\u{2022}@gmail.com"
        );
    }

    #[test]
    fn short_local_part_fully_masked_so_length_not_leaked() {
        assert_eq!(
            AccountHint::new("ab@example.com").to_string(),
            "\u{2022}\u{2022}\u{2022}@example.com"
        );
        assert_eq!(
            AccountHint::new("a@example.com").to_string(),
            "\u{2022}\u{2022}\u{2022}@example.com"
        );
    }

    #[test]
    fn non_email_hint_masked_as_opaque_prefix() {
        assert_eq!(AccountHint::new("account-123").to_string(), "ac\u{2022}\u{2022}\u{2022}");
        assert_eq!(AccountHint::new("xy").to_string(), "\u{2022}\u{2022}\u{2022}");
    }

    #[test]
    fn empty_hint_stays_empty() {
        assert_eq!(AccountHint::new("").to_string(), "");
    }

    #[test]
    fn debug_also_masks_so_logs_and_panics_never_leak_raw() {
        let h = AccountHint::new("agentssotest@gmail.com");
        let dbg = format!("{h:?}");
        assert!(dbg.contains("ag\u{2022}\u{2022}\u{2022}@gmail.com"), "debug must mask: {dbg}");
        assert!(!dbg.contains("agentssotest@gmail.com"), "debug must NOT contain raw: {dbg}");
    }

    #[test]
    fn reveal_returns_full_value_for_deliberate_callers() {
        assert_eq!(AccountHint::new("alpha@example.com").reveal(), "alpha@example.com");
    }

    #[test]
    fn serde_is_transparent_bare_string() {
        // Disk/wire form must be the bare string, not a wrapper object.
        let h = AccountHint::new("alpha@example.com");
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(json, "\"alpha@example.com\"");
        let back: AccountHint = serde_json::from_str(&json).unwrap();
        assert_eq!(back.reveal(), "alpha@example.com");
    }
}
