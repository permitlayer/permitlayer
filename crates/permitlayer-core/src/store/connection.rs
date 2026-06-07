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

use chrono::{DateTime, Utc};
use permitlayer_credential::ConnectionId;
use serde::{Deserialize, Serialize};

use crate::store::error::StoreError;

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
    #[serde(default)]
    pub account_hint: Option<String>,
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
