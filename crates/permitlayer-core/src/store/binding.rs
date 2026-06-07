//! `BindingStore` — the persistence trait for **Bindings** (Epic 11,
//! Story 11.9).
//!
//! A [`Binding`] is an `(agent, connection)` grant at a tier (with an
//! optional policy + selector alias). It is the amended FR47 model: an
//! agent's authority is its *set* of bindings, replacing the single
//! `AgentIdentity.policy_name` (deleted in this story).
//!
//! Persisted as `bindings/<agent>.toml` — one file per agent holding that
//! agent's binding set. The primary key is `(agent, connection_id)`: an
//! agent may hold many bindings (Chuck = {chuck-gmail rw, austin-gmail
//! ro, …}), but never two for the same connection.
//!
//! # No secrets here
//!
//! A binding references a connection by id; it carries no credential
//! material. Bind/unbind never touch the agent's bearer token — the
//! binding file is wholly separate from `agents/<name>.toml`.

use permitlayer_credential::ConnectionId;
use serde::{Deserialize, Serialize};

use crate::store::connection::ConnectionTier;
use crate::store::error::StoreError;

/// One `(agent, connection)` grant (Story 11.9).
///
/// The owning agent is the file key (`bindings/<agent>.toml`), so it is
/// not repeated on each entry; `connection_id` is the per-entry key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    /// The granted connection's id (ULID text form on disk).
    #[serde(with = "crate::store::binding::binding_id_serde")]
    pub connection_id: ConnectionId,
    /// The tier this agent is granted on the connection.
    pub tier: ConnectionTier,
    /// Optional policy name further constraining the grant. Existence is
    /// verified control-plane-side at bind time (Story 11.14), never here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// Optional selector alias for path-addressing (`/mcp/<alias>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
}

/// Serde adapter rendering a [`ConnectionId`] as its canonical 26-char
/// ULID text form. Shared shape with the connection-store adapter.
pub(crate) mod binding_id_serde {
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

/// Persist [`Binding`]s keyed on `(agent, connection_id)` (Story 11.9).
///
/// Implementations MUST mirror [`AgentIdentityStore`](crate::store::AgentIdentityStore):
/// atomic-write, `0o600` files in a `0o700` dir, skip-and-warn on
/// malformed entries, dir-absent → empty.
#[async_trait::async_trait]
pub trait BindingStore: Send + Sync {
    /// Add one binding for `agent`. Returns
    /// [`StoreError::BindingAlreadyExists`] if a binding for the same
    /// `(agent, binding.connection_id)` already exists (the PK refuses to
    /// clobber — change tier/policy via unbind+bind). Creates the agent's
    /// binding file if absent; otherwise appends to it atomically.
    async fn put_binding(&self, agent: &str, binding: Binding) -> Result<(), StoreError>;

    /// Return every binding held by `agent` (empty if the agent has none).
    async fn get(&self, agent: &str) -> Result<Vec<Binding>, StoreError>;

    /// List every agent that holds at least one binding.
    async fn list_agents(&self) -> Result<Vec<String>, StoreError>;

    /// Remove the single binding `(agent, connection_id)`. `Ok(true)` if a
    /// binding was removed, `Ok(false)` if none matched. Other bindings in
    /// the agent's file are preserved; if it was the last one, the file is
    /// removed.
    async fn remove(&self, agent: &str, connection_id: ConnectionId) -> Result<bool, StoreError>;

    /// Remove ALL bindings for `agent` (the whole file). Used by the
    /// `connection revoke` cascade (Story 11.13) and agent removal.
    /// `Ok(true)` if a file was deleted, `Ok(false)` if none existed.
    async fn remove_agent(&self, agent: &str) -> Result<bool, StoreError>;
}
