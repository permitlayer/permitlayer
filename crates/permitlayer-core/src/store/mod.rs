//! Storage traits for permitlayer.
//!
//! `CredentialStore` is the only trait defined here at Story 1.3. Later
//! stories will append `PolicyStore` (1.5), `AuditStore` (1.7), and
//! `AgentIdentityStore` (1.8) as sibling traits.
//!
//! # Discipline: the boundary only speaks `SealedCredential`
//!
//! Neither `CredentialStore` nor any helper in this module has a
//! signature that mentions `OAuthToken`, `OAuthRefreshToken`, or
//! `AgentBearerToken`. The storage layer is structurally incapable of
//! observing plaintext — the only way to get bytes from a store is to
//! `unseal` via `permitlayer-vault::Vault`. This is enforced at
//! compile time by `tests/compile_fail.rs` + `trybuild`, which proves
//! the trait rejects plaintext types.

pub mod binding;
pub mod connection;
pub mod error;
pub mod fs;
#[cfg(any(test, feature = "test-seam"))]
pub mod test_seams;
pub mod validate;

use permitlayer_credential::{ConnectionId, SealedCredential, Slot};

use crate::agent::AgentIdentity;
use crate::audit::event::AuditEvent;

pub use binding::{Binding, BindingStore};
pub use connection::{ConnectionRecord, ConnectionStatus, ConnectionStore, ConnectionTier};
pub use error::{EnvelopeParseError, StoreError};
pub use validate::validate_service_name;

/// Persist sealed credentials keyed by `(ConnectionId, Slot)` (Story 11.9).
///
/// The key matches the vault's v2 keying domain (Story 11.8): each
/// connection's `Access`/`Refresh`/`Client` material is a distinct entry.
/// On-disk the adapter names files `<connection_id>-<slot>.sealed`, so no
/// caller-supplied string ever becomes a path component — the id is a
/// machine-generated ULID and the slot is a fixed label.
///
/// Implementations MUST:
/// - write atomically (tempfile → fsync → rename → fsync parent dir)
/// - set restrictive filesystem permissions (0o600 on Unix)
/// - return `Ok(None)` from `get` when no entry exists
///
/// The trait is `async` because production adapters dispatch I/O to a
/// blocking worker via `tokio::task::spawn_blocking`.
#[async_trait::async_trait]
pub trait CredentialStore: Send + Sync {
    /// Store a sealed credential for `(id, slot)`. Overwrites any existing
    /// entry via atomic swap — callers see either the old value or the new
    /// value, never a partial write.
    async fn put(
        &self,
        id: ConnectionId,
        slot: Slot,
        sealed: SealedCredential,
    ) -> Result<(), StoreError>;

    /// Retrieve the sealed credential for `(id, slot)`. Returns `Ok(None)`
    /// if no entry exists.
    async fn get(
        &self,
        id: ConnectionId,
        slot: Slot,
    ) -> Result<Option<SealedCredential>, StoreError>;

    /// Enumerate every distinct `ConnectionId` for which at least one
    /// sealed slot is persisted (deduped across slots). Callers that need
    /// a specific slot's envelope follow up with [`Self::get`].
    ///
    /// Implementations MUST:
    /// - Skip dotfiles, editor lockfiles (`#name#`), tempfiles
    ///   (`*.tmp.*`), the rotation marker, and any non-regular file
    ///   (symlinks, FIFOs).
    /// - Skip-and-warn on any `<ulid>-<slot>.sealed` filename whose ULID
    ///   prefix or slot label fails to parse (mirrors
    ///   `AgentIdentityStore::list` posture).
    /// - Tolerate the vault directory being absent — return `Ok(vec![])`.
    /// - NOT promise any particular order. Callers that need determinism
    ///   must sort.
    ///
    /// Used by Story 7.6 (`agentsso rotate-key`) to enumerate every vault
    /// entry that needs re-encryption under a fresh master key, and by
    /// `connection list` (Story 11.13).
    async fn list_connections(&self) -> Result<Vec<ConnectionId>, StoreError>;
}

/// Append audit events to a durable log.
///
/// Implementations MUST:
/// - write each event as a single JSONL line (no partial writes visible)
/// - call `fsync` after every append for tamper-evidence
/// - handle date-based and size-based rotation transparently
#[async_trait::async_trait]
pub trait AuditStore: Send + Sync {
    /// Append an audit event to the log. The event is serialized as a
    /// single JSON line and flushed to durable storage before returning.
    async fn append(&self, event: AuditEvent) -> Result<(), StoreError>;
}

/// Persist `AgentIdentity` records keyed by validated agent name (Story 4.4).
///
/// Implementations MUST:
/// - validate the agent name via `agent::validate_agent_name` before
///   any I/O (the `AgentIdentity` constructor already enforces this on
///   construction, but `remove(name)` and `get(name)` accept raw `&str`
///   inputs and re-validate)
/// - write atomically (tempfile → fsync → rename → fsync parent dir)
///   so a crash mid-write never leaves a half-written agent file
/// - set restrictive filesystem permissions (0o600 on Unix; agent files
///   live alongside the Argon2id hash and the HMAC lookup key — both
///   sensitive)
/// - return `Ok(None)` from `get` and `Ok(false)` from `remove` when
///   the named agent does not exist (these are not error conditions)
///
/// The trait is `async` because production adapters dispatch I/O to a
/// blocking worker via `tokio::task::spawn_blocking`.
#[async_trait::async_trait]
pub trait AgentIdentityStore: Send + Sync {
    /// Persist a new agent identity. Returns
    /// [`StoreError::AgentAlreadyExists`] if an agent with the same
    /// name is already registered (the on-disk file refuses to clobber).
    async fn put(&self, identity: AgentIdentity) -> Result<(), StoreError>;

    /// Retrieve an agent by name. Returns `Ok(None)` if no entry
    /// exists. Returns [`StoreError::InvalidAgentName`] if `name`
    /// violates the allowlist.
    async fn get(&self, name: &str) -> Result<Option<AgentIdentity>, StoreError>;

    /// List every registered agent. Order is implementation-defined;
    /// callers that need deterministic order should sort by `name`
    /// after the call.
    async fn list(&self) -> Result<Vec<AgentIdentity>, StoreError>;

    /// Remove an agent. Returns `Ok(true)` if a file was deleted,
    /// `Ok(false)` if no agent with that name existed. Returns
    /// [`StoreError::InvalidAgentName`] if `name` violates the
    /// allowlist.
    async fn remove(&self, name: &str) -> Result<bool, StoreError>;

    /// Update an existing agent's `last_seen_at` timestamp. Best-effort:
    /// implementations that prefer to skip the write under high load
    /// MAY return `Ok(())` without persisting. The auth hot path uses
    /// this on every successful authentication.
    async fn touch_last_seen(&self, identity: AgentIdentity) -> Result<(), StoreError>;

    /// Atomically rewrite the `lookup_key_hex` and `token_hash` fields
    /// of an existing agent. Used by `agentsso rotate-key`'s Phase E
    /// (Story 7.6b AC #11) to re-issue bearer tokens under the new
    /// master-derived subkey while preserving every other field
    /// (`name`, `policy_name`, `created_at`, `last_seen_at`).
    ///
    /// Implementations MUST:
    /// - validate `name` via `agent::validate_agent_name` and surface
    ///   [`StoreError::InvalidAgentName`] on failure
    /// - mirror `put`'s atomic-write discipline (tempfile → fsync →
    ///   rename → fsync parent dir; mode `0o600` on Unix in `0o700`
    ///   parent dir)
    /// - return `Ok(false)` if no agent with that name exists
    /// - return `Ok(true)` on a successful rewrite
    ///
    /// **Why a dedicated 2-field method:** operator-driven rotation
    /// must mutate `lookup_key_hex` AND `token_hash` atomically — a
    /// typed signature makes that a compiler-checked property rather
    /// than relying on convention. A generic `put_overwrite` would be
    /// a footgun for any future caller who reaches for "I just need
    /// to update some fields" and accidentally clobbers others.
    async fn update_lookup_key_and_token(
        &self,
        name: &str,
        new_lookup_key_hex: String,
        new_token_hash: String,
    ) -> Result<bool, StoreError>;
}
