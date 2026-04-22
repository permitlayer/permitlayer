//! Agent identity registry — bearer-token → agent → policy binding (Story 4.4).
//!
//! This module owns the durable agent-identity layer that Story 4.4
//! introduces:
//!
//! - [`identity::AgentIdentity`] — the on-disk + in-memory record. Holds
//!   the agent's name, the bound policy name, the Argon2id at-rest hash
//!   of the bearer token, the per-agent salt, the sealed HMAC lookup
//!   key (hex-encoded; sealing happens at the daemon boundary), and
//!   timestamps. **No plaintext token bytes are ever stored on this
//!   struct.**
//! - [`identity::validate_agent_name`] — the path-traversal-safe
//!   character allowlist. Mirrors `validate_service_name` exactly.
//! - [`registry::AgentRegistry`] — the runtime cache, an
//!   `Arc<ArcSwap<RegistrySnapshot>>` so the auth hot path stays
//!   lock-free. The snapshot indexes agents by both `name` (for CRUD)
//!   and HMAC lookup key (for O(1) bearer-token validation).
//! - [`registry::hash_token`] / [`registry::verify_token`] — the
//!   Argon2id helpers used at register time and as the defense-in-depth
//!   verification step at auth time.
//! - [`registry::compute_lookup_key`] — the HMAC-SHA-256 derivation that
//!   produces the runtime index key from a plaintext token. The HMAC
//!   key itself is the daemon's master-derived "agent-token-lookup-v1"
//!   subkey (see `permitlayer-daemon::cli::start::run`).
//!
//! # The dual-index design
//!
//! Naive Argon2id-only auth is O(n × ~100ms) per request — fatal at any
//! registry size > 1. The dual-index design keeps the hot path O(1)
//! while preserving offline-brute-force resistance for the on-disk
//! hashes:
//!
//! 1. **At register time:** Generate a 32-byte plaintext token. Compute
//!    `argon2id_hash(plaintext, per_agent_salt)` for at-rest defense
//!    (written to `~/.agentsso/agents/<name>.toml`). Also compute
//!    `hmac_sha256(daemon_lookup_key, plaintext)` for the runtime
//!    index. Both go into the snapshot. The plaintext is dropped after
//!    register returns.
//! 2. **At daemon boot:** Each agent file holds the sealed HMAC lookup
//!    key. The daemon unseals it via `permitlayer-vault::Vault` and
//!    builds the in-memory `by_lookup_key` map.
//! 3. **At auth time:** HMAC the inbound token (~1 µs), look it up in
//!    the snapshot map (O(1)), then VERIFY by computing Argon2id
//!    against the stored hash (~100 ms). The double-check guarantees
//!    that an attacker who corrupts the in-memory map alone cannot
//!    forge a token without also defeating Argon2id on disk.
//!
//! See `docs/adrs/0003-agent-identity-token-lookup.md` for the full
//! design rationale, including alternatives considered.

pub mod identity;
pub mod registry;

pub use identity::{AgentIdentity, AgentIdentityRaw, AgentNameError, validate_agent_name};
pub use registry::{
    ARGON2_PARAMS_M_COST, ARGON2_PARAMS_P_COST, ARGON2_PARAMS_T_COST, AgentRegistry,
    BEARER_TOKEN_BYTES, BEARER_TOKEN_PREFIX, LOOKUP_KEY_BYTES, RegistrySnapshot,
    compute_lookup_key, generate_bearer_token_bytes, hash_token, lookup_key_from_hex,
    lookup_key_to_hex, verify_token,
};
