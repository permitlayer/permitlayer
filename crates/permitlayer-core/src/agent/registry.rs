//! `AgentRegistry` — runtime cache + Argon2id/HMAC helpers (Story 4.4).
//!
//! The registry holds a snapshot of every agent the daemon knows about.
//! Reads go through `Arc<ArcSwap<RegistrySnapshot>>` so the auth hot
//! path is lock-free; writes (register / remove / reload-from-store)
//! atomically swap a fresh snapshot.
//!
//! # Indexing
//!
//! Each [`RegistrySnapshot`] holds two maps:
//!
//! - `by_name: HashMap<String, AgentIdentity>` — for `agentsso agent
//!   list` and CRUD lookups.
//! - `by_lookup_key: HashMap<[u8; 32], AgentIdentity>` — keyed by the
//!   HMAC-SHA-256(daemon_subkey, plaintext_token) output. Populated
//!   from the on-disk `lookup_key_hex` field at boot. The auth hot
//!   path computes the HMAC of the inbound token (~1 µs) and looks it
//!   up here in O(1).
//!
//! # The verification step is mandatory
//!
//! After an O(1) hit on `by_lookup_key`, the auth handler MUST also
//! call [`verify_token`] against the matched agent's Argon2id hash.
//! This is defense-in-depth: even if an attacker corrupts the
//! in-memory map (impossible without process compromise, but worth
//! defending against), they still cannot forge a token without
//! computing a valid Argon2id round-trip.
//!
//! # OWASP Argon2id parameters
//!
//! `m=19456 KiB, t=2, p=1` are the OWASP 2023 minimum for "interactive"
//! password storage. They target ~100 ms on modern hardware. **Do not
//! lower them.** Lowering weakens at-rest defense; raising them blows
//! the boot-time budget when the daemon hash-verifies on every login.
//! Lock them via the `ARGON2_PARAMS_*` constants and treat any change
//! as a security review trigger.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

use super::identity::AgentIdentity;

// ──────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────

/// Length of the raw bearer token in bytes (before prefix + base64 encoding).
pub const BEARER_TOKEN_BYTES: usize = 32;

/// String prefix on every issued bearer token. Lets operators grep for
/// `agt_v1_` in stack traces, screenshots, and incident reports without
/// false positives. The `_v1_` segment leaves room for a future format
/// rotation without breaking existing tokens.
pub const BEARER_TOKEN_PREFIX: &str = "agt_v1_";

/// Length of the HMAC-SHA-256 lookup key in bytes (256 bits / 8).
pub const LOOKUP_KEY_BYTES: usize = 32;

/// OWASP-recommended Argon2id memory cost in KiB (interactive auth, 2023).
/// `m=19456` ≈ 19 MiB per verification. Combined with `t=2` and `p=1`
/// targets ~100 ms on a modern x86_64 core.
pub const ARGON2_PARAMS_M_COST: u32 = 19_456;
/// OWASP-recommended Argon2id time cost (number of iterations).
pub const ARGON2_PARAMS_T_COST: u32 = 2;
/// OWASP-recommended Argon2id parallelism (lanes). Single-threaded
/// keeps verification deterministic and avoids the multi-thread spin-up
/// cost on a per-request hot path.
pub const ARGON2_PARAMS_P_COST: u32 = 1;

// ──────────────────────────────────────────────────────────────────
// Token generation
// ──────────────────────────────────────────────────────────────────

/// Generate 32 bytes of cryptographically random material from `OsRng`.
///
/// The caller is responsible for prefixing + base64-encoding to produce
/// the final `agt_v1_*` user-facing token. This function returns raw
/// bytes so the prefix encoding decision lives in one place
/// (`permitlayer-daemon::server::control::register_agent_handler`).
///
/// `OsRng` panics on entropy failure — same fail-stop policy as the
/// vault nonce generator. Random source failure is catastrophic and
/// non-recoverable.
#[must_use]
pub fn generate_bearer_token_bytes() -> [u8; BEARER_TOKEN_BYTES] {
    let mut buf = [0u8; BEARER_TOKEN_BYTES];
    OsRng.fill_bytes(&mut buf);
    buf
}

// ──────────────────────────────────────────────────────────────────
// Argon2id helpers (at-rest hash)
// ──────────────────────────────────────────────────────────────────

/// Hash a plaintext bearer token with Argon2id and the OWASP-pinned
/// parameters. Returns the PHC string (`$argon2id$v=19$m=...$salt$hash`)
/// suitable for direct storage in the agent TOML file.
///
/// A fresh per-call salt is generated from `OsRng` — Argon2id's salt
/// must be unique per credential.
///
/// # Errors
///
/// Returns the underlying `argon2::password_hash::Error` if hashing
/// fails. In practice this only happens if the OWASP parameters are
/// out-of-range, which they aren't — but the function is fallible by
/// API design and we propagate cleanly rather than `expect`-ing.
pub fn hash_token(plaintext: &[u8]) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    #[allow(clippy::expect_used)] // Constants are static-checked OWASP values.
    let params =
        Params::new(ARGON2_PARAMS_M_COST, ARGON2_PARAMS_T_COST, ARGON2_PARAMS_P_COST, None)
            .expect("OWASP-pinned Argon2 params must construct");
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    Ok(hasher.hash_password(plaintext, &salt)?.to_string())
}

/// Verify a plaintext bearer token against a stored PHC hash string.
///
/// Returns `true` on a match, `false` on mismatch (including the case
/// where the stored PHC string is malformed — fail-closed: a corrupted
/// hash file should never authenticate, ever).
#[must_use]
pub fn verify_token(plaintext: &[u8], phc: &str) -> bool {
    let parsed = match PasswordHash::new(phc) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default().verify_password(plaintext, &parsed).is_ok()
}

// ──────────────────────────────────────────────────────────────────
// HMAC lookup-key derivation
// ──────────────────────────────────────────────────────────────────

type HmacSha256 = Hmac<Sha256>;

/// Compute the HMAC-SHA-256 lookup key for a plaintext bearer token.
///
/// The `daemon_subkey` is the 32-byte key derived from the daemon's
/// master key via HKDF with the info string
/// `b"permitlayer-agent-token-lookup-v1"`. See
/// `permitlayer-daemon::cli::start::run` for the derivation site and
/// `docs/adrs/0003-agent-identity-token-lookup.md` for the rationale.
///
/// # Panics
///
/// `Hmac::new_from_slice` only fails for zero-length keys, which is
/// architecturally impossible here — `daemon_subkey` is always 32
/// bytes by construction. We `expect` rather than thread the error.
#[must_use]
pub fn compute_lookup_key(
    daemon_subkey: &[u8; LOOKUP_KEY_BYTES],
    plaintext: &[u8],
) -> [u8; LOOKUP_KEY_BYTES] {
    #[allow(clippy::expect_used)] // 32-byte key never fails new_from_slice
    let mut mac =
        HmacSha256::new_from_slice(daemon_subkey).expect("HMAC-SHA-256 accepts any non-empty key");
    mac.update(plaintext);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; LOOKUP_KEY_BYTES];
    out.copy_from_slice(&result);
    out
}

/// Encode a 32-byte lookup key as a 64-character hex string for TOML
/// storage in `AgentIdentity::lookup_key_hex`.
#[must_use]
pub fn lookup_key_to_hex(key: &[u8; LOOKUP_KEY_BYTES]) -> String {
    let mut s = String::with_capacity(LOOKUP_KEY_BYTES * 2);
    for b in key {
        // Hand-rolled hex avoids pulling in the `hex` crate.
        s.push(nibble_to_hex(b >> 4));
        s.push(nibble_to_hex(b & 0x0f));
    }
    s
}

/// Decode a 64-character hex string into a 32-byte lookup key.
///
/// Returns `None` on length mismatch or any non-hex character. The
/// caller (registry boot code) treats `None` as a corrupted agent file
/// and skips the agent rather than panicking.
#[must_use]
pub fn lookup_key_from_hex(s: &str) -> Option<[u8; LOOKUP_KEY_BYTES]> {
    if s.len() != LOOKUP_KEY_BYTES * 2 {
        return None;
    }
    let mut out = [0u8; LOOKUP_KEY_BYTES];
    let bytes = s.as_bytes();
    for (i, chunk) in bytes.chunks(2).enumerate() {
        let hi = hex_to_nibble(chunk[0])?;
        let lo = hex_to_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

#[inline]
fn nibble_to_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => unreachable!("nibble must be 0..=15"),
    }
}

#[inline]
fn hex_to_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

// ──────────────────────────────────────────────────────────────────
// RegistrySnapshot — the immutable in-memory map
// ──────────────────────────────────────────────────────────────────

/// One immutable view of the agent registry.
///
/// Constructed by [`RegistrySnapshot::from_agents`] and never mutated
/// in place — every change replaces the snapshot via `ArcSwap::store`.
/// Cloning is cheap (the inner maps are not cloned; the wrapping
/// snapshot is held as `Arc<RegistrySnapshot>` inside `AgentRegistry`).
#[derive(Debug, Default)]
pub struct RegistrySnapshot {
    by_name: HashMap<String, AgentIdentity>,
    by_lookup_key: HashMap<[u8; LOOKUP_KEY_BYTES], AgentIdentity>,
}

impl RegistrySnapshot {
    /// Build a snapshot from a list of validated agents.
    ///
    /// Agents whose `lookup_key_hex` cannot be parsed are SKIPPED with
    /// a `tracing::warn!` — a corrupted entry in one file should not
    /// disable the entire registry. The skipped agent is structurally
    /// invisible to the auth path until the operator fixes the file.
    #[must_use]
    pub fn from_agents(agents: Vec<AgentIdentity>) -> Self {
        let mut by_name = HashMap::with_capacity(agents.len());
        let mut by_lookup_key = HashMap::with_capacity(agents.len());
        for agent in agents {
            let Some(key) = lookup_key_from_hex(&agent.lookup_key_hex) else {
                tracing::warn!(
                    agent_name = %agent.name(),
                    "skipping agent with malformed lookup_key_hex (not 64-char hex)"
                );
                continue;
            };
            by_name.insert(agent.name().to_owned(), agent.clone());
            by_lookup_key.insert(key, agent);
        }
        Self { by_name, by_lookup_key }
    }

    /// Number of registered agents in this snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Whether the snapshot has zero agents.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// Look up an agent by HMAC lookup key. O(1).
    ///
    /// # Timing
    ///
    /// This lookup uses `HashMap<[u8;32], _>` with `RandomState` (SipHash-1-3,
    /// randomly seeded per `HashMap` construction). The random seed prevents
    /// hash-flooding but the key comparison is still **NOT** constant-time
    /// with respect to a timing side-channel adversary. Per ADR 0003's threat
    /// model, a pinned-core local adversary with sub-microsecond precision is
    /// excluded by the single-user trust model.
    #[must_use]
    pub fn lookup_by_key(&self, key: &[u8; LOOKUP_KEY_BYTES]) -> Option<&AgentIdentity> {
        self.by_lookup_key.get(key)
    }

    /// Look up an agent by name. Used by CRUD paths and tests.
    #[must_use]
    pub fn get_by_name(&self, name: &str) -> Option<&AgentIdentity> {
        self.by_name.get(name)
    }

    /// All agents, sorted by name. Used by `agentsso agent list` so
    /// the operator-facing output is deterministic.
    #[must_use]
    pub fn agents_sorted(&self) -> Vec<AgentIdentity> {
        let mut v: Vec<AgentIdentity> = self.by_name.values().cloned().collect();
        v.sort_by(|a, b| a.name().cmp(b.name()));
        v
    }
}

// ──────────────────────────────────────────────────────────────────
// AgentRegistry — the ArcSwap-protected handle
// ──────────────────────────────────────────────────────────────────

/// The runtime agent registry. Lock-free reads via `ArcSwap`.
///
/// Cloned references (`Arc<AgentRegistry>`) are passed into `AuthLayer`
/// and the control-plane handlers. The registry itself is the swap
/// boundary; the snapshot inside is immutable.
pub struct AgentRegistry {
    snapshot: ArcSwap<RegistrySnapshot>,
}

impl AgentRegistry {
    /// Construct a registry seeded from an initial set of agents.
    /// `agents` may be empty — an empty registry is the boot state
    /// before any `agentsso agent register` runs.
    #[must_use]
    pub fn new(agents: Vec<AgentIdentity>) -> Self {
        Self { snapshot: ArcSwap::from_pointee(RegistrySnapshot::from_agents(agents)) }
    }

    /// Atomically swap in a fresh snapshot built from the supplied
    /// agent list. Returns the new agent count.
    pub fn replace_with(&self, agents: Vec<AgentIdentity>) -> usize {
        let snapshot = RegistrySnapshot::from_agents(agents);
        let count = snapshot.len();
        self.snapshot.store(Arc::new(snapshot));
        count
    }

    /// Acquire a guard on the current snapshot. Use this for any
    /// `lookup_*` call — the guard keeps the snapshot alive for the
    /// duration of the borrow even if a concurrent `replace_with` runs.
    #[must_use]
    pub fn snapshot(&self) -> arc_swap::Guard<Arc<RegistrySnapshot>> {
        self.snapshot.load()
    }

    /// Number of agents in the current snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.snapshot.load().len()
    }

    /// Whether the registry currently has zero agents.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.snapshot.load().is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn fake_agent(name: &str, lookup_key: [u8; LOOKUP_KEY_BYTES]) -> AgentIdentity {
        AgentIdentity::new(
            name.to_owned(),
            "default".to_owned(),
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".to_owned(),
            lookup_key_to_hex(&lookup_key),
            Utc::now(),
            None,
        )
        .unwrap()
    }

    // ── Argon2id round-trip ───────────────────────────────────────

    #[test]
    fn argon2_hash_then_verify_round_trip() {
        let plaintext = b"agt_v1_some-random-token-bytes";
        let phc = hash_token(plaintext).unwrap();
        assert!(verify_token(plaintext, &phc));
    }

    #[test]
    fn argon2_verify_rejects_wrong_token() {
        let phc = hash_token(b"correct").unwrap();
        assert!(!verify_token(b"wrong", &phc));
    }

    #[test]
    fn argon2_verify_rejects_malformed_phc() {
        // Fail-closed on corrupted on-disk hash.
        assert!(!verify_token(b"anything", "not-a-phc-string"));
        assert!(!verify_token(b"anything", ""));
    }

    #[test]
    fn argon2_two_calls_produce_distinct_hashes() {
        // Per-call salt → different ciphertexts even for the same plaintext.
        let h1 = hash_token(b"same").unwrap();
        let h2 = hash_token(b"same").unwrap();
        assert_ne!(h1, h2);
        assert!(verify_token(b"same", &h1));
        assert!(verify_token(b"same", &h2));
    }

    // ── HMAC lookup key ───────────────────────────────────────────

    #[test]
    fn compute_lookup_key_is_deterministic() {
        let subkey = [0x42u8; LOOKUP_KEY_BYTES];
        let token = b"agt_v1_deterministic";
        assert_eq!(compute_lookup_key(&subkey, token), compute_lookup_key(&subkey, token));
    }

    #[test]
    fn compute_lookup_key_changes_with_subkey() {
        let token = b"agt_v1_test";
        let key_a = compute_lookup_key(&[0xAAu8; LOOKUP_KEY_BYTES], token);
        let key_b = compute_lookup_key(&[0xBBu8; LOOKUP_KEY_BYTES], token);
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn compute_lookup_key_changes_with_plaintext() {
        let subkey = [0x42u8; LOOKUP_KEY_BYTES];
        assert_ne!(compute_lookup_key(&subkey, b"alpha"), compute_lookup_key(&subkey, b"beta"));
    }

    #[test]
    fn lookup_key_hex_round_trip() {
        let key = [0x12u8; LOOKUP_KEY_BYTES];
        let hex = lookup_key_to_hex(&key);
        assert_eq!(hex.len(), 64);
        assert_eq!(lookup_key_from_hex(&hex), Some(key));
    }

    #[test]
    fn lookup_key_from_hex_rejects_wrong_length() {
        assert!(lookup_key_from_hex("abcd").is_none());
        assert!(lookup_key_from_hex(&"a".repeat(63)).is_none());
        assert!(lookup_key_from_hex(&"a".repeat(65)).is_none());
    }

    #[test]
    fn lookup_key_from_hex_rejects_non_hex_chars() {
        assert!(lookup_key_from_hex(&"z".repeat(64)).is_none());
        assert!(lookup_key_from_hex(&"!".repeat(64)).is_none());
    }

    #[test]
    fn lookup_key_from_hex_accepts_uppercase() {
        let upper = "AB".repeat(32);
        let lower = "ab".repeat(32);
        assert_eq!(lookup_key_from_hex(&upper), lookup_key_from_hex(&lower));
    }

    // ── generate_bearer_token_bytes ───────────────────────────────

    #[test]
    fn generated_token_has_correct_length() {
        let token = generate_bearer_token_bytes();
        assert_eq!(token.len(), BEARER_TOKEN_BYTES);
    }

    #[test]
    fn generated_tokens_are_distinct() {
        // Two consecutive calls with overwhelming probability return
        // distinct values. A collision would imply OsRng is broken.
        let a = generate_bearer_token_bytes();
        let b = generate_bearer_token_bytes();
        assert_ne!(a, b);
    }

    // ── RegistrySnapshot ──────────────────────────────────────────

    #[test]
    fn snapshot_from_empty_agents() {
        let snap = RegistrySnapshot::from_agents(vec![]);
        assert_eq!(snap.len(), 0);
        assert!(snap.is_empty());
    }

    #[test]
    fn snapshot_indexes_by_name_and_lookup_key() {
        let key = [0x33u8; LOOKUP_KEY_BYTES];
        let agent = fake_agent("agent1", key);
        let snap = RegistrySnapshot::from_agents(vec![agent]);
        assert!(snap.get_by_name("agent1").is_some());
        assert!(snap.lookup_by_key(&key).is_some());
        assert!(snap.get_by_name("nonexistent").is_none());
        assert!(snap.lookup_by_key(&[0u8; LOOKUP_KEY_BYTES]).is_none());
    }

    #[test]
    fn snapshot_skips_agents_with_malformed_lookup_key() {
        // Construct an AgentIdentity with a malformed (wrong-length)
        // lookup_key_hex via the raw type's deserialize gate.
        let raw = super::super::identity::AgentIdentityRaw {
            name: "broken".to_owned(),
            policy_name: "default".to_owned(),
            token_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".to_owned(),
            lookup_key_hex: "not-hex".to_owned(),
            created_at: Utc::now(),
            last_seen_at: None,
        };
        let bad_agent = raw.into_validated().unwrap();
        let snap = RegistrySnapshot::from_agents(vec![bad_agent]);
        assert_eq!(snap.len(), 0, "snapshot must skip agents with bad lookup_key_hex");
    }

    #[test]
    fn snapshot_agents_sorted_returns_deterministic_order() {
        let snap = RegistrySnapshot::from_agents(vec![
            fake_agent("zebra", [0x01u8; LOOKUP_KEY_BYTES]),
            fake_agent("alpha", [0x02u8; LOOKUP_KEY_BYTES]),
            fake_agent("mike", [0x03u8; LOOKUP_KEY_BYTES]),
        ]);
        let names: Vec<String> =
            snap.agents_sorted().into_iter().map(|a| a.name().to_owned()).collect();
        assert_eq!(names, vec!["alpha", "mike", "zebra"]);
    }

    // ── AgentRegistry swap semantics ──────────────────────────────

    #[test]
    fn registry_new_is_empty_when_no_agents() {
        let reg = AgentRegistry::new(vec![]);
        assert_eq!(reg.len(), 0);
        assert!(reg.is_empty());
    }

    #[test]
    fn registry_replace_with_swaps_snapshot() {
        let reg = AgentRegistry::new(vec![]);
        assert_eq!(reg.len(), 0);

        let new_count = reg.replace_with(vec![
            fake_agent("a1", [0x01u8; LOOKUP_KEY_BYTES]),
            fake_agent("a2", [0x02u8; LOOKUP_KEY_BYTES]),
        ]);
        assert_eq!(new_count, 2);
        assert_eq!(reg.len(), 2);
        assert!(reg.snapshot().get_by_name("a1").is_some());
    }

    #[test]
    fn registry_replace_with_drops_old_entries() {
        let reg = AgentRegistry::new(vec![fake_agent("old", [0x01u8; LOOKUP_KEY_BYTES])]);
        assert_eq!(reg.len(), 1);
        reg.replace_with(vec![fake_agent("new", [0x02u8; LOOKUP_KEY_BYTES])]);
        assert!(reg.snapshot().get_by_name("old").is_none());
        assert!(reg.snapshot().get_by_name("new").is_some());
    }

    // ── Concurrency: AC #13 ────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_lookups_during_swap() {
        // Spawn 16 reader tasks doing 1000 lookups each, alongside one
        // writer task doing 100 swaps. Assert no panics, no torn reads
        // (every lookup result is internally consistent — name and
        // policy_name match the same snapshot).
        let key_a = [0xAAu8; LOOKUP_KEY_BYTES];
        let key_b = [0xBBu8; LOOKUP_KEY_BYTES];

        let registry = Arc::new(AgentRegistry::new(vec![fake_agent("a-agent", key_a)]));

        let mut readers = Vec::new();
        for _ in 0..16 {
            let r = Arc::clone(&registry);
            readers.push(tokio::spawn(async move {
                for _ in 0..1000 {
                    let snap = r.snapshot();
                    if let Some(agent) = snap.lookup_by_key(&key_a) {
                        assert_eq!(agent.name(), "a-agent");
                        assert_eq!(agent.policy_name, "default");
                    }
                    if let Some(agent) = snap.lookup_by_key(&key_b) {
                        assert_eq!(agent.name(), "b-agent");
                        assert_eq!(agent.policy_name, "default");
                    }
                }
            }));
        }

        let writer_reg = Arc::clone(&registry);
        let writer = tokio::spawn(async move {
            for i in 0..100 {
                if i % 2 == 0 {
                    writer_reg.replace_with(vec![fake_agent("a-agent", key_a)]);
                } else {
                    writer_reg.replace_with(vec![
                        fake_agent("a-agent", key_a),
                        fake_agent("b-agent", key_b),
                    ]);
                }
                tokio::task::yield_now().await;
            }
        });

        for r in readers {
            r.await.unwrap();
        }
        writer.await.unwrap();
    }
}
