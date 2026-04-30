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
use zeroize::Zeroizing;

use super::identity::{AgentIdentity, MAX_AGENT_NAME_LEN, validate_agent_name};

// ──────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────

/// Length of the raw bearer token in bytes (before prefix + base64 encoding).
pub const BEARER_TOKEN_BYTES: usize = 32;

/// String prefix on every issued bearer token. Lets operators grep for
/// `agt_v2_` in stack traces, screenshots, and incident reports without
/// false positives. The `_v2_` segment encodes the on-the-wire format
/// version: Story 7.6b switched from `agt_v1_<base64>` to
/// `agt_v2_<name>_<base64>` so the auth path can parse the agent name
/// directly from the token, compute a single HMAC against the agent's
/// `lookup_key_hex` index, and verify in O(1) regardless of registry
/// size.
///
/// Existing `agt_v1_*` tokens are NOT accepted post-7.6b. Operators
/// migrate by re-running `agentsso rotate-key` (issues fresh v2
/// tokens for every agent) or by re-registering each agent via
/// `agentsso agent register <name>`.
pub const BEARER_TOKEN_PREFIX: &str = "agt_v2_";

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

/// HKDF-SHA256 info string used to expand the master key into the
/// daemon's agent-token lookup subkey. ALL derivers (cli::start at boot,
/// rotate-key Phase E) MUST pass this exact byte string — a divergence
/// silently breaks v2 token authentication after rotation. Hoisted to a
/// shared constant after Story 7.6b code review flagged the duplicated
/// string-literal as a maintenance hazard.
pub const AGENT_LOOKUP_HKDF_INFO: &[u8] = b"permitlayer-agent-token-lookup-v1";

// ──────────────────────────────────────────────────────────────────
// Token generation
// ──────────────────────────────────────────────────────────────────

/// Maximum size (in decoded bytes) we are willing to accept for a v2
/// token's random suffix. Legitimate tokens have exactly
/// `BEARER_TOKEN_BYTES` (32) — anything beyond 64 bytes is structurally
/// impossible for a well-formed v2 token AND a vector for log/audit
/// inflation if a future bug allowed oversize suffixes through. Used
/// by `parse_v2_token` to fail fast on malformed input.
pub const MAX_V2_TOKEN_RANDOM_BYTES: usize = 64;

/// Maximum agent-name length accepted by [`parse_v2_token`]. Coupled
/// to [`MAX_AGENT_NAME_LEN`] so a future bump of the validator's
/// ceiling automatically widens the parser — preventing silent
/// "registered agent's token is rejected by the parser" drift.
pub const MAX_V2_TOKEN_NAME_BYTES: usize = MAX_AGENT_NAME_LEN;

/// Length, in URL-safe-no-padding base64 characters, of a legitimate
/// random suffix encoding [`BEARER_TOKEN_BYTES`] = 32 bytes. 32 bytes
/// → ceil(32 * 8 / 6) = 43 chars, no padding.
const V2_TOKEN_RANDOM_B64_LEN: usize = 43;

/// Parse a `agt_v2_<name>_<base64-random>` bearer token into
/// `(name, random_bytes)`. Returns `None` on any malformed input —
/// missing prefix, missing `_` separator between name and random,
/// invalid agent name, name that fails the validator, random suffix
/// not exactly [`BEARER_TOKEN_BYTES`] decoded bytes, or
/// non-URL-safe-base64 random suffix. Story 7.6b AC #12.
///
/// The `name` slice borrows from the input `token`; the random bytes
/// are decoded into an owned `Vec<u8>`.
///
/// # Why exactly 32 bytes (not "≤ MAX")
///
/// Story 7.6b round-1 review caught a DoS amplification: under the
/// original `random.is_empty() || random.len() > MAX` rule, a 1-byte
/// random suffix passed the parser, hit the registry HMAC index (since
/// the HMAC is over `name`, not `random`), and burned ~100 ms of
/// Argon2id work per request on attacker-controlled input. The fix is
/// a tight equality check — legitimate tokens are always exactly 32
/// bytes (`BEARER_TOKEN_BYTES`), so anything else is malformed.
///
/// # Leading `_` in the random suffix is legitimate
///
/// `_` is a valid character in the URL-safe base64 alphabet (index 63).
/// About 1 in 64 of the 32-byte random values minted by
/// `register_agent_handler` encode to a base64 string starting with
/// `_` — specifically, when the first byte's top six bits are
/// `0b111111` (i.e. the first byte is in `0xFC..=0xFF`). The encoded
/// token then looks like `agt_v2_<agent>__<rest>`. There is no
/// ambiguity: agent names reject `_` (allowlist is `[a-z0-9-]`), and
/// `split_once('_')` always splits on the first underscore — the one
/// after `<agent>`. A pre-7.6b reading worried that two materially-
/// different token strings could HMAC-hit the same agent, but that
/// concern was wrong: the HMAC is keyed by the agent name only, and
/// the parser deterministically produces the same `(name, random)`
/// for any well-formed input. The previous rejection of leading `_`
/// caused the daemon to mint legitimate tokens it would later refuse
/// to authenticate (~1.5% of register-then-auth flake rate).
///
/// # Why URL-safe base64 alphabet
///
/// `register_agent_handler` emits the random suffix via the same
/// URL-safe-no-padding encoder used since Story 4.4. v2 keeps that
/// alphabet unchanged — the format change is structural (name in
/// prefix), not encoding.
#[must_use]
pub fn parse_v2_token(token: &str) -> Option<(&str, Vec<u8>)> {
    // 1. Strip the `agt_v2_` prefix; reject any other shape.
    let body = token.strip_prefix(BEARER_TOKEN_PREFIX)?;

    // 2. Split on the FIRST `_` to extract `name` and `random`.
    //    Validated agent names allow `[a-z0-9-]` only — no underscores
    //    — so the first `_` cleanly separates name from random. The
    //    random suffix MAY itself begin with `_` (it's a valid base64-
    //    url char); see the doc comment.
    let (name, random_b64) = body.split_once('_')?;

    // 3. Cheap structural rejects BEFORE the validator / decoder.
    if name.is_empty() || name.len() > MAX_V2_TOKEN_NAME_BYTES {
        return None;
    }
    if random_b64.len() != V2_TOKEN_RANDOM_B64_LEN {
        return None;
    }

    // 4. Validate the agent-name against the allowlist.
    validate_agent_name(name).ok()?;

    // 5. Decode the URL-safe-no-padding random suffix and require the
    //    exact byte length we mint at registration time.
    let random = base64_url_no_pad_decode(random_b64)?;
    if random.len() != BEARER_TOKEN_BYTES {
        return None;
    }
    Some((name, random))
}

/// URL-safe base64 decode without padding (RFC 4648 §5).
/// Mirrors the encoder used by `register_agent_handler`. Returns `None`
/// on any non-alphabet byte or invalid trailing-character count.
fn base64_url_no_pad_decode(s: &str) -> Option<Vec<u8>> {
    // Lookup table: index by ASCII byte → 6-bit value (or 0xFF for
    // "not in alphabet"). Hand-rolled to keep `parse_v2_token`
    // dependency-free.
    const fn build_table() -> [u8; 256] {
        let mut t = [0xFFu8; 256];
        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut i = 0;
        while i < chars.len() {
            t[chars[i] as usize] = i as u8;
            i += 1;
        }
        t
    }
    const TABLE: [u8; 256] = build_table();

    let bytes = s.as_bytes();
    // Trailing-character count: 0, 2, or 3 chars after groups of 4.
    // 1 leftover char never produces an integer byte count.
    let rem = bytes.len() % 4;
    if rem == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let a = TABLE[bytes[i] as usize];
        let b = TABLE[bytes[i + 1] as usize];
        let c = TABLE[bytes[i + 2] as usize];
        let d = TABLE[bytes[i + 3] as usize];
        if a == 0xFF || b == 0xFF || c == 0xFF || d == 0xFF {
            return None;
        }
        let n = (u32::from(a) << 18) | (u32::from(b) << 12) | (u32::from(c) << 6) | u32::from(d);
        out.push(((n >> 16) & 0xFF) as u8);
        out.push(((n >> 8) & 0xFF) as u8);
        out.push((n & 0xFF) as u8);
        i += 4;
    }
    if rem == 2 {
        let a = TABLE[bytes[i] as usize];
        let b = TABLE[bytes[i + 1] as usize];
        if a == 0xFF || b == 0xFF {
            return None;
        }
        // Story 7.6b round-2 review: canonical-encoding check (RFC
        // 4648 §3.5). With 2 chars (12 bits) decoding to 1 byte (8
        // bits), the trailing 4 bits of `b` MUST be zero. Otherwise
        // an attacker could construct a different 2-char string
        // that decodes to the same byte (varying the unused bits)
        // and bypass token-string-based comparisons in defense-in-
        // depth code paths. We currently HMAC over the agent name
        // (not the token bytes), so this isn't a critical break,
        // but enforcing the canonical encoding closes a class of
        // bug-prone surface.
        if (b & 0x0F) != 0 {
            return None;
        }
        let n = (u32::from(a) << 18) | (u32::from(b) << 12);
        out.push(((n >> 16) & 0xFF) as u8);
    } else if rem == 3 {
        let a = TABLE[bytes[i] as usize];
        let b = TABLE[bytes[i + 1] as usize];
        let c = TABLE[bytes[i + 2] as usize];
        if a == 0xFF || b == 0xFF || c == 0xFF {
            return None;
        }
        // Same canonical check: 3 chars (18 bits) → 2 bytes (16
        // bits), so the trailing 2 bits of `c` MUST be zero.
        if (c & 0x03) != 0 {
            return None;
        }
        let n = (u32::from(a) << 18) | (u32::from(b) << 12) | (u32::from(c) << 6);
        out.push(((n >> 16) & 0xFF) as u8);
        out.push(((n >> 8) & 0xFF) as u8);
    }
    Some(out)
}

/// URL-safe base64 encode without padding (RFC 4648 §5). Story 7.6b
/// adds this here so rotation's Phase E can format the new
/// `agt_v2_<name>_<random>` tokens without depending on the daemon's
/// hand-rolled encoder. The output alphabet matches
/// [`base64_url_no_pad_decode`].
#[must_use]
pub fn base64_url_no_pad_encode(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len() * 4 / 3 + 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n =
            (u32::from(bytes[i]) << 16) | (u32::from(bytes[i + 1]) << 8) | u32::from(bytes[i + 2]);
        out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 6) & 0x3f) as usize] as char);
        out.push(CHARS[(n & 0x3f) as usize] as char);
        i += 3;
    }
    if i + 2 == bytes.len() {
        let n = (u32::from(bytes[i]) << 16) | (u32::from(bytes[i + 1]) << 8);
        out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 6) & 0x3f) as usize] as char);
    } else if i + 1 == bytes.len() {
        let n = u32::from(bytes[i]) << 16;
        out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
    }
    out
}

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

    /// Story 7.6b AC #12 — build a snapshot AND sanity-check every
    /// agent's on-disk `lookup_key_hex` against the value recomputed
    /// from the daemon's master-derived subkey. Agents whose stored
    /// hex disagrees with the recomputed HMAC are SKIPPED from the
    /// index with a structured `tracing::warn!`. This catches the
    /// "rotation interrupted mid-Phase-E" state where some agent
    /// files still hold an HMAC keyed by the OLD subkey.
    ///
    /// Boot stays read-only — no auto-rewrite. The operator is
    /// expected to re-run `agentsso rotate-key`, which idempotently
    /// completes Phase E and brings every agent back into the index.
    /// Until then, an unindexed agent's auth requests return 401.
    #[must_use]
    pub fn from_agents_checked(
        agents: Vec<AgentIdentity>,
        daemon_subkey: &[u8; LOOKUP_KEY_BYTES],
    ) -> Self {
        let mut by_name = HashMap::with_capacity(agents.len());
        let mut by_lookup_key = HashMap::with_capacity(agents.len());
        // Story 7.6b round-2 review: aggregate stale-lookup-key warns
        // into a single line. Pre-round-2 we emitted one warn per
        // stale agent at boot — for an operator with 1000 stale
        // agents (post-crash mass-rotation scenario) that's 1000
        // log lines per boot until they re-run rotate-key.
        let mut malformed: Vec<String> = Vec::new();
        let mut stale: Vec<String> = Vec::new();
        for agent in agents {
            let Some(stored_key) = lookup_key_from_hex(&agent.lookup_key_hex) else {
                malformed.push(agent.name().to_owned());
                continue;
            };
            let recomputed = compute_lookup_key(daemon_subkey, agent.name().as_bytes());
            if stored_key != recomputed {
                stale.push(agent.name().to_owned());
                // Still keep the agent visible to CRUD by name (so
                // `agentsso agent list/remove` can act on it), but
                // structurally invisible to the auth hot path.
                by_name.insert(agent.name().to_owned(), agent);
                continue;
            }
            by_name.insert(agent.name().to_owned(), agent.clone());
            by_lookup_key.insert(stored_key, agent);
        }
        if !malformed.is_empty() {
            let preview: Vec<&str> = malformed.iter().take(5).map(String::as_str).collect();
            tracing::warn!(
                count = malformed.len(),
                preview = ?preview,
                "skipping agents with malformed lookup_key_hex (not 64-char hex)"
            );
        }
        if !stale.is_empty() {
            let preview: Vec<&str> = stale.iter().take(5).map(String::as_str).collect();
            tracing::warn!(
                count = stale.len(),
                preview = ?preview,
                "skipping agents from auth index — lookup_key_hex does not match \
                 HMAC(daemon_subkey, agent_name). Re-run `agentsso rotate-key` to repair."
            );
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
///
/// # `daemon_subkey` and the Story 7.6b sanity check
///
/// When constructed via [`Self::with_subkey`], every snapshot build
/// (initial `agents` AND every subsequent `replace_with`) routes
/// through [`RegistrySnapshot::from_agents_checked`] — the registry
/// sanity-checks each agent's on-disk `lookup_key_hex` against the
/// HMAC recomputed from `daemon_subkey + agent.name()`. Mismatched
/// agents are dropped from the auth index with a structured warn.
/// This catches the post-Phase-E-crash state where some agent files
/// hold an HMAC keyed by the OLD subkey. Story 7.6b AC #12.
///
/// Tests that don't care about subkey sanity (most of them) construct
/// via [`Self::new`], which preserves the pre-7.6b "trust on-disk
/// hex" semantics. Production code paths in the daemon MUST use
/// `with_subkey`.
pub struct AgentRegistry {
    snapshot: ArcSwap<RegistrySnapshot>,
    /// Master-derived HMAC lookup subkey. `None` for tests / fixtures
    /// that don't have a real subkey; `Some` in production. When
    /// `Some`, every snapshot build verifies on-disk `lookup_key_hex`
    /// against the recomputed HMAC. Wrapped in `Zeroizing` so the
    /// backing allocation is scrubbed at registry drop.
    daemon_subkey: Option<Zeroizing<[u8; LOOKUP_KEY_BYTES]>>,
}

impl AgentRegistry {
    /// Construct a registry without a `daemon_subkey` — the legacy
    /// pre-7.6b path that trusts each agent's on-disk
    /// `lookup_key_hex` without sanity-checking it. Production code
    /// paths in the daemon MUST use [`Self::with_subkey`] instead;
    /// this constructor is retained for tests and pre-bootstrap code.
    #[must_use]
    pub fn new(agents: Vec<AgentIdentity>) -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(RegistrySnapshot::from_agents(agents)),
            daemon_subkey: None,
        }
    }

    /// Construct a registry with a `daemon_subkey` — every snapshot
    /// build (initial AND `replace_with`) sanity-checks each agent's
    /// on-disk `lookup_key_hex` against the recomputed HMAC and skips
    /// mismatches from the auth index. Story 7.6b AC #12.
    #[must_use]
    pub fn with_subkey(agents: Vec<AgentIdentity>, daemon_subkey: [u8; LOOKUP_KEY_BYTES]) -> Self {
        let subkey = Zeroizing::new(daemon_subkey);
        Self {
            snapshot: ArcSwap::from_pointee(RegistrySnapshot::from_agents_checked(agents, &subkey)),
            daemon_subkey: Some(subkey),
        }
    }

    /// Atomically swap in a fresh snapshot built from the supplied
    /// agent list. Returns the new agent count. When a
    /// `daemon_subkey` was supplied at construction, the snapshot
    /// build sanity-checks each agent's `lookup_key_hex` (Story 7.6b
    /// AC #12); otherwise it trusts the on-disk hex.
    pub fn replace_with(&self, agents: Vec<AgentIdentity>) -> usize {
        let snapshot = match self.daemon_subkey.as_deref() {
            Some(subkey) => RegistrySnapshot::from_agents_checked(agents, subkey),
            None => RegistrySnapshot::from_agents(agents),
        };
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
        let plaintext = b"agt_v2_some-random-token-bytes";
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
        let token = b"agt_v2_deterministic";
        assert_eq!(compute_lookup_key(&subkey, token), compute_lookup_key(&subkey, token));
    }

    #[test]
    fn compute_lookup_key_with_agent_name_is_deterministic() {
        // Story 7.6b AC #12: post-rotation, the message argument to
        // `compute_lookup_key` is the validated agent name, NOT the
        // bearer token. The HMAC must be deterministic over `name`.
        let subkey = [0x42u8; LOOKUP_KEY_BYTES];
        let name = b"my-agent";
        assert_eq!(compute_lookup_key(&subkey, name), compute_lookup_key(&subkey, name));
    }

    #[test]
    fn compute_lookup_key_changes_with_subkey() {
        let token = b"agt_v2_test";
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

    // ── Story 7.6b AC #12: parse_v2_token ─────────────────────────

    #[test]
    fn bearer_token_prefix_is_v2() {
        assert_eq!(BEARER_TOKEN_PREFIX, "agt_v2_");
    }

    #[test]
    fn parse_v2_token_round_trip() {
        let random_bytes = [0xABu8; BEARER_TOKEN_BYTES];
        let encoded = base64_url_no_pad_encode(&random_bytes);
        let token = format!("agt_v2_my-agent_{encoded}");
        let (name, decoded) = parse_v2_token(&token).unwrap();
        assert_eq!(name, "my-agent");
        assert_eq!(decoded.as_slice(), &random_bytes);
    }

    #[test]
    fn parse_v2_token_rejects_v1_prefix() {
        // Pre-7.6b tokens (`agt_v1_*`) must be rejected — operators
        // re-issue them via `agentsso rotate-key` or re-register.
        let random_bytes = [0xCDu8; BEARER_TOKEN_BYTES];
        let encoded = base64_url_no_pad_encode(&random_bytes);
        let token = format!("agt_v1_{encoded}");
        assert!(parse_v2_token(&token).is_none());
    }

    #[test]
    fn parse_v2_token_rejects_no_separator() {
        // `agt_v2_<name>` with no `_` between name and random.
        // (Note: `name` here also wouldn't validate, but the
        // separator check fires first.)
        assert!(parse_v2_token("agt_v2_namewithoutbase64").is_none());
    }

    #[test]
    fn parse_v2_token_rejects_invalid_name() {
        // Uppercase letters violate `validate_agent_name`'s allowlist.
        let random_bytes = [0xEFu8; BEARER_TOKEN_BYTES];
        let encoded = base64_url_no_pad_encode(&random_bytes);
        assert!(parse_v2_token(&format!("agt_v2_BadName_{encoded}")).is_none());
        // Dot in name — not in the allowlist.
        assert!(parse_v2_token(&format!("agt_v2_a.b_{encoded}")).is_none());
        // Oversized name (> MAX_V2_TOKEN_NAME_BYTES).
        let long_name = "a".repeat(MAX_V2_TOKEN_NAME_BYTES + 1);
        assert!(parse_v2_token(&format!("agt_v2_{long_name}_{encoded}")).is_none());
    }

    #[test]
    fn parse_v2_token_rejects_bad_base64() {
        // `*` is not in the URL-safe base64 alphabet.
        assert!(parse_v2_token("agt_v2_my-agent_***bad***").is_none());
        // Story 7.6b round-1 review: random suffix must be exactly
        // 32 bytes (43 base64 chars) — anything shorter is malformed
        // by definition, since `register_agent_handler` always mints
        // 32-byte randoms. This closes the DoS amp where a 1-2 byte
        // random could pass the parser, hit the registry HMAC index,
        // and burn ~100 ms of Argon2id work per request.
        assert!(parse_v2_token("agt_v2_my-agent_AB1").is_none()); // 2 bytes
        assert!(parse_v2_token("agt_v2_my-agent_A").is_none()); // 1 char
    }

    #[test]
    fn parse_v2_token_accepts_random_with_leading_underscore() {
        // ~1 in 64 of the 32-byte random values minted by
        // `register_agent_handler` encode to a base64 string starting
        // with `_` — specifically when the first byte's top six bits
        // are 0b111111 (i.e. first byte ∈ 0xFC..=0xFF). The encoded
        // token shape is `agt_v2_<agent>__<rest>`. There is no
        // ambiguity: agent names reject `_` so `split_once('_')`
        // always lands on the first underscore (the one after the
        // agent name), and the parser produces a deterministic
        // `(name, random)`. A pre-fix version of `parse_v2_token`
        // rejected this shape, causing the daemon to mint legitimate
        // tokens it would later 401 — surfaced as the
        // `auth.invalid_token` flake during the v0.3.0-rc.2 release
        // cycle on macos-15-intel/ubuntu/windows runners.
        let mut random_bytes = [0u8; BEARER_TOKEN_BYTES];
        random_bytes[0] = 0xFC;
        let encoded = base64_url_no_pad_encode(&random_bytes);
        assert_eq!(encoded.len(), V2_TOKEN_RANDOM_B64_LEN);
        assert!(
            encoded.starts_with('_'),
            "test precondition: encoded random must start with `_` to exercise the bug"
        );
        let token = format!("agt_v2_my-agent_{encoded}");
        let (name, decoded) = parse_v2_token(&token).expect("token must parse");
        assert_eq!(name, "my-agent");
        assert_eq!(decoded.as_slice(), &random_bytes);
    }

    #[test]
    fn parse_v2_token_rejects_empty_random() {
        assert!(parse_v2_token("agt_v2_my-agent_").is_none());
    }

    #[test]
    fn parse_v2_token_rejects_oversized_random() {
        // Story 7.6b round-1 review: random suffix must be exactly
        // BEARER_TOKEN_BYTES (32) — longer must reject as well.
        let huge = [0u8; MAX_V2_TOKEN_RANDOM_BYTES + 1];
        let encoded = base64_url_no_pad_encode(&huge);
        let token = format!("agt_v2_my-agent_{encoded}");
        assert!(parse_v2_token(&token).is_none());
    }

    #[test]
    fn parse_v2_token_rejects_short_random_below_canonical_length() {
        // Story 7.6b round-1 review: 31-byte random encodes to 42
        // chars; not the canonical 43-char shape. Must reject so the
        // parser cannot be coaxed into accepting weak-entropy tokens.
        let short = [0xAAu8; BEARER_TOKEN_BYTES - 1]; // 31 bytes
        let encoded = base64_url_no_pad_encode(&short);
        assert_ne!(encoded.len(), V2_TOKEN_RANDOM_B64_LEN);
        assert!(parse_v2_token(&format!("agt_v2_my-agent_{encoded}")).is_none());
    }

    #[test]
    fn base64_url_no_pad_round_trip() {
        // Spot-check the encoder/decoder pair across a few sizes.
        for size in [1, 2, 3, 4, 7, 31, 32, 33, 47] {
            let mut bytes = vec![0u8; size];
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(37);
            }
            let encoded = base64_url_no_pad_encode(&bytes);
            let decoded = base64_url_no_pad_decode(&encoded).unwrap();
            assert_eq!(bytes, decoded, "round-trip for size={size}");
        }
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
    fn from_agents_checked_skips_stale_lookup_keys_from_index() {
        // Story 7.6b AC #12: an agent whose on-disk lookup_key_hex was
        // computed under the OLD daemon subkey (i.e., a rotation that
        // crashed mid-Phase-E) is structurally invisible to the auth
        // index but still visible to `get_by_name` so CRUD works.
        let subkey_old = [0x11u8; LOOKUP_KEY_BYTES];
        let subkey_new = [0x22u8; LOOKUP_KEY_BYTES];

        // "stale" agent: lookup_key_hex computed under OLD subkey.
        let stale_lookup = compute_lookup_key(&subkey_old, b"stale-agent");
        let stale_agent = fake_agent("stale-agent", stale_lookup);

        // "fresh" agent: lookup_key_hex computed under NEW subkey.
        let fresh_lookup = compute_lookup_key(&subkey_new, b"fresh-agent");
        let fresh_agent = fake_agent("fresh-agent", fresh_lookup);

        let snap =
            RegistrySnapshot::from_agents_checked(vec![stale_agent, fresh_agent], &subkey_new);

        // Stale agent is visible by name (CRUD works) but NOT keyed
        // in the auth index.
        assert!(snap.get_by_name("stale-agent").is_some());
        assert!(snap.lookup_by_key(&stale_lookup).is_none());

        // Fresh agent is in both maps.
        assert!(snap.get_by_name("fresh-agent").is_some());
        assert!(snap.lookup_by_key(&fresh_lookup).is_some());
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
