//! Sealed credential envelope.
//!
//! [`SealedCredential`] is the only credential type that may cross the
//! storage boundary. It contains ciphertext + nonce + AAD + version — no
//! plaintext material. The vault is the sole surface that produces or
//! consumes sealed credentials.

use static_assertions::assert_not_impl_any;
use zeroize::ZeroizeOnDrop;

/// Version marker for the sealed-credential envelope format. Bumping this
/// breaks backward compatibility with on-disk vault files.
///
/// **Story 7.6a (2026-04-27)** bumped this from 1 to 2. The v2 envelope
/// adds a `key_id: u8` field at offset 3 (immediately after `nonce_len`)
/// so the vault is self-describing — every sealed file records which
/// master key sealed it. Read-only fallback for v1 envelopes is provided
/// by `permitlayer-core::store::fs::credential_fs::decode_envelope` (it
/// synthesizes `key_id = 0` for v1). All NEW writes are v2.
pub const SEALED_CREDENTIAL_VERSION: u16 = 2;

/// Identifier of the master key that sealed an envelope (Story 7.6a).
///
/// Newtype around `u8` rather than a bare `u8` so the
/// [`SealedCredential::from_trusted_bytes`] constructor's two
/// consecutive integer parameters (`version: u16`, `key_id: KeyId`)
/// have distinct types — a swap-the-arguments typo fails to compile
/// instead of silently producing an envelope with `version = 0` (round-1
/// review patch).
///
/// Construct via [`KeyId::new`] (or `KeyId(value)` since the inner
/// field is public — pattern-matching is occasionally useful).
/// Read out via [`KeyId::value`] or `.0`.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct KeyId(pub u8);

impl KeyId {
    /// The bootstrap / single-key sentinel: every v1 envelope decodes
    /// with this value, and every fresh v2 envelope sealed before the
    /// first rotation carries it. Story 7.6b's rotate-key v2 will
    /// increment from this baseline.
    pub const ZERO: KeyId = KeyId(0);

    /// Wrap a raw `u8`.
    #[must_use]
    pub const fn new(v: u8) -> Self {
        Self(v)
    }

    /// Unwrap to the raw `u8`.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl From<u8> for KeyId {
    fn from(v: u8) -> Self {
        KeyId(v)
    }
}

impl From<KeyId> for u8 {
    fn from(k: KeyId) -> Self {
        k.0
    }
}

/// Maximum plaintext size (in bytes) the vault will seal. Used at seal time
/// by `permitlayer-vault` and at parse time by the filesystem store's
/// envelope parser to bound `ct_len` reads. Set to 64 KiB — orders of
/// magnitude larger than any OAuth token or bearer token that the MVP
/// stores, while remaining tractable for property-test round trips.
pub const MAX_PLAINTEXT_LEN: usize = 64 * 1024;

/// A sealed credential: AES-256-GCM ciphertext plus the metadata needed to
/// unseal it. Contains no plaintext credential material.
///
/// Construct via [`SealedCredential::from_trusted_bytes`]; unseal via the
/// vault in `permitlayer-vault`.
///
/// # Envelope schema v2 (Story 7.6a)
///
/// The `key_id: u8` field identifies which master key sealed this
/// envelope. In v2 (the current format) it's stamped by `Vault::seal`
/// at construction. In v1 (legacy on-disk format), envelopes synthesize
/// `key_id = 0` at decode time — the v1 → v2 migration in
/// `permitlayer-daemon::cli::migrations::envelope_v1_to_v2`
/// rewrites every v1 envelope to v2 with `key_id = 0`. After migration
/// the on-disk format is uniformly v2.
#[derive(ZeroizeOnDrop)]
pub struct SealedCredential {
    ciphertext: Box<[u8]>,
    nonce: [u8; 12],
    aad: Box<[u8]>,
    version: u16,
    /// Which master key sealed this envelope. `0` for the current single
    /// key world (Story 7.6a) and for v1 envelopes synthesized at
    /// decode time. Future rotation (Story 7.6b) increments this on
    /// every reseal so the daemon can detect mixed-key vaults at boot.
    key_id: u8,
}

impl SealedCredential {
    /// Construct a sealed envelope. The caller — typically the vault — is
    /// responsible for having produced the ciphertext via a legitimate
    /// AEAD seal operation.
    ///
    /// **Story 7.6a:** the `key_id` parameter identifies which master
    /// key sealed this envelope. Pass [`KeyId::ZERO`] in single-key
    /// worlds; pass the active `KeyId` during rotation (Story 7.6b).
    /// The newtype prevents arg-swap typos with `version: u16`
    /// (Story 7.6a round-1 review patch).
    #[must_use = "a SealedCredential that is immediately dropped is wasted work"]
    pub fn from_trusted_bytes(
        ciphertext: Vec<u8>,
        nonce: [u8; 12],
        aad: Vec<u8>,
        version: u16,
        key_id: KeyId,
    ) -> Self {
        Self {
            ciphertext: ciphertext.into_boxed_slice(),
            nonce,
            aad: aad.into_boxed_slice(),
            version,
            key_id: key_id.value(),
        }
    }

    /// Reveal the ciphertext bytes for persistence to disk. Safe to expose
    /// because the ciphertext is, by definition, not plaintext.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Reveal the 12-byte nonce used for this envelope's AEAD encryption.
    #[must_use]
    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    /// Reveal the AAD bytes associated with this envelope.
    #[must_use]
    pub fn aad(&self) -> &[u8] {
        &self.aad
    }

    /// The envelope format version.
    #[must_use]
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Which master key sealed this envelope. Story 7.6a:
    /// `0` for single-key world, `0` synthesized for v1 envelopes
    /// decoded under the v1 → v2 fallback path.
    #[must_use]
    pub fn key_id(&self) -> u8 {
        self.key_id
    }
}

// Path C defense-in-depth: compile-time proof that SealedCredential
// implements none of the forbidden traits, via derive OR hand-written impl.
//
// Rationale for this specific list (differs slightly from the newtype
// credential types): `SealedCredential` holds a STRUCTURED envelope
// (ciphertext + nonce + aad + version) rather than an opaque byte string.
// We forbid:
//
// - Copy/Clone: bitwise copy of nonce/key material is hazardous
// - Debug/Display: envelope metadata shouldn't land in logs
// - Default/PartialEq/Eq/Hash/PartialOrd/Ord: same rationale as byte tokens
// - AsMut<[u8]>, BorrowMut<[u8]>, DerefMut: TAMPER vectors — mutating
//   ciphertext bytes after sealing breaks AEAD integrity
// - From<Vec<u8>>, From<Box<[u8]>>, From<&'static [u8]>: CONSTRUCT vectors —
//   would allow forging an envelope without nonce/aad/version
// - Into<Vec<u8>>, Into<Box<[u8]>>: unwrap-via-coercion anti-pattern
//
// Read-only byte exposure (`AsRef<[u8]>`, `Borrow<[u8]>`, `Deref`) is NOT
// forbidden here because `ciphertext()` already exposes ciphertext bytes
// as a public getter — and ciphertext is, by definition, not plaintext.
assert_not_impl_any!(
    SealedCredential:
    Clone,
    Copy,
    core::fmt::Debug,
    core::fmt::Display,
    Default,
    PartialEq,
    Eq,
    core::hash::Hash,
    PartialOrd,
    Ord,
    AsMut<[u8]>,
    core::borrow::BorrowMut<[u8]>,
    core::ops::DerefMut,
    From<Vec<u8>>,
    From<Box<[u8]>>,
    From<&'static [u8]>,
    Into<Vec<u8>>,
    Into<Box<[u8]>>,
);

#[cfg(test)]
mod cfg_test_assertions {
    use super::*;
    // Test-time assertions using serde (dev-only dep).
    assert_not_impl_any!(
        SealedCredential:
        serde::Serialize,
        serde::de::DeserializeOwned,
        TryFrom<Vec<u8>>,
        TryFrom<Box<[u8]>>,
        TryFrom<&'static [u8]>,
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Story 7.6a AC #5: guard against accidental version rollback.
    /// The bump 1 → 2 is a load-bearing schema change for envelope-v2 +
    /// `key_id` plumbing; flipping it back without a migration would
    /// poison every v2-sealed file in the vault.
    #[test]
    fn version_constant_is_2() {
        assert_eq!(SEALED_CREDENTIAL_VERSION, 2);
    }

    /// Story 7.6a AC #5: `key_id` round-trips through the constructor.
    #[test]
    fn key_id_round_trips_via_constructor() {
        let sealed = SealedCredential::from_trusted_bytes(
            vec![0xAA; 32],
            [0x11u8; 12],
            b"aad".to_vec(),
            SEALED_CREDENTIAL_VERSION,
            KeyId(42),
        );
        assert_eq!(sealed.key_id(), 42);
    }

    /// Edge case: `key_id = 0` is a valid sentinel (single-key world,
    /// v1-synthesized envelopes); the type signature must accept it.
    #[test]
    fn key_id_zero_is_a_valid_value() {
        let sealed = SealedCredential::from_trusted_bytes(
            vec![0xAA; 32],
            [0x22u8; 12],
            b"aad".to_vec(),
            SEALED_CREDENTIAL_VERSION,
            KeyId::ZERO,
        );
        assert_eq!(sealed.key_id(), 0);
    }

    /// Round-1 review patch: the typed `KeyId` newtype prevents
    /// arg-swap typos at the `from_trusted_bytes` boundary. This
    /// test pins down the round-trip + the From<u8>/Into<u8>
    /// shorthand that callers use in practice.
    #[test]
    fn key_id_newtype_round_trips() {
        let k: KeyId = 7u8.into();
        assert_eq!(k.value(), 7);
        let raw: u8 = k.into();
        assert_eq!(raw, 7);
        assert_eq!(KeyId::ZERO.value(), 0);
        assert_eq!(KeyId::new(255).value(), 255);
    }
}
