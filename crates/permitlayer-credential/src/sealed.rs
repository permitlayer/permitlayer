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
pub const SEALED_CREDENTIAL_VERSION: u16 = 1;

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
#[derive(ZeroizeOnDrop)]
pub struct SealedCredential {
    ciphertext: Box<[u8]>,
    nonce: [u8; 12],
    aad: Box<[u8]>,
    version: u16,
}

impl SealedCredential {
    /// Construct a sealed envelope. The caller — typically the vault — is
    /// responsible for having produced the ciphertext via a legitimate
    /// AEAD seal operation.
    #[must_use = "a SealedCredential that is immediately dropped is wasted work"]
    pub fn from_trusted_bytes(
        ciphertext: Vec<u8>,
        nonce: [u8; 12],
        aad: Vec<u8>,
        version: u16,
    ) -> Self {
        Self {
            ciphertext: ciphertext.into_boxed_slice(),
            nonce,
            aad: aad.into_boxed_slice(),
            version,
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
