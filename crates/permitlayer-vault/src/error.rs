//! Error types for vault operations.

use permitlayer_credential::{CryptoError, Slot};

/// Errors returned by vault seal/unseal operations.
///
/// The connection id (a ULID identifier, not credential material) and slot
/// label appear in error messages for diagnosis. Token plaintext NEVER
/// appears in any variant's `Display` or `Debug` — enforced by
/// `OAuthToken` being non-`Debug` per the credential type discipline.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum VaultError {
    /// AEAD seal (encrypt) failed. Effectively unreachable with a valid
    /// 32-byte subkey, but the `aes-gcm` API returns `Err` on encrypt so we
    /// map it defensively.
    #[error("failed to seal credential for connection '{connection}' slot '{slot}'")]
    SealFailed {
        /// The connection id (ULID text) the seal was attempted for.
        connection: String,
        /// The credential slot (access / refresh / client).
        slot: Slot,
        /// The underlying AEAD failure.
        #[source]
        source: CryptoError,
    },
    /// AEAD unseal (decrypt) failed. Returned on ciphertext tamper, wrong
    /// key, or a cross-connection / cross-slot subkey mismatch (HKDF info /
    /// AAD diverge). The vault NEVER returns a "best-effort" plaintext on
    /// tamper.
    #[error("failed to unseal credential for connection '{connection}' slot '{slot}'")]
    UnsealFailed {
        /// The connection id (ULID text) the unseal was attempted for.
        connection: String,
        /// The credential slot (access / refresh / client).
        slot: Slot,
        /// The underlying AEAD failure.
        #[source]
        source: CryptoError,
    },
    /// HKDF-SHA256 subkey expansion failed. Only possible for output
    /// lengths > 255 * 32 = 8160 bytes, which cannot occur with this
    /// vault's fixed 32-byte subkey size. Mapped defensively.
    #[error("HKDF subkey derivation failed for connection '{connection}' slot '{slot}'")]
    SubkeyDerivationFailed {
        /// The connection id (ULID text) whose subkey derivation failed.
        connection: String,
        /// The credential slot (access / refresh / client).
        slot: Slot,
    },
    /// The sealed envelope's version does not match the version this vault
    /// knows how to unseal. Bumping `SEALED_CREDENTIAL_VERSION` (in
    /// `permitlayer-credential`) triggers this for older envelopes.
    #[error("sealed envelope version {got} is unsupported (expected {expected})")]
    UnsupportedVersion {
        /// The version found on the envelope.
        got: u16,
        /// The version this vault knows how to unseal.
        expected: u16,
    },
}
