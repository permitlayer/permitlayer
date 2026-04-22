//! Error types for vault operations.

use permitlayer_credential::CryptoError;

/// Errors returned by vault seal/unseal operations.
///
/// Service names appear in error messages because they are not credential
/// material. Token plaintext NEVER appears in any variant's `Display` or
/// `Debug` impl — enforced by `OAuthToken` being non-`Debug` per the
/// credential type discipline.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum VaultError {
    /// AEAD seal (encrypt) failed. At MVP this is effectively unreachable
    /// with a valid 32-byte subkey, but the `aes-gcm` API returns `Err`
    /// on encrypt so we map it defensively.
    #[error("failed to seal credential for service '{service}'")]
    SealFailed {
        /// The service name the seal was attempted for.
        service: String,
        /// The underlying AEAD failure.
        #[source]
        source: CryptoError,
    },
    /// AEAD unseal (decrypt) failed. Returned on ciphertext tamper, wrong
    /// key, or cross-service subkey mismatch (HKDF info / AAD diverge).
    /// The vault NEVER returns a "best-effort" plaintext on tamper.
    #[error("failed to unseal credential for service '{service}'")]
    UnsealFailed {
        /// The service name the unseal was attempted for.
        service: String,
        /// The underlying AEAD failure.
        #[source]
        source: CryptoError,
    },
    /// HKDF-SHA256 subkey expansion failed. Only possible for output
    /// lengths > 255 * 32 = 8160 bytes, which cannot occur with this
    /// vault's fixed 32-byte subkey size. Mapped defensively.
    #[error("HKDF subkey derivation failed for service '{service}'")]
    SubkeyDerivationFailed {
        /// The service name whose subkey derivation failed.
        service: String,
    },
    /// The sealed envelope's version does not match the version this
    /// vault knows how to unseal. Bumping `SEALED_CREDENTIAL_VERSION`
    /// (in `permitlayer-credential`) triggers this for older envelopes.
    #[error("sealed envelope version {got} is unsupported (expected {expected})")]
    UnsupportedVersion {
        /// The version found on the envelope.
        got: u16,
        /// The version this vault knows how to unseal.
        expected: u16,
    },
    /// Service name exceeds the vault's length limit. Prevents unbounded
    /// AAD allocation and ensures the on-disk envelope's `MAX_AAD_LEN`
    /// cap is satisfied by construction.
    #[error("service name too long ({len} bytes, max {max})")]
    ServiceNameTooLong {
        /// Truncated service name (safe to log — service names are not
        /// credential material).
        service: String,
        /// Actual byte length of the service name.
        len: usize,
        /// Maximum permitted byte length.
        max: usize,
    },
}
