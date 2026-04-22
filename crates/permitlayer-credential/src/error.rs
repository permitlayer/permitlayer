//! Error types for credential sealing/unsealing.

/// Errors that can occur during AEAD cryptographic operations on credentials.
///
/// Lives in the leaf credential crate so both the vault (produces/consumes
/// sealed envelopes) and higher layers (unseal failures surfacing through
/// `VaultError`) can reference the same variants.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum CryptoError {
    /// AEAD tag verification failed during unseal. Ciphertext has been
    /// tampered with, or the wrong subkey / AAD was used to attempt
    /// decryption. The AEAD primitive does NOT distinguish these cases
    /// by design.
    #[error("AEAD tag verification failed (ciphertext tampered or wrong key)")]
    AeadTagMismatch,
    /// AEAD encryption engine failed during seal. At MVP this is
    /// effectively unreachable with a valid 32-byte subkey — the
    /// `aes-gcm` crate returns an opaque `Err` on encrypt only in
    /// degenerate conditions (e.g., allocation failure inside the AEAD).
    #[error("AEAD encryption failed")]
    AeadEncryptFailed,
    /// Plaintext exceeded the vault's maximum seal size. Prevents unbounded
    /// memory allocation on seal and bounds on-disk envelope sizes.
    #[error("plaintext exceeded maximum seal size ({len} > {max})")]
    PlaintextTooLarge {
        /// Actual plaintext length in bytes.
        len: usize,
        /// Maximum permitted plaintext length in bytes.
        max: usize,
    },
}
