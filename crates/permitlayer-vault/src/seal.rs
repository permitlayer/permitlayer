//! AES-256-GCM vault: seal/unseal with per-service HKDF-SHA256 subkeys.
//!
//! # Cryptographic construction
//!
//! - **Master key:** 32 bytes, produced by `permitlayer-keystore::KeyStore`
//!   (OS keychain or Argon2id-derived from passphrase). The vault holds it
//!   as `Zeroizing<[u8; 32]>` so it is wiped on drop.
//! - **Per-service subkey:** HKDF-SHA256 expanded from the master key with
//!   `info = b"permitlayer-vault-v1:" || service_bytes`. A distinct
//!   32-byte subkey per service. Sealing with service A cannot be unsealed
//!   with service B (different info → different subkey → AEAD tag check
//!   fails).
//! - **AEAD:** AES-256-GCM, fresh 12-byte random nonce per `seal()` call
//!   (via `OsRng`). `aad = b"permitlayer-vault-v1:" || service_bytes` —
//!   defense-in-depth: even if subkey derivation collided, the AEAD AAD
//!   check on mismatched service names would still fail.
//!
//! # Nonce discipline
//!
//! 12 random bytes per seal. GCM's security requires nonce-uniqueness per
//! key; 96-bit random nonces have a birthday bound of ~2^32 calls per
//! subkey before collision probability becomes meaningful. For a
//! single-user daemon sealing <1000 credentials/day, this is ~10^7 years
//! of use before worrying about collision — acceptable without a
//! counter-based scheme.
//!
//! # No salt in HKDF
//!
//! HKDF's `salt` parameter is for randomizing a low-entropy IKM. The
//! master key is 32 random bytes (native keystore) or a 32-byte Argon2id
//! output (passphrase keystore) — already uniformly random. Adding a salt
//! would complicate rotation without meaningful security gain.

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use permitlayer_credential::{
    CryptoError, MAX_PLAINTEXT_LEN, OAuthRefreshToken, OAuthToken, SEALED_CREDENTIAL_VERSION,
    SealedCredential,
};
use permitlayer_keystore::MASTER_KEY_LEN;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::VaultError;

/// HKDF info prefix + AAD prefix. Versioned so a future crypto-scheme
/// change can be detected and migrated. Bumping `v1` → `v2` is a
/// breaking change: all existing sealed envelopes become unreadable.
const VAULT_DOMAIN_V1: &[u8] = b"permitlayer-vault-v1:";

/// Maximum service-name byte length the vault will accept. Caps the AAD
/// at `VAULT_DOMAIN_V1.len() + MAX_SERVICE_BYTES = 21 + 107 = 128`,
/// matching the on-disk envelope's `MAX_AAD_LEN` cap in `permitlayer-core`.
/// The store's `validate_service_name` enforces a tighter limit (64 chars),
/// but the vault is a separate trust boundary and must not assume callers
/// run the store validator first.
const MAX_SERVICE_BYTES: usize = 107;

/// AES-256-GCM tag size (bytes). The `aes-gcm` crate returns ciphertext
/// with this tag appended; no separate out-parameter. Used by `unseal`
/// for ciphertext-length bounds checking, and by tests to validate
/// expected ciphertext length.
const GCM_TAG_LEN: usize = 16;

/// AES-256-GCM vault for sealing/unsealing OAuth tokens.
///
/// Holds the master key as `Zeroizing<[u8; 32]>` — wiped on drop. Per-seal
/// subkeys are derived fresh via HKDF and are also zeroized on
/// function exit.
///
/// The vault does NOT validate service names. Service-name validation
/// happens at the `CredentialStore` boundary (in `permitlayer-core`)
/// where the string becomes a filesystem path. The vault accepts any
/// `&str` as a service identifier; HKDF + AAD binding prevent collisions
/// at the cryptographic layer.
pub struct Vault {
    master_key: Zeroizing<[u8; MASTER_KEY_LEN]>,
}

impl Vault {
    /// Construct a vault from a master key. Ownership of the key moves
    /// into the vault; the caller's `Zeroizing` buffer is consumed.
    #[must_use = "a Vault that is immediately dropped wastes the master key derivation"]
    pub fn new(master_key: Zeroizing<[u8; MASTER_KEY_LEN]>) -> Self {
        Self { master_key }
    }

    /// Seal an OAuth token for a service. Produces a `SealedCredential`
    /// containing ciphertext + nonce + AAD + version, with no plaintext.
    ///
    /// Returns `VaultError::SealFailed` if plaintext exceeds
    /// `MAX_PLAINTEXT_LEN` or if the AEAD engine reports failure (the
    /// latter is effectively unreachable with a valid 32-byte subkey).
    pub fn seal(&self, service: &str, token: &OAuthToken) -> Result<SealedCredential, VaultError> {
        self.seal_bytes(service, token.reveal())
    }

    /// Unseal a `SealedCredential` for a service. Returns the plaintext
    /// bytes wrapped in an `OAuthToken`.
    ///
    /// Fails closed on any tamper — returns `VaultError::UnsealFailed`
    /// with a `CryptoError::AeadTagMismatch` source if the AEAD tag
    /// does not verify. Returns `VaultError::UnsupportedVersion` if the
    /// envelope's version is not recognized.
    pub fn unseal(
        &self,
        service: &str,
        sealed: &SealedCredential,
    ) -> Result<OAuthToken, VaultError> {
        self.unseal_bytes(service, sealed).map(OAuthToken::from_trusted_bytes)
    }

    /// Seal an OAuth refresh token for a service.
    ///
    /// Identical cryptographic construction to [`Vault::seal`] but accepts
    /// `&OAuthRefreshToken`. The refresh token is stored under a distinct
    /// service key (e.g. `"gmail-refresh"`) so it gets a different HKDF
    /// subkey than the access token.
    pub fn seal_refresh(
        &self,
        service: &str,
        token: &OAuthRefreshToken,
    ) -> Result<SealedCredential, VaultError> {
        self.seal_bytes(service, token.reveal())
    }

    /// Unseal a `SealedCredential` for a service, returning an `OAuthRefreshToken`.
    ///
    /// Identical cryptographic construction to [`Vault::unseal`] but returns
    /// `OAuthRefreshToken` instead of `OAuthToken`.
    pub fn unseal_refresh(
        &self,
        service: &str,
        sealed: &SealedCredential,
    ) -> Result<OAuthRefreshToken, VaultError> {
        self.unseal_bytes(service, sealed).map(OAuthRefreshToken::from_trusted_bytes)
    }

    /// Shared seal implementation operating on raw bytes. Both `seal()` and
    /// `seal_refresh()` delegate here — the crypto is identical, only the
    /// wrapper type differs.
    fn seal_bytes(&self, service: &str, plaintext: &[u8]) -> Result<SealedCredential, VaultError> {
        if service.len() > MAX_SERVICE_BYTES {
            return Err(VaultError::ServiceNameTooLong {
                service: service.chars().take(64).collect(),
                len: service.len(),
                max: MAX_SERVICE_BYTES,
            });
        }
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(VaultError::SealFailed {
                service: service.to_owned(),
                source: CryptoError::PlaintextTooLarge {
                    len: plaintext.len(),
                    max: MAX_PLAINTEXT_LEN,
                },
            });
        }

        let subkey = derive_subkey(&self.master_key, service)
            .map_err(|_| VaultError::SubkeyDerivationFailed { service: service.to_owned() })?;

        let aad = info_bytes(service);

        // OS RNG failure is catastrophic (no secure nonce possible). This
        // is the same fail-stop policy used by `passphrase.rs` for salt
        // generation. Do NOT switch to `try_fill_bytes` — a recoverable
        // error would tempt retry, which cannot help here.
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        // `Aes256Gcm::new` with a `[u8; 32]`-derived `GenericArray<u8, U32>`
        // is infallible: key size is enforced by the type.
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&*subkey));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
            .map_err(|_| VaultError::SealFailed {
                service: service.to_owned(),
                source: CryptoError::AeadEncryptFailed,
            })?;

        Ok(SealedCredential::from_trusted_bytes(ciphertext, nonce, aad, SEALED_CREDENTIAL_VERSION))
    }

    /// Shared unseal implementation returning raw bytes. Both `unseal()` and
    /// `unseal_refresh()` delegate here — the crypto is identical, only the
    /// wrapper type differs.
    fn unseal_bytes(
        &self,
        service: &str,
        sealed: &SealedCredential,
    ) -> Result<Vec<u8>, VaultError> {
        if service.len() > MAX_SERVICE_BYTES {
            return Err(VaultError::ServiceNameTooLong {
                service: service.chars().take(64).collect(),
                len: service.len(),
                max: MAX_SERVICE_BYTES,
            });
        }
        if sealed.version() != SEALED_CREDENTIAL_VERSION {
            return Err(VaultError::UnsupportedVersion {
                got: sealed.version(),
                expected: SEALED_CREDENTIAL_VERSION,
            });
        }
        // Defense-in-depth: the store's decoder already caps ct_len at
        // MAX_PLAINTEXT_LEN + 16, but the vault is a separate trust
        // boundary — a `SealedCredential` built via `from_trusted_bytes`
        // with attacker-controlled bytes would bypass the store's check.
        if sealed.ciphertext().len() > MAX_PLAINTEXT_LEN + GCM_TAG_LEN {
            return Err(VaultError::UnsealFailed {
                service: service.to_owned(),
                source: CryptoError::PlaintextTooLarge {
                    len: sealed.ciphertext().len().saturating_sub(GCM_TAG_LEN),
                    max: MAX_PLAINTEXT_LEN,
                },
            });
        }

        let subkey = derive_subkey(&self.master_key, service)
            .map_err(|_| VaultError::SubkeyDerivationFailed { service: service.to_owned() })?;

        let cipher = Aes256Gcm::new(GenericArray::from_slice(&*subkey));
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(sealed.nonce()),
                Payload { msg: sealed.ciphertext(), aad: sealed.aad() },
            )
            .map_err(|_| VaultError::UnsealFailed {
                service: service.to_owned(),
                source: CryptoError::AeadTagMismatch,
            })?;

        Ok(plaintext)
    }
}

/// HKDF info bytes / AAD bytes: `VAULT_DOMAIN_V1 || service_bytes`. The
/// same bytes are used for both HKDF info (subkey diversification) and
/// AEAD AAD (cross-service tamper detection).
fn info_bytes(service: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(VAULT_DOMAIN_V1.len() + service.len());
    v.extend_from_slice(VAULT_DOMAIN_V1);
    v.extend_from_slice(service.as_bytes());
    v
}

/// Expand the master key into a 32-byte per-service subkey via
/// HKDF-SHA256. The returned buffer is zeroized on drop.
fn derive_subkey(master: &[u8; MASTER_KEY_LEN], service: &str) -> Result<Zeroizing<[u8; 32]>, ()> {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut subkey = [0u8; 32];
    // `expand` only fails for output length > 255 * HashLen = 8160 bytes.
    // 32 bytes is trivially valid; mapped defensively.
    hk.expand(&info_bytes(service), &mut subkey).map_err(|_| ())?;
    Ok(Zeroizing::new(subkey))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Deterministic master key for test reproducibility. Real vaults
    /// use 32 random bytes from `OsRng` or Argon2id.
    const TEST_MASTER_KEY: [u8; MASTER_KEY_LEN] = [0x42; MASTER_KEY_LEN];
    const TEST_PLAINTEXT: &[u8] = b"test_plaintext_oauth_token_bytes_v1_sentinel";

    fn test_vault() -> Vault {
        Vault::new(Zeroizing::new(TEST_MASTER_KEY))
    }

    // `OAuthToken` and `SealedCredential` are deliberately non-`Debug`
    // (credential type discipline), so `.unwrap()` / `.unwrap_err()`
    // don't work on their `Result`s. These helpers panic with a static
    // message on the unexpected branch, avoiding the `Debug` bound.
    #[track_caller]
    fn must_seal(vault: &Vault, service: &str, token: &OAuthToken) -> SealedCredential {
        match vault.seal(service, token) {
            Ok(s) => s,
            Err(_) => panic!("seal({service}) unexpectedly failed"),
        }
    }

    #[track_caller]
    fn must_unseal(vault: &Vault, service: &str, sealed: &SealedCredential) -> OAuthToken {
        match vault.unseal(service, sealed) {
            Ok(t) => t,
            Err(_) => panic!("unseal({service}) unexpectedly failed"),
        }
    }

    #[track_caller]
    fn seal_err(vault: &Vault, service: &str, token: &OAuthToken) -> VaultError {
        match vault.seal(service, token) {
            Ok(_) => panic!("seal({service}) unexpectedly succeeded"),
            Err(e) => e,
        }
    }

    #[track_caller]
    fn unseal_err(vault: &Vault, service: &str, sealed: &SealedCredential) -> VaultError {
        match vault.unseal(service, sealed) {
            Ok(_) => panic!("unseal({service}) unexpectedly succeeded"),
            Err(e) => e,
        }
    }

    #[test]
    fn round_trip_byte_equal() {
        let vault = test_vault();
        let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let sealed = must_seal(&vault, "gmail", &token);
        let unsealed = must_unseal(&vault, "gmail", &sealed);
        assert_eq!(unsealed.reveal(), TEST_PLAINTEXT);
    }

    #[test]
    fn empty_token_round_trip() {
        let vault = test_vault();
        let token = OAuthToken::from_trusted_bytes(Vec::new());
        let sealed = must_seal(&vault, "gmail", &token);
        let unsealed = must_unseal(&vault, "gmail", &sealed);
        assert!(unsealed.reveal().is_empty());
    }

    #[test]
    fn sealed_envelope_has_version_and_expected_lengths() {
        let vault = test_vault();
        let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let sealed = must_seal(&vault, "gmail", &token);
        assert_eq!(sealed.version(), SEALED_CREDENTIAL_VERSION);
        assert_eq!(sealed.nonce().len(), 12);
        // Ciphertext = plaintext + 16-byte GCM tag.
        assert_eq!(sealed.ciphertext().len(), TEST_PLAINTEXT.len() + GCM_TAG_LEN);
        // AAD = VAULT_DOMAIN_V1 || service_bytes.
        let expected_aad_len = VAULT_DOMAIN_V1.len() + "gmail".len();
        assert_eq!(sealed.aad().len(), expected_aad_len);
    }

    #[test]
    fn sealed_bytes_do_not_contain_plaintext() {
        let vault = test_vault();
        let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let sealed = must_seal(&vault, "gmail", &token);
        // Neither the ciphertext nor the AAD should contain the plaintext
        // sentinel. (The test plaintext is long and distinctive enough
        // that accidental overlap is astronomically unlikely.)
        assert!(!contains_subsequence(sealed.ciphertext(), TEST_PLAINTEXT));
        assert!(!contains_subsequence(sealed.aad(), TEST_PLAINTEXT));
    }

    #[test]
    fn cross_service_unseal_fails() {
        let vault = test_vault();
        let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let sealed = must_seal(&vault, "gmail", &token);
        let err = unseal_err(&vault, "calendar", &sealed);
        assert!(matches!(
            err,
            VaultError::UnsealFailed { source: CryptoError::AeadTagMismatch, .. }
        ));
    }

    #[test]
    fn cross_service_matrix() {
        let vault = test_vault();
        let services = ["gmail", "calendar", "drive", "sheets", "docs"];
        for seal_svc in services {
            let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
            let sealed = must_seal(&vault, seal_svc, &token);
            for unseal_svc in services {
                let result = vault.unseal(unseal_svc, &sealed);
                if seal_svc == unseal_svc {
                    assert!(result.is_ok(), "{seal_svc} → {unseal_svc} should unseal");
                } else {
                    assert!(result.is_err(), "{seal_svc} → {unseal_svc} must NOT unseal");
                }
            }
        }
    }

    #[test]
    fn ciphertext_bit_flip_fails() {
        let vault = test_vault();
        let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let sealed = must_seal(&vault, "gmail", &token);
        let ct = sealed.ciphertext().to_vec();
        for i in 0..ct.len() {
            let mut mutated = ct.clone();
            mutated[i] ^= 0x01;
            let mutated_sealed = SealedCredential::from_trusted_bytes(
                mutated,
                *sealed.nonce(),
                sealed.aad().to_vec(),
                sealed.version(),
            );
            let err = unseal_err(&vault, "gmail", &mutated_sealed);
            assert!(matches!(
                err,
                VaultError::UnsealFailed { source: CryptoError::AeadTagMismatch, .. }
            ));
        }
    }

    #[test]
    fn nonce_bit_flip_fails() {
        let vault = test_vault();
        let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let sealed = must_seal(&vault, "gmail", &token);
        for i in 0..12 {
            let mut mutated_nonce = *sealed.nonce();
            mutated_nonce[i] ^= 0x01;
            let mutated = SealedCredential::from_trusted_bytes(
                sealed.ciphertext().to_vec(),
                mutated_nonce,
                sealed.aad().to_vec(),
                sealed.version(),
            );
            let err = unseal_err(&vault, "gmail", &mutated);
            assert!(matches!(
                err,
                VaultError::UnsealFailed { source: CryptoError::AeadTagMismatch, .. }
            ));
        }
    }

    #[test]
    fn aad_bit_flip_fails() {
        let vault = test_vault();
        let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let sealed = must_seal(&vault, "gmail", &token);
        let aad = sealed.aad().to_vec();
        for i in 0..aad.len() {
            let mut mutated_aad = aad.clone();
            mutated_aad[i] ^= 0x01;
            let mutated = SealedCredential::from_trusted_bytes(
                sealed.ciphertext().to_vec(),
                *sealed.nonce(),
                mutated_aad,
                sealed.version(),
            );
            let err = unseal_err(&vault, "gmail", &mutated);
            assert!(matches!(
                err,
                VaultError::UnsealFailed { source: CryptoError::AeadTagMismatch, .. }
            ));
        }
    }

    #[test]
    fn plaintext_too_large_rejected() {
        let vault = test_vault();
        let oversize = vec![0u8; MAX_PLAINTEXT_LEN + 1];
        let token = OAuthToken::from_trusted_bytes(oversize);
        let err = seal_err(&vault, "gmail", &token);
        assert!(matches!(
            err,
            VaultError::SealFailed {
                source: CryptoError::PlaintextTooLarge { len, max },
                ..
            } if len == MAX_PLAINTEXT_LEN + 1 && max == MAX_PLAINTEXT_LEN
        ));
    }

    #[test]
    fn plaintext_at_max_accepted() {
        let vault = test_vault();
        let max_size = vec![0xAAu8; MAX_PLAINTEXT_LEN];
        let token = OAuthToken::from_trusted_bytes(max_size.clone());
        let sealed = must_seal(&vault, "gmail", &token);
        let unsealed = must_unseal(&vault, "gmail", &sealed);
        assert_eq!(unsealed.reveal(), max_size.as_slice());
    }

    #[test]
    fn two_seals_produce_different_ciphertexts() {
        let vault = test_vault();
        let token1 = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let token2 = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let sealed1 = must_seal(&vault, "gmail", &token1);
        let sealed2 = must_seal(&vault, "gmail", &token2);
        // Random nonce ⇒ different ciphertext on every seal, even with
        // identical plaintext + subkey.
        assert_ne!(sealed1.nonce(), sealed2.nonce());
        assert_ne!(sealed1.ciphertext(), sealed2.ciphertext());
    }

    #[test]
    fn unsupported_version_rejected() {
        let vault = test_vault();
        let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let sealed = must_seal(&vault, "gmail", &token);
        // Forge an envelope with a bumped version.
        let forged = SealedCredential::from_trusted_bytes(
            sealed.ciphertext().to_vec(),
            *sealed.nonce(),
            sealed.aad().to_vec(),
            SEALED_CREDENTIAL_VERSION + 1,
        );
        let err = unseal_err(&vault, "gmail", &forged);
        assert!(matches!(err, VaultError::UnsupportedVersion { got, expected }
            if got == SEALED_CREDENTIAL_VERSION + 1 && expected == SEALED_CREDENTIAL_VERSION));
    }

    #[test]
    fn info_bytes_is_prefix_plus_service() {
        let bytes = info_bytes("gmail");
        assert!(bytes.starts_with(VAULT_DOMAIN_V1));
        assert_eq!(&bytes[VAULT_DOMAIN_V1.len()..], b"gmail");
    }

    #[test]
    fn derive_subkey_is_deterministic() {
        let master = [0x42u8; MASTER_KEY_LEN];
        let k1 = derive_subkey(&master, "gmail").unwrap();
        let k2 = derive_subkey(&master, "gmail").unwrap();
        assert_eq!(&*k1, &*k2);
    }

    #[test]
    fn derive_subkey_is_service_distinguishing() {
        let master = [0x42u8; MASTER_KEY_LEN];
        let k_gmail = derive_subkey(&master, "gmail").unwrap();
        let k_cal = derive_subkey(&master, "calendar").unwrap();
        assert_ne!(&*k_gmail, &*k_cal);
    }

    #[test]
    fn service_name_too_long_rejected_on_seal() {
        let vault = test_vault();
        let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let long_service = "a".repeat(MAX_SERVICE_BYTES + 1);
        let err = seal_err(&vault, &long_service, &token);
        assert!(matches!(
            err,
            VaultError::ServiceNameTooLong { len, max, .. }
            if len == MAX_SERVICE_BYTES + 1 && max == MAX_SERVICE_BYTES
        ));
    }

    #[test]
    fn service_name_too_long_rejected_on_unseal() {
        let vault = test_vault();
        let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        // Seal with a short service, then try to unseal with a long one.
        let sealed = must_seal(&vault, "gmail", &token);
        let long_service = "a".repeat(MAX_SERVICE_BYTES + 1);
        let err = unseal_err(&vault, &long_service, &sealed);
        assert!(matches!(
            err,
            VaultError::ServiceNameTooLong { len, max, .. }
            if len == MAX_SERVICE_BYTES + 1 && max == MAX_SERVICE_BYTES
        ));
    }

    #[test]
    fn service_name_at_max_bytes_accepted() {
        let vault = test_vault();
        let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let max_service = "a".repeat(MAX_SERVICE_BYTES);
        let sealed = must_seal(&vault, &max_service, &token);
        let unsealed = must_unseal(&vault, &max_service, &sealed);
        assert_eq!(unsealed.reveal(), TEST_PLAINTEXT);
    }

    fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
