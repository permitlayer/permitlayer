//! AES-256-GCM vault: seal/unseal with per-`(ConnectionId, Slot)`
//! HKDF-SHA256 subkeys (crypto-domain **v2**, Story 11.8).
//!
//! # Two orthogonal "v2"s — do not conflate
//!
//! - **Keying-domain v2 (this module):** the HKDF `info` / AEAD `aad`
//!   domain is `b"permitlayer-vault-v2:" || connection_id (16) || b":" ||
//!   slot_byte`. This replaced the v1 *service-string* domain
//!   (`b"permitlayer-vault-v1:" || service`) in Story 11.8. There is no v1
//!   keying read path.
//! - **Envelope-schema v2 (Story 7.6a, separate):** the on-disk envelope
//!   header carries `version` (`SEALED_CREDENTIAL_VERSION`) + `key_id`.
//!   That is unchanged here — only the `info`/`aad` bytes moved to the new
//!   keying domain. Do NOT touch `SEALED_CREDENTIAL_VERSION` or the
//!   envelope decoder for this story.
//!
//! # Cryptographic construction
//!
//! - **Master key:** 32 bytes from `permitlayer-keystore::KeyStore` (OS
//!   keychain or Argon2id-from-passphrase), held as `Zeroizing<[u8; 32]>`.
//! - **Per-`(ConnectionId, Slot)` subkey:** HKDF-SHA256 expanded from the
//!   master key with `info` = the v2 domain bytes. A distinct 32-byte
//!   subkey per connection AND per slot — sealing connection A's `Access`
//!   slot cannot be unsealed as connection B's, nor as A's `Refresh` slot
//!   (different domain → different subkey → AEAD tag check fails; NFR51).
//! - **AEAD:** AES-256-GCM, fresh 12-byte random nonce per `seal()` (via
//!   `OsRng`). `aad` = the same v2 domain bytes — defense-in-depth: even
//!   if subkey derivation collided, the AAD check on a mismatched
//!   `(id, slot)` would still fail.
//!
//! # Nonce discipline
//!
//! 12 random bytes per seal. GCM needs nonce-uniqueness per key; 96-bit
//! random nonces have a birthday bound of ~2^32 calls per subkey. For a
//! single-user daemon sealing <1000 credentials/day this is ~10^7 years —
//! acceptable without a counter scheme.
//!
//! # No salt in HKDF
//!
//! The master key is already 32 uniformly-random bytes, so HKDF's `salt`
//! (which randomizes low-entropy IKM) adds no security and would only
//! complicate rotation.

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use permitlayer_credential::{
    ConnectionId, CryptoError, KeyId, MAX_PLAINTEXT_LEN, OAuthRefreshToken, OAuthToken,
    SEALED_CREDENTIAL_VERSION, SealedCredential, Slot,
};
use permitlayer_keystore::MASTER_KEY_LEN;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::VaultError;

/// HKDF info prefix + AAD prefix for the **keying domain** (Story 11.8).
/// Versioned so a future keying-scheme change is detectable; this `v2`
/// supersedes the v1 service-keyed domain with no v1 read path. (Distinct
/// from the on-disk envelope-schema version — see the module docs.)
const VAULT_DOMAIN_V2: &[u8] = b"permitlayer-vault-v2:";

/// AES-256-GCM tag size (bytes). The `aes-gcm` crate appends this tag to
/// the ciphertext; used for ciphertext-length bounds checking.
const GCM_TAG_LEN: usize = 16;

/// AES-256-GCM vault for sealing/unsealing OAuth tokens.
///
/// Holds the master key as `Zeroizing<[u8; 32]>` — wiped on drop. Per-seal
/// subkeys are derived fresh via HKDF and zeroized on function exit.
///
/// The vault keys on `(ConnectionId, Slot)` (Story 11.8). The connection
/// id is a fixed 16 bytes and the slot a single byte, so there is no
/// caller-supplied string length to bound — the v1 `service`-name length
/// guard is gone.
pub struct Vault {
    master_key: Zeroizing<[u8; MASTER_KEY_LEN]>,
    /// Story 7.6a: which master key this vault represents. Stamped on
    /// every `SealedCredential` produced by `seal` / `seal_refresh`.
    /// `0` is the bootstrap (single-key, never-rotated) sentinel.
    key_id: u8,
}

impl Vault {
    /// Construct a vault from a master key. Ownership of the key moves
    /// into the vault; the caller's `Zeroizing` buffer is consumed.
    ///
    /// **Story 7.6a:** the `key_id` parameter records which master key
    /// this vault represents — stamped on every envelope produced by
    /// `seal` / `seal_refresh`. Pass `0` in single-key worlds.
    #[must_use = "a Vault that is immediately dropped wastes the master key derivation"]
    pub fn new(master_key: Zeroizing<[u8; MASTER_KEY_LEN]>, key_id: u8) -> Self {
        Self { master_key, key_id }
    }

    /// The `key_id` this vault stamps on sealed envelopes. Available to
    /// callers (notably `permitlayer-vault::rotation::reseal`) that need
    /// the post-rotation `key_id` without re-deriving it.
    #[must_use]
    pub fn key_id(&self) -> u8 {
        self.key_id
    }

    /// Seal an OAuth access token for `(connection, slot)`. Produces a
    /// `SealedCredential` (ciphertext + nonce + AAD + version), no plaintext.
    ///
    /// Returns `VaultError::SealFailed` if plaintext exceeds
    /// `MAX_PLAINTEXT_LEN` or the AEAD engine reports failure (the latter
    /// effectively unreachable with a valid 32-byte subkey).
    pub fn seal(
        &self,
        connection: ConnectionId,
        slot: Slot,
        token: &OAuthToken,
    ) -> Result<SealedCredential, VaultError> {
        self.seal_bytes(connection, slot, token.reveal())
    }

    /// Unseal a `SealedCredential` for `(connection, slot)`. Returns the
    /// plaintext wrapped in an `OAuthToken`.
    ///
    /// Fails closed on any tamper — `VaultError::UnsealFailed` with a
    /// `CryptoError::AeadTagMismatch` source if the AEAD tag does not
    /// verify. `VaultError::UnsupportedVersion` if the envelope version is
    /// not recognized.
    pub fn unseal(
        &self,
        connection: ConnectionId,
        slot: Slot,
        sealed: &SealedCredential,
    ) -> Result<OAuthToken, VaultError> {
        self.unseal_bytes(connection, slot, sealed).map(OAuthToken::from_trusted_bytes)
    }

    /// Seal an OAuth refresh token for `(connection, slot)`.
    ///
    /// Identical cryptographic construction to [`Vault::seal`] but accepts
    /// `&OAuthRefreshToken`. Callers pass [`Slot::Refresh`] so the refresh
    /// token gets a different HKDF subkey than the access token under the
    /// same connection (the v1 `"{service}-refresh"` suffix is gone).
    pub fn seal_refresh(
        &self,
        connection: ConnectionId,
        slot: Slot,
        token: &OAuthRefreshToken,
    ) -> Result<SealedCredential, VaultError> {
        self.seal_bytes(connection, slot, token.reveal())
    }

    /// Unseal a `SealedCredential` for `(connection, slot)`, returning an
    /// `OAuthRefreshToken`.
    pub fn unseal_refresh(
        &self,
        connection: ConnectionId,
        slot: Slot,
        sealed: &SealedCredential,
    ) -> Result<OAuthRefreshToken, VaultError> {
        self.unseal_bytes(connection, slot, sealed).map(OAuthRefreshToken::from_trusted_bytes)
    }

    /// Shared seal implementation operating on raw bytes. Both `seal()` and
    /// `seal_refresh()` delegate here — the crypto is identical, only the
    /// wrapper type differs.
    ///
    /// `pub(crate)` so the `rotation` module can perform a single-frame
    /// reseal (unseal-with-old-vault → seal-with-new-vault) without
    /// crossing an `OAuthToken` boundary. The `Zeroizing<Vec<u8>>` buffer
    /// is the only plaintext exposure and lives entirely on the stack
    /// frame of `rotation::reseal`.
    pub(crate) fn seal_bytes(
        &self,
        connection: ConnectionId,
        slot: Slot,
        plaintext: &[u8],
    ) -> Result<SealedCredential, VaultError> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(VaultError::SealFailed {
                connection: connection.to_string(),
                slot,
                source: CryptoError::PlaintextTooLarge {
                    len: plaintext.len(),
                    max: MAX_PLAINTEXT_LEN,
                },
            });
        }

        let subkey = derive_subkey(&self.master_key, connection, slot).map_err(|()| {
            VaultError::SubkeyDerivationFailed { connection: connection.to_string(), slot }
        })?;

        let aad = info_bytes(connection, slot);

        // OS RNG failure is catastrophic (no secure nonce possible). Same
        // fail-stop policy `passphrase.rs` uses for salt. Do NOT switch to
        // `try_fill_bytes` — a recoverable error would tempt a retry that
        // cannot help.
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        // `Aes256Gcm::new` with a `[u8; 32]`-derived key is infallible.
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&*subkey));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
            .map_err(|_| VaultError::SealFailed {
                connection: connection.to_string(),
                slot,
                source: CryptoError::AeadEncryptFailed,
            })?;

        Ok(SealedCredential::from_trusted_bytes(
            ciphertext,
            nonce,
            aad,
            SEALED_CREDENTIAL_VERSION,
            KeyId::new(self.key_id),
        ))
    }

    /// Shared unseal implementation returning raw bytes. Both `unseal()` and
    /// `unseal_refresh()` delegate here.
    ///
    /// `pub(crate)` so the `rotation` module can perform single-frame
    /// reseal — see [`Vault::seal_bytes`] for the full discipline.
    pub(crate) fn unseal_bytes(
        &self,
        connection: ConnectionId,
        slot: Slot,
        sealed: &SealedCredential,
    ) -> Result<Vec<u8>, VaultError> {
        if sealed.version() != SEALED_CREDENTIAL_VERSION {
            return Err(VaultError::UnsupportedVersion {
                got: sealed.version(),
                expected: SEALED_CREDENTIAL_VERSION,
            });
        }
        // Defense-in-depth: the store's decoder already caps ct_len, but
        // the vault is a separate trust boundary — a `SealedCredential`
        // built via `from_trusted_bytes` with attacker-controlled bytes
        // would bypass the store's check.
        if sealed.ciphertext().len() > MAX_PLAINTEXT_LEN + GCM_TAG_LEN {
            return Err(VaultError::UnsealFailed {
                connection: connection.to_string(),
                slot,
                source: CryptoError::PlaintextTooLarge {
                    len: sealed.ciphertext().len().saturating_sub(GCM_TAG_LEN),
                    max: MAX_PLAINTEXT_LEN,
                },
            });
        }

        let subkey = derive_subkey(&self.master_key, connection, slot).map_err(|()| {
            VaultError::SubkeyDerivationFailed { connection: connection.to_string(), slot }
        })?;

        let cipher = Aes256Gcm::new(GenericArray::from_slice(&*subkey));
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(sealed.nonce()),
                Payload { msg: sealed.ciphertext(), aad: sealed.aad() },
            )
            .map_err(|_| VaultError::UnsealFailed {
                connection: connection.to_string(),
                slot,
                source: CryptoError::AeadTagMismatch,
            })?;

        Ok(plaintext)
    }
}

/// HKDF info bytes / AAD bytes:
/// `VAULT_DOMAIN_V2 || connection_id (16) || b":" || slot_byte`.
///
/// The same bytes are used for both HKDF info (subkey diversification per
/// connection AND slot) and AEAD AAD (tamper detection). Fixed length:
/// `21 + 16 + 1 + 1 = 39` bytes.
fn info_bytes(connection: ConnectionId, slot: Slot) -> Vec<u8> {
    let mut v = Vec::with_capacity(VAULT_DOMAIN_V2.len() + 16 + 1 + 1);
    v.extend_from_slice(VAULT_DOMAIN_V2);
    v.extend_from_slice(connection.as_bytes());
    v.push(b':');
    v.push(slot.slot_byte());
    v
}

/// Expand the master key into a 32-byte per-`(connection, slot)` subkey via
/// HKDF-SHA256. The returned buffer is zeroized on drop.
fn derive_subkey(
    master: &[u8; MASTER_KEY_LEN],
    connection: ConnectionId,
    slot: Slot,
) -> Result<Zeroizing<[u8; 32]>, ()> {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut subkey = [0u8; 32];
    // `expand` only fails for output > 255 * HashLen = 8160 bytes. 32 is
    // trivially valid; mapped defensively.
    hk.expand(&info_bytes(connection, slot), &mut subkey).map_err(|_| ())?;
    Ok(Zeroizing::new(subkey))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Deterministic master key for test reproducibility. Real vaults use
    /// 32 random bytes from `OsRng` or Argon2id.
    const TEST_MASTER_KEY: [u8; MASTER_KEY_LEN] = [0x42; MASTER_KEY_LEN];
    const TEST_PLAINTEXT: &[u8] = b"test_plaintext_oauth_token_bytes_v2_sentinel";

    fn test_vault() -> Vault {
        Vault::new(Zeroizing::new(TEST_MASTER_KEY), 0)
    }

    /// A connection id for tests, derived from a label so different tests
    /// get distinct ids without hand-writing 16-byte arrays.
    fn cid(label: &str) -> ConnectionId {
        ConnectionId::from_service_shim(label)
    }

    // `OAuthToken` / `SealedCredential` are non-`Debug` (credential
    // discipline), so `.unwrap()` on their `Result`s won't compile. These
    // helpers panic with a static message on the unexpected branch.
    #[track_caller]
    fn must_seal(
        vault: &Vault,
        id: ConnectionId,
        slot: Slot,
        token: &OAuthToken,
    ) -> SealedCredential {
        match vault.seal(id, slot, token) {
            Ok(s) => s,
            Err(_) => panic!("seal({id}, {slot}) unexpectedly failed"),
        }
    }

    #[track_caller]
    fn must_unseal(
        vault: &Vault,
        id: ConnectionId,
        slot: Slot,
        sealed: &SealedCredential,
    ) -> OAuthToken {
        match vault.unseal(id, slot, sealed) {
            Ok(t) => t,
            Err(_) => panic!("unseal({id}, {slot}) unexpectedly failed"),
        }
    }

    #[track_caller]
    fn seal_err(vault: &Vault, id: ConnectionId, slot: Slot, token: &OAuthToken) -> VaultError {
        match vault.seal(id, slot, token) {
            Ok(_) => panic!("seal({id}, {slot}) unexpectedly succeeded"),
            Err(e) => e,
        }
    }

    #[track_caller]
    fn unseal_err(
        vault: &Vault,
        id: ConnectionId,
        slot: Slot,
        sealed: &SealedCredential,
    ) -> VaultError {
        match vault.unseal(id, slot, sealed) {
            Ok(_) => panic!("unseal({id}, {slot}) unexpectedly succeeded"),
            Err(e) => e,
        }
    }

    #[test]
    fn round_trip_byte_equal() {
        let vault = test_vault();
        let id = cid("gmail");
        let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let sealed = must_seal(&vault, id, Slot::Access, &token);
        let unsealed = must_unseal(&vault, id, Slot::Access, &sealed);
        assert_eq!(unsealed.reveal(), TEST_PLAINTEXT);
    }

    #[test]
    fn empty_token_round_trip() {
        let vault = test_vault();
        let id = cid("gmail");
        let token = OAuthToken::from_trusted_bytes(Vec::new());
        let sealed = must_seal(&vault, id, Slot::Access, &token);
        let unsealed = must_unseal(&vault, id, Slot::Access, &sealed);
        assert!(unsealed.reveal().is_empty());
    }

    #[test]
    fn sealed_envelope_has_version_and_expected_lengths() {
        let vault = test_vault();
        let id = cid("gmail");
        let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let sealed = must_seal(&vault, id, Slot::Access, &token);
        assert_eq!(sealed.version(), SEALED_CREDENTIAL_VERSION);
        assert_eq!(sealed.nonce().len(), 12);
        assert_eq!(sealed.ciphertext().len(), TEST_PLAINTEXT.len() + GCM_TAG_LEN);
        // AAD = VAULT_DOMAIN_V2 || id(16) || ':' || slot_byte = fixed 39.
        assert_eq!(sealed.aad().len(), VAULT_DOMAIN_V2.len() + 16 + 1 + 1);
        assert_eq!(sealed.aad().len(), 39);
    }

    #[test]
    fn sealed_bytes_do_not_contain_plaintext() {
        let vault = test_vault();
        let id = cid("gmail");
        let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let sealed = must_seal(&vault, id, Slot::Access, &token);
        assert!(!contains_subsequence(sealed.ciphertext(), TEST_PLAINTEXT));
        assert!(!contains_subsequence(sealed.aad(), TEST_PLAINTEXT));
    }

    #[test]
    fn cross_connection_unseal_fails() {
        // NFR51: connection A's sealed credential must NOT unseal as B.
        let vault = test_vault();
        let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let sealed = must_seal(&vault, cid("gmail"), Slot::Access, &token);
        let err = unseal_err(&vault, cid("calendar"), Slot::Access, &sealed);
        assert!(matches!(
            err,
            VaultError::UnsealFailed { source: CryptoError::AeadTagMismatch, .. }
        ));
    }

    #[test]
    fn cross_slot_unseal_fails() {
        // AC #3: the three slots under one id are isolated — an Access seal
        // must not unseal as Refresh or Client.
        let vault = test_vault();
        let id = cid("gmail");
        let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let sealed = must_seal(&vault, id, Slot::Access, &token);
        for wrong in [Slot::Refresh, Slot::Client] {
            let err = unseal_err(&vault, id, wrong, &sealed);
            assert!(
                matches!(
                    err,
                    VaultError::UnsealFailed { source: CryptoError::AeadTagMismatch, .. }
                ),
                "Access seal must not unseal as {wrong}"
            );
        }
    }

    #[test]
    fn cross_connection_matrix() {
        // AC #2: per-connection isolation matrix (the v2 analog of the old
        // cross_service_matrix). Same (id, slot) round-trips; any mismatch
        // of id OR slot fails.
        let vault = test_vault();
        let ids = [cid("gmail"), cid("calendar"), cid("drive")];
        let slots = [Slot::Access, Slot::Refresh, Slot::Client];
        for &seal_id in &ids {
            for &seal_slot in &slots {
                let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
                let sealed = must_seal(&vault, seal_id, seal_slot, &token);
                for &un_id in &ids {
                    for &un_slot in &slots {
                        let result = vault.unseal(un_id, un_slot, &sealed);
                        let should_ok = seal_id == un_id && seal_slot == un_slot;
                        assert_eq!(
                            result.is_ok(),
                            should_ok,
                            "({seal_id},{seal_slot}) -> ({un_id},{un_slot}) ok={should_ok}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn ciphertext_bit_flip_fails() {
        let vault = test_vault();
        let id = cid("gmail");
        let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let sealed = must_seal(&vault, id, Slot::Access, &token);
        let ct = sealed.ciphertext().to_vec();
        for i in 0..ct.len() {
            let mut mutated = ct.clone();
            mutated[i] ^= 0x01;
            let mutated_sealed = SealedCredential::from_trusted_bytes(
                mutated,
                *sealed.nonce(),
                sealed.aad().to_vec(),
                sealed.version(),
                KeyId::new(sealed.key_id()),
            );
            let err = unseal_err(&vault, id, Slot::Access, &mutated_sealed);
            assert!(matches!(
                err,
                VaultError::UnsealFailed { source: CryptoError::AeadTagMismatch, .. }
            ));
        }
    }

    #[test]
    fn nonce_bit_flip_fails() {
        let vault = test_vault();
        let id = cid("gmail");
        let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let sealed = must_seal(&vault, id, Slot::Access, &token);
        for i in 0..12 {
            let mut mutated_nonce = *sealed.nonce();
            mutated_nonce[i] ^= 0x01;
            let mutated = SealedCredential::from_trusted_bytes(
                sealed.ciphertext().to_vec(),
                mutated_nonce,
                sealed.aad().to_vec(),
                sealed.version(),
                KeyId::new(sealed.key_id()),
            );
            let err = unseal_err(&vault, id, Slot::Access, &mutated);
            assert!(matches!(
                err,
                VaultError::UnsealFailed { source: CryptoError::AeadTagMismatch, .. }
            ));
        }
    }

    #[test]
    fn aad_bit_flip_fails() {
        let vault = test_vault();
        let id = cid("gmail");
        let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let sealed = must_seal(&vault, id, Slot::Access, &token);
        let aad = sealed.aad().to_vec();
        for i in 0..aad.len() {
            let mut mutated_aad = aad.clone();
            mutated_aad[i] ^= 0x01;
            let mutated = SealedCredential::from_trusted_bytes(
                sealed.ciphertext().to_vec(),
                *sealed.nonce(),
                mutated_aad,
                sealed.version(),
                KeyId::new(sealed.key_id()),
            );
            let err = unseal_err(&vault, id, Slot::Access, &mutated);
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
        let err = seal_err(&vault, cid("gmail"), Slot::Access, &token);
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
        let id = cid("gmail");
        let max_size = vec![0xAAu8; MAX_PLAINTEXT_LEN];
        let token = OAuthToken::from_trusted_bytes(max_size.clone());
        let sealed = must_seal(&vault, id, Slot::Access, &token);
        let unsealed = must_unseal(&vault, id, Slot::Access, &sealed);
        assert_eq!(unsealed.reveal(), max_size.as_slice());
    }

    #[test]
    fn two_seals_produce_different_ciphertexts() {
        let vault = test_vault();
        let id = cid("gmail");
        let token1 = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let token2 = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let sealed1 = must_seal(&vault, id, Slot::Access, &token1);
        let sealed2 = must_seal(&vault, id, Slot::Access, &token2);
        assert_ne!(sealed1.nonce(), sealed2.nonce());
        assert_ne!(sealed1.ciphertext(), sealed2.ciphertext());
    }

    #[test]
    fn unsupported_version_rejected() {
        let vault = test_vault();
        let id = cid("gmail");
        let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let sealed = must_seal(&vault, id, Slot::Access, &token);
        let forged = SealedCredential::from_trusted_bytes(
            sealed.ciphertext().to_vec(),
            *sealed.nonce(),
            sealed.aad().to_vec(),
            SEALED_CREDENTIAL_VERSION + 1,
            KeyId::new(sealed.key_id()),
        );
        let err = unseal_err(&vault, id, Slot::Access, &forged);
        assert!(matches!(err, VaultError::UnsupportedVersion { got, expected }
            if got == SEALED_CREDENTIAL_VERSION + 1 && expected == SEALED_CREDENTIAL_VERSION));
    }

    #[test]
    fn info_bytes_is_v2_domain_id_and_slot() {
        let id = cid("gmail");
        let bytes = info_bytes(id, Slot::Refresh);
        assert!(bytes.starts_with(VAULT_DOMAIN_V2));
        let rest = &bytes[VAULT_DOMAIN_V2.len()..];
        assert_eq!(&rest[..16], id.as_bytes());
        assert_eq!(rest[16], b':');
        assert_eq!(rest[17], Slot::Refresh.slot_byte());
        // No v1 domain string remains (AC #5).
        assert!(!contains_subsequence(&bytes, b"permitlayer-vault-v1:"));
    }

    #[test]
    fn derive_subkey_is_deterministic() {
        let master = [0x42u8; MASTER_KEY_LEN];
        let id = cid("gmail");
        let k1 = derive_subkey(&master, id, Slot::Access).unwrap();
        let k2 = derive_subkey(&master, id, Slot::Access).unwrap();
        assert_eq!(&*k1, &*k2);
    }

    #[test]
    fn derive_subkey_distinguishes_connection_and_slot() {
        // AC #3: distinct id OR distinct slot → distinct subkey.
        let master = [0x42u8; MASTER_KEY_LEN];
        let gmail = cid("gmail");
        let cal = cid("calendar");
        let k_gmail_access = derive_subkey(&master, gmail, Slot::Access).unwrap();
        let k_cal_access = derive_subkey(&master, cal, Slot::Access).unwrap();
        let k_gmail_refresh = derive_subkey(&master, gmail, Slot::Refresh).unwrap();
        let k_gmail_client = derive_subkey(&master, gmail, Slot::Client).unwrap();
        // Distinct connection → distinct subkey.
        assert_ne!(&*k_gmail_access, &*k_cal_access);
        // Distinct slot under the same connection → distinct subkey.
        assert_ne!(&*k_gmail_access, &*k_gmail_refresh);
        assert_ne!(&*k_gmail_access, &*k_gmail_client);
        assert_ne!(&*k_gmail_refresh, &*k_gmail_client);
    }

    /// Story 7.6a AC #8: `Vault::new(key, key_id)` produces envelopes
    /// stamped with the supplied `key_id`.
    #[test]
    fn vault_seals_with_constructed_key_id() {
        let vault = Vault::new(Zeroizing::new(TEST_MASTER_KEY), 7);
        let token = OAuthToken::from_trusted_bytes(TEST_PLAINTEXT.to_vec());
        let sealed = must_seal(&vault, cid("gmail"), Slot::Access, &token);
        assert_eq!(sealed.key_id(), 7);
    }

    /// Story 7.6a AC #8: `seal_refresh` stamps `key_id` the same way.
    #[test]
    fn vault_seals_refresh_with_constructed_key_id() {
        let vault = Vault::new(Zeroizing::new(TEST_MASTER_KEY), 13);
        let refresh = OAuthRefreshToken::from_trusted_bytes(b"refresh-token".to_vec());
        let sealed = vault.seal_refresh(cid("gmail"), Slot::Refresh, &refresh).unwrap();
        assert_eq!(sealed.key_id(), 13);
    }

    /// Story 7.6a AC #8: `Vault::key_id` exposes the stamped value.
    #[test]
    fn vault_exposes_its_key_id() {
        let vault = Vault::new(Zeroizing::new(TEST_MASTER_KEY), 99);
        assert_eq!(vault.key_id(), 99);
    }

    fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
