//! Master-key rotation primitives for `agentsso rotate-key` (Story 7.6).
//!
//! The key contract here is `reseal`: take a `SealedCredential` produced
//! under an OLD master key and return a `SealedCredential` produced under
//! a NEW master key, with plaintext confined to a single function frame
//! that never crosses an `OAuthToken` / `OAuthRefreshToken` boundary.
//!
//! # Plaintext discipline
//!
//! The unseal step produces `Vec<u8>` of plaintext bytes. We immediately
//! wrap it in `Zeroizing<Vec<u8>>` so the buffer is wiped on drop, and
//! we feed it into the new vault's `seal_bytes` from the same scope.
//! The two private helpers are crate-internal (`pub(crate)`) — they were
//! exposed specifically to enable this single-frame reseal without
//! constructing a typed wrapper that would need a discipline carve-out
//! in `xtask::validate_credentials::POLICED_TYPES`.
//!
//! # Domain separation
//!
//! The HKDF info domain `permitlayer-vault-v2:` (in [`crate::seal`]) is
//! the keying-protocol version, NOT the master-key version. Rotation does
//! NOT change the domain — it only swaps the IKM (master key) that HKDF
//! expands into per-`(ConnectionId, Slot)` subkeys. Callers who need to
//! bump the keying domain (e.g., switch AEAD construction) own a separate
//! migration concern.
//!
//! # Failure modes
//!
//! Reseal fails if either the unseal-with-old or seal-with-new step
//! reports a `VaultError`. The most common failure is `UnsealFailed`
//! when the input envelope was tampered or sealed under a third (not
//! `old`) master key. In all failure cases the plaintext buffer drops
//! and zeroizes before the error is returned.

use permitlayer_credential::{ConnectionId, SealedCredential, Slot};
use zeroize::Zeroizing;

use crate::seal::Vault;

/// Re-encrypt a sealed credential under a new master key without ever
/// constructing an `OAuthToken` / `OAuthRefreshToken` wrapper.
///
/// Both `old` and `new` are borrowed (no ownership transfer); the caller
/// is expected to hold them for the duration of a rotation pass and
/// drop them when done.
///
/// `(connection, slot)` must match the values the original credential was
/// sealed under — they control the per-`(ConnectionId, Slot)` HKDF subkey
/// and AAD binding. Passing a different connection or slot fails closed at
/// unseal time with `VaultError::UnsealFailed` (AAD mismatch).
///
/// **Story 7.6a:** the resulting envelope's `key_id` comes from
/// `new.key_id()` (the value the caller passed at `Vault::new`
/// construction). Resealing the same envelope under the same `new`
/// vault is idempotent at the schema level — the bytes change (fresh
/// nonce + ciphertext) but the `key_id` does not.
///
/// **Caller invariant for rotation flows:** `new.key_id() > old.key_id()`.
/// The whole point of bumping `key_id` is to provide a monotonic
/// fingerprint of which key sealed which envelope; reusing or
/// regressing the value would defeat `compute_active_key_id`'s
/// `max(key_id)` boot-time scan. A `debug_assertions` check below
/// catches obvious mistakes (same value, regression) in tests; in
/// release builds the assertion compiles out and the ordering
/// invariant becomes a documentation contract that callers
/// (Story 7.6b's rotate-key v2) MUST honor.
///
/// # Plaintext exposure
///
/// The plaintext lives as a `Zeroizing<Vec<u8>>` for the duration of
/// this function call only. It is wiped on drop, including on the
/// error path.
pub fn reseal(
    old: &Vault,
    new: &Vault,
    sealed: &SealedCredential,
    connection: ConnectionId,
    slot: Slot,
) -> Result<SealedCredential, VaultRotationError> {
    // Story 7.6a (review patch): debug-only invariant. In release
    // builds this compiles out; in tests it catches callers that
    // build `new` with a non-monotonic `key_id` (which would
    // silently corrupt the daemon's max(key_id) boot scan).
    debug_assert!(
        new.key_id() > old.key_id(),
        "reseal: new.key_id() ({}) must exceed old.key_id() ({}); the monotonic invariant is what \
         lets compute_active_key_id detect rotation completion at boot",
        new.key_id(),
        old.key_id()
    );
    // Unseal with the OLD vault — this produces plaintext bytes.
    let plaintext_vec = old.unseal_bytes(connection, slot, sealed).map_err(|source| {
        VaultRotationError::UnsealOldFailed { connection: connection.to_string(), slot, source }
    })?;
    // Wrap in Zeroizing so the buffer is wiped when this scope exits,
    // even if the seal step below panics.
    let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(plaintext_vec);
    // Seal under the NEW vault — `seal_bytes` stamps `new.key_id()` on
    // the resulting envelope. The plaintext buffer drops + zeroes
    // when this expression's scope ends regardless of success or
    // failure.
    new.seal_bytes(connection, slot, &plaintext).map_err(|source| {
        VaultRotationError::SealNewFailed { connection: connection.to_string(), slot, source }
    })
}

/// Errors returned by [`reseal`].
///
/// Wraps the underlying [`crate::VaultError`] with a tag indicating
/// which side of the rotation pipeline failed (unseal-with-old vs
/// seal-with-new) — operators triaging a rotation failure need to
/// know which key was at fault.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum VaultRotationError {
    /// Unsealing with the old master key failed. The credential file
    /// may have been tampered, sealed under a different key entirely
    /// (manual edit), or the on-disk envelope is corrupt.
    #[error("rotation: unseal-with-old failed for connection '{connection}' slot '{slot}'")]
    UnsealOldFailed {
        /// The connection id (ULID text) whose unseal failed.
        connection: String,
        /// The credential slot (access / refresh / client).
        slot: Slot,
        /// The underlying vault error.
        #[source]
        source: crate::VaultError,
    },

    /// Sealing with the new master key failed. Effectively unreachable
    /// with a valid 32-byte new key (AES-256-GCM encrypt is infallible
    /// for valid keys + nonce sizes), but mapped defensively because
    /// the underlying `aes-gcm` API returns `Err`.
    #[error("rotation: seal-with-new failed for connection '{connection}' slot '{slot}'")]
    SealNewFailed {
        /// The connection id (ULID text) whose seal failed.
        connection: String,
        /// The credential slot (access / refresh / client).
        slot: Slot,
        /// The underlying vault error.
        #[source]
        source: crate::VaultError,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use permitlayer_credential::{ConnectionId, OAuthToken, Slot};
    use zeroize::Zeroizing;

    use super::*;
    use crate::Vault;
    use crate::master_key::MasterKey;

    /// Build a vault with a specific `key_id`. Rotation tests must
    /// pass `new_kid > old_kid` to honor the monotonic invariant that
    /// `reseal`'s debug-assert checks.
    fn vault_with(bytes: [u8; 32], key_id: u8) -> Vault {
        Vault::new(Zeroizing::new(bytes), key_id)
    }

    /// Deterministic test connection id from a label (FNV-1a spread over
    /// 16 bytes; distinct labels → distinct ids, no crypto needed).
    fn cid(label: &str) -> ConnectionId {
        let mut bytes = [0u8; 16];
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in label.as_bytes() {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        bytes[..8].copy_from_slice(&hash.to_le_bytes());
        bytes[8..].copy_from_slice(&hash.rotate_left(32).to_be_bytes());
        ConnectionId::from_bytes(bytes)
    }

    #[test]
    fn reseal_round_trips_plaintext() {
        let old = vault_with([0x11; 32], 0);
        let new = vault_with([0x22; 32], 1);
        let id = cid("gmail");
        let plaintext = b"ya29.fake-access-token-bytes";
        let token = OAuthToken::from_trusted_bytes(plaintext.to_vec());
        let sealed_old = old.seal(id, Slot::Access, &token).unwrap();

        let resealed = reseal(&old, &new, &sealed_old, id, Slot::Access).unwrap();
        // The new envelope unseals under the new vault and produces the
        // same plaintext.
        let recovered = new.unseal(id, Slot::Access, &resealed).unwrap();
        assert_eq!(recovered.reveal(), plaintext);
    }

    #[test]
    fn resealed_envelope_does_not_unseal_under_old_key() {
        let old = vault_with([0x33; 32], 0);
        let new = vault_with([0x44; 32], 1);
        let id = cid("calendar");
        let token = OAuthToken::from_trusted_bytes(b"secret".to_vec());
        let sealed_old = old.seal(id, Slot::Access, &token).unwrap();

        let resealed = reseal(&old, &new, &sealed_old, id, Slot::Access).unwrap();
        // The old vault must NOT be able to unseal the new envelope —
        // this is the cryptographic invariant that proves rotation
        // actually re-encrypted under a different key.
        assert!(old.unseal(id, Slot::Access, &resealed).is_err());
    }

    #[test]
    fn reseal_fails_on_connection_mismatch() {
        let old = vault_with([0x55; 32], 0);
        let new = vault_with([0x66; 32], 1);
        let token = OAuthToken::from_trusted_bytes(b"x".to_vec());
        let sealed_old = old.seal(cid("gmail"), Slot::Access, &token).unwrap();

        // Sealed under the gmail connection but resealing claims calendar —
        // AAD check fails closed. `SealedCredential` is non-Debug so we
        // pattern-match instead of `.unwrap_err()`.
        let calendar = cid("calendar");
        match reseal(&old, &new, &sealed_old, calendar, Slot::Access) {
            Ok(_) => panic!("expected connection-mismatch reseal to fail"),
            Err(VaultRotationError::UnsealOldFailed { connection, .. }) => {
                assert_eq!(connection, calendar.to_string());
            }
            Err(other) => panic!("expected UnsealOldFailed, got {other:?}"),
        }
    }

    #[test]
    fn reseal_fails_on_slot_mismatch() {
        // The slot is part of the keying domain — resealing the same
        // connection but a different slot must fail closed.
        let old = vault_with([0x5A; 32], 0);
        let new = vault_with([0x6B; 32], 1);
        let id = cid("gmail");
        let token = OAuthToken::from_trusted_bytes(b"x".to_vec());
        let sealed_old = old.seal(id, Slot::Access, &token).unwrap();
        match reseal(&old, &new, &sealed_old, id, Slot::Refresh) {
            Ok(_) => panic!("expected slot-mismatch reseal to fail"),
            Err(VaultRotationError::UnsealOldFailed { slot, .. }) => {
                assert_eq!(slot, Slot::Refresh);
            }
            Err(other) => panic!("expected UnsealOldFailed, got {other:?}"),
        }
    }

    #[test]
    fn reseal_fails_on_wrong_old_key() {
        let actual_old = vault_with([0x77; 32], 0);
        let claimed_old = vault_with([0x88; 32], 0);
        let new = vault_with([0x99; 32], 1);
        let id = cid("drive");
        let token = OAuthToken::from_trusted_bytes(b"y".to_vec());
        let sealed = actual_old.seal(id, Slot::Access, &token).unwrap();

        // We pass `claimed_old` (the wrong key) as the unseal vault;
        // AEAD tag check fails.
        match reseal(&claimed_old, &new, &sealed, id, Slot::Access) {
            Ok(_) => panic!("expected wrong-key reseal to fail"),
            Err(VaultRotationError::UnsealOldFailed { .. }) => {}
            Err(other) => panic!("expected UnsealOldFailed, got {other:?}"),
        }
    }

    /// Story 7.6a (review patch): the monotonic-key_id debug-assert
    /// catches non-monotonic callers in tests. Build a deliberately
    /// non-monotonic pair and assert the panic. Skipped in release
    /// builds (debug_assertions off → assertion compiles out).
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "monotonic invariant")]
    fn reseal_debug_asserts_monotonic_key_id() {
        let old = vault_with([0xCC; 32], 5);
        let new = vault_with([0xDD; 32], 5); // SAME key_id — must panic.
        let token = OAuthToken::from_trusted_bytes(b"z".to_vec());
        let sealed = old.seal(cid("svc"), Slot::Access, &token).unwrap();
        let _ = reseal(&old, &new, &sealed, cid("svc"), Slot::Access);
    }

    #[test]
    fn reseal_with_master_key_helper_round_trips_refresh_token() {
        // Exercise the full MasterKey + reseal workflow the way the CLI
        // will use it, on a refresh token (Slot::Refresh — confirms the
        // refresh slot flows through reseal correctly).
        use permitlayer_credential::OAuthRefreshToken;

        let old_key = MasterKey::from_bytes([0xAA; 32]);
        let new_key = MasterKey::from_bytes([0xBB; 32]);
        let old_vault = Vault::new(Zeroizing::new(*old_key.as_bytes()), 0);
        let new_vault = Vault::new(Zeroizing::new(*new_key.as_bytes()), 1);
        let id = cid("gmail");

        let refresh = OAuthRefreshToken::from_trusted_bytes(b"refresh-token-bytes".to_vec());
        let sealed = old_vault.seal_refresh(id, Slot::Refresh, &refresh).unwrap();
        let resealed = reseal(&old_vault, &new_vault, &sealed, id, Slot::Refresh).unwrap();
        let recovered = new_vault.unseal_refresh(id, Slot::Refresh, &resealed).unwrap();
        assert_eq!(recovered.reveal(), b"refresh-token-bytes");
    }
}
