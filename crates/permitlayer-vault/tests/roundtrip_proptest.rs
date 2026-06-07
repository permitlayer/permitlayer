//! Property test: `Vault::seal` → `Vault::unseal` is the identity for
//! arbitrary plaintext bytes, across arbitrary `(ConnectionId, Slot)`
//! keying (Story 11.8 crypto-v2 domain).
//!
//! The connection id is generated from 16 arbitrary bytes (the full ULID
//! value space) and the slot from the three variants — so the round-trip
//! identity is exercised across the whole keying domain, not just a fixed
//! service string.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use permitlayer_credential::{ConnectionId, OAuthToken, Slot};
use permitlayer_keystore::MASTER_KEY_LEN;
use permitlayer_vault::Vault;
use proptest::prelude::*;
use zeroize::Zeroizing;

/// Deterministic master key for reproducibility. Round-trip identity is
/// independent of the master key's bits.
const TEST_MASTER_KEY: [u8; MASTER_KEY_LEN] = [0x42; MASTER_KEY_LEN];

fn slot_strategy() -> impl Strategy<Value = Slot> {
    prop_oneof![Just(Slot::Access), Just(Slot::Refresh), Just(Slot::Client)]
}

proptest! {
    #![proptest_config(ProptestConfig {
        // 256 cases * up to 16 KiB each ≈ 4 MiB of sealed data per run.
        // Release mode (or default dev mode) stays well under 1s.
        cases: 256,
        .. ProptestConfig::default()
    })]

    #[test]
    fn seal_unseal_identity(
        plaintext in prop::collection::vec(any::<u8>(), 0..16384),
        id_bytes in any::<[u8; 16]>(),
        slot in slot_strategy(),
    ) {
        let vault = Vault::new(Zeroizing::new(TEST_MASTER_KEY), 0);
        let id = ConnectionId::from_bytes(id_bytes);
        let token = OAuthToken::from_trusted_bytes(plaintext.clone());
        let sealed = match vault.seal(id, slot, &token) {
            Ok(s) => s,
            Err(_) => panic!("seal failed on valid input"),
        };
        let unsealed = match vault.unseal(id, slot, &sealed) {
            Ok(t) => t,
            Err(_) => panic!("unseal failed on freshly sealed credential"),
        };
        prop_assert_eq!(unsealed.reveal(), plaintext.as_slice());
    }
}
