//! Property test: `Vault::seal` → `Vault::unseal` is the identity for
//! arbitrary plaintext bytes.
//!
//! The service-name regex below is a narrow *input generator* — it does
//! NOT mirror the runtime allowlist in
//! `permitlayer-core::store::validate::validate_service_name` (which
//! uses a wider pattern). The generator's job is to produce valid-ish
//! service strings quickly; the runtime validator's job is to reject
//! untrusted input before it becomes a filesystem path. Keeping the two
//! regexes separate prevents accidental coupling.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use permitlayer_credential::OAuthToken;
use permitlayer_keystore::MASTER_KEY_LEN;
use permitlayer_vault::Vault;
use proptest::prelude::*;
use zeroize::Zeroizing;

/// Deterministic master key for reproducibility. Round-trip identity is
/// independent of the master key's bits.
const TEST_MASTER_KEY: [u8; MASTER_KEY_LEN] = [0x42; MASTER_KEY_LEN];

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
        service in "[a-z][a-z0-9-]{1,30}[a-z0-9]",
    ) {
        let vault = Vault::new(Zeroizing::new(TEST_MASTER_KEY));
        let token = OAuthToken::from_trusted_bytes(plaintext.clone());
        let sealed = match vault.seal(&service, &token) {
            Ok(s) => s,
            Err(_) => panic!("seal failed on valid input"),
        };
        let unsealed = match vault.unseal(&service, &sealed) {
            Ok(t) => t,
            Err(_) => panic!("unseal failed on freshly sealed credential"),
        };
        prop_assert_eq!(unsealed.reveal(), plaintext.as_slice());
    }
}
