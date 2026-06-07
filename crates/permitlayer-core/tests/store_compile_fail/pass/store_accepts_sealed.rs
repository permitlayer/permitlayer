//! Sanity: a correctly-shaped `put(id, slot, SealedCredential)` call
//! compiles. If this stops compiling, the fail-tests below are suspect
//! (we might be detecting a broken API rather than a type-discipline
//! violation).

use permitlayer_core::store::CredentialStore;
use permitlayer_credential::{ConnectionId, KeyId, SEALED_CREDENTIAL_VERSION, SealedCredential, Slot};

#[allow(dead_code)]
async fn store_accepts_sealed<S: CredentialStore>(store: &S) {
    let id = ConnectionId::from_bytes([0u8; 16]);
    let sealed = SealedCredential::from_trusted_bytes(
        vec![0u8; 48],
        [0u8; 12],
        vec![0u8; 21],
        SEALED_CREDENTIAL_VERSION,
        KeyId::ZERO,
    );
    let _ = store.put(id, Slot::Access, sealed).await;
    let _ = store.get(id, Slot::Access).await;
}

fn main() {}
