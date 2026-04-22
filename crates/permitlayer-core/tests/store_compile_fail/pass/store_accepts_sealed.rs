//! Sanity: a correctly-shaped `put(service, SealedCredential)` call
//! compiles. If this stops compiling, the fail-tests below are suspect
//! (we might be detecting a broken API rather than a type-discipline
//! violation).

use permitlayer_core::store::CredentialStore;
use permitlayer_credential::{SEALED_CREDENTIAL_VERSION, SealedCredential};

#[allow(dead_code)]
async fn store_accepts_sealed<S: CredentialStore>(store: &S) {
    let sealed = SealedCredential::from_trusted_bytes(
        vec![0u8; 48],
        [0u8; 12],
        vec![0u8; 21],
        SEALED_CREDENTIAL_VERSION,
    );
    let _ = store.put("gmail", sealed).await;
    let _ = store.get("gmail").await;
}

fn main() {}
