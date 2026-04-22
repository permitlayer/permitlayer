//! MUST NOT compile: passing raw `Vec<u8>` (plaintext) to
//! `CredentialStore::put` is a type error. The boundary is structurally
//! typed — only `SealedCredential` is accepted.

use permitlayer_core::store::CredentialStore;

async fn store_rejects_vec<S: CredentialStore>(store: &S) {
    let _ = store.put("gmail", vec![1u8, 2, 3]).await;
}

fn main() {}
