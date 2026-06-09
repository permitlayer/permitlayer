//! MUST NOT compile: passing raw `Vec<u8>` (plaintext) to
//! `CredentialStore::put` is a type error. The boundary is structurally
//! typed — only `SealedCredential` is accepted as the sealed payload.

use permitlayer_core::store::CredentialStore;
use permitlayer_credential::{ConnectionId, Slot};

async fn store_rejects_vec<S: CredentialStore>(store: &S) {
    let id = ConnectionId::from_bytes([0u8; 16]);
    let _ = store.put(id, Slot::Access, vec![1u8, 2, 3]).await;
}

fn main() {}
