//! MUST NOT compile: passing an `OAuthToken` to `CredentialStore::put`
//! is a type error. `put` accepts only `SealedCredential` as the sealed
//! payload.

use permitlayer_core::store::CredentialStore;
use permitlayer_credential::{ConnectionId, OAuthToken, Slot};

async fn store_rejects_plaintext<S: CredentialStore>(store: &S) {
    let id = ConnectionId::from_bytes([0u8; 16]);
    let token = OAuthToken::from_trusted_bytes(vec![1u8, 2, 3]);
    let _ = store.put(id, Slot::Access, token).await;
}

fn main() {}
