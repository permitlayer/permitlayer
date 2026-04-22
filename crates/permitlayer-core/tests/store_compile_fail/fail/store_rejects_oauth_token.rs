//! MUST NOT compile: passing an `OAuthToken` to `CredentialStore::put`
//! is a type error. `put` accepts only `SealedCredential`.

use permitlayer_core::store::CredentialStore;
use permitlayer_credential::OAuthToken;

async fn store_rejects_plaintext<S: CredentialStore>(store: &S) {
    let token = OAuthToken::from_trusted_bytes(vec![1u8, 2, 3]);
    let _ = store.put("gmail", token).await;
}

fn main() {}
