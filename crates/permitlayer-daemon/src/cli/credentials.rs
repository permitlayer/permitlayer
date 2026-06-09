//! Credential helpers shared with the control plane.
//!
//! Story 11.12/11.13 retired the `agentsso credentials list|status|refresh`
//! CLI surface: `connection list` / `connection inspect` (Story 11.13) read
//! connection provenance from the `ConnectionStore`, and the proxy
//! auto-refreshes access tokens on the request path, so a manual
//! `credentials refresh` is vestigial. What survives is the BYO OAuth-client
//! resolver the control-plane verify handler's 401 self-heal uses — keyed on
//! the connection's `Client` slot via the credential store (no `-meta.json`,
//! no service→id derivation).

use std::sync::Arc;

/// Reconstruct the BYO OAuth client for `connection` by unsealing its
/// `Client` slot via the credential store.
///
/// `pub(crate)` so the control-plane verify handler's 401 self-heal
/// (`server::control::try_self_heal_refresh`) can reuse it. The bundle is
/// sealed in the vault — never re-read from a plaintext path. A missing
/// `Client` slot means the connection has no usable BYO client (the caller
/// treats that as "cannot self-heal").
pub(crate) async fn build_oauth_client_for_connection(
    vault: &permitlayer_vault::Vault,
    credential_store: &Arc<dyn permitlayer_core::store::CredentialStore>,
    connection: permitlayer_credential::ConnectionId,
) -> Result<Arc<permitlayer_oauth::OAuthClient>, String> {
    use permitlayer_credential::Slot;
    use permitlayer_oauth::{GoogleOAuthConfig, OAuthClient};

    let sealed = match credential_store.get(connection, Slot::Client).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Err(format!(
                "no sealed OAuth client bundle for connection {connection} (Client slot absent)"
            ));
        }
        Err(e) => {
            return Err(format!(
                "credential store read failed for connection {connection} Client slot: {e}"
            ));
        }
    };
    let token = vault.unseal(connection, Slot::Client, &sealed).map_err(|e| {
        format!("could not unseal OAuth client bundle for connection {connection}: {e}")
    })?;
    let config = GoogleOAuthConfig::from_sealed_bundle_bytes(token.reveal()).map_err(|e| {
        format!("malformed sealed OAuth client bundle for connection {connection}: {e}")
    })?;

    OAuthClient::new(config.client_id().to_owned(), config.client_secret().map(str::to_owned))
        .map(Arc::new)
        .map_err(|e| format!("could not construct OAuth client for connection {connection}: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use permitlayer_credential::{ConnectionId, OAuthToken, Slot};
    use permitlayer_vault::Vault;

    const CR_TEST_MASTER_KEY: [u8; 32] = [0x42; 32];

    fn cr_test_vault() -> Vault {
        Vault::new(zeroize::Zeroizing::new(CR_TEST_MASTER_KEY), 0)
    }

    fn cr_store(home: &std::path::Path) -> Arc<dyn permitlayer_core::store::CredentialStore> {
        Arc::new(permitlayer_core::store::fs::CredentialFsStore::new(home.to_path_buf()).unwrap())
    }

    /// Seal a BYO client bundle into the connection's `Client` slot via
    /// the real credential store (mirrors the daemon's seal handler).
    async fn seal_client_bundle(home: &std::path::Path, vault: &Vault, connection: ConnectionId) {
        let bundle = serde_json::json!({
            "client_id": "123.apps.googleusercontent.com",
            "client_secret": "GOCSPX-cli-parity-secret",
            "project_id": "cli-parity-proj",
            "v": 1,
        })
        .to_string();
        let token = OAuthToken::from_trusted_bytes(bundle.into_bytes());
        let sealed = vault.seal(connection, Slot::Client, &token).unwrap();
        cr_store(home).put(connection, Slot::Client, sealed).await.unwrap();
    }

    #[tokio::test]
    async fn build_oauth_client_reconstructs_from_sealed_client_slot() {
        // The BYO client is rebuilt by unsealing the connection's Client
        // slot via the store — NO filesystem read of any client JSON.
        let dir = tempfile::tempdir().unwrap();
        let vault = cr_test_vault();
        let connection = ConnectionId::generate();
        seal_client_bundle(dir.path(), &vault, connection).await;

        let store = cr_store(dir.path());
        let client = build_oauth_client_for_connection(&vault, &store, connection)
            .await
            .expect("must reconstruct the sealed BYO client from the Client slot");
        let _ = client; // OAuthClient has no public accessors; success is the assertion.
    }

    #[tokio::test]
    async fn build_oauth_client_errors_when_client_slot_absent() {
        // A connection with no sealed Client slot cannot be refreshed.
        let dir = tempfile::tempdir().unwrap();
        let vault = cr_test_vault();
        let store = cr_store(dir.path());
        let connection = ConnectionId::generate();
        // `OAuthClient` isn't `Debug`, so `expect_err` won't compile — match.
        let err = match build_oauth_client_for_connection(&vault, &store, connection).await {
            Ok(_) => panic!("absent Client slot must error"),
            Err(e) => e,
        };
        assert!(err.contains("Client slot absent"), "got: {err}");
    }

    #[tokio::test]
    async fn client_slot_not_cross_unsealable_from_other_slots() {
        // Story 7.35 / 11.8 namespace isolation: a bundle sealed under the
        // `Client` slot must NOT unseal under `Access` or `Refresh` of the
        // same connection.
        let dir = tempfile::tempdir().unwrap();
        let vault = cr_test_vault();
        let connection = ConnectionId::generate();
        let bundle = br#"{"client_id":"x.apps.googleusercontent.com","v":1}"#.to_vec();
        let token = OAuthToken::from_trusted_bytes(bundle);
        let sealed = vault.seal(connection, Slot::Client, &token).unwrap();
        assert!(vault.unseal(connection, Slot::Access, &sealed).is_err());
        assert!(vault.unseal(connection, Slot::Refresh, &sealed).is_err());
        assert!(vault.unseal(connection, Slot::Client, &sealed).is_ok());
        let _ = dir;
    }
}
