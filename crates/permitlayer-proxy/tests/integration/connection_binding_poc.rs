//! Story 11.11 — PoC checkpoint (GO/NO-GO gate).
//!
//! Proves the whole Connection / Binding / crypto-v2 model end-to-end on a
//! vertical slice before any Phase-4 CLI work: ONE connector
//! (`google-gmail`), TWO connections under TWO distinct ULIDs with TWO
//! distinct sealed access tokens, ONE agent holding TWO bindings (one
//! read-write, one read-only) addressed by TWO distinct selectors, driven
//! through the REAL `ProxyService` resolution → unseal → tier-gate →
//! dispatch chain (Story 11.10) against a mock upstream.
//!
//! Placement note: the charter named this under `permitlayer-daemon`, but
//! the faithful seam is `ProxyService::handle` with the REAL
//! `BindingStore` / `ConnectionStore` / `CredentialStore` / `Vault` + a
//! mock upstream — that exercises the production keying without standing
//! up a full mock Google API behind a live daemon. See the 11.11 story.
//!
//! Acceptance, all asserted below:
//!   1. Two distinct ConnectionIds + distinct sealed credentials; neither
//!      unseals under the other's id (NFR51 end-to-end).
//!   2. One agent, two bindings at different tiers, two distinct selectors.
//!   3. The read-write selector reaches connection A's token; the
//!      read-only selector reaches connection B's (each session = one
//!      account), proven by the mock observing the per-connection bearer.
//!   4. A write tool on the read-only selector is denied (tier gate).

use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{HeaderMap, Method, StatusCode};
use permitlayer_core::audit::event::AuditEvent;
use permitlayer_core::scrub::{ScrubEngine, builtin_rules};
use permitlayer_core::store::binding::Binding;
use permitlayer_core::store::connection::{ConnectionRecord, ConnectionStatus, ConnectionTier};
use permitlayer_core::store::fs::{BindingFsStore, ConnectionFsStore, CredentialFsStore};
use permitlayer_core::store::{
    AuditStore, BindingStore, ConnectionStore, CredentialStore, StoreError,
};
use permitlayer_credential::{ConnectionId, OAuthToken, Slot};
use permitlayer_proxy::error::ProxyError;
use permitlayer_proxy::request::ProxyRequest;
use permitlayer_proxy::service::ProxyService;
use permitlayer_proxy::token::ScopedTokenIssuer;
use permitlayer_proxy::upstream::UpstreamClient;
use permitlayer_vault::Vault;
use std::sync::Mutex;
use zeroize::Zeroizing;

const TEST_MASTER_KEY: [u8; 32] = [0x42; 32];
const TOKEN_A: &[u8] = b"oauth-access-token-for-connection-A";
const TOKEN_B: &[u8] = b"oauth-access-token-for-connection-B";

// google-gmail scope vocab (short name → full URI). Read tier carries
// `gmail.readonly`; the read-write tier additionally carries
// `gmail.send`/`compose`/`modify` (see the embedded connector def).
const GMAIL_READONLY_URI: &str = "https://www.googleapis.com/auth/gmail.readonly";
const GMAIL_SEND_URI: &str = "https://www.googleapis.com/auth/gmail.send";

struct CapturingAuditStore {
    events: Mutex<Vec<AuditEvent>>,
}
impl CapturingAuditStore {
    fn new() -> Self {
        Self { events: Mutex::new(Vec::new()) }
    }
}
#[async_trait::async_trait]
impl AuditStore for CapturingAuditStore {
    async fn append(&self, event: AuditEvent) -> Result<(), StoreError> {
        self.events.lock().unwrap().push(event);
        Ok(())
    }
}

fn test_vault() -> Vault {
    Vault::new(Zeroizing::new(TEST_MASTER_KEY), 0)
}

fn test_token_issuer() -> ScopedTokenIssuer {
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
    ScopedTokenIssuer::new(Zeroizing::new(key))
}

/// Seal `token_bytes` under `(id, Slot::Access)` and persist it via the
/// real `CredentialFsStore` rooted at `home`.
async fn seal_access(home: &std::path::Path, id: ConnectionId, token_bytes: &[u8]) {
    let vault = test_vault();
    let token = OAuthToken::from_trusted_bytes(token_bytes.to_vec());
    let sealed = vault.seal(id, Slot::Access, &token).expect("seal access");
    let store = CredentialFsStore::new(home.to_path_buf()).expect("credential store");
    store.put(id, Slot::Access, sealed).await.expect("put sealed access");
}

async fn write_connection(
    home: &std::path::Path,
    id: ConnectionId,
    name: &str,
    tier: ConnectionTier,
    granted: &[&str],
) {
    let rec = ConnectionRecord {
        id,
        connector_id: "google-gmail".to_owned(),
        name: name.to_owned(),
        account_hint: Some(format!("{name}@example.com")),
        granted_scopes: granted.iter().map(|s| (*s).to_owned()).collect(),
        tier,
        created_at: chrono::Utc::now(),
        status: ConnectionStatus::Active,
    };
    let store = ConnectionFsStore::new(home.to_path_buf()).expect("connection store");
    store.put(rec).await.expect("write connection record");
}

async fn write_binding(
    home: &std::path::Path,
    agent: &str,
    id: ConnectionId,
    tier: ConnectionTier,
    alias: &str,
) {
    let store = BindingFsStore::new(home.to_path_buf()).expect("binding store");
    store
        .put_binding(
            agent,
            Binding { connection_id: id, tier, policy: None, alias: Some(alias.to_owned()) },
        )
        .await
        .expect("write binding");
}

/// Build a `ProxyService` with real binding/connection/credential stores
/// (rooted at `home`) + a mock upstream URL, wiring `with_binding_resolution`.
fn build_poc_service(
    home: &std::path::Path,
    mock_url: &str,
) -> (Arc<ProxyService>, Arc<CapturingAuditStore>) {
    let credential_store: Arc<dyn CredentialStore> =
        Arc::new(CredentialFsStore::new(home.to_path_buf()).expect("credential store"));
    let binding_store: Arc<dyn BindingStore> =
        Arc::new(BindingFsStore::new(home.to_path_buf()).expect("binding store"));
    let connection_store: Arc<dyn ConnectionStore> =
        Arc::new(ConnectionFsStore::new(home.to_path_buf()).expect("connection store"));
    let vault = Arc::new(test_vault());
    let token_issuer = Arc::new(test_token_issuer());
    let upstream_client = Arc::new(UpstreamClient::new().unwrap());
    // Point the google-gmail connector's upstream at the mock server.
    let connectors = super::common::connector_registry_with(&[("gmail", mock_url)]);
    let audit_store = Arc::new(CapturingAuditStore::new());
    let scrub = Arc::new(ScrubEngine::new(builtin_rules().to_vec()).unwrap());

    let service = Arc::new(
        ProxyService::new(
            credential_store,
            vault,
            token_issuer,
            upstream_client,
            connectors,
            Arc::clone(&audit_store) as Arc<dyn AuditStore>,
            scrub,
            home.join("vault"),
            home.join("media"),
        )
        .with_binding_resolution(binding_store, connection_store),
    );
    (service, audit_store)
}

/// A `ProxyRequest` whose `service` field IS the selector (the
/// `/mcp/{selector}` segment); `scope` is the connector SHORT name the
/// tier gate checks.
fn req(selector: &str, scope: &str, method: Method, path: &str) -> ProxyRequest {
    ProxyRequest {
        service: selector.to_owned(),
        scope: scope.to_owned(),
        resource: path.to_owned(),
        method,
        path: path.to_owned(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
        agent_id: "poc-agent".to_owned(),
        request_id: ulid::Ulid::new().to_string(),
    }
}

/// AC#1 — per-connection cryptographic isolation (NFR51 end-to-end):
/// the same `(id, slot)` round-trips; the OTHER id's sealed bytes do NOT
/// unseal under this id.
#[tokio::test]
async fn poc_ac1_two_connections_are_cryptographically_isolated() {
    let vault = test_vault();
    let id_a = ConnectionId::generate();
    let id_b = ConnectionId::generate();
    assert_ne!(id_a, id_b, "two minted connection ids must differ");

    let sealed_a =
        vault.seal(id_a, Slot::Access, &OAuthToken::from_trusted_bytes(TOKEN_A.to_vec())).unwrap();
    let sealed_b =
        vault.seal(id_b, Slot::Access, &OAuthToken::from_trusted_bytes(TOKEN_B.to_vec())).unwrap();

    // Same (id, slot) round-trips to the original plaintext.
    let got_a = vault.unseal(id_a, Slot::Access, &sealed_a).expect("A unseals under A");
    assert_eq!(got_a.reveal(), TOKEN_A);

    // Cross-connection: B's ciphertext must NOT unseal under A's id, and
    // vice-versa — the AAD/HKDF domain binds the ciphertext to its id.
    let cross_a = vault.unseal(id_a, Slot::Access, &sealed_b);
    assert!(cross_a.is_err(), "B's sealed bytes must not unseal under A's id (NFR51)");
    let cross_b = vault.unseal(id_b, Slot::Access, &sealed_a);
    assert!(cross_b.is_err(), "A's sealed bytes must not unseal under B's id (NFR51)");
}

/// AC#2 + AC#3 — one agent, two bindings at distinct tiers + selectors;
/// each selector's read tool reaches its OWN connection's access token.
#[tokio::test]
async fn poc_ac2_ac3_each_selector_reaches_its_own_connection_token() {
    let home = tempfile::TempDir::new().unwrap();
    let mut server = mockito::Server::new_async().await;

    // The mock distinguishes the two connections by the bearer the proxy
    // attaches (the per-connection unsealed OAuth access token).
    let bearer_a = format!("Bearer {}", std::str::from_utf8(TOKEN_A).unwrap());
    let bearer_b = format!("Bearer {}", std::str::from_utf8(TOKEN_B).unwrap());
    let mock_a = server
        .mock("GET", "/users/me/messages")
        .match_header("authorization", bearer_a.as_str())
        .with_status(200)
        .with_body(r#"{"account":"A"}"#)
        .create_async()
        .await;
    let mock_b = server
        .mock("GET", "/users/me/messages")
        .match_header("authorization", bearer_b.as_str())
        .with_status(200)
        .with_body(r#"{"account":"B"}"#)
        .create_async()
        .await;

    // Seed: two google-gmail connections (distinct ids + tokens), one
    // agent bound to both — A read-write (alias acct-a), B read-only
    // (alias acct-b).
    let id_a = ConnectionId::generate();
    let id_b = ConnectionId::generate();
    write_connection(
        home.path(),
        id_a,
        "acct-a",
        ConnectionTier::ReadWrite,
        &[GMAIL_READONLY_URI, GMAIL_SEND_URI],
    )
    .await;
    write_connection(home.path(), id_b, "acct-b", ConnectionTier::Read, &[GMAIL_READONLY_URI])
        .await;
    seal_access(home.path(), id_a, TOKEN_A).await;
    seal_access(home.path(), id_b, TOKEN_B).await;
    write_binding(home.path(), "poc-agent", id_a, ConnectionTier::ReadWrite, "acct-a").await;
    write_binding(home.path(), "poc-agent", id_b, ConnectionTier::Read, "acct-b").await;

    // AC#2: the agent holds exactly two bindings → two distinct ids.
    let bindings =
        BindingFsStore::new(home.path().to_path_buf()).unwrap().get("poc-agent").await.unwrap();
    assert_eq!(bindings.len(), 2, "one agent, two bindings (FR47)");
    let ids: std::collections::BTreeSet<_> =
        bindings.iter().map(|b| *b.connection_id.as_bytes()).collect();
    assert_eq!(ids.len(), 2, "the two bindings address two distinct connections");

    let (service, _audit) = build_poc_service(home.path(), &format!("{}/", server.url()));

    // AC#3: read tool via the read-write selector reaches connection A.
    let resp_a = service
        .handle(req("acct-a", "gmail.readonly", Method::GET, "users/me/messages"))
        .await
        .expect("acct-a read dispatches");
    assert_eq!(resp_a.status, StatusCode::OK);
    assert_eq!(
        resp_a.body.as_ref(),
        br#"{"account":"A"}"# as &[u8],
        "acct-a selector must reach connection A"
    );

    // AC#3: read tool via the read-only selector reaches connection B.
    let resp_b = service
        .handle(req("acct-b", "gmail.readonly", Method::GET, "users/me/messages"))
        .await
        .expect("acct-b read dispatches");
    assert_eq!(resp_b.status, StatusCode::OK);
    assert_eq!(
        resp_b.body.as_ref(),
        br#"{"account":"B"}"# as &[u8],
        "acct-b selector must reach connection B"
    );

    mock_a.assert_async().await;
    mock_b.assert_async().await;
}

/// AC#4 — a write tool on the read-only selector is denied by the tier
/// gate (default-deny), before any upstream call.
#[tokio::test]
async fn poc_ac4_write_tool_on_readonly_selector_is_denied() {
    let home = tempfile::TempDir::new().unwrap();
    let mut server = mockito::Server::new_async().await;
    // Any upstream hit here is a FAILURE — the request must be denied
    // before dispatch. `expect(0)` makes `assert_async` fail if the proxy
    // ever dispatches the write to the upstream.
    let leak_guard = server
        .mock("POST", "/users/me/messages/send")
        .expect(0)
        .with_status(200)
        .with_body(r#"{"LEAK":"write reached upstream"}"#)
        .create_async()
        .await;

    let id_b = ConnectionId::generate();
    write_connection(home.path(), id_b, "acct-b", ConnectionTier::Read, &[GMAIL_READONLY_URI])
        .await;
    seal_access(home.path(), id_b, TOKEN_B).await;
    write_binding(home.path(), "poc-agent", id_b, ConnectionTier::Read, "acct-b").await;

    let (service, _audit) = build_poc_service(home.path(), &format!("{}/", server.url()));

    // `gmail.send` is a read-write-tier scope; the read-only binding's
    // tier bundle does not contain it → tier gate denies.
    let err = service
        .handle(req("acct-b", "gmail.send", Method::POST, "users/me/messages/send"))
        .await
        .expect_err("write tool on read-only selector must be denied");
    assert!(matches!(err, ProxyError::TierDenied { .. }), "expected tier.denied, got {err:?}");

    // The upstream must NOT have been reached (default-deny ahead of
    // dispatch) — `expect(0)` above + this assert fail if it was.
    leak_guard.assert_async().await;
}

/// F3 (review 2026-06-07) — the granted-scopes gate, DISTINCT from the
/// tier gate, denies a tool the tier WOULD allow when the connection's
/// `granted_scopes` lacks the scope's URI → 403 `scope.not_granted`.
/// Previously no test exercised this charter deny-class (Story 11.10).
#[tokio::test]
async fn poc_scope_not_granted_when_tier_allows_but_connection_lacks_scope() {
    let home = tempfile::TempDir::new().unwrap();
    let mut server = mockito::Server::new_async().await;
    // Any upstream hit is a failure — the request must be denied at the
    // granted-scopes gate, before dispatch.
    let leak_guard = server
        .mock("POST", "/users/me/messages/send")
        .expect(0)
        .with_status(200)
        .create_async()
        .await;

    // Read-WRITE tier (so gmail.send IS in the tier bundle), but the
    // connection was granted ONLY the readonly URI — so the granted-scopes
    // gate must deny gmail.send even though the tier permits it.
    let id = ConnectionId::generate();
    write_connection(home.path(), id, "acct-rw", ConnectionTier::ReadWrite, &[GMAIL_READONLY_URI])
        .await;
    seal_access(home.path(), id, TOKEN_A).await;
    write_binding(home.path(), "poc-agent", id, ConnectionTier::ReadWrite, "acct-rw").await;

    let (service, _audit) = build_poc_service(home.path(), &format!("{}/", server.url()));

    let err = service
        .handle(req("acct-rw", "gmail.send", Method::POST, "users/me/messages/send"))
        .await
        .expect_err("tier permits gmail.send but the connection lacks the granted scope");
    assert!(
        matches!(err, ProxyError::ScopeNotGranted { .. }),
        "expected scope.not_granted (granted-scopes gate, distinct from tier), got {err:?}"
    );
    leak_guard.assert_async().await;
}

/// F11 (review 2026-06-07) — the selector→binding match precedence is
/// alias → connection.name → id. Prove the ALIAS pass resolves at the
/// request path with an alias that DIFFERS from the connection name (all
/// prior tests set alias == name, so they couldn't distinguish the passes).
#[tokio::test]
async fn poc_alias_resolves_when_alias_differs_from_connection_name() {
    let home = tempfile::TempDir::new().unwrap();
    let mut server = mockito::Server::new_async().await;
    let bearer = format!("Bearer {}", std::str::from_utf8(TOKEN_A).unwrap());
    let mock = server
        .mock("GET", "/users/me/messages")
        .match_header("authorization", bearer.as_str())
        .with_status(200)
        .with_body(r#"{"via":"alias"}"#)
        .create_async()
        .await;

    // Connection name is "real-account-name"; the binding aliases it as
    // "my-alias". A request to /mcp/my-alias must resolve via the alias
    // pass (the name pass would NOT match "my-alias").
    let id = ConnectionId::generate();
    write_connection(
        home.path(),
        id,
        "real-account-name",
        ConnectionTier::Read,
        &[GMAIL_READONLY_URI],
    )
    .await;
    seal_access(home.path(), id, TOKEN_A).await;
    write_binding(home.path(), "poc-agent", id, ConnectionTier::Read, "my-alias").await;

    let (service, _audit) = build_poc_service(home.path(), &format!("{}/", server.url()));

    // The ALIAS resolves (Pass-1) — alias != connection name, so this
    // exercises the alias pass specifically.
    let resp = service
        .handle(req("my-alias", "gmail.readonly", Method::GET, "users/me/messages"))
        .await
        .expect("the alias selector must resolve via the alias pass");
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(resp.body.as_ref(), br#"{"via":"alias"}"# as &[u8]);
    mock.assert_async().await;

    // The connection NAME also resolves (Pass-2) — alias and name are BOTH
    // valid selectors for the same binding (alias is tried first but a name
    // match is a valid fallback; setting an alias is additive, not exclusive).
    let mock2 = server
        .mock("GET", "/users/me/messages")
        .match_header("authorization", bearer.as_str())
        .with_status(200)
        .with_body(r#"{"via":"name"}"#)
        .create_async()
        .await;
    let resp2 = service
        .handle(req("real-account-name", "gmail.readonly", Method::GET, "users/me/messages"))
        .await
        .expect("the connection name must also resolve via the name pass");
    assert_eq!(resp2.status, StatusCode::OK);
    assert_eq!(resp2.body.as_ref(), br#"{"via":"name"}"# as &[u8]);
    mock2.assert_async().await;

    // A selector matching NEITHER alias nor name nor id → binding.not_found.
    let err = service
        .handle(req("no-such-selector", "gmail.readonly", Method::GET, "users/me/messages"))
        .await
        .expect_err("an unrelated selector must not resolve");
    assert!(
        matches!(err, ProxyError::BindingNotFound { .. }),
        "expected binding.not_found for an unrelated selector, got {err:?}"
    );
}

/// F10 (review 2026-06-07) — defensive guard: a binding whose connection
/// record is `status = Revoked` must NOT resolve (the production `revoke`
/// verb DELETES the record, so this only fires on a hand-edited/partial
/// state, but the resolver must still fail closed). No prior test drove a
/// persisted Revoked record through resolution.
#[tokio::test]
async fn poc_revoked_connection_record_does_not_resolve() {
    let home = tempfile::TempDir::new().unwrap();
    let mut server = mockito::Server::new_async().await;
    let leak_guard = server.mock("GET", "/users/me/messages").expect(0).create_async().await;

    // Write a REVOKED connection record directly (production revoke would
    // have deleted it; this simulates a hand-edited / partial-cleanup state).
    let id = ConnectionId::generate();
    let revoked = ConnectionRecord {
        id,
        connector_id: "google-gmail".to_owned(),
        name: "revoked-acct".to_owned(),
        account_hint: None,
        granted_scopes: vec![GMAIL_READONLY_URI.to_owned()],
        tier: ConnectionTier::Read,
        created_at: chrono::Utc::now(),
        status: ConnectionStatus::Revoked,
    };
    ConnectionFsStore::new(home.path().to_path_buf()).unwrap().put(revoked).await.unwrap();
    seal_access(home.path(), id, TOKEN_A).await;
    write_binding(home.path(), "poc-agent", id, ConnectionTier::Read, "revoked-acct").await;

    let (service, _audit) = build_poc_service(home.path(), &format!("{}/", server.url()));

    let err = service
        .handle(req("revoked-acct", "gmail.readonly", Method::GET, "users/me/messages"))
        .await
        .expect_err("a revoked connection must not resolve (fail closed)");
    assert!(
        matches!(err, ProxyError::BindingNotFound { .. }),
        "expected binding.not_found for a revoked connection, got {err:?}"
    );
    leak_guard.assert_async().await;
}
