//! Integration tests for the MCP transport adapter.
//!
//! Verifies that the GmailMcpServer correctly:
//! - Lists 5 Gmail tools via the tool router
//! - Constructs correct ProxyRequest for each tool
//! - Returns upstream JSON as text content on success
//! - Returns error content (not transport error) on failure
//! - Shares the same ProxyService::handle code path as REST

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::http::{HeaderMap, Method, StatusCode};
use permitlayer_core::audit::event::AuditEvent;
use permitlayer_core::scrub::{ScrubEngine, builtin_rules};
use permitlayer_core::store::{AuditStore, CredentialStore, StoreError};
use permitlayer_credential::{OAuthToken, SealedCredential};
use permitlayer_proxy::request::ProxyRequest;
use permitlayer_proxy::service::ProxyService;
use permitlayer_proxy::token::ScopedTokenIssuer;
use permitlayer_proxy::transport::mcp::{CalendarMcpServer, DriveMcpServer, GmailMcpServer};
use permitlayer_proxy::upstream::UpstreamClient;
use permitlayer_vault::Vault;
use rmcp::ServerHandler;
use url::Url;
use zeroize::Zeroizing;

// --- Test Helpers (same pattern as proxy_service.rs) ---

const TEST_MASTER_KEY: [u8; 32] = [0x42; 32];

fn test_scrub_engine() -> Arc<ScrubEngine> {
    Arc::new(ScrubEngine::new(builtin_rules().to_vec()).unwrap())
}

fn test_vault() -> Vault {
    Vault::new(Zeroizing::new(TEST_MASTER_KEY))
}

fn test_token_issuer() -> ScopedTokenIssuer {
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
    ScopedTokenIssuer::new(Zeroizing::new(key))
}

struct MockCredentialStore {
    services: HashMap<String, Vec<u8>>,
    master_key: [u8; 32],
}

impl MockCredentialStore {
    fn new(master_key: [u8; 32]) -> Self {
        Self { services: HashMap::new(), master_key }
    }

    fn add_service(&mut self, service: &str, token_bytes: &[u8]) {
        self.services.insert(service.to_owned(), token_bytes.to_vec());
    }
}

#[async_trait::async_trait]
impl CredentialStore for MockCredentialStore {
    async fn put(&self, _service: &str, _sealed: SealedCredential) -> Result<(), StoreError> {
        Ok(())
    }
    async fn get(&self, service: &str) -> Result<Option<SealedCredential>, StoreError> {
        match self.services.get(service) {
            Some(token_bytes) => {
                let vault = Vault::new(Zeroizing::new(self.master_key));
                let token = OAuthToken::from_trusted_bytes(token_bytes.clone());
                match vault.seal(service, &token) {
                    Ok(sealed) => Ok(Some(sealed)),
                    Err(_) => panic!("mock seal failed for {service}"),
                }
            }
            None => Ok(None),
        }
    }
}

struct MockAuditStore {
    events: Mutex<Vec<AuditEvent>>,
}

impl MockAuditStore {
    fn new() -> Self {
        Self { events: Mutex::new(Vec::new()) }
    }

    fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl AuditStore for MockAuditStore {
    async fn append(&self, event: AuditEvent) -> Result<(), StoreError> {
        self.events.lock().unwrap().push(event);
        Ok(())
    }
}

async fn build_service(server_url: &str) -> (Arc<ProxyService>, Arc<MockAuditStore>) {
    let mut cred_store = MockCredentialStore::new(TEST_MASTER_KEY);
    cred_store.add_service("gmail", b"test-oauth-access-token");

    let credential_store: Arc<dyn CredentialStore> = Arc::new(cred_store);
    let vault = Arc::new(test_vault());
    let token_issuer = Arc::new(test_token_issuer());

    let client = reqwest::Client::builder().build().unwrap();
    let mut base_urls = HashMap::new();
    base_urls.insert("gmail".to_owned(), Url::parse(server_url).unwrap());
    let upstream_client = Arc::new(UpstreamClient::with_client_and_urls(client, base_urls));

    let audit_store = Arc::new(MockAuditStore::new());

    let service = Arc::new(ProxyService::new(
        credential_store,
        vault,
        token_issuer,
        upstream_client,
        Arc::clone(&audit_store) as Arc<dyn AuditStore>,
        test_scrub_engine(),
        std::env::temp_dir(),
    ));

    (service, audit_store)
}

// --- MCP tool listing tests ---

#[test]
fn mcp_tool_listing_returns_five_gmail_tools() {
    let vault = Arc::new(test_vault());
    let cred_store = MockCredentialStore::new(TEST_MASTER_KEY);
    let upstream = UpstreamClient::new().unwrap();
    let audit_store = Arc::new(MockAuditStore::new());
    let token_issuer = Arc::new(test_token_issuer());

    let proxy = Arc::new(ProxyService::new(
        Arc::new(cred_store) as Arc<dyn CredentialStore>,
        vault,
        token_issuer,
        Arc::new(upstream),
        audit_store as Arc<dyn AuditStore>,
        test_scrub_engine(),
        std::env::temp_dir(),
    ));

    let server = GmailMcpServer::new(proxy);

    // Use ServerHandler::get_tool to verify each tool is registered.
    let expected_names = [
        "gmail.messages.list",
        "gmail.messages.get",
        "gmail.threads.list",
        "gmail.threads.get",
        "gmail.search",
    ];

    for name in &expected_names {
        assert!(server.get_tool(name).is_some(), "tool '{name}' should be registered");
    }

    // Verify get_info reports tools capability.
    let info = server.get_info();
    assert!(info.capabilities.tools.is_some());
}

#[test]
fn mcp_tool_input_schemas_have_no_meta_schema_declaration() {
    // Strict MCP clients (e.g. OpenClaw / AJV) reject any tool whose
    // inputSchema declares an unresolvable `$schema` meta-schema. We
    // strip the schemars-emitted "$schema" key in `*McpServer::new` —
    // assert it never escapes for any of the three connectors. A single
    // leak here will silently break tool dispatch in those clients.
    let vault = Arc::new(test_vault());
    let cred_store = MockCredentialStore::new(TEST_MASTER_KEY);
    let upstream = UpstreamClient::new().unwrap();
    let audit_store = Arc::new(MockAuditStore::new());
    let token_issuer = Arc::new(test_token_issuer());

    let proxy = Arc::new(ProxyService::new(
        Arc::new(cred_store) as Arc<dyn CredentialStore>,
        vault,
        token_issuer,
        Arc::new(upstream),
        audit_store as Arc<dyn AuditStore>,
        test_scrub_engine(),
        std::env::temp_dir(),
    ));

    let gmail = GmailMcpServer::new(Arc::clone(&proxy));
    let calendar = CalendarMcpServer::new(Arc::clone(&proxy));
    let drive = DriveMcpServer::new(proxy);

    let gmail_tools = [
        "gmail.messages.list",
        "gmail.messages.get",
        "gmail.threads.list",
        "gmail.threads.get",
        "gmail.search",
    ];
    let calendar_tools = [
        "calendar.calendars.list",
        "calendar.events.list",
        "calendar.events.get",
        "calendar.events.create",
        "calendar.events.update",
    ];
    let drive_tools = [
        "drive.files.list",
        "drive.files.get",
        "drive.files.search",
        "drive.files.create",
        "drive.files.update",
    ];

    for name in &gmail_tools {
        let tool = gmail.get_tool(name).unwrap_or_else(|| panic!("tool '{name}' missing"));
        assert!(!tool.input_schema.contains_key("$schema"), "tool '{name}' leaks $schema");
    }
    for name in &calendar_tools {
        let tool = calendar.get_tool(name).unwrap_or_else(|| panic!("tool '{name}' missing"));
        assert!(!tool.input_schema.contains_key("$schema"), "tool '{name}' leaks $schema");
    }
    for name in &drive_tools {
        let tool = drive.get_tool(name).unwrap_or_else(|| panic!("tool '{name}' missing"));
        assert!(!tool.input_schema.contains_key("$schema"), "tool '{name}' leaks $schema");
    }
}

#[test]
fn mcp_server_info_has_correct_name_and_version() {
    // Build a minimal GmailMcpServer (needs a real ProxyService, but we
    // only call get_info which doesn't touch it).
    let vault = Arc::new(test_vault());
    let cred_store = MockCredentialStore::new(TEST_MASTER_KEY);
    let upstream = UpstreamClient::new().unwrap();
    let audit_store = Arc::new(MockAuditStore::new());
    let token_issuer = Arc::new(test_token_issuer());

    let proxy = Arc::new(ProxyService::new(
        Arc::new(cred_store) as Arc<dyn CredentialStore>,
        vault,
        token_issuer,
        Arc::new(upstream),
        audit_store as Arc<dyn AuditStore>,
        test_scrub_engine(),
        std::env::temp_dir(),
    ));

    let server = GmailMcpServer::new(proxy);
    let info = server.get_info();
    assert_eq!(info.server_info.name, "permitlayer");
    assert!(info.capabilities.tools.is_some());
}

// --- MCP tool call tests ---

#[tokio::test]
async fn mcp_messages_list_returns_upstream_json() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/users/me/messages")
        .match_header("authorization", "Bearer test-oauth-access-token")
        .with_status(200)
        .with_body(r#"{"messages":[{"id":"msg1","threadId":"t1"}]}"#)
        .create_async()
        .await;

    let (proxy, _audit) = build_service(&format!("{}/", server.url())).await;
    let mcp_server = GmailMcpServer::new(proxy);

    // Simulate a messages.list tool call by calling the dispatch helper.
    let req = GmailMcpServer::gmail_request("users/me/messages".to_owned(), "gmail.readonly");
    let result = mcp_server.dispatch(req).await;
    assert!(result.is_ok());
    let body = result.unwrap();
    assert!(body.contains("msg1"));

    mock.assert_async().await;
}

#[tokio::test]
async fn mcp_messages_get_constructs_correct_path() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/users/me/messages/abc123")
        .with_status(200)
        .with_body(r#"{"id":"abc123","snippet":"hello"}"#)
        .create_async()
        .await;

    let (proxy, _audit) = build_service(&format!("{}/", server.url())).await;
    let mcp_server = GmailMcpServer::new(proxy);

    let req =
        GmailMcpServer::gmail_request("users/me/messages/abc123".to_owned(), "gmail.readonly");
    let result = mcp_server.dispatch(req).await;
    assert!(result.is_ok());
    let body = result.unwrap();
    assert!(body.contains("abc123"));

    mock.assert_async().await;
}

#[tokio::test]
async fn mcp_search_constructs_correct_query_string() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/users/me/messages?q=from:me")
        .with_status(200)
        .with_body(r#"{"messages":[]}"#)
        .create_async()
        .await;

    let (proxy, _audit) = build_service(&format!("{}/", server.url())).await;
    let mcp_server = GmailMcpServer::new(proxy);

    let req =
        GmailMcpServer::gmail_request("users/me/messages?q=from:me".to_owned(), "gmail.readonly");
    let result = mcp_server.dispatch(req).await;
    assert!(result.is_ok());

    mock.assert_async().await;
}

#[tokio::test]
async fn mcp_tool_error_returns_error_string_not_transport_error() {
    // Use an unreachable upstream to trigger an error.
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_millis(100))
        .timeout(std::time::Duration::from_millis(200))
        .build()
        .unwrap();
    let mut base_urls = HashMap::new();
    base_urls.insert("gmail".to_owned(), Url::parse("http://127.0.0.1:1/").unwrap());
    let upstream_client = Arc::new(UpstreamClient::with_client_and_urls(client, base_urls));

    let mut cred_store = MockCredentialStore::new(TEST_MASTER_KEY);
    cred_store.add_service("gmail", b"test-oauth-access-token");

    let proxy = Arc::new(ProxyService::new(
        Arc::new(cred_store) as Arc<dyn CredentialStore>,
        Arc::new(test_vault()),
        Arc::new(test_token_issuer()),
        upstream_client,
        Arc::new(MockAuditStore::new()) as Arc<dyn AuditStore>,
        test_scrub_engine(),
        std::env::temp_dir(),
    ));

    let mcp_server = GmailMcpServer::new(proxy);
    let req = GmailMcpServer::gmail_request("users/me/messages".to_owned(), "gmail.readonly");

    // Should return Err(message) — not panic or transport error.
    let result = mcp_server.dispatch(req).await;
    assert!(result.is_err());
    let error_msg = result.unwrap_err();
    assert!(
        error_msg.contains("unreachable") || error_msg.contains("connection"),
        "error should mention connectivity: {error_msg}"
    );
}

// --- MCP audit event tests ---

#[tokio::test]
async fn mcp_originated_call_writes_audit_event() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/users/me/messages")
        .with_status(200)
        .with_body(r#"{"messages":[]}"#)
        .create_async()
        .await;

    let (proxy, audit) = build_service(&format!("{}/", server.url())).await;
    let mcp_server = GmailMcpServer::new(proxy);

    let req = GmailMcpServer::gmail_request("users/me/messages".to_owned(), "gmail.readonly");
    let result = mcp_server.dispatch(req).await;
    assert!(result.is_ok());

    // Verify audit event was written with correct fields.
    let events = audit.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].service, "gmail");
    assert_eq!(events[0].scope, "gmail.readonly");
    assert_eq!(events[0].outcome, "ok");
    assert_eq!(events[0].event_type, "api-call");

    mock.assert_async().await;
}

// --- REST and MCP parity test ---

#[tokio::test]
async fn rest_and_mcp_return_equivalent_response_data() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/users/me/messages")
        .with_status(200)
        .with_body(r#"{"messages":[{"id":"shared"}]}"#)
        .expect(2) // Called once by MCP, once by REST path
        .create_async()
        .await;

    let (proxy, _audit) = build_service(&format!("{}/", server.url())).await;

    // MCP path: GmailMcpServer::dispatch
    let mcp_server = GmailMcpServer::new(Arc::clone(&proxy));
    let mcp_req = GmailMcpServer::gmail_request("users/me/messages".to_owned(), "gmail.readonly");
    let mcp_result = mcp_server.dispatch(mcp_req).await.unwrap();

    // REST path: ProxyService::handle directly
    let rest_req = ProxyRequest {
        service: "gmail".to_owned(),
        scope: "gmail.readonly".to_owned(),
        resource: "users/me/messages".to_owned(),
        method: Method::GET,
        path: "users/me/messages".to_owned(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
        agent_id: "rest-client".to_owned(),
        request_id: "test-rest-id".to_owned(),
    };
    let rest_resp = proxy.handle(rest_req).await.unwrap();
    let rest_body = String::from_utf8_lossy(&rest_resp.body).into_owned();

    // Both should return the same upstream response data.
    assert_eq!(mcp_result, rest_body);
    assert_eq!(rest_resp.status, StatusCode::OK);

    mock.assert_async().await;
}
