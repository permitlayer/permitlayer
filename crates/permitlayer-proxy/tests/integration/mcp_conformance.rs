//! MCP conformance smoke tests.
//!
//! Starts an in-process axum server with the MCP `StreamableHttpService` backed
//! by mock dependencies, then verifies the MCP protocol handshake using raw HTTP:
//!
//! 1. `initialize` handshake succeeds
//! 2. `tools/list` returns 5 tools
//! 3. `tools/call` for `gmail.messages.list` returns a valid response
//!
//! These tests verify that the rmcp `StreamableHttpService` is correctly wired
//! and responds to standard MCP Streamable HTTP protocol requests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use permitlayer_core::audit::event::AuditEvent;
use permitlayer_core::scrub::{ScrubEngine, builtin_rules};
use permitlayer_core::store::{AuditStore, CredentialStore, StoreError};
use permitlayer_credential::{OAuthToken, SealedCredential};
use permitlayer_proxy::service::ProxyService;
use permitlayer_proxy::token::ScopedTokenIssuer;
use permitlayer_proxy::transport::mcp::mcp_service;
use permitlayer_proxy::upstream::UpstreamClient;
use permitlayer_vault::Vault;
use url::Url;
use zeroize::Zeroizing;

const TEST_MASTER_KEY: [u8; 32] = [0x42; 32];

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
}

#[async_trait::async_trait]
impl AuditStore for MockAuditStore {
    async fn append(&self, event: AuditEvent) -> Result<(), StoreError> {
        self.events.lock().unwrap().push(event);
        Ok(())
    }
}

/// Start an in-process axum server with the MCP service on an ephemeral port.
/// Returns the base URL (e.g., "http://127.0.0.1:12345").
async fn start_mcp_server(upstream_url: &str) -> (String, tokio::task::JoinHandle<()>) {
    let mut cred_store = MockCredentialStore::new(TEST_MASTER_KEY);
    cred_store.add_service("gmail", b"test-oauth-access-token");

    let client = reqwest::Client::builder().build().unwrap();
    let mut base_urls = HashMap::new();
    base_urls.insert("gmail".to_owned(), Url::parse(upstream_url).unwrap());

    let proxy = Arc::new(ProxyService::new(
        Arc::new(cred_store) as Arc<dyn CredentialStore>,
        Arc::new(Vault::new(Zeroizing::new(TEST_MASTER_KEY))),
        Arc::new({
            let mut key = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
            ScopedTokenIssuer::new(Zeroizing::new(key))
        }),
        Arc::new(UpstreamClient::with_client_and_urls(client, base_urls)),
        Arc::new(MockAuditStore::new()) as Arc<dyn AuditStore>,
        Arc::new(ScrubEngine::new(builtin_rules().to_vec()).unwrap()),
        std::env::temp_dir(),
    ));

    let mcp = mcp_service(proxy);
    let app = Router::new().nest_service("/mcp", mcp);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://127.0.0.1:{}", addr.port());

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Give the server a moment to bind.
    tokio::time::sleep(Duration::from_millis(50)).await;

    (base_url, handle)
}

#[tokio::test]
async fn mcp_initialize_handshake_succeeds() {
    let mut upstream = mockito::Server::new_async().await;
    let _mock = upstream
        .mock("GET", "/users/me/messages")
        .with_status(200)
        .with_body(r#"{"messages":[]}"#)
        .create_async()
        .await;

    let (base_url, handle) = start_mcp_server(&format!("{}/", upstream.url())).await;

    // Send MCP initialize request via raw HTTP POST.
    let client = reqwest::Client::new();
    let init_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        }
    });

    let resp = client
        .post(format!("{base_url}/mcp"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .json(&init_request)
        .send()
        .await
        .unwrap();

    assert!(resp.status().is_success(), "initialize should succeed, got {}", resp.status());

    let body = resp.text().await.unwrap();

    // The response may be SSE or JSON depending on config.
    // Either way, it should contain "permitlayer" as the server name.
    assert!(
        body.contains("permitlayer"),
        "response should contain server name 'permitlayer', got: {body}"
    );

    handle.abort();
}

#[tokio::test]
async fn mcp_tools_list_returns_five_tools() {
    let mut upstream = mockito::Server::new_async().await;
    let _mock = upstream
        .mock("GET", "/users/me/messages")
        .with_status(200)
        .with_body(r#"{"messages":[]}"#)
        .create_async()
        .await;

    let (base_url, handle) = start_mcp_server(&format!("{}/", upstream.url())).await;
    let client = reqwest::Client::new();

    // Step 1: Initialize to get a session.
    let init_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        }
    });

    let init_resp = client
        .post(format!("{base_url}/mcp"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .json(&init_request)
        .send()
        .await
        .unwrap();

    assert!(init_resp.status().is_success());

    // Extract session ID from Mcp-Session-Id header.
    let session_id =
        init_resp.headers().get("mcp-session-id").map(|v| v.to_str().unwrap().to_owned());

    // Step 2: Send initialized notification.
    let initialized = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });

    let mut initialized_req = client
        .post(format!("{base_url}/mcp"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream");
    if let Some(ref sid) = session_id {
        initialized_req = initialized_req.header("Mcp-Session-Id", sid);
    }
    let _ = initialized_req.json(&initialized).send().await.unwrap();

    // Step 3: List tools.
    let list_tools = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    });

    let mut tools_req = client
        .post(format!("{base_url}/mcp"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream");
    if let Some(ref sid) = session_id {
        tools_req = tools_req.header("Mcp-Session-Id", sid);
    }
    let tools_resp = tools_req.json(&list_tools).send().await.unwrap();
    assert!(tools_resp.status().is_success());

    let body = tools_resp.text().await.unwrap();

    // Count gmail tool names in the response.
    let expected_tools = [
        "gmail.messages.list",
        "gmail.messages.get",
        "gmail.threads.list",
        "gmail.threads.get",
        "gmail.search",
    ];

    for tool_name in &expected_tools {
        assert!(
            body.contains(tool_name),
            "tools/list response should contain '{tool_name}', got: {body}"
        );
    }

    handle.abort();
}

#[tokio::test]
async fn mcp_tools_call_gmail_messages_list_returns_valid_response() {
    let mut upstream = mockito::Server::new_async().await;
    let _mock = upstream
        .mock("GET", "/users/me/messages")
        .with_status(200)
        .with_body(r#"{"messages":[{"id":"conformance-test"}]}"#)
        .create_async()
        .await;

    let (base_url, handle) = start_mcp_server(&format!("{}/", upstream.url())).await;
    let client = reqwest::Client::new();

    // Initialize session.
    let init_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        }
    });

    let init_resp = client
        .post(format!("{base_url}/mcp"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .json(&init_request)
        .send()
        .await
        .unwrap();

    let session_id =
        init_resp.headers().get("mcp-session-id").map(|v| v.to_str().unwrap().to_owned());

    // Send initialized notification.
    let initialized = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    let mut req = client
        .post(format!("{base_url}/mcp"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream");
    if let Some(ref sid) = session_id {
        req = req.header("Mcp-Session-Id", sid);
    }
    let _ = req.json(&initialized).send().await.unwrap();

    // Call gmail.messages.list tool.
    let tool_call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "gmail.messages.list",
            "arguments": {}
        }
    });

    let mut call_req = client
        .post(format!("{base_url}/mcp"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream");
    if let Some(ref sid) = session_id {
        call_req = call_req.header("Mcp-Session-Id", sid);
    }
    let call_resp = call_req.json(&tool_call).send().await.unwrap();
    assert!(call_resp.status().is_success());

    let body = call_resp.text().await.unwrap();

    // The response should contain the upstream data.
    assert!(
        body.contains("conformance-test"),
        "tools/call response should contain upstream data, got: {body}"
    );

    handle.abort();
}
