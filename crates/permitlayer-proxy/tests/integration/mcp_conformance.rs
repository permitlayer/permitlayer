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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use permitlayer_core::audit::event::AuditEvent;
use permitlayer_core::scrub::{ScrubEngine, builtin_rules};
use permitlayer_core::store::{AuditStore, CredentialStore, StoreError};
use permitlayer_credential::{ConnectionId, OAuthToken, SealedCredential, Slot};
use permitlayer_proxy::error::AgentId;
use permitlayer_proxy::service::ProxyService;
use permitlayer_proxy::token::ScopedTokenIssuer;
use permitlayer_proxy::transport::mcp::mcp_service;
use permitlayer_proxy::upstream::UpstreamClient;
use permitlayer_vault::Vault;
use zeroize::Zeroizing;

const TEST_MASTER_KEY: [u8; 32] = [0x42; 32];

struct MockCredentialStore {
    // Keyed on `(ConnectionId bytes, Slot byte)` per the Story 11.9 store
    // re-key; `add_service` seeds under the legacy connection-id derivation
    // (no binding stores wired) + Slot::Access.
    services: HashMap<([u8; 16], u8), Vec<u8>>,
    master_key: [u8; 32],
}

impl MockCredentialStore {
    fn new(master_key: [u8; 32]) -> Self {
        Self { services: HashMap::new(), master_key }
    }

    fn add_service(&mut self, service: &str, token_bytes: &[u8]) {
        let connection = crate::common::legacy_connection_id_for_service(service);
        self.services
            .insert((*connection.as_bytes(), Slot::Access.slot_byte()), token_bytes.to_vec());
    }
}

#[async_trait::async_trait]
impl CredentialStore for MockCredentialStore {
    async fn put(
        &self,
        _id: ConnectionId,
        _slot: Slot,
        _sealed: SealedCredential,
    ) -> Result<(), StoreError> {
        Ok(())
    }
    async fn get(
        &self,
        id: ConnectionId,
        slot: Slot,
    ) -> Result<Option<SealedCredential>, StoreError> {
        match self.services.get(&(*id.as_bytes(), slot.slot_byte())) {
            Some(token_bytes) => {
                let vault = Vault::new(Zeroizing::new(self.master_key), 0);
                let token = OAuthToken::from_trusted_bytes(token_bytes.clone());
                match vault.seal(id, slot, &token) {
                    Ok(sealed) => Ok(Some(sealed)),
                    Err(_) => panic!("mock seal failed for {id:?}/{slot:?}"),
                }
            }
            None => Ok(None),
        }
    }
    async fn list_connections(&self) -> Result<Vec<ConnectionId>, StoreError> {
        Ok(self
            .services
            .keys()
            .map(|(id_bytes, _slot)| ConnectionId::from_bytes(*id_bytes))
            .collect())
    }
    async fn remove(&self, _id: ConnectionId, _slot: Slot) -> Result<bool, StoreError> {
        Ok(false)
    }
}

struct MockAuditStore {
    events: Mutex<Vec<AuditEvent>>,
}

impl MockAuditStore {
    fn new() -> Self {
        Self { events: Mutex::new(Vec::new()) }
    }

    fn snapshot(&self) -> Vec<AuditEvent> {
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

/// Start an in-process axum server with the MCP service on an ephemeral port.
/// Returns the base URL, the JoinHandle for the server task, and a clone of
/// the audit store so tests can read back the events the proxy wrote.
///
/// `agent_name` is the synthetic AgentId injected by the test middleware.
/// Production gets this from AuthLayer; we stand in for it.
async fn start_mcp_server(upstream_url: &str) -> (String, tokio::task::JoinHandle<()>) {
    let (base_url, handle, _audit) = start_mcp_server_with_agent(upstream_url, "test-agent").await;
    (base_url, handle)
}

async fn start_mcp_server_with_agent(
    upstream_url: &str,
    agent_name: &'static str,
) -> (String, tokio::task::JoinHandle<()>, Arc<MockAuditStore>) {
    let mut cred_store = MockCredentialStore::new(TEST_MASTER_KEY);
    cred_store.add_service("gmail", b"test-oauth-access-token");

    let connectors = super::common::connector_registry_with(&[("gmail", upstream_url)]);

    let audit_store = Arc::new(MockAuditStore::new());

    let proxy = Arc::new(ProxyService::new(
        Arc::new(cred_store) as Arc<dyn CredentialStore>,
        Arc::new(Vault::new(Zeroizing::new(TEST_MASTER_KEY), 0)),
        Arc::new({
            let mut key = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
            ScopedTokenIssuer::new(Zeroizing::new(key))
        }),
        Arc::new(UpstreamClient::new().unwrap()),
        connectors,
        Arc::clone(&audit_store) as Arc<dyn AuditStore>,
        Arc::new(ScrubEngine::new(builtin_rules().to_vec()).unwrap()),
        std::env::temp_dir(),
        std::env::temp_dir().join("permitlayer-test-media"),
    ));

    let mcp = mcp_service(proxy);
    // Test-only: inject the AgentId extension that AuthLayer would
    // populate in production. The MCP service rejects requests
    // without AgentId (auth.missing_agent_id), so we stand in for
    // AuthLayer here. Layered BEFORE nest_service so the extension
    // lives on the inbound request that rmcp captures into Parts.
    let app = Router::new().nest_service("/mcp/gmail", mcp).layer(axum::middleware::from_fn(
        move |mut req: axum::extract::Request, next: axum::middleware::Next| async move {
            req.extensions_mut().insert(AgentId(agent_name.to_owned()));
            next.run(req).await
        },
    ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://127.0.0.1:{}", addr.port());

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Give the server a moment to bind.
    tokio::time::sleep(Duration::from_millis(50)).await;

    (base_url, handle, audit_store)
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
        .post(format!("{base_url}/mcp/gmail"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Authorization", "Bearer test")
        .header("x-agentsso-scope", "gmail.readonly")
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
async fn bare_mcp_returns_404() {
    let mut upstream = mockito::Server::new_async().await;
    let _mock = upstream
        .mock("GET", "/users/me/messages")
        .with_status(200)
        .with_body(r#"{"messages":[]}"#)
        .create_async()
        .await;

    let (base_url, handle) = start_mcp_server(&format!("{}/", upstream.url())).await;
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
        .header("Authorization", "Bearer test")
        .header("x-agentsso-scope", "gmail.readonly")
        .json(&init_request)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);

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
        .post(format!("{base_url}/mcp/gmail"))
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
        .post(format!("{base_url}/mcp/gmail"))
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
        .post(format!("{base_url}/mcp/gmail"))
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
        .post(format!("{base_url}/mcp/gmail"))
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
        .post(format!("{base_url}/mcp/gmail"))
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
        .post(format!("{base_url}/mcp/gmail"))
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

/// Pin the regression: when an authenticated MCP request reaches a tool
/// handler, the audit event for the upstream call MUST be attributed to
/// the bearer-bound agent name, not a sentinel.
///
/// Pre-fix, every MCP tool call wrote `agent_id="mcp-client-unattributed"`
/// because the agent identity was carried in a tokio task-local that
/// did not survive rmcp's session-worker `tokio::spawn`. The fix routes
/// identity via `RequestContext.extensions[Parts].extensions[AgentId]`,
/// which DOES survive the spawn. This test exercises the full
/// initialize → notifications/initialized → tools/call dance and reads
/// the audit event back to confirm the bug is gone.
#[tokio::test]
async fn mcp_tool_call_attributes_audit_event_to_real_agent() {
    let mut upstream = mockito::Server::new_async().await;
    let _mock = upstream
        .mock("GET", "/users/me/messages")
        .with_status(200)
        .with_body(r#"{"messages":[{"id":"audit-test"}]}"#)
        .create_async()
        .await;

    let (base_url, handle, audit_store) =
        start_mcp_server_with_agent(&format!("{}/", upstream.url()), "real-agent").await;
    let client = reqwest::Client::new();

    // 1. initialize
    let init_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "1.0.0" }
        }
    });
    let init_resp = client
        .post(format!("{base_url}/mcp/gmail"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .json(&init_request)
        .send()
        .await
        .unwrap();
    let session_id =
        init_resp.headers().get("mcp-session-id").map(|v| v.to_str().unwrap().to_owned());

    // 2. notifications/initialized
    let initialized = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    let mut req = client
        .post(format!("{base_url}/mcp/gmail"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream");
    if let Some(ref sid) = session_id {
        req = req.header("Mcp-Session-Id", sid);
    }
    let _ = req.json(&initialized).send().await.unwrap();

    // 3. tools/call → invokes gmail.messages.list, which dispatches an
    //    upstream call that the proxy will write an audit event for.
    let tool_call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": { "name": "gmail.messages.list", "arguments": {} }
    });
    let mut call_req = client
        .post(format!("{base_url}/mcp/gmail"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream");
    if let Some(ref sid) = session_id {
        call_req = call_req.header("Mcp-Session-Id", sid);
    }
    let call_resp = call_req.json(&tool_call).send().await.unwrap();
    assert!(call_resp.status().is_success());

    // Audit dispatch is fire-and-forget; give it a tick to drain.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 4. Assert the audit event is attributed to the real agent name.
    let events = audit_store.snapshot();
    assert!(
        !events.is_empty(),
        "expected at least one audit event for the upstream call; got none",
    );
    let api_call = events
        .iter()
        .find(|e| e.event_type == "api-call")
        .expect("expected an api-call audit event");
    assert_eq!(
        api_call.agent_id, "real-agent",
        "api-call audit event must be attributed to the bearer-bound agent, not a sentinel",
    );
    // Defense in depth — make sure the sentinel string is nowhere.
    for e in &events {
        assert_ne!(
            e.agent_id, "mcp-client-unattributed",
            "found sentinel agent_id in audit log — regression of the rmcp task-local bug",
        );
    }

    handle.abort();
}

// ───────────────────────────────────────────────────────────────────────
// Story 9.1: Gmail read-tool gap-fill conformance.
//
// Mirrors the initialize → notifications/initialized → tools/call dance
// above. These pin: (AC#2) tools/list now shows all 11 Gmail tools;
// (AC#4) attachments.get returns the upstream JSON body byte-unmodified
// under the 10 MiB cap; (AC#3) history.list rejects a missing
// startHistoryId at the tool boundary; (AC#7) a new-tool MCP call emits
// an audit event attributed to the bearer-bound agent.
// ───────────────────────────────────────────────────────────────────────

/// Drive an initialized MCP session and return `(client, base_url,
/// session_id)` so each test can issue `tools/*` calls without repeating
/// the handshake boilerplate.
async fn init_session(base_url: &str) -> (reqwest::Client, Option<String>) {
    let client = reqwest::Client::new();
    let init_request = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "1.0.0" }
        }
    });
    let init_resp = client
        .post(format!("{base_url}/mcp/gmail"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .json(&init_request)
        .send()
        .await
        .unwrap();
    let session_id =
        init_resp.headers().get("mcp-session-id").map(|v| v.to_str().unwrap().to_owned());
    let initialized = serde_json::json!({
        "jsonrpc": "2.0", "method": "notifications/initialized"
    });
    let mut req = client
        .post(format!("{base_url}/mcp/gmail"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream");
    if let Some(ref sid) = session_id {
        req = req.header("Mcp-Session-Id", sid);
    }
    let _ = req.json(&initialized).send().await.unwrap();
    (client, session_id)
}

async fn call_tool(
    client: &reqwest::Client,
    base_url: &str,
    session_id: &Option<String>,
    name: &str,
    arguments: serde_json::Value,
) -> String {
    let tool_call = serde_json::json!({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": { "name": name, "arguments": arguments }
    });
    let mut call_req = client
        .post(format!("{base_url}/mcp/gmail"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream");
    if let Some(sid) = session_id {
        call_req = call_req.header("Mcp-Session-Id", sid);
    }
    let resp = call_req.json(&tool_call).send().await.unwrap();
    assert!(resp.status().is_success(), "tools/call HTTP status: {}", resp.status());
    resp.text().await.unwrap()
}

/// Extract a string field's value from an SSE-framed MCP tool result
/// where the descriptor JSON is escaped inside the `text` content (so
/// `"path":"..."` appears as `\"path\":\"...\"`). Returns the unescaped
/// value. Test-only convenience — not a general JSON parser.
fn extract_json_string_field(body: &str, field: &str) -> Option<String> {
    // Try escaped form first (inside MCP text content), then plain.
    for needle in [format!("\\\"{field}\\\":\\\""), format!("\"{field}\":\"")] {
        if let Some(start) = body.find(&needle) {
            let rest = &body[start + needle.len()..];
            // Terminator is the matching closing quote (escaped or plain).
            let end = rest.find("\\\"").or_else(|| rest.find('"'))?;
            return Some(rest[..end].to_owned());
        }
    }
    None
}

#[tokio::test]
async fn mcp_tools_list_returns_twenty_six_gmail_tools() {
    let mut upstream = mockito::Server::new_async().await;
    let _mock = upstream
        .mock("GET", "/users/me/messages")
        .with_status(200)
        .with_body(r#"{"messages":[]}"#)
        .create_async()
        .await;
    let (base_url, handle) = start_mcp_server(&format!("{}/", upstream.url())).await;
    let (client, session_id) = init_session(&base_url).await;

    let list_tools = serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/list"
    });
    let mut tools_req = client
        .post(format!("{base_url}/mcp/gmail"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream");
    if let Some(ref sid) = session_id {
        tools_req = tools_req.header("Mcp-Session-Id", sid);
    }
    let body = tools_req.json(&list_tools).send().await.unwrap().text().await.unwrap();

    // Original 5 + Story 9.1's 6 reads + Story 9.2's 7 writes + 8
    // settings reads = 26, each present with its dotted name.
    let expected = [
        // original 5
        "gmail.messages.list",
        "gmail.messages.get",
        "gmail.threads.list",
        "gmail.threads.get",
        "gmail.search",
        // Story 9.1 reads
        "gmail.attachments.get",
        "gmail.labels.list",
        "gmail.profile.get",
        "gmail.history.list",
        "gmail.drafts.list",
        "gmail.drafts.get",
        // Story 9.2 writes
        "gmail.messages.send",
        "gmail.messages.modify",
        "gmail.messages.trash",
        "gmail.messages.untrash",
        "gmail.drafts.create",
        "gmail.drafts.update",
        "gmail.drafts.send",
        // Story 9.2 settings reads
        "gmail.settings.sendAs.list",
        "gmail.settings.filters.list",
        "gmail.settings.language.get",
        "gmail.settings.imap.get",
        "gmail.settings.pop.get",
        "gmail.settings.vacation.get",
        "gmail.settings.forwarding.list",
        "gmail.settings.autoForwarding.get",
    ];
    assert_eq!(expected.len(), 26, "the expected-names list itself must be 26");
    for name in &expected {
        assert!(body.contains(name), "tools/list must contain '{name}', got: {body}");
    }
    // gmail.messages.delete is intentionally absent (needs the full
    // mail.google.com scope — deferred out of Story 9.2).
    assert!(
        !body.contains("gmail.messages.delete"),
        "gmail.messages.delete must NOT be present in 9.2 (deferred — needs mail.google.com)"
    );
    // Exact count: the tool objects each carry an "inputSchema" key, so
    // counting those is a robust proxy for the tool count regardless of
    // SSE framing.
    let tool_count = body.matches("inputSchema").count();
    assert_eq!(
        tool_count, 26,
        "expected exactly 26 Gmail tools in tools/list, found {tool_count}; body: {body}"
    );
    handle.abort();
}

#[tokio::test]
async fn mcp_attachments_get_writes_file_and_returns_path() {
    let mut upstream = mockito::Server::new_async().await;
    // attachments.get returns { size, data } (base64url). The proxy
    // decodes it, writes the bytes to a local file, and returns a path
    // descriptor — NOT the base64.
    // "hello-world-receipt-pdf" → base64url below.
    let decoded = b"hello-world-receipt-pdf";
    let upstream_body = r#"{"size":23,"data":"aGVsbG8td29ybGQtcmVjZWlwdC1wZGY"}"#;
    let _att_mock = upstream
        .mock("GET", "/users/me/messages/MSG1/attachments/ATT1")
        .with_status(200)
        .with_body(upstream_body)
        .create_async()
        .await;
    // The metadata lookup that resolves mimeType + filename. The proxy
    // requests `messages.get?format=full`; match the path with a query.
    let _meta_mock = upstream
        .mock("GET", "/users/me/messages/MSG1")
        .match_query(mockito::Matcher::Any)
        .with_status(200)
        .with_body(
            r#"{"id":"MSG1","payload":{"parts":[
                {"mimeType":"application/pdf","filename":"receipt.pdf",
                 "body":{"attachmentId":"ATT1","size":23}}]}}"#,
        )
        .create_async()
        .await;
    let (base_url, handle) = start_mcp_server(&format!("{}/", upstream.url())).await;
    let (client, session_id) = init_session(&base_url).await;

    let body = call_tool(
        &client,
        &base_url,
        &session_id,
        "gmail.attachments.get",
        serde_json::json!({ "message_id": "MSG1", "attachment_id": "ATT1" }),
    )
    .await;

    // The tool result must NOT contain the base64 (no bytes in context).
    assert!(
        !body.contains("aGVsbG8td29ybGQtcmVjZWlwdC1wZGY"),
        "attachment base64 must NOT appear in the tool result, got: {body}"
    );
    // It returns a descriptor with the resolved mime/filename + a path.
    assert!(body.contains("application/pdf"), "mimeType resolved from metadata: {body}");
    assert!(body.contains("receipt.pdf"), "filename resolved from metadata: {body}");

    // Extract the `path` from the tool result (SSE-framed JSON-in-text;
    // the descriptor is escaped inside the MCP text content). Pull the
    // value of the `path` field directly and verify the file exists with
    // the decoded bytes.
    let path = extract_json_string_field(&body, "path")
        .unwrap_or_else(|| panic!("descriptor has a path field; got: {body}"));
    let written = std::fs::read(&path).expect("attachment file exists at returned path");
    assert_eq!(written, decoded, "written file holds the decoded attachment bytes");
    let _ = std::fs::remove_file(&path);

    handle.abort();
}

#[tokio::test]
async fn mcp_history_list_rejects_missing_start_history_id() {
    let mut upstream = mockito::Server::new_async().await;
    // No upstream mock for /users/me/history: the tool must fail fast
    // BEFORE dispatching, so the upstream is never hit.
    let _guard =
        upstream.mock("GET", "/users/me/history").with_status(500).expect(0).create_async().await;
    let (base_url, handle) = start_mcp_server(&format!("{}/", upstream.url())).await;
    let (client, session_id) = init_session(&base_url).await;

    let body = call_tool(
        &client,
        &base_url,
        &session_id,
        "gmail.history.list",
        serde_json::json!({ "start_history_id": "" }),
    )
    .await;

    // rmcp maps a tool Err(String) into an MCP error result (isError),
    // not a transport failure — assert the message surfaces.
    assert!(
        body.contains("start_history_id is required"),
        "missing startHistoryId must produce a clear tool error, got: {body}"
    );
    handle.abort();
}

#[tokio::test]
async fn mcp_new_read_tool_emits_audit_event_for_real_agent() {
    let mut upstream = mockito::Server::new_async().await;
    let _mock = upstream
        .mock("GET", "/users/me/labels")
        .with_status(200)
        .with_body(r#"{"labels":[{"id":"INBOX","name":"INBOX"}]}"#)
        .create_async()
        .await;
    let (base_url, handle, audit_store) =
        start_mcp_server_with_agent(&format!("{}/", upstream.url()), "receipt-agent").await;
    let (client, session_id) = init_session(&base_url).await;

    let _ = call_tool(&client, &base_url, &session_id, "gmail.labels.list", serde_json::json!({}))
        .await;

    tokio::time::sleep(Duration::from_millis(100)).await;
    let events = audit_store.snapshot();
    let api_call = events
        .iter()
        .find(|e| e.event_type == "api-call")
        .expect("a new-tool MCP call must emit an api-call audit event");
    assert_eq!(
        api_call.agent_id, "receipt-agent",
        "new-tool audit event must be attributed to the bearer-bound agent",
    );
    handle.abort();
}

/// Story 9.2: a write tool (`gmail.messages.send`) issues a POST to the
/// correct upstream path carrying the JSON body, and emits an audit
/// event scoped to the tool's Google-minimum scope (`gmail.send`, NOT
/// `gmail.modify`).
#[tokio::test]
async fn mcp_messages_send_posts_body_and_audits_send_scope() {
    let mut upstream = mockito::Server::new_async().await;
    let mock = upstream
        .mock("POST", "/users/me/messages/send")
        .match_body(mockito::Matcher::PartialJsonString(r#"{"raw":"UkZDODIy"}"#.to_owned()))
        .with_status(200)
        .with_body(r#"{"id":"sent-msg-1","labelIds":["SENT"]}"#)
        .create_async()
        .await;
    let (base_url, handle, audit_store) =
        start_mcp_server_with_agent(&format!("{}/", upstream.url()), "sender-agent").await;
    let (client, session_id) = init_session(&base_url).await;

    let body = call_tool(
        &client,
        &base_url,
        &session_id,
        "gmail.messages.send",
        serde_json::json!({ "message": { "raw": "UkZDODIy" } }),
    )
    .await;

    // Upstream POST was hit with the JSON body, and the result flows back.
    mock.assert_async().await;
    assert!(
        body.contains("sent-msg-1"),
        "send result must surface the upstream response, got: {body}"
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    let events = audit_store.snapshot();
    let api_call = events
        .iter()
        .find(|e| e.event_type == "api-call")
        .expect("a write MCP call must emit an api-call audit event");
    assert_eq!(api_call.agent_id, "sender-agent");
    assert_eq!(
        api_call.scope, "gmail.send",
        "messages.send must audit under its Google-minimum scope gmail.send, not gmail.modify",
    );
    handle.abort();
}
