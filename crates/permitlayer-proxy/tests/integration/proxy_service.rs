//! Integration tests for the ProxyService.
//!
//! These tests verify the full request flow through ProxyService::handle
//! with mock dependencies (CredentialStore, AuditStore, upstream via mockito).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::http::{HeaderMap, Method, StatusCode};
use permitlayer_core::audit::event::AuditEvent;
use permitlayer_core::scrub::{ScrubEngine, ScrubSample, builtin_rules};
use permitlayer_core::store::{AuditStore, CredentialStore, StoreError};
use permitlayer_credential::{OAuthToken, SealedCredential};
use permitlayer_proxy::error::ProxyError;
use permitlayer_proxy::request::ProxyRequest;
use permitlayer_proxy::service::ProxyService;
use permitlayer_proxy::token::ScopedTokenIssuer;
use permitlayer_proxy::upstream::UpstreamClient;
use permitlayer_vault::Vault;
use url::Url;
use zeroize::Zeroizing;

// --- Test Helpers ---

const TEST_MASTER_KEY: [u8; 32] = [0x42; 32];

fn test_scrub_engine() -> Arc<ScrubEngine> {
    Arc::new(ScrubEngine::new(builtin_rules().to_vec()).unwrap())
}

fn test_vault() -> Vault {
    Vault::new(Zeroizing::new(TEST_MASTER_KEY), 0)
}

fn test_token_issuer() -> ScopedTokenIssuer {
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
    ScopedTokenIssuer::new(Zeroizing::new(key))
}

// --- Mock CredentialStore ---

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
                let vault = Vault::new(Zeroizing::new(self.master_key), 0);
                let token = OAuthToken::from_trusted_bytes(token_bytes.clone());
                match vault.seal(service, &token) {
                    Ok(sealed) => Ok(Some(sealed)),
                    Err(_) => panic!("mock seal failed for {service}"),
                }
            }
            None => Ok(None),
        }
    }
    async fn list_services(&self) -> Result<Vec<String>, StoreError> {
        Ok(self.services.keys().cloned().collect())
    }
}

// --- Mock AuditStore ---

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

// --- Service Builder ---

async fn build_service(server_url: &str) -> (Arc<ProxyService>, Arc<MockAuditStore>) {
    build_service_multi(&[("gmail", server_url, b"test-oauth-access-token" as &[u8])]).await
}

async fn build_service_multi(
    services: &[(&str, &str, &[u8])],
) -> (Arc<ProxyService>, Arc<MockAuditStore>) {
    let mut cred_store = MockCredentialStore::new(TEST_MASTER_KEY);
    let client = reqwest::Client::builder().build().unwrap();
    let mut base_urls = HashMap::new();

    for &(name, url, token) in services {
        cred_store.add_service(name, token);
        base_urls.insert(name.to_owned(), Url::parse(url).unwrap());
    }

    let credential_store: Arc<dyn CredentialStore> = Arc::new(cred_store);
    let vault = Arc::new(test_vault());
    let token_issuer = Arc::new(test_token_issuer());
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

fn make_request(service: &str, path: &str) -> ProxyRequest {
    ProxyRequest {
        service: service.to_owned(),
        scope: "mail.readonly".to_owned(),
        resource: path.to_owned(),
        method: Method::GET,
        path: path.to_owned(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
        agent_id: "agent-integration-test".to_owned(),
        request_id: ulid::Ulid::new().to_string(),
    }
}

// --- Integration Tests ---

#[tokio::test]
async fn full_happy_path() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/users/me/messages")
        .match_header("authorization", "Bearer test-oauth-access-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"messages":[{"id":"msg-1"}]}"#)
        .create_async()
        .await;

    let (service, audit_store) = build_service(&format!("{}/", server.url())).await;

    let req = make_request("gmail", "users/me/messages");
    let resp = service.handle(req).await.unwrap();

    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(resp.body, r#"{"messages":[{"id":"msg-1"}]}"#.as_bytes());

    let events = audit_store.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].agent_id, "agent-integration-test");
    assert_eq!(events[0].service, "gmail");
    assert_eq!(events[0].scope, "mail.readonly");
    assert_eq!(events[0].outcome, "ok");
    assert_eq!(events[0].event_type, "api-call");

    mock.assert_async().await;
}

#[tokio::test]
async fn missing_credentials_returns_503() {
    let server = mockito::Server::new_async().await;

    // Build service with no gmail credentials.
    let cred_store = MockCredentialStore::new(TEST_MASTER_KEY);
    let credential_store: Arc<dyn CredentialStore> = Arc::new(cred_store);
    let vault = Arc::new(test_vault());
    let token_issuer = Arc::new(test_token_issuer());
    let client = reqwest::Client::builder().build().unwrap();
    let mut base_urls = HashMap::new();
    base_urls.insert("gmail".to_owned(), Url::parse(&format!("{}/", server.url())).unwrap());
    let upstream_client = Arc::new(UpstreamClient::with_client_and_urls(client, base_urls));
    let audit_store = Arc::new(MockAuditStore::new());

    let service = ProxyService::new(
        credential_store,
        vault,
        token_issuer,
        upstream_client,
        audit_store,
        test_scrub_engine(),
        std::env::temp_dir(),
    );

    let req = make_request("gmail", "users/me/messages");
    let err = service.handle(req).await.unwrap_err();

    assert_eq!(err.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(err.to_string().contains("no credentials"));
}

#[tokio::test]
async fn upstream_unreachable_returns_503_with_audit() {
    let mut cred_store = MockCredentialStore::new(TEST_MASTER_KEY);
    cred_store.add_service("gmail", b"test-oauth-access-token");

    let credential_store: Arc<dyn CredentialStore> = Arc::new(cred_store);
    let vault = Arc::new(test_vault());
    let token_issuer = Arc::new(test_token_issuer());

    // Point to a port that's not listening.
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_millis(100))
        .timeout(std::time::Duration::from_millis(200))
        .build()
        .unwrap();
    let mut base_urls = HashMap::new();
    base_urls.insert("gmail".to_owned(), Url::parse("http://127.0.0.1:1/").unwrap());
    let upstream_client = Arc::new(UpstreamClient::with_client_and_urls(client, base_urls));
    let audit_store = Arc::new(MockAuditStore::new());

    let service = ProxyService::new(
        credential_store,
        vault,
        token_issuer,
        upstream_client,
        Arc::clone(&audit_store) as Arc<dyn AuditStore>,
        test_scrub_engine(),
        std::env::temp_dir(),
    );

    let req = make_request("gmail", "users/me/messages");
    let err = service.handle(req).await.unwrap_err();

    assert_eq!(err.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(err.error_code(), "upstream.unreachable");

    let events = audit_store.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "error");
    assert_eq!(events[0].event_type, "upstream-unreachable");
}

#[tokio::test]
async fn upstream_429_preserves_retry_after() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/users/me/messages")
        .with_status(429)
        .with_header("retry-after", "120")
        .create_async()
        .await;

    let (service, audit_store) = build_service(&format!("{}/", server.url())).await;

    let req = make_request("gmail", "users/me/messages");
    let err = service.handle(req).await.unwrap_err();

    assert_eq!(err.status_code(), StatusCode::TOO_MANY_REQUESTS);
    match &err {
        ProxyError::UpstreamRateLimited { retry_after, .. } => {
            assert_eq!(retry_after.as_deref(), Some("120"));
        }
        other => panic!("expected UpstreamRateLimited, got {other:?}"),
    }

    // Check the axum response has Retry-After header.
    let response = err.into_response_with_request_id(Some("01TEST".to_owned()));
    assert_eq!(response.headers().get("retry-after").unwrap().to_str().unwrap(), "120");

    let events = audit_store.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "error");
    assert_eq!(events[0].event_type, "rate-limited");

    mock.assert_async().await;
}

#[tokio::test]
async fn scoped_token_has_correct_claims_and_ttl() {
    let issuer = test_token_issuer();
    let token = issuer.issue("agent-1", "mail.readonly", "users/me/messages", 60);

    assert_eq!(token.agent_id, "agent-1");
    assert_eq!(token.scope, "mail.readonly");
    assert_eq!(token.resource, "users/me/messages");
    assert!(token.expires_at > token.issued_at);
    assert_eq!(token.expires_at - token.issued_at, 60);
    assert_eq!(token.token.len(), 64); // HMAC-SHA256 = 32 bytes = 64 hex chars

    // Validate succeeds.
    let result = issuer.validate(
        &token.token,
        &token.agent_id,
        &token.scope,
        &token.resource,
        token.issued_at,
        token.expires_at,
    );
    assert!(result.is_ok());
}

#[tokio::test]
async fn scoped_token_rejects_expired() {
    let issuer = test_token_issuer();
    // Manually create an already-expired token.
    let token = issuer.issue("agent-1", "mail.readonly", "users/me/messages", 0);

    // Wait just a moment for the token to expire (it was issued with TTL=0,
    // so expires_at == issued_at == now, and now >= expires_at).
    // The token is technically already expired or about to be.
    let result = issuer.validate(
        &token.token,
        &token.agent_id,
        &token.scope,
        &token.resource,
        token.issued_at,
        token.issued_at, // expires_at = issued_at → already expired
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn raw_oauth_token_not_in_response_body_or_headers() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/users/me/messages")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"messages":[]}"#)
        .create_async()
        .await;

    let (service, _) = build_service(&format!("{}/", server.url())).await;

    let req = make_request("gmail", "users/me/messages");
    let resp = service.handle(req).await.unwrap();

    // Verify the raw OAuth token doesn't appear in the response body.
    let body_str = String::from_utf8_lossy(&resp.body);
    assert!(
        !body_str.contains("test-oauth-access-token"),
        "raw OAuth token MUST NOT appear in response body"
    );

    // Verify the raw OAuth token doesn't appear in response headers.
    for (_name, value) in &resp.headers {
        let val_str = value.to_str().unwrap_or("");
        assert!(
            !val_str.contains("test-oauth-access-token"),
            "raw OAuth token MUST NOT appear in response headers"
        );
    }

    mock.assert_async().await;
}

// --- Scrub-before-log end-to-end test (Story 2.4) ---

#[tokio::test]
async fn scrub_before_log_otp_never_in_audit_file() {
    use permitlayer_core::store::fs::AuditFsStore;
    use tempfile::TempDir;

    let raw_otp = "847291";
    let response_body =
        format!("Your verification code is {raw_otp}. Please enter it within 5 minutes.");

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/users/me/messages")
        .with_status(200)
        .with_body(&response_body)
        .create_async()
        .await;

    // Build service with REAL AuditFsStore (writes to temp dir).
    let mut cred_store = MockCredentialStore::new(TEST_MASTER_KEY);
    cred_store.add_service("gmail", b"test-oauth-access-token");

    let credential_store: Arc<dyn CredentialStore> = Arc::new(cred_store);
    let vault = Arc::new(test_vault());
    let token_issuer = Arc::new(test_token_issuer());

    let client = reqwest::Client::builder().build().unwrap();
    let mut base_urls = HashMap::new();
    base_urls.insert("gmail".to_owned(), Url::parse(&format!("{}/", server.url())).unwrap());
    let upstream_client = Arc::new(UpstreamClient::with_client_and_urls(client, base_urls));

    let tmp = TempDir::new().unwrap();
    let audit_dir = tmp.path().join("audit");
    let scrub_engine = test_scrub_engine();
    let audit_store = Arc::new(
        AuditFsStore::new(audit_dir.clone(), 100 * 1024 * 1024, Arc::clone(&scrub_engine)).unwrap(),
    );

    let service = Arc::new(ProxyService::new(
        credential_store,
        vault,
        token_issuer,
        upstream_client,
        audit_store as Arc<dyn AuditStore>,
        scrub_engine,
        tmp.path().to_path_buf(),
    ));

    let req = make_request("gmail", "users/me/messages");
    let resp = service.handle(req).await.unwrap();

    // Verify the response body was scrubbed.
    let body_str = String::from_utf8_lossy(&resp.body);
    assert!(body_str.contains("<REDACTED_OTP>"), "response should contain redacted OTP");
    assert!(!body_str.contains(raw_otp), "response must NOT contain raw OTP");

    // Read the audit JSONL file and verify the raw OTP is nowhere.
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let audit_file = audit_dir.join(format!("{today}.jsonl"));
    assert!(audit_file.exists(), "audit file should exist");

    let audit_content = std::fs::read_to_string(&audit_file).unwrap();
    let lines: Vec<&str> = audit_content.lines().collect();
    assert_eq!(lines.len(), 1, "should have exactly one audit entry");

    // The raw OTP string must NOT appear anywhere in the audit file.
    assert!(
        !audit_content.contains(raw_otp),
        "raw OTP '{}' MUST NOT appear in audit file. Content: {}",
        raw_otp,
        audit_content
    );

    // Verify scrub_events is populated in the extra field (v2 nested shape).
    let event: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(event["schema_version"], 2, "audit schema v2 after Story 2.6");
    let scrub_events = &event["extra"]["scrub_events"];
    assert!(scrub_events["summary"].is_object(), "summary should be an object: {event}");
    assert!(scrub_events["samples"].is_array(), "samples should be an array: {event}");
    let samples = scrub_events["samples"].as_array().unwrap();
    assert!(!samples.is_empty(), "samples should be non-empty for scrubbed OTP response");
    assert_eq!(samples[0]["rule"], "otp-6digit");
    let snippet = samples[0]["snippet"].as_str().unwrap();
    assert!(snippet.contains("<REDACTED_OTP>"), "snippet should contain placeholder: {snippet}");
    assert!(!snippet.contains(raw_otp), "snippet must not contain raw OTP: {snippet}");

    // Story 2.6 end-to-end: deserialize the sample back into a ScrubSample
    // via the shipped serde path (proving the proxy → audit → disk →
    // `serde_json::from_value::<ScrubSample>` chain is intact for CLI
    // consumers like `agentsso audit --follow`).
    let sample: ScrubSample = serde_json::from_value(samples[0].clone())
        .expect("samples[0] should deserialize into ScrubSample");
    assert_eq!(sample.rule, "otp-6digit");
    assert!(sample.placeholder_len > 0, "placeholder_len must be > 0");
    let slice_end = sample.placeholder_offset + sample.placeholder_len;
    assert!(
        slice_end <= sample.snippet.len(),
        "placeholder_offset + placeholder_len ({slice_end}) > snippet.len() ({})",
        sample.snippet.len()
    );
    // Byte-slice the snippet at the reported offset/len and verify it
    // equals the placeholder token — this is the exact invariant the
    // ScrubInline renderer relies on.
    assert_eq!(
        &sample.snippet[sample.placeholder_offset..slice_end],
        "<REDACTED_OTP>",
        "placeholder_offset/len must slice exactly to <REDACTED_OTP>"
    );

    mock.assert_async().await;
}

// --- Calendar + Drive connector integration tests (Story 2.5) ---

fn make_request_with_scope(service: &str, path: &str, scope: &str) -> ProxyRequest {
    ProxyRequest {
        service: service.to_owned(),
        scope: scope.to_owned(),
        resource: path.to_owned(),
        method: Method::GET,
        path: path.to_owned(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
        agent_id: "agent-integration-test".to_owned(),
        request_id: ulid::Ulid::new().to_string(),
    }
}

fn make_write_request(
    service: &str,
    path: &str,
    scope: &str,
    method: Method,
    body: &[u8],
) -> ProxyRequest {
    let mut headers = HeaderMap::new();
    headers.insert(axum::http::header::CONTENT_TYPE, "application/json".parse().unwrap());
    ProxyRequest {
        service: service.to_owned(),
        scope: scope.to_owned(),
        resource: path.to_owned(),
        method,
        path: path.to_owned(),
        headers,
        body: Bytes::copy_from_slice(body),
        agent_id: "agent-integration-test".to_owned(),
        request_id: ulid::Ulid::new().to_string(),
    }
}

#[tokio::test]
async fn calendar_scrub_fires_on_response() {
    let raw_otp = "529134";
    let response_body = format!(
        r#"{{"summary":"Meeting","description":"Your verification code is {raw_otp}. Use it now."}}"#
    );

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/calendars/primary/events")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&response_body)
        .create_async()
        .await;

    let url = format!("{}/", server.url());
    let (service, audit_store) = build_service_multi(&[("calendar", &url, b"cal-token")]).await;

    let req = make_request_with_scope("calendar", "calendars/primary/events", "calendar.readonly");
    let resp = service.handle(req).await.unwrap();

    let body_str = String::from_utf8_lossy(&resp.body);
    assert!(
        body_str.contains("<REDACTED_OTP>"),
        "calendar response should be scrubbed: {body_str}"
    );
    assert!(!body_str.contains(raw_otp), "raw OTP must NOT appear in calendar response");

    let events = audit_store.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].service, "calendar");
    assert_eq!(events[0].scope, "calendar.readonly");
    assert_eq!(events[0].outcome, "ok");

    mock.assert_async().await;
}

#[tokio::test]
async fn drive_scrub_fires_on_response() {
    let raw_otp = "837261";
    let response_body =
        format!(r#"{{"name":"doc.txt","content":"Your verification code is {raw_otp}"}}"#);

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/files/abc123")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&response_body)
        .create_async()
        .await;

    let url = format!("{}/", server.url());
    let (service, audit_store) = build_service_multi(&[("drive", &url, b"drive-token")]).await;

    let req = make_request_with_scope("drive", "files/abc123", "drive.readonly");
    let resp = service.handle(req).await.unwrap();

    let body_str = String::from_utf8_lossy(&resp.body);
    assert!(body_str.contains("<REDACTED_OTP>"), "drive response should be scrubbed: {body_str}");
    assert!(!body_str.contains(raw_otp), "raw OTP must NOT appear in drive response");

    let events = audit_store.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].service, "drive");
    assert_eq!(events[0].scope, "drive.readonly");
    assert_eq!(events[0].outcome, "ok");

    mock.assert_async().await;
}

#[tokio::test]
async fn calendar_audit_records_correct_service_and_scrub_events() {
    let raw_otp = "192837";
    let response_body = format!(r#"{{"summary":"Call","notes":"verification code is {raw_otp}"}}"#);

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/users/me/calendarList")
        .with_status(200)
        .with_body(&response_body)
        .create_async()
        .await;

    let url = format!("{}/", server.url());
    let (service, audit_store) = build_service_multi(&[("calendar", &url, b"cal-token")]).await;

    let req = make_request_with_scope("calendar", "users/me/calendarList", "calendar.readonly");
    let resp = service.handle(req).await.unwrap();

    let body_str = String::from_utf8_lossy(&resp.body);
    assert!(body_str.contains("<REDACTED_OTP>"));

    let events = audit_store.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].service, "calendar");
    assert_eq!(events[0].event_type, "api-call");

    // Verify scrub_events in audit extra (v2 nested {summary, samples} shape).
    let extra = &events[0].extra;
    assert_eq!(events[0].schema_version, 2, "audit schema v2 after Story 2.6");
    let scrub_events = &extra["scrub_events"];
    assert!(scrub_events["summary"].is_object(), "summary missing: {extra}");
    assert!(scrub_events["samples"].is_array(), "samples missing: {extra}");
    let samples = scrub_events["samples"].as_array().unwrap();
    assert!(!samples.is_empty(), "calendar samples should be non-empty");
    assert_eq!(samples[0]["rule"], "otp-6digit");
    assert!(samples[0]["snippet"].as_str().unwrap().contains("<REDACTED_OTP>"));

    mock.assert_async().await;
}

#[tokio::test]
async fn drive_audit_records_correct_service_and_scope() {
    // Embed a verification code so scrub_events should be populated.
    let raw_otp = "456789";
    let response_body =
        format!(r#"{{"files":[{{"name":"doc","description":"verification code is {raw_otp}"}}]}}"#);

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/files")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&response_body)
        .create_async()
        .await;

    let url = format!("{}/", server.url());
    let (service, audit_store) = build_service_multi(&[("drive", &url, b"drive-token")]).await;

    let req = make_request_with_scope("drive", "files", "drive.readonly");
    let resp = service.handle(req).await.unwrap();

    assert_eq!(resp.status, StatusCode::OK);
    let body_str = String::from_utf8_lossy(&resp.body);
    assert!(body_str.contains("<REDACTED_OTP>"), "drive response should be scrubbed");

    let events = audit_store.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].service, "drive");
    assert_eq!(events[0].scope, "drive.readonly");
    assert_eq!(events[0].outcome, "ok");
    assert_eq!(events[0].event_type, "api-call");

    // Verify scrub_events in audit extra (v2 nested {summary, samples} shape).
    let extra = &events[0].extra;
    assert_eq!(events[0].schema_version, 2, "audit schema v2 after Story 2.6");
    let scrub_events = &extra["scrub_events"];
    assert!(scrub_events["summary"].is_object(), "summary missing: {extra}");
    assert!(scrub_events["samples"].is_array(), "samples missing: {extra}");
    let samples = scrub_events["samples"].as_array().unwrap();
    assert!(!samples.is_empty(), "drive samples should be non-empty");
    assert_eq!(samples[0]["rule"], "otp-6digit");
    let snippet = samples[0]["snippet"].as_str().unwrap();
    assert!(snippet.contains("<REDACTED_OTP>"));
    assert!(!snippet.contains(raw_otp), "raw OTP leaked into sample: {snippet}");

    mock.assert_async().await;
}

#[tokio::test]
async fn drive_create_file_writes_with_drive_file_scope() {
    let request_body = br#"{"name":"new-folder","mimeType":"application/vnd.google-apps.folder"}"#;
    // Response from Google after create — embed PII to confirm scrubbing fires
    // on write responses too.
    let raw_otp = "918273";
    let response_body = format!(
        r#"{{"id":"file-abc","name":"new-folder","description":"verification code is {raw_otp}"}}"#
    );

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/files")
        .match_header("content-type", "application/json")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&response_body)
        .create_async()
        .await;

    let url = format!("{}/", server.url());
    let (service, audit_store) = build_service_multi(&[("drive", &url, b"drive-token")]).await;

    let req = make_write_request("drive", "files", "drive.file", Method::POST, request_body);
    let resp = service.handle(req).await.unwrap();

    assert_eq!(resp.status, StatusCode::OK);

    // Scrubbing must fire on write responses too.
    let body_str = String::from_utf8_lossy(&resp.body);
    assert!(
        body_str.contains("<REDACTED_OTP>"),
        "drive create response should be scrubbed: {body_str}"
    );
    assert!(!body_str.contains(raw_otp), "raw OTP must NOT appear in create response");

    let events = audit_store.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].service, "drive");
    assert_eq!(events[0].scope, "drive.file");
    assert_eq!(events[0].outcome, "ok");
    assert_eq!(events[0].event_type, "api-call");

    let extra = &events[0].extra;
    let scrub_events = &extra["scrub_events"];
    assert!(scrub_events["summary"].is_object(), "summary missing: {extra}");
    let samples = scrub_events["samples"].as_array().expect("samples array");
    assert!(!samples.is_empty());
    let snippet = samples[0]["snippet"].as_str().unwrap();
    assert!(snippet.contains("<REDACTED_OTP>"));
    assert!(!snippet.contains(raw_otp));

    mock.assert_async().await;
}

#[tokio::test]
async fn drive_update_file_writes_with_drive_file_scope() {
    let request_body = br#"{"name":"renamed-file"}"#;
    // Embed PII so we can verify scrubbing fires on PATCH responses too.
    let raw_otp = "362514";
    let response_body = format!(
        r#"{{"id":"file-abc","name":"renamed-file","description":"verification code is {raw_otp}"}}"#
    );

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("PATCH", "/files/file-abc")
        .match_header("content-type", "application/json")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&response_body)
        .create_async()
        .await;

    let url = format!("{}/", server.url());
    let (service, audit_store) = build_service_multi(&[("drive", &url, b"drive-token")]).await;

    let req =
        make_write_request("drive", "files/file-abc", "drive.file", Method::PATCH, request_body);
    let resp = service.handle(req).await.unwrap();

    assert_eq!(resp.status, StatusCode::OK);

    // Scrubbing must fire on PATCH responses too.
    let body_str = String::from_utf8_lossy(&resp.body);
    assert!(
        body_str.contains("<REDACTED_OTP>"),
        "drive update response should be scrubbed: {body_str}"
    );
    assert!(!body_str.contains(raw_otp), "raw OTP must NOT appear in update response");

    let events = audit_store.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].service, "drive");
    assert_eq!(events[0].scope, "drive.file");
    assert_eq!(events[0].outcome, "ok");
    assert_eq!(events[0].event_type, "api-call");

    let extra = &events[0].extra;
    let scrub_events = &extra["scrub_events"];
    assert!(scrub_events["summary"].is_object(), "summary missing: {extra}");
    let samples = scrub_events["samples"].as_array().expect("samples array");
    assert!(!samples.is_empty());
    let snippet = samples[0]["snippet"].as_str().unwrap();
    assert!(snippet.contains("<REDACTED_OTP>"));
    assert!(!snippet.contains(raw_otp));

    mock.assert_async().await;
}
