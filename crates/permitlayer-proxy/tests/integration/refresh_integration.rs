//! Integration tests for the Story 1.14a refresh hook in
//! `ProxyService::handle`.
//!
//! These tests exercise the full refresh-and-retry flow end-to-end:
//!
//! 1. An in-process mock upstream server (axum) simulates a Google API
//!    that returns 401 then 200, or stays 401, or returns a different
//!    response on the retry path.
//! 2. An in-process mock OAuth token endpoint (axum) simulates Google's
//!    `https://oauth2.googleapis.com/token` with configurable behavior
//!    per test: return success, return `invalid_grant`, or return 500
//!    repeatedly.
//! 3. A `ProxyService` is constructed via the `#[cfg(test)]`
//!    `with_oauth_client_override` constructor from Story 1.14a Task 2b,
//!    injecting an `OAuthClient` that points at the mock OAuth server.
//!    The test vault directory has a valid `{service}-meta.json` as
//!    defense-in-depth, but the override takes precedence.
//! 4. Pre-sealed access + refresh tokens are put into a
//!    `PersistentMockCredentialStore` (an enhanced mock that actually
//!    persists via `put`, unlike the no-op stub in `proxy_service.rs`).
//!
//! The seven test cases map directly to Story 1.14a AC 7:
//!
//! - Gmail happy path (full assertion suite, AC 1)
//! - Calendar smoke test (AC 1, service-agnostic verification)
//! - Drive smoke test (AC 1)
//! - InvalidGrant → credential.revoked (AC 3)
//! - RefreshExhausted → upstream.unreachable (AC 4)
//! - Bounded retry: second 401 does not trigger second refresh (AC 2)
//! - Missing refresh token: original 401 passes through, audit
//!   `skipped_no_refresh_token` event fires (AC 5, invariant #7)
//!
//! The RefreshExhausted test uses `tokio::time::pause()` so the
//! 1s/2s/4s backoff between the 3 refresh attempts runs in microseconds
//! instead of ~7 seconds of wall clock.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::routing::{get, post};
use permitlayer_core::audit::event::AuditEvent;
use permitlayer_core::scrub::{ScrubEngine, builtin_rules};
use permitlayer_core::store::{AuditStore, CredentialStore, StoreError};
use permitlayer_credential::{OAuthRefreshToken, OAuthToken, SealedCredential};
use permitlayer_oauth::{CredentialMeta, OAuthClient};
use permitlayer_proxy::request::ProxyRequest;
use permitlayer_proxy::service::ProxyService;
use permitlayer_proxy::token::ScopedTokenIssuer;
use permitlayer_proxy::upstream::UpstreamClient;
use permitlayer_vault::Vault;
use tempfile::TempDir;
use url::Url;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Test Helpers (vault + scrub + token issuer)
// ---------------------------------------------------------------------------

const TEST_MASTER_KEY: [u8; 32] = [0x17; 32];

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

// ---------------------------------------------------------------------------
// PersistentMockCredentialStore
//
// Unlike the no-op `put` stub in `tests/proxy_service.rs`, this mock
// actually persists the sealed credentials that come through `put`.
// The refresh path needs this so post-refresh assertions can verify
// that the new access token landed in the store.
// ---------------------------------------------------------------------------

struct PersistentMockCredentialStore {
    /// Maps service key → raw token bytes (access tokens and refresh
    /// tokens stored uniformly; callers distinguish by key naming
    /// convention `{service}` vs `{service}-refresh`).
    ///
    /// Using raw bytes rather than `SealedCredential` because the
    /// sealed blob type is not `Clone` and the test fixtures need to
    /// read the same credential multiple times.
    services: Mutex<HashMap<String, Vec<u8>>>,
    master_key: [u8; 32],
}

impl PersistentMockCredentialStore {
    fn new(master_key: [u8; 32]) -> Self {
        Self { services: Mutex::new(HashMap::new()), master_key }
    }

    fn seed_access_token(&self, service: &str, token_bytes: &[u8]) {
        self.services.lock().unwrap().insert(service.to_owned(), token_bytes.to_vec());
    }

    fn seed_refresh_token(&self, service: &str, token_bytes: &[u8]) {
        self.services.lock().unwrap().insert(format!("{service}-refresh"), token_bytes.to_vec());
    }

    fn get_raw(&self, key: &str) -> Option<Vec<u8>> {
        self.services.lock().unwrap().get(key).cloned()
    }
}

#[async_trait::async_trait]
impl CredentialStore for PersistentMockCredentialStore {
    async fn put(&self, service: &str, sealed: SealedCredential) -> Result<(), StoreError> {
        // Unseal the incoming blob so we can store the raw bytes (to
        // support re-sealing on subsequent get() calls). This mirrors
        // how a real filesystem store would persist the sealed envelope
        // and re-hand it out on read.
        //
        // Dispatch on the key-name convention: `{service}-refresh`
        // carries a refresh token sealed via `vault.seal_refresh`,
        // everything else is an access token sealed via `vault.seal`.
        // The matching `get()` path below uses the same dispatch, so
        // production code that accidentally sealed a refresh token
        // with `vault.seal()` (or vice versa) produces a crypto error
        // here instead of silently "working" via fallback — which was
        // the mock's prior behavior and masked exactly that class of
        // bug.
        let vault = Vault::new(Zeroizing::new(self.master_key), 0);
        let bytes = if service.ends_with("-refresh") {
            vault
                .unseal_refresh(service, &sealed)
                .map(|refresh| refresh.reveal().to_vec())
                .map_err(|e| {
                    StoreError::IoError(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "mock store: unseal_refresh failed for '{service}' \
                             (did production code call vault.seal() instead of \
                             vault.seal_refresh()?): {e}"
                        ),
                    ))
                })?
        } else {
            vault.unseal(service, &sealed).map(|access| access.reveal().to_vec()).map_err(|e| {
                StoreError::IoError(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "mock store: unseal failed for '{service}' \
                         (did production code call vault.seal_refresh() instead of \
                         vault.seal()?): {e}"
                    ),
                ))
            })?
        };
        self.services.lock().unwrap().insert(service.to_owned(), bytes);
        Ok(())
    }

    async fn get(&self, service: &str) -> Result<Option<SealedCredential>, StoreError> {
        let bytes = match self.services.lock().unwrap().get(service).cloned() {
            Some(b) => b,
            None => return Ok(None),
        };
        let vault = Vault::new(Zeroizing::new(self.master_key), 0);
        // Same access-vs-refresh heuristic as in put: try the access
        // variant first, fall back to refresh. The service-name suffix
        // `-refresh` tells us which sealing function to use at call
        // time, but we keep the logic identical across both paths to
        // keep the mock simple.
        let sealed = if service.ends_with("-refresh") {
            let token = OAuthRefreshToken::from_trusted_bytes(bytes);
            vault.seal_refresh(service, &token).map_err(|_| {
                StoreError::IoError(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "mock store: seal_refresh failed",
                ))
            })?
        } else {
            let token = OAuthToken::from_trusted_bytes(bytes);
            vault.seal(service, &token).map_err(|_| {
                StoreError::IoError(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "mock store: seal failed",
                ))
            })?
        };
        Ok(Some(sealed))
    }
    async fn list_services(&self) -> Result<Vec<String>, StoreError> {
        Ok(self.services.lock().unwrap().keys().cloned().collect())
    }
}

// ---------------------------------------------------------------------------
// MockAuditStore
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Mock upstream server (axum) — simulates Gmail/Calendar/Drive APIs
// ---------------------------------------------------------------------------

/// Shared state for the upstream mock. Tracks call count and a response
/// script indexed by call number.
struct UpstreamMockState {
    call_count: AtomicUsize,
    /// Response script: `responses[i]` is what the mock returns on the
    /// i-th call (0-indexed). If the index exceeds the script length,
    /// the mock repeats the last entry.
    responses: Vec<(StatusCode, &'static str)>,
    /// Optional stale-bearer rejection. When `Some`, any request whose
    /// `Authorization` header is `Bearer {reject_bearer}` is answered
    /// with a hard-coded 401 regardless of the script — this lets the
    /// `gmail_second_call` test verify that the proxy actually switched
    /// to the newly-refreshed access token (as opposed to the mock
    /// script happily returning 200 regardless of what bearer arrived).
    reject_bearer: Option<&'static str>,
}

async fn upstream_handler(
    State(state): State<Arc<UpstreamMockState>>,
    headers: HeaderMap,
) -> (StatusCode, [(axum::http::HeaderName, &'static str); 1], String) {
    let call_index = state.call_count.fetch_add(1, Ordering::SeqCst);

    // If the test configured a stale-bearer rejection, inspect the
    // Authorization header and 401 on match.
    if let Some(stale) = state.reject_bearer {
        let expected = format!("Bearer {stale}");
        if headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok())
            == Some(expected.as_str())
        {
            return (
                StatusCode::UNAUTHORIZED,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                r#"{"error":"stale bearer rejected by mock"}"#.to_owned(),
            );
        }
    }

    let response_index = call_index.min(state.responses.len() - 1);
    let (status, body) = state.responses[response_index];
    (status, [(axum::http::header::CONTENT_TYPE, "application/json")], body.to_owned())
}

/// Spawn an in-process upstream mock server bound to 127.0.0.1:0 and
/// return its base URL plus the shared state handle.
///
/// The server handles any `GET /*` request with the scripted response
/// sequence. When `reject_bearer` is `Some`, the mock also 401s any
/// request whose `Authorization` header is `Bearer {reject_bearer}`
/// — see [`UpstreamMockState::reject_bearer`] for the rationale.
async fn spawn_mock_upstream_with_stale_bearer(
    responses: Vec<(StatusCode, &'static str)>,
    reject_bearer: Option<&'static str>,
) -> (String, Arc<UpstreamMockState>) {
    let state =
        Arc::new(UpstreamMockState { call_count: AtomicUsize::new(0), responses, reject_bearer });
    let app =
        axum::Router::new().route("/{*path}", get(upstream_handler)).with_state(Arc::clone(&state));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind upstream mock");
    let addr = listener.local_addr().expect("upstream local addr");
    let url = format!("http://127.0.0.1:{}", addr.port());

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("upstream mock serve");
    });

    (url, state)
}

// ---------------------------------------------------------------------------
// Mock OAuth token endpoint (axum) — simulates
// https://oauth2.googleapis.com/token for the refresh_token grant type
// ---------------------------------------------------------------------------

/// Behavior flags for the OAuth mock. Each test sets the desired mode
/// before spawning the server.
#[derive(Clone, Copy)]
enum OAuthMockBehavior {
    /// Return a successful token response with only an access_token
    /// (no rotation — the refresh_token field is omitted).
    Success,
    /// Return a successful token response with BOTH a new access_token
    /// and a new refresh_token (rotation path, exercising architecture
    /// invariant #3's atomic rotation ordering).
    SuccessWithRotation,
    /// Return `{"error":"invalid_grant"}` with HTTP 400.
    InvalidGrant,
    /// Return HTTP 500 on every request. Combined with the retry
    /// policy, this exercises the RefreshExhausted path.
    AlwaysFail,
}

struct OAuthMockState {
    call_count: AtomicUsize,
    behavior: OAuthMockBehavior,
}

async fn oauth_token_handler(
    State(state): State<Arc<OAuthMockState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    state.call_count.fetch_add(1, Ordering::SeqCst);
    match state.behavior {
        OAuthMockBehavior::Success => (
            StatusCode::OK,
            Json(serde_json::json!({
                "access_token": "ya29.new-access-token-from-refresh",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "https://www.googleapis.com/auth/gmail.readonly",
            })),
        ),
        OAuthMockBehavior::SuccessWithRotation => (
            StatusCode::OK,
            Json(serde_json::json!({
                "access_token": "ya29.new-access-token-from-refresh",
                "refresh_token": "new-refresh-token-rotated",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "https://www.googleapis.com/auth/gmail.readonly",
            })),
        ),
        OAuthMockBehavior::InvalidGrant => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Token has been revoked or is invalid.",
            })),
        ),
        OAuthMockBehavior::AlwaysFail => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
            })),
        ),
    }
}

async fn spawn_mock_oauth(behavior: OAuthMockBehavior) -> (String, Arc<OAuthMockState>) {
    let state = Arc::new(OAuthMockState { call_count: AtomicUsize::new(0), behavior });
    let app = axum::Router::new()
        .route("/token", post(oauth_token_handler))
        .with_state(Arc::clone(&state));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind oauth mock");
    let addr = listener.local_addr().expect("oauth local addr");
    let url = format!("http://127.0.0.1:{}/token", addr.port());

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("oauth mock serve");
    });

    (url, state)
}

// ---------------------------------------------------------------------------
// Fixture: `make_test_service` — builds a ProxyService wired to mocks
// ---------------------------------------------------------------------------

struct TestFixture {
    service: Arc<ProxyService>,
    cred_store: Arc<PersistentMockCredentialStore>,
    audit_store: Arc<MockAuditStore>,
    upstream_state: Arc<UpstreamMockState>,
    oauth_state: Arc<OAuthMockState>,
    _tempdir: TempDir,
}

/// Build a complete test fixture for a single service.
///
/// - `service_name`: `"gmail"`, `"calendar"`, or `"drive"`.
/// - `upstream_responses`: script for the upstream mock.
/// - `oauth_behavior`: how the OAuth mock should respond to refresh
///   requests.
/// - `pre_seal_refresh_token`: if false, no `{service}-refresh` entry
///   is created, exercising the AC 5 skipped_no_refresh_token path.
async fn make_test_service(
    service_name: &str,
    upstream_responses: Vec<(StatusCode, &'static str)>,
    oauth_behavior: OAuthMockBehavior,
    pre_seal_refresh_token: bool,
) -> TestFixture {
    make_test_service_full(
        service_name,
        upstream_responses,
        oauth_behavior,
        pre_seal_refresh_token,
        None,
    )
    .await
}

/// Fixture builder with stale-bearer rejection enabled. When
/// `reject_bearer` is `Some`, the upstream mock 401s any request whose
/// `Authorization` header is `Bearer {reject_bearer}`, regardless of
/// the scripted response. Used by the `gmail_second_call` test to
/// verify that the refreshed access token is actually sent on the
/// second call.
async fn make_test_service_full(
    service_name: &str,
    upstream_responses: Vec<(StatusCode, &'static str)>,
    oauth_behavior: OAuthMockBehavior,
    pre_seal_refresh_token: bool,
    reject_bearer: Option<&'static str>,
) -> TestFixture {
    let (upstream_url, upstream_state) =
        spawn_mock_upstream_with_stale_bearer(upstream_responses, reject_bearer).await;
    let (oauth_url, oauth_state) = spawn_mock_oauth(oauth_behavior).await;

    // Create a tempdir to serve as vault_dir and write a shared-casa
    // meta file. This is defense in depth — the oauth_client_overrides
    // map we inject takes precedence over metadata reads for the
    // override path, but a valid meta file means any unintended
    // fallthrough produces a useful error instead of a cryptic one.
    let tempdir = TempDir::new().expect("tempdir");
    let meta = CredentialMeta {
        client_type: "shared-casa".to_owned(),
        client_source: None,
        connected_at: "2026-04-09T12:00:00Z".to_owned(),
        last_refreshed_at: None,
        scopes: vec!["https://www.googleapis.com/auth/gmail.readonly".to_owned()],
        expires_in_secs: Some(3600),
    };
    let meta_path = tempdir.path().join(format!("{service_name}-meta.json"));
    std::fs::write(&meta_path, serde_json::to_string(&meta).unwrap()).expect("write meta");

    // Build the persistent credential store and seed tokens.
    let cred_store = Arc::new(PersistentMockCredentialStore::new(TEST_MASTER_KEY));
    cred_store.seed_access_token(service_name, b"initial-access-token-STALE");
    if pre_seal_refresh_token {
        cred_store.seed_refresh_token(service_name, b"refresh-token-for-exchange");
    }

    // Build the mock OAuth client pointing at the spawned token
    // endpoint. The auth URL is a placeholder — it's never called on
    // the refresh path.
    let mock_oauth_client = Arc::new(
        OAuthClient::new_with_endpoint_overrides(
            "test-client-id".to_owned(),
            None,
            "http://127.0.0.1:0/auth",
            &oauth_url,
        )
        .expect("build mock oauth client"),
    );

    // Build the upstream client pointing at the mock upstream.
    let mut base_urls = HashMap::new();
    base_urls.insert(
        service_name.to_owned(),
        Url::parse(&format!("{upstream_url}/")).expect("parse upstream url"),
    );
    let reqwest_client = reqwest::Client::builder().build().expect("build reqwest client");
    let upstream_client = Arc::new(UpstreamClient::with_client_and_urls(reqwest_client, base_urls));

    // Assemble the ProxyService with the OAuth override map.
    let mut overrides = HashMap::new();
    overrides.insert(service_name.to_owned(), mock_oauth_client);

    let audit_store = Arc::new(MockAuditStore::new());
    let service = Arc::new(ProxyService::with_oauth_client_override(
        Arc::clone(&cred_store) as Arc<dyn CredentialStore>,
        Arc::new(test_vault()),
        Arc::new(test_token_issuer()),
        upstream_client,
        Arc::clone(&audit_store) as Arc<dyn AuditStore>,
        test_scrub_engine(),
        tempdir.path().to_path_buf(),
        overrides,
    ));

    TestFixture { service, cred_store, audit_store, upstream_state, oauth_state, _tempdir: tempdir }
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
        agent_id: "agent-refresh-integration-test".to_owned(),
        request_id: ulid::Ulid::new().to_string(),
    }
}

// ---------------------------------------------------------------------------
// Test 1: Gmail happy path (full assertion suite)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gmail_happy_path_401_triggers_refresh_and_retry_succeeds() {
    let fixture = make_test_service(
        "gmail",
        vec![
            (StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#),
            (StatusCode::OK, r#"{"messages":[{"id":"msg-1"}]}"#),
        ],
        OAuthMockBehavior::Success,
        true,
    )
    .await;

    // First call: upstream returns 401, proxy refreshes, retries, gets 200.
    let req = make_request("gmail", "users/me/messages");
    let resp = fixture.service.handle(req).await.expect("first handle should succeed");

    assert_eq!(resp.status, StatusCode::OK, "proxy should return 200 after refresh+retry");
    assert_eq!(
        resp.body,
        r#"{"messages":[{"id":"msg-1"}]}"#.as_bytes(),
        "body should be the retry response, not the initial 401 body"
    );

    // Exactly one OAuth token endpoint call.
    assert_eq!(
        fixture.oauth_state.call_count.load(Ordering::SeqCst),
        1,
        "exactly one OAuth refresh call should have happened"
    );

    // Exactly two upstream calls (initial 401 + retry 200).
    assert_eq!(
        fixture.upstream_state.call_count.load(Ordering::SeqCst),
        2,
        "upstream should see exactly two calls: the initial and the retry"
    );

    // Audit events: exactly one token-refresh success + one api-call.
    let events = fixture.audit_store.events();
    let refresh_events: Vec<_> =
        events.iter().filter(|e| e.event_type == "token-refresh").collect();
    assert_eq!(refresh_events.len(), 1, "exactly one token-refresh event");
    assert_eq!(refresh_events[0].outcome, "success");
    assert_eq!(refresh_events[0].service, "gmail");

    let api_call_events: Vec<_> = events.iter().filter(|e| e.event_type == "api-call").collect();
    assert_eq!(api_call_events.len(), 1, "exactly one api-call event for the retry");
    assert_eq!(api_call_events[0].outcome, "ok");

    // The new access token is in the store.
    let stored = fixture.cred_store.get_raw("gmail").expect("access token sealed");
    assert_eq!(
        stored,
        b"ya29.new-access-token-from-refresh".to_vec(),
        "vault should now contain the refreshed access token"
    );

    assert_no_token_bytes_in_audit(&fixture);
}

#[tokio::test]
async fn gmail_second_call_uses_new_token_without_triggering_second_refresh() {
    // Two-phase test: first call refreshes, second call should use the
    // new token directly. Assert OAuth endpoint sees exactly one call
    // across both handle() invocations AND verify structurally that
    // the second call actually sends the new token — the mock's
    // `reject_bearer` hook 401s any request carrying the stale
    // `initial-access-token-STALE` bytes. Without this gate a stale-
    // token bug would silently pass because the mock script would
    // return 200 for any bearer.
    let fixture = make_test_service_full(
        "gmail",
        vec![(StatusCode::OK, r#"{"messages":[]}"#)],
        OAuthMockBehavior::Success,
        true,
        Some("initial-access-token-STALE"),
    )
    .await;

    // First call: the mock 401s the stale bearer, the proxy refreshes,
    // retries with the new bearer, and the mock answers 200 from the
    // script. Exactly one OAuth refresh call.
    let req1 = make_request("gmail", "users/me/messages");
    let resp1 = fixture.service.handle(req1).await.expect("first handle");
    assert_eq!(resp1.status, StatusCode::OK);
    assert_eq!(
        fixture.oauth_state.call_count.load(Ordering::SeqCst),
        1,
        "first call should trigger exactly one refresh"
    );

    // Second call: the proxy must send the *new* bearer. If it still
    // used `initial-access-token-STALE`, the mock's reject_bearer hook
    // would 401 it, which would trigger another refresh (OAuth count
    // would reach 2) — the assertion below catches that.
    let req2 = make_request("gmail", "users/me/messages");
    let resp2 = fixture.service.handle(req2).await.expect("second handle");
    assert_eq!(resp2.status, StatusCode::OK);
    assert_eq!(
        fixture.oauth_state.call_count.load(Ordering::SeqCst),
        1,
        "second call must use the refreshed token (structurally \
         verified via reject_bearer) and must NOT trigger a second refresh"
    );

    assert_no_token_bytes_in_audit(&fixture);
}

// ---------------------------------------------------------------------------
// Test 2: Calendar smoke test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn calendar_smoke_refresh_works_for_service_calendar() {
    let fixture = make_test_service(
        "calendar",
        vec![
            (StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#),
            (StatusCode::OK, r#"{"items":[]}"#),
        ],
        OAuthMockBehavior::Success,
        true,
    )
    .await;

    let req = make_request("calendar", "calendars/primary/events");
    let resp = fixture.service.handle(req).await.expect("calendar handle");

    // Full happy-path assertion suite, mirroring the gmail test so a
    // service-specific bug (e.g. a hard-coded "gmail" path) cannot
    // silently pass for calendar.
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(resp.body, r#"{"items":[]}"#.as_bytes());
    assert_eq!(fixture.oauth_state.call_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.upstream_state.call_count.load(Ordering::SeqCst),
        2,
        "calendar upstream should see initial 401 + retry 200"
    );
    let stored = fixture.cred_store.get_raw("calendar").expect("calendar access token sealed");
    assert_eq!(stored, b"ya29.new-access-token-from-refresh".to_vec());

    let refresh_events: Vec<_> = fixture
        .audit_store
        .events()
        .into_iter()
        .filter(|e| e.event_type == "token-refresh")
        .collect();
    assert_eq!(refresh_events.len(), 1);
    assert_eq!(refresh_events[0].service, "calendar");
    assert_eq!(refresh_events[0].outcome, "success");

    assert_no_token_bytes_in_audit(&fixture);
}

// ---------------------------------------------------------------------------
// Test 3: Drive smoke test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn drive_smoke_refresh_works_for_service_drive() {
    let fixture = make_test_service(
        "drive",
        vec![
            (StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#),
            (StatusCode::OK, r#"{"files":[]}"#),
        ],
        OAuthMockBehavior::Success,
        true,
    )
    .await;

    let req = make_request("drive", "files");
    let resp = fixture.service.handle(req).await.expect("drive handle");

    // Full happy-path assertion suite — mirror of the gmail test.
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(resp.body, r#"{"files":[]}"#.as_bytes());
    assert_eq!(fixture.oauth_state.call_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.upstream_state.call_count.load(Ordering::SeqCst),
        2,
        "drive upstream should see initial 401 + retry 200"
    );
    let stored = fixture.cred_store.get_raw("drive").expect("drive access token sealed");
    assert_eq!(stored, b"ya29.new-access-token-from-refresh".to_vec());

    let refresh_events: Vec<_> = fixture
        .audit_store
        .events()
        .into_iter()
        .filter(|e| e.event_type == "token-refresh")
        .collect();
    assert_eq!(refresh_events.len(), 1);
    assert_eq!(refresh_events[0].service, "drive");
    assert_eq!(refresh_events[0].outcome, "success");

    assert_no_token_bytes_in_audit(&fixture);
}

// ---------------------------------------------------------------------------
// Test 4: InvalidGrant → credential.revoked
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_grant_returns_credential_revoked_error() {
    use permitlayer_proxy::error::ProxyError;

    let fixture = make_test_service(
        "gmail",
        vec![
            (StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#),
            // This response should never be consumed — the OAuth refresh
            // fails with invalid_grant before the retry dispatch.
            (StatusCode::OK, r#"{"should":"not be returned"}"#),
        ],
        OAuthMockBehavior::InvalidGrant,
        true,
    )
    .await;

    let req = make_request("gmail", "users/me/messages");
    let result = fixture.service.handle(req).await;

    match result {
        Err(ProxyError::CredentialRevoked { service }) => {
            assert_eq!(service, "gmail");
        }
        Err(other) => panic!("expected CredentialRevoked, got {other:?}"),
        Ok(_) => panic!("expected error, got success"),
    }

    // Exactly one OAuth call (invalid_grant is non-retryable).
    assert_eq!(fixture.oauth_state.call_count.load(Ordering::SeqCst), 1);

    // The upstream was called exactly once (the initial 401). No retry.
    assert_eq!(fixture.upstream_state.call_count.load(Ordering::SeqCst), 1);

    // Exactly one token-refresh audit event with outcome=invalid_grant.
    let refresh_events: Vec<_> = fixture
        .audit_store
        .events()
        .into_iter()
        .filter(|e| e.event_type == "token-refresh")
        .collect();
    assert_eq!(refresh_events.len(), 1);
    assert_eq!(refresh_events[0].outcome, "invalid_grant");

    assert_no_token_bytes_in_audit(&fixture);
}

// ---------------------------------------------------------------------------
// Test 5: RefreshExhausted → upstream.unreachable
// ---------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn refresh_exhausted_returns_upstream_unreachable_with_oauth_service() {
    use permitlayer_proxy::error::ProxyError;

    // `start_paused = true` virtualizes tokio::time, so the 1s/2s/4s
    // backoff inside refresh_with_retry runs in nanoseconds of wall
    // clock. Mock server IO still runs in real time, which is fine —
    // tokio auto-advances virtual time whenever the runtime becomes
    // idle waiting on timers, and between HTTP calls the refresh
    // backoff parks on `tokio::time::sleep` which the auto-advancer
    // picks up automatically.
    let fixture = make_test_service(
        "gmail",
        vec![(StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#)],
        OAuthMockBehavior::AlwaysFail,
        true,
    )
    .await;

    let result = fixture.service.handle(make_request("gmail", "users/me/messages")).await;

    match result {
        Err(ProxyError::UpstreamUnreachable { service, retry_after_seconds, .. }) => {
            assert_eq!(service, "gmail-oauth");
            assert_eq!(retry_after_seconds, 30);
        }
        Err(other) => panic!("expected UpstreamUnreachable, got {other:?}"),
        Ok(_) => panic!("expected error, got success"),
    }

    // OAuth endpoint was called exactly 3 times (the retry policy).
    assert_eq!(fixture.oauth_state.call_count.load(Ordering::SeqCst), 3);

    // m4: Upstream was called exactly once (the initial 401) — AC 4
    // requires NO upstream retry on refresh exhaustion. Locking this
    // in structurally so a regression that retries upstream anyway is
    // caught by the test, not only by code review.
    assert_eq!(
        fixture.upstream_state.call_count.load(Ordering::SeqCst),
        1,
        "refresh exhaustion must not trigger an upstream retry"
    );

    // Exactly one token-refresh audit event with outcome=exhausted.
    let refresh_events: Vec<_> = fixture
        .audit_store
        .events()
        .into_iter()
        .filter(|e| e.event_type == "token-refresh")
        .collect();
    assert_eq!(refresh_events.len(), 1);
    assert_eq!(refresh_events[0].outcome, "exhausted");

    assert_no_token_bytes_in_audit(&fixture);
}

// ---------------------------------------------------------------------------
// Test 6: Bounded retry — second 401 does not trigger second refresh
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bounded_retry_second_401_is_passed_through_without_second_refresh() {
    // Mock upstream returns 401 on BOTH the initial call and the retry.
    // The refresh path must refresh once, retry once, and then return
    // the retry's 401 to the caller unchanged — no second refresh.
    let fixture = make_test_service(
        "gmail",
        vec![
            (StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#),
            (StatusCode::UNAUTHORIZED, r#"{"error":"still unauthorized"}"#),
        ],
        OAuthMockBehavior::Success,
        true,
    )
    .await;

    let req = make_request("gmail", "users/me/messages");
    let resp = fixture.service.handle(req).await.expect("handle returns Ok with 401 response");

    // The retry's 401 reaches the agent.
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    assert_eq!(resp.body, r#"{"error":"still unauthorized"}"#.as_bytes());

    // Exactly ONE OAuth call — the second 401 did NOT trigger a second
    // refresh. This is the structural enforcement of AC 2.
    assert_eq!(
        fixture.oauth_state.call_count.load(Ordering::SeqCst),
        1,
        "bounded retry invariant: at most one refresh per request"
    );

    // Exactly TWO upstream calls — the initial and the retry.
    assert_eq!(fixture.upstream_state.call_count.load(Ordering::SeqCst), 2);

    // Audit events: exactly one token-refresh success (the refresh
    // itself worked) AND exactly one api-call (for the retry which
    // returned the second 401).
    let events = fixture.audit_store.events();
    let refresh_events: Vec<_> =
        events.iter().filter(|e| e.event_type == "token-refresh").collect();
    assert_eq!(refresh_events.len(), 1);
    assert_eq!(refresh_events[0].outcome, "success");

    let api_call_events: Vec<_> = events.iter().filter(|e| e.event_type == "api-call").collect();
    assert_eq!(api_call_events.len(), 1);
    // m5: the retry's 401 must be reflected in the api-call audit
    // outcome, not papered over as "ok". The production code derives
    // outcome from `upstream_resp.status` (2xx → "ok", else
    // "http_error"); a regression that hardcodes "ok" again would
    // show up here, not just in operator confusion downstream.
    assert_eq!(
        api_call_events[0].outcome, "http_error",
        "bounded-retry 401 must surface as api-call outcome=http_error, not ok"
    );

    assert_no_token_bytes_in_audit(&fixture);
}

// ---------------------------------------------------------------------------
// Test 7: Missing refresh token — graceful degradation + audit signal
// ---------------------------------------------------------------------------

#[tokio::test]
#[tracing_test::traced_test]
async fn missing_refresh_token_returns_original_401_with_skip_audit_event() {
    // Fixture with pre_seal_refresh_token=false: access token is
    // present but no gmail-refresh entry. The refresh path should log
    // a warning, emit a token-refresh audit event with
    // outcome=skipped_no_refresh_token, and return the original 401
    // unchanged.
    let fixture = make_test_service(
        "gmail",
        vec![(StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#)],
        // OAuth behavior is irrelevant — no refresh should be attempted.
        OAuthMockBehavior::AlwaysFail,
        /* pre_seal_refresh_token: */ false,
    )
    .await;

    let req = make_request("gmail", "users/me/messages");
    let resp = fixture.service.handle(req).await.expect("handle returns Ok with 401");

    // The original 401 reaches the agent unchanged.
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    assert_eq!(resp.body, r#"{"error":"unauthorized"}"#.as_bytes());

    // The OAuth endpoint was NOT called.
    assert_eq!(
        fixture.oauth_state.call_count.load(Ordering::SeqCst),
        0,
        "no refresh should be attempted when the refresh token is missing"
    );

    // The upstream was called exactly once (initial, no retry).
    assert_eq!(fixture.upstream_state.call_count.load(Ordering::SeqCst), 1);

    // Exactly one token-refresh audit event with outcome=skipped_no_refresh_token.
    let refresh_events: Vec<_> = fixture
        .audit_store
        .events()
        .into_iter()
        .filter(|e| e.event_type == "token-refresh")
        .collect();
    assert_eq!(refresh_events.len(), 1, "exactly one skip audit event");
    assert_eq!(refresh_events[0].outcome, "skipped_no_refresh_token");
    assert_eq!(refresh_events[0].service, "gmail");

    // The warning log was emitted. `tracing-test` captures all tracing
    // output in the test; `logs_contain` checks the captured buffer.
    // Note that `tracing-test` captures events emitted on spans that
    // include the test's span, which means everything inside this
    // `#[tokio::test]` function is captured. The warn! inside
    // `try_refresh_and_retry` should reach the captured buffer.
    //
    // Debugging helper: if this assertion fails, check whether the
    // warn is firing at all by asserting on a simpler marker first.
    assert!(
        logs_contain("refresh token missing"),
        "expected a tracing::warn! containing 'refresh token missing' but \
         logs did not contain it. The production code emits \
         `warn!(service = %service, \"refresh token missing for service — ...\")`; \
         verify the warn is actually firing (e.g. by temporarily adding a \
         println in the same branch) if this keeps failing."
    );

    assert_no_token_bytes_in_audit(&fixture);
}

// ---------------------------------------------------------------------------
// Test 9: Rotation path — new refresh_token returned alongside access_token
//
// Exercises architecture invariant #3's atomic rotation ordering (new
// refresh token sealed + stored BEFORE new access token) and the
// `extra.refresh_token_rotated: true` audit field. Without this test,
// the entire rotation branch of `try_refresh_and_retry` ships
// completely untested end-to-end.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rotation_path_persists_both_tokens_and_marks_audit_extra() {
    let fixture = make_test_service(
        "gmail",
        vec![
            (StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#),
            (StatusCode::OK, r#"{"messages":[{"id":"post-rotation"}]}"#),
        ],
        OAuthMockBehavior::SuccessWithRotation,
        true,
    )
    .await;

    let req = make_request("gmail", "users/me/messages");
    let resp = fixture.service.handle(req).await.expect("rotation handle");

    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        resp.body,
        r#"{"messages":[{"id":"post-rotation"}]}"#.as_bytes(),
        "response body should be the post-rotation retry payload"
    );

    // Both new tokens are durably in the store after the refresh.
    let stored_access =
        fixture.cred_store.get_raw("gmail").expect("rotated access token should be persisted");
    assert_eq!(
        stored_access,
        b"ya29.new-access-token-from-refresh".to_vec(),
        "vault should contain the rotated access token"
    );
    let stored_refresh = fixture
        .cred_store
        .get_raw("gmail-refresh")
        .expect("rotated refresh token should be persisted");
    assert_eq!(
        stored_refresh,
        b"new-refresh-token-rotated".to_vec(),
        "vault should contain the rotated refresh token (invariant #3 atomic rotation)"
    );

    // Exactly one token-refresh success event with refresh_token_rotated=true.
    let events = fixture.audit_store.events();
    let refresh_events: Vec<_> =
        events.iter().filter(|e| e.event_type == "token-refresh").collect();
    assert_eq!(refresh_events.len(), 1, "exactly one token-refresh event");
    assert_eq!(refresh_events[0].outcome, "success");
    assert_eq!(refresh_events[0].service, "gmail");
    assert_eq!(
        refresh_events[0].extra.get("refresh_token_rotated"),
        Some(&serde_json::Value::Bool(true)),
        "rotation success event must set extra.refresh_token_rotated = true"
    );

    assert_no_token_bytes_in_audit(&fixture);
}

// ---------------------------------------------------------------------------
// M5: Sentinel helper — asserts no token-adjacent byte string ever
// appears in any field of any audit event.
//
// AC 4 (Story 1.14a) and the "Anti-patterns" section of the story
// spec both hard-prohibit token bytes from landing in audit fields.
// Today the protection is type-system-only (`OAuthToken` non-Debug,
// non-Clone). A future regression that interpolates a token into an
// `extra` payload or an error message would silently pass unless we
// check structurally. This helper serializes the entire audit event
// list and greps for the deterministic fixture sentinels.
//
// Sentinels (all three appear in fixtures/mocks):
//   - "initial-access-token-STALE" (seeded pre-refresh access token)
//   - "refresh-token-for-exchange" (seeded pre-refresh refresh token)
//   - "ya29.new-access-token-from-refresh" (mock OAuth success body)
//   - "new-refresh-token-rotated" (mock OAuth rotation body)
//
// Every test that constructs a TestFixture via `make_test_service`
// should call this at the end.
// ---------------------------------------------------------------------------

const TOKEN_SENTINELS: &[&str] = &[
    "initial-access-token-STALE",
    "refresh-token-for-exchange",
    "ya29.new-access-token-from-refresh",
    "new-refresh-token-rotated",
];

fn assert_no_token_bytes_in_audit(fixture: &TestFixture) {
    let events = fixture.audit_store.events();
    let json = serde_json::to_string(&events).expect("serialize audit events");
    for sentinel in TOKEN_SENTINELS {
        assert!(
            !json.contains(sentinel),
            "audit event stream contains token sentinel '{sentinel}' — \
             AC 4 prohibits token bytes in audit fields. Full serialized \
             events:\n{json}"
        );
    }
}
