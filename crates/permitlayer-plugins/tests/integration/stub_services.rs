//! Integration tests for [`permitlayer_plugins::StubHostServices`]
//! (Story 6.4 AC #17).
//!
//! These tests exercise the stub through the public re-export
//! (`permitlayer_plugins::StubHostServices`) — not the internal
//! `host_api::stub_services::StubHostServices` path — so a future
//! refactor that accidentally hides the stub from the public
//! surface would break these tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use permitlayer_plugins::{DecisionDesc, FetchReq, HostServices, PolicyEvalReq, StubHostServices};

#[test]
fn stub_get_token_returns_bearer() {
    let stub = StubHostServices::new();
    let tok = stub.issue_scoped_token("google-gmail", "gmail.readonly").unwrap();
    assert!(!tok.bearer.is_empty(), "stub must issue a non-empty bearer");
    assert_eq!(tok.scope, "gmail.readonly");
    assert_eq!(tok.resource, "google-gmail");
    assert!(tok.expires_at_epoch_secs > 0);
}

#[test]
fn stub_policy_enforce_returns_allow() {
    let stub = StubHostServices::new();
    let req = PolicyEvalReq {
        policy_name: String::new(),
        scope: "gmail.readonly".to_owned(),
        resource: None,
    };
    let decision = stub.evaluate_policy(req).unwrap();
    assert!(
        matches!(decision, DecisionDesc::Allow),
        "stub must always allow — deterministic for offline testing"
    );
}

#[test]
fn stub_scrub_text_passes_through() {
    let stub = StubHostServices::new();
    let resp = stub.scrub_text("hello world — no redactions here").unwrap();
    assert_eq!(resp.output, "hello world — no redactions here");
    assert!(resp.matches.is_empty(), "stub scrub must not invent matches");
}

#[test]
fn stub_http_fetch_returns_200_ok() {
    let stub = StubHostServices::new();
    let req = FetchReq {
        method: "GET".to_owned(),
        url: "https://example.com/test".to_owned(),
        headers: Vec::new(),
        body: None,
        timeout_ms: 1_000,
    };
    let resp = stub.fetch(req).unwrap();
    assert_eq!(resp.status, 200);
    assert!(resp.body_utf8_lossy.contains("stub"));
}

#[test]
fn stub_implements_host_services_trait_object_safe() {
    // AC #17: `Arc<dyn HostServices>` dispatch must compile. This
    // is what `register_host_api` consumes.
    let stub: Arc<dyn HostServices> = Arc::new(StubHostServices::new());
    assert!(!stub.current_agent_policy_name().is_empty());
    assert!(!stub.current_plugin_name().is_empty());
    let connected = stub.list_connected_services().unwrap();
    assert!(connected.contains(&"google-gmail".to_owned()));
}
