//! Deterministic stub [`HostServices`] for offline tool-invocation
//! smoke tests (Story 6.4 `agentsso connectors test`).
//!
//! The production [`HostServices`] impl lives in
//! `permitlayer-proxy::plugin_host_services::ProxyHostServices` and
//! requires a live `Vault`, `ScopedTokenIssuer`, `PolicyEngine`,
//! `ScrubEngine`, and `reqwest::Client` — none of which exist in the
//! standalone `agentsso connectors test` CLI (the tester is fully
//! offline; no daemon, no network). `StubHostServices` provides the
//! other end of the spectrum: every trait method returns a canned
//! "ok" response with plausible-looking placeholder data.
//!
//! This stub is **not** a security boundary — it exists so plugin
//! authors can invoke each exported tool during `connectors test`
//! and get a deterministic pass/fail without wiring up OAuth,
//! policies, or Gmail/Calendar/Drive credentials. The production
//! loader (Story 6.3) never touches this type.
//!
//! Co-locating the stub with the trait definition means trait
//! evolution (new methods in 1.x) breaks the stub build until the
//! stub implements the new methods — the desired direction of
//! force. If the stub drifted from the trait, tests would silently
//! weaken.

use crate::host_api::{
    DecisionDesc, FetchReq, FetchResp, HostApiError, HostServices, PolicyEvalReq, ScopedTokenDesc,
    ScrubMatchDesc, ScrubResponse,
};

/// Canned "Bearer test-stub-token" scope-token lifetime in seconds.
/// Matches the production `ScopedToken` TTL in `permitlayer-proxy`
/// so plugins that proactively refresh based on `expires_at_epoch_secs`
/// exercise the same code path.
const STUB_TOKEN_TTL_SECS: u64 = 60;

/// Default bearer value returned by [`StubHostServices::issue_scoped_token`].
const STUB_BEARER: &str = "stub-bearer-eyJzY29wZSI6InN0dWIifQ";

/// Canned policy name returned by [`StubHostServices::current_agent_policy_name`].
const STUB_POLICY_NAME: &str = "stub-policy";

/// Canned plugin name returned by [`StubHostServices::current_plugin_name`].
/// Callers that care about the real plugin name should override via a
/// wrapper type; the tester accepts the placeholder because the smoke
/// check only validates that the trait method is reachable.
const STUB_PLUGIN_NAME: &str = "stub-plugin";

/// Canned HTTP response body.
const STUB_HTTP_BODY: &str = r#"{"stub":"response"}"#;

/// Deterministic stub [`HostServices`] used by `agentsso connectors test`.
///
/// Behavior summary:
///
/// - `issue_scoped_token(service, scope)` — returns a fake bearer
///   with `scope = <requested>`, `resource = <service>`, 60-s TTL.
/// - `list_connected_services()` — returns the three built-in
///   connector names (`google-gmail`, `google-calendar`,
///   `google-drive`) so `agentsso.oauth.listConnectedServices()`
///   round-trips a non-empty list.
/// - `evaluate_policy(req)` — always returns `DecisionDesc::Allow`.
///   The `req` is ignored; no real policy engine is consulted.
/// - `scrub_text(input)` — pass-through (no matches). Plugin authors
///   who want to validate scrub behavior must run the real daemon.
/// - `fetch(req)` — returns `status=200`, `headers=[]`,
///   `body_utf8_lossy="{\"stub\":\"response\"}"`. **No network I/O
///   occurs.**
/// - `current_agent_policy_name()` / `current_plugin_name()` —
///   return canned strings.
///
/// A future enhancement could accept a programmable queue of
/// responses (`Vec<StubReply>`) so tests drive specific edge cases;
/// Story 6.4 uses all-defaults since the tool-invocation check only
/// verifies that each tool is *reachable* and returns JSON-
/// serializable output within the deadline.
#[derive(Debug, Default, Clone)]
pub struct StubHostServices;

impl StubHostServices {
    /// Construct a new stub. Usually wrapped in `Arc::new(...)` or
    /// `Arc::new(StubHostServices)` for passing into
    /// [`crate::PluginRuntime::with_host_api`].
    pub fn new() -> Self {
        Self
    }
}

impl HostServices for StubHostServices {
    fn issue_scoped_token(
        &self,
        service: &str,
        scope: &str,
    ) -> Result<ScopedTokenDesc, HostApiError> {
        // Epoch secs "now + TTL"; if the clock returns an error we
        // still produce a plausible future timestamp so the stub
        // stays deterministic (the tester is not a time-sensitive
        // oracle).
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(1_700_000_000);
        Ok(ScopedTokenDesc {
            bearer: STUB_BEARER.to_owned(),
            scope: scope.to_owned(),
            resource: service.to_owned(),
            expires_at_epoch_secs: now_secs.saturating_add(STUB_TOKEN_TTL_SECS),
        })
    }

    fn list_connected_services(&self) -> Result<Vec<String>, HostApiError> {
        Ok(vec!["google-gmail".to_owned(), "google-calendar".to_owned(), "google-drive".to_owned()])
    }

    fn evaluate_policy(&self, _req: PolicyEvalReq) -> Result<DecisionDesc, HostApiError> {
        Ok(DecisionDesc::Allow)
    }

    fn scrub_text(&self, input: &str) -> Result<ScrubResponse, HostApiError> {
        Ok(ScrubResponse { output: input.to_owned(), matches: Vec::<ScrubMatchDesc>::new() })
    }

    fn fetch(&self, _req: FetchReq) -> Result<FetchResp, HostApiError> {
        Ok(FetchResp {
            status: 200,
            headers: Vec::new(),
            body_utf8_lossy: STUB_HTTP_BODY.to_owned(),
        })
    }

    fn current_agent_policy_name(&self) -> String {
        STUB_POLICY_NAME.to_owned()
    }

    fn current_plugin_name(&self) -> String {
        STUB_PLUGIN_NAME.to_owned()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn stub_issue_scoped_token_echoes_service_and_scope() {
        let stub = StubHostServices::new();
        let tok = stub.issue_scoped_token("google-gmail", "gmail.readonly").unwrap();
        assert_eq!(tok.bearer, STUB_BEARER);
        assert_eq!(tok.scope, "gmail.readonly");
        assert_eq!(tok.resource, "google-gmail");
        assert!(tok.expires_at_epoch_secs > 0);
    }

    #[test]
    fn stub_evaluate_policy_returns_allow() {
        let stub = StubHostServices::new();
        let req = PolicyEvalReq {
            policy_name: String::new(),
            scope: "anything".to_owned(),
            resource: None,
        };
        let decision = stub.evaluate_policy(req).unwrap();
        assert!(matches!(decision, DecisionDesc::Allow));
    }

    #[test]
    fn stub_scrub_text_passes_through() {
        let stub = StubHostServices::new();
        let resp = stub.scrub_text("hello world with ssn 123-45-6789").unwrap();
        assert_eq!(resp.output, "hello world with ssn 123-45-6789");
        assert!(resp.matches.is_empty());
    }

    #[test]
    fn stub_fetch_returns_200_ok() {
        let stub = StubHostServices::new();
        let req = FetchReq {
            method: "GET".to_owned(),
            url: "https://example.com".to_owned(),
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
        // AC #17: the stub must be usable as `Arc<dyn HostServices>`
        // for `register_host_api` — trait-object safety is a
        // load-bearing contract.
        let stub: Arc<dyn HostServices> = Arc::new(StubHostServices::new());
        // Call through the trait object to force dyn dispatch.
        assert_eq!(stub.current_agent_policy_name(), STUB_POLICY_NAME);
        assert_eq!(stub.current_plugin_name(), STUB_PLUGIN_NAME);
        let services = stub.list_connected_services().unwrap();
        assert_eq!(services.len(), 3);
    }
}
