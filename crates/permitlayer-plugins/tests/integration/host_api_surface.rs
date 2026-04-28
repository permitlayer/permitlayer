//! Integration tests for Story 6.2 host API surface.
//!
//! These tests exercise the JS-side surface end-to-end via
//! `PluginRuntime::with_host_api` with a `MockHostServices` impl
//! that returns deterministic, easily-asserted responses. The
//! production proxy-side impl (`ProxyHostServices`) has its own
//! Rust-level unit tests in
//! `crates/permitlayer-proxy/src/plugin_host_services.rs::tests`.
//!
//! Test grouping mirrors the AC numbering of the Story 6.2 spec:
//!
//! - `version_*` — AC #2, #3
//! - `oauth_*` — AC #4-#7 (incl. the load-bearing AC #5 raw-token
//!   no-leak test)
//! - `policy_enforce_*` — AC #8-#11, #31
//! - `scrub_*` — AC #12-#14
//! - `http_fetch_*` — AC #15-#21 (uses an `axum` mock server on
//!   loopback)
//! - `error_class_*` — AC #22, #23
//! - `with_host_api_*` — AC #27

use std::sync::{Arc, Mutex};

use permitlayer_plugins::{
    DecisionDesc, FetchReq, FetchResp, HostApiError, HostApiErrorCode, HostCode, HostServices,
    PluginError, PluginRuntime, PolicyEvalReq, ScopedTokenDesc, ScrubMatchDesc, ScrubResponse,
};

// ─────────────────────────────────────────────────────────────────
// Test scaffolding
// ─────────────────────────────────────────────────────────────────

/// In-test mock for `HostServices`. Each method's behavior is
/// driven by the corresponding `Mock*` field — tests configure
/// them per test. Keeps every test independent.
#[derive(Clone)]
struct MockHostServices {
    inner: Arc<Mutex<MockHostServicesInner>>,
}

struct MockHostServicesInner {
    /// Pre-canned `issue_scoped_token` responses keyed by
    /// `(service, scope)`. Falls through to error if missing.
    scoped_tokens: std::collections::HashMap<(String, String), ScopedTokenDesc>,
    /// AC #5 (Story 6.2 review finding H1): hidden raw upstream
    /// OAuth token for the load-bearing no-leak test. Set by the
    /// test fixture; the mock NEVER reads it from any
    /// `HostServices` method. If a future refactor accidentally
    /// exposes it (e.g. by adding it to `ScopedTokenDesc`), the
    /// `oauth_get_token_does_not_leak_raw_oauth_material_anywhere`
    /// test will detect the leak via grep on the rendered
    /// `JSON.stringify(result)` output.
    hidden_raw_upstream_token: String,
    /// `list_connected_services` response.
    connected_services: Vec<String>,
    /// Pre-canned `evaluate_policy` decision (returned for every call;
    /// tests that need per-call routing build a more specific mock).
    policy_decision: DecisionDesc,
    /// `scrub_text` response transformer.
    scrub_fn: Box<dyn Fn(&str) -> ScrubResponse + Send + Sync>,
    /// `fetch` response (tests inject a fixed response or override
    /// per test).
    fetch_response: Result<FetchResp, HostApiError>,
    /// Records every fetch invocation for assertion.
    fetch_history: Vec<FetchReq>,
    /// Returned by `current_agent_policy_name`.
    agent_policy: String,
    /// Returned by `current_plugin_name`.
    plugin_name: String,
}

impl MockHostServices {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockHostServicesInner {
                scoped_tokens: std::collections::HashMap::new(),
                hidden_raw_upstream_token: String::new(),
                connected_services: Vec::new(),
                policy_decision: DecisionDesc::Allow,
                scrub_fn: Box::new(|s: &str| ScrubResponse {
                    output: s.to_owned(),
                    matches: Vec::new(),
                }),
                fetch_response: Ok(FetchResp {
                    status: 200,
                    headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
                    body_utf8_lossy: String::new(),
                }),
                fetch_history: Vec::new(),
                agent_policy: "test-agent-policy".to_owned(),
                plugin_name: "test-plugin".to_owned(),
            })),
        }
    }

    fn with_scoped_token(self, service: &str, scope: &str, token: ScopedTokenDesc) -> Self {
        self.inner
            .lock()
            .unwrap()
            .scoped_tokens
            .insert((service.to_owned(), scope.to_owned()), token);
        self
    }

    /// AC #5 (review finding H1): set the HIDDEN raw upstream OAuth
    /// token. The mock never reads this field from any trait method;
    /// the test fixture seeds it and asserts it MUST NOT appear
    /// anywhere in the JSON-stringified result.
    fn with_hidden_raw_upstream_token(self, token: &str) -> Self {
        self.inner.lock().unwrap().hidden_raw_upstream_token = token.to_owned();
        self
    }

    fn with_connected_services(self, services: Vec<String>) -> Self {
        self.inner.lock().unwrap().connected_services = services;
        self
    }

    fn with_policy_decision(self, decision: DecisionDesc) -> Self {
        self.inner.lock().unwrap().policy_decision = decision;
        self
    }

    fn with_scrub_fn(self, f: impl Fn(&str) -> ScrubResponse + Send + Sync + 'static) -> Self {
        self.inner.lock().unwrap().scrub_fn = Box::new(f);
        self
    }

    fn with_fetch_response(self, resp: Result<FetchResp, HostApiError>) -> Self {
        self.inner.lock().unwrap().fetch_response = resp;
        self
    }

    #[allow(dead_code)]
    fn with_agent_policy(self, name: &str) -> Self {
        self.inner.lock().unwrap().agent_policy = name.to_owned();
        self
    }

    fn with_plugin_name(self, name: &str) -> Self {
        self.inner.lock().unwrap().plugin_name = name.to_owned();
        self
    }

    fn fetch_history(&self) -> Vec<FetchReq> {
        self.inner.lock().unwrap().fetch_history.clone()
    }

    fn into_arc_dyn(self) -> Arc<dyn HostServices> {
        Arc::new(self)
    }
}

impl HostServices for MockHostServices {
    fn issue_scoped_token(
        &self,
        service: &str,
        scope: &str,
    ) -> Result<ScopedTokenDesc, HostApiError> {
        let inner = self.inner.lock().unwrap();
        inner.scoped_tokens.get(&(service.to_owned(), scope.to_owned())).cloned().ok_or_else(|| {
            HostApiError::new(
                HostApiErrorCode::Host(HostCode::OauthUnknownService),
                false,
                format!("mock: no scoped-token configured for `{service}`/`{scope}`"),
            )
        })
    }

    fn list_connected_services(&self) -> Result<Vec<String>, HostApiError> {
        Ok(self.inner.lock().unwrap().connected_services.clone())
    }

    fn evaluate_policy(&self, _req: PolicyEvalReq) -> Result<DecisionDesc, HostApiError> {
        Ok(match &self.inner.lock().unwrap().policy_decision {
            DecisionDesc::Allow => DecisionDesc::Allow,
            DecisionDesc::Prompt { policy_name, rule_id } => {
                DecisionDesc::Prompt { policy_name: policy_name.clone(), rule_id: rule_id.clone() }
            }
            DecisionDesc::Deny { policy_name, rule_id, denied_scope, denied_resource } => {
                DecisionDesc::Deny {
                    policy_name: policy_name.clone(),
                    rule_id: rule_id.clone(),
                    denied_scope: denied_scope.clone(),
                    denied_resource: denied_resource.clone(),
                }
            }
        })
    }

    fn scrub_text(&self, input: &str) -> Result<ScrubResponse, HostApiError> {
        Ok((self.inner.lock().unwrap().scrub_fn)(input))
    }

    fn fetch(&self, req: FetchReq) -> Result<FetchResp, HostApiError> {
        let mut inner = self.inner.lock().unwrap();
        inner.fetch_history.push(req);
        match &inner.fetch_response {
            Ok(r) => Ok(r.clone()),
            Err(e) => Err(e.clone()),
        }
    }

    fn current_agent_policy_name(&self) -> String {
        // AD3 (Story 6.2 course-correction 2026-04-17): the trait
        // now returns `String`; the prior leak-on-each-call
        // workaround is gone (M4 re-review patch removed the
        // obfuscated comment that was tripping CI greps).
        self.inner.lock().unwrap().agent_policy.clone()
    }

    fn current_plugin_name(&self) -> String {
        self.inner.lock().unwrap().plugin_name.clone()
    }
}

fn fresh_runtime() -> PluginRuntime {
    PluginRuntime::new_default().unwrap()
}

/// Run a JS expression that returns a string with the host API
/// installed. Auto-awaits a Promise return value via
/// `Promise::finish` (driving the QuickJS microtask queue).
fn eval_with_host_api_string(
    rt: &PluginRuntime,
    services: &Arc<dyn HostServices>,
    src: &str,
) -> Result<String, PluginError> {
    rt.with_host_api(services, |ctx| {
        // Eval the expression as a Value; if it's a Promise,
        // drive it to resolution; otherwise extract as String
        // directly. AD2: callers no longer have to manually
        // distinguish — every host-API method returns Promise but
        // sync expressions like `agentsso.version` return a plain
        // String.
        let raw: rquickjs::Value<'_> = ctx.eval(src)?;
        if let Some(promise) = raw.as_promise() {
            let resolved: String = promise.finish::<String>()?;
            Ok(resolved)
        } else {
            let s: rquickjs::String<'_> = rquickjs::String::from_value(raw)
                .map_err(|_| rquickjs::Error::new_from_js("value", "string"))?;
            Ok(s.to_string()?)
        }
    })
}

// Convenience: register host API + run a JS-side expression that
// may return either a plain value or a Promise; auto-awaits via
// `Promise::finish`; then JSON.stringify the resolved value and
// parse on the Rust side. AD2 (Story 6.2 course-correction):
// host-API methods return Promises, so the wrapper `await`s them
// inside the JS-side IIFE so `JSON.stringify` sees the resolved
// value.
fn eval_with_host_api_json(
    rt: &PluginRuntime,
    services: &Arc<dyn HostServices>,
    expr: &str,
) -> Result<serde_json::Value, PluginError> {
    // The async-IIFE pattern: `(async () => JSON.stringify(await
    // EXPR))()` returns a Promise<String>. We then `Promise::finish`
    // to drive the microtask queue and get the resolved String,
    // which we parse as JSON.
    let wrapped = format!("(async () => JSON.stringify(await ({expr})))()");
    let s = rt.with_host_api(services, |ctx| {
        let raw: rquickjs::Value<'_> = ctx.eval(wrapped.as_str())?;
        match raw.as_promise() {
            Some(promise) => {
                let resolved: String = promise.finish::<String>()?;
                Ok(resolved)
            }
            None => {
                // Non-Promise return — should never happen for an
                // async-IIFE call but handle gracefully for tests
                // that pass sync-only expressions.
                let s: rquickjs::String<'_> = rquickjs::String::from_value(raw)
                    .map_err(|_| rquickjs::Error::new_from_js("value", "string"))?;
                Ok(s.to_string()?)
            }
        }
    })?;
    Ok(serde_json::from_str(&s).unwrap_or(serde_json::Value::Null))
}

fn allow_services() -> Arc<dyn HostServices> {
    MockHostServices::new().into_arc_dyn()
}

/// Run a JS expression that returns a Promise, await it inside the
/// JS-side via async-IIFE, and convert a Promise rejection to a
/// Rust-side `Err(PluginError)`. Returns `Ok(())` if the Promise
/// resolves successfully (the resolved value is discarded — use
/// [`eval_with_host_api_json`] when you need the value).
///
/// AD2 (Story 6.2 course-correction): tests that previously asserted
/// `throw` now assert Promise rejection. The shape conversion goes
/// from `rquickjs::Error::Exception` → `PluginError::HostApiError`
/// via the runtime's `try_extract_agentsso_error` path; the
/// async-IIFE pattern surfaces a Promise rejection as a thrown
/// exception inside the IIFE which then propagates through
/// `Promise::finish`.
fn eval_with_host_api_await_unit(
    rt: &PluginRuntime,
    services: &Arc<dyn HostServices>,
    expr: &str,
) -> Result<(), PluginError> {
    // The pattern: `(async () => { await EXPR; })()` returns a
    // Promise. If EXPR's promise rejects, the await re-throws,
    // the async-IIFE's promise rejects, and `Promise::finish`
    // returns Err. The runtime's `Ctx::catch` arm then runs
    // `try_extract_agentsso_error` and produces
    // `PluginError::HostApiError`.
    let wrapped = format!("(async () => {{ await ({expr}); }})()");
    rt.with_host_api(services, |ctx| {
        let raw: rquickjs::Value<'_> = ctx.eval(wrapped.as_str())?;
        match raw.as_promise() {
            Some(promise) => {
                let _: rquickjs::Value<'_> = promise.finish::<rquickjs::Value<'_>>()?;
                Ok(())
            }
            None => Ok(()),
        }
    })
}

// ═══════════════════════════════════════════════════════════════════
// AC #2 / #3 — agentsso.version, agentsso.versionMeetsRequirement
// ═══════════════════════════════════════════════════════════════════

mod version {
    use super::*;

    #[test]
    fn version_property_returns_host_api_version() {
        let rt = fresh_runtime();
        let svc = allow_services();
        let v = eval_with_host_api_string(&rt, &svc, "agentsso.version").unwrap();
        assert_eq!(v, permitlayer_plugins::HOST_API_VERSION);
        assert_eq!(v, "1.0.0-rc.1");
    }

    #[test]
    fn version_property_descriptor_is_non_writable_non_configurable() {
        let rt = fresh_runtime();
        let svc = allow_services();
        // `JSON.stringify(Object.getOwnPropertyDescriptor(...))` is the
        // cleanest way to inspect a descriptor across the FFI.
        let desc = eval_with_host_api_json(
            &rt,
            &svc,
            r#"Object.getOwnPropertyDescriptor(agentsso, "version")"#,
        )
        .unwrap();
        assert_eq!(desc["value"].as_str(), Some("1.0.0-rc.1"));
        assert_eq!(desc["writable"].as_bool(), Some(false));
        assert_eq!(desc["configurable"].as_bool(), Some(false));
        assert_eq!(desc["enumerable"].as_bool(), Some(true));
    }

    #[test]
    fn version_property_strict_mode_assignment_throws() {
        let rt = fresh_runtime();
        let svc = allow_services();
        // In strict mode, assigning to a non-writable property
        // throws TypeError.
        let result = rt.with_host_api(&svc, |ctx| {
            let _: rquickjs::Value = ctx.eval(
                r#"
                    "use strict";
                    agentsso.version = "9.9.9";
                "#,
            )?;
            Ok(())
        });
        assert!(
            matches!(result, Err(PluginError::JsException { .. }))
                || matches!(result, Err(PluginError::HostApiError { .. })),
            "strict-mode write to read-only property must throw; got {result:?}"
        );
    }

    #[test]
    fn version_property_assignment_throws_in_quickjs() {
        let rt = fresh_runtime();
        let svc = allow_services();
        // QuickJS throws TypeError on writes to non-writable
        // properties regardless of strict mode (more conservative
        // than V8/SpiderMonkey, which silently fail in non-strict).
        // Either behavior is acceptable for our threat model — the
        // load-bearing invariant is "the property cannot be
        // mutated to mislead other plugins," which both throw and
        // silent-fail satisfy.
        let result = rt.with_host_api(&svc, |ctx| {
            let _: rquickjs::Value = ctx.eval(r#"agentsso.version = "9.9.9";"#)?;
            Ok(())
        });
        assert!(
            matches!(result, Err(PluginError::JsException { .. })),
            "expected TypeError on write to read-only property; got {result:?}"
        );

        // Verify a fresh call still sees "1.0.0-rc.1" (no carryover).
        let v = eval_with_host_api_string(&rt, &svc, "agentsso.version").unwrap();
        assert_eq!(v, "1.0.0-rc.1");
    }

    #[test]
    fn version_meets_requirement_true_for_met_version() {
        let rt = fresh_runtime();
        let svc = allow_services();
        // HOST_API_VERSION = "1.0.0-rc.1"; ">=1.0" should be true.
        let v = eval_with_host_api_string(
            &rt,
            &svc,
            r#"String(agentsso.versionMeetsRequirement(">=1.0"))"#,
        )
        .unwrap();
        assert_eq!(v, "true");
    }

    #[test]
    fn version_meets_requirement_false_for_higher_version() {
        let rt = fresh_runtime();
        let svc = allow_services();
        let v = eval_with_host_api_string(
            &rt,
            &svc,
            r#"String(agentsso.versionMeetsRequirement(">=1.1"))"#,
        )
        .unwrap();
        assert_eq!(v, "false");
    }

    #[test]
    fn version_meets_requirement_true_for_lower_version() {
        let rt = fresh_runtime();
        let svc = allow_services();
        let v = eval_with_host_api_string(
            &rt,
            &svc,
            r#"String(agentsso.versionMeetsRequirement(">=0.9"))"#,
        )
        .unwrap();
        assert_eq!(v, "true");
    }

    #[test]
    fn version_meets_requirement_false_for_major_jump() {
        let rt = fresh_runtime();
        let svc = allow_services();
        let v = eval_with_host_api_string(
            &rt,
            &svc,
            r#"String(agentsso.versionMeetsRequirement(">=2.0"))"#,
        )
        .unwrap();
        assert_eq!(v, "false");
    }

    #[test]
    fn version_meets_requirement_throws_agentsso_error_on_malformed_input() {
        let rt = fresh_runtime();
        let svc = allow_services();
        let result = rt.with_host_api(&svc, |ctx| {
            let _: rquickjs::Value = ctx.eval(r#"agentsso.versionMeetsRequirement("garbage")"#)?;
            Ok(())
        });
        match result {
            Err(PluginError::HostApiError { code, retryable, .. }) => {
                assert!(
                    matches!(&code, HostApiErrorCode::Plugin(p) if p.as_str() == "version.malformed_requirement")
                );
                assert!(!retryable);
            }
            other => panic!("expected HostApiError(VersionMalformedRequirement); got {other:?}"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// AC #4-#7 — agentsso.oauth.{getToken, listConnectedServices}
// ═══════════════════════════════════════════════════════════════════

mod oauth {
    use super::*;

    fn token_with_bearer(bearer: &str, scope: &str, resource: &str) -> ScopedTokenDesc {
        let now = chrono::Utc::now().timestamp() as u64;
        ScopedTokenDesc {
            bearer: bearer.to_owned(),
            scope: scope.to_owned(),
            resource: resource.to_owned(),
            expires_at_epoch_secs: now + 60,
        }
    }

    #[test]
    fn oauth_get_token_returns_handle_with_60s_ttl_at_most() {
        let svc = MockHostServices::new()
            .with_scoped_token(
                "gmail",
                "gmail.readonly",
                token_with_bearer("BEARER123", "gmail.readonly", "gmail"),
            )
            .into_arc_dyn();
        let rt = fresh_runtime();
        let result = eval_with_host_api_json(
            &rt,
            &svc,
            r#"agentsso.oauth.getToken("gmail", "gmail.readonly")"#,
        )
        .unwrap();
        assert_eq!(result["bearer"].as_str(), Some("BEARER123"));
        assert_eq!(result["scope"].as_str(), Some("gmail.readonly"));
        assert_eq!(result["resource"].as_str(), Some("gmail"));
        let expires_at = result["expiresAt"].as_f64().unwrap();
        let now = chrono::Utc::now().timestamp() as f64;
        assert!(expires_at > now, "expiresAt must be in the future");
        assert!(expires_at - now <= 60.0, "expiresAt - now must be ≤60s; got {}", expires_at - now);
    }

    /// M1 (re-review patch 2026-04-18): demonstration that the
    /// AC #5 sentinel-grep test CAN fail when the leak path
    /// exists. Runs a deliberately-buggy mock that exposes the
    /// "hidden" raw upstream token in the public `bearer` field
    /// — proves the sentinel-grep assertion catches the leak in
    /// principle. Marked `#[ignore]` so it doesn't fire on every
    /// `cargo test` run; invoke via `cargo test --ignored
    /// oauth_leak_test_can_fail_demo` to manually verify the
    /// AC #5 assertion has teeth.
    #[test]
    #[ignore = "AC #5 self-test: deliberately leaks the sentinel; run with --ignored to verify"]
    fn oauth_leak_test_can_fail_demo() {
        struct LeakyMock;
        impl HostServices for LeakyMock {
            fn issue_scoped_token(
                &self,
                _service: &str,
                _scope: &str,
            ) -> Result<ScopedTokenDesc, HostApiError> {
                // BUG: bearer aliases the sentinel — simulates a
                // future refactor that accidentally exposes the
                // raw upstream OAuth token in the bearer field.
                Ok(ScopedTokenDesc {
                    bearer: "RAW_OAUTH_ACCESS_TOKEN_NEVER_LEAK_ME".to_owned(),
                    scope: "gmail.readonly".to_owned(),
                    resource: "gmail".to_owned(),
                    expires_at_epoch_secs: 9_999_999_999,
                })
            }
            fn list_connected_services(&self) -> Result<Vec<String>, HostApiError> {
                Ok(Vec::new())
            }
            fn evaluate_policy(&self, _req: PolicyEvalReq) -> Result<DecisionDesc, HostApiError> {
                Ok(DecisionDesc::Allow)
            }
            fn scrub_text(&self, _input: &str) -> Result<ScrubResponse, HostApiError> {
                Ok(ScrubResponse { output: String::new(), matches: Vec::new() })
            }
            fn fetch(&self, _req: FetchReq) -> Result<FetchResp, HostApiError> {
                Ok(FetchResp { status: 200, headers: Vec::new(), body_utf8_lossy: String::new() })
            }
            fn current_agent_policy_name(&self) -> String {
                "test".to_owned()
            }
            fn current_plugin_name(&self) -> String {
                "test".to_owned()
            }
        }
        let svc: Arc<dyn HostServices> = Arc::new(LeakyMock);
        let rt = fresh_runtime();
        let result = eval_with_host_api_json(
            &rt,
            &svc,
            r#"agentsso.oauth.getToken("gmail", "gmail.readonly")"#,
        )
        .unwrap();
        let stringified = serde_json::to_string(&result).unwrap();
        // This assertion MUST fail when the LeakyMock is used —
        // proving the sentinel-grep assertion in the real test
        // catches the leak. If this test passes (i.e. the
        // sentinel does NOT appear in the result), the AC #5
        // assertion is broken.
        assert!(
            stringified.contains("RAW_OAUTH_ACCESS_TOKEN_NEVER_LEAK_ME"),
            "M1 self-test inverted: LeakyMock failed to leak the sentinel; the real AC #5 \
             test would have nothing to detect. Investigate the mock + assertion shape."
        );
    }

    #[test]
    fn oauth_get_token_does_not_leak_raw_oauth_material_anywhere() {
        // AC #5 (REWRITTEN per Story 6.2 review finding H1 + AD5):
        // load-bearing AR29 invariant. The previous form put the
        // sentinel in the public `bearer` field, which made the
        // test structurally incapable of catching the leak it was
        // designed to prevent. This form puts the sentinel in a
        // HIDDEN field on the mock that NO `HostServices` trait
        // method reads — and asserts the sentinel MUST NOT appear
        // anywhere in the JSON-stringified result.
        //
        // The sentinel string MUST appear EXACTLY TWICE in the
        // codebase: once as the mock fixture value below, once as
        // the assertion's substring check. A grep finding a third
        // occurrence is a red flag (it would mean some code path
        // is exposing raw OAuth material).
        let sentinel = "RAW_OAUTH_ACCESS_TOKEN_NEVER_LEAK_ME";
        let svc = MockHostServices::new()
            // The bearer is a normal HS256-shaped scoped-token
            // string (NOT the sentinel) — this is what the plugin
            // is supposed to receive.
            .with_scoped_token(
                "gmail",
                "gmail.readonly",
                token_with_bearer("scoped_hs256_bearer_xyz", "gmail.readonly", "gmail"),
            )
            // The sentinel goes into the HIDDEN field that
            // simulates the actual upstream OAuth access_token.
            // The mock never reads this field. If a future
            // refactor accidentally exposes it (e.g. by aliasing
            // it into ScopedTokenDesc.bearer), this test fails.
            .with_hidden_raw_upstream_token(sentinel)
            .into_arc_dyn();
        let rt = fresh_runtime();
        let result = eval_with_host_api_json(
            &rt,
            &svc,
            r#"agentsso.oauth.getToken("gmail", "gmail.readonly")"#,
        )
        .unwrap();
        // Render the result back to a JSON string so we can grep
        // every byte for the sentinel. The sentinel string
        // appears EXACTLY TWICE in this file — once as the mock
        // fixture value above, once as the assertion's substring
        // check below — per AC #5 (Story 6.2 review finding H1).
        let stringified = serde_json::to_string(&result).unwrap();
        assert!(
            !stringified.contains("RAW_OAUTH_ACCESS_TOKEN_NEVER_LEAK_ME"),
            "AR29 violation: raw upstream OAuth token leaked into plugin-visible result. \
             Result was: {stringified}"
        );
        // Suppress unused-variable warning — `sentinel` is held
        // for grep correlation with the mock fixture above.
        let _ = sentinel;
        // Defense-in-depth: also assert the public surface has
        // exactly the four documented keys. Extra keys would
        // indicate an alternative leak path.
        let obj = result.as_object().unwrap();
        let mut keys: Vec<&String> = obj.keys().collect();
        keys.sort();
        let expected: Vec<&str> = vec!["bearer", "expiresAt", "resource", "scope"];
        let actual: Vec<&str> = keys.iter().map(|k| k.as_str()).collect();
        assert_eq!(actual, expected, "result must have exactly the documented keys");
    }

    #[test]
    fn oauth_get_token_throws_unknown_service_for_missing_vault_entry() {
        let svc = MockHostServices::new().into_arc_dyn();
        let rt = fresh_runtime();
        // AD2: getToken returns a Promise that REJECTS on unknown
        // service. The await_unit helper surfaces the rejection
        // as PluginError::HostApiError via the runtime's class-
        // identity extraction.
        let result = eval_with_host_api_await_unit(
            &rt,
            &svc,
            r#"agentsso.oauth.getToken("unknown", "scope")"#,
        );
        match result {
            Err(PluginError::HostApiError { code, retryable, .. }) => {
                assert!(
                    matches!(&code, HostApiErrorCode::Plugin(p) if p.as_str() == "oauth.unknown_service")
                );
                assert!(!retryable);
            }
            other => panic!("expected OauthUnknownService; got {other:?}"),
        }
    }

    #[test]
    fn oauth_get_token_requires_explicit_scope() {
        let svc = MockHostServices::new().into_arc_dyn();
        let rt = fresh_runtime();
        let result =
            eval_with_host_api_await_unit(&rt, &svc, r#"agentsso.oauth.getToken("gmail")"#);
        match result {
            Err(PluginError::HostApiError { code, .. }) => {
                assert!(
                    matches!(&code, HostApiErrorCode::Plugin(p) if p.as_str() == "oauth.scope_required")
                );
            }
            other => panic!("expected OauthScopeRequired; got {other:?}"),
        }
    }

    #[test]
    fn oauth_list_connected_services_returns_array() {
        let svc = MockHostServices::new()
            .with_connected_services(vec![
                "calendar".to_owned(),
                "drive".to_owned(),
                "gmail".to_owned(),
            ])
            .into_arc_dyn();
        let rt = fresh_runtime();
        let result =
            eval_with_host_api_json(&rt, &svc, r#"agentsso.oauth.listConnectedServices()"#)
                .unwrap();
        let names: Vec<&str> =
            result.as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(names, vec!["calendar", "drive", "gmail"]);
    }
}

// ═══════════════════════════════════════════════════════════════════
// AC #8-#11, #31 — agentsso.policy.enforce
// ═══════════════════════════════════════════════════════════════════

mod policy_enforce {
    use super::*;

    #[test]
    fn allow_decision_returns_simple_object() {
        let svc = MockHostServices::new().with_policy_decision(DecisionDesc::Allow).into_arc_dyn();
        let rt = fresh_runtime();
        let result = eval_with_host_api_json(
            &rt,
            &svc,
            r#"agentsso.policy.enforce({scope: "gmail.readonly"})"#,
        )
        .unwrap();
        let obj = result.as_object().unwrap();
        assert_eq!(obj["decision"].as_str(), Some("allow"));
        assert_eq!(obj.len(), 1, "Allow decision must have only `decision` field; got {obj:?}");
    }

    #[test]
    fn deny_decision_carries_rule_id_and_denied_scope() {
        let svc = MockHostServices::new()
            .with_policy_decision(DecisionDesc::Deny {
                policy_name: "jamie".to_owned(),
                rule_id: "default-deny-scope-out-of-allowlist".to_owned(),
                denied_scope: Some("gmail.modify".to_owned()),
                denied_resource: None,
            })
            .into_arc_dyn();
        let rt = fresh_runtime();
        let result = eval_with_host_api_json(
            &rt,
            &svc,
            r#"agentsso.policy.enforce({scope: "gmail.modify"})"#,
        )
        .unwrap();
        assert_eq!(result["decision"].as_str(), Some("deny"));
        assert_eq!(result["policyName"].as_str(), Some("jamie"));
        assert_eq!(result["ruleId"].as_str(), Some("default-deny-scope-out-of-allowlist"));
        assert_eq!(result["deniedScope"].as_str(), Some("gmail.modify"));
        assert!(result["deniedResource"].is_null());
    }

    #[test]
    fn prompt_decision_carries_policy_and_rule_ids() {
        let svc = MockHostServices::new()
            .with_policy_decision(DecisionDesc::Prompt {
                policy_name: "jamie".to_owned(),
                rule_id: "default-prompt-approval-mode".to_owned(),
            })
            .into_arc_dyn();
        let rt = fresh_runtime();
        let result = eval_with_host_api_json(
            &rt,
            &svc,
            r#"agentsso.policy.enforce({scope: "gmail.readonly"})"#,
        )
        .unwrap();
        assert_eq!(result["decision"].as_str(), Some("prompt"));
        assert_eq!(result["policyName"].as_str(), Some("jamie"));
        assert_eq!(result["ruleId"].as_str(), Some("default-prompt-approval-mode"));
    }

    #[test]
    fn json_stringify_output_is_deterministic_and_camelcase() {
        // AC #31: Deterministic JSON shape, exact field names, null
        // for absent optional fields.
        let svc = MockHostServices::new()
            .with_policy_decision(DecisionDesc::Deny {
                policy_name: "p".to_owned(),
                rule_id: "r".to_owned(),
                denied_scope: Some("s".to_owned()),
                denied_resource: None,
            })
            .into_arc_dyn();
        let rt = fresh_runtime();
        // AD2: policy.enforce returns a Promise; JSON.stringify of
        // a Promise is `"{}"` (no own enumerable props). Need to
        // await first.
        let raw = eval_with_host_api_string(
            &rt,
            &svc,
            r#"(async () => JSON.stringify(await agentsso.policy.enforce({scope: "any"})))()"#,
        )
        .unwrap();
        // Direct string equality: the output must be deterministic
        // for plugins to round-trip it via `JSON.parse`.
        assert_eq!(
            raw,
            r#"{"decision":"deny","policyName":"p","ruleId":"r","deniedScope":"s","deniedResource":null}"#
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// AC #12-#14 — agentsso.scrub.{text, object}
// ═══════════════════════════════════════════════════════════════════

mod scrub {
    use super::*;

    fn otp_scrub_fn(input: &str) -> ScrubResponse {
        // Fake "OTP redactor" mock — replaces "123456" with placeholder.
        let placeholder = "<REDACTED_OTP>";
        if let Some(pos) = input.find("123456") {
            let mut output = String::new();
            output.push_str(&input[..pos]);
            output.push_str(placeholder);
            output.push_str(&input[pos + 6..]);
            ScrubResponse {
                output,
                matches: vec![ScrubMatchDesc {
                    rule_id: "otp-6digit".to_owned(),
                    placeholder: placeholder.to_owned(),
                    span_offset: pos,
                    span_length: placeholder.len(),
                }],
            }
        } else {
            ScrubResponse { output: input.to_owned(), matches: Vec::new() }
        }
    }

    #[test]
    fn scrub_text_redacts_otp_and_returns_match_metadata() {
        let svc = MockHostServices::new().with_scrub_fn(otp_scrub_fn).into_arc_dyn();
        let rt = fresh_runtime();
        let result = eval_with_host_api_json(
            &rt,
            &svc,
            r#"agentsso.scrub.text("Your verification code is 123456")"#,
        )
        .unwrap();
        assert_eq!(result["output"].as_str(), Some("Your verification code is <REDACTED_OTP>"));
        let matches = result["matches"].as_array().unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0]["ruleId"].as_str(), Some("otp-6digit"));
        assert_eq!(matches[0]["placeholder"].as_str(), Some("<REDACTED_OTP>"));
    }

    #[test]
    fn scrub_text_throws_invalid_input_on_undefined() {
        let svc = MockHostServices::new().with_scrub_fn(otp_scrub_fn).into_arc_dyn();
        let rt = fresh_runtime();
        // AD2: scrub.text returns a Promise that REJECTS on
        // non-coercible input.
        let result = eval_with_host_api_await_unit(&rt, &svc, "agentsso.scrub.text(undefined)");
        match result {
            Err(PluginError::HostApiError { code, .. }) => {
                assert!(
                    matches!(&code, HostApiErrorCode::Plugin(p) if p.as_str() == "scrub.invalid_input")
                );
            }
            other => panic!("expected ScrubInvalidInput; got {other:?}"),
        }
    }

    #[test]
    fn scrub_text_coerces_number_to_string() {
        let svc = MockHostServices::new().with_scrub_fn(otp_scrub_fn).into_arc_dyn();
        let rt = fresh_runtime();
        let result = eval_with_host_api_json(&rt, &svc, "agentsso.scrub.text(42)").unwrap();
        assert_eq!(result["output"].as_str(), Some("42"));
        assert!(result["matches"].as_array().unwrap().is_empty());
    }

    #[test]
    fn scrub_object_recurses_preserving_shape() {
        let svc = MockHostServices::new().with_scrub_fn(otp_scrub_fn).into_arc_dyn();
        let rt = fresh_runtime();
        let result = eval_with_host_api_json(
            &rt,
            &svc,
            r#"
                agentsso.scrub.object({
                    nested: { code: "Your code is 123456", count: 5 },
                    tags: ["a", "OTP 123456"]
                })
            "#,
        )
        .unwrap();
        assert_eq!(
            result["output"]["nested"]["code"].as_str(),
            Some("Your code is <REDACTED_OTP>")
        );
        // Number passes through unchanged.
        assert_eq!(result["output"]["nested"]["count"].as_i64(), Some(5));
        assert_eq!(result["output"]["tags"][0].as_str(), Some("a"));
        assert_eq!(result["output"]["tags"][1].as_str(), Some("OTP <REDACTED_OTP>"));
        // Two strings had matches → two entries in the matches array.
        let matches = result["matches"].as_array().unwrap();
        assert_eq!(matches.len(), 2);
    }
}

// ═══════════════════════════════════════════════════════════════════
// AC #15-#21 — agentsso.http.fetch
// ═══════════════════════════════════════════════════════════════════

mod http_fetch {
    use super::*;

    fn ok_resp(body: &str) -> FetchResp {
        FetchResp {
            status: 200,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body_utf8_lossy: body.to_owned(),
        }
    }

    #[test]
    fn http_fetch_basic_roundtrip_returns_status_headers_body() {
        let svc = MockHostServices::new()
            .with_fetch_response(Ok(ok_resp("{\"ok\":true}")))
            .into_arc_dyn();
        let rt = fresh_runtime();
        let result =
            eval_with_host_api_json(&rt, &svc, r#"agentsso.http.fetch("https://example.com/")"#)
                .unwrap();
        assert_eq!(result["status"].as_i64(), Some(200));
        assert_eq!(result["headers"]["content-type"].as_str(), Some("application/json"));
        assert_eq!(result["body"].as_str(), Some("{\"ok\":true}"));
    }

    #[test]
    fn http_fetch_blocks_file_scheme() {
        let svc = MockHostServices::new().into_arc_dyn();
        let rt = fresh_runtime();
        let result = eval_with_host_api_await_unit(
            &rt,
            &svc,
            r#"agentsso.http.fetch("file:///etc/passwd")"#,
        );
        match result {
            Err(PluginError::HostApiError { code, .. }) => {
                assert!(
                    matches!(&code, HostApiErrorCode::Plugin(p) if p.as_str() == "http.scheme_not_allowed")
                );
            }
            other => panic!("expected HttpSchemeNotAllowed for file://; got {other:?}"),
        }
    }

    #[test]
    fn http_fetch_blocks_data_scheme() {
        let svc = MockHostServices::new().into_arc_dyn();
        let rt = fresh_runtime();
        let result = eval_with_host_api_await_unit(
            &rt,
            &svc,
            r#"agentsso.http.fetch("data:text/plain,hi")"#,
        );
        assert!(matches!(
            result,
            Err(PluginError::HostApiError { code, .. }) if code.to_string() == "http.scheme_not_allowed"
        ));
    }

    #[test]
    fn http_fetch_blocks_javascript_scheme() {
        let svc = MockHostServices::new().into_arc_dyn();
        let rt = fresh_runtime();
        let result = eval_with_host_api_await_unit(
            &rt,
            &svc,
            r#"agentsso.http.fetch("javascript:alert(1)")"#,
        );
        assert!(matches!(
            result,
            Err(PluginError::HostApiError { code, .. }) if code.to_string() == "http.scheme_not_allowed"
        ));
    }

    #[test]
    fn http_fetch_blocks_ws_scheme() {
        let svc = MockHostServices::new().into_arc_dyn();
        let rt = fresh_runtime();
        let result =
            eval_with_host_api_await_unit(&rt, &svc, r#"agentsso.http.fetch("ws://localhost/")"#);
        assert!(matches!(
            result,
            Err(PluginError::HostApiError { code, .. }) if code.to_string() == "http.scheme_not_allowed"
        ));
    }

    #[test]
    fn http_fetch_injects_default_user_agent_when_plugin_omits() {
        let mock = MockHostServices::new()
            .with_plugin_name("notion")
            .with_fetch_response(Ok(ok_resp("ok")));
        let svc: Arc<dyn HostServices> = Arc::new(mock.clone());
        let rt = fresh_runtime();
        let _ =
            eval_with_host_api_json(&rt, &svc, r#"agentsso.http.fetch("https://example.com/")"#)
                .unwrap();
        let history = mock.fetch_history();
        assert_eq!(history.len(), 1);
        let ua = history[0]
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
            .expect("User-Agent must be present");
        assert_eq!(ua.1, "permitlayer-plugin/1.0.0-rc.1/notion");
    }

    #[test]
    fn http_fetch_appends_to_plugin_provided_user_agent() {
        let mock = MockHostServices::new()
            .with_plugin_name("notion")
            .with_fetch_response(Ok(ok_resp("ok")));
        let svc: Arc<dyn HostServices> = Arc::new(mock.clone());
        let rt = fresh_runtime();
        let _ = eval_with_host_api_json(
            &rt,
            &svc,
            r#"agentsso.http.fetch("https://example.com/", { headers: { "User-Agent": "custom/1.0" } })"#,
        )
        .unwrap();
        let history = mock.fetch_history();
        let ua = history[0]
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
            .expect("User-Agent must be present");
        assert_eq!(ua.1, "custom/1.0 permitlayer-plugin/1.0.0-rc.1/notion");
    }

    #[test]
    fn http_fetch_post_with_string_body() {
        let mock = MockHostServices::new().with_fetch_response(Ok(ok_resp("echo")));
        let svc: Arc<dyn HostServices> = Arc::new(mock.clone());
        let rt = fresh_runtime();
        let _ = eval_with_host_api_json(
            &rt,
            &svc,
            r#"
                agentsso.http.fetch("https://example.com/echo", {
                    method: "POST",
                    headers: { "content-type": "application/json" },
                    body: JSON.stringify({hello: "world"})
                })
            "#,
        )
        .unwrap();
        let history = mock.fetch_history();
        assert_eq!(history[0].method, "POST");
        assert_eq!(history[0].body.as_deref(), Some(b"{\"hello\":\"world\"}".as_slice()));
        let ct = history[0]
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .unwrap();
        assert_eq!(ct.1, "application/json");
    }

    #[test]
    fn http_fetch_uint8array_body() {
        let mock = MockHostServices::new().with_fetch_response(Ok(ok_resp("ok")));
        let svc: Arc<dyn HostServices> = Arc::new(mock.clone());
        let rt = fresh_runtime();
        let _ = eval_with_host_api_json(
            &rt,
            &svc,
            r#"
                agentsso.http.fetch("https://example.com/", {
                    method: "POST",
                    body: new Uint8Array([0x48, 0x49])
                })
            "#,
        )
        .unwrap();
        let history = mock.fetch_history();
        assert_eq!(history[0].body.as_deref(), Some(b"HI".as_slice()));
    }

    #[test]
    fn http_fetch_surfaces_host_api_error() {
        // Mock returns an HttpTimeout — the JS side must see a
        // thrown AgentssoError with the same code.
        let svc = MockHostServices::new()
            .with_fetch_response(Err(HostApiError::new(
                HostApiErrorCode::Host(HostCode::HttpTimeout),
                true,
                "mock timeout".to_owned(),
            )))
            .into_arc_dyn();
        let rt = fresh_runtime();
        let result = eval_with_host_api_await_unit(
            &rt,
            &svc,
            r#"agentsso.http.fetch("https://example.com/")"#,
        );
        match result {
            Err(PluginError::HostApiError { code, retryable, .. }) => {
                assert!(
                    matches!(&code, HostApiErrorCode::Plugin(p) if p.as_str() == "http.timeout")
                );
                assert!(retryable);
            }
            other => panic!("expected HttpTimeout HostApiError; got {other:?}"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// AC #22-#23 — globalThis.AgentssoError class
// ═══════════════════════════════════════════════════════════════════

mod error_class {
    use super::*;

    #[test]
    fn agentsso_error_class_is_function_at_global_scope() {
        let rt = fresh_runtime();
        let svc = allow_services();
        let v = eval_with_host_api_string(&rt, &svc, "typeof AgentssoError").unwrap();
        assert_eq!(v, "function");
    }

    #[test]
    fn agentsso_error_instance_is_instance_of_error() {
        let rt = fresh_runtime();
        let svc = allow_services();
        let v = eval_with_host_api_string(
            &rt,
            &svc,
            "String(new AgentssoError('msg', {code: 'c', retryable: true}) instanceof Error)",
        )
        .unwrap();
        assert_eq!(v, "true");
    }

    #[test]
    fn agentsso_error_carries_code_retryable_message() {
        let rt = fresh_runtime();
        let svc = allow_services();
        let v = eval_with_host_api_json(
            &rt,
            &svc,
            r#"
                (function() {
                    var e = new AgentssoError("hello", {code: "x.y.z", retryable: true});
                    return {name: e.name, message: e.message, code: e.code, retryable: e.retryable};
                })()
            "#,
        )
        .unwrap();
        assert_eq!(v["name"].as_str(), Some("AgentssoError"));
        assert_eq!(v["message"].as_str(), Some("hello"));
        assert_eq!(v["code"].as_str(), Some("x.y.z"));
        assert_eq!(v["retryable"].as_bool(), Some(true));
    }

    #[test]
    fn plugin_thrown_agentsso_error_round_trips_to_host_api_error() {
        // AC #23: a plugin-thrown `AgentssoError` with custom code
        // round-trips via `Other(String)`.
        let rt = fresh_runtime();
        let svc = allow_services();
        let result = rt.with_host_api(&svc, |ctx| {
            let _: rquickjs::Value = ctx.eval(
                r#"
                    throw new AgentssoError("boom", {
                        code: "plugin.custom",
                        retryable: true
                    });
                "#,
            )?;
            Ok(())
        });
        match result {
            Err(PluginError::HostApiError { code, retryable, message }) => {
                // Plugin-thrown codes route to Plugin(...) variant; compare via Display
                // (PluginThrownCode constructor is pub(crate) so we check the string form).
                assert!(
                    matches!(&code, HostApiErrorCode::Plugin(p) if p.as_str() == "plugin.custom")
                );
                assert!(retryable);
                assert_eq!(message, "boom");
            }
            other => panic!("expected HostApiError(Other('plugin.custom')); got {other:?}"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// AC #27 — with_host_api installs the full surface
// ═══════════════════════════════════════════════════════════════════

mod with_host_api_surface {
    use super::*;

    #[test]
    fn full_surface_is_present() {
        let rt = fresh_runtime();
        let svc = allow_services();
        // Sanity-check every documented entry point.
        let surface = eval_with_host_api_json(
            &rt,
            &svc,
            r#"
                ({
                    version: typeof agentsso.version,
                    versionMeetsRequirement: typeof agentsso.versionMeetsRequirement,
                    oauth_getToken: typeof agentsso.oauth.getToken,
                    oauth_listConnectedServices: typeof agentsso.oauth.listConnectedServices,
                    policy_enforce: typeof agentsso.policy.enforce,
                    scrub_text: typeof agentsso.scrub.text,
                    scrub_object: typeof agentsso.scrub.object,
                    http_fetch: typeof agentsso.http.fetch,
                    AgentssoError: typeof AgentssoError,
                })
            "#,
        )
        .unwrap();
        assert_eq!(surface["version"].as_str(), Some("string"));
        assert_eq!(surface["versionMeetsRequirement"].as_str(), Some("function"));
        assert_eq!(surface["oauth_getToken"].as_str(), Some("function"));
        assert_eq!(surface["oauth_listConnectedServices"].as_str(), Some("function"));
        assert_eq!(surface["policy_enforce"].as_str(), Some("function"));
        assert_eq!(surface["scrub_text"].as_str(), Some("function"));
        assert_eq!(surface["scrub_object"].as_str(), Some("function"));
        assert_eq!(surface["http_fetch"].as_str(), Some("function"));
        assert_eq!(surface["AgentssoError"].as_str(), Some("function"));
    }
}

// ═══════════════════════════════════════════════════════════════════
// Re-review patches (2026-04-18)
// ═══════════════════════════════════════════════════════════════════

/// AC #4/#7/#8/#12 + H16 (re-review patch): Promise-shape
/// assertions. Verifies `result instanceof Promise === true` for
/// every host-API method that's documented as Promise-returning
/// per AD2.
mod promise_shape_assertions {
    use super::*;

    #[test]
    fn oauth_get_token_returns_promise() {
        let svc = MockHostServices::new()
            .with_scoped_token(
                "gmail",
                "gmail.readonly",
                ScopedTokenDesc {
                    bearer: "b".to_owned(),
                    scope: "gmail.readonly".to_owned(),
                    resource: "gmail".to_owned(),
                    expires_at_epoch_secs: chrono::Utc::now().timestamp() as u64 + 60,
                },
            )
            .into_arc_dyn();
        let rt = fresh_runtime();
        let v = eval_with_host_api_string(
            &rt,
            &svc,
            r#"String(agentsso.oauth.getToken("gmail", "gmail.readonly") instanceof Promise)"#,
        )
        .unwrap();
        assert_eq!(v, "true");
    }

    #[test]
    fn oauth_list_connected_services_returns_promise() {
        let svc = allow_services();
        let rt = fresh_runtime();
        let v = eval_with_host_api_string(
            &rt,
            &svc,
            r#"String(agentsso.oauth.listConnectedServices() instanceof Promise)"#,
        )
        .unwrap();
        assert_eq!(v, "true");
    }

    #[test]
    fn policy_enforce_returns_promise() {
        let svc = MockHostServices::new().with_policy_decision(DecisionDesc::Allow).into_arc_dyn();
        let rt = fresh_runtime();
        let v = eval_with_host_api_string(
            &rt,
            &svc,
            r#"String(agentsso.policy.enforce({scope: "gmail.readonly"}) instanceof Promise)"#,
        )
        .unwrap();
        assert_eq!(v, "true");
    }

    #[test]
    fn scrub_text_returns_promise() {
        let svc = MockHostServices::new()
            .with_scrub_fn(|s| ScrubResponse { output: s.to_owned(), matches: Vec::new() })
            .into_arc_dyn();
        let rt = fresh_runtime();
        let v = eval_with_host_api_string(
            &rt,
            &svc,
            r#"String(agentsso.scrub.text("hello") instanceof Promise)"#,
        )
        .unwrap();
        assert_eq!(v, "true");
    }

    #[test]
    fn scrub_object_returns_promise() {
        let svc = MockHostServices::new()
            .with_scrub_fn(|s| ScrubResponse { output: s.to_owned(), matches: Vec::new() })
            .into_arc_dyn();
        let rt = fresh_runtime();
        let v = eval_with_host_api_string(
            &rt,
            &svc,
            r#"String(agentsso.scrub.object({a: "b"}) instanceof Promise)"#,
        )
        .unwrap();
        assert_eq!(v, "true");
    }

    #[test]
    fn http_fetch_returns_promise() {
        let svc = MockHostServices::new()
            .with_fetch_response(Ok(FetchResp {
                status: 200,
                headers: Vec::new(),
                body_utf8_lossy: String::new(),
            }))
            .into_arc_dyn();
        let rt = fresh_runtime();
        let v = eval_with_host_api_string(
            &rt,
            &svc,
            r#"String(agentsso.http.fetch("https://example.com/") instanceof Promise)"#,
        )
        .unwrap();
        assert_eq!(v, "true");
    }
}

/// AC #6 / H21: missing oauth-error sub-tests (3 of 4).
/// `unknown_service` is already covered above; this module adds
/// `scope_denied`, `invalid_grant_not_retryable`, and
/// `refresh_exhausted_retryable`.
mod oauth_get_token_errors {
    use super::*;

    fn services_with_token_error(err: HostApiError) -> Arc<dyn HostServices> {
        // The mock returns Err from issue_scoped_token only when the
        // (service, scope) key isn't pre-canned. To inject a SPECIFIC
        // error code, we use a custom mock impl. The simplest path:
        // use a `MockHostServicesWithCannedTokenErr` that always
        // returns the supplied Err.
        struct M(HostApiError);
        impl HostServices for M {
            fn issue_scoped_token(
                &self,
                _service: &str,
                _scope: &str,
            ) -> Result<ScopedTokenDesc, HostApiError> {
                Err(self.0.clone())
            }
            fn list_connected_services(&self) -> Result<Vec<String>, HostApiError> {
                Ok(Vec::new())
            }
            fn evaluate_policy(&self, _req: PolicyEvalReq) -> Result<DecisionDesc, HostApiError> {
                Ok(DecisionDesc::Allow)
            }
            fn scrub_text(&self, _input: &str) -> Result<ScrubResponse, HostApiError> {
                Ok(ScrubResponse { output: String::new(), matches: Vec::new() })
            }
            fn fetch(&self, _req: FetchReq) -> Result<FetchResp, HostApiError> {
                Ok(FetchResp { status: 200, headers: Vec::new(), body_utf8_lossy: String::new() })
            }
            fn current_agent_policy_name(&self) -> String {
                "test".to_owned()
            }
            fn current_plugin_name(&self) -> String {
                "test".to_owned()
            }
        }
        Arc::new(M(err))
    }

    #[test]
    fn scope_denied() {
        let svc = services_with_token_error(HostApiError::new(
            HostApiErrorCode::Host(HostCode::OauthScopeDenied),
            false,
            "scope not in allowlist".to_owned(),
        ));
        let rt = fresh_runtime();
        let result = eval_with_host_api_await_unit(
            &rt,
            &svc,
            r#"agentsso.oauth.getToken("gmail", "admin.everything")"#,
        );
        match result {
            Err(PluginError::HostApiError { code, retryable, .. }) => {
                assert!(
                    matches!(&code, HostApiErrorCode::Plugin(p) if p.as_str() == "oauth.scope_denied")
                );
                assert!(!retryable);
            }
            other => panic!("expected OauthScopeDenied; got {other:?}"),
        }
    }

    #[test]
    fn invalid_grant_not_retryable() {
        let svc = services_with_token_error(HostApiError::new(
            HostApiErrorCode::Host(HostCode::OauthRefreshFailed),
            false,
            "invalid_grant".to_owned(),
        ));
        let rt = fresh_runtime();
        let result = eval_with_host_api_await_unit(
            &rt,
            &svc,
            r#"agentsso.oauth.getToken("gmail", "gmail.readonly")"#,
        );
        match result {
            Err(PluginError::HostApiError { code, retryable, .. }) => {
                assert!(
                    matches!(&code, HostApiErrorCode::Plugin(p) if p.as_str() == "oauth.refresh_failed")
                );
                assert!(!retryable);
            }
            other => panic!("expected OauthRefreshFailed (non-retryable); got {other:?}"),
        }
    }

    #[test]
    fn refresh_exhausted_retryable() {
        let svc = services_with_token_error(HostApiError::new(
            HostApiErrorCode::Host(HostCode::OauthRefreshFailed),
            true,
            "exhausted".to_owned(),
        ));
        let rt = fresh_runtime();
        let result = eval_with_host_api_await_unit(
            &rt,
            &svc,
            r#"agentsso.oauth.getToken("gmail", "gmail.readonly")"#,
        );
        match result {
            Err(PluginError::HostApiError { code, retryable, .. }) => {
                assert!(
                    matches!(&code, HostApiErrorCode::Plugin(p) if p.as_str() == "oauth.refresh_failed")
                );
                assert!(retryable);
            }
            other => panic!("expected OauthRefreshFailed (retryable); got {other:?}"),
        }
    }
}

/// AC #11 / H21: missing default-vs-explicit policyName tests.
mod policy_enforce_policy_name {
    use super::*;

    /// Mock that captures the `policy_name` it sees in
    /// `evaluate_policy` calls + returns a Deny decision so tests
    /// can read the routed name back.
    #[derive(Default)]
    struct PolicyNameCapture {
        seen: Mutex<Vec<String>>,
    }
    impl HostServices for PolicyNameCapture {
        fn issue_scoped_token(
            &self,
            _service: &str,
            _scope: &str,
        ) -> Result<ScopedTokenDesc, HostApiError> {
            unreachable!()
        }
        fn list_connected_services(&self) -> Result<Vec<String>, HostApiError> {
            unreachable!()
        }
        fn evaluate_policy(&self, req: PolicyEvalReq) -> Result<DecisionDesc, HostApiError> {
            self.seen.lock().unwrap().push(req.policy_name.clone());
            Ok(DecisionDesc::Deny {
                policy_name: req.policy_name,
                rule_id: "test-rule".to_owned(),
                denied_scope: Some(req.scope),
                denied_resource: req.resource,
            })
        }
        fn scrub_text(&self, _input: &str) -> Result<ScrubResponse, HostApiError> {
            unreachable!()
        }
        fn fetch(&self, _req: FetchReq) -> Result<FetchResp, HostApiError> {
            unreachable!()
        }
        fn current_agent_policy_name(&self) -> String {
            "default-agent-policy".to_owned()
        }
        fn current_plugin_name(&self) -> String {
            "test".to_owned()
        }
    }

    #[test]
    fn policy_enforce_default_policy_name() {
        let mock = std::sync::Arc::new(PolicyNameCapture::default());
        let svc: Arc<dyn HostServices> = mock.clone();
        let rt = fresh_runtime();
        let result =
            eval_with_host_api_json(&rt, &svc, r#"agentsso.policy.enforce({scope: "any"})"#)
                .unwrap();
        assert_eq!(result["policyName"].as_str(), Some("default-agent-policy"));
        assert_eq!(mock.seen.lock().unwrap().last().unwrap(), "default-agent-policy");
    }

    #[test]
    fn policy_enforce_explicit_policy_name_override() {
        let mock = std::sync::Arc::new(PolicyNameCapture::default());
        let svc: Arc<dyn HostServices> = mock.clone();
        let rt = fresh_runtime();
        let result = eval_with_host_api_json(
            &rt,
            &svc,
            r#"agentsso.policy.enforce({scope: "any", policyName: "restrictive"})"#,
        )
        .unwrap();
        assert_eq!(result["policyName"].as_str(), Some("restrictive"));
        assert_eq!(mock.seen.lock().unwrap().last().unwrap(), "restrictive");
    }
}

/// AC #13 / M11: scrub.object depth-limit test.
mod scrub_object_depth_limit {
    use super::*;

    #[test]
    fn scrub_object_depth_limit_throws() {
        let svc = MockHostServices::new()
            .with_scrub_fn(|s| ScrubResponse { output: s.to_owned(), matches: Vec::new() })
            .into_arc_dyn();
        let rt = fresh_runtime();
        // Build a JS source that constructs a 200-deep nested
        // object — exceeds the SCRUB_OBJECT_MAX_DEPTH=128 cap.
        // The implementation should reject with ScrubInvalidInput.
        let result = eval_with_host_api_await_unit(
            &rt,
            &svc,
            r#"
                (function() {
                    var deep = "leaf";
                    for (var i = 0; i < 200; i++) {
                        deep = { nested: deep };
                    }
                    return agentsso.scrub.object(deep);
                })()
            "#,
        );
        match result {
            Err(PluginError::HostApiError { code, .. }) => {
                assert!(
                    matches!(&code, HostApiErrorCode::Plugin(p) if p.as_str() == "scrub.invalid_input")
                );
            }
            other => panic!("expected ScrubInvalidInput on 200-deep object; got {other:?}"),
        }
    }
}

/// AC #14 / M12: scrub.text additional invalid-input cases
/// (`null` and plain-object).
mod scrub_text_invalid_input_extra {
    use super::*;

    fn invalid_input_svc() -> Arc<dyn HostServices> {
        MockHostServices::new()
            .with_scrub_fn(|s| ScrubResponse { output: s.to_owned(), matches: Vec::new() })
            .into_arc_dyn()
    }

    #[test]
    fn scrub_text_invalid_input_null() {
        let rt = fresh_runtime();
        let svc = invalid_input_svc();
        let result = eval_with_host_api_await_unit(&rt, &svc, "agentsso.scrub.text(null)");
        match result {
            Err(PluginError::HostApiError { code, .. }) => {
                assert!(
                    matches!(&code, HostApiErrorCode::Plugin(p) if p.as_str() == "scrub.invalid_input")
                );
            }
            other => panic!("expected ScrubInvalidInput on null; got {other:?}"),
        }
    }

    #[test]
    fn scrub_text_invalid_input_plain_object() {
        let rt = fresh_runtime();
        let svc = invalid_input_svc();
        let result =
            eval_with_host_api_await_unit(&rt, &svc, r#"agentsso.scrub.text({foo: "bar"})"#);
        match result {
            Err(PluginError::HostApiError { code, .. }) => {
                assert!(
                    matches!(&code, HostApiErrorCode::Plugin(p) if p.as_str() == "scrub.invalid_input")
                );
            }
            other => panic!("expected ScrubInvalidInput on plain object; got {other:?}"),
        }
    }
}

/// AC #19 / new tests (re-review): negative timeoutMs rejects
/// with HttpInvalidTimeout.
mod http_fetch_invalid_timeout {
    use super::*;

    #[test]
    fn http_fetch_negative_timeout_rejects_with_invalid_timeout() {
        let svc = MockHostServices::new()
            .with_fetch_response(Ok(FetchResp {
                status: 200,
                headers: Vec::new(),
                body_utf8_lossy: String::new(),
            }))
            .into_arc_dyn();
        let rt = fresh_runtime();
        let result = eval_with_host_api_await_unit(
            &rt,
            &svc,
            r#"agentsso.http.fetch("https://example.com/", {timeoutMs: -1})"#,
        );
        match result {
            Err(PluginError::HostApiError { code, retryable, .. }) => {
                assert!(
                    matches!(&code, HostApiErrorCode::Plugin(p) if p.as_str() == "http.invalid_timeout")
                );
                assert!(!retryable);
            }
            other => panic!("expected HttpInvalidTimeout on negative timeoutMs; got {other:?}"),
        }
    }

    #[test]
    fn http_fetch_nan_timeout_rejects_with_invalid_timeout() {
        let svc = MockHostServices::new()
            .with_fetch_response(Ok(FetchResp {
                status: 200,
                headers: Vec::new(),
                body_utf8_lossy: String::new(),
            }))
            .into_arc_dyn();
        let rt = fresh_runtime();
        let result = eval_with_host_api_await_unit(
            &rt,
            &svc,
            r#"agentsso.http.fetch("https://example.com/", {timeoutMs: NaN})"#,
        );
        assert!(matches!(
            result,
            Err(PluginError::HostApiError { code, .. }) if code.to_string() == "http.invalid_timeout"
        ));
    }
}

/// AC #18 / B3 follow-up: header value CRLF injection rejection.
mod http_fetch_header_value_injection {
    use super::*;

    #[test]
    fn http_fetch_header_value_with_crlf_rejects() {
        let svc = MockHostServices::new().into_arc_dyn();
        let rt = fresh_runtime();
        let result = eval_with_host_api_await_unit(
            &rt,
            &svc,
            r#"agentsso.http.fetch("https://example.com/", { headers: { "X-Custom": "value\r\nInjected: true" } })"#,
        );
        match result {
            Err(PluginError::HostApiError { code, .. }) => {
                assert!(
                    matches!(&code, HostApiErrorCode::Plugin(p) if p.as_str() == "http.header_injection")
                );
            }
            other => panic!("expected HttpHeaderInjection on CRLF header value; got {other:?}"),
        }
    }
}

/// AC #23 / #38: forged AgentssoError shape rejection
/// (stamp-authentication test).
mod forged_agentsso_error {
    use super::*;

    #[test]
    fn forged_agentsso_shape_does_not_round_trip() {
        let rt = fresh_runtime();
        let svc = allow_services();
        // Throw a hand-crafted plain object with name === "AgentssoError"
        // and code/retryable/message fields. Without the AD5 stamp
        // it MUST NOT round-trip as PluginError::HostApiError.
        let result = rt.with_host_api(&svc, |ctx| {
            let _: rquickjs::Value<'_> = ctx.eval(
                r#"
                    throw {
                        name: "AgentssoError",
                        code: "plugin.custom",
                        retryable: true,
                        message: "fake"
                    };
                "#,
            )?;
            Ok(())
        });
        match result {
            Err(PluginError::JsException { .. }) => {
                // Correct: forged object → JsException, NOT HostApiError.
            }
            Err(PluginError::HostApiError { .. }) => {
                panic!(
                    "AD5 violation: forged AgentssoError shape was authenticated as HostApiError; \
                     stamp-based identity check failed"
                );
            }
            other => panic!("expected JsException for forged shape; got {other:?}"),
        }
    }
}

/// M8 (re-review patch): body-cap boundary test.
/// Note: the cap is enforced in the proxy-side `ProxyHostServices::fetch`
/// via the bounded-stream read, not in the plugin marshaller. The
/// plugin-side test surface uses `MockHostServices::with_fetch_response`
/// which doesn't exercise the bounded-stream path. This test is
/// SKIPPED-IN-PLUGIN and lives in `permitlayer-proxy/src/plugin_host_services.rs::tests`.
/// (See unit test there for the boundary verification.)
mod http_fetch_body_cap_boundary {
    use super::*;

    /// Sanity: at-or-below-cap response succeeds end-to-end via the
    /// mock path. Does NOT verify the proxy-side cap (that's
    /// covered by proxy-side unit tests with a real bounded read).
    #[test]
    fn http_fetch_at_cap_resolves() {
        let body = "x".repeat(1024); // 1 KiB — well below cap.
        let svc = MockHostServices::new()
            .with_fetch_response(Ok(FetchResp {
                status: 200,
                headers: Vec::new(),
                body_utf8_lossy: body.clone(),
            }))
            .into_arc_dyn();
        let rt = fresh_runtime();
        let result =
            eval_with_host_api_json(&rt, &svc, r#"agentsso.http.fetch("https://example.com/")"#)
                .unwrap();
        assert_eq!(result["body"].as_str().map(|s| s.len()), Some(body.len()));
    }
}

// ─────────────────────────────────────────────────────────────────
// Story 6.5 — agentsso.deprecated stub integration check
// ─────────────────────────────────────────────────────────────────

mod deprecated {
    use super::*;

    /// AC #16: `agentsso.deprecated` is installed as an empty frozen
    /// object via the full `register_host_api` path (the JS-side
    /// surface integration test, complementing the unit test in
    /// `host_api/deprecated.rs`).
    #[test]
    fn deprecated_is_empty_frozen_object() {
        let svc = MockHostServices::new().into_arc_dyn();
        let rt = fresh_runtime();
        let shape: serde_json::Value = rt
            .with_host_api(&svc, |ctx| {
                let key_count: i32 = ctx.eval("Object.keys(agentsso.deprecated).length")?;
                let is_object: bool = ctx.eval(r#"typeof agentsso.deprecated === "object""#)?;
                let is_frozen: bool = ctx.eval("Object.isFrozen(agentsso.deprecated)")?;
                Ok(serde_json::json!({
                    "key_count": key_count,
                    "is_object": is_object,
                    "is_frozen": is_frozen,
                }))
            })
            .unwrap();

        assert_eq!(shape["is_object"], serde_json::Value::Bool(true));
        assert_eq!(shape["is_frozen"], serde_json::Value::Bool(true));
        assert_eq!(shape["key_count"], serde_json::Value::from(0));
    }
}
