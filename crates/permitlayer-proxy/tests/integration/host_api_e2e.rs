//! Story 6.2 / AC #30 (in-process variant): exercise
//! `PluginRuntime::with_host_api` against the production
//! `ProxyHostServices` impl end-to-end, in-process.
//!
//! The story's AC #30 calls for a `/v1/debug/plugin-echo` HTTP
//! endpoint test. That endpoint is registered in
//! `crates/permitlayer-daemon/src/cli/start.rs` behind
//! `#[cfg(debug_assertions)]` and goes through `spawn_blocking`.
//! Spinning up the full daemon (with vault + master key + OAuth
//! setup fixtures) for an integration test is heavyweight; this
//! test instead exercises the same code path WITHOUT the HTTP
//! transport — the JS-side surface and the Rust-side
//! `ProxyHostServices` glue both run identically.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use permitlayer_core::audit::dispatcher::AuditDispatcher;
use permitlayer_core::policy::PolicySet;
use permitlayer_core::scrub::ScrubEngine;
use permitlayer_plugins::{HostServices, PluginRuntime};
use permitlayer_proxy::{ProxyHostServices, ScopedTokenIssuer};
use zeroize::Zeroizing;

fn build_services(vault_dir: std::path::PathBuf, plugin_name: &str) -> Arc<dyn HostServices> {
    let token_issuer = Arc::new(ScopedTokenIssuer::new(Zeroizing::new([0xAB; 32])));
    let scrub_engine =
        Arc::new(ScrubEngine::new(permitlayer_core::scrub::builtin_rules().to_vec()).unwrap());
    let policy = PolicySet::compile_from_str(
        r#"
            [[policies]]
            name = "default"
            scopes = ["gmail.readonly", "http.fetch"]
            resources = ["*"]
            approval-mode = "auto"
        "#,
        Path::new("test.toml"),
    )
    .unwrap();
    let policy_set = Arc::new(ArcSwap::from_pointee(policy));
    Arc::new(ProxyHostServices::new(
        token_issuer,
        scrub_engine,
        policy_set,
        vault_dir,
        "default".to_owned(),
        plugin_name.to_owned(),
        Arc::new(AuditDispatcher::none()),
        "test-agent".to_owned(),
    ))
}

/// Helper: drive a JS expression that may return a Promise to its
/// resolved value. AD2 (Story 6.2 course-correction): every host-API
/// method except `agentsso.version` returns a Promise. Tests await
/// via `Promise::finish` which drives the QuickJS microtask queue.
fn eval_and_finish_string(
    rt: &PluginRuntime,
    services: &Arc<dyn HostServices>,
    src: &str,
) -> Result<String, String> {
    rt.with_host_api(services, |ctx| {
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
    .map_err(|e| e.to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn debug_plugin_echo_returns_host_api_version_e2e() {
    // Spawn-blocking simulates the production CALLING CONTRACT
    // (the `/v1/debug/plugin-echo` handler runs the plugin call
    // inside `tokio::task::spawn_blocking`).
    let dir = tempfile::tempdir().unwrap();
    let services = build_services(dir.path().to_owned(), "debug-plugin-echo");
    let plugin_runtime = Arc::new(PluginRuntime::new_default().unwrap());

    let handle_result = tokio::task::spawn_blocking(move || -> Result<String, String> {
        // `agentsso.version` stays SYNC per AD2 — pure JS-heap
        // constant lookup. No await needed.
        eval_and_finish_string(&plugin_runtime, &services, "agentsso.version")
    })
    .await
    .unwrap();

    assert_eq!(handle_result.unwrap(), "1.0.0-rc.1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn debug_plugin_echo_oauth_token_round_trip_e2e() {
    let dir = tempfile::tempdir().unwrap();
    // Seed a vault meta entry so the service is "connected."
    std::fs::write(dir.path().join("gmail-meta.json"), r#"{"client_type":"shared-casa"}"#).unwrap();
    let services = build_services(dir.path().to_owned(), "debug-plugin-echo");
    let plugin_runtime = Arc::new(PluginRuntime::new_default().unwrap());

    let result = tokio::task::spawn_blocking(move || -> Result<String, String> {
        // AD2: oauth.getToken returns a Promise; await it inside
        // an async-IIFE that returns the final JSON string.
        eval_and_finish_string(
            &plugin_runtime,
            &services,
            r#"
                (async () => {
                    var t = await agentsso.oauth.getToken("gmail", "gmail.readonly");
                    return JSON.stringify({
                        bearer_present: typeof t.bearer === "string" && t.bearer.length > 0,
                        scope: t.scope,
                        resource: t.resource,
                        expires_in_future: t.expiresAt > (Date.now() / 1000)
                    });
                })()
            "#,
        )
    })
    .await
    .unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(parsed["bearer_present"].as_bool(), Some(true));
    assert_eq!(parsed["scope"].as_str(), Some("gmail.readonly"));
    assert_eq!(parsed["resource"].as_str(), Some("gmail"));
    assert_eq!(parsed["expires_in_future"].as_bool(), Some(true));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn debug_plugin_echo_scrub_text_e2e() {
    let dir = tempfile::tempdir().unwrap();
    let services = build_services(dir.path().to_owned(), "debug-plugin-echo");
    let plugin_runtime = Arc::new(PluginRuntime::new_default().unwrap());

    let result = tokio::task::spawn_blocking(move || -> Result<String, String> {
        // AD2: scrub.text returns a Promise; await it inside an
        // async-IIFE that returns the .output string directly.
        eval_and_finish_string(
            &plugin_runtime,
            &services,
            r#"(async () => (await agentsso.scrub.text("Your code is 123456")).output)()"#,
        )
    })
    .await
    .unwrap();

    assert_eq!(result.unwrap(), "Your code is <REDACTED_OTP>");
}
