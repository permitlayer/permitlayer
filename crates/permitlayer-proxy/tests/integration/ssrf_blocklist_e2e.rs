//! Story 8.3 / AC #1–3: SSRF blocklist integration test.
//!
//! Exercises `ProxyHostServices::fetch` with a real `AuditFsStore` to
//! verify that:
//! - URLs whose IP literal hits the cloud-metadata blocklist are rejected
//!   with `http.blocked_metadata_endpoint` even when policy allows all HTTP.
//! - The blocklist check fires BEFORE policy evaluation (no policy-denied
//!   error — the blocklist error is returned, not the policy error).
//! - Exactly one `plugin-http-blocked` audit event lands on disk for each
//!   blocked request.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use permitlayer_core::audit::dispatcher::AuditDispatcher;
use permitlayer_core::policy::PolicySet;
use permitlayer_core::scrub::ScrubEngine;
use permitlayer_core::store::fs::AuditFsStore;
use permitlayer_plugins::{HostServices, PluginRuntime};
use permitlayer_proxy::{ProxyHostServices, ScopedTokenIssuer};
use zeroize::Zeroizing;

fn build_services_with_audit(
    vault_dir: std::path::PathBuf,
    audit_dir: std::path::PathBuf,
    plugin_name: &str,
) -> (Arc<dyn HostServices>, Arc<AuditFsStore>, Arc<AuditDispatcher>) {
    let token_issuer = Arc::new(ScopedTokenIssuer::new(Zeroizing::new([0xAB; 32])));
    let scrub_engine =
        Arc::new(ScrubEngine::new(permitlayer_core::scrub::builtin_rules().to_vec()).unwrap());
    // Policy that allows all HTTP — SSRF check must fire BEFORE policy.
    let policy = PolicySet::compile_from_str(
        r#"
            [[policies]]
            name = "default"
            scopes = ["http.fetch"]
            resources = ["*"]
            approval-mode = "auto"
        "#,
        Path::new("test.toml"),
    )
    .unwrap();
    let policy_set = Arc::new(ArcSwap::from_pointee(policy));

    let store = Arc::new(
        AuditFsStore::new(audit_dir, 100 * 1024 * 1024, Arc::clone(&scrub_engine))
            .expect("build AuditFsStore"),
    );
    let dispatcher = Arc::new(AuditDispatcher::for_tests_unbounded(
        Arc::clone(&store) as Arc<dyn permitlayer_core::store::AuditStore>
    ));
    let services: Arc<dyn HostServices> = Arc::new(ProxyHostServices::new(
        token_issuer,
        scrub_engine,
        policy_set,
        vault_dir,
        "default".to_owned(),
        plugin_name.to_owned(),
        Arc::clone(&dispatcher),
        "test-agent".to_owned(),
    ));
    (services, store, dispatcher)
}

/// Count events of a given `event_type` in all `.jsonl` files under `audit_dir`.
fn count_audit_events(audit_dir: &Path, event_type: &str) -> usize {
    let mut count = 0;
    let Ok(entries) = std::fs::read_dir(audit_dir) else {
        return 0;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("jsonl") {
            continue;
        }
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line)
                && v.get("event_type").and_then(|s| s.as_str()) == Some(event_type)
            {
                count += 1;
            }
        }
    }
    count
}

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
async fn ssrf_blocklist_rejects_imds_v1_and_emits_audit_event() {
    let vault_dir = tempfile::tempdir().unwrap();
    let audit_dir = tempfile::tempdir().unwrap();
    let (services, _store, dispatcher) = build_services_with_audit(
        vault_dir.path().to_path_buf(),
        audit_dir.path().to_path_buf(),
        "test-connector",
    );
    let plugin_runtime = Arc::new(PluginRuntime::new_default().unwrap());

    let result = tokio::task::spawn_blocking(move || {
        eval_and_finish_string(
            &plugin_runtime,
            &services,
            r#"
                (async () => {
                    try {
                        await agentsso.http.fetch(
                            "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                        );
                        return "allowed";
                    } catch (e) {
                        return e.code || "unknown_error";
                    }
                })()
            "#,
        )
    })
    .await
    .unwrap();

    assert_eq!(
        result.unwrap(),
        "http.blocked_metadata_endpoint",
        "IMDS v1 URL should be rejected by SSRF blocklist"
    );

    // Drain the dispatcher deterministically — no arbitrary sleep.
    dispatcher.drain(std::time::Duration::from_secs(5)).await;

    let n = count_audit_events(audit_dir.path(), "plugin-http-blocked");
    assert_eq!(n, 1, "expected exactly one plugin-http-blocked audit event on disk");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssrf_blocklist_rejects_ipv6_imds_and_loopback() {
    let vault_dir = tempfile::tempdir().unwrap();
    let audit_dir = tempfile::tempdir().unwrap();
    let plugin_runtime = Arc::new(PluginRuntime::new_default().unwrap());

    let blocked_urls = [
        "http://[fd00:ec2::254]/latest/meta-data/",
        "http://127.0.0.1/internal",
        "http://[::1]/internal",
        "http://0.0.0.0/",
        "http://169.254.170.2/v2/metadata",
    ];

    for url in &blocked_urls {
        let (services, _store, _dispatcher) = build_services_with_audit(
            vault_dir.path().to_path_buf(),
            audit_dir.path().to_path_buf(),
            "test-connector",
        );
        let rt = Arc::clone(&plugin_runtime);
        let url_owned = url.to_string();
        let result = tokio::task::spawn_blocking(move || {
            eval_and_finish_string(
                &rt,
                &services,
                &format!(
                    r#"
                        (async () => {{
                            try {{
                                await agentsso.http.fetch("{url_owned}");
                                return "allowed";
                            }} catch (e) {{
                                return e.code || "unknown_error";
                            }}
                        }})()
                    "#
                ),
            )
        })
        .await
        .unwrap();
        assert_eq!(
            result.unwrap(),
            "http.blocked_metadata_endpoint",
            "URL {url} should be blocked"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssrf_blocklist_passes_domain_names_to_policy() {
    // Domain names pass through the SSRF blocklist (IP-literal-only check).
    // Use a policy that DENIES http.fetch to prove we got a policy error,
    // not an SSRF block — the SSRF check runs before policy and would
    // produce http.blocked_metadata_endpoint if triggered.
    let vault_dir = tempfile::tempdir().unwrap();
    let audit_dir = tempfile::tempdir().unwrap();
    let token_issuer = Arc::new(ScopedTokenIssuer::new(zeroize::Zeroizing::new([0xAB; 32])));
    let scrub_engine =
        Arc::new(ScrubEngine::new(permitlayer_core::scrub::builtin_rules().to_vec()).unwrap());
    // Policy that DENIES http.fetch — so if SSRF check passes the domain through,
    // we'll see http.policy_denied, not http.blocked_metadata_endpoint.
    let policy = PolicySet::compile_from_str(
        r#"
            [[policies]]
            name = "deny-all"
            scopes = ["http.fetch"]
            resources = ["*"]
            approval-mode = "deny"
        "#,
        Path::new("test.toml"),
    )
    .unwrap();
    let policy_set = Arc::new(ArcSwap::from_pointee(policy));
    let store = Arc::new(
        AuditFsStore::new(
            audit_dir.path().to_path_buf(),
            100 * 1024 * 1024,
            Arc::clone(&scrub_engine),
        )
        .expect("build AuditFsStore"),
    );
    let dispatcher = Arc::new(AuditDispatcher::for_tests_unbounded(
        Arc::clone(&store) as Arc<dyn permitlayer_core::store::AuditStore>
    ));
    let services: Arc<dyn HostServices> = Arc::new(ProxyHostServices::new(
        token_issuer,
        scrub_engine,
        policy_set,
        vault_dir.path().to_path_buf(),
        "deny-all".to_owned(),
        "test-connector".to_owned(),
        Arc::clone(&dispatcher),
        "test-agent".to_owned(),
    ));
    let plugin_runtime = Arc::new(PluginRuntime::new_default().unwrap());

    let result = tokio::task::spawn_blocking(move || {
        eval_and_finish_string(
            &plugin_runtime,
            &services,
            r#"
                (async () => {
                    try {
                        await agentsso.http.fetch("https://example.com/");
                        return "allowed";
                    } catch (e) {
                        return e.code || "unknown_error";
                    }
                })()
            "#,
        )
    })
    .await
    .unwrap();

    let code = result.unwrap();
    assert_ne!(
        code, "http.blocked_metadata_endpoint",
        "domain name should not be blocked by SSRF blocklist (got: {code})"
    );
    // Domain passed through SSRF check; policy denied it.
    assert_eq!(
        code, "http.policy_denied",
        "domain should reach policy evaluation and be denied (got: {code})"
    );
}
