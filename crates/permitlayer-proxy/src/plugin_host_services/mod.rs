//! Production [`permitlayer_plugins::HostServices`] implementation
//! backed by `Arc<ProxyService>` + the existing proxy state.
//!
//! Story 6.2 Task 7. The implementation translates between the
//! plugin-side service trait and the proxy's existing
//! `Arc<ScopedTokenIssuer>`, `Arc<ScrubEngine>`, hot-swappable
//! `Arc<ArcSwap<PolicySet>>`, etc. All trait methods are
//! synchronous; the `fetch` impl runs reqwest internally via
//! `tokio::runtime::Handle::current().block_on(...)` (see
//! CALLING CONTRACT below).
//!
//! # CALLING CONTRACT
//!
//! `ProxyHostServices::fetch` blocks the calling thread on a
//! reqwest future via `Handle::current().block_on(...)`. Callers
//! MUST invoke
//! [`permitlayer_plugins::PluginRuntime::with_host_api`] inside
//! [`tokio::task::spawn_blocking`] so the proxy's tokio worker
//! threads do NOT serve HTTP requests while a plugin call is in
//! flight. Failure to follow this contract causes a deadlock when
//! reqwest is the runtime's only worker (single-thread scheduler)
//! and silent worker starvation in multi-threaded scheduler
//! configurations.
//!
//! Story 6.1's D4 review deferral marked this as 6.2 territory;
//! this is where it lives.
//!
//! # Construction
//!
//! Build one `ProxyHostServices` per plugin call. The construction
//! cost is just a handful of `Arc::clone` operations plus two
//! `String::clone`s; per-call construction lets us bind the agent
//! identity + plugin name for the call duration. Story 6.3's
//! loader is the production caller.

pub mod ssrf_blocklist;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use permitlayer_core::audit::dispatcher::AuditDispatcher;
use permitlayer_core::audit::event::AuditEvent;
use permitlayer_core::policy::PolicySet;
use permitlayer_core::policy::eval::{Decision, EvalRequest};
use permitlayer_core::scrub::ScrubEngine;
use permitlayer_plugins::{
    DecisionDesc, FetchReq, FetchResp, HostApiError, HostApiErrorCode, HostCode, HostServices,
    PolicyEvalReq, ScopedTokenDesc, ScrubMatchDesc, ScrubResponse,
};

use crate::token::ScopedTokenIssuer;

/// Production `HostServices` impl. See module docs for the calling
/// contract.
pub struct ProxyHostServices {
    /// Token issuer; clones the inner `Arc<ScopedTokenIssuer>` so
    /// per-call `issue_scoped_token` is allocator-free past Arc
    /// refcount bump.
    token_issuer: Arc<ScopedTokenIssuer>,
    /// Scrub engine; immutable after construction so the `Arc` is
    /// shared across every plugin call.
    scrub_engine: Arc<ScrubEngine>,
    /// Hot-swappable policy IR (see `permitlayer-proxy::middleware::policy`).
    policy_set: Arc<ArcSwap<PolicySet>>,
    /// Vault directory — read by `list_connected_services` for
    /// `*-meta.json` enumeration.
    vault_dir: PathBuf,
    /// Reqwest client for `fetch`. One per `ProxyHostServices`
    /// instance — the underlying connection pool is shared. We
    /// build it at construction time rather than per-call so we
    /// don't pay TLS-context setup on every plugin call.
    http_client: reqwest::Client,
    /// Bound agent's policy name. Default for `policy.enforce`
    /// when the plugin doesn't pass one.
    agent_policy: String,
    /// Connector name (e.g. `"google-gmail"`, `"notion"`) for
    /// User-Agent injection.
    plugin_name: String,
    /// Audit dispatcher for emitting `plugin-http-blocked` events.
    audit_dispatcher: Arc<AuditDispatcher>,
    /// Agent identity string (e.g., agent_id) for audit events.
    agent_id: String,
}

impl ProxyHostServices {
    /// Construct a per-call `HostServices` impl bound to the agent
    /// policy and plugin name for this invocation.
    ///
    /// `policy_set` is the same `Arc<ArcSwap<PolicySet>>` the
    /// proxy's policy middleware holds — sharing the handle lets
    /// `policy.enforce` see hot-swapped reloads without per-call
    /// reconstruction.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token_issuer: Arc<ScopedTokenIssuer>,
        scrub_engine: Arc<ScrubEngine>,
        policy_set: Arc<ArcSwap<PolicySet>>,
        vault_dir: PathBuf,
        agent_policy: String,
        plugin_name: String,
        audit_dispatcher: Arc<AuditDispatcher>,
        agent_id: String,
    ) -> Self {
        // Default reqwest client: rustls-tls (per workspace
        // convention), 30s connect timeout (the per-request timeout
        // is set by `fetch`'s `RequestBuilder::timeout`).
        // `reqwest::Client::builder().build()` cannot fail with the
        // default config (no platform-cert-store reads or DNS
        // resolution at this point). The fallback to
        // `Client::new()` is functionally identical and is just a
        // belt-and-suspenders to silence clippy's `expect_used`
        // lint without panicking on the unreachable error path.
        let http_client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            token_issuer,
            scrub_engine,
            policy_set,
            vault_dir,
            http_client,
            agent_policy,
            plugin_name,
            audit_dispatcher,
            agent_id,
        }
    }
}

impl HostServices for ProxyHostServices {
    fn issue_scoped_token(
        &self,
        service: &str,
        scope: &str,
    ) -> Result<ScopedTokenDesc, HostApiError> {
        // Validate that the service has a vault entry before
        // issuing a token. The list_connected_services method
        // already does this enumeration; we duplicate the
        // existence check here (faster than building a full Vec
        // for one lookup).
        //
        // H8 (re-review patch 2026-04-18): not just existence —
        // also parse the meta file. A stale or corrupt
        // `*-meta.json` (e.g. truncated by a crash mid-write,
        // post-revoke leftover, schema drift) used to give the
        // plugin a bearer that would fail at the proxy's
        // ingress validation with a confusing "credential
        // revoked" message. Now: parse the file; if the parse
        // fails, return `OauthRefreshFailed` (retryable=false —
        // re-running setup will fix it) so the plugin author
        // gets a directly-actionable signal.
        let meta_path = self.vault_dir.join(format!("{service}-meta.json"));
        match std::fs::read_to_string(&meta_path) {
            Ok(contents) => {
                if let Err(parse_err) = serde_json::from_str::<serde_json::Value>(&contents) {
                    return Err(HostApiError::new(
                        HostApiErrorCode::Host(HostCode::OauthRefreshFailed),
                        false,
                        format!(
                            "vault meta file for service `{service}` is corrupt; re-run \
                             `agentsso setup {service}` to repair: {parse_err}"
                        ),
                    ));
                }
            }
            Err(io_err) if io_err.kind() == std::io::ErrorKind::NotFound => {
                return Err(HostApiError::new(
                    HostApiErrorCode::Host(HostCode::OauthUnknownService),
                    false,
                    format!("no vault credential for service `{service}`"),
                ));
            }
            Err(io_err) => {
                return Err(HostApiError::new(
                    HostApiErrorCode::Host(HostCode::OauthRefreshFailed),
                    false,
                    format!("vault meta file for service `{service}` is unreadable: {io_err}"),
                ));
            }
        }

        // Issue a 60s scoped token. Per AC #4 this is the documented
        // TTL ceiling — plugins can `Date.now()/1000` against the
        // returned `expiresAt` to know when to call `getToken` again.
        let token = self.token_issuer.issue(&self.agent_policy, scope, service, 60);
        Ok(ScopedTokenDesc {
            bearer: token.token,
            scope: token.scope,
            resource: token.resource,
            expires_at_epoch_secs: token.expires_at,
        })
    }

    /// List services connected to the vault by scanning `*-meta.json`
    /// files.
    ///
    /// **Performance budget:** <10ms for a 100-entry vault dir. The
    /// CALLING CONTRACT requires callers to run this inside
    /// `tokio::task::spawn_blocking` — the blocking I/O here is
    /// acceptable on a blocking worker without starving the tokio
    /// reactor. The synchronous-by-design `HostServices` trait (Story
    /// 6.2 AD2) is intentional; converting to `tokio::fs::read_dir`
    /// would fork the trait shape.
    fn list_connected_services(&self) -> Result<Vec<String>, HostApiError> {
        // Read directory entries matching `*-meta.json` and return
        // their basenames (sans the `-meta.json` suffix). Sorted
        // alphabetically for deterministic plugin behavior (AC #7).
        let entries = match std::fs::read_dir(&self.vault_dir) {
            Ok(e) => e,
            Err(_) => {
                // Vault dir doesn't exist — no services connected.
                // This is expected for fresh installs and is NOT an
                // error condition.
                return Ok(Vec::new());
            }
        };
        let mut names = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) =
                path.file_name().and_then(|n| n.to_str()).and_then(|n| n.strip_suffix("-meta.json"))
            {
                names.push(name.to_owned());
            }
        }
        names.sort();
        Ok(names)
    }

    fn evaluate_policy(&self, req: PolicyEvalReq) -> Result<DecisionDesc, HostApiError> {
        let policy_snapshot = self.policy_set.load();
        let core_req =
            EvalRequest { policy_name: req.policy_name, scope: req.scope, resource: req.resource };
        let decision = policy_snapshot.evaluate(&core_req);
        Ok(decision_to_desc(decision))
    }

    fn scrub_text(&self, input: &str) -> Result<ScrubResponse, HostApiError> {
        let result = self.scrub_engine.scrub(input);
        // Build per-match metadata with output-side offsets via the
        // running-delta pattern from
        // `permitlayer_core::scrub::engine::ScrubResult::samples`.
        let mut matches_desc: Vec<ScrubMatchDesc> = Vec::with_capacity(result.matches.len());
        let mut delta: isize = 0;
        for m in &result.matches {
            // L6 (re-review patch 2026-04-18): inlined the prior
            // `render_placeholder(&m.placeholder)` wrapper.
            let placeholder_str = m.placeholder.to_string();
            let placeholder_len = placeholder_str.len();
            let match_len = m.span.end - m.span.start;
            let output_offset = (m.span.start as isize + delta) as usize;
            delta += placeholder_len as isize - match_len as isize;
            matches_desc.push(ScrubMatchDesc {
                rule_id: m.rule_name.clone(),
                placeholder: placeholder_str,
                span_offset: output_offset,
                span_length: placeholder_len,
            });
        }
        Ok(ScrubResponse { output: result.output, matches: matches_desc })
    }

    fn fetch(&self, req: FetchReq) -> Result<FetchResp, HostApiError> {
        // Internal policy gate per AC #16. Build an EvalRequest for
        // scope `"http.fetch"` resource = URL host. Skip the gate
        // if we can't parse the URL into a host (the marshaller
        // already validated the scheme).
        let parsed = match url::Url::parse(&req.url) {
            Ok(u) => u,
            Err(_) => {
                return Err(HostApiError::new(
                    HostApiErrorCode::Host(HostCode::HttpSchemeNotAllowed),
                    false,
                    format!("malformed URL: {}", req.url),
                ));
            }
        };

        // Validate runtime flavor FIRST — before SSRF block_on and before policy.
        // This guards ALL block_on calls below (SSRF audit + reqwest).
        //
        // AD4 (Story 6.2 course-correction 2026-04-17): the prior
        // version only checked for *absence* of a runtime via
        // `Handle::try_current()`. On a current-thread runtime
        // (`Builder::new_current_thread()` — the default for
        // `#[tokio::test]` without `flavor = "multi_thread"`), the
        // subsequent `block_on` panics with `Cannot start a runtime
        // from within a runtime`. We now detect the flavor and
        // fail-CLOSED with a typed error instead of panicking,
        // honoring the "every host-API failure is an AgentssoError"
        // contract from AD5.
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(h) => h,
            Err(_) => {
                return Err(HostApiError::new(
                    HostApiErrorCode::Host(HostCode::HttpUpstreamUnreachable),
                    false,
                    "no tokio runtime in scope (plugin must run inside a tokio context)".to_owned(),
                ));
            }
        };
        // H18 (re-review patch 2026-04-18): whitelist multi-thread,
        // not blacklist current-thread. `RuntimeFlavor` is
        // `#[non_exhaustive]` upstream — a future tokio that adds
        // `LocalSet`-backed or other variants would silently pass
        // a blacklist check. The whitelist form fail-closes on
        // any new variant.
        if !matches!(handle.runtime_flavor(), tokio::runtime::RuntimeFlavor::MultiThread) {
            return Err(HostApiError::new(
                HostApiErrorCode::Host(HostCode::HttpUpstreamUnreachable),
                false,
                "caller must use spawn_blocking on a multi-thread runtime; \
                 detected non-multi-thread tokio runtime (would deadlock on block_on)"
                    .to_owned(),
            ));
        }

        // SSRF blocklist — before policy evaluation and before any network I/O.
        // Defense-in-depth even when http.allow = ["*"].
        if let Some(reason) = ssrf_blocklist::is_blocked_destination(&parsed) {
            let destination_ip = parsed.host_str().unwrap_or("unknown").to_owned();
            let truncated_url: String = req.url.chars().take(256).collect();
            tracing::warn!(
                target: "host_api.http",
                code = "http.blocked_metadata_endpoint",
                ip = %destination_ip,
                url = %truncated_url,
                "SSRF blocklist rejected plugin http.fetch"
            );
            // Emit plugin-http-blocked audit event via AuditDispatcher.
            let mut event = AuditEvent::new(
                self.agent_id.clone(),
                self.plugin_name.clone(),
                "http.fetch".to_owned(),
                destination_ip.clone(),
                "denied".to_owned(),
                "plugin-http-blocked".to_owned(),
            );
            event.extra = serde_json::json!({
                "reason": reason.as_audit_reason(),
                "destination_ip": destination_ip,
                "plugin_name": self.plugin_name,
                "origin": permitlayer_plugins::origin_str(
                    &HostApiErrorCode::Host(HostCode::HttpBlockedMetadataEndpoint)
                ),
            });
            let dispatcher = Arc::clone(&self.audit_dispatcher);
            handle.block_on(async move {
                dispatcher.dispatch(event).await;
            });
            return Err(HostApiError::new(
                HostApiErrorCode::Host(HostCode::HttpBlockedMetadataEndpoint),
                false,
                format!(
                    "defense-in-depth: destination IP {} is on the metadata-service blocklist; \
                     override via explicit operator policy in daemon config, NOT plugin request",
                    destination_ip
                ),
            ));
        }

        let host = parsed.host_str().unwrap_or("").to_owned();
        let core_req = EvalRequest {
            policy_name: self.agent_policy.clone(),
            scope: "http.fetch".to_owned(),
            resource: Some(host.clone()),
        };
        let decision = self.policy_set.load().evaluate(&core_req);
        match decision {
            Decision::Allow => {}
            Decision::Deny { rule_id, .. } => {
                return Err(HostApiError::new(
                    HostApiErrorCode::Host(HostCode::HttpPolicyDenied),
                    false,
                    rule_id,
                ));
            }
            Decision::Prompt { rule_id, .. } => {
                // 1.0.0 treats prompt-required as deny — plugins
                // can't synchronously trigger an operator prompt
                // mid-call. Future 1.x can route prompts through
                // a deferred channel; this is the simplest correct
                // behavior at 1.0.
                return Err(HostApiError::new(
                    HostApiErrorCode::Host(HostCode::HttpPolicyDenied),
                    false,
                    format!("prompt-required: {rule_id}"),
                ));
            }
            // `Decision` is `#[non_exhaustive]` — catch-all
            // conservatively denies any future variant we don't
            // know how to handle.
            _ => {
                return Err(HostApiError::new(
                    HostApiErrorCode::Host(HostCode::HttpPolicyDenied),
                    false,
                    "unknown policy decision variant".to_owned(),
                ));
            }
        }

        // Run reqwest synchronously using the validated handle from above.
        // Story 8.3 AC #13: multi-thread runtime with only ONE worker
        // thread can deadlock. The spawn_blocking task runs on a
        // dedicated blocking thread, but the two nested `block_on`
        // calls inside `fetch()` (builder.send + body drain) need the
        // reactor to make progress. A single-worker runtime serialises
        // both on the same thread as the caller's `spawn_blocking`
        // — potential stall. In debug builds: fail-closed so authors
        // catch the misconfiguration early. In release: emit a
        // one-time `tracing::warn` so operators can act without
        // losing availability.
        {
            let num_workers = handle.metrics().num_workers();
            if num_workers < 2 {
                #[cfg(debug_assertions)]
                {
                    return Err(HostApiError::new(
                        HostApiErrorCode::Host(HostCode::HttpUpstreamUnreachable),
                        false,
                        format!(
                            "CALLING CONTRACT: multi-thread runtime must have >=2 worker threads \
                             (detected {num_workers}); run with worker_threads >= 2 to avoid \
                             potential deadlock on nested block_on"
                        ),
                    ));
                }
                #[cfg(not(debug_assertions))]
                {
                    static WARNED: std::sync::Once = std::sync::Once::new();
                    WARNED.call_once(|| {
                        tracing::warn!(
                            target: "host_api.http",
                            num_workers,
                            "CALLING CONTRACT: multi-thread runtime with <2 workers may deadlock \
                             on nested block_on; recommended worker_threads >= 2"
                        );
                    });
                }
            }
        }

        let method = match reqwest::Method::from_bytes(req.method.as_bytes()) {
            Ok(m) => m,
            Err(_) => {
                return Err(HostApiError::new(
                    HostApiErrorCode::Host(HostCode::HttpUpstreamUnreachable),
                    false,
                    format!("invalid HTTP method: {}", req.method),
                ));
            }
        };
        let mut builder =
            self.http_client.request(method, parsed).timeout(Duration::from_millis(req.timeout_ms));
        for (k, v) in req.headers {
            builder = builder.header(k, v);
        }
        if let Some(body) = req.body {
            builder = builder.body(body);
        }

        let response_result = handle.block_on(async move { builder.send().await });
        let response = match response_result {
            Ok(r) => r,
            Err(e) => {
                // Story 6.2 review finding B5: classify via typed
                // predicates (`is_timeout`, `is_connect`,
                // `is_request`) and walk the source chain for
                // hyper/hickory-dns hints. The prior
                // `e.to_string().contains("dns")` was
                // locale/version-dependent string sniffing — any
                // future reqwest/hyper upgrade that changed the
                // error formatting would silently misclassify
                // DNS failures.
                let code = if e.is_timeout() {
                    HostApiErrorCode::Host(HostCode::HttpTimeout)
                } else if classify_as_dns_error(&e) {
                    // Check DNS BEFORE the generic upstream
                    // catch-all — DNS failures are technically a
                    // kind of connect-phase failure in reqwest,
                    // but they're more specifically diagnosable
                    // and the plugin may want to retry with a
                    // different host.
                    HostApiErrorCode::Host(HostCode::HttpDnsResolutionFailed)
                } else {
                    // is_connect() and any other failure mode
                    // map to the same generic upstream-unreachable
                    // code; clippy collapses the explicit arms.
                    HostApiErrorCode::Host(HostCode::HttpUpstreamUnreachable)
                };
                let retryable = matches!(
                    code,
                    HostApiErrorCode::Host(HostCode::HttpTimeout)
                        | HostApiErrorCode::Host(HostCode::HttpUpstreamUnreachable)
                        | HostApiErrorCode::Host(HostCode::HttpDnsResolutionFailed)
                );
                return Err(HostApiError::new(code, retryable, e.to_string()));
            }
        };

        let status = response.status().as_u16();
        let mut headers: Vec<(String, String)> = Vec::with_capacity(response.headers().len());
        for (name, value) in response.headers().iter() {
            if let Ok(v_str) = value.to_str() {
                headers.push((name.as_str().to_owned(), v_str.to_owned()));
            }
        }
        // Story 6.2 review findings B2 + M7 + B4 (re-review patch
        // 2026-04-18): response body cap. A malicious or buggy
        // upstream streaming a multi-GB body would otherwise be
        // fully buffered into the daemon's RSS (the QuickJS heap
        // limit doesn't cover the reqwest buffer). 10 MiB is enough
        // for every realistic API response we expect to ferry
        // through; plugins fetching larger payloads should stream
        // via 1.x's planned `responseType: "arrayBuffer"`
        // (deferred to 1.1).
        //
        // **B4 re-review fix:** the prior version used
        // `response.bytes().await` then checked `.len() > MAX`.
        // This buffered the entire body BEFORE the size check —
        // multi-GB upstream still OOMed the daemon. Fixed in two
        // layers:
        //   1. Pre-check `Content-Length` header — reject obvious
        //      oversize responses before any body bytes are read.
        //   2. Read body in chunks via `response.chunk().await`
        //      with a running counter that aborts as soon as the
        //      cap is exceeded, never accumulating more than
        //      `MAX_RESPONSE_BYTES` bytes in memory.
        const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

        // Layer 1: Content-Length pre-check. Headers are already
        // captured; re-extract via `response.content_length()`
        // which parses the header internally.
        if let Some(declared_len) = response.content_length()
            && declared_len as usize > MAX_RESPONSE_BYTES
        {
            return Err(HostApiError::new(
                HostApiErrorCode::Host(HostCode::HttpResponseTooLarge),
                false,
                format!(
                    "upstream Content-Length {declared_len} exceeds {MAX_RESPONSE_BYTES}-byte limit"
                ),
            ));
        }

        // Layer 2: bounded-stream read. Accumulates chunks into a
        // single Vec<u8>, aborting at the cap. Pre-allocates the
        // declared length when known to avoid amortized regrowth
        // for the common case.
        let pre_alloc =
            response.content_length().map(|n| n as usize).unwrap_or(0).min(MAX_RESPONSE_BYTES);
        let body_chunks_result = handle.block_on(async move {
            let mut response = response;
            let mut accumulated: Vec<u8> = Vec::with_capacity(pre_alloc);
            loop {
                match response.chunk().await {
                    Ok(Some(chunk)) => {
                        if accumulated.len() + chunk.len() > MAX_RESPONSE_BYTES {
                            // Cap exceeded mid-stream — return
                            // a marker error that the outer
                            // matcher converts to HttpResponseTooLarge.
                            return Err(BodyReadError::TooLarge(accumulated.len() + chunk.len()));
                        }
                        accumulated.extend_from_slice(&chunk);
                    }
                    Ok(None) => return Ok(accumulated),
                    Err(e) => return Err(BodyReadError::Reqwest(e)),
                }
            }
        });
        let buf: Vec<u8> = match body_chunks_result {
            Ok(b) => b,
            Err(BodyReadError::TooLarge(observed)) => {
                return Err(HostApiError::new(
                    HostApiErrorCode::Host(HostCode::HttpResponseTooLarge),
                    false,
                    format!(
                        "response body of {observed}+ bytes exceeds {MAX_RESPONSE_BYTES}-byte limit (read aborted mid-stream)"
                    ),
                ));
            }
            Err(BodyReadError::Reqwest(e)) => {
                return Err(HostApiError::new(
                    HostApiErrorCode::Host(HostCode::HttpUpstreamUnreachable),
                    true,
                    format!("response body read failed: {e}"),
                ));
            }
        };

        let body_utf8_lossy = String::from_utf8_lossy(&buf).into_owned();
        Ok(FetchResp { status, headers, body_utf8_lossy })
    }

    fn current_agent_policy_name(&self) -> String {
        self.agent_policy.clone()
    }

    fn current_plugin_name(&self) -> String {
        self.plugin_name.clone()
    }
}

/// Convert a `permitlayer_core::policy::Decision` into the
/// plugin-side `DecisionDesc` shape.
fn decision_to_desc(d: Decision) -> DecisionDesc {
    match d {
        Decision::Allow => DecisionDesc::Allow,
        Decision::Prompt { policy_name, rule_id } => DecisionDesc::Prompt { policy_name, rule_id },
        Decision::Deny { policy_name, rule_id, denied_scope, denied_resource } => {
            DecisionDesc::Deny { policy_name, rule_id, denied_scope, denied_resource }
        }
        // `Decision` is `#[non_exhaustive]` per
        // `policy/eval.rs:41-43`. Future variants conservatively
        // map to a synthetic Deny so plugins fail closed rather
        // than seeing an unexpected shape.
        //
        // Story 6.2 review finding M9: use a NAMED sentinel for
        // `policy_name` so operators can grep audit logs for
        // `__internal__unknown_policy_variant__` rather than
        // hunting for empty-string anomalies. This sentinel
        // cannot collide with a real policy name because real
        // names are validated by `permitlayer-core::policy::schema`
        // to match `[A-Za-z0-9_-]+` (no double-underscore prefix).
        _ => DecisionDesc::Deny {
            policy_name: "__internal__unknown_policy_variant__".to_owned(),
            rule_id: "unknown-decision-variant".to_owned(),
            denied_scope: None,
            denied_resource: None,
        },
    }
}

/// Internal error type for the bounded-stream body read in
/// `fetch`. Kept private — translated to `HostApiError` at the
/// call site. The `TooLarge` variant carries the observed byte
/// count for operator diagnostics.
enum BodyReadError {
    TooLarge(usize),
    Reqwest(reqwest::Error),
}

/// Classify a `reqwest::Error` as a DNS-resolution failure by
/// walking the error's source chain looking for hyper / hickory /
/// stdlib types whose name implies DNS resolution.
///
/// **Story 6.2 review finding B5:** the prior implementation used
/// `e.to_string().to_lowercase().contains("dns")` which was
/// locale/version-dependent string sniffing — any reqwest/hyper
/// upgrade that changed error formatting would silently
/// misclassify DNS failures as `HttpUpstreamUnreachable`. This
/// implementation walks the source chain and checks the rendered
/// type name (via `Debug` formatting on the source) which is
/// stable across reqwest minor versions.
fn classify_as_dns_error(e: &reqwest::Error) -> bool {
    // B5 (re-review patch 2026-04-18): two refinements —
    // 1. Bound the source-chain walk at 16 (defense against a
    //    self-referential `source()` chain causing an infinite loop).
    // 2. Truncate the per-iteration `Debug` rendering at 1 KiB
    //    before the `to_lowercase` + `contains` checks, so a
    //    user-controlled URL containing the word "dns" or
    //    "resolve" deep in a long chain doesn't blow up CPU
    //    AND doesn't trigger false-positive DNS classification
    //    just because the URL fragment happens to be in the
    //    Debug output. (We additionally check that the matched
    //    fragment is BOUNDED by non-letter chars, so e.g. the
    //    URL host `api.resolve.io` doesn't match the `resolve`
    //    needle since it appears as part of a hostname token,
    //    not a Rust type name.)
    //
    // The fundamental approach (Debug-string sniffing) is still
    // brittle relative to true type-downcast checks, but
    // reqwest's typed predicates (`is_connect`, `is_timeout`,
    // `is_request`) don't expose a DNS-specific check; the
    // best we can do without taking a hyper/hickory direct
    // dep is the truncated-bounded substring scan.
    use std::error::Error as StdError;
    const MAX_CHAIN_DEPTH: usize = 16;
    const MAX_DEBUG_BYTES: usize = 1024;
    let mut current: Option<&dyn StdError> = Some(e);
    let mut depth = 0;
    while let Some(err) = current {
        if depth >= MAX_CHAIN_DEPTH {
            // Chain too deep (or self-referential); stop walking.
            // Preserves the H1-equivalent guard from prior reviews.
            return false;
        }
        depth += 1;
        let dbg = format!("{err:?}");
        let dbg_lower = if dbg.len() > MAX_DEBUG_BYTES {
            // Truncate at a UTF-8 boundary so `to_lowercase`
            // doesn't choke. `floor_char_boundary` is unstable;
            // walk back from the byte index until we find a
            // boundary.
            let mut cap = MAX_DEBUG_BYTES;
            while cap > 0 && !dbg.is_char_boundary(cap) {
                cap -= 1;
            }
            dbg[..cap].to_lowercase()
        } else {
            dbg.to_lowercase()
        };
        // Check for DNS-specific type-name fragments. Match only
        // when the fragment appears with a non-letter neighbor
        // on at least one side (rough proxy for "this is a Rust
        // type-name fragment, not a substring of a URL or other
        // user-controlled string").
        if contains_word_fragment(&dbg_lower, "dns_lookup")
            || contains_word_fragment(&dbg_lower, "resolveerror")
            || contains_word_fragment(&dbg_lower, "name resolution")
        {
            return true;
        }
        current = err.source();
    }
    false
}

/// Helper: check whether `needle` appears in `haystack` with at
/// least one non-letter neighbor (start, end, or non-ASCII-letter
/// before/after). Used by `classify_as_dns_error` to reduce false
/// positives from URL-host-string matches.
fn contains_word_fragment(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    let bytes = haystack.as_bytes();
    let needle_bytes = needle.as_bytes();
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle_bytes {
            let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphabetic();
            let after_ok =
                i + needle.len() == bytes.len() || !bytes[i + needle.len()].is_ascii_alphabetic();
            if before_ok || after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::Path;
    use zeroize::Zeroizing;

    fn test_token_issuer() -> Arc<ScopedTokenIssuer> {
        Arc::new(ScopedTokenIssuer::new(Zeroizing::new([0xAB; 32])))
    }

    fn test_scrub_engine() -> Arc<ScrubEngine> {
        Arc::new(ScrubEngine::new(permitlayer_core::scrub::builtin_rules().to_vec()).unwrap())
    }

    fn test_policy_set(toml_src: &str) -> Arc<ArcSwap<PolicySet>> {
        let policy = PolicySet::compile_from_str(toml_src, Path::new("test.toml")).unwrap();
        Arc::new(ArcSwap::from_pointee(policy))
    }

    fn test_services(
        vault_dir: PathBuf,
        agent_policy: &str,
        plugin_name: &str,
    ) -> ProxyHostServices {
        ProxyHostServices::new(
            test_token_issuer(),
            test_scrub_engine(),
            test_policy_set(
                r#"
                    [[policies]]
                    name = "default"
                    scopes = ["gmail.readonly", "http.fetch"]
                    resources = ["*"]
                    approval-mode = "auto"
                "#,
            ),
            vault_dir,
            agent_policy.to_owned(),
            plugin_name.to_owned(),
            Arc::new(AuditDispatcher::none()),
            "test-agent".to_owned(),
        )
    }

    #[test]
    fn proxy_host_services_current_agent_policy_name() {
        let svc =
            test_services(tempfile::tempdir().unwrap().path().to_owned(), "agent-jamie", "notion");
        assert_eq!(svc.current_agent_policy_name(), "agent-jamie");
    }

    #[test]
    fn proxy_host_services_current_plugin_name() {
        let svc =
            test_services(tempfile::tempdir().unwrap().path().to_owned(), "default", "notion");
        assert_eq!(svc.current_plugin_name(), "notion");
    }

    #[test]
    fn proxy_host_services_issue_scoped_token_returns_60s_token() {
        let dir = tempfile::tempdir().unwrap();
        // Seed a vault meta file so the service is "connected".
        std::fs::write(dir.path().join("gmail-meta.json"), r#"{"client_type":"shared-casa"}"#)
            .unwrap();
        let svc = test_services(dir.path().to_owned(), "default", "notion");
        let token = svc.issue_scoped_token("gmail", "gmail.readonly").unwrap();
        assert!(!token.bearer.is_empty(), "bearer must be non-empty");
        assert_eq!(token.scope, "gmail.readonly");
        assert_eq!(token.resource, "gmail");
        let now = chrono::Utc::now().timestamp() as u64;
        assert!(token.expires_at_epoch_secs > now, "token must expire in the future");
        assert!(
            token.expires_at_epoch_secs - now <= 60,
            "token TTL must be ≤60s; got {}",
            token.expires_at_epoch_secs - now
        );
    }

    #[test]
    fn proxy_host_services_issue_scoped_token_unknown_service_throws() {
        let dir = tempfile::tempdir().unwrap();
        let svc = test_services(dir.path().to_owned(), "default", "notion");
        let err = svc.issue_scoped_token("nonexistent", "any").unwrap_err();
        assert_eq!(err.code, HostApiErrorCode::Host(HostCode::OauthUnknownService));
        assert!(!err.retryable);
    }

    #[test]
    fn proxy_host_services_list_connected_services_alphabetically_sorted() {
        let dir = tempfile::tempdir().unwrap();
        for svc in ["gmail", "drive", "calendar"] {
            std::fs::write(
                dir.path().join(format!("{svc}-meta.json")),
                r#"{"client_type":"shared-casa"}"#,
            )
            .unwrap();
        }
        let svc = test_services(dir.path().to_owned(), "default", "notion");
        let list = svc.list_connected_services().unwrap();
        assert_eq!(list, vec!["calendar".to_owned(), "drive".to_owned(), "gmail".to_owned()]);
    }

    #[test]
    fn proxy_host_services_list_connected_services_empty_when_vault_missing() {
        let dir = tempfile::tempdir().unwrap();
        // Pass a non-existent subdirectory to assert graceful handling.
        let svc = test_services(dir.path().join("does-not-exist"), "default", "notion");
        let list = svc.list_connected_services().unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn list_connected_services_returns_in_under_10ms_for_100_entries() {
        // AC #14: quantify the "blocking is fine on spawn_blocking"
        // performance budget: <10ms for a 100-entry vault dir.
        let dir = tempfile::tempdir().unwrap();
        for i in 0..100usize {
            std::fs::write(
                dir.path().join(format!("service-{i:03}-meta.json")),
                r#"{"client_type":"shared-casa"}"#,
            )
            .unwrap();
        }
        let svc = test_services(dir.path().to_owned(), "default", "notion");
        let start = std::time::Instant::now();
        let list = svc.list_connected_services().unwrap();
        let elapsed = start.elapsed();
        assert_eq!(list.len(), 100, "expected 100 entries");
        assert!(
            elapsed < std::time::Duration::from_millis(10),
            "list_connected_services took {elapsed:?}; must be <10ms for 100 entries"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multi_thread_single_worker_fails_closed_in_debug() {
        // AC #13: a multi-thread runtime with only 1 worker thread
        // should fail-closed in debug builds.
        //
        // We can't construct a true worker_threads(1) runtime inside
        // a test runner that is already on a worker_threads(2) tokio
        // runtime, but we CAN verify the guard compiles and produces
        // the expected error by running in debug mode with a custom
        // runtime.
        //
        // Build a separate `worker_threads(1)` multi-thread runtime
        // to exercise the guard directly.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("single-worker multi-thread runtime");

        let svc =
            test_services(tempfile::tempdir().unwrap().path().to_owned(), "default", "notion");

        // Must run rt.block_on from an OS thread that is NOT inside
        // another tokio runtime, to avoid "cannot start runtime from
        // within a runtime". Wrap in std::thread::spawn.
        let result: Result<FetchResp, HostApiError> = std::thread::spawn(move || {
            rt.block_on(async move {
                tokio::task::spawn_blocking(move || {
                    svc.fetch(FetchReq {
                        method: "GET".to_owned(),
                        url: "https://example.com/".to_owned(),
                        headers: Vec::new(),
                        body: None,
                        timeout_ms: 1000,
                    })
                })
                .await
                .expect("spawn_blocking must not be cancelled")
            })
        })
        .join()
        .expect("thread must not panic");

        // In debug builds: fails closed with HttpUpstreamUnreachable.
        // In release builds: emits a warn but proceeds (may fail for
        // other reasons — we only assert not an unexpected panic).
        #[cfg(debug_assertions)]
        match result {
            Err(HostApiError { code, message, .. }) => {
                assert_eq!(code, HostApiErrorCode::Host(HostCode::HttpUpstreamUnreachable));
                assert!(
                    message.contains("worker") || message.contains("CALLING CONTRACT"),
                    "error must mention calling contract; got: {message}"
                );
            }
            Ok(_) => panic!("single-worker multi-thread runtime must fail-closed in debug builds"),
        }
    }

    #[test]
    fn proxy_host_services_evaluate_policy_returns_allow() {
        let svc =
            test_services(tempfile::tempdir().unwrap().path().to_owned(), "default", "notion");
        let req = PolicyEvalReq {
            policy_name: "default".to_owned(),
            scope: "gmail.readonly".to_owned(),
            resource: None,
        };
        let decision = svc.evaluate_policy(req).unwrap();
        assert!(matches!(decision, DecisionDesc::Allow));
    }

    #[test]
    fn proxy_host_services_evaluate_policy_returns_deny_for_out_of_allowlist_scope() {
        let svc =
            test_services(tempfile::tempdir().unwrap().path().to_owned(), "default", "notion");
        let req = PolicyEvalReq {
            policy_name: "default".to_owned(),
            scope: "gmail.modify".to_owned(),
            resource: None,
        };
        let decision = svc.evaluate_policy(req).unwrap();
        match decision {
            DecisionDesc::Deny { rule_id, denied_scope, .. } => {
                assert_eq!(rule_id, "default-deny-scope-out-of-allowlist");
                assert_eq!(denied_scope, Some("gmail.modify".to_owned()));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn proxy_host_services_scrub_text_redacts_otp_and_returns_match_metadata() {
        let svc =
            test_services(tempfile::tempdir().unwrap().path().to_owned(), "default", "notion");
        let resp = svc.scrub_text("Your verification code is 123456").unwrap();
        assert!(
            resp.output.contains("<REDACTED_OTP>"),
            "output must contain redacted placeholder; got `{}`",
            resp.output
        );
        assert!(!resp.matches.is_empty(), "must report at least one match");
        let m = &resp.matches[0];
        assert_eq!(m.rule_id, "otp-6digit");
        assert_eq!(m.placeholder, "<REDACTED_OTP>");
    }

    #[test]
    fn proxy_host_services_scrub_text_clean_input_returns_unchanged_no_matches() {
        let svc =
            test_services(tempfile::tempdir().unwrap().path().to_owned(), "default", "notion");
        let resp = svc.scrub_text("hello, world").unwrap();
        assert_eq!(resp.output, "hello, world");
        assert!(resp.matches.is_empty());
    }

    /// AC #37 (Story 6.2 AD4 + review finding B1): `fetch` MUST
    /// fail-closed on a current-thread tokio runtime instead of
    /// panicking with `"Cannot start a runtime from within a
    /// runtime"`. The prior version detected only absence-of-runtime
    /// via `Handle::try_current`; this test pins the new
    /// runtime-flavor check.
    #[test]
    fn fetch_on_current_thread_runtime_fails_closed_not_panics() {
        let svc =
            test_services(tempfile::tempdir().unwrap().path().to_owned(), "default", "notion");
        // Build a current-thread runtime explicitly. Without
        // `enable_all`, reqwest can't even construct timers — but
        // the AD4 guard fires BEFORE any timer-needing work, so the
        // test passes even on the minimal runtime.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime must build");
        // Wrap in `catch_unwind` so a regression that panics here
        // (instead of returning `Err`) shows up as a test failure
        // rather than aborting the test process.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rt.block_on(async {
                svc.fetch(FetchReq {
                    method: "GET".to_owned(),
                    // Use a domain (not IP literal) so the SSRF
                    // blocklist passes it through — only the
                    // current-thread runtime guard (AD4) fires here.
                    url: "https://example.com/".to_owned(),
                    headers: Vec::new(),
                    body: None,
                    timeout_ms: 1000,
                })
            })
        }));
        let outcome = match result {
            Ok(r) => r,
            Err(_) => panic!(
                "AD4 violation: fetch panicked on current-thread runtime; must fail-closed with HttpUpstreamUnreachable"
            ),
        };
        match outcome {
            Err(HostApiError { code, retryable, message }) => {
                assert_eq!(code, HostApiErrorCode::Host(HostCode::HttpUpstreamUnreachable));
                assert!(!retryable, "current-thread runtime is a config bug, not retryable");
                assert!(
                    message.contains("multi-thread") || message.contains("spawn_blocking"),
                    "error message must explain the calling-contract violation; got `{message}`"
                );
            }
            Ok(_) => panic!("expected HostApiError(HttpUpstreamUnreachable); got Ok"),
        }
    }

    /// AC #16 / B2/B3 (re-review patch 2026-04-18): load-bearing
    /// "policy deny blocks fetch BEFORE dispatch" assertion.
    /// Stand up a real loopback `axum` server, configure
    /// `ProxyHostServices` with a deny policy for the loopback
    /// host, fire a `fetch` from a multi-thread runtime, and
    /// assert (a) the rejection is `HttpPolicyDenied`, AND (b)
    /// the mock server observes ZERO HTTP requests during a
    /// 200ms post-rejection grace window.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fetch_policy_deny_blocks_before_dispatch_zero_connections() {
        use std::sync::Arc as StdArc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Mock axum server that increments a request counter.
        let counter = StdArc::new(AtomicUsize::new(0));
        let counter_clone = StdArc::clone(&counter);
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(move || {
                let counter = StdArc::clone(&counter_clone);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    "ok"
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Build a ProxyHostServices with a policy that DENIES
        // `http.fetch` against the loopback host. The deny path
        // is keyed off `resource = <host>`, so we need the policy
        // to NOT include `127.0.0.1` in resources.
        let policy_set = test_policy_set(
            r#"
                [[policies]]
                name = "default"
                scopes = ["http.fetch"]
                resources = ["only-this-other-host.example.com"]
                approval-mode = "auto"
            "#,
        );
        let svc = ProxyHostServices::new(
            test_token_issuer(),
            test_scrub_engine(),
            policy_set,
            tempfile::tempdir().unwrap().path().to_owned(),
            "default".to_owned(),
            "test".to_owned(),
            Arc::new(AuditDispatcher::none()),
            "test-agent".to_owned(),
        );

        // Fetch from a spawn_blocking worker per the CALLING CONTRACT.
        let fetch_result = tokio::task::spawn_blocking(move || {
            svc.fetch(FetchReq {
                method: "GET".to_owned(),
                url: format!("http://localhost:{port}/"),
                headers: Vec::new(),
                body: None,
                timeout_ms: 1000,
            })
        })
        .await
        .unwrap();

        // Assert (a): policy deny rejection.
        match fetch_result {
            Err(HostApiError { code, .. }) => {
                assert_eq!(code, HostApiErrorCode::Host(HostCode::HttpPolicyDenied));
            }
            Ok(_) => panic!("expected HttpPolicyDenied rejection"),
        }

        // Assert (b): mock server observed ZERO requests during a
        // 200ms grace window. This is the load-bearing
        // "no policy bypass via plugins" invariant.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "AC #16 violation: mock server received connections after policy deny — \
             dispatch happened despite the policy gate"
        );

        server_handle.abort();
    }

    /// M8 (re-review patch 2026-04-18): body-cap boundary test.
    /// Verifies the response-body cap rejects payloads exceeding
    /// the 10 MiB limit. Uses a real body (rather than a lying
    /// Content-Length header — hyper rejects that with its own
    /// error before we get a chance to inspect). The bounded-
    /// stream read aborts mid-stream when the cap is exceeded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fetch_response_body_cap_rejects_oversize_real_body() {
        // Mock axum server that returns a real 11 MiB body —
        // exceeds the MAX_RESPONSE_BYTES (10 MiB) cap.
        let app = axum::Router::new().route(
            "/oversize",
            axum::routing::get(|| async {
                let body = vec![b'x'; 11 * 1024 * 1024];
                axum::response::Response::builder()
                    .status(200)
                    .body(axum::body::Body::from(body))
                    .unwrap()
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let svc = ProxyHostServices::new(
            test_token_issuer(),
            test_scrub_engine(),
            test_policy_set(
                r#"
                    [[policies]]
                    name = "default"
                    scopes = ["http.fetch"]
                    resources = ["*"]
                    approval-mode = "auto"
                "#,
            ),
            tempfile::tempdir().unwrap().path().to_owned(),
            "default".to_owned(),
            "test".to_owned(),
            Arc::new(AuditDispatcher::none()),
            "test-agent".to_owned(),
        );

        let fetch_result = tokio::task::spawn_blocking(move || {
            svc.fetch(FetchReq {
                method: "GET".to_owned(),
                url: format!("http://localhost:{port}/oversize"),
                headers: Vec::new(),
                body: None,
                timeout_ms: 30_000,
            })
        })
        .await
        .unwrap();

        match fetch_result {
            Err(HostApiError { code, message, .. }) => {
                assert_eq!(code, HostApiErrorCode::Host(HostCode::HttpResponseTooLarge));
                assert!(
                    message.contains("exceeds") || message.contains("Content-Length"),
                    "error message should mention the cap; got `{message}`"
                );
            }
            Ok(_) => panic!("expected HttpResponseTooLarge for 11 MiB body"),
        }
        server_handle.abort();
    }

    /// AC #28 follow-up: `proxy_host_services_fetch` unit test
    /// — verifies the fetch path produces a valid Ok response
    /// for a small body.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn proxy_host_services_fetch_basic_roundtrip() {
        let app = axum::Router::new().route(
            "/hello",
            axum::routing::get(|| async {
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "text/plain")
                    .body(axum::body::Body::from("hello world"))
                    .unwrap()
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let svc = ProxyHostServices::new(
            test_token_issuer(),
            test_scrub_engine(),
            test_policy_set(
                r#"
                    [[policies]]
                    name = "default"
                    scopes = ["http.fetch"]
                    resources = ["*"]
                    approval-mode = "auto"
                "#,
            ),
            tempfile::tempdir().unwrap().path().to_owned(),
            "default".to_owned(),
            "test".to_owned(),
            Arc::new(AuditDispatcher::none()),
            "test-agent".to_owned(),
        );

        let resp = tokio::task::spawn_blocking(move || {
            svc.fetch(FetchReq {
                method: "GET".to_owned(),
                url: format!("http://localhost:{port}/hello"),
                headers: Vec::new(),
                body: None,
                timeout_ms: 5000,
            })
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body_utf8_lossy, "hello world");
        server_handle.abort();
    }

    // ----- Story 8.4 AC #13: origin_str produces correct value for Host variant -----
    // The Plugin variant test lives in permitlayer-plugins/src/host_api/services.rs
    // because PluginThrownCode::new_for_test is only accessible within that crate.

    #[test]
    fn audit_event_includes_origin_field_for_host_api_error() {
        use permitlayer_plugins::{HostApiErrorCode, HostCode, origin_str};

        // Host-emitted error: origin must be "host_thrown".
        let host_code = HostApiErrorCode::Host(HostCode::HttpTimeout);
        assert_eq!(
            origin_str(&host_code),
            "host_thrown",
            "HostCode errors must report origin = host_thrown"
        );
    }
}
