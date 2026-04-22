//! Host-API service injection trait + supporting types.
//!
//! Every `host_api/<name>.rs` submodule is a thin marshalling layer
//! between the JS surface and a small set of Rust calls. Those Rust
//! calls live behind the [`HostServices`] trait so the plugin crate
//! does **not** depend on `permitlayer-proxy` (which is the upstream
//! crate per `deny.toml:124-127` — `permitlayer-proxy → permitlayer-
//! plugins`, never reverse).
//!
//! The production implementation of `HostServices` lives in
//! `crates/permitlayer-proxy/src/plugin_host_services.rs::ProxyHostServices`
//! (Story 6.2 Task 7) and reads through the proxy's existing
//! `Arc<ScopedTokenIssuer>`, `Arc<ScrubEngine>`, `Arc<Vault>`, etc.
//!
//! The trait itself is `Send + Sync` so `Arc<dyn HostServices>` can
//! be cheaply cloned across the per-call boundary, and is **fully
//! synchronous** — `fetch` blocks the caller, NOT a tokio reactor
//! task. Callers MUST invoke
//! [`crate::PluginRuntime::with_host_api`] inside
//! [`tokio::task::spawn_blocking`]; see the CALLING CONTRACT
//! documented on `ProxyHostServices`.
//!
//! # Why blocking, not async
//!
//! Story 6.1's B4 review patch rejected `rquickjs`'s `full-async`
//! feature in favor of `full`. That kept the sandbox attack surface
//! narrow (no async-lock / event-listener / loader pulled in
//! transitively). Re-introducing `full-async` for the host API
//! would defeat that decision. Instead the host-API submodules treat
//! every `HostServices` method as a synchronous call; the proxy-side
//! impl uses `tokio::runtime::Handle::current().block_on(...)`
//! internally to drive any reqwest futures. Plugin call sites are
//! latency-dominated by the upstream API anyway, so the extra
//! blocking-worker use is noise.

use std::fmt;

/// Service injection point for the JS host API.
///
/// One [`HostServices`] instance is constructed per plugin call by
/// the loader (Story 6.3 territory) and passed into
/// [`crate::PluginRuntime::with_host_api`]. The host-API submodules
/// capture a `&dyn HostServices` reference into the closures they
/// install on `globalThis.agentsso` — those closures are guaranteed
/// to be invoked only during the lifetime of the `with_host_api`
/// call, so capturing a reference (not an `Arc`) is sound.
pub trait HostServices: Send + Sync {
    /// Issue a short-lived scoped token for an upstream service +
    /// scope on behalf of the calling agent. Returns the HS256
    /// bearer string that the plugin then passes to
    /// [`HostServices::fetch`] as `Authorization: Bearer <bearer>`.
    /// The plugin **never** touches the raw OAuth credential — the
    /// daemon validates the scoped bearer on the way back in and
    /// swaps it for the upstream credential at dispatch time.
    fn issue_scoped_token(
        &self,
        service: &str,
        scope: &str,
    ) -> Result<ScopedTokenDesc, HostApiError>;

    /// Enumerate every service that currently has vault credentials.
    /// Read-only feature-detection surface for plugins (e.g. "is
    /// Drive connected?") that does NOT trigger a credential fetch
    /// or a refresh attempt.
    fn list_connected_services(&self) -> Result<Vec<String>, HostApiError>;

    /// Evaluate a policy decision. The plugin-facing
    /// `agentsso.policy.enforce` is a thin marshaller over this.
    /// Defaults to the calling agent's bound policy if `req.policy_name`
    /// is empty (the marshaller in `host_api/policy.rs` fills it in
    /// from [`Self::current_agent_policy_name`]).
    fn evaluate_policy(&self, req: PolicyEvalReq) -> Result<DecisionDesc, HostApiError>;

    /// Run the scrub engine over a UTF-8 string and return the
    /// scrubbed output plus per-match metadata. Infallible in
    /// practice (returns `Result` for uniformity with other trait
    /// methods; future signatures may surface real errors).
    fn scrub_text(&self, input: &str) -> Result<ScrubResponse, HostApiError>;

    /// Execute an HTTP request on behalf of the plugin. Synchronous
    /// — returns when the upstream response lands or the timeout
    /// fires. The host-API marshaller wraps the result in a JS
    /// Promise so the JS side `await`s naturally; the underlying
    /// I/O happens on a `spawn_blocking` worker, not a tokio
    /// reactor task.
    ///
    /// **Implementation contract:** the impl is responsible for
    /// running the policy check (`policy.fetch`/`http.fetch` scope
    /// gating) BEFORE dispatching the request. The marshaller in
    /// `host_api/http.rs` does the URL-scheme + User-Agent
    /// preparation; the impl does the policy gate + the actual
    /// dispatch.
    fn fetch(&self, req: FetchReq) -> Result<FetchResp, HostApiError>;

    /// Name of the policy bound to the calling agent. Used as the
    /// default `policyName` in `agentsso.policy.enforce` when the
    /// plugin omits it. Resolved by the loader (Story 6.3) from the
    /// agent identity registry before constructing the
    /// `HostServices` impl.
    ///
    /// **Returns owned `String` (Story 6.2 AD3).** The earlier `&str`
    /// signature forced the test mock into `Box::leak` per call;
    /// `String` is the correct shape. These methods are called once
    /// at register time per submodule (not per JS call), so the
    /// allocation cost is negligible.
    fn current_agent_policy_name(&self) -> String;

    /// Connector name (e.g. `"google-gmail"`, `"notion"`) for User-
    /// Agent injection in `agentsso.http.fetch`. Bound by the
    /// loader at per-call time. **Returns owned `String` per AD3.**
    fn current_plugin_name(&self) -> String;
}

/// A scoped token handed back to a plugin.
///
/// The `bearer` field is the HS256 string the plugin attaches to
/// `agentsso.http.fetch` as `Authorization: Bearer <bearer>`. It is
/// **not** an upstream OAuth token — the daemon validates it on
/// ingress and swaps for the real upstream credential at dispatch
/// time. The 60-second TTL caps blast radius on plugin compromise.
///
/// **Manual `Debug` impl** (not derived) — prints only the first 8
/// chars of `bearer` followed by `"..."` so a stray `tracing::debug!`
/// call cannot leak the full token. Mirrors the
/// `permitlayer-proxy::ProxyError::AuthInvalidToken { token_prefix }`
/// precedent at `crates/permitlayer-proxy/src/error.rs:48-51`.
#[derive(Clone)]
pub struct ScopedTokenDesc {
    /// HS256 bearer to be sent in the `Authorization: Bearer ...`
    /// header on subsequent `agentsso.http.fetch` calls.
    pub bearer: String,
    /// Scope this bearer is valid for (e.g. `"gmail.readonly"`).
    pub scope: String,
    /// Resource (typically the service name; mirrors
    /// `ScopedToken.resource`).
    pub resource: String,
    /// Unix epoch seconds at which the token expires. Plugins
    /// `Date.now()/1000` against this for proactive refresh.
    pub expires_at_epoch_secs: u64,
}

impl fmt::Debug for ScopedTokenDesc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Take the first 8 bytes of the bearer, falling back to the
        // whole string if it's shorter. NEVER print the full bearer.
        let prefix: String = self.bearer.chars().take(8).collect();
        f.debug_struct("ScopedTokenDesc")
            .field("bearer", &format!("{prefix}..."))
            .field("scope", &self.scope)
            .field("resource", &self.resource)
            .field("expires_at_epoch_secs", &self.expires_at_epoch_secs)
            .finish()
    }
}

/// Input to [`HostServices::evaluate_policy`].
#[derive(Debug, Clone)]
pub struct PolicyEvalReq {
    /// Policy to evaluate against. Empty string means "use the
    /// caller's bound policy" — the marshaller in
    /// `host_api/policy.rs` resolves this via
    /// [`HostServices::current_agent_policy_name`] before invoking
    /// the trait method.
    pub policy_name: String,
    /// OAuth scope the plugin is asking about (e.g.
    /// `"gmail.readonly"`).
    pub scope: String,
    /// Resource the request targets, when applicable.
    pub resource: Option<String>,
}

/// A policy decision marshalled back to JS.
///
/// Variants mirror `permitlayer_core::policy::Decision` but are
/// re-defined here so the host-API submodules can convert without
/// pulling `permitlayer-core` types directly into the JS
/// marshalling layer (which would tightly couple the plugin crate
/// to core's serde shape — keeping a local DTO lets the JS shape
/// evolve independently from any future core refactor).
#[derive(Debug, Clone)]
pub enum DecisionDesc {
    /// Request is allowed.
    Allow,
    /// Request requires operator approval (host-API surface treats
    /// this distinct from Allow so the plugin can short-circuit).
    Prompt {
        /// Policy that produced the prompt decision.
        policy_name: String,
        /// Stable rule ID.
        rule_id: String,
    },
    /// Request is denied.
    Deny {
        /// Policy that produced the denial.
        policy_name: String,
        /// Stable rule ID.
        rule_id: String,
        /// The scope that triggered the deny, when scope-driven.
        denied_scope: Option<String>,
        /// The resource that triggered the deny, when resource-driven.
        denied_resource: Option<String>,
    },
}

/// Output of [`HostServices::scrub_text`].
#[derive(Debug, Clone)]
pub struct ScrubResponse {
    /// The scrubbed text.
    pub output: String,
    /// One entry per replacement, in left-to-right document order.
    pub matches: Vec<ScrubMatchDesc>,
}

/// A single scrub-match record, JS-marshallable.
#[derive(Debug, Clone)]
pub struct ScrubMatchDesc {
    /// Stable rule identifier (e.g. `"otp-6digit"`).
    pub rule_id: String,
    /// The placeholder string written to `output` (e.g.
    /// `"<REDACTED_OTP>"`).
    pub placeholder: String,
    /// Byte offset of `placeholder` within `output`.
    pub span_offset: usize,
    /// Byte length of `placeholder`.
    pub span_length: usize,
}

/// Input to [`HostServices::fetch`].
#[derive(Debug, Clone)]
pub struct FetchReq {
    /// HTTP method (uppercase). Defaults to `"GET"` at the
    /// marshaller layer when the plugin omits it.
    pub method: String,
    /// Full URL (must be `http://` or `https://` — the marshaller
    /// rejects other schemes before constructing this struct).
    pub url: String,
    /// Header pairs in insertion order. The marshaller injects the
    /// permitlayer User-Agent into this list (appending to a plugin-
    /// provided UA when present, prepending the permitlayer suffix).
    pub headers: Vec<(String, String)>,
    /// Optional request body bytes.
    pub body: Option<Vec<u8>>,
    /// Per-request timeout. Bounded at the marshaller layer to
    /// `[1ms, 30000ms]`; defaults to 30 s when the plugin omits it.
    pub timeout_ms: u64,
}

/// Output of [`HostServices::fetch`].
#[derive(Debug, Clone)]
pub struct FetchResp {
    /// HTTP status code.
    pub status: u16,
    /// Response headers in arrival order.
    pub headers: Vec<(String, String)>,
    /// Response body decoded with UTF-8 lossy decoding (invalid
    /// sequences become `U+FFFD`). 1.0.0 has no `arrayBuffer`
    /// response type; binary support is deferred to 1.1.0.
    pub body_utf8_lossy: String,
}

/// Opaque newtype wrapping a plugin-thrown error code string.
///
/// **Unforgeability invariant:** the only construction path is
/// `PluginThrownCode::new_from_js`, which is `pub(crate)` and only
/// reachable from `crate::runtime::try_extract_agentsso_error`. External
/// crates (`permitlayer-proxy`, `permitlayer-daemon`) can read the value
/// via [`PluginThrownCode::as_str`] and pattern-match `HostApiErrorCode::Plugin(_)`,
/// but they CANNOT construct a `Plugin(...)` variant themselves.
///
/// If a future test within this crate needs to construct one, add a
/// `#[cfg(test)] pub fn new_for_test(s: String) -> Self` here — never
/// widen `new_from_js` to `pub`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginThrownCode(String);

impl PluginThrownCode {
    /// The only legitimate construction path — called exclusively by
    /// `runtime::try_extract_agentsso_error`.
    pub(crate) fn new_from_js(s: String) -> Self {
        PluginThrownCode(s)
    }

    /// Returns the dotted-lowercase code string exactly as the plugin passed it.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `#[cfg(test)]` constructor for unit tests within this crate.
    #[cfg(test)]
    pub fn new_for_test(s: impl Into<String>) -> Self {
        PluginThrownCode(s.into())
    }
}

impl fmt::Display for PluginThrownCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Error returned when `HostCode::from_str` cannot match a known variant.
///
/// Unknown strings should be routed to `PluginThrownCode::new_from_js`
/// (a `pub(crate)` constructor) by the caller
/// (`runtime::try_extract_agentsso_error`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownHostCode;

/// Named host-generated error codes.
///
/// This is the inner enum of [`HostApiErrorCode::Host`]. The variant set
/// is the **semver-locked surface** that Story 6.5's `xtask validate-plugin-api`
/// will snapshot into `host-api.lock`. Adding variants in 1.x is **additive**
/// (per `#[non_exhaustive]`); removing or renaming is a **breaking change**
/// requiring a major bump.
///
/// Naming convention: dotted lowercase (`"oauth.unknown_service"`).
/// **NOT** kebab-case (which is the TOML / CLI-flag convention per
/// architecture.md:472-480) — JS error codes are dotted by industry
/// norm (see DOM `DOMException.code` taxonomy, Node `SystemError.code`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostCode {
    /// `agentsso.oauth.getToken` invoked with a service that has no
    /// vault credentials.
    OauthUnknownService,
    /// `agentsso.oauth.getToken` invoked with a scope outside the
    /// agent's policy allowlist.
    OauthScopeDenied,
    /// `agentsso.oauth.getToken` invoked with no scope (1.0.0
    /// requires explicit scope).
    OauthScopeRequired,
    /// Refresh attempt on an expired token failed (vault returned
    /// `InvalidGrant` → `retryable=false`; `RefreshExhausted` →
    /// `retryable=true`).
    OauthRefreshFailed,
    /// `agentsso.policy.enforce` evaluation produced a structural
    /// failure (policy not loaded, IR missing, etc.). Distinct from
    /// a deny outcome — a deny is still a successful evaluation.
    PolicyEvalFailed,
    /// `agentsso.scrub.text` invoked with a non-string input that
    /// cannot be coerced (`undefined`, `null`, plain object).
    ScrubInvalidInput,
    /// `agentsso.http.fetch` invoked with a URL whose scheme is not
    /// `http:` or `https:`.
    HttpSchemeNotAllowed,
    /// `agentsso.http.fetch` blocked by the internal policy gate.
    /// `message` carries the denying rule ID for plugin diagnostics.
    HttpPolicyDenied,
    /// `agentsso.http.fetch` exceeded the `timeoutMs` budget.
    /// `retryable=true` since the upstream may simply have been
    /// slow.
    HttpTimeout,
    /// `agentsso.http.fetch` invoked with a malformed `timeoutMs`:
    /// negative, NaN, Infinity, or any value that doesn't reduce to
    /// a positive integer count of milliseconds. Story 6.2 review
    /// finding H9: previously such inputs silently fell through to
    /// the 30s default; now they reject with this code so plugin
    /// authors get a clear signal. Additive variant —
    /// `#[non_exhaustive]` allows.
    HttpInvalidTimeout,
    /// `agentsso.http.fetch` invoked with a `plugin_name` (or other
    /// caller-supplied header field) that contained CR / LF / NUL
    /// or other ASCII control characters which would enable HTTP
    /// header injection. Story 6.2 review finding B3 — defense in
    /// depth even when the loader controls the value. Additive.
    HttpHeaderInjection,
    /// `agentsso.http.fetch` response body exceeded the configured
    /// maximum size. Story 6.2 review finding B2/M7. Additive.
    HttpResponseTooLarge,
    /// `agentsso.http.fetch` headers object contained a value whose
    /// type was not a string (e.g. `{X-Count: 5}`). Story 6.2
    /// review finding H5: previously silently dropped; now rejects
    /// with this code so plugin authors get a clear signal.
    /// Additive.
    HttpHeaderTypeMismatch,
    /// `agentsso.http.fetch` body argument is the wrong type
    /// (not a string, not a Uint8Array) OR fails to decode.
    /// H1 (re-review patch 2026-04-18): previously misrouted
    /// through `HttpHeaderTypeMismatch` which misled plugin
    /// authors. Additive.
    HttpInvalidBody,
    /// `agentsso.http.fetch` request body exceeded the
    /// configured maximum. H7 (re-review patch 2026-04-18) —
    /// matches the response-side cap to prevent plugins from
    /// OOMing the daemon by posting multi-GB bodies. Additive.
    HttpRequestTooLarge,
    /// DNS resolution failed for the request host.
    HttpDnsResolutionFailed,
    /// TLS handshake failed (cert error, protocol mismatch).
    /// `retryable=false` since retrying without operator action is
    /// unlikely to succeed.
    HttpTlsHandshakeFailed,
    /// Upstream connection refused or reset before sending a
    /// response.
    HttpUpstreamUnreachable,
    /// `agentsso.http.fetch` destination IP is on the cloud-metadata
    /// SSRF blocklist (169.254.0.0/16, loopback, etc.). Story 8.3
    /// defense-in-depth — fires even when `http.allow = ["*"]`.
    HttpBlockedMetadataEndpoint,
    /// `agentsso.versionMeetsRequirement` invoked with a string
    /// that doesn't match the `>=MAJOR.MINOR` shape.
    VersionMalformedRequirement,
}

impl fmt::Display for HostCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: &str = match self {
            HostCode::OauthUnknownService => "oauth.unknown_service",
            HostCode::OauthScopeDenied => "oauth.scope_denied",
            HostCode::OauthScopeRequired => "oauth.scope_required",
            HostCode::OauthRefreshFailed => "oauth.refresh_failed",
            HostCode::PolicyEvalFailed => "policy.eval_failed",
            HostCode::ScrubInvalidInput => "scrub.invalid_input",
            HostCode::HttpSchemeNotAllowed => "http.scheme_not_allowed",
            HostCode::HttpPolicyDenied => "http.policy_denied",
            HostCode::HttpTimeout => "http.timeout",
            HostCode::HttpInvalidTimeout => "http.invalid_timeout",
            HostCode::HttpHeaderInjection => "http.header_injection",
            HostCode::HttpResponseTooLarge => "http.response_too_large",
            HostCode::HttpHeaderTypeMismatch => "http.header_type_mismatch",
            HostCode::HttpInvalidBody => "http.invalid_body",
            HostCode::HttpRequestTooLarge => "http.request_too_large",
            HostCode::HttpDnsResolutionFailed => "http.dns_resolution_failed",
            HostCode::HttpTlsHandshakeFailed => "http.tls_handshake_failed",
            HostCode::HttpUpstreamUnreachable => "http.upstream_unreachable",
            HostCode::HttpBlockedMetadataEndpoint => "http.blocked_metadata_endpoint",
            HostCode::VersionMalformedRequirement => "version.malformed_requirement",
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for HostCode {
    type Err = UnknownHostCode;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "oauth.unknown_service" => HostCode::OauthUnknownService,
            "oauth.scope_denied" => HostCode::OauthScopeDenied,
            "oauth.scope_required" => HostCode::OauthScopeRequired,
            "oauth.refresh_failed" => HostCode::OauthRefreshFailed,
            "policy.eval_failed" => HostCode::PolicyEvalFailed,
            "scrub.invalid_input" => HostCode::ScrubInvalidInput,
            "http.scheme_not_allowed" => HostCode::HttpSchemeNotAllowed,
            "http.policy_denied" => HostCode::HttpPolicyDenied,
            "http.timeout" => HostCode::HttpTimeout,
            "http.invalid_timeout" => HostCode::HttpInvalidTimeout,
            "http.header_injection" => HostCode::HttpHeaderInjection,
            "http.response_too_large" => HostCode::HttpResponseTooLarge,
            "http.header_type_mismatch" => HostCode::HttpHeaderTypeMismatch,
            "http.invalid_body" => HostCode::HttpInvalidBody,
            "http.request_too_large" => HostCode::HttpRequestTooLarge,
            "http.dns_resolution_failed" => HostCode::HttpDnsResolutionFailed,
            "http.tls_handshake_failed" => HostCode::HttpTlsHandshakeFailed,
            "http.upstream_unreachable" => HostCode::HttpUpstreamUnreachable,
            "http.blocked_metadata_endpoint" => HostCode::HttpBlockedMetadataEndpoint,
            "version.malformed_requirement" => HostCode::VersionMalformedRequirement,
            _ => return Err(UnknownHostCode),
        })
    }
}

/// Outer error-code enum with structural provenance.
///
/// `Host(HostCode)` — emitted by the host runtime; construction is
/// unrestricted within the workspace (just wrap a `HostCode` variant).
///
/// `Plugin(PluginThrownCode)` — emitted by a plugin JS `throw`; the
/// `PluginThrownCode` constructor is `pub(crate)` so only
/// `runtime::try_extract_agentsso_error` can produce this variant.
/// External crates can read it (pattern match + `.as_str()`) but
/// **cannot construct it** — provenance is enforced by the type system.
///
/// JS-observable `.code` string is byte-identical to the pre-8.3 flat
/// enum: `Host(HostCode::OauthUnknownService)` serializes to
/// `"oauth.unknown_service"`; `Plugin(PluginThrownCode("x.y"))` serializes
/// to `"x.y"`. The `Serialize` impl uses `Display` (unchanged from prior).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostApiErrorCode {
    /// Host-generated error — provenance is the permit-layer runtime.
    Host(HostCode),
    /// Plugin-thrown error — provenance is a JS `throw new AgentssoError(...)`.
    /// The wrapped code is the literal string the plugin passed to `{code: ...}`.
    Plugin(PluginThrownCode),
}

impl fmt::Display for HostApiErrorCode {
    /// Dotted-lowercase string form, used by `Serialize` and the
    /// JS-side `error.code` field. Plugin code matches on this
    /// string, so any change is a breaking change governed by the
    /// host API semver contract. Byte-identical to the pre-8.3 flat enum.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostApiErrorCode::Host(h) => h.fmt(f),
            HostApiErrorCode::Plugin(p) => f.write_str(p.as_str()),
        }
    }
}

impl serde::Serialize for HostApiErrorCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

/// Return a flat string indicating whether the error originated from
/// the host runtime or was thrown by plugin JS code.
///
/// Used by audit-event emitters to populate `extra.origin` without
/// requiring downstream consumers to understand the Rust enum shape.
pub fn origin_str(code: &HostApiErrorCode) -> &'static str {
    match code {
        HostApiErrorCode::Host(_) => "host_thrown",
        HostApiErrorCode::Plugin(_) => "plugin_thrown",
    }
}

/// Enumerate the full set of named [`HostCode`] variant strings in
/// lexicographic order.
///
/// Consumed by Story 6.5's `cargo xtask validate-plugin-api` to emit
/// the `## error_codes` section of `host-api.lock`. Plugin-thrown codes
/// are **deliberately omitted** — they are not part of the semver-locked
/// surface.
///
/// The returned list is sorted + deduplicated + round-trippable via
/// [`std::str::FromStr`] / [`std::fmt::Display`] — enforced by the
/// unit test below. Callers can rely on both invariants without
/// re-sorting.
pub fn all_error_code_names() -> Vec<&'static str> {
    // Adding a new named variant requires appending here AND to
    // `HostCode::Display` + `HostCode::FromStr`. The round-trip test catches drift.
    let mut names = vec![
        "http.blocked_metadata_endpoint",
        "http.dns_resolution_failed",
        "http.header_injection",
        "http.header_type_mismatch",
        "http.invalid_body",
        "http.invalid_timeout",
        "http.policy_denied",
        "http.request_too_large",
        "http.response_too_large",
        "http.scheme_not_allowed",
        "http.timeout",
        "http.tls_handshake_failed",
        "http.upstream_unreachable",
        "oauth.refresh_failed",
        "oauth.scope_denied",
        "oauth.scope_required",
        "oauth.unknown_service",
        "policy.eval_failed",
        "scrub.invalid_input",
        "version.malformed_requirement",
    ];
    names.sort_unstable();
    names
}

/// Rust-side host-API error shape. Returned by every [`HostServices`]
/// trait method's `Err` arm; surfaced to JS as a thrown
/// `AgentssoError` instance.
#[derive(Debug, Clone, thiserror::Error)]
#[error("[{code}] {message}")]
pub struct HostApiError {
    /// Stable error-code enum.
    pub code: HostApiErrorCode,
    /// Whether the plugin should retry the call.
    pub retryable: bool,
    /// Human-readable message. Intended for plugin diagnostics; **not**
    /// rendered into the operator-facing HTTP response by the proxy
    /// (AR29 — same no-leak discipline as `PluginError::JsException`).
    pub message: String,
}

impl HostApiError {
    /// Convenience constructor.
    pub fn new(code: HostApiErrorCode, retryable: bool, message: impl Into<String>) -> Self {
        Self { code, retryable, message: message.into() }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn host_code_display_named_variants() {
        assert_eq!(HostCode::OauthUnknownService.to_string(), "oauth.unknown_service");
        assert_eq!(HostCode::OauthScopeDenied.to_string(), "oauth.scope_denied");
        assert_eq!(HostCode::OauthScopeRequired.to_string(), "oauth.scope_required");
        assert_eq!(HostCode::OauthRefreshFailed.to_string(), "oauth.refresh_failed");
        assert_eq!(HostCode::PolicyEvalFailed.to_string(), "policy.eval_failed");
        assert_eq!(HostCode::ScrubInvalidInput.to_string(), "scrub.invalid_input");
        assert_eq!(HostCode::HttpSchemeNotAllowed.to_string(), "http.scheme_not_allowed");
        assert_eq!(HostCode::HttpPolicyDenied.to_string(), "http.policy_denied");
        assert_eq!(HostCode::HttpTimeout.to_string(), "http.timeout");
        assert_eq!(HostCode::HttpInvalidTimeout.to_string(), "http.invalid_timeout");
        assert_eq!(HostCode::HttpHeaderInjection.to_string(), "http.header_injection");
        assert_eq!(HostCode::HttpResponseTooLarge.to_string(), "http.response_too_large");
        assert_eq!(HostCode::HttpHeaderTypeMismatch.to_string(), "http.header_type_mismatch");
        assert_eq!(HostCode::HttpDnsResolutionFailed.to_string(), "http.dns_resolution_failed");
        assert_eq!(HostCode::HttpTlsHandshakeFailed.to_string(), "http.tls_handshake_failed");
        assert_eq!(HostCode::HttpUpstreamUnreachable.to_string(), "http.upstream_unreachable");
        assert_eq!(
            HostCode::HttpBlockedMetadataEndpoint.to_string(),
            "http.blocked_metadata_endpoint"
        );
        assert_eq!(
            HostCode::VersionMalformedRequirement.to_string(),
            "version.malformed_requirement"
        );
    }

    #[test]
    fn host_api_error_code_display_delegates_to_inner() {
        assert_eq!(
            HostApiErrorCode::Host(HostCode::OauthUnknownService).to_string(),
            "oauth.unknown_service"
        );
        assert_eq!(
            HostApiErrorCode::Plugin(PluginThrownCode::new_for_test("plugin.custom")).to_string(),
            "plugin.custom"
        );
    }

    #[test]
    fn host_code_from_str_round_trips_named_variants() {
        let names = [
            "oauth.unknown_service",
            "oauth.scope_denied",
            "oauth.scope_required",
            "oauth.refresh_failed",
            "policy.eval_failed",
            "scrub.invalid_input",
            "http.scheme_not_allowed",
            "http.policy_denied",
            "http.timeout",
            "http.invalid_timeout",
            "http.header_injection",
            "http.response_too_large",
            "http.header_type_mismatch",
            "http.invalid_body",
            "http.request_too_large",
            "http.dns_resolution_failed",
            "http.tls_handshake_failed",
            "http.upstream_unreachable",
            "http.blocked_metadata_endpoint",
            "version.malformed_requirement",
        ];
        for name in names {
            let code: HostCode = name.parse().unwrap();
            assert_eq!(code.to_string(), name, "round trip mismatch for `{name}`");
        }
    }

    #[test]
    fn host_code_from_str_unknown_returns_err() {
        let result: Result<HostCode, _> = "unknown.code".parse();
        assert!(result.is_err(), "unknown string must return Err, not fall through to a variant");
    }

    #[test]
    fn host_api_error_code_serialize_emits_dotted_string() {
        let code = HostApiErrorCode::Host(HostCode::OauthUnknownService);
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, "\"oauth.unknown_service\"");

        let code = HostApiErrorCode::Plugin(PluginThrownCode::new_for_test("plugin.custom"));
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, "\"plugin.custom\"");
    }

    #[test]
    fn scoped_token_desc_debug_redacts_bearer() {
        let token = ScopedTokenDesc {
            bearer: "abcdefghijklmnopqrstuvwxyz_extra_secret_material".to_owned(),
            scope: "gmail.readonly".to_owned(),
            resource: "gmail".to_owned(),
            expires_at_epoch_secs: 1_700_000_000,
        };
        let dbg = format!("{token:?}");
        assert!(dbg.contains("abcdefgh..."), "first 8 chars + ellipsis must appear: {dbg}");
        assert!(!dbg.contains("extra_secret_material"), "tail of bearer must NOT leak: {dbg}");
        assert!(dbg.contains("gmail.readonly"), "scope IS public, must appear: {dbg}");
    }

    #[test]
    fn host_api_error_display_round_trips_code_and_message() {
        let err = HostApiError::new(
            HostApiErrorCode::Host(HostCode::OauthUnknownService),
            false,
            "no such svc",
        );
        assert_eq!(err.to_string(), "[oauth.unknown_service] no such svc");
    }

    #[test]
    fn all_error_code_names_returns_complete_list_sorted() {
        let names = all_error_code_names();

        // Non-empty.
        assert!(!names.is_empty(), "error-code enumeration must not be empty");

        // Deduped.
        let mut unique: Vec<&'static str> = names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), names.len(), "error-code enumeration has duplicates");

        // Sorted lexicographically.
        for window in names.windows(2) {
            assert!(
                window[0] < window[1],
                "error-code names must be sorted: {:?} >= {:?}",
                window[0],
                window[1],
            );
        }

        // Round-trippable via HostCode::FromStr/Display.
        for name in &names {
            let code: HostCode = name.parse().unwrap();
            assert_eq!(code.to_string(), *name, "FromStr/Display round-trip failed for `{name}`");
        }

        // Story 6.5 snapshot expects 20 named variants after 8.3 adds
        // HttpBlockedMetadataEndpoint. host-api.lock updates alongside this count.
        assert_eq!(names.len(), 20, "Story 8.3 adds HttpBlockedMetadataEndpoint → 20 variants");
    }

    #[test]
    fn forged_host_code_from_plugin_routes_to_plugin_variant() {
        // Simulate the smoking-gun path: plugin throws AgentssoError with
        // code: "oauth.unknown_service". Pre-8.3 this promoted to
        // Host(OauthUnknownService); post-8.3 it ALWAYS routes to Plugin.
        // The PluginThrownCode constructor is only accessible inside this
        // crate (pub(crate)), so this test can construct it via new_for_test.
        let plugin_code = PluginThrownCode::new_for_test("oauth.unknown_service".to_owned());
        let code = HostApiErrorCode::Plugin(plugin_code);
        // Must be Plugin, not Host.
        assert!(
            matches!(&code, HostApiErrorCode::Plugin(p) if p.as_str() == "oauth.unknown_service")
        );
        // Display is still byte-identical to what a host-thrown code would show.
        assert_eq!(code.to_string(), "oauth.unknown_service");
        // But origin_str correctly distinguishes it.
        assert_eq!(origin_str(&code), "plugin_thrown");
        // Compare to a genuine Host variant.
        let host_code = HostApiErrorCode::Host(HostCode::OauthUnknownService);
        assert_eq!(origin_str(&host_code), "host_thrown");
    }

    #[test]
    fn audit_origin_flat_field_matches_enum_variant() {
        assert_eq!(origin_str(&HostApiErrorCode::Host(HostCode::HttpTimeout)), "host_thrown");
        assert_eq!(
            origin_str(&HostApiErrorCode::Plugin(PluginThrownCode::new_for_test("x.y"))),
            "plugin_thrown"
        );
    }
}
