//! Error types for the proxy and its middleware chain.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Errors returned by the proxy service and middleware layers.
///
/// Variants map to HTTP status codes per the fail-closed status table in
/// architecture.md.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum ProxyError {
    /// DNS-rebinding guard rejected the Host/Origin header.
    #[error("Host header '{host}' is not in the allowlist")]
    DnsRebindBlocked { host: String },

    /// Kill switch is active — all requests are denied.
    ///
    /// The `activated_at` timestamp is threaded through from
    /// `KillSwitch::activated_at()` so the response body can include
    /// the exact activation time. On the rare race where the request
    /// arrives between the atomic flag flip and the timestamp store,
    /// the middleware falls back to `Utc::now()` (defense-in-depth).
    #[error("permitlayer is in kill state — all requests denied")]
    KillSwitchActive { activated_at: chrono::DateTime<chrono::Utc> },

    /// Authentication failed (legacy generic variant — kept for the
    /// stub kill-switch and DNS-rebind paths that don't have a more
    /// specific reason).
    #[error("Unauthorized: {reason}")]
    Unauthorized { reason: String },

    /// `Authorization: Bearer <token>` header is missing on a route
    /// that requires agent authentication. Returned by `AuthLayer`
    /// (Story 4.4) for any non-operational path without a bearer
    /// token. Returns HTTP 401 with code `auth.missing_token` and a
    /// remediation pointing at `agentsso agent register`.
    #[error("Authorization header is missing")]
    AuthMissingToken,

    /// Inbound bearer token does not match any registered agent.
    /// Returned by `AuthLayer` (Story 4.4) on a registry miss. Returns
    /// HTTP 401 with code `auth.invalid_token` and a remediation
    /// pointing at `agentsso agent register`.
    ///
    /// `token_prefix` carries the first 8 characters of the inbound
    /// token (or `None` if the token is shorter than 8 chars) for
    /// audit-log grep-correlation. **Never carries the full token.**
    #[error("Bearer token is not registered")]
    AuthInvalidToken { token_prefix: Option<String> },

    /// Policy evaluation denied the request (FR36, FR53).
    ///
    /// Carries the full violation context so the response body names the
    /// policy, rule, scope, and resource that caused the denial. The
    /// `rule_id` is a stable string identifier from the policy TOML, not
    /// a file:line reference, so violations survive refactoring (UX-DR21).
    #[error("Policy denied: {message}")]
    PolicyDenied {
        policy_name: String,
        rule_id: String,
        denied_scope: Option<String>,
        denied_resource: Option<String>,
        message: String,
    },

    /// Policy engine failed to evaluate (NFR20 fail-closed).
    #[error("Policy evaluation failed")]
    PolicyEvalFailed,

    /// Policy evaluation returned `Decision::Prompt` and the operator
    /// denied the request (pressed `n`, or cached `never`). Returns HTTP
    /// 403 `policy.approval_required`. Agents should NOT retry — the
    /// operator deliberately said no.
    #[error("Approval required by policy '{policy_name}' rule '{rule_id}'")]
    ApprovalRequired { policy_name: String, rule_id: String },

    /// Policy evaluation returned `Decision::Prompt` and the operator
    /// did not respond before the configured timeout. Returns HTTP 403
    /// `policy.approval_timeout`. Distinct from `ApprovalRequired` so
    /// agents can implement smart retry: a timeout means "operator AFK,
    /// safe to retry later," while `approval_required` means "operator
    /// said no, do not retry."
    #[error("Approval timed out for policy '{policy_name}' rule '{rule_id}'")]
    ApprovalTimeout { policy_name: String, rule_id: String },

    /// Policy evaluation returned `Decision::Prompt` but the approval
    /// service is structurally unavailable (no controlling TTY, or the
    /// daemon is shutting down). Returns HTTP 503
    /// `policy.approval_unavailable`.
    ///
    /// Separate from [`ProxyError::ApprovalRequired`] so agents can
    /// distinguish "operator said no" (do not retry) from
    /// "environment can't prompt" (retry after operator fixes it).
    #[error("Approval prompts are unavailable for policy '{policy_name}' rule '{rule_id}'")]
    ApprovalUnavailable { policy_name: String, rule_id: String },

    /// Route not found.
    #[error("Not found: {path}")]
    NotFound { path: String },

    /// Internal error.
    #[error("Internal error: {message}")]
    Internal { message: String },

    /// Upstream API is unreachable (DNS failure, TLS error, connection timeout).
    #[error("Upstream {service} unreachable: {message}")]
    UpstreamUnreachable { service: String, message: String, retry_after_seconds: u32 },

    /// Upstream refresh token was rejected server-side (revoked, expired, or
    /// otherwise invalid per RFC 6749 `invalid_grant`). The user must re-run
    /// `agentsso setup <service>` to mint a fresh refresh token — no amount
    /// of retrying will recover this credential. See architecture.md
    /// "Credential Lifecycle and OAuth Refresh" invariant #5 (Story 1.14a).
    #[error("Credential for {service} was revoked server-side; re-run `agentsso setup {service}`")]
    CredentialRevoked { service: String },

    /// Upstream API returned HTTP 429 (rate limited).
    #[error("Upstream {service} rate limited")]
    UpstreamRateLimited { service: String, retry_after: Option<String> },

    /// Upstream API returned HTTP 5xx.
    #[error("Upstream {service} server error: {status}")]
    UpstreamServerError { service: String, status: u16, message: String },

    /// `X-Agentsso-Scope` header is missing on a proxy request (FR19 / F19).
    ///
    /// Replaced the previous silent `unwrap_or("*")` fallback (Story 8.4).
    /// Agents must declare the scope they are requesting; a missing header
    /// indicates a misconfigured agent, not a transient error.
    #[error("X-Agentsso-Scope header is required")]
    MissingScopeHeader,

    /// Content scrubbing failed (fail-closed per NFR20).
    #[error("Content scrubbing failed: {message}")]
    ScrubFailed { message: String },

    /// Plugin execution exceeded its resource budget (memory or
    /// wall-clock). Returns HTTP 503 `plugin_resource_exceeded` per
    /// Story 6.1 AC #5 / #12. `kind` carries the specific limit that
    /// was hit for operator correlation.
    #[error("plugin resource limit exceeded: {kind}")]
    PluginResourceExceeded { kind: ResourceKind },

    /// Plugin threw an uncaught JS exception or otherwise errored out
    /// in a non-resource-related way. Returns HTTP 500
    /// `plugin_internal` with a GENERIC message — per AR29, the JS
    /// exception text is NEVER leaked to the agent (it goes only to
    /// `tracing::warn!` with structured fields on the daemon side).
    ///
    /// D18 review patch: carries the source `PluginError` as
    /// `#[source]` so `tracing` chain-rendering keeps the
    /// underlying cause for incident response. The error's
    /// user-facing `Display` (`"connector plugin failed
    /// internally"`) is the ONLY string that reaches the HTTP
    /// response body — the source is read by `error.source()`
    /// consumers (typically `tracing::error!`/`tracing::warn!`
    /// with `error = %err`) but does NOT serialize into the
    /// JSON body.
    #[error("connector plugin failed internally")]
    PluginInternal {
        #[source]
        source: Box<permitlayer_plugins::PluginError>,
    },
}

/// Specific plugin resource-limit kind. Serializes as kebab-case so
/// the HTTP body has `"kind": "cpu"` / `"kind": "memory"` per
/// Story 6.1 AC #12.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKind {
    /// CPU / wall-clock deadline exceeded.
    Cpu,
    /// Heap memory limit exceeded.
    Memory,
}

impl std::fmt::Display for ResourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ResourceKind::Cpu => "cpu",
            ResourceKind::Memory => "memory",
        })
    }
}

impl From<permitlayer_plugins::PluginError> for ProxyError {
    fn from(err: permitlayer_plugins::PluginError) -> Self {
        // D12 review patch: explicit arm per variant (NOT a
        // collapsed `|`-chain) so the compiler's non-exhaustive
        // warning surfaces a decision every time a new variant
        // lands in `permitlayer_plugins::PluginError`. The final
        // wildcard arm is MANDATORY because `PluginError` is
        // declared `#[non_exhaustive]` in a different crate —
        // Rust requires the catch-all even when all current
        // variants are covered. The wildcard's body is a
        // deliberately-conservative `PluginInternal` (HTTP 500,
        // generic message) AND a `tracing::warn!` so any future
        // unmapped variant is visible in operator logs while the
        // agent gets the safe generic response.
        match err {
            permitlayer_plugins::PluginError::MemoryExceeded { .. } => {
                ProxyError::PluginResourceExceeded { kind: ResourceKind::Memory }
            }
            permitlayer_plugins::PluginError::ExecutionDeadlineExceeded { .. } => {
                ProxyError::PluginResourceExceeded { kind: ResourceKind::Cpu }
            }
            // AR29: JS exception text is NEVER returned to the agent.
            // The caller at the plugin execution site is responsible
            // for emitting a `tracing::warn!` with the structured
            // `js_exception_message` field before converting; this
            // `From` impl loses that context intentionally.
            err @ permitlayer_plugins::PluginError::JsException { .. } => {
                ProxyError::PluginInternal { source: Box::new(err) }
            }
            err @ permitlayer_plugins::PluginError::RuntimeInit(_) => {
                ProxyError::PluginInternal { source: Box::new(err) }
            }
            err @ permitlayer_plugins::PluginError::Internal(_) => {
                ProxyError::PluginInternal { source: Box::new(err) }
            }
            // Story 6.2 review finding M15 + AD5: explicit
            // HostApiError arm. Previously routed through the
            // wildcard which emitted a noisy `tracing::warn!`
            // every time a plugin threw an AgentssoError. The
            // mapping itself is the same (PluginInternal with
            // generic body — AR29 no-leak preserved by the
            // existing test).
            err @ permitlayer_plugins::PluginError::HostApiError { .. } => {
                ProxyError::PluginInternal { source: Box::new(err) }
            }
            // `#[non_exhaustive]` catch-all (compiler-required).
            // Any future variant lands here with a WARN log so an
            // operator seeing an unexpected 500 has a grep hook.
            other => {
                tracing::warn!(
                    unmapped_variant = ?other,
                    "unmapped PluginError variant — add an explicit From arm in permitlayer-proxy::error"
                );
                ProxyError::PluginInternal { source: Box::new(other) }
            }
        }
    }
}

/// JSON error body returned to callers.
#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream_service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<String>,
    /// RFC 3339 UTC activation timestamp for the `daemon_killed` error
    /// body. Only populated when `code == "daemon_killed"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    activated_at: Option<String>,
    /// Human-readable resume instructions for the `daemon_killed`
    /// error body. Only populated when `code == "daemon_killed"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    resume_instructions: Option<&'static str>,
    /// Policy name that produced the denial (FR36/FR53). Only
    /// populated when `code == "policy.denied"` or `"approval_required"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_name: Option<String>,
    /// The scope that was denied (FR36). Only populated on scope-driven
    /// denials.
    #[serde(skip_serializing_if = "Option::is_none")]
    denied_scope: Option<String>,
    /// The resource that was denied (FR36). Only populated on
    /// resource-driven denials.
    #[serde(skip_serializing_if = "Option::is_none")]
    denied_resource: Option<String>,
    /// Story 6.1: specific plugin-resource kind (`"cpu"` | `"memory"`).
    /// Only populated when `code == "plugin_resource_exceeded"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<&'static str>,
}

impl ProxyError {
    /// The domain-qualified error code for this variant.
    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::DnsRebindBlocked { .. } => "dns_rebind.blocked",
            // NOTE on the field name: this JSON key is `code`, not
            // `error_code`. The epic AC #4 literal JSON uses
            // `"error_code":"daemon_killed"`, but the existing
            // `ErrorBody` contract (shared with 9+ other variants) uses
            // `"code"`. The architecture-pinned identifier is
            // `daemon_killed` — the field name is `code` by the
            // existing contract. See Story 3.1 Gotchas for the full
            // rationale and a regression test in tests module below.
            Self::KillSwitchActive { .. } => "daemon_killed",
            Self::Unauthorized { .. } => "auth.unauthorized",
            // Story 4.4: bearer-token validation paths. Dotted convention
            // matches the rest of the auth.* family.
            Self::AuthMissingToken => "auth.missing_token",
            Self::AuthInvalidToken { .. } => "auth.invalid_token",
            // NOTE: The epic AC literal at epics.md:1421 uses
            // "policy_violation" (underscore). The codebase convention is
            // dotted codes. Keeping "policy.denied" for backward
            // compatibility with existing audit consumers and grep scripts.
            Self::PolicyDenied { .. } => "policy.denied",
            // NOTE: AC #3 literal is "policy_eval_failed" (underscore);
            // keeping the dotted convention for the same reason as above.
            Self::PolicyEvalFailed => "policy.eval_failed",
            // Story 4.5: dotted convention matches the policy.* family.
            // approval_required  = operator pressed `n` / `never`.
            // approval_timeout   = operator did not respond in time
            //                      (separate code so agents can retry).
            // approval_unavailable = no TTY or daemon shutting down.
            Self::ApprovalRequired { .. } => "policy.approval_required",
            Self::ApprovalTimeout { .. } => "policy.approval_timeout",
            Self::ApprovalUnavailable { .. } => "policy.approval_unavailable",
            Self::NotFound { .. } => "route.not_found",
            Self::Internal { .. } => "internal.error",
            Self::UpstreamUnreachable { .. } => "upstream.unreachable",
            Self::CredentialRevoked { .. } => "credential.revoked",
            Self::UpstreamRateLimited { .. } => "upstream.rate_limited",
            Self::UpstreamServerError { .. } => "upstream.server_error",
            Self::MissingScopeHeader => "proxy.missing_scope_header",
            Self::ScrubFailed { .. } => "scrub.failed",
            Self::PluginResourceExceeded { .. } => "plugin_resource_exceeded",
            Self::PluginInternal { .. } => "plugin_internal",
        }
    }

    /// The HTTP status code for this variant.
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::DnsRebindBlocked { .. } => StatusCode::BAD_REQUEST,
            Self::KillSwitchActive { .. } => StatusCode::FORBIDDEN,
            Self::Unauthorized { .. } => StatusCode::UNAUTHORIZED,
            Self::AuthMissingToken | Self::AuthInvalidToken { .. } => StatusCode::UNAUTHORIZED,
            Self::PolicyDenied { .. } => StatusCode::FORBIDDEN,
            Self::PolicyEvalFailed => StatusCode::SERVICE_UNAVAILABLE,
            Self::ApprovalRequired { .. } | Self::ApprovalTimeout { .. } => StatusCode::FORBIDDEN,
            Self::ApprovalUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Self::NotFound { .. } => StatusCode::NOT_FOUND,
            Self::Internal { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Self::UpstreamUnreachable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Self::CredentialRevoked { .. } => StatusCode::UNAUTHORIZED,
            Self::UpstreamRateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::UpstreamServerError { .. } => StatusCode::BAD_GATEWAY,
            Self::MissingScopeHeader => StatusCode::BAD_REQUEST,
            Self::ScrubFailed { .. } => StatusCode::SERVICE_UNAVAILABLE,
            // Story 6.1 AC #12: resource-exceeded → 503, internal → 500
            // (generic, no JS-exception leak per AR29).
            Self::PluginResourceExceeded { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Self::PluginInternal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Build a JSON [`Response`] for this error.
    ///
    /// `request_id` is `None` when the error occurs before `TraceLayer`
    /// generates a ULID (e.g. DNS-rebind rejections).
    #[must_use]
    pub fn into_response_with_request_id(self, request_id: Option<String>) -> Response {
        let status = self.status_code();
        let code = self.error_code();
        let message = self.to_string();

        let (rule_id, policy_name_field, denied_scope, denied_resource) = match &self {
            Self::PolicyDenied { policy_name, rule_id, denied_scope, denied_resource, .. } => (
                Some(rule_id.clone()),
                Some(policy_name.clone()),
                denied_scope.clone(),
                denied_resource.clone(),
            ),
            Self::ApprovalRequired { policy_name, rule_id }
            | Self::ApprovalTimeout { policy_name, rule_id }
            | Self::ApprovalUnavailable { policy_name, rule_id } => {
                (Some(rule_id.clone()), Some(policy_name.clone()), None, None)
            }
            _ => (None, None, None, None),
        };

        let (upstream_service, retry_after_seconds, remediation, retry_after_header) = match &self {
            Self::UpstreamUnreachable { service, retry_after_seconds, .. } => (
                Some(service.clone()),
                Some(*retry_after_seconds),
                Some("Check your network connection and try again.".to_owned()),
                None,
            ),
            Self::CredentialRevoked { service } => (
                Some(service.clone()),
                None,
                Some(format!("Re-run `agentsso setup {service}` to reconnect this account.")),
                None,
            ),
            Self::UpstreamRateLimited { service, retry_after } => {
                (Some(service.clone()), None, None, retry_after.clone())
            }
            Self::UpstreamServerError { service, .. } => (
                Some(service.clone()),
                None,
                Some("The upstream service is experiencing issues. Try again later.".to_owned()),
                None,
            ),
            Self::PolicyDenied { policy_name, rule_id, .. } => {
                // Special case: the no-agent-binding rule_id has policy_name="-",
                // so the file-edit remediation is meaningless. Point operators
                // at the actual fix instead. Story 4.4 ships the registry, so
                // the post-4.4 remediation is `agentsso agent register`.
                let remediation = if rule_id == "default-deny-no-agent-binding" {
                    "Run `agentsso agent register <name> --policy=<policy>` \
                     to bind this agent's bearer token to a policy."
                        .to_owned()
                } else {
                    format!("Edit ~/.agentsso/policies/{policy_name}.toml")
                };
                (None, None, Some(remediation), None)
            }
            Self::ApprovalRequired { .. } => (
                None,
                None,
                Some(
                    "Request was denied at the operator's approval prompt or remembered \
                      as 'never allow' earlier in this session. Do not retry — re-running \
                      will re-prompt or hit the cached 'never' decision. To unblock, edit \
                      the policy's approval-mode to auto-approve this rule, or run \
                      `agentsso reload` to clear the session cache."
                        .to_owned(),
                ),
                None,
            ),
            Self::ApprovalTimeout { .. } => (
                None,
                None,
                Some(
                    "Operator did not respond within the configured approval timeout. \
                      The request can be safely retried — a fresh prompt will be \
                      shown. To extend the timeout, set [approval] timeout_seconds \
                      in ~/.agentsso/config/daemon.toml."
                        .to_owned(),
                ),
                None,
            ),
            Self::ApprovalUnavailable { .. } => (
                None,
                None,
                Some(
                    "Approval prompts require a controlling TTY. Launch \
                      `agentsso start` in a foreground terminal, or change the \
                      policy's approval-mode to 'auto' or 'deny'."
                        .to_owned(),
                ),
                None,
            ),
            Self::MissingScopeHeader => (
                None,
                None,
                Some(
                    "Set the `X-Agentsso-Scope` header to the permission scope your agent is \
                      requesting (e.g., `X-Agentsso-Scope: gmail.readonly`)."
                        .to_owned(),
                ),
                None,
            ),
            Self::AuthMissingToken => (
                None,
                None,
                Some(
                    "Set the `Authorization: Bearer <token>` header. \
                      Run `agentsso agent register <name> --policy=<policy>` \
                      to mint a token if you do not have one."
                        .to_owned(),
                ),
                None,
            ),
            Self::AuthInvalidToken { .. } => (
                None,
                None,
                Some(
                    "The bearer token is not registered. Run `agentsso agent list` \
                      to see registered agents, or `agentsso agent register <name> \
                      --policy=<policy>` to mint a fresh token. If no agents are \
                      registered, check the daemon startup logs for 'agent registry \
                      unavailable' — the registry may have failed to load."
                        .to_owned(),
                ),
                None,
            ),
            _ => (None, None, None, None),
        };

        // Kill-switch-specific fields. `activated_at` uses the audit
        // log timestamp format (`%Y-%m-%dT%H:%M:%S%.3fZ` — ms precision
        // + `Z` suffix, NOT `to_rfc3339()` which emits `+00:00`) so
        // operators can grep across audit entries and error responses.
        // See story 3.1 Gotchas.
        let (activated_at, resume_instructions) = match &self {
            Self::KillSwitchActive { activated_at } => (
                Some(activated_at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()),
                Some("run: agentsso resume"),
            ),
            _ => (None, None),
        };

        // Story 6.1: plugin-specific `kind` field.
        let kind: Option<&'static str> = match &self {
            Self::PluginResourceExceeded { kind: ResourceKind::Cpu } => Some("cpu"),
            Self::PluginResourceExceeded { kind: ResourceKind::Memory } => Some("memory"),
            _ => None,
        };

        let body = ErrorBody {
            error: ErrorDetail {
                code,
                message,
                rule_id,
                request_id,
                upstream_service,
                retry_after_seconds,
                remediation,
                activated_at,
                resume_instructions,
                policy_name: policy_name_field,
                denied_scope,
                denied_resource,
                kind,
            },
        };

        let mut response = (status, axum::Json(body)).into_response();

        // Set Retry-After header for 429 responses.
        if let Some(retry_after) = retry_after_header
            && let Ok(val) = retry_after.parse()
        {
            response.headers_mut().insert("retry-after", val);
        }

        response
    }
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        // Default: no request_id available. Middleware layers that have
        // access to the request_id should use `into_response_with_request_id`
        // instead.
        self.into_response_with_request_id(None)
    }
}

/// Newtype wrapper for request IDs stored in request extensions.
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

/// Newtype wrapper for agent identity stored in request extensions.
#[derive(Clone, Debug)]
pub struct AgentId(pub String);

/// Newtype wrapper for the policy name an agent is bound to (Story 4.4).
///
/// Stamped into request extensions by `AuthLayer` after a successful
/// bearer-token lookup, then read by `PolicyLayer::resolve_policy_name`
/// to drive evaluation. Pre-Story-4.4 the policy name was resolved by
/// the `single-policy-shortcut` heuristic in `PolicyLayer`; that
/// heuristic is gone, replaced by this extension.
#[derive(Clone, Debug)]
pub struct AgentPolicyBinding(pub String);

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn dns_rebind_error_produces_400_json() {
        let err = ProxyError::DnsRebindBlocked { host: "evil.com".to_owned() };
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(err.error_code(), "dns_rebind.blocked");

        let response = err.into_response_with_request_id(None);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = response.into_body();
        let bytes = Body::new(body).collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["code"], "dns_rebind.blocked");
        assert!(json["error"]["request_id"].is_null());
    }

    #[tokio::test]
    async fn kill_switch_error_produces_403_json_with_daemon_killed_body() {
        // Story 3.1 AC #3: the kill-switch error body carries the
        // `daemon_killed` code, an ISO 8601 UTC activation timestamp,
        // the exact `run: agentsso resume` instruction string, and the
        // request ID.
        let activated_at = chrono::Utc::now();
        let err = ProxyError::KillSwitchActive { activated_at };
        assert_eq!(err.status_code(), StatusCode::FORBIDDEN);

        let response = err.into_response_with_request_id(Some("01TEST".to_owned()));
        let body = response.into_body();
        let bytes = Body::new(body).collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(json["error"]["code"], "daemon_killed");
        assert_eq!(json["error"]["request_id"], "01TEST");
        assert_eq!(json["error"]["resume_instructions"], "run: agentsso resume");

        let activated_at_str =
            json["error"]["activated_at"].as_str().expect("activated_at must be present");
        assert!(
            activated_at_str.ends_with('Z'),
            "activated_at must use Z suffix (audit log format), got: {activated_at_str}"
        );
        // Round-trip through RFC 3339 parse to prove the format is valid.
        chrono::DateTime::parse_from_rfc3339(activated_at_str)
            .expect("activated_at must parse as RFC 3339");
    }

    #[test]
    fn kill_switch_error_code_is_daemon_killed_regression_guard() {
        // Regression guard for Story 3.1 AC #3: the error code MUST be
        // the literal string `daemon_killed`, NOT `kill_switch.active`
        // (the pre-3.1 string) or `kill.switch.active` or any other
        // drift. The architecture spec at `epics.md:1281` pins this
        // identifier; the rename would silently break downstream audit
        // consumers that key off `$.error.code == "daemon_killed"`.
        let err = ProxyError::KillSwitchActive { activated_at: chrono::Utc::now() };
        assert_eq!(err.error_code(), "daemon_killed");
        assert!(!err.error_code().contains('.'));
        assert!(!err.error_code().contains("kill_switch"));
    }

    #[tokio::test]
    async fn policy_denied_includes_full_violation_body() {
        let err = ProxyError::PolicyDenied {
            policy_name: "gmail-read-only".to_owned(),
            rule_id: "no-gmail-send".to_owned(),
            denied_scope: Some("gmail.modify".to_owned()),
            denied_resource: None,
            message: "Blocked by policy".to_owned(),
        };
        let response = err.into_response_with_request_id(Some("01TESTPV".to_owned()));
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response.into_body();
        let bytes = Body::new(body).collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["code"], "policy.denied");
        assert_eq!(json["error"]["rule_id"], "no-gmail-send");
        assert_eq!(json["error"]["policy_name"], "gmail-read-only");
        assert_eq!(json["error"]["denied_scope"], "gmail.modify");
        assert!(json["error"]["denied_resource"].is_null());
        assert_eq!(json["error"]["request_id"], "01TESTPV");
        // Remediation should point at the policy file.
        let remediation = json["error"]["remediation"].as_str().unwrap();
        assert!(remediation.contains("gmail-read-only.toml"));
    }

    #[tokio::test]
    async fn approval_required_produces_403_with_correct_code() {
        let err = ProxyError::ApprovalRequired {
            policy_name: "test-prompt".to_owned(),
            rule_id: "default-prompt-approval-mode".to_owned(),
        };
        assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
        assert_eq!(err.error_code(), "policy.approval_required");
        let response = err.into_response_with_request_id(None);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response.into_body();
        let bytes = Body::new(body).collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["code"], "policy.approval_required");
        assert_eq!(json["error"]["policy_name"], "test-prompt");
        assert_eq!(json["error"]["rule_id"], "default-prompt-approval-mode");
        // Story 4.5: remediation now describes the real denial semantics.
        let remediation = json["error"]["remediation"].as_str().unwrap();
        assert!(
            remediation.contains("approval prompt")
                || remediation.contains("operator")
                || remediation.contains("timed out"),
            "remediation should describe the approval-denied / timeout path: {remediation}"
        );
    }

    #[tokio::test]
    async fn approval_unavailable_produces_503_with_correct_code() {
        // Story 4.5: the no-TTY / shutdown path returns 503 so agents
        // can distinguish "operator said no" from "environment can't prompt".
        let err = ProxyError::ApprovalUnavailable {
            policy_name: "test-prompt".to_owned(),
            rule_id: "default-prompt-approval-mode".to_owned(),
        };
        assert_eq!(err.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.error_code(), "policy.approval_unavailable");
        let response = err.into_response_with_request_id(Some("01TESTAU".to_owned()));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response.into_body();
        let bytes = Body::new(body).collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["code"], "policy.approval_unavailable");
        assert_eq!(json["error"]["policy_name"], "test-prompt");
        assert_eq!(json["error"]["rule_id"], "default-prompt-approval-mode");
        assert_eq!(json["error"]["request_id"], "01TESTAU");
        let remediation = json["error"]["remediation"].as_str().unwrap();
        assert!(
            remediation.contains("TTY") || remediation.contains("foreground terminal"),
            "remediation should mention the TTY requirement: {remediation}"
        );
    }

    #[tokio::test]
    async fn policy_eval_failed_produces_503_with_dotted_code() {
        // AC #3: panic/error in evaluate() returns HTTP 503 with code
        // "policy.eval_failed" (dotted, matching codebase convention).
        let err = ProxyError::PolicyEvalFailed;
        assert_eq!(err.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.error_code(), "policy.eval_failed");
        let response = err.into_response_with_request_id(Some("01TESTEV".to_owned()));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response.into_body();
        let bytes = Body::new(body).collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["code"], "policy.eval_failed");
        assert_eq!(json["error"]["request_id"], "01TESTEV");
    }

    #[tokio::test]
    async fn policy_denied_no_agent_binding_uses_special_remediation() {
        // The default-deny-no-agent-binding case has policy_name="-", so
        // the file-edit remediation would point at a nonexistent file.
        // The special-case remediation should explain the actual fix.
        // Story 4.4 ships the registry, so the remediation now points
        // operators at `agentsso agent register`.
        let err = ProxyError::PolicyDenied {
            policy_name: "-".to_owned(),
            rule_id: "default-deny-no-agent-binding".to_owned(),
            denied_scope: None,
            denied_resource: None,
            message: "No policy binding for agent".to_owned(),
        };
        let response = err.into_response_with_request_id(None);
        let body = response.into_body();
        let bytes = Body::new(body).collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let remediation = json["error"]["remediation"].as_str().unwrap();
        assert!(
            !remediation.contains("-.toml"),
            "remediation must not point at the nonexistent -.toml file"
        );
        assert!(
            remediation.contains("agentsso agent register"),
            "remediation should mention agentsso agent register: {remediation}"
        );
    }

    // ── Story 4.4: AuthMissingToken / AuthInvalidToken tests ──────

    #[tokio::test]
    async fn auth_missing_token_produces_401_with_dotted_code() {
        let err = ProxyError::AuthMissingToken;
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(err.error_code(), "auth.missing_token");
        let response = err.into_response_with_request_id(Some("01TESTAM".to_owned()));
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response.into_body();
        let bytes = Body::new(body).collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["code"], "auth.missing_token");
        assert_eq!(json["error"]["request_id"], "01TESTAM");
        let remediation = json["error"]["remediation"].as_str().unwrap();
        assert!(remediation.contains("Authorization"));
        assert!(remediation.contains("agentsso agent register"));
    }

    #[tokio::test]
    async fn auth_invalid_token_produces_401_with_dotted_code() {
        let err = ProxyError::AuthInvalidToken { token_prefix: Some("agt_v1_g".to_owned()) };
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(err.error_code(), "auth.invalid_token");
        let response = err.into_response_with_request_id(Some("01TESTAI".to_owned()));
        let body = response.into_body();
        let bytes = Body::new(body).collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["code"], "auth.invalid_token");
        assert_eq!(json["error"]["request_id"], "01TESTAI");
        // Token prefix MUST NOT appear in the error response body — it's
        // only used in the audit log for grep correlation.
        let body_str = serde_json::to_string(&json).unwrap();
        assert!(
            !body_str.contains("agt_v1_g"),
            "token prefix must not leak into the error response body"
        );
    }

    #[test]
    fn auth_error_codes_use_dotted_convention() {
        assert_eq!(ProxyError::AuthMissingToken.error_code(), "auth.missing_token");
        assert_eq!(
            ProxyError::AuthInvalidToken { token_prefix: None }.error_code(),
            "auth.invalid_token"
        );
        // Defense in depth: both must contain a dot, neither contains
        // an underscore-prefix variant by accident.
        assert!(ProxyError::AuthMissingToken.error_code().contains('.'));
        assert!(ProxyError::AuthInvalidToken { token_prefix: None }.error_code().contains('.'));
    }

    #[tokio::test]
    async fn into_response_trait_works() {
        let err = ProxyError::NotFound { path: "/missing".to_owned() };
        let response = IntoResponse::into_response(err);
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn credential_revoked_produces_401_with_upstream_service_and_remediation() {
        // Story 1.14a AC 3: when refresh_with_retry returns OAuthError::InvalidGrant,
        // the proxy surfaces `credential.revoked` with 401 status, the service name
        // in `upstream_service`, and a remediation pointing at `agentsso setup`.
        let err = ProxyError::CredentialRevoked { service: "gmail".to_owned() };

        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(err.error_code(), "credential.revoked");

        let response = err.into_response_with_request_id(Some("01TESTULID".to_owned()));
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = response.into_body();
        let bytes = Body::new(body).collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(json["error"]["code"], "credential.revoked");
        assert_eq!(json["error"]["upstream_service"], "gmail");
        assert_eq!(json["error"]["request_id"], "01TESTULID");
        // Remediation must point at `agentsso setup` with the specific service name
        // so operators can act on the error without consulting documentation.
        let remediation = json["error"]["remediation"].as_str().unwrap();
        assert!(remediation.contains("agentsso setup gmail"));
        // The error message itself mentions the service (from the thiserror
        // #[error(...)] format).
        assert!(json["error"]["message"].as_str().unwrap().contains("gmail"));
    }

    #[test]
    fn credential_revoked_error_code_matches_dotted_convention() {
        // Regression guard: the `credential.revoked` error code uses the dotted
        // convention established for `upstream.unreachable`, `policy.denied`, etc.
        // An earlier draft of the 1.14a spec used `credential_revoked` (underscore),
        // which drifted from the codebase convention. If someone proposes changing
        // this back to underscore form, this test should fire first.
        let err = ProxyError::CredentialRevoked { service: "calendar".to_owned() };
        assert_eq!(err.error_code(), "credential.revoked");
        assert!(!err.error_code().contains('_'));
    }

    #[test]
    fn internal_error_with_persistence_failed_message_surfaces_as_internal_error() {
        // Story 1.14a AC 6: when refresh succeeds but vault seal or credential
        // store put fails, the proxy returns ProxyError::Internal with a
        // recognizable message substring. The error_code remains `internal.error`
        // (we reuse the existing variant rather than adding a new one), and the
        // message substring `"refresh succeeded but could not persist new token"`
        // is how downstream audit assertions and operator debugging identify the
        // persistence-failure outcome.
        let err = ProxyError::Internal {
            message:
                "refresh succeeded but could not persist new token: vault seal failed: disk full"
                    .to_owned(),
        };
        assert_eq!(err.error_code(), "internal.error");
        assert_eq!(err.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(err.to_string().contains("refresh succeeded but could not persist new token"));
    }

    // ── Story 6.1: plugin resource-exceeded + internal ─────────────

    #[tokio::test]
    async fn plugin_resource_exceeded_cpu_response_shape() {
        use http_body_util::BodyExt;
        let err = ProxyError::PluginResourceExceeded { kind: ResourceKind::Cpu };
        assert_eq!(err.error_code(), "plugin_resource_exceeded");
        assert_eq!(err.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        let resp = err.into_response();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "plugin_resource_exceeded");
        assert_eq!(json["error"]["kind"], "cpu");
    }

    #[tokio::test]
    async fn plugin_resource_exceeded_memory_response_shape() {
        use http_body_util::BodyExt;
        let err = ProxyError::PluginResourceExceeded { kind: ResourceKind::Memory };
        let resp = err.into_response();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "plugin_resource_exceeded");
        assert_eq!(json["error"]["kind"], "memory");
    }

    #[test]
    fn plugin_internal_returns_500() {
        let err = ProxyError::PluginInternal {
            source: Box::new(permitlayer_plugins::PluginError::JsException {
                message: "test".to_owned(),
            }),
        };
        assert_eq!(err.error_code(), "plugin_internal");
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn plugin_internal_carries_source_for_tracing_chain() {
        // D18 review patch: `#[source]` is available via
        // `std::error::Error::source()` so `tracing::warn!(error =
        // %err)` renders the full chain including the underlying
        // PluginError. The HTTP body does NOT include the source —
        // only the response-builder message field, which is
        // derived from `Display`.
        use std::error::Error;
        let err = ProxyError::PluginInternal {
            source: Box::new(permitlayer_plugins::PluginError::JsException {
                message: "boom".to_owned(),
            }),
        };
        let source = err.source().expect("PluginInternal must carry #[source]");
        assert!(source.to_string().contains("boom"));
    }

    #[test]
    fn plugin_error_conversion_memory_to_memory_kind() {
        let src =
            permitlayer_plugins::PluginError::MemoryExceeded { limit_bytes: 32 * 1024 * 1024 };
        let converted: ProxyError = src.into();
        assert!(matches!(
            converted,
            ProxyError::PluginResourceExceeded { kind: ResourceKind::Memory }
        ));
    }

    #[test]
    fn plugin_error_conversion_deadline_to_cpu_kind() {
        let src = permitlayer_plugins::PluginError::ExecutionDeadlineExceeded { elapsed_ms: 2048 };
        let converted: ProxyError = src.into();
        assert!(matches!(
            converted,
            ProxyError::PluginResourceExceeded { kind: ResourceKind::Cpu }
        ));
    }

    #[tokio::test]
    async fn plugin_error_conversion_js_exception_maps_to_internal_not_leaking_message() {
        use http_body_util::BodyExt;
        // AR29: the JS exception text ("boom") must NOT appear in
        // the response body the agent sees.
        let src = permitlayer_plugins::PluginError::JsException {
            message: "Error: boom with internal secret".to_owned(),
        };
        let converted: ProxyError = src.into();
        assert!(matches!(converted, ProxyError::PluginInternal { .. }));
        let resp = converted.into_response();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(
            !body_str.contains("boom"),
            "AR29 violation: JS exception text leaked to response: {body_str}"
        );
        assert!(
            !body_str.contains("internal secret"),
            "AR29 violation: JS exception text leaked to response: {body_str}"
        );
    }

    // ----- Story 8.4 AC #7: missing scope header returns 400 -----

    #[tokio::test]
    async fn proxy_service_missing_scope_header_returns_400() {
        let err = ProxyError::MissingScopeHeader;
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(err.error_code(), "proxy.missing_scope_header");

        let response = err.into_response_with_request_id(Some("01TESTMS".to_owned()));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = response.into_body();
        let bytes = Body::new(body).collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["code"], "proxy.missing_scope_header");
        assert_eq!(json["error"]["request_id"], "01TESTMS");
        let message = json["error"]["message"].as_str().unwrap();
        assert!(
            message.contains("X-Agentsso-Scope") || message.contains("required"),
            "message must describe the missing header: {message}"
        );
        let remediation = json["error"]["remediation"].as_str().unwrap_or("");
        assert!(
            remediation.contains("X-Agentsso-Scope"),
            "remediation must mention the header name: {remediation}"
        );
    }

    // NOTE: `plugin_error_conversion_runtime_init_maps_to_internal`
    // was intentionally omitted — constructing an
    // `rquickjs::Error::Unknown` from this crate requires adding
    // `rquickjs` as a dev-dep, which would pull the full QuickJS C
    // build into this crate's test binary. The `RuntimeInit` →
    // `PluginInternal` arm is covered via the wildcard in the
    // `From<PluginError>` impl plus the `JsException` test above;
    // the intra-crate `permitlayer-plugins::error::tests` module
    // covers the variant construction itself.

    /// Story 6.2 / AC #24: a `PluginError::HostApiError` (Story
    /// 6.2's new variant for thrown `AgentssoError` instances)
    /// must convert to `ProxyError::PluginInternal` AND its
    /// internal message MUST NOT appear in the operator-facing
    /// HTTP response body.
    #[tokio::test]
    async fn plugin_error_conversion_host_api_error_maps_to_internal_not_leaking_message() {
        use http_body_util::BodyExt;
        let src = permitlayer_plugins::PluginError::HostApiError {
            code: permitlayer_plugins::HostApiErrorCode::Host(
                permitlayer_plugins::HostCode::OauthUnknownService,
            ),
            retryable: true,
            message: "internal-secret-message".to_owned(),
        };
        let converted: ProxyError = src.into();
        assert!(matches!(converted, ProxyError::PluginInternal { .. }));
        let resp = converted.into_response();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(
            !body_str.contains("internal-secret-message"),
            "AR29 violation: AgentssoError message leaked to response: {body_str}"
        );
        assert!(
            !body_str.contains("oauth.unknown_service"),
            "AR29 violation: AgentssoError code leaked to response: {body_str}"
        );
        // The body MUST contain the generic plugin_internal code.
        assert!(
            body_str.contains("plugin_internal"),
            "response body must carry the generic plugin_internal code: {body_str}"
        );
    }
}
