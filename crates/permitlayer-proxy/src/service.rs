//! Core proxy service orchestration.
//!
//! `ProxyService::handle` is the innermost handler: it fetches credentials,
//! unseals the vault, issues a scoped token, dispatches upstream, and writes
//! an audit event. The raw OAuth access token is NEVER returned to the agent.
//!
//! On upstream 401 responses the service attempts a single transparent token
//! refresh via [`permitlayer_oauth::OAuthClient::refresh`] (Story 1.14), bounded
//! to one refresh per request. The OAuth client is reconstructed lazily from
//! `{vault_dir}/{service}-meta.json` at refresh time — there is no eager client
//! state on the service. See architecture.md "Credential Lifecycle and OAuth
//! Refresh" for the full invariant set.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use tracing::{info, warn};
use zeroize::Zeroizing;

use permitlayer_core::audit::event::AuditEvent;
use permitlayer_core::scrub::{ScrubEngine, ScrubSample};
use permitlayer_core::store::{AuditStore, CredentialStore};
use permitlayer_oauth::{CredentialMeta, GoogleOAuthConfig, OAuthClient};
use permitlayer_vault::Vault;

use crate::error::{AgentId, ProxyError, RequestId};
use crate::request::ProxyRequest;
use crate::response::ProxyResponse;
use crate::token::ScopedTokenIssuer;
use crate::upstream::UpstreamClient;

/// Cloned copies of a `ProxyRequest`'s transport-level fields, captured
/// up-front in [`ProxyService::handle`] so the refresh hook can replay
/// the original upstream call after a successful token refresh.
///
/// This struct exists because the current `ProxyService::handle` moves
/// `req.method`, `req.headers`, and `req.body` into the first
/// [`UpstreamClient::dispatch`] call by value. By the time the 401
/// check runs, those fields are gone. The refresh helper needs the
/// original request data to issue the retry dispatch — so `handle`
/// clones the fields into a `ProxyRequestReplayParts` local BEFORE the
/// first dispatch, and passes `&ProxyRequestReplayParts` to
/// [`ProxyService::try_refresh_and_retry`] if that first dispatch
/// returns 401.
///
/// Clone costs:
/// - `method`: trivially cheap (small enum wrapping a smart string).
/// - `path`: `String` clone, typically <100 bytes.
/// - `headers`: `HeaderMap` clone, O(header count). Typically <20
///   headers per request; each header is a small static or cloned
///   byte string.
/// - `body`: `Bytes` clone, which is a **ref-count bump** — no payload
///   copy. The underlying bytes are shared.
///
/// Total cost is single-digit microseconds per request, same order of
/// magnitude as the existing `String::clone()` calls already in
/// `handle`. This is small enough that cloning unconditionally (even
/// for requests that never trigger refresh) is the correct trade-off
/// against the alternative of restructuring `handle` to not move the
/// fields in the first place.
///
/// Added in Story 1.14a Task 2 as part of the refresh integration —
/// the plan-review finding that motivated this shape rejected an
/// earlier "pass these as separate args" attempt.
#[derive(Clone)]
struct ProxyRequestReplayParts {
    method: axum::http::Method,
    path: String,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
}

/// Core proxy service that orchestrates credential fetch, scoped token
/// issuance, upstream dispatch, and audit logging.
pub struct ProxyService {
    credential_store: Arc<dyn CredentialStore>,
    vault: Arc<Vault>,
    token_issuer: Arc<ScopedTokenIssuer>,
    upstream_client: Arc<UpstreamClient>,
    audit_store: Arc<dyn AuditStore>,
    scrub_engine: Arc<ScrubEngine>,
    /// Directory containing per-service sealed credentials and
    /// `{service}-meta.json` provenance files. Used by the refresh path
    /// to reconstruct the correct `OAuthClient` on demand (Story 1.14).
    /// Typically `~/.agentsso/vault`.
    vault_dir: PathBuf,
    /// Test-only OAuth client override map.
    ///
    /// `None` in production. When `Some(map)`,
    /// [`Self::build_oauth_client_for_service`] returns the registered
    /// client directly without reading metadata — this is how integration
    /// tests inject mock-endpoint-pointing clients without polluting
    /// `CredentialMeta` with test-only fields.
    ///
    /// Populated only via [`Self::with_oauth_client_override`], which is
    /// itself `#[cfg(test)]`. Production callers use [`Self::new`] and
    /// always get `None` here.
    ///
    /// The field itself is NOT `#[cfg(test)]`-gated because that would
    /// make it inaccessible from `build_oauth_client_for_service` in
    /// production builds. Instead, the field always exists but is
    /// always `None` outside tests, and the constructor that populates
    /// it is gated.
    ///
    /// See Story 1.14a Task 2b for the rationale (the plan-review
    /// rejection of the `CredentialMeta.token_endpoint_override`
    /// alternative is documented in the story's Dev Notes).
    oauth_client_overrides: Option<HashMap<String, Arc<OAuthClient>>>,
}

impl ProxyService {
    /// Create a new proxy service with all required dependencies.
    ///
    /// `vault_dir` is the filesystem directory where per-service sealed
    /// credential blobs and `{service}-meta.json` metadata files live.
    /// The refresh path reads these meta files on demand to reconstruct
    /// the correct `OAuthClient` for each service being refreshed.
    #[must_use]
    pub fn new(
        credential_store: Arc<dyn CredentialStore>,
        vault: Arc<Vault>,
        token_issuer: Arc<ScopedTokenIssuer>,
        upstream_client: Arc<UpstreamClient>,
        audit_store: Arc<dyn AuditStore>,
        scrub_engine: Arc<ScrubEngine>,
        vault_dir: PathBuf,
    ) -> Self {
        Self {
            credential_store,
            vault,
            token_issuer,
            upstream_client,
            audit_store,
            scrub_engine,
            vault_dir,
            oauth_client_overrides: None,
        }
    }

    /// Construct a `ProxyService` with a pre-populated OAuth client
    /// override map.
    ///
    /// **Test harness and advanced-debugging constructor.** Production
    /// callers should use [`Self::new`]. This constructor is `pub
    /// #[doc(hidden)]` — it does not appear in rustdoc output and is
    /// not part of the stable public API.
    ///
    /// The override map is keyed by service name (e.g. `"gmail"`,
    /// `"calendar"`, `"drive"`) and provides pre-built `OAuthClient`
    /// instances that bypass the normal lazy reconstruction path
    /// in [`Self::build_oauth_client_for_service`]. Integration tests
    /// use this to inject clients pointed at mock OAuth servers on
    /// localhost — see Story 1.14a Task 2b and
    /// `crates/permitlayer-proxy/tests/refresh_integration.rs` (Story
    /// 1.14a Task 5).
    ///
    /// This constructor is NOT `#[cfg(test)]`-gated because integration
    /// tests in the `tests/` directory of this crate link against the
    /// library's regular (non-test) compilation unit and cannot see
    /// `#[cfg(test)]` items. The `#[doc(hidden)]` marker hides it from
    /// public documentation so downstream crates do not accidentally
    /// depend on it. It may be renamed or removed without notice if a
    /// cleaner test seam becomes available.
    ///
    /// The test seam lives here (on `ProxyService`) rather than on
    /// `CredentialMeta` because metadata is persisted production data
    /// and should not carry test-only fields (plan-review rejected the
    /// alternative `CredentialMeta.token_endpoint_override` field).
    #[doc(hidden)]
    #[must_use]
    #[allow(clippy::too_many_arguments)] // Test seam, mirrors `new` + 1 override arg.
    pub fn with_oauth_client_override(
        credential_store: Arc<dyn CredentialStore>,
        vault: Arc<Vault>,
        token_issuer: Arc<ScopedTokenIssuer>,
        upstream_client: Arc<UpstreamClient>,
        audit_store: Arc<dyn AuditStore>,
        scrub_engine: Arc<ScrubEngine>,
        vault_dir: PathBuf,
        oauth_client_overrides: HashMap<String, Arc<OAuthClient>>,
    ) -> Self {
        Self {
            credential_store,
            vault,
            token_issuer,
            upstream_client,
            audit_store,
            scrub_engine,
            vault_dir,
            oauth_client_overrides: Some(oauth_client_overrides),
        }
    }

    /// Accessor: shared scrub engine. Used by Story 6.2's
    /// `ProxyHostServices` to back `agentsso.scrub.text`/`.object`
    /// from inside a plugin call without re-instantiating the
    /// engine per call.
    #[must_use]
    pub fn scrub_engine(&self) -> Arc<ScrubEngine> {
        Arc::clone(&self.scrub_engine)
    }

    /// Accessor: scoped-token issuer. Used by Story 6.2's
    /// `ProxyHostServices` to back `agentsso.oauth.getToken`. The
    /// issuer's signing key is shared with the proxy's request-
    /// validation path, so plugin-issued tokens validate via the
    /// same code path agent-issued ones do.
    #[must_use]
    pub fn token_issuer(&self) -> Arc<crate::token::ScopedTokenIssuer> {
        Arc::clone(&self.token_issuer)
    }

    /// Accessor: vault directory. Used by Story 6.2's
    /// `ProxyHostServices` for `agentsso.oauth.listConnectedServices`
    /// (enumerates `*-meta.json` entries).
    #[must_use]
    pub fn vault_dir(&self) -> &std::path::Path {
        &self.vault_dir
    }

    /// Reconstruct the correct `OAuthClient` for a given service by
    /// reading its metadata file from the vault directory.
    ///
    /// This is the lazy extension point for non-Google services: every
    /// connected service writes a `{service}-meta.json` during setup
    /// recording its `client_type` (currently `"byo"` for Google, with
    /// historical `"shared-casa"` records needing re-setup; future
    /// connectors will add their own). The refresh path dispatches on
    /// `client_type` to rebuild the right client.
    ///
    /// Called once per refresh attempt. At MVP volumes the per-refresh
    /// file read is negligible; caching is a future optimization if
    /// refresh storms become measured.
    ///
    /// Returns an `Arc<OAuthClient>` rather than `OAuthClient` by value
    /// because (a) `OAuthClient` wraps types that are already
    /// `Arc`-wrapped internally, so handing out an `Arc` is zero-cost
    /// wrapping over the underlying state, and (b) the test-only
    /// override path in [`Self::oauth_client_overrides`] stores the
    /// client as `Arc<OAuthClient>` and needs to hand out cheap clones
    /// via `Arc::clone` — this return type lets the override path be
    /// trivially correct and the production path a single `Arc::new`.
    fn build_oauth_client_for_service(
        &self,
        service: &str,
    ) -> Result<Arc<OAuthClient>, ProxyError> {
        // Test-only fast path: if the integration test harness injected an
        // override client for this service via `with_oauth_client_override`,
        // clone the stored `Arc` and skip the metadata read entirely. This
        // is how tests point the refresh path at a mock OAuth server on
        // localhost without polluting production data structures.
        // `oauth_client_overrides` is always `None` in production.
        if let Some(ref overrides) = self.oauth_client_overrides
            && let Some(client) = overrides.get(service)
        {
            return Ok(Arc::clone(client));
        }

        // Story 1.14b code-review m3 fix: error messages used to be
        // prefixed with `"refresh: "`, but the wrapper at the
        // resolver-closure site (in `try_refresh_and_retry`) wraps
        // these messages in `RefreshFlowError::MetaInvalid` whose
        // `Display` adds its own `"refresh: OAuth client build
        // failed for service '{}': "` prefix. The result was a
        // double-prefix like `"refresh: OAuth client build failed
        // for service 'gmail': refresh: could not read metadata..."`.
        // The CLI's inlined copy (`build_oauth_client_for_cli`)
        // never had the prefix; the proxy version has been
        // harmonized to match.
        let meta_path = self.vault_dir.join(format!("{service}-meta.json"));
        let meta_contents =
            std::fs::read_to_string(&meta_path).map_err(|e| ProxyError::Internal {
                message: format!(
                    "could not read metadata for service '{service}' at {}: {e}",
                    meta_path.display()
                ),
            })?;
        let meta: CredentialMeta =
            serde_json::from_str(&meta_contents).map_err(|e| ProxyError::Internal {
                message: format!(
                    "malformed metadata for service '{service}' at {}: {e}",
                    meta_path.display()
                ),
            })?;

        let config = match meta.client_type.as_str() {
            "shared-casa" => {
                return Err(ProxyError::Internal {
                    message: format!(
                        "metadata for service '{service}' was stored against the removed shared-casa client; re-run `agentsso setup {service} --oauth-client <path>` to migrate to a bring-your-own OAuth client"
                    ),
                });
            }
            "byo" => {
                let source = meta.client_source.as_ref().ok_or_else(|| ProxyError::Internal {
                    message: format!(
                        "metadata for service '{service}' is marked 'byo' but has no client_source"
                    ),
                })?;
                GoogleOAuthConfig::from_client_json(std::path::Path::new(source)).map_err(|e| {
                    ProxyError::Internal {
                        message: format!(
                            "could not re-read BYO OAuth client JSON for service '{service}' at {source}: {e}"
                        ),
                    }
                })?
            }
            other => {
                return Err(ProxyError::Internal {
                    message: format!(
                        "metadata for service '{service}' has unknown client_type '{other}'"
                    ),
                });
            }
        };

        OAuthClient::new(config.client_id().to_owned(), config.client_secret().map(str::to_owned))
            .map(Arc::new)
            .map_err(|e| ProxyError::Internal {
                message: format!("could not construct OAuth client for service '{service}': {e}"),
            })
    }

    /// Attempt a single transparent OAuth token refresh on behalf of an
    /// in-flight request whose first upstream dispatch returned 401.
    ///
    /// Thin proxy-flavored wrapper around
    /// [`crate::refresh_flow::refresh_service`]. The shared core
    /// handles unseal → refresh → persist → meta-file update; this
    /// method handles the proxy-specific concerns on top of that:
    /// audit emission using the proxy's request context
    /// (`request_id` / `agent_id` / `scope` / `resource`), the retry
    /// dispatch via `ProxyRequestReplayParts`, and the
    /// `retry_dispatch_failed` outcome (which the shared core cannot
    /// produce because it knows nothing about upstream dispatch).
    ///
    /// Return semantics:
    /// - `Ok(Some(retry_upstream_resp))` — refresh succeeded and the
    ///   retry dispatch succeeded; caller substitutes this response for
    ///   the original 401 and continues with the normal scrub + audit
    ///   + return path.
    /// - `Ok(None)` — no refresh was attempted (missing
    ///   `{service}-refresh` vault entry, degraded operation per
    ///   architecture invariant #7); caller returns the original 401
    ///   response to the agent unchanged.
    /// - `Err(ProxyError)` — refresh definitively failed; caller
    ///   propagates the error (`CredentialRevoked`,
    ///   `UpstreamUnreachable`, or `Internal`).
    ///
    /// Every branch emits exactly one `token-refresh` audit event
    /// before returning. Possible `outcome` values (11 total, covering
    /// every variant of `Result<RefreshOutcome, RefreshFlowError>`
    /// plus the proxy-specific `retry_dispatch_failed`):
    /// `success`, `skipped_no_refresh_token`, `invalid_grant`,
    /// `exhausted`, `persistence_failed`, `malformed_token`,
    /// `store_read_failed`, `vault_unseal_failed`, `meta_invalid`,
    /// `unknown_oauth_error`, `retry_dispatch_failed`. Any future
    /// variant added to `RefreshFlowError` is a compile error here —
    /// the match is exhaustive, so the reviewer doesn't have to
    /// remember to update both sides manually.
    ///
    /// ## INVARIANT: bounded to exactly one refresh per request.
    ///
    /// This method MUST NOT call itself, either directly or through
    /// `self.handle`. The retry dispatch calls
    /// `self.upstream_client.dispatch` directly and returns whatever
    /// comes back — if that retry also returns 401 (e.g. scope
    /// mismatch), the caller will return the 401 to the agent without
    /// a second refresh attempt. This structural bound is the entire
    /// defense against spurious-refresh loops for misconfigured scopes.
    #[allow(clippy::too_many_arguments)]
    async fn try_refresh_and_retry(
        &self,
        service: &str,
        request_id: &str,
        agent_id: &str,
        scope: &str,
        resource: &str,
        replay: &ProxyRequestReplayParts,
    ) -> Result<Option<crate::upstream::UpstreamResponse>, ProxyError> {
        use crate::refresh_flow::{RefreshFlowError, RefreshOutcome, refresh_service};

        // Build the OAuth client resolver closure. The proxy path
        // consults `self.oauth_client_overrides` via
        // `build_oauth_client_for_service`, which preserves the
        // integration-test seam. The CLI path (`refresh_credentials`)
        // builds a simpler production-only resolver in its own module.
        let resolver = |svc: &str| -> Result<Arc<OAuthClient>, RefreshFlowError> {
            self.build_oauth_client_for_service(svc).map_err(|e| RefreshFlowError::MetaInvalid {
                service: svc.to_owned(),
                detail: match e {
                    ProxyError::Internal { message } => message,
                    other => format!("{other}"),
                },
            })
        };

        // Call the shared core. This is the bulk of the refresh state
        // machine — see crate::refresh_flow for details.
        let flow_result = refresh_service(
            &self.vault,
            &self.credential_store,
            &self.vault_dir,
            service,
            &resolver,
        )
        .await;

        // Match on the shared core's result. The two `Ok` arms are
        // proxy-flavored because they emit the proxy-context audit
        // event inline; the `Err` arm delegates both the audit
        // emission and the `ProxyError` mapping to
        // `RefreshFlowError::audit_outcome()` and
        // `From<RefreshFlowError> for ProxyError` (both defined in
        // `refresh_flow`). `PersistenceFailed` is the one error arm
        // that can't use plain `write_audit` because it carries
        // `extra.stage` — it gets a dedicated branch that calls
        // `emit_persistence_failed_audit` instead.
        let new_access_bytes: Zeroizing<Vec<u8>> = match flow_result {
            Ok(RefreshOutcome::Refreshed {
                rotated,
                new_access_bytes,
                new_expiry_at: _,
                last_refreshed_at: _,
            }) => {
                // Success audit BEFORE the retry dispatch. Matches
                // Story 1.14a's ordering: "refresh succeeded"
                // appears in the audit log even if the retry dispatch
                // itself fails, and the retry_dispatch_failed branch
                // at the bottom emits the follow-up event.
                let mut event = AuditEvent::with_request_id(
                    request_id.to_owned(),
                    agent_id.to_owned(),
                    service.to_owned(),
                    scope.to_owned(),
                    resource.to_owned(),
                    "success".to_owned(),
                    "token-refresh".to_owned(),
                );
                event.extra = serde_json::json!({ "refresh_token_rotated": rotated });
                if let Err(e) = self.audit_store.append(event).await {
                    warn!(
                        error = %e,
                        "token-refresh audit event write failed (best-effort)"
                    );
                }
                new_access_bytes
            }
            Ok(RefreshOutcome::Skipped) => {
                self.write_audit(
                    request_id,
                    agent_id,
                    service,
                    scope,
                    resource,
                    "skipped_no_refresh_token",
                    "token-refresh",
                    None,
                )
                .await;
                return Ok(None);
            }
            Err(err) => {
                // Dispatch on whether the error needs the
                // stage-aware audit emission (`PersistenceFailed`) or
                // the plain `write_audit` path (all other variants).
                // Both branches then convert the error via the `From`
                // impl defined in `refresh_flow`, which owns the
                // canonical `RefreshFlowError` → `ProxyError` mapping
                // and the exact message format strings that Story
                // 1.14a's unit tests lock in.
                match &err {
                    RefreshFlowError::PersistenceFailed { stage, .. } => {
                        self.emit_persistence_failed_audit(
                            request_id,
                            agent_id,
                            service,
                            scope,
                            resource,
                            stage.as_str(),
                        )
                        .await;
                    }
                    other => {
                        self.write_audit(
                            request_id,
                            agent_id,
                            service,
                            scope,
                            resource,
                            other.audit_outcome(),
                            "token-refresh",
                            None,
                        )
                        .await;
                    }
                }
                return Err(ProxyError::from(err));
            }
        };
        // `new_access_bytes` is now in scope from the match above,
        // containing the refreshed access token bytes (zeroized on
        // drop). Proceed to the retry dispatch using the replay parts
        // the caller captured BEFORE the first dispatch moved them.
        //
        // UTF-8 was already validated inside the shared core (via
        // `RefreshFlowError::MalformedToken` — if we reached this
        // line the bytes are guaranteed valid UTF-8). We handle the
        // theoretically-impossible Err arm by returning
        // `ProxyError::Internal` rather than panicking, to stay
        // within the workspace's `clippy::expect_used` policy.
        let access_token_str = match std::str::from_utf8(&new_access_bytes) {
            Ok(s) => s,
            Err(e) => {
                return Err(ProxyError::Internal {
                    message: format!(
                        "refresh: access token bytes became invalid UTF-8 between shared-core validation and retry (unreachable): {e}"
                    ),
                });
            }
        };

        // M2 (Story 1.14a): retry dispatch errors must emit a
        // `retry_dispatch_failed` audit event before propagation.
        // This is the 11th outcome — the shared core cannot produce
        // it because it knows nothing about upstream dispatch.
        let retry_dispatch = self
            .upstream_client
            .dispatch(
                service,
                &replay.path,
                replay.method.clone(),
                replay.headers.clone(),
                replay.body.clone(),
                access_token_str,
            )
            .await;

        match retry_dispatch {
            Ok(retry_response) => Ok(Some(retry_response)),
            Err(e) => {
                self.write_audit(
                    request_id,
                    agent_id,
                    service,
                    scope,
                    resource,
                    "retry_dispatch_failed",
                    "token-refresh",
                    None,
                )
                .await;
                Err(e)
            }
        }
    }

    // Old inline refresh logic (Story 1.14a) was lifted into
    // `crate::refresh_flow::refresh_service` as part of Story 1.14b
    // Task 1. See that module for the state machine and the
    // `From<RefreshFlowError> for ProxyError` mapping.

    /// Handle a validated proxy request.
    ///
    /// Orchestrates: credential fetch → vault unseal → scoped token issuance
    /// → upstream dispatch → audit event. The raw OAuth access token is used
    /// solely for the upstream `Authorization: Bearer` header and is NEVER
    /// returned to the agent.
    pub async fn handle(&self, req: ProxyRequest) -> Result<ProxyResponse, ProxyError> {
        // 1. Fetch sealed credential.
        let sealed = match self.credential_store.get(&req.service).await {
            Ok(Some(sealed)) => sealed,
            Ok(None) => {
                self.write_audit(
                    &req.request_id,
                    &req.agent_id,
                    &req.service,
                    &req.scope,
                    &req.resource,
                    "error",
                    "credential-missing",
                    None,
                )
                .await;
                return Err(ProxyError::Internal {
                    message: format!("no credentials for service '{}'", req.service),
                });
            }
            Err(e) => {
                self.write_audit(
                    &req.request_id,
                    &req.agent_id,
                    &req.service,
                    &req.scope,
                    &req.resource,
                    "error",
                    "credential-missing",
                    None,
                )
                .await;
                return Err(ProxyError::Internal {
                    message: format!("credential store error: {e}"),
                });
            }
        };

        // 2. Unseal to get OAuthToken (synchronous — wrap in spawn_blocking).
        let vault = Arc::clone(&self.vault);
        let service_for_unseal = req.service.clone();
        let unseal_result =
            tokio::task::spawn_blocking(move || vault.unseal(&service_for_unseal, &sealed)).await;

        let oauth_token = match unseal_result {
            Ok(Ok(token)) => token,
            Ok(Err(e)) => {
                self.write_audit(
                    &req.request_id,
                    &req.agent_id,
                    &req.service,
                    &req.scope,
                    &req.resource,
                    "error",
                    "vault-unseal-failed",
                    None,
                )
                .await;
                return Err(ProxyError::Internal { message: format!("vault unseal failed: {e}") });
            }
            Err(e) => {
                self.write_audit(
                    &req.request_id,
                    &req.agent_id,
                    &req.service,
                    &req.scope,
                    &req.resource,
                    "error",
                    "vault-unseal-failed",
                    None,
                )
                .await;
                return Err(ProxyError::Internal {
                    message: format!("vault unseal task failed: {e}"),
                });
            }
        };

        // Convert to string for Authorization header.
        let access_token_str = std::str::from_utf8(oauth_token.reveal()).map_err(|e| {
            ProxyError::Internal { message: format!("access token is not valid UTF-8: {e}") }
        })?;

        // 3. Issue scoped token (proves the proxy authorized this request).
        let scoped_token = self.token_issuer.issue(&req.agent_id, &req.scope, &req.resource, 60);

        info!(
            agent_id = %req.agent_id,
            service = %req.service,
            scope = %req.scope,
            resource = %req.resource,
            scoped_token = %scoped_token.token,
            "scoped token issued"
        );

        // 3b. Clone request transport fields for potential refresh retry.
        //
        // The first `dispatch` call on the next line moves `req.method`,
        // `req.headers`, and `req.body` by value, so the refresh hook in
        // `try_refresh_and_retry` (invoked after the dispatch if it
        // returns 401) cannot replay the upstream request without
        // pre-captured copies. Clone these fields into a
        // `ProxyRequestReplayParts` local now, before the move.
        //
        // Cost is bounded and documented on `ProxyRequestReplayParts`
        // itself. Not all requests will trigger refresh — most will not —
        // but the clone is unconditional because by the time we know we
        // need it, the source values are gone.
        let replay_parts = ProxyRequestReplayParts {
            method: req.method.clone(),
            path: req.path.clone(),
            headers: req.headers.clone(),
            body: req.body.clone(),
        };

        // 4. Dispatch upstream.
        let upstream_result = self
            .upstream_client
            .dispatch(&req.service, &req.path, req.method, req.headers, req.body, access_token_str)
            .await;

        // 5. Write error-case audit events immediately (no response body to scrub).
        // Success-case audit is deferred to after scrubbing (scrub-before-log invariant).
        if let Err(ref err) = upstream_result {
            let (outcome, event_type) = match err {
                ProxyError::UpstreamUnreachable { .. } => ("error", "upstream-unreachable"),
                ProxyError::UpstreamRateLimited { .. } => ("error", "rate-limited"),
                _ => ("error", "api-call"),
            };
            self.write_audit(
                &req.request_id,
                &req.agent_id,
                &req.service,
                &req.scope,
                &req.resource,
                outcome,
                event_type,
                None,
            )
            .await;
        }

        // 6. Scrub the upstream response body before returning to agent.
        let mut upstream_resp = upstream_result?;

        // 6a. Story 1.14a refresh hook: if the upstream returned 401,
        // attempt a single transparent token refresh and retry. The
        // bounded-retry invariant (exactly one refresh per request) is
        // enforced structurally — `try_refresh_and_retry` is
        // non-recursive and makes at most one retry dispatch.
        //
        // Three outcomes:
        //   - Ok(Some(retry_resp)): refresh + retry succeeded. Substitute
        //     the retry response and fall through to the normal scrub +
        //     audit + return path. The retry gets scrubbed and logged as
        //     a regular `api-call` event, preceded in the audit log by
        //     the `token-refresh` event emitted inside the helper.
        //   - Ok(None): no refresh attempted (missing refresh token,
        //     degraded operation per architecture invariant #7). The
        //     `skipped_no_refresh_token` audit event has already been
        //     emitted inside the helper. Fall through to the normal
        //     scrub + audit + return path with the ORIGINAL 401 intact.
        //   - Err(proxy_err): refresh definitively failed. The helper
        //     has already emitted the appropriate token-refresh audit
        //     event (`invalid_grant`, `exhausted`, `persistence_failed`,
        //     `malformed_token`, `store_read_failed`, `vault_unseal_failed`,
        //     `meta_invalid`, or `retry_dispatch_failed`). Propagate
        //     the error.
        if upstream_resp.status == 401 {
            match self
                .try_refresh_and_retry(
                    &req.service,
                    &req.request_id,
                    &req.agent_id,
                    &req.scope,
                    &req.resource,
                    &replay_parts,
                )
                .await
            {
                Ok(Some(retry_resp)) => {
                    upstream_resp = retry_resp;
                }
                Ok(None) => {
                    // Keep the original 401; fall through with it unchanged.
                }
                Err(proxy_err) => {
                    return Err(proxy_err);
                }
            }
        }

        let (scrubbed_body, scrub_summary, scrub_samples, was_scrubbed) =
            match std::str::from_utf8(&upstream_resp.body) {
                Ok(text) => {
                    let result = self.scrub_engine.scrub(text);
                    let clean = result.is_clean();
                    let match_count = result.match_count();
                    let summary = result.summary();
                    let spans: Vec<_> =
                        result.matches.iter().map(|m| m.span.start..m.span.end).collect();
                    // Capture samples BEFORE moving `result.output` into Bytes.
                    // Bounded to 3 samples × 48-byte windows per side (~110 bytes
                    // per sample, ~330 bytes total) to keep JSONL lines compact.
                    let samples = result.samples(3, 48);
                    let body = axum::body::Bytes::from(result.output);
                    if !clean {
                        info!(
                            matches = match_count,
                            ?summary,
                            ?spans,
                            "scrubbed upstream response"
                        );
                    }
                    (body, summary, samples, !clean)
                }
                Err(_) => {
                    // Binary/non-UTF-8 response — pass through without scrubbing.
                    (upstream_resp.body.clone(), Default::default(), Vec::new(), false)
                }
            };

        // 7. Write success-case audit event AFTER scrubbing (scrub-before-log invariant).
        // Enrich with scrub payload (summary + samples) when content was scrubbed.
        //
        // Outcome is derived from the upstream status so that a
        // non-success response (e.g. the bounded-retry 401 passthrough
        // after a refresh, or any 4xx/5xx that dispatch doesn't
        // classify as a transport error) is distinguishable from a 2xx
        // success in the audit log. Without this, operators reading
        // `agentsso audit --follow` could not tell "the upstream
        // returned 401" from "the upstream returned 200".
        let payload = if was_scrubbed {
            Some(ScrubPayload { summary: &scrub_summary, samples: &scrub_samples })
        } else {
            None
        };
        let api_call_outcome =
            if (200..300).contains(&upstream_resp.status) { "ok" } else { "http_error" };
        self.write_audit(
            &req.request_id,
            &req.agent_id,
            &req.service,
            &req.scope,
            &req.resource,
            api_call_outcome,
            "api-call",
            payload,
        )
        .await;

        // Remove Content-Length if scrubbing changed the body size.
        let mut headers = upstream_resp.headers;
        if was_scrubbed {
            headers.remove(axum::http::header::CONTENT_LENGTH);
        }

        Ok(ProxyResponse {
            status: StatusCode::from_u16(upstream_resp.status).unwrap_or(StatusCode::BAD_GATEWAY),
            headers,
            body: scrubbed_body,
        })
    }

    /// Build an axum router with this proxy service as the innermost handler.
    ///
    /// Mounts `/v1/tools/{service}/{*path}` accepting any HTTP method.
    /// The proxy forwards the client's method to the upstream API (GET, POST,
    /// PUT, DELETE, etc.), so clients use the correct method for each endpoint.
    pub fn into_router(self: Arc<Self>) -> Router {
        let service = self;
        Router::new().route(
            "/v1/tools/{service}/{*path}",
            any({
                let service = Arc::clone(&service);
                move |path: Path<(String, String)>, request: Request| {
                    let service = Arc::clone(&service);
                    async move { proxy_handler(service, path, request).await }
                }
            }),
        )
    }

    /// Write an audit event (best-effort — logs a warning on failure).
    ///
    /// Uses `AuditEvent::with_request_id` so the audit entry correlates
    /// with the proxy request's ULID from `RequestTraceLayer`.
    ///
    /// When `scrub_payload` is provided with a non-empty summary, the
    /// audit event's `extra` field is populated with
    /// `{ "scrub_events": { "summary": {...}, "samples": [...] } }`
    /// (audit schema v2, see Story 2.6). `samples` are already scrubbed
    /// by construction — the engine slices them from its own output.
    #[allow(clippy::too_many_arguments)]
    async fn write_audit(
        &self,
        request_id: &str,
        agent_id: &str,
        service: &str,
        scope: &str,
        resource: &str,
        outcome: &str,
        event_type: &str,
        scrub_payload: Option<ScrubPayload<'_>>,
    ) {
        let mut event = AuditEvent::with_request_id(
            request_id.to_owned(),
            agent_id.to_owned(),
            service.to_owned(),
            scope.to_owned(),
            resource.to_owned(),
            outcome.to_owned(),
            event_type.to_owned(),
        );
        if let Some(payload) = scrub_payload
            && !payload.summary.is_empty()
        {
            event.extra = serde_json::json!({
                "scrub_events": {
                    "summary": payload.summary,
                    "samples": payload.samples,
                }
            });
        }
        if let Err(e) = self.audit_store.append(event).await {
            warn!(error = %e, "audit event write failed (best-effort)");
        }
    }

    /// Emit a `token-refresh` audit event for the `persistence_failed`
    /// outcome, recording WHICH persist stage failed in `extra.stage`.
    ///
    /// The four possible stages (`refresh_token_seal`,
    /// `refresh_token_store`, `access_token_seal`,
    /// `access_token_store`) correspond to the four persistence steps
    /// in `try_refresh_and_retry`. Without this signal, the audit
    /// record for `persistence_failed` is ambiguous — operators would
    /// have to cross-reference the daemon log's `ProxyError::Internal`
    /// message (which carries the stage via the recognizable substring
    /// locked in by AC 6's unit test) to figure out what actually
    /// failed. Having it in the durable audit record itself is
    /// strictly better for post-incident forensics.
    ///
    /// Note: the stage label never includes any token bytes — it is a
    /// fixed enum of four constant strings, so the "no token bytes in
    /// audit fields" invariant is preserved structurally.
    #[allow(clippy::too_many_arguments)]
    async fn emit_persistence_failed_audit(
        &self,
        request_id: &str,
        agent_id: &str,
        service: &str,
        scope: &str,
        resource: &str,
        stage: &'static str,
    ) {
        let mut event = AuditEvent::with_request_id(
            request_id.to_owned(),
            agent_id.to_owned(),
            service.to_owned(),
            scope.to_owned(),
            resource.to_owned(),
            "persistence_failed".to_owned(),
            "token-refresh".to_owned(),
        );
        event.extra = serde_json::json!({ "stage": stage });
        if let Err(e) = self.audit_store.append(event).await {
            warn!(error = %e, "token-refresh persistence_failed audit write failed (best-effort)");
        }
    }
}

/// Bundled scrub payload passed to `write_audit` for v2 schema events.
///
/// `summary` mirrors the pre-v2 flat `{rule: count}` shape for backward
/// compatibility with count-only consumers. `samples` carries
/// pre-scrubbed contextual snippets for the inline rendering component.
#[derive(Debug, Clone, Copy)]
struct ScrubPayload<'a> {
    summary: &'a BTreeMap<String, usize>,
    samples: &'a [ScrubSample],
}

/// Axum handler that extracts path parameters and request extensions,
/// constructs a `ProxyRequest`, and delegates to `ProxyService::handle`.
async fn proxy_handler(
    service: Arc<ProxyService>,
    Path((svc, raw_path)): Path<(String, String)>,
    request: Request,
) -> Response {
    // F10: Validate service name before any I/O.
    if let Err(_e) = permitlayer_core::store::validate_service_name(&svc) {
        return ProxyError::NotFound { path: format!("/v1/tools/{svc}") }
            .into_response_with_request_id(None);
    }

    // F6: Strip leading `/` from axum's {*path} extractor to prevent
    // Url::join from rebasing the path (RFC 3986 resolution).
    let path = raw_path.strip_prefix('/').unwrap_or(&raw_path).to_owned();
    // TODO: reject with ProxyError::Unauthorized when auth middleware is wired (Epic 4).
    let agent_id = request
        .extensions()
        .get::<AgentId>()
        .map(|a| a.0.clone())
        .unwrap_or_else(|| {
            warn!("AgentId extension missing — defaulting to \"unknown\". Auth middleware not wired yet.");
            "unknown".to_owned()
        });

    let request_id =
        request.extensions().get::<RequestId>().map(|r| r.0.clone()).unwrap_or_default();

    let scope = match request.headers().get("x-agentsso-scope") {
        Some(v) => match v.to_str() {
            Ok(s) => s.to_owned(),
            Err(_) => {
                tracing::warn!(
                    request_id = %request_id,
                    "x-agentsso-scope header present but not valid UTF-8; rejecting as missing"
                );
                return ProxyError::MissingScopeHeader
                    .into_response_with_request_id(Some(request_id.clone()));
            }
        },
        None => {
            return ProxyError::MissingScopeHeader
                .into_response_with_request_id(Some(request_id.clone()));
        }
    };

    // F9: Reject scope values containing control characters (log injection defence).
    if scope.bytes().any(|b| b < 0x20) {
        return ProxyError::Internal {
            message: "x-agentsso-scope header contains invalid characters".to_owned(),
        }
        .into_response_with_request_id(Some(request_id.clone()));
    }

    let method = request.method().clone();
    let headers = request.headers().clone();

    let body = match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return ProxyError::Internal { message: format!("failed to read request body: {e}") }
                .into_response_with_request_id(Some(request_id));
        }
    };

    let resource = path.clone();

    let proxy_req = ProxyRequest {
        service: svc,
        scope,
        resource,
        method,
        path,
        headers,
        body,
        agent_id,
        request_id: request_id.clone(),
    };

    match service.handle(proxy_req).await {
        Ok(resp) => resp.into_response(),
        Err(err) => err.into_response_with_request_id(Some(request_id)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use axum::body::Bytes;
    use axum::http::{HeaderMap, Method};
    use permitlayer_core::scrub::builtin_rules;
    use permitlayer_core::store::StoreError;
    use permitlayer_credential::{OAuthToken, SealedCredential};
    use tempfile::TempDir;
    use url::Url;
    use zeroize::Zeroizing;

    // --- Mock CredentialStore ---
    //
    // SealedCredential is not Clone, so we store the raw bytes needed
    // to reconstruct it and seal a fresh copy on each `get()` call.

    struct MockCredentialStore {
        /// Maps service name → (master_key, token_bytes) so we can seal fresh
        /// on each get() call.
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
                    let vault = Vault::new(Zeroizing::new(self.master_key));
                    let token = OAuthToken::from_trusted_bytes(token_bytes.clone());
                    match vault.seal(service, &token) {
                        Ok(sealed) => Ok(Some(sealed)),
                        Err(_) => panic!("mock seal failed for {service}"),
                    }
                }
                None => Ok(None),
            }
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
    }

    #[async_trait::async_trait]
    impl AuditStore for MockAuditStore {
        async fn append(&self, event: AuditEvent) -> Result<(), StoreError> {
            self.events.lock().unwrap().push(event);
            Ok(())
        }
    }

    // --- Test helpers ---

    const TEST_MASTER_KEY: [u8; 32] = [0x42; 32];

    fn test_vault() -> Vault {
        Vault::new(Zeroizing::new(TEST_MASTER_KEY))
    }

    fn test_token_issuer() -> ScopedTokenIssuer {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        ScopedTokenIssuer::new(Zeroizing::new(key))
    }

    fn test_scrub_engine() -> Arc<ScrubEngine> {
        Arc::new(ScrubEngine::new(builtin_rules().to_vec()).unwrap())
    }

    async fn build_service_with_mock_upstream(
        server_url: &str,
    ) -> (Arc<ProxyService>, Arc<MockAuditStore>, TempDir) {
        let mut cred_store = MockCredentialStore::new(TEST_MASTER_KEY);
        cred_store.add_service("gmail", b"fake-access-token");

        let credential_store: Arc<dyn CredentialStore> = Arc::new(cred_store);
        let vault = Arc::new(test_vault());
        let token_issuer = Arc::new(test_token_issuer());

        let client = reqwest::Client::builder().build().unwrap();
        let mut base_urls = HashMap::new();
        base_urls.insert("gmail".to_owned(), Url::parse(server_url).unwrap());
        let upstream_client = Arc::new(UpstreamClient::with_client_and_urls(client, base_urls));

        let audit_store = Arc::new(MockAuditStore::new());

        // Hermetic per-test vault dir. The caller must keep the
        // returned `TempDir` alive for the test duration.
        let tempdir = TempDir::new().unwrap();

        let service = Arc::new(ProxyService::new(
            credential_store,
            vault,
            token_issuer,
            upstream_client,
            Arc::clone(&audit_store) as Arc<dyn AuditStore>,
            test_scrub_engine(),
            tempdir.path().to_path_buf(),
        ));

        (service, audit_store, tempdir)
    }

    fn test_request(service: &str, path: &str) -> ProxyRequest {
        ProxyRequest {
            service: service.to_owned(),
            scope: "mail.readonly".to_owned(),
            resource: path.to_owned(),
            method: Method::GET,
            path: path.to_owned(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
            agent_id: "agent-1".to_owned(),
            request_id: "01TESTULID".to_owned(),
        }
    }

    #[tokio::test]
    async fn happy_path_returns_upstream_response() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/users/me/messages")
            .match_header("authorization", "Bearer fake-access-token")
            .with_status(200)
            .with_body(r#"{"messages":[]}"#)
            .create_async()
            .await;

        let (service, audit_store, _tempdir) =
            build_service_with_mock_upstream(&format!("{}/", server.url())).await;

        let req = test_request("gmail", "users/me/messages");
        let resp = service.handle(req).await.unwrap();

        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body, r#"{"messages":[]}"#.as_bytes());

        // Verify audit event was written.
        {
            let events = audit_store.events.lock().unwrap();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].outcome, "ok");
            assert_eq!(events[0].event_type, "api-call");
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn missing_credentials_returns_error() {
        // Build service with no credentials.
        let vault = Arc::new(test_vault());
        let cred_store = MockCredentialStore::new(TEST_MASTER_KEY);
        let credential_store: Arc<dyn CredentialStore> = Arc::new(cred_store);
        let token_issuer = Arc::new(test_token_issuer());
        let upstream_client = Arc::new(UpstreamClient::new().unwrap());
        let audit_store = Arc::new(MockAuditStore::new());
        let _tempdir = TempDir::new().unwrap();

        let service = ProxyService::new(
            credential_store,
            vault,
            token_issuer,
            upstream_client,
            audit_store,
            test_scrub_engine(),
            _tempdir.path().to_path_buf(),
        );

        let req = test_request("gmail", "users/me/messages");
        let err = service.handle(req).await.unwrap_err();

        assert!(matches!(err, ProxyError::Internal { .. }));
        assert!(err.to_string().contains("no credentials"));
    }

    #[tokio::test]
    async fn vault_unseal_error_returns_internal() {
        // Seal with one master key, unseal with a different one.
        let mut cred_store = MockCredentialStore::new([0x42; 32]);
        cred_store.add_service("gmail", b"fake-token");

        let unseal_vault = Arc::new(Vault::new(Zeroizing::new([0x99; 32])));

        let credential_store: Arc<dyn CredentialStore> = Arc::new(cred_store);
        let token_issuer = Arc::new(test_token_issuer());
        let upstream_client = Arc::new(UpstreamClient::new().unwrap());
        let audit_store = Arc::new(MockAuditStore::new());
        let _tempdir = TempDir::new().unwrap();

        let service = ProxyService::new(
            credential_store,
            unseal_vault,
            token_issuer,
            upstream_client,
            audit_store,
            test_scrub_engine(),
            _tempdir.path().to_path_buf(),
        );

        let req = test_request("gmail", "users/me/messages");
        let err = service.handle(req).await.unwrap_err();
        assert!(matches!(err, ProxyError::Internal { .. }));
        assert!(err.to_string().contains("unseal"));
    }

    #[tokio::test]
    async fn upstream_unreachable_writes_audit_event() {
        let mut cred_store = MockCredentialStore::new(TEST_MASTER_KEY);
        cred_store.add_service("gmail", b"fake-access-token");

        let credential_store: Arc<dyn CredentialStore> = Arc::new(cred_store);
        let vault = Arc::new(test_vault());
        let token_issuer = Arc::new(test_token_issuer());

        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_millis(100))
            .timeout(std::time::Duration::from_millis(200))
            .build()
            .unwrap();
        let mut base_urls = HashMap::new();
        base_urls.insert("gmail".to_owned(), Url::parse("http://127.0.0.1:1/").unwrap());
        let upstream_client = Arc::new(UpstreamClient::with_client_and_urls(client, base_urls));
        let audit_store = Arc::new(MockAuditStore::new());
        let _tempdir = TempDir::new().unwrap();

        let service = ProxyService::new(
            credential_store,
            vault,
            token_issuer,
            upstream_client,
            Arc::clone(&audit_store) as Arc<dyn AuditStore>,
            test_scrub_engine(),
            _tempdir.path().to_path_buf(),
        );

        let req = test_request("gmail", "users/me/messages");
        let err = service.handle(req).await.unwrap_err();
        assert!(matches!(err, ProxyError::UpstreamUnreachable { .. }));

        let events = audit_store.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, "error");
        assert_eq!(events[0].event_type, "upstream-unreachable");
    }

    #[tokio::test]
    async fn upstream_429_passes_through() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/users/me/messages")
            .with_status(429)
            .with_header("retry-after", "30")
            .create_async()
            .await;

        let (service, audit_store, _tempdir) =
            build_service_with_mock_upstream(&format!("{}/", server.url())).await;

        let req = test_request("gmail", "users/me/messages");
        let err = service.handle(req).await.unwrap_err();

        match &err {
            ProxyError::UpstreamRateLimited { service, retry_after } => {
                assert_eq!(service, "gmail");
                assert_eq!(retry_after.as_deref(), Some("30"));
            }
            other => panic!("expected UpstreamRateLimited, got {other:?}"),
        }

        {
            let events = audit_store.events.lock().unwrap();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].outcome, "error");
            assert_eq!(events[0].event_type, "rate-limited");
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn raw_token_not_in_response() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/users/me/messages")
            .with_status(200)
            .with_body(r#"{"data":"safe"}"#)
            .create_async()
            .await;

        let (service, _, _tempdir) =
            build_service_with_mock_upstream(&format!("{}/", server.url())).await;

        let req = test_request("gmail", "users/me/messages");
        let resp = service.handle(req).await.unwrap();

        // The raw access token must not appear anywhere in the response.
        let body_str = String::from_utf8_lossy(&resp.body);
        assert!(!body_str.contains("fake-access-token"), "raw OAuth token found in response body!");

        // Check headers too.
        for (_name, value) in &resp.headers {
            let val_str = value.to_str().unwrap_or("");
            assert!(
                !val_str.contains("fake-access-token"),
                "raw OAuth token found in response headers!"
            );
        }

        mock.assert_async().await;
    }

    // --- Scrub pipeline tests (Story 2.3) ---

    #[tokio::test]
    async fn scrub_redacts_otp_in_response() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/users/me/messages")
            .with_status(200)
            .with_body("Your verification code is 123456. Please use it within 5 minutes.")
            .create_async()
            .await;

        let (service, _, _tempdir) =
            build_service_with_mock_upstream(&format!("{}/", server.url())).await;

        let req = test_request("gmail", "users/me/messages");
        let resp = service.handle(req).await.unwrap();

        let body_str = String::from_utf8_lossy(&resp.body);
        assert!(body_str.contains("<REDACTED_OTP>"), "OTP should be redacted: {body_str}");
        assert!(!body_str.contains("123456"), "original OTP should not be in response: {body_str}");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn scrub_passes_through_binary_response() {
        let mut server = mockito::Server::new_async().await;
        // Non-UTF-8 binary body
        let binary_body: Vec<u8> = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46];
        let mock = server
            .mock("GET", "/users/me/photo")
            .with_status(200)
            .with_body(binary_body.clone())
            .create_async()
            .await;

        let (service, _, _tempdir) =
            build_service_with_mock_upstream(&format!("{}/", server.url())).await;

        let req = test_request("gmail", "users/me/photo");
        let resp = service.handle(req).await.unwrap();

        assert_eq!(
            resp.body.as_ref(),
            binary_body.as_slice(),
            "binary body should pass through unchanged"
        );

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn scrub_clean_response_is_byte_identical() {
        let clean_body =
            r#"{"messages":[{"subject":"Meeting notes","snippet":"The meeting went well."}]}"#;

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/users/me/messages")
            .with_status(200)
            .with_body(clean_body)
            .create_async()
            .await;

        let (service, _, _tempdir) =
            build_service_with_mock_upstream(&format!("{}/", server.url())).await;

        let req = test_request("gmail", "users/me/messages");
        let resp = service.handle(req).await.unwrap();

        assert_eq!(
            resp.body.as_ref(),
            clean_body.as_bytes(),
            "clean body should be byte-identical"
        );

        mock.assert_async().await;
    }

    // --- Scrub summary enrichment tests (Story 2.4, extended to v2 shape in Story 2.6) ---

    #[tokio::test]
    async fn scrub_summary_in_audit_event_extra() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/users/me/messages")
            .with_status(200)
            .with_body("Your verification code is 123456. Please enter it now.")
            .create_async()
            .await;

        let (service, audit_store, _tempdir) =
            build_service_with_mock_upstream(&format!("{}/", server.url())).await;

        let req = test_request("gmail", "users/me/messages");
        service.handle(req).await.unwrap();

        {
            let events = audit_store.events.lock().unwrap();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].outcome, "ok");
            assert_eq!(events[0].schema_version, 2, "Story 2.6 audit schema bump to v2");

            // extra should contain scrub_events with {summary, samples} (v2 shape).
            let extra = &events[0].extra;
            assert!(!extra.is_null(), "extra should be populated when scrub fires");
            let scrub_events = &extra["scrub_events"];
            assert!(scrub_events.is_object(), "scrub_events should be an object: {extra}");

            // summary (v2 nested shape): OTP rule should have count >= 1.
            let summary = &scrub_events["summary"];
            assert!(summary.is_object(), "summary should be an object: {scrub_events}");
            let otp_count = summary
                .as_object()
                .unwrap()
                .iter()
                .find(|(k, _)| k.contains("otp"))
                .map(|(_, v)| v.as_u64().unwrap_or(0))
                .unwrap_or(0);
            assert!(otp_count >= 1, "OTP rule should fire at least once: {scrub_events}");

            // samples (Story 2.6): first sample is an OTP match with a snippet
            // containing <REDACTED_OTP> and a placeholder_offset that slices
            // to the placeholder within the snippet.
            let samples = &scrub_events["samples"];
            assert!(samples.is_array(), "samples should be an array: {scrub_events}");
            let samples_arr = samples.as_array().unwrap();
            assert!(!samples_arr.is_empty(), "samples should be non-empty");
            let first = &samples_arr[0];
            assert_eq!(first["rule"], "otp-6digit");
            let snippet = first["snippet"].as_str().unwrap();
            assert!(snippet.contains("<REDACTED_OTP>"), "snippet: {snippet}");
            assert!(!snippet.contains("123456"), "raw OTP leaked: {snippet}");
            let offset = first["placeholder_offset"].as_u64().unwrap() as usize;
            let len = first["placeholder_len"].as_u64().unwrap() as usize;
            assert_eq!(&snippet[offset..offset + len], "<REDACTED_OTP>");
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn clean_response_has_null_extra() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/users/me/messages")
            .with_status(200)
            .with_body(r#"{"messages":[]}"#)
            .create_async()
            .await;

        let (service, audit_store, _tempdir) =
            build_service_with_mock_upstream(&format!("{}/", server.url())).await;

        let req = test_request("gmail", "users/me/messages");
        service.handle(req).await.unwrap();

        {
            let events = audit_store.events.lock().unwrap();
            assert_eq!(events.len(), 1);
            assert!(
                events[0].extra.is_null(),
                "extra should be null for clean responses: {:?}",
                events[0].extra
            );
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn scrub_removes_content_length_when_body_changes() {
        let mut server = mockito::Server::new_async().await;
        let body = "Your verification code is 123456.";
        let mock = server
            .mock("GET", "/users/me/messages")
            .with_status(200)
            .with_header("content-length", &body.len().to_string())
            .with_body(body)
            .create_async()
            .await;

        let (service, _, _tempdir) =
            build_service_with_mock_upstream(&format!("{}/", server.url())).await;

        let req = test_request("gmail", "users/me/messages");
        let resp = service.handle(req).await.unwrap();

        // Content-Length should be removed since body was scrubbed.
        assert!(
            resp.headers.get(axum::http::header::CONTENT_LENGTH).is_none(),
            "Content-Length should be removed when body is scrubbed"
        );

        mock.assert_async().await;
    }

    // --- Story 1.14a Task 2b: oauth_client_overrides test seam ---

    #[tokio::test]
    async fn new_constructor_leaves_oauth_client_overrides_none() {
        // Production `ProxyService::new` must never populate the override map.
        // This is the "production code path is unpolluted" contract.
        let vault = Arc::new(test_vault());
        let cred_store =
            Arc::new(MockCredentialStore::new(TEST_MASTER_KEY)) as Arc<dyn CredentialStore>;
        let token_issuer = Arc::new(test_token_issuer());
        let upstream_client = Arc::new(UpstreamClient::new().unwrap());
        let audit_store = Arc::new(MockAuditStore::new()) as Arc<dyn AuditStore>;
        let _tempdir = TempDir::new().unwrap();

        let service = ProxyService::new(
            cred_store,
            vault,
            token_issuer,
            upstream_client,
            audit_store,
            test_scrub_engine(),
            _tempdir.path().to_path_buf(),
        );

        assert!(
            service.oauth_client_overrides.is_none(),
            "ProxyService::new must initialize oauth_client_overrides to None"
        );
    }

    #[tokio::test]
    async fn with_oauth_client_override_populates_override_map() {
        // Story 1.14a Task 2b: the test-only constructor stores the injected
        // override map so `build_oauth_client_for_service` can skip the metadata
        // read and return the registered Arc<OAuthClient> directly.
        let vault = Arc::new(test_vault());
        let cred_store =
            Arc::new(MockCredentialStore::new(TEST_MASTER_KEY)) as Arc<dyn CredentialStore>;
        let token_issuer = Arc::new(test_token_issuer());
        let upstream_client = Arc::new(UpstreamClient::new().unwrap());
        let audit_store = Arc::new(MockAuditStore::new()) as Arc<dyn AuditStore>;
        // Hermetic per-test vault dir. The fallthrough assertion at
        // the bottom depends on NO `calendar-meta.json` existing in
        // this directory — using a shared system temp dir could leak a
        // stale meta file from another test run and make the
        // assertion pass for the wrong reason.
        let tempdir = TempDir::new().unwrap();

        // Build a placeholder OAuth client. The endpoint URLs don't matter
        // for this test — we only care that the override map is populated
        // and that `build_oauth_client_for_service` returns the right Arc.
        let mock_client = Arc::new(
            permitlayer_oauth::OAuthClient::new_with_endpoint_overrides(
                "test-client".to_owned(),
                None,
                "http://127.0.0.1:0/auth",
                "http://127.0.0.1:0/token",
            )
            .expect("mock client construction"),
        );

        let mut overrides = HashMap::new();
        overrides.insert("gmail".to_owned(), Arc::clone(&mock_client));

        let service = ProxyService::with_oauth_client_override(
            cred_store,
            vault,
            token_issuer,
            upstream_client,
            audit_store,
            test_scrub_engine(),
            tempdir.path().to_path_buf(),
            overrides,
        );

        // Override is present for gmail.
        assert!(service.oauth_client_overrides.is_some());
        let got = service
            .build_oauth_client_for_service("gmail")
            .expect("override lookup should succeed");
        // Both Arcs point at the same underlying OAuthClient.
        assert!(Arc::ptr_eq(&got, &mock_client));

        // Override is NOT present for calendar — falls through to
        // metadata read, which must fail because the hermetic tempdir
        // contains no `calendar-meta.json`. This asserts the
        // fallthrough behavior: services absent from the override map
        // go through the production path.
        let fall_through = service.build_oauth_client_for_service("calendar");
        assert!(
            fall_through.is_err(),
            "services absent from override map should fall through to metadata read (and fail, in this test)"
        );
    }
}
