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
use permitlayer_credential::Slot;
use permitlayer_oauth::{GoogleOAuthConfig, OAuthClient};
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
    /// Connector registry (Story 11.5). Resolves a request's bare
    /// service name → the connector's upstream spec (`base_url` +
    /// `allowed_hosts`) for dispatch. Replaces the hardcoded `base_urls`
    /// map that used to live on `UpstreamClient`. Also the resolution
    /// point for scope/tier (11.7) and the full authz chain (11.10).
    connectors: Arc<permitlayer_connectors::ConnectorRegistry>,
    /// Story 11.6: operator escape hatch (`--allow-private-upstream`).
    /// When `false` (default), a host-installed connector may not use
    /// http or resolve to a private/loopback/metadata IP range. Built-in
    /// connectors are unaffected. Sourced from config at boot.
    allow_private_upstream: bool,
    audit_store: Arc<dyn AuditStore>,
    scrub_engine: Arc<ScrubEngine>,
    /// Directory containing per-connection sealed credentials
    /// (`<connection_id>-<slot>.sealed`, Story 11.9). The refresh path
    /// unseals the `Client` slot here to reconstruct the `OAuthClient` on
    /// demand. Typically `~/.agentsso/vault`.
    vault_dir: PathBuf,
    /// Directory where decoded inbound attachments are materialized for
    /// the MCP agent to read by local path (Gmail `attachments.get`). Per
    /// `permitlayer_core::paths::media_dir`. Files are written
    /// client-readable + TTL-swept by the daemon.
    media_dir: PathBuf,
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
    /// Story 11.10: per-agent binding store. `Some` in production (and the
    /// 11.10 e2e harness) wires real binding resolution; `None` keeps the
    /// legacy proxy unit tests — which construct `ProxyService` directly
    /// without binding stores — working via the
    /// [`Self::legacy_connection_id_for_service`] fallback. Both stores are
    /// `Some` or both `None`; mixing is a wiring bug (the builder sets them
    /// together).
    binding_store: Option<Arc<dyn permitlayer_core::store::BindingStore>>,
    /// Story 11.10: connection metadata store. See `binding_store`.
    connection_store: Option<Arc<dyn permitlayer_core::store::ConnectionStore>>,
}

impl ProxyService {
    /// Create a new proxy service with all required dependencies.
    ///
    /// `vault_dir` is the filesystem directory where per-service sealed
    /// credential blobs and `{service}-meta.json` metadata files live.
    /// The refresh path reads these meta files on demand to reconstruct
    /// the correct `OAuthClient` for each service being refreshed.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // wiring constructor: all deps + vault_dir + media_dir.
    #[allow(clippy::too_many_arguments)] // service wiring: all collaborators injected.
    pub fn new(
        credential_store: Arc<dyn CredentialStore>,
        vault: Arc<Vault>,
        token_issuer: Arc<ScopedTokenIssuer>,
        upstream_client: Arc<UpstreamClient>,
        connectors: Arc<permitlayer_connectors::ConnectorRegistry>,
        audit_store: Arc<dyn AuditStore>,
        scrub_engine: Arc<ScrubEngine>,
        vault_dir: PathBuf,
        media_dir: PathBuf,
    ) -> Self {
        Self {
            credential_store,
            vault,
            token_issuer,
            upstream_client,
            connectors,
            allow_private_upstream: false,
            audit_store,
            scrub_engine,
            vault_dir,
            media_dir,
            oauth_client_overrides: None,
            binding_store: None,
            connection_store: None,
        }
    }

    /// Wire real per-request binding resolution (Story 11.10).
    ///
    /// When both stores are present, [`Self::handle_inner`] resolves the
    /// connection id for `(agent, selector)` from the agent's bindings and
    /// gates the request on `tier ∩ granted_scopes ∩ binding.policy`
    /// (default-deny). When absent, the proxy falls back to the legacy
    /// service-string → connection-id derivation used by the existing unit
    /// tests. Builder-style so the many `new` call sites need no new
    /// argument.
    #[must_use]
    pub fn with_binding_resolution(
        mut self,
        binding_store: Arc<dyn permitlayer_core::store::BindingStore>,
        connection_store: Arc<dyn permitlayer_core::store::ConnectionStore>,
    ) -> Self {
        self.binding_store = Some(binding_store);
        self.connection_store = Some(connection_store);
        self
    }

    /// Set the `--allow-private-upstream` escape hatch (Story 11.6).
    /// Builder-style so the many `new` call sites need no new argument;
    /// defaults to `false`.
    #[must_use]
    pub fn with_allow_private_upstream(mut self, allow: bool) -> Self {
        self.allow_private_upstream = allow;
        self
    }

    /// Test-only fallback: derive a stable [`ConnectionId`] from a bare
    /// `service` string when no [`BindingStore`] is wired. Production
    /// always wires binding resolution via [`Self::with_binding_resolution`],
    /// so this path is only taken by the legacy proxy unit tests that
    /// construct a `ProxyService` directly and seed credentials by service
    /// name. Byte-identical to the daemon control-plane seal handler's
    /// equivalent derivation, so a credential sealed under `<service>`
    /// round-trips here.
    ///
    /// Remove when all proxy unit tests seed a binding + connection.
    ///
    /// [`BindingStore`]: permitlayer_core::store::BindingStore
    /// [`ConnectionId`]: permitlayer_credential::ConnectionId
    #[doc(hidden)]
    fn legacy_connection_id_for_service(service: &str) -> permitlayer_credential::ConnectionId {
        use sha2::{Digest, Sha256};
        const SHIM_DOMAIN: &[u8] = b"permitlayer-connectionid-shim-v1:";
        let mut hasher = Sha256::new();
        hasher.update(SHIM_DOMAIN);
        hasher.update(service.as_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        permitlayer_credential::ConnectionId::from_bytes(bytes)
    }

    /// Resolve the connection id for `(agent, selector)` and run the
    /// default-deny binding authz gate (Story 11.10).
    ///
    /// When both binding stores are wired, this is the production path:
    ///   1. load the agent's bindings,
    ///   2. match one by `alias`, then connection `name`, then id text,
    ///   3. confirm the connection is `Active`,
    ///   4. gate the tool's `required_scope` (= `req.scope`, a short name)
    ///      on `connector.tiers[tier] ∩ connection.granted_scopes`,
    ///   5. return the resolved [`ConnectionId`] AND the connection's
    ///      `connector_id` (so dispatch resolves the upstream from the
    ///      connection's connector, not the raw selector — the selector is
    ///      a per-account alias like `acct-a`, not a connector id).
    ///
    /// The optional per-binding `policy` is NOT evaluated here — it is
    /// surfaced upstream by `AuthService`, which stamps the matched
    /// binding's `policy` into `AgentPolicyBinding` so `PolicyLayer` + the
    /// approval engine (which run before this service) evaluate it. This
    /// resolver and that stamp use the SAME `crate::binding_resolve` match,
    /// so they always agree on which binding the selector addresses.
    ///
    /// When the stores are absent (legacy unit tests), it returns the
    /// [`Self::legacy_connection_id_for_service`] derivation with no gate
    /// and `connector_id = None` (the caller falls back to mapping the
    /// selector to a connector id — the tests pre-date the binding model).
    ///
    /// [`ConnectionId`]: permitlayer_credential::ConnectionId
    async fn resolve_connection(
        &self,
        agent_id: &str,
        selector: &str,
        required_scope: &str,
    ) -> Result<(permitlayer_credential::ConnectionId, Option<String>), ProxyError> {
        use permitlayer_core::store::connection::ConnectionTier;

        let (Some(binding_store), Some(connection_store)) =
            (self.binding_store.as_ref(), self.connection_store.as_ref())
        else {
            // Legacy fallback — no binding stores wired. `None` connector_id
            // tells the caller to map the selector → connector id itself.
            return Ok((Self::legacy_connection_id_for_service(selector), None));
        };

        // 1+2+3. Load the agent's bindings and match by the shared
        //   precedence (alias → connection name → id text), skipping
        //   revoked connections. Factored into `crate::binding_resolve` so
        //   `AuthService` (which stamps the binding's policy upstream) and
        //   this authoritative resolver agree on exactly which binding a
        //   selector addresses.
        let (binding, connection) = crate::binding_resolve::resolve_agent_binding(
            binding_store,
            connection_store,
            agent_id,
            selector,
        )
        .await
        .map_err(|e| ProxyError::Internal {
            message: format!("binding/connection store read failed for agent '{agent_id}': {e}"),
        })?
        .ok_or_else(|| ProxyError::BindingNotFound {
            agent: agent_id.to_owned(),
            selector: selector.to_owned(),
        })?;

        // 4. AUTHZ gate (default-deny): tier ∩ granted_scopes.
        //    `required_scope` (req.scope) is a connector short name (e.g.
        //    `gmail.send`); tier bundles hold short names; granted_scopes
        //    holds full OAuth URIs. So the tier check compares short names
        //    and the granted check compares the short name's URI.
        let connector =
            self.connectors.get(&connection.connector_id).ok_or_else(|| ProxyError::Internal {
                message: format!(
                    "connection '{}' references unknown connector '{}'",
                    connection.id, connection.connector_id
                ),
            })?;

        let tier_name = match binding.tier {
            ConnectionTier::Read => "read",
            ConnectionTier::ReadWrite => "read-write",
        };
        let tier_bundle =
            connector.def.tiers.get(tier_name).ok_or_else(|| ProxyError::Internal {
                message: format!(
                    "connector '{}' does not declare tier '{tier_name}'",
                    connection.connector_id
                ),
            })?;

        // Tier gate: required short name must be in the tier bundle.
        if !tier_bundle.scopes().iter().any(|s| s == required_scope) {
            return Err(ProxyError::TierDenied {
                connection: connection.id.to_string(),
                tier: tier_name.to_owned(),
                required_scope: required_scope.to_owned(),
            });
        }

        // Granted gate: the short name's full URI must be in the
        // connection's granted_scopes. A short name absent from the
        // connector vocab is impossible for a validated def, but treat a
        // miss as not-granted (fail closed) rather than panicking.
        let required_uri = connector.def.scopes.get(required_scope).ok_or_else(|| {
            ProxyError::ScopeNotGranted {
                connection: connection.id.to_string(),
                required_scope: required_scope.to_owned(),
            }
        })?;
        if !connection.granted_scopes.iter().any(|g| g == required_uri) {
            return Err(ProxyError::ScopeNotGranted {
                connection: connection.id.to_string(),
                required_scope: required_scope.to_owned(),
            });
        }

        // The optional per-binding `policy` is enforced UPSTREAM, not here:
        // `AuthService` resolves the same binding (via `crate::binding_resolve`)
        // and stamps `binding.policy` into `AgentPolicyBinding`, so
        // `PolicyLayer` + the approval engine — which run before this
        // service and hold the `PolicySet` — evaluate it (incl.
        // `Decision::Prompt` → approval). This resolver owns the
        // `tier ∩ granted_scopes` gate + the authoritative `binding.not_found`
        // deny; the two layers compose (either may deny independently).
        let _ = &binding;

        Ok((connection.id, Some(connection.connector_id)))
    }

    /// Resolve a request's bare service name (`gmail`/`calendar`/`drive`)
    /// to the connector's upstream `base_url` + `allowed_hosts`.
    ///
    /// Bridges the legacy bare-name vocabulary to the registry's
    /// canonical ids via [`crate::transport::mcp::selector_to_connector_id`]
    /// (Story 11.7 retires the bare names). Returns a typed `Internal`
    /// error for an unknown service rather than panicking.
    /// `resolved_connector_id` is `Some` when binding resolution
    /// (Story 11.10) already mapped the request to a connection's connector
    /// — the selector is then a per-account alias (e.g. `acct-a`), NOT a
    /// connector id, so we MUST use the resolved connector id. When `None`
    /// (legacy/no-binding-stores path), the selector is mapped to a
    /// connector id via `selector_to_connector_id`.
    fn resolve_upstream(
        &self,
        service: &str,
        resolved_connector_id: Option<&str>,
    ) -> Result<(url::Url, Vec<String>, permitlayer_connectors::TrustTier), ProxyError> {
        let conn = match resolved_connector_id {
            Some(cid) => self.connectors.get(cid).ok_or_else(|| ProxyError::Internal {
                message: format!("connector '{cid}' not registered"),
            })?,
            None => {
                let id =
                    crate::transport::mcp::selector_to_connector_id(service).ok_or_else(|| {
                        ProxyError::Internal {
                            message: format!("unknown connector for service '{service}'"),
                        }
                    })?;
                self.connectors.get(id).ok_or_else(|| ProxyError::Internal {
                    message: format!("connector '{id}' not registered"),
                })?
            }
        };
        Ok((
            conn.def.upstream.base_url.clone(),
            conn.def.upstream.allowed_hosts.clone(),
            conn.def.connector.trust_tier,
        ))
    }

    /// The directory where attachment bytes are materialized for the agent.
    #[must_use]
    pub fn media_dir(&self) -> &std::path::Path {
        &self.media_dir
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
        connectors: Arc<permitlayer_connectors::ConnectorRegistry>,
        audit_store: Arc<dyn AuditStore>,
        scrub_engine: Arc<ScrubEngine>,
        vault_dir: PathBuf,
        media_dir: PathBuf,
        oauth_client_overrides: HashMap<String, Arc<OAuthClient>>,
    ) -> Self {
        Self {
            credential_store,
            vault,
            token_issuer,
            upstream_client,
            connectors,
            allow_private_upstream: false,
            audit_store,
            scrub_engine,
            vault_dir,
            media_dir,
            oauth_client_overrides: Some(oauth_client_overrides),
            binding_store: None,
            connection_store: None,
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

    /// Reconstruct the correct `OAuthClient` for a connection by
    /// unsealing its `Client` slot.
    ///
    /// **Story 11.16:** the pre-Epic-11 path read a `{service}-meta.json`
    /// provenance file to dispatch on `client_type`. Epic 11 deleted that
    /// file (Story 11.12 — the `ConnectionRecord` is the provenance now)
    /// and every v2 connection is a sealed BYO client by construction
    /// (`connection add` always seals the `Client` slot). So the meta read
    /// is gone: this resolves the client straight from the connection's
    /// `(connection_id, Slot::Client)` envelope. A missing/corrupt Client
    /// slot is a clean error directing the operator to re-add the
    /// connection.
    ///
    /// Called once per refresh attempt. Returns an `Arc<OAuthClient>` so
    /// the test override path (`oauth_client_overrides`) can hand out cheap
    /// `Arc::clone`s and the production path is a single `Arc::new`.
    fn build_oauth_client_for_service(
        &self,
        service: &str,
        connection: permitlayer_credential::ConnectionId,
    ) -> Result<Arc<OAuthClient>, ProxyError> {
        // Test-only fast path: if the integration test harness injected an
        // override client for this service via `with_oauth_client_override`,
        // clone the stored `Arc`. `oauth_client_overrides` is always `None`
        // in production.
        if let Some(ref overrides) = self.oauth_client_overrides
            && let Some(client) = overrides.get(service)
        {
            return Ok(Arc::clone(client));
        }

        // Story 11.16: no `-meta.json` dispatch — the v2 connection's BYO
        // client config is sealed under `(connection_id, Slot::Client)`.
        let config = self.unseal_byo_client_config(service, connection)?;

        OAuthClient::new(config.client_id().to_owned(), config.client_secret().map(str::to_owned))
            .map(Arc::new)
            .map_err(|e| ProxyError::Internal {
                message: format!("could not construct OAuth client for service '{service}': {e}"),
            })
    }

    /// Story 7.35: recover the BYO OAuth client config by unsealing the
    /// `{service}-client` vault envelope — never reading a plaintext
    /// path. Mirrors this fn's existing sync `std::fs` discipline (the
    /// `{service}-client.sealed` file is decoded with the same public
    /// `decode_envelope` the credential store uses, then `vault.unseal`).
    fn unseal_byo_client_config(
        &self,
        service: &str,
        connection: permitlayer_credential::ConnectionId,
    ) -> Result<GoogleOAuthConfig, ProxyError> {
        // Story 11.16: the on-disk credential file is named
        // `<connection_id>-<slot>.sealed` (Story 11.9 store re-key), NOT the
        // legacy `{service}-client.sealed`. The Client slot holds the sealed
        // BYO client bundle for this connection.
        let sealed_path =
            self.vault_dir.join(format!("{connection}-{}.sealed", Slot::Client.label()));
        let bytes = std::fs::read(&sealed_path).map_err(|e| ProxyError::Internal {
            message: format!(
                "could not read sealed OAuth client bundle for service '{service}' at {} \
                 (re-add the connection: agentsso connection add): {e}",
                sealed_path.display()
            ),
        })?;
        let sealed =
            permitlayer_core::store::fs::credential_fs::decode_envelope(&bytes).map_err(|e| {
                ProxyError::Internal {
                    message: format!(
                        "corrupt sealed OAuth client bundle for service '{service}': {e}"
                    ),
                }
            })?;
        // Story 11.10: the BYO client bundle is sealed under the resolved
        // connection + `Slot::Client` (the `{service}-client.sealed` filename
        // is just on-disk naming; the crypto keys on the id, Story 11.8).
        let token = self.vault.unseal(connection, Slot::Client, &sealed).map_err(|e| {
            ProxyError::Internal {
                message: format!(
                    "could not unseal OAuth client bundle for service '{service}': {e}"
                ),
            }
        })?;
        GoogleOAuthConfig::from_sealed_bundle_bytes(token.reveal()).map_err(|e| {
            ProxyError::Internal {
                message: format!(
                    "malformed sealed OAuth client bundle for service '{service}': {e}"
                ),
            }
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
    #[allow(clippy::too_many_arguments)] // refresh retry: full request context + resolved connector.
    async fn try_refresh_and_retry(
        &self,
        service: &str,
        connection: permitlayer_credential::ConnectionId,
        resolved_connector_id: Option<&str>,
        request_id: &str,
        agent_id: &str,
        scope: &str,
        resource: &str,
        replay: &ProxyRequestReplayParts,
        max_body: usize,
    ) -> Result<Option<crate::upstream::UpstreamResponse>, ProxyError> {
        use crate::refresh_flow::{RefreshFlowError, RefreshOutcome, refresh_service};

        // Build the OAuth client resolver closure. The proxy path
        // consults `self.oauth_client_overrides` via
        // `build_oauth_client_for_service`, which preserves the
        // integration-test seam. The CLI path (`refresh_credentials`)
        // builds a simpler production-only resolver in its own module.
        let resolver = |svc: &str| -> Result<Arc<OAuthClient>, RefreshFlowError> {
            self.build_oauth_client_for_service(svc, connection).map_err(|e| {
                RefreshFlowError::MetaInvalid {
                    service: svc.to_owned(),
                    detail: match e {
                        ProxyError::Internal { message } => message,
                        other => format!("{other}"),
                    },
                }
            })
        };

        // Call the shared core. This is the bulk of the refresh state
        // machine — see crate::refresh_flow for details.
        let flow_result =
            refresh_service(&self.vault, &self.credential_store, service, connection, &resolver)
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
            Ok(RefreshOutcome::Refreshed { rotated, new_access_bytes, new_expiry_at: _ }) => {
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
        let (base_url, allowed_hosts, trust_tier) =
            self.resolve_upstream(service, resolved_connector_id)?;
        let guard = crate::upstream::ssrf_guard::UpstreamGuard {
            allowed_hosts: &allowed_hosts,
            trust_tier,
            allow_private_upstream: self.allow_private_upstream,
        };
        let retry_dispatch = self
            .upstream_client
            .dispatch(
                service,
                &base_url,
                &guard,
                &replay.path,
                replay.method.clone(),
                replay.headers.clone(),
                replay.body.clone(),
                access_token_str,
                max_body,
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
        self.handle_inner(req, true).await
    }

    /// Like [`Self::handle`] but returns the upstream body **un-scrubbed**.
    ///
    /// For binary upstream payloads where running the text scrub engine
    /// over the bytes would be both wrong (it corrupts non-text data —
    /// e.g. a base64 attachment blob whose characters incidentally match
    /// a scrub rule) and pointless (binary carries no scrub-targeted
    /// secrets). Still performs credential unseal, scoped-token issue,
    /// the 401 refresh-retry, and audit logging — only the scrub step is
    /// skipped. Used by the Gmail attachment-fetch path (`attachments.get`),
    /// which decodes the returned base64 itself.
    pub async fn fetch_raw(&self, req: ProxyRequest) -> Result<ProxyResponse, ProxyError> {
        self.handle_inner(req, false).await
    }

    /// Shared request pipeline for [`Self::handle`] (scrubbed) and
    /// [`Self::fetch_raw`] (un-scrubbed). `scrub_response` gates ONLY the
    /// response-body scrub step; credential/token/refresh/audit are
    /// identical on both paths.
    async fn handle_inner(
        &self,
        req: ProxyRequest,
        scrub_response: bool,
    ) -> Result<ProxyResponse, ProxyError> {
        // 0. Resolve the connection id from the agent's binding and run the
        // Story 11.10 default-deny authz gate (tier ∩ granted_scopes). In
        // production both binding stores are wired; legacy unit tests fall
        // back to the service-string derivation with no gate. A binding /
        // tier / scope denial is audited like credential-missing and
        // returned as a 403-class error.
        let (connection, resolved_connector_id) =
            match self.resolve_connection(&req.agent_id, &req.service, &req.scope).await {
                Ok(pair) => pair,
                Err(e) => {
                    let event_type = match &e {
                        ProxyError::BindingNotFound { .. } => "binding-not-found",
                        ProxyError::TierDenied { .. } => "tier-denied",
                        ProxyError::ScopeNotGranted { .. } => "scope-not-granted",
                        _ => "binding-resolution-failed",
                    };
                    self.write_audit(
                        &req.request_id,
                        &req.agent_id,
                        &req.service,
                        &req.scope,
                        &req.resource,
                        "error",
                        event_type,
                        None,
                    )
                    .await;
                    return Err(e);
                }
            };

        // 1. Fetch sealed credential. The store keys on `(ConnectionId, Slot)`
        // (Story 11.8); the access token lives under the connection + Slot::Access.
        let sealed = match self.credential_store.get(connection, Slot::Access).await {
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
        // Access token keys on the connection + Slot::Access (Story 11.8).
        let vault = Arc::clone(&self.vault);
        let unseal_result =
            tokio::task::spawn_blocking(move || vault.unseal(connection, Slot::Access, &sealed))
                .await;

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

        // 4. Dispatch upstream. The attachment-fetch path (`!scrub_response`)
        // uses a larger body cap since a single attachment's base64 can
        // exceed the 10 MiB JSON ceiling.
        let max_body = if scrub_response {
            crate::upstream::MAX_RESPONSE_BODY
        } else {
            crate::upstream::MAX_ATTACHMENT_BODY
        };
        let (base_url, allowed_hosts, trust_tier) =
            self.resolve_upstream(&req.service, resolved_connector_id.as_deref())?;
        let guard = crate::upstream::ssrf_guard::UpstreamGuard {
            allowed_hosts: &allowed_hosts,
            trust_tier,
            allow_private_upstream: self.allow_private_upstream,
        };
        let upstream_result = self
            .upstream_client
            .dispatch(
                &req.service,
                &base_url,
                &guard,
                &req.path,
                req.method,
                req.headers,
                req.body,
                access_token_str,
                max_body,
            )
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
                    connection,
                    resolved_connector_id.as_deref(),
                    &req.request_id,
                    &req.agent_id,
                    &req.scope,
                    &req.resource,
                    &replay_parts,
                    max_body,
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

        let (scrubbed_body, scrub_summary, scrub_samples, was_scrubbed) = if !scrub_response {
            // fetch_raw path: never scrub. The caller (attachment fetch)
            // owns binary bytes that must travel verbatim — scrubbing the
            // base64 would corrupt the decoded file.
            (upstream_resp.body.clone(), Default::default(), Vec::new(), false)
        } else {
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

    let request_id =
        request.extensions().get::<RequestId>().map(|r| r.0.clone()).unwrap_or_default();

    // AuthLayer is wired and runs before this handler for all
    // /v1/tools/* routes. Missing AgentId here means the request
    // bypassed auth (operational allowlist misconfigured) — refuse
    // rather than fall back to the "unknown" default that masquerades
    // as a real agent. Returns 401 with `auth.missing_agent_id`.
    let agent_id = match request.extensions().get::<AgentId>() {
        Some(a) => a.0.clone(),
        None => {
            warn!(request_id = %request_id, "AgentId extension missing on /v1/tools/* request — refusing");
            return ProxyError::AuthMissingAgentId.into_response_with_request_id(Some(request_id));
        }
    };

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
    use permitlayer_credential::{ConnectionId, OAuthToken, SealedCredential};
    use tempfile::TempDir;
    use url::Url;
    use zeroize::Zeroizing;

    // --- Mock CredentialStore ---
    //
    // SealedCredential is not Clone, so we store the raw bytes needed
    // to reconstruct it and seal a fresh copy on each `get()` call.

    struct MockCredentialStore {
        /// Maps `(ConnectionId bytes, Slot byte)` → token_bytes so we can
        /// seal fresh on each get() call. Story 11.9 re-keyed the store on
        /// `(ConnectionId, Slot)`; `add_service` seeds under the shim id +
        /// `Slot::Access` so the proxy request path reads it back.
        services: HashMap<([u8; 16], u8), Vec<u8>>,
        master_key: [u8; 32],
    }

    impl MockCredentialStore {
        fn new(master_key: [u8; 32]) -> Self {
            Self { services: HashMap::new(), master_key }
        }

        fn add_service(&mut self, service: &str, token_bytes: &[u8]) {
            // These unit tests construct `ProxyService` without binding
            // stores, so `handle_inner` resolves the connection id via
            // `ProxyService::legacy_connection_id_for_service`. Seed under
            // the same derivation + `Slot::Access` so the request path reads
            // it back.
            let connection = ProxyService::legacy_connection_id_for_service(service);
            self.services
                .insert((*connection.as_bytes(), Slot::Access.slot_byte()), token_bytes.to_vec());
        }
    }

    #[async_trait::async_trait]
    impl CredentialStore for MockCredentialStore {
        async fn put(
            &self,
            _id: ConnectionId,
            _slot: Slot,
            _sealed: SealedCredential,
        ) -> Result<(), StoreError> {
            Ok(())
        }
        async fn get(
            &self,
            id: ConnectionId,
            slot: Slot,
        ) -> Result<Option<SealedCredential>, StoreError> {
            match self.services.get(&(*id.as_bytes(), slot.slot_byte())) {
                Some(token_bytes) => {
                    let vault = Vault::new(Zeroizing::new(self.master_key), 0);
                    let token = OAuthToken::from_trusted_bytes(token_bytes.clone());
                    match vault.seal(id, slot, &token) {
                        Ok(sealed) => Ok(Some(sealed)),
                        Err(_) => panic!("mock seal failed for {id:?}/{slot:?}"),
                    }
                }
                None => Ok(None),
            }
        }
        async fn list_connections(&self) -> Result<Vec<ConnectionId>, StoreError> {
            Ok(self
                .services
                .keys()
                .map(|(id_bytes, _slot)| ConnectionId::from_bytes(*id_bytes))
                .collect())
        }
        async fn remove(&self, _id: ConnectionId, _slot: Slot) -> Result<bool, StoreError> {
            Ok(false)
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
        Vault::new(Zeroizing::new(TEST_MASTER_KEY), 0)
    }

    fn test_token_issuer() -> ScopedTokenIssuer {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        ScopedTokenIssuer::new(Zeroizing::new(key))
    }

    fn test_scrub_engine() -> Arc<ScrubEngine> {
        Arc::new(ScrubEngine::new(builtin_rules().to_vec()).unwrap())
    }

    /// A connector registry over the embedded built-in defs (real Google
    /// upstreams). For tests that construct a `ProxyService` but never
    /// dispatch upstream.
    fn test_connector_registry() -> Arc<permitlayer_connectors::ConnectorRegistry> {
        Arc::new(permitlayer_connectors::ConnectorRegistry::load(None).unwrap())
    }

    /// A connector registry whose named built-in service's `base_url`
    /// (and `allowed_hosts`) point at `url` — the 1:1 replacement for the
    /// old `base_urls` map. `svc` is the bare name (`gmail`/`calendar`/
    /// `drive`).
    fn test_connector_registry_with(
        svc: &str,
        url: &str,
    ) -> Arc<permitlayer_connectors::ConnectorRegistry> {
        let id = match svc {
            "gmail" => "google-gmail",
            "calendar" => "google-calendar",
            "drive" => "google-drive",
            other => other,
        };
        let parsed = Url::parse(url).expect("override base_url parses");
        let defs: Vec<permitlayer_connectors::ConnectorDef> =
            permitlayer_connectors::builtin_connector_defs()
                .expect("built-in defs")
                .into_iter()
                .map(|mut def| {
                    if def.connector.id == id {
                        if let Some(host) = parsed.host_str() {
                            def.upstream.allowed_hosts = vec![host.to_owned()];
                        }
                        def.upstream.base_url = parsed.clone();
                    }
                    def
                })
                .collect();
        Arc::new(permitlayer_connectors::ConnectorRegistry::from_defs(defs))
    }

    async fn build_service_with_mock_upstream(
        server_url: &str,
    ) -> (Arc<ProxyService>, Arc<MockAuditStore>, TempDir) {
        let mut cred_store = MockCredentialStore::new(TEST_MASTER_KEY);
        cred_store.add_service("gmail", b"fake-access-token");

        let credential_store: Arc<dyn CredentialStore> = Arc::new(cred_store);
        let vault = Arc::new(test_vault());
        let token_issuer = Arc::new(test_token_issuer());

        let upstream_client = Arc::new(UpstreamClient::new().unwrap());
        let connectors = test_connector_registry_with("gmail", server_url);

        let audit_store = Arc::new(MockAuditStore::new());

        // Hermetic per-test vault dir. The caller must keep the
        // returned `TempDir` alive for the test duration.
        let tempdir = TempDir::new().unwrap();

        let service = Arc::new(ProxyService::new(
            credential_store,
            vault,
            token_issuer,
            upstream_client,
            connectors,
            Arc::clone(&audit_store) as Arc<dyn AuditStore>,
            test_scrub_engine(),
            tempdir.path().to_path_buf(),
            tempdir.path().join("media"),
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
            test_connector_registry(),
            audit_store,
            test_scrub_engine(),
            _tempdir.path().to_path_buf(),
            _tempdir.path().join("media"),
        );

        let req = test_request("gmail", "users/me/messages");
        let err = service.handle(req).await.unwrap_err();

        assert!(matches!(err, ProxyError::Internal { .. }));
        assert!(err.to_string().contains("no credentials"));
    }

    // ── Story 7.35: BYO client bundle is unsealed from the vault,
    //    never re-read from a plaintext path (review M1) ─────────────

    /// Build a minimal `ProxyService` whose `vault_dir` is `dir`, using
    /// `TEST_MASTER_KEY` (so `test_vault()` can unseal what we seal
    /// here). No upstream/credential wiring — these tests only drive
    /// `build_oauth_client_for_service`.
    fn service_with_vault_dir(dir: &std::path::Path) -> ProxyService {
        ProxyService::new(
            Arc::new(MockCredentialStore::new(TEST_MASTER_KEY)) as Arc<dyn CredentialStore>,
            Arc::new(test_vault()),
            Arc::new(test_token_issuer()),
            Arc::new(UpstreamClient::new().unwrap()),
            test_connector_registry(),
            Arc::new(MockAuditStore::new()) as Arc<dyn AuditStore>,
            test_scrub_engine(),
            dir.to_path_buf(),
            dir.join("media"),
        )
    }

    /// Seal a BYO client bundle into `<connection>-client.sealed` exactly
    /// as the daemon's seal handler does: `OAuthToken::from_trusted_bytes`
    /// over the canonical bundle JSON → `vault.seal(connection, Slot::Client)`
    /// → `encode_envelope` to disk under the v2 `<ulid>-client.sealed` name.
    fn seal_client_bundle(
        vault_dir: &std::path::Path,
        service: &str,
        client_id: &str,
        client_secret: &str,
    ) {
        let bundle = serde_json::json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "project_id": "p",
            "v": 1,
        })
        .to_string();
        let token = permitlayer_credential::OAuthToken::from_trusted_bytes(bundle.into_bytes());
        // No binding stores wired in these unit tests → `handle_inner`
        // resolves the connection id via
        // `ProxyService::legacy_connection_id_for_service`, and the BYO
        // client bundle keys on that id + `Slot::Client`. Story 11.16: the
        // on-disk file is `<connection_id>-client.sealed` (the v2 store
        // naming), NOT the legacy `{service}-client.sealed`.
        let connection = ProxyService::legacy_connection_id_for_service(service);
        let sealed = test_vault().seal(connection, Slot::Client, &token).unwrap();
        let bytes = permitlayer_core::store::fs::credential_fs::encode_envelope(&sealed);
        std::fs::write(
            vault_dir.join(format!("{connection}-{}.sealed", Slot::Client.label())),
            bytes,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn byo_client_is_reconstructed_from_sealed_bundle_not_a_file() {
        let dir = TempDir::new().unwrap();
        // Story 11.16: no `-meta.json` is written; the refresh path
        // reconstructs the client straight from the sealed `Client` slot.
        seal_client_bundle(
            dir.path(),
            "gmail",
            "123.apps.googleusercontent.com",
            "GOCSPX-sealed-secret",
        );
        // Deliberately DO NOT create any client_secret.json — if the
        // code falls back to a path read this must fail, not succeed.

        let service = service_with_vault_dir(dir.path());
        // Success here proves the BYO client was reconstructed by
        // unsealing the `Client` slot — there is no client JSON on disk
        // and no meta file, so any fallback would error instead.
        let gmail_conn = ProxyService::legacy_connection_id_for_service("gmail");
        let _client = service
            .build_oauth_client_for_service("gmail", gmail_conn)
            .expect("sealed byo client must reconstruct from the vault with no file read");

        // And the underlying unseal yields exactly the sealed bundle.
        let cfg = service.unseal_byo_client_config("gmail", gmail_conn).unwrap();
        assert_eq!(cfg.client_id(), "123.apps.googleusercontent.com");
        assert_eq!(cfg.client_secret(), Some("GOCSPX-sealed-secret"));
    }

    #[tokio::test]
    async fn missing_client_slot_fails_with_actionable_error_no_path_fallback() {
        // Story 11.16: with the `-meta.json` provenance scheme gone, a
        // connection whose `Client` slot is absent (e.g. a partial cleanup,
        // or an access-only seed) must fail with a clean re-add hint — never
        // a plaintext-path fallback.
        let dir = TempDir::new().unwrap();
        // A real client_secret.json sitting right there must NOT be
        // silently re-read.
        std::fs::write(
            dir.path().join("legacy_client_secret.json"),
            r#"{"installed":{"client_id":"x","client_secret":"y"}}"#,
        )
        .unwrap();

        let service = service_with_vault_dir(dir.path());
        // `OAuthClient` isn't `Debug`, so `expect_err` won't compile —
        // match the error out explicitly.
        let gmail_conn = ProxyService::legacy_connection_id_for_service("gmail");
        let err = match service.build_oauth_client_for_service("gmail", gmail_conn) {
            Ok(_) => panic!("a connection with no sealed Client slot must be rejected"),
            Err(e) => e,
        };

        let msg = err.to_string();
        assert!(
            msg.contains("could not read sealed OAuth client bundle"),
            "error must name the missing sealed client bundle; got: {msg}"
        );
        assert!(
            msg.contains("connection add"),
            "error must name the actionable fix (re-add the connection); got: {msg}"
        );
    }

    #[tokio::test]
    async fn vault_unseal_error_returns_internal() {
        // Seal with one master key, unseal with a different one.
        let mut cred_store = MockCredentialStore::new([0x42; 32]);
        cred_store.add_service("gmail", b"fake-token");

        let unseal_vault = Arc::new(Vault::new(Zeroizing::new([0x99; 32]), 0));

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
            test_connector_registry(),
            audit_store,
            test_scrub_engine(),
            _tempdir.path().to_path_buf(),
            _tempdir.path().join("media"),
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

        let upstream_client = Arc::new(UpstreamClient::new().unwrap());
        let connectors = test_connector_registry_with("gmail", "http://127.0.0.1:1/");
        let audit_store = Arc::new(MockAuditStore::new());
        let _tempdir = TempDir::new().unwrap();

        let service = ProxyService::new(
            credential_store,
            vault,
            token_issuer,
            upstream_client,
            connectors,
            Arc::clone(&audit_store) as Arc<dyn AuditStore>,
            test_scrub_engine(),
            _tempdir.path().to_path_buf(),
            _tempdir.path().join("media"),
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
            test_connector_registry(),
            audit_store,
            test_scrub_engine(),
            _tempdir.path().to_path_buf(),
            _tempdir.path().join("media"),
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
            test_connector_registry(),
            audit_store,
            test_scrub_engine(),
            tempdir.path().to_path_buf(),
            tempdir.path().join("media"),
            overrides,
        );

        // Override is present for gmail. The override map is keyed by
        // service name, so the connection arg is irrelevant on this path;
        // pass the legacy derivation for consistency.
        assert!(service.oauth_client_overrides.is_some());
        let got = service
            .build_oauth_client_for_service(
                "gmail",
                ProxyService::legacy_connection_id_for_service("gmail"),
            )
            .expect("override lookup should succeed");
        // Both Arcs point at the same underlying OAuthClient.
        assert!(Arc::ptr_eq(&got, &mock_client));

        // Override is NOT present for calendar — falls through to
        // metadata read, which must fail because the hermetic tempdir
        // contains no `calendar-meta.json`. This asserts the
        // fallthrough behavior: services absent from the override map
        // go through the production path.
        let fall_through = service.build_oauth_client_for_service(
            "calendar",
            ProxyService::legacy_connection_id_for_service("calendar"),
        );
        assert!(
            fall_through.is_err(),
            "services absent from override map should fall through to metadata read (and fail, in this test)"
        );
    }
}
