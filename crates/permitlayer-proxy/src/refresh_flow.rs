//! Shared OAuth refresh core used by both `ProxyService::try_refresh_and_retry`
//! (reactive refresh on upstream 401) and the CLI's `agentsso credentials
//! refresh <service>` subcommand (operator escape hatch).
//!
//! Extracted from `ProxyService::try_refresh_and_retry` in Story 1.14b
//! Task 1. The split rationale:
//!
//! - Both callers need the same "unseal refresh token → call OAuthClient
//!   → persist new tokens → update meta file" logic.
//! - The proxy-specific concerns — request-replay retry dispatch, the
//!   `retry_dispatch_failed` outcome, and audit-event emission — stay in
//!   `ProxyService::try_refresh_and_retry` because they depend on the
//!   proxy's request context (`request_id`, `agent_id`, `scope`,
//!   `resource`, `ProxyRequestReplayParts`) which the CLI has no
//!   meaningful equivalent for.
//! - Per Story 1.14b AC 5's ownership split, this module does NOT emit
//!   audit events. Each caller (proxy + CLI) owns its own audit
//!   emission, pattern-matching on the `Result<RefreshOutcome,
//!   RefreshFlowError>` return type to select the outcome string.
//!
//! ## Audit outcome enumeration (load-bearing)
//!
//! Every possible audit outcome the refresh flow can produce is
//! structurally represented in the `Result<RefreshOutcome,
//! RefreshFlowError>` return type. Callers MUST handle every variant
//! — a new variant added here without updating the two call sites is
//! a compile error.
//!
//! **The shared core produces 10 of the 11 total `token-refresh`
//! outcomes.** The 11th — `retry_dispatch_failed` — is proxy-only and
//! fires AFTER `refresh_service` returns `Ok(Refreshed)` (see
//! `ProxyService::try_refresh_and_retry`'s post-core retry dispatch).
//!
//! Shared-core outcomes (10):
//!
//! | Outcome (audit)            | Variant                             |
//! |----------------------------|-------------------------------------|
//! | `success`                  | `Ok(Refreshed { .. })`              |
//! | `skipped_no_refresh_token` | `Ok(Skipped)`                       |
//! | `invalid_grant`            | `Err(CredentialRevoked)`            |
//! | `exhausted`                | `Err(Exhausted)`                    |
//! | `persistence_failed`       | `Err(PersistenceFailed { stage })`  |
//! | `malformed_token`          | `Err(MalformedToken)`               |
//! | `store_read_failed`        | `Err(StoreReadFailed)`              |
//! | `vault_unseal_failed`      | `Err(VaultUnsealFailed)`            |
//! | `meta_invalid`             | `Err(MetaInvalid)`                  |
//! | `unknown_oauth_error`      | `Err(UnknownOauthError)`            |
//!
//! Proxy-only outcome (the +1 = 11 total):
//!
//! | Outcome (audit)            | Where it lives                      |
//! |----------------------------|-------------------------------------|
//! | `retry_dispatch_failed`    | `ProxyService::try_refresh_and_retry` (post-core retry path) |

use std::path::{Path, PathBuf};
use std::sync::Arc;

use permitlayer_core::store::{CredentialStore, StoreError};
use permitlayer_oauth::{OAuthClient, OAuthError};
use permitlayer_vault::Vault;
use tracing::warn;
use zeroize::Zeroizing;

use crate::error::ProxyError;

/// Which persistence stage failed, for the `persistence_failed` audit
/// outcome's `extra.stage` field. Preserves the m6 contract from the
/// Story 1.14a code review: operators reading post-incident audit logs
/// need to see WHICH persist step broke, not just that "persistence
/// failed".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistStage {
    /// Sealing the new refresh token via `vault.seal_refresh`.
    RefreshTokenSeal,
    /// Storing the newly-sealed refresh token via `credential_store.put`.
    RefreshTokenStore,
    /// Sealing the new access token via `vault.seal`.
    AccessTokenSeal,
    /// Storing the newly-sealed access token via `credential_store.put`.
    AccessTokenStore,
}

impl PersistStage {
    /// String label for audit `extra.stage` serialization.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PersistStage::RefreshTokenSeal => "refresh_token_seal",
            PersistStage::RefreshTokenStore => "refresh_token_store",
            PersistStage::AccessTokenSeal => "access_token_seal",
            PersistStage::AccessTokenStore => "access_token_store",
        }
    }
}

/// Story 1.14b code-review m7 fix: previously `RefreshFlowError::PersistenceFailed`'s
/// `#[error]` attribute used `{stage:?}` (Debug formatting) which produced
/// `RefreshTokenSeal` while the audit log shows `refresh_token_seal`. Now
/// the error message uses `{stage}` (Display) which delegates here, so
/// the human-readable error and the audit `extra.stage` field always
/// match.
impl std::fmt::Display for PersistStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Successful refresh outcome returned by [`refresh_service`].
///
/// Callers pattern-match on this to emit the correct audit event
/// (proxy: with the proxy request's `request_id` / `agent_id`; CLI:
/// with a fresh ULID and `agent_id="cli"`).
#[derive(Debug)]
pub enum RefreshOutcome {
    /// The refresh completed successfully and the new tokens are
    /// durably persisted in the vault and credential store.
    Refreshed {
        /// Whether the provider rotated the refresh token (for the
        /// `extra.refresh_token_rotated` audit field).
        rotated: bool,
        /// New access token bytes, wrapped in `Zeroizing` so the
        /// buffer is zeroed on drop. The proxy retry path uses this
        /// for the retry dispatch; the CLI path drops it immediately
        /// (the bytes are already sealed into the vault at this
        /// point). Non-optional because the refresh always produces a
        /// new access token on success.
        new_access_bytes: Zeroizing<Vec<u8>>,
        /// Computed expiry timestamp for the new access token, if the
        /// provider returned an `expires_in` field. Used by the
        /// CLI's success output and by Task 4's meta-file update.
        new_expiry_at: Option<chrono::DateTime<chrono::Utc>>,
        /// The exact timestamp persisted to `meta.last_refreshed_at`
        /// during this refresh, OR `None` if the meta-file write
        /// failed. Story 1.14b code-review m1 fix: returning the
        /// persisted value (rather than letting the CLI compute its
        /// own `Utc::now()` later) means `agentsso credentials
        /// status` and the CLI's success output show the same
        /// "last refresh" timestamp the meta file was actually
        /// written with. `None` means the meta write failed and the
        /// CLI should not display a "last refresh" line because the
        /// status command will show the OLD persisted value.
        last_refreshed_at: Option<chrono::DateTime<chrono::Utc>>,
    },
    /// No refresh was attempted because the `{service}-refresh` vault
    /// entry is missing (graceful-degradation case for older installs
    /// predating Story 1.6, architecture invariant #7). Proxy returns
    /// the original 401 unchanged; CLI tells the user to re-run
    /// `agentsso setup <service>`.
    Skipped,
}

impl RefreshOutcome {
    /// The `token-refresh` audit-event `outcome` string for this
    /// variant. Single source of truth so callers never have to
    /// hand-map variants to strings.
    ///
    /// Story 1.14b code-review m6 fix: prior to this helper, both
    /// the proxy and the CLI hand-typed `"skipped_no_refresh_token"`
    /// at independent call sites, and a future rename would silently
    /// drift between the two. The compiler now enforces consistency.
    #[must_use]
    pub fn audit_outcome(&self) -> &'static str {
        match self {
            RefreshOutcome::Refreshed { .. } => "success",
            RefreshOutcome::Skipped => "skipped_no_refresh_token",
        }
    }
}

/// Errors returned by [`refresh_service`].
///
/// Each variant maps to exactly one audit `outcome` string that both
/// callers emit consistently. See the crate-level doc comment for the
/// full outcome enumeration.
#[derive(Debug, thiserror::Error)]
pub enum RefreshFlowError {
    /// The refresh token was revoked server-side (`invalid_grant`).
    /// Audit outcome: `invalid_grant`. Proxy returns
    /// `ProxyError::CredentialRevoked`; CLI prints a remediation
    /// message pointing at `agentsso setup <service>`.
    #[error("refresh token for service '{service}' was revoked server-side")]
    CredentialRevoked { service: String },

    /// All three retry attempts against the OAuth token endpoint
    /// failed with transport errors. Audit outcome: `exhausted`.
    /// Proxy returns `ProxyError::UpstreamUnreachable` with
    /// `service={service}-oauth`; CLI prints a transient-failure
    /// message with a suggestion to retry.
    #[error("OAuth token endpoint unreachable after 3 attempts for service '{service}'")]
    Exhausted { service: String },

    /// A vault seal or credential store put failed after the refresh
    /// itself succeeded. Audit outcome: `persistence_failed`; the
    /// `stage` field identifies which specific persist step broke.
    #[error(
        "refresh succeeded but could not persist new token for '{service}' at stage {stage}: {detail}"
    )]
    PersistenceFailed { service: String, stage: PersistStage, detail: String },

    /// The new access token bytes were not valid UTF-8. Rejected BEFORE
    /// any persistence to prevent the infinite audit-spam loop that
    /// a persist-then-validate ordering would create (Story 1.14a M3).
    /// Audit outcome: `malformed_token`.
    #[error("refresh: new access token for '{service}' is not valid UTF-8: {detail}")]
    MalformedToken { service: String, detail: String },

    /// The credential store returned an error on the initial read of
    /// `{service}-refresh`. Audit outcome: `store_read_failed`.
    #[error("refresh: credential store read failed for '{service}-refresh': {source}")]
    StoreReadFailed { service: String, source: StoreError },

    /// The vault unseal of the refresh token failed — a corruption /
    /// tamper signal. Audit outcome: `vault_unseal_failed`.
    #[error("refresh: vault unseal failed for '{service}-refresh': {detail}")]
    VaultUnsealFailed { service: String, detail: String },

    /// The OAuth client could not be reconstructed from
    /// `{service}-meta.json` (missing meta, malformed JSON, unknown
    /// `client_type`). Audit outcome: `meta_invalid`.
    #[error("refresh: OAuth client build failed for service '{service}': {detail}")]
    MetaInvalid { service: String, detail: String },

    /// A future `OAuthError` variant beyond `InvalidGrant` and
    /// `RefreshExhausted` slipped through. Classified honestly rather
    /// than silently conflated with `Exhausted` (Story 1.14a m7).
    /// Audit outcome: `unknown_oauth_error`.
    #[error("refresh: unexpected OAuthError variant for service '{service}': {detail}")]
    UnknownOauthError { service: String, detail: String },
}

impl RefreshFlowError {
    /// The `token-refresh` audit-event `outcome` string for this
    /// variant. Single source of truth so callers never have to
    /// hand-map variants to strings.
    ///
    /// Note: `PersistenceFailed` returns `"persistence_failed"`, but
    /// that audit event additionally carries `extra.stage` — callers
    /// that pattern-match on `PersistenceFailed` specifically must
    /// also read `stage` and emit the stage-aware audit variant (see
    /// `ProxyService::emit_persistence_failed_audit`).
    #[must_use]
    pub fn audit_outcome(&self) -> &'static str {
        match self {
            RefreshFlowError::CredentialRevoked { .. } => "invalid_grant",
            RefreshFlowError::Exhausted { .. } => "exhausted",
            RefreshFlowError::PersistenceFailed { .. } => "persistence_failed",
            RefreshFlowError::MalformedToken { .. } => "malformed_token",
            RefreshFlowError::StoreReadFailed { .. } => "store_read_failed",
            RefreshFlowError::VaultUnsealFailed { .. } => "vault_unseal_failed",
            RefreshFlowError::MetaInvalid { .. } => "meta_invalid",
            RefreshFlowError::UnknownOauthError { .. } => "unknown_oauth_error",
        }
    }
}

/// Convert a shared-core `RefreshFlowError` to the proxy's
/// `ProxyError`. Defines the canonical mapping used by
/// `ProxyService::try_refresh_and_retry` — centralized here so the
/// exhaustive-match pattern isn't duplicated at the call site.
///
/// Every `Internal` variant's message preserves the exact format
/// Story 1.14a's unit tests lock in — in particular the AC 6
/// recognizable substring `"refresh succeeded but could not persist
/// new token"`. Do NOT change these format strings without updating
/// the corresponding regression tests in
/// `crates/permitlayer-proxy/src/error.rs`.
impl From<RefreshFlowError> for ProxyError {
    fn from(err: RefreshFlowError) -> ProxyError {
        match err {
            RefreshFlowError::CredentialRevoked { service } => {
                ProxyError::CredentialRevoked { service }
            }
            RefreshFlowError::Exhausted { service } => ProxyError::UpstreamUnreachable {
                service: format!("{service}-oauth"),
                message: "OAuth token refresh exhausted after 3 attempts".to_owned(),
                retry_after_seconds: 30,
            },
            RefreshFlowError::PersistenceFailed { service, stage: _, detail } => {
                ProxyError::Internal {
                    message: format!(
                        "refresh succeeded but could not persist new token for '{service}': {detail}"
                    ),
                }
            }
            RefreshFlowError::MalformedToken { service, detail } => ProxyError::Internal {
                message: format!(
                    "refresh: new access token for '{service}' is not valid UTF-8: {detail}"
                ),
            },
            RefreshFlowError::StoreReadFailed { service, source } => ProxyError::Internal {
                message: format!(
                    "refresh: credential store read failed for '{service}-refresh': {source}"
                ),
            },
            RefreshFlowError::VaultUnsealFailed { service, detail } => ProxyError::Internal {
                message: format!("refresh: vault unseal failed for '{service}-refresh': {detail}"),
            },
            RefreshFlowError::MetaInvalid { service, detail } => ProxyError::Internal {
                message: format!(
                    "refresh: OAuth client build failed for service '{service}': {detail}"
                ),
            },
            RefreshFlowError::UnknownOauthError { service, detail } => ProxyError::Internal {
                message: format!(
                    "refresh: unexpected OAuthError variant for service '{service}': {detail}"
                ),
            },
        }
    }
}

/// Type alias for the OAuth client resolver closure passed into
/// [`refresh_service`]. The proxy constructs one that consults
/// `ProxyService::oauth_client_overrides` first (preserving the test
/// seam); the CLI constructs a simpler production-only version.
///
/// Returning `Result<Arc<OAuthClient>, RefreshFlowError>` means a
/// failed resolver is surfaced as `MetaInvalid` — consistent with the
/// Story 1.14a helper's error mapping.
pub type OAuthClientResolver<'a> =
    dyn Fn(&str) -> Result<Arc<OAuthClient>, RefreshFlowError> + Send + Sync + 'a;

/// The shared refresh core. Performs the full refresh state machine:
/// fetch sealed refresh token → unseal → resolve OAuth client →
/// `OAuthClient::refresh` → atomic rotation persistence → return.
///
/// This function does NOT:
/// - Emit audit events (per AC 5 ownership split — callers own this)
/// - Retry the original upstream request (proxy-specific, handled in
///   `ProxyService::try_refresh_and_retry` after this returns `Ok`)
///
/// This function DOES:
/// - Update `{vault_dir}/{service}-meta.json` with a fresh
///   `last_refreshed_at` timestamp AND a fresh `expires_in_secs`
///   on successful refresh (Story 1.14b Task 4 + code-review M1
///   fix, closing AC 2). The meta-file write is async — wrapped
///   in `tokio::task::spawn_blocking` (Story 1.14b code-review M2
///   fix) so the parent-directory fsync does not block the
///   executor. The read-merge-write sequence runs inside the same
///   blocking task to narrow the concurrent-writer window
///   (Story 1.14b code-review M4 fix). Best-effort: failures are
///   logged via `tracing::warn!` and do NOT fail the refresh —
///   the tokens are already durably persisted; only the display
///   timestamp and validity computation are affected.
///
/// Preserves all Story 1.14a review-fix contracts:
/// - **M3**: UTF-8 validation runs BEFORE any vault seal or store put
/// - **m6**: `PersistenceFailed.stage` identifies which of the four
///   persist steps broke
/// - **m7**: unknown `OAuthError` variants become `UnknownOauthError`,
///   never silently conflated with `Exhausted`
/// - **Architecture invariant #3**: if rotation happens, the new
///   refresh token is sealed and stored BEFORE the new access token
pub async fn refresh_service(
    vault: &Arc<Vault>,
    credential_store: &Arc<dyn CredentialStore>,
    vault_dir: &Path,
    service: &str,
    oauth_client_resolver: &OAuthClientResolver<'_>,
) -> Result<RefreshOutcome, RefreshFlowError> {
    let refresh_service_key = format!("{service}-refresh");

    // Step 1: Fetch the sealed refresh credential.
    let sealed_refresh = match credential_store.get(&refresh_service_key).await {
        Ok(Some(sealed)) => sealed,
        Ok(None) => {
            warn!(
                service = %service,
                "refresh token missing for service — cannot refresh, returning Skipped"
            );
            return Ok(RefreshOutcome::Skipped);
        }
        Err(e) => {
            return Err(RefreshFlowError::StoreReadFailed {
                service: service.to_owned(),
                source: e,
            });
        }
    };

    // Step 2: Unseal the refresh token. Synchronous crypto → spawn_blocking.
    let vault_for_unseal = Arc::clone(vault);
    let refresh_service_for_unseal = refresh_service_key.clone();
    let unseal_result = tokio::task::spawn_blocking(move || {
        vault_for_unseal.unseal_refresh(&refresh_service_for_unseal, &sealed_refresh)
    })
    .await;

    let refresh_token = match unseal_result {
        Ok(Ok(token)) => token,
        Ok(Err(e)) => {
            return Err(RefreshFlowError::VaultUnsealFailed {
                service: service.to_owned(),
                detail: format!("{e}"),
            });
        }
        Err(join_err) => {
            return Err(RefreshFlowError::VaultUnsealFailed {
                service: service.to_owned(),
                detail: format!("spawn_blocking join error: {join_err}"),
            });
        }
    };

    // Step 3: Resolve the OAuth client via the caller-supplied resolver.
    // Proxy → consults oauth_client_overrides first (test seam).
    // CLI → production metadata read only. The resolver already
    // returns a `RefreshFlowError` (typically `MetaInvalid`), so `?`
    // propagates it without any mapping.
    let oauth_client = oauth_client_resolver(service)?;

    // Step 4: Call OAuthClient::refresh.
    let refresh_outcome = oauth_client.refresh(&refresh_token).await;

    let refresh_result = match refresh_outcome {
        Ok(result) => result,
        Err(OAuthError::InvalidGrant { .. }) => {
            return Err(RefreshFlowError::CredentialRevoked { service: service.to_owned() });
        }
        Err(OAuthError::RefreshExhausted { .. }) => {
            return Err(RefreshFlowError::Exhausted { service: service.to_owned() });
        }
        Err(e) => {
            return Err(RefreshFlowError::UnknownOauthError {
                service: service.to_owned(),
                detail: format!("{e}"),
            });
        }
    };

    // Compute the new expiry timestamp while we still have the
    // provider's `expires_in` in hand. Used by Task 4's meta update
    // and by the CLI's success output.
    let new_expiry_at: Option<chrono::DateTime<chrono::Utc>> = refresh_result
        .expires_in
        .and_then(|d| chrono::Duration::from_std(d).ok())
        .map(|d| chrono::Utc::now() + d);

    // Extract the access token bytes into a Zeroizing buffer BEFORE
    // we move `new_access` into the seal task. The proxy retry path
    // needs these bytes for dispatch; the CLI drops them. Zeroizing
    // ensures the bytes are wiped on drop regardless of which caller
    // uses them.
    let new_access = refresh_result.access_token;
    let new_access_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(new_access.reveal().to_vec());

    // M3 (Story 1.14a): Validate UTF-8 BEFORE any persistence.
    // Rationale — without this check, a non-UTF-8 access token would
    // be sealed, stored, and success-audited, then fail at dispatch
    // time — leaving the vault with a poisoned token that every
    // subsequent request re-refreshes and re-persists in an infinite
    // audit-spam loop.
    if let Err(e) = std::str::from_utf8(&new_access_bytes) {
        return Err(RefreshFlowError::MalformedToken {
            service: service.to_owned(),
            detail: format!("{e}"),
        });
    }

    let rotated = refresh_result.new_refresh_token.is_some();

    // Step 5a: If rotation occurred, persist the new REFRESH token first.
    // Architecture invariant #3: the old refresh token stays usable
    // until the new one lands in the store, so a crash mid-persist
    // can always recover via the old refresh token.
    if let Some(new_refresh) = refresh_result.new_refresh_token {
        let vault_for_seal = Arc::clone(vault);
        let refresh_service_for_seal = refresh_service_key.clone();
        let seal_result = tokio::task::spawn_blocking(move || {
            vault_for_seal.seal_refresh(&refresh_service_for_seal, &new_refresh)
        })
        .await;

        let sealed_new_refresh = match seal_result {
            Ok(Ok(sealed)) => sealed,
            Ok(Err(e)) => {
                return Err(RefreshFlowError::PersistenceFailed {
                    service: service.to_owned(),
                    stage: PersistStage::RefreshTokenSeal,
                    // Story 1.14b code-review M5: stable substring
                    // — operator log-grep / audit forensics expects
                    // this exact prefix.
                    detail: format!("refresh-token seal failed: {e}"),
                });
            }
            Err(join_err) => {
                return Err(RefreshFlowError::PersistenceFailed {
                    service: service.to_owned(),
                    stage: PersistStage::RefreshTokenSeal,
                    detail: format!("refresh-token seal task failed: {join_err}"),
                });
            }
        };

        if let Err(e) = credential_store.put(&refresh_service_key, sealed_new_refresh).await {
            return Err(RefreshFlowError::PersistenceFailed {
                service: service.to_owned(),
                stage: PersistStage::RefreshTokenStore,
                detail: format!("refresh-token store put failed: {e}"),
            });
        }
    }

    // Step 5b: Persist the new ACCESS token.
    let vault_for_access_seal = Arc::clone(vault);
    let service_for_access_seal = service.to_owned();
    let seal_result = tokio::task::spawn_blocking(move || {
        vault_for_access_seal.seal(&service_for_access_seal, &new_access)
    })
    .await;

    let sealed_new_access = match seal_result {
        Ok(Ok(sealed)) => sealed,
        Ok(Err(e)) => {
            return Err(RefreshFlowError::PersistenceFailed {
                service: service.to_owned(),
                stage: PersistStage::AccessTokenSeal,
                // Story 1.14b code-review M5: stable substring.
                detail: format!("access-token seal failed: {e}"),
            });
        }
        Err(join_err) => {
            return Err(RefreshFlowError::PersistenceFailed {
                service: service.to_owned(),
                stage: PersistStage::AccessTokenSeal,
                detail: format!("access-token seal task failed: {join_err}"),
            });
        }
    };

    if let Err(e) = credential_store.put(service, sealed_new_access).await {
        return Err(RefreshFlowError::PersistenceFailed {
            service: service.to_owned(),
            stage: PersistStage::AccessTokenStore,
            detail: format!("access-token store put failed: {e}"),
        });
    }

    // Task 4 (Story 1.14b): Update the meta file's
    // `last_refreshed_at` AND `expires_in_secs` (M1 fix). Best-effort
    // — failures log a warning but do not fail the refresh; the
    // tokens are already durably persisted, only the display
    // timestamp is affected. See `update_last_refreshed_at`'s doc
    // comment for the M1/M2/M4 review-fix rationale.
    //
    // m1 fix (post-review): the helper returns the exact timestamp
    // it persisted (or `None` if the meta write failed) so the CLI's
    // success output displays the same value `agentsso credentials
    // status` would show. No more drift between the two views.
    let last_refreshed_at =
        update_last_refreshed_at(vault_dir, service, refresh_result.expires_in).await;

    Ok(RefreshOutcome::Refreshed { rotated, new_access_bytes, new_expiry_at, last_refreshed_at })
}

/// Update the `{service}-meta.json` file with the new
/// `last_refreshed_at` timestamp AND the new `expires_in_secs`
/// (Story 1.14b code-review fix M1). Best-effort — failures are
/// logged via `tracing::warn!` and do NOT fail the refresh (the
/// tokens are already durably persisted; only the display timestamp
/// and validity computation are affected).
///
/// ## Why both fields are updated
///
/// The Story 1.14b code review (M1) found that updating only
/// `last_refreshed_at` while leaving `expires_in_secs` at its setup
/// value caused `compute_token_validity` to display wrong expiries
/// whenever the provider returned a different `expires_in` than the
/// setup response. Worst case: setup returned `None`, refresh
/// returned `Some(3600)` → status displayed "unknown" forever after
/// every refresh. This function now updates both fields atomically.
///
/// ## Why the function is async + spawn_blocking
///
/// Story 1.14b code review M2: the previous synchronous version did
/// `std::fs::read_to_string` + `serde_json::from_str` + tempfile
/// create + write + fsync + parent fsync, all from the proxy's
/// async request-handling task. Under load, parent-directory fsync
/// can stall the executor thread for tens to hundreds of
/// milliseconds. All other vault operations in this module are
/// wrapped in `spawn_blocking`; this one was overlooked. Now fixed.
///
/// ## Why we re-read inside the blocking task
///
/// Story 1.14b code review M4: the previous version did read +
/// parse + mutate + write with no lock. A concurrent
/// `agentsso setup` (or another refresh from the daemon while the
/// CLI runs) could write `meta_path` between the read and the
/// persist, causing the second writer to silently clobber unrelated
/// fields like `scopes` or `client_source`. Doing the read INSIDE
/// the spawn_blocking task immediately before the write narrows the
/// window from "across the entire async refresh state machine" to
/// "the duration of one synchronous filesystem op", which is
/// microseconds.
///
/// This is not a complete fix — a true compare-and-swap would
/// require a sidecar lock file or RPC-through-daemon — but it's
/// good enough for the documented "do not run while the daemon is
/// active" contract. The CLI's startup warning still applies.
pub async fn update_last_refreshed_at(
    vault_dir: &Path,
    service: &str,
    new_expires_in: Option<std::time::Duration>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let meta_path: PathBuf = vault_dir.join(format!("{service}-meta.json"));
    let service_owned = service.to_owned();

    // M2: wrap the entire read-merge-write sequence in spawn_blocking
    // so the parent fsync inside write_metadata_atomic does not
    // block the tokio runtime. M4: the read happens INSIDE this
    // blocking task, immediately before the write, so concurrent
    // writers from setup or another refresh have a much narrower
    // window to interleave.
    //
    // m1 fix: capture `now` ONCE inside the blocking task and return
    // it on success. The CLI uses this value for its success output
    // so the displayed "last refresh" matches the persisted value
    // exactly (not a slightly-later `Utc::now()` from the caller).
    let join_result =
        tokio::task::spawn_blocking(move || -> Result<chrono::DateTime<chrono::Utc>, String> {
            // Read current meta.
            let contents = std::fs::read_to_string(&meta_path)
                .map_err(|e| format!("read {}: {e}", meta_path.display()))?;

            // Parse.
            let mut meta: permitlayer_oauth::metadata::CredentialMeta =
                serde_json::from_str(&contents)
                    .map_err(|e| format!("parse {}: {e}", meta_path.display()))?;

            // Merge: only touch last_refreshed_at and expires_in_secs.
            // Every other field (client_type, client_source, connected_at,
            // scopes) is preserved from the freshly-read meta — this is
            // the M4 race-window narrowing. If a concurrent setup wrote
            // new scopes between the original refresh-flow start and now,
            // we use those new scopes, not a stale snapshot.
            let now = chrono::Utc::now();
            meta.last_refreshed_at = Some(now.to_rfc3339());
            if let Some(d) = new_expires_in {
                meta.expires_in_secs = Some(d.as_secs());
            }

            // Write atomically.
            permitlayer_oauth::metadata::write_metadata_atomic(&meta_path, &meta)
                .map_err(|e| format!("write {}: {e}", meta_path.display()))?;

            Ok(now)
        })
        .await;

    match join_result {
        Ok(Ok(now)) => Some(now),
        Ok(Err(detail)) => {
            warn!(
                service = %service_owned,
                error = %detail,
                "refresh: could not update meta file \
                 (agentsso credentials status may display stale last-refresh time \
                 and/or stale expires_in_secs)"
            );
            None
        }
        Err(join_err) => {
            warn!(
                service = %service_owned,
                error = %join_err,
                "refresh: meta-update spawn_blocking task panicked \
                 (agentsso credentials status may display stale last-refresh time)"
            );
            None
        }
    }
}
