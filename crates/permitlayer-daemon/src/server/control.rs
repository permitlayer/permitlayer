//! Loopback-only HTTP control endpoints for `agentsso kill` / `agentsso resume`.
//!
//! These routes live on a separate axum router that is **not** wrapped in
//! `KillSwitchLayer` — that is intentional: kill / resume / state-probe must
//! keep working when the daemon is killed. The carve-out is achieved by
//! building this router with its own `.with_state(...)` and merging it onto
//! the main app **after** `.layer(middleware)` is applied to the main router
//! (see `cli/start.rs`).
//!
//! # Loopback-only
//!
//! Each handler enforces a runtime loopback check via `ConnectInfo<SocketAddr>`
//! and returns `403 forbidden_not_loopback` for non-loopback peers. This is
//! defense in depth against a future accidental non-loopback `bind_addr`:
//! `start.rs` already warns at startup (NFR17) but does not refuse to bind;
//! the handler-level check turns a misconfiguration into a 403 rather than a
//! remote unauthenticated kill switch.
//!
//! # Endpoints
//!
//! - `POST /v1/control/kill`   — calls `KillSwitch::activate(UserInitiated)` and returns `KillResponse`.
//! - `POST /v1/control/resume` — calls `KillSwitch::deactivate()` and returns `ResumeResponse`.
//! - `GET  /v1/control/state`  — reports `is_active()`, `activated_at()`, and `token_count()`.
//!
//! All three share a minimal `ControlState` wrapper holding
//! `Arc<KillSwitch>` and `Option<Arc<dyn AuditStore>>`. The full daemon
//! `AppState` is not needed here.
//!
//! # Audit events (Story 3.3)
//!
//! `kill_handler` and `resume_handler` each emit exactly one audit event
//! per invocation — `kill-activated` (with `cause`, `tokens_invalidated`,
//! `in_flight_cancelled`) and `kill-resumed` (with `duration_killed_seconds`
//! computed from the pre-deactivate snapshot of `KillSwitch::activated_at`).
//! Both writes are **best-effort**: a failure logs a `tracing::warn!` and
//! the handler still returns the normal response. The security state
//! change (kill / resume) is the primary effect; audit is defense-in-depth
//! forensics per FR64 / NFR20.
//!
//! Idempotent invocations (activate-while-killed or resume-while-running)
//! are logged too, with `outcome = "already-active"` / `"already-inactive"` —
//! the forensic value of "operator hit kill a second time" outweighs the
//! extra log line.
//!
//! `audit_store` is `Option<>` because the daemon boots successfully even
//! when the audit directory is broken: Story 3.3 chose best-effort writes
//! over fail-closed at boot so operators with a broken audit dir still
//! have a working kill switch. When `None`, each handler silently skips
//! the audit write (the daemon already logged a startup warn).
//!
//! `kill-blocked-request` events are emitted from `KillSwitchLayer`
//! itself (in `permitlayer-proxy::middleware::kill`), not from this
//! module — the short-circuit happens before the request reaches any
//! handler. See that module for the middleware-side write path.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use arc_swap::ArcSwap;
use axum::Json;
use axum::Router;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};

use permitlayer_core::agent::{
    AgentIdentity, AgentRegistry, BEARER_TOKEN_PREFIX, LOOKUP_KEY_BYTES, compute_lookup_key,
    generate_bearer_token_bytes, hash_token, lookup_key_to_hex, validate_agent_name,
};
use permitlayer_core::audit::event::{AuditEvent, format_audit_timestamp};
use permitlayer_core::killswitch::{
    ActivationSummary, DeactivationSummary, KillReason, KillSwitch,
};
use permitlayer_core::policy::PolicySet;
use permitlayer_core::policy::schema::TomlPolicyFile;
use permitlayer_core::store::{AgentIdentityStore, CredentialStore};

use crate::cli::start::ProxyActivationContext;

/// Lightweight state for the control router.
///
/// Holds only what the control handlers actually need. Intentionally distinct
/// from `cli::start::AppState` so that the control surface can't accidentally
/// grow a dependency on daemon-wide state.
///
/// `audit_store` is `Option<>` because the daemon can boot successfully with
/// a broken audit directory — Story 3.3 deliberately chose best-effort audit
/// writes over fail-closed at boot, so operators with a broken audit dir
/// still get a working kill switch.
#[derive(Clone)]
pub(crate) struct ControlState {
    pub kill_switch: Arc<KillSwitch>,
    pub audit_store: Option<Arc<dyn permitlayer_core::store::AuditStore>>,
    pub policy_set: Arc<ArcSwap<PolicySet>>,
    pub policies_dir: std::path::PathBuf,
    pub reload_mutex: Arc<std::sync::Mutex<()>>,
    /// Serializes policy-scope edits before the reload step. The
    /// underlying file edit is a read/modify/write operation and the
    /// editor deliberately does not own process-wide locking.
    pub policy_edit_mutex: Arc<tokio::sync::Mutex<()>>,
    /// Story 4.4: registry handle for the bearer-token lookup index.
    /// Required so the register/remove handlers can `replace_with(...)`
    /// after a successful CRUD operation.
    pub agent_registry: Arc<AgentRegistry>,
    /// Story 4.4: optional agent store. `None` when the agents
    /// directory cannot be created/read; the register/remove handlers
    /// return 503 in that case.
    pub agent_store: Option<Arc<dyn AgentIdentityStore>>,
    /// Story 4.4: HMAC subkey for bearer-token lookup. Zero placeholder
    /// when the master key is unavailable; the register handler refuses
    /// to mint tokens against a placeholder (otherwise the resulting
    /// agent file would be unusable for auth).
    ///
    /// Wrapped in `Arc<Zeroizing<_>>` so that cloning `ControlState`
    /// (which axum does per request via `State<ControlState>`) does NOT
    /// memcpy the key into fresh stack/heap bytes. The `Zeroizing`
    /// guard ensures the one backing allocation is scrubbed when the
    /// last `Arc` drops (daemon shutdown). Story 4.4 code-review fix.
    pub agent_lookup_key: Arc<zeroize::Zeroizing<[u8; LOOKUP_KEY_BYTES]>>,
    /// Story 4.4 code-review fix: cap concurrent register/remove
    /// operations at [`AGENT_CRUD_MAX_CONCURRENT`]. Each call to
    /// `register_agent_handler` or `remove_agent_handler` acquires a
    /// permit before doing any work. Without this, a loopback caller
    /// (rogue local process) can submit an unbounded stream of
    /// register requests, each of which costs ~100 ms Argon2id CPU +
    /// one fsync'd file write — exhausting the daemon's blocking
    /// thread pool and disk IO bandwidth.
    pub agent_crud_semaphore: Arc<tokio::sync::Semaphore>,
    /// Story 7.11 review-round-2 Q4: serializes the
    /// `[store.list().await + agent_registry.replace_with(agents)]`
    /// critical section across all agent CRUD handlers (register,
    /// remove, rebind). The agent_crud_semaphore (capacity 4) caps
    /// concurrent CRUD throughput but does NOT prevent two
    /// successful mutations from racing on the registry-reload
    /// step: A's `list()` could resolve AFTER B's `list()`, but
    /// A's `replace_with()` could land BEFORE B's, snapshotting
    /// A's earlier view of the world OVER B's later mutation.
    /// This mutex makes the list-then-replace pair atomic.
    pub agent_registry_reload_lock: Arc<tokio::sync::Mutex<()>>,
    /// Story 4.5: handle to the approval service so the reload path
    /// can call `clear_caches()` after a successful policy recompile.
    /// Operator edits to policy files should take immediate effect;
    /// stale remembered-decision caches would mask those edits.
    pub approval_service: Arc<dyn permitlayer_proxy::middleware::ApprovalService>,
    /// Story 5.5: in-process per-agent connection tracker shared with
    /// `AppState` (read by `health_handler`) and the proxy middleware
    /// chain (written by `ConnTrackLayer` via the
    /// `ConnTrackerAdapter`). Read by `connections_handler` to
    /// produce the `agentsso status --connections` table.
    pub conn_tracker: Arc<crate::server::conn_tracker::ConnTracker>,
    /// Story 6.3: plugin registry populated by
    /// `permitlayer_plugins::loader::load_all` at daemon boot.
    /// Read by [`connectors_handler`] (route
    /// `GET /v1/control/connectors`) which backs the
    /// `agentsso connectors list` CLI. The registry is the single
    /// source of truth for "which connector plugins did this
    /// daemon load" and serializes out via the connector's
    /// `Serialize` derive (`source` field is skipped per AR-
    /// analogous discipline — plugin source never crosses the
    /// control-plane wire).
    pub plugin_registry: Arc<permitlayer_plugins::PluginRegistry>,
    /// Story 8.7 AC #3: shared approval-timeout atomic. Written by
    /// [`reload_handler`] on every successful `POST /v1/control/reload`
    /// (after clamping via [`crate::cli::start::clamp_approval_timeout_seconds`])
    /// and read per-request by `PolicyLayer`. Both SIGHUP and the HTTP
    /// control endpoint share the same atomic so the user-facing reload
    /// surfaces stay behaviorally equivalent.
    pub approval_timeout_atomic: Arc<AtomicU64>,
    /// Story 8.7 AC #3: ArcSwap handle to the live daemon config,
    /// shared with the SIGHUP path. [`reload_handler`] re-reads
    /// `DaemonConfig::load(&cli_overrides)` on every HTTP reload and
    /// atomically swaps this handle on success.
    pub config_state: Arc<ArcSwap<crate::config::DaemonConfig>>,
    /// Story 8.7 AC #3: boot-time CLI overrides needed to re-load the
    /// daemon config from the HTTP reload path. Mirrors the argument
    /// already threaded into `spawn_reload_watcher`.
    pub cli_overrides: Arc<crate::config::CliOverrides>,
    /// Story 7.32: boot-time flag that is `true` when the daemon wired
    /// empty proxy route slots at startup. SIGHUP clears it only after
    /// successfully activating a real `ProxyService`; HTTP reload still
    /// uses it for a diagnostic when credentials appear but activation
    /// has not happened.
    pub proxy_stub_branch_active: Arc<AtomicBool>,
    pub proxy_activation: ProxyActivationContext,
    /// Story 8.7 AC #4: vault directory path to consult when the
    /// stub-active flag fires. Typically `{config.paths.home}/vault`.
    pub vault_dir: PathBuf,
    /// Story 7.30 AC #11: vault used by the credentials-seal /
    /// credentials-verify handlers. Constructed at boot from the
    /// eagerly-bootstrapped master key (see `cli/start.rs`). Shared
    /// via `Arc` with the proxy service so both sides see the same
    /// `active_key_id` and refresh-rotation seals stay consistent.
    pub vault: Arc<permitlayer_vault::Vault>,
    /// Story 7.30 AC #11 + Round-1 review P2: per-service seal lock
    /// map. Concurrent seals against the same service serialize on
    /// the per-service `Arc<Mutex<()>>`; seals against disjoint
    /// services (e.g., gmail + drive) run in parallel.
    ///
    /// Map access is guarded by `std::sync::Mutex` because the
    /// critical section is "insert-if-missing then clone the Arc" —
    /// pure CPU with no `.await`. The per-service inner mutex is
    /// `tokio::sync::Mutex` because it's held across
    /// `vault.seal` + `store.put` + `write_metadata_atomic` await
    /// points.
    pub credentials_seal_locks:
        Arc<std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    /// Round-1 review P7: cap concurrent seal operations across all
    /// services. Mirrors `agent_crud_semaphore`. Without this, a
    /// loopback caller can flood the seal handler — each call holds a
    /// per-service mutex + does blocking disk I/O + AEAD seal —
    /// exhausting the blocking thread pool and starving other control
    /// endpoints that share the runtime.
    pub credentials_seal_semaphore: Arc<tokio::sync::Semaphore>,
    /// Operator authentication token for `/v1/control/*` endpoints.
    /// The middleware layer at the router level (`require_control_token`)
    /// reads `X-Agentsso-Control` from each inbound request and
    /// constant-time-compares against this token. Loopback enforcement
    /// remains in each handler (`require_loopback`); two gates are
    /// kept for defense in depth.
    ///
    /// Minted (or read from disk) at daemon startup; persists across
    /// daemon restarts. See [`crate::lifecycle::control_token`] for the
    /// rotation policy and file-mode invariants.
    pub control_token: Arc<crate::lifecycle::control_token::ControlToken>,
}

/// Cap on concurrent agent CRUD operations. The number is small
/// because each operation runs an Argon2id hash on a blocking worker
/// (~100 ms) plus a disk write; 4 concurrent operations match a
/// typical laptop's blocking thread pool default and leave the
/// remaining workers free for the rest of the daemon. See Story 4.4
/// code-review HIGH finding "No rate limit on `register_agent_handler`."
pub(crate) const AGENT_CRUD_MAX_CONCURRENT: usize = 4;

/// Story 7.30 Round-1 review P7: cap on concurrent
/// credentials-seal operations. Each seal does AES-GCM seal (CPU) +
/// two `store.put` writes (blocking I/O) + `write_metadata_atomic`
/// (blocking I/O). 4 concurrent seals match the agent CRUD ceiling
/// and leave blocking-pool capacity for the rest of the daemon.
pub(crate) const CREDENTIALS_SEAL_MAX_CONCURRENT: usize = 4;

/// Daemon-side mirror of `permitlayer_core::killswitch::ActivationSummary`
/// that serializes `activated_at` as an RFC 3339 string with millisecond
/// precision + `Z` suffix (audit log format), plus a `reason` wire field
/// carrying the `KillReason` variant as a kebab-case string.
///
/// Wrapping at the daemon boundary keeps `permitlayer-core` free of web /
/// serde concerns (AR33 / AR34). `reason` is added here rather than to
/// `ActivationSummary` in core because Story 3.1's public API is frozen
/// per the handoff contract.
#[derive(Debug, Serialize)]
pub(crate) struct SerializableActivationSummary {
    pub tokens_invalidated: usize,
    /// RFC 3339 UTC with millisecond precision, `Z` suffix (matches
    /// `crates/permitlayer-core/src/audit/event.rs` format).
    pub activated_at: String,
    pub was_already_active: bool,
    /// Kebab-case label derived from `KillReason` — `"user-initiated"` for
    /// `KillReason::UserInitiated`. Future variants extend the mapping.
    pub reason: &'static str,
}

impl SerializableActivationSummary {
    /// Build from a `KillReason` + `ActivationSummary`. The control handler
    /// is the sole caller and already knows the reason it passed into
    /// `activate()`, so we thread it through explicitly rather than adding
    /// a field to the Story 3.1 `ActivationSummary` type.
    pub(crate) fn from_reason_and_summary(reason: &KillReason, summary: ActivationSummary) -> Self {
        Self {
            tokens_invalidated: summary.tokens_invalidated,
            activated_at: format_audit_timestamp(summary.activated_at),
            was_already_active: summary.was_already_active,
            reason: kill_reason_wire_label(reason),
        }
    }
}

/// Map a `KillReason` variant to its wire label.
///
/// This is the single source of truth for the daemon side. The CLI has a
/// symmetric helper in `design/kill_banner.rs::kill_reason_label` that maps
/// the SAME strings to banner display labels (currently identical, but kept
/// separate so the banner can add human-friendly phrasing if a future
/// variant's wire label is terse).
///
/// `KillReason` is `#[non_exhaustive]` in a different crate, so a wildcard
/// arm is mandatory. New variants fall through to `"unknown"` on the wire
/// and a `tracing::warn!` so the gap is auditable in the daemon log —
/// extend this function when adding `KillReason` variants in
/// `permitlayer-core`.
pub(crate) fn kill_reason_wire_label(reason: &KillReason) -> &'static str {
    match reason {
        KillReason::UserInitiated => "user-initiated",
        other => {
            tracing::warn!(
                target: "control",
                reason = ?other,
                "unknown KillReason variant — extend kill_reason_wire_label",
            );
            "unknown"
        }
    }
}

/// Daemon-side mirror of `permitlayer_core::killswitch::DeactivationSummary`.
#[derive(Debug, Serialize)]
pub(crate) struct SerializableDeactivationSummary {
    pub resumed_at: String,
    pub was_already_inactive: bool,
}

impl From<DeactivationSummary> for SerializableDeactivationSummary {
    fn from(value: DeactivationSummary) -> Self {
        Self {
            resumed_at: format_audit_timestamp(value.resumed_at),
            was_already_inactive: value.was_already_inactive,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct KillResponse {
    pub activation: SerializableActivationSummary,
    pub daemon_version: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct ResumeResponse {
    pub deactivation: SerializableDeactivationSummary,
    pub daemon_version: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct StateResponse {
    pub active: bool,
    pub activated_at: Option<String>,
    pub token_count: usize,
    pub daemon_version: &'static str,
}

// --------------------------------------------------------------------------
// ControlError — the 403 shape when a non-loopback peer hits the endpoint.
// --------------------------------------------------------------------------

/// Errors the control router can return.
///
/// Story 3.2 ships `ForbiddenNotLoopback`. Story 8.3 adds
/// `ConnectorsPayloadTooLarge` (AC #8). Plan B (operator-token auth)
/// adds `ForbiddenMissingControlToken` and `ForbiddenInvalidControlToken`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ControlError {
    #[error("control endpoints are loopback-only")]
    ForbiddenNotLoopback,
    /// Request did not carry an `X-Agentsso-Control` header.
    /// Distinct from `ForbiddenInvalidControlToken` so operators can
    /// distinguish "client forgot the header" from "client guessed wrong."
    #[error("X-Agentsso-Control header is required on /v1/control/* endpoints")]
    ForbiddenMissingControlToken,
    /// Request carried an `X-Agentsso-Control` header but it did not
    /// match the daemon's stored token.
    #[error("X-Agentsso-Control token did not match")]
    ForbiddenInvalidControlToken,
    /// `GET /v1/control/connectors` JSON exceeds the 1 MiB cap.
    #[error("connector registry JSON exceeds 1 MiB")]
    ConnectorsPayloadTooLarge { size_bytes: usize, limit_bytes: usize },
}

/// Wire shape for control-plane 4xx responses.
///
/// Carries both shapes simultaneously:
/// - **Top-level `status: "error"`** routes flat-shape parsers (e.g.,
///   `cli/connectors/list.rs`, which checks `parsed["status"] ==
///   "error"`) to the structured-error path. Without it, a 403 would
///   fall through to the empty-state success branch and the user who
///   forgot `AGENTSSO_CONTROL_TOKEN` would see "no connectors
///   registered" instead of "forbidden: control token required".
/// - **Nested `error.code` / `error.message`** is what the
///   structured-error parsers in `cli/agent.rs` and `cli/status.rs`
///   already expect, plus what the existing unit tests assert on
///   (`json["error"]["code"] == "forbidden_*"`). Keeping the nested
///   shape preserves backward-compat with every test and consumer
///   that already exists.
#[derive(Debug, Serialize)]
struct ControlErrorBody {
    status: &'static str,
    error: ControlErrorDetail,
}

#[derive(Debug, Serialize)]
struct ControlErrorDetail {
    code: &'static str,
    message: &'static str,
}

#[derive(Debug, Serialize)]
struct ConnectorsPayloadTooLargeBody {
    status: &'static str,
    code: &'static str,
    message: String,
    size_bytes: usize,
    limit_bytes: usize,
}

impl IntoResponse for ControlError {
    fn into_response(self) -> Response {
        match self {
            Self::ForbiddenNotLoopback => {
                let body = ControlErrorBody {
                    status: "error",
                    error: ControlErrorDetail {
                        code: "forbidden_not_loopback",
                        message: "control endpoints are loopback-only",
                    },
                };
                (StatusCode::FORBIDDEN, Json(body)).into_response()
            }
            Self::ForbiddenMissingControlToken => {
                let body = ControlErrorBody {
                    status: "error",
                    error: ControlErrorDetail {
                        code: "forbidden_missing_control_token",
                        message: "X-Agentsso-Control header is required on /v1/control/* endpoints",
                    },
                };
                (StatusCode::FORBIDDEN, Json(body)).into_response()
            }
            Self::ForbiddenInvalidControlToken => {
                let body = ControlErrorBody {
                    status: "error",
                    error: ControlErrorDetail {
                        code: "forbidden_invalid_control_token",
                        message: "X-Agentsso-Control token did not match",
                    },
                };
                (StatusCode::FORBIDDEN, Json(body)).into_response()
            }
            Self::ConnectorsPayloadTooLarge { size_bytes, limit_bytes } => {
                let body = ConnectorsPayloadTooLargeBody {
                    status: "error",
                    code: "connectors.payload_too_large",
                    message: format!(
                        "connector registry JSON exceeds 1 MiB (got {size_bytes} bytes); \
                         this is a registry-size anomaly — consider pruning unused connectors"
                    ),
                    size_bytes,
                    limit_bytes,
                };
                (StatusCode::PAYLOAD_TOO_LARGE, Json(body)).into_response()
            }
        }
    }
}

// --------------------------------------------------------------------------
// Handlers.
// --------------------------------------------------------------------------

/// Return `Ok(())` when the peer is a loopback address, else
/// `Err(ControlError::ForbiddenNotLoopback)`.
fn require_loopback(peer: SocketAddr) -> Result<(), ControlError> {
    if peer.ip().is_loopback() {
        Ok(())
    } else {
        tracing::warn!(
            target: "control",
            peer = %peer,
            "rejecting non-loopback request to control endpoint",
        );
        Err(ControlError::ForbiddenNotLoopback)
    }
}

/// Story 7.27 AC #1 (review fix): enrich an `AuditEvent.extra` JSON
/// object with the kernel-attested peer UID + GID from the request's
/// `Extension<PeerCredentials>`. No-op when the request has no
/// `PeerCredentials` extension (TCP control routes in dev/test mode,
/// non-macOS platforms) — those audit events stay schema-compatible
/// with rc.21.
///
/// Callers pass `req.extensions()`; the helper looks up
/// `PeerCredentials` and, when present, inserts `peer_uid` +
/// `peer_gid` keys into the JSON object. The `extra` value MUST be a
/// JSON object (`serde_json::Value::Object`) — every existing audit
/// emit site in this file uses `serde_json::json!({ ... })` which
/// produces an object, so this contract is upheld in practice.
pub(crate) fn enrich_audit_extra_with_peer(
    extra: &mut serde_json::Value,
    extensions: &axum::http::Extensions,
) {
    let Some(creds) = extensions.get::<crate::server::PeerCredentials>() else {
        return;
    };
    enrich_audit_extra_with_peer_creds(extra, Some(*creds));
}

/// Variant of [`enrich_audit_extra_with_peer`] that takes the
/// captured creds directly. Use in handlers that consume `req` via
/// `into_parts()` before the audit emit — snapshot the creds at the
/// top of the handler, then call this helper at each emit site.
pub(crate) fn enrich_audit_extra_with_peer_creds(
    extra: &mut serde_json::Value,
    creds: Option<crate::server::PeerCredentials>,
) {
    let Some(creds) = creds else { return };
    if creds.uid == u32::MAX {
        return;
    }
    // Story 7.27 Round-2 review fix (P2): upgrade `Value::Null`
    // to an empty object so freshly-constructed `AuditEvent::new(...)`
    // events (whose `extra` defaults to `Value::Null`) still
    // receive peer-cred enrichment. Pre-fix, the helper silently
    // returned for non-Object values — a future contributor
    // forgetting to set `event.extra = serde_json::json!({...})`
    // before calling this would lose peer attribution without any
    // warning. `debug_assert!` catches non-object non-null values
    // in test builds; release builds log via tracing::warn so
    // operators see the contract violation in the field.
    if extra.is_null() {
        *extra = serde_json::json!({});
    }
    let Some(obj) = extra.as_object_mut() else {
        debug_assert!(
            false,
            "enrich_audit_extra_with_peer_creds called with non-object `extra`: {extra:?}"
        );
        tracing::warn!(
            target: "control",
            extra = %extra,
            "enrich_audit_extra_with_peer_creds called with non-object `extra`; \
             peer-cred attribution dropped — fix the caller to pass a JSON object"
        );
        return;
    };
    // Round-3 review fix (R3-C3-P4): `entry(...).or_insert(...)` instead
    // of `insert(...)` so the helper is additive-only. Several handlers
    // (register, remove, rebind) already set `peer_uid`/`peer_gid`
    // explicitly in their `event.extra = serde_json::json!({...})` AND
    // call this helper afterward. The previous `insert` form clobbered
    // the explicit values silently; `or_insert` preserves them.
    obj.entry("peer_uid".to_owned()).or_insert_with(|| serde_json::json!(creds.uid));
    obj.entry("peer_gid".to_owned()).or_insert_with(|| serde_json::json!(creds.gid));
}

/// Header name carried by the CLI to authenticate against
/// `/v1/control/*`. Distinct from `Authorization: Bearer <agt_v2_*>`
/// (the agent-identity tokens used by /mcp/* and /v1/tools/*) so the
/// proxy's `AuthLayer` can't accidentally route operator tokens
/// through agent-identity validation.
const CONTROL_TOKEN_HEADER: &str = "x-agentsso-control";

/// Axum `from_fn_with_state` middleware that gates every `/v1/control/*`
/// request on a valid operator token.
///
/// Runs at the router level (NOT inline in each handler) so that auth
/// rejection happens before axum extracts the JSON body, the
/// `ConnectInfo`, or any other handler-side state. This is why the
/// fix uses `from_fn_with_state` rather than per-handler
/// `require_control_token(headers, &state)?` calls — Codex review
/// caught that handler-side checks happen after body extraction, so a
/// 1 GB JSON POST without the token would still consume server memory.
///
/// Constant-time comparison against the daemon's stored token is
/// defense in depth (`subtle::ConstantTimeEq`); the primary security
/// boundary is the `0o600` mode on `<home>/control.token`. See the
/// module-level doc on `ControlToken` for the full threat model.
/// Resolve `PERMITLAYER_OPERATOR_UID` once at first use; return `None`
/// if unset or malformed.
///
/// Story 7.27 Round-2 review fix (P1): pre-fix, `require_control_token`
/// called `std::env::var("PERMITLAYER_OPERATOR_UID")` on every
/// authenticated request — which (a) serializes through the global
/// env mutex on every request and (b) silently disables the
/// identity-mismatch check when an admin `setenv`s the variable
/// away. Reading once into a `OnceLock` at first-touch:
///   - amortizes the env-var lookup
///   - documents intent (env-var is a boot-time invariant, not a
///     runtime knob)
///   - emits a structured `WARN` audit-event surface at first-touch
///     if the env-var is missing or malformed, so operators know
///     the supplementary check is degraded.
fn operator_uid() -> Option<u32> {
    use std::sync::OnceLock;
    static OPERATOR_UID: OnceLock<Option<u32>> = OnceLock::new();
    *OPERATOR_UID.get_or_init(|| {
        let raw = std::env::var("PERMITLAYER_OPERATOR_UID").ok();
        match raw.as_deref().map(str::trim) {
            None => {
                tracing::warn!(
                    event = "control.operator_uid_missing",
                    "PERMITLAYER_OPERATOR_UID is not set; the supplementary \
                     kernel-attested-UID match against the operator-secret \
                     bearer-token is disabled. Set this in the LaunchDaemon \
                     plist (`<key>EnvironmentVariables</key>`) to enable it."
                );
                None
            }
            Some(s) => match s.parse::<u32>() {
                Ok(uid) => Some(uid),
                Err(e) => {
                    tracing::warn!(
                        event = "control.operator_uid_malformed",
                        raw = %s,
                        error = %e,
                        "PERMITLAYER_OPERATOR_UID is set but not a valid u32; \
                         the supplementary UID-match check is disabled."
                    );
                    None
                }
            },
        }
    })
}

pub(crate) async fn require_control_token(
    State(state): State<ControlState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let header_value = match req.headers().get(CONTROL_TOKEN_HEADER) {
        Some(v) => v,
        None => {
            tracing::warn!(
                target: "control",
                path = %req.uri().path(),
                "rejecting /v1/control/* request: missing X-Agentsso-Control header",
            );
            return ControlError::ForbiddenMissingControlToken.into_response();
        }
    };
    let candidate = match header_value.to_str() {
        Ok(s) => s,
        Err(_) => {
            tracing::warn!(
                target: "control",
                path = %req.uri().path(),
                "rejecting /v1/control/* request: X-Agentsso-Control header is not valid UTF-8",
            );
            return ControlError::ForbiddenInvalidControlToken.into_response();
        }
    };
    if !state.control_token.matches(candidate) {
        tracing::warn!(
            target: "control",
            path = %req.uri().path(),
            "rejecting /v1/control/* request: X-Agentsso-Control token did not match",
        );
        return ControlError::ForbiddenInvalidControlToken.into_response();
    }

    // Story 7.27 AC #15 (review fix): identity-mismatch detection.
    // The bearer-token (X-Agentsso-Control) is an operator-shared
    // secret. The kernel-attested peer UID identifies WHO is calling.
    // When PERMITLAYER_OPERATOR_UID is set (installed-as-LaunchDaemon
    // mode) AND the peer UID disagrees, log a WARN audit event but
    // DO NOT reject — the operator-secret IS the auth credential in
    // rc.22; the UID check is a supplementary forensics signal that
    // catches the case where a non-operator user on the Mac has
    // gained access to the operator-secret.
    //
    // Story 7.27 Round-2 review fix (P1): also enrich the
    // current tracing span with `peer_uid`/`peer_gid` here. The
    // outer `record_peer_credentials_layer` runs ABOVE the
    // `RequestTraceLayer` (axum layer order is outer-runs-first),
    // so its `Span::current().record(...)` calls hit the ambient
    // daemon span — which doesn't declare `peer_uid`/`peer_gid`
    // as fields, making the record a documented no-op. By moving
    // the recording here (inside `require_control_token`, which
    // runs INSIDE `RequestTraceLayer`'s `info_span!("request")`),
    // and by declaring `peer_uid` / `peer_gid` as `Empty` fields
    // in the request-span macro, the values now reach the
    // tracing surface for grep-correlation.
    if let Some(creds) = req.extensions().get::<crate::server::PeerCredentials>().copied() {
        tracing::Span::current().record("peer_uid", creds.uid);
        tracing::Span::current().record("peer_gid", creds.gid);
    }
    if let Some(creds) = req.extensions().get::<crate::server::PeerCredentials>().copied()
        && let Some(expected_uid) = operator_uid()
        && creds.uid != u32::MAX
        && creds.uid != expected_uid
    {
        let path = req.uri().path().to_owned();
        tracing::warn!(
            target: "control",
            path = %path,
            peer_uid = creds.uid,
            peer_gid = creds.gid,
            operator_uid = expected_uid,
            "control.identity_mismatch: peer UID differs from operator UID",
        );
        if let Some(store) = &state.audit_store {
            let mut event = AuditEvent::new(
                "system".to_owned(),
                "permitlayer".to_owned(),
                "-".to_owned(),
                "control-plane".to_owned(),
                "warn".to_owned(),
                "control.identity_mismatch".to_owned(),
            );
            event.extra = serde_json::json!({
                "peer_uid": creds.uid,
                "peer_gid": creds.gid,
                "operator_uid": expected_uid,
                "route": path,
            });
            if let Err(e) = store.append(event).await {
                tracing::warn!(
                    target: "control",
                    error = %e,
                    "control.identity_mismatch audit write failed",
                );
            }
        }
    }

    // Story 7.27 AC #1 (review fix): emit a per-request audit event
    // for every authenticated /v1/control/* request, carrying the
    // kernel-attested peer_uid + peer_gid. This gives universal
    // audit coverage for inspection handlers (whoami, list-agents,
    // state, connections, connectors, reload) that don't emit
    // domain-specific events of their own. Handlers that DO emit
    // their own domain event (kill, resume, register, remove,
    // rebind) get this as a request-level breadcrumb plus the
    // domain event with the same request_id — the two correlate
    // via the request_id field.
    //
    // Round-3 review fix (R3-C3-P3): `tokio::spawn` the audit-append
    // so the handler does NOT block on the audit store. The Round-2
    // patch wrapped the append in `tokio::time::timeout(5s, …)`
    // inline before `next.run(req).await`, which meant a slow store
    // serialized every authenticated request behind one append. The
    // spawned task holds an `Arc` clone of the audit store, runs the
    // same 5s-timeout discipline, and logs `WARN` on failure or
    // timeout — best-effort semantics preserved; latency restored.
    //
    // Round-3 review fix (R3-C3-P5): outcome field is
    // `"authenticated"` (not `"ok"`) because this emit fires BEFORE
    // the handler runs. `"ok"` would silently contradict downstream
    // 4xx/5xx / rate-limit responses; `"authenticated"` is neutral
    // and accurate (bearer-token + peer-cred check passed).
    if let Some(store) = &state.audit_store {
        let creds = req.extensions().get::<crate::server::PeerCredentials>().copied();
        let request_id = req
            .extensions()
            .get::<permitlayer_proxy::error::RequestId>()
            .map(|r| r.0.clone())
            .unwrap_or_else(|| ulid::Ulid::new().to_string());
        let path = req.uri().path().to_owned();
        let method = req.method().to_string();
        let mut event = AuditEvent::with_request_id(
            request_id,
            "system".to_owned(),
            "permitlayer".to_owned(),
            "-".to_owned(),
            "control-plane".to_owned(),
            "authenticated".to_owned(),
            "control-request-authenticated".to_owned(),
        );
        let mut extra = serde_json::json!({ "method": method, "path": path });
        if let Some(c) = creds
            && c.uid != u32::MAX
            && let Some(obj) = extra.as_object_mut()
        {
            obj.insert("peer_uid".to_owned(), serde_json::json!(c.uid));
            obj.insert("peer_gid".to_owned(), serde_json::json!(c.gid));
        }
        event.extra = extra;
        let store = std::sync::Arc::clone(store);
        tokio::spawn(async move {
            const AUDIT_APPEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
            match tokio::time::timeout(AUDIT_APPEND_TIMEOUT, store.append(event)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::warn!(
                        target: "control",
                        error = %e,
                        "control-request audit write failed (best-effort)",
                    );
                }
                Err(_elapsed) => {
                    tracing::warn!(
                        target: "control",
                        "control-request audit write timed out after 5s; \
                         event dropped (best-effort)",
                    );
                }
            }
        });
    }

    next.run(req).await
}

pub(crate) async fn kill_handler(
    State(state): State<ControlState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
) -> Result<Json<KillResponse>, ControlError> {
    require_loopback(peer)?;

    // Story 3.3 review patch (HIGH #2): read the `RequestId` extension
    // stamped by `RequestTraceLayer` (which is applied to the control
    // router — see `router()` below). This makes the audit event's
    // `request_id` match the operator's HTTP request trace in the
    // daemon's tracing log, enabling grep-correlation between the two
    // sources. Without this, the audit event would get a fresh ULID
    // from `AuditEvent::new()` with zero correlation to anything else.
    let request_id = req
        .extensions()
        .get::<permitlayer_proxy::error::RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_else(|| {
            // Unreachable in production (`RequestTraceLayer` is applied
            // to the control router in `router()`). Defense in depth:
            // log a warn and mint a fresh ULID so the audit event still
            // gets written; operators see the invariant violation in
            // the log.
            tracing::warn!(
                target: "control",
                "RequestId extension missing on control request — RequestTraceLayer misconfigured?",
            );
            ulid::Ulid::new().to_string()
        });

    // MVP: the only kill path is a user running `agentsso kill`. Future
    // stories can add `--reason` or internal trigger paths.
    let reason = KillReason::UserInitiated;
    let summary = state.kill_switch.activate(reason);

    tracing::info!(
        target: "control",
        request_id = %request_id,
        tokens_invalidated = summary.tokens_invalidated,
        was_already_active = summary.was_already_active,
        reason = kill_reason_wire_label(&reason),
        "kill switch activated via control endpoint",
    );

    // Emit the `kill-activated` audit event (Story 3.3). Best-effort:
    // failure logs a warn but the kill state still takes effect.
    // `in_flight_cancelled` is literal `0` today — Story 3.2 deferred
    // in-flight cancellation. A future story plumbing cancellation
    // through `UpstreamHttpClient` will replace the 0 with a real count
    // without any other code changes here.
    if let Some(store) = &state.audit_store {
        let outcome = if summary.was_already_active { "already-active" } else { "ok" };
        let mut event = AuditEvent::with_request_id(
            request_id.clone(),
            "system".to_owned(),
            "permitlayer".to_owned(),
            "-".to_owned(),
            "kill-switch".to_owned(),
            outcome.to_owned(),
            "kill-activated".to_owned(),
        );
        event.extra = serde_json::json!({
            "activated_at": format_audit_timestamp(summary.activated_at),
            "cause": kill_reason_wire_label(&reason),
            "tokens_invalidated": summary.tokens_invalidated,
            "in_flight_cancelled": 0,
            "was_already_active": summary.was_already_active,
        });
        enrich_audit_extra_with_peer(&mut event.extra, req.extensions());
        if let Err(e) = store.append(event).await {
            tracing::warn!(
                target: "control",
                error = %e,
                "kill-activated audit write failed — kill state still active",
            );
        }
    }

    Ok(Json(KillResponse {
        activation: SerializableActivationSummary::from_reason_and_summary(&reason, summary),
        daemon_version: env!("CARGO_PKG_VERSION"),
    }))
}

pub(crate) async fn resume_handler(
    State(state): State<ControlState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
) -> Result<Json<ResumeResponse>, ControlError> {
    require_loopback(peer)?;

    // Story 3.3 review patch (HIGH #2): read the `RequestId` extension
    // stamped by `RequestTraceLayer` so the audit event's `request_id`
    // matches the operator's HTTP request trace. See kill_handler for
    // the full rationale.
    let request_id = req
        .extensions()
        .get::<permitlayer_proxy::error::RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_else(|| {
            tracing::warn!(
                target: "control",
                "RequestId extension missing on control request — RequestTraceLayer misconfigured?",
            );
            ulid::Ulid::new().to_string()
        });

    // CRITICAL ordering: capture the activation timestamp BEFORE calling
    // `deactivate()`, because `deactivate()` clears
    // `KillSwitch.activated_at` to `None` on the successful path. Reading
    // after would always yield `None` and silently produce a
    // `duration_killed_seconds == 0` regression.
    let activated_at_snapshot = state.kill_switch.activated_at();

    let summary = state.kill_switch.deactivate();

    tracing::info!(
        target: "control",
        request_id = %request_id,
        was_already_inactive = summary.was_already_inactive,
        "kill switch resumed via control endpoint",
    );

    // Emit the `kill-resumed` audit event (Story 3.3). Best-effort:
    // failure logs a warn but the daemon has already resumed normal
    // operation. `duration_killed_seconds` is computed from the
    // pre-deactivate snapshot of `activated_at`; negative durations
    // (clock jumps) and `None` snapshots (idempotent resumes) both
    // clamp to 0.
    if let Some(store) = &state.audit_store {
        let duration_killed_seconds: u64 = match activated_at_snapshot {
            Some(start) => {
                let delta_seconds = (summary.resumed_at - start).num_seconds();
                if delta_seconds < 0 {
                    // Clock jumped backward between activate and resume
                    // (NTP adjustment, VM pause/resume, manual clock set).
                    // Clamp to 0 but log a warn so operators can diagnose —
                    // without this, a negative duration is indistinguishable
                    // from a legitimate sub-second kill incident.
                    tracing::warn!(
                        target: "control",
                        activated_at = %start,
                        resumed_at = %summary.resumed_at,
                        delta_seconds,
                        "negative duration_killed_seconds clamped to 0 — clock jump detected between activate and resume",
                    );
                }
                delta_seconds.max(0) as u64
            }
            None => 0,
        };
        let outcome = if summary.was_already_inactive { "already-inactive" } else { "ok" };
        let mut event = AuditEvent::with_request_id(
            request_id.clone(),
            "system".to_owned(),
            "permitlayer".to_owned(),
            "-".to_owned(),
            "kill-switch".to_owned(),
            outcome.to_owned(),
            "kill-resumed".to_owned(),
        );
        event.extra = serde_json::json!({
            "resumed_at": format_audit_timestamp(summary.resumed_at),
            "duration_killed_seconds": duration_killed_seconds,
            "was_already_inactive": summary.was_already_inactive,
        });
        enrich_audit_extra_with_peer(&mut event.extra, req.extensions());
        if let Err(e) = store.append(event).await {
            tracing::warn!(
                target: "control",
                error = %e,
                "kill-resumed audit write failed — daemon has resumed normal operation",
            );
        }
    }

    Ok(Json(ResumeResponse {
        deactivation: summary.into(),
        daemon_version: env!("CARGO_PKG_VERSION"),
    }))
}

pub(crate) async fn state_handler(
    State(state): State<ControlState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Result<Json<StateResponse>, ControlError> {
    require_loopback(peer)?;

    let active = state.kill_switch.is_active();
    let activated_at = state.kill_switch.activated_at().map(format_audit_timestamp);
    let token_count = state.kill_switch.token_count();

    Ok(Json(StateResponse {
        active,
        activated_at,
        token_count,
        daemon_version: env!("CARGO_PKG_VERSION"),
    }))
}

// --------------------------------------------------------------------------
// Active-connections endpoint (Story 5.5 — FR83).
// --------------------------------------------------------------------------

/// One row in the `connections_handler` response. Flattens
/// `ConnInfo` plus derived rate metrics into JSON-friendly fields.
#[derive(Debug, Serialize)]
pub(crate) struct ConnectionRow {
    pub agent_name: String,
    pub policy_name: String,
    /// RFC 3339 UTC, millisecond precision, `Z` suffix.
    pub connected_since: String,
    /// RFC 3339 UTC, millisecond precision, `Z` suffix.
    pub last_request_at: String,
    pub total_requests: u64,
    /// Requests recorded in the current 1-minute bucket.
    pub req_per_min: u64,
    /// Sum of all 60 minute-buckets — requests in the last hour.
    pub req_per_hour: u64,
    /// Mean of the preceding 59 minute-buckets, with hybrid-divisor
    /// cold-start smoothing (`min_samples=3`). Omitted when the
    /// baseline is undefined (no events in the preceding window).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_per_min: Option<f64>,
    /// `req_per_min / baseline_per_min`, rounded to 1 decimal.
    /// Omitted when `baseline_per_min` is `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiplier: Option<f64>,
}

/// Response body for `GET /v1/control/connections`.
#[derive(Debug, Serialize)]
pub(crate) struct ConnectionsResponse {
    pub connections: Vec<ConnectionRow>,
    /// RFC 3339 UTC, millisecond precision, `Z` suffix — the wall-clock
    /// instant the snapshot was taken (used for the `agentsso status`
    /// "refreshed `<relative>`" footer).
    pub generated_at: String,
}

pub(crate) async fn connections_handler(
    State(state): State<ControlState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Result<Json<ConnectionsResponse>, ControlError> {
    require_loopback(peer)?;

    // Sweep before snapshot so the response cannot include
    // already-stale entries even on a daemon that never had its
    // background sweep task fire (e.g. brand-new boot).
    //
    // **H2 review patch:** sweep takes a monotonic `Instant` so
    // wall-clock skew can't pause or stampede the eviction.
    // **M8 review patch:** log the count when the read-time
    // backstop actually does work — operators have no other signal
    // that the sweep is firing on the read path.
    let now_wall = chrono::Utc::now();
    let now_mono = std::time::Instant::now();
    let removed = state.conn_tracker.sweep_idle(now_mono);
    if removed > 0 {
        tracing::debug!(removed, "connections endpoint sweep");
    }

    let snapshot = state.conn_tracker.snapshot();
    let connections = snapshot
        .into_iter()
        .map(|info| {
            // **H1 review patch:** advance the cloned RateWindow to
            // "now" before reading. Without this, an agent that did
            // 60 req in minute T and then nothing for 10m still
            // reports `req_per_min=60` (the bucket array hasn't
            // rotated since the last `record()`). The whole point
            // of the table is "is this agent still hot?" — surfacing
            // last-minute's count as current is the wrong answer.
            let mut window = info.request_window;
            window.advance_to(now_mono);
            let req_per_min = window.current_rate();
            // Sum all 60 buckets (current + preceding 59).
            // Uses the new `requests_in_window` accessor (L5 review
            // patch) so `RateWindow::buckets` can stay private.
            let req_per_hour: u64 = window.requests_in_window();
            // Baseline over the preceding 59 buckets only — `min_samples=3`
            // matches the audit-anomaly detector's hybrid-divisor floor.
            let baseline = window.baseline_rate(3);
            let (baseline_per_min, multiplier) = if baseline > 0.0 {
                let mult = (req_per_min as f64 / baseline * 10.0).round() / 10.0;
                (Some((baseline * 100.0).round() / 100.0), Some(mult))
            } else {
                (None, None)
            };
            ConnectionRow {
                agent_name: info.agent_name,
                policy_name: info.policy_name,
                connected_since: format_audit_timestamp(info.connected_since),
                last_request_at: format_audit_timestamp(info.last_request_at),
                total_requests: info.total_requests,
                req_per_min,
                req_per_hour,
                baseline_per_min,
                multiplier,
            }
        })
        .collect();

    Ok(Json(ConnectionsResponse { connections, generated_at: format_audit_timestamp(now_wall) }))
}

// --------------------------------------------------------------------------
// Story 7.7 P19 — `/v1/control/whoami` identity beacon.
//
// Replaces the unauth'd `/health` PID field with a loopback-gated
// identity endpoint. Test seams (e.g. `assert_daemon_pid_matches`)
// use this to detect stale-daemon-on-port collisions without
// exposing the daemon PID to anyone on the LAN when the daemon
// binds `0.0.0.0`.
//
// Auth model matches every other `/v1/control/*` endpoint: peer
// must be loopback (`require_loopback`), enforced by axum
// `ConnectInfo`. A LAN peer hitting this endpoint on a `0.0.0.0`
// bind gets 403 forbidden_not_loopback — same shape as
// `/v1/control/connections`.
//
// Response is intentionally minimal (PID + version) for the test-
// seam case. Future callers (`agentsso doctor`, smoke tests) can
// extend with `started_at`, `bind_addr`, etc. when concrete needs
// land — premature fields would just be noise.
// --------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub(crate) struct WhoamiResponse {
    pub pid: u32,
    pub version: &'static str,
}

pub(crate) async fn whoami_handler(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Result<Json<WhoamiResponse>, ControlError> {
    require_loopback(peer)?;
    Ok(Json(WhoamiResponse { pid: std::process::id(), version: env!("CARGO_PKG_VERSION") }))
}

// --------------------------------------------------------------------------
// Policy reload handler (Story 4.2).
// --------------------------------------------------------------------------

/// Response body for `POST /v1/control/reload` on success.
///
/// Story 4.4 added `agents_loaded` so the operator's `agentsso reload`
/// output line shows both the policy count and the agent count.
#[derive(Debug, Serialize)]
pub(crate) struct ReloadResponse {
    pub status: &'static str,
    pub policies_loaded: usize,
    pub added: usize,
    pub modified: usize,
    pub unchanged: usize,
    pub removed: usize,
    pub agents_loaded: usize,
    /// Absolute path scanned for policy files (Story 7.34 AC #5).
    pub policy_scan_path: String,
}

/// Response body for `POST /v1/control/reload` on failure.
#[derive(Debug, Serialize)]
pub(crate) struct ReloadErrorResponse {
    pub status: &'static str,
    pub message: String,
}

/// Successful response body for `POST /v1/control/reload`.
///
/// Story 8.7 review patch (MEDIUM): when `DaemonConfig::load` fails
/// during a reload, the policy reload can still succeed — but the
/// operator's config edit was silently dropped. `config_reload_error`
/// (absent on success, present on TOML parse / figment failure)
/// surfaces that split outcome in the 200 response body so the
/// operator isn't misled by a blanket `"status": "ok"`.
#[derive(Debug, Serialize)]
pub(crate) struct ReloadResponseExtras {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_reload_error: Option<String>,
    /// Warning when the scanned policy directory exists but contains
    /// no candidate policy files (Story 7.34 AC #5).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_scan_empty_warning: Option<String>,
}

/// `POST /v1/control/reload` — re-read policy files, compile a new
/// `PolicySet`, and atomically swap it into the `ArcSwap`. Returns a
/// JSON body with the diff summary on success, or an error on failure.
///
/// Loopback-only via `require_loopback`, same as `kill_handler` /
/// `resume_handler`. The compile runs on `spawn_blocking` to avoid
/// blocking the async runtime with filesystem IO. On failure the
/// active `PolicySet` is NOT swapped.
///
/// Story 8.7 concurrency invariant: the config-swap section
/// (`DaemonConfig::load` → `approval_timeout_atomic.store` →
/// `config_state.store`) runs under `reload_mutex` so that two
/// concurrent reloaders (SIGHUP + HTTP, or two HTTP POSTs) can't
/// interleave and leave `config_state` paired with a mismatched
/// `approval_timeout_atomic`. SIGHUP's `reload_loop` wraps the same
/// section under the same mutex.
///
/// On success, a `policy-reloaded` audit event is written (best-effort)
/// via the shared `write_reload_audit_event` helper.
pub(crate) async fn reload_handler(
    State(state): State<ControlState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: axum::http::Request<axum::body::Body>,
) -> Response {
    if let Err(e) = require_loopback(addr) {
        return e.into_response();
    }

    // Story 8.7 review patch (LOW): thread the current RequestId into
    // `detect_stub_and_warn` so the `config-reload-stub-detected`
    // audit event is grep-correlatable with this HTTP reload call.
    // `RequestTraceLayer` (applied on the control router) inserts
    // `RequestId` into request extensions.
    let request_id =
        request.extensions().get::<permitlayer_proxy::error::RequestId>().map(|r| r.0.clone());

    // Story 8.7 review patch (MEDIUM): re-read DaemonConfig, clamp
    // approval_timeout, and swap both the atomic and `config_state`
    // under `reload_mutex`. This matches SIGHUP's serialization
    // discipline — the atomic + config_state pair is never torn.
    //
    // `std::sync::Mutex` (not `tokio::sync::Mutex`) is the right tool
    // here: the critical section does a short DaemonConfig::load +
    // two atomic stores + one ArcSwap store, all sync work with zero
    // `.await` points.
    let config_reload_error: Option<String> = {
        let _guard = state.reload_mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match crate::config::DaemonConfig::load(&state.cli_overrides) {
            Ok(new_config) => {
                let raw = new_config.approval.timeout_seconds;
                let clamped = crate::cli::start::clamp_approval_timeout_seconds(raw);
                if raw != clamped {
                    // Story 8.7 review patch (MEDIUM): mirror the
                    // startup warn so operators see the clamp on
                    // reload, not just at boot.
                    tracing::warn!(
                        configured = raw,
                        clamped = clamped,
                        "approval.timeout_seconds out of range [1,300]; clamping"
                    );
                }
                state.approval_timeout_atomic.store(clamped, Ordering::Relaxed);
                tracing::info!(
                    new_timeout_seconds = clamped,
                    "approval timeout updated via reload"
                );
                state.config_state.store(Arc::new(new_config));
                tracing::info!("configuration reloaded via control endpoint");
                None
            }
            Err(e) => {
                // Non-fatal: keep previous config, continue with
                // policy reload, but surface the error in the HTTP
                // response so the operator isn't misled.
                let msg = format!("{e}");
                tracing::error!(
                    "config reload via control endpoint failed, keeping previous config: {msg}"
                );
                Some(msg)
            }
        }
    };

    // Story 4.5: clear the approval-service always/never caches
    // BEFORE the ArcSwap policy swap. See sighup.rs for the full
    // rationale (race window + failed-reload semantics). Done outside
    // the spawn_blocking so it happens unconditionally regardless of
    // reload success.
    state.approval_service.clear_caches();
    tracing::info!("approval service caches cleared on reload (pre-swap)");

    let ps = Arc::clone(&state.policy_set);
    let dir = state.policies_dir.clone();
    let mtx = Arc::clone(&state.reload_mutex);

    let result = tokio::task::spawn_blocking(move || {
        super::sighup::reload_policies_with_diff_locked(&ps, &dir, &mtx)
    })
    .await;

    // Story 7.32: HTTP reload now shares the SIGHUP activation path.
    // If credentials appeared after a stub-only boot, promote the
    // swappable route slots to a real ProxyService; warn only when a
    // rebuild was attempted and still failed.
    activate_proxy_routes_if_ready(&state, request_id, "control-reload").await;

    match result {
        Ok(Ok(diff)) => {
            tracing::info!(
                policies_loaded = diff.policies_loaded,
                added = diff.added.len(),
                modified = diff.modified.len(),
                unchanged = diff.unchanged.len(),
                removed = diff.removed.len(),
                "policies reloaded via control endpoint"
            );

            // Best-effort audit event.
            super::sighup::write_reload_audit_event(state.audit_store.as_ref(), &diff).await;

            // Story 4.4: also reload the agent registry. A failure
            // here logs a warn but does NOT fail the reload — the two
            // hot-swaps are independent.
            let agents_loaded = if let Some(store) = &state.agent_store {
                match store.list().await {
                    Ok(agents) => state.agent_registry.replace_with(agents),
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "agent registry reload failed during /v1/control/reload — keeping existing snapshot"
                        );
                        state.agent_registry.len()
                    }
                }
            } else {
                state.agent_registry.len()
            };

            // Story 8.7 review patch (MEDIUM): include the config-
            // reload error (if any) in the 200 response body so the
            // operator knows the policy reload succeeded while the
            // config edit was dropped.
            let policy_scan_path = state.policies_dir.display().to_string();
            let policy_scan_empty_warning = if state.policies_dir.exists()
                && state.policies_dir.is_dir()
                && diff.policies_loaded == 0
            {
                Some(format!(
                    "policy directory {} exists but contains no candidate policy files",
                    policy_scan_path
                ))
            } else {
                None
            };
            let body = ReloadResponse {
                status: "ok",
                policies_loaded: diff.policies_loaded,
                added: diff.added.len(),
                modified: diff.modified.len(),
                unchanged: diff.unchanged.len(),
                removed: diff.removed.len(),
                agents_loaded,
                policy_scan_path,
            };
            let extras = ReloadResponseExtras { config_reload_error, policy_scan_empty_warning };
            (StatusCode::OK, Json(merge_reload_response(body, extras))).into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("policy reload failed via control endpoint: {e}");
            (
                StatusCode::BAD_REQUEST,
                Json(ReloadErrorResponse { status: "error", message: format!("{e}") }),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("policy reload task panicked: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ReloadErrorResponse {
                    status: "error",
                    message: "internal error during policy reload".to_owned(),
                }),
            )
                .into_response()
        }
    }
}

async fn activate_proxy_routes_if_ready(
    state: &ControlState,
    request_id: Option<String>,
    surface: &'static str,
) -> bool {
    if !state.proxy_stub_branch_active.load(Ordering::Relaxed) {
        return false;
    }

    match crate::cli::start::vault_has_sealed_credentials(&state.vault_dir) {
        Ok(false) => return false,
        Ok(true) => {}
        Err(e) => {
            tracing::debug!(
                vault_dir = %state.vault_dir.display(),
                error = %e,
                surface,
                "proxy activation: vault credential probe failed; attempting rebuild"
            );
        }
    }

    let cfg = state.config_state.load_full();
    let proxy = crate::cli::start::try_build_proxy_service(
        &cfg,
        state.proxy_activation.scrub_engine.as_ref(),
        state.proxy_activation.audit_store.as_ref(),
        &state.proxy_activation.master_key,
        Arc::clone(&state.proxy_activation.vault),
    )
    .await;

    if let Some(proxy) = proxy {
        if state
            .proxy_stub_branch_active
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        state.proxy_activation.routes.activate(proxy);
        tracing::info!(
            surface,
            "proxy service activated via reload -- MCP and REST routes now live"
        );
        true
    } else {
        super::sighup::detect_stub_and_warn(
            &state.vault_dir,
            state.audit_store.as_ref(),
            &state.proxy_stub_branch_active,
            request_id,
        )
        .await;
        false
    }
}

/// Merge `ReloadResponse` with `ReloadResponseExtras` into a single
/// `serde_json::Value` so the wire body stays flat (not nested under
/// `"extras"`). Keeps backward-compatibility for existing clients that
/// only read the `ReloadResponse` fields while making
/// `config_reload_error` a first-class top-level field.
fn merge_reload_response(body: ReloadResponse, extras: ReloadResponseExtras) -> serde_json::Value {
    // serde guarantees these flatten to `Object(_)` for our structs.
    let mut body_json = serde_json::to_value(body).unwrap_or(serde_json::Value::Null);
    let extras_json = serde_json::to_value(extras).unwrap_or(serde_json::Value::Null);
    if let (Some(body_obj), Some(extras_obj)) = (body_json.as_object_mut(), extras_json.as_object())
    {
        for (k, v) in extras_obj {
            body_obj.insert(k.clone(), v.clone());
        }
    }
    body_json
}

// --------------------------------------------------------------------------
// Agent identity handlers (Story 4.4).
// --------------------------------------------------------------------------

/// Inbound JSON body for `POST /v1/control/agent/register`.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct RegisterAgentRequest {
    pub name: String,
    pub policy_name: String,
}

/// Response body for a successful `POST /v1/control/agent/register`.
///
/// `bearer_token` carries the freshly minted plaintext token. This is
/// the ONLY surface (anywhere in the daemon) where token plaintext
/// crosses the loopback wire — the agent file holds only the Argon2id
/// hash and the HMAC lookup key. The CLI displays the token to the
/// operator once and discards it; no plaintext exists anywhere after
/// that point.
#[derive(Debug, serde::Serialize)]
pub(crate) struct RegisterAgentResponse {
    pub status: &'static str,
    pub name: String,
    pub policy_name: String,
    pub bearer_token: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_uid: Option<u32>,
    /// Story 7.27 AC #8: when the request came over the UDS
    /// control listener, the daemon writes the plaintext bearer
    /// token to `<home>/.agentsso/agent-bearer.token`. If that
    /// write fails (e.g., parent dir is a symlink), the agent is
    /// still registered successfully — this field carries the
    /// per-user-file failure message so the calling CLI can
    /// surface a partial-success warning to the operator. `None`
    /// on the happy path AND on TCP-served requests (which don't
    /// have a kernel-attested peer to write the file for).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bearer_token_file: Option<BearerTokenFileWriteResult>,
}

/// Per-user `agent-bearer.token` file write result, surfaced in
/// `RegisterAgentResponse::bearer_token_file`. `Ok` carries the
/// path the daemon wrote to; `Err` carries the error message so
/// the operator can take corrective action.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
// Constructed only inside `#[cfg(target_os = "macos")]` (the per-user
// file-write path lives behind peer-credential attestation, which is
// macOS UDS-only); on Linux + Windows the variants are dead but the
// type must stay cross-platform because `RegisterAgentResponse` carries
// `Option<Self>` unconditionally.
#[allow(dead_code)]
pub(crate) enum BearerTokenFileWriteResult {
    Written { path: String, replace_existing: bool },
    Failed { message: String },
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct AgentSummary {
    pub name: String,
    pub policy_name: String,
    pub created_at: String,
    pub last_seen_at: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct ListAgentsResponse {
    pub status: &'static str,
    pub agents: Vec<AgentSummary>,
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct RemoveAgentRequest {
    pub name: String,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct RemoveAgentResponse {
    pub status: &'static str,
    pub name: String,
    pub removed: bool,
}

/// Inbound JSON body for `POST /v1/control/agent/rebind` (Story 7.11).
#[derive(Debug, serde::Deserialize)]
pub(crate) struct RebindAgentRequest {
    pub name: String,
    pub policy_name: String,
}

/// Response body for `POST /v1/control/agent/rebind` (Story 7.11).
///
/// **CRITICAL INVARIANT:** This response MUST NOT include any
/// bearer-token-bearing field. The bearer token is unchanged across
/// rebind by design (architecture.md §"Authentication & Security" →
/// "Bearer token immutability across policy rebind"); re-disclosing
/// it here would defeat the invariant. The response uses the
/// `AgentSummary` shape (no `bearer_token` field) and is asserted
/// in `rebind_handler_response_does_not_include_bearer_token`.
#[derive(Debug, serde::Serialize)]
pub(crate) struct RebindAgentResponse {
    pub status: &'static str,
    pub agent: AgentSummary,
}

/// Response body for `POST /v1/control/agent/{name}/rotate` (Story 7.34).
///
/// Includes the new plaintext bearer token — the operator MUST copy it
/// immediately because it cannot be retrieved later.
#[derive(Debug, serde::Serialize)]
pub(crate) struct RotateAgentResponse {
    pub status: &'static str,
    pub name: String,
    pub bearer_token: String,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct AgentErrorResponse {
    pub status: &'static str,
    pub code: &'static str,
    pub message: String,
    /// Echoed from the `RequestId` extension stamped by
    /// `RequestTraceLayer` so operators can grep-correlate a failed
    /// control-plane response with the daemon's tracing log and the
    /// audit stream. `None` on early-path errors that fire before the
    /// request_id is known (e.g., the non-loopback 403). Serialized
    /// only when present to keep the happy-path payload stable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// `POST /v1/control/agent/register` — mint a fresh bearer token, hash
/// it, persist the agent file, and atomically swap the registry.
///
/// Loopback-only via `require_loopback`. Audit-emitting via
/// `agent-registered`. Refuses to mint a token when (a) the agent
/// store is unavailable, (b) the policy doesn't exist, or (c) the
/// agent name is already registered.
///
/// Story 1.15 removed the "HMAC subkey is the zero placeholder"
/// guard: the master key is now eagerly bootstrapped at daemon
/// start, so `agent_lookup_key` is always a real HMAC derivation
/// by the time this handler runs. The 503 `agent.no_master_key`
/// error code is deleted alongside it.
pub(crate) async fn register_agent_handler(
    State(state): State<ControlState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
) -> Response {
    if let Err(e) = require_loopback(peer) {
        return e.into_response();
    }

    let request_id = read_request_id(&req);

    // Story 7.27 AC #6 + #8: snapshot kernel-attested peer
    // credentials (injected by
    // `server::control_listener::record_peer_credentials_layer` on
    // the macOS UDS serve path) BEFORE the request body is
    // consumed. On TCP-served requests (Linux/Windows or pre-
    // 7.27 macOS fallback) the extension is absent and the
    // per-user token-write step is skipped.
    //
    // The value is `Copy` (`PeerCredentials { uid, gid }`) so we
    // dereference + copy out immediately, releasing the borrow on
    // `req.extensions()` before the body-consumption step.
    #[cfg(target_os = "macos")]
    let _peer_creds_for_register: Option<crate::server::PeerCredentials> =
        req.extensions().get::<crate::server::PeerCredentials>().copied();
    // Audit-emit peer creds snapshot (cross-platform, always None on TCP).
    let _peer_creds_for_audit: Option<crate::server::PeerCredentials> = {
        #[cfg(target_os = "macos")]
        {
            _peer_creds_for_register
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    };

    // Rate-limit concurrent agent CRUD. `try_acquire_owned` returns
    // immediately with an error when the semaphore is exhausted rather
    // than queueing the request — a flood of register calls returns
    // 429 instead of piling up on the blocking thread pool. See Story
    // 4.4 code-review HIGH finding "No rate limit on register_agent_handler."
    let _permit = match state.agent_crud_semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return agent_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "agent.rate_limited",
                format!(
                    "too many concurrent agent CRUD operations in flight \
                     (max {AGENT_CRUD_MAX_CONCURRENT}); retry shortly"
                ),
                Some(request_id.clone()),
            );
        }
    };

    // Parse JSON body. axum's State extractor consumed `req` already
    // for the request_id read; we need a fresh body extraction.
    let (_parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, 64 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return agent_error_response(
                StatusCode::BAD_REQUEST,
                "agent.bad_request",
                format!("failed to read request body: {e}"),
                Some(request_id.clone()),
            );
        }
    };
    let payload: RegisterAgentRequest = match serde_json::from_slice(&bytes) {
        Ok(p) => p,
        Err(e) => {
            return agent_error_response(
                StatusCode::BAD_REQUEST,
                "agent.bad_request",
                format!("invalid JSON body: {e}"),
                Some(request_id.clone()),
            );
        }
    };

    // 1. Validate the agent name.
    if let Err(e) = validate_agent_name(&payload.name) {
        return agent_error_response(
            StatusCode::BAD_REQUEST,
            "agent.invalid_name",
            format!("{e}"),
            Some(request_id.clone()),
        );
    }

    // 2. Verify the policy exists in the active set.
    {
        let snapshot = state.policy_set.load();
        if snapshot.get(&payload.policy_name).is_none() {
            let known: Vec<String> = snapshot.policy_names();
            let known_str =
                if known.is_empty() { "(none registered)".to_owned() } else { known.join(", ") };
            return agent_error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "agent.unknown_policy",
                format!("policy '{}' not found. Known policies: {known_str}", payload.policy_name),
                Some(request_id.clone()),
            );
        }
    }

    // 3. Verify the registry runtime is operational.
    //
    // Story 1.15 deleted the `agent_lookup_key == [0u8; 32]` check:
    // the master key is now eagerly bootstrapped at daemon start, so
    // `agent_lookup_key` is always a real HMAC derivation by the
    // time this handler runs. A failure would be a keystore failure
    // at boot, which is now fatal (`exit(2)`) — the daemon never
    // reaches this handler in a half-provisioned state.
    let Some(store) = state.agent_store.clone() else {
        return agent_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "agent.store_unavailable",
            "agent identity store is unavailable — check ~/.agentsso/agents/ permissions"
                .to_owned(),
            Some(request_id.clone()),
        );
    };

    // 4. Generate the plaintext token + derived material.
    //
    // Story 7.6b: bearer tokens are now `agt_v2_<name>_<random>` so
    // the auth path can parse the agent name from the prefix and look
    // up the agent in O(1) keyed by HMAC(daemon_subkey, name).
    // Before 7.6b: `agt_v1_<random>` plus a global Argon2id sweep.
    let raw_bytes = generate_bearer_token_bytes();
    let plaintext_body = base64_url_no_pad(&raw_bytes);
    let bearer_token = format!("{BEARER_TOKEN_PREFIX}{}_{plaintext_body}", payload.name);
    // Argon2id hashing is a ~100ms CPU burn — bounce it off the
    // blocking pool so the tokio worker thread isn't stalled for the
    // duration. The plaintext bytes are cloned into a Vec<u8> so the
    // closure can own them across the `await`. Story 4.4 review fix.
    let token_bytes = bearer_token.as_bytes().to_vec();
    let token_hash = match tokio::task::spawn_blocking(move || hash_token(&token_bytes)).await {
        Ok(Ok(hash)) => hash,
        Ok(Err(e)) => {
            tracing::error!(error = %e, "Argon2id hash_token failed during register");
            return agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "agent.internal",
                "failed to hash bearer token".to_owned(),
                Some(request_id.clone()),
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "spawn_blocking for hash_token panicked");
            return agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "agent.internal",
                "internal error hashing bearer token".to_owned(),
                Some(request_id.clone()),
            );
        }
    };
    // Story 7.6b: HMAC message is the agent name, NOT the full
    // bearer token. The auth path parses the name from the v2 token
    // prefix and computes the same HMAC to hit the registry index.
    let lookup_key = compute_lookup_key(&state.agent_lookup_key, payload.name.as_bytes());
    let lookup_key_hex = lookup_key_to_hex(&lookup_key);

    let created_at = chrono::Utc::now();
    let identity = match AgentIdentity::new(
        payload.name.clone(),
        payload.policy_name.clone(),
        token_hash,
        lookup_key_hex,
        created_at,
        None,
    ) {
        Ok(id) => id,
        Err(e) => {
            return agent_error_response(
                StatusCode::BAD_REQUEST,
                "agent.invalid_name",
                format!("{e}"),
                Some(request_id.clone()),
            );
        }
    };

    // 5. Persist + reload registry. Duplicate-name returns 409.
    if let Err(e) = store.put(identity.clone()).await {
        use permitlayer_core::store::StoreError;
        return match e {
            StoreError::AgentAlreadyExists { name } => agent_error_response(
                StatusCode::CONFLICT,
                "agent.duplicate_name",
                format!(
                    "agent '{name}' is already registered. Run `agentsso agent remove {name}` first."
                ),
                Some(request_id.clone()),
            ),
            other => agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "agent.persist_failed",
                format!("{other}"),
                Some(request_id.clone()),
            ),
        };
    }

    // Atomic registry swap from disk so the new agent is visible to
    // every subsequent auth request.
    //
    // Story 4.4 review fix: a failing `list()` here is NOT best-effort.
    // The agent file is already on disk, but the in-memory registry
    // snapshot doesn't know about it — which means the freshly minted
    // bearer token would 401 on first use. Returning 200 with an
    // unusable token is worse than failing loudly. Attempt to roll
    // back the write (so the operator can retry cleanly) and return
    // 500 with `agent.registry_reload_failed`.
    //
    // Story 7.11 review-round-2 Q4: serialize the [list + replace_with]
    // pair across all CRUD handlers via `agent_registry_reload_lock`.
    // The agent_crud_semaphore (capacity 4) caps concurrent CRUD
    // throughput but does NOT prevent two successful mutations from
    // racing on the registry-reload step. Without this lock, A's
    // `list()` could resolve AFTER B's `list()` (B mutated more
    // recently) but A's `replace_with()` could land BEFORE B's,
    // snapshotting A's earlier view OVER B's later mutation. The
    // lock is held only for the brief list+swap; mutations themselves
    // are NOT serialized through it (they run under the per-name
    // store-level lock instead).
    //
    // Story 7.11 review-round-3 #5: scope the reload_lock to JUST
    // the list+swap pair via a `{ ... }` block. Holding it across
    // audit append + JSON serialization throttles parallel CRUD
    // unnecessarily. Inside the block we capture the result; the
    // error-handling path (rollback + 500 response) runs AFTER the
    // lock releases, which is correct: the on-disk file is the
    // authority, and the rollback just needs the per-name lock
    // (acquired internally by `store.remove`).
    let reload_result = {
        let _reload_lock = state.agent_registry_reload_lock.lock().await;
        store.list().await.map(|agents| state.agent_registry.replace_with(agents))
    };
    if let Err(e) = reload_result {
        tracing::error!(
            error = %e,
            agent_name = identity.name(),
            "agent registry reload after register failed — attempting rollback of on-disk write",
        );
        if let Err(rollback_err) = store.remove(identity.name()).await {
            tracing::warn!(
                error = %rollback_err,
                agent_name = identity.name(),
                "rollback of agent file after failed registry reload did not complete — manual cleanup required",
            );
        }
        return agent_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "agent.registry_reload_failed",
            "agent was written to disk but registry reload failed; attempted rollback".to_owned(),
            Some(request_id.clone()),
        );
    }

    // 6. Audit event (best-effort).
    //
    // Story 4.4 review fix (B7): use the `scope="-", resource=<action>`
    // convention shared with `kill-blocked-request` (in
    // `permitlayer-proxy::middleware::kill`) and `agent-auth-denied`
    // (in `permitlayer-proxy::middleware::auth`). The positional
    // signature of `AuditEvent::with_request_id` is
    // (request_id, agent_id, service, scope, resource, outcome, event_type).
    if let Some(audit) = &state.audit_store {
        let mut event = AuditEvent::with_request_id(
            request_id.clone(),
            payload.name.clone(),
            "permitlayer".to_owned(),
            "-".to_owned(),
            "agent-register".to_owned(),
            "ok".to_owned(),
            "agent-registered".to_owned(),
        );
        event.extra = serde_json::json!({
            "policy_name": payload.policy_name,
            "created_at": format_audit_timestamp(created_at),
        });
        enrich_audit_extra_with_peer_creds(&mut event.extra, _peer_creds_for_audit);
        if let Err(e) = audit.append(event).await {
            tracing::warn!(error = %e, "agent-registered audit write failed (best-effort)");
        }
    }

    tracing::info!(
        target: "control",
        request_id = %request_id,
        agent_name = %payload.name,
        policy_name = %payload.policy_name,
        "agent registered via control endpoint"
    );

    // Story 7.27 AC #6 + #8 + #14: when the request came over the
    // UDS control listener, the daemon writes the plaintext bearer
    // token to the kernel-attested peer's
    // `<home>/.agentsso/agent-bearer.token` using the
    // tmp+chown+fchmod+renameatx_np(RENAME_EXCL)+O_NOFOLLOW pattern.
    // The peer credentials are injected into request extensions by
    // `server::control_listener::record_peer_credentials_layer` on
    // the UDS serve path; TCP-served requests (the rc.21 fallback
    // on non-macOS) have no extension, so we skip the per-user
    // file write. The agent registration itself has already
    // committed by this point — a token-write failure is logged +
    // surfaced as a partial-success response field but does NOT
    // undo the registration (the operator can re-run register to
    // retry the token-write step idempotently).
    #[cfg(target_os = "macos")]
    let bearer_token_file: Option<BearerTokenFileWriteResult> = {
        if let Some(creds) = _peer_creds_for_register {
            // Story 7.27 Round-2 review fix (P2): wrap the
            // bearer-token byte buffer in `Zeroizing` so the
            // plaintext is scrubbed when this scope exits, mirroring
            // the discipline used elsewhere in the daemon for
            // master-key bytes. Pre-fix, the `Vec<u8>` would survive
            // until allocator reuse, leaving plaintext token
            // fragments on the heap.
            let token_bytes: zeroize::Zeroizing<Vec<u8>> =
                zeroize::Zeroizing::new(bearer_token.clone().into_bytes());
            let state_dir = permitlayer_core::paths::daemon_state_dir(
                permitlayer_core::paths::home_override().as_deref(),
            );
            match crate::server::agent_token::write_bearer_token_to_user_home(
                &token_bytes,
                creds.uid,
                creds.gid,
                &state_dir,
            )
            .await
            {
                Ok(outcome) => {
                    tracing::info!(
                        target: "control",
                        request_id = %request_id,
                        peer_uid = creds.uid,
                        target = %outcome.target_path.display(),
                        replace_existing = outcome.replace_existing,
                        "bearer-token written to per-user file"
                    );
                    if let Some(audit) = &state.audit_store {
                        let event_type = if outcome.replace_existing {
                            "bearer-token-replaced"
                        } else {
                            "bearer-token-written"
                        };
                        let mut event = AuditEvent::with_request_id(
                            request_id.clone(),
                            payload.name.clone(),
                            "permitlayer".to_owned(),
                            "-".to_owned(),
                            "agent-bearer-token".to_owned(),
                            "ok".to_owned(),
                            event_type.to_owned(),
                        );
                        event.extra = serde_json::json!({
                            "peer_uid": creds.uid,
                            "peer_gid": creds.gid,
                            "target_path": outcome.target_path.to_string_lossy(),
                            "replace_existing": outcome.replace_existing,
                        });
                        if let Err(e) = audit.append(event).await {
                            tracing::warn!(error = %e, "bearer-token audit write failed (best-effort)");
                        }
                    }
                    Some(BearerTokenFileWriteResult::Written {
                        path: outcome.target_path.to_string_lossy().into_owned(),
                        replace_existing: outcome.replace_existing,
                    })
                }
                Err(e) => {
                    let symlink_attack = matches!(
                        e,
                        crate::server::agent_token::TokenWriteError::SymlinkInParentPath(_)
                    );
                    tracing::warn!(
                        target: "control",
                        request_id = %request_id,
                        peer_uid = creds.uid,
                        error = %e,
                        symlink_attack,
                        "bearer-token write to per-user file failed (partial success)"
                    );
                    if let Some(audit) = &state.audit_store {
                        let event_type = if symlink_attack {
                            "bearer-token-symlink-attack-blocked"
                        } else {
                            "bearer-token-write-failed"
                        };
                        let mut event = AuditEvent::with_request_id(
                            request_id.clone(),
                            payload.name.clone(),
                            "permitlayer".to_owned(),
                            "-".to_owned(),
                            "agent-bearer-token".to_owned(),
                            "error".to_owned(),
                            event_type.to_owned(),
                        );
                        event.extra = serde_json::json!({
                            "peer_uid": creds.uid,
                            "peer_gid": creds.gid,
                            "error": e.to_string(),
                        });
                        if let Err(audit_err) = audit.append(event).await {
                            tracing::warn!(error = %audit_err, "audit append failed (best-effort)");
                        }
                    }
                    Some(BearerTokenFileWriteResult::Failed {
                        message: format!("bearer-token file write failed: {e}"),
                    })
                }
            }
        } else {
            None
        }
    };
    #[cfg(not(target_os = "macos"))]
    let bearer_token_file: Option<BearerTokenFileWriteResult> = None;

    let body = RegisterAgentResponse {
        status: "ok",
        name: payload.name,
        policy_name: payload.policy_name,
        bearer_token,
        created_at: format_audit_timestamp(created_at),
        peer_uid: _peer_creds_for_audit.map(|creds| creds.uid),
        bearer_token_file,
    };
    (StatusCode::OK, Json(body)).into_response()
}

/// `GET /v1/control/agent/list` — return every registered agent.
///
/// Output is sorted by name. NEVER includes the bearer token plaintext
/// or the on-disk hash — only the metadata fields the operator needs
/// to identify and audit each agent.
pub(crate) async fn list_agents_handler(
    State(state): State<ControlState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
) -> Response {
    if let Err(e) = require_loopback(peer) {
        return e.into_response();
    }

    let request_id = read_request_id(&req);

    // Fail-fast when the agent store is unavailable instead of
    // returning an empty list that is indistinguishable from "no
    // agents registered yet." Without this, operators staring at an
    // empty `agentsso agent list` have no way to tell whether their
    // registry is broken or simply empty — see Story 4.4 review MED
    // finding "list_agents swallows agent_store=None vs empty snapshot."
    if state.agent_store.is_none() {
        return agent_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "agent.store_unavailable",
            "agent identity store is unavailable; check the daemon startup logs \
             for 'agent registry unavailable' — the registry may have failed to \
             load. Run `agentsso setup <service>` if the master key has not yet \
             been provisioned."
                .to_owned(),
            Some(request_id),
        );
    }

    let snapshot = state.agent_registry.snapshot();
    let agents: Vec<AgentSummary> = snapshot
        .agents_sorted()
        .into_iter()
        .map(|a| AgentSummary {
            name: a.name().to_owned(),
            policy_name: a.policy_name.clone(),
            created_at: format_audit_timestamp(a.created_at),
            last_seen_at: a.last_seen_at.map(format_audit_timestamp),
        })
        .collect();

    (StatusCode::OK, Json(ListAgentsResponse { status: "ok", agents })).into_response()
}

/// Response body for `GET /v1/control/agent/{name}/policy_name`
/// (Story 7.30 AC #1).
#[derive(Debug, Serialize)]
pub(crate) struct AgentPolicyNameResponse {
    pub name: String,
    pub policy_name: String,
}

/// `GET /v1/control/agent/{name}/policy_name` — return the policy
/// binding for a single agent (Story 7.30 AC #1).
///
/// The CLI's `agentsso connect` flow needs to resolve an agent's
/// policy name early so it can update the policy's scope set later in
/// the same flow. Before Story 7.30 the CLI opened the agent store
/// directly; now the daemon owns every fs touch, so this read-only
/// lookup moves daemon-side.
///
/// No audit event — read-only lookup matches the `list_agents_handler`
/// precedent. Operator-callable.
pub(crate) async fn agent_policy_name_handler(
    State(state): State<ControlState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(name): Path<String>,
    req: axum::extract::Request,
) -> Response {
    if let Err(e) = require_loopback(peer) {
        return e.into_response();
    }

    let request_id = read_request_id(&req);

    if let Err(e) = validate_agent_name(&name) {
        return agent_error_response(
            StatusCode::BAD_REQUEST,
            "agent.invalid_name",
            format!("{e}"),
            Some(request_id),
        );
    }

    let Some(store) = state.agent_store.clone() else {
        return agent_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "agent.store_unavailable",
            "agent identity store is unavailable; check the daemon startup logs \
             for 'agent registry unavailable' — the registry may have failed to \
             load."
                .to_owned(),
            Some(request_id),
        );
    };

    match store.get(&name).await {
        Ok(Some(identity)) => {
            // Round-1 review P21: cross-check that the agent's bound
            // policy still exists in the active set. If the policy was
            // removed from disk between agent registration and this
            // lookup, the CLI would otherwise POST to
            // `/policy/<dangling>/scopes` and get 404 `policy.not_found`
            // — two round-trips to discover the inconsistency. A 422
            // here with `agent.dangling_policy_binding` points the
            // operator at the right next step (`agent rebind`) one
            // call earlier.
            let snapshot = state.policy_set.load();
            if snapshot.get(&identity.policy_name).is_none() {
                return agent_error_response(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "agent.dangling_policy_binding",
                    format!(
                        "agent {name:?} is bound to policy {:?} which is not in the \
                         active policy set. Either restore the policy file and run \
                         `agentsso reload`, or rebind the agent: \
                         `agentsso agent rebind {name} --policy <new-policy>`.",
                        identity.policy_name
                    ),
                    Some(request_id),
                );
            }
            (
                StatusCode::OK,
                Json(AgentPolicyNameResponse {
                    name: identity.name().to_owned(),
                    policy_name: identity.policy_name.clone(),
                }),
            )
                .into_response()
        }
        Ok(None) => agent_error_response(
            StatusCode::NOT_FOUND,
            "agent.not_found",
            format!("no agent with name {name:?}"),
            Some(request_id),
        ),
        Err(e) => agent_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "agent.store_io_failed",
            format!("agent store read failed: {e}"),
            Some(request_id),
        ),
    }
}

/// Service set the credential endpoints accept (Story 7.30 AC #2
/// + #3). Mirrors `crates/permitlayer-daemon/src/cli/connect.rs::SUPPORTED_SERVICES`;
///   kept private until Task 12 deduplicates the constant.
pub(crate) const CREDENTIAL_SUPPORTED_SERVICES: &[&str] = &["gmail", "calendar", "drive"];

fn credential_service_supported(service: &str) -> bool {
    CREDENTIAL_SUPPORTED_SERVICES.contains(&service)
}

/// Response body for `GET /v1/control/credentials/{service}/meta`
/// (Story 7.30 AC #2).
///
/// Both branches (existing / not-existing) return HTTP 200 with a
/// boolean discriminator. This is deliberate: the CLI's idempotent
/// re-run branch is a single JSON-parse path, no special-casing 404.
#[derive(Debug, Serialize)]
pub(crate) struct CredentialMetaResponse {
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<permitlayer_oauth::metadata::CredentialMeta>,
}

/// `GET /v1/control/credentials/{service}/meta` — return the
/// `CredentialMeta` for a sealed credential, or `{ "exists": false }`
/// when none exists (Story 7.30 AC #2).
///
/// Reads `{state.vault_dir}/{service}-meta.json` via blocking-pool
/// tokio. No audit event — read-only, frequently polled during the
/// CLI's idempotent re-run check. Operator-callable.
pub(crate) async fn credentials_meta_handler(
    State(state): State<ControlState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(service): Path<String>,
    req: axum::extract::Request,
) -> Response {
    if let Err(e) = require_loopback(peer) {
        return e.into_response();
    }

    let request_id = read_request_id(&req);

    if !credential_service_supported(&service) {
        return agent_error_response(
            StatusCode::BAD_REQUEST,
            "credentials.unknown_service",
            format!(
                "service {:?} is not supported; allowed: {}",
                service,
                CREDENTIAL_SUPPORTED_SERVICES.join(", ")
            ),
            Some(request_id),
        );
    }

    let meta_path = state.vault_dir.join(format!("{service}-meta.json"));
    let read_result =
        tokio::task::spawn_blocking(move || std::fs::read_to_string(&meta_path)).await;

    let raw = match read_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return (StatusCode::OK, Json(CredentialMetaResponse { exists: false, meta: None }))
                .into_response();
        }
        Ok(Err(e)) => {
            return agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "credentials.meta_io_failed",
                format!("could not read {service} meta file: {e}"),
                Some(request_id),
            );
        }
        Err(e) => {
            return agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "credentials.meta_join_failed",
                format!("blocking task join failed: {e}"),
                Some(request_id),
            );
        }
    };

    match serde_json::from_str::<permitlayer_oauth::metadata::CredentialMeta>(&raw) {
        Ok(meta) => {
            (StatusCode::OK, Json(CredentialMetaResponse { exists: true, meta: Some(meta) }))
                .into_response()
        }
        Err(e) => agent_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "credentials.meta_parse_failed",
            format!("could not parse {service} meta file: {e}"),
            Some(request_id),
        ),
    }
}

/// Policy for the seal endpoint's `if_exists` field (Story 7.30 AC #3).
///
/// **Round-1 review fix:** spec line 57 named `replace` as the
/// default; review re-classified that as a data-destruction footgun if
/// a CLI bug ever drops the field. Fail-safe default `Error` returns
/// 409 instead of silently overwriting; the CLI's production path
/// always sets `if_exists: "replace"` explicitly so this is moot for
/// the seal-via-connect flow but tightens future API surface against
/// accidental overwrites.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SealIfExists {
    /// Replace the existing credential atomically.
    Replace,
    /// Skip writing if a credential already exists for this service.
    Skip,
    /// Return 409 if a credential already exists. Default (fail-safe).
    #[default]
    Error,
}

/// Request body for `POST /v1/control/credentials/seal` (Story 7.30 AC #3).
///
/// Token fields use `Zeroizing<String>` (zeroize 1.8 `serde` feature
/// added in Task 1, sourced from RustCrypto/utils
/// `zeroize/src/lib.rs:568-580`'s `Deserialize for Zeroizing<T>`
/// impl). When the handler scope exits, `Zeroizing`'s `Drop` calls
/// `String::zeroize` which writes zeros over the full `Vec<u8>`
/// capacity backing the String before the allocator frees it
/// (`zeroize/src/lib.rs:524-528`). The plaintext window per request
/// is documented in ADR-0007 (authored in Task 13).
#[derive(Debug, Deserialize)]
pub(crate) struct CredentialsSealRequest {
    pub service: String,
    pub agent: String,
    pub access_token: zeroize::Zeroizing<String>,
    #[serde(default)]
    pub refresh_token: Option<zeroize::Zeroizing<String>>,
    pub granted_scopes: Vec<String>,
    pub client_type: String,
    pub client_source: String,
    #[serde(default)]
    pub expires_in_secs: Option<u64>,
    #[serde(default)]
    pub if_exists: SealIfExists,
}

/// Response body for `POST /v1/control/credentials/seal`.
#[derive(Debug, Serialize)]
pub(crate) struct CredentialsSealResponse {
    pub sealed: bool,
    pub replaced_previous: bool,
    pub meta: permitlayer_oauth::metadata::CredentialMeta,
}

/// `POST /v1/control/credentials/seal` — atomically seal OAuth tokens
/// into the daemon's vault, write the provenance meta JSON, and emit
/// an audit event (Story 7.30 AC #3).
///
/// The CLI's `agentsso connect` flow drives the operator-interactive
/// OAuth dance, then POSTs the resulting tokens to this endpoint. The
/// daemon owns every fs touch + every vault-key access; the CLI never
/// reads the master key, never touches `vault/`, never writes
/// `*-meta.json`.
///
/// **Concurrency (round-1 review P2 + P7):**
/// - `state.credentials_seal_semaphore` caps concurrent seal operations
///   across all services at `CREDENTIALS_SEAL_MAX_CONCURRENT` (matches
///   `agent_crud_semaphore` discipline).
/// - `state.credentials_seal_locks` provides a per-service
///   `Arc<Mutex<()>>` so two concurrent seals of the SAME service
///   serialize, while disjoint services (gmail + drive) run in
///   parallel.
///
/// **Write order (round-1 review P1):** the meta JSON is the
/// "credential exists" sentinel for downstream readers
/// (`credentials_meta_handler`, the idempotent re-run check). To
/// avoid orphan sealed envelopes after a partial write, on failure
/// of any post-seal step we delete any envelopes we just wrote so
/// the on-disk state reflects "no credential" — the same state the
/// next caller will observe.
///
/// **Blocking I/O (round-1 review P3):** `meta_path.exists()`,
/// `std::fs::read_to_string` (skip arm), and `write_metadata_atomic`
/// are dispatched to `tokio::task::spawn_blocking` so a slow disk
/// doesn't stall the runtime worker.
///
/// Audit events:
/// - `credentials-sealed` on success, with `service`, `agent`,
///   `scopes`, `client_type`, `client_source`, `replaced_previous`,
///   `had_refresh_token`, plus `peer_uid` + `peer_gid` via
///   `enrich_audit_extra_with_peer_creds`.
/// - `credentials-seal-denied` on every failure path (round-1 review
///   P17, mirrors `agent-rebind-denied`), with the same enrichment
///   plus an `error_code` field naming the daemon-side failure code.
///
/// **ENOTSUP deviation from spec.** The story spec called for an
/// `ENOTSUP` classification branch returning
/// `credentials.unsupported_volume`. Pre-implementation research
/// confirmed the spec is wrong about which syscall surfaces ENOTSUP:
/// `write_metadata_atomic` goes through `tempfile::persist` →
/// `rustix::fs::rename` (no flags) and `CredentialFsStore::put` uses
/// `std::fs::rename` — both are plain POSIX `rename(2)`, which on
/// macOS does NOT return ENOTSUP (`man 2 rename` scopes ENOTSUP to
/// flag-bearing `renamex_np`/`renameatx_np` only, neither of which
/// is called from these paths). Branch dropped as dead code; non-APFS
/// failures surface as `EROFS`/`EIO`/`EXDEV`/`EACCES` via the generic
/// `credentials.store_io_failed` or `credentials.meta_write_failed`
/// arms. See ADR-0007 for the threat-model writeup.
pub(crate) async fn credentials_seal_handler(
    State(state): State<ControlState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
) -> Response {
    if let Err(e) = require_loopback(peer) {
        return e.into_response();
    }

    let request_id = read_request_id(&req);
    let peer_creds_for_audit: Option<crate::server::PeerCredentials> =
        req.extensions().get::<crate::server::PeerCredentials>().copied();

    // Round-1 review P7: rate-limit concurrent seals across all
    // services. `try_acquire_owned` returns immediately rather than
    // queueing, so a flood of seal requests returns 429 instead of
    // piling up on the blocking thread pool.
    let _seal_permit = match state.credentials_seal_semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            emit_seal_denied_audit(
                &state,
                &request_id,
                None,
                None,
                "credentials.rate_limited",
                peer_creds_for_audit,
            )
            .await;
            return agent_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "credentials.rate_limited",
                format!(
                    "too many concurrent seal operations in flight \
                     (max {CREDENTIALS_SEAL_MAX_CONCURRENT}); retry shortly"
                ),
                Some(request_id.clone()),
            );
        }
    };

    let (_parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, 64 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            emit_seal_denied_audit(
                &state,
                &request_id,
                None,
                None,
                "credentials.bad_request",
                peer_creds_for_audit,
            )
            .await;
            return agent_error_response(
                StatusCode::BAD_REQUEST,
                "credentials.bad_request",
                format!("failed to read request body: {e}"),
                Some(request_id.clone()),
            );
        }
    };
    let payload: CredentialsSealRequest = match serde_json::from_slice(&bytes) {
        Ok(p) => p,
        Err(e) => {
            emit_seal_denied_audit(
                &state,
                &request_id,
                None,
                None,
                "credentials.bad_request",
                peer_creds_for_audit,
            )
            .await;
            return agent_error_response(
                StatusCode::BAD_REQUEST,
                "credentials.bad_request",
                format!("invalid JSON body: {e}"),
                Some(request_id.clone()),
            );
        }
    };

    if !credential_service_supported(&payload.service) {
        emit_seal_denied_audit(
            &state,
            &request_id,
            Some(&payload.service),
            Some(&payload.agent),
            "credentials.unknown_service",
            peer_creds_for_audit,
        )
        .await;
        return agent_error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "credentials.unknown_service",
            format!(
                "service {:?} is not supported; allowed: {}",
                payload.service,
                CREDENTIAL_SUPPORTED_SERVICES.join(", ")
            ),
            Some(request_id),
        );
    }

    if let Err(e) = validate_agent_name(&payload.agent) {
        emit_seal_denied_audit(
            &state,
            &request_id,
            Some(&payload.service),
            None,
            "credentials.invalid_agent_name",
            peer_creds_for_audit,
        )
        .await;
        return agent_error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "credentials.invalid_agent_name",
            format!("{e}"),
            Some(request_id),
        );
    }

    {
        let snapshot = state.agent_registry.snapshot();
        if snapshot.get_by_name(&payload.agent).is_none() {
            emit_seal_denied_audit(
                &state,
                &request_id,
                Some(&payload.service),
                Some(&payload.agent),
                "credentials.unknown_agent",
                peer_creds_for_audit,
            )
            .await;
            return agent_error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "credentials.unknown_agent",
                format!("no agent named {:?} is registered", payload.agent),
                Some(request_id),
            );
        }
    }

    // Round-1 review P2: acquire a per-service mutex. The outer
    // std::sync::Mutex is a pure CPU critical section
    // (HashMap::entry → clone Arc). The inner tokio::sync::Mutex is
    // the lock actually held across the seal/put/meta await points.
    let service_lock = {
        let mut locks =
            state.credentials_seal_locks.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(
            locks
                .entry(payload.service.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    };
    let _seal_guard = service_lock.lock().await;

    let Some(home) = state.vault_dir.parent().map(std::path::Path::to_path_buf) else {
        emit_seal_denied_audit(
            &state,
            &request_id,
            Some(&payload.service),
            Some(&payload.agent),
            "credentials.vault_layout_invalid",
            peer_creds_for_audit,
        )
        .await;
        return agent_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "credentials.vault_layout_invalid",
            format!(
                "vault_dir {:?} has no parent — cannot derive credential store home",
                state.vault_dir
            ),
            Some(request_id),
        );
    };
    let meta_path = state.vault_dir.join(format!("{}-meta.json", payload.service));

    // Round-1 review P3: dispatch the existence check to a blocking
    // worker (it's a quick syscall but the principle stays consistent
    // with the other fs touches in this handler).
    let meta_path_for_exists = meta_path.clone();
    let credential_exists =
        match tokio::task::spawn_blocking(move || meta_path_for_exists.exists()).await {
            Ok(exists) => exists,
            Err(e) => {
                emit_seal_denied_audit(
                    &state,
                    &request_id,
                    Some(&payload.service),
                    Some(&payload.agent),
                    "credentials.meta_io_failed",
                    peer_creds_for_audit,
                )
                .await;
                return agent_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "credentials.meta_io_failed",
                    format!("blocking task join failed during existence check: {e}"),
                    Some(request_id),
                );
            }
        };

    match (payload.if_exists, credential_exists) {
        (SealIfExists::Error, true) => {
            emit_seal_denied_audit(
                &state,
                &request_id,
                Some(&payload.service),
                Some(&payload.agent),
                "credentials.already_exists",
                peer_creds_for_audit,
            )
            .await;
            return agent_error_response(
                StatusCode::CONFLICT,
                "credentials.already_exists",
                format!(
                    "credential for service {:?} already exists; pass \
                     `if_exists: \"replace\"` to overwrite",
                    payload.service
                ),
                Some(request_id),
            );
        }
        (SealIfExists::Skip, true) => {
            // Round-3 review P78: sanity-check the access envelope
            // alongside the meta sentinel. After a partial cleanup
            // (operator manually removed `{service}.sealed` but left
            // the meta file behind), the credential is NOT actually
            // usable — returning `sealed: false` here would lie. Fall
            // through to the fresh-seal path in that case so the
            // operator's `--no-force` re-run rebuilds the credential
            // instead of silently asserting it's fine.
            let envelope_path = state.vault_dir.join(format!("{}.sealed", payload.service));
            let envelope_path_for_exists = envelope_path.clone();
            let envelope_exists = match tokio::task::spawn_blocking(move || {
                envelope_path_for_exists.exists()
            })
            .await
            {
                Ok(exists) => exists,
                Err(e) => {
                    emit_seal_denied_audit(
                        &state,
                        &request_id,
                        Some(&payload.service),
                        Some(&payload.agent),
                        "credentials.meta_io_failed",
                        peer_creds_for_audit,
                    )
                    .await;
                    return agent_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "credentials.meta_io_failed",
                        format!("blocking task join failed during envelope existence check: {e}"),
                        Some(request_id),
                    );
                }
            };
            if !envelope_exists {
                tracing::warn!(
                    target: "control",
                    request_id = %request_id,
                    service = %payload.service,
                    "Skip: meta present but `{service}.sealed` envelope missing — falling through to fresh seal",
                    service = payload.service,
                );
                // Don't return — fall out of the match and proceed to
                // the Replace-equivalent seal path. `replaced_previous`
                // stays `true` (computed from `credential_exists` below)
                // so audit accurately reflects that a sentinel was overwritten.
            } else {
                // Round-1 review P3 + P16: dispatch the read to a
                // blocking worker AND use `symlink_metadata` so a
                // symlinked meta file is rejected before we read its
                // target (defense-in-depth — vault dir is 0700 root:wheel
                // so a daemon-spawned symlink is unlikely, but the
                // discipline matches `policy::edit::add_scopes_to_policy`).
                let meta_path_for_read = meta_path.clone();
                let read_result =
                    tokio::task::spawn_blocking(move || -> Result<String, std::io::Error> {
                        let md = std::fs::symlink_metadata(&meta_path_for_read)?;
                        if md.file_type().is_symlink() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                format!(
                                    "meta file is a symlink (refusing to follow): {}",
                                    meta_path_for_read.display()
                                ),
                            ));
                        }
                        std::fs::read_to_string(&meta_path_for_read)
                    })
                    .await;
                let meta_raw = match read_result {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        emit_seal_denied_audit(
                            &state,
                            &request_id,
                            Some(&payload.service),
                            Some(&payload.agent),
                            "credentials.meta_io_failed",
                            peer_creds_for_audit,
                        )
                        .await;
                        return agent_error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "credentials.meta_io_failed",
                            format!("could not read existing meta file: {e}"),
                            Some(request_id),
                        );
                    }
                    Err(e) => {
                        emit_seal_denied_audit(
                            &state,
                            &request_id,
                            Some(&payload.service),
                            Some(&payload.agent),
                            "credentials.meta_io_failed",
                            peer_creds_for_audit,
                        )
                        .await;
                        return agent_error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "credentials.meta_io_failed",
                            format!("blocking task join failed reading meta file: {e}"),
                            Some(request_id),
                        );
                    }
                };
                let meta: permitlayer_oauth::metadata::CredentialMeta =
                    match serde_json::from_str(&meta_raw) {
                        Ok(m) => m,
                        Err(e) => {
                            emit_seal_denied_audit(
                                &state,
                                &request_id,
                                Some(&payload.service),
                                Some(&payload.agent),
                                "credentials.meta_parse_failed",
                                peer_creds_for_audit,
                            )
                            .await;
                            return agent_error_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "credentials.meta_parse_failed",
                                format!("could not parse existing meta file: {e}"),
                                Some(request_id),
                            );
                        }
                    };
                return (
                    StatusCode::OK,
                    Json(CredentialsSealResponse { sealed: false, replaced_previous: false, meta }),
                )
                    .into_response();
            } // close P78 else branch (envelope_exists == true)
            // If we get here, envelope was missing — fall through to
            // the Replace-equivalent seal path.
        }
        _ => {} // Replace branch or no existing credential — proceed.
    }

    let replaced_previous = credential_exists;

    // Round-3 review D1: when a Replace re-seal omits a fresh refresh
    // token, unlink the stale `{service}-refresh.sealed` so the proxy
    // refresh path can't reach for a prior consent's refresh token
    // paired with the just-sealed access token. Best-effort: any I/O
    // error degrades to the pre-D1 behavior. Held inside the
    // per-service seal lock so no concurrent reader sees a half-state.
    if replaced_previous && payload.refresh_token.is_none() {
        let refresh_envelope = state.vault_dir.join(format!("{}-refresh.sealed", payload.service));
        let refresh_envelope_for_unlink = refresh_envelope.clone();
        let unlink_result = tokio::task::spawn_blocking(move || {
            match std::fs::remove_file(&refresh_envelope_for_unlink) {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(e),
            }
        })
        .await;
        match unlink_result {
            Ok(Ok(true)) => {
                tracing::info!(
                    target: "control",
                    request_id = %request_id,
                    service = %payload.service,
                    "stale refresh envelope unlinked on Replace without new refresh token"
                );
            }
            Ok(Ok(false)) => {}
            Ok(Err(e)) => {
                tracing::warn!(
                    target: "control",
                    request_id = %request_id,
                    service = %payload.service,
                    error = %e,
                    "best-effort unlink of stale refresh envelope failed"
                );
            }
            Err(e) => {
                tracing::warn!(
                    target: "control",
                    request_id = %request_id,
                    service = %payload.service,
                    error = %e,
                    "blocking task join failed during stale refresh unlink"
                );
            }
        }
    }

    let access_token = permitlayer_credential::OAuthToken::from_trusted_bytes(
        payload.access_token.as_bytes().to_vec(),
    );
    let sealed_access = match state.vault.seal(&payload.service, &access_token) {
        Ok(s) => s,
        Err(e) => {
            emit_seal_denied_audit(
                &state,
                &request_id,
                Some(&payload.service),
                Some(&payload.agent),
                "credentials.seal_failed",
                peer_creds_for_audit,
            )
            .await;
            return agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "credentials.seal_failed",
                format!("vault seal failed for access token: {e}"),
                Some(request_id),
            );
        }
    };

    let sealed_refresh = match payload.refresh_token.as_ref() {
        Some(refresh) => {
            let refresh_token = permitlayer_credential::OAuthRefreshToken::from_trusted_bytes(
                refresh.as_bytes().to_vec(),
            );
            let refresh_service = format!("{}-refresh", payload.service);
            match state.vault.seal_refresh(&refresh_service, &refresh_token) {
                Ok(s) => Some((refresh_service, s)),
                Err(e) => {
                    emit_seal_denied_audit(
                        &state,
                        &request_id,
                        Some(&payload.service),
                        Some(&payload.agent),
                        "credentials.seal_failed",
                        peer_creds_for_audit,
                    )
                    .await;
                    return agent_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "credentials.seal_failed",
                        format!("vault seal failed for refresh token: {e}"),
                        Some(request_id),
                    );
                }
            }
        }
        None => None,
    };

    let had_refresh_token = sealed_refresh.is_some();

    let store = match permitlayer_core::store::fs::CredentialFsStore::new(home.clone()) {
        Ok(s) => s,
        Err(e) => {
            emit_seal_denied_audit(
                &state,
                &request_id,
                Some(&payload.service),
                Some(&payload.agent),
                "credentials.store_init_failed",
                peer_creds_for_audit,
            )
            .await;
            return agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "credentials.store_init_failed",
                format!("credential store init failed: {e}"),
                Some(request_id),
            );
        }
    };

    // Track which envelope files we wrote so we can roll them back on
    // a downstream failure (round-1 review P1).
    let mut written_services: Vec<String> = Vec::with_capacity(2);

    if let Err(e) = store.put(&payload.service, sealed_access).await {
        emit_seal_denied_audit(
            &state,
            &request_id,
            Some(&payload.service),
            Some(&payload.agent),
            "credentials.store_io_failed",
            peer_creds_for_audit,
        )
        .await;
        return agent_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "credentials.store_io_failed",
            format!("credential store write failed for sealed access token: {e}"),
            Some(request_id),
        );
    }
    written_services.push(payload.service.clone());

    if let Some((refresh_service, sealed)) = sealed_refresh {
        if let Err(e) = store.put(&refresh_service, sealed).await {
            // Roll back the access envelope we just wrote (P1).
            rollback_sealed_envelopes(&state.vault_dir, &written_services).await;
            emit_seal_denied_audit(
                &state,
                &request_id,
                Some(&payload.service),
                Some(&payload.agent),
                "credentials.store_io_failed",
                peer_creds_for_audit,
            )
            .await;
            return agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "credentials.store_io_failed",
                format!("credential store write failed for sealed refresh token: {e}"),
                Some(request_id),
            );
        }
        written_services.push(refresh_service);
    }

    let meta = permitlayer_oauth::metadata::CredentialMeta {
        client_type: payload.client_type.clone(),
        client_source: Some(payload.client_source.clone()),
        // Round-1 review P4: use canonical `format_audit_timestamp`
        // so meta.connected_at matches the audit-log `Z` format
        // instead of rfc3339's `+00:00` suffix.
        connected_at: format_audit_timestamp(chrono::Utc::now()),
        last_refreshed_at: None,
        scopes: payload.granted_scopes.clone(),
        expires_in_secs: payload.expires_in_secs,
    };

    // Round-1 review P3: dispatch the meta write to a blocking
    // worker.
    let meta_path_for_write = meta_path.clone();
    let meta_for_write = meta.clone();
    let write_result = tokio::task::spawn_blocking(move || {
        permitlayer_oauth::metadata::write_metadata_atomic(&meta_path_for_write, &meta_for_write)
    })
    .await;
    match write_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            // Round-1 review P1: roll back the sealed envelopes so
            // we don't leave orphan access/refresh files with no
            // meta sentinel.
            rollback_sealed_envelopes(&state.vault_dir, &written_services).await;
            emit_seal_denied_audit(
                &state,
                &request_id,
                Some(&payload.service),
                Some(&payload.agent),
                "credentials.meta_write_failed",
                peer_creds_for_audit,
            )
            .await;
            return agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "credentials.meta_write_failed",
                format!("meta JSON write failed (sealed envelopes rolled back): {e}"),
                Some(request_id),
            );
        }
        Err(e) => {
            rollback_sealed_envelopes(&state.vault_dir, &written_services).await;
            emit_seal_denied_audit(
                &state,
                &request_id,
                Some(&payload.service),
                Some(&payload.agent),
                "credentials.meta_write_failed",
                peer_creds_for_audit,
            )
            .await;
            return agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "credentials.meta_write_failed",
                format!("blocking task join failed during meta write: {e}"),
                Some(request_id),
            );
        }
    }

    if let Some(audit) = &state.audit_store {
        let mut event = AuditEvent::with_request_id(
            request_id.clone(),
            payload.agent.clone(),
            "permitlayer".to_owned(),
            payload.service.clone(),
            "credentials-seal".to_owned(),
            "ok".to_owned(),
            "credentials-sealed".to_owned(),
        );
        event.extra = serde_json::json!({
            "service": payload.service,
            "agent": payload.agent,
            "scopes": payload.granted_scopes,
            "client_type": payload.client_type,
            "client_source": payload.client_source,
            "replaced_previous": replaced_previous,
            "had_refresh_token": had_refresh_token,
        });
        enrich_audit_extra_with_peer_creds(&mut event.extra, peer_creds_for_audit);
        if let Err(e) = audit.append(event).await {
            tracing::warn!(error = %e, "credentials-sealed audit write failed (best-effort)");
        }
    }

    tracing::info!(
        target: "control",
        request_id = %request_id,
        service = %payload.service,
        agent = %payload.agent,
        replaced_previous,
        had_refresh_token,
        "credential sealed via control endpoint"
    );

    (StatusCode::OK, Json(CredentialsSealResponse { sealed: true, replaced_previous, meta }))
        .into_response()
}

/// Round-1 review P17: emit `credentials-seal-denied` audit event on
/// every seal-handler failure path. Mirror of
/// `emit_rebind_denied_audit` from the agent-rebind handler. The
/// `error_code` field names the daemon-side failure code so operators
/// can correlate the audit row with the HTTP response.
async fn emit_seal_denied_audit(
    state: &ControlState,
    request_id: &str,
    service: Option<&str>,
    agent: Option<&str>,
    error_code: &str,
    peer_creds: Option<crate::server::PeerCredentials>,
) {
    let Some(audit) = state.audit_store.as_ref() else {
        return;
    };
    let mut event = AuditEvent::with_request_id(
        request_id.to_owned(),
        agent.unwrap_or("-").to_owned(),
        "permitlayer".to_owned(),
        service.unwrap_or("-").to_owned(),
        "credentials-seal".to_owned(),
        "denied".to_owned(),
        "credentials-seal-denied".to_owned(),
    );
    event.extra = serde_json::json!({
        "error_code": error_code,
        "service": service,
        "agent": agent,
    });
    enrich_audit_extra_with_peer_creds(&mut event.extra, peer_creds);
    if let Err(e) = audit.append(event).await {
        tracing::warn!(error = %e, "credentials-seal-denied audit write failed (best-effort)");
    }
}

/// Round-3 review P62: emit `credentials-verify-denied` audit event on
/// every verify-handler failure path that bails BEFORE the
/// verify-result match (where the inline `emit_audit` closure runs).
/// Without this, security-relevant failures — notably
/// `credentials.unseal_failed` (post-key-rotation, possible compromise)
/// and `credentials.not_found` — leave no forensic trail. Mirror of
/// `emit_seal_denied_audit`.
async fn emit_verify_denied_audit(
    state: &ControlState,
    request_id: &str,
    service: Option<&str>,
    agent: Option<&str>,
    error_code: &str,
    peer_creds: Option<crate::server::PeerCredentials>,
) {
    let Some(audit) = state.audit_store.as_ref() else {
        return;
    };
    let mut event = AuditEvent::with_request_id(
        request_id.to_owned(),
        agent.unwrap_or("-").to_owned(),
        "permitlayer".to_owned(),
        service.unwrap_or("-").to_owned(),
        "credentials-verify".to_owned(),
        "denied".to_owned(),
        "credentials-verify-denied".to_owned(),
    );
    event.extra = serde_json::json!({
        "error_code": error_code,
        "service": service,
        "agent": agent,
    });
    enrich_audit_extra_with_peer_creds(&mut event.extra, peer_creds);
    if let Err(e) = audit.append(event).await {
        tracing::warn!(error = %e, "credentials-verify-denied audit write failed (best-effort)");
    }
}

/// Round-3 review P63: emit `policy-scopes-denied` audit event on every
/// policy-scopes-handler failure path that bails BEFORE the success
/// path's `policy-scopes-added` event. Symmetric to
/// `emit_seal_denied_audit`/`emit_verify_denied_audit`. Covers
/// invalid-name, bad-request, and every `PolicyEditError` variant —
/// these are the security-relevant denials (path-traversal attempts,
/// symlink rejections, schema-violating edits).
async fn emit_policy_scopes_denied_audit(
    state: &ControlState,
    request_id: &str,
    policy_name: Option<&str>,
    error_code: &str,
    peer_creds: Option<crate::server::PeerCredentials>,
) {
    let Some(audit) = state.audit_store.as_ref() else {
        return;
    };
    let mut event = AuditEvent::with_request_id(
        request_id.to_owned(),
        "-".to_owned(), // policy_scopes is policy-scoped, not agent-scoped
        "permitlayer".to_owned(),
        "-".to_owned(),
        "policy-scopes-add".to_owned(),
        "denied".to_owned(),
        "policy-scopes-denied".to_owned(),
    );
    event.extra = serde_json::json!({
        "error_code": error_code,
        "policy_name": policy_name,
    });
    enrich_audit_extra_with_peer_creds(&mut event.extra, peer_creds);
    if let Err(e) = audit.append(event).await {
        tracing::warn!(error = %e, "policy-scopes-denied audit write failed (best-effort)");
    }
}

/// Round-1 review P1: roll back sealed envelope files when a
/// downstream step (meta write, etc.) fails. Best-effort: a roll-back
/// failure logs at warn but does not change the response code (the
/// operator already has a 500). Without this, a meta-write failure
/// leaves orphan `*.sealed` files that the next call sees as
/// `meta_path.exists() == false` and silently overwrites without
/// reporting `replaced_previous: true`.
async fn rollback_sealed_envelopes(vault_dir: &std::path::Path, services: &[String]) {
    for service in services {
        let envelope_path = vault_dir.join(format!("{service}.sealed"));
        let envelope_for_unlink = envelope_path.clone();
        let result =
            tokio::task::spawn_blocking(move || std::fs::remove_file(&envelope_for_unlink)).await;
        match result {
            Ok(Ok(())) => {
                tracing::info!(
                    target: "control",
                    path = %envelope_path.display(),
                    "rolled back orphan sealed envelope after partial-write failure"
                );
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                // Already absent — fine.
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    error = %e,
                    path = %envelope_path.display(),
                    "rollback of sealed envelope failed; operator may need to clean up by hand"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %envelope_path.display(),
                    "blocking task join failed during sealed-envelope rollback"
                );
            }
        }
    }
}

/// Request body for `POST /v1/control/credentials/{service}/verify`
/// (Story 7.30 AC #4).
#[derive(Debug, Deserialize)]
pub(crate) struct CredentialsVerifyRequest {
    pub agent: String,
    #[serde(default)]
    pub project_id: Option<String>,
}

/// Successful-verify response body (Story 7.30 AC #4 line 74 +
/// round-1 review P6 unified wire shape + P18 verified_scopes).
#[derive(Debug, Serialize)]
pub(crate) struct CredentialsVerifyOkResponse {
    pub ok: bool, // always true on this shape
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Round-1 review P18: scopes the sealed credential carries.
    /// Surfaces what the daemon successfully verified against Google
    /// so operators can confirm the grant matches their consent.
    /// Sourced from the credential's `*-meta.json` `scopes` field;
    /// empty when the meta file is missing or parse-fails (the verify
    /// probe still succeeded, the meta lookup is best-effort).
    pub verified_scopes: Vec<String>,
}

/// Structured Google-side verify failure (HTTP 200, `ok: false`).
/// Round-1 review P5 + P6: includes composite-flag follow-up
/// remediations so multi-cause failures (e.g. ScopeInsufficient +
/// also_service_disabled + also_billing_disabled on a fresh GCP
/// project) surface every step the operator needs to take.
#[derive(Debug, Serialize)]
pub(crate) struct CredentialsVerifyFailResponse {
    pub ok: bool, // always false on this shape
    pub status_code: u16,
    pub verify_reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation_url: Option<String>,
    pub reason_text: String,
    /// Empty when the primary `verify_reason` carries no composite
    /// flags. See `verify_reason_also_remediations`.
    pub also_remediations: Vec<AlsoRemediation>,
}

/// `POST /v1/control/credentials/{service}/verify` — read the sealed
/// credential, unseal via `state.vault`, and run the Google verify
/// probe daemon-side (Story 7.30 AC #4).
///
/// The CLI's `agentsso connect` flow drove the verify probe locally
/// pre-7.30 — which required CLI-side vault unseal access, which
/// requires the master key, which only the daemon should hold. This
/// handler keeps verify daemon-side while the CLI retains the
/// operator-interactive retry loop ("Press Enter to retry").
///
/// Audit event: `credentials-verified` with outcome `"ok"` or
/// `"error"`. `peer_uid` + `peer_gid` enriched via the standard
/// peer-creds helper.
///
/// **Round-1 review P6 wire-shape contract.** Every response from
/// this endpoint carries one of three precisely-typed shapes:
/// - 200 + `CredentialsVerifyOkResponse` (ok=true).
/// - 200 + `CredentialsVerifyFailResponse` (ok=false, structured
///   Google failure with composite remediations).
/// - 4xx/5xx + `agent_error_response` envelope (daemon-side failure:
///   missing credential, unseal failure, transport-to-Google failure).
///
/// **Round-1 review P20 unseal-hint.** `credentials.unseal_failed`
/// surfaces "re-run `agentsso connect <service>`" remediation so
/// operators who triggered key rotation between seal and verify get
/// an actionable next step.
pub(crate) async fn credentials_verify_handler(
    State(state): State<ControlState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(service): Path<String>,
    req: axum::extract::Request,
) -> Response {
    if let Err(e) = require_loopback(peer) {
        return e.into_response();
    }

    let request_id = read_request_id(&req);
    let peer_creds_for_audit: Option<crate::server::PeerCredentials> =
        req.extensions().get::<crate::server::PeerCredentials>().copied();

    if !credential_service_supported(&service) {
        emit_verify_denied_audit(
            &state,
            &request_id,
            Some(&service),
            None,
            "credentials.unknown_service",
            peer_creds_for_audit,
        )
        .await;
        return agent_error_response(
            StatusCode::BAD_REQUEST,
            "credentials.unknown_service",
            format!(
                "service {:?} is not supported; allowed: {}",
                service,
                CREDENTIAL_SUPPORTED_SERVICES.join(", ")
            ),
            Some(request_id),
        );
    }

    let (_parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, 16 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            emit_verify_denied_audit(
                &state,
                &request_id,
                Some(&service),
                None,
                "credentials.bad_request",
                peer_creds_for_audit,
            )
            .await;
            return agent_error_response(
                StatusCode::BAD_REQUEST,
                "credentials.bad_request",
                format!("failed to read request body: {e}"),
                Some(request_id),
            );
        }
    };
    let payload: CredentialsVerifyRequest = match serde_json::from_slice(&bytes) {
        Ok(p) => p,
        Err(e) => {
            emit_verify_denied_audit(
                &state,
                &request_id,
                Some(&service),
                None,
                "credentials.bad_request",
                peer_creds_for_audit,
            )
            .await;
            return agent_error_response(
                StatusCode::BAD_REQUEST,
                "credentials.bad_request",
                format!("invalid JSON body: {e}"),
                Some(request_id),
            );
        }
    };

    let Some(home) = state.vault_dir.parent().map(std::path::Path::to_path_buf) else {
        emit_verify_denied_audit(
            &state,
            &request_id,
            Some(&service),
            Some(&payload.agent),
            "credentials.vault_layout_invalid",
            peer_creds_for_audit,
        )
        .await;
        return agent_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "credentials.vault_layout_invalid",
            format!(
                "vault_dir {:?} has no parent — cannot derive credential store home",
                state.vault_dir
            ),
            Some(request_id),
        );
    };

    let store = match permitlayer_core::store::fs::CredentialFsStore::new(home) {
        Ok(s) => s,
        Err(e) => {
            emit_verify_denied_audit(
                &state,
                &request_id,
                Some(&service),
                Some(&payload.agent),
                "credentials.store_init_failed",
                peer_creds_for_audit,
            )
            .await;
            return agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "credentials.store_init_failed",
                format!("credential store init failed: {e}"),
                Some(request_id),
            );
        }
    };

    let sealed = match store.get(&service).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            emit_verify_denied_audit(
                &state,
                &request_id,
                Some(&service),
                Some(&payload.agent),
                "credentials.not_found",
                peer_creds_for_audit,
            )
            .await;
            return agent_error_response(
                StatusCode::NOT_FOUND,
                "credentials.not_found",
                format!("no sealed credential for service {service:?}"),
                Some(request_id),
            );
        }
        Err(e) => {
            emit_verify_denied_audit(
                &state,
                &request_id,
                Some(&service),
                Some(&payload.agent),
                "credentials.store_io_failed",
                peer_creds_for_audit,
            )
            .await;
            return agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "credentials.store_io_failed",
                format!("credential store read failed: {e}"),
                Some(request_id),
            );
        }
    };

    let access_token = match state.vault.unseal(&service, &sealed) {
        Ok(t) => t,
        Err(e) => {
            // Round-1 review P20: unseal failure usually means the
            // master key was rotated between seal and verify (Story
            // 7.6a/b rotate-key paths). Surface the recovery
            // remediation so operators don't have to guess.
            // Round-3 review P62: emit audit on this load-bearing
            // failure — post-rotation unseal failures are the
            // highest-signal forensic event in the verify path.
            emit_verify_denied_audit(
                &state,
                &request_id,
                Some(&service),
                Some(&payload.agent),
                "credentials.unseal_failed",
                peer_creds_for_audit,
            )
            .await;
            return agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "credentials.unseal_failed",
                format!(
                    "vault unseal failed: {e} — the sealed credential was likely \
                     produced under a different master key. Re-run \
                     `agentsso connect {service}` to re-seal under the current key."
                ),
                Some(request_id),
            );
        }
    };

    // Round-1 review P18: best-effort read of the credential's
    // `*-meta.json` to surface `verified_scopes` in the success
    // response. The verify probe is the load-bearing step; if the
    // meta file is unreadable we still return ok=true but with an
    // empty `verified_scopes`.
    let meta_path = state.vault_dir.join(format!("{service}-meta.json"));
    let verified_scopes: Vec<String> = {
        let meta_path_for_read = meta_path.clone();
        match tokio::task::spawn_blocking(move || std::fs::read_to_string(&meta_path_for_read))
            .await
        {
            Ok(Ok(raw)) => {
                serde_json::from_str::<permitlayer_oauth::metadata::CredentialMeta>(&raw)
                    .map(|m| m.scopes)
                    .unwrap_or_default()
            }
            _ => Vec::new(),
        }
    };

    let verify_result = permitlayer_oauth::google::verify::verify_connection(
        &service,
        access_token.reveal(),
        payload.project_id.as_deref(),
    )
    .await;

    // Audit-emit helper used by both ok and error paths.
    let emit_audit = |outcome: &'static str, extra: serde_json::Value| {
        let audit_store = state.audit_store.clone();
        let request_id = request_id.clone();
        let agent_name = payload.agent.clone();
        let service_for_audit = service.clone();
        let peer_creds = peer_creds_for_audit;
        let event_extra = extra;
        async move {
            if let Some(audit) = audit_store {
                let mut event = AuditEvent::with_request_id(
                    request_id,
                    agent_name,
                    "permitlayer".to_owned(),
                    service_for_audit,
                    "credentials-verify".to_owned(),
                    outcome.to_owned(),
                    "credentials-verified".to_owned(),
                );
                event.extra = event_extra;
                enrich_audit_extra_with_peer_creds(&mut event.extra, peer_creds);
                if let Err(e) = audit.append(event).await {
                    tracing::warn!(error = %e, "credentials-verified audit write failed (best-effort)");
                }
            }
        }
    };

    match verify_result {
        Ok(result) => {
            emit_audit(
                "ok",
                serde_json::json!({
                    "service": service,
                    "agent": payload.agent,
                    "scopes": verified_scopes,
                }),
            )
            .await;
            tracing::info!(
                target: "control",
                request_id = %request_id,
                service = %service,
                agent = %payload.agent,
                scope_count = verified_scopes.len(),
                "credential verified via control endpoint",
            );
            (
                StatusCode::OK,
                Json(CredentialsVerifyOkResponse {
                    ok: true,
                    summary: result.summary,
                    email: result.email,
                    verified_scopes,
                }),
            )
                .into_response()
        }
        Err(permitlayer_oauth::OAuthError::VerificationFailed {
            reason,
            status_code,
            verify_reason,
            ..
        }) => {
            let verify_reason_kebab =
                verify_reason.as_ref().map(verify_reason_kebab_label).unwrap_or("unknown");
            let remediation_url = verify_reason.as_ref().and_then(verify_reason_remediation_url);
            // Round-1 review P5: composite-flag follow-ups.
            let also_remediations =
                verify_reason.as_ref().map(verify_reason_also_remediations).unwrap_or_default();
            match status_code {
                Some(code) => {
                    emit_audit(
                        "error",
                        serde_json::json!({
                            "service": service,
                            "agent": payload.agent,
                            "status_code": code,
                            "verify_reason": verify_reason_kebab,
                            "also_remediation_count": also_remediations.len(),
                        }),
                    )
                    .await;
                    (
                        StatusCode::OK,
                        Json(CredentialsVerifyFailResponse {
                            ok: false,
                            status_code: code,
                            verify_reason: verify_reason_kebab,
                            remediation_url,
                            reason_text: reason,
                            also_remediations,
                        }),
                    )
                        .into_response()
                }
                None => {
                    emit_audit(
                        "error",
                        serde_json::json!({
                            "service": service,
                            "agent": payload.agent,
                            "verify_reason": verify_reason_kebab,
                            "transport_failure": true,
                        }),
                    )
                    .await;
                    // Round-1 review P6: unified error envelope —
                    // 4xx/5xx responses always use `agent_error_response`.
                    agent_error_response(
                        StatusCode::BAD_GATEWAY,
                        "credentials.transport_failed",
                        format!("verify transport failure: {reason}"),
                        Some(request_id),
                    )
                }
            }
        }
        Err(e) => {
            emit_audit(
                "error",
                serde_json::json!({
                    "service": service,
                    "agent": payload.agent,
                    "verify_reason": serde_json::Value::Null,
                    "transport_failure": true,
                }),
            )
            .await;
            agent_error_response(
                StatusCode::BAD_GATEWAY,
                "credentials.transport_failed",
                format!("verify call returned non-VerificationFailed error: {e}"),
                Some(request_id),
            )
        }
    }
}

/// Map a `VerifyReason` enum variant to a kebab-case wire label
/// (Story 7.30 AC #4). Mirrors the existing `kill_reason_wire_label`
/// pattern.
fn verify_reason_kebab_label(reason: &permitlayer_oauth::error::VerifyReason) -> &'static str {
    use permitlayer_oauth::error::VerifyReason;
    match reason {
        VerifyReason::ServiceDisabled { .. } => "service-disabled",
        VerifyReason::BillingDisabled { .. } => "billing-disabled",
        VerifyReason::ScopeInsufficient { .. } => "scope-insufficient",
        VerifyReason::Other => "other",
        // Round-1 review P13: `VerifyReason` is `#[non_exhaustive]`;
        // future variants surface as "other" with a `tracing::warn!`
        // so operators reading audit lines can distinguish a real
        // `Other` from a future variant that didn't get a wire label.
        // Mirrors the `kill_reason_wire_label` pattern.
        other => {
            tracing::warn!(
                target: "control",
                reason = ?other,
                "unknown VerifyReason variant — extend verify_reason_kebab_label",
            );
            "other"
        }
    }
}

/// Map a `VerifyReason` to an operator-facing remediation URL when
/// one is available. `None` if no canonical URL applies (e.g.
/// `Other`, or `ScopeInsufficient` which the operator must resolve
/// via re-consent rather than a URL).
fn verify_reason_remediation_url(
    reason: &permitlayer_oauth::error::VerifyReason,
) -> Option<String> {
    use permitlayer_oauth::error::VerifyReason;
    match reason {
        VerifyReason::ServiceDisabled { service, project, .. } => {
            Some(service_disabled_url(service, project.as_deref()))
        }
        VerifyReason::BillingDisabled { project } => Some(billing_disabled_url(project.as_deref())),
        VerifyReason::ScopeInsufficient { .. } | VerifyReason::Other => None,
        // VerifyReason is `#[non_exhaustive]`; future variants surface no URL.
        _ => None,
    }
}

fn service_disabled_url(service: &str, project: Option<&str>) -> String {
    // `service` is the canonical Google API name (e.g.
    // `"calendar.googleapis.com"`). Operators arrive at the
    // API-library page; the `?project=<id>` query pre-fills the
    // project switcher when present.
    let base = format!("https://console.cloud.google.com/apis/library/{service}");
    match project {
        Some(p) => format!("{base}?project={p}"),
        None => base,
    }
}

fn billing_disabled_url(project: Option<&str>) -> String {
    let base = "https://console.cloud.google.com/billing".to_owned();
    match project {
        Some(p) => format!("{base}/linkedaccount?project={p}"),
        None => base,
    }
}

/// One follow-up remediation for a composite `VerifyReason`.
/// Round-1 review P5: surfaces `also_service_disabled` /
/// `also_billing_disabled` flags so the CLI can render the full
/// fix-chain on the wire instead of dropping the secondary signal.
#[derive(Debug, Serialize)]
pub(crate) struct AlsoRemediation {
    pub reason: &'static str,
    pub url: String,
}

/// Round-1 review P5: collect the secondary remediations implied by
/// a primary `VerifyReason`. Empty when the primary reason carries no
/// composite flags. Operators with a `ScopeInsufficient`+
/// `also_service_disabled`+`also_billing_disabled` combo on a brand-
/// new GCP project see all three steps surfaced; without this they
/// re-consent (primary fix), retry, hit a fresh 403 because the API
/// is also off, etc.
fn verify_reason_also_remediations(
    reason: &permitlayer_oauth::error::VerifyReason,
) -> Vec<AlsoRemediation> {
    use permitlayer_oauth::error::VerifyReason;
    match reason {
        VerifyReason::ServiceDisabled { project, also_billing_disabled, .. } => {
            if *also_billing_disabled {
                vec![AlsoRemediation {
                    reason: "billing-disabled",
                    url: billing_disabled_url(project.as_deref()),
                }]
            } else {
                vec![]
            }
        }
        VerifyReason::ScopeInsufficient {
            also_service_disabled, also_billing_disabled, ..
        } => {
            let mut out = Vec::new();
            if let Some(service) = also_service_disabled {
                // ScopeInsufficient doesn't carry a project id on the
                // variant; surface the API-library URL without query.
                out.push(AlsoRemediation {
                    reason: "service-disabled",
                    url: service_disabled_url(service, None),
                });
            }
            if *also_billing_disabled {
                out.push(AlsoRemediation {
                    reason: "billing-disabled",
                    url: billing_disabled_url(None),
                });
            }
            out
        }
        _ => vec![],
    }
}

/// Request body for `POST /v1/control/policy/{policy_name}/scopes`
/// (Story 7.30 AC #5).
#[derive(Debug, Deserialize)]
pub(crate) struct PolicyScopesAddRequest {
    /// Short scope names to merge into the policy's allow-list
    /// (e.g. `["gmail.readonly", "gmail.modify"]`). NOT full Google
    /// scope URIs — the CLI maps URIs to shorts before sending.
    pub short_names: Vec<String>,
}

/// Response body for `POST /v1/control/policy/{policy_name}/scopes`.
#[derive(Debug, Serialize)]
pub(crate) struct PolicyScopesAddResponse {
    pub policy_name: String,
    pub before: Vec<String>,
    pub added: Vec<String>,
    pub after: Vec<String>,
    pub reloaded: bool,
}

/// `POST /v1/control/policy/{policy_name}/scopes` — merge new scopes
/// into a policy file and reload the active policy set (Story 7.30
/// AC #5).
///
/// Idempotent: when the requested `short_names` are already present,
/// the helper returns a no-op diff and the daemon skips the reload
/// + skips the audit event (matches the CLI's existing
///   `policy_was_modified` gating).
///
/// On a real merge, runs the same reload sequence as
/// `reload_handler`: clear approval caches, swap the `ArcSwap`
/// policy set via `reload_policies_with_diff_locked`, and emit a
/// reload audit event via `write_reload_audit_event`.
///
/// Audit event: `policy-scopes-added` with `policy_name`, `before`,
/// `added`, `after`. Plus the standard reload audit event when the
/// merge produced a real diff.
pub(crate) async fn policy_scopes_handler(
    State(state): State<ControlState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(policy_name): Path<String>,
    req: axum::extract::Request,
) -> Response {
    if let Err(e) = require_loopback(peer) {
        return e.into_response();
    }

    let request_id = read_request_id(&req);
    let peer_creds_for_audit: Option<crate::server::PeerCredentials> =
        req.extensions().get::<crate::server::PeerCredentials>().copied();

    // Defense-in-depth: reject path-traversal and obviously-invalid
    // policy names before `add_scopes_to_policy` joins them into a
    // filesystem path. `add_scopes_to_policy` itself will surface a
    // not-found, but a 400 here gives the caller a clearer typed
    // error code without ever doing fs I/O on a bad name.
    if policy_name.is_empty()
        || policy_name.contains('/')
        || policy_name.contains('\\')
        || policy_name.contains("..")
        || policy_name.starts_with('.')
    {
        emit_policy_scopes_denied_audit(
            &state,
            &request_id,
            Some(&policy_name),
            "policy.invalid_name",
            peer_creds_for_audit,
        )
        .await;
        return agent_error_response(
            StatusCode::BAD_REQUEST,
            "policy.invalid_name",
            format!("policy name {policy_name:?} contains illegal characters"),
            Some(request_id),
        );
    }

    let (_parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, 16 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            emit_policy_scopes_denied_audit(
                &state,
                &request_id,
                Some(&policy_name),
                "policy.bad_request",
                peer_creds_for_audit,
            )
            .await;
            return agent_error_response(
                StatusCode::BAD_REQUEST,
                "policy.bad_request",
                format!("failed to read request body: {e}"),
                Some(request_id),
            );
        }
    };
    let payload: PolicyScopesAddRequest = match serde_json::from_slice(&bytes) {
        Ok(p) => p,
        Err(e) => {
            emit_policy_scopes_denied_audit(
                &state,
                &request_id,
                Some(&policy_name),
                "policy.bad_request",
                peer_creds_for_audit,
            )
            .await;
            return agent_error_response(
                StatusCode::BAD_REQUEST,
                "policy.bad_request",
                format!("invalid JSON body: {e}"),
                Some(request_id),
            );
        }
    };

    // `add_scopes_to_policy` is a read/modify/write operation with a
    // caller-owned serialization contract. With the seeded multi-policy
    // default layout, unrelated policy names can now share one file, so
    // serialize the whole edit + reload sequence to avoid lost updates.
    let _policy_edit_guard = state.policy_edit_mutex.lock().await;

    let policies_dir = state.policies_dir.clone();
    let policy_name_for_blocking = policy_name.clone();
    let short_names_for_blocking: Vec<String> = payload.short_names.clone();
    let edit_result = tokio::task::spawn_blocking(move || {
        let short_name_refs: Vec<&str> =
            short_names_for_blocking.iter().map(String::as_str).collect();
        permitlayer_core::policy::edit::add_scopes_to_policy(
            &policies_dir,
            &policy_name_for_blocking,
            &short_name_refs,
        )
    })
    .await;

    let diff = match edit_result {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => {
            // Round-3 review P63: audit every PolicyEditError variant.
            // The variant determines the error_code label so operators
            // can grep `policy-scopes-denied` rows for the exact cause.
            let error_code = policy_edit_error_code(&e);
            emit_policy_scopes_denied_audit(
                &state,
                &request_id,
                Some(&policy_name),
                error_code,
                peer_creds_for_audit,
            )
            .await;
            return policy_edit_error_response(e, &request_id);
        }
        Err(e) => {
            emit_policy_scopes_denied_audit(
                &state,
                &request_id,
                Some(&policy_name),
                "policy.io_failed",
                peer_creds_for_audit,
            )
            .await;
            return agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "policy.io_failed",
                format!("policy edit task join failed: {e}"),
                Some(request_id),
            );
        }
    };

    let reloaded = if diff.is_no_op() {
        false
    } else {
        // Mirror `reload_handler`'s pre-swap discipline (Story 4.5):
        // clear approval caches BEFORE the ArcSwap regardless of
        // reload success. The cache may be referencing stale policy
        // that's about to be invalidated; clearing unconditionally
        // avoids serving from stale cache against the new policy.
        // Round-1 review P8 considered moving this to post-success
        // but rejected the change to keep behavioral parity with
        // `reload_handler` — both reload paths flush caches the same
        // way.
        state.approval_service.clear_caches();
        tracing::info!("approval service caches cleared on policy-scopes reload (pre-swap)");

        let ps = Arc::clone(&state.policy_set);
        let dir = state.policies_dir.clone();
        let mtx = Arc::clone(&state.reload_mutex);
        let result = tokio::task::spawn_blocking(move || {
            super::sighup::reload_policies_with_diff_locked(&ps, &dir, &mtx)
        })
        .await;

        match result {
            Ok(Ok(reload_diff)) => {
                tracing::info!(
                    policies_loaded = reload_diff.policies_loaded,
                    added = reload_diff.added.len(),
                    modified = reload_diff.modified.len(),
                    removed = reload_diff.removed.len(),
                    "policies reloaded via policy-scopes endpoint",
                );
                super::sighup::write_reload_audit_event(state.audit_store.as_ref(), &reload_diff)
                    .await;
                true
            }
            Ok(Err(e)) => {
                // Round-1 review P9 + P10: emit a partial-failure audit
                // event since the policy file is already mutated on
                // disk; surface `agentsso reload` as the recovery hint.
                emit_policy_scopes_partial_failure_audit(
                    &state,
                    &request_id,
                    &diff,
                    &format!("{e}"),
                    peer_creds_for_audit,
                )
                .await;
                return agent_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "policy.reload_failed",
                    format!(
                        "post-edit policy reload failed: {e} — the policy file IS \
                         already edited on disk. Recover with `agentsso reload` \
                         once the underlying issue is resolved; the in-memory \
                         policy set is still the pre-edit version until reload \
                         succeeds."
                    ),
                    Some(request_id),
                );
            }
            Err(e) => {
                emit_policy_scopes_partial_failure_audit(
                    &state,
                    &request_id,
                    &diff,
                    &format!("task panicked: {e}"),
                    peer_creds_for_audit,
                )
                .await;
                return agent_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "policy.reload_failed",
                    format!(
                        "post-edit policy reload task panicked: {e} — the policy \
                         file IS already edited on disk. Run `agentsso reload` to \
                         attempt recovery."
                    ),
                    Some(request_id),
                );
            }
        }
    };

    // policy-scopes-added audit event (only when a real merge happened,
    // matching the CLI's existing `policy_was_modified` gating).
    if !diff.is_no_op()
        && let Some(audit) = &state.audit_store
    {
        let mut event = AuditEvent::with_request_id(
            request_id.clone(),
            "operator".to_owned(),
            "permitlayer".to_owned(),
            "-".to_owned(),
            "policy-scopes-add".to_owned(),
            "ok".to_owned(),
            "policy-scopes-added".to_owned(),
        );
        event.extra = serde_json::json!({
            "policy_name": diff.policy_name,
            "before": diff.before,
            "added": diff.added,
            "after": diff.after,
        });
        enrich_audit_extra_with_peer_creds(&mut event.extra, peer_creds_for_audit);
        if let Err(e) = audit.append(event).await {
            tracing::warn!(error = %e, "policy-scopes-added audit write failed (best-effort)");
        }
    }

    tracing::info!(
        target: "control",
        request_id = %request_id,
        policy_name = %policy_name,
        added_count = diff.added.len(),
        reloaded,
        "policy scope merge complete",
    );
    activate_proxy_routes_if_ready(&state, Some(request_id.clone()), "policy-scopes").await;

    (
        StatusCode::OK,
        Json(PolicyScopesAddResponse {
            policy_name,
            before: diff.before,
            added: diff.added,
            after: diff.after,
            reloaded,
        }),
    )
        .into_response()
}

/// Round-1 review P9: emit `policy-scopes-add-partial-failure`
/// audit event when the policy file was successfully mutated on
/// disk but the in-memory reload failed. The audit row captures
/// (a) the on-disk state that drifted from in-memory and (b) the
/// underlying error so post-incident forensics can correlate the
/// 500 response with the policy file's then-current contents.
/// Mirrors `agent-rebind-denied`'s discipline for partial states.
async fn emit_policy_scopes_partial_failure_audit(
    state: &ControlState,
    request_id: &str,
    diff: &permitlayer_core::policy::edit::ScopeMergeDiff,
    error_text: &str,
    peer_creds: Option<crate::server::PeerCredentials>,
) {
    let Some(audit) = state.audit_store.as_ref() else {
        return;
    };
    let mut event = AuditEvent::with_request_id(
        request_id.to_owned(),
        "operator".to_owned(),
        "permitlayer".to_owned(),
        "-".to_owned(),
        "policy-scopes-add".to_owned(),
        "denied".to_owned(),
        "policy-scopes-add-partial-failure".to_owned(),
    );
    event.extra = serde_json::json!({
        "policy_name": diff.policy_name,
        "before": diff.before,
        "added": diff.added,
        "after": diff.after,
        "error": error_text,
    });
    enrich_audit_extra_with_peer_creds(&mut event.extra, peer_creds);
    if let Err(e) = audit.append(event).await {
        tracing::warn!(error = %e, "policy-scopes-add-partial-failure audit write failed (best-effort)");
    }
}

/// Round-3 review P63: map `PolicyEditError` to a stable audit-log
/// `error_code` string. Kept in lock-step with the HTTP-side mapping
/// in `policy_edit_error_response` so audit and response codes line
/// up for forensic correlation.
fn policy_edit_error_code(err: &permitlayer_core::policy::edit::PolicyEditError) -> &'static str {
    use permitlayer_core::policy::edit::PolicyEditError;
    match err {
        PolicyEditError::PolicyFileNotFound { .. } | PolicyEditError::PolicyNotInFile { .. } => {
            "policy.not_found"
        }
        PolicyEditError::PolicyDuplicateName { .. } => "policy.duplicate_name",
        PolicyEditError::PolicyFileIsSymlink { .. } => "policy.is_symlink",
        PolicyEditError::ParseFailed { .. } => "policy.parse_failed",
        PolicyEditError::CompileFailedAfterEdit { .. } => "policy.compile_failed_after_edit",
        PolicyEditError::Io { .. } => "policy.io_failed",
        PolicyEditError::SerializeFailed { .. } => "policy.serialize_failed",
    }
}

/// Map `PolicyEditError` variants to HTTP responses (Story 7.30 AC #5).
fn policy_edit_error_response(
    err: permitlayer_core::policy::edit::PolicyEditError,
    request_id: &str,
) -> Response {
    use permitlayer_core::policy::edit::PolicyEditError;
    match err {
        PolicyEditError::PolicyFileNotFound { path } => agent_error_response(
            StatusCode::NOT_FOUND,
            "policy.not_found",
            format!("policy file not found: {}", path.display()),
            Some(request_id.to_owned()),
        ),
        PolicyEditError::PolicyFileIsSymlink { path } => agent_error_response(
            StatusCode::CONFLICT,
            "policy.is_symlink",
            format!("policy file is a symlink (refusing to follow): {}", path.display()),
            Some(request_id.to_owned()),
        ),
        PolicyEditError::PolicyNotInFile { name, path } => agent_error_response(
            StatusCode::NOT_FOUND,
            "policy.not_found",
            format!("policy {name:?} not found in file {}", path.display()),
            Some(request_id.to_owned()),
        ),
        PolicyEditError::PolicyDuplicateName { name, dir, paths } => agent_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "policy.duplicate_name",
            format!(
                "policies dir {} contains multiple files with policy {name:?}: {paths:?}; \
                 the daemon's compile_from_dir should have rejected this at startup, \
                 so inspect the policies dir manually",
                dir.display()
            ),
            Some(request_id.to_owned()),
        ),
        PolicyEditError::ParseFailed { source } => agent_error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "policy.parse_failed",
            format!("policy file parse failed: {source}"),
            Some(request_id.to_owned()),
        ),
        PolicyEditError::CompileFailedAfterEdit { source } => agent_error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "policy.compile_failed_after_edit",
            format!("post-edit policy compile failed (file unchanged): {source}"),
            Some(request_id.to_owned()),
        ),
        PolicyEditError::Io { source } => agent_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "policy.io_failed",
            format!("policy file IO failed: {source}"),
            Some(request_id.to_owned()),
        ),
        PolicyEditError::SerializeFailed { source } => agent_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "policy.serialize_failed",
            format!("policy TOML serialize failed: {source}"),
            Some(request_id.to_owned()),
        ),
    }
}

/// `POST /v1/control/agent/remove` — delete an agent file and swap
/// the registry. Returns `removed: false` for a not-found name.
pub(crate) async fn remove_agent_handler(
    State(state): State<ControlState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
) -> Response {
    if let Err(e) = require_loopback(peer) {
        return e.into_response();
    }

    let request_id = read_request_id(&req);

    // Snapshot peer creds before `req.into_parts()` consumes the
    // request body. Story 7.27 AC #1 (review fix).
    let peer_creds_for_audit: Option<crate::server::PeerCredentials> =
        req.extensions().get::<crate::server::PeerCredentials>().copied();

    // Rate-limit concurrent agent CRUD (see register_agent_handler
    // for the rationale).
    let _permit = match state.agent_crud_semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return agent_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "agent.rate_limited",
                format!(
                    "too many concurrent agent CRUD operations in flight \
                     (max {AGENT_CRUD_MAX_CONCURRENT}); retry shortly"
                ),
                Some(request_id.clone()),
            );
        }
    };

    let (_parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, 64 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return agent_error_response(
                StatusCode::BAD_REQUEST,
                "agent.bad_request",
                format!("failed to read request body: {e}"),
                Some(request_id.clone()),
            );
        }
    };
    let payload: RemoveAgentRequest = match serde_json::from_slice(&bytes) {
        Ok(p) => p,
        Err(e) => {
            return agent_error_response(
                StatusCode::BAD_REQUEST,
                "agent.bad_request",
                format!("invalid JSON body: {e}"),
                Some(request_id.clone()),
            );
        }
    };

    if let Err(e) = validate_agent_name(&payload.name) {
        return agent_error_response(
            StatusCode::BAD_REQUEST,
            "agent.invalid_name",
            format!("{e}"),
            Some(request_id.clone()),
        );
    }

    let Some(store) = state.agent_store.clone() else {
        return agent_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "agent.store_unavailable",
            "agent identity store is unavailable".to_owned(),
            Some(request_id.clone()),
        );
    };

    // Story 4.4 review fix (B1): capture `had_last_seen` BEFORE the
    // remove so the audit event can report whether the agent had ever
    // authenticated. A failing `get()` here is informational-only: the
    // remove proceeds and the audit event records `had_last_seen =
    // false` so operators see an audit line rather than silently
    // losing forensic data. A `None` result means the agent was not
    // registered — short-circuit to a 404 without touching the store.
    let had_last_seen = match store.get(&payload.name).await {
        Ok(Some(identity)) => identity.last_seen_at.is_some(),
        Ok(None) => {
            // Story 4.4 review fix (B6): a not-found remove must
            // return 404 `agent.not_found` so the CLI can exit with
            // code 2, not 200 with `removed: false`.
            return agent_error_response(
                StatusCode::NOT_FOUND,
                "agent.not_found",
                format!("agent '{}' was not registered", payload.name),
                Some(request_id.clone()),
            );
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                agent_name = %payload.name,
                "agent store get() failed during remove — defaulting had_last_seen=false and continuing",
            );
            false
        }
    };

    let removed = match store.remove(&payload.name).await {
        Ok(b) => b,
        Err(e) => {
            return agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "agent.remove_failed",
                format!("{e}"),
                Some(request_id.clone()),
            );
        }
    };

    if !removed {
        // Race: the agent existed for `get()` but was gone by the
        // time `remove()` ran (concurrent operator or a failed
        // rollback in `register`). Return 404 — same shape as the
        // not-found-at-get case so the CLI exit semantics stay
        // consistent.
        return agent_error_response(
            StatusCode::NOT_FOUND,
            "agent.not_found",
            format!("agent '{}' was not registered", payload.name),
            Some(request_id.clone()),
        );
    }

    // Atomic registry swap so the deleted agent's token stops working.
    // Story 7.11 review-round-2 Q4: serialize [list + replace_with]
    // via `agent_registry_reload_lock` to prevent ordering races
    // with concurrent register/rebind handlers. See the explanation
    // in `register_agent_handler`.
    {
        let _reload_lock = state.agent_registry_reload_lock.lock().await;
        if let Ok(agents) = store.list().await {
            state.agent_registry.replace_with(agents);
        }
    }

    // Story 4.4 review fix (B7): swap scope/resource so the event
    // matches the `scope="-", resource=<action>` convention used by
    // `kill-blocked-request` and `agent-auth-denied`. The positional
    // signature of `with_request_id` is
    // (request_id, agent_id, service, scope, resource, outcome, event_type).
    //
    // Story 4.4 review fix (B1): include `had_last_seen` in `extra` so
    // operators can distinguish "removed a freshly created agent that
    // never authenticated" from "removed an active agent" without
    // cross-referencing the full audit stream.
    if let Some(audit) = &state.audit_store {
        let mut event = AuditEvent::with_request_id(
            request_id.clone(),
            payload.name.clone(),
            "permitlayer".to_owned(),
            "-".to_owned(),
            "agent-remove".to_owned(),
            "ok".to_owned(),
            "agent-removed".to_owned(),
        );
        event.extra = serde_json::json!({
            "had_last_seen": had_last_seen,
        });
        enrich_audit_extra_with_peer_creds(&mut event.extra, peer_creds_for_audit);
        if let Err(e) = audit.append(event).await {
            tracing::warn!(error = %e, "agent-removed audit write failed (best-effort)");
        }
    }

    tracing::info!(
        target: "control",
        request_id = %request_id,
        agent_name = %payload.name,
        had_last_seen,
        "agent removed via control endpoint"
    );

    (StatusCode::OK, Json(RemoveAgentResponse { status: "ok", name: payload.name, removed: true }))
        .into_response()
}

/// `POST /v1/control/agent/rebind` — update an agent's policy binding
/// WITHOUT rotating its bearer token (Story 7.11).
///
/// Loopback-only via `require_loopback`. Audit-emitting via
/// `agent-rebound`. Daemon-LIVE: this handler does NOT touch the
/// vault, only rewrites the plain TOML at `~/.agentsso/agents/<name>.toml`,
/// so it can run while the daemon is serving requests.
///
/// Pre-flight order (mirroring register):
/// 1. require_loopback (control-plane router middleware also enforces
///    `X-Agentsso-Control` header)
/// 2. agent_crud_semaphore rate-limit (429 if exhausted)
/// 3. Parse JSON body
/// 4. Validate agent name
/// 5. Verify target policy exists in active PolicySet (422 if not)
/// 6. Verify agent exists (404 if not)
/// 7. Atomically rewrite policy_name via `update_policy`
/// 8. Refresh in-memory registry via `replace_with`
/// 9. Emit audit event `agent-rebound`
/// 10. Return 200 with `RebindAgentResponse { agent: AgentSummary }`
///     — NO bearer_token field by design.
pub(crate) async fn rebind_agent_handler(
    State(state): State<ControlState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
) -> Response {
    if let Err(e) = require_loopback(peer) {
        return e.into_response();
    }

    let request_id = read_request_id(&req);

    // Snapshot peer creds before `req.into_parts()` consumes it.
    // Story 7.27 AC #1 (review fix).
    let peer_creds_for_audit: Option<crate::server::PeerCredentials> =
        req.extensions().get::<crate::server::PeerCredentials>().copied();

    // Rate-limit concurrent agent CRUD (same shape as register/remove).
    let _permit = match state.agent_crud_semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return agent_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "agent.rate_limited",
                format!(
                    "too many concurrent agent CRUD operations in flight \
                     (max {AGENT_CRUD_MAX_CONCURRENT}); retry shortly"
                ),
                Some(request_id.clone()),
            );
        }
    };

    // Parse JSON body.
    let (_parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, 64 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return agent_error_response(
                StatusCode::BAD_REQUEST,
                "agent.bad_request",
                format!("failed to read request body: {e}"),
                Some(request_id.clone()),
            );
        }
    };
    let payload: RebindAgentRequest = match serde_json::from_slice(&bytes) {
        Ok(p) => p,
        Err(e) => {
            return agent_error_response(
                StatusCode::BAD_REQUEST,
                "agent.bad_request",
                format!("invalid JSON body: {e}"),
                Some(request_id.clone()),
            );
        }
    };

    // 1. Validate agent name.
    if let Err(e) = validate_agent_name(&payload.name) {
        return agent_error_response(
            StatusCode::BAD_REQUEST,
            "agent.invalid_name",
            format!("{e}"),
            Some(request_id.clone()),
        );
    }

    // 2. Verify the target policy exists in the active PolicySet.
    //    Mirrors register_agent_handler:1228-1242 verbatim — same
    //    error code (`agent.unknown_policy`), same `known_str` shape.
    {
        let snapshot = state.policy_set.load();
        if snapshot.get(&payload.policy_name).is_none() {
            let known: Vec<String> = snapshot.policy_names();
            let known_str =
                if known.is_empty() { "(none registered)".to_owned() } else { known.join(", ") };
            // Story 7.11 review-round-1 P6: audit denied rebind.
            emit_rebind_denied_audit(
                &state,
                &request_id,
                &payload.name,
                "agent.unknown_policy",
                Some(payload.policy_name.clone()),
            )
            .await;
            return agent_error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "agent.unknown_policy",
                format!("policy '{}' not found. Known policies: {known_str}", payload.policy_name),
                Some(request_id.clone()),
            );
        }
    }

    // 3. Agent store must be available (same posture as register/remove).
    let Some(store) = state.agent_store.clone() else {
        return agent_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "agent.store_unavailable",
            "agent identity store is unavailable".to_owned(),
            Some(request_id.clone()),
        );
    };

    // 4. Verify the agent exists. Capture the OLD policy_name AND the
    //    real `created_at` / `last_seen_at` so the synthesized response
    //    fallback (step 8) doesn't fabricate timestamps under race.
    //    Mirrors remove_agent_handler's "get-then-remove" race-aware
    //    pattern.
    //
    //    Story 7.11 review-round-1 P1: prior code captured only
    //    `policy_name` and reached for `chrono::Utc::now()` on the
    //    fallback path, which is observable timestamp corruption when
    //    a concurrent `agent remove` races with rebind. Carrying the
    //    real values closes the gap.
    let (old_policy_name, real_created_at, real_last_seen_at) = match store.get(&payload.name).await
    {
        Ok(Some(identity)) => {
            (identity.policy_name.clone(), identity.created_at, identity.last_seen_at)
        }
        Ok(None) => {
            // Story 7.11 review-round-1 P6: emit a `agent-rebind-denied`
            // audit event on failure so compliance/forensics sees the
            // attempted change. Best-effort — audit failure logged at
            // warn but never blocks the response.
            emit_rebind_denied_audit(
                &state,
                &request_id,
                &payload.name,
                "agent.not_found",
                Some(payload.policy_name.clone()),
            )
            .await;
            return agent_error_response(
                StatusCode::NOT_FOUND,
                "agent.not_found",
                format!("agent '{}' was not registered", payload.name),
                Some(request_id.clone()),
            );
        }
        Err(e) => {
            return agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "agent.lookup_failed",
                format!("{e}"),
                Some(request_id.clone()),
            );
        }
    };

    // 4b. Story 7.11 review-round-1 P5: short-circuit no-op rebind
    //     (same policy as current). Avoids redundant write + audit +
    //     reload, and keeps the audit log free of `old == new` rows
    //     that confuse operators reading the trail.
    if old_policy_name == payload.policy_name {
        let agent = AgentSummary {
            name: payload.name.clone(),
            policy_name: payload.policy_name.clone(),
            created_at: format_audit_timestamp(real_created_at),
            last_seen_at: real_last_seen_at.map(format_audit_timestamp),
        };
        tracing::info!(
            target: "control",
            request_id = %request_id,
            agent_name = %payload.name,
            policy_name = %payload.policy_name,
            "agent rebind no-op (already bound to target policy); skipping write+audit+reload"
        );
        return (StatusCode::OK, Json(RebindAgentResponse { status: "ok", agent })).into_response();
    }

    // 5. Atomically rewrite policy_name. The store enforces the
    //    bearer-token-immutability invariant by typed contract:
    //    `update_policy` cannot touch token_hash or lookup_key_hex.
    match store.update_policy(&payload.name, payload.policy_name.clone()).await {
        Ok(true) => { /* fall through */ }
        Ok(false) => {
            // Race: agent removed between step 4's `get` and this
            // `update_policy` (concurrent operator action). Surface
            // as 404 — same shape as the not-found-at-get case so
            // CLI exit semantics stay consistent.
            // Story 7.11 review-round-1 P6: audit denied rebind.
            emit_rebind_denied_audit(
                &state,
                &request_id,
                &payload.name,
                "agent.not_found",
                Some(payload.policy_name.clone()),
            )
            .await;
            return agent_error_response(
                StatusCode::NOT_FOUND,
                "agent.not_found",
                format!("agent '{}' was not registered", payload.name),
                Some(request_id.clone()),
            );
        }
        Err(e) => {
            // Story 7.11 review-round-1 P6: audit denied rebind.
            emit_rebind_denied_audit(
                &state,
                &request_id,
                &payload.name,
                "agent.persist_failed",
                Some(payload.policy_name.clone()),
            )
            .await;
            return agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "agent.persist_failed",
                format!("{e}"),
                Some(request_id.clone()),
            );
        }
    }

    // 6. Refresh the in-memory registry so subsequent MCP requests
    //    evaluate against the new policy without daemon restart.
    //    Mirrors register_agent_handler's rollback discipline: if the
    //    list/replace fails, the on-disk file is already mutated, but
    //    the in-memory snapshot still has the OLD policy. Operators
    //    can run `agentsso reload` to recover. Returning 500 here
    //    surfaces the inconsistency loudly.
    //
    //    Story 7.11 review-round-2 Q4: serialize [list + replace_with]
    //    via `agent_registry_reload_lock`. See `register_agent_handler`
    //    for the full explanation.
    //
    //    Story 7.11 review-round-3 #5: scope the reload_lock to just
    //    the list+swap. The error-handling path below runs after
    //    the lock releases.
    let reload_result = {
        let _reload_lock = state.agent_registry_reload_lock.lock().await;
        store.list().await.map(|agents| state.agent_registry.replace_with(agents))
    };
    if let Err(e) = reload_result {
        tracing::error!(
            error = %e,
            agent_name = %payload.name,
            "agent registry reload after rebind failed — on-disk policy is updated but in-memory snapshot is stale; run `agentsso reload`",
        );
        // Story 7.11 review-round-1 P6: audit the partial-failure
        // path explicitly. Disk write succeeded but in-memory
        // snapshot is stale — operators auditing post-incident
        // need this row to correlate with the operator-visible
        // `agent.registry_reload_failed` error and the recovery
        // step `agentsso reload`.
        emit_rebind_denied_audit(
            &state,
            &request_id,
            &payload.name,
            "agent.registry_reload_failed",
            Some(payload.policy_name.clone()),
        )
        .await;
        return agent_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "agent.registry_reload_failed",
            "agent policy was rewritten on disk but registry reload failed; run `agentsso reload`"
                .to_owned(),
            Some(request_id.clone()),
        );
    }

    // 7. Audit event `agent-rebound`. Same shape conventions as
    //    `agent-registered` and `agent-removed` (B7 review fix).
    if let Some(audit) = &state.audit_store {
        let mut event = AuditEvent::with_request_id(
            request_id.clone(),
            payload.name.clone(),
            "permitlayer".to_owned(),
            "-".to_owned(),
            "agent-rebind".to_owned(),
            "ok".to_owned(),
            "agent-rebound".to_owned(),
        );
        event.extra = serde_json::json!({
            "old_policy_name": old_policy_name,
            "new_policy_name": payload.policy_name,
        });
        enrich_audit_extra_with_peer_creds(&mut event.extra, peer_creds_for_audit);
        if let Err(e) = audit.append(event).await {
            tracing::warn!(error = %e, "agent-rebound audit write failed (best-effort)");
        }
    }

    tracing::info!(
        target: "control",
        request_id = %request_id,
        agent_name = %payload.name,
        old_policy_name = %old_policy_name,
        new_policy_name = %payload.policy_name,
        "agent rebound via control endpoint (bearer token unchanged)"
    );

    // 8. Build response from the values THIS handler wrote, not from
    //    the registry snapshot. Story 7.11 review-round-3 #1: under
    //    concurrent rebinds for the same agent, the registry snapshot
    //    can reflect ANOTHER concurrent rebind's write that landed
    //    between this handler's update_policy and snapshot read. If
    //    we read policy_name from the snapshot, we'd return "policyA"
    //    for handler-A's response while the snapshot already shows
    //    "policyB" (handler-B's later write). The operator sees a
    //    response that contradicts the registry — silent consistency
    //    bug.
    //
    //    Fix: each handler reports what IT wrote — `payload.policy_name`,
    //    `payload.name`, the captured `real_created_at` / `real_last_seen_at`
    //    from step 4. The registry snapshot is the wrong source of
    //    truth for this handler's own response; the per-name lock
    //    held inside `update_policy` already proves THIS handler's
    //    write was the most recent for THIS name as of step 5.
    //
    //    Concurrent handler B that lands AFTER us will report B's
    //    own write the same way. Operators reading the registry
    //    later see whichever write was most recent on disk; there's
    //    no false claim that A's write didn't happen.
    //
    //    INVARIANT: RebindAgentResponse / AgentSummary do NOT carry
    //    a bearer_token field. Tests assert the response body
    //    contains neither "bearer_token" nor "agt_v2_".
    let agent = AgentSummary {
        name: payload.name.clone(),
        policy_name: payload.policy_name.clone(),
        created_at: format_audit_timestamp(real_created_at),
        last_seen_at: real_last_seen_at.map(format_audit_timestamp),
    };

    (StatusCode::OK, Json(RebindAgentResponse { status: "ok", agent })).into_response()
}

/// `POST /v1/control/agent/{name}/rotate` — atomically mint a new
/// bearer token for an existing agent and invalidate the old one
/// (Story 7.34 AC #4).
///
/// Loopback-only, audit-emitting. The old bearer is invalidated only
/// after the new one is durably persisted via
/// `AgentIdentityStore::update_lookup_key_and_token`.
pub(crate) async fn rotate_agent_handler(
    State(state): State<ControlState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(name): Path<String>,
    req: axum::extract::Request,
) -> Response {
    if let Err(e) = require_loopback(peer) {
        return e.into_response();
    }

    let request_id = read_request_id(&req);

    #[cfg(target_os = "macos")]
    let peer_creds_for_register: Option<crate::server::PeerCredentials> =
        req.extensions().get::<crate::server::PeerCredentials>().copied();
    let peer_creds_for_audit: Option<crate::server::PeerCredentials> = {
        #[cfg(target_os = "macos")]
        {
            peer_creds_for_register
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    };

    // Rate-limit concurrent agent CRUD.
    let _permit = match state.agent_crud_semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return agent_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "agent.rate_limited",
                format!(
                    "too many concurrent agent CRUD operations in flight \
                     (max {AGENT_CRUD_MAX_CONCURRENT}); retry shortly"
                ),
                Some(request_id.clone()),
            );
        }
    };

    // 1. Validate agent name.
    if let Err(e) = validate_agent_name(&name) {
        return agent_error_response(
            StatusCode::BAD_REQUEST,
            "agent.invalid_name",
            format!("{e}"),
            Some(request_id.clone()),
        );
    }

    // 2. Verify the agent exists and capture its current policy so the
    //    response can echo it back.
    let Some(store) = state.agent_store.clone() else {
        return agent_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "agent.store_unavailable",
            "agent identity store is unavailable".to_owned(),
            Some(request_id.clone()),
        );
    };

    let existing = match store.get(&name).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            return agent_error_response(
                StatusCode::NOT_FOUND,
                "agent.not_found",
                format!("agent '{}' was not registered", name),
                Some(request_id.clone()),
            );
        }
        Err(e) => {
            return agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "agent.lookup_failed",
                format!("{e}"),
                Some(request_id.clone()),
            );
        }
    };

    // 3. Generate new plaintext token + derived material.
    let raw_bytes = generate_bearer_token_bytes();
    let plaintext_body = base64_url_no_pad(&raw_bytes);
    let bearer_token = format!("{BEARER_TOKEN_PREFIX}{name}_{plaintext_body}");
    let token_bytes = bearer_token.as_bytes().to_vec();
    let token_hash = match tokio::task::spawn_blocking(move || hash_token(&token_bytes)).await {
        Ok(Ok(hash)) => hash,
        Ok(Err(e)) => {
            tracing::error!(error = %e, "Argon2id hash_token failed during rotate");
            return agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "agent.internal",
                "failed to hash bearer token".to_owned(),
                Some(request_id.clone()),
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "spawn_blocking for hash_token panicked during rotate");
            return agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "agent.internal",
                "internal error hashing bearer token".to_owned(),
                Some(request_id.clone()),
            );
        }
    };
    let lookup_key = compute_lookup_key(&state.agent_lookup_key, name.as_bytes());
    let lookup_key_hex = lookup_key_to_hex(&lookup_key);

    // 4. Atomically persist the new token + lookup key, invalidating
    //    the old bearer in one store write.
    match store.update_lookup_key_and_token(&name, lookup_key_hex, token_hash).await {
        Ok(true) => { /* fall through */ }
        Ok(false) => {
            // Race: agent removed between get and update.
            return agent_error_response(
                StatusCode::NOT_FOUND,
                "agent.not_found",
                format!("agent '{}' was not registered", name),
                Some(request_id.clone()),
            );
        }
        Err(e) => {
            return agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "agent.persist_failed",
                format!("{e}"),
                Some(request_id.clone()),
            );
        }
    }

    // 5. Atomic registry swap so the new token is live and the old one
    //    stops working.
    let reload_result = {
        let _reload_lock = state.agent_registry_reload_lock.lock().await;
        store.list().await.map(|agents| state.agent_registry.replace_with(agents))
    };
    if let Err(e) = reload_result {
        tracing::error!(
            error = %e,
            agent_name = %name,
            "agent registry reload after rotate failed — on-disk token is updated but in-memory snapshot is stale; run `agentsso reload`",
        );
        return agent_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "agent.registry_reload_failed",
            "agent token was rewritten on disk but registry reload failed; run `agentsso reload`"
                .to_owned(),
            Some(request_id.clone()),
        );
    }

    // 6. Audit event (best-effort).
    if let Some(audit) = &state.audit_store {
        let mut event = AuditEvent::with_request_id(
            request_id.clone(),
            name.clone(),
            "permitlayer".to_owned(),
            "-".to_owned(),
            "agent-rotate".to_owned(),
            "ok".to_owned(),
            "agent-rotated".to_owned(),
        );
        event.extra = serde_json::json!({
            "policy_name": existing.policy_name,
        });
        enrich_audit_extra_with_peer_creds(&mut event.extra, peer_creds_for_audit);
        if let Err(e) = audit.append(event).await {
            tracing::warn!(error = %e, "agent-rotated audit write failed (best-effort)");
        }
    }

    tracing::info!(
        target: "control",
        request_id = %request_id,
        agent_name = %name,
        "agent rotated via control endpoint (old bearer invalidated)"
    );

    // 7. On macOS, write the plaintext bearer token to the peer's home
    //    directory (same pattern as register_agent_handler).
    #[cfg(target_os = "macos")]
    let _bearer_token_file = {
        if let Some(creds) = peer_creds_for_register {
            let token_bytes: zeroize::Zeroizing<Vec<u8>> =
                zeroize::Zeroizing::new(bearer_token.clone().into_bytes());
            let state_dir = permitlayer_core::paths::daemon_state_dir(
                permitlayer_core::paths::home_override().as_deref(),
            );
            match crate::server::agent_token::write_bearer_token_to_user_home(
                &token_bytes,
                creds.uid,
                creds.gid,
                &state_dir,
            )
            .await
            {
                Ok(outcome) => {
                    tracing::info!(
                        target: "control",
                        request_id = %request_id,
                        peer_uid = creds.uid,
                        target = %outcome.target_path.display(),
                        replace_existing = outcome.replace_existing,
                        "bearer-token written to per-user file after rotate"
                    );
                    Some(outcome)
                }
                Err(e) => {
                    tracing::warn!(
                        target: "control",
                        request_id = %request_id,
                        peer_uid = creds.uid,
                        error = %e,
                        "bearer-token write after rotate failed (best-effort)"
                    );
                    None
                }
            }
        } else {
            None
        }
    };

    (StatusCode::OK, Json(RotateAgentResponse { status: "ok", name, bearer_token })).into_response()
}

/// Story 7.11 review-round-1 P6: emit `agent-rebind-denied` audit
/// event on rebind failure paths so compliance/forensics sees attempts
/// (even unsuccessful ones). Best-effort — audit failure is logged but
/// never blocks the operator-visible HTTP response.
async fn emit_rebind_denied_audit(
    state: &ControlState,
    request_id: &str,
    agent_name: &str,
    error_code: &str,
    target_policy: Option<String>,
) {
    let Some(audit) = &state.audit_store else {
        return;
    };
    let mut event = AuditEvent::with_request_id(
        request_id.to_owned(),
        agent_name.to_owned(),
        "permitlayer".to_owned(),
        "-".to_owned(),
        "agent-rebind".to_owned(),
        "denied".to_owned(),
        "agent-rebind-denied".to_owned(),
    );
    event.extra = serde_json::json!({
        "error_code": error_code,
        "target_policy_name": target_policy,
    });
    if let Err(e) = audit.append(event).await {
        tracing::warn!(error = %e, "agent-rebind-denied audit write failed (best-effort)");
    }
}

/// Read the `RequestId` extension or mint a sentinel string.
fn read_request_id(req: &axum::extract::Request) -> String {
    req.extensions()
        .get::<permitlayer_proxy::error::RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_else(|| {
            tracing::warn!(
                target: "control",
                "RequestId extension missing on agent control request — RequestTraceLayer misconfigured?"
            );
            ulid::Ulid::new().to_string()
        })
}

/// Build a JSON error response for the agent control endpoints.
///
/// `request_id` is optional because some early-path errors (loopback
/// guard rejection) fire before the handler has read the
/// `RequestId` extension. Callers that already know the request_id
/// should pass `Some(id)` to enable grep-correlation between failed
/// HTTP responses and audit/tracing logs — see the
/// `AgentErrorResponse::request_id` field doc.
fn agent_error_response(
    status: StatusCode,
    code: &'static str,
    message: String,
    request_id: Option<String>,
) -> Response {
    let body = AgentErrorResponse { status: "error", code, message, request_id };
    (status, Json(body)).into_response()
}

/// URL-safe base64 encode without padding (RFC 4648 §5). Hand-rolled
/// to avoid pulling in the `base64` crate for one call site. Used by
/// the register handler to render the 32 random token bytes as the
/// printable body of the `agt_v1_*` token.
fn base64_url_no_pad(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n =
            (u32::from(bytes[i]) << 16) | (u32::from(bytes[i + 1]) << 8) | u32::from(bytes[i + 2]);
        out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 6) & 0x3f) as usize] as char);
        out.push(CHARS[(n & 0x3f) as usize] as char);
        i += 3;
    }
    if i + 2 == bytes.len() {
        let n = (u32::from(bytes[i]) << 16) | (u32::from(bytes[i + 1]) << 8);
        out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 6) & 0x3f) as usize] as char);
    } else if i + 1 == bytes.len() {
        let n = u32::from(bytes[i]) << 16;
        out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
        out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
    }
    out
}

// --------------------------------------------------------------------------
// Router builder.
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
// Connector registry endpoint (Story 6.3 — FR40).
// --------------------------------------------------------------------------

/// Response body for `GET /v1/control/connectors`.
///
/// Each entry reflects one [`permitlayer_plugins::RegisteredConnector`]
/// from the daemon's [`permitlayer_plugins::PluginRegistry`]. Source JS is NOT included —
/// the registered connector's `#[serde(skip)]` on `source` keeps
/// plugin bytes off the wire. Operators who need the source can read
/// the on-disk file (user-installed) or inspect the daemon binary's
/// embedded assets (built-in).
///
/// Entries are emitted in `BTreeMap` iteration order (alphabetical
/// by connector name) so the CLI's table output is reproducible
/// across boots.
#[derive(Debug, Serialize)]
pub(crate) struct ConnectorsResponse {
    pub connectors: Vec<Arc<permitlayer_plugins::RegisteredConnector>>,
    pub daemon_version: &'static str,
}

/// Response body for `GET /v1/control/policies` (Story 7.34 AC #3).
#[derive(Debug, Serialize)]
pub(crate) struct ListPoliciesResponse {
    pub status: &'static str,
    pub policies: Vec<PolicyListEntry>,
}

/// One entry in the `GET /v1/control/policies` list.
#[derive(Debug, Serialize)]
pub(crate) struct PolicyListEntry {
    pub name: String,
    pub origin: String,
    pub scopes: Vec<String>,
}

/// `GET /v1/control/policies/{name}` — return the resolved policy as
/// TOML (Story 7.34 AC #1).
///
/// Loopback-only, read-only, no audit event.
pub(crate) async fn show_policy_handler(
    State(state): State<ControlState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(name): Path<String>,
    req: axum::extract::Request,
) -> Response {
    if let Err(e) = require_loopback(peer) {
        return e.into_response();
    }
    let request_id = read_request_id(&req);

    let snapshot = state.policy_set.load();
    let Some(policy) = snapshot.get(&name) else {
        return agent_error_response(
            StatusCode::NOT_FOUND,
            "policy.not_found",
            format!("policy '{name}' is not loaded"),
            Some(request_id),
        );
    };

    let toml_policy = policy.to_toml_policy();
    let file = TomlPolicyFile { policies: vec![toml_policy] };
    let toml_text = match toml::to_string_pretty(&file) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, policy_name = %name, "TOML serialization failed in show_policy_handler");
            return agent_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "policy.serialize_failed",
                format!("failed to serialize policy '{name}' to TOML: {e}"),
                Some(request_id),
            );
        }
    };

    (StatusCode::OK, [("content-type", "text/plain; charset=utf-8")], toml_text).into_response()
}

/// `GET /v1/control/policies` — return every loaded policy name,
/// source file, and scopes (Story 7.34 AC #3).
///
/// Loopback-only, read-only, no audit event.
pub(crate) async fn list_policies_handler(
    State(state): State<ControlState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
) -> Response {
    if let Err(e) = require_loopback(peer) {
        return e.into_response();
    }
    let _request_id = read_request_id(&req);

    let snapshot = state.policy_set.load();
    let mut policies: Vec<PolicyListEntry> = snapshot
        .policy_names()
        .into_iter()
        .filter_map(|name| {
            let policy = snapshot.get(&name)?;
            let origin = snapshot
                .origin(&name)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            let mut scopes: Vec<String> = policy.scope_allowlist.iter().cloned().collect();
            scopes.sort();
            Some(PolicyListEntry { name, origin, scopes })
        })
        .collect();
    policies.sort_by(|a, b| a.name.cmp(&b.name));

    (StatusCode::OK, Json(ListPoliciesResponse { status: "ok", policies })).into_response()
}

/// `GET /v1/control/connectors` — return the daemon's plugin
/// registry as JSON.
///
/// Read-only surface; no audit event emission (matches the
/// `state_handler` precedent — only state *changes* emit audit
/// events, reads don't). Loopback-only per the control-plane
/// discipline.
/// Payload cap for `GET /v1/control/connectors` (Story 8.3 AC #8).
const CONNECTORS_PAYLOAD_LIMIT_BYTES: usize = 1_048_576;

pub(crate) async fn connectors_handler(
    State(state): State<ControlState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Result<Response, ControlError> {
    require_loopback(peer)?;

    let snapshot = state.plugin_registry.snapshot();
    let connectors: Vec<Arc<permitlayer_plugins::RegisteredConnector>> =
        snapshot.values().cloned().collect();

    let response = ConnectorsResponse { connectors, daemon_version: env!("CARGO_PKG_VERSION") };
    // AC #8: cap the serialized payload at 1 MiB. Serialize once to measure;
    // reuse the bytes as the response body to avoid double-serialization.
    let serialized = serde_json::to_string(&response).unwrap_or_default();
    if serialized.len() > CONNECTORS_PAYLOAD_LIMIT_BYTES {
        return Err(ControlError::ConnectorsPayloadTooLarge {
            size_bytes: serialized.len(),
            limit_bytes: CONNECTORS_PAYLOAD_LIMIT_BYTES,
        });
    }

    Ok((StatusCode::OK, [("content-type", "application/json")], serialized).into_response())
}

// --------------------------------------------------------------------------
// Router builder.
// --------------------------------------------------------------------------

/// Build the control router.
///
/// The control router is deliberately carved OUT of the main middleware
/// chain (per ADR 0001: kill/resume must keep working when the daemon
/// is killed, which rules out `KillSwitchLayer`, `AuthLayer`, etc.).
/// But it DOES apply exactly one tower layer — `RequestTraceLayer` —
/// so every control-plane request gets a ULID stamped into its
/// extensions. The control handlers read that ULID and thread it into
/// `AuditEvent::with_request_id(...)` for the `kill-activated` /
/// `kill-resumed` audit events, giving operators grep-correlation
/// between the daemon's tracing log and the audit log for kill/resume
/// incidents. Story 3.3's review HIGH #2 flagged the missing
/// correlation; this layer is the fix.
#[allow(clippy::too_many_arguments)]
pub(crate) fn router(
    kill_switch: Arc<KillSwitch>,
    audit_store: Option<Arc<dyn permitlayer_core::store::AuditStore>>,
    policy_set: Arc<ArcSwap<PolicySet>>,
    policies_dir: std::path::PathBuf,
    reload_mutex: Arc<std::sync::Mutex<()>>,
    agent_registry: Arc<AgentRegistry>,
    agent_store: Option<Arc<dyn AgentIdentityStore>>,
    agent_lookup_key: Arc<zeroize::Zeroizing<[u8; LOOKUP_KEY_BYTES]>>,
    approval_service: Arc<dyn permitlayer_proxy::middleware::ApprovalService>,
    conn_tracker: Arc<crate::server::conn_tracker::ConnTracker>,
    plugin_registry: Arc<permitlayer_plugins::PluginRegistry>,
    approval_timeout_atomic: Arc<AtomicU64>,
    config_state: Arc<ArcSwap<crate::config::DaemonConfig>>,
    cli_overrides: Arc<crate::config::CliOverrides>,
    proxy_stub_branch_active: Arc<AtomicBool>,
    proxy_activation: ProxyActivationContext,
    vault_dir: PathBuf,
    vault: Arc<permitlayer_vault::Vault>,
    control_token: Arc<crate::lifecycle::control_token::ControlToken>,
) -> Router {
    // The caller owns the `Arc<Zeroizing<_>>` and shares the same
    // backing allocation with `AuthLayer` in the middleware chain —
    // see `cli/start.rs::run`. Cloning `ControlState` on every request
    // is an Arc bump, not a 32-byte memcpy, and the bytes are scrubbed
    // when the last clone drops at daemon shutdown.
    let state = ControlState {
        kill_switch,
        audit_store,
        policy_set,
        policies_dir,
        reload_mutex,
        policy_edit_mutex: Arc::new(tokio::sync::Mutex::new(())),
        agent_registry,
        agent_store,
        agent_lookup_key,
        agent_crud_semaphore: Arc::new(tokio::sync::Semaphore::new(AGENT_CRUD_MAX_CONCURRENT)),
        agent_registry_reload_lock: Arc::new(tokio::sync::Mutex::new(())),
        approval_service,
        conn_tracker,
        plugin_registry,
        approval_timeout_atomic,
        config_state,
        cli_overrides,
        proxy_stub_branch_active,
        proxy_activation,
        vault_dir,
        vault,
        credentials_seal_locks: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        credentials_seal_semaphore: Arc::new(tokio::sync::Semaphore::new(
            CREDENTIALS_SEAL_MAX_CONCURRENT,
        )),
        control_token,
    };
    Router::new()
        .route("/v1/control/kill", post(kill_handler))
        .route("/v1/control/resume", post(resume_handler))
        .route("/v1/control/state", get(state_handler))
        .route("/v1/control/reload", post(reload_handler))
        .route("/v1/control/agent/register", post(register_agent_handler))
        .route("/v1/control/agent/list", get(list_agents_handler))
        .route("/v1/control/agent/{name}/policy_name", get(agent_policy_name_handler))
        .route("/v1/control/credentials/{service}/meta", get(credentials_meta_handler))
        .route("/v1/control/credentials/seal", post(credentials_seal_handler))
        .route("/v1/control/credentials/{service}/verify", post(credentials_verify_handler))
        .route("/v1/control/policy/{policy_name}/scopes", post(policy_scopes_handler))
        .route("/v1/control/policies/{name}", get(show_policy_handler))
        .route("/v1/control/policies", get(list_policies_handler))
        .route("/v1/control/agent/remove", post(remove_agent_handler))
        .route("/v1/control/agent/rebind", post(rebind_agent_handler))
        .route("/v1/control/agent/{name}/rotate", post(rotate_agent_handler))
        .route("/v1/control/connections", get(connections_handler))
        .route("/v1/control/connectors", get(connectors_handler))
        .route("/v1/control/whoami", get(whoami_handler))
        // `from_fn_with_state` runs BEFORE the route handler reads the
        // body or extracts ConnectInfo, so a request with no token can't
        // consume server memory by sending a large JSON payload.
        .layer(axum::middleware::from_fn_with_state(state.clone(), require_control_token))
        .with_state(state)
        .layer(permitlayer_proxy::middleware::RequestTraceLayer::new())
}

// --------------------------------------------------------------------------
// Tests.
// --------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use http_body_util::BodyExt;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tower::ServiceExt;

    fn loopback_v4() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 54321)
    }

    fn loopback_v6() -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 54321)
    }

    fn non_loopback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 54321)
    }

    /// Build a router with `audit_store = None` — the default for tests that
    /// don't care about audit writes (everything except the Story 3.3 audit
    /// tests). The audit-sensitive tests use `build_with_audit` below.
    ///
    /// Story 4.2 added `policy_set` and `policies_dir` parameters. Tests
    /// that don't exercise reload get a default empty `PolicySet` and a
    /// throwaway temp directory.
    /// Build a no-op approval service for control router tests.
    /// The tests don't exercise the approval path directly, so a
    /// fail-closed `AlwaysDenyApprovalService` is fine.
    fn test_approval_service() -> Arc<dyn permitlayer_proxy::middleware::ApprovalService> {
        Arc::new(permitlayer_proxy::middleware::AlwaysDenyApprovalService::new())
    }

    /// Story 5.5: throw-away tracker for tests that don't exercise the
    /// `connections` endpoint. 5-minute idle timeout matches the
    /// production default.
    fn test_conn_tracker() -> Arc<crate::server::conn_tracker::ConnTracker> {
        Arc::new(crate::server::conn_tracker::ConnTracker::new(std::time::Duration::from_secs(300)))
    }

    /// Story 6.3: throw-away empty registry for tests that don't
    /// exercise the `connectors` endpoint. The shape is the same
    /// as the production loader's `Ok(registry)` with zero
    /// built-ins — useful for tests that care only about the
    /// kill/resume/agent surfaces.
    fn test_plugin_registry() -> Arc<permitlayer_plugins::PluginRegistry> {
        Arc::new(permitlayer_plugins::PluginRegistry::new(std::collections::BTreeMap::new()))
    }

    /// Story 8.7: default test wiring for the five new `router`
    /// parameters. Tests that don't exercise the reload path can use
    /// these as-is; tests that do will construct their own values.
    #[allow(clippy::type_complexity)]
    fn test_reload_wiring() -> (
        Arc<AtomicU64>,
        Arc<ArcSwap<crate::config::DaemonConfig>>,
        Arc<crate::config::CliOverrides>,
        Arc<AtomicBool>,
        std::path::PathBuf,
    ) {
        (
            Arc::new(AtomicU64::new(30)),
            Arc::new(ArcSwap::from_pointee(crate::config::DaemonConfig::default())),
            Arc::new(crate::config::CliOverrides::default()),
            Arc::new(AtomicBool::new(false)),
            std::path::PathBuf::from("/does/not/exist/vault"),
        )
    }

    /// Story 7.30: throw-away `Arc<Vault>` for tests that don't
    /// exercise credentials-seal / credentials-verify. The vault holds
    /// a deterministic 32-byte key + `key_id = 0`; `Vault::new` is
    /// a pure constructor so no I/O happens here.
    fn test_vault() -> Arc<permitlayer_vault::Vault> {
        let key = zeroize::Zeroizing::new([0x55u8; permitlayer_keystore::MASTER_KEY_LEN]);
        Arc::new(permitlayer_vault::Vault::new(key, 0))
    }

    fn test_proxy_activation() -> ProxyActivationContext {
        ProxyActivationContext {
            scrub_engine: None,
            audit_store: None,
            master_key: Arc::new(zeroize::Zeroizing::new(
                [0x55u8; permitlayer_keystore::MASTER_KEY_LEN],
            )),
            vault: test_vault(),
            routes: crate::cli::start::ProxyRouteSlots::new(None),
        }
    }

    /// Construct a ControlToken with deterministic bytes so test
    /// helpers can produce request headers that match. Production
    /// callers must always go through `ControlToken::read_or_mint`.
    pub(crate) const TEST_CONTROL_TOKEN_BYTES: [u8; 32] = [0x37u8; 32];

    fn test_control_token() -> Arc<crate::lifecycle::control_token::ControlToken> {
        Arc::new(crate::lifecycle::control_token::ControlToken::from_raw_bytes_for_test(
            TEST_CONTROL_TOKEN_BYTES,
        ))
    }

    /// Encoded form of the test token. Use as the `X-Agentsso-Control`
    /// header value in router tests.
    fn test_control_token_header() -> String {
        crate::lifecycle::control_token::ControlToken::from_raw_bytes_for_test(
            TEST_CONTROL_TOKEN_BYTES,
        )
        .encoded_for_test()
    }

    fn build(kill_switch: Arc<KillSwitch>) -> Router {
        let policy_set = Arc::new(ArcSwap::from_pointee(PolicySet::empty()));
        let policies_dir = tempfile::tempdir().unwrap().keep();
        let reload_mutex = Arc::new(std::sync::Mutex::new(()));
        // Story 4.4: empty registry + zero lookup key. Tests that
        // exercise the agent control endpoints construct their own
        // registry; everything else is fine with the default empty.
        let agent_registry = Arc::new(AgentRegistry::new(vec![]));
        let (ato, cs, co, stub, vault_dir) = test_reload_wiring();
        router(
            kill_switch,
            None,
            policy_set,
            policies_dir,
            reload_mutex,
            agent_registry,
            None,
            // Story 1.15: the agent lookup key is ALWAYS a real HKDF
            // derivation after boot (never zero). Using a non-zero
            // dummy here so the test fixture encodes the post-1.15
            // invariant — a future regression that re-introduces a
            // zero-key equality check would fail these tests.
            Arc::new(zeroize::Zeroizing::new([0x42u8; LOOKUP_KEY_BYTES])),
            test_approval_service(),
            test_conn_tracker(),
            test_plugin_registry(),
            ato,
            cs,
            co,
            stub,
            test_proxy_activation(),
            vault_dir,
            test_vault(),
            test_control_token(),
        )
    }

    /// Build a router with a concrete audit store (in-memory or tempdir-backed).
    /// Used by Story 3.3 handler tests that need to assert on audit writes.
    fn build_with_audit(
        kill_switch: Arc<KillSwitch>,
        audit_store: Arc<dyn permitlayer_core::store::AuditStore>,
    ) -> Router {
        let policy_set = Arc::new(ArcSwap::from_pointee(PolicySet::empty()));
        let policies_dir = tempfile::tempdir().unwrap().keep();
        let reload_mutex = Arc::new(std::sync::Mutex::new(()));
        let agent_registry = Arc::new(AgentRegistry::new(vec![]));
        let (ato, cs, co, stub, vault_dir) = test_reload_wiring();
        router(
            kill_switch,
            Some(audit_store),
            policy_set,
            policies_dir,
            reload_mutex,
            agent_registry,
            None,
            // Story 1.15: the agent lookup key is ALWAYS a real HKDF
            // derivation after boot (never zero). Using a non-zero
            // dummy here so the test fixture encodes the post-1.15
            // invariant — a future regression that re-introduces a
            // zero-key equality check would fail these tests.
            Arc::new(zeroize::Zeroizing::new([0x42u8; LOOKUP_KEY_BYTES])),
            test_approval_service(),
            test_conn_tracker(),
            test_plugin_registry(),
            ato,
            cs,
            co,
            stub,
            test_proxy_activation(),
            vault_dir,
            test_vault(),
            test_control_token(),
        )
    }

    /// Build a router pre-seeded with a tracker so the `/v1/control/connections`
    /// endpoint tests can exercise non-empty snapshots. The returned
    /// `Arc<ConnTracker>` is the same one held by the router's
    /// `ControlState`, so the test can `record_request` on it and the
    /// subsequent endpoint hit will see the entry.
    fn build_with_tracker(
        kill_switch: Arc<KillSwitch>,
        conn_tracker: Arc<crate::server::conn_tracker::ConnTracker>,
    ) -> Router {
        let policy_set = Arc::new(ArcSwap::from_pointee(PolicySet::empty()));
        let policies_dir = tempfile::tempdir().unwrap().keep();
        let reload_mutex = Arc::new(std::sync::Mutex::new(()));
        let agent_registry = Arc::new(AgentRegistry::new(vec![]));
        let (ato, cs, co, stub, vault_dir) = test_reload_wiring();
        router(
            kill_switch,
            None,
            policy_set,
            policies_dir,
            reload_mutex,
            agent_registry,
            None,
            Arc::new(zeroize::Zeroizing::new([0x42u8; LOOKUP_KEY_BYTES])),
            test_approval_service(),
            conn_tracker,
            test_plugin_registry(),
            ato,
            cs,
            co,
            stub,
            test_proxy_activation(),
            vault_dir,
            test_vault(),
            test_control_token(),
        )
    }

    /// Build a `Request` carrying a `ConnectInfo(addr)` extension so the
    /// `ConnectInfo` extractor sees the provided peer address when the
    /// router is driven via `ServiceExt::oneshot`. Also attaches the
    /// test-fixture `X-Agentsso-Control` header — every test routes
    /// through the auth layer, and Plan-B tests that need to exercise
    /// missing-/invalid-token cases use [`req_with_peer_no_token`] or
    /// [`req_with_peer_and_custom_token`] instead.
    fn req_with_peer(method: Method, path: &str, peer: SocketAddr) -> Request<Body> {
        let mut r = Request::builder()
            .method(method)
            .uri(path)
            .header("x-agentsso-control", test_control_token_header())
            .body(Body::empty())
            .unwrap();
        r.extensions_mut().insert(ConnectInfo(peer));
        r
    }

    /// Build a request without an `X-Agentsso-Control` header — used by
    /// Plan-B tests that pin the missing-token rejection.
    #[allow(dead_code)]
    fn req_with_peer_no_token(method: Method, path: &str, peer: SocketAddr) -> Request<Body> {
        let mut r = Request::builder().method(method).uri(path).body(Body::empty()).unwrap();
        r.extensions_mut().insert(ConnectInfo(peer));
        r
    }

    /// Build a request with a caller-specified `X-Agentsso-Control`
    /// value — used by Plan-B tests that pin the invalid-token branch.
    #[allow(dead_code)]
    fn req_with_peer_and_custom_token(
        method: Method,
        path: &str,
        peer: SocketAddr,
        token: &str,
    ) -> Request<Body> {
        let mut r = Request::builder()
            .method(method)
            .uri(path)
            .header("x-agentsso-control", token)
            .body(Body::empty())
            .unwrap();
        r.extensions_mut().insert(ConnectInfo(peer));
        r
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    // --- Positive cases: handlers activate / deactivate / report state --

    #[tokio::test]
    async fn kill_handler_activates_switch() {
        let switch = Arc::new(KillSwitch::new());
        let app = build(Arc::clone(&switch));

        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/kill", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["activation"]["was_already_active"], false);
        assert_eq!(json["activation"]["tokens_invalidated"], 0);
        assert!(json["activation"]["activated_at"].is_string());
        let activated_at = json["activation"]["activated_at"].as_str().unwrap();
        assert!(activated_at.ends_with('Z'), "activated_at must use Z suffix: {activated_at}");
        chrono::DateTime::parse_from_rfc3339(activated_at)
            .unwrap_or_else(|e| panic!("activated_at not RFC 3339: {activated_at} ({e})"));
        assert_eq!(
            json["activation"]["reason"], "user-initiated",
            "wire reason must be the kebab-case label"
        );
        assert!(switch.is_active(), "switch must be active after kill handler");
    }

    #[test]
    fn kill_reason_wire_label_maps_known_variant() {
        assert_eq!(kill_reason_wire_label(&KillReason::UserInitiated), "user-initiated");
    }

    #[tokio::test]
    async fn kill_handler_idempotent_when_already_active() {
        let switch = Arc::new(KillSwitch::new());
        switch.activate(KillReason::UserInitiated);
        let app = build(Arc::clone(&switch));

        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/kill", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["activation"]["was_already_active"], true);
        assert_eq!(json["activation"]["tokens_invalidated"], 0);
    }

    #[tokio::test]
    async fn resume_handler_deactivates_switch() {
        let switch = Arc::new(KillSwitch::new());
        switch.activate(KillReason::UserInitiated);
        let app = build(Arc::clone(&switch));

        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/resume", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["deactivation"]["was_already_inactive"], false);
        assert!(json["deactivation"]["resumed_at"].is_string());
        assert!(!switch.is_active(), "switch must be inactive after resume handler");
    }

    #[tokio::test]
    async fn resume_handler_idempotent_when_already_inactive() {
        let switch = Arc::new(KillSwitch::new());
        let app = build(Arc::clone(&switch));

        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/resume", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["deactivation"]["was_already_inactive"], true);
    }

    #[tokio::test]
    async fn state_handler_reports_inactive() {
        let switch = Arc::new(KillSwitch::new());
        let app = build(Arc::clone(&switch));

        let resp = app
            .oneshot(req_with_peer(Method::GET, "/v1/control/state", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["active"], false);
        assert_eq!(json["activated_at"], serde_json::Value::Null);
        assert_eq!(json["token_count"], 0);
    }

    #[tokio::test]
    async fn state_handler_reports_active_after_activate() {
        let switch = Arc::new(KillSwitch::new());
        switch.activate(KillReason::UserInitiated);
        let app = build(Arc::clone(&switch));

        let resp = app
            .oneshot(req_with_peer(Method::GET, "/v1/control/state", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["active"], true);
        let activated_at = json["activated_at"]
            .as_str()
            .unwrap_or_else(|| panic!("activated_at must be present when active: {json}"));
        assert!(activated_at.ends_with('Z'), "activated_at must use Z suffix: {activated_at}");
    }

    // --- Story 6.3 connectors_handler ---

    /// Build a router with a pre-populated registry so the
    /// `connectors_handler` tests can exercise a non-empty
    /// snapshot.
    fn build_with_plugin_registry(
        kill_switch: Arc<KillSwitch>,
        registry: Arc<permitlayer_plugins::PluginRegistry>,
    ) -> Router {
        let policy_set = Arc::new(ArcSwap::from_pointee(PolicySet::empty()));
        let policies_dir = tempfile::tempdir().unwrap().keep();
        let reload_mutex = Arc::new(std::sync::Mutex::new(()));
        let agent_registry = Arc::new(AgentRegistry::new(vec![]));
        let (ato, cs, co, stub, vault_dir) = test_reload_wiring();
        router(
            kill_switch,
            None,
            policy_set,
            policies_dir,
            reload_mutex,
            agent_registry,
            None,
            Arc::new(zeroize::Zeroizing::new([0x42u8; LOOKUP_KEY_BYTES])),
            test_approval_service(),
            test_conn_tracker(),
            registry,
            ato,
            cs,
            co,
            stub,
            test_proxy_activation(),
            vault_dir,
            test_vault(),
            test_control_token(),
        )
    }

    #[tokio::test]
    async fn connectors_handler_returns_empty_list_when_registry_empty() {
        // AC #18: loopback success path with an empty registry.
        let switch = Arc::new(KillSwitch::new());
        let app = build(Arc::clone(&switch));
        let resp = app
            .oneshot(req_with_peer(Method::GET, "/v1/control/connectors", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        let arr = json["connectors"].as_array().expect("connectors array");
        assert!(arr.is_empty(), "registry is empty; expected []; got {json}");
    }

    #[tokio::test]
    async fn connectors_handler_serializes_registered_entries() {
        // AC #16 + #18: a populated registry produces the
        // expected JSON shape on the control-plane wire.
        use permitlayer_plugins::{PluginRegistry, RegisteredConnector, TrustTier};
        use std::collections::BTreeMap;

        let mut map: BTreeMap<String, Arc<RegisteredConnector>> = BTreeMap::new();
        map.insert(
            "alpha".to_owned(),
            Arc::new(RegisteredConnector {
                name: "alpha".to_owned(),
                version: "1.0.0".to_owned(),
                scopes: vec!["alpha.readonly".to_owned()],
                description: Some("alpha test".to_owned()),
                trust_tier: TrustTier::Builtin,
                source: Arc::<str>::from("export const metadata = {};"),
                source_sha256_hex: "a".repeat(64),
            }),
        );
        map.insert(
            "beta".to_owned(),
            Arc::new(RegisteredConnector {
                name: "beta".to_owned(),
                version: "0.1.0".to_owned(),
                scopes: vec!["beta.readonly".to_owned(), "beta.write".to_owned()],
                description: None,
                trust_tier: TrustTier::TrustedUser,
                source: Arc::<str>::from("export const metadata = {};"),
                source_sha256_hex: "b".repeat(64),
            }),
        );
        let registry = Arc::new(PluginRegistry::new(map));

        let switch = Arc::new(KillSwitch::new());
        let app = build_with_plugin_registry(Arc::clone(&switch), registry);
        let resp = app
            .oneshot(req_with_peer(Method::GET, "/v1/control/connectors", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        let arr = json["connectors"].as_array().expect("connectors array");
        assert_eq!(arr.len(), 2);
        // BTreeMap iteration order is alphabetical — stable.
        assert_eq!(arr[0]["name"], "alpha");
        assert_eq!(arr[0]["trust_tier"], "builtin");
        assert_eq!(arr[0]["description"], "alpha test");
        assert_eq!(arr[1]["name"], "beta");
        assert_eq!(arr[1]["trust_tier"], "trusted-user");
        // `source` must NEVER appear on the wire (registered
        // connector's Serialize derive skips it).
        assert!(
            arr[0].get("source").is_none(),
            "source must not serialize over the control-plane wire: {json}"
        );
    }

    #[tokio::test]
    async fn connectors_handler_rejects_non_loopback() {
        // AC #18: non-loopback peer gets 403.
        let switch = Arc::new(KillSwitch::new());
        let app = build(Arc::clone(&switch));
        let resp = app
            .oneshot(req_with_peer(Method::GET, "/v1/control/connectors", non_loopback()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let json = body_json(resp).await;
        assert_eq!(json["error"]["code"], "forbidden_not_loopback");
    }

    #[tokio::test]
    async fn connectors_handler_returns_413_when_payload_exceeds_cap() {
        // AC #8: synthesize a registry whose serialized JSON exceeds 1 MiB.
        // Each connector gets a 1 KiB source_sha256_hex; 2 000 connectors ×
        // ~570 bytes each ≈ 1.14 MiB — safely over the 1 MiB cap.
        use permitlayer_plugins::{PluginRegistry, RegisteredConnector, TrustTier};
        use std::collections::BTreeMap;

        let mut map: BTreeMap<String, Arc<RegisteredConnector>> = BTreeMap::new();
        let big_hex = "a".repeat(1_024);
        for i in 0..2_000usize {
            let name = format!("connector-{i:05}");
            map.insert(
                name.clone(),
                Arc::new(RegisteredConnector {
                    name: name.clone(),
                    version: "1.0.0".to_owned(),
                    scopes: vec!["scope.read".to_owned()],
                    description: Some("x".repeat(64)),
                    trust_tier: TrustTier::Builtin,
                    source: Arc::<str>::from("export const metadata = {};"),
                    source_sha256_hex: big_hex.clone(),
                }),
            );
        }
        let registry = Arc::new(PluginRegistry::new(map));

        let switch = Arc::new(KillSwitch::new());
        let app = build_with_plugin_registry(Arc::clone(&switch), registry);
        let resp = app
            .oneshot(req_with_peer(Method::GET, "/v1/control/connectors", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "oversized registry must return 413"
        );
        let json = body_json(resp).await;
        assert_eq!(
            json["code"], "connectors.payload_too_large",
            "error code must be connectors.payload_too_large; got: {json}"
        );
    }

    // --- Loopback guard ---

    /// Plan B regression test: a request to `/v1/control/kill` with
    /// no `X-Agentsso-Control` header must be rejected with the
    /// `forbidden_missing_control_token` error code, even from
    /// loopback. The auth layer runs BEFORE the loopback check, so
    /// missing-token should fire first.
    ///
    /// Also asserts the top-level `status: "error"` field, which
    /// flat-shape CLI parsers (`cli/connectors/list.rs` checks
    /// `parsed["status"] == "error"`) rely on. Without it, a 403
    /// would fall through to the empty-state success branch and
    /// users who forgot the env var would see "no connectors
    /// registered" instead of a real error.
    #[tokio::test]
    async fn forbidden_when_no_control_token_header_on_kill() {
        let switch = Arc::new(KillSwitch::new());
        let app = build(Arc::clone(&switch));
        let resp = app
            .oneshot(req_with_peer_no_token(Method::POST, "/v1/control/kill", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let json = body_json(resp).await;
        assert_eq!(
            json["status"], "error",
            "missing top-level status field — flat-shape CLI parsers depend on it"
        );
        assert_eq!(json["error"]["code"], "forbidden_missing_control_token");
        assert!(!switch.is_active(), "missing-token request must NOT flip the switch");
    }

    /// Plan B regression test: a request with a malformed
    /// `X-Agentsso-Control` value must be rejected with
    /// `forbidden_invalid_control_token` even when the value is the
    /// right shape but doesn't match.
    #[tokio::test]
    async fn forbidden_when_wrong_control_token_on_kill() {
        let switch = Arc::new(KillSwitch::new());
        let app = build(Arc::clone(&switch));
        let resp = app
            .oneshot(req_with_peer_and_custom_token(
                Method::POST,
                "/v1/control/kill",
                loopback_v4(),
                "agt_ctl_definitelynotthistokenagt_ctl_definitely",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let json = body_json(resp).await;
        assert_eq!(json["error"]["code"], "forbidden_invalid_control_token");
        assert!(!switch.is_active(), "wrong-token request must NOT flip the switch");
    }

    #[tokio::test]
    async fn forbidden_when_non_loopback_on_kill() {
        let switch = Arc::new(KillSwitch::new());
        let app = build(Arc::clone(&switch));

        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/kill", non_loopback()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let json = body_json(resp).await;
        assert_eq!(json["error"]["code"], "forbidden_not_loopback");
        assert!(!switch.is_active(), "non-loopback request must NOT flip the switch");
    }

    #[tokio::test]
    async fn forbidden_when_non_loopback_on_resume() {
        let switch = Arc::new(KillSwitch::new());
        switch.activate(KillReason::UserInitiated);
        let app = build(Arc::clone(&switch));

        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/resume", non_loopback()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let json = body_json(resp).await;
        assert_eq!(json["error"]["code"], "forbidden_not_loopback");
        assert!(switch.is_active(), "non-loopback request must NOT deactivate the switch");
    }

    #[tokio::test]
    async fn forbidden_when_non_loopback_on_state() {
        let switch = Arc::new(KillSwitch::new());
        let app = build(Arc::clone(&switch));

        let resp = app
            .oneshot(req_with_peer(Method::GET, "/v1/control/state", non_loopback()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn loopback_ipv4_allowed_on_kill() {
        let switch = Arc::new(KillSwitch::new());
        let app = build(Arc::clone(&switch));

        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/kill", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn loopback_ipv6_allowed_on_kill() {
        let switch = Arc::new(KillSwitch::new());
        let app = build(Arc::clone(&switch));

        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/kill", loopback_v6()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // --- Response shape / version ---

    #[tokio::test]
    async fn kill_response_carries_daemon_version() {
        let switch = Arc::new(KillSwitch::new());
        let app = build(Arc::clone(&switch));

        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/kill", loopback_v4()))
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["daemon_version"], env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn audit_timestamp_format_has_millis_and_z_suffix() {
        let ts = chrono::DateTime::parse_from_rfc3339("2026-04-10T12:34:56.789Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let formatted = format_audit_timestamp(ts);
        assert_eq!(formatted, "2026-04-10T12:34:56.789Z");
        assert!(formatted.ends_with('Z'));
    }

    // ---------------------------------------------------------------------
    //
    // FR62: `agentsso kill` must not mutate stored OAuth credentials.
    //
    // ---------------------------------------------------------------------
    //
    // This is the in-process version of the former subprocess test
    // `vault_untouched_across_kill` in `tests/kill_resume_e2e.rs`. The
    // subprocess version had two problems:
    //
    // 1. Its first iteration staged a marker file in a
    //    `vault-backup/` subdirectory deliberately OUTSIDE any code path
    //    the daemon touches. That assertion would have passed even
    //    under a regression that scrubbed every real file in `vault/`,
    //    so it had no causal link to FR62.
    //
    // 2. Its second iteration tried to stage a real fixture inside
    //    `vault/`, but the presence of that directory caused
    //    `try_build_proxy_service` to walk into the keystore on macOS,
    //    which prompts the user via Keychain Access — blocking
    //    indefinitely in subprocess tests with no TTY.
    //
    // The in-process version drives the real `kill_handler` against a
    // fresh `ControlState`, stages fake sealed blobs under a temp home
    // directory, snapshots the full subtree before and after, and
    // asserts byte-for-byte + mtime equality. No subprocess, no
    // keystore, no Keychain.
    //
    // This version catches regressions that:
    //   1. rewrite files under `vault/` during activation
    //   2. delete or rename vault files
    //   3. create new spurious files under `vault/`
    //   4. update mtime on any vault file without changing contents

    use std::collections::BTreeMap;
    use std::hash::{Hash, Hasher};

    /// Snapshot every file under `dir` as `(relative_path → (hash, mtime))`
    /// for before/after comparison. Uses `DefaultHasher` (SipHash) — we're
    /// detecting in-test mutations, not adversarial tampering, so
    /// cryptographic strength is not required.
    fn snapshot_subtree(
        dir: &std::path::Path,
    ) -> BTreeMap<std::path::PathBuf, (u64, std::time::SystemTime)> {
        fn walk(
            base: &std::path::Path,
            dir: &std::path::Path,
            acc: &mut BTreeMap<std::path::PathBuf, (u64, std::time::SystemTime)>,
        ) {
            let entries = match std::fs::read_dir(dir) {
                Ok(e) => e,
                Err(_) => return,
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let metadata = match std::fs::symlink_metadata(&path) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if metadata.is_dir() {
                    walk(base, &path, acc);
                } else if metadata.is_file() {
                    let bytes = std::fs::read(&path).unwrap_or_default();
                    let mut hasher = std::collections::hash_map::DefaultHasher::new();
                    bytes.hash(&mut hasher);
                    let hash = hasher.finish();
                    let mtime = metadata.modified().unwrap_or(std::time::UNIX_EPOCH);
                    let rel = path.strip_prefix(base).unwrap_or(&path).to_path_buf();
                    acc.insert(rel, (hash, mtime));
                }
            }
        }

        let mut acc = BTreeMap::new();
        walk(dir, dir, &mut acc);
        acc
    }

    #[tokio::test]
    async fn fr62_kill_handler_does_not_touch_any_file_under_home() {
        let home = tempfile::TempDir::new().unwrap();

        // Stage a few sealed-style fixtures in the real vault/ dir.
        let vault_dir = home.path().join("vault");
        std::fs::create_dir_all(&vault_dir).unwrap();
        let fixtures = [
            ("gmail.sealed", b"\x00\x01\x02sealed-gmail-fixture\x03\x04\x05".as_slice()),
            ("calendar.sealed", b"\xff\xfecalendar-fixture\xfd\xfc".as_slice()),
            ("drive.sealed", b"drive-fixture-bytes".as_slice()),
        ];
        for (name, bytes) in &fixtures {
            std::fs::write(vault_dir.join(name), bytes).unwrap();
        }
        // Also stage a file directly under $home (not vault/) — a
        // regression that walks the whole home tree should be caught too.
        std::fs::write(home.path().join("agentsso.pid"), b"99999\n").unwrap();

        // Sleep briefly to make sure our "before" mtime is older than any
        // accidental touch (mtime resolution on macOS is 1µs, so 10ms is
        // plenty). Without this, a regression that rewrites the file with
        // identical content could land in the same mtime tick and pass.
        std::thread::sleep(std::time::Duration::from_millis(10));
        let before = snapshot_subtree(home.path());
        assert!(!before.is_empty(), "fixture setup failed — no files staged");

        // Drive the real kill handler against a real KillSwitch + axum
        // router. This is the same code path a live `agentsso kill`
        // command exercises against the daemon — only the transport
        // differs (tower::ServiceExt::oneshot instead of real TCP).
        let switch = Arc::new(KillSwitch::new());
        let app = build(Arc::clone(&switch));
        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/kill", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(switch.is_active(), "kill handler must have flipped the switch");

        // Snapshot the subtree after the kill and compare.
        let after = snapshot_subtree(home.path());
        assert_eq!(
            before, after,
            "FR62 violation: kill handler mutated files under $home\n\
             before: {before:#?}\n\
             after:  {after:#?}",
        );
    }

    #[tokio::test]
    async fn fr62_resume_handler_also_does_not_touch_any_file_under_home() {
        // Same assertion but for the resume path — neither should touch
        // the filesystem.
        let home = tempfile::TempDir::new().unwrap();
        let vault_dir = home.path().join("vault");
        std::fs::create_dir_all(&vault_dir).unwrap();
        std::fs::write(vault_dir.join("gmail.sealed"), b"sealed-fixture").unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));
        let before = snapshot_subtree(home.path());

        let switch = Arc::new(KillSwitch::new());
        switch.activate(KillReason::UserInitiated);
        let app = build(Arc::clone(&switch));
        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/resume", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!switch.is_active());

        let after = snapshot_subtree(home.path());
        assert_eq!(
            before, after,
            "FR62 violation: resume handler mutated files under $home\n\
             before: {before:#?}\n\
             after:  {after:#?}",
        );
    }

    // ---------------------------------------------------------------------
    //
    // Story 3.3: kill-activated / kill-resumed audit event writes.
    //
    // ---------------------------------------------------------------------
    //
    // These tests drive the real handler via `Router::oneshot` against a
    // `ControlState` backed by a real `AuditFsStore` in a temp dir, then
    // read `<temp_dir>/audit/<today>.jsonl` and parse each line as
    // `AuditEvent` to assert the audit line was actually written with the
    // expected shape. This exercises the full write path including the
    // scrub-before-log pipeline that `AuditFsWriter` enforces.

    use permitlayer_core::scrub::{ScrubEngine, builtin_rules};
    use permitlayer_core::store::AuditStore;
    use permitlayer_core::store::fs::AuditFsStore;

    /// Build a real `AuditFsStore` backed by `<tempdir>/audit/`. Returns
    /// both the store (wrapped as a trait object) and the root dir so the
    /// test can read back the JSONL file.
    fn build_audit_store(home: &std::path::Path) -> Arc<dyn AuditStore> {
        let scrub_engine = Arc::new(
            ScrubEngine::new(builtin_rules().to_vec()).expect("built-in scrub rules must compile"),
        );
        let audit_dir = home.join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        Arc::new(AuditFsStore::new(audit_dir, 100_000_000, scrub_engine).unwrap())
    }

    /// Read all audit events written to `<home>/audit/` across all
    /// rotated files. Parses each line as `AuditEvent` and skips blank
    /// lines. Panics on parse error (test diagnostic clarity > robustness).
    fn read_audit_events(home: &std::path::Path) -> Vec<AuditEvent> {
        let audit_dir = home.join("audit");
        let mut events = Vec::new();
        if !audit_dir.exists() {
            return events;
        }
        let entries = std::fs::read_dir(&audit_dir).unwrap();
        let mut paths: Vec<_> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("jsonl"))
            .collect();
        paths.sort();
        for path in paths {
            let contents = std::fs::read_to_string(&path).unwrap();
            for line in contents.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                let event: AuditEvent = serde_json::from_str(line)
                    .unwrap_or_else(|e| panic!("failed to parse audit line {line}: {e}"));
                events.push(event);
            }
        }
        events
    }

    #[tokio::test]
    async fn kill_handler_writes_kill_activated_audit_event() {
        let home = tempfile::TempDir::new().unwrap();
        let store = build_audit_store(home.path());
        let switch = Arc::new(KillSwitch::new());
        let app = build_with_audit(Arc::clone(&switch), Arc::clone(&store));

        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/kill", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let events = read_audit_events(home.path());
        let kill_events: Vec<_> =
            events.iter().filter(|e| e.event_type == "kill-activated").collect();
        assert_eq!(
            kill_events.len(),
            1,
            "expected exactly 1 kill-activated event, got {}",
            kill_events.len()
        );

        let event = kill_events[0];
        assert_eq!(event.agent_id, "system");
        assert_eq!(event.service, "permitlayer");
        assert_eq!(event.scope, "-");
        assert_eq!(event.resource, "kill-switch");
        assert_eq!(event.outcome, "ok");
        assert_eq!(event.schema_version, permitlayer_core::audit::event::AUDIT_SCHEMA_VERSION);

        // extra.*
        assert_eq!(event.extra["cause"], "user-initiated");
        assert_eq!(event.extra["tokens_invalidated"], 0);
        assert_eq!(event.extra["in_flight_cancelled"], 0);
        assert_eq!(event.extra["was_already_active"], false);
        let activated_at = event.extra["activated_at"].as_str().unwrap();
        assert!(activated_at.ends_with('Z'), "activated_at must use Z suffix: {activated_at}");
        // Story 3.3 review patch (LOW #12): enforce exact format length
        // `%Y-%m-%dT%H:%M:%S%.3fZ` = 24 chars. RFC 3339 parsing alone
        // accepts `+00:00` variants (25 chars) which drift from the
        // canonical audit-log format.
        assert_eq!(activated_at.len(), 24, "canonical audit timestamp must be exactly 24 chars");
        chrono::DateTime::parse_from_rfc3339(activated_at)
            .unwrap_or_else(|e| panic!("activated_at not RFC 3339: {activated_at} ({e})"));
    }

    /// Story 3.3 review HIGH #2 regression: the control-plane audit
    /// event's `request_id` must match the `x-agentsso-request-id`
    /// header stamped by `RequestTraceLayer`. Without this correlation,
    /// operators can't grep-join the daemon's tracing log for a kill
    /// incident with the corresponding audit event. The patch plumbed
    /// `RequestTraceLayer` into the control router and switched both
    /// handlers to `AuditEvent::with_request_id(...)`; this test locks
    /// in the invariant.
    #[tokio::test]
    async fn kill_handler_audit_request_id_matches_trace_header() {
        let home = tempfile::TempDir::new().unwrap();
        let store = build_audit_store(home.path());
        let switch = Arc::new(KillSwitch::new());
        let app = build_with_audit(Arc::clone(&switch), Arc::clone(&store));

        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/kill", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Extract the request_id the trace layer stamped and echoed.
        let trace_request_id = resp
            .headers()
            .get("x-agentsso-request-id")
            .expect("RequestTraceLayer must echo x-agentsso-request-id on control responses")
            .to_str()
            .unwrap()
            .to_owned();
        assert!(!trace_request_id.is_empty());

        // Read the audit event and assert its request_id matches.
        let events = read_audit_events(home.path());
        let kill_events: Vec<_> =
            events.iter().filter(|e| e.event_type == "kill-activated").collect();
        assert_eq!(kill_events.len(), 1);
        assert_eq!(
            kill_events[0].request_id, trace_request_id,
            "audit event request_id must match the x-agentsso-request-id header — operator grep-correlation is load-bearing",
        );
    }

    /// Same correlation invariant for resume.
    #[tokio::test]
    async fn resume_handler_audit_request_id_matches_trace_header() {
        let home = tempfile::TempDir::new().unwrap();
        let store = build_audit_store(home.path());
        let switch = Arc::new(KillSwitch::new());
        switch.activate(KillReason::UserInitiated);
        let app = build_with_audit(Arc::clone(&switch), Arc::clone(&store));

        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/resume", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let trace_request_id = resp
            .headers()
            .get("x-agentsso-request-id")
            .expect("RequestTraceLayer must echo x-agentsso-request-id on control responses")
            .to_str()
            .unwrap()
            .to_owned();

        let events = read_audit_events(home.path());
        let resume_events: Vec<_> =
            events.iter().filter(|e| e.event_type == "kill-resumed").collect();
        assert_eq!(resume_events.len(), 1);
        assert_eq!(
            resume_events[0].request_id, trace_request_id,
            "audit event request_id must match the x-agentsso-request-id header",
        );
    }

    #[tokio::test]
    async fn kill_handler_writes_audit_with_already_active_outcome_on_idempotent() {
        let home = tempfile::TempDir::new().unwrap();
        let store = build_audit_store(home.path());
        let switch = Arc::new(KillSwitch::new());
        // Pre-activate.
        switch.activate(KillReason::UserInitiated);

        let app = build_with_audit(Arc::clone(&switch), Arc::clone(&store));
        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/kill", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let events = read_audit_events(home.path());
        let kill_events: Vec<_> =
            events.iter().filter(|e| e.event_type == "kill-activated").collect();
        // Exactly one — from the idempotent call. (The pre-activate call
        // above is a direct `KillSwitch::activate` that bypasses the
        // handler, so it does NOT produce an audit event.)
        assert_eq!(kill_events.len(), 1);
        let event = kill_events[0];
        assert_eq!(event.outcome, "already-active");
        assert_eq!(event.extra["was_already_active"], true);
        assert_eq!(event.extra["tokens_invalidated"], 0);
    }

    /// Story 3.3 review patch (MED #9): prove that `tokens_invalidated`
    /// actually reflects the delta of the current activation, not a
    /// hardcoded 0. The original idempotent test uses an empty registry
    /// so both the first activation and the idempotent one report 0 —
    /// a regression that hardcoded `tokens_invalidated: 0` would be
    /// invisible. This test registers a real token, drives the handler
    /// for the first (non-idempotent) activation, and asserts the event
    /// reports `1` invalidated. A subsequent idempotent call reports
    /// `0` (the delta — nothing new was invalidated).
    #[tokio::test]
    async fn kill_handler_audit_tokens_invalidated_reflects_delta() {
        use permitlayer_core::killswitch::{TokenId, TokenInfo};

        let home = tempfile::TempDir::new().unwrap();
        let store = build_audit_store(home.path());
        let switch = Arc::new(KillSwitch::new());

        // Register a single scoped token so the first activation has
        // something to invalidate.
        switch
            .register_token(
                TokenId::new("test-token-1").unwrap(),
                TokenInfo::new("test-agent", "gmail", "mail.readonly", chrono::Utc::now()),
            )
            .unwrap();
        assert_eq!(switch.token_count(), 1);

        // First handler invocation: should invalidate 1 token.
        let app = build_with_audit(Arc::clone(&switch), Arc::clone(&store));
        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/kill", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let events = read_audit_events(home.path());
        let kill_events: Vec<_> =
            events.iter().filter(|e| e.event_type == "kill-activated").collect();
        assert_eq!(kill_events.len(), 1);
        assert_eq!(
            kill_events[0].extra["tokens_invalidated"], 1,
            "first activation must report the real count from the registry, not a hardcoded 0",
        );
        assert_eq!(kill_events[0].extra["was_already_active"], false);

        // Second handler invocation: idempotent — no new tokens to
        // invalidate, so the delta is 0.
        let app = build_with_audit(Arc::clone(&switch), Arc::clone(&store));
        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/kill", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let events = read_audit_events(home.path());
        let kill_events: Vec<_> =
            events.iter().filter(|e| e.event_type == "kill-activated").collect();
        assert_eq!(
            kill_events.len(),
            2,
            "expected 2 kill-activated events after two handler calls"
        );
        // The second event is the idempotent one.
        let idempotent = kill_events[1];
        assert_eq!(idempotent.outcome, "already-active");
        assert_eq!(idempotent.extra["was_already_active"], true);
        assert_eq!(
            idempotent.extra["tokens_invalidated"], 0,
            "idempotent activation must report 0 new invalidations (delta semantics)",
        );
    }

    #[tokio::test]
    async fn kill_handler_no_audit_store_skips_write_without_panic() {
        // Regression for the `audit_store = None` branch — kill still
        // works, the handler returns 200, and nothing panics.
        let switch = Arc::new(KillSwitch::new());
        let app = build(Arc::clone(&switch)); // None audit_store
        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/kill", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(switch.is_active());
    }

    /// In-memory `AuditStore` that always returns an error. Verifies the
    /// best-effort contract: audit failure must NOT block the kill state
    /// change or fail the HTTP response.
    struct FailingAuditStore;

    #[async_trait::async_trait]
    impl AuditStore for FailingAuditStore {
        async fn append(
            &self,
            _event: AuditEvent,
        ) -> Result<(), permitlayer_core::store::error::StoreError> {
            Err(permitlayer_core::store::error::StoreError::AuditWriteFailed {
                reason: "test-forced failure".to_owned(),
                source: None,
            })
        }
    }

    #[tokio::test]
    async fn kill_handler_best_effort_on_audit_failure() {
        let switch = Arc::new(KillSwitch::new());
        let store: Arc<dyn AuditStore> = Arc::new(FailingAuditStore);
        let app = build_with_audit(Arc::clone(&switch), store);

        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/kill", loopback_v4()))
            .await
            .unwrap();
        // Kill succeeded even though audit write failed.
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(switch.is_active(), "kill state must take effect despite audit failure");
    }

    #[tokio::test]
    async fn resume_handler_writes_kill_resumed_audit_event_with_duration() {
        let home = tempfile::TempDir::new().unwrap();
        let store = build_audit_store(home.path());
        let switch = Arc::new(KillSwitch::new());
        // Pre-activate so we have a duration to measure.
        switch.activate(KillReason::UserInitiated);
        // Small sleep so `duration_killed_seconds` >= 0 is trivially true
        // (millisecond-scale wall clock rounds down to 0 seconds, which
        // is still non-negative and a valid assertion).
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let app = build_with_audit(Arc::clone(&switch), Arc::clone(&store));
        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/resume", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let events = read_audit_events(home.path());
        let resume_events: Vec<_> =
            events.iter().filter(|e| e.event_type == "kill-resumed").collect();
        assert_eq!(resume_events.len(), 1, "expected exactly 1 kill-resumed event");

        let event = resume_events[0];
        assert_eq!(event.agent_id, "system");
        assert_eq!(event.service, "permitlayer");
        assert_eq!(event.scope, "-");
        assert_eq!(event.resource, "kill-switch");
        assert_eq!(event.outcome, "ok");

        // extra.*
        let resumed_at = event.extra["resumed_at"].as_str().unwrap();
        assert!(resumed_at.ends_with('Z'));
        // Story 3.3 review patch (LOW #12): the exact audit-log format
        // is `%Y-%m-%dT%H:%M:%S%.3fZ` = 24 chars (e.g.
        // `2026-04-11T22:18:05.672Z`). Asserting the exact length
        // catches regressions that switch to `.to_rfc3339()` (`+00:00`,
        // 25 chars) which RFC3339-parses cleanly but drifts from the
        // canonical format used across the audit stream.
        assert_eq!(resumed_at.len(), 24, "canonical audit timestamp must be exactly 24 chars");
        chrono::DateTime::parse_from_rfc3339(resumed_at).unwrap();
        let duration = event.extra["duration_killed_seconds"].as_u64().unwrap();
        // Sub-second wall clock → 0 whole seconds; assert it's there
        // and non-negative.
        assert_eq!(duration, 0, "sub-second test wall clock must round to 0");
        assert_eq!(event.extra["was_already_inactive"], false);
    }

    /// Story 3.3 review patch (MED #8): prove that
    /// `duration_killed_seconds` is actually computed from the activate
    /// → resume delta, not hardcoded to 0. The original test
    /// (`resume_handler_writes_kill_resumed_audit_event_with_duration`)
    /// uses a 10ms pre-sleep and asserts `duration == 0`, which would
    /// pass if production were `let duration_killed_seconds: u64 = 0;`.
    /// This test sleeps long enough to produce a non-zero whole-second
    /// duration and asserts `>= 1`, locking in the delta semantics.
    #[tokio::test]
    async fn resume_handler_audit_duration_reflects_actual_kill_time() {
        let home = tempfile::TempDir::new().unwrap();
        let store = build_audit_store(home.path());
        let switch = Arc::new(KillSwitch::new());
        switch.activate(KillReason::UserInitiated);

        // Sleep long enough to produce a >= 1-second delta.
        tokio::time::sleep(std::time::Duration::from_millis(1_050)).await;

        let app = build_with_audit(Arc::clone(&switch), Arc::clone(&store));
        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/resume", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let events = read_audit_events(home.path());
        let resume_events: Vec<_> =
            events.iter().filter(|e| e.event_type == "kill-resumed").collect();
        assert_eq!(resume_events.len(), 1);
        let duration = resume_events[0].extra["duration_killed_seconds"].as_u64().unwrap();
        assert!(
            duration >= 1,
            "duration_killed_seconds must reflect the actual kill time, got {duration}",
        );
    }

    #[tokio::test]
    async fn resume_handler_writes_audit_with_already_inactive_outcome_on_idempotent() {
        let home = tempfile::TempDir::new().unwrap();
        let store = build_audit_store(home.path());
        let switch = Arc::new(KillSwitch::new()); // never killed

        let app = build_with_audit(Arc::clone(&switch), Arc::clone(&store));
        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/resume", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let events = read_audit_events(home.path());
        let resume_events: Vec<_> =
            events.iter().filter(|e| e.event_type == "kill-resumed").collect();
        assert_eq!(resume_events.len(), 1);
        let event = resume_events[0];
        assert_eq!(event.outcome, "already-inactive");
        assert_eq!(event.extra["was_already_inactive"], true);
        assert_eq!(event.extra["duration_killed_seconds"], 0);
    }

    #[tokio::test]
    async fn resume_handler_best_effort_on_audit_failure() {
        let switch = Arc::new(KillSwitch::new());
        switch.activate(KillReason::UserInitiated);
        let store: Arc<dyn AuditStore> = Arc::new(FailingAuditStore);
        let app = build_with_audit(Arc::clone(&switch), store);

        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/resume", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!switch.is_active(), "resume must take effect despite audit failure");
    }

    #[tokio::test]
    async fn resume_handler_no_audit_store_skips_write_without_panic() {
        let switch = Arc::new(KillSwitch::new());
        switch.activate(KillReason::UserInitiated);
        let app = build(Arc::clone(&switch)); // None audit_store
        let resp = app
            .oneshot(req_with_peer(Method::POST, "/v1/control/resume", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!switch.is_active());
    }

    // ── Story 5.5: /v1/control/connections endpoint ───────────────

    #[tokio::test]
    async fn connections_endpoint_loopback_v4_ok_empty() {
        let switch = Arc::new(KillSwitch::new());
        let app = build(Arc::clone(&switch));
        let resp = app
            .oneshot(req_with_peer(Method::GET, "/v1/control/connections", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert!(json["connections"].is_array());
        assert_eq!(json["connections"].as_array().unwrap().len(), 0);
        assert!(json["generated_at"].is_string());
        let ts = json["generated_at"].as_str().unwrap();
        assert!(ts.ends_with('Z'), "generated_at must use Z suffix: {ts}");
    }

    #[tokio::test]
    async fn connections_endpoint_loopback_v6_ok() {
        let switch = Arc::new(KillSwitch::new());
        let app = build(Arc::clone(&switch));
        let resp = app
            .oneshot(req_with_peer(Method::GET, "/v1/control/connections", loopback_v6()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn connections_endpoint_non_loopback_403() {
        let switch = Arc::new(KillSwitch::new());
        let app = build(Arc::clone(&switch));
        let resp = app
            .oneshot(req_with_peer(Method::GET, "/v1/control/connections", non_loopback()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let json = body_json(resp).await;
        assert_eq!(json["error"]["code"], "forbidden_not_loopback");
    }

    #[tokio::test]
    async fn connections_endpoint_returns_recorded_entries() {
        let switch = Arc::new(KillSwitch::new());
        let tracker = Arc::new(crate::server::conn_tracker::ConnTracker::new(
            std::time::Duration::from_secs(300),
        ));
        // Seed two distinct agents. The endpoint sweeps before
        // snapshot, so seeding with `Utc::now()` ensures both rows
        // survive the sweep.
        let now_wall = chrono::Utc::now();
        let now_mono = std::time::Instant::now();
        tracker.record_request("agent-alpha", "policy-default", now_wall, now_mono);
        tracker.record_request(
            "agent-beta",
            "policy-default",
            now_wall + chrono::Duration::seconds(1),
            now_mono + std::time::Duration::from_secs(1),
        );
        // Two more from agent-alpha to drive `total_requests` up.
        tracker.record_request(
            "agent-alpha",
            "policy-default",
            now_wall + chrono::Duration::seconds(2),
            now_mono + std::time::Duration::from_secs(2),
        );
        tracker.record_request(
            "agent-alpha",
            "policy-default",
            now_wall + chrono::Duration::seconds(3),
            now_mono + std::time::Duration::from_secs(3),
        );

        let app = build_with_tracker(Arc::clone(&switch), Arc::clone(&tracker));
        let resp = app
            .oneshot(req_with_peer(Method::GET, "/v1/control/connections", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        let rows = json["connections"].as_array().unwrap();
        assert_eq!(rows.len(), 2, "expected two distinct agent entries");
        // snapshot() sorts by connected_since DESC — agent-beta has
        // the later anchor (T+1s vs T+0s).
        assert_eq!(rows[0]["agent_name"], "agent-beta");
        assert_eq!(rows[0]["total_requests"], 1);
        assert_eq!(rows[1]["agent_name"], "agent-alpha");
        assert_eq!(rows[1]["total_requests"], 3);
        // RFC 3339 + Z on every timestamp field.
        for row in rows {
            assert!(row["connected_since"].as_str().unwrap().ends_with('Z'));
            assert!(row["last_request_at"].as_str().unwrap().ends_with('Z'));
        }
    }

    // ── Story 7.7 P19: /v1/control/whoami ───────────────────────────

    #[tokio::test]
    async fn whoami_handler_loopback_returns_pid_and_version() {
        let switch = Arc::new(KillSwitch::new());
        let app = build(Arc::clone(&switch));
        let resp = app
            .oneshot(req_with_peer(Method::GET, "/v1/control/whoami", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        // PID matches this process; version matches Cargo.toml.
        assert_eq!(json["pid"].as_u64().unwrap(), u64::from(std::process::id()));
        assert_eq!(json["version"].as_str().unwrap(), env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn whoami_handler_non_loopback_returns_403() {
        let switch = Arc::new(KillSwitch::new());
        let app = build(Arc::clone(&switch));
        let resp = app
            .oneshot(req_with_peer(Method::GET, "/v1/control/whoami", non_loopback()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let json = body_json(resp).await;
        assert_eq!(json["error"]["code"], "forbidden_not_loopback");
    }

    // ── Story 7.30 Task 2: GET /v1/control/agent/{name}/policy_name ──

    /// In-memory `AgentIdentityStore` for the agent-policy-name handler
    /// tests. Holds a fixed map of agent records; only `get`/`list` are
    /// meaningful — other trait methods are no-ops (the read-only
    /// handler under test never calls them).
    #[derive(Clone, Default)]
    struct InMemoryAgentStore {
        agents: std::collections::HashMap<String, permitlayer_core::agent::AgentIdentity>,
    }

    impl InMemoryAgentStore {
        fn with_agent(name: &str, policy_name: &str) -> Self {
            let identity = permitlayer_core::agent::AgentIdentity::new(
                name.to_owned(),
                policy_name.to_owned(),
                "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".to_owned(),
                "0".repeat(64),
                chrono::Utc::now(),
                None,
            )
            .unwrap();
            let mut agents = std::collections::HashMap::new();
            agents.insert(name.to_owned(), identity);
            Self { agents }
        }
    }

    #[async_trait::async_trait]
    impl permitlayer_core::store::AgentIdentityStore for InMemoryAgentStore {
        async fn put(
            &self,
            _identity: permitlayer_core::agent::AgentIdentity,
        ) -> Result<(), permitlayer_core::store::StoreError> {
            Ok(())
        }
        async fn get(
            &self,
            name: &str,
        ) -> Result<
            Option<permitlayer_core::agent::AgentIdentity>,
            permitlayer_core::store::StoreError,
        > {
            Ok(self.agents.get(name).cloned())
        }
        async fn list(
            &self,
        ) -> Result<Vec<permitlayer_core::agent::AgentIdentity>, permitlayer_core::store::StoreError>
        {
            Ok(self.agents.values().cloned().collect())
        }
        async fn remove(&self, _name: &str) -> Result<bool, permitlayer_core::store::StoreError> {
            Ok(false)
        }
        async fn touch_last_seen(
            &self,
            _identity: permitlayer_core::agent::AgentIdentity,
        ) -> Result<(), permitlayer_core::store::StoreError> {
            Ok(())
        }
        async fn update_lookup_key_and_token(
            &self,
            _name: &str,
            _new_lookup_key_hex: String,
            _new_token_hash: String,
        ) -> Result<bool, permitlayer_core::store::StoreError> {
            Ok(false)
        }
        async fn update_policy(
            &self,
            _name: &str,
            _new_policy_name: String,
        ) -> Result<bool, permitlayer_core::store::StoreError> {
            Ok(false)
        }
    }

    /// Build a router wired with a caller-supplied `Option<Arc<dyn
    /// AgentIdentityStore>>`. Used by Story 7.30 endpoint tests; `None`
    /// exercises the `agent.store_unavailable` 503 branch.
    ///
    /// Round-1 review P21: callers may pass `known_policies` to seed
    /// `state.policy_set` with empty stub policies. Tests that want
    /// to exercise the dangling-policy-binding 422 branch pass `&[]`;
    /// tests that need the happy path stage the agent's policy name
    /// here.
    fn build_with_agent_store(
        kill_switch: Arc<KillSwitch>,
        agent_store: Option<Arc<dyn permitlayer_core::store::AgentIdentityStore>>,
        known_policies: &[&str],
    ) -> AgentStoreHarness {
        // Round-1 review P23: hold the TempDir in the returned
        // harness so the policies_dir survives the request (the
        // router stores its path) but is cleaned up when the test's
        // local binding drops — instead of `.keep()`'ing it which
        // leaks per-test directories under `$TMPDIR`.
        let policies_dir_tempdir = tempfile::tempdir().unwrap();
        let policies_dir = policies_dir_tempdir.path().to_path_buf();
        let policy_set = if known_policies.is_empty() {
            Arc::new(ArcSwap::from_pointee(PolicySet::empty()))
        } else {
            for name in known_policies {
                stage_minimal_policy(&policies_dir, name, &["gmail.readonly"]);
            }
            let compiled = permitlayer_core::policy::PolicySet::compile_from_dir(&policies_dir)
                .expect("test policy set must compile");
            Arc::new(ArcSwap::from_pointee(compiled))
        };
        let reload_mutex = Arc::new(std::sync::Mutex::new(()));
        let agent_registry = Arc::new(AgentRegistry::new(vec![]));
        let (ato, cs, co, stub, vault_dir) = test_reload_wiring();
        let router = router(
            kill_switch,
            None,
            policy_set,
            policies_dir,
            reload_mutex,
            agent_registry,
            agent_store,
            Arc::new(zeroize::Zeroizing::new([0x42u8; LOOKUP_KEY_BYTES])),
            test_approval_service(),
            test_conn_tracker(),
            test_plugin_registry(),
            ato,
            cs,
            co,
            stub,
            test_proxy_activation(),
            vault_dir,
            test_vault(),
            test_control_token(),
        );
        AgentStoreHarness { router, _policies_dir: policies_dir_tempdir }
    }

    /// Returned by `build_with_agent_store`. Holds the TempDir for
    /// the staged policies_dir so it survives as long as the test's
    /// binding; deref to `Router` for the oneshot-style call sites.
    struct AgentStoreHarness {
        router: Router,
        /// Underscored to suppress dead-code lint — the lifetime is
        /// the load-bearing function, not the field access.
        _policies_dir: tempfile::TempDir,
    }

    impl AgentStoreHarness {
        async fn oneshot(self, req: Request<Body>) -> Result<Response, std::convert::Infallible> {
            <Router as tower::ServiceExt<Request<Body>>>::oneshot(self.router, req).await
        }
    }

    #[tokio::test]
    async fn agent_policy_name_handler_returns_policy_for_existing_agent() {
        let switch = Arc::new(KillSwitch::new());
        let store: Arc<dyn permitlayer_core::store::AgentIdentityStore> =
            Arc::new(InMemoryAgentStore::with_agent("claude-desktop", "gmail-read-only"));
        // Round-1 review P21: stage the agent's policy so the
        // dangling-binding cross-check passes.
        let app = build_with_agent_store(Arc::clone(&switch), Some(store), &["gmail-read-only"]);

        let resp = app
            .oneshot(req_with_peer(
                Method::GET,
                "/v1/control/agent/claude-desktop/policy_name",
                loopback_v4(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["name"], "claude-desktop");
        assert_eq!(json["policy_name"], "gmail-read-only");
    }

    #[tokio::test]
    async fn agent_policy_name_handler_returns_404_for_missing_agent() {
        let switch = Arc::new(KillSwitch::new());
        let store: Arc<dyn permitlayer_core::store::AgentIdentityStore> =
            Arc::new(InMemoryAgentStore::with_agent("claude-desktop", "gmail-read-only"));
        let app = build_with_agent_store(Arc::clone(&switch), Some(store), &["gmail-read-only"]);

        let resp = app
            .oneshot(req_with_peer(
                Method::GET,
                "/v1/control/agent/openclaw-test/policy_name",
                loopback_v4(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let json = body_json(resp).await;
        assert_eq!(json["code"], "agent.not_found");
    }

    #[tokio::test]
    async fn agent_policy_name_handler_returns_503_when_store_unavailable() {
        let switch = Arc::new(KillSwitch::new());
        let app = build_with_agent_store(Arc::clone(&switch), None, &[]);

        let resp = app
            .oneshot(req_with_peer(
                Method::GET,
                "/v1/control/agent/claude-desktop/policy_name",
                loopback_v4(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json = body_json(resp).await;
        assert_eq!(json["code"], "agent.store_unavailable");
    }

    #[tokio::test]
    async fn agent_policy_name_handler_rejects_invalid_name() {
        let switch = Arc::new(KillSwitch::new());
        let store: Arc<dyn permitlayer_core::store::AgentIdentityStore> =
            Arc::new(InMemoryAgentStore::default());
        let app = build_with_agent_store(Arc::clone(&switch), Some(store), &[]);

        // `..` is not a valid agent name (path traversal guard).
        let resp = app
            .oneshot(req_with_peer(
                Method::GET,
                "/v1/control/agent/..%2Fetc/policy_name",
                loopback_v4(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert_eq!(json["code"], "agent.invalid_name");
    }

    /// Round-1 review P21: agent's policy_name is no longer in the
    /// active policy set (operator removed the file + reloaded).
    /// Handler returns 422 with operator-actionable remediation.
    #[tokio::test]
    async fn agent_policy_name_handler_returns_422_for_dangling_policy_binding() {
        let switch = Arc::new(KillSwitch::new());
        let store: Arc<dyn permitlayer_core::store::AgentIdentityStore> =
            Arc::new(InMemoryAgentStore::with_agent("claude-desktop", "removed-policy"));
        // Stage a DIFFERENT policy in the active set; the agent's
        // binding to "removed-policy" is dangling.
        let app = build_with_agent_store(Arc::clone(&switch), Some(store), &["gmail-read-only"]);

        let resp = app
            .oneshot(req_with_peer(
                Method::GET,
                "/v1/control/agent/claude-desktop/policy_name",
                loopback_v4(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let json = body_json(resp).await;
        assert_eq!(json["code"], "agent.dangling_policy_binding");
        let message = json["message"].as_str().unwrap_or_default();
        assert!(message.contains("agentsso agent rebind"), "remediation hint missing: {message}");
    }

    // ── Story 7.30 Task 3: GET /v1/control/credentials/{service}/meta ──

    /// Build a router with `state.vault_dir` pinned to a caller-supplied
    /// path. Used by Story 7.30 credentials-meta tests that need to
    /// stage a meta JSON fixture on disk.
    fn build_with_vault_dir(kill_switch: Arc<KillSwitch>, vault_dir: std::path::PathBuf) -> Router {
        let policy_set = Arc::new(ArcSwap::from_pointee(PolicySet::empty()));
        // Round-3 review P77: hold the TempDir for the router's
        // lifetime via `.keep()`. The prior pattern
        // `tempfile::tempdir().unwrap().path().to_path_buf()` dropped
        // the TempDir at end of let-binding, leaving a dangling
        // PathBuf to a removed directory — fine for handlers that
        // never touch policies_dir, but a footgun for any future
        // test using the helper that does. `.keep()` is consistent
        // with sibling test helpers in this file (e.g.
        // build_with_policies_dir).
        let policies_dir = tempfile::tempdir().unwrap().keep();
        let reload_mutex = Arc::new(std::sync::Mutex::new(()));
        let agent_registry = Arc::new(AgentRegistry::new(vec![]));
        let (ato, cs, co, stub, _placeholder_vault_dir) = test_reload_wiring();
        router(
            kill_switch,
            None,
            policy_set,
            policies_dir,
            reload_mutex,
            agent_registry,
            None,
            Arc::new(zeroize::Zeroizing::new([0x42u8; LOOKUP_KEY_BYTES])),
            test_approval_service(),
            test_conn_tracker(),
            test_plugin_registry(),
            ato,
            cs,
            co,
            stub,
            test_proxy_activation(),
            vault_dir,
            test_vault(),
            test_control_token(),
        )
    }

    #[tokio::test]
    async fn credentials_meta_handler_returns_exists_true_with_meta_for_present_credential() {
        let switch = Arc::new(KillSwitch::new());
        let vault_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            vault_dir.path().join("gmail-meta.json"),
            r#"{"client_type":"byo","client_source":"/abs/cs.json","connected_at":"2026-05-12T12:00:00Z","scopes":["https://mail.google.com/"]}"#,
        )
        .unwrap();
        let app = build_with_vault_dir(Arc::clone(&switch), vault_dir.path().to_path_buf());

        let resp = app
            .oneshot(req_with_peer(
                Method::GET,
                "/v1/control/credentials/gmail/meta",
                loopback_v4(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["exists"], true);
        assert_eq!(json["meta"]["client_type"], "byo");
        assert_eq!(json["meta"]["scopes"][0], "https://mail.google.com/");
    }

    #[tokio::test]
    async fn credentials_meta_handler_returns_exists_false_when_meta_missing() {
        let switch = Arc::new(KillSwitch::new());
        let vault_dir = tempfile::tempdir().unwrap();
        let app = build_with_vault_dir(Arc::clone(&switch), vault_dir.path().to_path_buf());

        let resp = app
            .oneshot(req_with_peer(
                Method::GET,
                "/v1/control/credentials/gmail/meta",
                loopback_v4(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["exists"], false);
        assert!(json.get("meta").is_none_or(serde_json::Value::is_null));
    }

    #[tokio::test]
    async fn credentials_meta_handler_rejects_unknown_service() {
        let switch = Arc::new(KillSwitch::new());
        let vault_dir = tempfile::tempdir().unwrap();
        let app = build_with_vault_dir(Arc::clone(&switch), vault_dir.path().to_path_buf());

        let resp = app
            .oneshot(req_with_peer(
                Method::GET,
                "/v1/control/credentials/slack/meta",
                loopback_v4(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert_eq!(json["code"], "credentials.unknown_service");
    }

    #[tokio::test]
    async fn credentials_meta_handler_returns_500_on_parse_failure() {
        let switch = Arc::new(KillSwitch::new());
        let vault_dir = tempfile::tempdir().unwrap();
        std::fs::write(vault_dir.path().join("gmail-meta.json"), b"this is not json").unwrap();
        let app = build_with_vault_dir(Arc::clone(&switch), vault_dir.path().to_path_buf());

        let resp = app
            .oneshot(req_with_peer(
                Method::GET,
                "/v1/control/credentials/gmail/meta",
                loopback_v4(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let json = body_json(resp).await;
        assert_eq!(json["code"], "credentials.meta_parse_failed");
    }

    // ── Story 7.30 Task 4: POST /v1/control/credentials/seal ─────────

    /// Wiring for seal-handler tests: builds a router with a fixed
    /// agent registry (single agent `"test-agent"` → policy `"test-policy"`),
    /// a real `tempdir/vault` directory for `state.vault_dir`, an
    /// optional audit store, and a real `Arc<Vault>` (so seal() can
    /// produce envelope bytes). Returns the router + the `home` tempdir
    /// (so tests can read the resulting on-disk files), keeping the
    /// tempdir alive for the test scope.
    fn build_with_seal_wiring(
        agent_name: &str,
        audit_store: Option<Arc<dyn permitlayer_core::store::AuditStore>>,
    ) -> (Router, tempfile::TempDir, Arc<KillSwitch>) {
        let switch = Arc::new(KillSwitch::new());
        let home_tmp = tempfile::tempdir().unwrap();
        let home = home_tmp.path();
        let vault_dir_path = home.join("vault");
        std::fs::create_dir_all(&vault_dir_path).unwrap();

        let identity = permitlayer_core::agent::AgentIdentity::new(
            agent_name.to_owned(),
            "test-policy".to_owned(),
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".to_owned(),
            "0".repeat(64),
            chrono::Utc::now(),
            None,
        )
        .unwrap();
        let agent_registry = Arc::new(AgentRegistry::new(vec![identity]));

        let policy_set = Arc::new(ArcSwap::from_pointee(PolicySet::empty()));
        // Round-3 review P77: hold the TempDir for the router's
        // lifetime via `.keep()`. Seal/verify endpoints don't read
        // `state.policies_dir`, but the prior pattern left a dangling
        // PathBuf — fix the foundation rather than rely on the
        // handlers staying policies_dir-free.
        let policies_dir = tempfile::tempdir().unwrap().keep();
        let reload_mutex = Arc::new(std::sync::Mutex::new(()));
        let (ato, cs, co, stub, _placeholder_vault_dir) = test_reload_wiring();

        let router = router(
            Arc::clone(&switch),
            audit_store,
            policy_set,
            policies_dir,
            reload_mutex,
            agent_registry,
            None,
            Arc::new(zeroize::Zeroizing::new([0x42u8; LOOKUP_KEY_BYTES])),
            test_approval_service(),
            test_conn_tracker(),
            test_plugin_registry(),
            ato,
            cs,
            co,
            stub,
            test_proxy_activation(),
            vault_dir_path,
            test_vault(),
            test_control_token(),
        );
        (router, home_tmp, switch)
    }

    /// Build a seal-handler request with the canonical valid body. Override
    /// individual fields via closure mutation before serialization.
    fn seal_request_body(
        service: &str,
        agent: &str,
        if_exists: &str,
        with_refresh: bool,
    ) -> serde_json::Value {
        let mut body = serde_json::json!({
            "service": service,
            "agent": agent,
            "access_token": "ya29.test-access-token-bytes",
            "granted_scopes": ["https://mail.google.com/"],
            "client_type": "byo",
            "client_source": "/abs/cs.json",
            "expires_in_secs": 3599,
            "if_exists": if_exists,
        });
        if with_refresh {
            body["refresh_token"] = serde_json::json!("1//test-refresh-token-bytes");
        }
        body
    }

    fn post_seal_request(body: serde_json::Value) -> Request<Body> {
        let mut r = Request::builder()
            .method(Method::POST)
            .uri("/v1/control/credentials/seal")
            .header("content-type", "application/json")
            .header("x-agentsso-control", test_control_token_header())
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        r.extensions_mut().insert(ConnectInfo(loopback_v4()));
        r
    }

    #[tokio::test]
    async fn credentials_seal_handler_seals_fresh_credential() {
        let (app, home_tmp, _) = build_with_seal_wiring("test-agent", None);
        let body = seal_request_body("gmail", "test-agent", "replace", true);
        let resp = app.oneshot(post_seal_request(body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["sealed"], true);
        assert_eq!(json["replaced_previous"], false);
        assert_eq!(json["meta"]["client_type"], "byo");

        // On-disk artifacts.
        let vault_dir = home_tmp.path().join("vault");
        assert!(vault_dir.join("gmail.sealed").is_file());
        assert!(vault_dir.join("gmail-refresh.sealed").is_file());
        assert!(vault_dir.join("gmail-meta.json").is_file());
    }

    #[tokio::test]
    async fn credentials_seal_handler_replaces_previous_on_replace() {
        let (app, home_tmp, switch) = build_with_seal_wiring("test-agent", None);
        // First seal.
        let body = seal_request_body("gmail", "test-agent", "replace", false);
        let resp = app.oneshot(post_seal_request(body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Second seal (replace).
        let (app2, _home2, _) = (
            build_with_seal_wiring_with_existing_home(
                "test-agent",
                home_tmp.path().to_path_buf(),
                None,
            ),
            home_tmp,
            switch,
        );
        let body = seal_request_body("gmail", "test-agent", "replace", false);
        let resp = app2.oneshot(post_seal_request(body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["sealed"], true);
        assert_eq!(json["replaced_previous"], true);
    }

    /// Variant of `build_with_seal_wiring` that reuses an existing
    /// `home` directory. Used by the `replace` test which needs to
    /// observe state across two sequential handler invocations.
    fn build_with_seal_wiring_with_existing_home(
        agent_name: &str,
        home: std::path::PathBuf,
        audit_store: Option<Arc<dyn permitlayer_core::store::AuditStore>>,
    ) -> Router {
        let switch = Arc::new(KillSwitch::new());
        let vault_dir_path = home.join("vault");
        std::fs::create_dir_all(&vault_dir_path).unwrap();

        let identity = permitlayer_core::agent::AgentIdentity::new(
            agent_name.to_owned(),
            "test-policy".to_owned(),
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".to_owned(),
            "0".repeat(64),
            chrono::Utc::now(),
            None,
        )
        .unwrap();
        let agent_registry = Arc::new(AgentRegistry::new(vec![identity]));

        let policy_set = Arc::new(ArcSwap::from_pointee(PolicySet::empty()));
        // Round-3 review P77: hold the TempDir for the router's
        // lifetime via `.keep()`. See sibling helper.
        let policies_dir = tempfile::tempdir().unwrap().keep();
        let reload_mutex = Arc::new(std::sync::Mutex::new(()));
        let (ato, cs, co, stub, _placeholder_vault_dir) = test_reload_wiring();

        router(
            Arc::clone(&switch),
            audit_store,
            policy_set,
            policies_dir,
            reload_mutex,
            agent_registry,
            None,
            Arc::new(zeroize::Zeroizing::new([0x42u8; LOOKUP_KEY_BYTES])),
            test_approval_service(),
            test_conn_tracker(),
            test_plugin_registry(),
            ato,
            cs,
            co,
            stub,
            test_proxy_activation(),
            vault_dir_path,
            test_vault(),
            test_control_token(),
        )
    }

    #[tokio::test]
    async fn credentials_seal_handler_skips_when_if_exists_skip_and_present() {
        let (app, home_tmp, _) = build_with_seal_wiring("test-agent", None);
        // First seal establishes the credential.
        let body = seal_request_body("gmail", "test-agent", "replace", false);
        let resp = app.oneshot(post_seal_request(body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Second seal with if_exists=skip.
        let app2 = build_with_seal_wiring_with_existing_home(
            "test-agent",
            home_tmp.path().to_path_buf(),
            None,
        );
        let body = seal_request_body("gmail", "test-agent", "skip", false);
        let resp = app2.oneshot(post_seal_request(body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["sealed"], false);
        assert_eq!(json["replaced_previous"], false);
    }

    #[tokio::test]
    async fn credentials_seal_handler_returns_409_when_if_exists_error_and_present() {
        let (app, home_tmp, _) = build_with_seal_wiring("test-agent", None);
        let body = seal_request_body("gmail", "test-agent", "replace", false);
        let resp = app.oneshot(post_seal_request(body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let app2 = build_with_seal_wiring_with_existing_home(
            "test-agent",
            home_tmp.path().to_path_buf(),
            None,
        );
        let body = seal_request_body("gmail", "test-agent", "error", false);
        let resp = app2.oneshot(post_seal_request(body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let json = body_json(resp).await;
        assert_eq!(json["code"], "credentials.already_exists");
    }

    #[tokio::test]
    async fn credentials_seal_handler_returns_422_for_unknown_agent() {
        let (app, _home_tmp, _) = build_with_seal_wiring("test-agent", None);
        let body = seal_request_body("gmail", "no-such-agent", "replace", false);
        let resp = app.oneshot(post_seal_request(body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let json = body_json(resp).await;
        assert_eq!(json["code"], "credentials.unknown_agent");
    }

    #[tokio::test]
    async fn credentials_seal_handler_returns_422_for_unknown_service() {
        let (app, _home_tmp, _) = build_with_seal_wiring("test-agent", None);
        let body = seal_request_body("slack", "test-agent", "replace", false);
        let resp = app.oneshot(post_seal_request(body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let json = body_json(resp).await;
        assert_eq!(json["code"], "credentials.unknown_service");
    }

    #[tokio::test]
    async fn credentials_seal_handler_emits_audit_event_with_expected_shape() {
        let home_tmp = tempfile::tempdir().unwrap();
        let store = build_audit_store(home_tmp.path());

        // First seal — fresh credential, `replaced_previous: false`.
        let app1 = build_with_seal_wiring_with_existing_home(
            "test-agent",
            home_tmp.path().to_path_buf(),
            Some(Arc::clone(&store)),
        );
        let body = seal_request_body("gmail", "test-agent", "replace", true);
        let resp = app1.oneshot(post_seal_request(body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Round-1 review P15: second seal — replaces the first, so
        // `replaced_previous: true` AND the audit log carries TWO
        // `credentials-sealed` events with distinct replaced_previous
        // values.
        let app2 = build_with_seal_wiring_with_existing_home(
            "test-agent",
            home_tmp.path().to_path_buf(),
            Some(Arc::clone(&store)),
        );
        let body2 = seal_request_body("gmail", "test-agent", "replace", true);
        let resp2 = app2.oneshot(post_seal_request(body2)).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);

        let events = read_audit_events(home_tmp.path());
        let seal_events: Vec<_> =
            events.iter().filter(|e| e.event_type == "credentials-sealed").collect();
        assert_eq!(seal_events.len(), 2, "expected one event per seal call");

        // First (fresh) seal — replaced_previous=false.
        let first = seal_events[0];
        assert_eq!(first.outcome, "ok");
        assert_eq!(first.extra["service"], "gmail");
        assert_eq!(first.extra["agent"], "test-agent");
        assert_eq!(first.extra["client_type"], "byo");
        assert_eq!(first.extra["client_source"], "/abs/cs.json");
        assert_eq!(first.extra["replaced_previous"], false);
        assert_eq!(first.extra["had_refresh_token"], true);
        assert_eq!(first.extra["scopes"][0], "https://mail.google.com/");

        // Second (replace) seal — replaced_previous=true.
        let second = seal_events[1];
        assert_eq!(second.outcome, "ok");
        assert_eq!(second.extra["replaced_previous"], true);
    }

    #[tokio::test]
    async fn credentials_seal_handler_rejects_bad_json() {
        let (app, _home_tmp, _) = build_with_seal_wiring("test-agent", None);
        let mut r = Request::builder()
            .method(Method::POST)
            .uri("/v1/control/credentials/seal")
            .header("content-type", "application/json")
            .header("x-agentsso-control", test_control_token_header())
            .body(Body::from(b"not json".to_vec()))
            .unwrap();
        r.extensions_mut().insert(ConnectInfo(loopback_v4()));
        let resp = app.oneshot(r).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert_eq!(json["code"], "credentials.bad_request");
    }

    // ── Story 7.30 Task 5: POST /v1/control/credentials/{service}/verify

    fn post_verify_request(service: &str, agent: &str) -> Request<Body> {
        let body = serde_json::json!({ "agent": agent });
        let mut r = Request::builder()
            .method(Method::POST)
            .uri(format!("/v1/control/credentials/{service}/verify"))
            .header("content-type", "application/json")
            .header("x-agentsso-control", test_control_token_header())
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        r.extensions_mut().insert(ConnectInfo(loopback_v4()));
        r
    }

    #[tokio::test]
    async fn credentials_verify_handler_returns_404_when_credential_missing() {
        let (app, _home_tmp, _) = build_with_seal_wiring("test-agent", None);
        let resp = app.oneshot(post_verify_request("gmail", "test-agent")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let json = body_json(resp).await;
        assert_eq!(json["code"], "credentials.not_found");
    }

    #[tokio::test]
    async fn credentials_verify_handler_rejects_unknown_service() {
        let (app, _home_tmp, _) = build_with_seal_wiring("test-agent", None);
        let resp = app.oneshot(post_verify_request("slack", "test-agent")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert_eq!(json["code"], "credentials.unknown_service");
    }

    #[tokio::test]
    async fn credentials_verify_handler_rejects_bad_json() {
        let (app, _home_tmp, _) = build_with_seal_wiring("test-agent", None);
        let mut r = Request::builder()
            .method(Method::POST)
            .uri("/v1/control/credentials/gmail/verify")
            .header("content-type", "application/json")
            .header("x-agentsso-control", test_control_token_header())
            .body(Body::from(b"not json".to_vec()))
            .unwrap();
        r.extensions_mut().insert(ConnectInfo(loopback_v4()));
        let resp = app.oneshot(r).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert_eq!(json["code"], "credentials.bad_request");
    }

    /// Corrupt-envelope path: write garbage bytes that fail at the
    /// envelope decoder. `CredentialFsStore::get` surfaces this as
    /// `StoreError::CorruptEnvelope` BEFORE the vault gets a chance
    /// to unseal — the daemon returns `credentials.store_io_failed`.
    /// Round-1 review P14: tightened from the previous "either
    /// store_io_failed or unseal_failed" loose match to pin the
    /// specific code that the corrupt-envelope path produces.
    #[tokio::test]
    async fn credentials_verify_handler_returns_500_on_corrupt_envelope() {
        let home_tmp = tempfile::tempdir().unwrap();
        let vault_dir = home_tmp.path().join("vault");
        std::fs::create_dir_all(&vault_dir).unwrap();
        std::fs::write(vault_dir.join("gmail.sealed"), b"not-a-real-sealed-envelope").unwrap();

        let app = build_with_seal_wiring_with_existing_home(
            "test-agent",
            home_tmp.path().to_path_buf(),
            None,
        );
        let resp = app.oneshot(post_verify_request("gmail", "test-agent")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let json = body_json(resp).await;
        assert_eq!(
            json["code"], "credentials.store_io_failed",
            "corrupt envelope should surface as store_io_failed (envelope decoder failure), \
             not unseal_failed (AEAD failure)",
        );
    }

    /// Key-drift path: stage a structurally-valid sealed envelope
    /// produced under one Vault key, then run verify with a Vault
    /// holding a different key. The envelope parses cleanly so
    /// `CredentialFsStore::get` returns Ok, but `Vault::unseal`
    /// produces an AEAD tag mismatch — daemon returns
    /// `credentials.unseal_failed`. Round-1 review P14: distinct
    /// test from the corrupt-envelope path so each code branch is
    /// pinned independently.
    #[tokio::test]
    async fn credentials_verify_handler_returns_500_on_key_drift() {
        let home_tmp = tempfile::tempdir().unwrap();
        let vault_dir = home_tmp.path().join("vault");
        std::fs::create_dir_all(&vault_dir).unwrap();

        // Seal a real envelope under a "wrong" key (all 0xAA).
        let wrong_key = zeroize::Zeroizing::new([0xAAu8; permitlayer_keystore::MASTER_KEY_LEN]);
        let wrong_vault = permitlayer_vault::Vault::new(wrong_key, 0);
        let token = permitlayer_credential::OAuthToken::from_trusted_bytes(b"ya29.fake".to_vec());
        let sealed = wrong_vault.seal("gmail", &token).expect("wrong-vault seal");

        // Write the sealed envelope to disk via the real store so
        // the bytes are in the format `CredentialFsStore::get`
        // expects.
        let store_for_seal =
            permitlayer_core::store::fs::CredentialFsStore::new(home_tmp.path().to_path_buf())
                .expect("store init");
        permitlayer_core::store::CredentialStore::put(&store_for_seal, "gmail", sealed)
            .await
            .expect("put sealed");

        // Build the handler with the canonical test_vault (key
        // `[0x55u8; ...]`) — different from the 0xAA we sealed
        // under, so unseal will AEAD-fail.
        let app = build_with_seal_wiring_with_existing_home(
            "test-agent",
            home_tmp.path().to_path_buf(),
            None,
        );
        let resp = app.oneshot(post_verify_request("gmail", "test-agent")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let json = body_json(resp).await;
        assert_eq!(
            json["code"], "credentials.unseal_failed",
            "key drift should surface as unseal_failed (AEAD tag mismatch), \
             not store_io_failed (envelope decoder)",
        );
        // P20 recovery hint: confirm operator gets the re-run hint.
        let message = json["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("agentsso connect"),
            "unseal-fail message should suggest re-running agentsso connect; got: {message}",
        );
    }

    #[test]
    fn verify_reason_kebab_label_covers_known_variants() {
        use permitlayer_oauth::error::VerifyReason;
        assert_eq!(
            verify_reason_kebab_label(&VerifyReason::ServiceDisabled {
                service: "calendar.googleapis.com".to_owned(),
                project: None,
                also_billing_disabled: false,
            }),
            "service-disabled"
        );
        assert_eq!(
            verify_reason_kebab_label(&VerifyReason::BillingDisabled { project: None }),
            "billing-disabled"
        );
        assert_eq!(
            verify_reason_kebab_label(&VerifyReason::ScopeInsufficient {
                missing_scopes: vec![],
                also_service_disabled: None,
                also_billing_disabled: false,
            }),
            "scope-insufficient"
        );
        assert_eq!(verify_reason_kebab_label(&VerifyReason::Other), "other");
    }

    #[test]
    fn verify_reason_remediation_url_renders_console_url_for_service_disabled() {
        use permitlayer_oauth::error::VerifyReason;
        let url = verify_reason_remediation_url(&VerifyReason::ServiceDisabled {
            service: "calendar.googleapis.com".to_owned(),
            project: Some("my-project".to_owned()),
            also_billing_disabled: false,
        })
        .unwrap();
        assert_eq!(
            url,
            "https://console.cloud.google.com/apis/library/calendar.googleapis.com?project=my-project"
        );
        // None for `ScopeInsufficient` (operator must re-consent, no URL applies).
        assert!(
            verify_reason_remediation_url(&VerifyReason::ScopeInsufficient {
                missing_scopes: vec![],
                also_service_disabled: None,
                also_billing_disabled: false,
            })
            .is_none()
        );
    }

    // ── Story 7.30 Task 6: POST /v1/control/policy/{name}/scopes ─────

    /// Build a router with `state.policies_dir` pinned to a caller-
    /// supplied path, plus an optional audit store. Used by the
    /// policy-scopes-endpoint tests which need to stage a policy file
    /// on disk and (in the audit-shape test) observe the
    /// `policy-scopes-added` event.
    fn build_with_policies_dir(
        policies_dir: std::path::PathBuf,
        audit_store: Option<Arc<dyn permitlayer_core::store::AuditStore>>,
    ) -> Router {
        let switch = Arc::new(KillSwitch::new());
        let policy_set = Arc::new(ArcSwap::from_pointee(PolicySet::empty()));
        let reload_mutex = Arc::new(std::sync::Mutex::new(()));
        let agent_registry = Arc::new(AgentRegistry::new(vec![]));
        let (ato, cs, co, stub, vault_dir) = test_reload_wiring();
        router(
            switch,
            audit_store,
            policy_set,
            policies_dir,
            reload_mutex,
            agent_registry,
            None,
            Arc::new(zeroize::Zeroizing::new([0x42u8; LOOKUP_KEY_BYTES])),
            test_approval_service(),
            test_conn_tracker(),
            test_plugin_registry(),
            ato,
            cs,
            co,
            stub,
            test_proxy_activation(),
            vault_dir,
            test_vault(),
            test_control_token(),
        )
    }

    fn stage_minimal_policy(policies_dir: &std::path::Path, name: &str, scopes: &[&str]) {
        let scopes_toml: String =
            scopes.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(", ");
        let body = format!(
            "[[policies]]\nname = \"{name}\"\nscopes = [{scopes_toml}]\nresources = [\"*\"]\napproval-mode = \"auto\"\nauto-approve-reads = true\n"
        );
        std::fs::write(policies_dir.join(format!("{name}.toml")), body).unwrap();
    }

    fn stage_multi_policy_default(policies_dir: &std::path::Path, gmail_scopes: &[&str]) {
        let scopes_toml: String =
            gmail_scopes.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(", ");
        let body = format!(
            r#"[[policies]]
name = "gmail-read-only"
scopes = [{scopes_toml}]
resources = ["*"]
approval-mode = "auto"
auto-approve-reads = true

[[policies]]
name = "calendar-prompt-on-write"
scopes = ["calendar.readonly", "calendar.events"]
resources = ["primary"]
approval-mode = "prompt"
auto-approve-reads = true

[[policies.rules]]
id = "allow-calendar-reads"
scopes = ["calendar.readonly"]
action = "allow"

[[policies]]
name = "drive-research-scope-restricted"
scopes = ["drive.readonly", "drive.metadata"]
resources = ["research-shared"]
approval-mode = "auto"
auto-approve-reads = true
"#,
        );
        std::fs::write(policies_dir.join("default.toml"), body).unwrap();
    }

    fn post_policy_scopes(policy_name: &str, short_names: &[&str]) -> Request<Body> {
        let body = serde_json::json!({ "short_names": short_names });
        let mut r = Request::builder()
            .method(Method::POST)
            .uri(format!("/v1/control/policy/{policy_name}/scopes"))
            .header("content-type", "application/json")
            .header("x-agentsso-control", test_control_token_header())
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        r.extensions_mut().insert(ConnectInfo(loopback_v4()));
        r
    }

    #[tokio::test]
    async fn policy_scopes_handler_multi_policy_default_toml_noops_for_seeded_gmail() {
        let home_tmp = tempfile::tempdir().unwrap();
        let store = build_audit_store(home_tmp.path());

        let policies_dir = tempfile::tempdir().unwrap();
        stage_multi_policy_default(policies_dir.path(), &["gmail.readonly", "gmail.metadata"]);
        let default_path = policies_dir.path().join("default.toml");
        let before = std::fs::read(&default_path).unwrap();

        let app =
            build_with_policies_dir(policies_dir.path().to_path_buf(), Some(Arc::clone(&store)));
        let resp =
            app.oneshot(post_policy_scopes("gmail-read-only", &["gmail.readonly"])).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["policy_name"], "gmail-read-only");
        assert_eq!(json["added"].as_array().unwrap().len(), 0);
        assert_eq!(json["reloaded"], false);
        assert!(!policies_dir.path().join("gmail-read-only.toml").exists());
        assert_eq!(std::fs::read(&default_path).unwrap(), before);

        let events = read_audit_events(home_tmp.path());
        let scope_events: Vec<_> =
            events.iter().filter(|e| e.event_type == "policy-scopes-added").collect();
        assert_eq!(scope_events.len(), 0, "seeded-gmail no-op must not emit add audit");
    }

    #[tokio::test]
    async fn policy_scopes_handler_merges_into_default_toml_when_scope_absent() {
        let policies_dir = tempfile::tempdir().unwrap();
        stage_multi_policy_default(policies_dir.path(), &["gmail.readonly"]);

        let app = build_with_policies_dir(policies_dir.path().to_path_buf(), None);
        let resp =
            app.oneshot(post_policy_scopes("gmail-read-only", &["gmail.metadata"])).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["policy_name"], "gmail-read-only");
        assert_eq!(json["added"][0], "gmail.metadata");
        assert_eq!(json["reloaded"], true);
        assert!(!policies_dir.path().join("gmail-read-only.toml").exists());

        let text = std::fs::read_to_string(policies_dir.path().join("default.toml")).unwrap();
        let parsed: permitlayer_core::policy::schema::TomlPolicyFile =
            toml::from_str(&text).unwrap();
        let gmail = parsed.policies.iter().find(|p| p.name == "gmail-read-only").unwrap();
        assert_eq!(gmail.scopes, vec!["gmail.metadata", "gmail.readonly"]);
        let calendar =
            parsed.policies.iter().find(|p| p.name == "calendar-prompt-on-write").unwrap();
        assert_eq!(calendar.resources, vec!["primary"]);
        assert_eq!(calendar.rules.len(), 1);
    }

    #[tokio::test]
    async fn policy_scopes_handler_duplicate_name_returns_500_and_audit() {
        let home_tmp = tempfile::tempdir().unwrap();
        let store = build_audit_store(home_tmp.path());

        let policies_dir = tempfile::tempdir().unwrap();
        stage_minimal_policy(policies_dir.path(), "gmail-read-only", &["gmail.readonly"]);
        let duplicate = r#"[[policies]]
name = "gmail-read-only"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
auto-approve-reads = true
"#;
        std::fs::write(policies_dir.path().join("duplicate.toml"), duplicate).unwrap();

        let app =
            build_with_policies_dir(policies_dir.path().to_path_buf(), Some(Arc::clone(&store)));
        let resp =
            app.oneshot(post_policy_scopes("gmail-read-only", &["gmail.metadata"])).await.unwrap();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let json = body_json(resp).await;
        assert_eq!(json["code"], "policy.duplicate_name");

        let events = read_audit_events(home_tmp.path());
        let denied: Vec<_> =
            events.iter().filter(|e| e.event_type == "policy-scopes-denied").collect();
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].extra["error_code"], "policy.duplicate_name");
    }

    #[tokio::test]
    async fn policy_scopes_handler_merges_new_scopes() {
        let home_tmp = tempfile::tempdir().unwrap();
        let store = build_audit_store(home_tmp.path());

        let policies_dir = tempfile::tempdir().unwrap();
        stage_minimal_policy(policies_dir.path(), "gmail-read-only", &["gmail.readonly"]);

        let app =
            build_with_policies_dir(policies_dir.path().to_path_buf(), Some(Arc::clone(&store)));
        let resp =
            app.oneshot(post_policy_scopes("gmail-read-only", &["gmail.metadata"])).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["policy_name"], "gmail-read-only");
        assert_eq!(json["before"][0], "gmail.readonly");
        assert_eq!(json["added"][0], "gmail.metadata");
        assert_eq!(json["after"].as_array().unwrap().len(), 2);
        assert_eq!(json["reloaded"], true);

        // Round-1 review P22: pin the reload audit event's diff
        // shape so a regression that confuses "added" vs "modified"
        // (e.g., loading an already-empty PolicySet vs. starting
        // from the previous-edit state) fails this assertion.
        // `build_with_policies_dir` starts with `PolicySet::empty()`
        // so the test policy is "added" to the live set on reload.
        let events = read_audit_events(home_tmp.path());
        let reload_events: Vec<_> =
            events.iter().filter(|e| e.event_type == "policy-reloaded").collect();
        assert_eq!(reload_events.len(), 1, "exactly one reload audit event expected");
        let event = reload_events[0];
        assert_eq!(event.outcome, "ok");
        let added = event.extra["added"].as_array().expect("added array");
        let modified = event.extra["modified"].as_array().expect("modified array");
        let removed = event.extra["removed"].as_array().expect("removed array");
        assert!(
            added.iter().any(|v| v == "gmail-read-only"),
            "policy 'gmail-read-only' should appear in `added` (PolicySet was empty pre-reload); \
             got added={added:?}, modified={modified:?}, removed={removed:?}",
        );
    }

    #[tokio::test]
    async fn policy_scopes_handler_no_op_when_scopes_already_present() {
        let policies_dir = tempfile::tempdir().unwrap();
        stage_minimal_policy(
            policies_dir.path(),
            "gmail-read-only",
            &["gmail.readonly", "gmail.metadata"],
        );

        let app = build_with_policies_dir(policies_dir.path().to_path_buf(), None);
        let resp =
            app.oneshot(post_policy_scopes("gmail-read-only", &["gmail.metadata"])).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["added"].as_array().unwrap().len(), 0);
        assert_eq!(json["reloaded"], false);
    }

    #[tokio::test]
    async fn policy_scopes_handler_returns_404_when_policy_file_missing() {
        let policies_dir = tempfile::tempdir().unwrap();
        let app = build_with_policies_dir(policies_dir.path().to_path_buf(), None);
        let resp =
            app.oneshot(post_policy_scopes("does-not-exist", &["gmail.metadata"])).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let json = body_json(resp).await;
        assert_eq!(json["code"], "policy.not_found");
    }

    #[tokio::test]
    async fn policy_scopes_handler_rejects_invalid_policy_name() {
        let policies_dir = tempfile::tempdir().unwrap();
        let app = build_with_policies_dir(policies_dir.path().to_path_buf(), None);
        // `..` path traversal: server-side check rejects before fs touch.
        let resp = app.oneshot(post_policy_scopes("..%2Fetc", &["gmail.metadata"])).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert_eq!(json["code"], "policy.invalid_name");
    }

    #[tokio::test]
    async fn policy_scopes_handler_emits_audit_event_on_merge() {
        let home_tmp = tempfile::tempdir().unwrap();
        let store = build_audit_store(home_tmp.path());

        let policies_dir = tempfile::tempdir().unwrap();
        stage_minimal_policy(policies_dir.path(), "gmail-read-only", &["gmail.readonly"]);

        let app =
            build_with_policies_dir(policies_dir.path().to_path_buf(), Some(Arc::clone(&store)));
        let resp =
            app.oneshot(post_policy_scopes("gmail-read-only", &["gmail.metadata"])).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let events = read_audit_events(home_tmp.path());
        let scope_events: Vec<_> =
            events.iter().filter(|e| e.event_type == "policy-scopes-added").collect();
        assert_eq!(scope_events.len(), 1);
        let event = scope_events[0];
        assert_eq!(event.outcome, "ok");
        assert_eq!(event.extra["policy_name"], "gmail-read-only");
        assert_eq!(event.extra["before"][0], "gmail.readonly");
        assert_eq!(event.extra["added"][0], "gmail.metadata");
        let after = event.extra["after"].as_array().unwrap();
        assert_eq!(after.len(), 2);
    }

    #[tokio::test]
    async fn policy_scopes_handler_no_op_skips_audit_event() {
        let home_tmp = tempfile::tempdir().unwrap();
        let store = build_audit_store(home_tmp.path());

        let policies_dir = tempfile::tempdir().unwrap();
        stage_minimal_policy(
            policies_dir.path(),
            "gmail-read-only",
            &["gmail.readonly", "gmail.metadata"],
        );

        let app =
            build_with_policies_dir(policies_dir.path().to_path_buf(), Some(Arc::clone(&store)));
        let resp =
            app.oneshot(post_policy_scopes("gmail-read-only", &["gmail.metadata"])).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let events = read_audit_events(home_tmp.path());
        let scope_events: Vec<_> =
            events.iter().filter(|e| e.event_type == "policy-scopes-added").collect();
        assert_eq!(scope_events.len(), 0, "no-op merge must not emit audit event");
    }

    // ── Story 7.34 Task 1: GET /v1/control/policies/{name} ───────────

    async fn body_string(resp: Response) -> String {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn build_with_loaded_policies(policies_dir: std::path::PathBuf) -> Router {
        let compiled = permitlayer_core::policy::PolicySet::compile_from_dir(&policies_dir)
            .expect("test policy set must compile");
        let policy_set = Arc::new(ArcSwap::from_pointee(compiled));
        let reload_mutex = Arc::new(std::sync::Mutex::new(()));
        let agent_registry = Arc::new(AgentRegistry::new(vec![]));
        let (ato, cs, co, stub, vault_dir) = test_reload_wiring();
        router(
            Arc::new(KillSwitch::new()),
            None,
            policy_set,
            policies_dir,
            reload_mutex,
            agent_registry,
            None,
            Arc::new(zeroize::Zeroizing::new([0x42u8; LOOKUP_KEY_BYTES])),
            test_approval_service(),
            test_conn_tracker(),
            test_plugin_registry(),
            ato,
            cs,
            co,
            stub,
            test_proxy_activation(),
            vault_dir,
            test_vault(),
            test_control_token(),
        )
    }

    #[tokio::test]
    async fn show_policy_handler_returns_toml_for_existing_policy() {
        let policies_dir = tempfile::tempdir().unwrap();
        stage_minimal_policy(policies_dir.path(), "gmail-read-only", &["gmail.readonly"]);
        let app = build_with_loaded_policies(policies_dir.path().to_path_buf());

        let resp = app
            .oneshot(req_with_peer(
                Method::GET,
                "/v1/control/policies/gmail-read-only",
                loopback_v4(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.contains("text/plain"), "expected text/plain, got {ct}");
        let body = body_string(resp).await;
        assert!(body.contains("name = \"gmail-read-only\""), "TOML should contain policy name");
        assert!(body.contains("scopes = [\"gmail.readonly\"]"), "TOML should contain scopes");

        // Round-trip: the emitted TOML parses back into a TomlPolicyFile.
        let parsed: permitlayer_core::policy::schema::TomlPolicyFile =
            toml::from_str(&body).expect("show_policy_handler TOML must round-trip");
        assert_eq!(parsed.policies.len(), 1);
        assert_eq!(parsed.policies[0].name, "gmail-read-only");
    }

    #[tokio::test]
    async fn show_policy_handler_returns_404_for_missing_policy() {
        let policies_dir = tempfile::tempdir().unwrap();
        let app = build_with_loaded_policies(policies_dir.path().to_path_buf());

        let resp = app
            .oneshot(req_with_peer(
                Method::GET,
                "/v1/control/policies/does-not-exist",
                loopback_v4(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let json = body_json(resp).await;
        assert_eq!(json["code"], "policy.not_found");
    }

    // ── Story 7.34 Task 1: GET /v1/control/policies ──────────────────

    #[tokio::test]
    async fn list_policies_handler_returns_sorted_policies_with_origins_and_scopes() {
        let policies_dir = tempfile::tempdir().unwrap();
        stage_multi_policy_default(policies_dir.path(), &["gmail.readonly", "gmail.metadata"]);
        let app = build_with_loaded_policies(policies_dir.path().to_path_buf());

        let resp = app
            .oneshot(req_with_peer(Method::GET, "/v1/control/policies", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["status"], "ok");
        let policies = json["policies"].as_array().unwrap();
        assert_eq!(policies.len(), 3, "expected 3 policies from default.toml");
        // Sorted alphabetically
        assert_eq!(policies[0]["name"], "calendar-prompt-on-write");
        assert_eq!(
            policies[0]["scopes"],
            serde_json::json!(["calendar.events", "calendar.readonly"])
        );
        assert!(
            policies[0]["origin"].as_str().unwrap().contains("default.toml"),
            "origin should contain default.toml"
        );
        assert_eq!(policies[1]["name"], "drive-research-scope-restricted");
        assert_eq!(policies[2]["name"], "gmail-read-only");
    }

    #[tokio::test]
    async fn list_policies_handler_returns_empty_list_when_no_policies() {
        let policies_dir = tempfile::tempdir().unwrap();
        let app = build_with_loaded_policies(policies_dir.path().to_path_buf());

        let resp = app
            .oneshot(req_with_peer(Method::GET, "/v1/control/policies", loopback_v4()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["status"], "ok");
        let policies = json["policies"].as_array().unwrap();
        assert_eq!(policies.len(), 0);
    }

    // ── Story 7.34 Task 2: POST /v1/control/agent/{name}/rotate ──────

    /// Agent store that returns `Ok(true)` for `update_lookup_key_and_token`
    /// so the rotate handler can reach the happy path.
    #[derive(Clone, Default)]
    struct RotatableAgentStore {
        agents: std::collections::HashMap<String, permitlayer_core::agent::AgentIdentity>,
    }

    impl RotatableAgentStore {
        fn with_agent(name: &str, policy_name: &str) -> Self {
            let identity = permitlayer_core::agent::AgentIdentity::new(
                name.to_owned(),
                policy_name.to_owned(),
                "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".to_owned(),
                "0".repeat(64),
                chrono::Utc::now(),
                None,
            )
            .unwrap();
            let mut agents = std::collections::HashMap::new();
            agents.insert(name.to_owned(), identity);
            Self { agents }
        }
    }

    #[async_trait::async_trait]
    impl permitlayer_core::store::AgentIdentityStore for RotatableAgentStore {
        async fn put(
            &self,
            _identity: permitlayer_core::agent::AgentIdentity,
        ) -> Result<(), permitlayer_core::store::StoreError> {
            Ok(())
        }
        async fn get(
            &self,
            name: &str,
        ) -> Result<
            Option<permitlayer_core::agent::AgentIdentity>,
            permitlayer_core::store::StoreError,
        > {
            Ok(self.agents.get(name).cloned())
        }
        async fn list(
            &self,
        ) -> Result<Vec<permitlayer_core::agent::AgentIdentity>, permitlayer_core::store::StoreError>
        {
            Ok(self.agents.values().cloned().collect())
        }
        async fn remove(&self, _name: &str) -> Result<bool, permitlayer_core::store::StoreError> {
            Ok(false)
        }
        async fn touch_last_seen(
            &self,
            _identity: permitlayer_core::agent::AgentIdentity,
        ) -> Result<(), permitlayer_core::store::StoreError> {
            Ok(())
        }
        async fn update_lookup_key_and_token(
            &self,
            name: &str,
            _new_lookup_key_hex: String,
            _new_token_hash: String,
        ) -> Result<bool, permitlayer_core::store::StoreError> {
            Ok(self.agents.contains_key(name))
        }
        async fn update_policy(
            &self,
            _name: &str,
            _new_policy_name: String,
        ) -> Result<bool, permitlayer_core::store::StoreError> {
            Ok(false)
        }
    }

    fn build_with_rotatable_agent_store(
        store: Arc<RotatableAgentStore>,
    ) -> (Router, Arc<RotatableAgentStore>) {
        let switch = Arc::new(KillSwitch::new());
        let policy_set = Arc::new(ArcSwap::from_pointee(PolicySet::empty()));
        let policies_dir = tempfile::tempdir().unwrap().keep();
        let reload_mutex = Arc::new(std::sync::Mutex::new(()));
        let agent_registry = Arc::new(AgentRegistry::new(vec![]));
        let (ato, cs, co, stub, vault_dir) = test_reload_wiring();
        let router = router(
            switch,
            None,
            policy_set,
            policies_dir,
            reload_mutex,
            agent_registry,
            Some(store.clone()),
            Arc::new(zeroize::Zeroizing::new([0x42u8; LOOKUP_KEY_BYTES])),
            test_approval_service(),
            test_conn_tracker(),
            test_plugin_registry(),
            ato,
            cs,
            co,
            stub,
            test_proxy_activation(),
            vault_dir,
            test_vault(),
            test_control_token(),
        );
        (router, store)
    }

    #[tokio::test]
    async fn rotate_agent_handler_returns_new_bearer_for_existing_agent() {
        let store = Arc::new(RotatableAgentStore::with_agent("test-agent", "test-policy"));
        let (app, _store) = build_with_rotatable_agent_store(store);

        let resp = app
            .oneshot(req_with_peer(
                Method::POST,
                "/v1/control/agent/test-agent/rotate",
                loopback_v4(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["status"], "ok");
        assert_eq!(json["name"], "test-agent");
        let bearer = json["bearer_token"].as_str().unwrap();
        assert!(
            bearer.starts_with("agt_v2_test-agent_"),
            "bearer_token should start with agt_v2_test-agent_, got {bearer}"
        );
    }

    #[tokio::test]
    async fn rotate_agent_handler_returns_404_for_missing_agent() {
        let store = Arc::new(RotatableAgentStore::default());
        let (app, _store) = build_with_rotatable_agent_store(store);

        let resp = app
            .oneshot(req_with_peer(
                Method::POST,
                "/v1/control/agent/missing-agent/rotate",
                loopback_v4(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let json = body_json(resp).await;
        assert_eq!(json["code"], "agent.not_found");
    }

    #[tokio::test]
    async fn rotate_agent_handler_returns_503_when_store_unavailable() {
        let app = build(Arc::new(KillSwitch::new()));

        let resp = app
            .oneshot(req_with_peer(
                Method::POST,
                "/v1/control/agent/test-agent/rotate",
                loopback_v4(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json = body_json(resp).await;
        assert_eq!(json["code"], "agent.store_unavailable");
    }

    #[tokio::test]
    async fn rotate_agent_handler_rejects_invalid_name() {
        let store = Arc::new(RotatableAgentStore::with_agent("test-agent", "test-policy"));
        let (app, _store) = build_with_rotatable_agent_store(store);

        let resp = app
            .oneshot(req_with_peer(
                Method::POST,
                "/v1/control/agent/..%2Fetc/rotate",
                loopback_v4(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert_eq!(json["code"], "agent.invalid_name");
    }
}
