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
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Serialize;

use permitlayer_core::agent::{
    AgentIdentity, AgentRegistry, BEARER_TOKEN_PREFIX, LOOKUP_KEY_BYTES, compute_lookup_key,
    generate_bearer_token_bytes, hash_token, lookup_key_to_hex, validate_agent_name,
};
use permitlayer_core::audit::event::{AuditEvent, format_audit_timestamp};
use permitlayer_core::killswitch::{
    ActivationSummary, DeactivationSummary, KillReason, KillSwitch,
};
use permitlayer_core::policy::PolicySet;
use permitlayer_core::store::AgentIdentityStore;

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
    /// Story 8.7 AC #4: boot-time flag that is `true` when the daemon
    /// wired the 501-stub router branch at startup (no vault present).
    /// Set once at boot (before `spawn_reload_watcher` so an early
    /// SIGHUP can't observe a stale `false`). On every reload the
    /// handler checks whether `vault_dir` has since been created and,
    /// if so, emits a `tracing::warn!` + `config-reload-stub-detected`
    /// audit event — then CAS's the flag `true → false` so subsequent
    /// reloads short-circuit.
    ///
    /// **Once-per-daemon-lifetime** (decision 2:B of Story 8.7 review):
    /// the flag is only ever cleared by `detect_stub_and_warn` after a
    /// successful fire, never flipped back to `true`. The underlying
    /// invariant — "the axum router was wired for 501 stubs and can't
    /// be hot-swapped at runtime" — requires a full daemon restart to
    /// change, so repeating the diagnostic after the first fire would
    /// be pure audit-log noise.
    pub proxy_stub_branch_active: Arc<AtomicBool>,
    /// Story 8.7 AC #4: vault directory path to consult when the
    /// stub-active flag fires. Typically `{config.paths.home}/vault`.
    pub vault_dir: PathBuf,
}

/// Cap on concurrent agent CRUD operations. The number is small
/// because each operation runs an Argon2id hash on a blocking worker
/// (~100 ms) plus a disk write; 4 concurrent operations match a
/// typical laptop's blocking thread pool default and leave the
/// remaining workers free for the rest of the daemon. See Story 4.4
/// code-review HIGH finding "No rate limit on `register_agent_handler`."
pub(crate) const AGENT_CRUD_MAX_CONCURRENT: usize = 4;

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
/// `ConnectorsPayloadTooLarge` (AC #8).
#[derive(Debug, thiserror::Error)]
pub(crate) enum ControlError {
    #[error("control endpoints are loopback-only")]
    ForbiddenNotLoopback,
    /// `GET /v1/control/connectors` JSON exceeds the 1 MiB cap.
    #[error("connector registry JSON exceeds 1 MiB")]
    ConnectorsPayloadTooLarge { size_bytes: usize, limit_bytes: usize },
}

#[derive(Debug, Serialize)]
struct ControlErrorBody {
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
                    error: ControlErrorDetail {
                        code: "forbidden_not_loopback",
                        message: "control endpoints are loopback-only",
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

    // Story 8.7 review decision 1:A — detect_stub_and_warn fires
    // UNCONDITIONALLY at the tail, not only in the policy-reload
    // success arm. Keeps SIGHUP and HTTP reload behaviorally
    // equivalent per Task 3.5. The helper is idempotent per daemon
    // lifetime via CAS on `proxy_stub_branch_active` (decision 2:B).
    let stub_audit_store = state.audit_store.clone();
    let stub_vault_dir = state.vault_dir.clone();
    let stub_flag = Arc::clone(&state.proxy_stub_branch_active);
    super::sighup::detect_stub_and_warn(
        &stub_vault_dir,
        stub_audit_store.as_ref(),
        &stub_flag,
        request_id,
    )
    .await;

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
            let body = ReloadResponse {
                status: "ok",
                policies_loaded: diff.policies_loaded,
                added: diff.added.len(),
                modified: diff.modified.len(),
                unchanged: diff.unchanged.len(),
                removed: diff.removed.len(),
                agents_loaded,
            };
            let extras = ReloadResponseExtras { config_reload_error };
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
    let raw_bytes = generate_bearer_token_bytes();
    let plaintext_body = base64_url_no_pad(&raw_bytes);
    let bearer_token = format!("{BEARER_TOKEN_PREFIX}{plaintext_body}");
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
    let lookup_key = compute_lookup_key(&state.agent_lookup_key, bearer_token.as_bytes());
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
    if let Err(e) = store.list().await.map(|agents| state.agent_registry.replace_with(agents)) {
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

    let body = RegisterAgentResponse {
        status: "ok",
        name: payload.name,
        policy_name: payload.policy_name,
        bearer_token,
        created_at: format_audit_timestamp(created_at),
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
    if let Ok(agents) = store.list().await {
        state.agent_registry.replace_with(agents);
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
    vault_dir: PathBuf,
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
        agent_registry,
        agent_store,
        agent_lookup_key,
        agent_crud_semaphore: Arc::new(tokio::sync::Semaphore::new(AGENT_CRUD_MAX_CONCURRENT)),
        approval_service,
        conn_tracker,
        plugin_registry,
        approval_timeout_atomic,
        config_state,
        cli_overrides,
        proxy_stub_branch_active,
        vault_dir,
    };
    Router::new()
        .route("/v1/control/kill", post(kill_handler))
        .route("/v1/control/resume", post(resume_handler))
        .route("/v1/control/state", get(state_handler))
        .route("/v1/control/reload", post(reload_handler))
        .route("/v1/control/agent/register", post(register_agent_handler))
        .route("/v1/control/agent/list", get(list_agents_handler))
        .route("/v1/control/agent/remove", post(remove_agent_handler))
        .route("/v1/control/connections", get(connections_handler))
        .route("/v1/control/connectors", get(connectors_handler))
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

    fn build(kill_switch: Arc<KillSwitch>) -> Router {
        let policy_set = Arc::new(ArcSwap::from_pointee(PolicySet::empty()));
        let policies_dir = tempfile::tempdir().unwrap().keep();
        let reload_mutex = Arc::new(std::sync::Mutex::new(()));
        // Story 4.4: empty registry + zero lookup key. Tests that
        // exercise the agent control endpoints construct their own
        // registry; everything else is fine with the default empty.
        let agent_registry = Arc::new(AgentRegistry::new(vec![]));
        let (ato, cs, co, stub, vault) = test_reload_wiring();
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
            vault,
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
        let (ato, cs, co, stub, vault) = test_reload_wiring();
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
            vault,
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
        let (ato, cs, co, stub, vault) = test_reload_wiring();
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
            vault,
        )
    }

    /// Build a `Request` carrying a `ConnectInfo(addr)` extension so the
    /// `ConnectInfo` extractor sees the provided peer address when the
    /// router is driven via `ServiceExt::oneshot`.
    fn req_with_peer(method: Method, path: &str, peer: SocketAddr) -> Request<Body> {
        let mut r = Request::builder().method(method).uri(path).body(Body::empty()).unwrap();
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
        let (ato, cs, co, stub, vault) = test_reload_wiring();
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
            vault,
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
}
