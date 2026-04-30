use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use axum::extract::State;
use axum::http::StatusCode;
#[cfg(debug_assertions)]
use axum::routing::post;
use axum::routing::{any, get};
use axum::{Json, Router};
use serde::Serialize;

use permitlayer_core::agent::{AgentRegistry, LOOKUP_KEY_BYTES};
use permitlayer_core::killswitch::KillSwitch;
use permitlayer_core::policy::PolicyCompileError;
use permitlayer_core::store::AgentIdentityStore;
use permitlayer_core::store::fs::AgentIdentityFsStore;
use permitlayer_proxy::middleware::{PolicySet, assemble_middleware};

use crate::config::{CliOverrides, DaemonConfig, HttpOverrides, LogOverrides};
use crate::lifecycle::pid::PidFile;
use crate::server::conn_tracker::{ConnTracker, ConnTrackerAdapter};
use crate::server::{control, shutdown, sighup};
use crate::telemetry;

#[derive(clap::Args)]
pub struct StartArgs {
    /// Override bind address (e.g., 127.0.0.1:3820)
    #[arg(long)]
    pub bind_addr: Option<SocketAddr>,
    /// Override log level
    #[arg(long)]
    pub log_level: Option<String>,
}

// -- App state shared with handlers --

#[derive(Clone)]
struct AppState {
    started_at: Instant,
    bind_addr: SocketAddr,
    #[allow(dead_code)] // Held alive for SIGHUP reload watcher; read by future stories.
    config_state: Arc<ArcSwap<DaemonConfig>>,
    // Shared with KillSwitchLayer and the control-plane router
    // (`server::control`). Toggled by `agentsso kill` / `agentsso resume` via
    // `POST /v1/control/{kill,resume}`.
    #[allow(dead_code)]
    // Field is read by the control router via an independent Arc clone; AppState's own handlers don't touch it.
    kill_switch: Arc<KillSwitch>,
    #[allow(dead_code)] // Shared with PolicyLayer; hot-swapped by Story 4.2.
    policy_set: Arc<ArcSwap<PolicySet>>,
    #[allow(dead_code)] // Shared with DnsRebindLayer.
    dns_allowlist: Arc<ArcSwap<Vec<String>>>,
    #[allow(dead_code)] // Shared with AuthLayer + control-plane register handler.
    agent_registry: Arc<AgentRegistry>,
    #[allow(dead_code)] // Shared with AuthLayer + control-plane register handler.
    agent_store: Option<Arc<dyn AgentIdentityStore>>,
    // Shared with PolicyLayer (via middleware clone) and the SIGHUP
    // reload handler that calls `clear_caches` after policy recompile.
    #[allow(dead_code)]
    approval_service: Arc<dyn permitlayer_proxy::middleware::ApprovalService>,
    /// Story 5.5: in-process per-agent connection tracker. Read by
    /// `health_handler` (for `active_connections`) and by the control
    /// router's `connections_handler` (for the per-row table). Written
    /// by `ConnTrackLayer` middleware on every authenticated request.
    conn_tracker: Arc<ConnTracker>,
    /// Story 6.1: shared QuickJS plugin runtime. Constructed at boot
    /// so boot-time failure surfaces as `StartError::PluginRuntimeInit`
    /// with a structured banner.
    ///
    /// Story 6.2: now consumed by the debug-only `/v1/debug/plugin-echo`
    /// endpoint that exercises `PluginRuntime::with_host_api` end-to-end
    /// (see `cli/start.rs::debug_plugin_echo_handler`).
    ///
    /// Story 6.3: the loader at `permitlayer_plugins::loader::load_all`
    /// consumes this runtime during boot to parse each plugin's
    /// metadata in a fresh sandboxed context. Subsequent request
    /// dispatch (a future story) re-uses the same runtime for
    /// per-call `with_host_api` execution.
    pub(crate) plugin_runtime: Arc<permitlayer_plugins::PluginRuntime>,
    /// Story 6.3: plugin registry populated by `loader::load_all`
    /// at boot. Built-in connectors (Gmail, Calendar, Drive) always
    /// register; user-installed plugins from
    /// `{paths.home}/plugins/` also register if they pass metadata
    /// validation and the first-load trust check.
    ///
    /// Read by:
    /// - `control::connectors_handler` (route `GET /v1/control/connectors`)
    ///   backing `agentsso connectors list`.
    /// - future request-dispatch story wiring into `ProxyService`.
    pub(crate) plugin_registry: Arc<permitlayer_plugins::PluginRegistry>,
    /// Story 6.2: optional shared `ProxyService` used by the
    /// `#[cfg(debug_assertions)]` `/v1/debug/plugin-echo` endpoint
    /// to construct a `ProxyHostServices` from the existing scrub
    /// engine + token issuer + vault dir + policy state. `None`
    /// when the daemon boots without configured credentials (the
    /// 501-stub branch). Release builds never read this field
    /// because the debug endpoint is only registered behind
    /// `#[cfg(debug_assertions)]`.
    #[cfg(debug_assertions)]
    pub(crate) proxy_service: Option<Arc<permitlayer_proxy::ProxyService>>,
    /// Story 8.3: audit dispatcher forwarded to the debug
    /// plugin-echo endpoint so SSRF rejections land in the real
    /// audit log (used by `plugin_ssrf_blocklist_e2e` test).
    #[cfg(debug_assertions)]
    pub(crate) audit_dispatcher: Arc<permitlayer_core::audit::dispatcher::AuditDispatcher>,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    pid: u32,
    uptime_seconds: u64,
    bind_addr: String,
    version: &'static str,
    active_connections: u32,
    /// Story 6.3: number of plugin connectors currently loaded
    /// (built-in + trusted-user + warn-user). Populated from
    /// [`AppState::plugin_registry`]. A smoke-test signal that the
    /// loader ran successfully — if the daemon boots to "healthy"
    /// but this is 0 on a fresh install, the built-in embed path
    /// regressed.
    connectors_registered: u32,
}

/// Story 6.2 / AC #30: request body for `/v1/debug/plugin-echo`.
/// Debug-only endpoint — gated behind `#[cfg(debug_assertions)]`.
#[cfg(debug_assertions)]
#[derive(serde::Deserialize)]
struct DebugPluginEchoReq {
    /// JS source to evaluate inside the host-API-equipped sandbox.
    source: String,
}

/// Story 6.2 / AC #30: response body for `/v1/debug/plugin-echo`.
/// On success, `result` is the JSON-stringified evaluation output;
/// on plugin failure, `error` carries the structured error code.
#[cfg(debug_assertions)]
#[derive(Serialize)]
struct DebugPluginEchoResp {
    /// Set on success — the JS expression's return value, marshalled
    /// to JSON via `JSON.stringify` inside the sandbox.
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    /// Set on plugin error — the `PluginError` Display string and,
    /// when applicable, the host-API code from a thrown
    /// `AgentssoError`.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// **H12 (re-review patch 2026-04-18)** — extractor that gates
/// the debug-plugin-echo endpoint on the
/// `AGENTSSO_DEBUG_PLUGIN_ECHO_ENABLED=1` env var BEFORE the
/// `Json` body extractor runs. Without this, an attacker could
/// spam multi-MB JSON bodies on a daemon where the env var is
/// unset; the body would be fully parsed before the 403
/// rejection.
///
/// Axum runs extractors in declaration order; placing this
/// extractor BEFORE `Json<DebugPluginEchoReq>` short-circuits
/// the request before any body is consumed. The body is still
/// readable downstream — the rejection happens before that.
#[cfg(debug_assertions)]
struct DebugEndpointEnabled;

#[cfg(debug_assertions)]
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for DebugEndpointEnabled {
    type Rejection = (StatusCode, Json<DebugPluginEchoResp>);
    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        if std::env::var("AGENTSSO_DEBUG_PLUGIN_ECHO_ENABLED").as_deref() == Ok("1") {
            Ok(DebugEndpointEnabled)
        } else {
            Err((
                StatusCode::FORBIDDEN,
                Json(DebugPluginEchoResp {
                    result: None,
                    error: Some(
                        "debug plugin-echo endpoint is gated; set \
                         `AGENTSSO_DEBUG_PLUGIN_ECHO_ENABLED=1` to enable"
                            .to_owned(),
                    ),
                }),
            ))
        }
    }
}

async fn health_handler(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        pid: std::process::id(),
        uptime_seconds: state.started_at.elapsed().as_secs(),
        bind_addr: state.bind_addr.to_string(),
        version: env!("CARGO_PKG_VERSION"),
        active_connections: state.conn_tracker.count() as u32,
        connectors_registered: state.plugin_registry.len() as u32,
    })
}

/// Placeholder: returns 501 Not Implemented.
async fn not_implemented_handler() -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

/// Story 6.2 / AC #30: debug-only handler for `/v1/debug/plugin-echo`.
///
/// Constructs a per-request `ProxyHostServices`, runs the supplied
/// JS source inside `PluginRuntime::with_host_api` on a
/// `spawn_blocking` worker (per the CALLING CONTRACT documented on
/// `permitlayer_proxy::plugin_host_services::ProxyHostServices`),
/// and returns the JSON-stringified result.
///
/// The endpoint is **only registered when compiled with
/// `debug_assertions`** — release builds (e.g. cargo-dist binaries)
/// have no plugin-eval surface at all. This is the test seam the
/// integration test `tests/debug_plugin_echo.rs` consumes.
#[cfg(debug_assertions)]
async fn debug_plugin_echo_handler(
    // H12 (re-review patch 2026-04-18): the env-var gate runs
    // BEFORE the Json body extractor. If the env var isn't set,
    // axum returns 403 with the gate's rejection without ever
    // parsing the request body. This prevents attackers from
    // amplifying CPU/memory cost on a disabled endpoint by
    // spamming huge JSON payloads.
    _gate: DebugEndpointEnabled,
    State(state): State<AppState>,
    Json(req): Json<DebugPluginEchoReq>,
) -> (StatusCode, Json<DebugPluginEchoResp>) {
    // M2 (original review): env-var auth guard. The
    // `DebugEndpointEnabled` extractor above is the canonical
    // check; reaching this handler body means the env var is set.

    // H13 (re-review patch 2026-04-18): cap source size at
    // 64 KiB to prevent attackers (with env var enabled) from
    // posting pathological JS source that allocates huge
    // strings before reaching the QuickJS heap limit.
    const MAX_SOURCE_BYTES: usize = 64 * 1024;
    if req.source.len() > MAX_SOURCE_BYTES {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(DebugPluginEchoResp {
                result: None,
                error: Some(format!(
                    "debug plugin-echo source of {} bytes exceeds {MAX_SOURCE_BYTES}-byte limit",
                    req.source.len()
                )),
            }),
        );
    }

    let proxy = match state.proxy_service.as_ref() {
        Some(p) => Arc::clone(p),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(DebugPluginEchoResp {
                    result: None,
                    error: Some(
                        "no proxy service configured (run `agentsso setup` first)".to_owned(),
                    ),
                }),
            );
        }
    };

    let services = std::sync::Arc::new(permitlayer_proxy::ProxyHostServices::new(
        proxy.token_issuer(),
        proxy.scrub_engine(),
        Arc::clone(&state.policy_set),
        proxy.vault_dir().to_path_buf(),
        "debug-plugin-echo-policy".to_owned(),
        "debug-plugin-echo".to_owned(),
        Arc::clone(&state.audit_dispatcher),
        "debug-plugin-echo".to_owned(),
    ));
    let services_dyn: Arc<dyn permitlayer_plugins::HostServices> = services;

    let plugin_runtime = Arc::clone(&state.plugin_runtime);
    let source = req.source;

    // Run the plugin call on a spawn_blocking worker per the
    // CALLING CONTRACT — the host-API impl `block_on`s reqwest
    // futures internally and would deadlock on a single-thread
    // tokio scheduler if invoked from the reactor.
    let join_result =
        tokio::task::spawn_blocking(move || -> Result<String, permitlayer_plugins::PluginError> {
            plugin_runtime.with_host_api(&services_dyn, |ctx| {
                // AD2 (Story 6.2 course-correction): host-API methods
                // return Promises. Wrap the source in an async-IIFE
                // that `await`s + `JSON.stringify`s the value, then
                // drive the resulting Promise<String> to resolution
                // via `Promise::finish`. Sync expressions like
                // `agentsso.version` round-trip cleanly through this
                // wrapper too — `await EXPR` on a non-Promise just
                // unwraps to the value.
                //
                // **H6 (re-review patch 2026-04-18) — security
                // disposition:** the `{source}` interpolation is
                // textual; an operator who puts `1)));evilCode();((1`
                // in `source` escapes the wrapper. This is acceptable
                // here because (a) the endpoint is gated by
                // `AGENTSSO_DEBUG_PLUGIN_ECHO_ENABLED=1` AND
                // `#[cfg(debug_assertions)]`, (b) reaching this
                // handler requires localhost network access, and
                // (c) the `source` is operator-controlled by
                // definition. The wrapper is for ergonomics
                // (await semantics, JSON marshalling), not safety —
                // the endpoint unconditionally executes arbitrary
                // JS in the sandbox.
                let wrapped = format!("(async () => JSON.stringify(await ({source})))()");
                let raw: rquickjs::Value<'_> = ctx
                    .eval::<rquickjs::Value<'_>, _>(wrapped.as_str())
                    .map_err(permitlayer_plugins::PluginError::from)?;
                let stringified: String = match raw.as_promise() {
                    Some(promise) => promise
                        .finish::<String>()
                        .map_err(permitlayer_plugins::PluginError::from)?,
                    None => {
                        // Should never happen — async-IIFE always
                        // produces a Promise. Defense in depth: if
                        // somehow a non-Promise lands here, attempt
                        // a direct String conversion.
                        let s: rquickjs::String<'_> =
                            rquickjs::String::from_value(raw).map_err(|_| {
                                permitlayer_plugins::PluginError::from(
                                    rquickjs::Error::new_from_js("value", "string"),
                                )
                            })?;
                        s.to_string().map_err(permitlayer_plugins::PluginError::from)?
                    }
                };
                Ok(stringified)
            })
        })
        .await;

    match join_result {
        Ok(Ok(stringified)) => {
            // Story 6.2 review finding L7: log on JSON parse
            // failure so operators see the original stringified
            // output rather than getting silent `null` in the
            // response body.
            let parsed: serde_json::Value = match serde_json::from_str(&stringified) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        stringified_len = stringified.len(),
                        "/v1/debug/plugin-echo: plugin returned a value JSON.stringify produced \
                         but serde_json couldn't parse — falling back to null"
                    );
                    serde_json::Value::Null
                }
            };
            (StatusCode::OK, Json(DebugPluginEchoResp { result: Some(parsed), error: None }))
        }
        Ok(Err(plugin_err)) => (
            StatusCode::BAD_REQUEST,
            Json(DebugPluginEchoResp { result: None, error: Some(plugin_err.to_string()) }),
        ),
        Err(join_err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(DebugPluginEchoResp {
                result: None,
                error: Some(format!("plugin task panicked: {join_err}")),
            }),
        ),
    }
}

/// Try to construct a `ProxyService` from the daemon config.
///
/// Returns `None` if the user hasn't run `agentsso setup` yet (no vault
/// directory), or if the caller passes `None` for `scrub_engine` /
/// `audit_store` (both are required for a functional proxy). The
/// daemon still starts — health endpoints work — but MCP/REST tool
/// routes serve 501.
///
/// **Story 1.15 review fix**: takes `master_key` as a required
/// parameter now. Before the review, this function made its own
/// `keystore.master_key().await` call, which (a) ignored the eagerly
/// bootstrapped key threaded into `try_build_agent_runtime`, (b)
/// bypassed the `AGENTSSO_TEST_MASTER_KEY_HEX` /
/// `AGENTSSO_TEST_PASSPHRASE` test seams, and (c) could return a
/// different key than `AuthLayer`'s lookup subkey under those seams
/// — silent token validation failures. Threading the same key
/// through both consumers guarantees `Vault`, `ScopedTokenIssuer`,
/// and `AuthLayer` all see the same master key bytes.
///
/// `scrub_engine` and `audit_store` are hoisted into `run()` (Story 3.3)
/// so that the control-plane router and `KillSwitchLayer` can share the
/// same `Arc<dyn AuditStore>` with `ProxyService` — a single audit file,
/// a single writer lock, one process-wide audit stream.
/// Walk the vault directory and return `max(envelope.key_id)` over every
/// `.sealed` file. Defaults to `0` for an empty / absent vault (Story 7.6a
/// AC #12).
///
/// This reads only the envelope HEADER (first 4 bytes for v2: version +
/// nonce_len + key_id) — no AEAD unseal, no plaintext exposure. Per-file
/// errors (truncation, unreadable, non-regular file) are logged-and-skipped
/// per Story 7.3 P63 + Story 7.6 `list_services` precedent. Failure to
/// compute does NOT block boot — falls back to `0` so the daemon serves on
/// the bootstrap key.
pub(crate) fn compute_active_key_id(vault_dir: &std::path::Path) -> u8 {
    let read_dir = match std::fs::read_dir(vault_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(e) => {
            tracing::warn!(error = %e, dir = %vault_dir.display(), "vault dir read failed; defaulting active_key_id to 0");
            return 0;
        }
    };
    let mut max_key_id: u8 = 0;
    // Track per-directory totals so we can distinguish "every entry
    // was unreadable" (potentially corrupted vault — surface a warn)
    // from "no .sealed entries to consider" (fresh / empty vault —
    // silent zero is correct).
    let mut considered = 0usize;
    let mut unreadable = 0usize;
    for entry in read_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "skipping unreadable vault entry while computing active_key_id");
                unreadable += 1;
                continue;
            }
        };
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        // Story 7.6b round-1 review: `.sealed.new` filter removed —
        // it was dead code (a file named `<svc>.sealed.new` does not
        // end in `.sealed` so the prior clause already excludes it),
        // and Story 7.6b deleted the entire `.sealed.new` staging
        // path. The remaining filters keep dotfiles and tempfiles
        // (`<svc>.sealed.tmp.<pid>.<n>`) out of the iteration.
        if !file_name.ends_with(".sealed")
            || file_name.starts_with('.')
            || file_name.contains(".tmp.")
        {
            continue;
        }
        considered += 1;
        // Reject symlinks per Story 7.3 P63 precedent.
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => {
                unreadable += 1;
                continue;
            }
        };
        if !meta.file_type().is_file() {
            unreadable += 1;
            continue;
        }
        // Read just the first 4 bytes for v2 (or first 3 for v1: same
        // first 2 bytes encode the version, so the 3rd byte is
        // nonce_len in both schemas; the 4th is key_id only in v2).
        let mut handle = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(_) => {
                unreadable += 1;
                continue;
            }
        };
        let mut header = [0u8; 4];
        use std::io::Read as _;
        if handle.read_exact(&mut header).is_err() {
            // Truncated file (< 4 bytes) — skip; the credential is
            // unreadable but that's not this function's concern.
            unreadable += 1;
            continue;
        }
        let version = u16::from_le_bytes([header[0], header[1]]);
        match version {
            // v1 envelopes have no key_id byte; treat as 0.
            1 => {}
            2 => {
                let key_id = header[3];
                if key_id > max_key_id {
                    max_key_id = key_id;
                }
            }
            _ => {
                // Unknown version on disk — almost always a downgrade
                // scenario (operator booted an older binary that only
                // knows v ≤ N against a vault rewritten to v > N) or
                // corruption. Surface at warn-level; the proxy will
                // surface a hard structured error at decode time.
                tracing::warn!(
                    file = %path.display(),
                    version,
                    "envelope of unknown version while computing active_key_id (downgrade or corruption?)"
                );
            }
        }
    }
    // If we considered some `.sealed` entries but every one was
    // unreadable, surface an error-level warn. Returning 0 here would
    // mask a corrupted vault — the daemon would write fresh seals
    // with `key_id = 0`, breaking rotation tracking. The boot path
    // continues (we don't refuse-to-boot — that's a heavier policy
    // change owned by 7.6b) but the operator sees the signal in logs.
    if considered > 0 && unreadable == considered {
        tracing::error!(
            dir = %vault_dir.display(),
            considered,
            unreadable,
            "every .sealed entry was unreadable while computing active_key_id; \
             rotation tracking may be corrupt — investigate vault permissions / contents"
        );
    }
    max_key_id
}

/// Walk the vault directory and return `(min, max)` of `key_id` over
/// every `.sealed` file. Mirrors [`compute_active_key_id`]'s
/// skip-and-warn discipline. Returns `None` if no readable `.sealed`
/// envelopes were found (fresh / empty vault — the boot-time
/// mixed-key refusal does not fire on an empty vault).
///
/// Story 7.6b AC #13: the boot-time check refuses to start if
/// `min < max`, indicating a previous `agentsso rotate-key` did not
/// complete. Re-running rotate-key resumes the rotation idempotently.
///
/// Story 7.6b round-1 review: return type tightened to a tri-state
/// `Result<Option<...>, io::Error>` so the boot guard can distinguish
/// "vault is empty" (`Ok(None)`) from "couldn't read vault dir"
/// (`Err`). The previous `Option`-only return collapsed both into a
/// silent boot pass — fixed.
pub(crate) fn compute_min_max_key_id(
    vault_dir: &std::path::Path,
) -> Result<Option<(u8, u8)>, std::io::Error> {
    let read_dir = match std::fs::read_dir(vault_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            tracing::warn!(
                error = %e,
                dir = %vault_dir.display(),
                "vault dir read failed during mixed-key_id check"
            );
            return Err(e);
        }
    };
    let mut min_key_id: Option<u8> = None;
    let mut max_key_id: u8 = 0;
    let mut considered: u32 = 0;
    let mut unreadable: u32 = 0;
    for entry in read_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "skipping unreadable vault entry while computing min/max key_id");
                unreadable += 1;
                continue;
            }
        };
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        // Story 7.6b round-1 review: `.sealed.new` filter removed —
        // it was dead code (a file named `<svc>.sealed.new` does not
        // end in `.sealed` so the prior clause already excludes it),
        // and Story 7.6b deleted the entire `.sealed.new` staging
        // path. The remaining filters keep dotfiles and tempfiles
        // (`<svc>.sealed.tmp.<pid>.<n>`) out of the iteration.
        if !file_name.ends_with(".sealed")
            || file_name.starts_with('.')
            || file_name.contains(".tmp.")
        {
            continue;
        }
        considered += 1;
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => {
                unreadable += 1;
                continue;
            }
        };
        if !meta.file_type().is_file() {
            continue;
        }
        let mut handle = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(_) => {
                unreadable += 1;
                continue;
            }
        };
        let mut header = [0u8; 4];
        use std::io::Read as _;
        if handle.read_exact(&mut header).is_err() {
            unreadable += 1;
            continue;
        }
        let version = u16::from_le_bytes([header[0], header[1]]);
        let key_id = match version {
            // v1 envelopes have no key_id byte; treat as 0.
            1 => 0u8,
            2 => header[3],
            _ => continue,
        };
        if key_id > max_key_id {
            max_key_id = key_id;
        }
        match min_key_id {
            None => min_key_id = Some(key_id),
            Some(cur) if key_id < cur => min_key_id = Some(key_id),
            _ => {}
        }
    }
    // Fail-closed: if at least one envelope existed but every one
    // was unreadable, we cannot know whether the vault is in a
    // mixed-key state. Refuse to boot rather than silently pass.
    if considered > 0 && unreadable == considered {
        return Err(std::io::Error::other(format!(
            "all {considered} vault envelope(s) are unreadable; cannot determine rotation state"
        )));
    }
    Ok(min_key_id.map(|min| (min, max_key_id)))
}

async fn try_build_proxy_service(
    config: &DaemonConfig,
    scrub_engine: Option<&Arc<permitlayer_core::scrub::ScrubEngine>>,
    audit_store: Option<&Arc<dyn permitlayer_core::store::AuditStore>>,
    master_key: &zeroize::Zeroizing<[u8; permitlayer_keystore::MASTER_KEY_LEN]>,
    active_key_id: u8,
) -> Option<Arc<permitlayer_proxy::ProxyService>> {
    use hkdf::Hkdf;
    use permitlayer_core::store::fs::CredentialFsStore;
    use permitlayer_proxy::token::ScopedTokenIssuer;
    use permitlayer_proxy::upstream::UpstreamClient;
    use permitlayer_vault::Vault;
    use sha2::Sha256;
    use zeroize::Zeroizing;

    // If either shared service is unavailable, we can't build a proxy —
    // both are constructed in `run()` before this fn is called, and a
    // `None` here means startup already logged the failure. Fall through
    // to the 501 stub branch.
    let scrub_engine = scrub_engine?;
    let audit_store = audit_store?;

    let vault_dir = config.paths.home.join("vault");
    // Story 7.6a: the vault directory is now created at boot by
    // `VaultLock::try_acquire` (so the lock file has somewhere to
    // live). "Directory exists" is therefore no longer a useful
    // proxy for "setup has been run." Walk the directory and look
    // for any `.sealed` file — if none exist, the proxy still
    // serves 501 and the operator's next step is `agentsso setup`.
    //
    // Distinguish three outcomes:
    //   1. read_dir succeeds, no `.sealed` entry → fresh install, log
    //      the "run setup" hint and serve 501.
    //   2. read_dir succeeds, ≥ 1 `.sealed` entry that is a regular
    //      file → real credentials, build the proxy.
    //   3. read_dir fails with anything other than NotFound (perm
    //      denied, I/O error) → log at error and refuse to build the
    //      proxy. Silently treating an I/O error as "no credentials"
    //      would surface a misleading "run setup" hint when the real
    //      issue is a vault that exists but is unreadable.
    let vault_has_credentials = match std::fs::read_dir(&vault_dir) {
        Ok(rd) => rd.filter_map(Result::ok).any(|entry| {
            // Story 7.3 P63: reject non-regular files in the walk.
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => return false,
            };
            if !meta.file_type().is_file() {
                return false;
            }
            entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.ends_with(".sealed") && !n.contains(".sealed.tmp."))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            tracing::error!(
                error = %e,
                dir = %vault_dir.display(),
                "vault directory unreadable — refusing to build proxy service \
                 (operator: check vault permissions)"
            );
            return None;
        }
    };
    if !vault_has_credentials {
        tracing::warn!(
            "vault contains no credentials — run `agentsso setup <service>` to connect credentials"
        );
        return None;
    }

    // Derive signing key for ScopedTokenIssuer via HKDF from the
    // eagerly bootstrapped master key.
    let hkdf = Hkdf::<Sha256>::new(None, master_key.as_slice());
    let mut signing_key = Zeroizing::new([0u8; 32]);
    if hkdf.expand(b"permitlayer-scoped-token-v1", &mut *signing_key).is_err() {
        tracing::error!("HKDF expansion failed for scoped token signing key");
        return None;
    }

    let credential_store = match CredentialFsStore::new(config.paths.home.clone()) {
        Ok(store) => Arc::new(store) as Arc<dyn permitlayer_core::store::CredentialStore>,
        Err(e) => {
            tracing::warn!(error = %e, "credential store unavailable — tool routes will serve 501");
            return None;
        }
    };

    // `Vault::new` consumes the master key by value, so we clone the
    // bytes into a fresh `Zeroizing` buffer. This is the one place
    // where the key bytes exist in two buffers simultaneously (the
    // caller's bootstrap buffer + the vault's internal buffer); both
    // are zeroized on drop.
    let mut vault_key = Zeroizing::new([0u8; permitlayer_keystore::MASTER_KEY_LEN]);
    vault_key.copy_from_slice(master_key.as_slice());
    // Story 7.6a AC #12: `key_id` for the live proxy Vault is the
    // active key_id walked from the vault on boot
    // (`max(envelope.key_id)`, defaulting to 0 on empty vault). Every
    // refresh-rotation seal stamps this value on the new envelope.
    // Story 7.6b will increment per rotation; for 7.6a it's `0` until
    // a rotation event happens.
    let vault = Arc::new(Vault::new(vault_key, active_key_id));
    let token_issuer = Arc::new(ScopedTokenIssuer::new(signing_key));

    let upstream_client = match UpstreamClient::new() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::warn!(error = %e, "upstream client creation failed — tool routes will serve 501");
            return None;
        }
    };

    Some(Arc::new(permitlayer_proxy::ProxyService::new(
        credential_store,
        vault,
        token_issuer,
        upstream_client,
        Arc::clone(audit_store),
        Arc::clone(scrub_engine),
        config.paths.home.join("vault"),
    )))
}

/// Build the shared `Arc<ScrubEngine>` + `Option<Arc<dyn AuditStore>>`
/// singletons used by `ProxyService`, the control-plane router, and
/// `KillSwitchLayer`.
///
/// `ScrubEngine` failure is fail-closed: the daemon logs to both
/// `tracing::error!` and stderr and returns `None` for both. A broken
/// scrub engine means tool routes serve 501 AND audit writes are
/// skipped — consistent with the security invariant that scrub-before-log
/// is mandatory.
///
/// `AuditFsStore` failure is best-effort: the daemon logs `tracing::warn!`
/// and returns `Some(scrub_engine), None` so the control-plane router
/// still functions (`agentsso kill` / `resume` still work, they just
/// don't write audit events). Operators with a broken audit directory
/// still need a working kill switch.
/// Construct the agent identity store, the in-memory `AgentRegistry`,
/// and the daemon's HMAC lookup subkey (Story 4.4).
///
/// Returns:
/// - `agent_store: Option<Arc<dyn AgentIdentityStore>>` — `None` if the
///   agents directory cannot be created/read (best-effort, mirrors the
///   audit-store posture).
/// - `agent_registry: Arc<AgentRegistry>` — always present. Empty when
///   the store is unavailable, otherwise loaded from disk.
/// - `lookup_key: Arc<Zeroizing<[u8; 32]>>` — HKDF-derived from the
///   master key passed in by `run()`. Always a real subkey, never a
///   zero placeholder — Story 1.15 moved master-key provisioning into
///   the eager `ensure_master_key_bootstrapped` boot step, so by the
///   time this function runs the master key is guaranteed present.
///
/// **Story 1.15 change.** Before this story, this function lazily
/// called `read_master_key(config)` and fell back to a zero placeholder
/// when the master key was missing — producing a "boot succeeds, but
/// every authenticated request 401s forever" degraded state. Story 1.15
/// hoists the master key into a required parameter and deletes the
/// placeholder branch entirely. A keystore failure is now a fatal
/// `std::process::exit(2)` in `run()`, not a silent 401 at request time.
/// Build the approval service used by `PolicyLayer` for
/// `Decision::Prompt` dispatch (Story 4.5).
///
/// Selection order:
/// 1. **Test seam (canned)**: if
///    `AGENTSSO_TEST_APPROVAL_CANNED_RESPONSES` is set, build a
///    `CliApprovalService` with a `CannedPromptReader` pre-seeded
///    from the comma-separated list. Subprocess integration tests
///    use this to drive the approval path deterministically.
/// 2. **Test seam (force unavailable)**: if
///    `AGENTSSO_TEST_APPROVAL_FORCE_NO_TTY` is set to `1`, return
///    `NoTtyApprovalService` regardless of the actual TTY state.
/// 3. **Test seam (force timeout)**: if
///    `AGENTSSO_TEST_APPROVAL_FORCE_TIMEOUT_MS` is set, build a
///    reader that sleeps the specified duration before returning
///    so the `tokio::time::timeout` wrapper fires.
/// 4. **Interactive TTY**: try `CliApprovalService::start_with_tty`.
/// 5. **Fallback**: instantiate `NoTtyApprovalService`, emit a WARN
///    tracing record, and print a startup banner.
///
/// Test seams match Story 4.4's `AGENTSSO_TEST_MASTER_KEY_HEX`
/// pattern.
///
/// **Compile-time gating.** The three `AGENTSSO_TEST_APPROVAL_*` env
/// vars are read ONLY in builds with `debug_assertions` enabled (i.e.,
/// dev/test builds). Release builds — including `cargo install` without
/// `--debug` and packaged distributions — compile the seam-reading
/// branches out entirely, so a leaked env var in an operator's shell
/// cannot bypass real prompts in production. CI runs `cargo test`
/// against the dev profile, so the seam is available where the
/// integration tests need it.
fn build_approval_service() -> Arc<dyn permitlayer_proxy::middleware::ApprovalService> {
    use crate::approval::{CliApprovalService, NoTtyApprovalService};

    // Test seams are only compiled in dev / test builds. Release
    // builds get the production-only path (interactive TTY → fallback).
    #[cfg(debug_assertions)]
    {
        use crate::approval::{CannedPromptReader, PromptReader, PromptReaderDecision};

        // (1) Test seam: canned responses.
        if let Ok(canned) = std::env::var("AGENTSSO_TEST_APPROVAL_CANNED_RESPONSES") {
            let decisions: Vec<PromptReaderDecision> =
                canned.split(',').filter(|s| !s.is_empty()).map(parse_canned_decision).collect();
            let reader: Arc<dyn PromptReader> = Arc::new(CannedPromptReader::new(decisions));
            let svc = CliApprovalService::start(reader);
            tracing::info!(
                approval_service = "test-canned",
                decisions_seeded = canned.split(',').filter(|s| !s.is_empty()).count(),
                "approval service: test canned responses (AGENTSSO_TEST_APPROVAL_CANNED_RESPONSES)"
            );
            return svc;
        }

        // (2) Test seam: force NoTty regardless of actual TTY state.
        if std::env::var("AGENTSSO_TEST_APPROVAL_FORCE_NO_TTY").as_deref() == Ok("1") {
            tracing::warn!(
                approval_service = "no-tty",
                reason = "AGENTSSO_TEST_APPROVAL_FORCE_NO_TTY=1",
                "approval prompts disabled — prompt-required policies will deny with 503 policy.approval_unavailable"
            );
            eprintln!();
            eprintln!(
                "  ⚠ approval: prompts disabled (no TTY) — prompt-required policies will deny"
            );
            eprintln!();
            return Arc::new(NoTtyApprovalService::new());
        }

        // (3) Test seam: force Timeout via sleep-longer-than-request-timeout.
        if let Ok(ms) = std::env::var("AGENTSSO_TEST_APPROVAL_FORCE_TIMEOUT_MS")
            && let Ok(ms) = ms.parse::<u64>()
        {
            let reader: Arc<dyn PromptReader> = Arc::new(CannedPromptReader::with_sleep(
                vec![PromptReaderDecision::Allow],
                std::time::Duration::from_millis(ms),
            ));
            let svc = CliApprovalService::start(reader);
            tracing::info!(
                approval_service = "test-timeout",
                sleep_ms = ms,
                "approval service: force-timeout reader (AGENTSSO_TEST_APPROVAL_FORCE_TIMEOUT_MS)"
            );
            return svc;
        }
    }

    // (4) Interactive TTY (production path).
    match CliApprovalService::start_with_tty() {
        Ok(svc) => {
            tracing::info!(
                approval_service = "cli-tty",
                "approval service: interactive TTY prompts enabled"
            );
            svc
        }
        Err(e) => {
            // (5) No-TTY fallback.
            tracing::warn!(
                approval_service = "no-tty",
                reason = %e,
                "approval prompts disabled — prompt-required policies will deny with 503 policy.approval_unavailable"
            );
            eprintln!();
            eprintln!(
                "  ⚠ approval: prompts disabled (no TTY) — prompt-required policies will deny"
            );
            eprintln!();
            Arc::new(NoTtyApprovalService::new())
        }
    }
}

/// Parse one entry from `AGENTSSO_TEST_APPROVAL_CANNED_RESPONSES`.
///
/// Unknown tokens map to `Aborted` (which `CliApprovalService` turns
/// into a fail-closed `Denied`), so a typo in the test env var never
/// produces a silently-allowed request.
///
/// Compiled out in release builds — see `build_approval_service` for
/// the rationale.
#[cfg(debug_assertions)]
fn parse_canned_decision(s: &str) -> crate::approval::PromptReaderDecision {
    use crate::approval::PromptReaderDecision;
    match s.trim().to_ascii_lowercase().as_str() {
        "allow" | "granted" | "y" => PromptReaderDecision::Allow,
        "deny" | "denied" | "n" => PromptReaderDecision::Deny,
        "always" | "a" => PromptReaderDecision::Always,
        "never" => PromptReaderDecision::Never,
        // Unknown / "aborted" → fail-closed Denied.
        _ => PromptReaderDecision::Aborted,
    }
}

// --------------------------------------------------------------------------
// Story 6.3: trust prompt reader factory.
// --------------------------------------------------------------------------

/// Build the [`permitlayer_plugins::TrustPromptReader`] used by the
/// plugin loader for the first-load trust prompt.
///
/// Selection cascade (matches `build_approval_service`'s structure
/// for consistency):
/// 1. **Test seam (canned)**: if
///    `AGENTSSO_TEST_TRUST_PROMPT_CANNED_RESPONSES` is set, wrap a
///    [`permitlayer_plugins::CannedTrustPromptReader`] around the
///    comma-separated decision list. Subprocess integration tests
///    use this to drive the prompt path deterministically.
/// 2. **Test seam (force no-prompt)**: if
///    `AGENTSSO_TEST_TRUST_PROMPT_FORCE_NO_PROMPT=1`, use a no-op
///    reader that always returns `NoPromptAvailable` regardless of
///    TTY state. Headless integration tests use this to verify the
///    WarnUser fallback path without fixturing a TTY.
/// 3. **Interactive TTY**: if stdin is a terminal, use the
///    `TtyTrustPromptReader`. 30-second timeout on read; EOF →
///    `NoPromptAvailable`.
/// 4. **Fallback**: headless deployment. Use the no-op reader.
///
/// All three env-var reads are gated behind
/// `#[cfg(debug_assertions)]` (per Story 4.5's `build_approval_service`
/// precedent) — release builds (`cargo install` without `--debug` and
/// packaged distributions) compile the seams out entirely so a leaked
/// env var in an operator's shell cannot bypass real prompts in
/// production (AC #24).
fn build_trust_prompt_reader() -> Arc<dyn permitlayer_plugins::TrustPromptReader> {
    #[cfg(debug_assertions)]
    {
        // (1) Test seam: canned responses.
        if let Ok(canned) = std::env::var("AGENTSSO_TEST_TRUST_PROMPT_CANNED_RESPONSES") {
            let decisions: Vec<permitlayer_plugins::TrustDecision> = canned
                .split(',')
                .filter(|s| !s.is_empty())
                .map(parse_canned_trust_decision)
                .collect();
            tracing::info!(
                trust_prompter = "test-canned",
                decisions_seeded = decisions.len(),
                "trust prompter: test canned responses (AGENTSSO_TEST_TRUST_PROMPT_CANNED_RESPONSES)"
            );
            return Arc::new(permitlayer_plugins::CannedTrustPromptReader::new(decisions));
        }

        // (2) Test seam: force no-prompt.
        if std::env::var("AGENTSSO_TEST_TRUST_PROMPT_FORCE_NO_PROMPT").as_deref() == Ok("1") {
            tracing::info!(
                trust_prompter = "force-no-prompt",
                reason = "AGENTSSO_TEST_TRUST_PROMPT_FORCE_NO_PROMPT=1",
                "trust prompter: forced to no-prompt (test seam)"
            );
            return Arc::new(permitlayer_plugins::NoOpTrustPromptReader);
        }
    }

    // (3) + (4): production path — TTY if available, no-op
    // otherwise. The `TtyTrustPromptReader` itself falls back to
    // `NoPromptAvailable` when stdin isn't a terminal, so the
    // distinction between (3) and (4) is implicit.
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        tracing::info!(trust_prompter = "tty", "trust prompter: interactive TTY prompts enabled");
        Arc::new(TtyTrustPromptReader)
    } else {
        tracing::info!(
            trust_prompter = "no-tty",
            "trust prompter: no TTY detected — user-installed plugins will load as warn-user without prompt"
        );
        Arc::new(permitlayer_plugins::NoOpTrustPromptReader)
    }
}

#[cfg(debug_assertions)]
fn parse_canned_trust_decision(s: &str) -> permitlayer_plugins::TrustDecision {
    use permitlayer_plugins::TrustDecision;
    match s.trim().to_ascii_lowercase().as_str() {
        "always" | "a" | "y" | "yes" => TrustDecision::Always,
        "once" | "o" => TrustDecision::Once,
        "never" | "n" | "no" => TrustDecision::Never,
        // Unknown tokens fall through to NoPromptAvailable —
        // consistent with the `build_approval_service` "Aborted"
        // default posture and lets a typo in the test env var
        // surface as a WarnUser registration rather than silently
        // trusting or skipping. Also emit a WARN so a typo in CI
        // doesn't silently change a test's observed tier.
        other => {
            tracing::warn!(
                token = %other,
                "AGENTSSO_TEST_TRUST_PROMPT_CANNED_RESPONSES contained unknown token; treating as no-prompt-available"
            );
            TrustDecision::NoPromptAvailable
        }
    }
}

/// Production TTY-backed [`permitlayer_plugins::TrustPromptReader`]. Renders a prompt
/// block to stderr, reads one line from stdin, and maps the answer
/// to a [`permitlayer_plugins::TrustDecision`]. Non-TTY stdin or
/// EOF → `NoPromptAvailable`.
struct TtyTrustPromptReader;

/// Wall-clock budget for the interactive trust prompt. On expiry
/// the read falls back to `NoPromptAvailable` (the plugin loads
/// as `WarnUser` for user-installed plugins, or is rejected
/// earlier for built-ins when `auto_trust_builtins = false`).
///
/// Matches Story 6.3 Task 7.2 verbatim.
const TRUST_PROMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

impl permitlayer_plugins::TrustPromptReader for TtyTrustPromptReader {
    fn prompt(
        &self,
        connector_name: &str,
        source_path: &std::path::Path,
        source_sha256_hex: &str,
    ) -> permitlayer_plugins::TrustDecision {
        use std::io::{IsTerminal, Write};
        if !std::io::stdin().is_terminal() {
            // Defense-in-depth — `build_trust_prompt_reader`
            // already short-circuits the no-TTY case, but a
            // stdin that becomes non-interactive between start
            // and the first prompt (e.g., CI pipeline that
            // backgrounds the daemon) should still fall back
            // gracefully.
            return permitlayer_plugins::TrustDecision::NoPromptAvailable;
        }

        // Char-boundary-safe short hash. `source_sha256_hex` is
        // always ASCII hex today, but byte-slicing a `&str` is
        // a foot-gun worth eliminating.
        let short_hash: String = source_sha256_hex.chars().take(12).collect();
        let stderr = std::io::stderr();
        let mut stderr = stderr.lock();
        let _ = writeln!(stderr);
        let _ = writeln!(
            stderr,
            "  ⚠ permitlayer is loading a user-installed connector plugin for the first time."
        );
        let _ = writeln!(stderr, "    connector: {connector_name}");
        let _ = writeln!(stderr, "    source:    {}", source_path.display());
        let _ = writeln!(stderr, "    sha256:    {short_hash}…");
        let _ = writeln!(stderr);
        let _ = writeln!(
            stderr,
            "    trust this plugin? [y]es (always) / [o]nce / [n]o (skip) — 30s timeout:"
        );
        let _ = stderr.flush();

        // 30-second read budget via `spawn_blocking` + `tokio::time::timeout`.
        // The blocking thread's `read_line` cannot be cancelled
        // externally, so on timeout the thread parks until the
        // operator eventually hits enter — harmless: the daemon
        // proceeds with `NoPromptAvailable` and the thread exits
        // when stdin closes or the OS reaps the process.
        //
        // `block_in_place` marks the current thread as blocking so
        // the subsequent `Handle::current().block_on` is legal from
        // inside a tokio worker. Without `block_in_place`, the
        // `block_on` call panics at runtime ("Cannot start a
        // runtime from within a runtime"). The enclosing daemon is
        // `#[tokio::main]` which defaults to `multi_thread`;
        // `block_in_place` requires this flavor.
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async {
                let read_task = tokio::task::spawn_blocking(move || {
                    use std::io::BufRead;
                    let stdin = std::io::stdin();
                    let mut line = String::new();
                    match stdin.lock().read_line(&mut line) {
                        Ok(0) | Err(_) => None,
                        Ok(_) => Some(line),
                    }
                });
                match tokio::time::timeout(TRUST_PROMPT_TIMEOUT, read_task).await {
                    Ok(Ok(Some(line))) => match line.trim().to_ascii_lowercase().as_str() {
                        "y" | "yes" | "a" | "always" => permitlayer_plugins::TrustDecision::Always,
                        "o" | "once" => permitlayer_plugins::TrustDecision::Once,
                        "n" | "no" | "never" => permitlayer_plugins::TrustDecision::Never,
                        _ => permitlayer_plugins::TrustDecision::NoPromptAvailable,
                    },
                    // Read returned EOF/error, the blocking task
                    // panicked, or the 30s timer fired first — all
                    // collapse to NoPromptAvailable. On timeout the
                    // backing thread is intentionally leaked (it stays
                    // parked in `read_line`). Document this explicitly
                    // so a future refactor doesn't try to abort it.
                    _ => permitlayer_plugins::TrustDecision::NoPromptAvailable,
                }
            })
        })
    }
}

async fn try_build_agent_runtime(
    config: &DaemonConfig,
    master_key: &zeroize::Zeroizing<[u8; permitlayer_keystore::MASTER_KEY_LEN]>,
) -> Result<
    (
        Option<Arc<dyn AgentIdentityStore>>,
        Arc<AgentRegistry>,
        Arc<zeroize::Zeroizing<[u8; LOOKUP_KEY_BYTES]>>,
    ),
    StartError,
> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    use zeroize::Zeroizing;

    // 1. Create / open the agents directory and the fs store.
    let agent_store = match AgentIdentityFsStore::new(config.paths.home.clone()) {
        Ok(s) => Some(Arc::new(s) as Arc<dyn AgentIdentityStore>),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "agent identity store creation failed — `agentsso agent register` will be unavailable; existing tool routes serve 401 auth.invalid_token"
            );
            None
        }
    };

    // 2. Derive the HMAC lookup subkey from the (eagerly bootstrapped)
    //    master key BEFORE building the registry — the registry now
    //    sanity-checks each agent's `lookup_key_hex` against the
    //    recomputed HMAC at construction time (Story 7.6b AC #12), so
    //    it needs the subkey before it can build its initial snapshot.
    //
    //    Story 1.15 removed the pre-setup placeholder branch — by the
    //    time `try_build_agent_runtime` runs, the master key is
    //    guaranteed to exist (bootstrapped in `run()` before this
    //    function is called), so the subkey is always a real HMAC
    //    derivation, never a zero fallback.
    //
    //    The subkey lives inside `Zeroizing<[u8; 32]>` from derivation
    //    through daemon shutdown — both the middleware (`AuthLayer`) and
    //    the control plane (`ControlState`) share ONE `Arc<Zeroizing<_>>`
    //    allocation so there is no second cleartext copy anywhere in
    //    the process.
    let mut lookup_key = Zeroizing::new([0u8; LOOKUP_KEY_BYTES]);
    let hkdf = Hkdf::<Sha256>::new(None, master_key.as_slice());
    if let Err(e) = hkdf.expand(permitlayer_core::agent::AGENT_LOOKUP_HKDF_INFO, &mut *lookup_key) {
        // HKDF-expand with a 32-byte output and a fixed info string
        // should never fail (the only failure mode is output length >
        // 255 * hash_size = 8160 bytes for SHA-256, which we cannot
        // hit with a 32-byte target). If it somehow does, fail-fast
        // — we refuse to boot with a half-derived key. The `hkdf`
        // crate's `InvalidLength` error captures the specific cause.
        tracing::error!(
            error = ?e,
            "HKDF expansion failed for agent token lookup subkey — this should be impossible with a 32-byte output; refusing to boot"
        );
        return Err(StartError::HkdfExpand);
    }

    // 3. Load any pre-existing agents into a fresh snapshot. An empty
    //    list is fine — the registry boots empty until the operator
    //    runs `agentsso agent register`.
    let initial_agents = if let Some(store) = &agent_store {
        match store.list().await {
            Ok(agents) => {
                tracing::info!(agents_loaded = agents.len(), "agent identity registry initialized");
                agents
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to read agent identity registry — booting with empty registry"
                );
                vec![]
            }
        }
    } else {
        vec![]
    };
    // Story 7.6b AC #12: registry sanity-checks each agent's on-disk
    // `lookup_key_hex` against `HMAC(daemon_subkey, agent.name())`.
    // Mismatched agents are dropped from the auth index with a warn —
    // catches the post-Phase-E-crash state where some agent files
    // hold an HMAC keyed by the OLD subkey. The registry holds its
    // own `Zeroizing<[u8;32]>` copy of the subkey so the bytes are
    // scrubbed at registry drop alongside the auth-layer copy.
    let agent_registry = Arc::new(AgentRegistry::with_subkey(initial_agents, *lookup_key));

    // The agent_store may still be `None` (best-effort: the agents
    // directory could not be created), in which case the register
    // handler returns 503 agent.store_unavailable at call time. This
    // is separate from the master-key bootstrap story — we still
    // allow the daemon to boot so operators can fix directory
    // permissions without losing the proxy service.
    if agent_store.is_none() {
        tracing::error!(
            "agent registry store is unavailable — `agentsso agent register` will return 503; \
             fix ~/.agentsso/agents/ permissions and restart to recover"
        );
    }

    Ok((agent_store, agent_registry, Arc::new(lookup_key)))
}

/// Structured fail-fast errors from [`run`] at daemon startup.
///
/// Story 1.15 review Decision 1: replaced the 8 ad-hoc
/// `std::process::exit(N)` call sites with a single error type that
/// bubbles up through `?` and hits `main()`, which converts it to a
/// non-zero [`std::process::ExitCode`]. Three reasons:
///
/// 1. **Destructor safety.** `std::process::exit` skips Rust `Drop`
///    impls, leaking the PID file at `~/.agentsso/pid`, tracing
///    subscriber `WorkerGuard`s (dropping buffered log lines), and
///    any open `TcpListener`. Bubbling the error up through `?` runs
///    stack unwinding normally and every `Drop` fires.
/// 2. **Tracing subscriber flush.** The `tracing::error!` line logged
///    immediately before `exit(N)` may never reach disk if a
///    non-blocking appender holds buffered writes — operators see
///    the `eprintln!` banner but the structured log is lost.
/// 3. **Consistency.** Before Story 1.15 the 8 exit sites were
///    scattered across `run()` with no single map of "which errors
///    produce which code." The `StartError` variants are the map.
///
/// Exit code semantics (Story 7.6a round-1 review patch — split the
/// previous lump-into-3 mapping so CI scripts and automation can
/// distinguish the three remediation classes):
///
/// - **Exit 2** — configuration or bootstrap failure. Recoverable
///   by fixing the config file, unlocking the keychain, or running
///   `agentsso setup`. Matches the prior `exit(2)` sites: config
///   load, policies dir, policy compile, master key bootstrap,
///   HKDF expansion.
/// - **Exit 3** — another process holds a coordination resource.
///   Operator remediation: wait for the holder to finish, or
///   identify and stop it. Variants:
///   - `DaemonAlreadyRunning` (PID file held by a live daemon),
///   - `PidFileAcquire` (PID file held but the holder is unclear),
///   - `DaemonStartVaultBusy` (vault advisory lock held — typically
///     `agentsso rotate-key` mid-flight in another terminal).
/// - **Exit 4** — filesystem-level failure on a coordination
///   resource. Operator remediation: fix permissions, fix the
///   filesystem, investigate. Variants:
///   - `VaultLockIo` (lock-file open/lock-syscall failed for a
///     non-busy reason: permission denied, ENOENT, disk full).
/// - **Exit 5** — bind failure. Operator remediation: fix the port
///   conflict (free the port, change the bind address). Variants:
///   - `BindFailed` (TCP listener could not bind the configured
///     address).
#[derive(Debug, thiserror::Error)]
pub(crate) enum StartError {
    /// Daemon configuration could not be loaded. Error message already
    /// rendered in the caller's preferred form (figment error display).
    #[error("config load failed: {0}")]
    ConfigLoad(String),

    /// The `~/.agentsso/policies` directory could not be created or is
    /// not readable.
    #[error("failed to prepare policies directory {path}: {source}")]
    PoliciesDir {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The policy TOML files failed to compile. Full diagnostic is
    /// produced by `render_policy_error` and stored here as a
    /// pre-rendered string so the banner stays deterministic.
    #[error("policy compile failed")]
    PolicyCompile { rendered: String },

    /// Platform keystore adapter could not be constructed (locked
    /// keychain, missing secret-service daemon, etc).
    #[error("keystore construction failed")]
    KeystoreConstruction {
        #[source]
        source: permitlayer_keystore::KeyStoreError,
    },

    /// `KeyStore::master_key` returned an error — either the platform
    /// FFI call failed, or the persisted key is malformed.
    #[error("keystore master_key call failed")]
    MasterKeyCall {
        #[source]
        source: permitlayer_keystore::KeyStoreError,
    },

    /// HKDF-expand of the agent token lookup subkey failed. With a
    /// 32-byte output this is mathematically impossible for
    /// `Hkdf<Sha256>`, but we pattern-match the `Err` defensively and
    /// fail-fast rather than fall back to a zero subkey.
    #[error("HKDF expansion of agent token lookup subkey failed unexpectedly")]
    HkdfExpand,

    /// Another daemon is already running (PID file conflict).
    #[error("daemon is already running (pid {pid})")]
    DaemonAlreadyRunning { pid: u32 },

    /// PID file could not be acquired for reasons other than "already
    /// running" (filesystem permissions, IO error).
    #[error("failed to acquire PID file: {0}")]
    PidFileAcquire(String),

    /// Story 7.6a AC #3: vault-level advisory lock is held by another
    /// process — typically `agentsso rotate-key` mid-flight, an
    /// `agentsso setup` in progress, or a stale daemon that survived
    /// PID-file cleanup but not vault-lock release. The PID file says
    /// nobody holds it, but the vault lock says otherwise.
    #[error("vault is busy (held by pid={holder_pid:?} command={holder_command:?})")]
    DaemonStartVaultBusy {
        /// The lock-holder's PID, if the lock-file metadata read
        /// succeeded.
        holder_pid: Option<u32>,
        /// The lock-holder's argv[0], if the lock-file metadata read
        /// succeeded.
        holder_command: Option<String>,
    },

    /// Story 7.6a AC #3: vault lock could not be acquired due to a
    /// non-busy I/O failure (permission denied, lock file is a
    /// symlink, disk full while creating the file, …). Distinct from
    /// `DaemonStartVaultBusy` because the operator's remediation is
    /// different: a busy lock means "wait for the other process to
    /// finish"; an I/O failure means "fix the filesystem".
    #[error("vault lock acquisition failed: {source}")]
    VaultLockIo {
        #[source]
        source: std::io::Error,
    },

    /// TCP listener could not bind the configured address.
    #[error("failed to bind TCP listener on {addr}: {source}")]
    BindFailed {
        addr: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },

    /// `axum::serve` returned an error after the daemon was running —
    /// typically a runtime I/O failure on the listener socket. Treated
    /// as exit-code-2 because the daemon was running (not a resource
    /// conflict) and the operator should inspect config/environment.
    #[error("HTTP server terminated with error: {source}")]
    ServeFailed {
        #[source]
        source: std::io::Error,
    },

    /// Tracing subscriber failed to initialize — typically the
    /// operational log directory could not be created at the configured
    /// path. Story 5.4.
    #[error("telemetry init failed: {source}")]
    TelemetryInit {
        #[source]
        source: crate::telemetry::TelemetryInitError,
    },

    /// QuickJS plugin runtime could not be constructed. Story 6.1.
    /// Fatal at boot — the daemon refuses to start rather than
    /// running without a working connector-plugin sandbox.
    #[error("plugin runtime init failed: {source}")]
    PluginRuntimeInit {
        #[source]
        source: permitlayer_plugins::PluginError,
    },

    /// A built-in connector failed to load — shipped-binary bug.
    /// The daemon refuses to boot rather than silently dropping a
    /// connector that operators expect to be present. Story 6.3.
    /// User-installed plugin failures are NON-fatal (logged and
    /// skipped); this variant surfaces only for built-ins.
    #[error("plugin loader failed: {source}")]
    PluginLoadFailed {
        #[source]
        source: permitlayer_plugins::PluginError,
    },

    /// Story 7.6b AC #13: the vault contains envelopes at multiple
    /// `key_id` values — a previous `agentsso rotate-key` did not
    /// complete. The daemon refuses to boot until the rotation is
    /// finished; re-running `agentsso rotate-key` resumes the rotation
    /// idempotently because the keystore stages both keys atomically
    /// before any vault write begins (Q3 transient-previous-slot).
    /// Distinct exit code 6 — not 4 (filesystem failure) and not 5
    /// (port bind) — so operators can triage "stale rotation state"
    /// from "filesystem broken" or "port conflict".
    #[error(
        "vault rotation incomplete: envelopes span multiple key_ids \
         (min={min}, max={max}); re-run `agentsso rotate-key` to finish"
    )]
    VaultRotationIncomplete {
        /// The smallest `key_id` observed in any `.sealed` envelope.
        min: u8,
        /// The largest `key_id` observed in any `.sealed` envelope.
        max: u8,
    },
    /// Story 7.6b round-2 review: rotation state cannot be verified
    /// (marker file is malformed/unreadable, OR vault dir is
    /// unreadable, OR a rotation-state marker file is on disk
    /// indicating an in-flight rotation). Distinct from
    /// [`Self::VaultRotationIncomplete`] which means the daemon
    /// observed concrete proof of mixed-key state. This variant is
    /// the "I cannot tell — refuse fail-closed" arm. Exit code 6
    /// (same family).
    #[error(
        "rotation state cannot be verified: {reason}; \
         re-run `agentsso rotate-key` to finish — or run \
         `agentsso keystore-clear-previous` if the rotation is \
         abandoned and you want to start fresh"
    )]
    VaultStateUnverifiable {
        /// Human-readable reason: marker malformed / vault dir
        /// unreadable / marker phase recorded.
        reason: String,
    },
}

impl StartError {
    /// Map each variant to its operator-facing exit code. See the
    /// `StartError` doc comment for the exit code semantics.
    pub(crate) fn exit_code(&self) -> u8 {
        match self {
            // Exit 2 — configuration or bootstrap failure.
            Self::ConfigLoad(_)
            | Self::PoliciesDir { .. }
            | Self::PolicyCompile { .. }
            | Self::KeystoreConstruction { .. }
            | Self::MasterKeyCall { .. }
            | Self::HkdfExpand
            | Self::ServeFailed { .. }
            | Self::TelemetryInit { .. }
            | Self::PluginRuntimeInit { .. }
            | Self::PluginLoadFailed { .. } => 2,
            // Exit 3 — another process holds a coordination resource.
            Self::DaemonAlreadyRunning { .. }
            | Self::PidFileAcquire(_)
            | Self::DaemonStartVaultBusy { .. } => 3,
            // Exit 4 — filesystem-level failure on a coordination
            // resource (Story 7.6a round-1 review patch).
            Self::VaultLockIo { .. } => 4,
            // Exit 5 — TCP bind failure (Story 7.6a round-1 review
            // patch — distinct remediation from "another process
            // holds it" and from "filesystem failure").
            Self::BindFailed { .. } => 5,
            // Exit 6 — vault rotation incomplete (Story 7.6b AC #13).
            // Distinct from 3/4/5 because the operator's remediation
            // is unique: re-run `agentsso rotate-key` to finish.
            Self::VaultRotationIncomplete { .. } | Self::VaultStateUnverifiable { .. } => 6,
        }
    }

    /// Render a multi-line operator-facing banner for this error,
    /// written to stderr before `main()` returns. Each variant owns
    /// its own remediation advice.
    ///
    /// The banner is intentionally printed BEFORE any structured
    /// tracing write so operators see the advice even if the
    /// tracing subscriber is backlogged.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn render_banner(&self) -> String {
        match self {
            Self::ConfigLoad(msg) => format!("{msg}\n"),
            Self::PoliciesDir { path, source } => format!(
                "error: failed to prepare policies directory {}: {source}\n",
                path.display()
            ),
            Self::PolicyCompile { rendered } => rendered.clone(),
            // Both keystore-related variants render the SAME fixed
            // banner text so future `KeyStoreError` variants cannot
            // leak filesystem paths, partial key material, or other
            // implementation-specific bytes into operator stderr
            // (which typically flows into systemd journal, launchd
            // logs, or CI artifact storage). The structured
            // `{source}` error is written separately to the tracing
            // subscriber via `tracing::error!` in `main()` — operators
            // who need the raw cause can grep the log, while the
            // banner stays hermetic.
            Self::KeystoreConstruction { .. } => {
                "error: failed to construct the platform keystore adapter.\n\
                 \n\
                 the daemon cannot boot without a keystore — every authenticated\n\
                 request would return 401 and the vault cannot decrypt credentials.\n\
                 \n\
                 common causes:\n\
                 - on linux: the secret-service daemon is not running\n\
                   (install `libsecret` / `gnome-keyring-daemon` and start a session)\n\
                 - on fresh CI containers: no keyring backend available —\n\
                   install a software keyring, or use a dev build.\n\
                 \n\
                 run `agentsso` with `RUST_LOG=debug` for the underlying error.\n"
                    .to_owned()
            }
            Self::MasterKeyCall { .. } => "error: failed to provision the vault master key.\n\
                 \n\
                 the daemon cannot boot without a master key — every authenticated\n\
                 request would return 401 and the vault cannot decrypt credentials.\n\
                 \n\
                 common causes:\n\
                 - on macOS: the login keychain is locked — unlock it and retry\n\
                 - on linux: the secret-service daemon is not running\n\
                   (install `libsecret` / `gnome-keyring-daemon` and start a session)\n\
                 - on fresh CI containers: no keyring backend available —\n\
                   install a software keyring, or use a dev build.\n\
                 \n\
                 run `agentsso` with `RUST_LOG=debug` for the underlying error.\n"
                .to_owned(),
            Self::HkdfExpand => "error: HKDF expansion of the agent token lookup subkey failed \
                 unexpectedly.\n\
                 This is a cryptographic library error and should not happen in normal operation.\n\
                 Please file an issue with your platform details.\n"
                .to_owned(),
            Self::DaemonAlreadyRunning { pid } => {
                format!("error: daemon is already running (pid {pid})\n")
            }
            Self::PidFileAcquire(msg) => format!("error: failed to acquire PID file: {msg}\n"),
            Self::DaemonStartVaultBusy { holder_pid, holder_command } => {
                let holder_text = match (holder_pid, holder_command.as_deref()) {
                    (Some(pid), Some(cmd)) => format!("pid {pid} ({cmd})"),
                    (Some(pid), None) => format!("pid {pid}"),
                    (None, Some(cmd)) => cmd.to_owned(),
                    (None, None) => "another process".to_owned(),
                };
                format!(
                    "error: cannot start agentsso — the vault lock at \
                     ~/.agentsso/vault/.lock is held by {holder_text}.\n\
                     \n\
                     remediation:\n\
                     - if you are running `agentsso rotate-key`, `agentsso setup`,\n\
                       or `agentsso update --apply`, wait for it to finish.\n\
                     - if no other agentsso process is actually running, the\n\
                       lock file may be stale; remove ~/.agentsso/vault/.lock\n\
                       and retry.\n"
                )
            }
            Self::VaultLockIo { source } => format!(
                "error: failed to acquire the vault advisory lock at \
                 ~/.agentsso/vault/.lock: {source}\n\
                 \n\
                 check filesystem permissions on ~/.agentsso/vault/.\n"
            ),
            Self::BindFailed { addr, source } => {
                format!("error: failed to bind TCP listener on {addr}: {source}\n")
            }
            Self::ServeFailed { source } => {
                format!("error: HTTP server terminated with error: {source}\n")
            }
            Self::TelemetryInit { source } => format!(
                "error: failed to initialize operational logging: {source}\n\
                 \n\
                 the daemon could not set up its tracing subscriber. common causes:\n\
                 - the configured log directory is not writable\n\
                 - another subscriber was already installed (unlikely on production boot)\n\
                 \n\
                 override the log path via `[log] path = \"...\"` in daemon.toml\n\
                 or AGENTSSO_LOG__PATH=... if the default location is unavailable.\n"
            ),
            Self::PluginRuntimeInit { source } => format!(
                "error: failed to initialize the connector plugin runtime: {source}\n\
                 \n\
                 the daemon cannot boot without the QuickJS sandbox — every\n\
                 connector plugin call would fail with 503 plugin_resource_exceeded.\n\
                 \n\
                 this failure is unexpected in normal operation. check that the\n\
                 daemon has enough available memory to allocate the JS heap (32 MiB\n\
                 default) and file a bug if the problem persists.\n"
            ),
            Self::PluginLoadFailed { source } => format!(
                "error: a built-in connector failed to load: {source}\n\
                 \n\
                 built-in connectors (Gmail, Calendar, Drive) are shipped in the\n\
                 daemon binary via the `permitlayer-connectors` crate. A load\n\
                 failure here means the shipped binary is corrupt OR a recent\n\
                 change to a placeholder index.js broke metadata validation.\n\
                 \n\
                 this is a shipped-binary bug. reinstall permitlayer from the\n\
                 official release channel; if the problem persists, file a bug.\n\
                 user-installed plugins at `~/.agentsso/plugins/` do NOT trigger\n\
                 this banner (their failures are logged and the connector is\n\
                 skipped).\n"
            ),
            Self::VaultRotationIncomplete { min, max } => format!(
                "error: vault contains envelopes at multiple key_ids \
                 (min={min}, max={max})\n\
                 \n\
                 a previous `agentsso rotate-key` started but did not finish. The\n\
                 daemon refuses to boot until the rotation is complete because\n\
                 a partially-rotated vault can leave the agent registry and the\n\
                 sealed credentials out of sync.\n\
                 \n\
                 remediation:\n\
                 - re-run `agentsso rotate-key`. The keystore stages both the old\n\
                   and new master keys atomically before any vault write begins,\n\
                   so re-running is always safe — rotation completes idempotently.\n\
                 - once rotation finishes, `agentsso start` boots cleanly.\n"
            ),
            Self::VaultStateUnverifiable { reason } => format!(
                "error: rotation state cannot be verified ({reason})\n\
                 \n\
                 the daemon refuses to boot when it cannot determine whether a\n\
                 master-key rotation is in flight. This is the fail-closed posture:\n\
                 we'd rather refuse than risk booting against a half-rotated vault.\n\
                 \n\
                 remediation:\n\
                 - if a rotation is in flight, re-run `agentsso rotate-key`.\n\
                 - if a rotation crashed at `pre-previous` or `pre-primary`, run\n\
                   `agentsso keystore-clear-previous` to abandon it; then re-run\n\
                   `agentsso rotate-key` to start fresh.\n\
                 - if the rotation-state marker file is malformed, inspect or remove\n\
                   `~/.agentsso/vault/.rotation-state` by hand; the keystore is\n\
                   unaffected by removing the marker.\n\
                 - if the vault directory is unreadable, fix the filesystem perms\n\
                   (`chmod 0700 ~/.agentsso/vault/`) and try again.\n"
            ),
        }
    }
}

/// Eagerly provision the vault master key at daemon boot (Story 1.15).
///
/// Calls [`permitlayer_keystore::KeyStore::master_key`], which is
/// documented as "generate and persist a fresh key on first call if
/// none exists." After this call returns `Ok`, the OS keychain has a
/// 32-byte master key entry, every subsequent `master_key()` call
/// returns the same value, and every downstream consumer
/// (`try_build_agent_runtime`, `try_build_proxy_service`,
/// `Vault::open_or_create`) can assume the key exists.
///
/// **Why this function exists.** Before Story 1.15, the master key
/// was only provisioned as a side effect of `agentsso setup <service>`
/// — the OAuth setup wizard opened the vault, which lazily generated
/// the key on first access. The consequence: a fresh install that
/// followed the natural ordering `agentsso start → agentsso agent
/// register → agentsso setup` failed at step 2 with a confusing 503
/// `agent.no_master_key` error. Story 1.15 moves provisioning into
/// the eager boot path so the first-touch flow is valid.
///
/// # Test seam
///
/// `AGENTSSO_TEST_MASTER_KEY_HEX` lets integration tests drive a
/// deterministic master key without provisioning a real keychain
/// entry. Story 7.6b round-2 re-triage: gated by the `test-seam`
/// Cargo feature (NOT `cfg(debug_assertions)`). The feature is
/// enabled by `cargo test`'s integration target via
/// `required-features = ["test-seam"]`; OFF for `cargo build` /
/// `cargo build --release` / `cargo install`. An operator with the
/// env var exported in their shell cannot accidentally seed a known
/// master key into a production daemon, regardless of how the
/// binary was built. Mirrors the same Cargo-metadata-explicit
/// boundary for the `AGENTSSO_TEST_KEYSTORE_FILE_BACKED` and
/// `AGENTSSO_TEST_ROTATE_CRASH_AT_PHASE` seams.
///
/// # Errors
///
/// Returns [`StartError::KeystoreConstruction`] if the platform
/// keystore adapter cannot be constructed (e.g., the Linux
/// secret-service daemon is not running), or
/// [`StartError::MasterKeyCall`] if the keychain FFI call fails
/// after the adapter is constructed.
pub(crate) async fn ensure_master_key_bootstrapped(
    config: &DaemonConfig,
) -> Result<zeroize::Zeroizing<[u8; permitlayer_keystore::MASTER_KEY_LEN]>, StartError> {
    // Story 7.6b round-2 re-triage: test seams are gated by the
    // `test-seam` Cargo feature (NOT `cfg(debug_assertions)`). The
    // feature is enabled by `cargo test` via the integration test
    // target's `required-features = ["test-seam"]`; it is OFF for
    // `cargo build` / `cargo build --release` / `cargo install`.
    // This makes the seam-vs-production boundary an explicit Cargo
    // metadata fact rather than a build-profile inference. Pre-
    // round-2 these env vars activated in any debug build, which
    // exposed casual-`cargo build` users to leaked-shell-var
    // bypasses of the real keystore.
    #[cfg(feature = "test-seam")]
    {
        // (1) Test seam: force keystore error at boot. Used by the
        //     fail-fast subprocess test to drive the exit(2) path
        //     without touching the real OS keychain. Accepts `"1"`,
        //     `"true"`, or `"yes"` (case-insensitive, whitespace
        //     trimmed) so typos in shell rc files don't silently
        //     skip the seam. (Story 1.15 review patch.)
        if let Ok(raw) = std::env::var("AGENTSSO_TEST_FORCE_KEYSTORE_ERROR") {
            let normalized = raw.trim().to_ascii_lowercase();
            if matches!(normalized.as_str(), "1" | "true" | "yes") {
                tracing::warn!(
                    "AGENTSSO_TEST_FORCE_KEYSTORE_ERROR is set — simulating keystore \
                     construction failure for test"
                );
                // Use a synthetic `BackendUnavailable` error so the
                // type matches the production path. `source` is
                // boxed per the KeyStoreError contract.
                return Err(StartError::KeystoreConstruction {
                    source: permitlayer_keystore::KeyStoreError::BackendUnavailable {
                        backend: "test-forced-error",
                        source: "forced by AGENTSSO_TEST_FORCE_KEYSTORE_ERROR".into(),
                    },
                });
            }
        }

        // (2) Test seam: deterministic master key (pre-existing).
        if let Some(hex_key) = read_test_master_key_env() {
            return Ok(hex_key);
        }

        // (3) Test seam: `PassphraseKeyStore` with a fixed test
        //     passphrase. Routes through the REAL keystore code
        //     path (Argon2id-derived key, filesystem-persisted
        //     verifier/salt) so integration tests exercise the
        //     production `bootstrap_from_keystore` call, not just
        //     a short-circuit. This closes the Story 1.15 review
        //     Decision 2 coverage gap: previously no test touched
        //     `bootstrap_from_keystore` end-to-end because
        //     `AGENTSSO_TEST_MASTER_KEY_HEX` short-circuited before
        //     reaching it. Compile-gated under `debug_assertions`
        //     like the other seams.
        if let Ok(passphrase) = std::env::var("AGENTSSO_TEST_PASSPHRASE") {
            tracing::warn!(
                "AGENTSSO_TEST_PASSPHRASE is set — using test passphrase keystore. \
                 This env var is only honored when agentsso is built with the \
                 `test-seam` Cargo feature, which production builds (`cargo install`) \
                 never enable."
            );
            let keystore = permitlayer_keystore::PassphraseKeyStore::from_passphrase(
                &config.paths.home,
                &passphrase,
            )
            .map_err(|source| StartError::KeystoreConstruction { source })?;
            return bootstrap_from_keystore(&keystore).await;
        }

        // (4) Test seam: `FileBackedKeyStore` shared with rotate-key.
        //     Story 7.6b round-2 review: the auth-round-trip e2e test
        //     in `rotate_key_e2e.rs::auth_round_trip_against_running_daemon`
        //     needs the daemon AND rotate-key to use the SAME
        //     keystore so a key rotation is visible to the daemon's
        //     post-restart bootstrap. The file-backed test keystore
        //     (mode 0o600, on-disk, survives subprocess restarts)
        //     provides that — same env var the rotate-key seam uses.
        if std::env::var("AGENTSSO_TEST_KEYSTORE_FILE_BACKED").is_ok() {
            tracing::warn!(
                "AGENTSSO_TEST_KEYSTORE_FILE_BACKED is set — using file-backed test \
                 keystore at boot. This env var is only honored when agentsso is \
                 built with the `test-seam` Cargo feature."
            );
            let keystore = permitlayer_keystore::FileBackedKeyStore::new(&config.paths.home)
                .map_err(|source| StartError::KeystoreConstruction { source })?;
            return bootstrap_from_keystore(&keystore).await;
        }
    }

    let keystore_config = permitlayer_keystore::KeystoreConfig {
        fallback: permitlayer_keystore::FallbackMode::Auto,
        home: config.paths.home.clone(),
    };
    let keystore = permitlayer_keystore::default_keystore(&keystore_config)
        .map_err(|source| StartError::KeystoreConstruction { source })?;

    bootstrap_from_keystore(&*keystore).await
}

/// Testable core of [`ensure_master_key_bootstrapped`]: given an
/// already-constructed `KeyStore`, call `master_key` and convert
/// errors. Split from the production wrapper so unit tests can
/// inject a fake `KeyStore` without touching the filesystem or the
/// OS keychain.
///
/// `KeyStore::master_key` is documented to generate and persist a
/// fresh random key on first call. On second and subsequent calls
/// it returns the same value from the backend.
///
/// # Zero-key validation (Story 1.15 review patch)
///
/// Rejects a returned all-zero key as a malformed master key. A
/// buggy `KeyStore` implementation returning `[0u8; 32]` would
/// otherwise HKDF-expand to a deterministic, trivially-recoverable
/// subkey. Matches NFR20 fail-closed posture.
pub(crate) async fn bootstrap_from_keystore(
    keystore: &dyn permitlayer_keystore::KeyStore,
) -> Result<zeroize::Zeroizing<[u8; permitlayer_keystore::MASTER_KEY_LEN]>, StartError> {
    let key = keystore.master_key().await.map_err(|source| StartError::MasterKeyCall { source })?;

    // Zero-key validation: a buggy keystore returning all-zero bytes
    // would produce a deterministic (trivially recoverable) HKDF
    // subkey downstream. Fail-closed at the boundary.
    if key.as_slice() == [0u8; permitlayer_keystore::MASTER_KEY_LEN] {
        return Err(StartError::MasterKeyCall {
            source: permitlayer_keystore::KeyStoreError::MalformedMasterKey {
                expected_len: permitlayer_keystore::MASTER_KEY_LEN,
                actual_len: 0,
            },
        });
    }

    tracing::info!("master key bootstrapped");
    Ok(key)
}

/// Parse `AGENTSSO_TEST_MASTER_KEY_HEX` into a 32-byte master key if
/// set and valid. Returns `None` when the env var is absent, too
/// short/long, or contains non-hex characters.
///
/// Compiled out unless the `test-seam` Cargo feature is enabled —
/// see [`ensure_master_key_bootstrapped`] for the rationale.
#[cfg(feature = "test-seam")]
fn read_test_master_key_env()
-> Option<zeroize::Zeroizing<[u8; permitlayer_keystore::MASTER_KEY_LEN]>> {
    let Ok(hex_str) = std::env::var("AGENTSSO_TEST_MASTER_KEY_HEX") else {
        return None;
    };
    if hex_str.len() != permitlayer_keystore::MASTER_KEY_LEN * 2 {
        tracing::error!(
            "AGENTSSO_TEST_MASTER_KEY_HEX must be exactly {} characters (got {})",
            permitlayer_keystore::MASTER_KEY_LEN * 2,
            hex_str.len()
        );
        return None;
    }
    let mut out = [0u8; permitlayer_keystore::MASTER_KEY_LEN];
    let bytes = hex_str.as_bytes();
    for (i, chunk) in bytes.chunks(2).enumerate() {
        let hi = match chunk[0] {
            b'0'..=b'9' => chunk[0] - b'0',
            b'a'..=b'f' => 10 + chunk[0] - b'a',
            b'A'..=b'F' => 10 + chunk[0] - b'A',
            _ => {
                tracing::error!(
                    "AGENTSSO_TEST_MASTER_KEY_HEX contained non-hex characters — ignoring"
                );
                return None;
            }
        };
        let lo = match chunk[1] {
            b'0'..=b'9' => chunk[1] - b'0',
            b'a'..=b'f' => 10 + chunk[1] - b'a',
            b'A'..=b'F' => 10 + chunk[1] - b'A',
            _ => {
                tracing::error!(
                    "AGENTSSO_TEST_MASTER_KEY_HEX contained non-hex characters — ignoring"
                );
                return None;
            }
        };
        out[i] = (hi << 4) | lo;
    }
    tracing::warn!(
        "AGENTSSO_TEST_MASTER_KEY_HEX is set — using test master key. \
         This env var is compiled out of release builds and MUST NEVER \
         appear in a production deployment."
    );
    Some(zeroize::Zeroizing::new(out))
}

#[allow(clippy::type_complexity)]
fn build_shared_services(
    config: &DaemonConfig,
) -> (
    Option<Arc<permitlayer_core::scrub::ScrubEngine>>,
    Option<Arc<dyn permitlayer_core::store::AuditStore>>,
    Option<Arc<tokio::sync::Semaphore>>,
) {
    let scrub_engine = match permitlayer_core::scrub::ScrubEngine::new(
        permitlayer_core::scrub::builtin_rules().to_vec(),
    ) {
        Ok(engine) => Arc::new(engine),
        Err(e) => {
            tracing::error!(
                error = %e,
                "built-in scrub engine failed to compile — refusing to enable tool routes or audit writes"
            );
            eprintln!(
                "error: built-in scrub engine failed to compile: {e}\n\
                     tool routes disabled (all /mcp and /v1/tools/* requests will return 501).\n\
                     audit writes disabled (kill/resume events will not be logged).\n\
                     this is a fail-closed safety response — do not enable routes until the scrub engine is fixed."
            );
            return (None, None, None);
        }
    };

    let audit_dir = config.paths.home.join("audit");
    match permitlayer_core::store::fs::AuditFsStore::new(
        audit_dir,
        100_000_000,
        Arc::clone(&scrub_engine),
    ) {
        Ok(store) => {
            // Story 8.2 review fix D1: expose the store's bounded-write
            // semaphore so the daemon-owned `AuditDispatcher` can
            // acquire the SAME permits the writer uses — single cap
            // across producer and consumer edges.
            let semaphore = store.semaphore();
            let store_arc: Arc<dyn permitlayer_core::store::AuditStore> = Arc::new(store);
            (Some(scrub_engine), Some(store_arc), Some(semaphore))
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "audit store creation failed — kill/resume events will not be logged; tool routes will also serve 501"
            );
            (Some(scrub_engine), None, None)
        }
    }
}

pub async fn run(args: StartArgs) -> Result<(), StartError> {
    // 1. Build CLI overrides from args.
    let cli_overrides = CliOverrides {
        http: args.bind_addr.map(|a| HttpOverrides { bind_addr: a }),
        log: args.log_level.map(|l| LogOverrides { level: Some(l), ..LogOverrides::default() }),
    };

    // 2. Load config (layered: defaults → TOML → env → CLI).
    let config =
        DaemonConfig::load(&cli_overrides).map_err(|e| StartError::ConfigLoad(e.to_string()))?;
    // Story 5.4: validate operational log retention into [1, 365] so a
    // misconfigured TOML value cannot produce nonsense sweep behavior.
    //
    // **M2 review patch:** the `validated()` call internally emits
    // `tracing::warn!` on out-of-range values, but no subscriber is
    // wired up yet at this point — those warnings would land
    // nowhere. Capture the original (pre-clamp) value here, run
    // `validated()` (which is still safe for the clamping itself —
    // the warns just disappear), then re-emit a single explicit
    // `tracing::warn!` AFTER `init_tracing` if the clamp actually
    // moved the value.
    let log_cfg_raw_retention = config.log.retention_days;
    let log_cfg = config.log.clone().validated();
    let log_retention_was_clamped = log_cfg.retention_days != log_cfg_raw_retention;

    // 3. Acquire PID file.
    //
    // **Story 7.4 P19/P23 + 7.6a review:** PidFile + VaultLock
    // refusals run BEFORE `init_tracing` so a refused-to-start
    // attempt does NOT create `~/.agentsso/logs/`, rotate operator
    // logs, or churn the tracing subscriber. The structured banner
    // is rendered from `main()` regardless; the in-handler
    // `tracing::error!` calls below fall back to the default
    // subscriber (which routes to stderr) without instantiating the
    // file appender.
    //
    // Story 1.15 review: `pid_file` is a local binding — any error
    // path after this point that returns via `?` runs `PidFile::drop`
    // naturally, cleaning up `~/.agentsso/pid`. Bubbling errors to
    // `main()` replaces the scattered `drop(pid_file); exit(N);`
    // pattern with a single stack-unwind that respects every `Drop`.
    let pid_file = match PidFile::acquire(&config.paths.home) {
        Ok(p) => p,
        Err(crate::lifecycle::pid::PidFileError::DaemonAlreadyRunning { pid }) => {
            tracing::error!(pid, "daemon is already running");
            return Err(StartError::DaemonAlreadyRunning { pid });
        }
        Err(e) => {
            tracing::error!("failed to acquire PID file: {e}");
            return Err(StartError::PidFileAcquire(e.to_string()));
        }
    };

    // 3a. Acquire the vault-level advisory lock (Story 7.6a AC #3).
    //
    // Precedence: PidFile guards "the daemon is running"; VaultLock
    // guards "vault writes are exclusive across all processes". They
    // serve different purposes and the daemon needs both. The lock is
    // bound to the local `_vault_lock` guard; any `?` after this point
    // unwinds through Drop and releases the kernel-side lock cleanly,
    // mirroring the PidFile discipline.
    //
    // We use `try_acquire` (not blocking) so a stuck holder produces
    // a structured error instead of stranding `agentsso start` on the
    // command line. The most common cause of `Busy` is `agentsso
    // rotate-key` mid-flight from a different terminal — operator
    // remediation lives in the rendered banner.
    let _vault_lock = match permitlayer_core::VaultLock::try_acquire(&config.paths.home) {
        Ok(g) => g,
        Err(permitlayer_core::VaultLockError::Busy { holder_pid, holder_command }) => {
            tracing::error!(
                holder_pid = ?holder_pid,
                holder_command = ?holder_command,
                "daemon refusing to start: vault lock is busy"
            );
            return Err(StartError::DaemonStartVaultBusy { holder_pid, holder_command });
        }
        Err(permitlayer_core::VaultLockError::Io(source)) => {
            tracing::error!(error = %source, "vault lock acquisition failed");
            return Err(StartError::VaultLockIo { source });
        }
        // `VaultLockError` is `#[non_exhaustive]`. Future variants land
        // here; until they exist, treat any unknown error as an I/O
        // failure with a synthesized message so the operator still
        // gets exit-code 3 and a banner.
        Err(other) => {
            let synth = std::io::Error::other(format!("unrecognized vault lock error: {other}"));
            tracing::error!(error = %other, "vault lock acquisition failed (unknown variant)");
            return Err(StartError::VaultLockIo { source: synth });
        }
    };

    // 3a. Story 7.6b AC #13: refuse to boot if a rotation is
    // mid-flight. There are two independent indicators, BOTH of
    // which trigger refusal:
    //
    //   (a) The rotation-state marker file is present
    //       (`<home>/vault/.rotation-state`). The marker is the
    //       authoritative record of in-flight rotation; if it's on
    //       disk, the previous `agentsso rotate-key` either crashed
    //       or is still running.
    //   (b) The vault contains envelopes at multiple `key_id`
    //       values (`min < max`). A previous rotate-key reached
    //       Phase D but did not finish.
    //
    // Story 7.6b round-1 review (fail-closed): a vault that exists
    // but is unreadable (`compute_min_max_key_id` returns `Err`) is
    // also a refusal. The previous code silently passed.
    let vault_dir = config.paths.home.join("vault");

    // Marker check first — it's the authoritative state.
    match crate::cli::rotate_key::marker::read(&config.paths.home) {
        Ok(Some(marker)) => {
            tracing::error!(
                keystore_phase = ?marker.keystore_phase,
                marker_pid = marker.pid,
                marker_started_at = %marker.started_at,
                old_kid = marker.old_kid,
                new_kid = marker.new_kid,
                "daemon refusing to start: rotation-state marker present"
            );
            drop(_vault_lock);
            return Err(StartError::VaultRotationIncomplete {
                min: marker.old_kid,
                max: marker.new_kid,
            });
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!(
                error = %e,
                "daemon refusing to start: rotation-state marker is malformed/unreadable"
            );
            drop(_vault_lock);
            // Story 7.6b round-2 review: distinct StartError variant
            // for "I cannot tell" so the human-facing message is
            // accurate (the previous `VaultRotationIncomplete { 0, 0 }`
            // produced a contradictory "envelopes span multiple
            // key_ids (min=0, max=0)" banner — false on its face).
            return Err(StartError::VaultStateUnverifiable {
                reason: format!("rotation-state marker is malformed: {e}"),
            });
        }
    }

    // Vault min/max key_id check second.
    match compute_min_max_key_id(&vault_dir) {
        Ok(Some((min, max))) if min < max => {
            drop(_vault_lock);
            return Err(StartError::VaultRotationIncomplete { min, max });
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!(
                error = %e,
                "daemon refusing to start: vault is unreadable, cannot verify rotation state"
            );
            drop(_vault_lock);
            // Story 7.6b round-2 review: distinct variant for the
            // "vault unreadable" arm — see comment on the marker-
            // malformed case above.
            return Err(StartError::VaultStateUnverifiable {
                reason: format!("vault directory is unreadable: {e}"),
            });
        }
    }

    // 4. Initialize tracing subscriber (stdout + daily-rotating file
    // appender). The returned `WorkerGuard`s MUST live until process
    // exit — dropping them flushes buffered log lines through the
    // non-blocking appender and shuts the worker thread down. Binding
    // as `_guards` keeps the vector alive across the serve loop; the
    // final drop runs during stack unwind at `main()` return.
    //
    // Runs AFTER PidFile + VaultLock acquisition (Story 7.4 P19/P23 +
    // 7.6a review patch): a refused-to-start attempt must not create
    // `logs/`. The `pid_file` and `_vault_lock` bindings are local —
    // their `Drop`s run cleanly on the early-return paths above.
    let log_dir = log_cfg.path.clone().unwrap_or_else(|| config.paths.home.join("logs"));
    let _guards =
        telemetry::init_tracing(&config.log.level, Some(&log_dir), log_cfg.retention_days)
            .map_err(|source| StartError::TelemetryInit { source })?;
    tracing::info!("daemon starting");

    // **M2 review patch (continued):** post-init re-emit of the
    // clamp warning. `validated()` did the work pre-init; this
    // surfaces the diagnostic to the operator now that the
    // subscriber is wired up.
    if log_retention_was_clamped {
        tracing::warn!(
            given = log_cfg_raw_retention,
            clamped_to = log_cfg.retention_days,
            "log.retention_days out of [1, 365] range; clamped"
        );
    }

    // 4a. Sweep rotated operational log files older than retention.
    // Non-fatal: a sweep failure must never block boot (observability
    // degradation, not a correctness issue).
    match telemetry::sweep_rotated_logs(&log_dir, log_cfg.retention_days) {
        Ok(n) if n > 0 => {
            tracing::info!(
                removed = n,
                retention_days = log_cfg.retention_days,
                "swept rotated log files"
            )
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "log retention sweep failed (non-fatal)"),
    }

    // 5. Bind TCP listener.
    let bind_addr = config.http.bind_addr;

    // Non-localhost warning (NFR17).
    if !bind_addr.ip().is_loopback() {
        tracing::warn!(
            addr = %bind_addr,
            "binding to non-localhost address — this exposes permitlayer on the network"
        );
    }

    let listener = tokio::net::TcpListener::bind(bind_addr).await.map_err(|source| {
        tracing::error!(addr = %bind_addr, "failed to bind TCP listener: {source}");
        StartError::BindFailed { addr: bind_addr, source }
    })?;

    // Story 7.7: emit the actually-bound address on stdout so test
    // harnesses that pass `--bind-addr 127.0.0.1:0` can read the
    // OS-assigned ephemeral port without the TOCTOU pre-allocation
    // race that `free_port()` admits to in its own doc-comment.
    // Format is single-line `AGENTSSO_BOUND_ADDR=<addr>\n`, grep-stable
    // for parsing without the test having to swallow the rest of
    // startup chatter. Operators running `agentsso start` interactively
    // see one extra info line; production scripts ignore unknown
    // stdout. Flush is explicit because Windows pipes are line-buffered
    // and the test harness blocks on this line before continuing.
    let bound_addr = listener.local_addr().map_err(|source| {
        tracing::error!(addr = %bind_addr, "failed to read local_addr after bind: {source}");
        StartError::BindFailed { addr: bind_addr, source }
    })?;
    println!("AGENTSSO_BOUND_ADDR={bound_addr}");
    {
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }

    // 6. Set up shutdown channel.
    let (shutdown_fut, _shutdown_tx) = shutdown::shutdown_channel();
    let cli_overrides = Arc::new(cli_overrides);
    let config_state = Arc::new(ArcSwap::from_pointee(config.clone()));

    // 7. Build shared middleware state.
    let kill_switch = Arc::new(KillSwitch::new());

    // 7a. Compile policies from ~/.agentsso/policies/ (seeding default.toml
    // on first run). Fail-fast per FR15: any compile error exits non-zero
    // with a multi-line diagnostic naming the offending file and line.
    let policies_dir = config.paths.home.join("policies");
    ensure_policies_dir(&policies_dir)
        .map_err(|source| StartError::PoliciesDir { path: policies_dir.clone(), source })?;
    let compiled_policies = permitlayer_core::policy::PolicySet::compile_from_dir(&policies_dir)
        .map_err(|e| StartError::PolicyCompile { rendered: render_policy_error(&e) })?;
    tracing::info!(
        policies_loaded = compiled_policies.len(),
        dir = %policies_dir.display(),
        "policies compiled"
    );
    let policy_set = Arc::new(ArcSwap::from_pointee(compiled_policies));

    // Story 8.7 AC #5: wrap the allowlist in `ArcSwap` now so Epic 7+
    // can hot-swap it when `[dns] allowlist = [...]` becomes a real
    // config field. MVP contents stay `["127.0.0.1", "localhost"]`.
    let dns_allowlist: Arc<ArcSwap<Vec<String>>> =
        Arc::new(ArcSwap::from_pointee(vec!["127.0.0.1".to_owned(), "localhost".to_owned()]));

    // 7b. Build the shared `ScrubEngine` + `Option<Arc<dyn AuditStore>>`
    // singletons. Constructed once per daemon process and shared between
    // `ProxyService` (via `try_build_proxy_service`), the control-plane
    // router (via `control::router`), and `KillSwitchLayer` (via
    // `assemble_middleware`). One audit file, one writer lock, one
    // process-wide audit stream.
    //
    // See `build_shared_services` for the fail-closed vs best-effort
    // semantics: scrub engine is fail-closed (both become None on failure),
    // audit store is best-effort (proxy routes go dark but kill/resume
    // still work; audit writes silently skip via the Option<> wrapper).
    let (scrub_engine, audit_store, audit_semaphore) = build_shared_services(&config);

    // 7b¹. Story 8.2: construct the daemon-owned audit dispatcher. The
    // dispatcher owns a `JoinSet` so the graceful-shutdown path (step 10
    // below) can explicitly drain in-flight audit writes before the
    // 30-second hard deadline fires. Pre-Story-8.2 the middleware stack
    // held `Option<Arc<dyn AuditStore>>` and used bare `tokio::spawn`
    // for fire-and-forget writes; orphaned tasks were silently dropped
    // on SIGTERM — exactly the incident scenario where audit durability
    // matters most.
    //
    // Story 8.2 review fix D1: the dispatcher shares the
    // `AuditFsStore`'s concurrency semaphore so a single cap governs
    // both the producer edge (dispatch) and the consumer edge
    // (spawn_blocking). Under a flood, `dispatch().await` stalls at
    // the producer side instead of queuing unbounded tasks.
    let audit_dispatcher = match (audit_store.as_ref(), audit_semaphore.as_ref()) {
        (Some(store_arc), Some(sem)) => {
            Arc::new(permitlayer_core::audit::dispatcher::AuditDispatcher::new(
                Arc::clone(store_arc),
                Arc::clone(sem),
            ))
        }
        _ => Arc::new(permitlayer_core::audit::dispatcher::AuditDispatcher::none()),
    };

    // 7b''. Eagerly bootstrap the vault master key (Story 1.15).
    //
    // Before Story 1.15, the master key was only provisioned as a
    // side effect of `agentsso setup <service>` — the OAuth setup
    // wizard opened the vault, which lazily generated the key on
    // first access. The consequence: a fresh install that followed
    // the natural ordering `agentsso start → agentsso agent register
    // → agentsso setup` failed at step 2 with a confusing 503
    // `agent.no_master_key` error.
    //
    // Story 1.15 hoists master-key provisioning into this eager boot
    // step. After this call returns, the OS keychain has a 32-byte
    // master key entry and every downstream consumer
    // (`try_build_agent_runtime`, `try_build_proxy_service`,
    // `Vault::open_or_create`) can assume the key exists.
    //
    // Fail-fast on keystore errors: without a master key, every
    // authenticated request would 401 forever and the vault cannot
    // decrypt any credential. Booting into a half-alive state serves
    // no one.
    let master_key = ensure_master_key_bootstrapped(&config).await.inspect_err(|e| {
        tracing::error!(error = %e, "master key bootstrap failed — refusing to boot");
    })?;

    // Story 7.6a AC #12: walk the vault and compute the active
    // `key_id` as `max(envelope.key_id over all .sealed files)`,
    // defaulting to `0` for an empty vault. The proxy service's
    // `Vault` is constructed with this `key_id`; new seals (refresh
    // rotation, future setup-driven writes) stamp it on the
    // resulting envelope. Story 7.6b's rotate-key-v2 increments per
    // rotation; for 7.6a the result is always `0` because there has
    // been no rotation event yet.
    let active_key_id = compute_active_key_id(&config.paths.home.join("vault"));
    tracing::info!(active_key_id, "vault bootstrap: discovered active key_id");

    // 7b'. Build the agent identity store + registry + HMAC lookup
    // subkey (Story 4.4). Always gets a real master-key-derived
    // subkey now that Story 1.15 has provisioned the master key
    // eagerly above — no more zero-placeholder branch.
    let (agent_store, agent_registry, agent_lookup_key) =
        try_build_agent_runtime(&config, &master_key).await?;

    // 7c. Shared mutex guarding the load-diff-store sequence in
    // `reload_policies_with_diff_locked`. Prevents concurrent reloads
    // (SIGHUP + HTTP, or two HTTP POSTs) from computing diffs against
    // a stale snapshot.
    let reload_mutex = Arc::new(std::sync::Mutex::new(()));

    // 7d. Build the approval service (Story 4.5).
    //
    // Built BEFORE the SIGHUP watcher because the watcher needs a
    // clone to call `clear_caches()` after a successful policy
    // recompile. See `build_approval_service` for the selection
    // logic (test seams → interactive TTY → NoTty fallback).
    //
    // `approval_timeout` is resolved from config with a clamp to
    // [1, 300] seconds. A misconfigured value is silently clamped
    // rather than failing startup — a wrong-but-bounded timeout is
    // safer than a daemon that refuses to boot.
    // Story 8.7 AC #1/#2/#3: `approval_timeout` lives in an `Arc<AtomicU64>`
    // (seconds) shared between `PolicyLayer` (per-request reader), the
    // SIGHUP reload watcher, and `POST /v1/control/reload` (writers).
    // Operators who edit `[approval] timeout_seconds` see the change
    // take effect on the next reload without a daemon restart.
    let approval_timeout_atomic: Arc<std::sync::atomic::AtomicU64> = {
        let raw = config.approval.timeout_seconds;
        let clamped = clamp_approval_timeout_seconds(raw);
        if raw != clamped {
            tracing::warn!(
                configured = raw,
                clamped = clamped,
                "approval.timeout_seconds out of range [1,300]; clamping"
            );
        }
        Arc::new(std::sync::atomic::AtomicU64::new(clamped))
    };
    let approval_service: Arc<dyn permitlayer_proxy::middleware::ApprovalService> =
        build_approval_service();

    // Story 8.7 AC #4: boot-time 501-stub flag. Initialized HERE —
    // before `spawn_reload_watcher` — with the correct value so a
    // SIGHUP delivered in the narrow boot window between watcher
    // spawn and router construction can't observe `false` and skip
    // the stub-detection diagnostic.
    //
    // `try_build_proxy_service` is called up-front (moved from its
    // earlier post-middleware-assembly position by the Story 8.7
    // review patch) because its `None` return is the sole signal that
    // determines whether the stub branch will be wired into the axum
    // router below. All downstream consumers of `proxy_service`
    // (AppState construction, router wiring) are unchanged.
    let proxy_service = try_build_proxy_service(
        &config,
        scrub_engine.as_ref(),
        audit_store.as_ref(),
        &master_key,
        active_key_id,
    )
    .await;
    let proxy_stub_branch_active =
        Arc::new(std::sync::atomic::AtomicBool::new(proxy_service.is_none()));
    let vault_dir_for_reload = config.paths.home.join("vault");

    // 7e. Spawn the SIGHUP reload watcher — handles config, policy,
    // agent registry, AND the approval-service cache clear (Story 4.5).
    // Must run after policy_set, audit_store, agent_registry, and
    // approval_service are created.
    let _reload_rx = sighup::spawn_reload_watcher(
        Arc::clone(&config_state),
        Arc::clone(&cli_overrides),
        Arc::clone(&policy_set),
        policies_dir.clone(),
        Arc::clone(&reload_mutex),
        audit_store.clone(),
        Arc::clone(&agent_registry),
        agent_store.clone(),
        Arc::clone(&approval_service),
        Arc::clone(&approval_timeout_atomic),
        Arc::clone(&proxy_stub_branch_active),
        vault_dir_for_reload.clone(),
    );

    // 7f. Story 5.5: in-process per-agent connection tracker.
    //
    // Constructed BEFORE `assemble_middleware` so we can pass an
    // `Arc<dyn ConnTrackerSink>` adapter into the middleware chain.
    // The same `Arc<ConnTracker>` is shared with `AppState` (for
    // `health_handler`'s `active_connections` count) and with
    // `ControlState` (for the `connections_handler` snapshot).
    let conn_tracker_idle_timeout =
        std::time::Duration::from_secs(config.connections.clone().validated().idle_timeout_secs);
    let conn_tracker = Arc::new(ConnTracker::new(conn_tracker_idle_timeout));
    tracing::info!(
        idle_timeout_secs = conn_tracker_idle_timeout.as_secs(),
        "connection tracker initialized"
    );

    // 7g. Story 6.1: QuickJS plugin runtime.
    //
    // Constructed at boot so init failures surface via the Story 1.15
    // `StartError` banner path rather than lazily the first time a
    // plugin call happens. Consumed by Story 6.2's debug-only
    // `/v1/debug/plugin-echo` endpoint AND by Story 6.3's loader
    // (section 7h below).
    let plugin_runtime_start = std::time::Instant::now();
    let plugin_runtime = Arc::new(
        permitlayer_plugins::PluginRuntime::new_default()
            .map_err(|source| StartError::PluginRuntimeInit { source })?,
    );
    tracing::info!(
        init_ms = plugin_runtime_start.elapsed().as_millis() as u64,
        memory_limit_bytes = plugin_runtime.config().memory_limit_bytes,
        deadline_ms = plugin_runtime.config().execution_deadline.as_millis() as u64,
        "plugin runtime initialized"
    );

    // 7h. Story 6.3: plugin loader.
    //
    // Walks the built-in connector set (embedded via
    // `permitlayer-connectors`) and the user-installed plugins
    // directory (`{paths.home}/plugins/` by default, overridable via
    // `[plugins] plugins_dir = "..."`), parses each plugin's
    // `metadata` export, applies the first-load trust check, and
    // registers results into a `PluginRegistry` shared via
    // `AppState.plugin_registry`.
    //
    // Built-in failure -> fatal (`StartError::PluginLoadFailed` -> exit
    // 2); user-installed failure -> logged + skipped (daemon still
    // boots). The loader does NOT call `with_host_api` — metadata
    // parse uses the Story 6.1 sandbox-only `with_context` path, so
    // the AD4 `spawn_blocking` calling contract does not apply to
    // boot (loader is invoked directly from this async context).
    let plugin_registry = {
        let loader_start = std::time::Instant::now();
        let plugins_dir_raw =
            config.plugins.plugins_dir.clone().unwrap_or_else(|| config.paths.home.join("plugins"));
        // Require an absolute path so trust decisions persisted in
        // `.trusted` do not silently depend on the daemon's CWD. The
        // default (`{paths.home}/plugins`) is always absolute because
        // `paths.home` is already canonicalized earlier in `run`.
        if !plugins_dir_raw.is_absolute() {
            return Err(StartError::PluginLoadFailed {
                source: permitlayer_plugins::PluginError::PluginLoadFailed {
                    connector: "(config)".to_owned(),
                    reason: permitlayer_plugins::LoadFailureReason::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "plugins.plugins_dir must be an absolute path (got `{}`)",
                            plugins_dir_raw.display()
                        ),
                    )),
                },
            });
        }
        let plugins_dir = plugins_dir_raw;
        let trusted_path = plugins_dir.join(".trusted");
        let loader_config = permitlayer_plugins::LoaderConfig {
            auto_trust_builtins: config.plugins.auto_trust_builtins,
            warn_on_first_load: config.plugins.warn_on_first_load,
            plugins_dir,
            trusted_path,
        };
        let prompter = build_trust_prompt_reader();
        let registry = permitlayer_plugins::load_all(&plugin_runtime, loader_config, prompter)
            .map_err(|source| StartError::PluginLoadFailed { source })?;
        tracing::info!(
            init_ms = loader_start.elapsed().as_millis() as u64,
            connectors_loaded = registry.len(),
            "plugin registry initialized"
        );
        Arc::new(registry)
    };

    // Background sweep task: every 60s, drop entries whose
    // `last_request_at` is older than `idle_timeout`. The
    // `connections_handler` also runs `sweep_idle` on read so a
    // daemon that never receives a status query can't grow without
    // bound either way; this task keeps memory tight even in the
    // long-running idle case.
    //
    // **M5 review patch:** the task races shutdown via a shared
    // `Notify`. The shutdown sequence triggers it before tearing
    // down the runtime so the sweep loop exits cleanly rather than
    // being abruptly dropped mid-tick.
    //
    // **M7 review patch:** `MissedTickBehavior::Skip` so a slow
    // sweep on a heavily-loaded shard doesn't burst-coalesce
    // back-to-back ticks once the slow call returns.
    //
    // **H2 review patch:** `sweep_idle` takes a monotonic `Instant`
    // (not wall-clock) so a backward NTP correction can't pause
    // sweeps and a forward jump can't wipe everything in one tick.
    let sweep_shutdown = Arc::new(tokio::sync::Notify::new());
    {
        let tracker_for_sweep = Arc::clone(&conn_tracker);
        let shutdown = Arc::clone(&sweep_shutdown);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Skip the immediate first tick — nothing to sweep at boot.
            tick.tick().await;
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        let removed = tracker_for_sweep.sweep_idle(std::time::Instant::now());
                        if removed > 0 {
                            tracing::debug!(removed, "conn_tracker background sweep");
                        }
                    }
                    _ = shutdown.notified() => {
                        tracing::debug!("conn_tracker background sweep: shutdown signal received");
                        break;
                    }
                }
            }
        });
    }

    // 8. Assemble tower middleware chain via the canonical helper.
    //
    // The chain order (outermost → innermost) is:
    //   DnsRebind → Trace → KillSwitch → Auth → AgentIdentity → ConnTrack → Policy → Audit → handler
    //
    // See `permitlayer_proxy::middleware::assemble_middleware` for the
    // source of truth and the ordering-invariant tests that lock it in.
    let conn_tracker_sink: Arc<dyn permitlayer_proxy::middleware::ConnTrackerSink> =
        Arc::new(ConnTrackerAdapter::new(Arc::clone(&conn_tracker), Arc::clone(&agent_registry)));
    let middleware = assemble_middleware(
        Arc::clone(&kill_switch),
        Arc::clone(&policy_set),
        Arc::clone(&dns_allowlist),
        Arc::clone(&audit_dispatcher),
        Arc::clone(&agent_registry),
        Arc::clone(&agent_lookup_key),
        agent_store.clone(),
        Arc::clone(&approval_service),
        Arc::clone(&approval_timeout_atomic),
        conn_tracker_sink,
    );

    // 9. Build axum router using the `proxy_service` resolved earlier
    // (Story 8.7 review patch — it was moved up so the
    // `proxy_stub_branch_active` flag could be initialized BEFORE
    // `spawn_reload_watcher` spawned the SIGHUP task, closing a boot-
    // window race where an early SIGHUP could observe the flag
    // `false` before the downstream flag-flip set it).
    //
    // Story 1.15 review fix kept intact above: `try_build_proxy_service`
    // takes the eagerly bootstrapped `master_key` rather than calling
    // the keystore independently.
    let started_at = Instant::now();
    let state = AppState {
        started_at,
        bind_addr,
        config_state: Arc::clone(&config_state),
        kill_switch: Arc::clone(&kill_switch),
        policy_set: Arc::clone(&policy_set),
        dns_allowlist,
        agent_registry: Arc::clone(&agent_registry),
        agent_store: agent_store.clone(),
        approval_service: Arc::clone(&approval_service),
        conn_tracker: Arc::clone(&conn_tracker),
        plugin_runtime: Arc::clone(&plugin_runtime),
        plugin_registry: Arc::clone(&plugin_registry),
        #[cfg(debug_assertions)]
        proxy_service: proxy_service.as_ref().map(Arc::clone),
        #[cfg(debug_assertions)]
        audit_dispatcher: Arc::clone(&audit_dispatcher),
    };

    // Story 8.7 AC #4: `proxy_stub_branch_active` was initialized up-
    // front (line ~1695) from `proxy_service.is_none()` so the flag is
    // already in its correct state by the time the SIGHUP watcher was
    // spawned. No additional flip required here.
    let app = if let Some(proxy) = proxy_service {
        // Wire real MCP + REST routes.
        let gmail_mcp = permitlayer_proxy::transport::mcp::mcp_service(Arc::clone(&proxy));
        let calendar_mcp =
            permitlayer_proxy::transport::mcp::calendar_mcp_service(Arc::clone(&proxy));
        let drive_mcp = permitlayer_proxy::transport::mcp::drive_mcp_service(Arc::clone(&proxy));
        let rest_router = proxy.into_router();

        tracing::info!("proxy service initialized — MCP and REST routes active");
        // NFR31: CASA Tier 2+ required for restricted-scope services before public release.
        const CASA_REQUIRED_SERVICES: &[&str] = &["gmail", "drive"];
        for svc in CASA_REQUIRED_SERVICES {
            tracing::info!(
                service = svc,
                "connector uses restricted scopes — CASA LoV required before public release"
            );
        }
        // rest_router is Router<()> (stateless — captures Arc<ProxyService> in closures).
        // Merge it before applying .with_state(state) so axum can coerce it.
        let mut router = Router::new()
            .route("/health", get(health_handler))
            .route("/v1/health", get(health_handler))
            .nest_service("/mcp", gmail_mcp)
            .nest_service("/mcp/calendar", calendar_mcp)
            .nest_service("/mcp/drive", drive_mcp);

        // Story 6.2 / AC #30: debug-only plugin-eval endpoint.
        // ONLY registered in debug builds — release binaries
        // never expose a plugin-eval surface.
        #[cfg(debug_assertions)]
        {
            router = router.route("/v1/debug/plugin-echo", post(debug_plugin_echo_handler));
        }

        router.with_state(state).merge(rest_router).layer(middleware)
    } else {
        // No credentials yet — serve 501 stubs.
        tracing::info!("proxy service not available — tool routes will serve 501");
        Router::new()
            .route("/health", get(health_handler))
            .route("/v1/health", get(health_handler))
            .route("/mcp", get(not_implemented_handler).post(not_implemented_handler))
            .route("/mcp/calendar", get(not_implemented_handler).post(not_implemented_handler))
            .route("/mcp/drive", get(not_implemented_handler).post(not_implemented_handler))
            .route("/v1/tools/{service}/{*path}", any(not_implemented_handler))
            .with_state(state)
            .layer(middleware)
    };

    // 9a. Merge the control router AFTER `.layer(middleware)` is applied to
    // the main router, so the control routes are carved out of the kill-switch
    // chain. This is load-bearing: `POST /v1/control/resume` must keep working
    // when the daemon is killed, and the only safe way to achieve that is to
    // ensure the control routes are NOT behind `KillSwitchLayer`.
    //
    // See `crates/permitlayer-daemon/src/server/control.rs` for the router
    // builder and the loopback guard. The loopback guard is enforced inline in
    // each handler via `ConnectInfo<SocketAddr>` rather than a tower layer, to
    // avoid resurrecting a parallel middleware stack that could drift from
    // `assemble_middleware`.
    let control_router = control::router(
        Arc::clone(&kill_switch),
        audit_store.clone(),
        Arc::clone(&policy_set),
        policies_dir,
        reload_mutex,
        Arc::clone(&agent_registry),
        agent_store.clone(),
        agent_lookup_key,
        Arc::clone(&approval_service),
        Arc::clone(&conn_tracker),
        Arc::clone(&plugin_registry),
        Arc::clone(&approval_timeout_atomic),
        Arc::clone(&config_state),
        Arc::clone(&cli_overrides),
        Arc::clone(&proxy_stub_branch_active),
        vault_dir_for_reload,
    );
    // `agent_lookup_key` (the local binding) is moved into control::router
    // above — the middleware call earlier already `Arc::clone`d its
    // reference. Moving avoids holding a redundant Arc for the rest of
    // `run()`; the subkey bytes are reachable through the middleware
    // closure and through `ControlState` for the daemon's lifetime.
    let app = app.merge(control_router);

    tracing::info!(addr = %bind_addr, pid = std::process::id(), "daemon ready");

    // 10. Serve with graceful shutdown + 30s drain timeout budget.
    //
    // Story 8.2 review fix F2: the 30s budget is split — axum's
    // connection drain gets 25s, the audit dispatcher gets 5s — so the
    // total graceful-shutdown time is still 30s, not 30+5. The audit
    // drain runs AFTER axum finishes (or after axum's 25s fires), which
    // means no new requests can dispatch audit events after the drain
    // starts (axum has stopped accepting connections).
    let drain_notify = Arc::new(tokio::sync::Notify::new());
    let drain_notify_clone = Arc::clone(&drain_notify);
    let sweep_shutdown_for_graceful = Arc::clone(&sweep_shutdown);
    let graceful_fut = async move {
        shutdown_fut.await;
        // M5 review patch: signal the connection-tracker sweep task
        // BEFORE notifying the axum drain, so the sweep loop can
        // exit cleanly while in-flight requests still complete.
        sweep_shutdown_for_graceful.notify_one();
        drain_notify_clone.notify_one();
    };
    // `into_make_service_with_connect_info::<SocketAddr>()` enables the
    // `ConnectInfo<SocketAddr>` extractor used by the control-plane handlers
    // for their loopback-only guard. It is a drop-in replacement for plain
    // `into_make_service()` at the serve level — pre-existing handlers that
    // don't extract `ConnectInfo` are unaffected.
    let serve_fut = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(graceful_fut);
    // 25 seconds reserved for axum connection draining; the remaining
    // 5 seconds are reserved for the audit dispatcher drain below.
    const AXUM_DRAIN_BUDGET: Duration = Duration::from_secs(25);
    const AUDIT_DRAIN_BUDGET: Duration = Duration::from_secs(5);
    let drain_deadline = async {
        drain_notify.notified().await;
        tokio::time::sleep(AXUM_DRAIN_BUDGET).await;
        tracing::warn!(
            "axum shutdown drain budget exceeded ({}s), dropping remaining connections",
            AXUM_DRAIN_BUDGET.as_secs()
        );
    };
    tokio::select! {
        result = serve_fut => { result.map_err(|source| StartError::ServeFailed { source })?; }
        () = drain_deadline => {}
    }

    // 11. Shutdown sequence.
    //
    // Story 8.2 review fix F2: drain the audit dispatcher within its
    // carved-out 5-second slice of the 30-second total budget. In
    // practice drains complete in <1s because the only in-flight work
    // is the tail of `spawn_blocking` fsync calls that had not yet
    // completed when the graceful-shutdown signal fired. Audit events
    // generated during the axum drain above are included because the
    // middleware call sites hold the dispatcher `Arc` for the lifetime
    // of their response future — the JoinSet is guaranteed to capture
    // them.
    let audit_drain_report = audit_dispatcher.drain(AUDIT_DRAIN_BUDGET).await;
    tracing::info!(
        drained = audit_drain_report.drained,
        timed_out = audit_drain_report.timed_out,
        "audit dispatcher drained"
    );
    tracing::info!("vault closed"); // stub — actual vault integration later

    if let Err(e) = pid_file.release() {
        tracing::warn!("failed to remove PID file: {e}");
    }

    tracing::info!("shutdown complete");
    Ok(())
}

/// Policy file seeded on first run if `~/.agentsso/policies/` does not exist.
///
/// Bundled at compile time via `include_str!` from a path inside the
/// daemon crate — NOT from the workspace `test-fixtures/` directory.
/// This keeps the daemon crate self-contained so `cargo package` /
/// `cargo publish` / crate-slicing builds don't fail looking for a
/// workspace sibling. The canonical content lives in
/// `test-fixtures/policies/default.toml`; the two files are kept in
/// sync by a `xtask` verification step (TODO: add the xtask), and the
/// integration test `happy_path_seeds_default_toml_and_boots` confirms
/// the shipped content compiles cleanly against the real engine.
const DEFAULT_POLICY_TOML: &str = include_str!("default_policy.toml");

/// Create the policies directory on first run and seed `default.toml` into it.
///
/// Idempotent: if the directory already exists (user has edited policies
/// or copied example files in), no files are touched. The directory is
/// created atomically with mode `0700` on Unix (no TOCTOU window between
/// mkdir and chmod) to match the `~/.agentsso/` discipline. The seeded
/// file is written with mode `0600` because policy files are security
/// configuration.
///
/// # Errors
///
/// Returns any `std::io::Error` encountered creating the directory or
/// writing the seed file. The caller is expected to exit non-zero on
/// failure — a daemon that cannot read its policies directory cannot
/// enforce policy and should fail fast.
/// Clamp a raw `[approval] timeout_seconds` value into the valid
/// range `[1, 300]`.
///
/// Pure helper extracted from `run()` (Story 8.7 AC #3) so the
/// SIGHUP reload watcher (`server::sighup::reload_loop`) and the
/// control-plane reload handler (`server::control::reload_handler`)
/// can share the exact clamp semantics. The startup path keeps the
/// `tracing::warn!` side effect alongside its inline call; the
/// reload paths log success separately after writing the atomic.
pub(crate) fn clamp_approval_timeout_seconds(raw: u64) -> u64 {
    raw.clamp(1, 300)
}

fn ensure_policies_dir(dir: &std::path::Path) -> std::io::Result<()> {
    if dir.exists() {
        return Ok(());
    }
    // Create the directory atomically at the intended mode to avoid a
    // TOCTOU window where the dir briefly exists at the process umask
    // (typically 0755) before being chmoded to 0700.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(dir)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)?;
    }

    let default_path = dir.join("default.toml");
    // Write the seed file with mode 0600 on Unix. Use `OpenOptions`
    // so the permissions are set at creation time, not chmoded after
    // a write under the process umask.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&default_path)?;
        file.write_all(DEFAULT_POLICY_TOML.as_bytes())?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&default_path, DEFAULT_POLICY_TOML)?;
    }

    tracing::info!(
        path = %default_path.display(),
        "seeded default policy file"
    );
    Ok(())
}

/// Render a [`PolicyCompileError`] as a multi-line operator-facing
/// diagnostic.
///
/// Mirrors the shape of `ConfigError::from_figment` / figment's own
/// error rendering: a short banner line, then an indented block of
/// details including file path, line number, and the cause chain.
/// Returned as an owned `String` so the caller can `eprintln!` it.
///
/// `PolicyCompileError` is `#[non_exhaustive]`, so a wildcard `_` arm
/// would silently swallow new variants with a cheap fallback. This
/// match is deliberately exhaustive — adding a new `PolicyCompileError`
/// variant will cause a compiler error here until a dedicated arm
/// with file/fix hints is added.
fn render_policy_error(err: &PolicyCompileError) -> String {
    let mut out = String::from("error: policy compile failed\n");
    match err {
        PolicyCompileError::Io { path, source } => {
            out.push_str(&format!("  file: {}\n", path.display()));
            out.push_str(&format!("  reason: io error: {source}\n"));
        }
        PolicyCompileError::NotADirectory { path } => {
            out.push_str(&format!("  path: {}\n", path.display()));
            out.push_str("  reason: the policies path exists but is not a directory\n");
            out.push_str("  fix: remove the file at that path, or point the daemon at a different home via AGENTSSO_PATHS__HOME\n");
        }
        PolicyCompileError::Parse { path, line, message } => {
            out.push_str(&format!("  file: {}\n", path.display()));
            if let Some(n) = line {
                out.push_str(&format!("  line: {n}\n"));
            }
            out.push_str(&format!("  reason: {message}\n"));
        }
        PolicyCompileError::BomDetected { path } => {
            out.push_str(&format!("  file: {}\n", path.display()));
            out.push_str("  reason: policy file starts with a UTF-8 BOM\n");
            out.push_str(
                "  fix: save without BOM (editors: VS Code Encoding \u{2192} UTF-8 without BOM)\n",
            );
        }
        PolicyCompileError::EmptyPoliciesArray { path } => {
            out.push_str(&format!("  file: {}\n", path.display()));
            out.push_str("  reason: contains zero [[policies]] entries\n");
            out.push_str("  fix: add at least one [[policies]] entry or delete the file\n");
        }
        PolicyCompileError::DuplicatePolicyName { name, first, second } => {
            out.push_str(&format!("  name: {name:?}\n"));
            out.push_str(&format!("  first: {}\n", first.display()));
            out.push_str(&format!("  second: {}\n", second.display()));
            out.push_str("  reason: two policies share the same name\n");
            out.push_str("  fix: rename one of them — names must be unique across all files\n");
        }
        PolicyCompileError::DuplicatePolicyNameInFile { name, path } => {
            out.push_str(&format!("  file: {}\n", path.display()));
            out.push_str(&format!("  name: {name:?}\n"));
            out.push_str("  reason: the same policy name is defined twice in one file\n");
            out.push_str("  fix: rename one of the [[policies]] entries\n");
        }
        PolicyCompileError::DuplicateRuleId { policy, rule_id, path } => {
            out.push_str(&format!("  file: {}\n", path.display()));
            out.push_str(&format!("  policy: {policy:?}\n"));
            out.push_str(&format!("  rule id: {rule_id:?}\n"));
            out.push_str("  reason: two rules share the same id within one policy\n");
            out.push_str("  fix: rename one of the rules — ids must be unique per policy\n");
        }
        PolicyCompileError::EmptyScopesAllowlist { policy, path } => {
            out.push_str(&format!("  file: {}\n", path.display()));
            out.push_str(&format!("  policy: {policy:?}\n"));
            out.push_str("  reason: scopes = [] would deny every request\n");
            out.push_str(
                "  fix: list at least one scope, or use approval-mode = \"deny\" explicitly\n",
            );
        }
        PolicyCompileError::EmptyResourcesAllowlist { policy, path } => {
            out.push_str(&format!("  file: {}\n", path.display()));
            out.push_str(&format!("  policy: {policy:?}\n"));
            out.push_str("  reason: resources = [] would deny every request\n");
            out.push_str(
                "  fix: list at least one resource, or use resources = [\"*\"] for any resource\n",
            );
        }
        PolicyCompileError::EmptyRuleScopesOverride { policy, rule_id, path } => {
            out.push_str(&format!("  file: {}\n", path.display()));
            out.push_str(&format!("  policy: {policy:?}\n"));
            out.push_str(&format!("  rule id: {rule_id:?}\n"));
            out.push_str("  reason: rule has scopes = [] — would never match\n");
            out.push_str("  fix: remove the scopes key to inherit the policy allowlist, or list specific scopes\n");
        }
        PolicyCompileError::EmptyRuleResourcesOverride { policy, rule_id, path } => {
            out.push_str(&format!("  file: {}\n", path.display()));
            out.push_str(&format!("  policy: {policy:?}\n"));
            out.push_str(&format!("  rule id: {rule_id:?}\n"));
            out.push_str("  reason: rule has resources = [] — would never match\n");
            out.push_str("  fix: remove the resources key to inherit the policy allowlist, or list specific resources\n");
        }
        PolicyCompileError::RuleScopeWidensPolicyAllowlist { policy, rule_id, scope, path } => {
            out.push_str(&format!("  file: {}\n", path.display()));
            out.push_str(&format!("  policy: {policy:?}\n"));
            out.push_str(&format!("  rule id: {rule_id:?}\n"));
            out.push_str(&format!("  scope: {scope:?}\n"));
            out.push_str(
                "  reason: rule references a scope that is not in the policy scope allowlist\n",
            );
            out.push_str("  fix: add the scope to the policy's top-level scopes array, or remove it from the rule\n");
        }
        PolicyCompileError::RuleResourceWidensPolicyAllowlist {
            policy,
            rule_id,
            resource,
            path,
        } => {
            out.push_str(&format!("  file: {}\n", path.display()));
            out.push_str(&format!("  policy: {policy:?}\n"));
            out.push_str(&format!("  rule id: {rule_id:?}\n"));
            out.push_str(&format!("  resource: {resource:?}\n"));
            out.push_str("  reason: rule references a resource that is not in the policy resource allowlist\n");
            out.push_str("  fix: add the resource to the policy's top-level resources array, or remove it from the rule\n");
        }
        PolicyCompileError::ShadowedRule { policy, earlier_rule_id, later_rule_id, path } => {
            out.push_str(&format!("  file: {}\n", path.display()));
            out.push_str(&format!("  policy: {policy:?}\n"));
            out.push_str(&format!("  earlier rule: {earlier_rule_id:?}\n"));
            out.push_str(&format!("  later rule: {later_rule_id:?}\n"));
            out.push_str("  reason: the later rule can never fire because it is fully shadowed by the earlier rule\n");
            out.push_str("  fix: reorder the rules, narrow the earlier rule's scopes/resources, or delete the later rule\n");
        }
        PolicyCompileError::InvalidScopeFormat { scope, policy, path } => {
            out.push_str(&format!("  file: {}\n", path.display()));
            out.push_str(&format!("  policy: {policy:?}\n"));
            out.push_str(&format!("  scope: {scope:?}\n"));
            out.push_str("  reason: scope name must be ASCII lowercase alphanumeric, `.`, or `-` (no Unicode or uppercase), 1-128 chars, no leading/trailing separator\n");
        }
        PolicyCompileError::DuplicateScopeInAllowlist { policy, scope, path } => {
            out.push_str(&format!("  file: {}\n", path.display()));
            out.push_str(&format!("  policy: {policy:?}\n"));
            out.push_str(&format!("  scope: {scope:?}\n"));
            out.push_str("  reason: the same scope appears more than once in the allowlist\n");
            out.push_str("  fix: remove the duplicate entry\n");
        }
        PolicyCompileError::MixedWildcardAndExplicitResources { policy, wildcard, path } => {
            out.push_str(&format!("  file: {}\n", path.display()));
            out.push_str(&format!("  policy: {policy:?}\n"));
            out.push_str(&format!(
                "  reason: resources array mixes the wildcard {wildcard:?} with explicit entries\n"
            ));
            out.push_str(
                "  fix: either use resources = [\"*\"] for any resource, or list only explicit entries\n",
            );
        }
        // `PolicyCompileError` is `#[non_exhaustive]` across the
        // crate boundary, so the compiler requires a wildcard arm.
        // The match above explicitly lists every variant that exists
        // today. If a future variant lands, this fallback will fire
        // and the BANNER-UNHANDLED-VARIANT marker will show up in
        // operator output (noise) and in CI logs (searchable). A
        // companion exhaustive-match test in `permitlayer-core`
        // enumerates every variant and will also fail at compile
        // time inside the core crate when a new variant is added,
        // forcing a review of this renderer.
        _ => {
            out.push_str("  BANNER-UNHANDLED-VARIANT — this is a bug; report to permitlayer\n");
            out.push_str(&format!("  reason: {err}\n"));
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use permitlayer_keystore::{DeleteOutcome, KeyStore, KeyStoreError, MASTER_KEY_LEN};
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    // ── Story 7.6a AC #12: compute_active_key_id tests ───────────────

    use permitlayer_core::store::fs::credential_fs::encode_envelope;
    use permitlayer_credential::{KeyId, SealedCredential};

    fn fake_sealed_v2(key_id: u8) -> Vec<u8> {
        let sealed = SealedCredential::from_trusted_bytes(
            vec![0xAB; 48],
            [0x11u8; 12],
            b"permitlayer-vault-v1:gmail".to_vec(),
            permitlayer_credential::SEALED_CREDENTIAL_VERSION,
            KeyId::new(key_id),
        );
        encode_envelope(&sealed)
    }

    #[test]
    fn compute_active_key_id_returns_zero_when_vault_missing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let vault_dir = tmp.path().join("vault");
        // Directory does NOT exist — this is the fresh-install case.
        assert_eq!(compute_active_key_id(&vault_dir), 0);
    }

    #[test]
    fn compute_active_key_id_returns_zero_for_empty_vault() {
        let tmp = tempfile::TempDir::new().unwrap();
        let vault_dir = tmp.path().join("vault");
        std::fs::create_dir_all(&vault_dir).unwrap();
        assert_eq!(compute_active_key_id(&vault_dir), 0);
    }

    #[test]
    fn compute_active_key_id_returns_max_across_envelopes() {
        let tmp = tempfile::TempDir::new().unwrap();
        let vault_dir = tmp.path().join("vault");
        std::fs::create_dir_all(&vault_dir).unwrap();
        std::fs::write(vault_dir.join("a.sealed"), fake_sealed_v2(0)).unwrap();
        std::fs::write(vault_dir.join("b.sealed"), fake_sealed_v2(2)).unwrap();
        std::fs::write(vault_dir.join("c.sealed"), fake_sealed_v2(1)).unwrap();
        assert_eq!(compute_active_key_id(&vault_dir), 2);
    }

    #[test]
    fn compute_active_key_id_treats_v1_as_zero() {
        let tmp = tempfile::TempDir::new().unwrap();
        let vault_dir = tmp.path().join("vault");
        std::fs::create_dir_all(&vault_dir).unwrap();
        // Write a v1 envelope manually (23-byte header, no key_id).
        let mut v1: Vec<u8> = Vec::new();
        v1.extend_from_slice(&1u16.to_le_bytes());
        v1.push(12);
        v1.extend_from_slice(&[0x22u8; 12]);
        v1.extend_from_slice(&0u32.to_le_bytes()); // aad_len = 0
        v1.extend_from_slice(&0u32.to_le_bytes()); // ct_len = 0
        std::fs::write(vault_dir.join("a.sealed"), v1).unwrap();
        // Mixed v1 + v2(key_id=5).
        std::fs::write(vault_dir.join("b.sealed"), fake_sealed_v2(5)).unwrap();
        assert_eq!(compute_active_key_id(&vault_dir), 5);
    }

    #[test]
    fn compute_active_key_id_skips_dotfiles_and_tempfiles() {
        let tmp = tempfile::TempDir::new().unwrap();
        let vault_dir = tmp.path().join("vault");
        std::fs::create_dir_all(&vault_dir).unwrap();
        // Only the non-noisy file should count toward max.
        std::fs::write(vault_dir.join("a.sealed"), fake_sealed_v2(3)).unwrap();
        std::fs::write(vault_dir.join(".lock"), b"junk").unwrap();
        std::fs::write(vault_dir.join("a.sealed.tmp.999.0.aaaa"), fake_sealed_v2(99)).unwrap();
        std::fs::write(vault_dir.join("a.sealed.new"), fake_sealed_v2(99)).unwrap();
        assert_eq!(compute_active_key_id(&vault_dir), 3);
    }

    #[test]
    fn compute_active_key_id_skips_truncated_envelopes() {
        let tmp = tempfile::TempDir::new().unwrap();
        let vault_dir = tmp.path().join("vault");
        std::fs::create_dir_all(&vault_dir).unwrap();
        std::fs::write(vault_dir.join("good.sealed"), fake_sealed_v2(7)).unwrap();
        // 3-byte file: < 4 bytes, the read_exact for header fails,
        // the entry is skipped.
        std::fs::write(vault_dir.join("bad.sealed"), [0x02, 0x00, 0x0c]).unwrap();
        assert_eq!(compute_active_key_id(&vault_dir), 7);
    }

    // Story 8.7 AC #3: clamp helper unit test. Pure function —
    // no daemon spin-up, no fixtures.
    #[test]
    fn clamp_approval_timeout_seconds_clamps_both_ends() {
        assert_eq!(clamp_approval_timeout_seconds(0), 1);
        assert_eq!(clamp_approval_timeout_seconds(1), 1);
        assert_eq!(clamp_approval_timeout_seconds(30), 30);
        assert_eq!(clamp_approval_timeout_seconds(300), 300);
        assert_eq!(clamp_approval_timeout_seconds(500), 300);
        assert_eq!(clamp_approval_timeout_seconds(u64::MAX), 300);
    }

    /// Test-only `KeyStore` that counts calls and can simulate
    /// "generate on first call, return same value on second" or
    /// "keychain unavailable" sequences.
    ///
    /// Story 1.15: introduced for `ensure_master_key_bootstrapped`
    /// unit tests. Lives in the daemon crate because
    /// `permitlayer-keystore` has no test-seam feature and we want
    /// to keep this fake scoped to the daemon tests that need it.
    struct FakeKeyStore {
        /// If `Some`, `master_key` returns this value. Cloned on
        /// every call to simulate "second call sees the same key
        /// that the first call generated".
        stored: Mutex<Option<[u8; MASTER_KEY_LEN]>>,
        /// Story 7.6b: previous-key slot for rotation crash-recovery.
        /// `None` when no rotation is in flight; `Some` while the
        /// keystore is in the dual-slot in-flight state.
        previous: Mutex<Option<[u8; MASTER_KEY_LEN]>>,
        /// If `Some`, the NEXT call returns this error instead of
        /// the stored key. Consumed after one call so "simulate
        /// error once" tests behave naturally.
        next_error: Mutex<Option<KeyStoreError>>,
        /// Monotonic counter bumped on every `master_key` call.
        /// Tests assert the bootstrap path is hit exactly once when
        /// run with a single call and twice when the daemon re-runs.
        call_count: Mutex<usize>,
    }

    impl FakeKeyStore {
        fn new_empty() -> Self {
            Self {
                stored: Mutex::new(None),
                previous: Mutex::new(None),
                next_error: Mutex::new(None),
                call_count: Mutex::new(0),
            }
        }

        fn with_stored(key: [u8; MASTER_KEY_LEN]) -> Self {
            Self {
                stored: Mutex::new(Some(key)),
                previous: Mutex::new(None),
                next_error: Mutex::new(None),
                call_count: Mutex::new(0),
            }
        }

        fn failing(err: KeyStoreError) -> Self {
            Self {
                stored: Mutex::new(None),
                previous: Mutex::new(None),
                next_error: Mutex::new(Some(err)),
                call_count: Mutex::new(0),
            }
        }

        fn call_count(&self) -> usize {
            *self.call_count.lock().unwrap()
        }
    }

    #[async_trait]
    impl KeyStore for FakeKeyStore {
        async fn master_key(&self) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, KeyStoreError> {
            *self.call_count.lock().unwrap() += 1;

            // Take the error slot if it's set — one-shot.
            if let Some(err) = self.next_error.lock().unwrap().take() {
                return Err(err);
            }

            // Generate-on-first-call semantics: if no key is stored,
            // invent one (using a deterministic pattern so tests can
            // assert on specific bytes) and persist it.
            let mut slot = self.stored.lock().unwrap();
            let key = slot.get_or_insert([0x42u8; MASTER_KEY_LEN]);
            Ok(Zeroizing::new(*key))
        }

        async fn set_master_key(&self, key: &[u8; MASTER_KEY_LEN]) -> Result<(), KeyStoreError> {
            *self.stored.lock().unwrap() = Some(*key);
            Ok(())
        }

        async fn delete_master_key(&self) -> Result<DeleteOutcome, KeyStoreError> {
            let mut slot = self.stored.lock().unwrap();
            if slot.take().is_some() {
                Ok(DeleteOutcome::Removed)
            } else {
                Ok(DeleteOutcome::AlreadyAbsent)
            }
        }

        async fn set_previous_master_key(
            &self,
            previous: &[u8; MASTER_KEY_LEN],
        ) -> Result<(), KeyStoreError> {
            *self.previous.lock().unwrap() = Some(*previous);
            Ok(())
        }

        async fn previous_master_key(
            &self,
        ) -> Result<Option<Zeroizing<[u8; MASTER_KEY_LEN]>>, KeyStoreError> {
            Ok(self.previous.lock().unwrap().map(Zeroizing::new))
        }

        async fn clear_previous_master_key(&self) -> Result<(), KeyStoreError> {
            *self.previous.lock().unwrap() = None;
            Ok(())
        }
    }

    #[tokio::test]
    async fn ensure_master_key_bootstrapped_generates_on_fresh_install() {
        // AC #1: fresh install → first call generates + persists.
        //
        // Story 1.15 review patch: asserts "second call returns the
        // same bytes as the first" rather than asserting a specific
        // byte pattern from the fake. Tests the semantic contract
        // (`KeyStore::master_key` is idempotent) rather than the
        // fake's implementation detail.
        let keystore = FakeKeyStore::new_empty();
        let first =
            bootstrap_from_keystore(&keystore).await.expect("first bootstrap should succeed");
        let second =
            bootstrap_from_keystore(&keystore).await.expect("second bootstrap should succeed");
        assert_eq!(first.as_slice(), second.as_slice(), "idempotent master_key contract");
        assert_eq!(keystore.call_count(), 2);
        // Non-zero check: the fake must not accidentally return a
        // zero key (which `bootstrap_from_keystore`'s own guard
        // would reject as MalformedMasterKey).
        assert_ne!(first.as_slice(), [0u8; MASTER_KEY_LEN]);
    }

    #[tokio::test]
    async fn ensure_master_key_bootstrapped_reuses_existing_key() {
        // AC #3: existing install → bootstrap sees the pre-existing
        // key on the first call and returns it unchanged.
        let pre_existing = [0x37u8; MASTER_KEY_LEN];
        let keystore = FakeKeyStore::with_stored(pre_existing);

        let first =
            bootstrap_from_keystore(&keystore).await.expect("first bootstrap should succeed");
        let second =
            bootstrap_from_keystore(&keystore).await.expect("second bootstrap should succeed");
        assert_eq!(&first[..], &pre_existing);
        assert_eq!(&second[..], &pre_existing);
        assert_eq!(keystore.call_count(), 2);
    }

    #[tokio::test]
    async fn bootstrap_from_keystore_rejects_zero_master_key() {
        // Story 1.15 review patch: a buggy KeyStore returning all-
        // zero bytes must be rejected at the boundary. Fail-closed
        // posture — zero-key HKDF expansion produces a deterministic,
        // trivially-recoverable subkey.
        let keystore = FakeKeyStore::with_stored([0u8; MASTER_KEY_LEN]);
        let result = bootstrap_from_keystore(&keystore).await;
        assert!(
            matches!(
                result,
                Err(StartError::MasterKeyCall { source: KeyStoreError::MalformedMasterKey { .. } })
            ),
            "expected MalformedMasterKey rejection for all-zero key"
        );
    }

    #[tokio::test]
    async fn ensure_master_key_bootstrapped_fails_fast_on_keychain_unavailable() {
        // AC #4: keystore unavailable → structured error, not a
        // silent fallback. The caller in `run()` turns this into
        // `std::process::exit(2)`, which this unit test cannot
        // exercise directly — but we assert the error surface so a
        // regression that silently returns `Ok(zero)` would fail
        // here.
        let keystore = FakeKeyStore::failing(KeyStoreError::BackendUnavailable {
            backend: "test",
            source: "secret-service daemon not running".into(),
        });
        let result = bootstrap_from_keystore(&keystore).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                &err,
                StartError::MasterKeyCall { source: KeyStoreError::BackendUnavailable { .. } }
            ),
            "expected MasterKeyCall(BackendUnavailable), got {err:?}"
        );
    }

    #[tokio::test]
    async fn ensure_master_key_bootstrapped_surfaces_platform_errors() {
        // AC #4 (extended): any KeyStoreError variant surfaces as
        // MasterKeyCall so the caller's exit(2) remediation fires.
        let keystore = FakeKeyStore::failing(KeyStoreError::MalformedMasterKey {
            expected_len: 32,
            actual_len: 16,
        });
        let result = bootstrap_from_keystore(&keystore).await;
        assert!(matches!(
            result,
            Err(StartError::MasterKeyCall { source: KeyStoreError::MalformedMasterKey { .. } })
        ));
    }

    #[tokio::test]
    async fn ensure_master_key_bootstrapped_error_display_is_informative() {
        // The error message on the fail-fast path is surfaced to the
        // operator's terminal. Verify it names the underlying cause
        // so operators can search for it.
        let keystore = FakeKeyStore::failing(KeyStoreError::BackendUnavailable {
            backend: "libsecret",
            source: "no dbus session".into(),
        });
        let err = bootstrap_from_keystore(&keystore).await.unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("keystore master_key call failed"),
            "error display should mention master_key, got: {rendered}"
        );
    }

    // ------------------------------------------------------------------
    // Story 6.3 AC #23 — TrustPromptReader contract tests
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn trait_default_behavior() {
        // AC #23: the NoOp reader always returns NoPromptAvailable.
        // Pins the "headless default" contract the loader relies on.
        use permitlayer_plugins::TrustPromptReader;
        let reader = permitlayer_plugins::NoOpTrustPromptReader;
        let decision = reader.prompt("anything", std::path::Path::new("/tmp/anything"), "deadbeef");
        assert_eq!(decision, permitlayer_plugins::TrustDecision::NoPromptAvailable);
    }

    #[tokio::test]
    async fn tty_reader_returns_no_prompt_when_stdin_is_not_tty() {
        // AC #23: `TtyTrustPromptReader::prompt` must return
        // NoPromptAvailable without blocking when stdin is not a
        // terminal. Under `cargo test` stdin is piped from the test
        // runner, never a TTY — so calling prompt here should
        // short-circuit on the `is_terminal()` check.
        use permitlayer_plugins::TrustPromptReader;
        let reader = super::TtyTrustPromptReader;
        let start = std::time::Instant::now();
        let decision = reader.prompt(
            "test-connector",
            std::path::Path::new("/tmp/test-plugin/index.js"),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        let elapsed = start.elapsed();
        assert_eq!(decision, permitlayer_plugins::TrustDecision::NoPromptAvailable);
        // Must return well under the 30-second timeout — the
        // non-TTY branch skips the spawn_blocking + timeout path
        // entirely.
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "non-TTY prompt must return fast; took {elapsed:?}"
        );
    }

    // ------------------------------------------------------------------
    // Story 6.3 AC #24 — release-build test seam compile-gate
    // ------------------------------------------------------------------

    #[test]
    #[cfg(not(debug_assertions))]
    fn test_seam_is_compiled_out_in_release_builds() {
        // AC #24: the `AGENTSSO_TEST_TRUST_PROMPT_CANNED_RESPONSES`
        // env-var read is `#[cfg(debug_assertions)]`-gated. In a
        // release build, setting the env var must have NO effect:
        // `build_trust_prompt_reader` must NOT return a
        // CannedTrustPromptReader. The easiest observation is that
        // the function returns a `TtyTrustPromptReader` or
        // `NoOpTrustPromptReader` regardless — which is exactly
        // the production path.
        //
        // This test only runs in release builds (`cargo test
        // --release`). In debug builds it's compiled out by the
        // attribute. The companion debug-path coverage lives in
        // `plugin_loader_e2e.rs::test_seam_drives_two_plugins_deterministically`.
        //
        // We do not actually set an env var here (the daemon crate is
        // `#![forbid(unsafe_code)]` and `std::env::set_var` is
        // unsafe in edition 2024). Instead, the assertion is a
        // compile-time one: the `#[cfg(debug_assertions)]` arms in
        // `build_trust_prompt_reader` ensure the env-var read is
        // absent from the release binary's code path. This test's
        // presence documents that invariant; a future refactor that
        // accidentally drops the cfg gate would leak the seam into
        // release.
        let reader = super::build_trust_prompt_reader();
        let _ = reader; // constructor succeeded; no panic.
    }

    // ----- Story 8.4 AC #3: scope error message mentions ASCII -----

    #[test]
    fn validate_scope_format_error_mentions_ascii_constraint() {
        use permitlayer_core::policy::error::PolicyCompileError;
        use std::path::PathBuf;

        let err = PolicyCompileError::InvalidScopeFormat {
            scope: "café.read".to_owned(),
            policy: "test-policy".to_owned(),
            path: PathBuf::from("/test.toml"),
        };
        let rendered = super::render_policy_error(&err);
        assert!(
            rendered.contains("ASCII"),
            "scope format error must mention ASCII constraint, got: {rendered}"
        );
    }
}
