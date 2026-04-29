use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use tokio::sync::watch;

use permitlayer_core::agent::AgentRegistry;
use permitlayer_core::audit::event::AuditEvent;
use permitlayer_core::policy::{PolicyCompileError, PolicySet, PolicySetDiff};

#[cfg(unix)]
use crate::cli::start::clamp_approval_timeout_seconds;
use crate::config::{CliOverrides, DaemonConfig};

/// Spawn a background task that listens for SIGHUP, re-reads configuration
/// AND policy files from disk, and atomically swaps both live state holders.
///
/// Returns a `watch::Receiver<()>` that fires each time a successful reload
/// occurs (config OR policy — but NOT on failure). On reload failure the
/// previous state is preserved (fail-safe) and the watch channel does NOT
/// fire.
///
/// Story 4.2 extended this from config-only to config+policy reload.
/// Story 4.4 AC #10 extended it again so SIGHUP also re-reads
/// `~/.agentsso/agents/*.toml` and atomically swaps the in-memory
/// `AgentRegistry` snapshot. The agent reload is independent of the
/// policy reload: a failure in one does not break the other.
#[allow(clippy::too_many_arguments)]
pub fn spawn_reload_watcher(
    config_state: Arc<ArcSwap<DaemonConfig>>,
    cli_overrides: Arc<CliOverrides>,
    policy_set: Arc<ArcSwap<PolicySet>>,
    policies_dir: PathBuf,
    reload_mutex: Arc<Mutex<()>>,
    audit_store: Option<Arc<dyn permitlayer_core::store::AuditStore>>,
    agent_registry: Arc<AgentRegistry>,
    agent_store: Option<Arc<dyn permitlayer_core::store::AgentIdentityStore>>,
    approval_service: Arc<dyn permitlayer_proxy::middleware::ApprovalService>,
    // Story 8.7 AC #3: shared atomic written on every successful
    // config reload (SIGHUP + `POST /v1/control/reload`).
    approval_timeout_atomic: Arc<AtomicU64>,
    // Story 8.7 AC #4: boot-time 501-stub flag. `true` when the
    // daemon booted without a vault (proxy routes serve 501 stubs);
    // drives the stub-detection warn + audit event on reload.
    proxy_stub_branch_active: Arc<AtomicBool>,
    // Story 8.7 AC #4: vault directory path used by the stub
    // detector to check whether `agentsso setup` has since created
    // the directory.
    vault_dir: PathBuf,
) -> watch::Receiver<()> {
    let (tx, rx) = watch::channel(());
    tokio::spawn(async move {
        reload_loop(
            config_state,
            cli_overrides,
            policy_set,
            policies_dir,
            reload_mutex,
            audit_store,
            agent_registry,
            agent_store,
            approval_service,
            approval_timeout_atomic,
            proxy_stub_branch_active,
            vault_dir,
            tx,
        )
        .await;
    });
    rx
}

#[allow(clippy::expect_used)] // Signal handler registration is infallible in practice.
#[allow(clippy::too_many_arguments)]
async fn reload_loop(
    config_state: Arc<ArcSwap<DaemonConfig>>,
    cli_overrides: Arc<CliOverrides>,
    policy_set: Arc<ArcSwap<PolicySet>>,
    policies_dir: PathBuf,
    reload_mutex: Arc<Mutex<()>>,
    audit_store: Option<Arc<dyn permitlayer_core::store::AuditStore>>,
    agent_registry: Arc<AgentRegistry>,
    agent_store: Option<Arc<dyn permitlayer_core::store::AgentIdentityStore>>,
    approval_service: Arc<dyn permitlayer_proxy::middleware::ApprovalService>,
    approval_timeout_atomic: Arc<AtomicU64>,
    proxy_stub_branch_active: Arc<AtomicBool>,
    vault_dir: PathBuf,
    tx: watch::Sender<()>,
) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sighup =
            signal(SignalKind::hangup()).expect("static invariant: SIGHUP handler registration");
        loop {
            sighup.recv().await;
            let mut any_success = false;

            // 1. Reload configuration.
            //
            // Story 8.7 review patch (MEDIUM): the config-load +
            // approval-timeout atomic store + `config_state` swap run
            // under `reload_mutex` so that a concurrent HTTP reload
            // (`reload_handler` in server/control.rs) can't interleave
            // and leave the atomic paired with a mismatched
            // `config_state` snapshot. `reload_mutex` is held only
            // across synchronous work — no `.await` in the critical
            // section — matching the same discipline at
            // `reload_policies_with_diff_locked`.
            {
                let _guard = reload_mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                match DaemonConfig::load(&cli_overrides) {
                    Ok(new_config) => {
                        let raw = new_config.approval.timeout_seconds;
                        let clamped = clamp_approval_timeout_seconds(raw);
                        if raw != clamped {
                            tracing::warn!(
                                configured = raw,
                                clamped = clamped,
                                "approval.timeout_seconds out of range [1,300]; clamping"
                            );
                        }
                        approval_timeout_atomic.store(clamped, Ordering::Relaxed);
                        tracing::info!(
                            new_timeout_seconds = clamped,
                            "approval timeout updated via reload"
                        );

                        config_state.store(Arc::new(new_config));
                        tracing::info!("configuration reloaded");
                        any_success = true;
                    }
                    Err(e) => {
                        tracing::error!("config reload failed, keeping previous config: {e}");
                    }
                }
            }

            // 2. Reload policies (wrapped in spawn_blocking to avoid
            // blocking the async runtime with filesystem IO).
            //
            // Story 4.5: clear the approval-service always/never caches
            // BEFORE the ArcSwap policy swap, not after. Two reasons:
            //
            //   1. **Race window.** Clearing after the swap leaves a
            //      microsecond window where requests see the new policy
            //      + the old cache. A renamed rule could serve a stale
            //      "always allow" decision against the new policy.
            //   2. **Failed-reload semantics.** Operators who edit a
            //      policy to evict a stale `always`/`never` decision
            //      expect `agentsso reload` to clear the cache, even
            //      if their TOML edit has a syntax error. Clearing
            //      first makes the cache eviction reload-result-
            //      independent, matching operator expectation.
            //
            // The cost: a successful reload also clears the cache for
            // unchanged rules, which means operators see one re-prompt
            // for previously-cached decisions on the next request. That
            // is already the documented contract in default_policy.toml.
            approval_service.clear_caches();
            tracing::info!("approval service caches cleared on reload (pre-swap)");

            let ps = Arc::clone(&policy_set);
            let dir = policies_dir.clone();
            let mtx = Arc::clone(&reload_mutex);
            let audit = audit_store.clone();
            match tokio::task::spawn_blocking(move || {
                reload_policies_with_diff_locked(&ps, &dir, &mtx)
            })
            .await
            {
                Ok(Ok(diff)) => {
                    tracing::info!(
                        policies_loaded = diff.policies_loaded,
                        added = diff.added.len(),
                        modified = diff.modified.len(),
                        unchanged = diff.unchanged.len(),
                        removed = diff.removed.len(),
                        "policies reloaded"
                    );
                    // Best-effort audit event (same as control-plane path).
                    write_reload_audit_event(audit.as_ref(), &diff).await;
                    any_success = true;
                }
                Ok(Err(e)) => {
                    tracing::error!("policy reload failed, keeping previous policies: {e}");
                }
                Err(e) => {
                    tracing::error!("policy reload task panicked: {e}");
                }
            }

            // 3. Reload agents from the filesystem store (Story 4.4 AC #10).
            // Independent of the policy reload: a failure here keeps the
            // previous in-memory snapshot and does NOT invalidate the
            // policy swap above.
            if let Some(store) = &agent_store {
                let store = Arc::clone(store);
                match store.list().await {
                    Ok(agents) => {
                        let count = agent_registry.replace_with(agents);
                        tracing::info!(agents_loaded = count, "agents reloaded");
                        any_success = true;
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "agent reload failed, keeping previous snapshot"
                        );
                    }
                }
            }

            // 4. Story 5.4: sweep rotated operational log files so
            // operators editing `[log] retention_days` via TOML see the
            // new value take effect without a full restart. The sweep
            // runs AFTER the config reload so it uses the post-reload
            // retention value. Non-fatal: a sweep failure never blocks
            // the reload.
            let cfg = config_state.load_full();
            let log_cfg = cfg.log.clone().validated();
            let log_dir = log_cfg.path.clone().unwrap_or_else(|| cfg.paths.home.join("logs"));
            match crate::telemetry::sweep_rotated_logs(&log_dir, log_cfg.retention_days) {
                Ok(n) if n > 0 => tracing::info!(
                    removed = n,
                    retention_days = log_cfg.retention_days,
                    "reload: swept rotated log files"
                ),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "reload: log retention sweep failed"),
            }

            // 5. Story 8.7 AC #4: detect the boot-time 501-stub branch
            // still being active but `{paths.home}/vault/` now exists,
            // and emit a structured operator-facing warning + audit
            // event telling the operator to restart the daemon.
            // Fires at most once per daemon lifetime via CAS on the
            // flag (decision 2:B). SIGHUP has no request context, so
            // `request_id` is `None` — `detect_stub_and_warn` falls
            // back to a synthesized ULID.
            detect_stub_and_warn(&vault_dir, audit_store.as_ref(), &proxy_stub_branch_active, None)
                .await;

            // Only notify downstream watchers if at least one reload succeeded.
            if any_success {
                let _ = tx.send(());
            }
        }
    }
    #[cfg(not(unix))]
    {
        // SIGHUP not available on non-Unix. Reload via `agentsso reload` only.
        let _ = (
            config_state,
            cli_overrides,
            policy_set,
            policies_dir,
            reload_mutex,
            audit_store,
            agent_registry,
            agent_store,
            approval_service,
            approval_timeout_atomic,
            proxy_stub_branch_active,
            vault_dir,
            tx,
        );
        std::future::pending::<()>().await;
    }
}

/// Emit a structured operator-facing warning and best-effort audit
/// event when the daemon booted with `proxy_service: None` (so the
/// axum router is wired to 501 stubs) but `{paths.home}/vault/` now
/// exists — meaning the operator has since run `agentsso setup <svc>`
/// and is wondering why `agentsso reload` isn't activating the proxy
/// routes. The honest answer is "the router was chosen at boot and
/// can't be hot-swapped; restart the daemon."
///
/// # Dedup (Story 8.7 review decision 2:B)
///
/// Fires **at most once per daemon lifetime**. After the first
/// successful fire, `stub_active` is CAS'd from `true → false` so
/// every subsequent reload short-circuits at the guard. Rationale:
/// the stub-detection event is forensically interesting on first
/// observation; repeating it on every unrelated reload (policy edits,
/// approval-timeout edits, log-rotation) would spam audit logs and
/// dilute signal.
///
/// # Unconditional call-site (Story 8.7 review decision 1:A)
///
/// Both `reload_handler` (HTTP) and the SIGHUP `reload_loop` invoke
/// this helper UNCONDITIONALLY at the tail of their reload flows —
/// not gated on policy-reload success. Keeps the two surfaces
/// behaviorally equivalent per Task 3.5.
///
/// # Parameters
///
/// - `vault_dir` — typically `{config.paths.home}/vault`.
/// - `audit_store` — `None` skips the audit write; the `warn!` still fires.
/// - `stub_active` — shared `Arc<AtomicBool>` flipped to `true` at boot
///   iff the daemon took the 501-stub router branch. Flipped back to
///   `false` by this helper after a successful fire (one-shot dedup).
/// - `request_id` — `Some(id)` when called from `reload_handler`
///   (axum extension), `None` from the SIGHUP loop (no request
///   context). `None` falls back to a synthesized ULID so every audit
///   event still has a non-empty `request_id`.
///
/// Returns `true` if the warning fired; `false` otherwise. IO errors
/// from `try_exists` are swallowed (stub-detection must never break
/// the reload flow) but emit a `tracing::debug!` breadcrumb for
/// fuse / CIFS / permission-denied forensics.
pub(crate) async fn detect_stub_and_warn(
    vault_dir: &std::path::Path,
    audit_store: Option<&Arc<dyn permitlayer_core::store::AuditStore>>,
    stub_active: &Arc<AtomicBool>,
    request_id: Option<String>,
) -> bool {
    if !stub_active.load(Ordering::Relaxed) {
        return false;
    }
    match vault_dir.try_exists() {
        Ok(true) => {}
        Ok(false) => return false,
        Err(e) => {
            tracing::debug!(
                vault_dir = %vault_dir.display(),
                error = %e,
                "stub-detection: try_exists errored; skipping warning (likely fuse/CIFS/permission-denied)"
            );
            return false;
        }
    }
    // CAS-dedup: flip the flag `true → false`. If we lose the race,
    // another caller already fired the diagnostic — short-circuit.
    if stub_active.compare_exchange(true, false, Ordering::Relaxed, Ordering::Relaxed).is_err() {
        return false;
    }
    tracing::warn!(
        vault_dir = %vault_dir.display(),
        "proxy routes are serving 501 stubs because no vault existed at boot; \
         restart the daemon (agentsso stop && agentsso start) to activate the \
         proxy now that vault/ is present"
    );
    if let Some(store) = audit_store {
        let event_request_id = request_id.unwrap_or_else(|| ulid::Ulid::new().to_string());
        let mut event = AuditEvent::with_request_id(
            event_request_id,
            "control".to_owned(),
            "control".to_owned(),
            "control".to_owned(), // scope: the control-plane subsystem
            "daemon".to_owned(),
            "ok".to_owned(),
            "config-reload-stub-detected".to_owned(),
        );
        event.extra = serde_json::json!({
            "action": "reload",
            "vault_present": true,
            "proxy_service_active": false,
            "remediation": "restart daemon",
        });
        if let Err(e) = store.append(event).await {
            tracing::warn!("failed to write config-reload-stub-detected audit event: {e}");
        }
    }
    true
}

/// Compile policies, swap on success, and return the diff.
///
/// Guarded by `reload_mutex` to prevent two concurrent callers
/// (SIGHUP + HTTP, or two HTTP POSTs) from observing a stale
/// snapshot via `policy_set.load()` when both try to diff-then-store
/// simultaneously. Uses `std::sync::Mutex` (not `tokio::sync::Mutex`)
/// because the critical section is microseconds of CPU work with no
/// `.await` points and no risk of holding across a yield.
pub(crate) fn reload_policies_with_diff_locked(
    policy_set: &ArcSwap<PolicySet>,
    dir: &std::path::Path,
    reload_mutex: &Mutex<()>,
) -> Result<PolicySetDiff, PolicyCompileError> {
    let _guard = reload_mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let new_set = PolicySet::compile_from_dir(dir)?;
    let diff = new_set.diff(&policy_set.load());
    policy_set.store(Arc::new(new_set));
    Ok(diff)
}

/// Write a `policy-reloaded` audit event. Best-effort — failure logs
/// a warn but does not propagate.
pub(crate) async fn write_reload_audit_event(
    audit_store: Option<&Arc<dyn permitlayer_core::store::AuditStore>>,
    diff: &PolicySetDiff,
) {
    let Some(store) = audit_store else {
        return;
    };
    let request_id = ulid::Ulid::new().to_string();
    let mut event = AuditEvent::with_request_id(
        request_id,
        "control".to_owned(),
        "control".to_owned(),
        "reload".to_owned(),
        "control".to_owned(),
        "ok".to_owned(),
        "policy-reloaded".to_owned(),
    );
    event.extra = serde_json::json!({
        "policies_loaded": diff.policies_loaded,
        "added": &diff.added,
        "modified": &diff.modified,
        "unchanged": &diff.unchanged,
        "removed": &diff.removed,
    });
    if let Err(e) = store.append(event).await {
        tracing::warn!("failed to write policy-reloaded audit event: {e}");
    }
}
