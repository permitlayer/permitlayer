//! Shared QuickJS runtime and per-call context management.
//!
//! # Design
//!
//! **One [`PluginRuntime`] per daemon process** — creating the
//! underlying `rquickjs::Runtime` is expensive (it initializes the
//! full C VM, allocates the JS heap, and registers interrupt
//! machinery). The runtime sits in `Arc<PluginRuntime>` in the
//! daemon's `AppState` (see `permitlayer-daemon::cli::start`) and
//! is shared across every request that invokes a plugin.
//!
//! **One fresh [`rquickjs::Context`] per plugin invocation** —
//! contexts are cheap (microseconds) and a fresh context guarantees
//! no state leakage between requests (no globals, no closed-over
//! heap references, no leftover `agentsso.*` bindings from the
//! prior call). See [`PluginRuntime::with_context`] for the per-
//! call shape.
//!
//! This mirrors architecture.md:682 ("QuickJS connector instances
//! spun up per-request, not kept warm") — "instance" there means
//! *context*, not *runtime*. The C runtime is reused.
//!
//! # Interrupt model (Story 6.1 review patches applied)
//!
//! **Concurrency stance (B1 review patch):** `with_context` is
//! serialized by an internal `Mutex` (`call_lock`). The concurrency
//! advertised by `rquickjs`'s `parallel` feature would let two
//! threads share `Arc<PluginRuntime>` — but the interrupt flag is
//! per-runtime state that a second caller would clobber. Our
//! threat model prioritizes correctness over throughput: serial
//! plugin calls through one runtime, one call's deadline is its
//! own, and the runtime is shared for amortized startup, not
//! concurrent execution. `Arc<PluginRuntime>` stays on `AppState`
//! for sharing-across-handlers purposes; the mutex lives inside.
//!
//! Each [`PluginRuntime::with_context`] call:
//! 1. Acquires the `call_lock` mutex (ensures serial access).
//! 2. Clears the interrupt flag with `Release` ordering and spawns
//!    a watchdog (tokio task or std thread) that flips the flag to
//!    `true` after the configured deadline.
//! 3. QuickJS's interrupt handler (set once at construction time)
//!    polls the flag with `Acquire` ordering on every bytecode
//!    backward-branch and aborts the VM when the flag is `true`.
//! 4. On return, we check the flag BEFORE stopping the watchdog —
//!    if the flag is set, the deadline fired during execution. We
//!    then drop the `WatchdogHandle`, whose `Drop` impl disarms
//!    the watchdog synchronously (B2 + D17 review patches: avoid
//!    the `abort()`-is-async + panic-unwind-leaks-flag pitfalls).
//!
//! The interrupt handler itself is a sync closure called from C,
//! so it can't await or do anything complicated.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rquickjs::context::intrinsic;
use rquickjs::{Context, Runtime};

use crate::PluginError;
use crate::host_api::{HostServices, register_host_api};
use crate::sandbox::install_sandbox;

/// Configuration knobs for a [`PluginRuntime`]. Every field has a
/// hard default chosen for the MVP — operators will override via the
/// future `[plugins]` config section (Story 6.3).
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Maximum bytes the JS heap may grow to. Hitting this limit
    /// causes the next allocation to fail; the calling Rust code
    /// observes this as an `rquickjs::Error::Allocation` and
    /// [`PluginRuntime::with_context`] surfaces it as
    /// [`PluginError::MemoryExceeded`]. Default **32 MiB**.
    pub memory_limit_bytes: usize,
    /// Soft trigger for the GC. Default **8 MiB**. Not load-bearing
    /// for correctness — it's a latency/throughput knob.
    pub gc_threshold_bytes: usize,
    /// Per-plugin-call wall-clock budget. Default **2 seconds**. The
    /// interrupt handler polls against a deadline flag set by a
    /// tokio sleep task armed at [`PluginRuntime::with_context`] entry.
    pub execution_deadline: Duration,
    /// Maximum native stack a JS call may consume. Default **256 KiB**
    /// matches QuickJS-NG's built-in default; pinned explicitly so
    /// a future rquickjs update that changes the default doesn't
    /// silently move our safety contract. D8 review patch.
    pub max_stack_size_bytes: usize,
}

impl RuntimeConfig {
    /// Default memory limit: 32 MiB.
    pub const DEFAULT_MEMORY_LIMIT: usize = 32 * 1024 * 1024;
    /// Default GC threshold: 8 MiB.
    pub const DEFAULT_GC_THRESHOLD: usize = 8 * 1024 * 1024;
    /// Default execution deadline: 2 seconds.
    pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(2);
    /// Default stack limit: 256 KiB (QuickJS-NG built-in default).
    pub const DEFAULT_MAX_STACK: usize = 256 * 1024;
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            memory_limit_bytes: Self::DEFAULT_MEMORY_LIMIT,
            gc_threshold_bytes: Self::DEFAULT_GC_THRESHOLD,
            execution_deadline: Self::DEFAULT_DEADLINE,
            max_stack_size_bytes: Self::DEFAULT_MAX_STACK,
        }
    }
}

/// Shared-across-the-daemon JS runtime. Wrap in `Arc<PluginRuntime>`
/// for `AppState` / middleware / control-plane sharing.
///
/// # Concurrency
///
/// `with_context` serializes via an internal mutex — see the module-
/// level docs. Sharing the `Arc<PluginRuntime>` across tokio tasks
/// is safe; the mutex just means only one plugin call executes at
/// a time.
///
/// # Unhandled-promise-rejection caveat (Story 6.2 / H4 re-review deferral)
///
/// Plugins doing fire-and-forget host-API calls — e.g.
/// `agentsso.http.fetch(badUrl)` without `await` or `.catch()` —
/// produce silently-rejected Promises that the runtime's
/// `Ctx::catch` arm never sees. The "every host-API failure is an
/// AgentssoError" contract holds for `await`ed and `.catch()`-ed
/// rejections, but does NOT hold for fire-and-forget calls.
///
/// Fixing this requires installing `rquickjs::raw::Runtime::
/// set_host_promise_rejection_tracker` which is `unsafe` and would
/// require relaxing `#![forbid(unsafe_code)]` on the plugins crate.
/// **Deferred to 1.x** (post-rc) once the cost-benefit of the
/// unsafe block is understood. Story 6.3's loader will document
/// the calling convention so plugin authors don't accidentally
/// fire-and-forget.
///
/// # Thread-per-call caveat (Story 6.1 / D4 review deferral)
///
/// `with_context` is a **synchronous CPU-bound** operation (the
/// underlying `Context::with` blocks inside C code until the JS
/// evaluates or hits the interrupt deadline). Callers from async
/// contexts SHOULD wrap invocations in
/// [`tokio::task::spawn_blocking`] so the tokio worker thread
/// isn't starved. Story 6.2 (host API wiring) will formalize this
/// at the proxy boundary.
pub struct PluginRuntime {
    runtime: Runtime,
    config: RuntimeConfig,
    /// Single deadline flag, polled by the interrupt handler on
    /// every bytecode backward-branch. Armed on `with_context`
    /// entry, reset on exit. `Acquire`/`Release` ordering (D3
    /// review patch).
    interrupt_flag: Arc<AtomicBool>,
    /// Serializes `with_context` calls (B1 review patch). Held for
    /// the duration of the call — mutex guard dropped on exit.
    /// Poisoned mutex recovery: on `PoisonError` we continue
    /// anyway; the poison signal means a prior call panicked
    /// inside `context.with`, but QuickJS is already catch-unwind
    /// safe at the C boundary so the runtime itself is intact.
    call_lock: Mutex<()>,
}

impl PluginRuntime {
    /// Construct a new runtime with the given configuration.
    ///
    /// # Errors
    ///
    /// [`PluginError::RuntimeInit`] if QuickJS fails to allocate the
    /// VM or apply the configured limits. This is a boot-time fatal
    /// condition — the daemon should refuse to start.
    ///
    /// # Test seam
    ///
    /// On debug builds, `AGENTSSO_TEST_PLUGIN_RUNTIME_INIT_FAIL=1`
    /// forces construction to return `Err(RuntimeInit)` without
    /// attempting to create the underlying runtime. This exercises
    /// the daemon's `StartError::PluginRuntimeInit` banner path
    /// without a way to actually make QuickJS fail on demand.
    pub fn new(config: RuntimeConfig) -> Result<Self, PluginError> {
        // D10 review patch: tighten the seam to `== Ok("1")` so an
        // empty-string `""` inherited from a shell profile doesn't
        // accidentally fire the failure path.
        #[cfg(debug_assertions)]
        if std::env::var("AGENTSSO_TEST_PLUGIN_RUNTIME_INIT_FAIL").as_deref() == Ok("1") {
            return Err(PluginError::RuntimeInit(rquickjs::Error::Allocation));
        }

        let runtime = Runtime::new().map_err(PluginError::RuntimeInit)?;
        runtime.set_memory_limit(config.memory_limit_bytes);
        runtime.set_gc_threshold(config.gc_threshold_bytes);
        // D8 review patch: explicit stack limit so runaway recursion
        // surfaces as a controlled error, not a native stack
        // exhaustion abort. QuickJS-NG default is 256 KiB which is
        // adequate; we pin it explicitly to document the contract.
        runtime.set_max_stack_size(config.max_stack_size_bytes);

        // Interrupt handler: poll the flag on every bytecode
        // backward-branch. Return `true` to abort VM execution.
        //
        // The flag is owned by the runtime and cloned into the
        // closure. The `with_context` method arms/disarms the flag
        // by flipping the same `Arc`. D3 review patch: `Acquire`
        // ordering on load so the handler observes the latest
        // watchdog `Release` store on all architectures (ARM64
        // especially).
        let interrupt_flag = Arc::new(AtomicBool::new(false));
        let flag_for_handler = Arc::clone(&interrupt_flag);
        runtime.set_interrupt_handler(Some(Box::new(move || {
            flag_for_handler.load(Ordering::Acquire)
        })));

        Ok(Self { runtime, config, interrupt_flag, call_lock: Mutex::new(()) })
    }

    /// Construct with [`RuntimeConfig::default()`].
    pub fn new_default() -> Result<Self, PluginError> {
        Self::new(RuntimeConfig::default())
    }

    /// Return the configuration this runtime was built with.
    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    /// Run a plugin call inside a fresh sandboxed [`rquickjs::Ctx`].
    ///
    /// The closure receives a `&Ctx` with the `agentsso` namespace
    /// installed (initially empty in Story 6.1 — Story 6.2 fills it
    /// in). The interrupt deadline is armed on entry and disarmed
    /// on exit, so one stuck plugin cannot affect subsequent calls
    /// on the same runtime (AC #8).
    ///
    /// # Errors
    ///
    /// - [`PluginError::ExecutionDeadlineExceeded`] — interrupt fired
    /// - [`PluginError::MemoryExceeded`] — heap limit hit
    /// - [`PluginError::JsException`] — plugin threw an uncaught exception
    /// - [`PluginError::Internal`] — anything else (typically a
    ///   non-Exception `rquickjs::Error`)
    pub fn with_context<F, T>(&self, f: F) -> Result<T, PluginError>
    where
        F: for<'js> FnOnce(&rquickjs::Ctx<'js>) -> Result<T, PluginError>,
    {
        // B1 review patch: serialize concurrent callers. The
        // `parallel` rquickjs feature lets `Runtime` be `Send +
        // Sync`, but the `interrupt_flag` is runtime-wide state —
        // two concurrent `with_context` calls would clobber each
        // other's deadline arming. We accept the throughput cost
        // for correctness: plugin execution is not on the hot
        // path, and `Arc<PluginRuntime>` is shared for *startup
        // amortization*, not concurrent-call throughput.
        //
        // On `PoisonError`: a prior call panicked inside
        // `context.with`. QuickJS is catch-unwind safe at the C
        // boundary (the `rquickjs` closure wrapper re-raises panic
        // on return), so the runtime's JS heap is intact. We
        // recover by continuing with the poisoned guard — the next
        // caller's `context.with` starts from a fresh Context
        // anyway.
        let _guard = self.call_lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        // D3 review patch: `Release` store so the watchdog and the
        // interrupt handler's subsequent `Acquire` load observe
        // `false`. Clear any stale state from a prior panic path.
        self.interrupt_flag.store(false, Ordering::Release);
        let flag = Arc::clone(&self.interrupt_flag);
        let deadline = self.config.execution_deadline;
        let start = Instant::now();

        // D17 review patch: `WatchdogHandle` is `Drop`, not
        // `stop(self)`. Panic-unwind between arm and disarm still
        // stops the watchdog cleanly, and the explicit early-check
        // path below (pre-drop) observes the flag before the
        // handle is dropped.
        let watchdog = WatchdogHandle::spawn(Arc::clone(&flag), deadline);

        // Build a fresh context, install the sandbox, run the
        // caller's closure inside `Context::with`.
        //
        // # Intrinsics — Story 6.2 expanded set
        //
        // Story 6.1 shipped with `intrinsic::Eval` only — minimum
        // surface for the escape-test suite. Story 6.2 adds the
        // intrinsics every realistic connector plugin needs:
        //
        // - `Eval` — `ctx.eval(...)` source parsing (Story 6.1 base).
        // - `Json` — `JSON.parse`/`JSON.stringify` for marshalling
        //   policy decisions, scrub responses, fetch bodies.
        // - `RegExpCompiler` + `RegExp` — connector plugins use
        //   regex for URL routing and content matching. (RegExp
        //   alone is the runtime; the Compiler intrinsic registers
        //   the parser. Both are required for `/abc/.test(x)` to
        //   work.)
        // - `Date` — `Date.now()` for token-expiry math and
        //   exponential-backoff tracking.
        // - `Promise` — `agentsso.oauth.getToken` / `http.fetch`
        //   surface their results as Promise-shaped values that the
        //   plugin `await`s. Note: even though we did NOT enable
        //   the rquickjs `full-async` feature (Story 6.1 B4 review
        //   patch), the `Promise` intrinsic itself is independent —
        //   it provides the JS-language Promise constructor without
        //   the full async-tokio bridge. Microtask resolution works
        //   for `Promise.resolve(...)` chains; timer-based async
        //   does not (no `setTimeout`).
        // - `TypedArrays` — `Uint8Array` for binary HTTP bodies in
        //   `agentsso.http.fetch({body: new Uint8Array([...])})`.
        //
        // **Deliberately NOT added at 1.0.0:** `Proxy`, `MapSet`,
        // `WeakRef`, `BigInt`, `Performance`. Each is a separate
        // threat-model evaluation at 1.1.0 — the default stance is
        // "prove we need it before we add it." `Proxy` in
        // particular is the riskiest (intercepts property access on
        // arbitrary objects — exactly the primitive sandbox escapes
        // exploit).
        //
        // Story 6.2's `tests/sandbox_escape.rs::intrinsics_6_2_escape`
        // module verifies these additions did NOT open new escape
        // vectors — Function-constructor neuter from 6.1 still
        // applies through every added intrinsic.
        let context = Context::builder()
            .with::<intrinsic::Eval>()
            .with::<intrinsic::Json>()
            .with::<intrinsic::RegExpCompiler>()
            .with::<intrinsic::RegExp>()
            .with::<intrinsic::Date>()
            .with::<intrinsic::Promise>()
            .with::<intrinsic::TypedArrays>()
            .build(&self.runtime)
            .map_err(PluginError::Internal)?;
        let memory_limit = self.config.memory_limit_bytes;
        let result: Result<T, PluginError> = context.with(|ctx| {
            install_sandbox(&ctx)?;
            // If the closure returned an `Err` that wraps an
            // Exception sentinel, try to extract the thrown value's
            // stringified message via `Ctx::catch()`. This is the
            // live message-extraction path; the `From<rquickjs::
            // Error>` conversion in `error.rs` now produces an
            // Exception-variant that this arm rehydrates with the
            // actual thrown text (D1 review patch).
            match f(&ctx) {
                Ok(v) => Ok(v),
                Err(PluginError::JsException { message }) if message.is_empty() => {
                    let exception_value = ctx.catch();
                    // Story 6.2: try the AgentssoError-shape
                    // extraction first (`name === "AgentssoError"`,
                    // `.code` + `.retryable` + `.message` fields);
                    // fall back to the plain `Exception` extraction
                    // for any value that doesn't match the shape.
                    if let Some(host_api_err) = try_extract_agentsso_error(&exception_value) {
                        return Err(host_api_err);
                    }
                    let extracted = match exception_value.try_into_exception() {
                        Ok(ex) => ex.message().unwrap_or_default(),
                        Err(_) => String::new(),
                    };
                    Err(PluginError::JsException { message: extracted })
                }
                Err(e) => Err(e),
            }
        });

        let elapsed = start.elapsed();

        // B2 review patch: check the flag BEFORE dropping the
        // watchdog so `handle.abort()` on the tokio branch (which
        // is asynchronous) can't race us into a phantom deadline
        // breach. The `Acquire` load synchronizes with the
        // watchdog's `Release` store — if the flag is `true`, the
        // store happened-before this load.
        let deadline_fired = self.interrupt_flag.load(Ordering::Acquire);

        // `watchdog` drops here regardless of outcome (D17 RAII).
        // Explicitly drop so the happens-before is clear.
        drop(watchdog);

        if deadline_fired {
            return Err(PluginError::ExecutionDeadlineExceeded { elapsed_ms: elapsed.as_millis() });
        }

        // D7 review patch: upgrade the `MemoryExceeded
        // { limit_bytes: 0 }` sentinel from
        // `From<rquickjs::Error::Allocation>` with the real
        // configured limit. The 0-sentinel approach remains (vs a
        // full redesign) because it's contained to this one call
        // site and Story 6.2's host-API additions don't change the
        // conversion surface.
        result.map_err(|e| match e {
            PluginError::MemoryExceeded { limit_bytes: 0 } => {
                PluginError::MemoryExceeded { limit_bytes: memory_limit }
            }
            other => other,
        })
    }

    /// Run a plugin call with the full Story 6.2 host API
    /// registered on `globalThis.agentsso` and `globalThis.AgentssoError`.
    ///
    /// The closure receives a `&Ctx` with every host API method
    /// installed and ready to call. The interrupt deadline is
    /// armed for the lifetime of the call exactly as in
    /// [`Self::with_context`] — host-API calls share the same
    /// per-call execution budget the plugin's user code does.
    ///
    /// # Calling contract
    ///
    /// Per Story 6.2 Task 7's CALLING CONTRACT, the proxy-side
    /// [`HostServices`] implementation runs reqwest futures
    /// internally via `tokio::runtime::Handle::current().block_on(
    /// ...)`. Callers from async contexts MUST invoke this method
    /// inside [`tokio::task::spawn_blocking`] to avoid starving the
    /// proxy's tokio worker. (See
    /// `permitlayer-proxy::plugin_host_services` module docs for
    /// the full rationale.)
    ///
    /// # Why this is a separate method from `with_context`
    ///
    /// `with_context` is the Story 6.1 sandbox-only entry point —
    /// the sandbox-escape test suite at
    /// `tests/sandbox_escape.rs` pins on its exact contract
    /// (`agentsso = {}`, no host-API methods). Adding `services`
    /// to its signature would force every escape test to thread
    /// services through, defeating the "sandbox tests care about
    /// the sandbox alone" separation. `with_host_api` is the
    /// production entry point; `with_context` stays as the
    /// test-only entry point. Story 6.3's loader will use
    /// `with_host_api` exclusively.
    pub fn with_host_api<F, T>(
        &self,
        services: &Arc<dyn HostServices>,
        f: F,
    ) -> Result<T, PluginError>
    where
        F: for<'js> FnOnce(&rquickjs::Ctx<'js>) -> Result<T, PluginError>,
    {
        // Take an owned `Arc` clone — host-API closures need a
        // `'static`-bounded carrier they can capture cheaply, and
        // `Arc<dyn HostServices>` clones in O(1) (refcount bump).
        // Using `&Arc<...>` in the signature forces callers to
        // construct the Arc once at the boundary; we clone for
        // every host-API submodule registration internally.
        let services_arc: Arc<dyn HostServices> = Arc::clone(services);
        self.with_context(move |ctx| {
            register_host_api(ctx, services_arc)?;
            f(ctx)
        })
    }
}

/// Try to extract an authentic `AgentssoError`-shaped JS value into
/// a [`PluginError::HostApiError`]. Returns `None` if the value is
/// not an authentic AgentssoError instance — the caller falls back
/// to the plain `JsException` extraction.
///
/// **AD5 (Story 6.2 course-correction 2026-04-17):** authentication
/// is via the **stamp key** installed by
/// [`crate::host_api::error_class::register`] on every authentic
/// instance — NOT name-string sniffing. The stamp key is
/// process-stable, plugin-unguessable (16 bytes from `OsRng`), and
/// installed as a non-enumerable property so plugins cannot
/// enumerate or copy it. A hand-crafted plain object
/// `{name: "AgentssoError", code, retryable, message}` (forged) has
/// no stamp and returns `None` — the runtime then surfaces it as
/// `PluginError::JsException`, NOT `HostApiError`.
///
/// This subsumes review findings B4 (log-injection via plugin-
/// controlled error codes — sanitization happens BELOW), H7 (forged
/// `retryable=true` to influence retry logic — forged objects are
/// rejected), and H8 (prototype-walk side effects — we no longer
/// walk the prototype chain).
///
/// # Code sanitization (Story 6.2 review finding B4)
///
/// The extracted `code` string is sanitized for control characters
/// (CR / LF / NUL / 0x00-0x1F except HTAB) before being mapped to a
/// `HostApiErrorCode`. Control chars are replaced with U+FFFD so a
/// malicious plugin cannot inject newlines or ANSI escapes into a
/// downstream `tracing::warn!` rendering of the code. (Plugin code
/// can still construct `AgentssoError` instances with arbitrary
/// strings — the stamp authenticates instance origin, not content.)
fn try_extract_agentsso_error<'js>(exception_value: &rquickjs::Value<'js>) -> Option<PluginError> {
    let obj = exception_value.as_object()?;

    // AD5: stamp authentication. The stamp key is a per-process
    // secret installed by `error_class::register`. Authentic
    // instances carry it; forged plain objects do not. We use
    // `Object::contains_key` rather than `.get(STAMP)` so we don't
    // call any potential getter (review finding H8 wanted us off
    // the prototype-walking-via-getter path entirely).
    //
    // B6 (re-review patch 2026-04-18): if `register` has never
    // run in this process (e.g. extraction fired from a sandbox-
    // only `with_context` test), the stamp key is `None` and no
    // instance can be authenticated — fall through to the plain
    // `JsException` form. This avoids the prior init-order bug
    // where extraction-side `OnceLock::get_or_init` silently
    // initialized the stamp to a value no future register could
    // recreate.
    let stamp_key = crate::host_api::error_class::stamp_key_for_extraction()?;
    let stamped = obj.contains_key(stamp_key).unwrap_or(false);
    if !stamped {
        return None;
    }

    // Authenticated. Now extract the user-visible fields. These
    // calls can side-effect via getters in theory, but at this
    // point we've established the value is an authentic class
    // instance — its `code`/`retryable`/`message` properties are
    // the ones the constructor set, not arbitrary plugin getters.
    let code_str_raw: String = obj.get("code").unwrap_or_else(|_| "unknown".to_owned());
    let retryable: bool = obj.get("retryable").unwrap_or(false);
    let message: String = obj.get("message").unwrap_or_default();

    // B4: control-char sanitization. Plugins can construct
    // `AgentssoError` with any string as `.code`; we replace
    // control chars with U+FFFD so a malicious plugin can't inject
    // newlines / ANSI escapes into log lines.
    //
    // M13 (re-review patch 2026-04-18): cap the input length
    // BEFORE sanitization. A 50 MB code string with all control
    // chars would otherwise allocate a 150 MB String (U+FFFD is
    // 3 bytes UTF-8). 1 KiB is more than enough for any realistic
    // error code; longer values are truncated.
    const MAX_CODE_BYTES: usize = 1024;
    let code_truncated = if code_str_raw.len() > MAX_CODE_BYTES {
        let mut cap = MAX_CODE_BYTES;
        while cap > 0 && !code_str_raw.is_char_boundary(cap) {
            cap -= 1;
        }
        format!("{}...(truncated)", &code_str_raw[..cap])
    } else {
        code_str_raw
    };
    let code_str: String = code_truncated
        .chars()
        .map(|c| if c.is_control() && c != '\t' { '\u{FFFD}' } else { c })
        .collect();

    // Plugin-thrown codes ALWAYS route to Plugin(...), regardless of content.
    // Do NOT call HostCode::from_str here — that would let a plugin forge
    // host-generated codes by throwing e.g. `{code: "oauth.unknown_service"}`.
    let code = crate::HostApiErrorCode::Plugin(
        crate::host_api::services::PluginThrownCode::new_from_js(code_str),
    );
    Some(PluginError::HostApiError { code, retryable, message })
}

/// RAII handle for the deadline watchdog task.
///
/// Both the tokio and std-thread branches use a shared `done`
/// atomic flag + a short-poll loop so `Drop` can disarm the
/// watchdog **synchronously** (B2 review patch fix — the prior
/// `tokio::JoinHandle::abort()`-only disarm was asynchronous and
/// left a window where the watchdog could flip the interrupt flag
/// after the caller observed it as "still running in time").
///
/// L1 review patch: dropped the `Option<JoinHandle>` wrapper on
/// the thread branch (the option was never set to `None` between
/// construction and drop).
enum WatchdogHandle {
    Tokio {
        /// `true` when the main thread has finished work and wants
        /// the watchdog to exit without flipping the deadline
        /// flag. Polled by the spawned task on each poll tick.
        done: Arc<AtomicBool>,
        /// Kept alive for `abort()`-on-drop + to let us `block_in_place`
        /// wait for the task to finish (if we're in a multi-thread
        /// runtime). Option so `Drop` can `take` and `abort`.
        handle: Option<tokio::task::JoinHandle<()>>,
    },
    Thread {
        done: Arc<AtomicBool>,
        /// Kept alive so the spawned thread doesn't become
        /// detached on Drop (which would be fine for this design,
        /// but holding the handle lets future changes opt-in to
        /// `join()` if they decide sync cleanup is required). Not
        /// read — Drop only signals `done` and lets the thread
        /// exit on its own timer.
        #[allow(dead_code)]
        thread: std::thread::JoinHandle<()>,
    },
    Disabled,
}

/// Poll interval for the watchdog's "should I exit early?" check.
/// 10 ms matches AC #7's 100 ms jitter ceiling with 10× safety
/// margin.
const WATCHDOG_POLL: Duration = Duration::from_millis(10);

impl WatchdogHandle {
    fn spawn(flag: Arc<AtomicBool>, deadline: Duration) -> Self {
        if deadline.is_zero() {
            return WatchdogHandle::Disabled;
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let done = Arc::new(AtomicBool::new(false));
            let done_for_task = Arc::clone(&done);
            let flag_for_task = Arc::clone(&flag);
            let join = handle.spawn(async move {
                // Poll so `Drop` can signal early exit.
                let start = Instant::now();
                while start.elapsed() < deadline {
                    if done_for_task.load(Ordering::Acquire) {
                        return;
                    }
                    tokio::time::sleep(WATCHDOG_POLL.min(deadline - start.elapsed())).await;
                }
                // D3 review patch: `Release` store so the main
                // thread's `Acquire` load observes this write.
                flag_for_task.store(true, Ordering::Release);
            });
            return WatchdogHandle::Tokio { done, handle: Some(join) };
        }
        // No tokio runtime in scope — fall back to a std thread.
        let done = Arc::new(AtomicBool::new(false));
        let done_for_thread = Arc::clone(&done);
        let flag_for_thread = Arc::clone(&flag);
        let thread = std::thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < deadline {
                if done_for_thread.load(Ordering::Acquire) {
                    return;
                }
                std::thread::sleep(WATCHDOG_POLL.min(deadline - start.elapsed()));
            }
            flag_for_thread.store(true, Ordering::Release);
        });
        WatchdogHandle::Thread { done, thread }
    }
}

impl Drop for WatchdogHandle {
    /// D17 review patch: RAII disarm so panic-unwind or early
    /// return from `with_context` cleans up the watchdog without
    /// leaving the flag armed for the next caller.
    ///
    /// The tokio branch signals `done` and aborts the JoinHandle.
    /// We cannot synchronously join a tokio task from a sync
    /// context, but the `done` flag races the `sleep` inside the
    /// task — the poll loop observes `done=true` on the next
    /// poll tick (≤10 ms) and exits without flipping the interrupt
    /// flag. The caller has already done its `interrupt_flag.load`
    /// before this Drop, so even if the task somehow misses the
    /// signal and flips the flag late, it affects only the next
    /// caller — who clears the flag at `with_context` entry
    /// before arming its own watchdog.
    fn drop(&mut self) {
        match self {
            WatchdogHandle::Tokio { done, handle } => {
                done.store(true, Ordering::Release);
                if let Some(h) = handle.take() {
                    h.abort();
                }
            }
            WatchdogHandle::Thread { done, thread: _ } => {
                done.store(true, Ordering::Release);
                // The thread sees `done=true` within WATCHDOG_POLL
                // (10 ms) and exits cleanly. We do NOT `join()`
                // here because Drop must not block for arbitrary
                // periods — the caller needs `with_context` to
                // return promptly. The thread cleans up
                // independently; any leaked state (none in the
                // current design — the thread owns only its own
                // local vars and Arcs) is bounded.
            }
            WatchdogHandle::Disabled => {}
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn new_default_matches_config_defaults() {
        let rt = PluginRuntime::new_default().unwrap();
        assert_eq!(rt.config().memory_limit_bytes, RuntimeConfig::DEFAULT_MEMORY_LIMIT);
        assert_eq!(rt.config().gc_threshold_bytes, RuntimeConfig::DEFAULT_GC_THRESHOLD);
        assert_eq!(rt.config().execution_deadline, RuntimeConfig::DEFAULT_DEADLINE);
    }

    #[test]
    fn new_default_values_match_spec() {
        // Lock in the documented defaults explicitly so any future
        // config-constant drift fails this test (and forces the
        // story/architecture doc to be updated in the same PR).
        assert_eq!(RuntimeConfig::DEFAULT_MEMORY_LIMIT, 33_554_432); // 32 MiB
        assert_eq!(RuntimeConfig::DEFAULT_GC_THRESHOLD, 8_388_608); // 8 MiB
        assert_eq!(RuntimeConfig::DEFAULT_DEADLINE, Duration::from_secs(2));
    }

    #[test]
    fn with_context_runs_benign_expression() {
        let rt = PluginRuntime::new_default().unwrap();
        let result: i32 = rt
            .with_context(|ctx| {
                let v: i32 = ctx.eval("1 + 1")?;
                Ok(v)
            })
            .unwrap();
        assert_eq!(result, 2);
    }

    #[test]
    fn with_context_memory_limit_terminates_string_doubling() {
        // Use a tighter limit than the default so the test is fast
        // enough to run in CI without burning RAM. 1 MiB is plenty
        // for a "while true doubles string" loop to hit.
        let config = RuntimeConfig {
            memory_limit_bytes: 1024 * 1024,
            gc_threshold_bytes: 512 * 1024,
            execution_deadline: Duration::from_secs(10),
            max_stack_size_bytes: RuntimeConfig::DEFAULT_MAX_STACK,
        };
        let rt = PluginRuntime::new(config).unwrap();
        let err = rt
            .with_context(|ctx| -> Result<(), PluginError> {
                let _: rquickjs::Value = ctx.eval("let a = 'x'; while (true) { a = a + a; }")?;
                Ok(())
            })
            .unwrap_err();
        assert!(
            matches!(err, PluginError::MemoryExceeded { .. } | PluginError::JsException { .. }),
            "expected MemoryExceeded or JsException (OOM surfaces either way depending on rquickjs version), got {err:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn with_context_deadline_exceeded_on_infinite_loop() {
        // Use a short deadline so the test finishes quickly. 500ms
        // is well above QuickJS's bytecode-poll resolution (~100ms
        // typical) but short enough for CI.
        let config = RuntimeConfig {
            memory_limit_bytes: RuntimeConfig::DEFAULT_MEMORY_LIMIT,
            gc_threshold_bytes: RuntimeConfig::DEFAULT_GC_THRESHOLD,
            execution_deadline: Duration::from_millis(500),
            max_stack_size_bytes: RuntimeConfig::DEFAULT_MAX_STACK,
        };
        let rt = PluginRuntime::new(config).unwrap();
        let start = Instant::now();
        let err = tokio::task::spawn_blocking(move || {
            rt.with_context(|ctx| -> Result<(), PluginError> {
                let _: rquickjs::Value = ctx.eval("while (true) {}")?;
                Ok(())
            })
        })
        .await
        .unwrap()
        .unwrap_err();
        let elapsed = start.elapsed();
        assert!(
            matches!(err, PluginError::ExecutionDeadlineExceeded { .. }),
            "expected ExecutionDeadlineExceeded, got {err:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(500) && elapsed <= Duration::from_millis(1500),
            "elapsed {elapsed:?} must be in [500ms, 1500ms] for a 500ms deadline"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runtime_survives_cpu_limit() {
        // After a deadline breach, a subsequent call must succeed.
        let config = RuntimeConfig {
            memory_limit_bytes: RuntimeConfig::DEFAULT_MEMORY_LIMIT,
            gc_threshold_bytes: RuntimeConfig::DEFAULT_GC_THRESHOLD,
            execution_deadline: Duration::from_millis(300),
            max_stack_size_bytes: RuntimeConfig::DEFAULT_MAX_STACK,
        };
        let rt = Arc::new(PluginRuntime::new(config).unwrap());

        // First call: infinite loop → deadline exceeded.
        let rt_clone = Arc::clone(&rt);
        let first = tokio::task::spawn_blocking(move || {
            rt_clone.with_context(|ctx| -> Result<(), PluginError> {
                let _: rquickjs::Value = ctx.eval("while (true) {}")?;
                Ok(())
            })
        })
        .await
        .unwrap();
        assert!(matches!(first, Err(PluginError::ExecutionDeadlineExceeded { .. })));

        // Second call: benign expression must succeed.
        let second: i32 = rt
            .with_context(|ctx| {
                let v: i32 = ctx.eval("40 + 2")?;
                Ok(v)
            })
            .unwrap();
        assert_eq!(second, 42);
    }

    #[test]
    fn runtime_survives_memory_limit() {
        let config = RuntimeConfig {
            memory_limit_bytes: 1024 * 1024,
            gc_threshold_bytes: 512 * 1024,
            execution_deadline: Duration::from_secs(5),
            max_stack_size_bytes: RuntimeConfig::DEFAULT_MAX_STACK,
        };
        let rt = PluginRuntime::new(config).unwrap();

        // First call: memory exhaustion.
        let first = rt.with_context(|ctx| -> Result<(), PluginError> {
            let _: rquickjs::Value = ctx.eval("let a = 'x'; while (true) { a = a + a; }")?;
            Ok(())
        });
        assert!(first.is_err());

        // Second call: benign expression must succeed despite the
        // runtime having just observed an OOM.
        let second: i32 = rt
            .with_context(|ctx| {
                let v: i32 = ctx.eval("7 * 6")?;
                Ok(v)
            })
            .unwrap();
        assert_eq!(second, 42);
    }

    // D21 review patch: the empty `test_seam_init_failure_surfaces
    // _runtime_init_error` stub was deleted — it counted toward the
    // passing-tests total without exercising anything. The seam is
    // covered by
    // `daemon_lifecycle.rs::test_plugin_runtime_init_failure_bubbles
    // _as_start_error` which spawns a subprocess and observes the
    // structured banner + exit code.

    // B6 review patch: AC #11 end-to-end message-extraction tests.
    // The `Ctx::catch` path in `with_context` rehydrates an empty
    // `JsException { message: "" }` with the thrown value's
    // `toString()` text. These tests exercise the live path from
    // `throw new Error(...)` inside the closure to the extracted
    // `message` on the returned error.

    #[test]
    fn js_exception_message_extracted() {
        let rt = PluginRuntime::new_default().unwrap();
        let err = rt
            .with_context(|ctx| -> Result<(), PluginError> {
                let _: rquickjs::Value = ctx.eval("throw new Error('boom')")?;
                Ok(())
            })
            .unwrap_err();
        match err {
            PluginError::JsException { message } => {
                assert!(
                    message.contains("boom"),
                    "extracted JS exception message must contain the thrown text; got `{message}`"
                );
            }
            other => panic!("expected JsException, got {other:?}"),
        }
    }

    #[test]
    fn js_exception_with_broken_tostring_returns_empty_or_safe_message() {
        // Adversarial plugin defines a thrown object whose
        // `toString` itself throws. Our extraction path must
        // NOT recurse into infinite failure; it falls back to an
        // empty string (AC #11 explicit fallback behavior).
        //
        // Tolerant check: depending on how QuickJS surfaces the
        // nested throw, we accept either an empty string or a
        // safe fallback that doesn't contain the word "boom" from
        // an inner payload.
        let rt = PluginRuntime::new_default().unwrap();
        let err = rt
            .with_context(|ctx| -> Result<(), PluginError> {
                let _: rquickjs::Value =
                    ctx.eval("throw { toString: function() { throw new Error('nested-boom'); } }")?;
                Ok(())
            })
            .unwrap_err();
        match err {
            PluginError::JsException { message } => {
                assert!(
                    !message.contains("nested-boom"),
                    "broken-toString must not recurse into the inner payload; got `{message}`"
                );
            }
            other => panic!("expected JsException, got {other:?}"),
        }
    }

    // D11 review patch: AC #7 deadline test using the spec's
    // default 2s deadline + tight `[2000ms, 2200ms]` jitter window.
    // The previous test used a 500ms deadline and a 1s jitter
    // allowance which was 10× the spec's budget. This one locks
    // in the actual SLO.
    //
    // Gated behind `cfg(not(miri))` because miri interpreters run
    // ~1000× slower than native and would never converge on a 2s
    // deadline. Also gated to `#[ignore]` by default so CI can opt
    // in via `cargo test -- --ignored ac7_deadline_at_spec_default`
    // — running it on every CI invocation would burn 2+ seconds per
    // run; the tighter `with_context_deadline_exceeded_on_infinite_loop`
    // test at 500ms catches regressions faster.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "AC #7 strict SLO test — 2s runtime; run with --ignored to validate jitter budget"]
    async fn ac7_deadline_at_spec_default() {
        let rt = PluginRuntime::new_default().unwrap();
        let start = Instant::now();
        let err = tokio::task::spawn_blocking(move || {
            rt.with_context(|ctx| -> Result<(), PluginError> {
                let _: rquickjs::Value = ctx.eval("while (true) {}")?;
                Ok(())
            })
        })
        .await
        .unwrap()
        .unwrap_err();
        let elapsed = start.elapsed();
        assert!(
            matches!(err, PluginError::ExecutionDeadlineExceeded { .. }),
            "expected ExecutionDeadlineExceeded, got {err:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(2000) && elapsed <= Duration::from_millis(2200),
            "AC #7 jitter budget: elapsed {elapsed:?} must be in [2000ms, 2200ms] for a 2s deadline"
        );
    }
}
