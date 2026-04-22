//! `agentsso.deprecated` namespace — scaffolding for the NFR41
//! 6-month deprecation-window contract (epics.md:1784-1787).
//!
//! At 1.0.0-rc.1 the namespace is an empty frozen object. A plugin
//! accessing `agentsso.deprecated` sees `{}` and cannot mutate it.
//! 1.x stories that need to deprecate a host-API method call
//! [`install_deprecated`] to register a warning-wrapper around the
//! old method so operators see a single `tracing::warn!` line per
//! method per daemon lifetime when the old method is invoked.
//!
//! # Why an empty stub at 1.0.0-rc.1
//!
//! Reserving the namespace NOW means a 1.x story can land a deprecated
//! method as a pure additive change against `host-api.lock`: the
//! snapshot for 1.0.0-rc.1 has `agentsso.deprecated : object` in
//! `## js_surface`, and a later `1.2.0` release that adds
//! `agentsso.deprecated.legacyFoo(...)` shows up in the diff as a new
//! line (additive). No need to re-decide the namespace shape in
//! 1.x — the contract is locked today.
//!
//! # Freeze semantics
//!
//! The namespace object is frozen via `Object.freeze` after install.
//! Plugins cannot:
//! - Add properties (`agentsso.deprecated.foo = "bar"` is dropped in
//!   non-strict mode, throws `TypeError` in strict mode).
//! - Delete properties.
//! - Replace the namespace itself (`agentsso.deprecated = null` — the
//!   `agentsso` object itself is not frozen but plugins that shadow
//!   the namespace only affect their own local binding; other plugins
//!   loaded in the same `with_host_api` call still see the frozen
//!   original).
//!
//! [`install_deprecated`] is Rust-side only — it bypasses `freeze`
//! because it runs inside the host-API register chain before the
//! freeze happens. A 1.x story registers a deprecated method by:
//! 1. Calling `install_deprecated(ctx, agentsso, "legacyFoo", emitter, wrapped)`
//!    from its own `register` function, BEFORE `deprecated::register`
//!    runs (or it can wrap the freeze-then-unfreeze dance explicitly).
//! 2. Adding the method string to `JS_SURFACE`.
//! 3. Committing the refreshed `host-api.lock` via the xtask.

use std::sync::Arc;
use std::sync::Mutex;

use rquickjs::function::{Func, MutFn};
use rquickjs::{Ctx, Function, Object, Value};

use crate::PluginError;

/// Install the `agentsso.deprecated` namespace as a frozen empty
/// object.
///
/// Called by [`super::register_host_api`] after `version::register`
/// and before the service-backed submodules (`oauth`, `policy`,
/// `scrub`, `http`). Placement is load-bearing only insofar as
/// `deprecated` is visible to plugins that call `agentsso.deprecated`;
/// it does NOT consume `HostServices`.
pub fn register<'js>(ctx: &Ctx<'js>, agentsso: &Object<'js>) -> Result<(), PluginError> {
    let deprecated = Object::new(ctx.clone())?;
    agentsso.set("deprecated", deprecated)?;
    // Freeze the installed namespace so plugins cannot add / mutate
    // / delete properties. `Object.freeze` returns the same object
    // reference; we rely on the global `globalThis.agentsso` path to
    // reach it rather than capturing a JS handle.
    ctx.eval::<(), _>(r#"Object.freeze(globalThis.agentsso.deprecated);"#)?;
    Ok(())
}

/// Emit a one-shot deprecation WARN line per `(method_name, daemon
/// lifetime)` pair.
///
/// `Send + Sync` so an [`Arc`]-wrapped instance can be shared across
/// closures installed on the runtime. The per-daemon rate-limiting
/// state is the emitter's responsibility: [`TracingDeprecationWarnEmitter`]
/// implements this by holding a `Mutex<BTreeSet<String>>` of names
/// that have already emitted.
pub trait DeprecationWarnEmitter: Send + Sync {
    /// Emit (at most) one WARN line per `method_name` over the life
    /// of the emitter instance. Repeated calls with the same name are
    /// no-ops.
    fn emit(&self, method_name: &str);
}

/// Default emitter that dedups via a `Mutex<BTreeSet<String>>` and
/// emits `tracing::warn!` lines.
///
/// 1.x host-API wiring constructs one of these at daemon startup and
/// passes an `Arc<TracingDeprecationWarnEmitter>` into every
/// `install_deprecated` call. At 1.0.0-rc.1 there are no deprecated
/// methods yet, so the emitter is unused in production — it's tested
/// via the unit test below to prove the machinery works.
#[derive(Default)]
pub struct TracingDeprecationWarnEmitter {
    emitted: Mutex<std::collections::BTreeSet<String>>,
}

impl TracingDeprecationWarnEmitter {
    /// Construct a fresh emitter with an empty dedup set.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

impl DeprecationWarnEmitter for TracingDeprecationWarnEmitter {
    fn emit(&self, method_name: &str) {
        // Mutex poisoning on a `BTreeSet::insert` call would require
        // a panic between `lock()` and `drop(guard)`, which does not
        // happen in this function. If the mutex IS poisoned we fall
        // through to the warn! emission (defensive: over-emit rather
        // than silently drop the signal).
        let already_emitted = match self.emitted.lock() {
            Ok(mut guard) => !guard.insert(method_name.to_owned()),
            Err(_) => false,
        };
        if !already_emitted {
            tracing::warn!(
                method = method_name,
                "plugin invoked deprecated host-API method; see CHANGELOG for the \
                 replacement + removal timeline (NFR41: 6-month window)",
            );
        }
    }
}

/// Register a deprecated method wrapper on `agentsso.deprecated.<method_name>`.
///
/// **At 1.0.0-rc.1 this helper is unused** — the namespace is empty.
/// It exists so a 1.x story can add a deprecated method with a single
/// call from its own `register` function:
///
/// ```ignore
/// install_deprecated(
///     ctx,
///     agentsso,
///     "legacyFoo",
///     Arc::clone(&deprecation_emitter),
///     wrapped_legacy_foo_closure,
/// )?;
/// ```
///
/// The helper:
/// 1. Unfreezes `agentsso.deprecated` (`Object.freeze` is idempotent
///    reverse via `Object.defineProperty` setting `configurable`, but
///    the simpler path is: install BEFORE the top-level `register`
///    runs — see note below).
/// 2. Installs a closure that calls `warn_emitter.emit(method_name)`
///    and then delegates to the `wrapped` function.
/// 3. Caller is responsible for (a) freezing the namespace again
///    after all deprecated methods are installed, and (b) adding
///    the method to `JS_SURFACE`.
///
/// **Caller discipline:** Because `register` (above) freezes the
/// namespace, callers who want to install a deprecated method MUST
/// run `install_deprecated` BEFORE `register` — or adjust the
/// register order. At 1.0.0-rc.1 this helper is pure scaffolding;
/// the first real 1.x deprecation story will land the ordering
/// decision alongside the first deprecated method.
pub fn install_deprecated<'js>(
    _ctx: &Ctx<'js>,
    agentsso: &Object<'js>,
    method_name: &str,
    warn_emitter: Arc<dyn DeprecationWarnEmitter>,
    wrapped: Function<'js>,
) -> Result<(), PluginError> {
    // Reach into `agentsso.deprecated` to install the wrapper. At
    // 1.0.0-rc.1 this namespace has been frozen by `register` — the
    // test seam bypasses that by calling `install_deprecated`
    // BEFORE the freeze (via a dedicated test-only entrypoint; see
    // unit test `install_deprecated_rate_limits_warn_per_method`).
    let deprecated: Object<'js> = agentsso.get("deprecated")?;

    // Build a wrapper that:
    //   1. Fires a warn via the emitter (dedupe handled by emitter).
    //   2. Forwards `...args` to the original `wrapped` function and
    //      returns its return value.
    let method_name_owned = method_name.to_owned();
    let emitter = Arc::clone(&warn_emitter);
    let wrapped_persistent = wrapped.clone();
    let closure = move |_ctx: Ctx<'js>,
                        args: rquickjs::function::Rest<Value<'js>>|
          -> rquickjs::Result<Value<'js>> {
        emitter.emit(&method_name_owned);
        // Delegate to the wrapped function with the captured args,
        // preserving every arg the plugin passed. `Function::call`
        // expects a tuple of args; `Rest<Value>` implements
        // `IntoArgs` so we forward it directly.
        let result: Value<'js> = wrapped_persistent.call((args,))?;
        Ok(result)
    };
    deprecated.set(method_name, Func::from(MutFn::new(closure)))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Test emitter that counts `emit` invocations per method name.
    /// Rate-limits the same way `TracingDeprecationWarnEmitter` does,
    /// but records each call so tests can assert on counts directly.
    #[derive(Default)]
    struct CountingEmitter {
        emits: Mutex<Vec<String>>,
        /// Per-method dedup, matches production emitter semantics.
        seen: Mutex<std::collections::BTreeSet<String>>,
    }

    impl DeprecationWarnEmitter for CountingEmitter {
        fn emit(&self, method_name: &str) {
            let first = match self.seen.lock() {
                Ok(mut g) => g.insert(method_name.to_owned()),
                Err(_) => true,
            };
            if first && let Ok(mut v) = self.emits.lock() {
                v.push(method_name.to_owned());
            }
        }
    }

    impl CountingEmitter {
        fn count(&self) -> usize {
            self.emits.lock().map(|v| v.len()).unwrap_or(0)
        }
    }

    #[test]
    fn tracing_deprecation_warn_emitter_dedupes_same_name() {
        // First call with a given name emits; subsequent calls are
        // no-ops. Different names each emit once.
        let emitter = TracingDeprecationWarnEmitter::new();
        // Can't easily assert on the `tracing::warn!` output without
        // pulling `tracing-test` into a new dep slot. Instead, drive
        // the dedup behavior directly: if the internal set grows
        // exactly twice for two distinct names and stays at 2 on
        // repeats, the dedup works.
        emitter.emit("foo");
        emitter.emit("foo");
        emitter.emit("foo");
        emitter.emit("bar");
        emitter.emit("bar");
        let guard = emitter.emitted.lock().unwrap();
        assert_eq!(guard.len(), 2, "expected 2 unique names, got {:?}", *guard);
        assert!(guard.contains("foo"));
        assert!(guard.contains("bar"));
    }

    #[test]
    fn install_deprecated_rate_limits_warn_per_method() {
        // AC #17: repeated invocation of a wrapped deprecated method
        // fires the warn exactly once AND delegates to the wrapped
        // function on every call.
        //
        // The wrapped callable is a pure-JS function (defined via
        // `eval`) rather than a Rust closure: this keeps the test's
        // JS-side reference graph acyclic so rquickjs's GC can
        // collect it before runtime drop. The wrapper closure built
        // by `install_deprecated` itself DOES hold captured Rust
        // state (the emitter), but `MutFn` + rquickjs's own finalize
        // path handle that — it's the wrapped-Function cycle that
        // defeats the GC when both sides hold Rust captures.
        use crate::PluginRuntime;
        use crate::RuntimeConfig;

        let runtime = PluginRuntime::new(RuntimeConfig::default()).expect("runtime");
        let emitter: Arc<CountingEmitter> = Arc::new(CountingEmitter::default());
        let emitter_trait: Arc<dyn DeprecationWarnEmitter> = Arc::clone(&emitter) as _;

        runtime
            .with_context(|ctx| {
                // Boot minimal globals + a JS-native counter.
                ctx.eval::<(), _>(
                    r#"
                    globalThis.agentsso = { deprecated: {} };
                    globalThis.__invocation_count = 0;
                    globalThis.__wrapped_impl = function(n) {
                        globalThis.__invocation_count += 1;
                        return 42;
                    };
                    "#,
                )?;
                let agentsso: Object<'_> = ctx.globals().get("agentsso")?;
                let wrapped_fn: Function<'_> = ctx.globals().get("__wrapped_impl")?;

                install_deprecated(
                    ctx,
                    &agentsso,
                    "legacyFoo",
                    Arc::clone(&emitter_trait),
                    wrapped_fn,
                )
                .expect("install_deprecated");

                // Invoke the wrapped method 10 times via JS.
                let result: i32 = ctx.eval(
                    r#"
                    let last = null;
                    for (let i = 0; i < 10; i++) {
                        last = agentsso.deprecated.legacyFoo(i);
                    }
                    last
                    "#,
                )?;
                assert_eq!(result, 42, "wrapped function return value must propagate");

                // Pull the invocation count back out to Rust.
                let invocations: i32 = ctx.eval("globalThis.__invocation_count")?;
                assert_eq!(
                    invocations, 10,
                    "wrapper must delegate to wrapped on every call, not just the first",
                );

                // Clear globals so the GC has nothing left to trace
                // when the context drops.
                ctx.eval::<(), _>(
                    r#"
                    delete globalThis.__invocation_count;
                    delete globalThis.__wrapped_impl;
                    delete globalThis.agentsso;
                    "#,
                )?;

                Ok::<(), crate::PluginError>(())
            })
            .expect("with_context");

        // Emitter saw exactly ONE emit, for "legacyFoo".
        assert_eq!(emitter.count(), 1, "warn must fire once per method per lifetime");
    }

    #[test]
    fn register_installs_empty_frozen_object() {
        // AC #16: `agentsso.deprecated` is installed as an empty
        // frozen object. Plugin-side mutation is rejected.
        use crate::PluginRuntime;
        use crate::RuntimeConfig;

        let runtime = PluginRuntime::new(RuntimeConfig::default()).expect("runtime");

        runtime
            .with_context(|ctx| {
                // Manually replicate what `register_host_api` does,
                // but only for the pieces we need (empty agentsso +
                // deprecated::register). Avoids wiring HostServices.
                ctx.eval::<(), _>(r#"globalThis.agentsso = {};"#)?;
                let agentsso: Object<'_> = ctx.globals().get("agentsso")?;
                register(ctx, &agentsso).expect("deprecated::register");

                // Type check.
                let is_object: bool = ctx.eval(r#"typeof agentsso.deprecated === "object""#)?;
                assert!(is_object, "agentsso.deprecated must be an object");

                // Empty.
                let key_count: i32 = ctx.eval(r#"Object.keys(agentsso.deprecated).length"#)?;
                assert_eq!(key_count, 0, "agentsso.deprecated must have zero own keys at rc.1");

                // Frozen — write is rejected. QuickJS throws on all
                // writes to frozen objects regardless of strict-mode
                // flag (it enforces `[[Extensible]] === false` at
                // the property-set level). We wrap in try/catch and
                // assert the write threw AND the subsequent read
                // returns undefined.
                let write_threw: bool = ctx.eval(
                    r#"
                    let threw = false;
                    try { agentsso.deprecated.foo = "bar"; }
                    catch (_e) { threw = true; }
                    threw
                    "#,
                )?;
                assert!(write_threw, "write to frozen namespace must throw");
                let foo_value: Value<'_> = ctx.eval(r#"agentsso.deprecated.foo"#)?;
                assert!(foo_value.is_undefined(), "frozen object must not accept new props");

                // Object.isFrozen reports true.
                let is_frozen: bool = ctx.eval(r#"Object.isFrozen(agentsso.deprecated)"#)?;
                assert!(is_frozen, "agentsso.deprecated must be frozen");

                Ok::<(), crate::PluginError>(())
            })
            .expect("with_context");
    }

    #[test]
    fn plugin_cannot_mutate_deprecated_in_strict_mode() {
        use crate::PluginRuntime;
        use crate::RuntimeConfig;

        let runtime = PluginRuntime::new(RuntimeConfig::default()).expect("runtime");

        runtime
            .with_context(|ctx| {
                ctx.eval::<(), _>(r#"globalThis.agentsso = {};"#)?;
                let agentsso: Object<'_> = ctx.globals().get("agentsso")?;
                register(ctx, &agentsso).expect("deprecated::register");

                // Strict-mode assignment throws TypeError. We wrap in
                // try/catch to observe the throw without propagating.
                let caught: bool = ctx.eval(
                    r#"
                    "use strict";
                    let threw = false;
                    try { agentsso.deprecated.foo = "bar"; }
                    catch (e) { threw = (e instanceof TypeError); }
                    threw
                    "#,
                )?;
                assert!(caught, "strict-mode write to frozen namespace must throw TypeError");

                Ok::<(), crate::PluginError>(())
            })
            .expect("with_context");
    }
}
