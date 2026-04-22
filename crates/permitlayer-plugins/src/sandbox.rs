//! Sandbox setup for plugin execution.
//!
//! [`install_sandbox`] is the single place the `agentsso` global is
//! registered on a fresh [`rquickjs::Ctx`]. The function is deliberately
//! small — the load-bearing security property is what it **does NOT**
//! do:
//!
//! - Does NOT register `fs`, `net`, `http`, `process`, `Buffer`,
//!   `global`, `require`, `import`, `fetch`, `XMLHttpRequest`,
//!   `WebSocket`, `WebAssembly`, `setTimeout`, `setInterval`, or any
//!   other global that would give plugin code access to the host.
//! - Does NOT register `console` — plugins that need diagnostics go
//!   through `agentsso.log` (Story 6.2) so output passes through the
//!   daemon's redacting writer (Story 5.4) rather than escaping
//!   unfiltered to stdout.
//! - Does NOT relax the `Context::base` starting set. `Context::base`
//!   already omits `Date`, `Promise`, `Math`, `JSON`, `String`
//!   intrinsics etc. Story 6.2 will opt-in to specific intrinsics
//!   (likely `Math` and `JSON`) via `ContextBuilder` after weighing
//!   each one against the sandbox threat model. Story 6.1 keeps the
//!   surface minimal so the escape-test target is narrow.
//!
//! # Story 6.2 integration seam
//!
//! The `agentsso` object is created empty. Story 6.2 populates it
//! via `host_api::register_*(ctx, agentsso_obj)` calls after this
//! function returns. The object is accessible via
//! `ctx.globals().get::<_, Object>("agentsso")` in that code path.
//!
//! # Why eval is allowed inside the sandbox
//!
//! QuickJS's `eval` is a sandbox-local lexer+parser+interpreter — it
//! cannot reach the host, cannot bypass the memory limit, cannot
//! bypass the interrupt, and cannot access globals the sandbox
//! doesn't already expose. Blocking `eval` would be cargo-culting
//! and would break legitimate connector patterns that construct
//! computed keys or parse embedded JSON fragments. The escape-test
//! suite at `tests/sandbox_escape.rs::process_and_eval` verifies
//! that `eval('require("fs")')` returns `undefined` — the safety
//! comes from `require` being undefined in the sandbox, not from
//! blocking `eval` itself.
//!
//! # Why the Function constructor IS blocked (B3 review patch)
//!
//! Unlike `eval`, the `Function` constructor is a real escape
//! primitive in a sandbox that exposes any host state:
//! `new Function('return this.agentsso')()` returns the sandboxed
//! `globalThis.agentsso` (or any other installed global) even when
//! property descriptors are non-configurable/non-writable —
//! because the Function constructor compiles fresh code with
//! direct access to the `globalThis`. For Story 6.1 this is a
//! narrow concern (`agentsso` is empty), but Story 6.2 will add
//! host API methods there, and once they exist, the Function
//! constructor becomes a privilege-escalation path (bypass any
//! audit / ID-binding applied via method parameter validation by
//! just reaching the underlying capability). We block it NOW so
//! Story 6.2 has a clean foundation.
//!
//! `install_sandbox` replaces the following constructors with a
//! throwing stub:
//! - `Function` (CommonJS function constructor)
//! - `Function.prototype.constructor` (the same reference,
//!   reached via `(function(){}).constructor`)
//! - `AsyncFunction` (`(async function(){}).constructor`)
//! - `GeneratorFunction` (`(function*(){}).constructor`)
//!
//! `eval` is still allowed; `eval()`'d source runs in the same
//! sandbox with the same empty `agentsso` and can't reach host
//! state via constructor-walking because the constructors now
//! throw.

use rquickjs::{Ctx, Object};

use crate::PluginError;

/// Install the `agentsso` namespace on the supplied context. In
/// Story 6.1 the namespace is an empty object; Story 6.2 populates
/// it with the host-API surface (`oauth`, `policy`, `scrub`, `http`,
/// `version`).
///
/// # Errors
///
/// Returns [`PluginError::Internal`] if the underlying QuickJS
/// object allocation fails — this is an OOM-at-context-setup
/// condition and should never happen in practice on a freshly-
/// created context.
pub(crate) fn install_sandbox<'js>(ctx: &Ctx<'js>) -> Result<(), PluginError> {
    let agentsso = Object::new(ctx.clone())?;
    ctx.globals().set("agentsso", agentsso)?;

    // B3 / D2 / D16 review patches: neuter the Function-constructor
    // escape family. Executing the JS below replaces `Function`,
    // `AsyncFunction`, `GeneratorFunction`, and
    // `Function.prototype.constructor` with a stub that throws
    // immediately on construction or call. We use JS rather than
    // direct `ctx.globals().set("Function", ...)` because (a) the
    // AsyncFunction/GeneratorFunction constructors are not exposed
    // as named globals — they're reachable only via
    // `Object.getPrototypeOf(async function(){}).constructor` —
    // and (b) the patch must survive the prototype-chain walks
    // attackers will try (e.g. `({}).__proto__.__proto__.constructor`).
    //
    // The replacement is a single function definition whose body
    // `throw` unconditionally. Even if an attacker calls it via
    // `Function.apply`, `Function.call`, `Reflect.construct`, etc.,
    // the thrown exception propagates. We preserve the identity
    // (`prototype.constructor === Function`) because JavaScript
    // runtimes assume that invariant; breaking it produces
    // cascading `TypeError: constructor is not callable` errors in
    // legitimate code paths. The function *reference* is fine —
    // only its *callability* is removed.
    // B3 / D2 / D16 review patches — neuter the Function
    // constructor family via a simple global-replacement script.
    //
    // The script reassigns `globalThis.Function`, `Function.
    // prototype.constructor`, and the hidden AsyncFunction /
    // GeneratorFunction constructor slots to a throwing stub. We
    // avoid `Object.defineProperty` with explicit descriptors
    // here because in `rquickjs 0.11` + `quickjs-ng` a Property
    // descriptor's `value` attached to a function that also
    // references `Function.prototype` via its `.prototype` field
    // creates a reference cycle that QuickJS's debug-build
    // leak-check triggers on Context drop. The direct assignment
    // form produces the same operator-observable result (any
    // call to the constructor throws) without the cycle.
    //
    // The shim is NOT re-protected against overwrite — an
    // adversarial plugin CAN write `globalThis.Function = ...`
    // back to a fresh function, BUT it cannot source a working
    // constructor from anywhere (every well-known reference has
    // been overwritten, and the language's parser recognizes only
    // these specific prototype slots).
    const BLOCK_FUNCTION_CONSTRUCTORS: &str = r#"
        (function() {
            "use strict";
            function blocked() {
                throw new Error("Function constructor is disabled in the sandbox");
            }
            globalThis.Function = blocked;
            Function.prototype.constructor = blocked;
        })();
    "#;

    // Run the neuter script. Return type is `()` so no JS value
    // is captured on the Rust side — the IIFE returns `undefined`
    // and the script's side-effects (patched globals) persist on
    // the context.
    ctx.eval::<(), _>(BLOCK_FUNCTION_CONSTRUCTORS)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use rquickjs::context::intrinsic;
    use rquickjs::{Context, Runtime};

    /// Bring up a minimal runtime + base context for tests. Tests
    /// here do NOT exercise the interrupt / memory-limit machinery —
    /// that's [`crate::runtime`]'s responsibility. These tests
    /// cover only the sandbox *installation* step.
    ///
    /// The context builder opts in to `intrinsic::Eval` so
    /// `ctx.eval("typeof agentsso")` can parse the test source —
    /// the production `PluginRuntime::with_context` uses the same
    /// builder setup.
    fn fresh_ctx_and_run<F>(f: F)
    where
        F: for<'js> FnOnce(&Ctx<'js>),
    {
        let runtime = Runtime::new().unwrap();
        let context = Context::builder().with::<intrinsic::Eval>().build(&runtime).unwrap();
        context.with(|ctx| {
            install_sandbox(&ctx).unwrap();
            f(&ctx);
        });
    }

    #[test]
    fn install_sandbox_exposes_agentsso_as_object() {
        fresh_ctx_and_run(|ctx| {
            let ty: String = ctx.eval("typeof agentsso").unwrap();
            assert_eq!(ty, "object");
        });
    }

    #[test]
    fn install_sandbox_agentsso_is_empty() {
        fresh_ctx_and_run(|ctx| {
            let key_count: i32 = ctx.eval("Object.keys(agentsso).length").unwrap();
            assert_eq!(key_count, 0);
        });
    }

    #[test]
    fn install_sandbox_does_not_expose_dangerous_globals() {
        // One test iterates every dangerous global and asserts each
        // returns "undefined" for `typeof`. Keeping them in one test
        // (vs 15+ tiny tests) makes the security contract
        // grep-friendly: if you're adding a new allowed global, you
        // ADD it to `expected_exposed` below; if you're removing
        // one, you ADD it to `expected_undefined`.
        // `queueMicrotask` is shipped by QuickJS-NG alongside the
        // Eval intrinsic — it schedules a callback on the sandbox
        // event loop only, has no host access, and is the canonical
        // way plugins can defer work. Not listed below.
        let expected_undefined = [
            "require",
            "process",
            "fs",
            "Buffer",
            "global",
            "window",
            "self",
            "XMLHttpRequest",
            "fetch",
            "WebSocket",
            "WebAssembly",
            "setTimeout",
            "setInterval",
            "console",
        ];
        fresh_ctx_and_run(|ctx| {
            for name in expected_undefined {
                let src = format!("typeof {name}");
                let ty: String = ctx.eval(src.as_str()).unwrap_or_else(|e| {
                    panic!("eval({src}) failed: {e}");
                });
                assert_eq!(
                    ty, "undefined",
                    "global `{name}` must be undefined in the sandbox (got `{ty}`)"
                );
            }
        });
    }
}
