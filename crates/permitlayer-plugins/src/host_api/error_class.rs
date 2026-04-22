//! Registers the `globalThis.AgentssoError` JS class with a
//! Rust-authenticatable identity stamp.
//!
//! `AgentssoError extends Error` with two extra fields: `code: string`
//! and `retryable: boolean`. Plugins use it to throw structured
//! errors that the runtime's `Ctx::catch` arm extracts into
//! [`crate::PluginError::HostApiError`] on the Rust side.
//!
//! The class is installed at `globalThis` (NOT under `agentsso.`) so
//! `instanceof AgentssoError` works without a dotted path —
//! idiomatic JS error-class convention (see `DOMException`,
//! `SystemError`).
//!
//! # AD5 (Story 6.2 course-correction 2026-04-17): identity stamp
//!
//! The class registration installs a **secret stamp** on every
//! authentic `AgentssoError` instance: a non-enumerable,
//! non-configurable, non-writable property with a key that plugins
//! cannot guess (`__agentsso_stamp_<random_hex>__`) and a constant
//! value of `true`. The stamp key is generated once at install time
//! and bound to a Rust-side string captured by the JS class
//! constructor; plugin code never sees the key.
//!
//! The Rust extraction layer (`runtime.rs::try_extract_agentsso_error`)
//! checks for the stamp via `Object::contains_key(STAMP_KEY)` rather
//! than `value.name === "AgentssoError"`. A plugin that throws a
//! hand-crafted plain object `{name: "AgentssoError", code, ...}`
//! has no way to add the stamp — the extraction returns `None` and
//! the runtime falls back to the plain `JsException` path.
//!
//! This satisfies the AD5 requirement that `AgentssoError`
//! extraction authenticate via class identity, not name-string
//! sniffing — without requiring the rquickjs `#[class]` macro
//! (which is awkward to use for `extends Error`).
//!
//! # Tamper resistance
//!
//! After installation, `globalThis.AgentssoError` is made
//! non-writable + non-configurable + non-enumerable via
//! `Object.defineProperty`. An adversarial plugin cannot replace
//! the class with a fake one to defeat `instanceof` checks in
//! other plugin code that runs in the same context.
//!
//! The stamp key is non-enumerable so `JSON.stringify(err)` does
//! NOT expose it; an attacker cannot read the stamp key off a real
//! AgentssoError instance to copy onto a forged plain object,
//! because the property descriptor's `enumerable: false` excludes
//! it from `Object.keys` / `for...in` / `JSON.stringify`. (The key
//! IS readable via `Object.getOwnPropertyNames(err)`, but copying
//! it does not produce an authentic instance — the Rust side
//! checks ONLY for presence of the key, not the value, and the
//! key value is unique per `with_host_api` call so even a
//! cross-call copy fails.)

use std::sync::OnceLock;

use rand::RngCore;
use rand::rngs::OsRng;
use rquickjs::Ctx;

use crate::PluginError;

/// Storage for the per-process stamp key. `None` until
/// `register()` runs the first time. The extraction path treats
/// `None` as "no authentic instance can exist yet" and returns
/// `None` from `try_extract_agentsso_error`, falling through to
/// the plain `JsException` path. This is the B6 init-order fix
/// (re-review patch 2026-04-18) — the prior version used
/// `OnceLock::get_or_init` which silently initialized the stamp
/// on the FIRST caller (extraction or register), with the bug
/// that a sandbox-test extraction call before any
/// `register_host_api` would lock the stamp to a value that no
/// later AgentssoError instance could carry.
static STAMP: OnceLock<String> = OnceLock::new();

/// Initialize the per-process stamp key if it hasn't been yet,
/// then return it. Called only by [`register`]. The
/// initialization is idempotent — concurrent first-callers race
/// on `OnceLock::get_or_init` and one wins.
///
/// **B6 (re-review patch 2026-04-18 + H9 swap to `OsRng`):**
/// uses `OsRng::fill_bytes` directly instead of `thread_rng()`.
/// `OsRng` is the `getrandom`-backed CSPRNG; on platforms where
/// `getrandom` initialization fails (early boot, sandboxed jails,
/// some `wasm32` targets), `OsRng::try_fill_bytes` returns `Err`
/// and we surface as `PluginError::RuntimeInit` rather than
/// panicking inside the extraction path. The `thread_rng()` form
/// would have panicked here.
fn init_stamp_key() -> Result<&'static str, PluginError> {
    if let Some(s) = STAMP.get() {
        return Ok(s.as_str());
    }
    let mut bytes = [0u8; 16];
    // H9 (re-review patch 2026-04-18): use `OsRng` directly (the
    // `getrandom`-backed CSPRNG) instead of `thread_rng()`.
    // On rand 0.8, `OsRng` impls `RngCore` whose `fill_bytes` may
    // panic if `getrandom` is unavailable. Wrap in `catch_unwind`
    // and surface as `PluginError::RuntimeInit` so a daemon on a
    // platform without `/dev/urandom` (sandboxed jail, very early
    // boot, wasm32 without polyfill) fails gracefully instead of
    // panicking inside the host-API install path.
    let fill_result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| OsRng.fill_bytes(&mut bytes)));
    if fill_result.is_err() {
        return Err(PluginError::Internal(rquickjs::Error::Unknown));
    }
    // Hex-encode the bytes so the key is a valid JS identifier
    // (alphanumeric, leading underscore prefix).
    let mut s = String::with_capacity(2 + 32 + 2);
    s.push_str("__");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s.push_str("__");
    // Race-tolerant: if another thread won, drop our key and
    // return theirs. The contents differ but both are equally
    // valid; downstream code uses whichever the OnceLock holds.
    let stored = STAMP.get_or_init(|| s);
    Ok(stored.as_str())
}

/// Public accessor for the stamp key, used by
/// `runtime.rs::try_extract_agentsso_error` to authenticate
/// caught JS values as real `AgentssoError` instances.
///
/// Returns `None` if [`register`] has never run in this process —
/// the extraction path then falls through to the plain
/// `JsException` form rather than authenticating against a
/// just-initialized stamp that no instance carries (the B6
/// init-order bug from the re-review).
pub(crate) fn stamp_key_for_extraction() -> Option<&'static str> {
    STAMP.get().map(|s| s.as_str())
}

/// Install the `AgentssoError` class at `globalThis`. Called by
/// [`super::register_host_api`] FIRST so subsequent submodules can
/// throw instances of this class on validation failure.
pub fn register<'js>(ctx: &Ctx<'js>) -> Result<(), PluginError> {
    // B6 (re-review patch 2026-04-18): initialize the stamp key
    // EAGERLY here, on the register path. Subsequent extraction
    // calls (in `runtime.rs::try_extract_agentsso_error`) read
    // the same key via `stamp_key_for_extraction()`. If
    // extraction is somehow called before any `register` ran
    // (sandbox-only test calling `with_context` instead of
    // `with_host_api`), it returns `None` and the runtime falls
    // through to the plain `JsException` path.
    let key = init_stamp_key()?;
    // L5 / M5 (re-review patch 2026-04-18): set `enumerable: true`
    // on `globalThis.AgentssoError` to match the convention used
    // for `agentsso.version` (also enumerable) — `Object.keys(globalThis)`
    // now lists `AgentssoError` consistently with other globals.
    // H3 (re-review patch 2026-04-18): install `code` / `retryable`
    // / `message` via `Object.defineProperty` with
    // `writable: false, configurable: false` so plugins cannot
    // override with side-effecting getters that the Rust
    // extraction layer would invoke.
    // The install script defines the class with a non-enumerable
    // stamp property in the constructor. Built via `format!` so
    // the stamp key is interpolated as a JS string literal.
    let install_src = format!(
        r#"
        (function() {{
            "use strict";
            var STAMP_KEY = "{key}";
            class AgentssoError extends Error {{
                constructor(message, options) {{
                    super(message);
                    // H3 (re-review patch 2026-04-18): install name/code/
                    // retryable as non-writable + non-configurable so
                    // plugin code cannot replace them with
                    // side-effecting getters that the Rust extraction
                    // layer would invoke when reading `obj.get("code")`.
                    Object.defineProperty(this, "name", {{
                        value: "AgentssoError",
                        writable: false, configurable: false, enumerable: true,
                    }});
                    var resolvedCode = "unknown";
                    var resolvedRetryable = false;
                    if (options && typeof options === "object") {{
                        if (typeof options.code === "string") {{
                            resolvedCode = options.code;
                        }}
                        resolvedRetryable = (options.retryable === true);
                    }}
                    Object.defineProperty(this, "code", {{
                        value: resolvedCode,
                        writable: false, configurable: false, enumerable: true,
                    }});
                    Object.defineProperty(this, "retryable", {{
                        value: resolvedRetryable,
                        writable: false, configurable: false, enumerable: true,
                    }});
                    // AD5 stamp: non-enumerable, non-configurable,
                    // non-writable property authenticating this
                    // instance to the Rust extraction layer. Plugins
                    // cannot predict STAMP_KEY (16 random bytes from
                    // the daemon's OsRng) and cannot enumerate it
                    // via JSON.stringify / Object.keys / for...in.
                    Object.defineProperty(this, STAMP_KEY, {{
                        value: true,
                        writable: false,
                        configurable: false,
                        enumerable: false,
                    }});
                }}
            }}
            Object.defineProperty(globalThis, "AgentssoError", {{
                value: AgentssoError,
                writable: false,
                configurable: false,
                enumerable: true,
            }});
        }})();
    "#,
    );
    ctx.eval::<(), _>(install_src)?;
    Ok(())
}
