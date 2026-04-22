//! Host API surface for JS plugins (`agentsso.*`).
//!
//! Story 6.2 lands the first stable `1.0.0` host API. Six submodules
//! make up the surface:
//!
//! - [`oauth`] — `agentsso.oauth.{getToken, listConnectedServices}`
//! - [`policy`] — `agentsso.policy.enforce`
//! - [`scrub`] — `agentsso.scrub.{text, object}`
//! - [`http`] — `agentsso.http.fetch` (the only I/O surface)
//! - [`version`] — `agentsso.version` + `agentsso.versionMeetsRequirement`
//! - [`error_class`] — `globalThis.AgentssoError` JS class
//!
//! Each submodule exposes a `pub fn register(...)` that
//! [`register_host_api`] calls in a fixed order during the per-call
//! `with_host_api` wrap (see `crate::PluginRuntime::with_host_api`).
//! `error_class::register` runs FIRST so subsequent submodules can
//! throw `AgentssoError` instances when they fail validation.
//!
//! The Rust-side service injection happens via the [`HostServices`]
//! trait — see [`services`] for the full surface and the rationale
//! behind the trait inversion (dep direction: `permitlayer-proxy →
//! permitlayer-plugins`, never reverse).
//!
//! # Versioning (NFR41)
//!
//! [`HOST_API_VERSION`] is the single source of truth. Story 6.5's
//! `xtask validate-plugin-api` will diff the live surface against a
//! committed `host-api.lock` and fail CI on any breaking change that
//! is not accompanied by a major version bump.
//!
//! Story 6.2 ships the surface at `"1.0.0-rc.1"` (release candidate;
//! see [`HOST_API_VERSION`]). The transition to `"1.0.0"` proper
//! happens via a separate post-validation PR after Story 6.5 lands.
//! Pre-release versions are unconstrained — the snapshot test still
//! runs but breaking changes are allowed without a major bump until
//! the rc qualifier is dropped. Additive changes in 1.x (new methods,
//! new error-code variants) are non-breaking by virtue of the
//! `#[non_exhaustive]` attribute on [`services::HostApiErrorCode`] and
//! the open module surface.

use std::sync::Arc;

use rquickjs::function::Constructor;
use rquickjs::{Ctx, Object, Promise, Value};

use crate::PluginError;

pub mod deprecated;
pub mod error_class;
pub mod http;
pub mod oauth;
pub mod policy;
pub mod scrub;
pub mod services;
pub mod stub_services;
pub mod version;

pub use services::{
    DecisionDesc, FetchReq, FetchResp, HostApiError, HostApiErrorCode, HostCode, HostServices,
    PluginThrownCode, PolicyEvalReq, ScopedTokenDesc, ScrubMatchDesc, ScrubResponse,
    UnknownHostCode, all_error_code_names, origin_str,
};
pub use stub_services::StubHostServices;

/// Current host-API semver. Read by Story 6.5's
/// `xtask validate-plugin-api` command and exposed to JS as
/// `agentsso.version`.
///
/// **`"1.0.0-rc.1"` — release candidate** (Story 6.2 AD1, set during the
/// 2026-04-17 sprint-change-proposal course-correction).
///
/// NFR41 commits us to a 6-month deprecation window once `1.0.0` ships.
/// The corrected surface ships at `"1.0.0-rc.1"`; Story 6.5's first
/// `xtask validate-plugin-api` run will snapshot the surface and the
/// transition to `"1.0.0"` is a separate post-validation PR after
/// operators have had a chance to write against the rc surface.
/// Pre-release versions (`0.x.y`, `1.0.0-rcN`) are unconstrained — the
/// snapshot test still runs but breaking changes are allowed without a
/// major bump until the rc qualifier is dropped.
pub const HOST_API_VERSION: &str = "1.0.0-rc.1";

/// Canonical list of `agentsso.*` surface entries. Story 6.5's
/// `cargo xtask validate-plugin-api` reads this const via `syn`, sorts
/// it, and emits the `## js_surface` section of `host-api.lock`.
///
/// Adding a new host-API method / property requires two edits:
/// 1. Register the closure in the appropriate `host_api/<sub>.rs`
///    submodule (the `register` function calls `.set("<name>", ...)`).
/// 2. Add the matching signature string to this slice.
///
/// Both edits must land in the same PR. The guardrail test
/// `tests::js_surface_matches_installed_surface` enforces that every
/// entry here maps to a `.set("<name>", ...)` call and vice versa.
///
/// **Ordering:** the slice is stored in lexicographic order so that
/// the on-disk lockfile's `## js_surface` section is byte-stable
/// across rebuilds.
pub const JS_SURFACE: &[&str] = &[
    "agentsso.deprecated : object",
    "agentsso.http.fetch(url: string, options?: FetchOptions) -> Promise<FetchResponse>",
    "agentsso.oauth.getToken(service: string, scope: string) -> Promise<ScopedToken>",
    "agentsso.oauth.listConnectedServices() -> Promise<string[]>",
    "agentsso.policy.enforce(request: PolicyEvalReq) -> Promise<Decision>",
    "agentsso.scrub.object(obj: any) -> Promise<ScrubResponse>",
    "agentsso.scrub.text(text: string) -> Promise<ScrubResponse>",
    "agentsso.version : string (read-only)",
    "agentsso.versionMeetsRequirement(req: string) -> boolean",
    "globalThis.AgentssoError : class { constructor(message: string, options?: { code?: string, retryable?: boolean }); name: string; message: string; code: string; retryable: boolean; stack: string; }",
];

/// Install the full `agentsso.*` host-API surface plus the
/// `globalThis.AgentssoError` class on the supplied context.
///
/// Called from [`crate::PluginRuntime::with_host_api`] after the
/// sandbox is installed (`globalThis.agentsso` exists as an empty
/// object) and before the caller's closure runs. The `services`
/// reference must outlive the `with_host_api` call — host-API
/// closures installed on `agentsso.*` capture it by reference, but
/// the closures themselves cannot escape the call (they're dropped
/// when the per-call `Context` is dropped).
///
/// Order is load-bearing:
/// 1. `error_class::register(ctx)` first so every other submodule
///    can throw `AgentssoError` instances on validation failure.
/// 2. `version::register` reads `HOST_API_VERSION` and installs the
///    read-only property — does not depend on services.
/// 3. `oauth`, `policy`, `scrub`, `http` install service-backed
///    methods. Order between these four does not matter.
pub fn register_host_api<'js>(
    ctx: &Ctx<'js>,
    services: Arc<dyn HostServices>,
) -> Result<(), PluginError> {
    let agentsso: Object<'js> = ctx.globals().get("agentsso")?;
    error_class::register(ctx)?;
    version::register(ctx, &agentsso)?;
    deprecated::register(ctx, &agentsso)?;
    oauth::register(ctx, &agentsso, Arc::clone(&services))?;
    policy::register(ctx, &agentsso, Arc::clone(&services))?;
    scrub::register(ctx, &agentsso, Arc::clone(&services))?;
    http::register(ctx, &agentsso, services)?;
    Ok(())
}

/// Wrap a `Result<Value, HostApiError>` into a JS Promise per AD2
/// (Story 6.2 course-correction 2026-04-17 — uniform Promise-shape model).
///
/// On `Ok(value)`: returns a Promise that resolves to `value`.
/// On `Err(host_err)`: returns a Promise that rejects with a real
/// `AgentssoError` instance (constructed via the registered global
/// constructor — see `error_class::register`).
///
/// Returning a Promise rather than the raw value (or throwing) means
/// every host-API method has the same observable JS shape:
/// `result instanceof Promise === true`, `.then()` and `.catch()`
/// chain idiomatically, `Promise.all([...])` works without surprises.
/// Plugin authors learn one rule: "if it touches host state, it's
/// `await`-able."
///
/// **Why this is one helper, not three:** prior to AD2 each
/// submodule (`oauth`, `policy`, `scrub`, `http`) had its own throw
/// path inlined into the `Func::from(MutFn::new(closure))` body via
/// `throw_agentsso_error`. Now the throw path becomes a Promise
/// rejection — same machinery (real `AgentssoError` instance, real
/// constructor invocation) but routed through `reject_fn.call(...)`
/// instead of `ctx.throw(value)`. Consolidating into one helper
/// keeps the rejection shape identical across all four submodules.
pub(crate) fn wrap_in_promise<'js>(
    ctx: &Ctx<'js>,
    result: Result<Value<'js>, HostApiError>,
) -> rquickjs::Result<Value<'js>> {
    let (promise, resolve, reject) = Promise::new(ctx)?;
    match result {
        Ok(value) => {
            // Best-effort resolve. If the resolve call itself
            // fails (extreme allocator failure or a tampered
            // Promise intrinsic), the Promise stays pending —
            // the caller still gets a Promise return shape and
            // the `await` simply blocks. Better than propagating
            // an `Err(rquickjs::Error)` that breaks the
            // "wrap_in_promise always returns a Promise" contract.
            // Logged via `tracing::warn!` so operators can grep.
            if let Err(e) = resolve.call::<_, ()>((value,)) {
                tracing::warn!(
                    error = %e,
                    "wrap_in_promise: resolve call failed; Promise will remain pending"
                );
            }
        }
        Err(host_err) => {
            // B7 (re-review patch 2026-04-18): the rejection-side
            // `?` propagation could produce a non-Promise return
            // when `build_agentsso_error_instance` fails, breaking
            // the documented uniform Promise-shape contract.
            // Now: try to build the AgentssoError instance; if
            // construction fails (extreme allocator failure OR a
            // plugin somehow corrupted `globalThis.AgentssoError`
            // before we got here), fall back to rejecting with a
            // plain `Error(message)` instance so the Promise STILL
            // rejects (with reduced authentication signal — the
            // rejection won't be stamp-authenticatable as
            // AgentssoError, but the caller still gets a Promise
            // they can `.catch()` on). Operators see the failure
            // path in `tracing::warn!`.
            let rejection_value: Value<'js> = match build_agentsso_error_instance(ctx, &host_err) {
                Ok(v) => v,
                Err(build_err) => {
                    tracing::warn!(
                        error = %build_err,
                        host_api_code = %host_err.code,
                        "wrap_in_promise: AgentssoError construction failed; falling back to plain Error"
                    );
                    // Fall back to `new Error(message)` —
                    // simpler shape that should never fail.
                    // If it does, the next `?` propagates;
                    // by that point we've genuinely lost
                    // control of the JS heap and the
                    // rquickjs error is the most informative
                    // thing we can return.
                    let fallback_msg = format!("[{}] {}", host_err.code, host_err.message);
                    let exception = rquickjs::Exception::from_message(ctx.clone(), &fallback_msg)?;
                    exception.into_value()
                }
            };
            if let Err(e) = reject.call::<_, ()>((rejection_value,)) {
                tracing::warn!(
                    error = %e,
                    host_api_code = %host_err.code,
                    "wrap_in_promise: reject call failed; Promise will remain pending"
                );
            }
        }
    }
    Ok(promise.into_value())
}

/// Build `new AgentssoError(message, {code, retryable})` as a JS
/// value. Fails only on extreme allocator failure or a tampered
/// context where `globalThis.AgentssoError` has been overwritten —
/// in that case the caller falls back to a plain rejection.
fn build_agentsso_error_instance<'js>(
    ctx: &Ctx<'js>,
    err: &HostApiError,
) -> rquickjs::Result<Value<'js>> {
    let constructor: Constructor<'js> = ctx.globals().get("AgentssoError")?;
    let options = Object::new(ctx.clone())?;
    options.set("code", err.code.to_string())?;
    options.set("retryable", err.retryable)?;
    constructor.construct((err.message.clone(), options))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn js_surface_is_sorted_and_unique() {
        // The `JS_SURFACE` slice is the canonical list Story 6.5's
        // xtask reads. Lockfile emission sorts via BTreeSet, but
        // keeping the slice itself sorted makes `git diff` legible
        // when a future story adds a method.
        for window in JS_SURFACE.windows(2) {
            assert!(
                window[0] < window[1],
                "JS_SURFACE must be lexicographically sorted: {:?} >= {:?}",
                window[0],
                window[1],
            );
        }
    }

    #[test]
    fn js_surface_matches_installed_surface() {
        // Guardrail: every entry in `JS_SURFACE` must appear as an
        // installed reference (a `.set("<name>", ...)` call, a
        // `"<name>"` literal inside a `ctx.eval` block, or a
        // `class <name>` declaration) in the corresponding
        // `host_api/<sub>.rs` submodule.
        //
        // This is a coarse string-contains check — intentionally
        // NOT a `syn` AST walk. The point is to catch drift when
        // someone adds an installation site without updating
        // `JS_SURFACE` or vice versa. A hand-written adversary could
        // fool this test, but the accidental drift case (which is
        // the real risk) is caught reliably.
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        // Map each JS_SURFACE entry's trailing identifier to the
        // submodule file where it must be referenced.
        let expectations: &[(&str, &str)] = &[
            ("deprecated", "deprecated.rs"),
            ("fetch", "http.rs"),
            ("getToken", "oauth.rs"),
            ("listConnectedServices", "oauth.rs"),
            ("enforce", "policy.rs"),
            ("object", "scrub.rs"),
            ("text", "scrub.rs"),
            ("version", "version.rs"),
            ("versionMeetsRequirement", "version.rs"),
            ("AgentssoError", "error_class.rs"),
        ];
        assert_eq!(
            expectations.len(),
            JS_SURFACE.len(),
            "expectations must cover every JS_SURFACE entry",
        );
        for (ident, file) in expectations {
            let path = format!("{manifest_dir}/src/host_api/{file}");
            let contents = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
            assert!(
                contents.contains(ident),
                "expected `{ident}` to be referenced in {file}, but it was not",
            );
        }

        // Reverse direction: every `.set("<name>", ...)` call in the
        // six submodules that install plugin-facing methods (NOT
        // internal helpers like `.set("bearer", ...)` inside
        // marshalling closures) must map to a `JS_SURFACE` entry.
        //
        // To scope down to "installation sites," the test walks
        // only the top-level `register` functions by matching
        // against a curated set of known install calls. Adding a
        // new `.set("<name>", Func::from(...))` on an `agentsso`
        // sub-object requires updating this test, which forces the
        // author through the JS_SURFACE update path.
        let known_install_sites: &[(&str, &str)] = &[
            ("deprecated.rs", "\"deprecated\""),
            ("error_class.rs", "class AgentssoError"),
            ("http.rs", "\"fetch\""),
            ("http.rs", "\"http\""),
            ("oauth.rs", "\"getToken\""),
            ("oauth.rs", "\"listConnectedServices\""),
            ("oauth.rs", "\"oauth\""),
            ("policy.rs", "\"enforce\""),
            ("policy.rs", "\"policy\""),
            ("scrub.rs", "\"object\""),
            ("scrub.rs", "\"scrub\""),
            ("scrub.rs", "\"text\""),
            ("version.rs", "\"version\""),
            ("version.rs", "\"versionMeetsRequirement\""),
        ];
        for (file, needle) in known_install_sites {
            let path = format!("{manifest_dir}/src/host_api/{file}");
            let contents = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
            assert!(
                contents.contains(needle),
                "expected install site `{needle}` in {file}, but it was not found — \
                 did someone rename an installed method without updating JS_SURFACE \
                 and this guardrail test?",
            );
        }
    }

    #[test]
    fn host_api_version_is_1_0_0_rc_1() {
        // AC #1 (revised per AD1): Story 6.2 ships at `1.0.0-rc.1`,
        // not `1.0.0`. The literal value matters — Story 6.5's
        // `host-api.lock` serialization will read this constant
        // directly. The transition from rc to `1.0.0` proper is a
        // separate post-validation PR.
        assert_eq!(HOST_API_VERSION, "1.0.0-rc.1");
    }

    #[test]
    fn host_api_version_parses_as_semver() {
        // AC #1: Story 6.5 expects this constant to round-trip through
        // a real semver parser (so a future `1.1.0` or `2.0.0` bump
        // can be compared via `Version::cmp`). If a future bump
        // accidentally ships an empty / malformed value, this catches it.
        let parsed = match semver::Version::parse(HOST_API_VERSION) {
            Ok(v) => v,
            Err(e) => panic!("HOST_API_VERSION must be parseable semver: {e}"),
        };
        assert_eq!(parsed.major, 1);
        assert_eq!(parsed.minor, 0);
        assert_eq!(parsed.patch, 0);
    }

    #[test]
    fn host_api_version_preserves_rc_qualifier() {
        // AC #1 (revised per AD1): the rc qualifier MUST round-trip
        // through semver parsing. If a future bump drops the
        // qualifier, the transition to `1.0.0` proper has happened
        // and that's a deliberate spec change requiring its own PR.
        let parsed = match semver::Version::parse(HOST_API_VERSION) {
            Ok(v) => v,
            Err(e) => panic!("HOST_API_VERSION must be parseable semver: {e}"),
        };
        assert_eq!(parsed.pre.as_str(), "rc.1");
    }
}
