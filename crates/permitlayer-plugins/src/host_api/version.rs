//! `agentsso.version` (read-only string property) +
//! `agentsso.versionMeetsRequirement(req: string) -> boolean`.
//!
//! Plugins use these to feature-detect across host API versions.
//! The version constant is the [`super::HOST_API_VERSION`] value;
//! the property is non-writable + non-configurable so adversarial
//! plugins cannot monkey-patch it to deceive other plugins or
//! observers.
//!
//! `versionMeetsRequirement` accepts only the `">=MAJOR.MINOR"`
//! shape at 1.0.0. Full semver ranges are out of scope; if plugins
//! need them, they can pull `HOST_API_VERSION` and run their own
//! comparator. Throws `AgentssoError { code:
//! "version.malformed_requirement" }` on bad input.

use rquickjs::function::{Constructor, Func, MutFn};
use rquickjs::{Ctx, Object, Value};

// Re-import discipline note: `Value` is used inside the closure-
// returning fallible block in `throw_agentsso_error`. Don't strip it.

use super::HOST_API_VERSION;
use crate::PluginError;
use crate::host_api::HostApiError;
use crate::host_api::services::{HostApiErrorCode, HostCode};

/// Install `agentsso.version` (data-property) and
/// `agentsso.versionMeetsRequirement` (function).
///
/// `version::register` does NOT take `services` — version reading
/// requires no host state. Other `register` functions in this
/// module tree do.
pub fn register<'js>(ctx: &Ctx<'js>, agentsso: &Object<'js>) -> Result<(), PluginError> {
    install_version_property(ctx, agentsso)?;
    install_meets_requirement(ctx, agentsso)?;
    Ok(())
}

/// Install `agentsso.version` as a non-writable, non-configurable
/// data property via `Object.defineProperty`.
fn install_version_property<'js>(
    ctx: &Ctx<'js>,
    _agentsso: &Object<'js>,
) -> Result<(), PluginError> {
    // We use `ctx.eval` rather than the rquickjs `Object::set`
    // because `set` produces a writable + configurable property by
    // default, and the rquickjs 0.11 surface doesn't expose
    // `Object.defineProperty` directly. Running a tiny IIFE keeps
    // the property descriptor exactly to the AC #2 shape:
    //   {value: HOST_API_VERSION, writable: false,
    //    configurable: false, enumerable: true}
    // `serde_json::to_string` of a `&str` is infallible — but the
    // signature returns `Result`, so we use a `match` rather than
    // `expect()` to keep clippy's `expect_used` lint quiet. The
    // `Err` arm is unreachable in practice; if it ever fires, fall
    // back to a literal-quoted string with manual escaping (which
    // for `1.0.0` is identical to the JSON encoding anyway).
    let version_literal = match serde_json::to_string(HOST_API_VERSION) {
        Ok(s) => s,
        Err(_) => format!("\"{HOST_API_VERSION}\""),
    };
    let install_src = format!(
        r#"
            Object.defineProperty(globalThis.agentsso, "version", {{
                value: {version_literal},
                writable: false,
                configurable: false,
                enumerable: true,
            }});
        "#,
    );
    ctx.eval::<(), _>(install_src)?;
    Ok(())
}

/// Install `agentsso.versionMeetsRequirement(req: string) -> bool`.
///
/// Parses `req` as `">=MAJOR.MINOR"` (e.g. `">=1.0"`, `">=1.1"`).
/// Returns `true` iff the host's `(MAJOR, MINOR)` tuple is >=
/// the requested one (patch + pre-release qualifiers IGNORED, so
/// `">=1.0"` matches `"1.0.0-rc.1"` per AC #3 implementation note).
/// Throws `AgentssoError {code: "version.malformed_requirement"}`
/// on parse failure.
///
/// **Supported shapes (1.0):**
/// - `">=MAJOR.MINOR"` — only this exact form.
///
/// **Rejected shapes (predictable failure beats silent acceptance):**
/// - `">=MAJOR.MINOR.PATCH"` — patch-level requirements rejected;
///   if a plugin needs patch-level checks, read `agentsso.version`
///   directly and parse with their own comparator.
/// - `">MAJOR.MINOR"` / `"<=..."` / `"^..."` / `"~..."` — only `>=`
///   supported at 1.0.
/// - `">=+1.0"` / `">=01.0"` — leading-sign and leading-zero forms.
///
/// **Whitespace tolerance:** Unicode-aware via `char::is_whitespace`
/// (NBSP, zero-width space, etc. trimmed correctly).
///
/// 1.x can extend the parser additively per `#[non_exhaustive]`
/// `HostApiErrorCode`.
fn install_meets_requirement<'js>(
    _ctx: &Ctx<'js>,
    agentsso: &Object<'js>,
) -> Result<(), PluginError> {
    // Capture the host-API version once outside the closure so the
    // FnMut doesn't allocate a new `Version` per call. Parse failure
    // is impossible in practice — `host_api/mod.rs::tests::host_api_version_parses_as_semver`
    // locks the constant — but we fall back to `0.0.0` rather than
    // `expect()` to avoid a clippy warning AND to keep the runtime
    // graceful in the impossible case.
    let host_version =
        semver::Version::parse(HOST_API_VERSION).unwrap_or_else(|_| semver::Version::new(0, 0, 0));
    // AC #3 (Story 6.2 course-correction implementation note):
    // compare on (major, minor) tuple only — IGNORE patch and
    // pre-release qualifiers. Per semver, `1.0.0-rc.1 < 1.0.0`,
    // which would cause `versionMeetsRequirement(">=1.0")` to
    // return false on an rc build — surprising for plugin authors
    // who think of "1.0" as "the 1.0 line including rcs." The
    // (major, minor)-only compare honors that intuition.
    let host_major = host_version.major;
    let host_minor = host_version.minor;
    let closure = move |ctx: Ctx<'js>, req: String| -> rquickjs::Result<bool> {
        match parse_requirement(&req) {
            Ok((major, minor)) => Ok((host_major, host_minor) >= (major, minor)),
            Err(_) => {
                // Throw an `AgentssoError` from inside the closure.
                // The runtime's `Ctx::catch` extraction picks this
                // up as `PluginError::HostApiError`.
                Err(throw_agentsso_error(
                    &ctx,
                    HostApiError::new(
                        HostApiErrorCode::Host(HostCode::VersionMalformedRequirement),
                        false,
                        format!(
                            "versionMeetsRequirement requires `>=MAJOR.MINOR` shape; got `{req}`"
                        ),
                    ),
                ))
            }
        }
    };
    agentsso.set("versionMeetsRequirement", Func::from(MutFn::new(closure)))?;
    Ok(())
}

/// Parse a `">=MAJOR.MINOR"` requirement string. Whitespace
/// tolerant (Unicode-aware). Returns `Err` for any other shape.
///
/// **H14 (re-review patch 2026-04-18):** `req.trim()` only trims
/// ASCII whitespace; switched to `trim_matches(char::is_whitespace)`
/// which trims Unicode whitespace (NBSP, zero-width space, etc.)
/// — defense against copy-paste from docs that contain
/// invisible non-breaking spaces.
///
/// **H14 also:** reject leading zeros (`>=01.0`) — undocumented
/// form silently accepted by `u64::parse`. Predictable failure
/// beats silent acceptance.
fn parse_requirement(req: &str) -> Result<(u64, u64), ()> {
    let trimmed = req.trim_matches(char::is_whitespace);
    let rest = trimmed.strip_prefix(">=").ok_or(())?.trim_start_matches(char::is_whitespace);
    let (major_str, minor_str) = rest.split_once('.').ok_or(())?;
    // Reject extra dots so `">=1.0.0"` doesn't sneak through with
    // patch silently dropped (predictable failure beats silent
    // truncation).
    if minor_str.contains('.') {
        return Err(());
    }
    // H15 review patch (original): reject leading `+`.
    if major_str.starts_with('+') || minor_str.starts_with('+') {
        return Err(());
    }
    // H14 (re-review patch 2026-04-18): reject leading zeros.
    // `"01".parse::<u64>()` succeeds; `>=01.0` is not the shape
    // we advertise.
    if (major_str.len() > 1 && major_str.starts_with('0'))
        || (minor_str.len() > 1 && minor_str.starts_with('0'))
    {
        return Err(());
    }
    let major: u64 = major_str.parse().map_err(|_| ())?;
    let minor: u64 = minor_str.parse().map_err(|_| ())?;
    Ok((major, minor))
}

/// Construct an `AgentssoError` JS instance from a Rust
/// [`HostApiError`] and throw it. Returns `Err(rquickjs::Error)`
/// after the throw so the calling closure short-circuits.
///
/// Used by every host-API submodule to surface validation failures
/// uniformly — keeps the throw machinery in one place so the
/// extraction path (in `runtime.rs`'s `Ctx::catch` arm) only has
/// one shape to recognize.
pub(crate) fn throw_agentsso_error<'js>(ctx: &Ctx<'js>, err: HostApiError) -> rquickjs::Error {
    // Build `new AgentssoError(message, {code, retryable})` and
    // throw it. `globalThis.AgentssoError` is installed by
    // `error_class::register` FIRST in `register_host_api`, so by
    // the time any other host-API closure runs, the constructor is
    // available.
    //
    // If anything in the construction path itself fails (which
    // would only happen with an extreme allocator failure or a
    // tampered context), fall back to throwing a plain `Error` —
    // operators see SOMETHING in the rejection rather than a
    // silent allocator panic.
    let result = (|| -> rquickjs::Result<Value<'js>> {
        let constructor: Constructor<'js> = ctx.globals().get("AgentssoError")?;
        let options = Object::new(ctx.clone())?;
        options.set("code", err.code.to_string())?;
        options.set("retryable", err.retryable)?;
        constructor.construct((err.message.clone(), options))
    })();
    match result {
        Ok(instance) => ctx.throw(instance),
        Err(_) => {
            rquickjs::Exception::throw_internal(ctx, &format!("[{}] {}", err.code, err.message))
        }
    }
}
