//! `agentsso.scrub.{text, object}` — content scrubbing.
//!
//! - `agentsso.scrub.text(text: string) -> Promise<{output, matches}>`
//! - `agentsso.scrub.object(obj) -> Promise<{output, matches}>`
//!   (recurses on string values; non-string values pass through unchanged)
//!
//! **AD2 (Story 6.2 course-correction 2026-04-17 — uniform Promise-shape
//! model):** both methods return real Promises (via `wrap_in_promise`).
//! Scrub is sync internally today, but future 1.x may add user-defined
//! scrub rules with cold-cache costs OR an LLM-scrub second-pass option,
//! both of which are async. Uniform Promise shape now means no breaking
//! change later. Plugin-author cost: one `await` per call.
//!
//! # Recursion depth limit (Story 6.2 review finding H11)
//!
//! `scrub.object` caps recursion at 128 levels. Cyclic objects or
//! pathologically-deep trees throw `AgentssoError {code:
//! "scrub.invalid_input", message: "object depth exceeds 128"}`
//! instead of blowing the native stack.
//!
//! # Span semantics (M3 re-review patch 2026-04-18)
//!
//! For `scrub.text`, the returned `matches[i].span.offset` is the
//! byte offset of the placeholder within the returned `output`
//! string — i.e. `output[span.offset .. span.offset + span.length]`
//! IS the placeholder text.
//!
//! For `scrub.object`, the returned `matches[]` carries entries
//! from EVERY string leaf scrubbed during the recursion, in
//! depth-first document order. The `span.offset` field is
//! **per-leaf relative**, not relative to any global "output"
//! string — there is no single output string for an object,
//! only the rebuilt nested structure. Plugins consuming
//! `scrub.object` matches MUST match on `ruleId` rather than
//! treating `span.offset` as an index into a flat output.
//! A future 1.x may add a `path: string[]` field to disambiguate
//! per-leaf matches.
//!
//! # Object-property enumeration (Story 6.2 review finding H13)
//!
//! `scrub.object` walks ONLY own-enumerable string-keyed properties.
//! Symbol-keyed properties, non-enumerable data-properties, and
//! inherited (prototype-chain) properties are silently dropped from
//! the output. Plugins that need to scrub Symbol-keyed values must
//! marshal manually before calling `scrub.object`. Documented here
//! and in the `agentsso.scrub.object` JSDoc shipped with Story 6.4's
//! scaffolder.

use rquickjs::function::{Func, MutFn};
use rquickjs::{Array, Ctx, Object, Value};

use crate::PluginError;
use crate::host_api::services::{HostApiErrorCode, HostCode, ScrubMatchDesc};
use crate::host_api::{HostApiError, HostServices, wrap_in_promise};

/// Maximum nesting depth for `scrub.object` recursion. Prevents
/// stack overflow on cyclic / pathologically-deep input
/// (Story 6.2 review finding H11).
const SCRUB_OBJECT_MAX_DEPTH: usize = 128;

/// Install `agentsso.scrub.text` and `agentsso.scrub.object`.
pub fn register<'js>(
    ctx: &Ctx<'js>,
    agentsso: &Object<'js>,
    services: std::sync::Arc<dyn HostServices>,
) -> Result<(), PluginError> {
    let scrub = Object::new(ctx.clone())?;

    install_text(ctx, &scrub, std::sync::Arc::clone(&services))?;
    install_object(ctx, &scrub, services)?;

    agentsso.set("scrub", scrub)?;
    Ok(())
}

fn install_text<'js>(
    _ctx: &Ctx<'js>,
    scrub: &Object<'js>,
    services: std::sync::Arc<dyn HostServices>,
) -> Result<(), PluginError> {
    let closure = move |ctx: Ctx<'js>, input: Value<'js>| -> rquickjs::Result<Value<'js>> {
        let result: Result<Value<'js>, HostApiError> = match coerce_to_string(&input) {
            Ok(input_str) => match services.scrub_text(&input_str) {
                Ok(resp) => marshal_scrub_response(&ctx, resp).map_err(|e| {
                    HostApiError::new(
                        HostApiErrorCode::Host(HostCode::ScrubInvalidInput),
                        false,
                        format!("scrub response marshalling failed: {e}"),
                    )
                }),
                Err(host_err) => Err(host_err),
            },
            Err(host_err) => Err(host_err),
        };
        wrap_in_promise(&ctx, result)
    };
    scrub.set("text", Func::from(MutFn::new(closure)))?;
    Ok(())
}

fn install_object<'js>(
    _ctx: &Ctx<'js>,
    scrub: &Object<'js>,
    services: std::sync::Arc<dyn HostServices>,
) -> Result<(), PluginError> {
    let closure = move |ctx: Ctx<'js>, input: Value<'js>| -> rquickjs::Result<Value<'js>> {
        let mut all_matches: Vec<ScrubMatchDesc> = Vec::new();
        let mut path_stack: Vec<String> = Vec::new();
        let result: Result<Value<'js>, HostApiError> = match recurse_and_scrub(
            &ctx,
            services.as_ref(),
            input,
            &mut all_matches,
            &mut path_stack,
            0,
        ) {
            Ok(scrubbed) => {
                // Object construction + matches-array build all
                // succeed-or-fail together; on failure we surface
                // a single HostApiError for Promise rejection.
                let build_result: rquickjs::Result<Object<'js>> = (|| {
                    let obj = Object::new(ctx.clone())?;
                    obj.set("output", scrubbed)?;
                    let matches_arr = Array::new(ctx.clone())?;
                    for (i, m) in all_matches.into_iter().enumerate() {
                        matches_arr.set(i, scrub_match_to_js(&ctx, m)?)?;
                    }
                    obj.set("matches", matches_arr)?;
                    Ok(obj)
                })();
                match build_result {
                    Ok(obj) => Ok(obj.into_value()),
                    Err(e) => Err(HostApiError::new(
                        HostApiErrorCode::Host(HostCode::ScrubInvalidInput),
                        false,
                        format!("scrub object marshalling failed: {e}"),
                    )),
                }
            }
            Err(host_err) => Err(host_err),
        };
        wrap_in_promise(&ctx, result)
    };
    scrub.set("object", Func::from(MutFn::new(closure)))?;
    Ok(())
}

/// Coerce a JS value to a string per `String(x)` semantics.
/// Numbers / booleans coerce; `undefined` / `null` / objects return
/// `Err(HostApiError {code: "scrub.invalid_input"})`.
///
/// **AD2:** returns `Result<String, HostApiError>` (Rust-side); the
/// caller wraps via `wrap_in_promise` for Promise-rejection delivery
/// to JS.
fn coerce_to_string<'js>(input: &Value<'js>) -> Result<String, HostApiError> {
    if let Some(s) = input.as_string() {
        // Already a string — direct path, no coercion needed.
        return s.to_string().map_err(|e| {
            // UTF-16-surrogate failure path (Story 6.2 review finding M14):
            // `rquickjs::String::to_string` requires valid UTF-8; an
            // unpaired surrogate fails. Surface as a typed HostApiError
            // rather than the generic rquickjs::Error path.
            HostApiError::new(
                HostApiErrorCode::Host(HostCode::ScrubInvalidInput),
                false,
                format!(
                    "scrub input contained invalid UTF-8 (likely an unpaired UTF-16 surrogate): {e}"
                ),
            )
        });
    }
    if input.is_number()
        && let Some(n) = input.as_number()
    {
        return Ok(format_js_number(n));
    }
    if input.is_bool()
        && let Some(b) = input.as_bool()
    {
        return Ok(if b { "true".to_owned() } else { "false".to_owned() });
    }
    Err(HostApiError::new(
        HostApiErrorCode::Host(HostCode::ScrubInvalidInput),
        false,
        "agentsso.scrub.text requires a string, number, or boolean argument",
    ))
}

/// Format a JS number per `String(n)` semantics — integers without
/// decimals, otherwise the default `f64` Display. Good enough for
/// the test cases AC #14 covers; doesn't try to match every quirk
/// of ECMAScript's `ToString(Number)` (e.g. `1e21` notation
/// thresholds — Story 6.2 review finding M11 documented this).
fn format_js_number(n: f64) -> String {
    if n.is_nan() {
        return "NaN".to_owned();
    }
    if n.is_infinite() {
        return if n > 0.0 { "Infinity".to_owned() } else { "-Infinity".to_owned() };
    }
    if n == 0.0 {
        return "0".to_owned();
    }
    if n.fract() == 0.0 && n.abs() < 1e16 {
        return format!("{}", n as i64);
    }
    format!("{n}")
}

/// Marshal a [`crate::host_api::ScrubResponse`] into the JS-side
/// `{output: string, matches: ScrubMatch[]}` shape.
fn marshal_scrub_response<'js>(
    ctx: &Ctx<'js>,
    resp: crate::host_api::ScrubResponse,
) -> rquickjs::Result<Value<'js>> {
    let result = Object::new(ctx.clone())?;
    result.set("output", resp.output)?;
    let matches_arr = Array::new(ctx.clone())?;
    for (i, m) in resp.matches.into_iter().enumerate() {
        matches_arr.set(i, scrub_match_to_js(ctx, m)?)?;
    }
    result.set("matches", matches_arr)?;
    Ok(result.into_value())
}

fn scrub_match_to_js<'js>(ctx: &Ctx<'js>, m: ScrubMatchDesc) -> rquickjs::Result<Value<'js>> {
    let obj = Object::new(ctx.clone())?;
    obj.set("ruleId", m.rule_id)?;
    obj.set("placeholder", m.placeholder)?;
    let span = Object::new(ctx.clone())?;
    span.set("offset", m.span_offset as f64)?;
    span.set("length", m.span_length as f64)?;
    obj.set("span", span)?;
    Ok(obj.into_value())
}

/// Maximum byte length for the path string in a depth-limit error.
/// Truncated with `…` suffix if exceeded.
const SCRUB_PATH_MAX_CHARS: usize = 128;

/// Format the path stack into a dotted-bracket path string.
/// Object keys prefix with `.`; array indices render as `[N]`.
/// Truncates at segment boundaries when the path exceeds `SCRUB_PATH_MAX_CHARS`,
/// appending `…` so the truncation point is always between segments, not mid-key.
fn format_path(path: &[String]) -> String {
    let mut out = String::new();
    for segment in path {
        if out.chars().count() + segment.chars().count() > SCRUB_PATH_MAX_CHARS {
            out.push('…');
            return out;
        }
        out.push_str(segment);
    }
    out
}

/// Recurse on a JS value, scrubbing every string leaf. Returns the
/// scrubbed value and accumulates per-match metadata into
/// `all_matches` in document-order.
///
/// **Depth-limited per Story 6.2 review finding H11:** caps at
/// `SCRUB_OBJECT_MAX_DEPTH` (128). Cyclic objects or
/// pathologically-deep trees return
/// `Err(HostApiError {code: "scrub.invalid_input"})` instead of
/// blowing the native stack.
///
/// **Story 8.3 AC #4:** threads `path_stack` to include the failing
/// key path in the depth-limit error message.
fn recurse_and_scrub<'js>(
    ctx: &Ctx<'js>,
    services: &dyn HostServices,
    value: Value<'js>,
    all_matches: &mut Vec<ScrubMatchDesc>,
    path_stack: &mut Vec<String>,
    depth: usize,
) -> Result<Value<'js>, HostApiError> {
    if depth >= SCRUB_OBJECT_MAX_DEPTH {
        let path = format_path(path_stack);
        return Err(HostApiError::new(
            HostApiErrorCode::Host(HostCode::ScrubInvalidInput),
            false,
            format!(
                "agentsso.scrub.object recursion exceeds maximum depth {SCRUB_OBJECT_MAX_DEPTH} at path {path} (cyclic object or pathologically-deep tree)"
            ),
        ));
    }
    if let Some(string_val) = value.as_string() {
        let s = string_val.to_string().map_err(|e| {
            HostApiError::new(
                HostApiErrorCode::Host(HostCode::ScrubInvalidInput),
                false,
                format!("scrub.object encountered invalid UTF-8 in a string leaf: {e}"),
            )
        })?;
        match services.scrub_text(&s) {
            Ok(mut resp) => {
                all_matches.append(&mut resp.matches);
                let scrubbed_str =
                    rquickjs::String::from_str(ctx.clone(), &resp.output).map_err(|e| {
                        HostApiError::new(
                            HostApiErrorCode::Host(HostCode::ScrubInvalidInput),
                            false,
                            format!("scrub.object output string allocation failed: {e}"),
                        )
                    })?;
                Ok(scrubbed_str.into_value())
            }
            Err(host_err) => Err(host_err),
        }
    } else if let Some(arr) = value.as_array() {
        let new_arr = Array::new(ctx.clone()).map_err(|e| {
            HostApiError::new(
                HostApiErrorCode::Host(HostCode::ScrubInvalidInput),
                false,
                format!("scrub.object array construction failed: {e}"),
            )
        })?;
        // H17 (re-review patch 2026-04-18): iterate via
        // `arr.iter()` which snapshots the array's elements
        // once. The prior `for i in 0..arr.len()` form was
        // TOCTOU-vulnerable: a plugin defining a custom
        // `length` getter via `Object.defineProperty(arr,
        // "length", {get: () => 5})` could cause `arr.len()`
        // and `arr.get(i)` to disagree, producing out-of-bounds
        // `undefined` reads or shape drift. Iterator-based
        // iteration uses QuickJS's own length-snapshot at
        // iteration start.
        for (i, elem_result) in arr.iter::<Value<'js>>().enumerate() {
            let elem = elem_result.map_err(|e| {
                HostApiError::new(
                    HostApiErrorCode::Host(HostCode::ScrubInvalidInput),
                    false,
                    format!("scrub.object array index {i} read failed: {e}"),
                )
            })?;
            path_stack.push(format!("[{i}]"));
            let scrubbed =
                recurse_and_scrub(ctx, services, elem, all_matches, path_stack, depth + 1);
            path_stack.pop();
            let scrubbed = scrubbed?;
            new_arr.set(i, scrubbed).map_err(|e| {
                HostApiError::new(
                    HostApiErrorCode::Host(HostCode::ScrubInvalidInput),
                    false,
                    format!("scrub.object array index {i} write failed: {e}"),
                )
            })?;
        }
        Ok(new_arr.into_value())
    } else if let Some(obj) = value.as_object() {
        let new_obj = Object::new(ctx.clone()).map_err(|e| {
            HostApiError::new(
                HostApiErrorCode::Host(HostCode::ScrubInvalidInput),
                false,
                format!("scrub.object inner-object construction failed: {e}"),
            )
        })?;
        // H13 caveat: `obj.props::<String, Value>()` walks ONLY
        // own-enumerable string-keyed properties. Symbol keys,
        // non-enumerable, and inherited props are silently dropped.
        for kv in obj.props::<String, Value<'js>>() {
            let (k, v) = kv.map_err(|e| {
                HostApiError::new(
                    HostApiErrorCode::Host(HostCode::ScrubInvalidInput),
                    false,
                    format!("scrub.object property iteration failed: {e}"),
                )
            })?;
            path_stack.push(format!(".{k}"));
            let scrubbed = recurse_and_scrub(ctx, services, v, all_matches, path_stack, depth + 1);
            path_stack.pop();
            let scrubbed = scrubbed?;
            new_obj.set(k, scrubbed).map_err(|e| {
                HostApiError::new(
                    HostApiErrorCode::Host(HostCode::ScrubInvalidInput),
                    false,
                    format!("scrub.object property write failed: {e}"),
                )
            })?;
        }
        Ok(new_obj.into_value())
    } else {
        // Numbers, booleans, null, undefined — pass through unchanged.
        Ok(value)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn format_path_empty_returns_empty_string() {
        assert_eq!(format_path(&[]), "");
    }

    #[test]
    fn format_path_object_keys_use_dot_prefix() {
        let path = vec![".response".to_owned(), ".user".to_owned(), ".name".to_owned()];
        assert_eq!(format_path(&path), ".response.user.name");
    }

    #[test]
    fn format_path_array_indices_use_brackets() {
        let path = vec![".items".to_owned(), "[2]".to_owned(), ".id".to_owned()];
        assert_eq!(format_path(&path), ".items[2].id");
    }

    #[test]
    fn format_path_truncates_at_segment_boundary_with_ellipsis() {
        // 4 segments of 51 chars each = 204 total > 128, so truncation applies.
        // Segment-boundary truncation: segments 1+2 = 102 chars fit; segment 3
        // would bring it to 153 > 128, so we emit '…' before segment 3.
        // Result: 102 fitting chars + 1 ellipsis = 103 chars.
        let long_key = "a".repeat(50);
        let path: Vec<String> = (0..4).map(|_| format!(".{long_key}")).collect();
        let result = format_path(&path);
        assert!(result.ends_with('…'), "truncated path must end with …");
        // All chars before the ellipsis must be a prefix of the full path.
        let full: String = path.iter().flat_map(|s| s.chars()).collect();
        let prefix: String = result.chars().take(result.chars().count() - 1).collect();
        assert!(full.starts_with(&prefix), "truncated prefix must be a valid path prefix");
        // The prefix must end at a segment boundary (either at '.' or '[').
        assert!(
            prefix.is_empty() || prefix.ends_with(']') || {
                // ends at end of a segment = last char is alphanumeric or `-`/`_`
                prefix.chars().last().is_some_and(|c| c.is_alphanumeric() || c == '-' || c == '_')
            },
            "truncation must occur at a segment boundary: {prefix:?}"
        );
    }

    #[test]
    fn scrub_object_depth_error_includes_path() {
        use crate::PluginRuntime;
        use crate::host_api::services::{
            DecisionDesc, FetchReq, FetchResp, HostApiError, HostApiErrorCode, HostCode,
            ScopedTokenDesc, ScrubResponse,
        };
        use std::sync::Arc;

        // Minimal stub services — only scrub_text is exercised.
        struct PassThroughServices;
        impl crate::host_api::HostServices for PassThroughServices {
            fn issue_scoped_token(
                &self,
                _s: &str,
                _sc: &str,
            ) -> Result<ScopedTokenDesc, HostApiError> {
                Err(HostApiError::new(
                    HostApiErrorCode::Host(HostCode::OauthUnknownService),
                    false,
                    "stub",
                ))
            }
            fn list_connected_services(&self) -> Result<Vec<String>, HostApiError> {
                Ok(vec![])
            }
            fn evaluate_policy(
                &self,
                _r: crate::host_api::PolicyEvalReq,
            ) -> Result<DecisionDesc, HostApiError> {
                Ok(DecisionDesc::Deny {
                    policy_name: "stub".to_owned(),
                    rule_id: "stub".to_owned(),
                    denied_scope: None,
                    denied_resource: None,
                })
            }
            fn scrub_text(&self, input: &str) -> Result<ScrubResponse, HostApiError> {
                Ok(ScrubResponse { output: input.to_owned(), matches: vec![] })
            }
            fn fetch(&self, _r: FetchReq) -> Result<FetchResp, HostApiError> {
                Err(HostApiError::new(HostApiErrorCode::Host(HostCode::HttpTimeout), false, "stub"))
            }
            fn current_agent_policy_name(&self) -> String {
                "stub".to_owned()
            }
            fn current_plugin_name(&self) -> String {
                "stub".to_owned()
            }
        }

        let rt = PluginRuntime::new_default().expect("runtime");
        let services: Arc<dyn crate::host_api::HostServices> = Arc::new(PassThroughServices);

        // Build a 130-level nested object: `{a: {a: {a: ...}}}`.
        // We generate the JS literal programmatically.
        const DEPTH: usize = 130;
        let open: String = r#"{"a":"#.repeat(DEPTH);
        let close: String = "}".repeat(DEPTH);
        let js_src = format!(
            r#"(async () => {{ try {{ await agentsso.scrub.object({open}"leaf"{close}); return "ok"; }} catch(e) {{ return e.message; }} }})()"#
        );

        let result = rt.with_host_api(&services, |ctx| {
            let raw: rquickjs::Value<'_> = ctx.eval(js_src.as_str())?;
            if let Some(promise) = raw.as_promise() {
                let resolved: String = promise.finish::<String>()?;
                Ok(resolved)
            } else {
                Err(crate::PluginError::JsException { message: "expected promise".to_owned() })
            }
        });

        let msg = result.expect("should succeed (error caught in JS)");
        // Message must contain the path prefix (first few .a.a.a segments).
        assert!(msg.contains(".a.a.a"), "depth error should include path in message; got: {msg}");
        // Message must contain the standard depth text.
        assert!(msg.contains("recursion exceeds maximum depth"), "message: {msg}");
        // Since path is > 128 chars, it must be truncated with ….
        assert!(msg.contains('…'), "long path must be truncated with …; got: {msg}");
    }
}
