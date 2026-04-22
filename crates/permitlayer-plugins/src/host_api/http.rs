//! `agentsso.http.fetch(url, options) -> Promise<{status, headers, body}>`.
//!
//! THE ONLY I/O surface plugins have. Implemented in two layers:
//!
//! 1. **JS marshalling (this file)** — validates URL scheme, builds
//!    a [`FetchReq`], delegates to `services.fetch(...)`, marshals
//!    the [`FetchResp`] back to JS as `{status, headers, body}`.
//!    Per AC #16, the marshaller does NOT do the policy check
//!    itself — that's the [`HostServices::fetch`] impl's
//!    responsibility (the impl has direct access to the policy
//!    engine via the proxy's `Arc<PolicySet>`). Marshaller
//!    responsibilities: scheme allowlist + User-Agent injection +
//!    timeout defaults + plugin-name CRLF guard.
//! 2. **Proxy-side dispatch (Story 6.2 Task 7,
//!    `permitlayer-proxy::plugin_host_services`)** — runs the
//!    policy gate, executes the reqwest call inside `block_on`,
//!    returns the response.
//!
//! **AD2 (Story 6.2 course-correction 2026-04-17 — uniform Promise-shape
//! model):** the method returns a real Promise (via `wrap_in_promise`),
//! not a plain Object. `result instanceof Promise === true`; `.then()`
//! and `.catch()` chain idiomatically; `Promise.all([...])` works.
//!
//! Defaults:
//! - `method = "GET"`
//! - `timeoutMs = 30000` (clamped to `[1, 30000]`); negative or
//!   non-finite values reject with `HttpInvalidTimeout` per H9
//! - `headers = { "User-Agent": "permitlayer-plugin/<HOST_API_VERSION>/<connector>" }`
//!   (appended to plugin-provided UA when present, prepended otherwise)
//!
//! Allowed URL schemes: `http:` and `https:`. Everything else
//! (`file:`, `data:`, `ws:`, `javascript:`, etc.) rejects with
//! `AgentssoError {code: "http.scheme_not_allowed"}` BEFORE
//! attempting the policy check (cheap reject, smaller cost on
//! abuse).
//!
//! # CRLF injection guard (Story 6.2 review finding B3)
//!
//! `current_plugin_name()` is interpolated into the User-Agent
//! header value. If a plugin name contains CR (`\r`), LF (`\n`), or
//! NUL (`\0`), the marshaller rejects with `HttpHeaderInjection`
//! before the request can be dispatched. Defense in depth: the
//! loader (Story 6.3) is expected to validate plugin names at load
//! time, but we re-check here so a future loader bug can't escalate
//! to header injection.
//!
//! # Header value type-strictness (Story 6.2 review finding H5)
//!
//! `headers: { "X-Count": 5 }` (numeric value) rejects with
//! `HttpHeaderTypeMismatch`. Previously such values were silently
//! dropped; now plugin authors get a clear signal.

use rquickjs::function::{Func, MutFn, Opt};
use rquickjs::{Ctx, Object, TypedArray, Value};

use crate::PluginError;
use crate::host_api::services::{HostApiErrorCode, HostCode};
use crate::host_api::{
    FetchReq, FetchResp, HOST_API_VERSION, HostApiError, HostServices, wrap_in_promise,
};

/// Maximum per-request timeout in milliseconds. Plugins cannot
/// override this upward — anything above this gets clamped down
/// (silently). 30 s is the AR ceiling for upstream API calls.
const TIMEOUT_MAX_MS: u64 = 30_000;

/// Default per-request timeout when the plugin omits `timeoutMs`.
const TIMEOUT_DEFAULT_MS: u64 = 30_000;

/// Validate that a string contains no characters that would enable
/// HTTP header injection (CR, LF, NUL, or any control character
/// 0x00-0x1F except HTAB 0x09). Used at `register` time on the
/// plugin name (Story 6.2 review finding B3).
fn contains_header_unsafe_char(s: &str) -> bool {
    s.bytes().any(|b| matches!(b, 0x00..=0x08 | 0x0A..=0x1F))
}

/// Install `agentsso.http.fetch`.
pub fn register<'js>(
    ctx: &Ctx<'js>,
    agentsso: &Object<'js>,
    services: std::sync::Arc<dyn HostServices>,
) -> Result<(), PluginError> {
    // AD3: trait returns `String` directly.
    let plugin_name = services.current_plugin_name();
    // B3 review patch — fail-fast at register time if the loader
    // somehow gave us a control-character-bearing plugin name. The
    // loader (Story 6.3) is expected to validate at load time, but
    // we re-check so a future loader bug can't escalate.
    // B1 (re-review patch 2026-04-18): renamed from `plugin_name_safe`
    // — the variable's value tracks UNSAFENESS (true ⇒ unsafe),
    // not safety. Logic was correct; only the name was misleading.
    let plugin_name_unsafe = contains_header_unsafe_char(&plugin_name);
    let http = Object::new(ctx.clone())?;

    let closure = move |ctx: Ctx<'js>,
                        url: String,
                        options: Opt<Object<'js>>|
          -> rquickjs::Result<Value<'js>> {
        let options = options.0;

        // 0. Plugin-name safety guard (Story 6.2 review finding B3).
        // If `current_plugin_name()` was unsafe at register time,
        // reject every fetch attempt. Documented as a deliberate
        // belt-and-suspenders defense — the loader (Story 6.3) is
        // the primary enforcement point.
        if plugin_name_unsafe {
            return wrap_in_promise(
                &ctx,
                Err(HostApiError::new(
                    HostApiErrorCode::Host(HostCode::HttpHeaderInjection),
                    false,
                    format!(
                        "plugin name `{plugin_name}` contains control characters that could \
                         enable HTTP header injection; rejecting all fetch attempts"
                    ),
                )),
            );
        }

        // 1. Scheme check — cheap reject before any allocation /
        //    policy evaluation. URL parsing happens here too;
        //    invalid URLs round-trip through `scheme_not_allowed`.
        let parsed = match url::Url::parse(&url) {
            Ok(u) => u,
            Err(_) => {
                return wrap_in_promise(
                    &ctx,
                    Err(HostApiError::new(
                        HostApiErrorCode::Host(HostCode::HttpSchemeNotAllowed),
                        false,
                        format!("agentsso.http.fetch URL is malformed: {url}"),
                    )),
                );
            }
        };
        match parsed.scheme() {
            "http" | "https" => {}
            other => {
                return wrap_in_promise(
                    &ctx,
                    Err(HostApiError::new(
                        HostApiErrorCode::Host(HostCode::HttpSchemeNotAllowed),
                        false,
                        format!(
                            "agentsso.http.fetch only supports http/https; got `{other}` for {url}"
                        ),
                    )),
                );
            }
        }

        // 2. Build the FetchReq. Defaults: GET, no body, 30s timeout.
        let mut method = "GET".to_owned();
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut body: Option<Vec<u8>> = None;
        let mut timeout_ms: u64 = TIMEOUT_DEFAULT_MS;

        if let Some(opts) = options {
            if let Ok(Some(m)) = opts.get::<_, Option<String>>("method") {
                method = m.to_uppercase();
            }
            if let Ok(Some(headers_obj)) = opts.get::<_, Option<Object<'js>>>("headers") {
                // H5 review patch: type-strict header iteration.
                // Iterate via `Value` and reject any value that
                // isn't a string. Previously `props::<String,
                // String>()` silently dropped non-string values.
                let prop_iter = headers_obj.props::<String, Value<'js>>();
                for kv in prop_iter {
                    let (k, v) = match kv {
                        Ok(pair) => pair,
                        Err(e) => {
                            return wrap_in_promise(
                                &ctx,
                                Err(HostApiError::new(
                                    HostApiErrorCode::Host(HostCode::HttpHeaderTypeMismatch),
                                    false,
                                    format!("agentsso.http.fetch headers iteration failed: {e}"),
                                )),
                            );
                        }
                    };
                    let v_str = match v.as_string() {
                        Some(s) => match s.to_string() {
                            Ok(decoded) => decoded,
                            Err(e) => {
                                return wrap_in_promise(
                                    &ctx,
                                    Err(HostApiError::new(
                                        HostApiErrorCode::Host(HostCode::HttpHeaderTypeMismatch),
                                        false,
                                        format!(
                                            "agentsso.http.fetch header `{k}` value decode failed: {e}"
                                        ),
                                    )),
                                );
                            }
                        },
                        None => {
                            return wrap_in_promise(
                                &ctx,
                                Err(HostApiError::new(
                                    HostApiErrorCode::Host(HostCode::HttpHeaderTypeMismatch),
                                    false,
                                    format!(
                                        "agentsso.http.fetch header `{k}` value must be a string; \
                                         got non-string"
                                    ),
                                )),
                            );
                        }
                    };
                    // H2 (re-review patch 2026-04-18): defense-in-depth
                    // CRLF/control-char check on plugin-supplied
                    // header values (the B3 guard only covered the
                    // plugin name). A plugin sending
                    // `headers: {"X-Custom": "value\r\nInjected: true"}`
                    // gets rejected before reqwest's HeaderValue
                    // construction has a chance to do its own
                    // (similar) check.
                    if contains_header_unsafe_char(&k) || contains_header_unsafe_char(&v_str) {
                        return wrap_in_promise(
                            &ctx,
                            Err(HostApiError::new(
                                HostApiErrorCode::Host(HostCode::HttpHeaderInjection),
                                false,
                                format!(
                                    "agentsso.http.fetch header `{k}` contains control characters \
                                     that could enable HTTP header injection"
                                ),
                            )),
                        );
                    }
                    headers.push((k, v_str));
                }
            }
            if let Ok(Some(body_value)) = opts.get::<_, Option<Value<'js>>>("body") {
                body = match extract_body_bytes(&body_value) {
                    Ok(b) => b,
                    Err(host_err) => return wrap_in_promise(&ctx, Err(host_err)),
                };
            }
            // H9 review patch: timeoutMs validation. Negative,
            // NaN, Infinity, or zero values reject with
            // HttpInvalidTimeout instead of silently falling
            // through to the 30s default.
            if let Ok(Some(t)) = opts.get::<_, Option<f64>>("timeoutMs") {
                if !t.is_finite() || t <= 0.0 {
                    return wrap_in_promise(
                        &ctx,
                        Err(HostApiError::new(
                            HostApiErrorCode::Host(HostCode::HttpInvalidTimeout),
                            false,
                            format!(
                                "agentsso.http.fetch timeoutMs must be a positive finite number; \
                                 got {t}"
                            ),
                        )),
                    );
                }
                timeout_ms = (t as u64).clamp(1, TIMEOUT_MAX_MS);
            }
        }

        // 3. User-Agent injection. Case-insensitive lookup; if the
        //    plugin provided one, prepend it before the permitlayer
        //    suffix; otherwise inject ours alone.
        let permitlayer_ua = format!("permitlayer-plugin/{HOST_API_VERSION}/{plugin_name}");
        let existing_ua_idx =
            headers.iter().position(|(k, _)| k.eq_ignore_ascii_case("user-agent"));
        match existing_ua_idx {
            Some(i) => {
                let existing = std::mem::take(&mut headers[i].1);
                headers[i] = ("User-Agent".to_owned(), format!("{existing} {permitlayer_ua}"));
            }
            None => {
                headers.push(("User-Agent".to_owned(), permitlayer_ua));
            }
        }

        let req = FetchReq { method, url, headers, body, timeout_ms };

        // 4. Delegate to the HostServices impl. Per Task 7's CALLING
        //    CONTRACT, the impl runs the policy gate AND the reqwest
        //    call (synchronously via internal block_on). The
        //    marshaller is service-agnostic past this point.
        let result: Result<Value<'js>, HostApiError> = match services.fetch(req) {
            Ok(resp) => marshal_fetch_resp(&ctx, resp).map_err(|e| {
                HostApiError::new(
                    HostApiErrorCode::Host(HostCode::HttpUpstreamUnreachable),
                    true,
                    format!("fetch response marshalling failed: {e}"),
                )
            }),
            Err(host_err) => Err(host_err),
        };
        wrap_in_promise(&ctx, result)
    };
    http.set("fetch", Func::from(MutFn::new(closure)))?;
    agentsso.set("http", http)?;
    Ok(())
}

/// Extract bytes from a JS body argument. Accepts string and
/// `Uint8Array`; everything else returns `Err(HostApiError)`.
/// Maximum request body size in bytes. Plugins posting larger
/// bodies are rejected with `HttpRequestTooLarge` before
/// dispatch. Matches the response-side cap to prevent plugins
/// from OOMing the daemon by posting multi-GB bodies. H7
/// (re-review patch 2026-04-18).
const MAX_REQUEST_BYTES: usize = 10 * 1024 * 1024;

/// Extract bytes from a JS body argument with size cap.
///
/// **H1 (re-review patch 2026-04-18):** body type/decode errors
/// now return `HttpInvalidBody` instead of being misrouted
/// through `HttpHeaderTypeMismatch`.
///
/// **H7 (re-review patch 2026-04-18):** caps body size at
/// `MAX_REQUEST_BYTES` (10 MiB); larger bodies reject with
/// `HttpRequestTooLarge`.
fn extract_body_bytes<'js>(value: &Value<'js>) -> Result<Option<Vec<u8>>, HostApiError> {
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    if let Some(s) = value.as_string() {
        let decoded = s.to_string().map_err(|e| {
            HostApiError::new(
                HostApiErrorCode::Host(HostCode::HttpInvalidBody),
                false,
                format!("agentsso.http.fetch body string decode failed: {e}"),
            )
        })?;
        if decoded.len() > MAX_REQUEST_BYTES {
            return Err(HostApiError::new(
                HostApiErrorCode::Host(HostCode::HttpRequestTooLarge),
                false,
                format!(
                    "request body of {} bytes exceeds {MAX_REQUEST_BYTES}-byte limit",
                    decoded.len()
                ),
            ));
        }
        return Ok(Some(decoded.into_bytes()));
    }
    if let Ok(typed) = TypedArray::<u8>::from_value(value.clone()) {
        let bytes = typed.as_bytes().ok_or_else(|| {
            HostApiError::new(
                HostApiErrorCode::Host(HostCode::HttpInvalidBody),
                false,
                "agentsso.http.fetch body Uint8Array has detached buffer".to_owned(),
            )
        })?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(HostApiError::new(
                HostApiErrorCode::Host(HostCode::HttpRequestTooLarge),
                false,
                format!(
                    "request body of {} bytes exceeds {MAX_REQUEST_BYTES}-byte limit",
                    bytes.len()
                ),
            ));
        }
        return Ok(Some(bytes.to_vec()));
    }
    // Could be ArrayBuffer or other binary types; not supported at 1.0.
    Err(HostApiError::new(
        HostApiErrorCode::Host(HostCode::HttpInvalidBody),
        false,
        "agentsso.http.fetch body must be a string or Uint8Array".to_owned(),
    ))
}

/// Marshal a [`FetchResp`] into the JS-side `{status, headers, body}`
/// shape.
fn marshal_fetch_resp<'js>(ctx: &Ctx<'js>, resp: FetchResp) -> rquickjs::Result<Value<'js>> {
    let obj = Object::new(ctx.clone())?;
    obj.set("status", resp.status as f64)?;

    // Headers as an object; if the upstream sent the same header
    // twice (legal per HTTP/1.1), the LATER value wins (deterministic).
    // Story 6.2 review finding M6 documented Set-Cookie collapse;
    // 1.x can add an array-of-arrays representation.
    let headers = Object::new(ctx.clone())?;
    for (k, v) in resp.headers {
        headers.set(k.to_lowercase(), v)?;
    }
    obj.set("headers", headers)?;
    obj.set("body", resp.body_utf8_lossy)?;
    Ok(obj.into_value())
}
