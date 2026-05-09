//! Post-consent verification via lightweight read-only test queries.
//!
//! After sealing OAuth tokens, the setup wizard calls [`verify_connection`]
//! to confirm the grant actually works end-to-end. This module lives in
//! `permitlayer-oauth` (not in the daemon) because it is part of the OAuth
//! domain — verifying that the grant produced usable tokens.
//!
//! # Privacy (Story 2.7 Decision 2B; extended Story 7.12)
//!
//! Google API error responses can include user-identifying content:
//! email addresses in `invalid_grant` messages, account IDs, internal
//! service tokens. We DO NOT include the raw error body in the
//! user-facing `reason` field of [`OAuthError::VerificationFailed`] — a
//! failed-setup screenshot shared for troubleshooting would otherwise
//! leak that content. Instead, the body is emitted via
//! `tracing::debug!` under a `permitlayer_oauth::google::verify`
//! target, so operators who need diagnostics can opt in with
//! `RUST_LOG=debug permitlayer_oauth=debug` while normal users see
//! only a status-code-level message.
//!
//! Story 7.12 extends the contract to the parsed
//! [`VerifyReason`](crate::error::VerifyReason) attached to the new
//! `verify_reason` field on `VerificationFailed`: only canonical
//! taxonomy fields (`service`, `project`, `missing_scopes`) flow into
//! the typed reason. The raw body never appears there. The closed
//! whitelist lives in [`parse_verify_403_reason`].

use crate::error::{OAuthError, VerifyReason};

/// Gmail profile API endpoint.
const GMAIL_PROFILE_URL: &str = "https://gmail.googleapis.com/gmail/v1/users/me/profile";
/// Calendar list API endpoint (lightweight read-only check).
const CALENDAR_LIST_URL: &str =
    "https://www.googleapis.com/calendar/v3/users/me/calendarList?maxResults=1";
/// Drive about API endpoint (lightweight read-only check).
const DRIVE_ABOUT_URL: &str = "https://www.googleapis.com/drive/v3/about?fields=user";

/// Build the shared `reqwest::Client` used by every `verify_*` function.
///
/// Connection pool, TLS context, user-agent, and timeout settings are
/// constructed exactly once per call. Wraps any build failure as
/// [`OAuthError::VerificationFailed`].
fn build_verify_client(service: &str) -> Result<reqwest::Client, OAuthError> {
    reqwest::Client::builder()
        .user_agent("agentsso/0.1")
        .timeout(std::time::Duration::from_secs(10))
        // R3-P26 round-3 review: per-read timeout bounds slow-loris
        // chunked-transfer attacks. The overall `timeout` doesn't bound
        // per-chunk wait time, so a hostile upstream that dribbles
        // 1 byte/second can hold the connection for the full 10s
        // overall timeout. The 2s read_timeout interrupts within 2s
        // of any chunk-read stall — and Google's verify endpoints
        // return well under 2s in practice.
        .read_timeout(std::time::Duration::from_secs(2))
        .build()
        .map_err(|e| OAuthError::VerificationFailed {
            service: service.to_owned(),
            reason: "failed to build HTTP client".to_owned(),
            status_code: None,
            verify_reason: None,
            source: Some(Box::new(e)),
        })
}

/// Maximum accepted size of a verify-API response body (P6 — Story 7.12
/// review). Google's verify endpoints return ≤ ~2 KiB legitimately
/// (gmail profile is ~250 bytes, drive about ~1 KiB, calendar list
/// ~2 KiB for 1 calendar). The 64 KiB cap absorbs unexpectedly large
/// error bodies (HTML proxy pages, misconfigured upstreams) without
/// allowing an unbounded body to flood `tracing::debug!` output, the
/// JSON parser's allocator, or operator memory.
const MAX_VERIFY_RESPONSE_BYTES: usize = 65_536;

/// Read up to [`MAX_VERIFY_RESPONSE_BYTES`] from a `reqwest::Response`
/// body, stopping the moment the cap is exceeded (P6 — Story 7.12
/// review). Returns the truncated body string. The cap applies
/// regardless of `Content-Length` (which may be absent or lying); we
/// stream chunks via `Response::chunk` and stop when our own counter
/// trips. Uses `reqwest`'s built-in chunk API rather than
/// `bytes_stream` so we don't introduce a new `futures`/`bytes`
/// workspace dependency.
async fn read_capped_body(mut response: reqwest::Response) -> Result<String, reqwest::Error> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    // R3-P5 round-3 review: track total upstream-sent bytes (including
    // bytes we discarded after the cap-truncation) so the DEBUG log
    // can report the actual wire byte count rather than the post-cap
    // buffered length. Pre-fix `wire_byte_len = buf.len()` was captured
    // AFTER the in-loop truncation and didn't reflect what the upstream
    // actually sent.
    let mut total_wire_bytes: usize = 0;
    while let Some(chunk) = response.chunk().await? {
        total_wire_bytes = total_wire_bytes.saturating_add(chunk.len());
        if buf.len() + chunk.len() > MAX_VERIFY_RESPONSE_BYTES {
            // Truncate at the cap. The body is already known to be
            // hostile-or-buggy beyond this point; we surface what we
            // have so the privacy debug log still gets a sample.
            let remaining = MAX_VERIFY_RESPONSE_BYTES - buf.len();
            buf.extend_from_slice(&chunk[..remaining]);
            // R2-P19 round-2 review: keep the structured `cap` field
            // (consumable by log parsers) and drop the interpolation
            // duplicate from the message string.
            tracing::debug!(
                cap = MAX_VERIFY_RESPONSE_BYTES,
                "verify response body exceeded cap; truncated"
            );
            break;
        }
        buf.extend_from_slice(&chunk);
    }
    // R2-P4 round-2 review: align truncation to a UTF-8 character
    // boundary by walking back from the truncation point until we land
    // at a valid UTF-8 prefix. This avoids inserting U+FFFD at the cap
    // when a multi-byte codepoint straddles `MAX_VERIFY_RESPONSE_BYTES`.
    let buffered_byte_len = buf.len();
    let valid_prefix_len = match std::str::from_utf8(&buf) {
        Ok(_) => buf.len(),
        Err(e) => e.valid_up_to(),
    };
    if valid_prefix_len < buf.len() {
        // Trailing bytes after `valid_prefix_len` are either a partial
        // multi-byte codepoint (truncation-induced) or genuinely
        // non-UTF-8 (binary upstream payload). Drop them — the JSON
        // parser would fail on them anyway, and the DEBUG log still
        // gets the valid prefix.
        buf.truncate(valid_prefix_len);
    }
    if buf.len() < buffered_byte_len {
        // R3-P5 round-3 review: log the TRUE wire byte count (including
        // any bytes discarded by the cap-truncation) AND the buffered
        // byte count so an operator can distinguish "upstream sent N
        // bytes, we capped at the limit" from "upstream sent N bytes,
        // some were non-UTF-8 trailing".
        tracing::debug!(
            total_wire_bytes,
            buffered_byte_len,
            valid_prefix_len = buf.len(),
            "verify response body had non-UTF-8 trailing bytes; trimmed to last valid UTF-8 prefix"
        );
    }
    // The buffer is now guaranteed to be valid UTF-8 (truncated to
    // `valid_prefix_len` above). `from_utf8` consumes the Vec without
    // allocation; the defensive `into_bytes()` recovery is the
    // unreachable branch and only fires if a future change breaks
    // the truncation invariant. R3-P3 round-3 review: pre-fix used
    // `buf.clone()` which doubled peak memory for no benefit.
    Ok(String::from_utf8(buf)
        .unwrap_or_else(|e| String::from_utf8_lossy(&e.into_bytes()).into_owned()))
}

/// Join a base URL with a path, producing a slash-safe URL.
///
/// Handles all four combinations of trailing / leading slashes on
/// `base` and `path`:
///
/// | base         | path  | result      |
/// |--------------|-------|-------------|
/// | `http://x`   | `foo` | `http://x/foo` |
/// | `http://x`   | `/foo`| `http://x/foo` |
/// | `http://x/`  | `foo` | `http://x/foo` |
/// | `http://x/`  | `/foo`| `http://x/foo` |
///
/// We manually normalize rather than using `url::Url::join` because
/// the latter has surprising semantics when the base lacks a trailing
/// slash (it treats the last path segment as a "file" and replaces it),
/// which does not match the caller's intent here (base is always a
/// host, path is always a route).
fn join_verify_url(base: &str, path: &str) -> String {
    let base_trimmed = base.trim_end_matches('/');
    let path_trimmed = path.trim_start_matches('/');
    format!("{base_trimmed}/{path_trimmed}")
}

/// Consume a non-2xx verify response body, log it at DEBUG, and return
/// the parsed [`VerifyReason`] when the status is 403 and the body
/// matches Google's canonical `errdetails` taxonomy.
///
/// **Privacy (Story 2.7 Decision 2B; extended Story 7.12):** the raw
/// body is logged via `tracing::debug!` (operators can opt in with
/// `RUST_LOG=debug permitlayer_oauth=debug`) but is NEVER returned to
/// the caller as a string. The returned `Option<VerifyReason>` carries
/// only the canonical taxonomy fields extracted by
/// [`parse_verify_403_reason`].
///
/// The 403-only gating means non-403 statuses (401, 5xx, transport
/// failures) always return `None` — only the established 403 reason
/// codes are operator-actionable; other statuses fall through to the
/// existing generic remediation message.
async fn consume_verify_error_body(
    response: reqwest::Response,
    service: &str,
    status_code: u16,
    project: Option<&str>,
) -> Option<VerifyReason> {
    // R2-P14 round-2 review: pre-check Content-Length against the cap.
    // If the upstream advertises a body larger than MAX_VERIFY_RESPONSE_BYTES,
    // bail immediately rather than streaming up to the cap (which can
    // waste the full 10s client timeout against a slow-loris upstream).
    // Chunked-transfer paths (no Content-Length) still rely on the cap
    // inside `read_capped_body`.
    if let Some(advertised) = response.content_length()
        && advertised > MAX_VERIFY_RESPONSE_BYTES as u64
    {
        tracing::warn!(
            service,
            status_code,
            content_length = advertised,
            cap = MAX_VERIFY_RESPONSE_BYTES,
            "verify response Content-Length exceeds cap; not reading body"
        );
        return None;
    }
    // P6 round-1 review: cap the body at MAX_VERIFY_RESPONSE_BYTES to
    // bound the cost of the DEBUG log + JSON parse. The pre-fix call
    // `response.text().await` would buffer an arbitrarily large body
    // before we got a chance to inspect it.
    let body = match read_capped_body(response).await {
        Ok(body) => body,
        Err(e) => {
            tracing::debug!(
                service,
                status_code,
                error = %e,
                "failed to read verify response body"
            );
            return None;
        }
    };
    // R2-P10 round-2 review: the typed `verify_reason` field on
    // VerificationFailed is whitelist-bound (see parse_verify_403_reason).
    // This DEBUG log emits the FULL upstream body unchanged — operators
    // on `RUST_LOG=debug permitlayer_oauth=debug` see exactly what they
    // always saw. The privacy contract narrowing applies ONLY to the
    // typed reason crossing into user-facing OAuthError; it does NOT
    // narrow the DEBUG-log payload (which has always carried the full
    // body and remains gated behind RUST_LOG opt-in).
    tracing::debug!(
        service,
        status_code,
        body_len = body.len(),
        body = %body,
        "verify response body (full upstream body — contains potentially sensitive \
         Google API content — gated behind RUST_LOG=debug; not included in user-facing error)"
    );
    if status_code == 403 { parse_verify_403_reason(&body, project) } else { None }
}

/// Maximum accepted byte length for a `metadata.service` value (P2 — Story
/// 7.12 review). Google service identifiers are ≤ 253 bytes per RFC 1035
/// host-name limit (the format is `<short>.googleapis.com`); legitimate
/// values are ≤ 30 bytes in practice. The cap prevents an unbounded
/// upstream value from flooding terminal output or log lines.
const MAX_SERVICE_BYTES: usize = 253;

/// Maximum accepted byte length per scope URI (P4 — Story 7.12 review).
/// OAuth 2 scope URIs are well below this in practice (Google's are
/// ~50 bytes; the longest documented Google API scope is ~80 bytes).
const MAX_SCOPE_BYTES: usize = 256;

/// Validate a Google service identifier from `details[].metadata.service`
/// (P2 — Story 7.12 review). Returns `Some(owned)` if the value matches
/// the canonical `<short>.googleapis.com` shape with a length cap, no
/// control chars, and ASCII-only bytes. Otherwise `None`.
///
/// Privacy contract: this function is the boundary between "Google
/// taxonomy field" and "string interpolated into operator-facing
/// URLs/CLI commands/log lines." A future widening of
/// [`parse_verify_403_reason`] that copies non-canonical fields into a
/// `VerifyReason::ServiceDisabled.service` will fail this validation
/// and produce a `None`, falling back to the generic remediation.
fn validate_service_identifier(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.len() > MAX_SERVICE_BYTES {
        return None;
    }
    // Canonical Google API service identifier: each label between dots
    // matches `[a-z][a-z0-9-]*[a-z0-9]?` (no consecutive hyphens, no
    // leading/trailing hyphen per label) and the full identifier ends
    // in `.googleapis.com`. R2-P8 round-2 review tightened this from
    // the round-1 byte-class check, which accepted pathological forms
    // like `a..googleapis.com` and `a----.googleapis.com`.
    //
    // The byte-class check still rejects whitespace, ANSI escapes,
    // control chars, query-string metacharacters (`?`, `&`, `#`), and
    // shell metacharacters (`;`, `$`, `` ` ``, backslash) — every
    // URL/log/shell-injection vector flagged by round-1 review.
    let bytes = raw.as_bytes();
    if !bytes[0].is_ascii_lowercase() {
        return None;
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'.' || *b == b'-')
    {
        return None;
    }
    // R2-P8: reject consecutive dots and consecutive hyphens. Both are
    // non-canonical for Google service identifiers.
    if raw.contains("..") || raw.contains("--") {
        return None;
    }
    // R2-P8: reject leading-or-trailing hyphen on any label. Split on
    // `.` and check each label for hyphen-on-edge.
    for label in raw.split('.') {
        if label.is_empty() {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
    }
    // MUST end in `.googleapis.com`. Defensive against a future Google
    // rename: if the suffix changes, we drop to the generic remediation
    // rather than synthesizing a wrong URL.
    if !raw.ends_with(".googleapis.com") {
        return None;
    }
    Some(raw.to_owned())
}

/// OIDC standard scopes — opaque tokens (not URLs) defined by OpenID
/// Connect Core 1.0 §5.4 and surfaced by Google alongside its API
/// scopes (R2-P3 round-2 review). The pre-fix R1-P4 validator rejected
/// these because they lack `http(s)://` prefix, dropping the most
/// common consent-flow scope set from `missing_scopes`.
const OIDC_OPAQUE_SCOPES: &[&str] = &["openid", "email", "profile", "address", "phone"];

/// Validate one OAuth scope from `details[].metadata.scope` (R1-P4 +
/// R2-P3 round-2 review). Returns `Some(owned)` for either:
/// - an OIDC opaque scope (`openid`, `email`, `profile`, `address`, `phone`), or
/// - a non-empty ASCII-only HTTP/HTTPS URL within the size cap, no control chars.
///
/// Returns `None` for everything else.
///
/// **R2-P3 round-2 review fix:** the URL-only validator dropped Google's
/// most common consent-flow scope set (`openid email profile`) silently.
/// The OIDC opaque-scope allowlist is the canonical fix; non-allowlist
/// non-URL strings are still rejected (terminal-injection / malformed).
fn validate_scope(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.len() > MAX_SCOPE_BYTES {
        return None;
    }
    // R3-P23 round-3 review: OIDC scope tokens are technically
    // case-sensitive per RFC 6749 §3.3, but Google's documented
    // response is lowercase and a future deviation would silently
    // lose information. Case-insensitive allowlist match + return
    // the lowercased form so downstream rendering is consistent.
    let lower = raw.to_ascii_lowercase();
    if OIDC_OPAQUE_SCOPES.contains(&lower.as_str()) {
        return Some(lower);
    }
    if !(raw.starts_with("https://") || raw.starts_with("http://")) {
        return None;
    }
    let bytes = raw.as_bytes();
    // Reject control chars (< 0x20) and DEL (0x7F) and any non-ASCII.
    // Spaces are also rejected (a single scope must not contain spaces;
    // the splitter already separates on whitespace).
    if bytes.iter().any(|b| *b < 0x21 || *b > 0x7e) {
        return None;
    }
    Some(raw.to_owned())
}

/// Parse a Google API 403 error body into a typed [`VerifyReason`].
///
/// Walks the canonical Google `errdetails` taxonomy:
/// `{ "error": { "details": [ { "reason": "<code>", "metadata": {...} }, ... ] } }`.
///
/// Returns the highest-priority recognized variant and `None` for any
/// malformed, missing, or unrecognized shape. The whitelist of accepted
/// reasons (`SERVICE_DISABLED`, `BILLING_DISABLED`,
/// `ACCESS_TOKEN_SCOPE_INSUFFICIENT`) is the privacy-contract boundary:
/// only fields named in this allowlist (`reason`, `metadata.service`,
/// `metadata.scope`) cross into typed enum data, and each one is
/// shape-validated by [`validate_service_identifier`] /
/// [`validate_scope`] before crossing. All other body content is
/// invisible to callers.
///
/// **P1 (round-1 review fix):** the loop uses `continue` rather than
/// `?` so a leading `Help` / `LocalizedMessage` / `RetryInfo` entry
/// (Google's real responses commonly bundle these in `details[]`) does
/// NOT short-circuit the entire scan — we continue to find the
/// `ErrorInfo` entry that carries `reason`.
///
/// **P7 (round-1 review fix):** when `details[]` carries multiple
/// recognized reasons (Google bundles `BILLING_DISABLED` +
/// `SERVICE_DISABLED` for new projects), we collect them all and
/// return the most-actionable per the priority order
/// `ScopeInsufficient` > `ServiceDisabled` > `BillingDisabled`. The
/// rationale: `ScopeInsufficient` requires re-consent and is upstream
/// of any post-OAuth verification; `ServiceDisabled` requires API
/// enablement and resolves the verify path; `BillingDisabled` is the
/// most-recoverable — operators who hit it typically also have to
/// enable the API. Returning the most-actionable first means the
/// remediation moves the operator toward green in one step.
///
/// Pure function (no I/O); safe to unit-test against fixture strings.
pub(crate) fn parse_verify_403_reason(body: &str, project: Option<&str>) -> Option<VerifyReason> {
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    let details = json.get("error")?.get("details")?.as_array()?;

    let mut found_service: Option<VerifyReason> = None;
    let mut found_billing: Option<VerifyReason> = None;
    let mut found_scope: Option<VerifyReason> = None;

    // R2-P12 + R3-P1: track whether each reason appeared so the
    // post-loop synthesis can attach `also_*` flags on whichever
    // variant wins priority. Captured separately so the
    // priority-order return at the bottom can still emit standalone
    // BillingDisabled / ScopeInsufficient when only one is present.
    let mut saw_billing_disabled = false;
    let mut found_service_service: Option<String> = None;
    let mut found_scope_missing_scopes: Option<Vec<String>> = None;

    for entry in details {
        // P1: skip entries without a string `reason` (Google's `Help`,
        // `LocalizedMessage`, `RetryInfo` details lack this field).
        let Some(reason) = entry.get("reason").and_then(|v| v.as_str()) else {
            continue;
        };
        match reason {
            "SERVICE_DISABLED" => {
                // P2: validate `metadata.service` shape; reject malformed
                // values (empty, oversize, control chars, query-string
                // metacharacters, non-canonical suffix). On failure we
                // skip this entry rather than surface an empty/dangerous
                // service to the renderer.
                let service = entry
                    .get("metadata")
                    .and_then(|m| m.get("service"))
                    .and_then(|v| v.as_str())
                    .and_then(validate_service_identifier);
                let Some(service) = service else { continue };
                if let Some(prev) = &found_service_service {
                    // R3-P20 round-3 review: log the dropped second
                    // SERVICE_DISABLED so an operator on RUST_LOG=debug
                    // can diagnose unexpected multi-API responses.
                    // Today's verify path is single-API so this should
                    // never fire in production.
                    tracing::debug!(
                        kept = %prev,
                        dropped = %service,
                        "verify response carried >1 SERVICE_DISABLED reason; keeping first, dropping second"
                    );
                    continue;
                }
                found_service_service = Some(service);
            }
            "BILLING_DISABLED" => {
                saw_billing_disabled = true;
                if found_billing.is_some() {
                    // R3-P20 round-3 review: log the dropped second
                    // BILLING_DISABLED for diagnostic parity.
                    tracing::debug!(
                        "verify response carried >1 BILLING_DISABLED reason; keeping first"
                    );
                    continue;
                }
                found_billing =
                    Some(VerifyReason::BillingDisabled { project: project.map(str::to_owned) });
            }
            "ACCESS_TOKEN_SCOPE_INSUFFICIENT" => {
                if found_scope_missing_scopes.is_some() {
                    continue;
                }
                let missing_scopes = entry
                    .get("metadata")
                    .and_then(|m| m.get("scope"))
                    .and_then(|v| v.as_str())
                    .map(|raw| {
                        // Google's metadata.scope is a single string with
                        // space- or comma-separated scope URIs. P4: each
                        // scope is shape-validated; entries that fail
                        // are silently dropped.
                        let mut out: Vec<String> = raw
                            .split(|c: char| c.is_whitespace() || c == ',')
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .filter_map(validate_scope)
                            .collect();
                        // R3-P24 round-3 review: dedup-keeping-first.
                        // Anomalous responses where Google repeats the
                        // same scope in the metadata string would
                        // otherwise produce duplicates in the operator-
                        // facing message ("missing scopes: x, x").
                        let mut seen = std::collections::HashSet::new();
                        out.retain(|s| seen.insert(s.clone()));
                        out
                    })
                    .unwrap_or_default();
                found_scope_missing_scopes = Some(missing_scopes);
            }
            _ => continue,
        }
    }

    // R2-P12 + R3-P1: synthesize the highest-priority variant with
    // ALL applicable `also_*` flags attached so the renderer surfaces
    // a single combined remediation instead of forcing the operator
    // through 2 or 3 sequential 403s.
    //
    // ScopeInsufficient (when present) carries both flags — it's
    // strictly upstream of the others (operator must re-consent) but
    // the others must be fixed AFTER, so they're rendered as ordered
    // "Then…" steps in the remediation text.
    //
    // ServiceDisabled carries only the billing flag — when present
    // without ScopeInsufficient, billing is the only other actionable
    // step.
    if let Some(missing_scopes) = found_scope_missing_scopes {
        found_scope = Some(VerifyReason::ScopeInsufficient {
            missing_scopes,
            also_service_disabled: found_service_service.clone(),
            also_billing_disabled: saw_billing_disabled,
        });
    }
    if let Some(service) = found_service_service {
        found_service = Some(VerifyReason::ServiceDisabled {
            service,
            project: project.map(str::to_owned),
            also_billing_disabled: saw_billing_disabled,
        });
    }

    // P7: priority order. ScopeInsufficient is upstream of any verify
    // success (operator must re-consent). ServiceDisabled resolves the
    // verify path on its own (now also surfacing billing-disabled if
    // both were present). BillingDisabled is least-actionable because
    // the API itself may also be disabled — surfacing ScopeInsufficient
    // (with all `also_*` flags) or ServiceDisabled (with billing flag)
    // first nudges the operator toward the green-after-one-step fix.
    found_scope.or(found_service).or(found_billing)
}

/// Result of a post-consent verification query.
#[derive(Debug)]
#[must_use]
pub struct VerifyResult {
    /// Human-readable summary of what was verified (e.g., "email: user@example.com").
    pub summary: String,
    /// Verified email address if available (e.g., from gmail.users.getProfile).
    pub email: Option<String>,
}

/// Run a lightweight read-only verification query for the given service.
///
/// Uses the access token directly (before sealing) to confirm the OAuth
/// grant actually works end-to-end. Returns structured error on failure.
///
/// `project_id` is the operator's Google Cloud project (from
/// `client_secret.json`'s `project_id`); when present it is attached to
/// any [`VerifyReason::ServiceDisabled`] / [`VerifyReason::BillingDisabled`]
/// the parser produces from a 403 body, so the rendered remediation URL
/// can pre-fill `?project=<id>`. Pass `None` if unknown.
pub async fn verify_connection(
    service: &str,
    access_token: &[u8],
    project_id: Option<&str>,
) -> Result<VerifyResult, OAuthError> {
    verify_connection_with_url(service, access_token, None, project_id).await
}

/// Internal implementation that accepts an optional base URL override for testing.
async fn verify_connection_with_url(
    service: &str,
    access_token: &[u8],
    base_url: Option<&str>,
    project_id: Option<&str>,
) -> Result<VerifyResult, OAuthError> {
    match service {
        "gmail" => verify_gmail(access_token, base_url, project_id).await,
        "calendar" => verify_calendar(access_token, base_url, project_id).await,
        "drive" => verify_drive(access_token, base_url, project_id).await,
        _ => Ok(VerifyResult { summary: "no verification available".to_owned(), email: None }),
    }
}

async fn verify_gmail(
    access_token: &[u8],
    base_url: Option<&str>,
    project_id: Option<&str>,
) -> Result<VerifyResult, OAuthError> {
    let token_str =
        std::str::from_utf8(access_token).map_err(|e| OAuthError::VerificationFailed {
            service: "gmail".to_owned(),
            reason: "access token is not valid UTF-8".to_owned(),
            status_code: None,
            verify_reason: None,
            source: Some(Box::new(e)),
        })?;

    if token_str.is_empty() {
        return Err(OAuthError::VerificationFailed {
            service: "gmail".to_owned(),
            reason: "access token is empty".to_owned(),
            status_code: None,
            verify_reason: None,
            source: None,
        });
    }

    let url = match base_url {
        Some(base) => join_verify_url(base, "gmail/v1/users/me/profile"),
        None => GMAIL_PROFILE_URL.to_owned(),
    };

    let client = build_verify_client("gmail")?;

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {token_str}"))
        .send()
        .await
        .map_err(|e| OAuthError::VerificationFailed {
            service: "gmail".to_owned(),
            reason: format!("request failed: {e}"),
            status_code: None,
            verify_reason: None,
            source: Some(Box::new(e)),
        })?;

    let status = response.status();
    if !status.is_success() {
        let status_code = status.as_u16();
        // Privacy (Story 2.7 Decision 2B + 7.12): log body at DEBUG; only
        // canonical-taxonomy fields cross into the typed verify_reason.
        let verify_reason =
            consume_verify_error_body(response, "gmail", status_code, project_id).await;
        return Err(OAuthError::VerificationFailed {
            service: "gmail".to_owned(),
            reason: format!("{status_code} {}", status.canonical_reason().unwrap_or("unknown")),
            status_code: Some(status_code),
            verify_reason,
            source: None,
        });
    }

    let json: serde_json::Value =
        response.json().await.map_err(|e| OAuthError::VerificationFailed {
            service: "gmail".to_owned(),
            reason: "failed to parse profile response".to_owned(),
            status_code: None,
            verify_reason: None,
            source: Some(Box::new(e)),
        })?;

    let email = json.get("emailAddress").and_then(|v| v.as_str()).map(|s| s.to_owned());

    let summary = match &email {
        Some(addr) => format!("email: {addr}"),
        None => "profile retrieved (no email in response)".to_owned(),
    };

    Ok(VerifyResult { summary, email })
}

async fn verify_calendar(
    access_token: &[u8],
    base_url: Option<&str>,
    project_id: Option<&str>,
) -> Result<VerifyResult, OAuthError> {
    let token_str =
        std::str::from_utf8(access_token).map_err(|e| OAuthError::VerificationFailed {
            service: "calendar".to_owned(),
            reason: "access token is not valid UTF-8".to_owned(),
            status_code: None,
            verify_reason: None,
            source: Some(Box::new(e)),
        })?;

    if token_str.is_empty() {
        return Err(OAuthError::VerificationFailed {
            service: "calendar".to_owned(),
            reason: "access token is empty".to_owned(),
            status_code: None,
            verify_reason: None,
            source: None,
        });
    }

    let url = match base_url {
        Some(base) => join_verify_url(base, "calendar/v3/users/me/calendarList?maxResults=1"),
        None => CALENDAR_LIST_URL.to_owned(),
    };

    let client = build_verify_client("calendar")?;

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {token_str}"))
        .send()
        .await
        .map_err(|e| OAuthError::VerificationFailed {
            service: "calendar".to_owned(),
            reason: format!("request failed: {e}"),
            status_code: None,
            verify_reason: None,
            source: Some(Box::new(e)),
        })?;

    let status = response.status();
    if !status.is_success() {
        let status_code = status.as_u16();
        // Privacy (Story 2.7 Decision 2B + 7.12): log body at DEBUG; only
        // canonical-taxonomy fields cross into the typed verify_reason.
        let verify_reason =
            consume_verify_error_body(response, "calendar", status_code, project_id).await;
        return Err(OAuthError::VerificationFailed {
            service: "calendar".to_owned(),
            reason: format!("{status_code} {}", status.canonical_reason().unwrap_or("unknown")),
            status_code: Some(status_code),
            verify_reason,
            source: None,
        });
    }

    let json: serde_json::Value =
        response.json().await.map_err(|e| OAuthError::VerificationFailed {
            service: "calendar".to_owned(),
            reason: "failed to parse calendarList response".to_owned(),
            status_code: None,
            verify_reason: None,
            source: Some(Box::new(e)),
        })?;

    let calendar_count = json.get("items").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);

    Ok(VerifyResult { summary: format!("{calendar_count} calendar(s) accessible"), email: None })
}

async fn verify_drive(
    access_token: &[u8],
    base_url: Option<&str>,
    project_id: Option<&str>,
) -> Result<VerifyResult, OAuthError> {
    let token_str =
        std::str::from_utf8(access_token).map_err(|e| OAuthError::VerificationFailed {
            service: "drive".to_owned(),
            reason: "access token is not valid UTF-8".to_owned(),
            status_code: None,
            verify_reason: None,
            source: Some(Box::new(e)),
        })?;

    if token_str.is_empty() {
        return Err(OAuthError::VerificationFailed {
            service: "drive".to_owned(),
            reason: "access token is empty".to_owned(),
            status_code: None,
            verify_reason: None,
            source: None,
        });
    }

    let url = match base_url {
        Some(base) => join_verify_url(base, "drive/v3/about?fields=user"),
        None => DRIVE_ABOUT_URL.to_owned(),
    };

    let client = build_verify_client("drive")?;

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {token_str}"))
        .send()
        .await
        .map_err(|e| OAuthError::VerificationFailed {
            service: "drive".to_owned(),
            reason: format!("request failed: {e}"),
            status_code: None,
            verify_reason: None,
            source: Some(Box::new(e)),
        })?;

    let status = response.status();
    if !status.is_success() {
        let status_code = status.as_u16();
        // Privacy (Story 2.7 Decision 2B + 7.12): log body at DEBUG; only
        // canonical-taxonomy fields cross into the typed verify_reason.
        let verify_reason =
            consume_verify_error_body(response, "drive", status_code, project_id).await;
        return Err(OAuthError::VerificationFailed {
            service: "drive".to_owned(),
            reason: format!("{status_code} {}", status.canonical_reason().unwrap_or("unknown")),
            status_code: Some(status_code),
            verify_reason,
            source: None,
        });
    }

    let json: serde_json::Value =
        response.json().await.map_err(|e| OAuthError::VerificationFailed {
            service: "drive".to_owned(),
            reason: "failed to parse about response".to_owned(),
            status_code: None,
            verify_reason: None,
            source: Some(Box::new(e)),
        })?;

    let email = json
        .get("user")
        .and_then(|u| u.get("emailAddress"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());

    let display_name = json
        .get("user")
        .and_then(|u| u.get("displayName"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let summary = match &email {
        Some(addr) => format!("drive: {display_name} ({addr})"),
        None => format!("drive: {display_name}"),
    };

    Ok(VerifyResult { summary, email })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ── Story 7.12: parse_verify_403_reason unit tests ─────────────────

    #[test]
    fn parses_service_disabled_with_metadata() {
        let body = r#"{
            "error": {
                "code": 403,
                "message": "Calendar API has not been used in project ...",
                "status": "PERMISSION_DENIED",
                "details": [
                    {
                        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                        "reason": "SERVICE_DISABLED",
                        "domain": "googleapis.com",
                        "metadata": {
                            "service": "calendar.googleapis.com",
                            "consumer": "projects/12345"
                        }
                    }
                ]
            }
        }"#;
        let parsed = parse_verify_403_reason(body, Some("my-project"));
        assert_eq!(
            parsed,
            Some(VerifyReason::ServiceDisabled {
                service: "calendar.googleapis.com".to_owned(),
                project: Some("my-project".to_owned()),
                also_billing_disabled: false,
            })
        );
    }

    #[test]
    fn parses_service_disabled_without_project() {
        let body = r#"{"error":{"details":[{"reason":"SERVICE_DISABLED","metadata":{"service":"drive.googleapis.com"}}]}}"#;
        let parsed = parse_verify_403_reason(body, None);
        assert_eq!(
            parsed,
            Some(VerifyReason::ServiceDisabled {
                service: "drive.googleapis.com".to_owned(),
                project: None,
                also_billing_disabled: false,
            })
        );
    }

    #[test]
    fn parses_billing_disabled() {
        let body = r#"{"error":{"details":[{"reason":"BILLING_DISABLED"}]}}"#;
        let parsed = parse_verify_403_reason(body, Some("p1"));
        assert_eq!(parsed, Some(VerifyReason::BillingDisabled { project: Some("p1".to_owned()) }));
    }

    #[test]
    fn parses_scope_insufficient_with_metadata_scope() {
        let body = r#"{
            "error": {
                "details": [
                    {
                        "reason": "ACCESS_TOKEN_SCOPE_INSUFFICIENT",
                        "metadata": {
                            "scope": "https://www.googleapis.com/auth/calendar.events https://www.googleapis.com/auth/drive.readonly"
                        }
                    }
                ]
            }
        }"#;
        let parsed = parse_verify_403_reason(body, None);
        match parsed {
            Some(VerifyReason::ScopeInsufficient { missing_scopes, .. }) => {
                assert_eq!(
                    missing_scopes,
                    vec![
                        "https://www.googleapis.com/auth/calendar.events".to_owned(),
                        "https://www.googleapis.com/auth/drive.readonly".to_owned(),
                    ]
                );
            }
            other => panic!("expected ScopeInsufficient, got {other:?}"),
        }
    }

    #[test]
    fn parses_scope_insufficient_with_comma_separated_scopes() {
        // P4 round-1 review: scopes must validate as HTTP/HTTPS URLs.
        // Pre-fix the fixture used short identifiers ("a,b,c") which
        // would silently produce a misleading remediation message; the
        // validation now requires real Google scope URLs.
        let body = r#"{"error":{"details":[{"reason":"ACCESS_TOKEN_SCOPE_INSUFFICIENT","metadata":{"scope":"https://www.googleapis.com/auth/calendar.readonly,https://www.googleapis.com/auth/drive.readonly , https://www.googleapis.com/auth/gmail.readonly"}}]}}"#;
        let parsed = parse_verify_403_reason(body, None);
        match parsed {
            Some(VerifyReason::ScopeInsufficient { missing_scopes, .. }) => {
                assert_eq!(
                    missing_scopes,
                    vec![
                        "https://www.googleapis.com/auth/calendar.readonly".to_owned(),
                        "https://www.googleapis.com/auth/drive.readonly".to_owned(),
                        "https://www.googleapis.com/auth/gmail.readonly".to_owned(),
                    ]
                );
            }
            other => panic!("expected ScopeInsufficient, got {other:?}"),
        }
    }

    /// P4 round-1 review: malformed scopes (non-URL, control chars,
    /// over-length) are silently dropped from `missing_scopes`. A
    /// fixture mixing valid + invalid scopes verifies the filter.
    #[test]
    fn parses_scope_insufficient_drops_malformed_entries() {
        let body = r#"{"error":{"details":[{"reason":"ACCESS_TOKEN_SCOPE_INSUFFICIENT","metadata":{"scope":"https://www.googleapis.com/auth/calendar.readonly not-a-url"}}]}}"#;
        let parsed = parse_verify_403_reason(body, None);
        match parsed {
            Some(VerifyReason::ScopeInsufficient { missing_scopes, .. }) => {
                // The "not-a-url" entry is dropped; only the canonical
                // URL survives validation.
                assert_eq!(
                    missing_scopes,
                    vec!["https://www.googleapis.com/auth/calendar.readonly".to_owned()]
                );
            }
            other => panic!("expected ScopeInsufficient, got {other:?}"),
        }
    }

    /// R2-P3 round-2 review: OIDC standard opaque scopes (`openid`,
    /// `email`, `profile`, `address`, `phone`) — Google's most common
    /// consent-flow scope set — must validate. The pre-fix R1-P4
    /// URL-only validator silently dropped them.
    #[test]
    fn parses_scope_insufficient_accepts_oidc_opaque_scopes() {
        let body = r#"{"error":{"details":[{"reason":"ACCESS_TOKEN_SCOPE_INSUFFICIENT","metadata":{"scope":"openid email profile https://www.googleapis.com/auth/calendar"}}]}}"#;
        let parsed = parse_verify_403_reason(body, None);
        match parsed {
            Some(VerifyReason::ScopeInsufficient { missing_scopes, .. }) => {
                assert_eq!(
                    missing_scopes,
                    vec![
                        "openid".to_owned(),
                        "email".to_owned(),
                        "profile".to_owned(),
                        "https://www.googleapis.com/auth/calendar".to_owned(),
                    ],
                    "R2-P3: OIDC opaque scopes must validate alongside URL scopes"
                );
            }
            other => panic!("expected ScopeInsufficient, got {other:?}"),
        }
    }

    /// R2-P3 round-2 review: non-allowlist non-URL opaque strings
    /// (e.g., a typo like `opnid` or a hostile `; rm -rf /`) are
    /// still rejected.
    #[test]
    fn parses_scope_insufficient_rejects_unknown_opaque_strings() {
        let body = r#"{"error":{"details":[{"reason":"ACCESS_TOKEN_SCOPE_INSUFFICIENT","metadata":{"scope":"opnid not-a-scope"}}]}}"#;
        let parsed = parse_verify_403_reason(body, None);
        match parsed {
            Some(VerifyReason::ScopeInsufficient { missing_scopes, .. }) => {
                assert!(
                    missing_scopes.is_empty(),
                    "R2-P3: non-allowlist non-URL opaque strings must be dropped: {missing_scopes:?}"
                );
            }
            other => panic!("expected ScopeInsufficient, got {other:?}"),
        }
    }

    /// P4 round-1 review: a scope containing ANSI escape codes / control
    /// chars is dropped — terminal-injection vector.
    #[test]
    fn parses_scope_insufficient_drops_ansi_injection() {
        // \x1b[2J\x1b[H = ANSI clear-screen + cursor-home.
        let body = "{\"error\":{\"details\":[{\"reason\":\"ACCESS_TOKEN_SCOPE_INSUFFICIENT\",\"metadata\":{\"scope\":\"https://evil.example/\\u001b[2J\"}}]}}";
        let parsed = parse_verify_403_reason(body, None);
        match parsed {
            Some(VerifyReason::ScopeInsufficient { missing_scopes, .. }) => {
                assert!(
                    missing_scopes.is_empty(),
                    "scope with ANSI escape must be dropped: {missing_scopes:?}"
                );
            }
            other => panic!("expected ScopeInsufficient, got {other:?}"),
        }
    }

    #[test]
    fn parses_scope_insufficient_without_metadata() {
        let body = r#"{"error":{"details":[{"reason":"ACCESS_TOKEN_SCOPE_INSUFFICIENT"}]}}"#;
        let parsed = parse_verify_403_reason(body, None);
        assert_eq!(
            parsed,
            Some(VerifyReason::ScopeInsufficient {
                missing_scopes: vec![],
                also_service_disabled: None,
                also_billing_disabled: false,
            })
        );
    }

    #[test]
    fn unrecognized_reason_returns_none() {
        let body =
            r#"{"error":{"details":[{"reason":"QUOTA_EXCEEDED","metadata":{"limit":"500"}}]}}"#;
        assert_eq!(parse_verify_403_reason(body, Some("p")), None);
    }

    #[test]
    fn malformed_body_returns_none() {
        assert_eq!(parse_verify_403_reason("", None), None);
        assert_eq!(parse_verify_403_reason("not-json", None), None);
        assert_eq!(parse_verify_403_reason("{}", None), None);
        assert_eq!(parse_verify_403_reason(r#"{"error":{}}"#, None), None);
        assert_eq!(parse_verify_403_reason(r#"{"error":{"details":[]}}"#, None), None);
        assert_eq!(parse_verify_403_reason(r#"{"error":{"details":["string"]}}"#, None), None);
        assert_eq!(parse_verify_403_reason(r#"{"error":{"details":[{}]}}"#, None), None);
    }

    #[test]
    fn multi_detail_picks_first_recognized() {
        let body = r#"{
            "error": {
                "details": [
                    {"reason": "OTHER"},
                    {"reason": "SERVICE_DISABLED", "metadata": {"service": "gmail.googleapis.com"}}
                ]
            }
        }"#;
        let parsed = parse_verify_403_reason(body, Some("p"));
        assert_eq!(
            parsed,
            Some(VerifyReason::ServiceDisabled {
                service: "gmail.googleapis.com".to_owned(),
                project: Some("p".to_owned()),
                also_billing_disabled: false,
            })
        );
    }

    /// P1 round-1 review: real Google 403 SERVICE_DISABLED responses
    /// commonly bundle a `Help` (or `LocalizedMessage`) entry BEFORE
    /// the `ErrorInfo` entry that carries `reason`. The pre-fix
    /// parser used `?` on `entry.get("reason")`, returning `None`
    /// from the entire function on the first non-`reason`-bearing
    /// entry — silently regressing AC #1 to the generic remediation.
    /// This test fixture mirrors a real Google response shape; the
    /// parser must skip the leading `Help` entry and find the
    /// `ErrorInfo` entry that follows.
    #[test]
    fn parses_service_disabled_with_leading_non_reason_entry() {
        let body = r#"{
            "error": {
                "code": 403,
                "details": [
                    {
                        "@type": "type.googleapis.com/google.rpc.Help",
                        "links": [{"description": "Google docs", "url": "https://example.com"}]
                    },
                    {
                        "@type": "type.googleapis.com/google.rpc.LocalizedMessage",
                        "locale": "en-US",
                        "message": "Calendar API is disabled."
                    },
                    {
                        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                        "reason": "SERVICE_DISABLED",
                        "domain": "googleapis.com",
                        "metadata": {"service": "calendar.googleapis.com"}
                    }
                ]
            }
        }"#;
        let parsed = parse_verify_403_reason(body, Some("my-project"));
        assert_eq!(
            parsed,
            Some(VerifyReason::ServiceDisabled {
                service: "calendar.googleapis.com".to_owned(),
                project: Some("my-project".to_owned()),
                also_billing_disabled: false,
            }),
            "P1 regression: leading non-reason entry must not short-circuit the scan"
        );
    }

    /// P2 round-1 review: `metadata.service` must validate against the
    /// canonical `<short>.googleapis.com` shape. Hostile values
    /// containing query-string metacharacters, control chars, or
    /// non-canonical suffixes are rejected — the parser falls back to
    /// `None` (generic remediation) rather than synthesizing a
    /// dangerous URL/CLI command.
    #[test]
    fn rejects_service_with_query_string_injection() {
        let body = r#"{"error":{"details":[{"reason":"SERVICE_DISABLED","metadata":{"service":"calendar.googleapis.com?inject=evil"}}]}}"#;
        assert_eq!(
            parse_verify_403_reason(body, Some("p")),
            None,
            "P2: service with `?` must be rejected"
        );
    }

    #[test]
    fn rejects_service_with_ansi_escape() {
        // Embedded ANSI clear-screen sequence.
        let body = "{\"error\":{\"details\":[{\"reason\":\"SERVICE_DISABLED\",\"metadata\":{\"service\":\"foo.googleapis.com\\u001b[2J\"}}]}}";
        assert_eq!(
            parse_verify_403_reason(body, Some("p")),
            None,
            "P2: service with ANSI escape must be rejected"
        );
    }

    #[test]
    fn rejects_service_with_non_canonical_suffix() {
        let body = r#"{"error":{"details":[{"reason":"SERVICE_DISABLED","metadata":{"service":"evil.example.com"}}]}}"#;
        assert_eq!(
            parse_verify_403_reason(body, Some("p")),
            None,
            "P2: service must end in .googleapis.com"
        );
    }

    #[test]
    fn rejects_empty_or_missing_service_metadata() {
        // Pre-fix `unwrap_or("").to_owned()` produced `service: ""` and
        // a broken URL `https://...library/?project=p`. Now we reject.
        let empty_body =
            r#"{"error":{"details":[{"reason":"SERVICE_DISABLED","metadata":{"service":""}}]}}"#;
        assert_eq!(
            parse_verify_403_reason(empty_body, Some("p")),
            None,
            "P2: empty service must be rejected"
        );
        let missing_body = r#"{"error":{"details":[{"reason":"SERVICE_DISABLED"}]}}"#;
        assert_eq!(
            parse_verify_403_reason(missing_body, Some("p")),
            None,
            "P2: missing service must be rejected"
        );
    }

    /// R2-P8 round-2 review: consecutive dots in the service identifier
    /// are rejected (non-canonical Google shape; pre-fix produced
    /// malformed URL `library/a..googleapis.com`).
    #[test]
    fn rejects_service_with_consecutive_dots() {
        let body = r#"{"error":{"details":[{"reason":"SERVICE_DISABLED","metadata":{"service":"a..googleapis.com"}}]}}"#;
        assert_eq!(
            parse_verify_403_reason(body, Some("p")),
            None,
            "R2-P8: service with consecutive dots must be rejected"
        );
    }

    /// R2-P8 round-2 review: consecutive hyphens in the service identifier
    /// are rejected.
    #[test]
    fn rejects_service_with_consecutive_hyphens() {
        let body = r#"{"error":{"details":[{"reason":"SERVICE_DISABLED","metadata":{"service":"a----.googleapis.com"}}]}}"#;
        assert_eq!(
            parse_verify_403_reason(body, Some("p")),
            None,
            "R2-P8: service with consecutive hyphens must be rejected"
        );
    }

    /// R2-P8 round-2 review: a label starting with a hyphen is rejected.
    #[test]
    fn rejects_service_with_label_starting_with_hyphen() {
        let body = r#"{"error":{"details":[{"reason":"SERVICE_DISABLED","metadata":{"service":"-foo.googleapis.com"}}]}}"#;
        assert_eq!(parse_verify_403_reason(body, Some("p")), None);
    }

    /// R2-P16 round-2 review: shell metachars (`;`, `\`, `$`, `` ` ``,
    /// `&`, `#`, `|`) are rejected. Belt-and-suspenders test for the
    /// privacy contract — locks future allowlist widening against a
    /// regression that would re-open the channel.
    #[test]
    fn rejects_service_with_shell_metacharacters() {
        for hostile in &[
            "calendar;rm.googleapis.com",
            "calendar$.googleapis.com",
            "calendar`.googleapis.com",
            "calendar&.googleapis.com",
            "calendar#.googleapis.com",
            "calendar|.googleapis.com",
        ] {
            let body = format!(
                r#"{{"error":{{"details":[{{"reason":"SERVICE_DISABLED","metadata":{{"service":"{hostile}"}}}}]}}}}"#
            );
            assert_eq!(
                parse_verify_403_reason(&body, Some("p")),
                None,
                "R2-P16: service with shell metachar must be rejected: {hostile}"
            );
        }
    }

    /// P2: oversized service (e.g., a flooding attack via `metadata.service`)
    /// is rejected by the length cap.
    #[test]
    fn rejects_oversize_service_identifier() {
        let huge = "a".repeat(300) + ".googleapis.com";
        let body = format!(
            r#"{{"error":{{"details":[{{"reason":"SERVICE_DISABLED","metadata":{{"service":"{huge}"}}}}]}}}}"#
        );
        assert_eq!(
            parse_verify_403_reason(&body, Some("p")),
            None,
            "P2: oversize service must be rejected"
        );
    }

    /// P7 round-1 review: multi-reason `details[]` (Google bundles
    /// `BILLING_DISABLED + SERVICE_DISABLED` for new projects).
    /// Priority: `ServiceDisabled` > `BillingDisabled` (fixing the
    /// service unblocks more than fixing billing alone). R2-P12: when
    /// both appear in the same response, the ServiceDisabled variant
    /// carries `also_billing_disabled: true` so the renderer surfaces
    /// both fixes (operator enables billing first, then the API).
    #[test]
    fn multi_recognized_reasons_picks_service_over_billing() {
        let body = r#"{
            "error": {
                "details": [
                    {"reason": "BILLING_DISABLED"},
                    {"reason": "SERVICE_DISABLED", "metadata": {"service": "calendar.googleapis.com"}}
                ]
            }
        }"#;
        let parsed = parse_verify_403_reason(body, Some("p"));
        assert_eq!(
            parsed,
            Some(VerifyReason::ServiceDisabled {
                service: "calendar.googleapis.com".to_owned(),
                project: Some("p".to_owned()),
                also_billing_disabled: true,
            }),
            "R2-P12: ServiceDisabled wins over BillingDisabled, AND carries also_billing_disabled=true"
        );
    }

    /// R2-P12 round-2 review: standalone SERVICE_DISABLED (no billing)
    /// must produce `also_billing_disabled: false`.
    #[test]
    fn standalone_service_disabled_has_billing_flag_false() {
        let body = r#"{"error":{"details":[{"reason":"SERVICE_DISABLED","metadata":{"service":"calendar.googleapis.com"}}]}}"#;
        let parsed = parse_verify_403_reason(body, Some("p"));
        match parsed {
            Some(VerifyReason::ServiceDisabled { also_billing_disabled, .. }) => {
                assert!(
                    !also_billing_disabled,
                    "standalone ServiceDisabled must have also_billing_disabled=false"
                );
            }
            other => panic!("expected ServiceDisabled, got {other:?}"),
        }
    }

    /// R2-P12 round-2 review: when both SERVICE_DISABLED and BILLING_DISABLED
    /// appear, the rendered remediation must mention both URLs (the API
    /// enablement URL AND the billing console URL).
    #[test]
    fn renders_billing_footer_when_both_reasons_present() {
        use crate::error::OAuthError;
        let body = r#"{
            "error": {
                "details": [
                    {"reason": "BILLING_DISABLED"},
                    {"reason": "SERVICE_DISABLED", "metadata": {"service": "calendar.googleapis.com"}}
                ]
            }
        }"#;
        let parsed =
            parse_verify_403_reason(body, Some("my-project")).expect("parse should succeed");
        let err = OAuthError::VerificationFailed {
            service: "calendar".to_owned(),
            reason: "403 Forbidden".to_owned(),
            status_code: Some(403),
            verify_reason: Some(parsed),
            source: None,
        };
        let remediation = err.remediation_owned();
        assert!(
            remediation.contains("https://console.cloud.google.com/apis/library/calendar.googleapis.com?project=my-project"),
            "remediation must include the SERVICE enablement URL: {remediation}"
        );
        assert!(
            remediation.contains("https://console.cloud.google.com/billing?project=my-project"),
            "remediation must include the BILLING console URL: {remediation}"
        );
        // R3-P2 round-3 review: footer text was reshaped to "First enable
        // billing for this project ..." so it reads correctly after
        // `error_block` flattens the indent hierarchy. Assert on the
        // new wording.
        assert!(
            remediation.to_lowercase().contains("first enable billing"),
            "remediation must explicitly mention enabling billing first: {remediation}"
        );
    }

    /// P7: when both `BILLING_DISABLED` AND `SERVICE_DISABLED` appear,
    /// order in the array does NOT matter — priority is
    /// service-over-billing regardless.
    #[test]
    fn multi_recognized_reasons_priority_independent_of_order() {
        let body = r#"{
            "error": {
                "details": [
                    {"reason": "SERVICE_DISABLED", "metadata": {"service": "drive.googleapis.com"}},
                    {"reason": "BILLING_DISABLED"}
                ]
            }
        }"#;
        let parsed = parse_verify_403_reason(body, Some("p"));
        assert!(matches!(parsed, Some(VerifyReason::ServiceDisabled { .. })));
    }

    /// P7: scope insufficient is highest-priority (re-consent required;
    /// upstream of any verify success).
    #[test]
    fn multi_recognized_reasons_picks_scope_over_service_and_billing() {
        let body = r#"{
            "error": {
                "details": [
                    {"reason": "BILLING_DISABLED"},
                    {"reason": "SERVICE_DISABLED", "metadata": {"service": "gmail.googleapis.com"}},
                    {"reason": "ACCESS_TOKEN_SCOPE_INSUFFICIENT", "metadata": {"scope": "https://www.googleapis.com/auth/gmail.readonly"}}
                ]
            }
        }"#;
        let parsed = parse_verify_403_reason(body, Some("p"));
        assert!(matches!(parsed, Some(VerifyReason::ScopeInsufficient { .. })));
    }

    // ── Story 7.12: integration tests via mockito (verify_reason wiring) ─

    #[tokio::test]
    async fn gmail_403_service_disabled_attaches_reason() {
        let mut server = mockito::Server::new_async().await;
        let body = r#"{"error":{"code":403,"details":[{"reason":"SERVICE_DISABLED","metadata":{"service":"gmail.googleapis.com"}}]}}"#;
        let mock = server
            .mock("GET", "/gmail/v1/users/me/profile")
            .with_status(403)
            .with_body(body)
            .create_async()
            .await;

        let err =
            verify_connection_with_url("gmail", b"tok", Some(&server.url()), Some("my-project"))
                .await
                .expect_err("403 should fail");

        match &err {
            OAuthError::VerificationFailed { verify_reason, status_code, .. } => {
                assert_eq!(*status_code, Some(403));
                assert_eq!(
                    verify_reason,
                    &Some(VerifyReason::ServiceDisabled {
                        service: "gmail.googleapis.com".to_owned(),
                        project: Some("my-project".to_owned()),
                        also_billing_disabled: false,
                    })
                );
            }
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn calendar_403_service_disabled_attaches_reason() {
        let mut server = mockito::Server::new_async().await;
        let body = r#"{"error":{"code":403,"details":[{"reason":"SERVICE_DISABLED","metadata":{"service":"calendar.googleapis.com"}}]}}"#;
        let mock = server
            .mock("GET", "/calendar/v3/users/me/calendarList?maxResults=1")
            .with_status(403)
            .with_body(body)
            .create_async()
            .await;

        let err =
            verify_connection_with_url("calendar", b"tok", Some(&server.url()), Some("my-project"))
                .await
                .expect_err("403 should fail");

        match &err {
            OAuthError::VerificationFailed { verify_reason, .. } => {
                assert_eq!(
                    verify_reason,
                    &Some(VerifyReason::ServiceDisabled {
                        service: "calendar.googleapis.com".to_owned(),
                        project: Some("my-project".to_owned()),
                        also_billing_disabled: false,
                    })
                );
            }
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn drive_403_billing_disabled_attaches_reason() {
        let mut server = mockito::Server::new_async().await;
        let body = r#"{"error":{"code":403,"details":[{"reason":"BILLING_DISABLED"}]}}"#;
        let mock = server
            .mock("GET", "/drive/v3/about?fields=user")
            .with_status(403)
            .with_body(body)
            .create_async()
            .await;

        let err = verify_connection_with_url("drive", b"tok", Some(&server.url()), Some("p1"))
            .await
            .expect_err("403 should fail");

        match &err {
            OAuthError::VerificationFailed { verify_reason, .. } => {
                assert_eq!(
                    verify_reason,
                    &Some(VerifyReason::BillingDisabled { project: Some("p1".to_owned()) })
                );
            }
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn gmail_403_unknown_reason_keeps_reason_none() {
        // AC #4 regression guard: 403 with unrecognized reason → verify_reason
        // stays None so the existing generic remediation kicks in.
        let mut server = mockito::Server::new_async().await;
        let body = r#"{"error":{"code":403,"details":[{"reason":"QUOTA_EXCEEDED"}]}}"#;
        let mock = server
            .mock("GET", "/gmail/v1/users/me/profile")
            .with_status(403)
            .with_body(body)
            .create_async()
            .await;

        let err = verify_connection_with_url("gmail", b"tok", Some(&server.url()), Some("p"))
            .await
            .expect_err("403 should fail");

        match &err {
            OAuthError::VerificationFailed { verify_reason, status_code, .. } => {
                assert_eq!(*status_code, Some(403));
                assert!(verify_reason.is_none(), "unknown reason must not populate verify_reason");
            }
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn gmail_401_unauthorized_keeps_reason_none() {
        // AC #4 regression guard: only 403 triggers parsing; 401 stays None
        // even if the body happens to contain a Google details[] shape.
        let mut server = mockito::Server::new_async().await;
        let body = r#"{"error":{"code":401,"details":[{"reason":"SERVICE_DISABLED","metadata":{"service":"gmail.googleapis.com"}}]}}"#;
        let mock = server
            .mock("GET", "/gmail/v1/users/me/profile")
            .with_status(401)
            .with_body(body)
            .create_async()
            .await;

        let err = verify_connection_with_url("gmail", b"tok", Some(&server.url()), Some("p"))
            .await
            .expect_err("401 should fail");

        match &err {
            OAuthError::VerificationFailed { verify_reason, status_code, .. } => {
                assert_eq!(*status_code, Some(401));
                assert!(verify_reason.is_none(), "non-403 must keep verify_reason None");
            }
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
        mock.assert_async().await;
    }

    // ── End Story 7.12 additions ───────────────────────────────────────

    #[tokio::test]
    async fn gmail_successful_profile() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/gmail/v1/users/me/profile")
            .match_header("Authorization", "Bearer test-token-123")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"emailAddress": "test@example.com", "messagesTotal": 42}"#)
            .create_async()
            .await;

        let result =
            verify_connection_with_url("gmail", b"test-token-123", Some(&server.url()), None)
                .await
                .expect("verification should succeed");

        assert_eq!(result.email, Some("test@example.com".to_owned()));
        assert_eq!(result.summary, "email: test@example.com");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn gmail_401_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/gmail/v1/users/me/profile")
            .with_status(401)
            .with_body(r#"{"error": {"code": 401, "message": "Invalid Credentials"}}"#)
            .create_async()
            .await;

        let err = verify_connection_with_url("gmail", b"bad-token", Some(&server.url()), None)
            .await
            .expect_err("should fail with 401");

        assert_eq!(err.error_code(), "verification_failed");
        match &err {
            OAuthError::VerificationFailed { status_code, service, .. } => {
                assert_eq!(*status_code, Some(401));
                assert_eq!(service, "gmail");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn gmail_403_forbidden() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/gmail/v1/users/me/profile")
            .with_status(403)
            .with_body(r#"{"error": {"code": 403, "message": "Forbidden"}}"#)
            .create_async()
            .await;

        let err = verify_connection_with_url("gmail", b"token", Some(&server.url()), None)
            .await
            .expect_err("should fail with 403");

        match &err {
            OAuthError::VerificationFailed { status_code, .. } => {
                assert_eq!(*status_code, Some(403));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn unknown_service_passthrough() {
        let result = verify_connection_with_url("notion", b"token", None, None)
            .await
            .expect("unknown service should return Ok");

        assert_eq!(result.summary, "no verification available");
        assert!(result.email.is_none());
    }

    #[tokio::test]
    async fn network_timeout() {
        // Use a URL that will refuse connection quickly.
        let err = verify_connection_with_url("gmail", b"token", Some("http://127.0.0.1:1"), None)
            .await
            .expect_err("should fail with connection error");

        assert_eq!(err.error_code(), "verification_failed");
    }

    #[tokio::test]
    async fn gmail_empty_token_rejected() {
        let err = verify_connection_with_url("gmail", b"", None, None)
            .await
            .expect_err("empty token should be rejected");

        assert_eq!(err.error_code(), "verification_failed");
        match &err {
            OAuthError::VerificationFailed { reason, .. } => {
                assert!(reason.contains("empty"), "reason should mention empty: {reason}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn calendar_successful_verification() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/calendar/v3/users/me/calendarList?maxResults=1")
            .match_header("Authorization", "Bearer cal-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"kind":"calendar#calendarList","items":[{"id":"primary","summary":"My Calendar"}]}"#,
            )
            .create_async()
            .await;

        let result =
            verify_connection_with_url("calendar", b"cal-token", Some(&server.url()), None)
                .await
                .expect("calendar verification should succeed");

        assert_eq!(result.summary, "1 calendar(s) accessible");
        assert!(result.email.is_none());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn calendar_401_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/calendar/v3/users/me/calendarList?maxResults=1")
            .with_status(401)
            .with_body(r#"{"error":{"code":401}}"#)
            .create_async()
            .await;

        let err = verify_connection_with_url("calendar", b"bad-token", Some(&server.url()), None)
            .await
            .expect_err("should fail with 401");

        match &err {
            OAuthError::VerificationFailed { status_code, service, .. } => {
                assert_eq!(*status_code, Some(401));
                assert_eq!(service, "calendar");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn drive_successful_verification() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/drive/v3/about?fields=user")
            .match_header("Authorization", "Bearer drive-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"user":{"displayName":"Test User","emailAddress":"test@example.com"}}"#)
            .create_async()
            .await;

        let result = verify_connection_with_url("drive", b"drive-token", Some(&server.url()), None)
            .await
            .expect("drive verification should succeed");

        assert_eq!(result.email, Some("test@example.com".to_owned()));
        assert_eq!(result.summary, "drive: Test User (test@example.com)");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn drive_403_forbidden() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/drive/v3/about?fields=user")
            .with_status(403)
            .with_body(r#"{"error":{"code":403}}"#)
            .create_async()
            .await;

        let err = verify_connection_with_url("drive", b"token", Some(&server.url()), None)
            .await
            .expect_err("should fail with 403");

        match &err {
            OAuthError::VerificationFailed { status_code, service, .. } => {
                assert_eq!(*status_code, Some(403));
                assert_eq!(service, "drive");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
        mock.assert_async().await;
    }

    // ----- Story 2.7: shared helpers + privacy-safe body logging -----

    #[test]
    fn build_verify_client_returns_configured_client() {
        // Smoke test: the helper must produce a client without error and
        // propagate the service name into the error path if it ever fails.
        let client = build_verify_client("gmail").expect("client builds");
        // The client is opaque; we just verify it exists and can be used.
        // A deeper assertion (user-agent, timeout) would require a mock
        // server request — covered by the existing success-path tests.
        drop(client);
    }

    #[test]
    fn join_verify_url_handles_trailing_slash_on_base() {
        // The four base/path slash combinations must all produce the
        // same output.
        let expected = "http://example.com/gmail/v1/users/me/profile";
        assert_eq!(join_verify_url("http://example.com", "gmail/v1/users/me/profile"), expected);
        assert_eq!(join_verify_url("http://example.com", "/gmail/v1/users/me/profile"), expected);
        assert_eq!(join_verify_url("http://example.com/", "gmail/v1/users/me/profile"), expected);
        assert_eq!(join_verify_url("http://example.com/", "/gmail/v1/users/me/profile"), expected);
    }

    #[test]
    fn join_verify_url_preserves_query_string_in_path() {
        // Query strings must survive the normalization so the calendar
        // URL's `?maxResults=1` parameter is not dropped.
        let joined = join_verify_url(
            "http://example.com/",
            "calendar/v3/users/me/calendarList?maxResults=1",
        );
        assert_eq!(joined, "http://example.com/calendar/v3/users/me/calendarList?maxResults=1");
    }

    #[tokio::test]
    async fn gmail_verify_error_body_never_leaks_into_reason() {
        // Privacy regression test (Story 2.7 Decision 2B): a Google
        // error response containing user-identifying content must NOT
        // appear in the user-facing `OAuthError::VerificationFailed.reason`
        // field. The body goes to `tracing::debug!` only.
        //
        // This fixture body mimics a real Google `invalid_grant` error
        // which would normally include an email address — the test
        // uses a sentinel string `"SENSITIVE_EMAIL_alice@example.com"`
        // that is unambiguous to search for.
        let mut server = mockito::Server::new_async().await;
        let sensitive_marker = "SENSITIVE_EMAIL_alice@example.com";
        let body =
            format!(r#"{{"error":"invalid_grant","error_description":"{sensitive_marker}"}}"#);
        let mock = server
            .mock("GET", "/gmail/v1/users/me/profile")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(&body)
            .create_async()
            .await;

        let err = verify_connection_with_url("gmail", b"leaked-token", Some(&server.url()), None)
            .await
            .expect_err("should fail with 401");

        match &err {
            OAuthError::VerificationFailed {
                reason,
                status_code,
                service,
                source,
                verify_reason,
            } => {
                // The status code IS in the user-facing reason (that's safe).
                assert_eq!(*status_code, Some(401));
                assert_eq!(service, "gmail");
                assert!(reason.contains("401"), "reason should contain status code: {reason}");
                // CRITICAL: the Google error body must NOT be in `reason`.
                assert!(
                    !reason.contains(sensitive_marker),
                    "Story 2.7 Decision 2B PRIVACY REGRESSION: \
                     Google response body leaked into user-facing OAuthError.reason. \
                     reason={reason}, sensitive_marker={sensitive_marker}"
                );
                // Also check it didn't sneak into the canonical status text.
                assert!(!reason.contains("alice@example.com"));
                // Story 2.7 review patch: lock the `source: None` invariant
                // on 4xx/5xx paths. A future refactor that wraps the
                // reqwest error into `source` would re-leak the body via
                // `std::error::Error::source()` chain traversal in
                // operator log pipelines. Assert the source is None.
                assert!(
                    source.is_none(),
                    "Story 2.7 review patch PRIVACY REGRESSION: \
                     4xx/5xx verify failure carries a `source` error, which \
                     could leak the response body via error-chain traversal. \
                     source={source:?}"
                );
                // Story 7.12: this is a 401 (not 403) so the parser must
                // not have populated verify_reason, and even if it had,
                // the typed fields must not contain the sensitive marker.
                assert!(
                    verify_reason.is_none(),
                    "non-403 must not populate verify_reason: {verify_reason:?}"
                );
                assert_typed_reason_does_not_contain(verify_reason, sensitive_marker);
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn calendar_verify_error_body_never_leaks_into_reason() {
        // Same privacy assertion as the gmail test, for the calendar path.
        let mut server = mockito::Server::new_async().await;
        let sensitive_marker = "SENSITIVE_CALENDAR_OWNER_bob@example.com";
        let body = format!(r#"{{"error":{{"code":403,"message":"{sensitive_marker}"}}}}"#);
        let mock = server
            .mock("GET", "/calendar/v3/users/me/calendarList?maxResults=1")
            .with_status(403)
            .with_body(&body)
            .create_async()
            .await;

        let err = verify_connection_with_url("calendar", b"token", Some(&server.url()), None)
            .await
            .expect_err("should fail with 403");

        match &err {
            OAuthError::VerificationFailed {
                reason, status_code, source, verify_reason, ..
            } => {
                assert_eq!(*status_code, Some(403));
                assert!(reason.contains("403"));
                assert!(
                    !reason.contains(sensitive_marker),
                    "calendar body leaked into reason: {reason}"
                );
                // Story 2.7 review patch: lock source = None on 4xx/5xx.
                assert!(
                    source.is_none(),
                    "calendar 4xx/5xx carries a source error (potential body leak): {source:?}"
                );
                // Story 7.12: this fixture's body is NOT a Google
                // errdetails shape (it's `{"error":{"code":403,"message":...}}`
                // with no `details[]`), so the parser must return None and
                // the sensitive marker must not appear in the typed reason.
                assert!(
                    verify_reason.is_none(),
                    "malformed 403 must not populate verify_reason: {verify_reason:?}"
                );
                assert_typed_reason_does_not_contain(verify_reason, sensitive_marker);
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn drive_verify_error_body_never_leaks_into_reason() {
        // Same privacy assertion as the gmail/calendar tests, for drive.
        let mut server = mockito::Server::new_async().await;
        let sensitive_marker = "SENSITIVE_DRIVE_USER_carol@example.com";
        let body = format!(r#"{{"error":{{"code":401,"message":"{sensitive_marker}"}}}}"#);
        let mock = server
            .mock("GET", "/drive/v3/about?fields=user")
            .with_status(401)
            .with_body(&body)
            .create_async()
            .await;

        let err = verify_connection_with_url("drive", b"token", Some(&server.url()), None)
            .await
            .expect_err("should fail with 401");

        match &err {
            OAuthError::VerificationFailed {
                reason, status_code, source, verify_reason, ..
            } => {
                assert_eq!(*status_code, Some(401));
                assert!(reason.contains("401"));
                assert!(
                    !reason.contains(sensitive_marker),
                    "drive body leaked into reason: {reason}"
                );
                // Story 2.7 review patch: lock source = None on 4xx/5xx.
                assert!(
                    source.is_none(),
                    "drive 4xx/5xx carries a source error (potential body leak): {source:?}"
                );
                // Story 7.12: 401 (not 403) → no parsing → no leak.
                assert!(
                    verify_reason.is_none(),
                    "non-403 must not populate verify_reason: {verify_reason:?}"
                );
                assert_typed_reason_does_not_contain(verify_reason, sensitive_marker);
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
        mock.assert_async().await;
    }

    // R2-P13 round-2 review: extract the panic-message format strings
    // into named constants so the `#[should_panic(expected = "...")]`
    // self-tests below cannot silently desync from the assertion
    // strings in `assert_typed_reason_does_not_contain`. A future PR
    // that rewords either side will require updating both — the
    // constant is the single source of truth.
    const PRIVACY_LEAK_MSG_SERVICE: &str =
        "Story 7.12 PRIVACY REGRESSION: ServiceDisabled.service leaked";
    const PRIVACY_LEAK_MSG_SERVICE_PROJECT: &str =
        "Story 7.12 PRIVACY REGRESSION: ServiceDisabled.project leaked";
    const PRIVACY_LEAK_MSG_BILLING_PROJECT: &str =
        "Story 7.12 PRIVACY REGRESSION: BillingDisabled.project leaked";
    const PRIVACY_LEAK_MSG_SCOPE: &str =
        "Story 7.12 PRIVACY REGRESSION: ScopeInsufficient.missing_scopes leaked";

    /// Story 7.12 privacy assertion helper. Walks every owned-string
    /// field of `Option<VerifyReason>` and asserts none of them contain
    /// the sentinel marker. If a future contributor accidentally widens
    /// `parse_verify_403_reason` to copy more body content into typed
    /// fields, this helper catches it from the existing privacy tests.
    fn assert_typed_reason_does_not_contain(
        verify_reason: &Option<VerifyReason>,
        sensitive_marker: &str,
    ) {
        let Some(vr) = verify_reason else { return };
        match vr {
            VerifyReason::ServiceDisabled { service, project, .. } => {
                assert!(
                    !service.contains(sensitive_marker),
                    "{PRIVACY_LEAK_MSG_SERVICE}: {service}"
                );
                assert!(
                    project.as_deref().map(|p| !p.contains(sensitive_marker)).unwrap_or(true),
                    "{PRIVACY_LEAK_MSG_SERVICE_PROJECT}: {project:?}"
                );
            }
            VerifyReason::BillingDisabled { project } => {
                assert!(
                    project.as_deref().map(|p| !p.contains(sensitive_marker)).unwrap_or(true),
                    "{PRIVACY_LEAK_MSG_BILLING_PROJECT}: {project:?}"
                );
            }
            VerifyReason::ScopeInsufficient { missing_scopes, .. } => {
                for scope in missing_scopes {
                    assert!(!scope.contains(sensitive_marker), "{PRIVACY_LEAK_MSG_SCOPE}: {scope}");
                }
            }
            VerifyReason::Other => {}
        }
    }

    /// P5 round-1 review: self-test the privacy regression helper.
    /// Constructs each `Some(VerifyReason::*)` variant with a sentinel
    /// marker embedded in every owned-string field and asserts the
    /// helper PANICS — proving the assertion logic actually runs and
    /// would catch a future widening of `parse_verify_403_reason`.
    ///
    /// Without these self-tests, the helper sits dead in the existing
    /// privacy-leak tests (which all produce `verify_reason: None`)
    /// and would silently accept any future regression.
    #[test]
    #[should_panic(expected = "PRIVACY REGRESSION: ServiceDisabled.service leaked")]
    fn privacy_helper_self_test_catches_service_leak() {
        let leaked = Some(VerifyReason::ServiceDisabled {
            service: "calendar.googleapis.com.PRIVACY_SENTINEL".to_owned(),
            project: Some("p".to_owned()),
            also_billing_disabled: false,
        });
        assert_typed_reason_does_not_contain(&leaked, "PRIVACY_SENTINEL");
    }

    #[test]
    #[should_panic(expected = "PRIVACY REGRESSION: ServiceDisabled.project leaked")]
    fn privacy_helper_self_test_catches_service_project_leak() {
        let leaked = Some(VerifyReason::ServiceDisabled {
            service: "calendar.googleapis.com".to_owned(),
            project: Some("project-PRIVACY_SENTINEL".to_owned()),
            also_billing_disabled: false,
        });
        assert_typed_reason_does_not_contain(&leaked, "PRIVACY_SENTINEL");
    }

    #[test]
    #[should_panic(expected = "PRIVACY REGRESSION: BillingDisabled.project leaked")]
    fn privacy_helper_self_test_catches_billing_project_leak() {
        let leaked =
            Some(VerifyReason::BillingDisabled { project: Some("PRIVACY_SENTINEL".to_owned()) });
        assert_typed_reason_does_not_contain(&leaked, "PRIVACY_SENTINEL");
    }

    #[test]
    #[should_panic(expected = "PRIVACY REGRESSION: ScopeInsufficient.missing_scopes leaked")]
    fn privacy_helper_self_test_catches_scope_leak() {
        let leaked = Some(VerifyReason::ScopeInsufficient {
            missing_scopes: vec![
                "https://www.googleapis.com/auth/calendar".to_owned(),
                "https://example.com/PRIVACY_SENTINEL".to_owned(),
            ],
            also_service_disabled: None,
            also_billing_disabled: false,
        });
        assert_typed_reason_does_not_contain(&leaked, "PRIVACY_SENTINEL");
    }

    /// P5 round-1 review: positive privacy test — when the parser
    /// extracts canonical fields from a body that ALSO contains a
    /// sentinel marker in adjacent (non-allowlisted) fields, the
    /// sentinel must NOT appear in the typed reason. The validation
    /// gate (`validate_service_identifier`) should only let canonical
    /// service identifiers through.
    #[tokio::test]
    async fn verify_403_with_sensitive_adjacent_fields_does_not_leak() {
        let mut server = mockito::Server::new_async().await;
        // The sentinel marker appears in `error.message`, `domain`, and
        // a `metadata.email` field that the parser must NOT copy.
        let body = r#"{
            "error": {
                "code": 403,
                "message": "PRIVACY_SENTINEL_alice@example.com is not authorized",
                "details": [
                    {
                        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                        "reason": "SERVICE_DISABLED",
                        "domain": "PRIVACY_SENTINEL_googleapis.com",
                        "metadata": {
                            "service": "calendar.googleapis.com",
                            "email": "PRIVACY_SENTINEL_alice@example.com",
                            "consumer": "projects/PRIVACY_SENTINEL"
                        }
                    }
                ]
            }
        }"#;
        let mock = server
            .mock("GET", "/calendar/v3/users/me/calendarList?maxResults=1")
            .with_status(403)
            .with_body(body)
            .create_async()
            .await;
        let err =
            verify_connection_with_url("calendar", b"tok", Some(&server.url()), Some("my-project"))
                .await
                .expect_err("403 should fail");
        match &err {
            OAuthError::VerificationFailed { verify_reason, .. } => {
                assert_eq!(
                    verify_reason,
                    &Some(VerifyReason::ServiceDisabled {
                        service: "calendar.googleapis.com".to_owned(),
                        project: Some("my-project".to_owned()),
                        also_billing_disabled: false,
                    }),
                    "parser must extract only canonical fields"
                );
                // The helper must pass — none of the typed fields
                // carry the sentinel, even though the body did.
                assert_typed_reason_does_not_contain(verify_reason, "PRIVACY_SENTINEL");
            }
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
        mock.assert_async().await;
    }

    /// R3-P27 round-3 review: when SERVICE_DISABLED has invalid
    /// `metadata.service` AND BILLING_DISABLED is also present, the
    /// parser falls back to standalone BillingDisabled (no synthesized
    /// empty-service ServiceDisabled, no billing footer attached).
    /// Locks the defensive-depth behavior promoted from R3-D9.
    #[test]
    fn billing_disabled_returned_when_service_metadata_invalid() {
        let body = r#"{
            "error": {
                "details": [
                    {"reason": "SERVICE_DISABLED", "metadata": {"service": "evil.example.com"}},
                    {"reason": "BILLING_DISABLED"}
                ]
            }
        }"#;
        let parsed = parse_verify_403_reason(body, Some("p"));
        // The invalid service identifier (non-canonical suffix) is
        // dropped by validate_service_identifier; only BillingDisabled
        // survives. No synthesized ServiceDisabled with empty service.
        assert!(
            matches!(parsed, Some(VerifyReason::BillingDisabled { .. })),
            "expected standalone BillingDisabled, got {parsed:?}"
        );
    }

    /// R3-P15 round-3 review: parser correctly de-dupes repeated
    /// `BILLING_DISABLED` entries — the `if found_billing.is_some()
    /// { continue; }` guard fires on the second one. Coverage gap
    /// flagged by Edge Case Hunter #8.
    #[test]
    fn multi_recognized_reasons_dedupes_repeated_billing() {
        let body = r#"{
            "error": {
                "details": [
                    {"reason": "BILLING_DISABLED"},
                    {"reason": "BILLING_DISABLED"},
                    {"reason": "SERVICE_DISABLED", "metadata": {"service": "calendar.googleapis.com"}}
                ]
            }
        }"#;
        let parsed = parse_verify_403_reason(body, Some("p"));
        match parsed {
            Some(VerifyReason::ServiceDisabled { also_billing_disabled, .. }) => {
                assert!(also_billing_disabled, "duplicate BILLING_DISABLED still sets the flag");
            }
            other => panic!("expected ServiceDisabled, got {other:?}"),
        }
    }

    /// R3-P1 round-3 review: 3-reason body
    /// `[SERVICE_DISABLED, ACCESS_TOKEN_SCOPE_INSUFFICIENT, BILLING_DISABLED]`
    /// produces a `ScopeInsufficient` variant with both `also_*` flags
    /// set, so the renderer surfaces all three remediations in a single
    /// operator-facing message instead of forcing 3 sequential 403s.
    #[test]
    fn renders_full_chain_when_scope_service_billing_all_present() {
        use crate::error::OAuthError;
        let body = r#"{
            "error": {
                "details": [
                    {"reason": "SERVICE_DISABLED", "metadata": {"service": "calendar.googleapis.com"}},
                    {"reason": "ACCESS_TOKEN_SCOPE_INSUFFICIENT", "metadata": {"scope": "https://www.googleapis.com/auth/calendar.readonly"}},
                    {"reason": "BILLING_DISABLED"}
                ]
            }
        }"#;
        let parsed =
            parse_verify_403_reason(body, Some("my-project")).expect("parse should succeed");
        match &parsed {
            VerifyReason::ScopeInsufficient {
                missing_scopes,
                also_service_disabled,
                also_billing_disabled,
            } => {
                assert_eq!(missing_scopes.len(), 1);
                assert_eq!(
                    also_service_disabled.as_deref(),
                    Some("calendar.googleapis.com"),
                    "R3-P1: also_service_disabled must carry the canonical service name"
                );
                assert!(also_billing_disabled, "R3-P1: also_billing_disabled must be true");
            }
            other => panic!("expected ScopeInsufficient, got {other:?}"),
        }
        // Render and verify all three remediations appear in the
        // single operator-facing string.
        let err = OAuthError::VerificationFailed {
            service: "calendar".to_owned(),
            reason: "403 Forbidden".to_owned(),
            status_code: Some(403),
            verify_reason: Some(parsed),
            source: None,
        };
        let remediation = err.remediation_owned();
        assert!(
            remediation.contains("calendar.readonly"),
            "must include the missing scope: {remediation}"
        );
        assert!(
            remediation.contains("Then enable Calendar API in Google Cloud Console"),
            "must include the API-enablement footer: {remediation}"
        );
        assert!(
            remediation.contains("calendar.googleapis.com"),
            "must include the service URL: {remediation}"
        );
        assert!(
            remediation.contains("Then enable billing"),
            "must include the billing footer: {remediation}"
        );
    }

    /// R3-P10 round-3 review: render uses singular "scope" when
    /// missing_scopes.len() == 1.
    #[test]
    fn scope_insufficient_renders_singular_for_one_scope() {
        use crate::error::OAuthError;
        let err = OAuthError::VerificationFailed {
            service: "calendar".to_owned(),
            reason: "403".to_owned(),
            status_code: Some(403),
            verify_reason: Some(VerifyReason::ScopeInsufficient {
                missing_scopes: vec!["openid".to_owned()],
                also_service_disabled: None,
                also_billing_disabled: false,
            }),
            source: None,
        };
        let text = err.remediation_owned();
        assert!(
            text.contains("missing scope: openid"),
            "single-scope renders singular `scope:`: {text}"
        );
        assert!(
            !text.contains("missing scopes:"),
            "must NOT use plural `scopes:` for a single scope: {text}"
        );
    }

    /// R3-P23 round-3 review: OIDC opaque-scope allowlist matches
    /// case-insensitively. Pre-fix would have dropped `OpenID` /
    /// `EMAIL` / etc. from `missing_scopes`.
    #[test]
    fn parses_scope_insufficient_accepts_oidc_opaque_scopes_case_insensitive() {
        let body = r#"{"error":{"details":[{"reason":"ACCESS_TOKEN_SCOPE_INSUFFICIENT","metadata":{"scope":"OpenID Email PROFILE"}}]}}"#;
        let parsed = parse_verify_403_reason(body, None);
        match parsed {
            Some(VerifyReason::ScopeInsufficient { missing_scopes, .. }) => {
                // Returned in lowercase form for consistent rendering.
                assert_eq!(
                    missing_scopes,
                    vec!["openid".to_owned(), "email".to_owned(), "profile".to_owned()]
                );
            }
            other => panic!("expected ScopeInsufficient, got {other:?}"),
        }
    }

    /// R3-P24 round-3 review: parser dedupes repeated scopes in
    /// `missing_scopes`. Anomalous Google response with the same
    /// scope listed twice produces only one entry in the rendered
    /// remediation.
    #[test]
    fn parses_scope_insufficient_dedupes_repeated_scopes() {
        let body = r#"{"error":{"details":[{"reason":"ACCESS_TOKEN_SCOPE_INSUFFICIENT","metadata":{"scope":"https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/drive"}}]}}"#;
        let parsed = parse_verify_403_reason(body, None);
        match parsed {
            Some(VerifyReason::ScopeInsufficient { missing_scopes, .. }) => {
                assert_eq!(
                    missing_scopes,
                    vec![
                        "https://www.googleapis.com/auth/calendar".to_owned(),
                        "https://www.googleapis.com/auth/drive".to_owned(),
                    ],
                    "duplicate calendar scope must be deduped"
                );
            }
            other => panic!("expected ScopeInsufficient, got {other:?}"),
        }
    }

    /// R3-P14 round-3 review: trailing-dot service identifier coverage gap.
    #[test]
    fn rejects_service_with_trailing_dot() {
        let body = r#"{"error":{"details":[{"reason":"SERVICE_DISABLED","metadata":{"service":"calendar.googleapis.com."}}]}}"#;
        assert_eq!(
            parse_verify_403_reason(body, Some("p")),
            None,
            "trailing-dot service identifier must be rejected"
        );
    }

    /// R3-P13 round-3 review: entirely non-UTF-8 body (`valid_up_to() == 0`)
    /// produces an empty body string and `verify_reason: None`.
    #[tokio::test]
    async fn read_capped_body_handles_entirely_non_utf8_body() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/gmail/v1/users/me/profile")
            .with_status(403)
            .with_body(&[0xFFu8, 0xFE, 0xFD][..])
            .create_async()
            .await;
        let err = verify_connection_with_url("gmail", b"tok", Some(&server.url()), Some("p"))
            .await
            .expect_err("403 should fail");
        match &err {
            OAuthError::VerificationFailed { verify_reason, status_code, .. } => {
                assert_eq!(*status_code, Some(403));
                assert!(verify_reason.is_none(), "non-UTF-8 body must produce verify_reason: None");
            }
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
        mock.assert_async().await;
    }

    /// R2-P11 round-2 review: `read_capped_body` boundary tests via
    /// mockito. Round-1 P6 added the cap but no direct unit tests
    /// exercised: cap-on-first-chunk, exact-cap (off-by-one on `>`),
    /// zero-length body, and oversized body.
    ///
    /// We test these end-to-end through `verify_connection_with_url`
    /// because `read_capped_body` is private and exercising it
    /// directly would require constructing a `reqwest::Response` (no
    /// public constructor). The end-to-end path proves the same
    /// invariants since `read_capped_body` is the only body reader.
    #[tokio::test]
    async fn read_capped_body_handles_zero_length_body() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/gmail/v1/users/me/profile")
            .with_status(403)
            .with_body("")
            .create_async()
            .await;
        let err = verify_connection_with_url("gmail", b"tok", Some(&server.url()), Some("p"))
            .await
            .expect_err("403 should fail");
        match &err {
            OAuthError::VerificationFailed { verify_reason, status_code, .. } => {
                assert_eq!(*status_code, Some(403));
                assert!(verify_reason.is_none(), "empty body must produce verify_reason: None");
            }
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn read_capped_body_handles_body_at_exact_cap() {
        // Body of exactly MAX_VERIFY_RESPONSE_BYTES (65_536) bytes,
        // shaped as valid JSON but not matching the errdetails taxonomy
        // → parser returns None; behavior is correct regardless. We
        // construct the body to be exactly 65_536 bytes using a known
        // template + padding, computing the padding length so the
        // total matches the cap.
        let template_overhead = r#"{"error":{"message":"","code":403}}"#.len();
        let padding = "x".repeat(65_536 - template_overhead);
        let body = format!(r#"{{"error":{{"message":"{padding}","code":403}}}}"#);
        assert_eq!(body.len(), 65_536, "test fixture must be exactly cap bytes");
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/gmail/v1/users/me/profile")
            .with_status(403)
            .with_body(&body)
            .create_async()
            .await;
        let err = verify_connection_with_url("gmail", b"tok", Some(&server.url()), Some("p"))
            .await
            .expect_err("403 should fail");
        match &err {
            OAuthError::VerificationFailed { verify_reason, status_code, .. } => {
                assert_eq!(*status_code, Some(403));
                // Body at exactly cap is read in full; parsing may or
                // may not succeed depending on JSON validity. We only
                // assert no panic and that AC #4 holds.
                let _ = verify_reason;
            }
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
        mock.assert_async().await;
    }

    /// R2-P14 round-2 review: when upstream advertises Content-Length
    /// larger than the cap, we bail immediately rather than streaming
    /// up to the cap (slow-loris defense). Verify by mocking a body
    /// that lies about Content-Length via mockito's header injection.
    #[tokio::test]
    async fn rejects_response_with_oversize_content_length() {
        // mockito's `with_body` sets Content-Length automatically; to
        // simulate an oversize body we'd need a body that's actually
        // > 64 KiB. Here we send 70 KiB; the Content-Length pre-check
        // bails immediately and the parser never runs.
        let big_body = "x".repeat(70_000);
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/gmail/v1/users/me/profile")
            .with_status(403)
            .with_body(&big_body)
            .create_async()
            .await;
        let err = verify_connection_with_url("gmail", b"tok", Some(&server.url()), Some("p"))
            .await
            .expect_err("oversize 403 should fail");
        match &err {
            OAuthError::VerificationFailed { verify_reason, status_code, .. } => {
                assert_eq!(*status_code, Some(403));
                // R2-P14: parser never ran (Content-Length pre-check
                // bailed); verify_reason stays None.
                assert!(
                    verify_reason.is_none(),
                    "oversize body must bail before parsing: {verify_reason:?}"
                );
            }
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
        mock.assert_async().await;
    }

    /// R2-P17 round-2 review: renamed from
    /// `body_read_failure_returns_verify_reason_none`. The original
    /// name claimed to exercise the `Err(e) => return None` branch in
    /// `consume_verify_error_body`, but a clean `shutdown().await`
    /// after partial-body bytes more likely hits the JSON-parse-failure
    /// path. The behavior under test is correct regardless of which
    /// internal branch fires (AC #4: malformed/truncated body falls
    /// back to generic remediation), so the rename matches what the
    /// test actually proves.
    ///
    /// **R2-P5 round-2 review:** the prior single-shot `accept` would
    /// hang if reqwest opened a second connection. Now the server task
    /// loops on accept until cancellation, the `server_handle.await` is
    /// wrapped in `tokio::time::timeout` to bound flake-blast-radius,
    /// and the handle is `abort()`-ed after the assertion to prevent
    /// task leaks on test panic.
    ///
    /// Cfg-gated to `not(windows)`: hosted Windows runners (winsock +
    /// reqwest interaction with prematurely-closed responses) report
    /// the connection close as a transport error BEFORE the response
    /// status is captured, so `status_code` arrives as `None` instead
    /// of `Some(403)`. The behavior contract (truncated body falls
    /// back to generic remediation) is asserted on Linux + macOS;
    /// Windows-specific transport divergence is a known-but-unrelated
    /// flake (see PR #35 discussion). File a follow-up issue if needed.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn truncated_body_returns_verify_reason_none() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_handle = tokio::spawn(async move {
            // R2-P5: loop on accept until task is aborted; handle
            // multiple connections (reqwest may open a second).
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                // Use a 403 with a Content-Length much larger than the
                // bytes we'll actually send, then drop the connection.
                let resp = b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{\"partial";
                let _ = stream.write_all(resp).await;
                let _ = stream.shutdown().await;
                drop(stream);
            }
        });

        let url = format!("http://127.0.0.1:{port}");
        let err = verify_connection_with_url("gmail", b"tok", Some(&url), Some("p"))
            .await
            .expect_err("403 with truncated body should fail");

        // R2-P5: abort the listener task explicitly so it doesn't leak
        // on test panic. `abort()` is idempotent if the task already
        // exited.
        server_handle.abort();
        // Wrap the await in a 2s timeout so we don't hang the test
        // suite if the abort is racy.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_handle).await;

        match &err {
            OAuthError::VerificationFailed { verify_reason, status_code, .. } => {
                // The 403 status was received from headers...
                assert_eq!(*status_code, Some(403));
                // ...but the truncated body either fails parsing (giving
                // verify_reason: None) or the read errors out (also None).
                // Either path is acceptable; both fall back to the
                // generic remediation message per AC #4.
                assert!(
                    verify_reason.is_none(),
                    "truncated body must not yield a typed reason: {verify_reason:?}"
                );
            }
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_with_trailing_slash_base_url_produces_no_double_slash() {
        // Regression test for the `verify_*` trailing-slash issue:
        // a base_url like `http://mock/` must not produce `//gmail/...`
        // in the constructed URL. mockito::Server::url() returns
        // without a trailing slash, so we manually append one.
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/gmail/v1/users/me/profile")
            .with_status(200)
            .with_body(r#"{"emailAddress":"test@example.com"}"#)
            .create_async()
            .await;

        let trailing_base = format!("{}/", server.url());
        let result =
            verify_connection_with_url("gmail", b"tok", Some(&trailing_base), None).await.unwrap();
        assert_eq!(result.email, Some("test@example.com".to_owned()));
        mock.assert_async().await;
    }
}
