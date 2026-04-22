//! Sensitive-field filter for operational log output (Story 5.4 —
//! NFR15, AR38, FR81).
//!
//! The operational log stream passes through a byte-level prefix
//! scanner that detects and redacts the documented set of credential
//! patterns before they reach disk or stdout. This is **defense in
//! depth** — the primary protection is the type system (credentials
//! are non-`Debug` newtypes sealed by the `permitlayer-credential`
//! crate) — but a future mis-formatting bug that serializes a
//! credential via a different path would otherwise silently leak it
//! to the operator log. The scanner is the backstop.
//!
//! # Pattern coverage
//!
//! Each pattern below has a literal byte prefix and a body-byte class
//! that defines where the match stops. The scanner emits the pattern's
//! prefix + the literal `<REDACTED>` replacement in place of the
//! body; adjacent whitespace, quotes, and punctuation end the match so
//! log lines that mention the format for documentation stay readable.
//!
//! - `agt_v1_*` — permitlayer-minted bearer tokens (Story 4.4).
//! - `ya29.*` — Google OAuth 2.0 access token prefix.
//! - `1//*` — Google OAuth 2.0 refresh token prefix.
//! - `master_key=<64 hex>` / `hmac_subkey=<64 hex>` / `daemon_subkey=
//!   <64 hex>` — vault-derived hex secrets in `key=value` log form.
//! - `code_verifier=<43-128 base64url>` — PKCE code verifier in
//!   `key=value` form. Also matches `"code_verifier":"<value>"` form
//!   via a separate entry.
//! - `$argon2id$*` — Argon2id PHC-format hashes (keystore passphrase
//!   verifier strings).
//!
//! # Scope fence
//!
//! This module does NOT implement regex-based content scrubbing. The
//! [`permitlayer_core::scrub::ScrubEngine`] handles free-form body
//! content (OTPs, reset links, emails). The two live at different
//! layers: `ScrubEngine` is the audit-log pipeline's redactor;
//! [`redact_sensitive_patterns`] is the operational-log redactor.
//! See Story 5.4 Dev Notes § "Scope fence on re-scrubbing".

/// Replacement string rendered in place of any matched body. All
/// patterns share the same single replacement so operators grepping
/// for `<REDACTED>` find every scrubbed occurrence across pattern
/// families.
const REDACTED_MARKER: &[u8] = b"<REDACTED>";

/// One row of the sensitive-pattern scanner table. Each pattern is a
/// literal byte prefix plus a body-byte class that decides where the
/// match stops. Pattern order matters only when prefixes overlap — in
/// the current table the longest prefix wins naturally because every
/// pattern has a distinct fixed prefix.
#[derive(Clone, Copy)]
struct SensitivePattern {
    /// Literal byte sequence that marks the start of a credential.
    prefix: &'static [u8],
    /// Returns `true` if `byte` is a valid continuation of the
    /// credential body. The scanner consumes bytes until this returns
    /// `false`, then emits the redaction and resumes scanning.
    body_byte_class: fn(u8) -> bool,
}

/// Base64url-safe body character class used by most token formats.
/// Matches `[A-Za-z0-9_-]` — the alphabet used by `agt_v1_` tokens,
/// PKCE code verifiers, and Google OAuth tokens past the delimiter.
#[inline]
fn is_base64url_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// Google OAuth 2.0 access-token body class. Google's `ya29.` and
/// `1//` tokens are URL-safe base64 (`[A-Za-z0-9_-]`) with occasional
/// `=` padding — they do NOT contain embedded `.` or `/` after the
/// fixed prefix. Accepting `.`/`/` in the body would cause the scanner
/// to swallow whatever follows a token in a compound log line (e.g.
/// `access_token=ya29.BODY user=bob` → `access_token=ya29.BODY.user=bob`
/// if a dot happens to appear just after the real token end).
///
/// B2 fix: restrict body to `[A-Za-z0-9_\-=]` so redaction terminates
/// at any adjacent field separator.
#[inline]
fn is_google_token_body_byte(b: u8) -> bool {
    is_base64url_byte(b) || b == b'='
}

/// Hex body class used by the `master_key=`/`hmac_subkey=`/
/// `daemon_subkey=` patterns. Matches `[0-9a-fA-F]` only so a string
/// like `master_key=bad_not_hex` terminates at the underscore rather
/// than swallowing the trailing non-hex text.
#[inline]
fn is_hex_byte(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// Argon2id PHC body class. PHC strings use `[A-Za-z0-9+/=$,\-_]`.
/// `$` separates fields, `,` separates parameters, `+/=` are standard
/// base64 padding, and `-_` are URL-safe base64 characters that some
/// encoders emit in salts/hashes. B3 fix: include `-` and `_` so
/// salts/hashes encoded with URL-safe base64 do not terminate the
/// match mid-body and leave the trailing hash bytes visible.
#[inline]
fn is_argon2_body_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'$' | b',' | b'-' | b'_')
}

/// The authoritative set of sensitive patterns scrubbed from every
/// byte buffer emitted by the tracing subscribers. Keep in sync with
/// the module-level documentation and with architecture.md AR38.
const SENSITIVE_PATTERNS: &[SensitivePattern] = &[
    // Story 4.4 permitlayer bearer tokens. MUST stay in sync with
    // `permitlayer-core::agent::registry`'s `generate_bearer_token
    // _bytes` prefix. Not in the test set below because the existing
    // `telemetry/mod.rs` tests already lock this in.
    SensitivePattern { prefix: b"agt_v1_", body_byte_class: is_base64url_byte },
    // Google OAuth 2.0 access token prefix. Typical shape:
    // `ya29.a0AcM612w...`. Body extends through base64url + `.`.
    SensitivePattern { prefix: b"ya29.", body_byte_class: is_google_token_body_byte },
    // Google OAuth 2.0 refresh token prefix. Typical shape:
    // `1//0gpGnX...`. Body extends through base64url + `.` + `/`.
    SensitivePattern { prefix: b"1//", body_byte_class: is_google_token_body_byte },
    // Vault-derived hex secrets in `key=value` log form. Targeted
    // prefixes prevent false positives on generic 64-hex strings
    // (commit hashes, SHA-256 digests of non-secrets).
    SensitivePattern { prefix: b"master_key=", body_byte_class: is_hex_byte },
    SensitivePattern { prefix: b"hmac_subkey=", body_byte_class: is_hex_byte },
    SensitivePattern { prefix: b"daemon_subkey=", body_byte_class: is_hex_byte },
    // PKCE code verifier in `key=value` log form. The `CodeVerifier`
    // newtype is the primary line of defense; this catches fallback
    // cases where a future caller logs the value as a raw string.
    SensitivePattern { prefix: b"code_verifier=", body_byte_class: is_base64url_byte },
    // PKCE code verifier in JSON-style `"code_verifier":"<value>"`
    // form. Matches the opening sequence through to the first
    // non-base64url character (typically the closing `"`).
    SensitivePattern { prefix: b"\"code_verifier\":\"", body_byte_class: is_base64url_byte },
    // Argon2id PHC-format hashes (keystore passphrase verifier
    // strings, e.g. `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`).
    SensitivePattern { prefix: b"$argon2id$", body_byte_class: is_argon2_body_byte },
];

/// Scan `buf` for every [`SensitivePattern`] and replace each match's
/// body with the shared `<REDACTED>` marker. Allocates a fresh
/// `Vec<u8>` only when at least one match is found; otherwise returns
/// a verbatim copy of the input (the copy keeps the `Vec<u8>`-return
/// signature uniform for the callers; the Write trait implementations
/// in `telemetry/mod.rs` tolerate the copy cost).
///
/// The scanner is a single linear pass: at each byte position, it
/// checks whether any pattern's prefix starts there. If so, it emits
/// the prefix + redaction marker and skips the body; otherwise it
/// copies the byte verbatim and advances by one. Worst-case complexity
/// is `O(n × P)` where `P` is the number of patterns — a small
/// constant — so the runtime is effectively linear in buffer length.
pub fn redact_sensitive_patterns(buf: &[u8]) -> Vec<u8> {
    // Fast path: if no pattern's prefix appears anywhere in the buffer,
    // return the input unchanged. This is the common case for log
    // lines that don't touch credential material.
    if !any_pattern_prefix_present(buf) {
        return buf.to_vec();
    }

    let mut out = Vec::with_capacity(buf.len());
    let mut i = 0;
    while i < buf.len() {
        if let Some(pattern) = matching_pattern_at(buf, i) {
            out.extend_from_slice(pattern.prefix);
            out.extend_from_slice(REDACTED_MARKER);
            let mut j = i + pattern.prefix.len();
            while j < buf.len() && (pattern.body_byte_class)(buf[j]) {
                j += 1;
            }
            i = j;
        } else {
            out.push(buf[i]);
            i += 1;
        }
    }
    out
}

/// Return the first [`SensitivePattern`] whose prefix starts at
/// `buf[start..]`, or `None` if no pattern matches.
fn matching_pattern_at(buf: &[u8], start: usize) -> Option<SensitivePattern> {
    SENSITIVE_PATTERNS.iter().find(|p| buf[start..].starts_with(p.prefix)).copied()
}

/// Quick existence check: does `buf` contain any pattern prefix? Used
/// to skip the allocation path on the common no-match case.
fn any_pattern_prefix_present(buf: &[u8]) -> bool {
    SENSITIVE_PATTERNS.iter().any(|p| contains_subslice(buf, p.prefix))
}

#[inline]
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ── agt_v1_* bearer tokens (existing coverage preserved) ────────

    #[test]
    fn redacts_agt_v1_bearer_token() {
        let input = b"Authorization: Bearer agt_v1_abcDEF012345xyz trailing";
        let output = redact_sensitive_patterns(input);
        assert_eq!(output, b"Authorization: Bearer agt_v1_<REDACTED> trailing".to_vec());
    }

    #[test]
    fn redacts_multiple_agt_v1_tokens() {
        let input = b"old=agt_v1_AAAA new=agt_v1_BBBB";
        let output = redact_sensitive_patterns(input);
        assert_eq!(output, b"old=agt_v1_<REDACTED> new=agt_v1_<REDACTED>".to_vec());
    }

    // ── ya29.* Google OAuth access tokens ──────────────────────────

    #[test]
    fn redacts_ya29_google_access_token() {
        let input = b"access_token=ya29.a0AcM612wSecretBody-_ abc";
        let output = redact_sensitive_patterns(input);
        assert_eq!(output, b"access_token=ya29.<REDACTED> abc".to_vec());
    }

    #[test]
    fn does_not_redact_partial_ya29_match() {
        // Match requires the literal `ya29.` prefix; `ya29 ` alone
        // (space after) must NOT match.
        let input = b"service version=ya29 deployment target";
        let output = redact_sensitive_patterns(input);
        assert_eq!(output, input.to_vec());
    }

    #[test]
    fn ya29_body_terminates_at_second_dot_to_preserve_following_field() {
        // B2 regression lock: a log line concatenating a token with a
        // trailing structured field must NOT have the field absorbed
        // into the redaction. The body class rejects `.` so the match
        // ends at the FIRST dot-terminated segment after the prefix.
        let input = b"access_token=ya29.BODY.user=bob";
        let output = redact_sensitive_patterns(input);
        assert_eq!(output, b"access_token=ya29.<REDACTED>.user=bob".to_vec());
    }

    #[test]
    fn ya29_body_accepts_base64_padding_equals() {
        // L18: some Google OAuth tokens include `=` padding at the
        // tail. The body class must accept it so the padded suffix is
        // redacted with the rest of the body.
        let input = b"access_token=ya29.AbCdEfGhIjKl== next=field";
        let output = redact_sensitive_patterns(input);
        assert_eq!(output, b"access_token=ya29.<REDACTED> next=field".to_vec());
    }

    // ── 1// Google OAuth refresh tokens ────────────────────────────

    #[test]
    fn redacts_1_slash_slash_refresh_token() {
        let input = b"refresh_token=1//0gpGnXsecretBody end";
        let output = redact_sensitive_patterns(input);
        assert_eq!(output, b"refresh_token=1//<REDACTED> end".to_vec());
    }

    #[test]
    fn does_not_redact_plain_1_slash() {
        // A legitimate log line containing `version 1/2 rolled out`
        // must not trigger the `1//` match.
        let input = b"version 1/2 rolled out";
        let output = redact_sensitive_patterns(input);
        assert_eq!(output, input.to_vec());
    }

    #[test]
    fn one_slash_slash_body_stops_before_trailing_path() {
        // B2 regression lock: a `1//` token followed by a path-like
        // suffix must not absorb the path. `/` is no longer in the
        // body class so the match ends at the first `/` after the
        // fixed prefix.
        let input = b"refresh_token=1//BODY/path/to/anything";
        let output = redact_sensitive_patterns(input);
        assert_eq!(output, b"refresh_token=1//<REDACTED>/path/to/anything".to_vec());
    }

    // ── master_key / hmac_subkey / daemon_subkey hex secrets ──────

    #[test]
    fn redacts_master_key_hex_value() {
        let input = b"loaded master_key=0123456789abcdefDEADBEEF rest";
        let output = redact_sensitive_patterns(input);
        assert_eq!(output, b"loaded master_key=<REDACTED> rest".to_vec());
    }

    #[test]
    fn redacts_hmac_subkey_hex_value() {
        let input = b"derived hmac_subkey=fedcba9876543210 more";
        let output = redact_sensitive_patterns(input);
        assert_eq!(output, b"derived hmac_subkey=<REDACTED> more".to_vec());
    }

    #[test]
    fn redacts_daemon_subkey_hex_value() {
        let input = b"daemon_subkey=aabbccddeeff0011 trailing";
        let output = redact_sensitive_patterns(input);
        assert_eq!(output, b"daemon_subkey=<REDACTED> trailing".to_vec());
    }

    #[test]
    fn master_key_body_stops_at_non_hex() {
        let input = b"master_key=abcDEF_not_hex";
        let output = redact_sensitive_patterns(input);
        // Hex class is [0-9a-fA-F]; `_` terminates the body.
        assert_eq!(output, b"master_key=<REDACTED>_not_hex".to_vec());
    }

    #[test]
    fn does_not_redact_master_key_log_field_name_alone() {
        // Mention of the field name WITHOUT the `=` delimiter and body
        // must not trigger redaction.
        let input = b"about master_key rotation policy";
        let output = redact_sensitive_patterns(input);
        assert_eq!(output, input.to_vec());
    }

    // ── PKCE code_verifier (key=value form) ────────────────────────

    #[test]
    fn redacts_code_verifier_key_value_form() {
        let input = b"code_verifier=abc123DEF_-xyz end";
        let output = redact_sensitive_patterns(input);
        assert_eq!(output, b"code_verifier=<REDACTED> end".to_vec());
    }

    // ── PKCE code_verifier (JSON form) ─────────────────────────────

    #[test]
    fn redacts_code_verifier_json_form() {
        let input = br#"{"code_verifier":"xyz-123_SecretBody","other":1}"#;
        let output = redact_sensitive_patterns(input);
        assert_eq!(output, br#"{"code_verifier":"<REDACTED>","other":1}"#.to_vec());
    }

    // ── Argon2id PHC hashes ────────────────────────────────────────

    #[test]
    fn redacts_argon2id_phc_hash() {
        let input = b"stored $argon2id$v=19$m=19456,t=2,p=1$salt$hash trailing";
        let output = redact_sensitive_patterns(input);
        assert_eq!(output, b"stored $argon2id$<REDACTED> trailing".to_vec());
    }

    #[test]
    fn argon2id_body_accepts_urlsafe_base64_salt_and_hash() {
        // B3 regression lock: salts/hashes encoded with URL-safe
        // base64 (`-` and `_` instead of `+`/`/`) must be fully
        // consumed by the match so the trailing bytes are redacted
        // with the rest of the hash.
        let input = b"verifier $argon2id$v=19$m=19456,t=2,p=1$salt-With_Dashes$hash-_ trailing";
        let output = redact_sensitive_patterns(input);
        assert_eq!(output, b"verifier $argon2id$<REDACTED> trailing".to_vec());
    }

    #[test]
    fn does_not_redact_mention_of_argon2id_algorithm() {
        // Without the leading `$` the string is just a named
        // algorithm reference and must NOT be redacted.
        let input = b"using argon2id for key derivation";
        let output = redact_sensitive_patterns(input);
        assert_eq!(output, input.to_vec());
    }

    // ── General scanner invariants ─────────────────────────────────

    #[test]
    fn passes_through_non_sensitive_content() {
        let input = b"plain log line with no secrets";
        let output = redact_sensitive_patterns(input);
        assert_eq!(output, input.to_vec());
    }

    #[test]
    fn redacts_multiple_distinct_patterns_in_one_line() {
        let input = b"token=agt_v1_AAA access=ya29.BBB refresh=1//CCC";
        let output = redact_sensitive_patterns(input);
        assert_eq!(
            output,
            b"token=agt_v1_<REDACTED> access=ya29.<REDACTED> refresh=1//<REDACTED>".to_vec()
        );
    }

    #[test]
    fn prefix_only_still_redacted() {
        let input = b"token=agt_v1_";
        let output = redact_sensitive_patterns(input);
        assert_eq!(output, b"token=agt_v1_<REDACTED>".to_vec());
    }

    #[test]
    fn body_ends_at_quote_boundary() {
        let input = br#"{"token":"agt_v1_abcDEF123"}"#;
        let output = redact_sensitive_patterns(input);
        assert_eq!(output, br#"{"token":"agt_v1_<REDACTED>"}"#.to_vec());
    }

    #[test]
    fn empty_buffer_returns_empty() {
        let input: &[u8] = b"";
        let output = redact_sensitive_patterns(input);
        assert!(output.is_empty());
    }
}
