//! Headless OAuth flow: print the auth URL, accept a pasted redirect
//! URL from the operator, validate it, exchange the code for tokens.
//!
//! # Why this module exists
//!
//! `OAuthClient::authorize` (in `client.rs`) spawns a loopback TCP
//! listener and waits for the operator's browser to redirect back to
//! it. That works when the browser is on the same machine as the
//! daemon — but not when the operator is SSH'd in from another
//! machine. In the SSH case, the browser is on the operator's local
//! laptop, and the redirect URL points at `127.0.0.1` of that laptop,
//! which the daemon can't reach.
//!
//! `authorize_headless` solves this by NOT spawning a callback
//! listener. Instead, the daemon prints the consent URL, the operator
//! opens it in any browser they like, approves consent, then copies
//! the resulting redirect URL (which their browser cannot actually
//! load — `127.0.0.1:<port>` doesn't exist on their laptop) and
//! pastes it back into the daemon's terminal. The daemon parses the
//! pasted URL, validates the CSRF state, and exchanges the code for
//! tokens.
//!
//! # Why we still bind a port
//!
//! Google's OAuth API requires the `redirect_uri` parameter at auth
//! request time to match the one used at token-exchange time
//! (`oauth2-rs` enforces this on our side via `set_redirect_uri`).
//! That redirect URI must look like `http://127.0.0.1:{port}/callback`
//! to match the OAuth client config registered in Google Cloud
//! Console. The PORT must be a real, currently-available port (Chrome
//! refuses to even visit `127.0.0.1:1`).
//!
//! Solution: bind 127.0.0.1:0, capture the ephemeral port, then drop
//! the listener immediately. We use the captured port string in both
//! the auth URL we print and the redirect_uri at token exchange. The
//! operator's browser tries to load that URL after consent, gets
//! "connection refused", and the operator copies the URL from the
//! address bar — which is exactly what we need.
//!
//! There's a tiny race between dropping the listener and the
//! operator's browser following the redirect: another process could
//! claim the port. Negligible — and even if it happened, the redirect
//! would land on the unrelated process, fail there, and the operator
//! would still copy the URL from the browser's address bar (the URL
//! is in the address bar regardless of whether the connection
//! succeeds).

use subtle::ConstantTimeEq;
use url::Url;

use crate::error::OAuthError;

/// Bracketed-paste markers that some terminals (iTerm2, Kitty,
/// Wezterm, modern xterm with `?2004h` enabled) wrap pasted text
/// with. Strip these before URL parsing.
const BRACKETED_PASTE_START: &str = "\x1b[200~";
const BRACKETED_PASTE_END: &str = "\x1b[201~";

/// Parse a pasted OAuth redirect URL, validate it against the
/// expected callback shape and CSRF state, and return the
/// authorization code.
///
/// `expected_redirect_uri` MUST be exactly the redirect_uri we passed
/// to Google at auth-URL construction time. We compare scheme, host,
/// port, and path strictly: any difference rejects the paste with
/// `PastedUrlMismatch`.
///
/// `expected_state` is the CSRF token we generated at the start of
/// the flow. We compare it to the pasted URL's `state` parameter via
/// constant-time comparison (mirrors `callback.rs`'s validation).
pub(crate) fn parse_redirect_url(
    pasted: &str,
    expected_redirect_uri: &str,
    expected_state: &str,
) -> Result<String, OAuthError> {
    // Strip whitespace and bracketed-paste markers. Order:
    // 1. Trim outer whitespace (operator's stray newline).
    // 2. Strip ALL leading start markers (some terminals double-bracket).
    // 3. Strip ALL trailing end markers (same reason).
    // 4. Trim again (markers may have been adjacent to inner ws).
    //
    // The while-loops handle terminals that emit nested bracketed-paste
    // sequences (rare but real: certain terminal multiplexer + emulator
    // combinations forward the inner emitter's brackets verbatim,
    // resulting in `\e[200~\e[200~URL\e[201~\e[201~`). A single
    // `strip_prefix` would leave the inner `\e[200~` in the URL and
    // `Url::parse` would fail with `PastedUrlMalformed`.
    let mut s = pasted.trim();
    while let Some(rest) = s.strip_prefix(BRACKETED_PASTE_START) {
        s = rest;
    }
    while let Some(rest) = s.strip_suffix(BRACKETED_PASTE_END) {
        s = rest;
    }
    let trimmed = s.trim();

    let url = Url::parse(trimmed).map_err(|_| OAuthError::PastedUrlMalformed)?;

    // Strict structural match. The redirect_uri we issued is built
    // by us, so it WILL parse — using `expect` would be acceptable,
    // but a defensive `map_err` is cheap.
    let expected = Url::parse(expected_redirect_uri).map_err(|_| OAuthError::PastedUrlMalformed)?;

    if url.scheme() != expected.scheme()
        || url.host_str() != expected.host_str()
        || url.port() != expected.port()
        || url.path() != expected.path()
    {
        let got = format!(
            "{}://{}{}{}",
            url.scheme(),
            url.host_str().unwrap_or("?"),
            url.port().map(|p| format!(":{p}")).unwrap_or_default(),
            url.path(),
        );
        return Err(OAuthError::PastedUrlMismatch { got });
    }

    let mut code = None;
    let mut state = None;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            "error" => {
                // Google encodes user denial as `error=access_denied`
                // in the redirect (mirrors callback.rs:162).
                return Err(OAuthError::UserDeniedConsent { service: "google-oauth".to_owned() });
            }
            _ => {}
        }
    }

    let code = code.ok_or(OAuthError::PastedUrlMissingCode)?;
    let state = state.ok_or(OAuthError::PastedUrlMissingState)?;

    // CSRF check via constant-time compare. `ct_eq` returns
    // `Choice::from(0|1)`; `.unwrap_u8()` extracts the `u8`.
    if state.as_bytes().ct_eq(expected_state.as_bytes()).unwrap_u8() != 1 {
        return Err(OAuthError::PastedUrlStateMismatch);
    }

    Ok(code)
}

/// Reserve an ephemeral port by binding 127.0.0.1:0 and immediately
/// dropping the listener. Returns the port number that was assigned.
///
/// The captured port is reused as the `:port` in the redirect URI for
/// both the auth-URL and the token-exchange. The operator's browser
/// will try to connect to `127.0.0.1:{port}` after consent and get
/// "connection refused" — that's expected. They copy the URL from
/// their browser's address bar.
pub(crate) async fn reserve_ephemeral_port() -> Result<u16, OAuthError> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| OAuthError::CallbackServerFailed { source: e })?;
    let port =
        listener.local_addr().map_err(|e| OAuthError::CallbackServerFailed { source: e })?.port();
    // Drop happens automatically at end of scope, but make it
    // explicit for clarity: we are NOT going to listen on this port.
    drop(listener);
    Ok(port)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const REDIRECT: &str = "http://127.0.0.1:54321/callback";
    const STATE: &str = "csrf-state-token-abc";

    fn make_url(code: &str, state: &str) -> String {
        format!("{REDIRECT}?code={code}&state={state}")
    }

    #[test]
    fn happy_path_returns_code() {
        let pasted = make_url("auth-code-xyz", STATE);
        let code = parse_redirect_url(&pasted, REDIRECT, STATE).expect("happy path parses");
        assert_eq!(code, "auth-code-xyz");
    }

    #[test]
    fn happy_path_with_extra_params_still_works() {
        // Google often adds `scope=...` and `authuser=...`.
        let pasted = format!(
            "{REDIRECT}?state={STATE}&code=auth-code-xyz&scope=https://www.googleapis.com/auth/gmail.readonly&authuser=0"
        );
        let code = parse_redirect_url(&pasted, REDIRECT, STATE).expect("extra params ignored");
        assert_eq!(code, "auth-code-xyz");
    }

    #[test]
    fn state_mismatch_rejected() {
        let pasted = make_url("auth-code-xyz", "wrong-state-token");
        let result = parse_redirect_url(&pasted, REDIRECT, STATE);
        assert!(matches!(result, Err(OAuthError::PastedUrlStateMismatch)), "got {result:?}");
    }

    #[test]
    fn missing_code_rejected() {
        let pasted = format!("{REDIRECT}?state={STATE}");
        let result = parse_redirect_url(&pasted, REDIRECT, STATE);
        assert!(matches!(result, Err(OAuthError::PastedUrlMissingCode)), "got {result:?}");
    }

    #[test]
    fn missing_state_rejected() {
        let pasted = format!("{REDIRECT}?code=auth-code-xyz");
        let result = parse_redirect_url(&pasted, REDIRECT, STATE);
        assert!(matches!(result, Err(OAuthError::PastedUrlMissingState)), "got {result:?}");
    }

    #[test]
    fn malformed_url_rejected() {
        let pasted = "this is not a url at all";
        let result = parse_redirect_url(pasted, REDIRECT, STATE);
        assert!(matches!(result, Err(OAuthError::PastedUrlMalformed)), "got {result:?}");
    }

    #[test]
    fn wrong_scheme_rejected() {
        let pasted = format!("https://127.0.0.1:54321/callback?code=x&state={STATE}");
        let result = parse_redirect_url(&pasted, REDIRECT, STATE);
        assert!(matches!(result, Err(OAuthError::PastedUrlMismatch { .. })), "got {result:?}");
    }

    #[test]
    fn wrong_host_rejected() {
        let pasted = format!("http://accounts.google.com:54321/callback?code=x&state={STATE}");
        let result = parse_redirect_url(&pasted, REDIRECT, STATE);
        assert!(matches!(result, Err(OAuthError::PastedUrlMismatch { .. })), "got {result:?}");
    }

    #[test]
    fn wrong_port_rejected() {
        // 8080 vs the expected 54321 — would happen if operator pasted
        // from a previous setup session that bound a different port.
        let pasted = format!("http://127.0.0.1:8080/callback?code=x&state={STATE}");
        let result = parse_redirect_url(&pasted, REDIRECT, STATE);
        assert!(matches!(result, Err(OAuthError::PastedUrlMismatch { .. })), "got {result:?}");
    }

    #[test]
    fn wrong_path_rejected() {
        let pasted = format!("http://127.0.0.1:54321/some-other-path?code=x&state={STATE}");
        let result = parse_redirect_url(&pasted, REDIRECT, STATE);
        assert!(matches!(result, Err(OAuthError::PastedUrlMismatch { .. })), "got {result:?}");
    }

    #[test]
    fn user_denied_consent_recognized() {
        // Google's deny shape: the redirect carries `?error=access_denied`
        // instead of `code` + `state`.
        let pasted = format!("{REDIRECT}?error=access_denied&state={STATE}");
        let result = parse_redirect_url(&pasted, REDIRECT, STATE);
        assert!(matches!(result, Err(OAuthError::UserDeniedConsent { .. })), "got {result:?}");
    }

    #[test]
    fn bracketed_paste_markers_stripped() {
        // Modern terminals wrap pastes in \e[200~...\e[201~. The
        // markers must be stripped before URL parsing or url::Url::parse
        // fails opaquely. (Includes a leading newline because some
        // operators paste-then-Enter and some paste with the URL on
        // its own line.)
        let core = make_url("auth-code-xyz", STATE);
        let pasted = format!("{BRACKETED_PASTE_START}{core}{BRACKETED_PASTE_END}");
        let code = parse_redirect_url(&pasted, REDIRECT, STATE).expect("brackets stripped");
        assert_eq!(code, "auth-code-xyz");
    }

    #[test]
    fn bracketed_paste_with_surrounding_whitespace() {
        let core = make_url("auth-code-xyz", STATE);
        let pasted = format!("  \n{BRACKETED_PASTE_START}{core}{BRACKETED_PASTE_END}\n  ");
        let code = parse_redirect_url(&pasted, REDIRECT, STATE).expect("strips ws + brackets");
        assert_eq!(code, "auth-code-xyz");
    }

    /// Some terminal multiplexer + emulator combinations forward the
    /// inner emitter's bracketed-paste sequences verbatim, producing
    /// `\e[200~\e[200~URL\e[201~\e[201~`. The strip code uses
    /// while-loops to handle this; a single `strip_prefix`/`strip_suffix`
    /// would leave the inner markers in the URL and `Url::parse` would
    /// fail with `PastedUrlMalformed`.
    #[test]
    fn double_bracketed_paste_stripped() {
        let core = make_url("auth-code-xyz", STATE);
        let pasted = format!(
            "{BRACKETED_PASTE_START}{BRACKETED_PASTE_START}{core}\
             {BRACKETED_PASTE_END}{BRACKETED_PASTE_END}"
        );
        let code = parse_redirect_url(&pasted, REDIRECT, STATE).expect("strips both layers");
        assert_eq!(code, "auth-code-xyz");
    }

    #[test]
    fn ephemeral_port_reservation_returns_real_port() {
        let rt = tokio::runtime::Runtime::new().expect("rt");
        let port = rt.block_on(reserve_ephemeral_port()).expect("port reserved");
        // Port 0 is the "any" sentinel; the OS-assigned port is
        // always non-zero and always above 1024 on a non-root
        // process.
        assert!(port > 0);
        assert!(port > 1024, "ephemeral port should be in unprivileged range, got {port}");
    }
}
