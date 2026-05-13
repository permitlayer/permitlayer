//! OAuth 2.1 client wrapping `oauth2::BasicClient`.
//!
//! Handles the full authorization code flow with PKCE:
//! 1. Generate PKCE challenge + verifier
//! 2. Spawn ephemeral loopback callback server
//! 3. Construct authorization URL and open browser
//! 4. Await callback with authorization code
//! 5. Exchange code for tokens
//! 6. Convert to `permitlayer-credential` types at the boundary

use std::time::Duration;

use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet, EndpointSet,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use permitlayer_credential::{OAuthRefreshToken, OAuthToken};

use crate::callback;
use crate::error::OAuthError;
use crate::pkce;

/// Google OAuth 2.0 endpoints.
const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// Concrete `BasicClient` type with auth URL and token URL set.
pub(crate) type ConfiguredClient =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

/// Result of a successful OAuth authorization.
pub struct AuthorizeResult {
    /// The access token, wrapped in `OAuthToken` for credential discipline.
    pub access_token: OAuthToken,
    /// The refresh token (if granted), wrapped in `OAuthRefreshToken`.
    pub refresh_token: Option<OAuthRefreshToken>,
    /// Token expiry duration (if provided by the server).
    pub expires_in: Option<Duration>,
    /// Scopes that were actually granted (may differ from requested).
    pub scopes: Vec<String>,
}

/// OAuth 2.1 client for Google services.
pub struct OAuthClient {
    inner: ConfiguredClient,
    http_client: reqwest::Client,
}

impl OAuthClient {
    /// Construct a new OAuth client for Google.
    ///
    /// `client_id` and `client_secret` are passed in — Story 1.7 decides
    /// which client (CASA vs BYO).
    pub fn new(client_id: String, client_secret: Option<String>) -> Result<Self, OAuthError> {
        Self::build(client_id, client_secret, GOOGLE_AUTH_URL, GOOGLE_TOKEN_URL)
    }

    /// Construct an OAuth client with explicit authorization and token
    /// endpoint URLs, bypassing the Google defaults used by [`Self::new`].
    ///
    /// **Test harness and advanced-debugging constructor.** Production
    /// callers should use [`Self::new`] and let it default to Google's
    /// endpoints. This exists because integration tests in downstream
    /// crates (specifically `crates/permitlayer-proxy/tests/refresh_integration.rs`,
    /// Story 1.14a) need to point the OAuth client at a mock localhost
    /// server, and a crate-private `#[cfg(test)]` gate is not visible
    /// across crate boundaries (tests in other crates link against the
    /// library's non-test compilation unit).
    ///
    /// The function is `pub #[doc(hidden)]` so it does not appear in
    /// rustdoc output and is not part of the stable public API. Do not
    /// depend on this symbol in production code — it may be renamed or
    /// removed without notice if a cleaner test seam becomes available.
    ///
    /// Gated behind the `test-seam` Cargo feature so it is never compiled
    /// into production binaries, only into test builds and dev-dependency
    /// consumers that explicitly opt in.
    #[cfg(any(test, feature = "test-seam"))]
    #[doc(hidden)]
    pub fn new_with_endpoint_overrides(
        client_id: String,
        client_secret: Option<String>,
        auth_url: &str,
        token_url: &str,
    ) -> Result<Self, OAuthError> {
        Self::build(client_id, client_secret, auth_url, token_url)
    }

    fn build(
        client_id: String,
        client_secret: Option<String>,
        auth_url: &str,
        token_url: &str,
    ) -> Result<Self, OAuthError> {
        let client_id = ClientId::new(client_id);

        let mut builder = BasicClient::new(client_id)
            .set_auth_uri(AuthUrl::new(auth_url.to_owned()).map_err(|_| {
                OAuthError::TokenExchangeFailed {
                    service: "google-oauth".to_owned(),
                    source: "invalid auth URL".into(),
                }
            })?)
            .set_token_uri(TokenUrl::new(token_url.to_owned()).map_err(|_| {
                OAuthError::TokenExchangeFailed {
                    service: "google-oauth".to_owned(),
                    source: "invalid token URL".into(),
                }
            })?);

        if let Some(secret) = client_secret {
            builder = builder.set_client_secret(ClientSecret::new(secret));
        }

        let http_client =
            reqwest::ClientBuilder::new().build().map_err(|e| OAuthError::TokenExchangeFailed {
                service: "google-oauth".to_owned(),
                source: Box::new(e),
            })?;

        Ok(Self { inner: builder, http_client })
    }

    /// Run the full OAuth 2.1 authorization code flow with PKCE,
    /// using a local callback server.
    ///
    /// 1. Generates PKCE challenge + verifier
    /// 2. Spawns ephemeral callback server
    /// 3. Opens the operator's default browser to the consent screen;
    ///    on `open::that()` failure (no GUI, headless context), falls
    ///    back to printing the URL so a same-host browser can be
    ///    pointed at it manually
    /// 4. Awaits callback with authorization code
    /// 5. Exchanges code for tokens
    /// 6. Returns tokens wrapped in credential types
    ///
    /// For SSH-from-another-machine (where the operator's local
    /// browser cannot reach this host's loopback), use
    /// [`Self::authorize_headless`] instead — it skips the listener
    /// entirely and reads the redirect URL via stdin paste.
    pub async fn authorize(
        &self,
        scopes: Vec<String>,
        timeout: Option<Duration>,
    ) -> Result<AuthorizeResult, OAuthError> {
        // Generate PKCE.
        let (pkce_challenge, pkce_verifier) = pkce::generate_pkce();

        // Generate CSRF state token.
        let csrf_state = CsrfToken::new_random();

        // Spawn callback server BEFORE constructing auth URL (need redirect_uri).
        let callback_server =
            callback::spawn_callback_server(csrf_state.secret().clone(), timeout).await?;

        // Set redirect URI on the client for this request.
        let redirect_url =
            RedirectUrl::new(callback_server.redirect_uri.to_string()).map_err(|_| {
                OAuthError::CallbackServerFailed {
                    source: std::io::Error::other("invalid redirect URL"),
                }
            })?;

        // Build authorization URL.
        let mut auth_request = self
            .inner
            .authorize_url(|| csrf_state)
            .set_pkce_challenge(pkce_challenge)
            .set_redirect_uri(std::borrow::Cow::Owned(redirect_url));

        for scope in &scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.clone()));
        }

        let (auth_url, _csrf_token) = auth_request.url();

        // Story 7.30 AC #9: detect SSH / sudo / no-Aqua contexts and
        // skip `open::that()` entirely. Per Apple DTS Quinn (thread
        // 756081) and TN2083, `/usr/bin/open` is AppKit-linked and
        // "isn't rated for use in a non-GUI context" — it silently
        // fails with `LSOpenURLsWithRole() failed with error -54` on
        // SSH-only sessions. Surface a copy-paste URL block + suggest
        // `--headless` / `--device-flow` instead.
        let url_string = auth_url.to_string();
        if should_skip_browser_open() {
            tracing::info!("skipping browser open: detected non-GUI / cross-session context");
            print_non_gui_consent_block(&url_string, None);
        } else {
            // `open::that()` returns when LaunchServices (or xdg-open /
            // `start`) *accepts* the URL — microseconds, not "browser
            // is on-screen." A wall-clock timeout doesn't help: it
            // either fires before the accept (false positive) or after
            // a slow accept that already succeeded. And tokio's
            // `timeout` would not cancel the inner `spawn_blocking`
            // worker anyway, so a wedged accept would leak the worker
            // thread.
            //
            // Instead: rely on `should_skip_browser_open()` to catch
            // known-bad contexts up front, and route any `Err` from
            // `open::that()` itself to the same non-GUI consent block
            // (with the underlying io::Error rendered so the operator
            // can distinguish "xdg-open missing" from "we decided not
            // to try"). A `spawn_blocking` join failure — runtime
            // shutdown or panic — aborts the whole `authorize` call
            // since there's no useful recovery.
            let url_for_open = url_string.clone();
            let open_result = tokio::task::spawn_blocking(move || open::that(&url_for_open))
                .await
                .map_err(|e| OAuthError::BrowserOpenFailed {
                    source: std::io::Error::other(e.to_string()),
                })?;
            if let Err(e) = open_result {
                tracing::warn!(err = %e, "browser open failed; falling back to manual copy");
                print_non_gui_consent_block(&url_string, Some(&e));
            }
        }

        // Await authorization code from callback server.
        let code =
            callback_server.code_receiver.await.map_err(|_| OAuthError::CallbackTimeout {
                timeout_secs: timeout.unwrap_or(Duration::from_secs(120)).as_secs(),
            })??;

        // Exchange code for tokens.
        let redirect_url_for_exchange = RedirectUrl::new(callback_server.redirect_uri.to_string())
            .map_err(|_| OAuthError::CallbackServerFailed {
                source: std::io::Error::other("invalid redirect URL for exchange"),
            })?;

        let token_response = self
            .inner
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(pkce_verifier)
            .set_redirect_uri(std::borrow::Cow::Owned(redirect_url_for_exchange))
            .request_async(&self.http_client)
            .await
            .map_err(|e| OAuthError::TokenExchangeFailed {
                service: "google-oauth".to_owned(),
                source: Box::new(e),
            })?;

        // Convert to credential types IMMEDIATELY — no intermediate String
        // variables holding token values (scoped token exposure, guardrail #9).
        let access_token = OAuthToken::from_trusted_bytes(
            token_response.access_token().secret().as_bytes().to_vec(),
        );

        let refresh_token = token_response
            .refresh_token()
            .map(|rt| OAuthRefreshToken::from_trusted_bytes(rt.secret().as_bytes().to_vec()));

        let expires_in = token_response.expires_in();

        let scopes = token_response
            .scopes()
            .map(|s| s.iter().map(|scope| scope.to_string()).collect())
            .unwrap_or_default();

        Ok(AuthorizeResult { access_token, refresh_token, expires_in, scopes })
    }

    /// Run the OAuth authorization flow in headless mode: print the
    /// auth URL via the caller's `paste_url_renderer`, expect the
    /// caller to return the operator's pasted redirect URL, validate
    /// it, and exchange the code for tokens.
    ///
    /// This is the SSH-from-another-machine path: there is no usable
    /// browser on this host AND no callback listener is spawned. The
    /// operator opens the URL on their local machine, approves
    /// consent, and pastes the resulting `http://127.0.0.1:<port>/...`
    /// redirect URL back into the daemon's terminal.
    ///
    /// `paste_url_renderer` is owned by the caller (`cli/setup.rs`)
    /// because it runs the operator-facing terminal interaction —
    /// printing the URL, attempting an OSC 52 clipboard copy, reading
    /// stdin with a bounded timeout. This crate doesn't bundle
    /// terminal UX.
    pub async fn authorize_headless<F, Fut>(
        &self,
        scopes: Vec<String>,
        paste_url_renderer: F,
    ) -> Result<AuthorizeResult, OAuthError>
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = Result<String, OAuthError>>,
    {
        // Generate PKCE.
        let (pkce_challenge, pkce_verifier) = pkce::generate_pkce();

        // Generate CSRF state token.
        let csrf_state = CsrfToken::new_random();
        let csrf_state_secret = csrf_state.secret().clone();

        // Reserve an ephemeral port (bind 127.0.0.1:0, capture, drop).
        // The port becomes part of the redirect_uri Google will
        // validate AND the URL the operator's browser shows after
        // consent. We never actually listen on it.
        let port = crate::headless::reserve_ephemeral_port().await?;
        let redirect_uri_str = format!("http://127.0.0.1:{port}/callback");
        let redirect_url = RedirectUrl::new(redirect_uri_str.clone()).map_err(|_| {
            OAuthError::CallbackServerFailed {
                source: std::io::Error::other("invalid redirect URL"),
            }
        })?;

        // Build authorization URL.
        let mut auth_request = self
            .inner
            .authorize_url(|| csrf_state)
            .set_pkce_challenge(pkce_challenge)
            .set_redirect_uri(std::borrow::Cow::Owned(redirect_url));

        for scope in &scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.clone()));
        }

        let (auth_url, _csrf_token) = auth_request.url();
        let auth_url_string = auth_url.to_string();

        // Hand off to the caller's renderer. The caller is expected
        // to print the URL, attempt OSC 52 clipboard copy, and read
        // the operator's pasted redirect URL from stdin with a
        // bounded timeout.
        let pasted = paste_url_renderer(auth_url_string).await?;

        // Validate the pasted URL: scheme/host/port/path match,
        // strip bracketed-paste markers, extract code, constant-
        // time-compare CSRF state.
        let code =
            crate::headless::parse_redirect_url(&pasted, &redirect_uri_str, &csrf_state_secret)?;

        // Exchange code for tokens. Same shape as `authorize` —
        // redirect_uri MUST match the one used at auth-URL
        // construction time.
        let redirect_url_for_exchange =
            RedirectUrl::new(redirect_uri_str).map_err(|_| OAuthError::CallbackServerFailed {
                source: std::io::Error::other("invalid redirect URL for exchange"),
            })?;

        let token_response = self
            .inner
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(pkce_verifier)
            .set_redirect_uri(std::borrow::Cow::Owned(redirect_url_for_exchange))
            .request_async(&self.http_client)
            .await
            .map_err(|e| OAuthError::TokenExchangeFailed {
                service: "google-oauth".to_owned(),
                source: Box::new(e),
            })?;

        let access_token = OAuthToken::from_trusted_bytes(
            token_response.access_token().secret().as_bytes().to_vec(),
        );
        let refresh_token = token_response
            .refresh_token()
            .map(|rt| OAuthRefreshToken::from_trusted_bytes(rt.secret().as_bytes().to_vec()));
        let expires_in = token_response.expires_in();
        let scopes = token_response
            .scopes()
            .map(|s| s.iter().map(|scope| scope.to_string()).collect())
            .unwrap_or_default();

        Ok(AuthorizeResult { access_token, refresh_token, expires_in, scopes })
    }

    /// Get a reference to the inner `BasicClient`.
    ///
    /// Crate-private accessor used by the internal token-exchange test
    /// harness to bypass the full authorize flow. The public refresh
    /// surface is [`Self::refresh`], which is what external callers
    /// (permitlayer-proxy, permitlayer-daemon) should use.
    #[cfg(test)]
    pub(crate) fn inner(&self) -> &ConfiguredClient {
        &self.inner
    }

    /// Get a reference to the inner `reqwest::Client`.
    ///
    /// Crate-private accessor used by the internal token-exchange test
    /// harness. External callers should go through [`Self::refresh`].
    #[cfg(test)]
    pub(crate) fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }

    /// Refresh an access token using a stored refresh token.
    ///
    /// Thin wrapper over [`crate::refresh::refresh_with_retry`] that hides
    /// the internal `ConfiguredClient` and `reqwest::Client` types from
    /// callers outside this crate. Applies the standard retry policy
    /// (3 attempts, 1s/2s/4s exponential backoff with ±20% jitter per AR44).
    ///
    /// Returns `OAuthError::InvalidGrant` if the refresh token was
    /// revoked server-side (non-retryable), `OAuthError::RefreshExhausted`
    /// if all attempts fail with transport errors.
    ///
    /// This is the public refresh entry point used by `permitlayer-proxy`
    /// for reactive refresh on upstream 401 (Story 1.14).
    pub async fn refresh(
        &self,
        refresh_token: &permitlayer_credential::OAuthRefreshToken,
    ) -> Result<crate::refresh::RefreshResult, crate::error::OAuthError> {
        crate::refresh::refresh_with_retry(&self.inner, &self.http_client, refresh_token).await
    }
}

/// Story 7.30 AC #9: detect non-GUI / cross-session contexts where
/// `/usr/bin/open` (and `xdg-open` / `start`) are likely to fail
/// silently — SSH sessions without a local browser, `sudo` from SSH,
/// and processes running under a different user's GUI session on
/// macOS.
///
/// Heuristics are best-effort. `SSH_CONNECTION` is unset under
/// `sudo -i` from SSH, and the macOS `console`-owner check is racy
/// with fast user-switching. When in doubt, prefer surfacing the URL
/// over silent `open::that()` failure.
///
/// **Test seam:** `AGENTSSO_FORCE_BROWSER_FALLBACK=1` forces the
/// non-GUI branch unconditionally (used by the unit test below).
pub(crate) fn should_skip_browser_open() -> bool {
    if std::env::var_os("AGENTSSO_FORCE_BROWSER_FALLBACK").is_some() {
        return true;
    }
    if std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some() {
        return true;
    }
    // `sudo -i` from SSH masks `SSH_CONNECTION` but preserves
    // `SUDO_USER`. If we're running as root via sudo AND there's no
    // DISPLAY (Linux) / no console-owner match (macOS), assume
    // non-GUI. Use `effective` UID, not real: under `sudo -s` and
    // some sudoers configs the real UID stays as the invoking
    // operator's while euid is elevated to 0, so `getuid().is_root()`
    // can return false. `geteuid()` is the elevation signal we
    // actually want — it's 0 under every sudo flavor.
    #[cfg(unix)]
    {
        let is_sudo_root =
            std::env::var_os("SUDO_USER").is_some() && nix::unistd::Uid::effective().is_root();
        if is_sudo_root {
            #[cfg(target_os = "linux")]
            {
                // Treat GUI as "reachable" if any of DISPLAY,
                // WAYLAND_DISPLAY, XAUTHORITY, or DBUS_SESSION_BUS_ADDRESS
                // survive sudo's env_reset. Default sudoers on Debian/
                // Ubuntu/Fedora strip all four under `env_reset`, so a
                // bare `sudo` from a GUI terminal will still trip the
                // "no GUI" branch — that's the correct behavior (no env
                // → can't reach the X/Wayland server anyway). The
                // additional vars catch operator configs that opt them
                // into `env_keep` (`Defaults env_keep += "XAUTHORITY"`)
                // or invoke via `sudo -E`, where the GUI IS reachable
                // and we should NOT skip.
                let gui_env = std::env::var_os("DISPLAY").is_some()
                    || std::env::var_os("WAYLAND_DISPLAY").is_some()
                    || std::env::var_os("XAUTHORITY").is_some()
                    || std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some();
                if !gui_env {
                    return true;
                }
            }
            #[cfg(target_os = "macos")]
            {
                // On macOS, check whether the running user matches the
                // console owner via `stat -f %Su /dev/console`. A
                // mismatch (e.g. `_root` while `alice` holds the GUI
                // session) means `open::that()` would attempt to talk
                // to a session this process can't reach.
                match std::process::Command::new("/usr/bin/stat")
                    .args(["-f", "%Su", "/dev/console"])
                    .output()
                {
                    Ok(out) if out.status.success() => {
                        let console_owner = String::from_utf8_lossy(&out.stdout).trim().to_owned();
                        let sudo_user = std::env::var("SUDO_USER").unwrap_or_default();
                        if console_owner != sudo_user {
                            return true;
                        }
                        // Tiebreaker for the rare case where SSH stripped
                        // `SSH_CONNECTION` (sudo env_reset) and the
                        // console owner happens to match `$SUDO_USER`
                        // by coincidence: a forwarded `SSH_AUTH_SOCK`
                        // points at `/tmp/ssh-*` (sshd's per-session
                        // socket). The macOS launchd ssh-agent uses
                        // `/private/tmp/com.apple.launchd.*/Listeners`
                        // which is set on every local Terminal session
                        // by default — checking just `is_some()` here
                        // would false-positive on every local sudo.
                        if let Some(sock) = std::env::var_os("SSH_AUTH_SOCK")
                            && let Some(s) = sock.to_str()
                            && (s.starts_with("/tmp/ssh-") || s.starts_with("/var/tmp/ssh-"))
                        {
                            return true;
                        }
                    }
                    Ok(out) => {
                        tracing::warn!(
                            stderr = %String::from_utf8_lossy(&out.stderr),
                            "/usr/bin/stat /dev/console exited non-zero; assuming GUI session"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            err = %e,
                            "console-owner probe failed; assuming GUI session"
                        );
                    }
                }
            }
        }
    }
    false
}

/// Print the non-GUI consent block: prominent copy-paste markers
/// around the OAuth URL plus a suggestion to re-run with
/// `--headless` or `--device-flow` so the redirect can be captured
/// without a local browser. `open_err` is `Some` when the block is
/// shown because `open::that()` failed (vs. shown because
/// `should_skip_browser_open` tripped up front).
fn print_non_gui_consent_block(url: &str, open_err: Option<&std::io::Error>) {
    let mut stderr = std::io::stderr();
    let _ = render_non_gui_consent_block(&mut stderr, url, open_err);
}

fn render_non_gui_consent_block<W: std::io::Write>(
    w: &mut W,
    url: &str,
    open_err: Option<&std::io::Error>,
) -> std::io::Result<()> {
    writeln!(w)?;
    if let Some(err) = open_err {
        writeln!(w, "  could not open browser ({err}) — falling back to manual copy.")?;
    } else {
        writeln!(w, "  detected non-GUI / cross-session context — skipping browser-open.")?;
    }
    writeln!(w)?;
    writeln!(w, "  ── copy this URL into a browser on any device ──────────────")?;
    writeln!(w)?;
    writeln!(w, "    {url}")?;
    writeln!(w)?;
    writeln!(w, "  ─────────────────────────────────────────────────────────────")?;
    writeln!(w)?;
    writeln!(w, "  this OAuth flow needs to receive the redirect URL too. Re-run")?;
    writeln!(w, "  with one of:")?;
    writeln!(w)?;
    writeln!(w, "    --headless        — paste the post-consent URL back via stdin")?;
    writeln!(w, "                        (best for SSH from a machine with a browser)")?;
    writeln!(w, "    --device-flow     — Google OAuth 2.0 device flow (RFC 8628;")?;
    writeln!(w, "                        best for truly browser-less hosts)")?;
    writeln!(w)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::Json;
    use axum::routing::post;

    /// Spawn a mock token endpoint that returns canned tokens.
    async fn spawn_mock_token_server() -> (String, tokio::net::TcpListener) {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind mock server");
        let addr = listener.local_addr().expect("local addr");
        let url = format!("http://127.0.0.1:{}", addr.port());
        (url, listener)
    }

    fn mock_token_app() -> axum::Router {
        axum::Router::new().route("/token", post(mock_token_handler))
    }

    async fn mock_token_handler() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "access_token": "ya29.test-access-token-placeholder",
            "refresh_token": "1//test-refresh-token-placeholder",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "https://www.googleapis.com/auth/gmail.readonly"
        }))
    }

    // ── Story 7.30 Task 11: browser-launch fallback ──────────────────

    /// Verify that the rendered non-GUI consent block carries the
    /// load-bearing operator hints (URL, --headless, --device-flow).
    /// Output shape is deliberately pinned because operator
    /// documentation in `docs/user-guide/install.md` references it.
    #[test]
    fn non_gui_consent_block_renders_url_and_remediation_hints() {
        let mut buf: Vec<u8> = Vec::new();
        render_non_gui_consent_block(&mut buf, "https://accounts.google.com/test-url", None)
            .unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("https://accounts.google.com/test-url"));
        assert!(text.contains("--headless"));
        assert!(text.contains("--device-flow"));
        assert!(text.contains("non-GUI"));
        // rc.13 anti-regression: never recommend a curl-from-this-host
        // recipe (that fallback was misleading because the OAuth code
        // grant requires the browser callback, not just a fetch).
        assert!(!text.contains("curl"), "rc.13: drop the misleading curl-from-this-host hint");
    }

    /// When the consent block is rendered because `open::that()`
    /// returned an error (vs. because `should_skip_browser_open`
    /// tripped up front), surface the underlying error so the
    /// operator can distinguish "no GUI detected, didn't try" from
    /// "tried to open and it failed."
    #[test]
    fn non_gui_consent_block_with_open_err_renders_underlying_error() {
        let err = std::io::Error::other("xdg-open: command not found");
        let mut buf: Vec<u8> = Vec::new();
        render_non_gui_consent_block(&mut buf, "https://accounts.google.com/test-url", Some(&err))
            .unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("could not open browser"));
        assert!(text.contains("xdg-open: command not found"));
        assert!(text.contains("--headless"));
        assert!(text.contains("--device-flow"));
        assert!(!text.contains("curl"));
    }

    #[test]
    fn oauth_client_construction_succeeds() {
        let client =
            OAuthClient::new("test-client-id".to_owned(), Some("test-client-secret".to_owned()));
        assert!(client.is_ok());
    }

    #[test]
    fn oauth_client_without_secret_succeeds() {
        let client = OAuthClient::new("test-client-id".to_owned(), None);
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn mock_token_exchange() {
        // Start mock token server.
        let (base_url, listener) = spawn_mock_token_server().await;
        let token_url = format!("{base_url}/token");
        let auth_url = format!("{base_url}/auth");

        tokio::spawn(async move {
            axum::serve(listener, mock_token_app()).await.expect("mock server");
        });

        let client = OAuthClient::new_with_endpoint_overrides(
            "test-client-id".to_owned(),
            Some("test-secret".to_owned()),
            &auth_url,
            &token_url,
        )
        .expect("client construction");

        // Directly test token exchange (bypassing browser flow).
        let redirect_url =
            RedirectUrl::new("http://127.0.0.1:9999/callback".to_owned()).expect("redirect url");
        let (_pkce_challenge, pkce_verifier) = pkce::generate_pkce();

        let token_response = client
            .inner()
            .exchange_code(AuthorizationCode::new("test-code".to_owned()))
            .set_pkce_verifier(pkce_verifier)
            .set_redirect_uri(std::borrow::Cow::Owned(redirect_url))
            .request_async(client.http_client())
            .await;

        assert!(token_response.is_ok(), "token exchange should succeed with mock server");
        let resp = token_response.unwrap();

        // Convert at boundary.
        let access =
            OAuthToken::from_trusted_bytes(resp.access_token().secret().as_bytes().to_vec());
        assert_eq!(access.reveal(), b"ya29.test-access-token-placeholder");

        let refresh = resp
            .refresh_token()
            .map(|rt| OAuthRefreshToken::from_trusted_bytes(rt.secret().as_bytes().to_vec()));
        assert!(refresh.is_some());
        assert_eq!(refresh.as_ref().unwrap().reveal(), b"1//test-refresh-token-placeholder");
    }

    /// rc.13 contract pin: `authorize_headless` reuses the SAME
    /// `redirect_uri` between auth-URL construction and token exchange.
    /// A regression that drifts those two values would cause Google to
    /// reject the token exchange with `redirect_uri_mismatch`. We
    /// verify by capturing the form body the mock token server sees
    /// and asserting the `redirect_uri` field matches what was minted
    /// at the start of the headless flow.
    #[tokio::test]
    async fn authorize_headless_round_trip_uses_consistent_redirect_uri() {
        use std::sync::Mutex;

        // Shared state: the token handler stashes the form body it
        // receives so the test can assert on it.
        #[derive(Default)]
        struct Captured {
            form: Option<String>,
        }
        let captured = std::sync::Arc::new(Mutex::new(Captured::default()));

        let captured_for_handler = std::sync::Arc::clone(&captured);
        let app = axum::Router::new().route(
            "/token",
            post(move |body: String| {
                let captured = std::sync::Arc::clone(&captured_for_handler);
                async move {
                    captured.lock().expect("not poisoned").form = Some(body);
                    Json(serde_json::json!({
                        "access_token": "ya29.headless-roundtrip-token",
                        "refresh_token": "1//headless-refresh",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "scope": "https://www.googleapis.com/auth/gmail.readonly",
                    }))
                }
            }),
        );

        let (base_url, listener) = spawn_mock_token_server().await;
        let token_url = format!("{base_url}/token");
        let auth_url_endpoint = format!("{base_url}/auth");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock server");
        });

        let client = OAuthClient::new_with_endpoint_overrides(
            "test-client-id".to_owned(),
            Some("test-secret".to_owned()),
            &auth_url_endpoint,
            &token_url,
        )
        .expect("client");

        // Capture the auth URL the closure receives so we can extract
        // the redirect_uri the daemon minted, then synthesize a paste
        // that matches.
        let captured_auth_url = std::sync::Arc::new(Mutex::new(String::new()));
        let captured_auth_url_for_renderer = std::sync::Arc::clone(&captured_auth_url);

        let result = client
            .authorize_headless(
                vec!["https://www.googleapis.com/auth/gmail.readonly".to_owned()],
                move |auth_url| {
                    let captured_auth_url = std::sync::Arc::clone(&captured_auth_url_for_renderer);
                    async move {
                        // Parse the auth URL Google would receive,
                        // extract redirect_uri + state, build a
                        // matching paste.
                        let parsed = url::Url::parse(&auth_url).expect("auth url parses");
                        let redirect_uri = parsed
                            .query_pairs()
                            .find(|(k, _)| k == "redirect_uri")
                            .map(|(_, v)| v.into_owned())
                            .expect("redirect_uri in auth url");
                        let state = parsed
                            .query_pairs()
                            .find(|(k, _)| k == "state")
                            .map(|(_, v)| v.into_owned())
                            .expect("state in auth url");
                        *captured_auth_url.lock().expect("not poisoned") = auth_url.clone();
                        Ok(format!("{redirect_uri}?code=test-headless-code&state={state}"))
                    }
                },
            )
            .await;

        let result = result.expect("authorize_headless succeeds");
        assert_eq!(
            result.access_token.reveal(),
            b"ya29.headless-roundtrip-token",
            "access token plumbs through correctly",
        );

        // The crucial pin: the token-exchange form body MUST contain
        // the same redirect_uri that was in the auth URL.
        let captured_auth_url = captured_auth_url.lock().expect("not poisoned").clone();
        let auth_url_parsed = url::Url::parse(&captured_auth_url).expect("auth url");
        let auth_redirect_uri = auth_url_parsed
            .query_pairs()
            .find(|(k, _)| k == "redirect_uri")
            .map(|(_, v)| v.into_owned())
            .expect("auth redirect_uri");

        let form_body = captured.lock().expect("not poisoned").form.clone().expect("form captured");
        // Form-encoded; redirect_uri appears as redirect_uri=...
        // url-encoded. We just substring-search for the encoded form.
        let encoded_redirect_uri =
            url::form_urlencoded::byte_serialize(auth_redirect_uri.as_bytes()).collect::<String>();
        assert!(
            form_body.contains(&format!("redirect_uri={encoded_redirect_uri}")),
            "token-exchange form body must reuse the auth-URL redirect_uri (got body: {form_body})",
        );
    }
}
