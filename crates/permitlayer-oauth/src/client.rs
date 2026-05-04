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

    /// Run the full OAuth 2.1 authorization code flow with PKCE.
    ///
    /// 1. Generates PKCE challenge + verifier
    /// 2. Spawns ephemeral callback server
    /// 3. Opens browser to consent screen (or prints URL if `no_browser`)
    /// 4. Awaits callback with authorization code
    /// 5. Exchanges code for tokens
    /// 6. Returns tokens wrapped in credential types
    ///
    /// When `no_browser` is true, the URL is printed to stdout and the
    /// caller (or end-user) is responsible for opening it. When false,
    /// `open::that()` is invoked; on IO failure the URL is printed to
    /// stderr as a fallback so the user can complete the flow manually.
    pub async fn authorize(
        &self,
        scopes: Vec<String>,
        timeout: Option<Duration>,
        no_browser: bool,
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

        // Open browser — or print URL if --no-browser was requested.
        // open::that() is blocking on some platforms, so we use
        // spawn_blocking to avoid stalling the async executor.
        let url_string = auth_url.to_string();
        if no_browser {
            print_manual_auth_url(&url_string);
        } else {
            let url_for_open = url_string.clone();
            let open_result = tokio::task::spawn_blocking(move || open::that(&url_for_open)).await;
            match open_result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    // Auto-fallback: if open::that() can't reach a usable
                    // browser (no DISPLAY, headless SSH, `su` without GUI
                    // context, etc.), print the URL so the user can
                    // complete the flow manually instead of dead-ending.
                    print_browser_fallback_message(&url_string, &e);
                }
                Err(e) => {
                    return Err(OAuthError::BrowserOpenFailed {
                        source: std::io::Error::other(e.to_string()),
                    });
                }
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

/// Render the manual-paste consent message to the given writer.
///
/// Extracted as a writer-injected helper so unit tests can assert the
/// rendered text without capturing global stdout. Production callers
/// pipe through [`print_manual_auth_url`].
pub(crate) fn render_manual_auth_url(w: &mut dyn std::io::Write, url: &str) -> std::io::Result<()> {
    writeln!(w)?;
    writeln!(w, "  Open this URL in any browser to grant consent:")?;
    writeln!(w)?;
    writeln!(w, "    {url}")?;
    writeln!(w)?;
    writeln!(w, "  After approving, you'll be redirected to a 127.0.0.1 page on this host.")?;
    writeln!(w, "  If you completed consent in a browser on the SAME machine, the redirect")?;
    writeln!(w, "  lands here automatically. If you used a DIFFERENT machine, copy the full")?;
    writeln!(w, "  redirected URL (starting with http://127.0.0.1:...) and curl it from this")?;
    writeln!(w, "  host:")?;
    writeln!(w)?;
    writeln!(w, "    curl '<paste-redirect-url-here>'")?;
    writeln!(w)?;
    Ok(())
}

/// Render the auto-fallback "browser launch failed" message to the
/// given writer. See [`render_manual_auth_url`] for the writer-injection
/// rationale.
pub(crate) fn render_browser_fallback_message(
    w: &mut dyn std::io::Write,
    url: &str,
    err: &std::io::Error,
) -> std::io::Result<()> {
    writeln!(w)?;
    writeln!(w, "  Could not open browser ({err}). Open this URL manually:")?;
    writeln!(w)?;
    writeln!(w, "    {url}")?;
    writeln!(w)?;
    Ok(())
}

/// Print the manual-paste consent message to stdout. The callback
/// server is already listening before this is called.
fn print_manual_auth_url(url: &str) {
    let mut stdout = std::io::stdout();
    // Best-effort: a stdout write failure here is unrecoverable for the
    // user-facing flow but shouldn't fail the OAuth call. The auth URL
    // is also available in trace logs at INFO level.
    let _ = render_manual_auth_url(&mut stdout, url);
}

/// Print the auto-fallback message to stderr when `open::that()` fails.
fn print_browser_fallback_message(url: &str, err: &std::io::Error) {
    let mut stderr = std::io::stderr();
    let _ = render_browser_fallback_message(&mut stderr, url, err);
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

    #[test]
    fn render_manual_auth_url_includes_url_and_instructions() {
        let mut buf = Vec::new();
        render_manual_auth_url(&mut buf, "https://example.test/auth?foo=bar")
            .expect("write into Vec cannot fail");
        let out = String::from_utf8(buf).expect("ascii output");
        assert!(out.contains("https://example.test/auth?foo=bar"), "URL must appear in output");
        assert!(out.contains("Open this URL"), "primary instruction must appear");
        assert!(out.contains("127.0.0.1"), "loopback note must appear");
        assert!(out.contains("curl"), "curl-fallback note must appear for cross-host case");
    }

    #[test]
    fn render_browser_fallback_includes_url_and_error() {
        let err = std::io::Error::other("simulated open failure");
        let mut buf = Vec::new();
        render_browser_fallback_message(&mut buf, "https://example.test/auth", &err)
            .expect("write into Vec cannot fail");
        let out = String::from_utf8(buf).expect("ascii output");
        assert!(out.contains("https://example.test/auth"), "URL must appear in fallback output");
        assert!(out.contains("Could not open browser"), "fallback header must appear");
        assert!(out.contains("simulated open failure"), "underlying error must appear");
    }
}
