//! Error types for OAuth 2.1 operations.
//!
//! All variants include structured metadata (error codes, service names,
//! remediation hints) but NEVER include credential bytes. The credential
//! types (`OAuthToken`, `OAuthRefreshToken`) are non-`Debug` by design;
//! this enum keeps `#[derive(Debug)]` because it holds only metadata.

/// Errors returned by OAuth client operations.
///
/// # Credential safety
///
/// No variant's `Display` or `Debug` output contains token bytes.
/// This is enforced by the type system (`OAuthToken` / `OAuthRefreshToken`
/// are non-`Debug`, non-`Display`) and by integration tests that scan
/// error output for known sentinel values.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum OAuthError {
    /// PKCE code generation failure.
    #[error("PKCE code generation failed")]
    PkceGenerationFailed,

    /// Loopback server timed out waiting for the OAuth callback.
    #[error(
        "OAuth callback timed out after {timeout_secs}s — the browser may not have completed the consent flow"
    )]
    CallbackTimeout {
        /// How long the server waited before giving up.
        timeout_secs: u64,
    },

    /// The `state` CSRF parameter in the callback did not match the
    /// expected value.
    #[error("OAuth callback state parameter mismatch (possible CSRF attack)")]
    CallbackStateMismatch,

    /// The user clicked "Deny" on the OAuth consent screen.
    #[error("user denied consent for service '{service}'")]
    UserDeniedConsent {
        /// The upstream service (e.g. `"google-oauth"`).
        service: String,
    },

    /// The authorization-code-for-token exchange failed.
    #[error("token exchange failed for service '{service}'")]
    TokenExchangeFailed {
        /// The upstream service.
        service: String,
        /// The underlying HTTP or protocol error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// A single refresh-token attempt failed (retryable).
    #[error("refresh failed for service '{service}'")]
    RefreshFailed {
        /// The upstream service.
        service: String,
        /// The underlying HTTP or protocol error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// All retry attempts for token refresh have been exhausted.
    #[error("OAuth token refresh failed after {attempts} attempts for service '{service}'")]
    RefreshExhausted {
        /// The upstream service.
        service: String,
        /// Number of attempts made before giving up.
        attempts: u32,
    },

    /// The refresh token was revoked or expired server-side
    /// (`invalid_grant` error from the provider).
    #[error("refresh token is invalid (revoked or expired) for service '{service}'")]
    InvalidGrant {
        /// The upstream service.
        service: String,
    },

    /// Could not open the user's default browser.
    #[error("failed to open default browser")]
    BrowserOpenFailed {
        /// The underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// Could not bind the ephemeral loopback callback server.
    #[error("failed to start OAuth callback server")]
    CallbackServerFailed {
        /// The underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// Vault seal/unseal failed during token storage or retrieval.
    #[error("vault operation failed: {message}")]
    VaultError {
        /// Human-readable description of what went wrong.
        message: String,
        /// The underlying vault error.
        #[source]
        source: permitlayer_vault::VaultError,
    },

    /// Could not read the OAuth client JSON file from disk.
    #[error("failed to read OAuth client JSON from '{}'", path.display())]
    ClientJsonReadFailed {
        /// Path to the file that could not be read.
        path: std::path::PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The OAuth client JSON file is malformed or missing required fields.
    #[error("invalid OAuth client JSON at '{}': {reason}", path.display())]
    ClientJsonInvalid {
        /// Path to the malformed file.
        path: std::path::PathBuf,
        /// What was wrong with the file.
        reason: String,
    },

    /// Post-consent verification query failed.
    #[error("verification failed for service '{service}': {reason}")]
    VerificationFailed {
        /// The service being verified.
        service: String,
        /// What went wrong.
        reason: String,
        /// HTTP status code if applicable.
        status_code: Option<u16>,
        /// Underlying error for chain inspection (e.g., reqwest::Error).
        /// Consistent with TokenExchangeFailed and RefreshFailed which both carry `#[source]`.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    // --- rc.13 headless-paste flow variants ---
    /// The redirect URL the operator pasted could not be parsed as a URL,
    /// even after stripping bracketed-paste markers (\e[200~ ... \e[201~).
    #[error("could not parse the pasted redirect URL — make sure you copied the full address")]
    PastedUrlMalformed,

    /// The pasted URL parsed but did not match the redirect URI we issued
    /// to Google (scheme/host/port/path mismatch). Most commonly: operator
    /// pasted from the wrong browser tab, or pasted a URL from a previous
    /// session.
    #[error("pasted redirect URL doesn't match the expected callback (got {got})")]
    PastedUrlMismatch {
        /// The scheme://host:port/path of what we got, for operator
        /// diagnosis.
        got: String,
    },

    /// The pasted URL was missing the `code=` query parameter. Likely a
    /// truncated paste or a URL from before consent was granted.
    #[error("pasted redirect URL has no `code` parameter — make sure consent was approved")]
    PastedUrlMissingCode,

    /// The pasted URL was missing the `state=` query parameter. The
    /// state parameter is how we defend against CSRF; without it we
    /// cannot trust the pasted URL.
    #[error("pasted redirect URL has no `state` parameter — paste was likely truncated")]
    PastedUrlMissingState,

    /// The pasted URL's `state` parameter did not match the one we issued.
    /// Either the paste was from a stale prior session OR an attacker
    /// substituted a different consent flow's URL.
    #[error(
        "pasted redirect URL has the wrong `state` parameter — possible stale paste or CSRF attempt"
    )]
    PastedUrlStateMismatch,
}

impl OAuthError {
    /// Return a user-facing remediation hint for this error.
    #[must_use]
    pub fn remediation(&self) -> &'static str {
        match self {
            Self::PkceGenerationFailed => {
                "This is an internal error. Please retry the setup command."
            }
            Self::CallbackTimeout { .. } => {
                "The browser did not complete the consent flow in time. Run `agentsso setup gmail` again."
            }
            Self::CallbackStateMismatch => {
                "The OAuth callback contained an unexpected state parameter. Run `agentsso setup gmail` again."
            }
            Self::UserDeniedConsent { .. } => {
                "Run `agentsso setup gmail` again and approve the consent screen."
            }
            Self::TokenExchangeFailed { .. } => {
                "Token exchange with the provider failed. Check your network connection and try again."
            }
            Self::RefreshFailed { .. } => {
                "Token refresh failed. The daemon will retry automatically."
            }
            Self::RefreshExhausted { .. } => {
                "Token refresh failed after multiple retries. Run `agentsso setup gmail` to re-authenticate."
            }
            Self::InvalidGrant { .. } => {
                "The refresh token has been revoked or expired. Run `agentsso setup gmail` to re-authenticate."
            }
            Self::BrowserOpenFailed { .. } => {
                "Could not open your default browser. Open the authorization URL manually."
            }
            Self::CallbackServerFailed { .. } => {
                "Could not bind a local port for the OAuth callback. Check for port conflicts."
            }
            Self::VaultError { .. } => {
                "Credential storage failed. Check that the vault is initialized."
            }
            Self::ClientJsonReadFailed { .. } => {
                "Check that the file exists and is a valid Google OAuth client JSON."
            }
            Self::ClientJsonInvalid { .. } => {
                "The file must be a Google Cloud Console OAuth client JSON (installed or web type)."
            }
            Self::VerificationFailed { .. } => {
                "Credentials are stored. Re-run setup or check the service status at https://www.google.com/appsstatus."
            }
            Self::PastedUrlMalformed => {
                "Copy the entire URL from your browser's address bar (starting with http://127.0.0.1:) and paste it again."
            }
            Self::PastedUrlMismatch { .. } => {
                "Make sure you pasted the redirect URL (starts with http://127.0.0.1:), not the original consent URL or a different page."
            }
            Self::PastedUrlMissingCode => {
                "The pasted URL didn't include an authorization code — approve the consent screen and try the redirect URL again."
            }
            Self::PastedUrlMissingState => {
                "Paste the full redirect URL including the `state` query parameter — it's part of the URL after `?state=...`."
            }
            Self::PastedUrlStateMismatch => {
                "The pasted URL is from a different setup session. Run `agentsso setup gmail --headless` again to start a fresh flow."
            }
        }
    }

    /// Return a machine-readable error code suitable for JSON error responses.
    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::PkceGenerationFailed => "pkce_generation_failed",
            Self::CallbackTimeout { .. } => "callback_timeout",
            Self::CallbackStateMismatch => "callback_state_mismatch",
            Self::UserDeniedConsent { .. } => "user_denied_consent",
            Self::TokenExchangeFailed { .. } => "token_exchange_failed",
            Self::RefreshFailed { .. } => "refresh_failed",
            Self::RefreshExhausted { .. } => "upstream_unreachable",
            Self::InvalidGrant { .. } => "invalid_grant",
            Self::BrowserOpenFailed { .. } => "browser_open_failed",
            Self::CallbackServerFailed { .. } => "callback_server_failed",
            Self::VaultError { .. } => "vault_error",
            Self::ClientJsonReadFailed { .. } => "client_json_read_failed",
            Self::ClientJsonInvalid { .. } => "client_json_invalid",
            Self::VerificationFailed { .. } => "verification_failed",
            Self::PastedUrlMalformed => "pasted_url_malformed",
            Self::PastedUrlMismatch { .. } => "pasted_url_mismatch",
            Self::PastedUrlMissingCode => "pasted_url_missing_code",
            Self::PastedUrlMissingState => "pasted_url_missing_state",
            Self::PastedUrlStateMismatch => "pasted_url_state_mismatch",
        }
    }
}
