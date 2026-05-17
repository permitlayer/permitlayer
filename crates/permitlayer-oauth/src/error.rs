//! Error types for OAuth 2.1 operations.
//!
//! All variants include structured metadata (error codes, service names,
//! remediation hints) but NEVER include credential bytes. The credential
//! types (`OAuthToken`, `OAuthRefreshToken`) are non-`Debug` by design;
//! this enum keeps `#[derive(Debug)]` because it holds only metadata.

use std::borrow::Cow;

/// Parsed form of the canonical Google API `errdetails[].reason` taxonomy
/// surfaced on a 403 from the post-OAuth verification probe.
///
/// Only the canonical-protocol fields named by Google's `errdetails`
/// taxonomy (`reason`, `metadata.service`, `metadata.scope`) flow into
/// these variants. The raw response body NEVER appears here — the
/// privacy contract from Story 2.7 Decision 2B is preserved by the
/// closed whitelist in `permitlayer_oauth::google::verify::parse_verify_403_reason`.
///
/// New variants should be added when a new canonical reason needs
/// operator-actionable remediation. Reasons that fall outside the
/// allowlist (e.g. `QUOTA_EXCEEDED`, `IP_ADDRESS_DENIED`) leave the
/// enclosing `OAuthError::VerificationFailed.reason` set to `None` so
/// the existing generic remediation message remains in effect.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyReason {
    /// `details[].reason == "SERVICE_DISABLED"` — the named API is not
    /// enabled in the operator's GCP project. The remediation URL points
    /// at the API library page; `gcloud services enable …` is the
    /// CLI-equivalent.
    ServiceDisabled {
        /// Canonical service name (e.g. `"calendar.googleapis.com"`)
        /// from `details[].metadata.service`.
        service: String,
        /// Operator's GCP project ID (from `client_secret.json`'s
        /// `project_id` field) if known. None ⇒ remediation URL omits
        /// the `?project=…` query parameter.
        project: Option<String>,
        /// **R2-P12 round-2 review:** when Google bundles
        /// `BILLING_DISABLED` alongside `SERVICE_DISABLED` in the same
        /// `details[]` (common for new GCP projects), the parser sets
        /// this flag and the renderer appends a billing-also-disabled
        /// footer to the remediation. Without this flag the operator
        /// would enable the API, retry, and hit a second 403 because
        /// billing wasn't fixed first.
        also_billing_disabled: bool,
    },
    /// `details[].reason == "BILLING_DISABLED"` — billing is not enabled
    /// for the operator's GCP project. The remediation URL points at the
    /// billing console.
    BillingDisabled {
        /// Operator's GCP project ID, if known.
        project: Option<String>,
    },
    /// `details[].reason == "ACCESS_TOKEN_SCOPE_INSUFFICIENT"` — the
    /// granted access token doesn't carry the scopes required by the
    /// API endpoint we tried to call. Operator must re-run the consent
    /// flow with the missing scopes selected.
    ScopeInsufficient {
        /// Scopes named in `details[].metadata.scope` (split on
        /// whitespace and commas, trimmed, empty entries dropped).
        ///
        /// **R3-P21 round-3 review — semantic contract:**
        /// `Some(ScopeInsufficient { missing_scopes: vec![] })` is a
        /// valid "we know there's a scope problem but Google didn't
        /// tell us which" state, distinct from `None` which means
        /// "parser found no recognized reason in `details[]`." Future
        /// code that branches on `verify_reason.is_some()` to decide
        /// whether to emit a "structured remediation available"
        /// signal should be aware that an empty-scopes case still
        /// counts as "structured" — the operator-facing message
        /// includes a re-consent hint with no scope list.
        missing_scopes: Vec<String>,
        /// **R3-P1 round-3 review:** when Google bundles
        /// `SERVICE_DISABLED` alongside `ACCESS_TOKEN_SCOPE_INSUFFICIENT`
        /// (real for brand-new GCP projects with missing scopes), the
        /// parser captures the canonical service identifier here so the
        /// renderer can surface the API-enablement step alongside the
        /// re-consent step. Operator avoids hitting a second 403 after
        /// re-consenting with full scopes.
        also_service_disabled: Option<String>,
        /// **R3-P1 round-3 review:** when Google bundles
        /// `BILLING_DISABLED` in the same `details[]`, the renderer
        /// surfaces the billing-console URL alongside the re-consent
        /// step.
        also_billing_disabled: bool,
    },
    /// Recognized 403 shape but the specific reason is not in our
    /// allowlist. Reserved for future expansion; today's parser never
    /// constructs this variant (it returns `None` for unknown reasons
    /// so the generic remediation kicks in via the outer `Option`).
    Other,
}

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

    /// The vault-sealed BYO OAuth client bundle could not be
    /// (de)serialized (Story 7.35). `reason` carries only the serde
    /// error position/kind — never the bundle contents.
    #[error("sealed OAuth client bundle is malformed: {reason}")]
    SealedClientBundleInvalid {
        /// Serde (de)serialization failure detail (no secret material).
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
        /// Story 7.12: typed parse of the response body's
        /// `errdetails[].reason` taxonomy on a 403, when present.
        ///
        /// **Privacy invariant (extends Story 2.7 Decision 2B):** only
        /// canonical-protocol fields cross from the response body into
        /// these variants. The raw body string never appears here. See
        /// `permitlayer_oauth::google::verify::parse_verify_403_reason`
        /// for the field whitelist.
        verify_reason: Option<VerifyReason>,
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

    // --- Story 7.17 OAuth 2.0 device flow (RFC 8628) variants ---
    /// Google's `expires_in` window for the device code elapsed before
    /// the operator approved consent. Distinct from `DeviceFlowTimeout`,
    /// which is the operator-configured local timeout firing first.
    #[error("device flow expired — Google's device code window elapsed before consent was granted")]
    DeviceCodeExpired,
    /// The operator-configured `--device-flow-timeout` elapsed before
    /// Google reported consent. The device code may still be valid
    /// upstream; re-running the connect command issues a fresh code.
    #[error("device flow timed out after {timeout_secs}s waiting for consent")]
    DeviceFlowTimeout {
        /// Elapsed seconds waited before giving up.
        timeout_secs: u64,
    },
    /// The operator clicked "Deny" on Google's device-flow consent page.
    #[error("operator denied consent on Google's device-flow consent page")]
    DeviceCodeDenied,
    /// RFC 8628 error code we don't model individually, plus any
    /// non-2xx/non-RFC-8628 HTTP error during polling. The `error_code`
    /// is the upstream-reported value (`invalid_grant`, `invalid_client`,
    /// etc.); the `description` is either the upstream `error_description`
    /// or our HTTP-status synthesis (e.g., `"http 502: bad gateway"`).
    #[error("device flow protocol error: {error_code}: {description}")]
    DeviceFlowProtocol {
        /// Upstream `error` field or synthesized HTTP status code.
        error_code: String,
        /// Upstream `error_description` or HTTP body excerpt.
        description: String,
    },
}

/// Friendly short-name for a known Google API service identifier.
/// Returns `None` for unknown services so the renderer can fall back to
/// the raw identifier (`<service>.googleapis.com`). Adding a new entry
/// here is a one-line change.
///
/// **R2-P9 round-2 review:** the prior round-1 P11(b) `to_ascii_lowercase`
/// allocation was provably dead behind `validate_service_identifier`'s
/// strict-lowercase byte-class check. The parser's gate is the actual
/// contract; this lookup matches `service` directly. If a future caller
/// bypasses the parser (e.g., a CLI subcommand pretty-printing stored
/// reasons), they're responsible for normalizing case before lookup.
/// **R3-P9 round-3 review:** single source of truth for the verify-failed
/// generic remediation text. Referenced by both `OAuthError::remediation`
/// (the static-string fallback) and `render_verify_remediation`'s
/// defensive `VerifyReason::Other` arm so future text updates land in
/// one place. Pre-fix R2-P6 had the text duplicated in both arms; if
/// `remediation` was updated and the `Other` arm forgotten, debug builds
/// would panic loudly but release builds would silently serve stale
/// text.
pub(crate) const VERIFY_FAILED_GENERIC_REMEDIATION: &str = "Credentials are stored. Re-run setup or check the service status at https://www.google.com/appsstatus.";

fn google_api_friendly_name(service: &str) -> Option<&'static str> {
    match service {
        "calendar.googleapis.com" => Some("Calendar API"),
        "drive.googleapis.com" => Some("Drive API"),
        "gmail.googleapis.com" => Some("Gmail API"),
        "sheets.googleapis.com" => Some("Sheets API"),
        "docs.googleapis.com" => Some("Docs API"),
        _ => None,
    }
}

impl OAuthError {
    /// Return a user-facing remediation hint for this error.
    ///
    /// Returns a `&'static str` for backwards compatibility. Variants
    /// whose remediation needs runtime data (URLs, project IDs, scope
    /// lists) MUST be rendered via [`Self::remediation_owned`] —
    /// `remediation` returns the static fallback for those variants so
    /// existing static-string callers degrade gracefully.
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
            Self::SealedClientBundleInvalid { .. } => {
                "The sealed OAuth client bundle is unreadable. Re-run `agentsso connect <service> --agent <agent> --oauth-client <path>` to re-seal it."
            }
            Self::VerificationFailed { .. } => VERIFY_FAILED_GENERIC_REMEDIATION,
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
            // Story 7.17 device flow:
            Self::DeviceCodeExpired => {
                "Re-run `agentsso connect <service> --device-flow` to issue a fresh device code, then approve consent before it expires."
            }
            Self::DeviceFlowTimeout { .. } => {
                "Re-run `agentsso connect <service> --device-flow` and approve consent more quickly, or extend the deadline with `--device-flow-timeout <seconds>`."
            }
            Self::DeviceCodeDenied => {
                "Re-run `agentsso connect <service> --device-flow` and click 'Allow' on the Google consent page."
            }
            Self::DeviceFlowProtocol { .. } => {
                "Verify the OAuth client is of type 'TV and Limited Input Device' (not 'Desktop app'). Re-run `agentsso connect <service> --device-flow --oauth-client <path>` once the client type is fixed."
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
            Self::SealedClientBundleInvalid { .. } => "sealed_client_bundle_invalid",
            Self::VerificationFailed { .. } => "verification_failed",
            Self::PastedUrlMalformed => "pasted_url_malformed",
            Self::PastedUrlMismatch { .. } => "pasted_url_mismatch",
            Self::PastedUrlMissingCode => "pasted_url_missing_code",
            Self::PastedUrlMissingState => "pasted_url_missing_state",
            Self::PastedUrlStateMismatch => "pasted_url_state_mismatch",
            Self::DeviceCodeExpired => "device_code_expired",
            Self::DeviceFlowTimeout { .. } => "device_flow_timeout",
            Self::DeviceCodeDenied => "device_code_denied",
            Self::DeviceFlowProtocol { .. } => "device_flow_protocol",
        }
    }

    /// Return a user-facing remediation hint that may include
    /// runtime-computed data (URLs, project IDs, scope names).
    ///
    /// Companion to [`Self::remediation`]: variants whose text is
    /// purely static return `Cow::Borrowed(self.remediation())`;
    /// variants that need runtime data return `Cow::Owned(...)`.
    /// Story 7.12 added the dynamic dispatch arms for
    /// `VerificationFailed { verify_reason: Some(...), .. }` so that
    /// post-OAuth 403 errors render an actionable URL + `gcloud`
    /// command. New `OAuthError` variants in the future should add a
    /// match arm here only if their text needs runtime data; otherwise
    /// the default branch handles them.
    ///
    /// **P8 round-1 review:** `VerifyReason::Other` falls through to
    /// the static [`Self::remediation`] text via `Cow::Borrowed`
    /// rather than allocating a fresh `String`. This keeps the static
    /// fallback text in a single place — if `remediation`'s text is
    /// updated, `Other` follows automatically.
    #[must_use]
    pub fn remediation_owned(&self) -> Cow<'static, str> {
        if let Self::VerificationFailed { verify_reason: Some(vr), .. } = self {
            // P8: Other shares the static text with `verify_reason: None`
            // and other static variants — borrow rather than allocate.
            if matches!(vr, VerifyReason::Other) {
                return Cow::Borrowed(self.remediation());
            }
            return Cow::Owned(render_verify_remediation(vr));
        }
        Cow::Borrowed(self.remediation())
    }
}

/// Render a [`VerifyReason`] into operator-facing remediation text.
///
/// Pure string interpolation — no I/O, no panics, allocation bounded
/// (worst-case ~500 bytes). Output is rendered into terminal UIs
/// (`error_block`) and structured `tracing` events.
///
/// **P8 round-1 review:** the `Other` variant is intentionally NOT
/// handled here — [`OAuthError::remediation_owned`] short-circuits
/// `Other` to `Cow::Borrowed(self.remediation())` so the static
/// fallback text lives in exactly one place. The match below is
/// therefore exhaustive over the remaining variants of the
/// `#[non_exhaustive]` enum (caught by the unreachable!() guard).
fn render_verify_remediation(vr: &VerifyReason) -> String {
    match vr {
        VerifyReason::ServiceDisabled { service, project, also_billing_disabled } => {
            let friendly = google_api_friendly_name(service).unwrap_or(service);
            let console_url = match project {
                Some(p) => {
                    format!("https://console.cloud.google.com/apis/library/{service}?project={p}")
                }
                None => format!("https://console.cloud.google.com/apis/library/{service}"),
            };
            let gcloud = match project {
                Some(p) => format!("gcloud services enable {service} --project {p}"),
                None => format!("gcloud services enable {service}"),
            };
            let mut out = format!(
                "Enable {friendly} in Google Cloud Console:\n    {console_url}\n  Or via gcloud:\n    {gcloud}"
            );
            // R2-P12 + R3-P2 round-3 review: when Google bundles billing
            // AND service-disabled (common for new GCP projects), surface
            // both fixes. The footer text is flat so it reads correctly
            // after `error_block`'s continuation-line indent (R3-P2:
            // pre-fix used 2-space and 4-space sub-indents to convey
            // "do this first" hierarchy, which `error_block` flattens).
            if *also_billing_disabled {
                let billing_url = match project {
                    Some(p) => format!("https://console.cloud.google.com/billing?project={p}"),
                    None => "https://console.cloud.google.com/billing".to_owned(),
                };
                out.push_str(&format!(
                    "\nFirst enable billing for this project (the API enablement above will fail without billing):\n{billing_url}"
                ));
            }
            out
        }
        VerifyReason::BillingDisabled { project } => {
            let url = match project {
                Some(p) => format!("https://console.cloud.google.com/billing?project={p}"),
                None => "https://console.cloud.google.com/billing".to_owned(),
            };
            format!("Enable billing for this Google Cloud project:\n    {url}")
        }
        VerifyReason::ScopeInsufficient {
            missing_scopes,
            also_service_disabled,
            also_billing_disabled,
        } => {
            // R3-P10 round-3 review: pluralize correctly when only one
            // scope is missing.
            let mut out = if missing_scopes.is_empty() {
                "Re-run setup with the missing scopes (none reported in the error metadata — \
                 try the consent flow again with all required scopes)."
                    .to_owned()
            } else {
                let noun = if missing_scopes.len() == 1 { "scope" } else { "scopes" };
                let list = missing_scopes.join(", ");
                format!("Re-run setup with the missing {noun}: {list}")
            };
            // R3-P1 round-3 review: when Google bundles SERVICE and/or
            // BILLING alongside SCOPE_INSUFFICIENT (real for brand-new
            // GCP projects), surface them as ordered "do this AFTER
            // re-consenting" steps so the operator avoids a 2nd or 3rd
            // 403 after fixing the scopes.
            if let Some(service) = also_service_disabled {
                let friendly = google_api_friendly_name(service).unwrap_or(service);
                out.push_str(&format!(
                    "\n  Then enable {friendly} in Google Cloud Console:\n    https://console.cloud.google.com/apis/library/{service}"
                ));
            }
            if *also_billing_disabled {
                out.push_str(
                    "\n  Then enable billing for this Google Cloud project:\n    https://console.cloud.google.com/billing"
                );
            }
            out
        }
        // R2-P6 round-2 review: `Other` is short-circuited in
        // `remediation_owned` to `Cow::Borrowed(self.remediation())`
        // and should not reach this function. The pre-fix `unreachable!`
        // would panic in production if a future caller bypassed the
        // short-circuit. We now `debug_assert!` for the dev-time
        // signal and return the same static fallback text the
        // short-circuit would have produced — fail-open in release,
        // loud in debug. Behavior is identical to going through the
        // short-circuit.
        VerifyReason::Other => {
            debug_assert!(
                false,
                "VerifyReason::Other should be handled by OAuthError::remediation_owned's short-circuit"
            );
            // R3-P9: reference the same constant `OAuthError::remediation`
            // serves so a future text update lands in exactly one place.
            VERIFY_FAILED_GENERIC_REMEDIATION.to_owned()
        }
    }
}
