//! Google OAuth 2.0 device flow per RFC 8628 — Story 7.17 Task 2.
//!
//! Used by `agentsso connect <service> --device-flow` to onboard
//! agents on truly headless boxes (no browser, no SSH-from-laptop
//! redirect-paste). Operator opens the printed URL on any device with
//! a browser and enters the printed user code; this module polls
//! Google's token endpoint until consent is granted, denied, or
//! expires.
//!
//! # Design notes
//!
//! - **Deadline algorithm:** the cutoff is the EARLIEST of (a) the
//!   operator-configured local timeout (default 120s) and (b) Google's
//!   server-side `expires_in` (typically 1800s, capped at 30min by us
//!   defensively). Codex review 3 caught the prior `max` formulation
//!   that would have parked the daemon for 30min on a stale invocation.
//!
//! - **Injectable `Clock` + `Sleeper`:** time and sleeps go through
//!   trait seams so the unit tests advance virtual time without
//!   wall-clock waits. Production wiring uses [`SystemClock`] and
//!   [`TokioSleeper`].
//!
//! - **Adapter contract:** the public entry point [`run_device_flow`]
//!   returns [`DeviceFlowResult`] which carries the same field set as
//!   [`crate::client::AuthorizeResult`] so connect.rs can `From`-convert
//!   into the existing seal/store path without a translation layer.
//!
//! - **Privacy:** like the rest of the OAuth crate, error variants
//!   never carry credential bytes. Upstream JSON `error_description`
//!   is forwarded into [`OAuthError::DeviceFlowProtocol`] for
//!   actionable operator feedback; the response body itself is
//!   tracing::debug-logged under this module's target.

use std::io::{self, Write};
use std::time::{Duration, Instant};

use permitlayer_credential::{OAuthRefreshToken, OAuthToken};
use serde::{Deserialize, Serialize};

use crate::error::OAuthError;

/// RFC 8628 device-flow grant type literal. Required form parameter
/// on the token-endpoint POST.
const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Defensive cap on Google's `expires_in` field. RFC 8628 doesn't bound
/// the server-issued window; Google currently sends 1800s but a
/// future change to 86400s (1 day) would let a stale `connect` invocation
/// hold the daemon hostage for the full duration. The local
/// `--device-flow-timeout` wins anyway, but keeping the upstream cap
/// at 30min keeps the worst-case predictable.
const MAX_GOOGLE_EXPIRES_IN_SECS: u64 = 1800;

/// Default polling interval RFC 8628 recommends (5s) when the upstream
/// response omits or zeroes the `interval` field.
const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;

/// Increment added to the polling interval on each `slow_down` response
/// per RFC 8628 §3.5.
const SLOW_DOWN_INCREMENT_SECS: u64 = 5;

/// Endpoint URLs for the device flow.
///
/// Held as a struct (not constants) so unit tests can point both URLs
/// at a mockito server without poking module-private statics.
#[derive(Debug, Clone)]
pub struct DeviceFlowEndpoints {
    /// `https://oauth2.googleapis.com/device/code` in production.
    pub device_code: String,
    /// `https://oauth2.googleapis.com/token` in production.
    pub token: String,
}

impl DeviceFlowEndpoints {
    /// Production endpoints.
    #[must_use]
    pub fn google() -> Self {
        Self {
            device_code: "https://oauth2.googleapis.com/device/code".to_owned(),
            token: "https://oauth2.googleapis.com/token".to_owned(),
        }
    }
}

/// Device-flow's request body shape for `POST /device/code`.
#[derive(Serialize, Debug)]
struct DeviceCodeRequest<'a> {
    client_id: &'a str,
    /// Space-joined per RFC 8628 §3.1.
    scope: String,
}

/// Device-flow's response shape for `POST /device/code`.
///
/// Field names mirror the wire format. `verification_url` is Google's
/// canonical name (RFC 8628 calls it `verification_uri`); we accept
/// either via `#[serde(alias)]` for forward-compat with non-Google
/// providers if we ever extend.
#[derive(Deserialize, Debug, Clone)]
pub struct DeviceCodeResponse {
    /// The opaque code our token-poll requests carry to identify this
    /// device-flow session.
    pub device_code: String,
    /// The short human-typed code the operator enters at
    /// [`DeviceCodeResponse::verification_url`].
    pub user_code: String,
    /// URL to display to the operator. Google sends `verification_url`;
    /// RFC 8628 names it `verification_uri`. We accept both.
    #[serde(alias = "verification_uri")]
    pub verification_url: String,
    /// Server-side expiry window (seconds).
    pub expires_in: u64,
    /// Recommended polling interval (seconds). RFC 8628 §3.2 says
    /// implementations SHOULD use this if present; missing → 5s default
    /// per [`DEFAULT_POLL_INTERVAL_SECS`].
    #[serde(default)]
    pub interval: Option<u64>,
}

/// Token-endpoint response shape on success.
///
/// `pub` only because [`poll_for_token`] returns it for the unit tests
/// to introspect. Production callers should consume
/// [`run_device_flow`]'s [`DeviceFlowResult`] instead.
#[derive(Deserialize, Debug, Clone)]
pub struct DeviceTokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    /// Space-joined granted scopes.
    #[serde(default)]
    pub scope: Option<String>,
}

/// Token-endpoint response shape on RFC 8628 error.
#[derive(Deserialize, Debug, Clone)]
struct DeviceTokenErrorBody {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// Final outcome of [`run_device_flow`].
///
/// Field set mirrors [`crate::client::AuthorizeResult`] so
/// [`From<DeviceFlowResult> for crate::client::AuthorizeResult`]
/// (defined below) is a structural move — no field renaming. The
/// adapter lives in this crate (not in connect.rs) because the
/// orphan rule forbids defining `From` between two foreign types
/// from a downstream crate.
pub struct DeviceFlowResult {
    /// The access token, wrapped in `OAuthToken` for credential discipline.
    pub access_token: OAuthToken,
    /// The refresh token (if granted), wrapped in `OAuthRefreshToken`.
    pub refresh_token: Option<OAuthRefreshToken>,
    /// Token expiry duration (if provided by the server).
    pub expires_in: Option<Duration>,
    /// Scopes that were actually granted.
    pub scopes: Vec<String>,
}

impl From<DeviceFlowResult> for crate::client::AuthorizeResult {
    fn from(d: DeviceFlowResult) -> Self {
        Self {
            access_token: d.access_token,
            refresh_token: d.refresh_token,
            expires_in: d.expires_in,
            scopes: d.scopes,
        }
    }
}

// ── Trait seams: Clock + Sleeper ──────────────────────────────────

/// Time-now seam for testability.
///
/// Production: [`SystemClock`] wraps `Instant::now()`. Tests: a fake
/// clock advances virtual time so polling-loop deadlines fire without
/// wall-clock waits.
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

/// Production clock — wall-clock `Instant::now()`.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Sleep seam for testability. Async-trait via boxed-future to avoid
/// pulling in `async-trait` for one method.
pub trait Sleeper: Send + Sync {
    /// Suspend the current task for `duration`.
    fn sleep<'a>(
        &'a self,
        duration: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;
}

/// Production sleeper — `tokio::time::sleep`.
#[derive(Debug, Default)]
pub struct TokioSleeper;

impl Sleeper for TokioSleeper {
    fn sleep<'a>(
        &'a self,
        duration: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(tokio::time::sleep(duration))
    }
}

// ── Public API ────────────────────────────────────────────────────

/// POST `client_id` + space-joined `scopes` to the device-code endpoint.
///
/// Returns the parsed [`DeviceCodeResponse`] on 200 OK; any non-200 or
/// parse failure surfaces as [`OAuthError::DeviceFlowProtocol`] with
/// the upstream error code if parseable, else a synthesized
/// `"http_<status>"` code.
pub async fn request_device_code(
    client: &reqwest::Client,
    endpoint: &str,
    client_id: &str,
    scopes: &[&str],
) -> Result<DeviceCodeResponse, OAuthError> {
    let body = DeviceCodeRequest { client_id, scope: scopes.join(" ") };
    let response = client.post(endpoint).form(&body).send().await.map_err(|e| {
        OAuthError::DeviceFlowProtocol {
            error_code: "request_failed".to_owned(),
            description: format!("device-code POST failed: {e}"),
        }
    })?;

    let status = response.status();
    let raw = response.text().await.map_err(|e| OAuthError::DeviceFlowProtocol {
        error_code: "response_read_failed".to_owned(),
        description: format!("could not read device-code response: {e}"),
    })?;
    if !status.is_success() {
        // Try to parse RFC 8628 error body; fall back to synthesized.
        if let Ok(parsed) = serde_json::from_str::<DeviceTokenErrorBody>(&raw) {
            return Err(OAuthError::DeviceFlowProtocol {
                error_code: parsed.error,
                description: parsed.error_description.unwrap_or_default(),
            });
        }
        return Err(OAuthError::DeviceFlowProtocol {
            error_code: format!("http_{}", status.as_u16()),
            description: truncate_for_display(&raw),
        });
    }
    serde_json::from_str::<DeviceCodeResponse>(&raw).map_err(|e| OAuthError::DeviceFlowProtocol {
        error_code: "device_code_response_invalid".to_owned(),
        description: format!("device-code response did not parse: {e}"),
    })
}

/// Render the device-code block to `out`. Pure I/O — no network, no
/// allocation beyond `write!` formatting. Returns `io::Result` so the
/// caller chooses whether to fail-loud or fail-soft on tty errors.
///
/// The stdout block is the operator's only path to the consent URL,
/// so we write it before the polling loop starts (caller's job).
pub fn render_device_code_to_operator(
    response: &DeviceCodeResponse,
    out: &mut impl Write,
) -> io::Result<()> {
    writeln!(out)?;
    writeln!(out, "### open this URL on any device with a browser ###")?;
    writeln!(out)?;
    writeln!(out, "    {}", response.verification_url)?;
    writeln!(out)?;
    writeln!(out, "### and enter this code ###")?;
    writeln!(out)?;
    writeln!(out, "    {}", response.user_code)?;
    writeln!(out)?;
    writeln!(out, "Polling for consent (expires in {}s)...", response.expires_in)?;
    writeln!(out)?;
    Ok(())
}

/// Compute the polling deadline as the EARLIEST cutoff between the
/// operator's local timeout (default 120s if `None`) and Google's
/// server-side `expires_in` (capped at [`MAX_GOOGLE_EXPIRES_IN_SECS`]).
///
/// Codex review 3 issue #1 fix: prior draft used `max` which
/// produced the LATEST cutoff, defeating the local-timeout safety net.
pub fn compute_deadline(
    now: Instant,
    timeout: Option<Duration>,
    google_expires_in_secs: u64,
) -> Instant {
    let local_timeout = timeout.unwrap_or(Duration::from_secs(120));
    let google_window = Duration::from_secs(google_expires_in_secs.min(MAX_GOOGLE_EXPIRES_IN_SECS));
    now + local_timeout.min(google_window)
}

/// Poll the token endpoint until success, error, or deadline.
///
/// `clock` and `sleep` are seams for the test suite to advance
/// virtual time. The loop exits on (a) 200 + `access_token` →
/// `Ok(...)`; (b) 400 with RFC 8628 terminal error
/// (`expired_token`, `access_denied`) → typed `Err`; (c) any other
/// upstream-shape we don't model → [`OAuthError::DeviceFlowProtocol`];
/// (d) `clock.now() >= deadline` → [`OAuthError::DeviceFlowTimeout`].
///
/// `authorization_pending` and `slow_down` are non-terminal: the loop
/// sleeps `current_interval` (or `current_interval + 5s` after
/// `slow_down`) and continues.
#[allow(clippy::too_many_arguments)]
pub async fn poll_for_token(
    client: &reqwest::Client,
    endpoint: &str,
    client_id: &str,
    device_code: &str,
    deadline: Instant,
    initial_interval: Duration,
    clock: &dyn Clock,
    sleep: &dyn Sleeper,
) -> Result<DeviceTokenResponse, OAuthError> {
    let mut current_interval = initial_interval;
    let started = clock.now();

    loop {
        if clock.now() >= deadline {
            let elapsed = clock.now().duration_since(started).as_secs();
            return Err(OAuthError::DeviceFlowTimeout { timeout_secs: elapsed });
        }

        let response = client
            .post(endpoint)
            .form(&[
                ("client_id", client_id),
                ("device_code", device_code),
                ("grant_type", DEVICE_GRANT_TYPE),
            ])
            .send()
            .await
            .map_err(|e| OAuthError::DeviceFlowProtocol {
                error_code: "request_failed".to_owned(),
                description: format!("token POST failed: {e}"),
            })?;

        let status = response.status();
        let raw = response.text().await.map_err(|e| OAuthError::DeviceFlowProtocol {
            error_code: "response_read_failed".to_owned(),
            description: format!("could not read token response: {e}"),
        })?;

        if status.is_success() {
            return serde_json::from_str::<DeviceTokenResponse>(&raw).map_err(|e| {
                OAuthError::DeviceFlowProtocol {
                    error_code: "token_response_invalid".to_owned(),
                    description: format!("token response did not parse: {e}"),
                }
            });
        }

        // Non-2xx: try to parse RFC 8628 error.
        let parsed: Result<DeviceTokenErrorBody, _> = serde_json::from_str(&raw);
        match parsed {
            Ok(err) => match err.error.as_str() {
                "authorization_pending" => {
                    sleep.sleep(current_interval).await;
                    continue;
                }
                "slow_down" => {
                    current_interval = current_interval
                        .saturating_add(Duration::from_secs(SLOW_DOWN_INCREMENT_SECS));
                    sleep.sleep(current_interval).await;
                    continue;
                }
                "expired_token" => return Err(OAuthError::DeviceCodeExpired),
                "access_denied" => return Err(OAuthError::DeviceCodeDenied),
                other => {
                    return Err(OAuthError::DeviceFlowProtocol {
                        error_code: other.to_owned(),
                        description: err.error_description.unwrap_or_default(),
                    });
                }
            },
            Err(_) => {
                return Err(OAuthError::DeviceFlowProtocol {
                    error_code: format!("http_{}", status.as_u16()),
                    description: truncate_for_display(&raw),
                });
            }
        }
    }
}

/// End-to-end device flow: request_device_code →
/// render_device_code_to_operator → compute deadline → poll_for_token.
///
/// `timeout` is the operator's local timeout (`--device-flow-timeout`).
/// `None` → 120s default.
pub async fn run_device_flow(
    client: &reqwest::Client,
    endpoints: DeviceFlowEndpoints,
    client_id: &str,
    scopes: &[&str],
    timeout: Option<Duration>,
    clock: &dyn Clock,
    sleep: &dyn Sleeper,
) -> Result<DeviceFlowResult, OAuthError> {
    let device_response =
        request_device_code(client, &endpoints.device_code, client_id, scopes).await?;

    // Best-effort stdout render. If stdout is closed (rare scripted-CI
    // edge case) we still proceed — the URL is also tracing::info-logged
    // for diagnostic capture.
    tracing::info!(
        target: "permitlayer_oauth::google::device_flow",
        verification_url = %device_response.verification_url,
        user_code = %device_response.user_code,
        expires_in = device_response.expires_in,
        "device flow consent block printed"
    );
    let _ = render_device_code_to_operator(&device_response, &mut io::stdout().lock());

    let deadline = compute_deadline(clock.now(), timeout, device_response.expires_in);
    let initial_interval = Duration::from_secs(
        device_response.interval.filter(|i| *i > 0).unwrap_or(DEFAULT_POLL_INTERVAL_SECS),
    );

    let token_response = poll_for_token(
        client,
        &endpoints.token,
        client_id,
        &device_response.device_code,
        deadline,
        initial_interval,
        clock,
        sleep,
    )
    .await?;

    let access_token = OAuthToken::from_trusted_bytes(token_response.access_token.into_bytes());
    let refresh_token =
        token_response.refresh_token.map(|t| OAuthRefreshToken::from_trusted_bytes(t.into_bytes()));
    let expires_in = token_response.expires_in.map(Duration::from_secs);
    let scopes = token_response
        .scope
        .map(|s| s.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default();

    Ok(DeviceFlowResult { access_token, refresh_token, expires_in, scopes })
}

/// Truncate a body string for display in error messages. 200 chars is
/// enough to surface upstream HTML/proxy error pages without dragging
/// the whole body into the operator-facing error block.
fn truncate_for_display(s: &str) -> String {
    const MAX: usize = 200;
    if s.len() <= MAX {
        s.to_owned()
    } else {
        let mut out = s.chars().take(MAX).collect::<String>();
        out.push('…');
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Fake clock that advances virtual time only when explicitly asked,
    /// so polling-loop deadlines fire without wall-clock waits.
    #[derive(Debug)]
    struct FakeClock {
        now: Mutex<Instant>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self { now: Mutex::new(Instant::now()) }
        }
        fn advance(&self, d: Duration) {
            let mut g = self.now.lock().unwrap();
            *g += d;
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            *self.now.lock().unwrap()
        }
    }

    /// Sleeper that advances the [`FakeClock`] by the requested duration
    /// and returns immediately. The `Arc<FakeClock>` is shared with the
    /// test so assertions can read elapsed virtual time.
    struct VirtualSleeper {
        clock: std::sync::Arc<FakeClock>,
        log: Mutex<Vec<Duration>>,
    }

    impl VirtualSleeper {
        fn new(clock: std::sync::Arc<FakeClock>) -> Self {
            Self { clock, log: Mutex::new(Vec::new()) }
        }
        fn slept_durations(&self) -> Vec<Duration> {
            self.log.lock().unwrap().clone()
        }
    }

    impl Sleeper for VirtualSleeper {
        fn sleep<'a>(
            &'a self,
            duration: Duration,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
            self.log.lock().unwrap().push(duration);
            self.clock.advance(duration);
            Box::pin(async {})
        }
    }

    fn http_client() -> reqwest::Client {
        reqwest::Client::builder().build().unwrap()
    }

    #[test]
    fn deadline_uses_minimum_of_local_and_google_window() {
        // Codex review 3 issue #1: local 5s vs google 1800s → 5s wins.
        let now = Instant::now();
        let deadline = compute_deadline(now, Some(Duration::from_secs(5)), 1800);
        let delta = deadline.duration_since(now);
        assert_eq!(delta, Duration::from_secs(5));
    }

    #[test]
    fn deadline_uses_google_window_when_smaller_than_local() {
        let now = Instant::now();
        let deadline = compute_deadline(now, Some(Duration::from_secs(600)), 60);
        let delta = deadline.duration_since(now);
        assert_eq!(delta, Duration::from_secs(60));
    }

    #[test]
    fn deadline_caps_google_at_30min_even_if_upstream_promises_more() {
        let now = Instant::now();
        let deadline = compute_deadline(now, None, 86_400); // upstream says 1 day
        let delta = deadline.duration_since(now);
        // 120s default local timeout wins anyway, but verify the cap
        // is what would have applied otherwise.
        assert_eq!(delta, Duration::from_secs(120));
        // Now with a generous local timeout, the cap fires.
        let deadline = compute_deadline(now, Some(Duration::from_secs(7200)), 86_400);
        let delta = deadline.duration_since(now);
        assert_eq!(delta, Duration::from_secs(MAX_GOOGLE_EXPIRES_IN_SECS));
    }

    #[test]
    fn deadline_default_local_is_120s() {
        let now = Instant::now();
        let deadline = compute_deadline(now, None, 1800);
        let delta = deadline.duration_since(now);
        assert_eq!(delta, Duration::from_secs(120));
    }

    #[test]
    fn render_device_code_block_contains_url_and_code() {
        let response = DeviceCodeResponse {
            device_code: "secret-device-code".to_owned(),
            user_code: "ABCD-EFGH".to_owned(),
            verification_url: "https://example.test/verify".to_owned(),
            expires_in: 1800,
            interval: Some(5),
        };
        let mut buf = Vec::new();
        render_device_code_to_operator(&response, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("https://example.test/verify"));
        assert!(s.contains("ABCD-EFGH"));
        assert!(s.contains("expires in 1800s"));
        // The opaque device_code MUST NOT leak into the operator block.
        assert!(!s.contains("secret-device-code"), "device_code is opaque, never displayed");
    }

    #[tokio::test]
    async fn device_code_request_posts_correct_form_fields() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/device/code")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("client_id".into(), "test-client".into()),
                mockito::Matcher::UrlEncoded(
                    "scope".into(),
                    "https://www.googleapis.com/auth/gmail.readonly".into(),
                ),
            ]))
            .with_status(200)
            .with_body(
                r#"{"device_code":"dc","user_code":"UC","verification_url":"https://x.test/","expires_in":1800,"interval":5}"#,
            )
            .create_async()
            .await;

        let endpoint = format!("{}/device/code", server.url());
        let scopes = ["https://www.googleapis.com/auth/gmail.readonly"];
        let resp = request_device_code(&http_client(), &endpoint, "test-client", &scopes)
            .await
            .expect("device code request should succeed");
        assert_eq!(resp.device_code, "dc");
        assert_eq!(resp.user_code, "UC");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn device_flow_polls_until_authorization_grants_token() {
        let mut server = mockito::Server::new_async().await;
        // Three pending responses, then success.
        let pending = server
            .mock("POST", "/token")
            .with_status(400)
            .with_body(r#"{"error":"authorization_pending"}"#)
            .expect(3)
            .create_async()
            .await;
        let success = server
            .mock("POST", "/token")
            .with_status(200)
            .with_body(
                r#"{"access_token":"tok123","refresh_token":"refresh","expires_in":3600,"scope":"a b"}"#,
            )
            .expect(1)
            .create_async()
            .await;

        let clock = std::sync::Arc::new(FakeClock::new());
        let sleeper = VirtualSleeper::new(clock.clone());

        let token_endpoint = format!("{}/token", server.url());
        let deadline = clock.now() + Duration::from_secs(120);
        let resp = poll_for_token(
            &http_client(),
            &token_endpoint,
            "client-id",
            "device-code",
            deadline,
            Duration::from_secs(1),
            clock.as_ref(),
            &sleeper,
        )
        .await
        .expect("poll should succeed after 3 pending responses");

        assert_eq!(resp.access_token, "tok123");
        assert_eq!(resp.refresh_token.as_deref(), Some("refresh"));
        // Three sleeps each at 1s — the polling cadence is what we
        // documented; the regression case was sleeping zero times
        // (busy-loop) or doubling intervals on a non-slow_down response.
        assert_eq!(sleeper.slept_durations().len(), 3);
        assert!(sleeper.slept_durations().iter().all(|d| *d == Duration::from_secs(1)));

        pending.assert_async().await;
        success.assert_async().await;
    }

    #[tokio::test]
    async fn device_flow_handles_slow_down_by_increasing_interval() {
        let mut server = mockito::Server::new_async().await;
        let slow_down = server
            .mock("POST", "/token")
            .with_status(400)
            .with_body(r#"{"error":"slow_down"}"#)
            .expect(1)
            .create_async()
            .await;
        let success = server
            .mock("POST", "/token")
            .with_status(200)
            .with_body(r#"{"access_token":"t","expires_in":3600}"#)
            .expect(1)
            .create_async()
            .await;

        let clock = std::sync::Arc::new(FakeClock::new());
        let sleeper = VirtualSleeper::new(clock.clone());

        let token_endpoint = format!("{}/token", server.url());
        let deadline = clock.now() + Duration::from_secs(300);
        poll_for_token(
            &http_client(),
            &token_endpoint,
            "client-id",
            "device-code",
            deadline,
            Duration::from_secs(2), // initial interval 2s
            clock.as_ref(),
            &sleeper,
        )
        .await
        .expect("should succeed after one slow_down");

        // First sleep is initial_interval + SLOW_DOWN_INCREMENT_SECS = 7s.
        let durs = sleeper.slept_durations();
        assert_eq!(durs.len(), 1, "exactly one slow-down sleep before success");
        assert_eq!(durs[0], Duration::from_secs(2 + SLOW_DOWN_INCREMENT_SECS));
        slow_down.assert_async().await;
        success.assert_async().await;
    }

    #[tokio::test]
    async fn device_flow_returns_expired_when_google_expires_token() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/token")
            .with_status(400)
            .with_body(r#"{"error":"expired_token","error_description":"code expired"}"#)
            .create_async()
            .await;

        let clock = std::sync::Arc::new(FakeClock::new());
        let sleeper = VirtualSleeper::new(clock.clone());
        let token_endpoint = format!("{}/token", server.url());
        let err = poll_for_token(
            &http_client(),
            &token_endpoint,
            "client-id",
            "device-code",
            clock.now() + Duration::from_secs(120),
            Duration::from_secs(5),
            clock.as_ref(),
            &sleeper,
        )
        .await
        .expect_err("should fail with DeviceCodeExpired");
        assert!(matches!(err, OAuthError::DeviceCodeExpired), "got: {err:?}");
    }

    #[tokio::test]
    async fn device_flow_returns_denied_when_user_denies() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/token")
            .with_status(400)
            .with_body(r#"{"error":"access_denied"}"#)
            .create_async()
            .await;

        let clock = std::sync::Arc::new(FakeClock::new());
        let sleeper = VirtualSleeper::new(clock.clone());
        let token_endpoint = format!("{}/token", server.url());
        let err = poll_for_token(
            &http_client(),
            &token_endpoint,
            "client-id",
            "device-code",
            clock.now() + Duration::from_secs(120),
            Duration::from_secs(5),
            clock.as_ref(),
            &sleeper,
        )
        .await
        .expect_err("should fail with DeviceCodeDenied");
        assert!(matches!(err, OAuthError::DeviceCodeDenied), "got: {err:?}");
    }

    #[tokio::test]
    async fn device_flow_respects_local_timeout_before_google_expires_in() {
        let mut server = mockito::Server::new_async().await;
        let _pending = server
            .mock("POST", "/token")
            .with_status(400)
            .with_body(r#"{"error":"authorization_pending"}"#)
            .expect_at_least(1)
            .create_async()
            .await;

        let clock = std::sync::Arc::new(FakeClock::new());
        let sleeper = VirtualSleeper::new(clock.clone());
        let token_endpoint = format!("{}/token", server.url());

        // Deadline 5s away; each pending response sleeps 2s of virtual
        // time. After three iterations we cross the deadline.
        let err = poll_for_token(
            &http_client(),
            &token_endpoint,
            "client-id",
            "device-code",
            clock.now() + Duration::from_secs(5),
            Duration::from_secs(2),
            clock.as_ref(),
            &sleeper,
        )
        .await
        .expect_err("should DeviceFlowTimeout");
        assert!(matches!(err, OAuthError::DeviceFlowTimeout { .. }), "got: {err:?}");
    }

    #[tokio::test]
    async fn device_flow_protocol_variant_carries_unknown_error_codes() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/token")
            .with_status(400)
            .with_body(r#"{"error":"invalid_grant","error_description":"client mismatch"}"#)
            .create_async()
            .await;

        let clock = std::sync::Arc::new(FakeClock::new());
        let sleeper = VirtualSleeper::new(clock.clone());
        let token_endpoint = format!("{}/token", server.url());
        let err = poll_for_token(
            &http_client(),
            &token_endpoint,
            "client-id",
            "device-code",
            clock.now() + Duration::from_secs(120),
            Duration::from_secs(5),
            clock.as_ref(),
            &sleeper,
        )
        .await
        .expect_err("should DeviceFlowProtocol");
        match err {
            OAuthError::DeviceFlowProtocol { error_code, description } => {
                assert_eq!(error_code, "invalid_grant");
                assert_eq!(description, "client mismatch");
            }
            other => panic!("expected DeviceFlowProtocol, got {other:?}"),
        }
    }
}
