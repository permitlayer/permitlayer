//! Shared OAuth-flow rendering helpers — Story 7.13 round-1 D1 factor-out.
//!
//! These helpers were originally inlined in `cli/setup.rs` (deleted in
//! Story 7.13) and then ported into `cli/connect.rs`. The round-1 review
//! deferred the factor-out to a follow-up under the rationale "no
//! second consumer post-merge". The defer-audit corrected that: a
//! mechanical move is exactly the kind of work the
//! `feedback_no_lazy_deferrals.md` rule asks us to do now, not later.
//! Future commands like `credentials reauth` (or any verb that runs an
//! OAuth flow against the same daemon) inherit these helpers without
//! needing to re-extract them.
//!
//! # Contents
//!
//! - [`SpinnerGuard`] — RAII wrapper around `indicatif::ProgressBar`
//!   that guarantees `finish_and_clear()` even on panic.
//! - [`build_teal_theme`] — accent-color `dialoguer::ColorfulTheme`
//!   that matches the rest of the CLI design system.
//! - [`OAuthErrorSeverity`] + [`render_oauth_error`] — surface
//!   `OAuthError::remediation_owned()` (Story 7.12) into either the
//!   design-system error block (interactive) or structured tracing
//!   (non-interactive).
//! - [`print_headless_consent_block`] / [`read_pasted_redirect_url`] —
//!   the rc.13 `--headless` paste-redirect-URL flow with OSC 52 clipboard
//!   prefetch.

use std::io::Write as _;

use permitlayer_oauth::error::OAuthError;

use crate::design::render;
use crate::design::theme::Theme;

/// RAII guard that ensures an [`indicatif::ProgressBar`] spinner is
/// `finish_and_clear`'d when the guard drops, even on panic or early
/// return.
pub(crate) struct SpinnerGuard {
    spinner: Option<indicatif::ProgressBar>,
}

impl SpinnerGuard {
    pub(crate) fn new(spinner: indicatif::ProgressBar) -> Self {
        Self { spinner: Some(spinner) }
    }
}

impl Drop for SpinnerGuard {
    fn drop(&mut self) {
        if let Some(spinner) = self.spinner.take() {
            spinner.finish_and_clear();
        }
    }
}

/// Build the accent-colored `dialoguer::ColorfulTheme` used by every
/// interactive prompt in the OAuth flow.
///
/// Originally `cli::setup::build_teal_theme`. Same accent rules as the
/// rest of the CLI design system: teal 43 for Carapace/Tidepool,
/// darker teal 30 for the Molt light theme.
pub(crate) fn build_teal_theme(theme: &Theme) -> dialoguer::theme::ColorfulTheme {
    let accent_256 = match theme {
        Theme::Carapace | Theme::Tidepool => 43_u8,
        Theme::Molt => 30,
    };
    dialoguer::theme::ColorfulTheme {
        prompt_prefix: console::style("?".to_string()).for_stderr().color256(accent_256),
        success_prefix: console::style("\u{2713}".to_string()).for_stderr().color256(accent_256),
        values_style: console::Style::new().for_stderr().color256(accent_256),
        ..dialoguer::theme::ColorfulTheme::default()
    }
}

/// Severity of an `OAuthError` for the non-interactive tracing-log
/// dispatch path. Story 11.13: the OAuth dance (`oauth_seal`) only ever
/// reports `Fatal` now — verify-on-seal is a separate daemon-side probe
/// (not routed through this renderer), so the former `NonFatal` arm was
/// removed with the retired `connect` verb.
#[derive(Debug, Clone, Copy)]
pub(crate) enum OAuthErrorSeverity {
    Fatal,
}

/// Render an [`OAuthError`] using the design system or structured
/// tracing.
///
/// Story 7.12 invariant: `e.remediation_owned()` so VerificationFailed
/// with a typed VerifyReason renders the actionable URL/gcloud command
/// (the `Cow::Owned` path); static-text variants delegate via
/// `Cow::Borrowed`.
pub(crate) fn render_oauth_error(
    e: &OAuthError,
    service: &str,
    interactive: bool,
    severity: OAuthErrorSeverity,
    log_context: &str,
) {
    let remediation = e.remediation_owned();
    if interactive {
        print!(
            "{}",
            render::error_block(
                e.error_code(),
                &format!("{service} \u{00b7} {e}"),
                remediation.as_ref(),
                None,
            )
        );
    } else {
        let remediation_single_line = remediation.replace('\r', "").replace('\n', "\\n");
        match severity {
            OAuthErrorSeverity::Fatal => tracing::error!(
                service = %service,
                error_code = %e.error_code(),
                error = %e,
                remediation = %remediation_single_line,
                "{}",
                log_context
            ),
        }
    }
}

/// rc.13 headless paste-redirect-URL timeout.
pub(crate) const HEADLESS_PASTE_TIMEOUT_SECS: u64 = 300;

/// Print the rc.13 `--headless` consent block with OSC 52 clipboard
/// prefetch. Output goes to stderr so a `2>` redirect can capture
/// operator-facing UX without entangling stdout.
pub(crate) fn print_headless_consent_block(url: &str) {
    eprintln!();
    eprintln!("  Open this URL in any browser to grant consent:");
    eprintln!();
    eprintln!("    {url}");
    eprintln!();
    emit_osc52_copy(url);
    eprintln!("  (Attempted to copy the URL to your terminal's clipboard. If your");
    eprintln!("   terminal supports OSC 52, paste it directly. Otherwise select");
    eprintln!("   and copy the URL above manually.)");
    eprintln!();
    eprintln!("  After approving, your browser will redirect to a 127.0.0.1 URL");
    eprintln!("  that won't load (this host isn't listening for it). That's expected.");
    eprintln!("  Copy the full redirect URL from your browser's address bar and");
    eprintln!("  paste it below.");
    eprintln!();
}

fn emit_osc52_copy(text: &str) {
    let payload = encode_base64_standard(text.as_bytes());
    eprint!("\x1b]52;c;{payload}\x07");
    let _ = std::io::stderr().flush();
}

fn encode_base64_standard(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0b11) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() >= 2 {
            out.push(ALPHABET[(((b1 & 0b1111) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() >= 3 {
            out.push(ALPHABET[(b2 & 0b111111) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Read the operator's pasted redirect URL from stdin. Bounded
/// timeout (`HEADLESS_PASTE_TIMEOUT_SECS`) so a closed-browser-tab
/// session doesn't hang the runtime forever; empty input
/// (Ctrl-D / immediate Enter) is treated as an explicit cancel and
/// surfaces as `OAuthError::CallbackTimeout`.
///
/// Sync stdin reads run inside `tokio::task::spawn_blocking` per the
/// daemon's Story P61 discipline.
pub(crate) async fn read_pasted_redirect_url() -> Result<String, permitlayer_oauth::OAuthError> {
    use std::io::BufRead;
    eprint!("  Paste redirect URL (Ctrl-D to cancel): ");
    let _ = std::io::stderr().flush();
    let read_handle = tokio::task::spawn_blocking(|| -> std::io::Result<String> {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        Ok(line)
    });
    let line = match tokio::time::timeout(
        std::time::Duration::from_secs(HEADLESS_PASTE_TIMEOUT_SECS),
        read_handle,
    )
    .await
    {
        Ok(Ok(Ok(s))) => s,
        Ok(Ok(Err(e))) => {
            return Err(permitlayer_oauth::OAuthError::CallbackServerFailed { source: e });
        }
        Ok(Err(join_err)) => {
            return Err(permitlayer_oauth::OAuthError::CallbackServerFailed {
                source: std::io::Error::other(format!("stdin task panicked: {join_err}")),
            });
        }
        Err(_) => {
            return Err(permitlayer_oauth::OAuthError::CallbackTimeout {
                timeout_secs: HEADLESS_PASTE_TIMEOUT_SECS,
            });
        }
    };
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(permitlayer_oauth::OAuthError::CallbackTimeout {
            timeout_secs: HEADLESS_PASTE_TIMEOUT_SECS,
        });
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod base64_tests {
    use super::encode_base64_standard;

    /// RFC 4648 §10 test vectors.
    #[test]
    fn rfc4648_vectors() {
        assert_eq!(encode_base64_standard(b""), "");
        assert_eq!(encode_base64_standard(b"f"), "Zg==");
        assert_eq!(encode_base64_standard(b"fo"), "Zm8=");
        assert_eq!(encode_base64_standard(b"foo"), "Zm9v");
        assert_eq!(encode_base64_standard(b"foob"), "Zm9vYg==");
        assert_eq!(encode_base64_standard(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode_base64_standard(b"foobar"), "Zm9vYmFy");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn spinner_guard_clears_on_drop() {
        let spinner = indicatif::ProgressBar::new_spinner();
        spinner.set_message("test message");
        assert!(!spinner.is_finished(), "spinner should start not-finished");
        {
            let _guard = SpinnerGuard::new(spinner.clone());
            assert!(!spinner.is_finished());
        }
        assert!(spinner.is_finished(), "SpinnerGuard::drop should finish the spinner");
    }
}
