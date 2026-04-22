//! Password reset URL detection rules.

use crate::scrub::placeholder::Placeholder;
use crate::scrub::rule::ScrubRule;

/// Returns rules for detecting password reset/verify/confirm URLs.
///
/// # Panics
///
/// Panics if a regex pattern fails to compile (programmer error).
#[allow(clippy::expect_used)]
pub(super) fn reset_link_rules() -> Vec<ScrubRule> {
    vec![ScrubRule::new(
        "reset-link",
        vec![
            "reset".into(),
            "password".into(),
            "verify".into(),
            "confirm".into(),
            "activate".into(),
            "token=".into(),
            "code=".into(),
        ],
        // Match URLs with reset/verify/confirm/activate path segments (bounded by / or ? or end)
        // or token=/code= query params
        r#"(?i)https?://[^\s<>"']+(?:/(?:reset|verify|confirm|activate|password)(?:/|[?#]|$)[^\s<>"']*|[?&](?:token|code|reset_token|verification_code)=[^\s<>"']+)"#,
        Placeholder::ResetLink,
    )
    .expect("reset-link pattern must compile")]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::scrub::engine::ScrubEngine;

    fn engine() -> ScrubEngine {
        ScrubEngine::new(reset_link_rules()).unwrap()
    }

    // --- True positives ---

    #[test]
    fn tp_gmail_reset() {
        let r = engine()
            .scrub("Click here: https://accounts.google.com/reset/password?token=abc123def");
        assert!(r.output.contains("<REDACTED_RESET_LINK>"), "output: {}", r.output);
    }

    #[test]
    fn tp_outlook_verify() {
        let r = engine()
            .scrub("Verify your email: https://login.microsoftonline.com/verify/email?code=xyz789");
        assert!(r.output.contains("<REDACTED_RESET_LINK>"));
    }

    #[test]
    fn tp_saas_password_reset() {
        let r =
            engine().scrub("Reset your password: https://app.example.com/password/reset/abc123");
        assert!(r.output.contains("<REDACTED_RESET_LINK>"));
    }

    #[test]
    fn tp_activate_link() {
        let r = engine().scrub("Activate account: https://example.com/activate/account?token=abc");
        assert!(r.output.contains("<REDACTED_RESET_LINK>"));
    }

    #[test]
    fn tp_confirm_link() {
        let r = engine().scrub("Confirm email: https://example.com/confirm/email?code=def456");
        assert!(r.output.contains("<REDACTED_RESET_LINK>"));
    }

    #[test]
    fn tp_token_query_param() {
        let r = engine().scrub("https://app.bank.com/auth/callback?token=eyJhbGciOiJSUzI1NiJ9");
        assert!(r.output.contains("<REDACTED_RESET_LINK>"));
    }

    // --- True negatives ---

    #[test]
    fn tn_normal_url() {
        let r = engine().scrub("Visit https://www.example.com/about for more info");
        assert!(r.is_clean(), "normal URL should not match: {}", r.output);
    }

    #[test]
    fn tn_documentation_url() {
        let r = engine().scrub("See docs at https://docs.example.com/api/reference");
        assert!(r.is_clean());
    }

    #[test]
    fn tn_api_endpoint() {
        let r = engine().scrub("POST https://api.example.com/v1/users/create");
        assert!(r.is_clean());
    }

    #[test]
    fn tn_plain_text_reset() {
        let r = engine().scrub("Please reset your preferences in settings");
        assert!(r.is_clean(), "plain text with 'reset' should not match: {}", r.output);
    }

    #[test]
    fn rules_have_literals() {
        for rule in reset_link_rules() {
            assert!(!rule.literals.is_empty(), "rule '{}' must have literals", rule.name);
        }
    }
}
