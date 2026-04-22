//! OTP code detection rules (6-digit and 8-digit).

use crate::scrub::placeholder::Placeholder;
use crate::scrub::rule::ScrubRule;

/// Returns rules for detecting OTP codes in email/message content.
///
/// # Panics
///
/// Panics if a regex pattern fails to compile (programmer error).
#[allow(clippy::expect_used)]
pub(super) fn otp_rules() -> Vec<ScrubRule> {
    vec![
        // 6-digit OTP: requires context words before the digits
        ScrubRule::new(
            "otp-6digit",
            vec![
                "code is".into(),
                "code:".into(),
                "verification code".into(),
                "passcode".into(),
                "one-time".into(),
                "otp".into(),
                "pin is".into(),
                "pin:".into(),
            ],
            r"(?i)(?:(?:verification\s+)?code(?:\s+is)?|passcode|one[- ]time\s+(?:password|code|pin)|otp|pin(?:\s+is)?)\s*[:=]?\s*\b(\d{6})\b",
            Placeholder::Otp,
        )
        .expect("otp-6digit pattern must compile"),

        // 8-digit OTP: same context words, 8 digits
        ScrubRule::new(
            "otp-8digit",
            vec![
                "code is".into(),
                "code:".into(),
                "verification code".into(),
                "passcode".into(),
                "one-time".into(),
                "otp".into(),
                "pin is".into(),
                "pin:".into(),
            ],
            r"(?i)(?:(?:verification\s+)?code(?:\s+is)?|passcode|one[- ]time\s+(?:password|code|pin)|otp|pin(?:\s+is)?)\s*[:=]?\s*\b(\d{8})\b",
            Placeholder::Otp,
        )
        .expect("otp-8digit pattern must compile"),
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::scrub::engine::ScrubEngine;

    fn engine() -> ScrubEngine {
        ScrubEngine::new(otp_rules()).unwrap()
    }

    // --- True positives ---

    #[test]
    fn tp_code_is_6digit() {
        let r = engine().scrub("Your verification code is 123456. Please enter it.");
        assert!(r.output.contains("<REDACTED_OTP>"));
        assert!(!r.output.contains("123456"));
    }

    #[test]
    fn tp_code_colon_6digit() {
        let r = engine().scrub("code: 987654");
        assert!(r.output.contains("<REDACTED_OTP>"));
    }

    #[test]
    fn tp_passcode_6digit() {
        let r = engine().scrub("Your passcode is 654321");
        assert!(r.output.contains("<REDACTED_OTP>"));
    }

    #[test]
    fn tp_otp_keyword_6digit() {
        let r = engine().scrub("OTP: 111222");
        assert!(r.output.contains("<REDACTED_OTP>"));
    }

    #[test]
    fn tp_one_time_code_6digit() {
        let r = engine().scrub("Your one-time code is 999888");
        assert!(r.output.contains("<REDACTED_OTP>"));
    }

    #[test]
    fn tp_pin_is_6digit() {
        let r = engine().scrub("Your pin is 554433");
        assert!(r.output.contains("<REDACTED_OTP>"));
    }

    #[test]
    fn tp_8digit_otp() {
        let r = engine().scrub("Your verification code is 12345678");
        assert!(r.output.contains("<REDACTED_OTP>"));
        assert!(!r.output.contains("12345678"));
    }

    #[test]
    fn tp_case_insensitive() {
        let r = engine().scrub("YOUR CODE IS 123456");
        assert!(r.output.contains("<REDACTED_OTP>"));
    }

    #[test]
    fn tp_code_equals_6digit() {
        let r = engine().scrub("verification code=223344");
        assert!(r.output.contains("<REDACTED_OTP>"));
    }

    // --- True negatives ---

    #[test]
    fn tn_bare_6digits() {
        let r = engine().scrub("The amount is 123456 dollars");
        assert!(r.is_clean(), "bare 6-digit number should not match: {}", r.output);
    }

    #[test]
    fn tn_zip_code() {
        let r = engine().scrub("ZIP code 90210 is in California");
        assert!(r.is_clean(), "zip code should not match");
    }

    #[test]
    fn tn_phone_number() {
        let r = engine().scrub("Call 555-123-4567");
        assert!(r.is_clean());
    }

    #[test]
    fn tn_dollar_amount() {
        let r = engine().scrub("Total: $123456.00");
        assert!(r.is_clean());
    }

    #[test]
    fn tn_date() {
        let r = engine().scrub("Date: 20240615");
        assert!(r.is_clean());
    }

    #[test]
    fn tn_standalone_digits_no_context() {
        let r = engine().scrub("Order number 654321 has shipped");
        assert!(r.is_clean());
    }

    #[test]
    fn rules_have_literals() {
        for rule in otp_rules() {
            assert!(!rule.literals.is_empty(), "rule '{}' must have literals", rule.name);
        }
    }
}
