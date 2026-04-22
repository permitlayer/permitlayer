//! PII detection rules: email, US phone, SSN, credit card.

use crate::scrub::placeholder::Placeholder;
use crate::scrub::rule::ScrubRule;

/// Luhn checksum validation for credit card numbers.
///
/// Strips non-digit characters (spaces, dashes) and validates the Luhn algorithm.
/// Exposed publicly so consumers can post-filter credit card regex matches.
pub fn luhn_check(digits_raw: &str) -> bool {
    let digits: Vec<u8> =
        digits_raw.chars().filter(|c| c.is_ascii_digit()).map(|c| c as u8 - b'0').collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let mut sum: u32 = 0;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut val = u32::from(d);
        if double {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// Returns rules for detecting common PII types.
///
/// # Panics
///
/// Panics if a regex pattern fails to compile (programmer error).
#[allow(clippy::expect_used)]
pub(super) fn pii_rules() -> Vec<ScrubRule> {
    vec![
        // Email addresses
        ScrubRule::new(
            "email",
            vec!["@".into()],
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            Placeholder::Email,
        )
        .expect("email pattern must compile"),
        // US phone numbers
        ScrubRule::new(
            "phone",
            vec!["(".into(), "+1".into(), "555".into(), "-".into(), ".".into()],
            r"(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s])\d{3}[-.\s]?\d{4}\b",
            Placeholder::Phone,
        )
        .expect("phone pattern must compile"),
        // SSN (requires context words)
        ScrubRule::new(
            "ssn",
            vec!["ssn".into(), "social security".into(), "ss#".into()],
            r"(?i)(?:ssn|social\s+security(?:\s+number)?|ss#)\s*[:=]?\s*\b(\d{3}-\d{2}-\d{4})\b",
            Placeholder::Ssn,
        )
        .expect("ssn pattern must compile"),
        // Credit card with Luhn post-filter via validator callback.
        ScrubRule::with_validator(
            "credit-card",
            vec![
                "card".into(),
                "visa".into(),
                "mastercard".into(),
                "amex".into(),
                "credit".into(),
                "debit".into(),
            ],
            // Matches 13-19 digit card numbers, optionally space/dash separated in groups of 4
            r"(?i)(?:card|visa|mastercard|amex|credit|debit)[\s#:]*\b(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7})\b",
            Placeholder::CreditCard,
            luhn_check,
        )
        .expect("credit-card pattern must compile"),
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::scrub::engine::ScrubEngine;

    fn engine() -> ScrubEngine {
        ScrubEngine::new(pii_rules()).unwrap()
    }

    // --- Luhn tests ---

    #[test]
    fn luhn_valid_visa() {
        assert!(luhn_check("4111111111111111"));
    }

    #[test]
    fn luhn_valid_mastercard() {
        assert!(luhn_check("5500000000000004"));
    }

    #[test]
    fn luhn_valid_amex() {
        assert!(luhn_check("378282246310005"));
    }

    #[test]
    fn luhn_valid_with_separators() {
        assert!(luhn_check("4111-1111-1111-1111"));
        assert!(luhn_check("4111 1111 1111 1111"));
    }

    #[test]
    fn luhn_invalid() {
        assert!(!luhn_check("4111111111111112"));
    }

    #[test]
    fn luhn_too_short() {
        assert!(!luhn_check("123456"));
    }

    // --- Email true positives ---

    #[test]
    fn tp_email_standard() {
        let r = engine().scrub("Contact: john.doe@example.com for details");
        assert!(r.output.contains("<REDACTED_EMAIL>"), "output: {}", r.output);
    }

    #[test]
    fn tp_email_plus_addressing() {
        let r = engine().scrub("Send to user+tag@gmail.com");
        assert!(r.output.contains("<REDACTED_EMAIL>"));
    }

    // --- Email true negatives ---

    #[test]
    fn tn_invalid_email_no_tld() {
        let r = engine().scrub("user@localhost");
        assert!(r.is_clean(), "no TLD should not match: {}", r.output);
    }

    // --- Phone true positives ---

    #[test]
    fn tp_phone_parens() {
        let r = engine().scrub("Call (555) 123-4567 for info");
        assert!(r.output.contains("<REDACTED_PHONE>"), "output: {}", r.output);
    }

    #[test]
    fn tp_phone_plus1() {
        let r = engine().scrub("Phone: +1-555-123-4567");
        assert!(r.output.contains("<REDACTED_PHONE>"), "output: {}", r.output);
    }

    #[test]
    fn tp_phone_dots() {
        let r = engine().scrub("Reach us at 555.123.4567");
        assert!(r.output.contains("<REDACTED_PHONE>"), "output: {}", r.output);
    }

    // --- Phone true negatives ---

    #[test]
    fn tn_phone_bare_10digits() {
        // No separators or formatting — could be anything
        let r = engine().scrub("ID: 5551234567");
        assert!(r.is_clean(), "bare 10-digit number should not match: {}", r.output);
    }

    // --- SSN true positives ---

    #[test]
    fn tp_ssn_with_context() {
        let r = engine().scrub("SSN: 123-45-6789");
        assert!(r.output.contains("<REDACTED_SSN>"), "output: {}", r.output);
    }

    #[test]
    fn tp_ssn_social_security() {
        let r = engine().scrub("Social Security Number: 987-65-4321");
        assert!(r.output.contains("<REDACTED_SSN>"));
    }

    #[test]
    fn tp_ssn_ss_hash() {
        let r = engine().scrub("SS# 111-22-3333");
        assert!(r.output.contains("<REDACTED_SSN>"));
    }

    // --- SSN true negatives ---

    #[test]
    fn tn_ssn_without_context() {
        let r = engine().scrub("Reference: 123-45-6789");
        assert!(r.is_clean(), "SSN without context should not match: {}", r.output);
    }

    // --- Credit card true positives ---

    #[test]
    fn tp_cc_visa() {
        let r = engine().scrub("Visa card 4111111111111111");
        assert!(r.output.contains("<REDACTED_CC>"), "output: {}", r.output);
    }

    #[test]
    fn tp_cc_mastercard() {
        let r = engine().scrub("Mastercard 5500000000000004");
        assert!(r.output.contains("<REDACTED_CC>"), "output: {}", r.output);
    }

    #[test]
    fn tp_cc_with_spaces() {
        let r = engine().scrub("Card: 4111 1111 1111 1111");
        assert!(r.output.contains("<REDACTED_CC>"), "output: {}", r.output);
    }

    // --- Credit card true negatives ---

    #[test]
    fn tn_cc_failing_luhn_function() {
        assert!(!luhn_check("4111111111111112"));
    }

    #[test]
    fn tn_cc_failing_luhn_engine_rejects() {
        // 4111111111111112 fails Luhn — engine must NOT redact it
        let r = engine().scrub("Visa card 4111111111111112");
        assert!(r.is_clean(), "Luhn-failing number should not be redacted: {}", r.output);
    }

    #[test]
    fn rules_have_literals() {
        for rule in pii_rules() {
            assert!(!rule.literals.is_empty(), "rule '{}' must have literals", rule.name);
        }
    }
}
