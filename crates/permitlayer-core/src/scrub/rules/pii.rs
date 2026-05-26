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

/// Google domains whose `<local>@<domain>` strings are opaque *identifiers*,
/// not human mailboxes. They are syntactically identical to email addresses
/// (so the email regex matches them) but the agent must round-trip them
/// verbatim to the Google API — redacting them corrupts calendar/resource
/// lookups (a redacted calendar ID yields HTTP 404 upstream).
///
/// - `group.calendar.google.com` — secondary / family / shared calendars
/// - `import.calendar.google.com` — imported (iCal-subscription) calendars
/// - `resource.calendar.google.com` — resource calendars (rooms, equipment)
///
/// Matched on a case-insensitive exact-domain-suffix basis (not a substring
/// `contains`, which a crafted local-part or lookalike domain could spoof).
const GOOGLE_IDENTIFIER_DOMAINS: [&str; 3] =
    ["group.calendar.google.com", "import.calendar.google.com", "resource.calendar.google.com"];

/// Service-account identifier domain suffix. Service-account addresses
/// (`<name>@<project>.iam.gserviceaccount.com`, and the legacy
/// `<id>@<project>.gserviceaccount.com` form) appear in attendee /
/// organizer / ACL payloads as identifiers, not reachable mailboxes.
const GSERVICEACCOUNT_SUFFIX: &str = ".gserviceaccount.com";

/// Post-match validator for the `email` rule: returns `true` (redact) for a
/// genuine email address, `false` (pass through) for a Google non-mailbox
/// identifier (calendar/resource/service-account). Mirrors the `luhn_check`
/// post-filter on the credit-card rule.
///
/// Real human addresses — `@gmail.com`, `@googlemail.com`, corporate domains —
/// are NOT in the carve-out and are still redacted: the PII guarantee holds.
///
/// Fail-safe note: the engine invokes this on the regex match within a bounded
/// window (`scrub/engine.rs` `REGEX_WINDOW_BYTES`). A domain longer than that
/// window would be truncated, so `rsplit_once('@')` could see a clipped domain
/// — but a clipped domain can never `==`-match a carve-out domain nor end with
/// `.gserviceaccount.com`, so it falls through to `true` (redact). Truncation
/// therefore fails toward redaction, never toward leaking an identifier as a
/// false email — and toward redaction is the safe direction for PII anyway.
pub fn is_real_email_not_google_identifier(matched: &str) -> bool {
    let Some((_local, domain)) = matched.rsplit_once('@') else {
        // No `@` — the regex shouldn't produce this, but if it does, treat
        // it as a real match (fail toward redaction, never toward leaking).
        return true;
    };
    let domain = domain.trim().to_ascii_lowercase();

    if GOOGLE_IDENTIFIER_DOMAINS.iter().any(|d| domain == *d) {
        return false;
    }
    // `*.gserviceaccount.com` (any project subdomain), but not a domain that
    // merely ends with the literal string as a non-label boundary.
    if domain == "gserviceaccount.com" || domain.ends_with(GSERVICEACCOUNT_SUFFIX) {
        return false;
    }
    true
}

/// Returns rules for detecting common PII types.
///
/// # Panics
///
/// Panics if a regex pattern fails to compile (programmer error).
#[allow(clippy::expect_used)]
pub(super) fn pii_rules() -> Vec<ScrubRule> {
    vec![
        // Email addresses. The validator excludes Google non-mailbox
        // identifiers (calendar/resource/service-account) that are
        // syntactically emails but must round-trip to the API verbatim.
        ScrubRule::with_validator(
            "email",
            vec!["@".into()],
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            Placeholder::Email,
            is_real_email_not_google_identifier,
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

    // --- Google non-mailbox identifier carve-out (Story 10.8) ---
    // These are calendar/resource/service-account IDs the agent must
    // round-trip to the API; redacting them yields HTTP 404 upstream.

    #[test]
    fn tn_google_group_calendar_id_preserved() {
        let id = "c_9c5d88d2c9f3a44ae8d6b0b88dd3e0f5@group.calendar.google.com";
        let r = engine().scrub(&format!("calendar id: {id}"));
        assert!(r.is_clean(), "group calendar id must pass through: {}", r.output);
        assert!(r.output.contains(id), "id must be intact verbatim: {}", r.output);
    }

    #[test]
    fn tn_google_import_calendar_id_preserved() {
        let id = "abc123@import.calendar.google.com";
        let r = engine().scrub(id);
        assert!(r.is_clean(), "import calendar id must pass through: {}", r.output);
    }

    #[test]
    fn tn_google_resource_calendar_id_preserved() {
        let id = "room-42@resource.calendar.google.com";
        let r = engine().scrub(id);
        assert!(r.is_clean(), "resource calendar id must pass through: {}", r.output);
    }

    #[test]
    fn tn_google_service_account_id_preserved() {
        let id = "agent-bot@my-project-123.iam.gserviceaccount.com";
        let r = engine().scrub(id);
        assert!(r.is_clean(), "service-account id must pass through: {}", r.output);
        // Legacy (non-iam) form too.
        let legacy = "12345@my-project.gserviceaccount.com";
        let r2 = engine().scrub(legacy);
        assert!(r2.is_clean(), "legacy SA id must pass through: {}", r2.output);
    }

    #[test]
    fn tp_mixed_payload_redacts_email_keeps_calendar_id() {
        // A list_calendars-style payload: a real human email AND a calendar
        // identifier in the same input. Only the human email is redacted.
        let human = "alice@gmail.com";
        let cal = "c_deadbeef@group.calendar.google.com";
        let input = format!("{{\"summary\":\"{human}\",\"id\":\"{cal}\"}}");
        let r = engine().scrub(&input);
        assert!(r.output.contains("<REDACTED_EMAIL>"), "human email must redact: {}", r.output);
        assert!(!r.output.contains(human), "human email must not survive: {}", r.output);
        assert!(r.output.contains(cal), "calendar id must survive: {}", r.output);
    }

    #[test]
    fn tp_googlemail_still_redacted() {
        // A lookalike Google domain that IS a real mailbox — not carved out.
        let r = engine().scrub("reach me at bob@googlemail.com");
        assert!(r.output.contains("<REDACTED_EMAIL>"), "googlemail is real PII: {}", r.output);
    }

    #[test]
    fn validator_unit_distinguishes_identifiers_from_mailboxes() {
        // Real mailboxes → redact (true).
        assert!(is_real_email_not_google_identifier("alice@gmail.com"));
        assert!(is_real_email_not_google_identifier("bob@googlemail.com"));
        assert!(is_real_email_not_google_identifier("x@example.com"));
        // A domain that merely *contains* a carve-out string but isn't a
        // suffix-label match must still redact (anti-spoof).
        assert!(is_real_email_not_google_identifier("x@group.calendar.google.com.evil.com"));
        assert!(is_real_email_not_google_identifier("x@notgserviceaccount.com"));
        // Google identifiers → pass through (false).
        assert!(!is_real_email_not_google_identifier("c_1@group.calendar.google.com"));
        assert!(!is_real_email_not_google_identifier("a@import.calendar.google.com"));
        assert!(!is_real_email_not_google_identifier("r@resource.calendar.google.com"));
        assert!(!is_real_email_not_google_identifier("sa@p.iam.gserviceaccount.com"));
        assert!(!is_real_email_not_google_identifier("sa@gserviceaccount.com"));
        // Case-insensitive.
        assert!(!is_real_email_not_google_identifier("C_1@Group.Calendar.Google.Com"));
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
