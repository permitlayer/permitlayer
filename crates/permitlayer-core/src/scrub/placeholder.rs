//! Typed redaction placeholders for scrubbed content.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Typed redaction placeholder per FR58.
///
/// Each variant maps to a specific category of sensitive content.
/// The engine replaces matched spans with the `Display` output
/// (e.g., `<REDACTED_OTP>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Placeholder {
    Otp,
    ResetLink,
    Bearer,
    Jwt,
    Email,
    Phone,
    Ssn,
    CreditCard,
    /// User-defined custom rule placeholder with an index into the rule name table.
    Custom(u16),
}

impl fmt::Display for Placeholder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Otp => f.write_str("<REDACTED_OTP>"),
            Self::ResetLink => f.write_str("<REDACTED_RESET_LINK>"),
            Self::Bearer => f.write_str("<REDACTED_BEARER>"),
            Self::Jwt => f.write_str("<REDACTED_JWT>"),
            Self::Email => f.write_str("<REDACTED_EMAIL>"),
            Self::Phone => f.write_str("<REDACTED_PHONE>"),
            Self::Ssn => f.write_str("<REDACTED_SSN>"),
            Self::CreditCard => f.write_str("<REDACTED_CC>"),
            Self::Custom(n) => write!(f, "<REDACTED_CUSTOM_{n}>"),
        }
    }
}

impl Placeholder {
    /// Returns the kebab-case rule name for this placeholder type.
    ///
    /// Used in audit event `extra` fields and the UX `why?` affordance.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Otp => "otp-6digit",
            Self::ResetLink => "reset-link",
            Self::Bearer => "bearer",
            Self::Jwt => "jwt",
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Ssn => "ssn",
            Self::CreditCard => "credit-card",
            // Custom placeholders use a static fallback tag. The caller
            // should use the rule name from `ScrubMatch` for specificity.
            Self::Custom(_) => "custom",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_display_all_variants() {
        assert_eq!(Placeholder::Otp.to_string(), "<REDACTED_OTP>");
        assert_eq!(Placeholder::ResetLink.to_string(), "<REDACTED_RESET_LINK>");
        assert_eq!(Placeholder::Bearer.to_string(), "<REDACTED_BEARER>");
        assert_eq!(Placeholder::Jwt.to_string(), "<REDACTED_JWT>");
        assert_eq!(Placeholder::Email.to_string(), "<REDACTED_EMAIL>");
        assert_eq!(Placeholder::Phone.to_string(), "<REDACTED_PHONE>");
        assert_eq!(Placeholder::Ssn.to_string(), "<REDACTED_SSN>");
        assert_eq!(Placeholder::CreditCard.to_string(), "<REDACTED_CC>");
    }

    #[test]
    fn test_custom_display_includes_index() {
        assert_eq!(Placeholder::Custom(0).to_string(), "<REDACTED_CUSTOM_0>");
        assert_eq!(Placeholder::Custom(42).to_string(), "<REDACTED_CUSTOM_42>");
        assert_eq!(Placeholder::Custom(u16::MAX).to_string(), "<REDACTED_CUSTOM_65535>");
    }

    #[test]
    fn test_tag_all_variants() {
        let variants: &[Placeholder] = &[
            Placeholder::Otp,
            Placeholder::ResetLink,
            Placeholder::Bearer,
            Placeholder::Jwt,
            Placeholder::Email,
            Placeholder::Phone,
            Placeholder::Ssn,
            Placeholder::CreditCard,
            Placeholder::Custom(0),
        ];
        for v in variants {
            let tag = v.tag();
            assert!(!tag.is_empty(), "tag for {v:?} should not be empty");
            // Tags should be kebab-case (lowercase, hyphens, digits).
            assert!(
                tag.chars().all(|c| c.is_ascii_lowercase() || c == '-' || c.is_ascii_digit()),
                "tag '{tag}' for {v:?} is not kebab-case"
            );
        }
    }
}
