//! Scrub rule: a literal+regex pair for two-pass matching.

use super::error::ScrubError;
use super::placeholder::Placeholder;

/// Optional post-match validator. Returns `true` if the matched text should
/// be redacted. Used for checks that cannot be expressed as regex (e.g., Luhn).
pub type Validator = fn(&str) -> bool;

/// A single scrubbing rule combining fast-path literals with regex confirmation.
#[derive(Clone)]
pub struct ScrubRule {
    /// Human-readable name (e.g., `"otp-6digit"`).
    pub name: String,
    /// Literal strings for the aho-corasick first pass. If any literal
    /// matches in the input, the regex second pass is invoked on the
    /// surrounding region.
    pub literals: Vec<String>,
    /// Regex pattern for confirmation + capture. If the pattern contains
    /// a capture group 1, the engine replaces only that group; otherwise
    /// group 0 (the full match) is replaced.
    pub pattern: regex::Regex,
    /// Placeholder type for replacement.
    pub placeholder: Placeholder,
    /// Optional post-match validator. When set, a regex match is only
    /// confirmed if `validator(matched_text)` returns `true`.
    pub validator: Option<Validator>,
}

impl std::fmt::Debug for ScrubRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScrubRule")
            .field("name", &self.name)
            .field("literals", &self.literals)
            .field("pattern", &self.pattern)
            .field("placeholder", &self.placeholder)
            .field("validator", &self.validator.map(|_| "fn(&str) -> bool"))
            .finish()
    }
}

impl ScrubRule {
    /// Create a new scrub rule, compiling the regex pattern.
    ///
    /// # Errors
    ///
    /// Returns [`ScrubError::RegexCompile`] if `pattern_str` is not a valid regex.
    pub fn new(
        name: impl Into<String>,
        literals: Vec<String>,
        pattern_str: &str,
        placeholder: Placeholder,
    ) -> Result<Self, ScrubError> {
        let pattern = regex::Regex::new(pattern_str).map_err(|source| {
            ScrubError::RegexCompile { pattern: pattern_str.to_string(), source }
        })?;
        Ok(Self { name: name.into(), literals, pattern, placeholder, validator: None })
    }

    /// Create a new scrub rule with a post-match validator.
    ///
    /// The validator is called with the matched text (capture group 1 if
    /// present, otherwise group 0). Only matches where the validator
    /// returns `true` are redacted.
    ///
    /// # Errors
    ///
    /// Returns [`ScrubError::RegexCompile`] if `pattern_str` is not a valid regex.
    pub fn with_validator(
        name: impl Into<String>,
        literals: Vec<String>,
        pattern_str: &str,
        placeholder: Placeholder,
        validator: Validator,
    ) -> Result<Self, ScrubError> {
        let pattern = regex::Regex::new(pattern_str).map_err(|source| {
            ScrubError::RegexCompile { pattern: pattern_str.to_string(), source }
        })?;
        Ok(Self { name: name.into(), literals, pattern, placeholder, validator: Some(validator) })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_construction() {
        let rule =
            ScrubRule::new("test-rule", vec!["code".to_string()], r"\d{6}", Placeholder::Otp);
        assert!(rule.is_ok());
        let rule = rule.unwrap();
        assert_eq!(rule.name, "test-rule");
        assert_eq!(rule.literals, vec!["code".to_string()]);
    }

    #[test]
    fn test_invalid_regex_error() {
        let result = ScrubRule::new(
            "bad-rule",
            vec!["literal".to_string()],
            "(", // unclosed group
            Placeholder::Otp,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ScrubError::RegexCompile { pattern, .. } => {
                assert_eq!(pattern, "(");
            }
            other => panic!("expected RegexCompile, got: {other:?}"),
        }
    }

    #[test]
    fn test_empty_literals_accepted() {
        let rule = ScrubRule::new("regex-only", vec![], r"\d+", Placeholder::Custom(0));
        assert!(rule.is_ok());
        let rule = rule.unwrap();
        assert!(rule.literals.is_empty());
        assert!(rule.validator.is_none());
    }

    #[test]
    fn test_with_validator() {
        let rule = ScrubRule::with_validator(
            "validated",
            vec!["test".to_string()],
            r"\d+",
            Placeholder::Custom(0),
            |s| s.len() > 3,
        );
        assert!(rule.is_ok());
        let rule = rule.unwrap();
        assert!(rule.validator.is_some());
        assert!((rule.validator.unwrap())("1234"));
        assert!(!(rule.validator.unwrap())("12"));
    }
}
