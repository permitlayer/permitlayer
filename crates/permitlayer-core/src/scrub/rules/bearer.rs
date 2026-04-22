//! Bearer token and JWT detection rules.

use crate::scrub::placeholder::Placeholder;
use crate::scrub::rule::ScrubRule;

/// Returns rules for detecting bearer tokens and JWTs.
///
/// # Panics
///
/// Panics if a regex pattern fails to compile (programmer error).
#[allow(clippy::expect_used)]
pub(super) fn bearer_rules() -> Vec<ScrubRule> {
    vec![
        // Bearer token in Authorization header style
        ScrubRule::new(
            "bearer",
            vec!["bearer".into()],
            r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]{20,}=*",
            Placeholder::Bearer,
        )
        .expect("bearer pattern must compile"),
        // JWT-shaped strings (three base64url segments separated by dots)
        // All JWTs start with base64('{"') = "eyJ"
        ScrubRule::new(
            "jwt",
            vec!["eyJ".into()],
            r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            Placeholder::Jwt,
        )
        .expect("jwt pattern must compile"),
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::scrub::engine::ScrubEngine;

    fn engine() -> ScrubEngine {
        ScrubEngine::new(bearer_rules()).unwrap()
    }

    // --- Bearer true positives ---

    #[test]
    fn tp_bearer_auth_header() {
        let r = engine().scrub("Authorization: Bearer abc123def456ghi789jkl012mno345");
        assert!(r.output.contains("<REDACTED_BEARER>"), "output: {}", r.output);
    }

    #[test]
    fn tp_bearer_lowercase() {
        let r = engine().scrub("bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9token");
        assert!(!r.is_clean());
    }

    // --- JWT true positives ---

    #[test]
    fn tp_jwt_standard() {
        let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let r = engine().scrub(&format!("Token: {jwt}"));
        assert!(r.output.contains("<REDACTED_JWT>"), "output: {}", r.output);
    }

    #[test]
    fn tp_jwt_in_response_body() {
        let r = engine().scrub(r#"{"access_token":"eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJhcGkuZXhhbXBsZS5jb20ifQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}"#);
        assert!(r.output.contains("<REDACTED_JWT>"));
    }

    // --- True negatives ---

    #[test]
    fn tn_short_bearer() {
        let r = engine().scrub("Authorization: Bearer short");
        assert!(r.is_clean(), "short token should not match: {}", r.output);
    }

    #[test]
    fn tn_file_path_with_dots() {
        let r = engine().scrub("config at /etc/app.config.yaml");
        assert!(r.is_clean());
    }

    #[test]
    fn tn_short_base64() {
        let r = engine().scrub("data: aGVsbG8=");
        assert!(r.is_clean());
    }

    #[test]
    fn tn_non_jwt_with_eyj() {
        // eyJ prefix but not three segments
        let r = engine().scrub("eyJhbGciOiJSUzI1NiJ9");
        assert!(r.is_clean(), "single-segment base64 should not match JWT: {}", r.output);
    }

    #[test]
    fn rules_have_literals() {
        for rule in bearer_rules() {
            assert!(!rule.literals.is_empty(), "rule '{}' must have literals", rule.name);
        }
    }
}
