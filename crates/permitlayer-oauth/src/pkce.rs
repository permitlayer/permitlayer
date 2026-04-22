//! PKCE S256 helpers for OAuth 2.1.
//!
//! Thin convenience wrapper around `oauth2::PkceCodeChallenge::new_random_sha256()`.
//! The `oauth2` crate handles all crypto (SHA-256 + base64url encoding).
//! Do NOT hand-roll PKCE math.

use oauth2::{PkceCodeChallenge, PkceCodeVerifier};

/// Generate a PKCE code challenge + verifier pair using S256.
///
/// Delegates entirely to `oauth2::PkceCodeChallenge::new_random_sha256()`.
/// This wrapper centralizes PKCE creation for use by `client.rs`.
#[must_use]
pub fn generate_pkce() -> (PkceCodeChallenge, PkceCodeVerifier) {
    PkceCodeChallenge::new_random_sha256()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn generate_pkce_returns_non_empty() {
        let (challenge, verifier) = generate_pkce();
        // Challenge method must be S256.
        assert_eq!(challenge.method().as_str(), "S256");
        // Verifier must be non-empty.
        let verifier_str = verifier.secret();
        assert!(!verifier_str.is_empty(), "verifier must be non-empty");
    }

    #[test]
    fn verifier_length_within_rfc7636_spec() {
        // RFC 7636 §4.1: code_verifier is 43-128 characters of unreserved
        // characters (base64url-encoded).
        let (_challenge, verifier) = generate_pkce();
        let len = verifier.secret().len();
        assert!(
            (43..=128).contains(&len),
            "verifier length {len} outside RFC 7636 spec range [43, 128]"
        );
    }

    #[test]
    fn two_calls_produce_different_verifiers() {
        let (_c1, v1) = generate_pkce();
        let (_c2, v2) = generate_pkce();
        assert_ne!(
            v1.secret(),
            v2.secret(),
            "two PKCE generations must produce distinct verifiers"
        );
    }
}
