//! HMAC-SHA256 scoped token issuance and validation.
//!
//! The scoped token is NOT a bearer token the agent presents to Google —
//! it is a receipt proving permitlayer authorized a specific request.
//! Token validation is local-only (no I/O), targeting <5ms p99 (NFR3).

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::ProxyError;

type HmacSha256 = Hmac<Sha256>;

/// A scoped token binding an agent to a specific scope and resource.
pub struct ScopedToken {
    /// Hex-encoded HMAC-SHA256 token value.
    pub token: String,
    /// OAuth scope this token authorizes.
    pub scope: String,
    /// Resource this token authorizes access to.
    pub resource: String,
    /// Agent identity this token was issued for.
    pub agent_id: String,
    /// Unix epoch seconds when the token was issued.
    pub issued_at: u64,
    /// Unix epoch seconds when the token expires.
    pub expires_at: u64,
}

/// Issues and validates HMAC-SHA256 scoped tokens.
///
/// Holds a pre-derived signing key (derived from the master key via HKDF
/// at the daemon wiring layer). The key is zeroized on drop.
pub struct ScopedTokenIssuer {
    signing_key: Zeroizing<[u8; 32]>,
}

impl ScopedTokenIssuer {
    /// Create a new issuer with a pre-derived signing key.
    ///
    /// The signing key should be derived via `HKDF-SHA256(master_key,
    /// info=b"permitlayer-scoped-token-v1")` at the daemon wiring layer.
    /// For unit tests, a random 32-byte key is acceptable.
    #[must_use]
    pub fn new(signing_key: Zeroizing<[u8; 32]>) -> Self {
        Self { signing_key }
    }

    /// Issue a scoped token for the given agent, scope, and resource.
    ///
    /// The token expires after `ttl_secs` seconds. Default TTL is 60s
    /// (one tool call lifetime).
    #[must_use]
    pub fn issue(&self, agent_id: &str, scope: &str, resource: &str, ttl_secs: u64) -> ScopedToken {
        let now = chrono::Utc::now().timestamp() as u64;
        let expires_at = now + ttl_secs;

        let token = self.compute_hmac(agent_id, scope, resource, now, expires_at);

        ScopedToken {
            token,
            scope: scope.to_owned(),
            resource: resource.to_owned(),
            agent_id: agent_id.to_owned(),
            issued_at: now,
            expires_at,
        }
    }

    /// Validate a scoped token string against the expected claims.
    ///
    /// Recomputes the HMAC, checks expiry, and uses constant-time
    /// comparison to prevent timing attacks. Completes in <5ms (NFR3).
    pub fn validate(
        &self,
        token_string: &str,
        agent_id: &str,
        scope: &str,
        resource: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<(), ProxyError> {
        // Check expiry first (cheap).
        let now = chrono::Utc::now().timestamp() as u64;
        if now >= expires_at {
            return Err(ProxyError::Internal { message: "scoped token expired".to_owned() });
        }

        let expected = self.compute_hmac(agent_id, scope, resource, issued_at, expires_at);

        // Constant-time comparison to prevent timing attacks.
        let token_bytes = token_string.as_bytes();
        let expected_bytes = expected.as_bytes();

        if token_bytes.len() != expected_bytes.len()
            || token_bytes.ct_eq(expected_bytes).unwrap_u8() != 1
        {
            return Err(ProxyError::Internal {
                message: "scoped token validation failed".to_owned(),
            });
        }

        Ok(())
    }

    /// Compute the HMAC-SHA256 token value.
    ///
    /// `canonical_message = agent_id || "\0" || scope || "\0" || resource
    /// || "\0" || issued_at || "\0" || expires_at`
    fn compute_hmac(
        &self,
        agent_id: &str,
        scope: &str,
        resource: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> String {
        #[allow(clippy::expect_used)]
        let mut mac =
            HmacSha256::new_from_slice(&*self.signing_key).expect("HMAC accepts any key size");

        mac.update(agent_id.as_bytes());
        mac.update(b"\0");
        mac.update(scope.as_bytes());
        mac.update(b"\0");
        mac.update(resource.as_bytes());
        mac.update(b"\0");
        mac.update(issued_at.to_string().as_bytes());
        mac.update(b"\0");
        mac.update(expires_at.to_string().as_bytes());

        let result = mac.finalize().into_bytes();
        let mut hex = String::with_capacity(result.len() * 2);
        for byte in result.iter() {
            hex.push_str(&format!("{byte:02x}"));
        }
        hex
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn test_issuer() -> ScopedTokenIssuer {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        ScopedTokenIssuer::new(Zeroizing::new(key))
    }

    #[test]
    fn issue_and_validate_succeeds() {
        let issuer = test_issuer();
        let token = issuer.issue("agent-1", "mail.readonly", "users/me/messages", 60);

        let result = issuer.validate(
            &token.token,
            &token.agent_id,
            &token.scope,
            &token.resource,
            token.issued_at,
            token.expires_at,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn expired_token_rejected() {
        let issuer = test_issuer();
        // Issue with 0 TTL — already expired.
        let now = chrono::Utc::now().timestamp() as u64;
        let token_str = issuer.compute_hmac("agent-1", "mail.readonly", "res", now - 10, now - 5);

        let result =
            issuer.validate(&token_str, "agent-1", "mail.readonly", "res", now - 10, now - 5);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_scope_rejected() {
        let issuer = test_issuer();
        let token = issuer.issue("agent-1", "mail.readonly", "users/me/messages", 60);

        let result = issuer.validate(
            &token.token,
            &token.agent_id,
            "mail.send", // wrong scope
            &token.resource,
            token.issued_at,
            token.expires_at,
        );
        assert!(result.is_err());
    }

    #[test]
    fn wrong_agent_rejected() {
        let issuer = test_issuer();
        let token = issuer.issue("agent-1", "mail.readonly", "users/me/messages", 60);

        let result = issuer.validate(
            &token.token,
            "agent-evil", // wrong agent
            &token.scope,
            &token.resource,
            token.issued_at,
            token.expires_at,
        );
        assert!(result.is_err());
    }

    #[test]
    fn tampered_token_rejected() {
        let issuer = test_issuer();
        let token = issuer.issue("agent-1", "mail.readonly", "users/me/messages", 60);

        let mut tampered = token.token.clone();
        // Flip last character.
        let last = tampered.pop().unwrap_or('0');
        tampered.push(if last == 'f' { '0' } else { 'f' });

        let result = issuer.validate(
            &tampered,
            &token.agent_id,
            &token.scope,
            &token.resource,
            token.issued_at,
            token.expires_at,
        );
        assert!(result.is_err());
    }

    #[test]
    fn token_is_64_hex_chars() {
        let issuer = test_issuer();
        let token = issuer.issue("agent-1", "mail.readonly", "users/me/messages", 60);
        // HMAC-SHA256 produces 32 bytes = 64 hex chars.
        assert_eq!(token.token.len(), 64);
        assert!(token.token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn validate_performance_under_5ms() {
        let issuer = test_issuer();
        let token = issuer.issue("agent-1", "mail.readonly", "users/me/messages", 60);

        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let _ = issuer.validate(
                &token.token,
                &token.agent_id,
                &token.scope,
                &token.resource,
                token.issued_at,
                token.expires_at,
            );
        }
        let elapsed = start.elapsed();
        let per_call = elapsed / 1000;
        // Should be well under 5ms per call.
        assert!(
            per_call.as_millis() < 5,
            "validate took {}ms per call, NFR3 requires <5ms",
            per_call.as_millis()
        );
    }
}
