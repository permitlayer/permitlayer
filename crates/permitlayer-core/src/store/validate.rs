//! Service-name allowlist validator.
//!
//! The validator is deliberately hand-rolled (no `regex` crate). Every
//! service name goes through this check before any filesystem operation
//! — it MUST be fast, allocation-free, and introduce zero dependencies.
//! The `regex` crate compiles to ~500 KiB and requires a lazy-static
//! singleton; that's orders of magnitude too much machinery for a
//! single conservative pattern.
//!
//! # Pattern
//!
//! `^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$` — lowercase alphanumeric + `-`,
//! 2–64 chars, no leading/trailing hyphen. Exactly this subset is
//! structurally path-traversal-safe (no `.`, no `/`, no NUL bytes, no
//! `..` sequences — any attempt fails the character-set check before
//! the string can become a filesystem path).
//!
//! Double hyphens like `"a--b"` ARE valid per this pattern. Documented
//! deliberately: disallowing them buys nothing security-wise and rules
//! out legitimate names like `"google--cloud"`.

use crate::store::error::StoreError;

/// Minimum service name length.
const MIN_SERVICE_LEN: usize = 2;
/// Maximum service name length. Caps filesystem path length at
/// `len("vault/") + 64 + len(".sealed") = 77 bytes` — well under any
/// platform's PATH_MAX.
const MAX_SERVICE_LEN: usize = 64;

/// Validate a service name against the conservative allowlist.
///
/// Returns `Ok(())` on success; `StoreError::InvalidServiceName` on
/// any violation. The same validator is called by every public entry
/// point into the store — it's the single source of truth for what
/// constitutes a legal service identifier.
pub fn validate_service_name(s: &str) -> Result<(), StoreError> {
    let len = s.len();
    if !(MIN_SERVICE_LEN..=MAX_SERVICE_LEN).contains(&len) {
        return Err(StoreError::InvalidServiceName { input: s.to_owned() });
    }
    let bytes = s.as_bytes();
    // First/last char must be alphanumeric (no leading/trailing hyphen).
    if !is_alnum_lower(bytes[0]) || !is_alnum_lower(bytes[len - 1]) {
        return Err(StoreError::InvalidServiceName { input: s.to_owned() });
    }
    // Every byte must be lowercase alphanumeric or hyphen.
    for &b in bytes {
        if !is_alnum_lower(b) && b != b'-' {
            return Err(StoreError::InvalidServiceName { input: s.to_owned() });
        }
    }
    Ok(())
}

#[inline]
fn is_alnum_lower(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_names() {
        // Minimal and common cases.
        assert!(validate_service_name("gmail").is_ok());
        assert!(validate_service_name("google-calendar").is_ok());
        assert!(validate_service_name("a1").is_ok());
        assert!(validate_service_name("x9").is_ok());
        // Double hyphen is documented as valid.
        assert!(validate_service_name("a--b").is_ok());
        assert!(validate_service_name("google--cloud").is_ok());
        // 64-char boundary.
        let sixty_four = "a".repeat(64);
        assert!(validate_service_name(&sixty_four).is_ok());
    }

    #[test]
    fn rejects_empty_and_too_short() {
        assert!(validate_service_name("").is_err());
        assert!(validate_service_name("a").is_err());
    }

    #[test]
    fn rejects_too_long() {
        let sixty_five = "a".repeat(65);
        assert!(validate_service_name(&sixty_five).is_err());
    }

    #[test]
    fn rejects_uppercase() {
        assert!(validate_service_name("Gmail").is_err());
        assert!(validate_service_name("A1").is_err());
        assert!(validate_service_name("google-Cloud").is_err());
    }

    #[test]
    fn rejects_disallowed_chars() {
        assert!(validate_service_name("gmail_modify").is_err());
        assert!(validate_service_name("gmail.modify").is_err());
        assert!(validate_service_name("gmail/modify").is_err());
        assert!(validate_service_name("gmail modify").is_err());
        assert!(validate_service_name("gmail!").is_err());
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(validate_service_name("..").is_err());
        assert!(validate_service_name("../etc").is_err());
        assert!(validate_service_name("..foo").is_err());
        // Embedded NUL.
        assert!(validate_service_name("a\0b").is_err());
    }

    #[test]
    fn rejects_leading_or_trailing_hyphen() {
        assert!(validate_service_name("-leading").is_err());
        assert!(validate_service_name("trailing-").is_err());
        assert!(validate_service_name("-a-").is_err());
    }

    #[test]
    fn invalid_service_name_error_contains_input() {
        let err = validate_service_name("Bad").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("Bad"));
    }
}
