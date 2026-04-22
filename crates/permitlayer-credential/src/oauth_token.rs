//! OAuth access and refresh tokens.
//!
//! Both types wrap opaque bytes and derive [`ZeroizeOnDrop`]. They
//! deliberately do NOT derive `Debug`, `Display`, `Clone`, `Copy`,
//! `Serialize`, `Deserialize`, `PartialEq`, `Eq`, `Hash`, `Default`, or
//! any ordering traits.
//!
//! Two independent enforcement layers guard this discipline:
//!
//! 1. `cargo xtask validate-credentials` scans the crate source and
//!    rejects forbidden `#[derive(...)]` at CI time.
//! 2. The [`static_assertions::assert_not_impl_any!`] block below fails
//!    at `cargo build` time if any forbidden trait gets implemented —
//!    whether via derive OR hand-written `impl`. This closes the gap
//!    where a manual `impl Clone for OAuthToken { … }` would bypass
//!    the derive scanner.

use static_assertions::assert_not_impl_any;
use zeroize::ZeroizeOnDrop;

/// A short-lived OAuth 2.1 access token issued by an upstream provider.
///
/// Construct via [`OAuthToken::from_trusted_bytes`]. The `from_trusted_bytes`
/// name is intentional: it signals that the caller is responsible for having
/// earned the bytes (via vault unseal, OAuth exchange, or a similarly
/// privileged code path). Callers with a legitimate need for the bytes use
/// [`OAuthToken::reveal`].
#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

impl OAuthToken {
    /// Construct an access token from raw bytes. The caller is responsible
    /// for having obtained these bytes from a trusted source.
    #[must_use = "an OAuthToken that is immediately dropped is wasted work"]
    pub fn from_trusted_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes.into_boxed_slice())
    }

    /// Intentionally reveal the underlying bytes. Use sparingly and only at
    /// the last possible moment before handing the token to an HTTP client.
    #[must_use = "revealing credential bytes without using them defeats the purpose"]
    pub fn reveal(&self) -> &[u8] {
        &self.0
    }
}

// Path C defense-in-depth: compile-time proof that OAuthToken implements
// none of the forbidden traits, via derive OR hand-written impl. Every trait
// in the scanner's FORBIDDEN_DERIVES list is mirrored here — the scanner
// catches `#[derive(...)]`, the assertions catch manual `impl ...` blocks.
assert_not_impl_any!(
    OAuthToken:
    // Copy/Clone: bitwise copy escapes zeroization
    Clone,
    Copy,
    // Formatting: would leak token bytes to logs/displays
    core::fmt::Debug,
    core::fmt::Display,
    // Default: conjures empty credentials from thin air
    Default,
    // Equality: enables timing-attack-friendly byte comparisons
    PartialEq,
    Eq,
    // Hashing: leaks bytes via HashMap keys
    core::hash::Hash,
    PartialOrd,
    Ord,
    // Auto-coerce: exposes inner bytes through trait machinery
    AsRef<[u8]>,
    AsMut<[u8]>,
    core::borrow::Borrow<[u8]>,
    core::borrow::BorrowMut<[u8]>,
    core::ops::Deref,
    core::ops::DerefMut,
    // Construction from untyped bytes: bypasses `from_trusted_bytes` naming
    From<Vec<u8>>,
    From<Box<[u8]>>,
    From<&'static [u8]>,
    // Conversion to bytes: hands token material to untyped receivers
    Into<Vec<u8>>,
    Into<Box<[u8]>>,
);

/// A long-lived OAuth 2.1 refresh token used for access-token rotation.
///
/// Construct via [`OAuthRefreshToken::from_trusted_bytes`].
#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

impl OAuthRefreshToken {
    /// Construct a refresh token from raw bytes. Caller is responsible for
    /// the source's trustworthiness.
    #[must_use = "an OAuthRefreshToken that is immediately dropped is wasted work"]
    pub fn from_trusted_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes.into_boxed_slice())
    }

    /// Intentionally reveal the underlying bytes.
    #[must_use = "revealing credential bytes without using them defeats the purpose"]
    pub fn reveal(&self) -> &[u8] {
        &self.0
    }
}

// Path C defense-in-depth: compile-time proof for OAuthRefreshToken. Same
// discipline as OAuthToken (see that type's annotated list above).
assert_not_impl_any!(
    OAuthRefreshToken:
    Clone,
    Copy,
    core::fmt::Debug,
    core::fmt::Display,
    Default,
    PartialEq,
    Eq,
    core::hash::Hash,
    PartialOrd,
    Ord,
    AsRef<[u8]>,
    AsMut<[u8]>,
    core::borrow::Borrow<[u8]>,
    core::borrow::BorrowMut<[u8]>,
    core::ops::Deref,
    core::ops::DerefMut,
    From<Vec<u8>>,
    From<Box<[u8]>>,
    From<&'static [u8]>,
    Into<Vec<u8>>,
    Into<Box<[u8]>>,
);

#[cfg(test)]
mod tests {
    use super::*;

    // Test-time-only assertions that require dev-only crates (serde). These
    // catch manual `impl serde::Serialize for OAuthToken` blocks. Gated
    // behind `#[cfg(test)]` so serde never enters the production graph.
    assert_not_impl_any!(
        OAuthToken:
        serde::Serialize,
        serde::de::DeserializeOwned,
        TryFrom<Vec<u8>>,
        TryFrom<Box<[u8]>>,
        TryFrom<&'static [u8]>,
        Into<String>,
    );
    assert_not_impl_any!(
        OAuthRefreshToken:
        serde::Serialize,
        serde::de::DeserializeOwned,
        TryFrom<Vec<u8>>,
        TryFrom<Box<[u8]>>,
        TryFrom<&'static [u8]>,
        Into<String>,
    );

    #[test]
    fn oauth_token_round_trip() {
        let original = b"test_access_token_round_trip_bytes".to_vec();
        let token = OAuthToken::from_trusted_bytes(original.clone());
        assert_eq!(token.reveal(), original.as_slice());
    }

    #[test]
    fn oauth_refresh_token_round_trip() {
        let original = b"test_refresh_token_round_trip_bytes".to_vec();
        let token = OAuthRefreshToken::from_trusted_bytes(original.clone());
        assert_eq!(token.reveal(), original.as_slice());
    }

    #[test]
    fn empty_token_is_valid() {
        // Empty tokens are syntactically valid at this layer. Domain
        // validation (minimum entropy, provider-specific format) belongs
        // at the vault/OAuth layer where tokens are loaded or minted.
        let token = OAuthToken::from_trusted_bytes(Vec::new());
        assert!(token.reveal().is_empty());
    }
}
