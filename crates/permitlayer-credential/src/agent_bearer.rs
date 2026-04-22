//! Agent bearer tokens.
//!
//! Issued by the daemon during `agentsso agent register`. Stored in the
//! agent's own config file (outside the vault — it is an agent secret, not
//! a user credential). Used for inbound agent→daemon HTTP authentication.

use static_assertions::assert_not_impl_any;
use zeroize::ZeroizeOnDrop;

/// A bearer token issued to an agent at registration time.
///
/// Construct via [`AgentBearerToken::from_trusted_bytes`].
#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);

impl AgentBearerToken {
    /// Construct a bearer token from raw bytes. Caller — typically the agent
    /// registry — is responsible for the source's trustworthiness.
    #[must_use = "an AgentBearerToken that is immediately dropped is wasted work"]
    pub fn from_trusted_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes.into_boxed_slice())
    }

    /// Intentionally reveal the underlying bytes.
    #[must_use = "revealing credential bytes without using them defeats the purpose"]
    pub fn reveal(&self) -> &[u8] {
        &self.0
    }
}

// Path C defense-in-depth: compile-time proof that AgentBearerToken
// implements none of the forbidden traits, via derive OR hand-written impl.
// Mirrors OAuthToken's list (see `oauth_token.rs` for per-trait rationale).
assert_not_impl_any!(
    AgentBearerToken:
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
mod cfg_test_assertions {
    use super::*;
    assert_not_impl_any!(
        AgentBearerToken:
        serde::Serialize,
        serde::de::DeserializeOwned,
        TryFrom<Vec<u8>>,
        TryFrom<Box<[u8]>>,
        TryFrom<&'static [u8]>,
        Into<String>,
    );
}
