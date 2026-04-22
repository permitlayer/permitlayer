//! Sealed credential types for permitlayer.
//!
//! This crate defines the four credential types that must never be observable
//! as plaintext outside the vault seal/unseal path:
//!
//! - [`SealedCredential`] — ciphertext + nonce + AAD (the only credential type
//!   that may cross the storage boundary)
//! - [`OAuthToken`] — short-lived access token from an upstream OAuth provider
//! - [`OAuthRefreshToken`] — long-lived refresh token for rotation
//! - [`AgentBearerToken`] — token issued to an agent at registration time
//!
//! All four types are non-`Debug`, non-`Clone`, non-`Copy`, non-`Serialize`,
//! and derive `ZeroizeOnDrop`. These invariants are enforced by
//! `cargo xtask validate-credentials`.
//!
//! This crate is the leaf of the workspace dependency graph and must not
//! depend on any other `permitlayer-*` crate.

#![forbid(unsafe_code)]

pub mod agent_bearer;
pub mod error;
pub mod oauth_token;
pub mod sealed;

pub use agent_bearer::AgentBearerToken;
pub use error::CryptoError;
pub use oauth_token::{OAuthRefreshToken, OAuthToken};
pub use sealed::{MAX_PLAINTEXT_LEN, SEALED_CREDENTIAL_VERSION, SealedCredential};
