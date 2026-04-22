//! OAuth 2.1 client for permitlayer.
//!
//! Implements PKCE S256, loopback callback server, refresh token rotation
//! with exponential backoff, and structured error handling. All credential
//! bytes are wrapped in `OAuthToken`/`OAuthRefreshToken` types that enforce
//! zero-on-drop and prevent accidental logging.

#![forbid(unsafe_code)]

pub mod callback;
pub mod client;
pub mod error;
pub mod google;
pub mod metadata;
pub mod pkce;
pub mod refresh;

pub use client::OAuthClient;
pub use error::OAuthError;
pub use google::consent::GoogleOAuthConfig;
pub use metadata::CredentialMeta;
