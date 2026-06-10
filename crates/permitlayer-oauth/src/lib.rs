//! OAuth 2.1 client for permitlayer.
//!
//! Implements PKCE S256, loopback callback server, refresh token rotation
//! with exponential backoff, and structured error handling. All credential
//! bytes are wrapped in `OAuthToken`/`OAuthRefreshToken` types that enforce
//! zero-on-drop and prevent accidental logging.

#![forbid(unsafe_code)]

// Story 7.11 review-round-2 Q3: workspace-wide test-seam discipline.
// See `permitlayer-core::lib.rs` for the full rationale.
#[cfg(all(feature = "test-seam", not(debug_assertions)))]
compile_error!(
    "the `test-seam` feature must NOT be enabled in release builds. \
     If you need to run integration tests against this crate, build \
     with `cargo test --features test-seam` (debug profile) instead."
);

pub mod callback;
pub mod client;
pub mod error;
pub mod google;
pub(crate) mod headless;
pub mod osc52;
pub mod pkce;
pub mod refresh;

pub use client::OAuthClient;
pub use error::OAuthError;
pub use google::consent::GoogleOAuthConfig;
