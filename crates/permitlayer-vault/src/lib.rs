//! Master key lifecycle and seal/unseal operations for permitlayer credentials.
//!
//! The vault is the sole surface that holds the master key and performs
//! seal/unseal. The storage layer is structurally incapable of observing
//! plaintext credentials.

#![forbid(unsafe_code)]

pub mod error;
pub mod seal;

pub use error::VaultError;
pub use seal::Vault;
