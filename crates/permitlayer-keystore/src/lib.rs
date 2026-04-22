//! OS keychain abstraction for permitlayer.
//!
//! This crate provides one job: produce the 32-byte master key that the
//! vault (`permitlayer-vault`, Story 1.3) uses to seal/unseal credentials.
//! It does NOT store credentials, encrypt blobs, or manage any per-
//! (service, account) state. The vault owns all of that.
//!
//! Four adapters satisfy the [`KeyStore`] trait:
//! - `MacKeyStore` — macOS Keychain Services via the `keyring` crate
//! - `LinuxKeyStore` — libsecret/Secret Service via the `keyring` crate
//! - `WindowsKeyStore` — DPAPI/Credential Manager via the `keyring` crate
//! - `PassphraseKeyStore` — cross-platform fallback, re-derives the key
//!   via Argon2id from a user passphrase on every process start
//!
//! The three native adapters persist a single entry at
//! (`{MASTER_KEY_SERVICE}`, `{MASTER_KEY_ACCOUNT}`). The passphrase
//! adapter derives the key from user input; its [`KeyStore::set_master_key`]
//! is intentionally an error because there is no persisted key to replace.
//!
//! # Unsafe policy
//!
//! This crate is the single exception to the workspace's
//! `#![forbid(unsafe_code)]` policy (see `architecture.md` §Process
//! Patterns, lines 552–559). At MVP this crate writes no `unsafe` blocks
//! itself — the `keyring` crate handles FFI internally. The `forbid` lift
//! is preparatory: if a later story needs to bypass `keyring`, the
//! infrastructure is ready. Any `unsafe` block authored here MUST carry a
//! `// SAFETY:` comment documenting (1) invariants, (2) why they hold,
//! and (3) what breaks if violated.
//!
//! # Async discipline
//!
//! Every platform adapter wraps its `keyring::Entry` calls in
//! `tokio::task::spawn_blocking` (AC #3). The `keyring` crate's FFI
//! boundary is synchronous and can block arbitrarily (the macOS keychain,
//! for instance, can prompt the user). Calling it from an async task
//! without `spawn_blocking` risks deadlocking the runtime.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod error;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod passphrase;
#[cfg(target_os = "windows")]
pub mod windows;

use std::path::PathBuf;

use zeroize::Zeroizing;

pub use error::KeyStoreError;
#[cfg(target_os = "linux")]
pub use linux::LinuxKeyStore;
#[cfg(target_os = "macos")]
pub use macos::MacKeyStore;
pub use passphrase::PassphraseKeyStore;
#[cfg(target_os = "windows")]
pub use windows::WindowsKeyStore;

/// Length of the master key in bytes. Fixed at 32 to match AES-256.
pub const MASTER_KEY_LEN: usize = 32;

/// Reverse-DNS service identifier used by native adapters when talking
/// to the OS keychain. Compile-time constant — callers cannot supply
/// their own service strings, which structurally eliminates path-
/// traversal and delimiter-collision concerns.
pub const MASTER_KEY_SERVICE: &str = "io.permitlayer.master-key";

/// Account identifier for the master-key entry. At MVP there is exactly
/// one key per machine; this may become a slot identifier when key
/// rotation (Story 7.6) introduces versioning.
pub const MASTER_KEY_ACCOUNT: &str = "master";

/// Cross-platform provider for the 32-byte master encryption key.
///
/// Implementations wrap native OS keychains or derive the key from a
/// user passphrase via Argon2id. The vault calls [`Self::master_key`]
/// once at boot and uses the returned bytes for AEAD seal/unseal.
///
/// All methods are async; platform FFI calls MUST be dispatched to a
/// blocking worker via `tokio::task::spawn_blocking` inside the
/// implementation (AC #3).
#[async_trait::async_trait]
pub trait KeyStore: Send + Sync {
    /// Fetch the 32-byte master key, generating and persisting a fresh
    /// random key on first call if none exists (for adapters that
    /// persist). The returned buffer is zeroized on drop.
    #[must_use = "master key result must not be silently discarded"]
    async fn master_key(&self) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, KeyStoreError>;

    /// Replace the stored master key. Used by `agentsso rotate-key`
    /// (Story 7.6). Returns [`KeyStoreError::PassphraseAdapterImmutable`]
    /// for the passphrase adapter, which derives its key from user
    /// input rather than persisting it.
    #[must_use = "set_master_key result must not be silently discarded"]
    async fn set_master_key(&self, key: &[u8; MASTER_KEY_LEN]) -> Result<(), KeyStoreError>;
}

/// Configuration passed by the daemon to select a keystore adapter.
///
/// Keystore owns its own config schema — it does NOT derive
/// `serde::Deserialize`. Daemon (Story 1.4) converts its TOML-derived
/// struct into this one at boot.
#[derive(Debug)]
pub struct KeystoreConfig {
    /// Fallback behavior when the native backend is unavailable.
    pub fallback: FallbackMode,
    /// Home directory for keystore on-disk state (salt + verifier).
    /// Typically `~/.agentsso`.
    pub home: PathBuf,
}

/// How to pick an adapter when the native OS keychain cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FallbackMode {
    /// Try the native backend first; fall back to the passphrase
    /// adapter if the backend is unavailable. Requires a terminal —
    /// `PassphraseKeyStore::from_prompt` blocks on stdin.
    Auto,
    /// Always use the passphrase adapter — never touch the OS
    /// keychain. Headless Linux servers often want this.
    Passphrase,
    /// Never fall back. If the native backend is unavailable, fail.
    None,
}

/// Construct the default keystore adapter for this platform + config.
///
/// Selection matrix:
///
/// | `fallback`        | native available | result                |
/// |-------------------|------------------|-----------------------|
/// | `Auto`            | yes              | native adapter        |
/// | `Auto`            | no               | passphrase adapter    |
/// | `Passphrase`      | (ignored)        | passphrase adapter    |
/// | `None`            | yes              | native adapter        |
/// | `None`            | no               | `BackendUnavailable`  |
///
/// The passphrase adapter prompts the user via `rpassword` in
/// non-echoing mode. It MUST NOT be constructed from a non-interactive
/// context unless the config explicitly opts in
/// (`FallbackMode::Passphrase`).
pub fn default_keystore(config: &KeystoreConfig) -> Result<Box<dyn KeyStore>, KeyStoreError> {
    match config.fallback {
        FallbackMode::Passphrase => Ok(Box::new(PassphraseKeyStore::from_prompt(&config.home)?)),
        FallbackMode::Auto | FallbackMode::None => {
            native_or_fallback(&config.home, config.fallback)
        }
    }
}

#[cfg(target_os = "macos")]
fn native_or_fallback(
    home: &std::path::Path,
    fallback: FallbackMode,
) -> Result<Box<dyn KeyStore>, KeyStoreError> {
    match MacKeyStore::new() {
        Ok(ks) => Ok(Box::new(ks)),
        Err(e) if fallback == FallbackMode::Auto && is_backend_unavailable(&e) => {
            log_fallback("apple", &e);
            Ok(Box::new(PassphraseKeyStore::from_prompt(home)?))
        }
        Err(e) => Err(e),
    }
}

#[cfg(target_os = "linux")]
fn native_or_fallback(
    home: &std::path::Path,
    fallback: FallbackMode,
) -> Result<Box<dyn KeyStore>, KeyStoreError> {
    match LinuxKeyStore::new() {
        Ok(ks) => Ok(Box::new(ks)),
        Err(e) if fallback == FallbackMode::Auto && is_backend_unavailable(&e) => {
            log_fallback("libsecret", &e);
            Ok(Box::new(PassphraseKeyStore::from_prompt(home)?))
        }
        Err(e) => Err(e),
    }
}

#[cfg(target_os = "windows")]
fn native_or_fallback(
    home: &std::path::Path,
    fallback: FallbackMode,
) -> Result<Box<dyn KeyStore>, KeyStoreError> {
    match WindowsKeyStore::new() {
        Ok(ks) => Ok(Box::new(ks)),
        Err(e) if fallback == FallbackMode::Auto && is_backend_unavailable(&e) => {
            log_fallback("windows", &e);
            Ok(Box::new(PassphraseKeyStore::from_prompt(home)?))
        }
        Err(e) => Err(e),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn native_or_fallback(
    home: &std::path::Path,
    fallback: FallbackMode,
) -> Result<Box<dyn KeyStore>, KeyStoreError> {
    if fallback == FallbackMode::None {
        return Err(KeyStoreError::PlatformError {
            backend: "none",
            message: "no native keychain on this platform and fallback is disabled".into(),
        });
    }
    Ok(Box::new(PassphraseKeyStore::from_prompt(home)?))
}

/// Only `BackendUnavailable` triggers auto-fallback. Genuine platform
/// failures (`PlatformError`) surface to the caller so a misconfigured
/// keychain doesn't silently drop users into passphrase mode.
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn is_backend_unavailable(e: &KeyStoreError) -> bool {
    matches!(e, KeyStoreError::BackendUnavailable { .. })
}

/// Log the native backend's error before falling back. This is the ONE
/// place the error chain is surfaced for debugging — without it, users
/// see an unexplained passphrase prompt.
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn log_fallback(backend: &'static str, e: &KeyStoreError) {
    eprintln!("keystore: native backend '{backend}' unavailable, falling back to passphrase: {e}");
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod factory_tests {
    use super::*;
    use tempfile::TempDir;

    /// Compile-time check that `KeyStore` is object-safe and that
    /// `PassphraseKeyStore` can be boxed through the trait.
    #[tokio::test]
    async fn passphrase_keystore_is_dyn_safe() {
        let home = TempDir::new().unwrap();
        let concrete =
            PassphraseKeyStore::from_passphrase(home.path(), "test-passphrase-correct-horse")
                .unwrap();
        let boxed: Box<dyn KeyStore> = Box::new(concrete);
        // Drive master_key through the trait object to prove async fn
        // dispatch works through dyn.
        let key = boxed.master_key().await.unwrap();
        assert_eq!(key.len(), MASTER_KEY_LEN);
        // set_master_key on passphrase adapter must be immutable.
        let err = boxed.set_master_key(&[0u8; MASTER_KEY_LEN]).await.unwrap_err();
        assert!(matches!(err, KeyStoreError::PassphraseAdapterImmutable));
    }

    #[test]
    fn fallback_mode_debug_and_eq() {
        let a = FallbackMode::Auto;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(FallbackMode::Auto, FallbackMode::None);
        let _ = format!("{a:?}");
    }

    #[test]
    fn master_key_service_and_account_are_stable() {
        // These constants are baked into on-disk state (OS keychain).
        // Changing them without a migration breaks existing installs.
        assert_eq!(MASTER_KEY_SERVICE, "io.permitlayer.master-key");
        assert_eq!(MASTER_KEY_ACCOUNT, "master");
    }
}
