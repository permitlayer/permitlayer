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

// Story 7.11 review-round-2 Q3: workspace-wide test-seam discipline.
// The `test-seam` feature exposes `FileBackedKeyStore` and
// `PassphraseKeyStore::from_passphrase` for integration tests; it
// must NOT be enabled in release builds. See
// `permitlayer-core::lib.rs` for the full rationale.
#[cfg(all(feature = "test-seam", not(debug_assertions)))]
compile_error!(
    "the `test-seam` feature must NOT be enabled in release builds. \
     If you need to run integration tests against this crate, build \
     with `cargo test --features test-seam` (debug profile) instead."
);

pub mod error;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
pub(crate) mod fallback;
#[cfg(feature = "test-seam")]
pub mod file_backed;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
pub(crate) mod keyring_shared;
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
#[cfg(feature = "test-seam")]
pub use file_backed::FileBackedKeyStore;
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

/// Account identifier for the *previous* master-key slot, used by
/// `agentsso rotate-key` (Story 7.6b). The previous slot is non-empty
/// only while a rotation is in flight (between Phase C' "atomic
/// dual-slot install" and Phase F "clear previous slot"). Outside of
/// in-flight rotation, `previous_master_key()` returns `Ok(None)` and
/// the OS keychain entry at this account does not exist.
pub const MASTER_KEY_PREVIOUS_ACCOUNT: &str = "master-previous";

/// Outcome of a [`KeyStore::delete_master_key`] call.
///
/// Distinguishes "we removed an entry that was there" from "there was
/// nothing to remove". Both are success — `agentsso uninstall`
/// (Story 7.4) treats them identically — but operators benefit from
/// the distinction in audit/log output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeleteOutcome {
    /// An existing master-key entry was removed from the OS keychain.
    Removed,
    /// No entry existed for ([`MASTER_KEY_SERVICE`], [`MASTER_KEY_ACCOUNT`])
    /// — the call was a no-op and idempotent.
    AlreadyAbsent,
}

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

    /// Remove the persisted master-key entry from the OS keychain.
    /// Used by `agentsso uninstall` (Story 7.4). Returns
    /// `Ok(DeleteOutcome::Removed)` if an entry was deleted,
    /// `Ok(DeleteOutcome::AlreadyAbsent)` if no entry existed (idempotent),
    /// or `Err(KeyStoreError::PassphraseAdapterImmutable)` for the
    /// passphrase adapter (no persisted entry to remove — caller should
    /// just unlink the on-disk verifier file directly).
    #[must_use = "delete_master_key result must not be silently discarded"]
    async fn delete_master_key(&self) -> Result<DeleteOutcome, KeyStoreError>;

    /// Identify which adapter family backs this keystore.
    ///
    /// Used by `agentsso rotate-key` (Story 7.6) to refuse cleanly on
    /// passphrase-mode hosts (which rotate by changing the passphrase,
    /// not by minting a new key). The default impl returns
    /// [`KeyStoreKind::Native`] — passphrase adapters override.
    fn kind(&self) -> KeyStoreKind {
        KeyStoreKind::Native
    }

    /// Write the "previous" master key slot.
    ///
    /// Story 7.6b round-1 review (Decision 1+2 resolution): the
    /// rotation no longer asks the keystore to be transactional
    /// across two slots — it can't, on any of our backends. Instead,
    /// the keystore exposes single-slot primitives, and the rotation
    /// orchestrates the dual-slot install with marker-staged crash
    /// recovery (`cli::rotate_key::marker`). Each call here writes
    /// exactly one slot; the rotation reads back via
    /// [`Self::previous_master_key`] to verify and advances its
    /// marker only when the read-back matches.
    ///
    /// Idempotent: writing the same bytes that are already on disk
    /// MUST succeed. Used by `cli::rotate_key`'s Phase C' resume path
    /// when `keystore_phase == PrePrevious` re-enters this call after
    /// a crash.
    ///
    /// Returns [`KeyStoreError::PassphraseAdapterImmutable`] for the
    /// passphrase adapter (which has no concept of a previous slot —
    /// passphrase rotation goes through a different code path).
    #[must_use = "set_previous_master_key result must not be silently discarded"]
    async fn set_previous_master_key(
        &self,
        previous: &[u8; MASTER_KEY_LEN],
    ) -> Result<(), KeyStoreError>;

    /// Read the "previous" master key slot. Returns `Ok(None)` when
    /// no rotation is in flight (post-Phase-F clear, or fresh
    /// install). Story 7.6b AC #17.
    ///
    /// Returns [`KeyStoreError::PassphraseAdapterImmutable`] for the
    /// passphrase adapter (which has no concept of a previous slot —
    /// passphrase rotation goes through a different code path).
    #[must_use = "previous_master_key result must not be silently discarded"]
    async fn previous_master_key(
        &self,
    ) -> Result<Option<Zeroizing<[u8; MASTER_KEY_LEN]>>, KeyStoreError>;

    /// Clear the "previous" master key slot. Idempotent — calling on
    /// a single-slot keystore returns `Ok(())`. Called by
    /// `agentsso rotate-key`'s Phase F to finalize rotation. Story
    /// 7.6b AC #17.
    ///
    /// Returns [`KeyStoreError::PassphraseAdapterImmutable`] for the
    /// passphrase adapter.
    #[must_use = "clear_previous_master_key result must not be silently discarded"]
    async fn clear_previous_master_key(&self) -> Result<(), KeyStoreError>;
}

/// Adapter family — used by callers that need to branch on
/// "is this an OS-keychain-backed keystore vs a passphrase-derived one?"
/// (Story 7.6 rotate-key refusal). Native covers
/// macOS Keychain Services / Linux libsecret / Windows DPAPI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyStoreKind {
    /// OS-keychain-backed adapter: macOS Keychain Services, Linux
    /// libsecret, or Windows DPAPI / Credential Manager. Master key
    /// is replaceable via [`KeyStore::set_master_key`].
    Native,
    /// Passphrase-derived adapter: master key is `Argon2id(passphrase,
    /// salt)`. There is no key to "rotate" — only a passphrase to
    /// change. [`KeyStore::set_master_key`] returns
    /// [`KeyStoreError::PassphraseAdapterImmutable`] for this adapter.
    Passphrase,
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

/// Wrap a successfully-constructed native keystore in the runtime
/// `FallbackKeyStore` if `FallbackMode::Auto` is active. Otherwise
/// return the native bare. The wrapper makes runtime
/// `BackendUnavailable` from `master_key()` etc. engage lazy fallback
/// — without it, the daemon hard-fails on probe-vs-runtime
/// disagreement (rc.10/rc.11 onboarding hit this twice).
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn maybe_wrap_native(
    home: &std::path::Path,
    fallback: FallbackMode,
    native: Box<dyn KeyStore>,
) -> Result<Box<dyn KeyStore>, KeyStoreError> {
    match fallback {
        FallbackMode::Auto => Ok(Box::new(fallback::FallbackKeyStore::production(
            home.to_path_buf(),
            fallback,
            native,
        )?)),
        FallbackMode::None | FallbackMode::Passphrase => Ok(native),
    }
}

/// Marker-driven preference: if `<home>/keystore/passphrase.state`
/// exists, a previous boot engaged passphrase fallback. We MUST keep
/// using passphrase regardless of whether native is now available —
/// switching back to native would mint a different key and orphan
/// every credential sealed under the passphrase-derived key. This
/// check fires BEFORE constructing the native adapter, so a hung or
/// surprising native probe cannot bypass marker preference.
///
/// Returns `Some(boxed_passphrase_keystore)` when the marker exists
/// and we should short-circuit native entirely. Returns `None` when
/// the marker is absent and the caller should proceed with the
/// normal native-or-fallback flow.
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn marker_short_circuit(
    home: &std::path::Path,
    fallback: FallbackMode,
) -> Result<Option<Box<dyn KeyStore>>, KeyStoreError> {
    if fallback != FallbackMode::Auto {
        return Ok(None);
    }
    if !home.join("keystore").join("passphrase.state").exists() {
        return Ok(None);
    }
    let fb = PassphraseKeyStore::from_prompt(home)?;
    Ok(Some(Box::new(fb)))
}

#[cfg(target_os = "macos")]
fn native_or_fallback(
    home: &std::path::Path,
    fallback: FallbackMode,
) -> Result<Box<dyn KeyStore>, KeyStoreError> {
    if let Some(passphrase) = marker_short_circuit(home, fallback)? {
        return Ok(passphrase);
    }
    match MacKeyStore::new() {
        Ok(ks) => maybe_wrap_native(home, fallback, Box::new(ks)),
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
    if let Some(passphrase) = marker_short_circuit(home, fallback)? {
        return Ok(passphrase);
    }
    match LinuxKeyStore::new() {
        Ok(ks) => maybe_wrap_native(home, fallback, Box::new(ks)),
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
    if let Some(passphrase) = marker_short_circuit(home, fallback)? {
        return Ok(passphrase);
    }
    match WindowsKeyStore::new() {
        Ok(ks) => maybe_wrap_native(home, fallback, Box::new(ks)),
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
pub(crate) fn is_backend_unavailable(e: &KeyStoreError) -> bool {
    matches!(e, KeyStoreError::BackendUnavailable { .. })
}

/// Log the native backend's error before falling back. This is the ONE
/// place the error chain is surfaced for debugging — without it, users
/// see an unexplained passphrase prompt.
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn log_fallback(backend: &'static str, e: &KeyStoreError) {
    eprintln!("keystore: native backend '{backend}' unavailable, falling back to passphrase: {e}");
}

/// Log the native backend's error before engaging RUNTIME fallback
/// (the lazy `FallbackKeyStore` wrapper, post-rc.12). Distinct from
/// `log_fallback` (construction-time) so operators reading logs can
/// tell which decision point fired. Carries the full error chain via
/// `{e}` — Plan A's `BackendUnavailable: {source}` Display still
/// surfaces the OSStatus.
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
pub(crate) fn log_fallback_runtime(e: &KeyStoreError) {
    eprintln!("keystore: native backend unavailable at runtime, engaging passphrase fallback: {e}");
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
        // delete_master_key on passphrase adapter must also be
        // immutable — the key is re-derived from a passphrase, never
        // persisted, so there is nothing to delete.
        let del_err = boxed.delete_master_key().await.unwrap_err();
        assert!(matches!(del_err, KeyStoreError::PassphraseAdapterImmutable));
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
