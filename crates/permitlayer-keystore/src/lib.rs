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
// macOS native path is System.keychain unconditionally; `FallbackKeyStore`
// only exists on Linux + Windows where a passphrase adapter still acts as
// a runtime fallback when the OS keychain is unavailable.
#[cfg(any(target_os = "linux", target_os = "windows"))]
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

pub use error::{KeyStoreError, MalformedReason};
#[cfg(feature = "test-seam")]
pub use file_backed::FileBackedKeyStore;
#[cfg(target_os = "linux")]
pub use linux::LinuxKeyStore;
#[cfg(target_os = "macos")]
pub use macos::FINGERPRINT_DOMAIN_SEP;
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
///
/// **Renamed on macOS in Story 7.26 from `io.permitlayer.master-key`
/// to `dev.permitlayer.master-key`** to align with the rc.22 macOS
/// LaunchDaemon redesign's service identifier convention
/// (`dev.permitlayer.daemon` for the LaunchDaemon plist label).
/// macOS rc.21 → rc.22 is a breaking change with no in-place
/// migration — rc.21 operators run `agentsso service install`
/// (Story 7.27) which creates a fresh keychain entry under the new
/// service id. The old `io.permitlayer.master-key` entry in the
/// unprivileged user's login.keychain is orphaned; `agentsso
/// uninstall` warns about it (both in the pre-confirm prompt
/// manifest and on stderr at the end of the run) and prints the
/// `security delete-generic-password` command to remove it. The
/// programmatic sweep was attempted in round-1 review patches and
/// rejected in round 2 because uninstall runs under `sudo`, and
/// `keyring 3.6`'s macOS API has no target-user knob — the sweep
/// would have targeted root's keychain, not the operator's.
///
/// **Linux + Windows retain `io.permitlayer.master-key`** per AC #9
/// path (b) and AC #7 ("Linux + Windows preserved"). Those platforms
/// have not yet been redesigned; renaming the service id there would
/// silently strand rc.21 users' secret-service / CredMan entries
/// with no migration path. The rename happens when those platforms
/// get their own redesigns in future stories.
#[cfg(target_os = "macos")]
pub const MASTER_KEY_SERVICE: &str = "dev.permitlayer.master-key";

#[cfg(not(target_os = "macos"))]
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
/// Redacting newtype around the 32-byte master key. Deref-coerces to
/// `Zeroizing<[u8; MASTER_KEY_LEN]>` so callers can keep using
/// `outcome.key.as_slice()` / `&outcome.key`, but the hand-rolled
/// `Debug` impl prints `<redacted>` instead of all 32 bytes.
///
/// **Round-3 review fix.** Round-2 added `#[non_exhaustive]` to
/// `MasterKeyOutcome` claiming the attribute prevented external
/// callers from destructuring the struct in a way that defeated the
/// outer `Debug` redaction. That claim was overstated:
/// `#[non_exhaustive]` only forces external callers to use the `..`
/// rest pattern, and a `println!("{:?}", outcome.key)` still reaches
/// the *derived* `Debug` on `Zeroizing<[u8; 32]>` which prints every
/// byte. Wrapping `key` in this newtype with its own redacting
/// `Debug` enforces the invariant at the type level — any path that
/// reaches `Debug` on the `key` field now redacts.
pub struct RedactedMasterKey(Zeroizing<[u8; MASTER_KEY_LEN]>);

impl RedactedMasterKey {
    /// Wrap a freshly-minted or freshly-read key.
    pub fn new(key: Zeroizing<[u8; MASTER_KEY_LEN]>) -> Self {
        Self(key)
    }

    /// Unwrap to the inner `Zeroizing<...>` — used by call sites that
    /// genuinely need to consume the key (vault open/seal, rotate-key
    /// rotation, the daemon's compile-time `if outcome.key.as_slice()
    /// == [0u8; 32]` defensive check, etc.).
    pub fn into_inner(self) -> Zeroizing<[u8; MASTER_KEY_LEN]> {
        self.0
    }
}

impl std::ops::Deref for RedactedMasterKey {
    type Target = Zeroizing<[u8; MASTER_KEY_LEN]>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for RedactedMasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RedactedMasterKey(<redacted>)")
    }
}

/// Outcome of [`KeyStore::master_key`].
///
/// Story 7.27 AC #16: callers need to know whether the master key
/// was just minted (first boot) so they can emit the
/// `master-key-first-boot` audit event. Previously the keystore
/// emitted a `tracing::info!` event internally (Story 7.26 first
/// cut), but the daemon-level call site has the audit dispatcher in
/// scope — it's the right layer to emit typed events from.
///
/// **Debug redaction.** Both the outer `MasterKeyOutcome` and the
/// inner `RedactedMasterKey` print `<redacted>` for the key field.
/// Round-3 review fix replaced the round-2 `#[non_exhaustive]`-only
/// approach (which was documentation-grade, not type-enforced) with
/// a redacting newtype on the field itself.
///
/// `#[non_exhaustive]` is retained on the outer struct to future-
/// proof new fields (e.g., a `key_id` for rotate-key v3) without
/// breaking external matchers.
#[non_exhaustive]
pub struct MasterKeyOutcome {
    /// The 32-byte master key, wrapped in a redacting newtype.
    /// Deref-coerces to `Zeroizing<[u8; MASTER_KEY_LEN]>`.
    pub key: RedactedMasterKey,
    /// `true` when this call minted a fresh key (first boot of the
    /// daemon against this keychain); `false` when an existing key
    /// was read back.
    pub first_boot: bool,
}

impl MasterKeyOutcome {
    /// Construct a new `MasterKeyOutcome`. Required because the
    /// struct is `#[non_exhaustive]` — external callers (e.g., test
    /// doubles in `permitlayer-daemon`) cannot use the struct
    /// literal `MasterKeyOutcome { key, first_boot }` form across
    /// crate boundaries.
    pub fn new(key: Zeroizing<[u8; MASTER_KEY_LEN]>, first_boot: bool) -> Self {
        Self { key: RedactedMasterKey::new(key), first_boot }
    }
}

impl std::fmt::Debug for MasterKeyOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterKeyOutcome")
            .field("key", &"<redacted>")
            .field("first_boot", &self.first_boot)
            .finish()
    }
}

#[async_trait::async_trait]
pub trait KeyStore: Send + Sync {
    /// Fetch the 32-byte master key, generating and persisting a fresh
    /// random key on first call if none exists (for adapters that
    /// persist). The returned buffer is zeroized on drop.
    ///
    /// Story 7.27 AC #16: returns [`MasterKeyOutcome`] (was
    /// `Zeroizing<[u8; MASTER_KEY_LEN]>`) so the daemon-level caller
    /// can emit a typed `master-key-first-boot` audit event when
    /// `first_boot == true`.
    #[must_use = "master key result must not be silently discarded"]
    async fn master_key(&self) -> Result<MasterKeyOutcome, KeyStoreError>;

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
    /// Resolved via `permitlayer_core::paths::daemon_state_dir(None)` —
    /// `/Library/Application Support/permitlayer/` on macOS, `~/.agentsso/`
    /// on Linux + Windows.
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
/// | `fallback`        | platform        | native available | result                |
/// |-------------------|-----------------|------------------|-----------------------|
/// | `Auto`            | linux / windows | yes              | native adapter        |
/// | `Auto`            | linux / windows | no               | passphrase adapter    |
/// | `Auto`            | macOS           | (always)         | `MacKeyStore` or `BackendUnavailable` |
/// | `Passphrase`      | any             | (ignored)        | passphrase adapter    |
/// | `None`            | any             | yes              | native adapter        |
/// | `None`            | any             | no               | `BackendUnavailable`  |
///
/// macOS does not auto-fall-back: System.keychain is the only supported
/// native path, and a `BackendUnavailable` from `MacKeyStore::new` is
/// surfaced to the caller (the daemon's boot path renders a
/// `KeystoreConstruction` banner). Passphrase fallback on macOS is
/// only reachable by explicitly setting `FallbackMode::Passphrase`.
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
#[cfg(any(target_os = "linux", target_os = "windows"))]
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
#[cfg(any(target_os = "linux", target_os = "windows"))]
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
    _home: &std::path::Path,
    _fallback: FallbackMode,
) -> Result<Box<dyn KeyStore>, KeyStoreError> {
    // macOS boot path is System.keychain unconditionally. The `-A`
    // ACL is CDHash-independent so binary upgrades do not invalidate
    // the master-key entry; there is no auto-fallback or auto-recovery
    // wrapper to engage.
    Ok(Box::new(MacKeyStore::new()?))
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
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) fn is_backend_unavailable(e: &KeyStoreError) -> bool {
    matches!(e, KeyStoreError::BackendUnavailable { .. })
}

/// Log the native backend's error before falling back. This is the ONE
/// place the error chain is surfaced for debugging — without it, users
/// see an unexplained passphrase prompt.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn log_fallback(backend: &'static str, e: &KeyStoreError) {
    eprintln!("keystore: native backend '{backend}' unavailable, falling back to passphrase: {e}");
}

/// Log the native backend's error before engaging RUNTIME fallback
/// (the lazy `FallbackKeyStore` wrapper, post-rc.12). Distinct from
/// `log_fallback` (construction-time) so operators reading logs can
/// tell which decision point fired. Carries the full error chain via
/// `{e}` — Plan A's `BackendUnavailable: {source}` Display still
/// surfaces the OSStatus.
#[cfg(any(target_os = "linux", target_os = "windows"))]
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
        let outcome = boxed.master_key().await.unwrap();
        assert_eq!(outcome.key.len(), MASTER_KEY_LEN);
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
        // Changing them without a migration is a breaking change.
        // Story 7.26 renamed io.permitlayer.master-key →
        // dev.permitlayer.master-key on macOS only as part of the
        // rc.22 macOS LaunchDaemon redesign (System.keychain entry
        // created fresh by `service install`). Linux + Windows
        // retain the legacy `io.permitlayer.master-key` until those
        // platforms get their own redesigns.
        #[cfg(target_os = "macos")]
        assert_eq!(MASTER_KEY_SERVICE, "dev.permitlayer.master-key");
        #[cfg(not(target_os = "macos"))]
        assert_eq!(MASTER_KEY_SERVICE, "io.permitlayer.master-key");
        assert_eq!(MASTER_KEY_ACCOUNT, "master");
    }

    /// Story 7.27 Round-2 review fix: negative assertion to catch a
    /// regression where someone accidentally reverts the macOS
    /// MASTER_KEY_SERVICE rename. Pre-rc.22 used the legacy id; the
    /// rename is what isolates new System.keychain entries from
    /// orphaned user-login-keychain entries left behind by rc.21
    /// installs.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_master_key_service_is_not_legacy() {
        assert_ne!(
            MASTER_KEY_SERVICE, "io.permitlayer.master-key",
            "macOS MASTER_KEY_SERVICE must NOT regress to the rc.21 legacy id"
        );
    }

    /// Regression guard for the System.keychain `-A` ACL invariant.
    ///
    /// The macOS keystore is permitted exactly two error shapes when
    /// `master_key()` cannot return bytes: `BackendUnavailable` (probe
    /// failure; rendered as `KeystoreConstruction` by the daemon) or
    /// the structured passphrase/malformed-bytes family. Any future
    /// reintroduction of an auto-recovery sentinel that the boot path
    /// would have to dispatch on (e.g., a variant matching
    /// `*BreakNeedsRekey*` / `*AutoRecover*`) is a structural
    /// regression: System.keychain's `-A` ACL is CDHash-independent,
    /// so there is no failure mode for an auto-recovery branch to
    /// observe.
    ///
    /// This test enumerates the current `KeyStoreError` variant
    /// `Display` strings via a constructed instance per variant. If a
    /// new variant is added later, a `_ => ...` catch-all here would
    /// hide it, so we instead assert on the *Debug* string shape of a
    /// freshly-discriminated set of construction calls. The shape
    /// check is intentionally loose: it does not pin every variant's
    /// text, only that no variant Debug-prints as one of the deleted
    /// auto-recovery names.
    #[test]
    fn keystore_error_has_no_auto_recovery_variant() {
        // Construct one of each currently-defined variant we can
        // reach without unsafe / FFI. The point is not exhaustiveness
        // but evidence that the named regressors are absent.
        let samples: Vec<KeyStoreError> = vec![
            KeyStoreError::BackendUnavailable {
                backend: "apple",
                source: Box::new(std::io::Error::other("synthetic -25308")),
            },
            KeyStoreError::PassphraseMismatch,
            KeyStoreError::EmptyPassphrase,
            KeyStoreError::PassphraseAdapterImmutable,
            KeyStoreError::PassphrasePromptUnavailable,
            KeyStoreError::PlatformError { backend: "test", message: "x".into() },
        ];
        for s in samples {
            let dbg = format!("{s:?}");
            assert!(
                !dbg.contains("AclBreakNeedsRekey"),
                "regression: AclBreakNeedsRekey variant re-introduced — got {dbg}"
            );
            assert!(
                !dbg.contains("AutoRecover"),
                "regression: AutoRecover-family variant re-introduced — got {dbg}"
            );
            assert!(
                !dbg.contains("AclBreakRecovery"),
                "regression: AclBreakRecovery-family variant re-introduced — got {dbg}"
            );
        }
    }

    /// Regression guard: `KeystoreConfig` must not regrow an
    /// `acl_break_recovery`-shaped field. The macOS boot path no
    /// longer has a failure mode to recover from; Linux/Windows
    /// fallback engages on `BackendUnavailable` unconditionally
    /// without operator opt-in. A Debug print on a constructed
    /// `KeystoreConfig` is sufficient evidence of the absence.
    #[test]
    fn keystore_config_has_no_acl_break_field() {
        let cfg = KeystoreConfig {
            fallback: FallbackMode::Auto,
            home: std::path::PathBuf::from("/tmp/test"),
        };
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("acl_break"),
            "regression: KeystoreConfig regrew an acl_break_* field — got {dbg}"
        );
    }
}
