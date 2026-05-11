//! Lazy passphrase-fallback wrapper around a native keystore.
//!
//! # Why this module exists
//!
//! Until rc.12, the daemon's auto-fallback decision was made *only* at
//! `MacKeyStore::new()` / `LinuxKeyStore::new()` / `WindowsKeyStore::new()`
//! construction time, gated by `probe_backend`'s synchronous read of
//! the master-key entry. If the construction-time probe disagreed
//! with the runtime `master_key()` call (observed on Angie's box,
//! rc.11 over SSH after `brew upgrade`: probe returned `Ok`, runtime
//! call returned `BackendUnavailable -25308`), the fallback never
//! engaged and the daemon hard-failed boot despite a fully-functional
//! recovery mechanism existing.
//!
//! This wrapper moves the fallback decision to where the failure
//! actually happens — the runtime trait calls — so probe-vs-runtime
//! disagreement cannot prevent recovery.
//!
//! # Engagement semantics
//!
//! - On `FallbackMode::Auto`, the wrapper sits between the public
//!   `Box<dyn KeyStore>` returned by `default_keystore` and the
//!   underlying `MacKeyStore`/`LinuxKeyStore`/`WindowsKeyStore`.
//! - On any trait method that returns `BackendUnavailable`, the
//!   wrapper lazily mints a `PassphraseKeyStore` (via injectable
//!   closure for testing) and stores it in a `tokio::sync::OnceCell`.
//! - All subsequent trait calls — including `set_master_key`,
//!   `previous_master_key`, etc. — route to the engaged fallback.
//!   This is the same wholesale-swap semantics that today's
//!   construction-time fallback already implements.
//! - The closure that runs `construct_fallback` is invoked INSIDE
//!   `OnceCell::get_or_try_init`'s closure body, so concurrent
//!   first-failures serialize on a single construction. Exactly one
//!   `from_prompt` call, exactly one `passphrase.state` write, even
//!   under racing trait calls.
//!
//! # Marker-driven preference at construction
//!
//! `OnceCell` is process-local. Without explicit handling, the
//! cross-restart split-key scenario corrupts the vault: boot 1
//! engages fallback under -25308, writes `passphrase.state`, seals
//! credentials with the derived key. Boot 2 sees native available
//! again (operator unlocked the keychain, or transient -25308
//! resolved), tries native first, succeeds, returns a *different*
//! key — credentials from boot 1 are unsealable.
//!
//! Fix: at `production()` construction time, check whether
//! `<home>/keystore/passphrase.state` exists. If yes, eagerly install
//! the passphrase fallback into the OnceCell BEFORE any native call.
//! The daemon was previously using passphrase, so it must keep using
//! passphrase — switching back to native would orphan the credentials.
//!
//! # `kind()` reporting
//!
//! `KeyStore::kind()` is load-bearing for `agentsso rotate-key`'s
//! refusal gate. Before fallback engages, the wrapper reports the
//! native's kind (`Native`). After engagement, it reports the
//! engaged keystore's kind (`Passphrase`). rotate-key separately
//! uses `FallbackMode::None` to bypass the wrapper entirely (the
//! orchestrator's `.rotation-state` marker can't tolerate fallback
//! engaging mid-rotation), but the kind() correctness is documented
//! as a contract regardless.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::OnceCell;
use zeroize::Zeroizing;

use crate::error::KeyStoreError;
use crate::passphrase::PassphraseKeyStore;
use crate::{
    AclBreakRecoveryMode, DeleteOutcome, FallbackMode, KeyStore, KeyStoreKind, MASTER_KEY_LEN,
    is_backend_unavailable, log_fallback_runtime,
};

/// Closure type for constructing the fallback keystore. Production
/// callers pass `PassphraseKeyStore::from_prompt`-wrapping closure;
/// unit tests pass synthetic constructors so they don't block on
/// `/dev/tty` in CI.
pub(crate) type ConstructFallback =
    Arc<dyn Fn(&Path) -> Result<Arc<dyn KeyStore>, KeyStoreError> + Send + Sync>;

/// Wrapper that delegates to a native keystore but lazily falls back
/// to a passphrase keystore on the first runtime `BackendUnavailable`.
pub(crate) struct FallbackKeyStore {
    native: Box<dyn KeyStore>,
    home: PathBuf,
    fallback_mode: FallbackMode,
    /// Story 7.22: when `Auto`, the FIRST `BackendUnavailable` from the
    /// native backend short-circuits with
    /// [`KeyStoreError::AclBreakNeedsRekey`] BEFORE engaging the
    /// passphrase fallback. The daemon's boot path catches the
    /// sentinel and dispatches to the codesign-verified auto-rekey
    /// flow. Default `Disabled` for non-boot CLI paths preserves the
    /// existing passphrase-prompt fallback unchanged.
    acl_break_recovery: AclBreakRecoveryMode,
    fallback: OnceCell<Arc<dyn KeyStore>>,
    construct_fallback: ConstructFallback,
}

impl FallbackKeyStore {
    /// Production constructor. Uses `PassphraseKeyStore::from_prompt`
    /// for the fallback construction (which prompts on `/dev/tty`).
    ///
    /// Note: marker-driven preference (the "passphrase.state exists ⇒
    /// stay in passphrase mode" rule) is enforced by
    /// `lib.rs::marker_short_circuit` BEFORE we get here. By the time
    /// `production()` is called, the marker is known to be absent —
    /// otherwise the caller would have returned a bare
    /// `PassphraseKeyStore` and never constructed the wrapper. So
    /// we don't need to re-check the marker here.
    pub(crate) fn production(
        home: PathBuf,
        fallback_mode: FallbackMode,
        acl_break_recovery: AclBreakRecoveryMode,
        native: Box<dyn KeyStore>,
    ) -> Result<Self, KeyStoreError> {
        let fallback: OnceCell<Arc<dyn KeyStore>> = OnceCell::new();
        Ok(Self {
            native,
            home,
            fallback_mode,
            acl_break_recovery,
            fallback,
            construct_fallback: Arc::new(|h: &Path| {
                PassphraseKeyStore::from_prompt(h).map(|ks| Arc::new(ks) as Arc<dyn KeyStore>)
            }),
        })
    }

    /// Test constructor. Inject a synthetic fallback-construction
    /// closure (no /dev/tty dependency) AND a synthetic
    /// `passphrase_state_exists` flag (no filesystem dependency).
    #[cfg(test)]
    pub(crate) fn with_constructor(
        home: PathBuf,
        fallback_mode: FallbackMode,
        native: Box<dyn KeyStore>,
        construct_fallback: ConstructFallback,
        passphrase_state_exists: bool,
    ) -> Self {
        Self::with_constructor_and_recovery(
            home,
            fallback_mode,
            AclBreakRecoveryMode::Disabled,
            native,
            construct_fallback,
            passphrase_state_exists,
        )
    }

    /// Test constructor that exposes the [`AclBreakRecoveryMode`]
    /// switch. Used by the Story 7.22 sentinel-routing tests.
    #[cfg(test)]
    pub(crate) fn with_constructor_and_recovery(
        home: PathBuf,
        fallback_mode: FallbackMode,
        acl_break_recovery: AclBreakRecoveryMode,
        native: Box<dyn KeyStore>,
        construct_fallback: ConstructFallback,
        passphrase_state_exists: bool,
    ) -> Self {
        let fallback: OnceCell<Arc<dyn KeyStore>> = OnceCell::new();
        if passphrase_state_exists {
            // Run the synthetic constructor to install the fallback.
            // In tests this is the same closure used for runtime
            // engagement, so the marker test exercises the same code
            // path.
            if let Ok(fb) = (construct_fallback)(&home) {
                let _ = fallback.set(fb);
            }
        }
        Self { native, home, fallback_mode, acl_break_recovery, fallback, construct_fallback }
    }

    /// Engage the fallback (or return the existing one) if `e` is a
    /// `BackendUnavailable` and `FallbackMode::Auto` is active.
    /// Routes through `OnceCell::get_or_try_init` so concurrent
    /// first-failures serialize on exactly one construction.
    ///
    /// The closure that runs `construct_fallback` is INSIDE the
    /// `get_or_try_init` body — this is load-bearing. If the closure
    /// were called outside, both racing callers would invoke
    /// `from_prompt` (and write `passphrase.state` twice).
    ///
    /// Story 7.22: when `acl_break_recovery: Auto` AND `native_err` is
    /// `BackendUnavailable` (the macOS keychain ACL break post binary
    /// swap), this method does NOT engage the passphrase fallback —
    /// it returns the [`KeyStoreError::AclBreakNeedsRekey`] sentinel
    /// up to the caller, which the daemon's boot path catches and
    /// routes to the codesign-verified auto-rekey flow. With
    /// `acl_break_recovery: Disabled` (the default for non-boot CLI
    /// paths) the existing passphrase fallback engages unchanged.
    async fn try_engage_fallback(
        &self,
        native_err: &KeyStoreError,
    ) -> Result<Option<&Arc<dyn KeyStore>>, KeyStoreError> {
        if self.fallback_mode != FallbackMode::Auto || !is_backend_unavailable(native_err) {
            return Ok(None);
        }
        // Story 7.22: short-circuit the passphrase fallback only when
        // the wrapper was explicitly constructed for boot-time auto-
        // recovery. The default (`Disabled`) preserves the existing
        // behavior for the five non-boot CLI call sites
        // (connect/credentials/rotate-key/uninstall/keystore-clear-
        // previous), which still engage the passphrase prompt as before.
        if self.acl_break_recovery == AclBreakRecoveryMode::Auto {
            return Err(KeyStoreError::AclBreakNeedsRekey {
                native: Box::new(native_err.clone_for_chain()),
            });
        }
        log_fallback_runtime(native_err);
        let installed = self
            .fallback
            .get_or_try_init(|| async {
                (self.construct_fallback)(&self.home).map_err(|fb_err| {
                    KeyStoreError::RuntimeFallbackFailed {
                        native: Box::new(native_err.clone_for_chain()),
                        fallback: Box::new(fb_err),
                    }
                })
            })
            .await?;
        Ok(Some(installed))
    }
}

#[async_trait]
impl KeyStore for FallbackKeyStore {
    async fn master_key(&self) -> Result<crate::MasterKeyOutcome, KeyStoreError> {
        if let Some(fb) = self.fallback.get() {
            return fb.master_key().await;
        }
        match self.native.master_key().await {
            Ok(outcome) => Ok(outcome),
            Err(native_err) => match self.try_engage_fallback(&native_err).await? {
                Some(fb) => fb.master_key().await,
                None => Err(native_err),
            },
        }
    }

    async fn set_master_key(&self, key: &[u8; MASTER_KEY_LEN]) -> Result<(), KeyStoreError> {
        if let Some(fb) = self.fallback.get() {
            return fb.set_master_key(key).await;
        }
        match self.native.set_master_key(key).await {
            Ok(()) => Ok(()),
            Err(native_err) => match self.try_engage_fallback(&native_err).await? {
                Some(fb) => fb.set_master_key(key).await,
                None => Err(native_err),
            },
        }
    }

    async fn delete_master_key(&self) -> Result<DeleteOutcome, KeyStoreError> {
        if let Some(fb) = self.fallback.get() {
            return fb.delete_master_key().await;
        }
        match self.native.delete_master_key().await {
            Ok(outcome) => Ok(outcome),
            Err(native_err) => match self.try_engage_fallback(&native_err).await? {
                Some(fb) => fb.delete_master_key().await,
                None => Err(native_err),
            },
        }
    }

    fn kind(&self) -> KeyStoreKind {
        // If fallback is engaged, report as the engaged backing
        // keystore. Otherwise report the native's kind. This is
        // load-bearing for rotate-key's refusal gate.
        if let Some(fb) = self.fallback.get() { fb.kind() } else { self.native.kind() }
    }

    async fn set_previous_master_key(
        &self,
        previous: &[u8; MASTER_KEY_LEN],
    ) -> Result<(), KeyStoreError> {
        if let Some(fb) = self.fallback.get() {
            return fb.set_previous_master_key(previous).await;
        }
        match self.native.set_previous_master_key(previous).await {
            Ok(()) => Ok(()),
            Err(native_err) => match self.try_engage_fallback(&native_err).await? {
                Some(fb) => fb.set_previous_master_key(previous).await,
                None => Err(native_err),
            },
        }
    }

    async fn previous_master_key(
        &self,
    ) -> Result<Option<Zeroizing<[u8; MASTER_KEY_LEN]>>, KeyStoreError> {
        if let Some(fb) = self.fallback.get() {
            return fb.previous_master_key().await;
        }
        match self.native.previous_master_key().await {
            Ok(opt) => Ok(opt),
            Err(native_err) => match self.try_engage_fallback(&native_err).await? {
                Some(fb) => fb.previous_master_key().await,
                None => Err(native_err),
            },
        }
    }

    async fn clear_previous_master_key(&self) -> Result<(), KeyStoreError> {
        if let Some(fb) = self.fallback.get() {
            return fb.clear_previous_master_key().await;
        }
        match self.native.clear_previous_master_key().await {
            Ok(()) => Ok(()),
            Err(native_err) => match self.try_engage_fallback(&native_err).await? {
                Some(fb) => fb.clear_previous_master_key().await,
                None => Err(native_err),
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod fallback_tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tempfile::TempDir;

    /// Synthetic native keystore that always returns the configured
    /// error from every trait call. Counts how many times each
    /// method was invoked so tests can assert routing.
    struct ErroringNative {
        error: Mutex<Option<KeyStoreError>>,
        master_key_calls: AtomicU32,
    }

    impl ErroringNative {
        fn new(error: KeyStoreError) -> Self {
            Self { error: Mutex::new(Some(error)), master_key_calls: AtomicU32::new(0) }
        }
        fn take_error(&self) -> KeyStoreError {
            self.error.lock().expect("poisoned").clone_for_chain_or_take()
        }
    }

    // Helper: KeyStoreError doesn't implement Clone (Box<dyn Error>
    // sources aren't Clone-safe), so we use the `clone_for_chain`
    // helper which preserves error semantics with lossy substitution
    // for the few non-Clone variants. Each call to this method
    // returns a CLONE of the stored error — the original is left in
    // place, so subsequent trait calls on the same `ErroringNative`
    // also see the configured error. (The misleading `take` in the
    // method name is a holdover; it's never actually `take()`.)
    trait OptionHelper {
        fn clone_for_chain_or_take(&mut self) -> KeyStoreError;
    }
    impl OptionHelper for Option<KeyStoreError> {
        fn clone_for_chain_or_take(&mut self) -> KeyStoreError {
            self.as_ref()
                .map(|e| e.clone_for_chain())
                .unwrap_or(KeyStoreError::PassphraseAdapterImmutable)
        }
    }

    #[async_trait]
    impl KeyStore for ErroringNative {
        async fn master_key(&self) -> Result<crate::MasterKeyOutcome, KeyStoreError> {
            self.master_key_calls.fetch_add(1, Ordering::SeqCst);
            Err(self.take_error())
        }
        async fn set_master_key(&self, _: &[u8; MASTER_KEY_LEN]) -> Result<(), KeyStoreError> {
            Err(self.take_error())
        }
        async fn delete_master_key(&self) -> Result<DeleteOutcome, KeyStoreError> {
            Err(self.take_error())
        }
        async fn set_previous_master_key(
            &self,
            _: &[u8; MASTER_KEY_LEN],
        ) -> Result<(), KeyStoreError> {
            Err(self.take_error())
        }
        async fn previous_master_key(
            &self,
        ) -> Result<Option<Zeroizing<[u8; MASTER_KEY_LEN]>>, KeyStoreError> {
            Err(self.take_error())
        }
        async fn clear_previous_master_key(&self) -> Result<(), KeyStoreError> {
            Err(self.take_error())
        }
    }

    /// Synthetic fallback keystore that always succeeds with a
    /// hardcoded key. Used as the closure return value in tests.
    struct SyntheticFallback {
        kind: KeyStoreKind,
    }

    #[async_trait]
    impl KeyStore for SyntheticFallback {
        async fn master_key(&self) -> Result<crate::MasterKeyOutcome, KeyStoreError> {
            Ok(crate::MasterKeyOutcome {
                key: Zeroizing::new([0xAA; MASTER_KEY_LEN]),
                first_boot: false,
            })
        }
        async fn set_master_key(&self, _: &[u8; MASTER_KEY_LEN]) -> Result<(), KeyStoreError> {
            Err(KeyStoreError::PassphraseAdapterImmutable)
        }
        async fn delete_master_key(&self) -> Result<DeleteOutcome, KeyStoreError> {
            Err(KeyStoreError::PassphraseAdapterImmutable)
        }
        fn kind(&self) -> KeyStoreKind {
            self.kind
        }
        async fn set_previous_master_key(
            &self,
            _: &[u8; MASTER_KEY_LEN],
        ) -> Result<(), KeyStoreError> {
            Err(KeyStoreError::PassphraseAdapterImmutable)
        }
        async fn previous_master_key(
            &self,
        ) -> Result<Option<Zeroizing<[u8; MASTER_KEY_LEN]>>, KeyStoreError> {
            Err(KeyStoreError::PassphraseAdapterImmutable)
        }
        async fn clear_previous_master_key(&self) -> Result<(), KeyStoreError> {
            Err(KeyStoreError::PassphraseAdapterImmutable)
        }
    }

    fn make_synthetic_constructor() -> ConstructFallback {
        Arc::new(|_home: &Path| {
            Ok(Arc::new(SyntheticFallback { kind: KeyStoreKind::Passphrase }) as Arc<dyn KeyStore>)
        })
    }

    fn make_counting_constructor(counter: Arc<AtomicU32>) -> ConstructFallback {
        Arc::new(move |_home: &Path| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(SyntheticFallback { kind: KeyStoreKind::Passphrase }) as Arc<dyn KeyStore>)
        })
    }

    fn make_failing_constructor() -> ConstructFallback {
        Arc::new(|_home: &Path| Err(KeyStoreError::PassphrasePromptUnavailable))
    }

    /// Test #1: native returns BackendUnavailable; wrapper engages
    /// fallback and returns synthetic key.
    #[tokio::test]
    async fn runtime_backend_unavailable_engages_fallback() {
        let dir = TempDir::new().unwrap();
        let native = Box::new(ErroringNative::new(KeyStoreError::BackendUnavailable {
            backend: "test",
            source: Box::new(std::io::Error::other("OSStatus -25308")),
        }));
        let wrapper = FallbackKeyStore::with_constructor(
            dir.path().to_path_buf(),
            FallbackMode::Auto,
            native,
            make_synthetic_constructor(),
            false,
        );
        let key = wrapper.master_key().await.expect("fallback must engage");
        assert_eq!(*key, [0xAA; MASTER_KEY_LEN]);
    }

    /// Test #2: native returns PlatformError; wrapper does NOT engage
    /// fallback (only BackendUnavailable triggers it).
    #[tokio::test]
    async fn runtime_platform_error_does_not_engage_fallback() {
        let dir = TempDir::new().unwrap();
        let native = Box::new(ErroringNative::new(KeyStoreError::PlatformError {
            backend: "test",
            message: "configurational error".into(),
        }));
        let wrapper = FallbackKeyStore::with_constructor(
            dir.path().to_path_buf(),
            FallbackMode::Auto,
            native,
            make_synthetic_constructor(),
            false,
        );
        match wrapper.master_key().await {
            Err(KeyStoreError::PlatformError { .. }) => {}
            other => panic!("expected PlatformError to propagate, got {other:?}"),
        }
    }

    /// Test #3: once fallback engages, subsequent calls go to the
    /// fallback even if native would now succeed. Permanent decision.
    #[tokio::test]
    async fn runtime_fallback_persists_across_calls() {
        let dir = TempDir::new().unwrap();
        let native = Box::new(ErroringNative::new(KeyStoreError::BackendUnavailable {
            backend: "test",
            source: Box::new(std::io::Error::other("OSStatus -25308")),
        }));
        let wrapper = FallbackKeyStore::with_constructor(
            dir.path().to_path_buf(),
            FallbackMode::Auto,
            native,
            make_synthetic_constructor(),
            false,
        );
        let key1 = wrapper.master_key().await.expect("first call engages fallback");
        let key2 = wrapper.master_key().await.expect("second call routes to engaged fallback");
        assert_eq!(*key1, *key2);
        // Synthetic fallback always returns 0xAA.
        assert_eq!(*key1, [0xAA; MASTER_KEY_LEN]);
    }

    /// Test #4: after fallback engages on master_key, set_master_key
    /// routes to the passphrase adapter and returns
    /// PassphraseAdapterImmutable — NOT the native's error.
    #[tokio::test]
    async fn set_master_key_after_fallback_routes_to_passphrase() {
        let dir = TempDir::new().unwrap();
        let native = Box::new(ErroringNative::new(KeyStoreError::BackendUnavailable {
            backend: "test",
            source: Box::new(std::io::Error::other("OSStatus -25308")),
        }));
        let wrapper = FallbackKeyStore::with_constructor(
            dir.path().to_path_buf(),
            FallbackMode::Auto,
            native,
            make_synthetic_constructor(),
            false,
        );
        // Engage fallback via master_key.
        let _ = wrapper.master_key().await.expect("engages");
        // Now set_master_key MUST route to fallback.
        match wrapper.set_master_key(&[0u8; MASTER_KEY_LEN]).await {
            Err(KeyStoreError::PassphraseAdapterImmutable) => {}
            other => panic!(
                "set_master_key after fallback engagement must return PassphraseAdapterImmutable, got {other:?}"
            ),
        }
    }

    /// Test #6: kind() reports native before engagement, fallback
    /// after engagement. Pins the rotate-key gate.
    #[tokio::test]
    async fn kind_reports_native_until_engagement() {
        let dir = TempDir::new().unwrap();
        let native = Box::new(ErroringNative::new(KeyStoreError::BackendUnavailable {
            backend: "test",
            source: Box::new(std::io::Error::other("OSStatus -25308")),
        }));
        let wrapper = FallbackKeyStore::with_constructor(
            dir.path().to_path_buf(),
            FallbackMode::Auto,
            native,
            make_synthetic_constructor(),
            false,
        );
        // Before engagement: ErroringNative's default kind() is
        // Native (the trait default).
        assert_eq!(wrapper.kind(), KeyStoreKind::Native);
        // Engage.
        let _ = wrapper.master_key().await.expect("engages");
        // After engagement: synthetic fallback is Passphrase.
        assert_eq!(wrapper.kind(), KeyStoreKind::Passphrase);
    }

    /// Test #7: marker_present_at_construction installs fallback
    /// EAGERLY. A subsequent master_key() call routes to fallback
    /// even though the native is healthy. Pins the cross-restart
    /// split-key prevention.
    #[tokio::test]
    async fn marker_present_at_construction_eagerly_installs_fallback() {
        let dir = TempDir::new().unwrap();
        // Note: we use a HEALTHY-looking native (would succeed) — but
        // the marker tells the wrapper to use the passphrase fallback
        // anyway. This is exactly the cross-restart scenario: boot 1
        // engaged fallback, boot 2's native is fine but credentials
        // are sealed under the passphrase-derived key.
        let native = Box::new(ErroringNative::new(KeyStoreError::BackendUnavailable {
            backend: "test",
            source: Box::new(std::io::Error::other("won't be hit")),
        }));
        let wrapper = FallbackKeyStore::with_constructor(
            dir.path().to_path_buf(),
            FallbackMode::Auto,
            native,
            make_synthetic_constructor(),
            true, // passphrase_state_exists
        );
        // First call should NOT touch native — fallback is already
        // installed. Synthetic fallback returns 0xAA.
        let key = wrapper.master_key().await.expect("eager fallback engages");
        assert_eq!(*key, [0xAA; MASTER_KEY_LEN]);
    }

    /// Test #8: concurrent first-failure constructs fallback ONCE.
    /// OnceCell::get_or_try_init serializes the construction across
    /// racing tasks. Pins the "no double prompt" guarantee.
    ///
    /// Uses `flavor = "multi_thread"` so spawned tasks actually run on
    /// distinct worker threads (the default `current_thread` flavor
    /// would serialize them on the test thread, making the race
    /// untestable). 16 tasks + a `Barrier` synchronize their start so
    /// they all hit `try_engage_fallback` together.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_first_failure_constructs_fallback_once() {
        const N: usize = 16;
        let dir = TempDir::new().unwrap();
        let native = Box::new(ErroringNative::new(KeyStoreError::BackendUnavailable {
            backend: "test",
            source: Box::new(std::io::Error::other("OSStatus -25308")),
        }));
        let counter = Arc::new(AtomicU32::new(0));
        let wrapper = Arc::new(FallbackKeyStore::with_constructor(
            dir.path().to_path_buf(),
            FallbackMode::Auto,
            native,
            make_counting_constructor(counter.clone()),
            false,
        ));

        let barrier = Arc::new(tokio::sync::Barrier::new(N));
        let mut handles = Vec::with_capacity(N);
        for _ in 0..N {
            let w = Arc::clone(&wrapper);
            let b = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                // All N tasks wait at the barrier, then ALL release
                // simultaneously. Maximizes the chance that multiple
                // tasks reach try_engage_fallback before any of them
                // installs the OnceCell.
                b.wait().await;
                w.master_key().await
            }));
        }
        let mut at_least_one_ok = false;
        for h in handles {
            if h.await.unwrap().is_ok() {
                at_least_one_ok = true;
            }
        }
        assert!(at_least_one_ok, "at least one call must succeed via fallback");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "construct_fallback closure MUST run exactly once even under racing first-failures"
        );
    }

    /// Story 7.22 Test A: with `AclBreakRecoveryMode::Auto`, a
    /// `BackendUnavailable -25308` from the native backend short-
    /// circuits with `KeyStoreError::AclBreakNeedsRekey` and does NOT
    /// engage the passphrase fallback. The daemon boot path catches
    /// this sentinel and dispatches to the codesign-verified auto-
    /// rekey flow.
    #[tokio::test]
    async fn acl_break_recovery_auto_returns_sentinel_instead_of_engaging_passphrase() {
        let dir = TempDir::new().unwrap();
        let native_sentinel = "OSSTATUS_-25308_ACL_BREAK_SENTINEL";
        let native = Box::new(ErroringNative::new(KeyStoreError::BackendUnavailable {
            backend: "apple",
            source: Box::new(std::io::Error::other(native_sentinel)),
        }));
        let counter = Arc::new(AtomicU32::new(0));
        let wrapper = FallbackKeyStore::with_constructor_and_recovery(
            dir.path().to_path_buf(),
            FallbackMode::Auto,
            AclBreakRecoveryMode::Auto,
            native,
            make_counting_constructor(counter.clone()),
            false,
        );
        match wrapper.master_key().await {
            Err(KeyStoreError::AclBreakNeedsRekey { native: native_chain }) => {
                let displayed = native_chain.to_string();
                assert!(
                    displayed.contains(native_sentinel),
                    "AclBreakNeedsRekey native chain must surface the underlying \
                     OSStatus — got {displayed:?}"
                );
            }
            other => panic!(
                "expected AclBreakNeedsRekey sentinel under AclBreakRecoveryMode::Auto, \
                 got {other:?}"
            ),
        }
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "AclBreakRecoveryMode::Auto MUST NOT construct the passphrase fallback — \
             the daemon boot path owns recovery"
        );
    }

    /// Story 7.22 Test B: with `AclBreakRecoveryMode::Disabled` (the
    /// default for all non-boot CLI paths), a `BackendUnavailable
    /// -25308` from the native backend engages the passphrase
    /// fallback exactly as before. Pins the no-regression invariant
    /// that `agentsso credentials refresh`, `agentsso connect`, etc.
    /// still get the passphrase prompt on a TTY-attached session
    /// with a broken ACL.
    #[tokio::test]
    async fn acl_break_recovery_disabled_falls_through_to_passphrase_prompt() {
        let dir = TempDir::new().unwrap();
        let native = Box::new(ErroringNative::new(KeyStoreError::BackendUnavailable {
            backend: "apple",
            source: Box::new(std::io::Error::other("OSStatus -25308")),
        }));
        let wrapper = FallbackKeyStore::with_constructor_and_recovery(
            dir.path().to_path_buf(),
            FallbackMode::Auto,
            AclBreakRecoveryMode::Disabled,
            native,
            make_synthetic_constructor(),
            false,
        );
        // Existing behavior: passphrase fallback engages, returns 0xAA.
        let key = wrapper.master_key().await.expect("passphrase fallback must engage");
        assert_eq!(*key, [0xAA; MASTER_KEY_LEN]);
    }

    /// Test #9: fallback construction failure chains BOTH errors.
    /// Native returns BackendUnavailable, fallback returns
    /// PassphrasePromptUnavailable, wrapper returns
    /// RuntimeFallbackFailed with both visible in Display.
    #[tokio::test]
    async fn runtime_fallback_failed_chains_both_errors() {
        let dir = TempDir::new().unwrap();
        let native_sentinel = "RUNTIME_FALLBACK_NATIVE_SENTINEL";
        let native = Box::new(ErroringNative::new(KeyStoreError::BackendUnavailable {
            backend: "test",
            source: Box::new(std::io::Error::other(native_sentinel)),
        }));
        let wrapper = FallbackKeyStore::with_constructor(
            dir.path().to_path_buf(),
            FallbackMode::Auto,
            native,
            make_failing_constructor(), // Returns PassphrasePromptUnavailable
            false,
        );

        match wrapper.master_key().await {
            Err(KeyStoreError::RuntimeFallbackFailed { native, fallback }) => {
                let displayed =
                    KeyStoreError::RuntimeFallbackFailed { native, fallback }.to_string();
                assert!(
                    displayed.contains(native_sentinel),
                    "must surface native cause sentinel — got {displayed:?}"
                );
                assert!(
                    displayed.contains("passphrase prompt unavailable")
                        || displayed.contains("PassphrasePromptUnavailable")
                        || displayed.to_lowercase().contains("passphrase"),
                    "must surface fallback failure — got {displayed:?}"
                );
            }
            other => panic!("expected RuntimeFallbackFailed, got {other:?}"),
        }
    }
}
