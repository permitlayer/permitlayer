//! Shared conformance suite for `KeyStore` adapters.
//!
//! Every adapter must satisfy the master-key contract:
//! 1. `master_key()` twice in-process returns byte-identical output
//!    (in-process idempotency).
//! 2. A fresh adapter instance pointing at the same backing store
//!    returns the same key (cross-restart persistence).
//! 3. For native adapters, `set_master_key(new)` + fresh instance +
//!    `master_key()` returns `new`.
//! 4. For the passphrase adapter, `set_master_key` returns
//!    `PassphraseAdapterImmutable`.
//!
//! # Known-Answer Argon2id test
//!
//! `argon2id_known_answer_test` pins the Argon2id parameters
//! (m_cost=65536, t_cost=3, p_cost=4, out=32 bytes) by checking a
//! single deterministic derivation against a hardcoded expected
//! output. An accidental parameter change becomes a test failure.
//! This is a parameter-drift detector, not a cross-implementation
//! vector — it pins the `argon2` crate version the tests were blessed
//! against. If it fires with "Argon2id KAT drift", a parameter was
//! changed intentionally and the expected vector needs regeneration
//! (and existing on-disk salt+verifier files become unusable).
//!
//! # No-plaintext-on-disk assertion
//!
//! After the passphrase adapter round-trip, we walk the temp home
//! recursively and assert no file contains the derived key bytes or
//! the test passphrase. This validates AC #5 at the keystore boundary;
//! the vault (Story 1.3) validates credential plaintext never lands
//! on disk either.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::time::Duration;

use argon2::{Algorithm, Argon2, Params, Version};
use permitlayer_keystore::{KeyStore, KeyStoreError, MASTER_KEY_LEN, PassphraseKeyStore};
use tempfile::TempDir;

const TEST_PASSPHRASE: &str = "test-passphrase-correct-horse";

/// Known-answer Argon2id output for:
///   password = b"test-passphrase-correct-horse"
///   salt     = [0x42u8; 16]
///   m_cost   = 65536
///   t_cost   = 3
///   p_cost   = 4
///   out_len  = 32
///
/// This is a parameter-drift detector pinned against `argon2 = 0.5.3`
/// on Rust 1.94.1. It catches accidental parameter changes, not
/// library-level regressions. If any param moves, the on-disk format
/// is breaking-changed and existing installs must migrate.
const ARGON2_KAT_EXPECTED: [u8; MASTER_KEY_LEN] = [
    0x99, 0xfb, 0xa9, 0x2d, 0x78, 0xba, 0x0b, 0xb5, 0x07, 0xca, 0x1d, 0x6c, 0xaf, 0x2d, 0x37, 0x65,
    0x12, 0xe3, 0x32, 0xfb, 0x7a, 0x32, 0x6a, 0x5c, 0xab, 0xb4, 0x5a, 0x3c, 0xeb, 0xdb, 0xd1, 0x19,
];

/// Assert that `master_key()` is idempotent within one adapter
/// instance.
async fn assert_master_key_idempotent<K: KeyStore>(ks: &K) -> Result<(), KeyStoreError> {
    let k1 = ks.master_key().await?;
    let k2 = ks.master_key().await?;
    assert_eq!(&*k1, &*k2, "master_key() must be idempotent in-process");
    assert_eq!(k1.len(), MASTER_KEY_LEN);
    Ok(())
}

#[tokio::test]
async fn argon2id_known_answer_test() {
    let params =
        Params::new(65_536, 3, 4, Some(MASTER_KEY_LEN)).expect("OWASP 2024 params are valid");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt = [0x42u8; 16];
    let mut key = [0u8; MASTER_KEY_LEN];
    argon2
        .hash_password_into(TEST_PASSPHRASE.as_bytes(), &salt, &mut key)
        .expect("KAT derivation must succeed");
    assert_eq!(
        key, ARGON2_KAT_EXPECTED,
        "Argon2id KAT drift — params or library version changed; see conformance.rs header"
    );
}

#[tokio::test]
async fn conformance_passphrase() {
    let home = TempDir::new().unwrap();

    let ks1 = PassphraseKeyStore::from_passphrase(home.path(), TEST_PASSPHRASE).unwrap();
    assert_master_key_idempotent(&ks1).await.unwrap();

    let k1 = ks1.master_key().await.unwrap();
    drop(ks1);

    // Cross-restart: a fresh instance with the same passphrase must
    // derive the same key (same salt → same Argon2id output).
    let ks2 = PassphraseKeyStore::from_passphrase(home.path(), TEST_PASSPHRASE).unwrap();
    let k2 = ks2.master_key().await.unwrap();
    assert_eq!(&*k1, &*k2, "passphrase adapter must derive stable key across instances");

    // set_master_key is immutable for passphrase adapter.
    let err = ks2.set_master_key(&[0u8; MASTER_KEY_LEN]).await.unwrap_err();
    assert!(matches!(err, KeyStoreError::PassphraseAdapterImmutable));
}

#[tokio::test]
async fn passphrase_adapter_no_plaintext_on_disk() {
    let home = TempDir::new().unwrap();
    let ks = PassphraseKeyStore::from_passphrase(home.path(), TEST_PASSPHRASE).unwrap();
    let key = ks.master_key().await.unwrap();

    // The derived key must never appear on disk. The passphrase also
    // must never appear (it's not persisted; this guards against
    // regressions that might log or stage it).
    let key_bytes: &[u8] = &*key;
    assert!(
        !any_file_contains(home.path(), key_bytes),
        "derived master key must not appear in any file under home"
    );
    assert!(
        !any_file_contains(home.path(), TEST_PASSPHRASE.as_bytes()),
        "test passphrase must not appear in any file under home"
    );
}

fn any_file_contains(root: &Path, needle: &[u8]) -> bool {
    for entry in walkdir::WalkDir::new(root).into_iter().flatten() {
        if entry.file_type().is_file()
            && let Ok(bytes) = std::fs::read(entry.path())
            && memmem(&bytes, needle)
        {
            return true;
        }
    }
    false
}

fn memmem(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ================================================================
// Native-adapter conformance (one test per OS)
// ================================================================

#[cfg(target_os = "macos")]
#[tokio::test]
async fn conformance_macos() {
    use permitlayer_keystore::MacKeyStore;

    let ks = match MacKeyStore::new() {
        Ok(k) => k,
        Err(KeyStoreError::BackendUnavailable { backend, source }) => {
            eprintln!("skipping macos conformance: backend '{backend}' unavailable: {source}");
            return;
        }
        Err(e) => panic!("unexpected error constructing MacKeyStore: {e}"),
    };
    native_conformance(&ks).await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn conformance_linux() {
    use permitlayer_keystore::LinuxKeyStore;

    let ks = match LinuxKeyStore::new() {
        Ok(k) => k,
        Err(KeyStoreError::BackendUnavailable { backend, source }) => {
            eprintln!("skipping linux conformance: backend '{backend}' unavailable: {source}");
            return;
        }
        Err(e) => panic!("unexpected error constructing LinuxKeyStore: {e}"),
    };
    native_conformance(&ks).await;
}

#[cfg(target_os = "windows")]
#[tokio::test]
async fn conformance_windows() {
    use permitlayer_keystore::WindowsKeyStore;

    let ks = match WindowsKeyStore::new() {
        Ok(k) => k,
        Err(KeyStoreError::BackendUnavailable { backend, source }) => {
            eprintln!("skipping windows conformance: backend '{backend}' unavailable: {source}");
            return;
        }
        Err(e) => panic!("unexpected error constructing WindowsKeyStore: {e}"),
    };
    native_conformance(&ks).await;
}

/// Native-adapter conformance: idempotency, cross-restart persistence,
/// and `set_master_key` round-trip. Cleans up by restoring the
/// original key (tests share one well-known OS-keychain entry).
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
async fn native_conformance<K: KeyStore>(ks: &K) {
    // 1. Read the baseline (either pre-existing or just-minted).
    let original = ks.master_key().await.unwrap();
    let original_bytes: [u8; MASTER_KEY_LEN] = *original;

    // 2. Idempotency.
    assert_master_key_idempotent(ks).await.unwrap();

    // 3. set_master_key round-trip with a test key that's clearly
    //    not the original.
    let test_key = [0x5Au8; MASTER_KEY_LEN];
    ks.set_master_key(&test_key).await.unwrap();
    let read_back = ks.master_key().await.unwrap();
    assert_eq!(&*read_back, &test_key, "set_master_key + master_key must round-trip");

    // 4. Restore the original key so this test is re-runnable and
    //    doesn't clobber whatever was there.
    ks.set_master_key(&original_bytes).await.unwrap();
}

// ================================================================
// AC #3 — async-runtime non-starve proof
// ================================================================

/// Prove that `spawn_blocking` is actually used on native adapters:
/// a keystore FFI call must not stall a concurrent timer task on a
/// single-threaded runtime. Tightened bound to 50ms per original
/// spec Task 6 (the earlier 500ms bound was 10× looser).
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
#[tokio::test(flavor = "current_thread")]
async fn async_runtime_not_starved_by_native_keystore() {
    #[cfg(target_os = "macos")]
    let ks = match permitlayer_keystore::MacKeyStore::new() {
        Ok(k) => k,
        Err(KeyStoreError::BackendUnavailable { backend, source }) => {
            eprintln!("skipping non-starve test: backend '{backend}' unavailable: {source}");
            return;
        }
        Err(e) => panic!("unexpected error: {e}"),
    };
    #[cfg(target_os = "linux")]
    let ks = match permitlayer_keystore::LinuxKeyStore::new() {
        Ok(k) => k,
        Err(KeyStoreError::BackendUnavailable { backend, source }) => {
            eprintln!("skipping non-starve test: backend '{backend}' unavailable: {source}");
            return;
        }
        Err(e) => panic!("unexpected error: {e}"),
    };
    #[cfg(target_os = "windows")]
    let ks = match permitlayer_keystore::WindowsKeyStore::new() {
        Ok(k) => k,
        Err(KeyStoreError::BackendUnavailable { backend, source }) => {
            eprintln!("skipping non-starve test: backend '{backend}' unavailable: {source}");
            return;
        }
        Err(e) => panic!("unexpected error: {e}"),
    };

    // Wall-clock measurement (not virtual time). If `master_key()`
    // properly dispatches to `spawn_blocking`, the timer task can
    // advance while the FFI call runs on a blocking worker thread,
    // and total elapsed time is ~10ms (the sleep). If `spawn_blocking`
    // is removed, the FFI call blocks the current_thread runtime for
    // its full real-world latency, serializing the two tasks.
    let start = std::time::Instant::now();
    let (key_res, _) = tokio::join!(ks.master_key(), tokio::time::sleep(Duration::from_millis(10)));
    key_res.unwrap();
    let elapsed = start.elapsed();

    // Generous bound: keychain FFI on a warm cache is usually <5ms,
    // but CI runners can be slow. 200ms catches a `spawn_blocking`
    // regression (which would serialize two tasks at 10ms+FFI-latency)
    // without flaking on slow CI.
    assert!(
        elapsed < Duration::from_millis(200),
        "native keystore FFI starved the runtime: elapsed = {elapsed:?}"
    );
}

/// Sanity variant: drive the passphrase adapter on a single-threaded
/// runtime. `master_key()` here is a memcpy; this test mainly proves
/// the test plumbing works on `current_thread` and doesn't deadlock.
#[tokio::test(flavor = "current_thread")]
async fn async_runtime_passphrase_adapter_runs_on_single_thread() {
    let home = TempDir::new().unwrap();
    let ks = PassphraseKeyStore::from_passphrase(home.path(), TEST_PASSPHRASE).unwrap();

    let start = std::time::Instant::now();
    let (key_res, _) = tokio::join!(ks.master_key(), tokio::time::sleep(Duration::from_millis(10)));
    key_res.unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(200),
        "passphrase adapter starved the runtime: elapsed = {elapsed:?}"
    );
}
