//! Kill-9 recovery integration test.
//!
//! Exercises 10 simulated-crash points during `CredentialFsStore::put`
//! (5 syscall boundaries × 2 store states: empty vs. populated) and
//! asserts that after every crash the store is in one of three valid
//! states: absent file, previous valid envelope, or new valid envelope.
//! Partial/corrupted files are never observed.
//!
//! # Why fault injection (not `std::process::abort`)
//!
//! `std::process::abort()` kills the whole test process — the harness
//! has no chance to assert anything. Instead, the store exposes a
//! feature-gated `CredentialFsIo` trait (under `#[cfg(feature =
//! "test-seam")]`) whose methods map 1:1 to the 5 real syscalls inside
//! the atomic-write sequence. The test substitutes a `FaultyFsIo`
//! implementation that returns `io::Error` at a configurable point.
//!
//! # Fixture strategy
//!
//! The test builds `SealedCredential` values via
//! `SealedCredential::from_trusted_bytes` with pre-computed fixture
//! bytes. The fixture does NOT need to be AEAD-valid — the test only
//! exercises envelope serialization + atomic-swap behavior. This lets
//! the test live in `permitlayer-core/tests/` without adding
//! `permitlayer-vault` as a dev-dep of core (which `cargo deny` would
//! reject per the `wrappers` rule for vault).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{self, Write as _};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use permitlayer_core::store::CredentialStore;
use permitlayer_core::store::fs::credential_fs::{CredentialFsIo, CredentialFsStore};
use permitlayer_credential::{SEALED_CREDENTIAL_VERSION, SealedCredential};
use tempfile::TempDir;
use walkdir::WalkDir;

/// Sentinel bytes that MUST NEVER appear in any on-disk artifact. The
/// `test_` prefix matches the Story 1.1 convention so accidental
/// leakage is grep-detectable.
const SENTINEL: &[u8] = b"test_plaintext_oauth_token_bytes_v1_sentinel";

/// Fake ciphertext bytes for fixture A. Opaque bytes — they don't need
/// to round-trip through any vault. The ciphertext intentionally does
/// NOT contain `SENTINEL` — the fixture builder uses a distinct byte
/// pattern for the ciphertext (0xAA).
fn fixture_a() -> SealedCredential {
    let aad = [b"permitlayer-vault-v1:", b"gmail" as &[u8]].concat();
    let ciphertext = vec![0xAAu8; 48];
    let nonce = [0x11u8; 12];
    SealedCredential::from_trusted_bytes(ciphertext, nonce, aad, SEALED_CREDENTIAL_VERSION)
}

fn fixture_b() -> SealedCredential {
    let aad = [b"permitlayer-vault-v1:", b"gmail" as &[u8]].concat();
    let ciphertext = vec![0xBBu8; 48];
    let nonce = [0x22u8; 12];
    SealedCredential::from_trusted_bytes(ciphertext, nonce, aad, SEALED_CREDENTIAL_VERSION)
}

#[allow(clippy::enum_variant_names)] // "Before" prefix is load-bearing: each variant names a real pre-syscall checkpoint
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CrashPoint {
    BeforeCreateTempfile,
    BeforeWriteAll,
    BeforeSyncAll,
    BeforeRename,
    BeforeSyncParentDir,
}

impl CrashPoint {
    fn all() -> [CrashPoint; 5] {
        [
            CrashPoint::BeforeCreateTempfile,
            CrashPoint::BeforeWriteAll,
            CrashPoint::BeforeSyncAll,
            CrashPoint::BeforeRename,
            CrashPoint::BeforeSyncParentDir,
        ]
    }
}

/// Injects `io::Error` at the configured crash point. Uses an atomic
/// counter so only the FIRST call past the crash point fails — if the
/// crash point is past end of run, the injector is a no-op and the
/// full write completes normally.
struct FaultyFsIo {
    crash_at: CrashPoint,
    /// Set to true by the injector once it has fired; downstream calls
    /// in the same `put()` are unreachable because the closure has
    /// already returned an error, but the flag keeps us from firing
    /// twice across different `put()` calls on the same injector.
    fired: AtomicUsize,
}

impl FaultyFsIo {
    fn new(crash_at: CrashPoint) -> Self {
        Self { crash_at, fired: AtomicUsize::new(0) }
    }

    fn maybe_fail(&self, point: CrashPoint) -> io::Result<()> {
        if point == self.crash_at && self.fired.fetch_add(1, Ordering::Relaxed) == 0 {
            return Err(io::Error::other("injected crash"));
        }
        Ok(())
    }
}

impl CredentialFsIo for FaultyFsIo {
    fn create_tempfile(&self, tmp: &Path) -> io::Result<std::fs::File> {
        self.maybe_fail(CrashPoint::BeforeCreateTempfile)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(tmp)
        }
        #[cfg(not(unix))]
        {
            std::fs::OpenOptions::new().write(true).create_new(true).open(tmp)
        }
    }
    fn write_all(&self, file: &mut std::fs::File, bytes: &[u8]) -> io::Result<()> {
        self.maybe_fail(CrashPoint::BeforeWriteAll)?;
        file.write_all(bytes)
    }
    fn sync_all(&self, file: &std::fs::File) -> io::Result<()> {
        self.maybe_fail(CrashPoint::BeforeSyncAll)?;
        file.sync_all()
    }
    fn rename(&self, tmp: &Path, target: &Path) -> io::Result<()> {
        self.maybe_fail(CrashPoint::BeforeRename)?;
        std::fs::rename(tmp, target)
    }
    fn sync_parent_dir(&self, parent: &Path) -> io::Result<()> {
        self.maybe_fail(CrashPoint::BeforeSyncParentDir)?;
        let dir = std::fs::File::open(parent)?;
        dir.sync_all()
    }
}

/// After every simulated crash, walk `home` and assert no file
/// contains the test sentinel bytes as a bare substring.
///
/// **Self-check, not a vault-level plaintext-leak test.** The fixtures
/// here use opaque filler bytes (0xAA/0xBB) for ciphertext — the
/// sentinel is never sealed by a real vault. This assertion's job is to
/// prove that the *test harness itself* doesn't accidentally write the
/// sentinel as plaintext via a bug in the fixture builder or an
/// unexpected code path. The true vault-level "no plaintext on disk"
/// proof lives in the vault's `sealed_bytes_do_not_contain_plaintext`
/// unit test and Story 1.3 AC #8.
///
/// walkdir traversal errors are propagated (not swallowed via
/// `.expect()`) so they surface as test failures rather than masking
/// the sentinel check.
fn assert_no_sentinel_on_disk(home: &Path) {
    for entry in WalkDir::new(home) {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => panic!("walkdir traversal error: {e}"),
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let bytes = match std::fs::read(entry.path()) {
            Ok(b) => b,
            Err(e) => panic!("failed to read {}: {e}", entry.path().display()),
        };
        if contains_subsequence(&bytes, SENTINEL) {
            panic!("sentinel appeared in {}", entry.path().display());
        }
    }
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Reconstruct a real (non-faulty) store at `home` and call `get`.
/// Used after every simulated crash to verify recovery state.
async fn verify_get_returns_one_of(
    home: &Path,
    service: &str,
    valid_options: &[Option<&SealedCredential>],
) {
    let store = CredentialFsStore::new(home.to_path_buf()).expect("post-crash store must re-open");
    let got = store.get(service).await.expect("get must not error on crash-recovery");
    match &got {
        None => {
            assert!(
                valid_options.iter().any(|o| o.is_none()),
                "got None but test did not expect None"
            );
        }
        Some(sealed) => {
            let mut matched = false;
            for expected in valid_options.iter().flatten() {
                if sealed.ciphertext() == expected.ciphertext()
                    && sealed.nonce() == expected.nonce()
                    && sealed.aad() == expected.aad()
                    && sealed.version() == expected.version()
                {
                    matched = true;
                    break;
                }
            }
            assert!(matched, "got Some(sealed) that does not match any expected fixture");
        }
    }
}

#[tokio::test]
async fn first_write_crash_leaves_empty_or_complete() {
    for crash_point in CrashPoint::all() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().to_path_buf();
        let io = Arc::new(FaultyFsIo::new(crash_point));
        let store =
            CredentialFsStore::new_with_io(home.clone(), io).expect("construct with faulty io");

        let a = fixture_a();
        let expected_if_rename_succeeded = fixture_a();
        let result = store.put("gmail", a).await;

        // At points 1–4 (before rename), result MUST be Err (pre-rename
        // crash points all propagate the injected error). At point 5
        // (after rename, before parent-dir fsync), the rename already
        // happened — result is Err but the file is durable-enough.
        match crash_point {
            CrashPoint::BeforeCreateTempfile
            | CrashPoint::BeforeWriteAll
            | CrashPoint::BeforeSyncAll
            | CrashPoint::BeforeRename => {
                assert!(result.is_err(), "{crash_point:?} should fail put()");
                // File must not exist.
                verify_get_returns_one_of(&home, "gmail", &[None]).await;
            }
            CrashPoint::BeforeSyncParentDir => {
                assert!(result.is_err(), "BeforeSyncParentDir should fail put()");
                // Rename already succeeded — file exists with new contents.
                verify_get_returns_one_of(&home, "gmail", &[Some(&expected_if_rename_succeeded)])
                    .await;
            }
        }

        // No orphaned tempfiles (the RAII guard cleans up pre-rename crashes).
        let vault_dir = home.join("vault");
        let leftover: Vec<_> = std::fs::read_dir(&vault_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp."))
            .collect();
        assert!(leftover.is_empty(), "{crash_point:?} left orphaned tempfiles: {leftover:?}");

        assert_no_sentinel_on_disk(&home);
    }
}

#[tokio::test]
async fn overwrite_crash_preserves_prior_or_commits_new() {
    for crash_point in CrashPoint::all() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().to_path_buf();

        // First: write fixture A successfully (real I/O, no fault).
        let store_clean = CredentialFsStore::new(home.clone()).expect("clean store construct");
        store_clean.put("gmail", fixture_a()).await.expect("first put must succeed");
        drop(store_clean);

        // Second: write fixture B, crashing at `crash_point`.
        let io = Arc::new(FaultyFsIo::new(crash_point));
        let store_faulty =
            CredentialFsStore::new_with_io(home.clone(), io).expect("faulty store construct");
        let result = store_faulty.put("gmail", fixture_b()).await;

        let prior = fixture_a();
        let new_one = fixture_b();
        match crash_point {
            CrashPoint::BeforeCreateTempfile
            | CrashPoint::BeforeWriteAll
            | CrashPoint::BeforeSyncAll
            | CrashPoint::BeforeRename => {
                assert!(result.is_err(), "{crash_point:?} should fail put()");
                // Pre-rename crash: prior fixture A must still be intact.
                verify_get_returns_one_of(&home, "gmail", &[Some(&prior)]).await;
            }
            CrashPoint::BeforeSyncParentDir => {
                assert!(result.is_err(), "BeforeSyncParentDir should fail put()");
                // Rename already swapped A → B; store returns B.
                verify_get_returns_one_of(&home, "gmail", &[Some(&new_one)]).await;
            }
        }

        let vault_dir = home.join("vault");
        let leftover: Vec<_> = std::fs::read_dir(&vault_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp."))
            .collect();
        assert!(leftover.is_empty(), "{crash_point:?} left orphaned tempfiles: {leftover:?}");

        assert_no_sentinel_on_disk(&home);
    }
}
