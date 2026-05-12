//! File-backed test keystore — DEBUG-ONLY.
//!
//! Story 7.6b round-1 review re-triage (2026-04-28): `agentsso
//! rotate-key`'s integration tests need a `KeyStore` that
//!   1. survives subprocess crashes mid-rotation (so the crash-
//!      resume e2e can spawn → SIGKILL → re-spawn → assert), and
//!   2. doesn't touch the operator's real OS keychain on the test
//!      runner.
//!
//! This adapter persists the primary + previous slots to two files
//! under `<home>/keystore-test/` (mode `0o600`) and is selected at
//! rotate-key entry when the env var
//! `AGENTSSO_TEST_KEYSTORE_FILE_BACKED=1` is present.
//!
//! # Feature gating (round-2 review re-triage)
//!
//! Both this module AND the env-var check in
//! `cli/rotate_key/mod.rs::run` are gated behind the `test-seam`
//! Cargo feature (NOT `cfg(debug_assertions)`). This makes the
//! seam-vs-production boundary an explicit Cargo metadata fact:
//!   - `cargo build` / `cargo build --release` → seams compiled out
//!     (the `test-seam` feature is not on by default).
//!   - `cargo nextest run` / `cargo build --features test-seam` →
//!     seams compiled in (the daemon's integration tests opt in).
//!   - `cargo install` → seams compiled out (cargo install does not
//!     enable dev-dependencies or non-default features).
//!
//! Pre-round-2 the seams used `#[cfg(debug_assertions)]`, which is
//! a build-PROFILE flag. A casual `cargo build && ./target/debug/...`
//! shipped the seams enabled even though the user had not opted in.
//! The feature flag closes that footgun: the binary either has the
//! seams or it doesn't, and the binary's metadata records which.
//!
//! # Why a separate adapter, not a passphrase reuse
//!
//! `PassphraseKeyStore` rotates by changing the passphrase, not by
//! minting a new key — `agentsso rotate-key` REFUSES early on a
//! passphrase backend (AC #6). Reusing it would require relaxing
//! that refusal, which would weaken production safety. A separate
//! `Native`-kind file adapter that satisfies the same trait shape is
//! simpler and isolates the test surface.
//!
//! # Atomic writes
//!
//! Each slot is written via tempfile-rename so a process kill in the
//! middle of a write leaves either the previous content or the new
//! content, never a half-written file. The conformance tests in
//! `tests/conformance.rs` already cover this invariant for the
//! native backends; this adapter inherits it via the same shape.

#![cfg(feature = "test-seam")]

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::error::KeyStoreError;
use crate::{DeleteOutcome, KeyStore, KeyStoreKind, MASTER_KEY_LEN};

const BACKEND: &str = "file-backed-test";
const PRIMARY_FILENAME: &str = "primary.bin";
const PREVIOUS_FILENAME: &str = "previous.bin";

/// File-backed test keystore. NOT for production use.
pub struct FileBackedKeyStore {
    dir: PathBuf,
    /// Single-process serialization. The on-disk files survive
    /// across processes; this mutex is just defense against
    /// concurrent in-process writers in tests.
    write_lock: Mutex<()>,
}

impl FileBackedKeyStore {
    /// Construct rooted at `<home>/keystore-test/`. Creates the dir
    /// with mode 0o700 if missing. Idempotent across calls and
    /// across processes (matches the production-keystore
    /// "constructor is cheap, state lives on disk" pattern).
    pub fn new(home: &Path) -> Result<Self, KeyStoreError> {
        let dir = home.join("keystore-test");
        fs::create_dir_all(&dir).map_err(|e| KeyStoreError::PlatformError {
            backend: BACKEND,
            message: format!("create_dir_all({}): {e}", dir.display()),
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o700);
            let _ = fs::set_permissions(&dir, perms);
        }
        Ok(Self { dir, write_lock: Mutex::new(()) })
    }

    fn primary_path(&self) -> PathBuf {
        self.dir.join(PRIMARY_FILENAME)
    }

    fn previous_path(&self) -> PathBuf {
        self.dir.join(PREVIOUS_FILENAME)
    }
}

#[async_trait]
impl KeyStore for FileBackedKeyStore {
    async fn master_key(&self) -> Result<crate::MasterKeyOutcome, KeyStoreError> {
        let path = self.primary_path();
        match read_key_file(&path)? {
            Some(key) => Ok(crate::MasterKeyOutcome { key, first_boot: false }),
            None => {
                use rand::RngCore;
                let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
                rand::rngs::OsRng.fill_bytes(&mut *key);
                let _g = self.write_lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                write_key_file(&path, &key)?;
                Ok(crate::MasterKeyOutcome { key, first_boot: true })
            }
        }
    }

    async fn set_master_key(&self, key: &[u8; MASTER_KEY_LEN]) -> Result<(), KeyStoreError> {
        let _g = self.write_lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let key_copy = Zeroizing::new(*key);
        write_key_file(&self.primary_path(), &key_copy)?;
        // Read-back-verify to mirror native-backend discipline.
        match read_key_file(&self.primary_path())? {
            Some(rb) if subtle_eq(&rb, &key_copy) => Ok(()),
            _ => Err(KeyStoreError::PlatformError {
                backend: BACKEND,
                message: "set_master_key read-back did not match written value".into(),
            }),
        }
    }

    async fn delete_master_key(&self) -> Result<DeleteOutcome, KeyStoreError> {
        let _g = self.write_lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match fs::remove_file(self.primary_path()) {
            Ok(()) => Ok(DeleteOutcome::Removed),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(DeleteOutcome::AlreadyAbsent),
            Err(e) => Err(KeyStoreError::PlatformError {
                backend: BACKEND,
                message: format!("remove primary: {e}"),
            }),
        }
    }

    fn kind(&self) -> KeyStoreKind {
        // Identifies as Native so rotate-key's passphrase-refusal
        // gate doesn't fire — we want rotate-key to PROCEED against
        // this adapter under test.
        KeyStoreKind::Native
    }

    async fn set_previous_master_key(
        &self,
        previous: &[u8; MASTER_KEY_LEN],
    ) -> Result<(), KeyStoreError> {
        let _g = self.write_lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev_copy = Zeroizing::new(*previous);
        write_key_file(&self.previous_path(), &prev_copy)?;
        match read_key_file(&self.previous_path())? {
            Some(rb) if subtle_eq(&rb, &prev_copy) => Ok(()),
            _ => Err(KeyStoreError::PlatformError {
                backend: BACKEND,
                message: "previous-slot read-back did not match written value".into(),
            }),
        }
    }

    async fn previous_master_key(
        &self,
    ) -> Result<Option<Zeroizing<[u8; MASTER_KEY_LEN]>>, KeyStoreError> {
        read_key_file(&self.previous_path())
    }

    async fn clear_previous_master_key(&self) -> Result<(), KeyStoreError> {
        let _g = self.write_lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match fs::remove_file(self.previous_path()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(KeyStoreError::PlatformError {
                backend: BACKEND,
                message: format!("remove previous: {e}"),
            }),
        }
    }
}

fn read_key_file(path: &Path) -> Result<Option<Zeroizing<[u8; MASTER_KEY_LEN]>>, KeyStoreError> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(KeyStoreError::PlatformError {
                backend: BACKEND,
                message: format!("read {}: {e}", path.display()),
            });
        }
    };
    if bytes.len() != MASTER_KEY_LEN {
        return Err(KeyStoreError::MalformedMasterKey {
            expected_len: MASTER_KEY_LEN,
            actual_len: bytes.len(),
        });
    }
    let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    key.copy_from_slice(&bytes);
    Ok(Some(key))
}

fn write_key_file(path: &Path, key: &[u8; MASTER_KEY_LEN]) -> Result<(), KeyStoreError> {
    let parent = path.parent().ok_or_else(|| KeyStoreError::PlatformError {
        backend: BACKEND,
        message: "key path has no parent".into(),
    })?;
    let pid = std::process::id();
    let tmp = parent.join(format!(
        ".{}.tmp.{pid}.{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("key"),
        rand_suffix()
    ));
    {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f: File = opts.open(&tmp).map_err(|e| KeyStoreError::PlatformError {
            backend: BACKEND,
            message: format!("open tempfile {}: {e}", tmp.display()),
        })?;
        f.write_all(key).map_err(|e| KeyStoreError::PlatformError {
            backend: BACKEND,
            message: format!("write tempfile: {e}"),
        })?;
        f.sync_all().map_err(|e| KeyStoreError::PlatformError {
            backend: BACKEND,
            message: format!("sync tempfile: {e}"),
        })?;
    }
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        KeyStoreError::PlatformError {
            backend: BACKEND,
            message: format!("rename {} → {}: {e}", tmp.display(), path.display()),
        }
    })?;
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn rand_suffix() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    format!("{:016x}", u64::from_le_bytes(buf))
}

fn subtle_eq(a: &[u8; MASTER_KEY_LEN], b: &[u8; MASTER_KEY_LEN]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Story 7.27 Round-2 review fix: prior to this test, no
    /// automated coverage exercised the `MasterKeyOutcome.first_boot`
    /// round-trip. The destructive macOS test is `#[ignore]` so CI
    /// never runs it; this `FileBackedKeyStore` test gives us
    /// fast-path coverage of the "first call mints, sets first_boot=
    /// true; subsequent call reads, sets first_boot=false" contract.
    #[tokio::test]
    async fn master_key_first_boot_then_existing_round_trip() {
        let dir = TempDir::new().expect("tempdir");
        let store = FileBackedKeyStore::new(dir.path()).expect("create store");

        let first = store.master_key().await.expect("first master_key call");
        assert!(first.first_boot, "first master_key call must report first_boot=true");
        assert_eq!(first.key.len(), MASTER_KEY_LEN);

        let second = store.master_key().await.expect("second master_key call");
        assert!(!second.first_boot, "second master_key call must report first_boot=false");
        assert!(subtle_eq(&first.key, &second.key), "key bytes must persist across calls");
    }

    #[tokio::test]
    async fn master_key_idempotent_on_existing_file() {
        // Pre-existing key file (operator-restored from backup, or
        // an upgrade-from-older-format scenario). First call should
        // report `first_boot=false` because the file is already there.
        let dir = TempDir::new().expect("tempdir");
        let store = FileBackedKeyStore::new(dir.path()).expect("create store");
        let preset = [0x42u8; MASTER_KEY_LEN];
        write_key_file(&store.primary_path(), &Zeroizing::new(preset)).expect("preset write");

        let outcome = store.master_key().await.expect("master_key call");
        assert!(!outcome.first_boot, "existing-file master_key must report first_boot=false");
        assert!(subtle_eq(&outcome.key, &Zeroizing::new(preset)));
    }
}
