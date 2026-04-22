//! Passphrase-derived keystore adapter (Argon2id KDF + HMAC verifier).
//!
//! Used as the cross-platform fallback when a native OS keychain is
//! unavailable (headless Linux servers, CI matrix gaps, user
//! preference). The master key is never persisted — only a 16-byte
//! salt and a 32-byte HMAC verifier live on disk. On every daemon
//! start, the user is prompted for a passphrase, Argon2id re-derives
//! the key, and the derived key is checked against the verifier.
//!
//! # Scope
//!
//! - In scope: deriving a 32-byte master key from a passphrase, and
//!   verifying the derived key via a one-way HMAC tag.
//! - Out of scope: storing credentials, AEAD primitives (both live in
//!   the vault, Story 1.3).
//!
//! # On-disk state
//!
//! One combined file `~/.agentsso/keystore/passphrase.state` holds:
//! - 2 bytes: format version (big-endian u16)
//! - 16 bytes: salt
//! - 32 bytes: `HMAC-SHA256(derived_key, "permitlayer-verifier-v1")`
//!
//! Salt and verifier live in a single file so they cannot drift on a
//! crash mid-first-run. The file is written via `persist_noclobber`
//! (Unix `link(2)`, Windows `MoveFileEx` without the overwrite flag)
//! so concurrent first-run writers don't clobber each other. On
//! subsequent starts, we recompute the HMAC with the fresh derived
//! key and constant-time-compare. Because HMAC is one-way, an
//! attacker with file read access cannot recover the derived key
//! from the verifier — they must still brute-force the passphrase
//! against Argon2id.
//!
//! # Argon2id parameters (OWASP 2024, hardcoded)
//!
//! These are NOT configurable. Bumping any of them is a breaking
//! change requiring a migration (existing salt + verifier become
//! unusable).
//!
//! | Param          | Value          | Rationale                      |
//! |----------------|----------------|--------------------------------|
//! | `m_cost`       | 65,536 KiB     | OWASP minimum for interactive  |
//! | `t_cost`       | 3 iterations   | OWASP interactive preset       |
//! | `p_cost`       | 4 lanes        | OWASP recommendation           |
//! | output length  | 32 bytes       | AES-256 key size               |
//! | salt size      | 16 random bytes| NIST SP 800-132 minimum        |
//!
//! Argon2id derivation runs on the current async task (not
//! `spawn_blocking`) because it happens exactly once at daemon startup
//! in the constructor, not per-request. If derivation ever moves into
//! a hot path, it must move to `spawn_blocking`.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::KeyStoreError;
use crate::{KeyStore, MASTER_KEY_LEN};

/// OWASP 2024 interactive profile. Changing any of these values is a
/// breaking on-disk format change.
const ARGON2_M_COST: u32 = 65_536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;
const SALT_LEN: usize = 16;
const VERIFIER_LEN: usize = 32;

/// On-disk state layout: 2-byte version || 16-byte salt || 32-byte
/// HMAC verifier = 50 bytes total. Written as a single atomic file so
/// salt and verifier cannot drift out of sync on a crash.
const STATE_VERSION: u16 = 1;
const STATE_LEN: usize = 2 + SALT_LEN + VERIFIER_LEN;

/// HMAC domain-separation tag. Versioned so a future scheme change can
/// be detected and migrated.
const VERIFIER_DOMAIN: &[u8] = b"permitlayer-verifier-v1";

type HmacSha256 = Hmac<Sha256>;

/// Passphrase-derived keystore adapter.
///
/// Holds a zeroizing 32-byte derived key in memory plus the keystore
/// directory path. The derived key is zeroized on drop.
pub struct PassphraseKeyStore {
    /// Kept for test introspection and future key-rotation paths
    /// (Story 7.6) that may need to write the derived key back to
    /// disk if the passphrase scheme ever persists the key.
    #[allow(dead_code)]
    keystore_dir: PathBuf,
    derived_key: Zeroizing<[u8; MASTER_KEY_LEN]>,
}

impl PassphraseKeyStore {
    /// Construct by prompting the user for a passphrase via
    /// non-echoing stdin.
    ///
    /// On first run (salt absent): generate 16 bytes from `OsRng`,
    /// write atomically with mode 0600 on Unix, derive the key, write
    /// the HMAC verifier.
    ///
    /// On subsequent runs (salt present): read the salt, derive the
    /// key, HMAC-verify against the stored tag; `PassphraseMismatch`
    /// on mismatch (fail-closed per AC #4).
    pub fn from_prompt(home: &Path) -> Result<Self, KeyStoreError> {
        // Wrap the prompted passphrase in `Zeroizing<String>` so the
        // bytes are wiped when the scope ends, not left on the heap
        // until some future allocator reuse. `rpassword` returns a
        // plain `String` which does NOT zeroize on drop, so the
        // original string would otherwise linger after derivation.
        let passphrase: Zeroizing<String> =
            Zeroizing::new(rpassword::prompt_password("permitlayer passphrase: ")?);
        Self::from_passphrase_inner(home, passphrase.as_str())
    }

    /// Construct from an explicit passphrase string. Only available
    /// in tests or with the `test-seam` feature — production callers
    /// must use `from_prompt`.
    #[cfg(any(test, feature = "test-seam"))]
    pub fn from_passphrase(home: &Path, passphrase: &str) -> Result<Self, KeyStoreError> {
        Self::from_passphrase_inner(home, passphrase)
    }

    /// Internal constructor shared by `from_prompt` and `from_passphrase`.
    fn from_passphrase_inner(home: &Path, passphrase: &str) -> Result<Self, KeyStoreError> {
        if passphrase.is_empty() {
            return Err(KeyStoreError::EmptyPassphrase);
        }

        let keystore_dir = home.join("keystore");
        create_dir_secure(&keystore_dir)?;

        let state_path = keystore_dir.join("passphrase.state");

        // Salt + verifier live in one file — they MUST NOT drift. On
        // first run we generate salt, derive the key, compute the
        // verifier, and write all three bytes together atomically.
        // On subsequent runs we read them back together.
        let derived_key = if state_path.exists() {
            let (salt, stored_verifier) = read_state(&state_path)?;
            let derived_key = derive_key(passphrase, &salt)?;
            let computed_verifier = compute_verifier(&derived_key);
            if !constant_time_eq(&stored_verifier, &computed_verifier) {
                return Err(KeyStoreError::PassphraseMismatch);
            }
            derived_key
        } else {
            let mut salt = [0u8; SALT_LEN];
            OsRng.fill_bytes(&mut salt);
            let derived_key = derive_key(passphrase, &salt)?;
            let verifier = compute_verifier(&derived_key);
            match write_state(&state_path, &salt, &verifier) {
                Ok(()) => derived_key,
                Err(KeyStoreError::IoError(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // A concurrent first-run process beat us to it.
                    // Read their state and verify our passphrase
                    // against their salt+verifier. If it matches, we
                    // raced two writers with the same passphrase;
                    // both succeed. If it doesn't match, the peer
                    // used a different passphrase — treat as mismatch.
                    let (their_salt, their_verifier) = read_state(&state_path)?;
                    let their_derived = derive_key(passphrase, &their_salt)?;
                    let their_check = compute_verifier(&their_derived);
                    if !constant_time_eq(&their_verifier, &their_check) {
                        return Err(KeyStoreError::PassphraseMismatch);
                    }
                    their_derived
                }
                Err(e) => return Err(e),
            }
        };

        Ok(Self { keystore_dir, derived_key })
    }

    /// Test hook: report the keystore directory for perm-check tests.
    #[cfg(test)]
    fn keystore_dir(&self) -> &Path {
        &self.keystore_dir
    }
}

#[async_trait::async_trait]
impl KeyStore for PassphraseKeyStore {
    async fn master_key(&self) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, KeyStoreError> {
        // Copy the already-derived key into a fresh Zeroizing buffer
        // so callers get an owned, drop-zeroized copy. Argon2id
        // derivation has already happened in the constructor.
        Ok(Zeroizing::new(*self.derived_key))
    }

    async fn set_master_key(&self, _key: &[u8; MASTER_KEY_LEN]) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::PassphraseAdapterImmutable)
    }
}

fn derive_key(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, KeyStoreError> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(MASTER_KEY_LEN))
        .map_err(KeyStoreError::Argon2ParamsFailed)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    argon2.hash_password_into(passphrase.as_bytes(), salt, &mut *key)?;
    Ok(key)
}

/// Write the combined state file (version || salt || verifier)
/// atomically, refusing to clobber an existing target.
fn write_state(
    path: &Path,
    salt: &[u8; SALT_LEN],
    verifier: &[u8; VERIFIER_LEN],
) -> Result<(), KeyStoreError> {
    let mut buf = [0u8; STATE_LEN];
    buf[0..2].copy_from_slice(&STATE_VERSION.to_be_bytes());
    buf[2..2 + SALT_LEN].copy_from_slice(salt);
    buf[2 + SALT_LEN..STATE_LEN].copy_from_slice(verifier);
    atomic_write_new(path, &buf)
}

/// Read the combined state file, validating version + length.
fn read_state(path: &Path) -> Result<([u8; SALT_LEN], [u8; VERIFIER_LEN]), KeyStoreError> {
    let bytes = fs::read(path)?;
    if bytes.len() != STATE_LEN {
        return Err(KeyStoreError::PlatformError {
            backend: "passphrase",
            message: format!(
                "state file has wrong length: expected {STATE_LEN}, got {}",
                bytes.len()
            ),
        });
    }
    let version = u16::from_be_bytes([bytes[0], bytes[1]]);
    if version != STATE_VERSION {
        return Err(KeyStoreError::PlatformError {
            backend: "passphrase",
            message: format!("unsupported state version: expected {STATE_VERSION}, got {version}"),
        });
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[2..2 + SALT_LEN]);
    let mut verifier = [0u8; VERIFIER_LEN];
    verifier.copy_from_slice(&bytes[2 + SALT_LEN..STATE_LEN]);
    Ok((salt, verifier))
}

/// `HMAC-SHA256(derived_key, VERIFIER_DOMAIN)`. One-way: an attacker
/// with file access cannot recover the derived key from the tag.
fn compute_verifier(derived_key: &[u8; MASTER_KEY_LEN]) -> [u8; VERIFIER_LEN] {
    // HMAC-SHA256 accepts any key length. `new_from_slice` only
    // returns `Err` on impossible key lengths (e.g., `> u32::MAX`
    // bytes), which cannot occur for a fixed 32-byte input. Writing a
    // placeholder verifier on failure would be catastrophic — the
    // file would never match any passphrase AND would clobber any
    // prior legitimate verifier. Panic is the correct response to an
    // impossible precondition.
    #[allow(clippy::expect_used)] // static invariant documented above
    let mut mac = HmacSha256::new_from_slice(derived_key)
        .expect("HMAC-SHA256 accepts any key length; 32 bytes is trivially valid");
    mac.update(VERIFIER_DOMAIN);
    let out = mac.finalize().into_bytes();
    // hmac::digest::Output<Sha256> is GenericArray<u8, U32>; copy into
    // a fixed-size array for the stable on-disk layout.
    let mut tag = [0u8; VERIFIER_LEN];
    tag.copy_from_slice(&out);
    tag
}

/// Create `dir` with mode `0o700` on Unix. Uses `DirBuilder::mode`
/// when first creating so the perms are set atomically — no window
/// during which the directory exists with umask-default perms.
fn create_dir_secure(dir: &Path) -> Result<(), KeyStoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        if !dir.exists() {
            std::fs::DirBuilder::new().mode(0o700).recursive(true).create(dir)?;
        } else {
            // Tighten perms on an existing dir (e.g., upgrade path).
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(dir)?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(dir, perms)?;
        }
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)?;
        // On Windows the keystore directory inherits user-only ACLs
        // from %USERPROFILE%\.agentsso\. Explicit ACL tightening is
        // deferred (Story 1.4 daemon setup).
    }
    Ok(())
}

/// Atomic tempfile+rename write that refuses to clobber an existing
/// target (used for the combined state file, which is write-once).
/// Returns an `AlreadyExists` io error if the target is already
/// present; callers that race should fall back to reading.
///
/// Uses `persist_noclobber` (Unix `link(2)`, Windows `MoveFileEx`
/// without overwrite flag) so two concurrent first-run writers
/// cannot silently overwrite each other.
fn atomic_write_new(target: &Path, bytes: &[u8]) -> Result<(), KeyStoreError> {
    let parent = target.parent().ok_or_else(|| {
        KeyStoreError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "target path has no parent directory",
        ))
    })?;
    fs::create_dir_all(parent)?;

    let mut builder = tempfile::Builder::new();
    builder.prefix(".tmp-").suffix(".part");
    let mut tmp = builder.tempfile_in(parent)?;
    tmp.as_file_mut().write_all(bytes)?;
    tmp.as_file_mut().sync_all()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = tmp.as_file().metadata()?.permissions();
        perms.set_mode(0o600);
        tmp.as_file().set_permissions(perms)?;
    }

    // `persist_noclobber` is race-safe: it maps to `link(2)` on Unix
    // (atomic refuse-if-exists) and `MoveFileEx` without overwrite on
    // Windows. A pre-check + clobbering `persist` would TOCTOU — two
    // racers could both see `!exists()` and silently overwrite each
    // other's state.
    tmp.persist_noclobber(target).map_err(|e| {
        let err = e.error;
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            KeyStoreError::IoError(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "target already exists",
            ))
        } else {
            KeyStoreError::IoError(std::io::Error::other(format!("atomic rename failed: {err}")))
        }
    })?;

    // Fsync the parent directory so the rename is durable. Without
    // this, a crash between `persist` and the OS's next dir-flush
    // could lose the rename even though the tempfile data is on disk.
    if let Ok(parent_dir) = fs::File::open(parent) {
        let _ = parent_dir.sync_all();
    }

    Ok(())
}

/// Constant-time byte-slice equality via the `subtle` crate.
/// Prevents timing side-channel on the verifier check.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const TEST_PASSPHRASE: &str = "test-passphrase-correct-horse";

    #[test]
    fn empty_passphrase_rejected() {
        let home = TempDir::new().unwrap();
        let err =
            PassphraseKeyStore::from_passphrase(home.path(), "").err().expect("must reject empty");
        assert!(matches!(err, KeyStoreError::EmptyPassphrase));
    }

    #[test]
    fn state_file_persisted_across_calls() {
        let home = TempDir::new().unwrap();
        let _first = PassphraseKeyStore::from_passphrase(home.path(), TEST_PASSPHRASE).unwrap();
        let state_path = home.path().join("keystore").join("passphrase.state");
        let state_bytes_first = fs::read(&state_path).unwrap();
        assert_eq!(state_bytes_first.len(), STATE_LEN);

        let _second = PassphraseKeyStore::from_passphrase(home.path(), TEST_PASSPHRASE).unwrap();
        let state_bytes_second = fs::read(&state_path).unwrap();
        assert_eq!(state_bytes_first, state_bytes_second);
    }

    #[test]
    fn mismatched_passphrase_rejected() {
        let home = TempDir::new().unwrap();
        let _first = PassphraseKeyStore::from_passphrase(home.path(), TEST_PASSPHRASE).unwrap();
        let err = PassphraseKeyStore::from_passphrase(home.path(), "wrong-passphrase-entirely")
            .err()
            .expect("must reject mismatched passphrase");
        assert!(matches!(err, KeyStoreError::PassphraseMismatch));
    }

    #[test]
    fn correct_passphrase_unlocks_across_runs() {
        let home = TempDir::new().unwrap();
        let _first = PassphraseKeyStore::from_passphrase(home.path(), TEST_PASSPHRASE).unwrap();
        let _second = PassphraseKeyStore::from_passphrase(home.path(), TEST_PASSPHRASE).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn state_file_has_0600_mode() {
        use std::os::unix::fs::PermissionsExt;
        let home = TempDir::new().unwrap();
        let ks = PassphraseKeyStore::from_passphrase(home.path(), TEST_PASSPHRASE).unwrap();
        let state_mode =
            fs::metadata(ks.keystore_dir().join("passphrase.state")).unwrap().permissions().mode();
        assert_eq!(state_mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn keystore_dir_has_0700_mode() {
        use std::os::unix::fs::PermissionsExt;
        let home = TempDir::new().unwrap();
        let ks = PassphraseKeyStore::from_passphrase(home.path(), TEST_PASSPHRASE).unwrap();
        let dir_mode = fs::metadata(ks.keystore_dir()).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700);
    }

    #[test]
    fn constant_time_eq_matches_partial_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }

    #[tokio::test]
    async fn master_key_is_idempotent() {
        let home = TempDir::new().unwrap();
        let ks = PassphraseKeyStore::from_passphrase(home.path(), TEST_PASSPHRASE).unwrap();
        let k1 = ks.master_key().await.unwrap();
        let k2 = ks.master_key().await.unwrap();
        assert_eq!(&*k1, &*k2);
        assert_eq!(k1.len(), MASTER_KEY_LEN);
    }

    #[tokio::test]
    async fn master_key_stable_across_adapter_instances() {
        let home = TempDir::new().unwrap();
        let ks1 = PassphraseKeyStore::from_passphrase(home.path(), TEST_PASSPHRASE).unwrap();
        let k1 = ks1.master_key().await.unwrap();
        drop(ks1);

        let ks2 = PassphraseKeyStore::from_passphrase(home.path(), TEST_PASSPHRASE).unwrap();
        let k2 = ks2.master_key().await.unwrap();
        assert_eq!(&*k1, &*k2);
    }

    #[tokio::test]
    async fn set_master_key_is_immutable() {
        let home = TempDir::new().unwrap();
        let ks = PassphraseKeyStore::from_passphrase(home.path(), TEST_PASSPHRASE).unwrap();
        let err = ks.set_master_key(&[0u8; MASTER_KEY_LEN]).await.unwrap_err();
        assert!(matches!(err, KeyStoreError::PassphraseAdapterImmutable));
    }

    #[test]
    fn hmac_verifier_is_one_way_fixed_vector() {
        // Sanity: the verifier is deterministic for a fixed key + domain.
        let key = [0x42u8; MASTER_KEY_LEN];
        let tag1 = compute_verifier(&key);
        let tag2 = compute_verifier(&key);
        assert_eq!(tag1, tag2);

        // Different key → different tag.
        let other_key = [0x43u8; MASTER_KEY_LEN];
        let tag_other = compute_verifier(&other_key);
        assert_ne!(tag1, tag_other);
    }
}
