//! Filesystem-backed `CredentialStore` adapter.
//!
//! Writes sealed credentials to `{home}/vault/<service>.sealed` via the
//! canonical atomic-swap dance: create-tempfile → write → fsync →
//! rename → fsync parent-dir. On Unix the file mode is `0o600` and the
//! parent directory mode is `0o700`. On Windows the file inherits the
//! parent directory's ACL; tightening the ACL explicitly is deferred.
//!
//! # On-disk format (binary envelope, little-endian)
//!
//! ```text
//! offset  bytes  field
//!   0      2     version        (u16 = SEALED_CREDENTIAL_VERSION)
//!   2      1     nonce_len      (u8 = 12)
//!   3     12     nonce          ([u8; 12])
//!  15      4     aad_len        (u32)
//!  19   aad_len  aad            ([u8; aad_len])
//!    *     4     ct_len         (u32)
//!    *  ct_len   ciphertext     ([u8; ct_len], includes 16-byte GCM tag)
//! ```
//!
//! Total size: `23 + aad_len + ct_len`. Not JSON: serde is forbidden on
//! credential types and the fixed-size header is immune to deserialization
//! resource-exhaustion attacks.
//!
//! # Concurrency
//!
//! All I/O runs inside `tokio::task::spawn_blocking`, so the async
//! runtime is never held for a syscall. The adapter does not serialize
//! `put` calls against each other — two concurrent `put`s on the same
//! service will race, with the last-renamer winning. That's correct:
//! `rename` is atomic on POSIX and NTFS.

use std::io::Write as _;
use std::path::{Path, PathBuf};
#[cfg(any(test, feature = "test-seam"))]
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use permitlayer_credential::{MAX_PLAINTEXT_LEN, SEALED_CREDENTIAL_VERSION, SealedCredential};

use crate::store::CredentialStore;
use crate::store::error::{EnvelopeParseError, StoreError};
use crate::store::validate::validate_service_name;

/// Fixed-size prefix of the envelope: version (2) + nonce_len (1) +
/// nonce (12) + aad_len (4) + ct_len (4).
const FIXED_HEADER_LEN: usize = 23;
/// Expected value of the `nonce_len` byte at version 1.
const EXPECTED_NONCE_LEN: u8 = 12;
/// AES-256-GCM tag overhead appended to ciphertext.
const GCM_TAG_LEN: usize = 16;
/// Max AAD length on disk. Actual AAD at version 1 is
/// `21 + service.len() <= 21 + 64 = 85`; 128 is a conservative cap.
const MAX_AAD_LEN: u32 = 128;
/// Max ciphertext length on disk. Derived from `MAX_PLAINTEXT_LEN` +
/// GCM tag overhead.
const MAX_CIPHERTEXT_LEN: u32 = (MAX_PLAINTEXT_LEN + GCM_TAG_LEN) as u32;

/// Per-process tempfile counter. Combined with `std::process::id()` to
/// ensure cross-process uniqueness without nanosecond-precision names
/// (lesson from Story 1.1 review).
static TEMPFILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Filesystem-backed `CredentialStore`.
///
/// Holds a cloned `home: PathBuf` (to avoid borrowing `self` inside
/// `spawn_blocking` closures) plus an `Arc<dyn CredentialFsIo>` seam
/// used only for fault injection in tests. Production callers
/// construct via `CredentialFsStore::new`, which installs the real
/// I/O backend and never panics on the hot path.
pub struct CredentialFsStore {
    home: PathBuf,
    #[cfg(any(test, feature = "test-seam"))]
    io: Arc<dyn CredentialFsIo>,
}

impl CredentialFsStore {
    /// Construct the adapter rooted at `{home}/vault/`. Creates the
    /// `vault/` directory if absent; sets mode `0o700` on Unix.
    pub fn new(home: PathBuf) -> Result<Self, StoreError> {
        let vault_dir = home.join("vault");
        create_vault_dir(&vault_dir)?;

        #[cfg(windows)]
        {
            // Windows ACL enforcement deferred to a follow-up story; MVP
            // target OS is macOS/Linux per architecture.md.
            tracing::warn!("Windows ACL enforcement deferred; relying on parent-dir ACL");
        }

        Ok(Self {
            home,
            #[cfg(any(test, feature = "test-seam"))]
            io: Arc::new(RealCredentialFsIo),
        })
    }

    /// Test-only: construct with an injected I/O backend for fault
    /// simulation. Gated behind `#[cfg(any(test, feature = "test-seam"))]`
    /// so production builds cannot reach this constructor.
    #[cfg(any(test, feature = "test-seam"))]
    #[doc(hidden)]
    pub fn new_with_io(home: PathBuf, io: Arc<dyn CredentialFsIo>) -> Result<Self, StoreError> {
        let vault_dir = home.join("vault");
        create_vault_dir(&vault_dir)?;
        Ok(Self { home, io })
    }

    fn target_path(&self, service: &str) -> PathBuf {
        self.home.join("vault").join(format!("{service}.sealed"))
    }

    fn tempfile_path(&self, service: &str) -> PathBuf {
        let pid = std::process::id();
        let counter = TEMPFILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        // Random suffix prevents PID-reuse collisions: if a previous
        // process crashed with the same PID and counter=0, the random
        // component makes the new name distinct with overwhelming
        // probability (~2^-64 collision). `OsRng` panics on entropy
        // failure — same fail-stop policy as nonce generation in the
        // vault (OS RNG failure is catastrophic and non-recoverable).
        let rand: u64 = {
            use rand::RngCore;
            let mut buf = [0u8; 8];
            rand::rngs::OsRng.fill_bytes(&mut buf);
            u64::from_le_bytes(buf)
        };
        self.home.join("vault").join(format!("{service}.sealed.tmp.{pid}.{counter}.{rand:016x}"))
    }
}

#[async_trait]
impl CredentialStore for CredentialFsStore {
    async fn put(&self, service: &str, sealed: SealedCredential) -> Result<(), StoreError> {
        validate_service_name(service)?;

        // Reject envelopes with an unsupported version before writing to
        // disk — prevents write-only poison (a stale envelope from a prior
        // vault epoch would serialize successfully but become immediately
        // unreadable via `get()`, which rejects unknown versions).
        if sealed.version() != SEALED_CREDENTIAL_VERSION {
            return Err(StoreError::UnsupportedVersion {
                got: sealed.version(),
                expected: SEALED_CREDENTIAL_VERSION,
            });
        }

        // Serialize BEFORE spawning the blocking closure: `SealedCredential`
        // is not `Clone`, and encoding consumes its bytes into a `Vec<u8>`
        // that the closure can own via `move`.
        let buffer = encode_envelope(&sealed);
        drop(sealed); // zeroize ciphertext/nonce/aad promptly

        let target = self.target_path(service);
        let tmp = self.tempfile_path(service);
        let vault_dir = self.home.join("vault");

        #[cfg(any(test, feature = "test-seam"))]
        let io = self.io.clone();

        #[cfg(any(test, feature = "test-seam"))]
        {
            tokio::task::spawn_blocking(move || -> Result<(), StoreError> {
                atomic_write_via_io(&*io, &tmp, &target, &vault_dir, &buffer)
            })
            .await??;
        }
        #[cfg(not(any(test, feature = "test-seam")))]
        {
            tokio::task::spawn_blocking(move || -> Result<(), StoreError> {
                atomic_write_real(&tmp, &target, &vault_dir, &buffer)
            })
            .await??;
        }

        Ok(())
    }

    async fn get(&self, service: &str) -> Result<Option<SealedCredential>, StoreError> {
        validate_service_name(service)?;
        let path = self.target_path(service);
        tokio::task::spawn_blocking(move || -> Result<Option<SealedCredential>, StoreError> {
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(StoreError::IoError(e)),
            };
            let sealed = decode_envelope(&bytes)?;
            Ok(Some(sealed))
        })
        .await?
    }
}

/// Encode a `SealedCredential` to the on-disk envelope format.
pub(crate) fn encode_envelope(sealed: &SealedCredential) -> Vec<u8> {
    let aad = sealed.aad();
    let ct = sealed.ciphertext();
    let mut buf = Vec::with_capacity(FIXED_HEADER_LEN + aad.len() + ct.len());
    buf.extend_from_slice(&sealed.version().to_le_bytes());
    buf.push(EXPECTED_NONCE_LEN);
    buf.extend_from_slice(sealed.nonce());
    #[allow(clippy::expect_used)] // aad_len fits in u32 by bound
    let aad_len: u32 = aad.len().try_into().expect(
        "static invariant: aad.len() <= MAX_AAD_LEN (128) via vault construction, fits u32",
    );
    buf.extend_from_slice(&aad_len.to_le_bytes());
    buf.extend_from_slice(aad);
    #[allow(clippy::expect_used)] // ct_len fits in u32 by MAX_PLAINTEXT_LEN bound
    let ct_len: u32 = ct
        .len()
        .try_into()
        .expect("static invariant: ct.len() <= MAX_PLAINTEXT_LEN + GCM_TAG_LEN, fits u32");
    buf.extend_from_slice(&ct_len.to_le_bytes());
    buf.extend_from_slice(ct);
    buf
}

/// Parse the on-disk envelope into a `SealedCredential`.
///
/// Every length field is bounds-checked against the file size AND the
/// per-version cap BEFORE any slice is taken. Untrusted bytes never
/// produce an out-of-bounds panic.
pub(crate) fn decode_envelope(bytes: &[u8]) -> Result<SealedCredential, StoreError> {
    let file_size = bytes.len() as u64;
    if bytes.len() < FIXED_HEADER_LEN {
        return Err(StoreError::CorruptEnvelope {
            source: EnvelopeParseError::Truncated {
                offset: 0,
                needed: FIXED_HEADER_LEN,
                remaining: bytes.len(),
            },
        });
    }
    let version = u16::from_le_bytes([bytes[0], bytes[1]]);
    if version != SEALED_CREDENTIAL_VERSION {
        return Err(StoreError::UnsupportedVersion {
            got: version,
            expected: SEALED_CREDENTIAL_VERSION,
        });
    }
    let nonce_len = bytes[2];
    if nonce_len != EXPECTED_NONCE_LEN {
        return Err(StoreError::CorruptEnvelope {
            source: EnvelopeParseError::NonceLenMismatch {
                got: nonce_len,
                expected: EXPECTED_NONCE_LEN,
            },
        });
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bytes[3..15]);
    let aad_len = u32::from_le_bytes([bytes[15], bytes[16], bytes[17], bytes[18]]);
    if aad_len > MAX_AAD_LEN {
        return Err(StoreError::CorruptEnvelope {
            source: EnvelopeParseError::AadTooLarge { got: aad_len, max: MAX_AAD_LEN },
        });
    }
    let aad_start = 19usize;
    let aad_end = aad_start.checked_add(aad_len as usize).ok_or(StoreError::CorruptEnvelope {
        source: EnvelopeParseError::LengthFieldExceedsFile {
            field: "aad_len",
            value: aad_len as u64,
            file_size,
        },
    })?;
    // Need aad_end + 4 bytes for ct_len field.
    let ct_len_start = aad_end.checked_add(4).ok_or(StoreError::CorruptEnvelope {
        source: EnvelopeParseError::LengthFieldExceedsFile {
            field: "ct_len_header",
            value: aad_end as u64 + 4,
            file_size,
        },
    })?;
    if ct_len_start > bytes.len() {
        return Err(StoreError::CorruptEnvelope {
            source: EnvelopeParseError::LengthFieldExceedsFile {
                field: "ct_len_header",
                value: ct_len_start as u64,
                file_size,
            },
        });
    }
    let aad = bytes[aad_start..aad_end].to_vec();
    let ct_len = u32::from_le_bytes([
        bytes[aad_end],
        bytes[aad_end + 1],
        bytes[aad_end + 2],
        bytes[aad_end + 3],
    ]);
    if ct_len > MAX_CIPHERTEXT_LEN {
        return Err(StoreError::CorruptEnvelope {
            source: EnvelopeParseError::CiphertextTooLarge { got: ct_len, max: MAX_CIPHERTEXT_LEN },
        });
    }
    let ct_start = ct_len_start;
    let ct_end = ct_start.checked_add(ct_len as usize).ok_or(StoreError::CorruptEnvelope {
        source: EnvelopeParseError::LengthFieldExceedsFile {
            field: "ct_len",
            value: ct_len as u64,
            file_size,
        },
    })?;
    if ct_end > bytes.len() {
        return Err(StoreError::CorruptEnvelope {
            source: EnvelopeParseError::LengthFieldExceedsFile {
                field: "ct_len",
                value: ct_len as u64,
                file_size,
            },
        });
    }
    // Strict: declared layout must consume the whole file. Trailing
    // garbage is a corruption signal, not something to silently ignore.
    let declared = (FIXED_HEADER_LEN as u64)
        .checked_add(aad_len as u64)
        .and_then(|v| v.checked_add(ct_len as u64))
        .ok_or(StoreError::CorruptEnvelope {
            source: EnvelopeParseError::LengthFieldExceedsFile {
                field: "aad_len+ct_len",
                value: aad_len as u64 + ct_len as u64,
                file_size,
            },
        })?;
    if declared != file_size {
        return Err(StoreError::CorruptEnvelope {
            source: EnvelopeParseError::SizeMismatch { declared, file_size },
        });
    }
    let ciphertext = bytes[ct_start..ct_end].to_vec();
    Ok(SealedCredential::from_trusted_bytes(ciphertext, nonce, aad, version))
}

/// Create the vault directory if absent, with mode `0o700` on Unix.
///
/// Parents are created with default permissions (via `create_dir_all`);
/// only the leaf `vault/` directory gets the restrictive `0o700` mode.
/// This avoids stamping `0o700` on shared parent directories that other
/// services may need to read.
fn create_vault_dir(dir: &Path) -> Result<(), StoreError> {
    // Ensure parent chain exists with default (umask-governed) perms.
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        // Try to create just the leaf directory with 0o700. If it
        // already exists, tighten permissions in case a prior run
        // left them too open.
        match std::fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Use symlink_metadata to avoid following symlinks — a
                // symlink at the vault path would silently redirect
                // credential writes to the symlink target.
                let meta = std::fs::symlink_metadata(dir)?;
                if meta.file_type().is_symlink() {
                    return Err(StoreError::IoError(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!("vault path is a symlink (refusing to follow): {}", dir.display()),
                    )));
                }
                if !meta.is_dir() {
                    return Err(StoreError::IoError(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!("vault path exists but is not a directory: {}", dir.display()),
                    )));
                }
                use std::os::unix::fs::PermissionsExt;
                let mut perms = meta.permissions();
                perms.set_mode(0o700);
                std::fs::set_permissions(dir, perms)?;
            }
            Err(e) => return Err(StoreError::IoError(e)),
        }
    }
    #[cfg(not(unix))]
    {
        match std::fs::create_dir(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let meta = std::fs::symlink_metadata(dir)?;
                if meta.file_type().is_symlink() {
                    return Err(StoreError::IoError(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!("vault path is a symlink (refusing to follow): {}", dir.display()),
                    )));
                }
                if !meta.is_dir() {
                    return Err(StoreError::IoError(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!("vault path exists but is not a directory: {}", dir.display()),
                    )));
                }
            }
            Err(e) => return Err(StoreError::IoError(e)),
        }
    }
    Ok(())
}

// ============================================================================
// I/O seam (test-only)
// ============================================================================

/// Fault-injection seam for the atomic-write sequence. Production code
/// uses `RealCredentialFsIo`; tests substitute a `FaultyCredentialFsIo`
/// to inject `io::Error`s at specific syscall boundaries.
///
/// Gated behind `#[cfg(any(test, feature = "test-seam"))]` + `#[doc(hidden)]`
/// because integration tests in `tests/` cannot see `pub(crate)` items.
#[cfg(any(test, feature = "test-seam"))]
#[doc(hidden)]
pub trait CredentialFsIo: Send + Sync {
    /// Create the tempfile with mode `0o600` on Unix, refusing to
    /// clobber an existing file (`create_new`).
    fn create_tempfile(&self, tmp: &Path) -> std::io::Result<std::fs::File>;
    /// Write `bytes` to the open tempfile.
    fn write_all(&self, file: &mut std::fs::File, bytes: &[u8]) -> std::io::Result<()>;
    /// `fsync` the tempfile's data and metadata.
    fn sync_all(&self, file: &std::fs::File) -> std::io::Result<()>;
    /// Atomic `rename(tmp, target)`.
    fn rename(&self, tmp: &Path, target: &Path) -> std::io::Result<()>;
    /// `fsync` the parent directory so the rename is durable.
    fn sync_parent_dir(&self, parent: &Path) -> std::io::Result<()>;
}

#[cfg(any(test, feature = "test-seam"))]
struct RealCredentialFsIo;

#[cfg(any(test, feature = "test-seam"))]
impl CredentialFsIo for RealCredentialFsIo {
    fn create_tempfile(&self, tmp: &Path) -> std::io::Result<std::fs::File> {
        real_create_tempfile(tmp)
    }
    fn write_all(&self, file: &mut std::fs::File, bytes: &[u8]) -> std::io::Result<()> {
        file.write_all(bytes)
    }
    fn sync_all(&self, file: &std::fs::File) -> std::io::Result<()> {
        file.sync_all()
    }
    fn rename(&self, tmp: &Path, target: &Path) -> std::io::Result<()> {
        std::fs::rename(tmp, target)
    }
    fn sync_parent_dir(&self, parent: &Path) -> std::io::Result<()> {
        let dir = std::fs::File::open(parent)?;
        dir.sync_all()
    }
}

#[cfg(any(test, feature = "test-seam"))]
fn atomic_write_via_io(
    io: &dyn CredentialFsIo,
    tmp: &Path,
    target: &Path,
    parent: &Path,
    bytes: &[u8],
) -> Result<(), StoreError> {
    // Tempfile is best-effort cleanup-on-drop via a RAII guard: if any
    // step after creation fails, we remove the tempfile so the next
    // write doesn't hit `AlreadyExists` on an orphaned `.tmp` file.
    let mut file = io.create_tempfile(tmp)?;
    let guard = TempfileGuard { path: tmp };
    io.write_all(&mut file, bytes)?;
    io.sync_all(&file)?;
    drop(file);
    io.rename(tmp, target)?;
    // Rename succeeded — tempfile no longer exists under `tmp`, so the
    // guard becomes a no-op.
    std::mem::forget(guard);
    io.sync_parent_dir(parent)?;
    Ok(())
}

/// RAII guard that deletes a tempfile if the write sequence is aborted
/// before the atomic rename.
struct TempfileGuard<'a> {
    path: &'a Path,
}

impl Drop for TempfileGuard<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.path);
    }
}

fn real_create_tempfile(tmp: &Path) -> std::io::Result<std::fs::File> {
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

// ============================================================================
// Production atomic-write path (no test seam)
// ============================================================================

#[cfg(not(any(test, feature = "test-seam")))]
fn atomic_write_real(
    tmp: &Path,
    target: &Path,
    parent: &Path,
    bytes: &[u8],
) -> Result<(), StoreError> {
    let mut file = real_create_tempfile(tmp)?;
    let guard = TempfileGuard { path: tmp };
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(tmp, target)?;
    std::mem::forget(guard);
    let dir = std::fs::File::open(parent)?;
    dir.sync_all()?;
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use permitlayer_credential::SealedCredential;
    use tempfile::TempDir;

    // Build a fake `SealedCredential` with deterministic fields. The
    // ciphertext doesn't need to be unsealable — the store only cares
    // that the envelope round-trips byte-for-byte.
    fn fake_sealed(service: &str, ct_filler: u8) -> SealedCredential {
        let aad: Vec<u8> = [b"permitlayer-vault-v1:", service.as_bytes()].concat();
        let ciphertext = vec![ct_filler; 48]; // 32 bytes plaintext + 16-byte tag
        let nonce = [0x11u8; 12];
        SealedCredential::from_trusted_bytes(ciphertext, nonce, aad, SEALED_CREDENTIAL_VERSION)
    }

    fn new_store(tmp: &TempDir) -> CredentialFsStore {
        CredentialFsStore::new(tmp.path().to_path_buf()).unwrap()
    }

    // `SealedCredential` is deliberately non-`Debug` (credential
    // discipline), so `.unwrap_err()` on `Result<Option<SealedCredential>, _>`
    // or `Result<SealedCredential, _>` won't compile. These helpers
    // panic with a static message instead.
    #[track_caller]
    fn get_err(r: Result<Option<SealedCredential>, StoreError>) -> StoreError {
        match r {
            Ok(_) => panic!("get unexpectedly succeeded"),
            Err(e) => e,
        }
    }

    #[track_caller]
    fn decode_err(r: Result<SealedCredential, StoreError>) -> StoreError {
        match r {
            Ok(_) => panic!("decode_envelope unexpectedly succeeded"),
            Err(e) => e,
        }
    }

    #[track_caller]
    fn decode_ok(r: Result<SealedCredential, StoreError>) -> SealedCredential {
        match r {
            Ok(s) => s,
            Err(_) => panic!("decode_envelope unexpectedly failed"),
        }
    }

    #[tokio::test]
    async fn round_trip_put_get() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        let sealed = fake_sealed("gmail", 0xAB);
        let expected_ct = sealed.ciphertext().to_vec();
        let expected_aad = sealed.aad().to_vec();
        let expected_nonce = *sealed.nonce();
        store.put("gmail", sealed).await.unwrap();
        let got = store.get("gmail").await.unwrap();
        let got = match got {
            Some(s) => s,
            None => panic!("expected Some after put"),
        };
        assert_eq!(got.ciphertext(), expected_ct.as_slice());
        assert_eq!(got.aad(), expected_aad.as_slice());
        assert_eq!(got.nonce(), &expected_nonce);
        assert_eq!(got.version(), SEALED_CREDENTIAL_VERSION);
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        assert!(store.get("gmail").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn put_overwrites_existing() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        store.put("gmail", fake_sealed("gmail", 0xAA)).await.unwrap();
        store.put("gmail", fake_sealed("gmail", 0xBB)).await.unwrap();
        let got = store.get("gmail").await.unwrap().expect("present");
        assert_eq!(got.ciphertext()[0], 0xBB);
    }

    #[tokio::test]
    async fn invalid_service_name_rejected_before_io() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        let err = store.put("Bad/Name", fake_sealed("gmail", 0x00)).await.unwrap_err();
        assert!(matches!(err, StoreError::InvalidServiceName { .. }));
        // No tempfile should exist.
        let entries: Vec<_> = std::fs::read_dir(tmp.path().join("vault"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(entries.is_empty(), "no files should be created: {entries:?}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_mode_is_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        store.put("gmail", fake_sealed("gmail", 0xAA)).await.unwrap();
        let mode =
            std::fs::metadata(tmp.path().join("vault/gmail.sealed")).unwrap().permissions().mode()
                & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn vault_dir_mode_is_0700_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let _store = new_store(&tmp);
        let mode =
            std::fs::metadata(tmp.path().join("vault")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[tokio::test]
    async fn truncated_file_returns_corrupt_envelope() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        store.put("gmail", fake_sealed("gmail", 0xAA)).await.unwrap();
        let target = tmp.path().join("vault/gmail.sealed");
        // Truncate to mid-header (10 bytes).
        let bytes = std::fs::read(&target).unwrap();
        std::fs::write(&target, &bytes[..10]).unwrap();
        let err = get_err(store.get("gmail").await);
        assert!(matches!(err, StoreError::CorruptEnvelope { .. }));
    }

    #[tokio::test]
    async fn file_with_trailing_garbage_returns_corrupt_envelope() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        store.put("gmail", fake_sealed("gmail", 0xAA)).await.unwrap();
        let target = tmp.path().join("vault/gmail.sealed");
        let mut bytes = std::fs::read(&target).unwrap();
        bytes.extend_from_slice(b"trailing garbage");
        std::fs::write(&target, &bytes).unwrap();
        let err = get_err(store.get("gmail").await);
        assert!(matches!(
            err,
            StoreError::CorruptEnvelope { source: EnvelopeParseError::SizeMismatch { .. } }
        ));
    }

    #[tokio::test]
    async fn envelope_round_trips_byte_exact() {
        let sealed = fake_sealed("gmail", 0xCD);
        let encoded = encode_envelope(&sealed);
        let decoded = decode_ok(decode_envelope(&encoded));
        assert_eq!(decoded.ciphertext(), sealed.ciphertext());
        assert_eq!(decoded.aad(), sealed.aad());
        assert_eq!(decoded.nonce(), sealed.nonce());
        assert_eq!(decoded.version(), sealed.version());
    }

    #[tokio::test]
    async fn bad_version_returns_unsupported_version() {
        // Forge an envelope with version = 99.
        let mut encoded = encode_envelope(&fake_sealed("gmail", 0x00));
        encoded[0] = 99;
        encoded[1] = 0;
        let err = decode_err(decode_envelope(&encoded));
        assert!(matches!(err, StoreError::UnsupportedVersion { got: 99, .. }));
    }

    #[tokio::test]
    async fn bad_nonce_len_returns_corrupt_envelope() {
        let mut encoded = encode_envelope(&fake_sealed("gmail", 0x00));
        encoded[2] = 8; // wrong nonce_len
        let err = decode_err(decode_envelope(&encoded));
        assert!(matches!(
            err,
            StoreError::CorruptEnvelope {
                source: EnvelopeParseError::NonceLenMismatch { got: 8, expected: 12 }
            }
        ));
    }

    #[tokio::test]
    async fn oversized_aad_len_rejected() {
        let mut encoded = encode_envelope(&fake_sealed("gmail", 0x00));
        // Overwrite aad_len with a huge value.
        let oversize: u32 = MAX_AAD_LEN + 1;
        encoded[15..19].copy_from_slice(&oversize.to_le_bytes());
        let err = decode_err(decode_envelope(&encoded));
        assert!(matches!(
            err,
            StoreError::CorruptEnvelope { source: EnvelopeParseError::AadTooLarge { .. } }
        ));
    }
}
