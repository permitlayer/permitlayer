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
//! Story 7.6a bumped `SEALED_CREDENTIAL_VERSION` from 1 to 2 to add a
//! `key_id: u8` field. Writes always emit v2; reads accept both v1 and
//! v2 (v1 synthesizes `key_id = 0`). The
//! `cli::update::migrations::envelope_v1_to_v2` migration rewrites
//! every v1 envelope to v2 once.
//!
//! ## v2 (current — 24-byte fixed header)
//! ```text
//! offset  bytes  field
//!   0      2     version        (u16 = 2)
//!   2      1     nonce_len      (u8 = 12)
//!   3      1     key_id         (u8)              ← added in v2
//!   4     12     nonce          ([u8; 12])
//!  16      4     aad_len        (u32)
//!  20   aad_len  aad            ([u8; aad_len])
//!    *     4     ct_len         (u32)
//!    *  ct_len   ciphertext     ([u8; ct_len], includes 16-byte GCM tag)
//! ```
//! Total size: `24 + aad_len + ct_len`.
//!
//! ## v1 (legacy — 23-byte fixed header, read-only)
//! ```text
//! offset  bytes  field
//!   0      2     version        (u16 = 1)
//!   2      1     nonce_len      (u8 = 12)
//!   3     12     nonce          ([u8; 12])
//!  15      4     aad_len        (u32)
//!  19   aad_len  aad            ([u8; aad_len])
//!    *     4     ct_len         (u32)
//!    *  ct_len   ciphertext     ([u8; ct_len])
//! ```
//! Total size: `23 + aad_len + ct_len`.
//!
//! Not JSON: serde is forbidden on credential types and the fixed-size
//! header is immune to deserialization resource-exhaustion attacks.
//!
//! # Concurrency
//!
//! All I/O runs inside `tokio::task::spawn_blocking`, so the async
//! runtime is never held for a syscall. Story 7.6a added a
//! vault-level advisory lock
//! ([`crate::vault::lock::VaultLock`]): every `put` acquires
//! `<home>/.vault.lock` for the duration of the atomic-write sequence.
//! Concurrent `put`s — same-service or different-service, same-
//! process or cross-process — serialize via the kernel's `flock` /
//! `LockFileEx`. Reads (`get`, `list_services`) do NOT acquire the
//! lock; the worst case is observing a since-vanished service, which
//! `list_services` already handles via skip-and-warn semantics.

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
use crate::vault::lock::{VaultLock, VaultLockError};

/// Fixed-size prefix of the v1 envelope: version (2) + nonce_len (1) +
/// nonce (12) + aad_len (4) + ct_len (4) = 23. Read-only — v1 is the
/// pre-Story-7.6a format. NEW writes use [`FIXED_HEADER_LEN_V2`].
const FIXED_HEADER_LEN_V1: usize = 23;
/// Fixed-size prefix of the v2 envelope: version (2) + nonce_len (1) +
/// key_id (1) + nonce (12) + aad_len (4) + ct_len (4) = 24. Story 7.6a
/// inserted the `key_id: u8` field at offset 3 immediately after
/// `nonce_len`.
const FIXED_HEADER_LEN_V2: usize = 24;
/// Expected value of the `nonce_len` byte (12 in both v1 and v2).
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

/// Lift a [`VaultLockError`] into [`StoreError::VaultLockFailed`].
fn map_lock_err(e: VaultLockError) -> StoreError {
    StoreError::VaultLockFailed(e)
}

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
        // Story 7.6a AC #2: acquire the vault-level advisory lock for
        // the duration of the atomic write. The lock and the I/O
        // happen on the same blocking thread (acquired inside the
        // closure) so the kernel-side `flock` is held by the same
        // task that does the rename. Drop releases the lock when
        // the closure returns, regardless of success/failure.
        let lock_home = self.home.clone();

        #[cfg(any(test, feature = "test-seam"))]
        let io = self.io.clone();

        #[cfg(any(test, feature = "test-seam"))]
        {
            tokio::task::spawn_blocking(move || -> Result<(), StoreError> {
                let _vault_lock = VaultLock::acquire(&lock_home).map_err(map_lock_err)?;
                atomic_write_via_io(&*io, &tmp, &target, &vault_dir, &buffer)
            })
            .await??;
        }
        #[cfg(not(any(test, feature = "test-seam")))]
        {
            tokio::task::spawn_blocking(move || -> Result<(), StoreError> {
                let _vault_lock = VaultLock::acquire(&lock_home).map_err(map_lock_err)?;
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

    async fn list_services(&self) -> Result<Vec<String>, StoreError> {
        let vault_dir = self.home.join("vault");
        tokio::task::spawn_blocking(move || -> Result<Vec<String>, StoreError> {
            let mut out = Vec::new();
            let read_dir = match std::fs::read_dir(&vault_dir) {
                Ok(rd) => rd,
                // Vault dir absent (fresh install before first put) is
                // not an error — return empty list. Mirrors
                // `AgentIdentityStore::list` posture.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
                Err(e) => return Err(StoreError::IoError(e)),
            };
            for entry in read_dir {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        // Per-entry read_dir failure (race with remove,
                        // perm flap) must not abort the whole listing.
                        tracing::warn!(
                            dir = %vault_dir.display(),
                            error = %e,
                            "skipping unreadable vault directory entry"
                        );
                        continue;
                    }
                };
                let path = entry.path();
                let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
                    // Non-UTF-8 filename — skip silently. Vault writes
                    // only ASCII-safe names through `validate_service_name`,
                    // so this only fires on operator-edited dirs.
                    continue;
                };
                // Skip dotfiles, editor lockfiles, tempfiles, the
                // rotation marker, and anything not ending in `.sealed`.
                if file_name.starts_with('.') || file_name.starts_with('#') {
                    continue;
                }
                if file_name.contains(".tmp.") || file_name.contains(".sealed.new") {
                    continue;
                }
                let Some(stem) = file_name.strip_suffix(".sealed") else {
                    continue;
                };
                // Reject non-regular files (symlinks etc.) per the
                // Story 7.3 P63 precedent — autostart status applies the
                // same rule. The vault adapter only ever writes regular
                // files via atomic rename; a symlink at one of these
                // paths means out-of-band edit.
                let meta = match std::fs::symlink_metadata(&path) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::warn!(
                            path = %path.display(),
                            error = %e,
                            "skipping vault entry — symlink_metadata failed"
                        );
                        continue;
                    }
                };
                if !meta.file_type().is_file() {
                    tracing::warn!(
                        path = %path.display(),
                        "skipping vault entry — not a regular file (symlink?)"
                    );
                    continue;
                }
                if validate_service_name(stem).is_err() {
                    tracing::warn!(
                        path = %path.display(),
                        "skipping vault entry with invalid service name in stem"
                    );
                    continue;
                }
                out.push(stem.to_owned());
            }
            Ok(out)
        })
        .await?
    }
}

/// Encode a `SealedCredential` to the on-disk envelope format.
///
/// **Always writes v2** (24-byte fixed header with `key_id` at offset
/// 3) — Story 7.6a. Old binaries that only know v1 will fail to parse
/// v2 envelopes with `StoreError::UnsupportedVersion`, which is the
/// intended forward-only behavior (downgrade is via binary rollback,
/// not envelope rewrite).
///
/// `pub` (not `pub(crate)`) so Story 7.6b's rotate-key v2 flow and the
/// envelope-v1-to-v2 migration can stage envelopes at non-store paths
/// (`.sealed.new`, the migration's tempfile) using the exact same
/// on-disk format. Callers that already hold the [`crate::VaultLock`]
/// MUST NOT route through `CredentialFsStore::put` — they would
/// deadlock on lock re-acquire — and instead build bytes here +
/// atomic-write to disk via their own helper.
pub fn encode_envelope(sealed: &SealedCredential) -> Vec<u8> {
    let aad = sealed.aad();
    let ct = sealed.ciphertext();
    // v2 always: callers may construct `SealedCredential` with
    // `version = 1` for round-trip tests; we still emit v2 bytes.
    // The `version` field on disk is what dictates parser dispatch,
    // not the in-memory value, so this is the correct write-time
    // posture (forward-only).
    let mut buf = Vec::with_capacity(FIXED_HEADER_LEN_V2 + aad.len() + ct.len());
    let version: u16 = SEALED_CREDENTIAL_VERSION;
    buf.extend_from_slice(&version.to_le_bytes());
    buf.push(EXPECTED_NONCE_LEN);
    buf.push(sealed.key_id());
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

/// Atomic-write `bytes` to `target` via tempfile + rename + parent
/// fsync. Companion to [`encode_envelope`] for callers that already
/// hold the [`crate::VaultLock`] and MUST NOT route through
/// [`CredentialFsStore::put`] (which would deadlock on lock
/// re-acquire). Story 7.6b promoted this from a private helper in
/// `cli::update::migrations::envelope_v1_to_v2` so rotation's reseal
/// loop can reuse the discipline without duplicating it.
///
/// On Unix, the tempfile is created with mode `0o600`. On a
/// failed `rename`, the tempfile is best-effort cleaned up.
pub fn atomic_write_bytes(target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    let parent = target.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "target has no parent directory")
    })?;
    let tmp_name = match target.file_name().and_then(|n| n.to_str()) {
        Some(n) => format!("{n}.tmp.{}.{}", std::process::id(), {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            COUNTER.fetch_add(1, Ordering::Relaxed)
        }),
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "target has no file name",
            ));
        }
    };
    let tmp = parent.join(tmp_name);

    let mut file = open_tempfile_0600(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    if let Err(e) = std::fs::rename(&tmp, target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // Parent-dir fsync is Unix-only — see agent_fs::atomic_write for
    // the rationale (NTFS journals; opening a dir for read on
    // Windows fails with PermissionDenied).
    #[cfg(unix)]
    {
        let dir = std::fs::File::open(parent)?;
        dir.sync_all()?;
    }
    Ok(())
}

#[cfg(unix)]
fn open_tempfile_0600(tmp: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(tmp)
}

#[cfg(not(unix))]
fn open_tempfile_0600(tmp: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().write(true).create_new(true).open(tmp)
}

/// Parse the on-disk envelope into a `SealedCredential`.
///
/// Story 7.6a — dispatches on the `version` byte:
/// - **v1** (legacy): 23-byte fixed header, no `key_id`. Synthesized
///   `key_id = 0` at decode time. Read-only — writers always emit v2.
/// - **v2** (current): 24-byte fixed header, `key_id` at offset 3.
/// - **v > 2**: rejected with `StoreError::UnsupportedVersion`.
///
/// Every length field is bounds-checked against the file size AND the
/// per-version cap BEFORE any slice is taken. Untrusted bytes never
/// produce an out-of-bounds panic.
pub fn decode_envelope(bytes: &[u8]) -> Result<SealedCredential, StoreError> {
    let file_size = bytes.len() as u64;
    if bytes.len() < 2 {
        return Err(StoreError::CorruptEnvelope {
            source: EnvelopeParseError::Truncated { offset: 0, needed: 2, remaining: bytes.len() },
        });
    }
    let version = u16::from_le_bytes([bytes[0], bytes[1]]);
    match version {
        1 => decode_envelope_v1(bytes, file_size),
        2 => decode_envelope_v2(bytes, file_size),
        other => {
            Err(StoreError::UnsupportedVersion { got: other, expected: SEALED_CREDENTIAL_VERSION })
        }
    }
}

/// Decode a v1 envelope (legacy, 23-byte header, no `key_id`).
/// Synthesizes `key_id = 0` per Story 7.6a's read-fallback policy.
fn decode_envelope_v1(bytes: &[u8], file_size: u64) -> Result<SealedCredential, StoreError> {
    if bytes.len() < FIXED_HEADER_LEN_V1 {
        return Err(StoreError::CorruptEnvelope {
            source: EnvelopeParseError::Truncated {
                offset: 0,
                needed: FIXED_HEADER_LEN_V1,
                remaining: bytes.len(),
            },
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
    let aad_start = 19usize;
    let (aad, ct_start, ct_len) =
        parse_aad_and_ct(bytes, aad_start, aad_len, file_size, FIXED_HEADER_LEN_V1)?;
    Ok(SealedCredential::from_trusted_bytes(
        bytes[ct_start..ct_start + ct_len as usize].to_vec(),
        nonce,
        aad,
        1,
        // v1 envelopes pre-date `key_id`; everything in a v1 vault
        // was sealed under the bootstrap (single, never-rotated) key.
        permitlayer_credential::KeyId::ZERO,
    ))
}

/// Decode a v2 envelope (Story 7.6a, 24-byte header, `key_id` at offset 3).
fn decode_envelope_v2(bytes: &[u8], file_size: u64) -> Result<SealedCredential, StoreError> {
    if bytes.len() < FIXED_HEADER_LEN_V2 {
        return Err(StoreError::CorruptEnvelope {
            source: EnvelopeParseError::Truncated {
                offset: 0,
                needed: FIXED_HEADER_LEN_V2,
                remaining: bytes.len(),
            },
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
    let key_id = bytes[3];
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bytes[4..16]);
    let aad_len = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let aad_start = 20usize;
    let (aad, ct_start, ct_len) =
        parse_aad_and_ct(bytes, aad_start, aad_len, file_size, FIXED_HEADER_LEN_V2)?;
    Ok(SealedCredential::from_trusted_bytes(
        bytes[ct_start..ct_start + ct_len as usize].to_vec(),
        nonce,
        aad,
        2,
        permitlayer_credential::KeyId::new(key_id),
    ))
}

/// Shared bounds-check logic for the AAD + ciphertext sections of
/// both v1 and v2 envelopes. `aad_start` differs (19 in v1, 20 in v2)
/// but everything downstream is identical.
fn parse_aad_and_ct(
    bytes: &[u8],
    aad_start: usize,
    aad_len: u32,
    file_size: u64,
    fixed_header_len: usize,
) -> Result<(Vec<u8>, usize, u32), StoreError> {
    if aad_len > MAX_AAD_LEN {
        return Err(StoreError::CorruptEnvelope {
            source: EnvelopeParseError::AadTooLarge { got: aad_len, max: MAX_AAD_LEN },
        });
    }
    let aad_end = aad_start.checked_add(aad_len as usize).ok_or(StoreError::CorruptEnvelope {
        source: EnvelopeParseError::LengthFieldExceedsFile {
            field: "aad_len",
            value: aad_len as u64,
            file_size,
        },
    })?;
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
    let declared = (fixed_header_len as u64)
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
    Ok((aad, ct_start, ct_len))
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
        // Unix-only: see atomic_write_bytes for rationale.
        #[cfg(unix)]
        {
            let dir = std::fs::File::open(parent)?;
            dir.sync_all()
        }
        #[cfg(not(unix))]
        {
            let _ = parent;
            Ok(())
        }
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
    // Unix-only: see atomic_write_bytes for rationale.
    #[cfg(unix)]
    {
        let dir = std::fs::File::open(parent)?;
        dir.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
    }
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
        // Story 7.6a: `key_id = 0` for the single-key world.
        SealedCredential::from_trusted_bytes(
            ciphertext,
            nonce,
            aad,
            SEALED_CREDENTIAL_VERSION,
            permitlayer_credential::KeyId::ZERO,
        )
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
        // v2 aad_len lives at offset 16..20 (after version, nonce_len,
        // key_id, nonce). Story 7.6a renumbered this from offset 15..19.
        let oversize: u32 = MAX_AAD_LEN + 1;
        encoded[16..20].copy_from_slice(&oversize.to_le_bytes());
        let err = decode_err(decode_envelope(&encoded));
        assert!(matches!(
            err,
            StoreError::CorruptEnvelope { source: EnvelopeParseError::AadTooLarge { .. } }
        ));
    }

    // ── Story 7.6a AC #6/#7: envelope v2 + key_id round-trip ─────────

    /// Story 7.6a AC #6: every encode produces a v2 envelope (24-byte
    /// header) regardless of the in-memory `version` field.
    #[tokio::test]
    async fn encode_always_writes_v2_header_byte() {
        let sealed = SealedCredential::from_trusted_bytes(
            vec![0xAB; 48],
            [0x11u8; 12],
            b"permitlayer-vault-v1:gmail".to_vec(),
            SEALED_CREDENTIAL_VERSION,
            permitlayer_credential::KeyId::new(0x55),
        );
        let encoded = encode_envelope(&sealed);
        // Bytes 0-1 = u16 version (= 2), byte 2 = nonce_len (= 12),
        // byte 3 = key_id (= 0x55).
        assert_eq!(u16::from_le_bytes([encoded[0], encoded[1]]), 2);
        assert_eq!(encoded[2], 12);
        assert_eq!(encoded[3], 0x55);
    }

    /// Story 7.6a AC #6: v2 envelope round-trips with `key_id`
    /// preserved.
    #[tokio::test]
    async fn encode_then_decode_v2_round_trips() {
        let original = SealedCredential::from_trusted_bytes(
            vec![0xCD; 48],
            [0x11u8; 12],
            b"permitlayer-vault-v1:gmail".to_vec(),
            SEALED_CREDENTIAL_VERSION,
            permitlayer_credential::KeyId::new(7),
        );
        let encoded = encode_envelope(&original);
        let decoded = decode_ok(decode_envelope(&encoded));
        assert_eq!(decoded.version(), 2);
        assert_eq!(decoded.key_id(), 7);
        assert_eq!(decoded.ciphertext(), original.ciphertext());
        assert_eq!(decoded.aad(), original.aad());
        assert_eq!(decoded.nonce(), original.nonce());
    }

    /// Story 7.6a AC #6: a v1 envelope (legacy 23-byte header)
    /// decodes successfully and synthesizes `key_id = 0`.
    #[tokio::test]
    async fn decode_v1_envelope_returns_key_id_zero() {
        // Build a v1 envelope manually: version=1, nonce_len=12, no
        // key_id byte, then nonce (12), aad_len (4), aad, ct_len (4),
        // ct.
        let aad: Vec<u8> = b"permitlayer-vault-v1:gmail".to_vec();
        let ct: Vec<u8> = vec![0x99; 48];
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.push(12);
        buf.extend_from_slice(&[0x22u8; 12]);
        buf.extend_from_slice(&u32::try_from(aad.len()).unwrap().to_le_bytes());
        buf.extend_from_slice(&aad);
        buf.extend_from_slice(&u32::try_from(ct.len()).unwrap().to_le_bytes());
        buf.extend_from_slice(&ct);

        let decoded = decode_ok(decode_envelope(&buf));
        assert_eq!(decoded.version(), 1);
        assert_eq!(decoded.key_id(), 0, "v1 envelopes synthesize key_id = 0");
        assert_eq!(decoded.aad(), aad.as_slice());
        assert_eq!(decoded.ciphertext(), ct.as_slice());
    }

    /// Story 7.6a AC #6: a v2 envelope with non-zero `key_id`
    /// decodes with that exact value.
    #[tokio::test]
    async fn decode_v2_envelope_returns_correct_key_id() {
        let original = SealedCredential::from_trusted_bytes(
            vec![0xCD; 48],
            [0x11u8; 12],
            b"permitlayer-vault-v1:gmail".to_vec(),
            SEALED_CREDENTIAL_VERSION,
            permitlayer_credential::KeyId::new(123),
        );
        let encoded = encode_envelope(&original);
        let decoded = decode_ok(decode_envelope(&encoded));
        assert_eq!(decoded.key_id(), 123);
    }

    /// Story 7.6a AC #6: future versions (v3+) are rejected up front
    /// so a forward-incompatible envelope cannot reach a parser
    /// branch with mismatched header expectations.
    #[tokio::test]
    async fn decode_unsupported_version_3_or_higher_rejected() {
        let mut encoded = encode_envelope(&fake_sealed("gmail", 0x00));
        encoded[0..2].copy_from_slice(&3u16.to_le_bytes());
        let err = decode_err(decode_envelope(&encoded));
        assert!(matches!(err, StoreError::UnsupportedVersion { got: 3, .. }));
    }

    /// Story 7.6a AC #7: `put` rejects a v1-shaped `SealedCredential`
    /// constructed via `from_trusted_bytes(... version=1)`. The
    /// existing version-mismatch guard fires once
    /// `SEALED_CREDENTIAL_VERSION` is bumped.
    #[tokio::test]
    async fn put_rejects_v1_envelope_with_unsupported_version() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        let v1 = SealedCredential::from_trusted_bytes(
            vec![0xAA; 48],
            [0x11u8; 12],
            b"permitlayer-vault-v1:gmail".to_vec(),
            1,
            permitlayer_credential::KeyId::ZERO,
        );
        let err = store.put("gmail", v1).await.unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedVersion { got: 1, expected: 2 }));
    }

    // ── Story 7.6: list_services tests ───────────────────────────────

    #[tokio::test]
    async fn list_services_returns_empty_when_vault_dir_absent() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        // Delete the vault dir that `new_store` just created so we
        // exercise the NotFound branch.
        std::fs::remove_dir_all(tmp.path().join("vault")).unwrap();
        let services = store.list_services().await.unwrap();
        assert!(services.is_empty());
    }

    #[tokio::test]
    async fn list_services_returns_all_persisted_services() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        store.put("gmail", fake_sealed("gmail", 0xAA)).await.unwrap();
        store.put("gmail-refresh", fake_sealed("gmail-refresh", 0xBB)).await.unwrap();
        store.put("calendar", fake_sealed("calendar", 0xCC)).await.unwrap();

        let mut services = store.list_services().await.unwrap();
        services.sort();
        assert_eq!(services, vec!["calendar", "gmail", "gmail-refresh"]);
    }

    #[tokio::test]
    async fn list_services_skips_dotfiles_and_tempfiles_and_marker() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        store.put("gmail", fake_sealed("gmail", 0xAA)).await.unwrap();

        // Plant noise the rotate-key flow may legitimately produce.
        let vault_dir = tmp.path().join("vault");
        std::fs::write(vault_dir.join(".rotation.in-progress"), b"{}").unwrap();
        std::fs::write(vault_dir.join(".DS_Store"), b"").unwrap();
        std::fs::write(vault_dir.join("gmail.sealed.tmp.999.0.deadbeef"), b"junk").unwrap();
        std::fs::write(vault_dir.join("calendar.sealed.new"), b"in-flight").unwrap();
        std::fs::write(vault_dir.join("readme.txt"), b"not a sealed envelope").unwrap();
        std::fs::write(vault_dir.join("#editor#"), b"emacs lockfile").unwrap();

        let services = store.list_services().await.unwrap();
        assert_eq!(services, vec!["gmail"]);
    }

    #[tokio::test]
    async fn list_services_skips_files_with_invalid_service_names() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        store.put("gmail", fake_sealed("gmail", 0xAA)).await.unwrap();

        // Plant a file whose stem fails validate_service_name (uppercase).
        let vault_dir = tmp.path().join("vault");
        std::fs::write(vault_dir.join("BadName.sealed"), b"impossible-via-put").unwrap();

        let services = store.list_services().await.unwrap();
        assert_eq!(services, vec!["gmail"]);
    }

    // ── Story 7.6a AC #2: VaultLock acquired around put ──────────────

    /// Fault-injection IO that records the order in which `put`
    /// calls reach `create_tempfile` (the first syscall AFTER
    /// `VaultLock::acquire`). If the lock genuinely serializes the
    /// writes, the recorded order matches the order in which
    /// acquires completed; without serialization, the records would
    /// interleave (both would be present before either rename).
    ///
    /// The first writer pauses for ~150ms between `create_tempfile`
    /// and `rename` — long enough that a non-serializing second
    /// writer would observably reach its own `create_tempfile`
    /// before the first finishes its rename.
    struct BarrierIo {
        log: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
        first_done: std::sync::Arc<std::sync::atomic::AtomicBool>,
        is_first: std::sync::atomic::AtomicBool,
    }

    impl BarrierIo {
        fn new(log: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>) -> Self {
            Self {
                log,
                first_done: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                is_first: std::sync::atomic::AtomicBool::new(true),
            }
        }
    }

    impl CredentialFsIo for BarrierIo {
        fn create_tempfile(&self, tmp: &Path) -> std::io::Result<std::fs::File> {
            // Mark which writer reached create_tempfile first.
            // Subsequent writers see is_first = false.
            let me_first = self.is_first.swap(false, std::sync::atomic::Ordering::SeqCst);
            self.log.lock().unwrap().push(if me_first { "first:create" } else { "second:create" });
            real_create_tempfile(tmp)
        }
        fn write_all(&self, file: &mut std::fs::File, bytes: &[u8]) -> std::io::Result<()> {
            file.write_all(bytes)
        }
        fn sync_all(&self, file: &std::fs::File) -> std::io::Result<()> {
            file.sync_all()
        }
        fn rename(&self, tmp: &Path, target: &Path) -> std::io::Result<()> {
            // Pause here ONLY for the first writer — long enough for
            // a non-serializing second writer to observably enter
            // create_tempfile before this rename completes. Under
            // serialization the second writer is blocked in its
            // VaultLock::acquire and CANNOT have logged "second:create"
            // yet at the moment we record "first:rename".
            let last = {
                let log = self.log.lock().unwrap();
                log.last().copied().unwrap_or("")
            };
            if last == "first:create" && !self.first_done.load(std::sync::atomic::Ordering::SeqCst)
            {
                std::thread::sleep(std::time::Duration::from_millis(150));
                self.log.lock().unwrap().push("first:rename");
                self.first_done.store(true, std::sync::atomic::Ordering::SeqCst);
            } else {
                self.log.lock().unwrap().push("second:rename");
            }
            std::fs::rename(tmp, target)
        }
        fn sync_parent_dir(&self, parent: &Path) -> std::io::Result<()> {
            // Unix-only: see RealCredentialFsIo::sync_parent_dir for
            // rationale (NTFS won't open dirs for read).
            #[cfg(unix)]
            {
                let dir = std::fs::File::open(parent)?;
                dir.sync_all()
            }
            #[cfg(not(unix))]
            {
                let _ = parent;
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn concurrent_puts_serialize_via_vault_lock() {
        // Two concurrent `put` calls must serialize via the
        // `VaultLock` advisory lock acquired inside the
        // spawn_blocking closure. The lock guarantees one writer at
        // a time at the syscall level — kernel-enforced via flock /
        // LockFileEx.
        //
        // Without the lock, the second writer would reach
        // `create_tempfile` while the first is still paused in its
        // rename — the recorded log would be:
        //   ["first:create", "second:create", "first:rename", ...]
        //
        // With the lock, the second writer is blocked in
        // `VaultLock::acquire` until the first writer's spawn_blocking
        // closure returns and Drop releases — so the recorded log is:
        //   ["first:create", "first:rename", "second:create", "second:rename"]
        //
        // We assert the second sequence exactly.
        let tmp = TempDir::new().unwrap();
        let log: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let io: std::sync::Arc<dyn CredentialFsIo> =
            std::sync::Arc::new(BarrierIo::new(std::sync::Arc::clone(&log)));
        let store = std::sync::Arc::new(
            CredentialFsStore::new_with_io(tmp.path().to_path_buf(), io).unwrap(),
        );
        let s1 = std::sync::Arc::clone(&store);
        let s2 = std::sync::Arc::clone(&store);
        let h1 = tokio::spawn(async move { s1.put("gmail", fake_sealed("gmail", 0xAA)).await });
        // Stagger second writer slightly so first wins the lock race
        // deterministically.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let h2 = tokio::spawn(async move { s2.put("gmail", fake_sealed("gmail", 0xBB)).await });
        h1.await.unwrap().expect("first put succeeded");
        h2.await.unwrap().expect("second put succeeded");
        let recorded = log.lock().unwrap().clone();
        assert_eq!(
            recorded,
            vec!["first:create", "first:rename", "second:create", "second:rename"],
            "writes did not serialize via VaultLock — recorded order: {recorded:?}"
        );
        // Final state: one of the two values is on disk.
        let got = store.get("gmail").await.unwrap().expect("present");
        assert!(matches!(got.ciphertext()[0], 0xAA | 0xBB));
    }

    #[tokio::test]
    async fn put_succeeds_when_lock_already_held_by_same_process_after_release() {
        // Acquire the lock externally, release, then put: must
        // succeed (the put acquires fresh inside the closure).
        use crate::vault::lock::VaultLock;
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        {
            let _guard = VaultLock::try_acquire(tmp.path()).expect("acquire");
        }
        // Guard dropped — put can now acquire.
        store.put("gmail", fake_sealed("gmail", 0x42)).await.expect("put after lock release");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn list_services_skips_symlinks() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        store.put("gmail", fake_sealed("gmail", 0xAA)).await.unwrap();

        // Create a symlink at <vault>/calendar.sealed pointing at the
        // gmail file. Even though the *content* is valid, we treat the
        // symlink as suspicious and skip it (Story 7.3 P63 precedent).
        let vault_dir = tmp.path().join("vault");
        std::os::unix::fs::symlink(
            vault_dir.join("gmail.sealed"),
            vault_dir.join("calendar.sealed"),
        )
        .unwrap();

        let services = store.list_services().await.unwrap();
        assert_eq!(services, vec!["gmail"]);
    }
}
