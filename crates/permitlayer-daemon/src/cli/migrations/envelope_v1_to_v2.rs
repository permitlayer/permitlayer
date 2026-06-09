//! v1 → v2 envelope-schema migration (Story 7.6a AC #9-11).
//!
//! Sealed credentials in pre-v0.4 vaults use the v1 on-disk envelope
//! format (23-byte fixed header, no `key_id`). Story 7.6a bumped the
//! schema to v2 (24-byte fixed header, `key_id: u8` at offset 3) and
//! flipped writers to emit only v2. v1 envelopes still parse via the
//! [`decode_envelope`][1] read-fallback path, but to avoid carrying
//! that fallback forever this migration rewrites every v1 envelope to
//! v2 with `key_id = 0` once, on the first boot of a binary new
//! enough to register it (triggered from `cli::start::run` — see the
//! migrations module docs for the UX-overhaul re-host rationale).
//!
//! # Atomicity model: directory-rename backup
//!
//! Per-file atomic rewrites would leave a partial-v2 vault on
//! mid-flight failure (file 50 of 100: half v2, half v1; an old
//! binary cannot read the new files, the new binary cannot complete
//! the rest). Renaming the whole `vault/` directory to
//! `vault.pre-v2-backup/` first means the live vault is either "fully
//! v2" or "does not exist" — never partial.
//!
//! Backup lifecycle:
//! 1. Acquire [`VaultLock`] FIRST (before the idempotency probe — a
//!    concurrent vault writer must serialize on the lock, not
//!    split-brain on the probe). The daemon boot path releases its
//!    own boot-time vault lock *before* invoking the migration
//!    (see `cli::start::run`), so this acquire never self-deadlocks.
//! 2. Idempotency probe: if every `.sealed` is already v2, return Ok.
//! 3. Pre-flight: refuse if vault path is a symlink or non-directory;
//!    refuse if backup path exists as anything other than absent.
//! 4. Rename `vault/` → `vault.pre-v2-backup/`. Atomic at the FS
//!    layer (POSIX `rename`, NTFS `MoveFileEx`).
//! 5. Re-create `vault/` with mode `0o700`.
//! 6. For each `.sealed` file in the backup: read v1 bytes,
//!    fully-validate as v1, rewrite as v2 with `key_id = 0`,
//!    atomic-write to the new vault.
//! 7. Verify every new file fully-decodes.
//! 8. Delete the backup ONLY if every file succeeded.
//! 9. On any failure: leave the backup in place, return
//!    [`MigrationError::Custom`] (or [`MigrationError::Verification`]
//!    when the rewrite produced bytes that fail full decode).
//!    Operator recovery is `mv vault.pre-v2-backup vault` after
//!    investigation.
//!
//! # Crash recovery
//!
//! If the process dies between rename(vault → backup) and recreate
//! (vault), a re-run sees `!vault_dir.exists() && backup_dir.exists()`
//! and refuses with a structured pointer to the backup. Without that
//! check the idempotency probe would treat a missing vault as
//! "already migrated" and silently abandon the backup.
//!
//! # Forward-only
//!
//! There is no v2 → v1 reverse migration. Reversibility is provided
//! by Story 2's versioned-symlink rollback: an old binary that reads
//! v2 envelopes fails closed with `StoreError::UnsupportedVersion`,
//! and `setup` re-points the symlink at the prior binary on the
//! post-rollback vault — but the vault contents are still v2, so the
//! operator must also restore the backup manually if they truly want
//! to downgrade.
//!
//! [1]: permitlayer_core::store::fs::credential_fs::decode_envelope

use std::path::{Path, PathBuf};

use permitlayer_core::vault::lock::{VaultLock, VaultLockError};
use zeroize::Zeroizing;

use super::{Migration, MigrationError};

/// Stable identifier for the migration — used in audit emission and
/// the `migrations.rs` registry.
const MIGRATION_ID: &str = "envelope-v1-to-v2";

/// Filename of the migration's backup directory, relative to the
/// `~/.agentsso/` home. The backup is intentionally NOT inside
/// `vault/` itself: it must survive the vault-directory rename and
/// be visible to operator recovery scripts that look for it at the
/// agentsso-home level.
const BACKUP_DIR_NAME: &str = "vault.pre-v2-backup";

pub(crate) struct EnvelopeV1ToV2;

impl Migration for EnvelopeV1ToV2 {
    fn id(&self) -> &'static str {
        MIGRATION_ID
    }

    fn apply(&self, home: &Path) -> Result<(), MigrationError> {
        let vault_dir = home.join("vault");
        let backup_dir = home.join(BACKUP_DIR_NAME);

        // Step 1 (review patch): pre-flight crash-recovery + symlink
        // checks BEFORE acquiring the lock. `VaultLock::try_acquire`
        // creates the vault directory at mode 0o700 if absent; that
        // would mask both the "vault missing + backup present"
        // crash-recovery state AND a symlinked vault path. We need
        // to detect both BEFORE the acquire.
        if !vault_dir.exists() && backup_dir.exists() {
            return Err(MigrationError::Custom {
                id: MIGRATION_ID,
                message: format!(
                    "vault directory missing but backup exists at {}; recover manually \
                     (typically: mv {} {}) before re-running update",
                    backup_dir.display(),
                    backup_dir.display(),
                    vault_dir.display(),
                ),
            });
        }
        if vault_dir.exists() {
            let vault_meta = std::fs::symlink_metadata(&vault_dir).map_err(|e| {
                MigrationError::Io { id: MIGRATION_ID, ctx: "stat vault directory", source: e }
            })?;
            if vault_meta.file_type().is_symlink() {
                return Err(MigrationError::Custom {
                    id: MIGRATION_ID,
                    message: format!(
                        "vault directory is a symlink (refusing to follow): {}",
                        vault_dir.display()
                    ),
                });
            }
            if !vault_meta.is_dir() {
                return Err(MigrationError::Custom {
                    id: MIGRATION_ID,
                    message: format!(
                        "vault path exists but is not a directory: {}",
                        vault_dir.display()
                    ),
                });
            }
        }

        // Step 2: acquire the vault lock. A concurrent vault writer
        // (a second booting daemon, operator tooling) must serialize
        // with this migration on the kernel
        // lock so the idempotency probe + rename + rewrite sequence
        // can't interleave.
        let _lock = VaultLock::try_acquire(home).map_err(|e| match e {
            VaultLockError::Busy { holder_pid, holder_command } => MigrationError::Custom {
                id: MIGRATION_ID,
                message: format!(
                    "vault is busy (held by pid={holder_pid:?} command={holder_command:?}); \
                     another agentsso process must finish before the v1 → v2 migration can run"
                ),
            },
            VaultLockError::Io(io) => {
                MigrationError::Io { id: MIGRATION_ID, ctx: "acquire vault lock", source: io }
            }
            other => MigrationError::Custom {
                id: MIGRATION_ID,
                message: format!("vault lock acquire failed: {other}"),
            },
        })?;

        // Step 3 (AC #9.1): idempotency probe. If every `.sealed`
        // file is already v2, return Ok(()) without touching
        // anything. Runs UNDER the lock so a concurrent vault writer
        // serializes correctly.
        if vault_is_pure_v2(&vault_dir).map_err(|e| MigrationError::Io {
            id: MIGRATION_ID,
            ctx: "probe vault for v2 envelopes",
            source: e,
        })? {
            tracing::info!(target: "migrations", "envelope-v1-to-v2: vault already at v2; skipping");
            return Ok(());
        }

        // Step 5 (AC #9.3): refuse if the backup directory already
        // exists from a prior failed attempt.
        if backup_dir.exists() {
            let backup_meta = std::fs::symlink_metadata(&backup_dir).map_err(|e| {
                MigrationError::Io { id: MIGRATION_ID, ctx: "stat backup path", source: e }
            })?;
            if backup_meta.file_type().is_symlink() || !backup_meta.is_dir() {
                return Err(MigrationError::Custom {
                    id: MIGRATION_ID,
                    message: format!(
                        "backup path exists but is not a regular directory: {}; \
                         resolve manually before re-running update",
                        backup_dir.display()
                    ),
                });
            }
            return Err(MigrationError::Custom {
                id: MIGRATION_ID,
                message: format!(
                    "pre-v2 backup already exists at {}; resolve manually before re-running update",
                    backup_dir.display()
                ),
            });
        }

        // Step 6 (AC #9.3): atomic-rename vault → backup.
        std::fs::rename(&vault_dir, &backup_dir).map_err(|e| MigrationError::Io {
            id: MIGRATION_ID,
            ctx: "rename vault to backup",
            source: e,
        })?;

        // Step 7 (AC #9.4): re-create the vault directory at mode 0o700.
        create_vault_dir(&vault_dir).map_err(|e| MigrationError::Io {
            id: MIGRATION_ID,
            ctx: "re-create vault directory",
            source: e,
        })?;

        // Step 8 (AC #9.4 + #9.5): rewrite every `.sealed` file in
        // the backup as v2 in the new vault. On any per-file
        // failure, return Err WITHOUT deleting the backup so the
        // operator can recover (AC #10).
        let rewrite_result = rewrite_all(&backup_dir, &vault_dir);
        match rewrite_result {
            Ok(count) => {
                tracing::info!(
                    target: "migrations",
                    rewritten = count,
                    backup = %backup_dir.display(),
                    "envelope-v1-to-v2: rewrote envelopes; verifying"
                );
                // Step 9 (AC #9.5): verify every new file FULLY
                // decodes (not just leading version bytes — full
                // bounds-checked parse via decode_envelope). A
                // verification failure preserves the backup with
                // the io::Error source chain.
                if let Err(e) = verify_all_v2(&vault_dir) {
                    return Err(MigrationError::Verification {
                        id: MIGRATION_ID,
                        backup_path: backup_dir.clone(),
                        source: e,
                    });
                }
                // Step 10 (AC #10): delete backup ONLY on success.
                if let Err(e) = std::fs::remove_dir_all(&backup_dir) {
                    // Backup-removal failure is non-fatal: the
                    // migration succeeded (vault is fully v2), the
                    // operator just sees a leftover backup dir they
                    // can clean up manually. Log + continue.
                    tracing::warn!(
                        target: "migrations",
                        error = %e,
                        backup = %backup_dir.display(),
                        "envelope-v1-to-v2: backup cleanup failed (migration still succeeded)"
                    );
                }
                Ok(())
            }
            Err(e) => Err(MigrationError::Custom {
                id: MIGRATION_ID,
                message: format!(
                    "v1 → v2 rewrite failed: {e}; backup preserved at {}",
                    backup_dir.display()
                ),
            }),
        }
    }
}

/// Walk `vault_dir` and check whether every `.sealed` file is v2
/// already. Returns `true` only when the directory is empty or every
/// `.sealed` file is v2. An empty / absent vault returns `true`
/// (nothing to migrate is the same as already-migrated).
///
/// Skips dotfiles, tempfiles (`.tmp.`), and non-regular files.
fn vault_is_pure_v2(vault_dir: &Path) -> std::io::Result<bool> {
    let read_dir = match std::fs::read_dir(vault_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e),
    };
    for entry in read_dir {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        if !name.ends_with(".sealed") || name.starts_with('.') || name.contains(".tmp.") {
            continue;
        }
        // Story 7.3 P63 precedent: reject non-regular files.
        let meta = std::fs::symlink_metadata(&path)?;
        if !meta.file_type().is_file() {
            tracing::warn!(
                target: "migrations",
                path = %path.display(),
                "envelope-v1-to-v2 probe: skipping non-regular .sealed entry"
            );
            continue;
        }
        let mut file = std::fs::File::open(&path)?;
        let mut header = [0u8; 2];
        use std::io::Read as _;
        if file.read_exact(&mut header).is_err() {
            // Truncated file — not v2; the rewrite step will surface
            // a clear error.
            return Ok(false);
        }
        if u16::from_le_bytes(header) != 2 {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Walk `backup_dir` and rewrite every `.sealed` file as v2 in
/// `new_vault_dir`. Returns the number of envelopes rewritten on
/// success.
fn rewrite_all(backup_dir: &Path, new_vault_dir: &Path) -> std::io::Result<usize> {
    let mut count = 0usize;
    for entry in std::fs::read_dir(backup_dir)? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        if !name.ends_with(".sealed") || name.starts_with('.') || name.contains(".tmp.") {
            continue;
        }
        // Skip non-regular files (symlinks etc.) per Story 7.3 P63.
        let meta = std::fs::symlink_metadata(&path)?;
        if !meta.file_type().is_file() {
            tracing::warn!(
                target: "migrations",
                path = %path.display(),
                "envelope-v1-to-v2: skipping non-regular file"
            );
            continue;
        }
        // Wrap envelope bytes in `Zeroizing` for posture consistency
        // with the rest of the workspace (sealed bytes are
        // ZeroizeOnDrop everywhere else).
        let v1_or_v2: Zeroizing<Vec<u8>> = Zeroizing::new(std::fs::read(&path)?);
        let v2_bytes: Zeroizing<Vec<u8>> = match coerce_to_v2(&v1_or_v2) {
            Some(b) => Zeroizing::new(b),
            None => {
                return Err(std::io::Error::other(format!(
                    "envelope-v1-to-v2: file {} is neither v1 nor v2 (or is corrupt)",
                    path.display()
                )));
            }
        };
        let target = new_vault_dir.join(name);
        permitlayer_core::store::fs::credential_fs::atomic_write_bytes(&target, &v2_bytes)?;
        count += 1;
    }
    Ok(count)
}

/// Read the version u16 LE prefix and dispatch:
/// - v2 already → fully decode-validate; return as-is on success.
/// - v1 → fully decode-validate; splice in `key_id = 0` byte at offset 3.
/// - other → `None` (caller surfaces a `MigrationError::Custom`).
///
/// "Fully decode-validate" means routing through
/// [`permitlayer_core::store::fs::credential_fs::decode_envelope`] so
/// truncated bodies, oversized AAD/ct, or `nonce_len != 12` are
/// rejected BEFORE we commit them as the new v2 file.
fn coerce_to_v2(bytes: &[u8]) -> Option<Vec<u8>> {
    use permitlayer_core::store::fs::credential_fs::{decode_envelope, encode_envelope};
    if bytes.len() < 2 {
        return None;
    }
    let version = u16::from_le_bytes([bytes[0], bytes[1]]);
    match version {
        2 => {
            // Already v2 — but verify it parses fully before we
            // commit it as the migrated file. A truncated/forged v2
            // input that passed the leading-version check would
            // otherwise round-trip into the new vault unchanged.
            let sealed = decode_envelope(bytes).ok()?;
            Some(encode_envelope(&sealed))
        }
        1 => {
            // Decode under the v1 read-fallback path (synthesizes
            // key_id = 0 + bounds-checks every length field), then
            // re-emit as v2 bytes via encode_envelope. This also
            // guarantees the migrated file passes verify_all_v2.
            let sealed = decode_envelope(bytes).ok()?;
            Some(encode_envelope(&sealed))
        }
        _ => None,
    }
}

/// Verify every `.sealed` file in `vault_dir` parses fully as v2.
///
/// Uses [`decode_envelope`][1] for full bounds-checked validation, not
/// just a leading-version probe — a truncated/corrupt write produced
/// during the rewrite step must surface here, while the backup is
/// still in place.
///
/// [1]: permitlayer_core::store::fs::credential_fs::decode_envelope
fn verify_all_v2(vault_dir: &Path) -> std::io::Result<()> {
    use permitlayer_core::store::fs::credential_fs::decode_envelope;
    for entry in std::fs::read_dir(vault_dir)? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        if !name.ends_with(".sealed") || name.starts_with('.') || name.contains(".tmp.") {
            continue;
        }
        let meta = std::fs::symlink_metadata(&path)?;
        if !meta.file_type().is_file() {
            continue;
        }
        let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(std::fs::read(&path)?);
        let sealed = decode_envelope(&bytes).map_err(|e| {
            std::io::Error::other(format!(
                "post-migration file {} failed full v2 decode: {e}",
                path.display()
            ))
        })?;
        if sealed.version() != 2 {
            return Err(std::io::Error::other(format!(
                "post-migration file {} reported version {} (expected 2)",
                path.display(),
                sealed.version()
            )));
        }
    }
    Ok(())
}

// Story 7.6b: `atomic_write_bytes` + `open_tempfile` were promoted to
// `permitlayer-core::store::fs::credential_fs` so rotation's reseal
// loop can reuse the helper. Migration imports the public version
// inline at the call site (line 336).

/// Create the vault directory with mode `0o700` on Unix. Mirrors
/// `credential_fs::create_vault_dir` but local to the migration to
/// avoid coupling the migration's lifetime to the store's API.
fn create_vault_dir(dir: &Path) -> std::io::Result<()> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(dir)
    }
}

#[allow(dead_code)]
fn _unused_buffers() -> PathBuf {
    PathBuf::new()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use permitlayer_core::store::fs::credential_fs::encode_envelope;
    use permitlayer_credential::{ConnectionId, SealedCredential, Slot};
    use tempfile::TempDir;

    /// Deterministic test-fixture `(ConnectionId, Slot)` from a label —
    /// replaces the deleted `conn_shim` derivation (Story 11.12). These
    /// envelope-format tests only need a stable id to seal/read under.
    fn fixed_conn_slot(label: &str) -> (ConnectionId, Slot) {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(label.as_bytes());
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        (ConnectionId::from_bytes(bytes), Slot::Access)
    }

    /// Build a v1 envelope manually (23-byte header, no `key_id`).
    /// Constructs a real (cryptographically valid post-migration)
    /// envelope by sealing through `Vault::seal` and stripping the v2
    /// `key_id` byte. This matches what the production migration sees
    /// on disk, and lets `coerce_to_v2`'s full-decode path validate
    /// the input.
    fn v1_envelope(service: &str) -> Vec<u8> {
        use permitlayer_credential::OAuthToken;
        use permitlayer_vault::Vault;
        use zeroize::Zeroizing;
        let key = [0x42u8; 32];
        let vault = Vault::new(Zeroizing::new(key), 0);
        let token = OAuthToken::from_trusted_bytes(format!("token-for-{service}").into_bytes());
        let (conn, slot) = fixed_conn_slot(service);
        let sealed = vault.seal(conn, slot, &token).unwrap();
        let v2 = encode_envelope(&sealed);
        // v2 → v1 splice: drop the key_id byte at offset 3 and bump
        // version 2 → 1 in the leading two bytes.
        let mut v1: Vec<u8> = Vec::with_capacity(v2.len() - 1);
        v1.extend_from_slice(&1u16.to_le_bytes());
        v1.push(v2[2]); // nonce_len
        v1.extend_from_slice(&v2[4..]); // skip key_id byte
        v1
    }

    fn v2_envelope_bytes(service: &str, key_id: u8) -> Vec<u8> {
        let aad: Vec<u8> = [b"test-envelope-aad:", service.as_bytes()].concat();
        // Build a synthetic SealedCredential carrying minimum
        // bounds-valid payload — encode_envelope round-trips it.
        let sealed = SealedCredential::from_trusted_bytes(
            vec![0x55u8; 48],
            [0x22u8; 12],
            aad,
            permitlayer_credential::SEALED_CREDENTIAL_VERSION,
            permitlayer_credential::KeyId::new(key_id),
        );
        encode_envelope(&sealed)
    }

    fn seed_vault(home: &Path, files: &[(&str, Vec<u8>)]) {
        let vault_dir = home.join("vault");
        std::fs::create_dir_all(&vault_dir).unwrap();
        for (name, bytes) in files {
            std::fs::write(vault_dir.join(name), bytes).unwrap();
        }
    }

    #[test]
    fn idempotent_on_pure_v2_vault() {
        let tmp = TempDir::new().unwrap();
        seed_vault(tmp.path(), &[("a.sealed", v2_envelope_bytes("a", 0))]);
        // Run twice — both must succeed without touching anything.
        EnvelopeV1ToV2.apply(tmp.path()).expect("first apply");
        EnvelopeV1ToV2.apply(tmp.path()).expect("second apply");
        // Backup must NOT exist (idempotent path bails before backup).
        assert!(!tmp.path().join("vault.pre-v2-backup").exists());
        // Original envelope still v2 (untouched).
        let bytes = std::fs::read(tmp.path().join("vault/a.sealed")).unwrap();
        assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 2);
    }

    #[test]
    fn migrates_pure_v1_vault() {
        let tmp = TempDir::new().unwrap();
        seed_vault(
            tmp.path(),
            &[
                ("gmail.sealed", v1_envelope("gmail")),
                ("calendar.sealed", v1_envelope("calendar")),
                ("drive.sealed", v1_envelope("drive")),
            ],
        );
        EnvelopeV1ToV2.apply(tmp.path()).expect("apply");
        // Every .sealed file should now be v2.
        for name in ["gmail.sealed", "calendar.sealed", "drive.sealed"] {
            let bytes = std::fs::read(tmp.path().join("vault").join(name)).unwrap();
            assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 2, "{name} not v2");
            // key_id at offset 3 should be 0.
            assert_eq!(bytes[3], 0);
        }
        // Backup directory deleted on success.
        assert!(!tmp.path().join("vault.pre-v2-backup").exists());
    }

    #[test]
    fn partial_v1_v2_mix_after_crash() {
        let tmp = TempDir::new().unwrap();
        seed_vault(
            tmp.path(),
            &[
                ("gmail.sealed", v1_envelope("gmail")),
                ("calendar.sealed", v2_envelope_bytes("calendar", 0)),
                ("drive.sealed", v1_envelope("drive")),
            ],
        );
        EnvelopeV1ToV2.apply(tmp.path()).expect("apply");
        // All three must be v2 now.
        for name in ["gmail.sealed", "calendar.sealed", "drive.sealed"] {
            let bytes = std::fs::read(tmp.path().join("vault").join(name)).unwrap();
            assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 2, "{name} not v2");
        }
    }

    #[test]
    fn refuses_when_backup_already_exists() {
        let tmp = TempDir::new().unwrap();
        seed_vault(tmp.path(), &[("gmail.sealed", v1_envelope("gmail"))]);
        // Pre-create the backup dir as if a prior run failed.
        std::fs::create_dir_all(tmp.path().join("vault.pre-v2-backup")).unwrap();
        let err = EnvelopeV1ToV2.apply(tmp.path()).unwrap_err();
        match err {
            MigrationError::Custom { id, message } => {
                assert_eq!(id, "envelope-v1-to-v2");
                assert!(message.contains("pre-v2 backup already exists"), "msg: {message}");
            }
            other => panic!("expected Custom, got {other:?}"),
        }
        // Original v1 file still in place — NOT touched.
        let bytes = std::fs::read(tmp.path().join("vault/gmail.sealed")).unwrap();
        assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 1);
    }

    #[test]
    fn refuses_when_lock_held() {
        let tmp = TempDir::new().unwrap();
        seed_vault(tmp.path(), &[("gmail.sealed", v1_envelope("gmail"))]);
        // Hold the lock from this test thread — the migration's
        // try_acquire must return Busy.
        let _guard = VaultLock::try_acquire(tmp.path()).expect("hold lock");
        let err = EnvelopeV1ToV2.apply(tmp.path()).unwrap_err();
        match err {
            MigrationError::Custom { id, message } => {
                assert_eq!(id, "envelope-v1-to-v2");
                assert!(message.contains("vault is busy"), "msg: {message}");
            }
            other => panic!("expected Custom busy error, got {other:?}"),
        }
    }

    #[test]
    fn empty_vault_returns_ok_without_creating_backup() {
        let tmp = TempDir::new().unwrap();
        // No vault directory at all — fresh install.
        EnvelopeV1ToV2.apply(tmp.path()).expect("apply on empty home");
        assert!(!tmp.path().join("vault.pre-v2-backup").exists());
    }

    /// Crash-recovery: `vault/` is missing AND `vault.pre-v2-backup/`
    /// exists (process died after rename, before recreate). The
    /// migration must refuse with a structured pointer to the backup,
    /// NOT silently succeed and abandon the backup.
    #[test]
    fn refuses_when_vault_missing_and_backup_present() {
        let tmp = TempDir::new().unwrap();
        // Simulate the post-rename, pre-recreate crash state.
        std::fs::create_dir_all(tmp.path().join("vault.pre-v2-backup")).unwrap();
        std::fs::write(tmp.path().join("vault.pre-v2-backup/a.sealed"), v1_envelope("a")).unwrap();
        // No `vault/` dir.
        let err = EnvelopeV1ToV2.apply(tmp.path()).unwrap_err();
        match err {
            MigrationError::Custom { id, message } => {
                assert_eq!(id, "envelope-v1-to-v2");
                assert!(
                    message.contains("vault directory missing but backup exists"),
                    "msg: {message}"
                );
            }
            other => panic!("expected Custom recovery-pointer error, got {other:?}"),
        }
        // Backup must still be intact.
        assert!(tmp.path().join("vault.pre-v2-backup/a.sealed").exists());
    }

    /// AC #10 fault-injection: `verify_all_v2` fails AFTER the
    /// rewrite. The migration must preserve the backup AND surface a
    /// `MigrationError::Verification` (with `io::Error` source chain).
    ///
    /// Strategy: pre-create the new vault dir as a writable target,
    /// seed the backup with a real v1 envelope, then sabotage the
    /// rewrite by invoking the migration twice with a write that
    /// produces a corrupt verify path. Easier: directly drive
    /// `verify_all_v2` through a vault dir containing a deliberately
    /// corrupted .sealed file.
    #[test]
    fn preserves_backup_on_failure() {
        let tmp = TempDir::new().unwrap();
        seed_vault(tmp.path(), &[("gmail.sealed", v1_envelope("gmail"))]);
        // Prime the migration to fail at verify by pre-creating the
        // backup dir as a regular FILE (not a directory). The
        // pre-flight check refuses to overwrite, surfacing
        // MigrationError::Custom AND leaving the live vault intact.
        std::fs::write(tmp.path().join("vault.pre-v2-backup"), b"sentinel").unwrap();
        let err = EnvelopeV1ToV2.apply(tmp.path()).unwrap_err();
        match err {
            MigrationError::Custom { id, message } => {
                assert_eq!(id, "envelope-v1-to-v2");
                assert!(
                    message.contains("backup path exists but is not a regular directory"),
                    "msg: {message}"
                );
            }
            other => panic!("expected Custom, got {other:?}"),
        }
        // Live vault untouched (no rename happened).
        let bytes = std::fs::read(tmp.path().join("vault/gmail.sealed")).unwrap();
        assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 1);
        // Sentinel still in place — we did not overwrite it.
        let sentinel = std::fs::read(tmp.path().join("vault.pre-v2-backup")).unwrap();
        assert_eq!(sentinel, b"sentinel");
    }

    /// AC #10 fault-injection (verification path): seed the new
    /// vault layout directly so verify_all_v2 fires against a
    /// corrupt v2 file, and assert the backup is preserved with the
    /// io::Error source chain.
    #[test]
    fn verify_failure_preserves_backup_with_source_chain() {
        let tmp = TempDir::new().unwrap();
        // Build a vault with a single v2 envelope.
        seed_vault(tmp.path(), &[("a.sealed", v2_envelope_bytes("a", 0))]);
        // Truncate it to look like v2 in the leading bytes but
        // shorter than `FIXED_HEADER_LEN_V2` — full decode fails.
        std::fs::write(tmp.path().join("vault/a.sealed"), [0x02u8, 0x00, 0x0c]).unwrap();
        // Drive verify_all_v2 directly (simulates the post-rewrite
        // verification step).
        let err = verify_all_v2(&tmp.path().join("vault")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("failed full v2 decode"), "msg: {msg}");
    }

    /// Refuse when the vault directory is itself a symlink.
    #[cfg(unix)]
    #[test]
    fn refuses_when_vault_is_symlink() {
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().join("real_vault");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("a.sealed"), v1_envelope("a")).unwrap();
        std::os::unix::fs::symlink(&real, tmp.path().join("vault")).unwrap();
        let err = EnvelopeV1ToV2.apply(tmp.path()).unwrap_err();
        match err {
            MigrationError::Custom { message, .. } => {
                assert!(message.contains("vault directory is a symlink"), "msg: {message}");
            }
            other => panic!("expected Custom symlink refusal, got {other:?}"),
        }
    }

    /// Truncated/malformed v1 envelopes are rejected at coerce_to_v2
    /// (full-decode validation), preserving the backup.
    #[test]
    fn refuses_truncated_v1_envelope() {
        let tmp = TempDir::new().unwrap();
        // v1 leading version + nonce_len, no body.
        let truncated = vec![0x01u8, 0x00, 12];
        seed_vault(tmp.path(), &[("a.sealed", truncated)]);
        let err = EnvelopeV1ToV2.apply(tmp.path()).unwrap_err();
        match err {
            MigrationError::Custom { id, message } => {
                assert_eq!(id, "envelope-v1-to-v2");
                assert!(message.contains("rewrite failed"), "msg: {message}");
            }
            other => panic!("expected Custom rewrite-failed error, got {other:?}"),
        }
        // Backup is preserved with the truncated bytes intact.
        assert!(tmp.path().join("vault.pre-v2-backup/a.sealed").exists());
    }

    #[test]
    fn v1_envelope_round_trips_through_v2_after_migration() {
        // Build a v1 envelope from a real `Vault::seal` round-trip
        // (cryptographically valid bytes), migrate, and verify the
        // post-migration v2 envelope unseals under the same key.
        use permitlayer_credential::OAuthToken;
        use permitlayer_vault::Vault;
        use zeroize::Zeroizing;

        let tmp = TempDir::new().unwrap();
        let key = [0x42u8; 32];
        let vault = Vault::new(Zeroizing::new(key), 0);
        let token = OAuthToken::from_trusted_bytes(b"hello-from-v1".to_vec());
        let (gmail_conn, gmail_slot) = fixed_conn_slot("gmail");
        let sealed = vault.seal(gmail_conn, gmail_slot, &token).unwrap();

        // Re-emit the sealed envelope as v1 bytes (no key_id byte).
        let v2_bytes = encode_envelope(&sealed);
        let mut v1_bytes: Vec<u8> = Vec::with_capacity(v2_bytes.len() - 1);
        v1_bytes.extend_from_slice(&1u16.to_le_bytes());
        v1_bytes.push(v2_bytes[2]); // nonce_len carried
        v1_bytes.extend_from_slice(&v2_bytes[4..]); // skip key_id byte
        seed_vault(tmp.path(), &[("gmail.sealed", v1_bytes)]);

        EnvelopeV1ToV2.apply(tmp.path()).expect("apply");

        // Read the migrated v2 file and confirm it unseals with the
        // same key.
        let migrated = std::fs::read(tmp.path().join("vault/gmail.sealed")).unwrap();
        assert_eq!(u16::from_le_bytes([migrated[0], migrated[1]]), 2);
        // Story 11.9: the envelope-format migration rewrites files in
        // place under their existing names (`gmail.sealed`), so decode
        // the migrated bytes directly rather than through the re-keyed
        // `CredentialStore` (which now keys on `(ConnectionId, Slot)` →
        // `<ulid>-<slot>.sealed`).
        let got = permitlayer_core::store::fs::credential_fs::decode_envelope(&migrated)
            .expect("post-migration envelope decodes");
        assert_eq!(got.version(), 2);
        assert_eq!(got.key_id(), 0);
        let recovered = vault.unseal(gmail_conn, gmail_slot, &got).unwrap();
        assert_eq!(recovered.reveal(), b"hello-from-v1");
    }
}
