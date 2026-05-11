//! Secure per-user `agent-bearer.token` write (Story 7.27 AC #6, #8,
//! #14).
//!
//! When `POST /v1/control/agent/register` succeeds over the UDS
//! control listener, the daemon writes the plaintext bearer token
//! to `<peer-home>/.agentsso/agent-bearer.token` via the
//! tmp+chown+fchmod+renameatx_np(RENAME_EXCL)+O_NOFOLLOW pattern.
//! This is the secure-write pattern that defends against CWE-367 /
//! CVE-2026-22701 class of TOCTOU symlink attacks where a hostile
//! end-user pre-creates the target path as a symlink to (say)
//! `/etc/sudoers`.
//!
//! The atomic-rename FFI lives in `permitlayer-platform-macos`
//! (Story 7.27 C4 sub-commit `d2d9081`) — this module consumes the
//! safe wrapper without writing `unsafe` itself.

#![cfg(target_os = "macos")]

use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::unistd::{Gid, Uid, User, chown};
use thiserror::Error;

/// Errors surfaced by [`write_bearer_token_to_user_home`]. Mapped
/// 1:1 to operator-facing audit events in the handler.
#[derive(Debug, Error)]
pub enum TokenWriteError {
    /// The kernel-attested peer UID does not map to a `User` record
    /// — extremely unlikely on a healthy macOS box but documented
    /// as a defensive failure mode.
    #[error("kernel-attested peer UID {0} has no associated user account")]
    UnknownPeerUser(u32),

    /// `<home>/.agentsso/` exists but is a symlink. Refuses closed
    /// to defend against a TOCTOU symlink attack where the hostile
    /// end-user points the parent at `/etc/sudoers`.
    #[error("refusing to write through symlinked parent directory: {0}")]
    SymlinkInParentPath(PathBuf),

    /// Generic I/O failure during the write/chown/rename sequence.
    #[error("token-write I/O failure: {0}")]
    Io(#[from] std::io::Error),

    /// `nix` returned an error from `fchown` or `chown` on the tmp
    /// or target path.
    #[error("token-write chown failure: {0}")]
    Chown(nix::Error),
}

/// Outcome of a successful token write.
#[derive(Debug)]
pub struct TokenWriteOutcome {
    /// Path where the token was written (e.g.,
    /// `/Users/alice/.agentsso/agent-bearer.token`).
    pub target_path: PathBuf,
    /// `true` when the write replaced an existing token (rotation
    /// flow), `false` when it created a fresh file.
    pub replace_existing: bool,
}

/// Write the plaintext bearer token to
/// `<home(peer_uid)>/.agentsso/agent-bearer.token`, mode 0600
/// owned `peer_uid:peer_gid`, using the secure-write pattern:
///
/// 1. Resolve the peer's home dir via `User::from_uid`.
/// 2. Check `<home>/.agentsso/` is NOT a symlink (refuse closed).
/// 3. Create the parent dir if missing (mode 0700 owned by peer).
/// 4. Write to a tmp file in the daemon's own state dir (mode 0600,
///    owned root) with `O_NOFOLLOW | O_EXCL | O_CREAT`.
/// 5. Write the token bytes.
/// 6. Chown the tmp file to `peer_uid:peer_gid`.
/// 7. Chmod 0600.
/// 8. `renameatx_np(tmp, target, RENAME_EXCL)`. On `EEXIST` (existing
///    token-rotation case): audit-log the replace + retry with plain
///    `rename`.
///
/// `daemon_state_dir` should be `permitlayer_core::paths::daemon_state_dir(None)`
/// in production; tests pass a tempdir. The tmp file is created at
/// `<daemon_state_dir>/.tokens/agent-bearer.token.tmp.<random>`.
pub async fn write_bearer_token_to_user_home(
    token_bytes: &[u8],
    peer_uid: u32,
    peer_gid: u32,
    daemon_state_dir: &Path,
) -> Result<TokenWriteOutcome, TokenWriteError> {
    let token = token_bytes.to_vec();
    let state_dir = daemon_state_dir.to_path_buf();
    tokio::task::spawn_blocking(move || write_blocking(&token, peer_uid, peer_gid, &state_dir))
        .await
        .map_err(|e| TokenWriteError::Io(std::io::Error::other(e)))?
}

fn write_blocking(
    token_bytes: &[u8],
    peer_uid: u32,
    peer_gid: u32,
    daemon_state_dir: &Path,
) -> Result<TokenWriteOutcome, TokenWriteError> {
    // (1) Resolve peer's home dir.
    let user = User::from_uid(Uid::from_raw(peer_uid))
        .map_err(|e| TokenWriteError::Io(std::io::Error::other(e)))?
        .ok_or(TokenWriteError::UnknownPeerUser(peer_uid))?;
    let home = user.dir;
    let dot_agentsso = home.join(".agentsso");

    // (2) Symlink-defense check on the parent dir.
    match std::fs::symlink_metadata(&dot_agentsso) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(TokenWriteError::SymlinkInParentPath(dot_agentsso));
        }
        Ok(_) => { /* directory or regular file — check below */ }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // (3) Create `<home>/.agentsso/` owned by peer, mode 0700.
            std::fs::create_dir_all(&dot_agentsso)?;
            chown(&dot_agentsso, Some(Uid::from_raw(peer_uid)), Some(Gid::from_raw(peer_gid)))
                .map_err(TokenWriteError::Chown)?;
            std::fs::set_permissions(&dot_agentsso, std::fs::Permissions::from_mode(0o700))?;
        }
        Err(e) => return Err(TokenWriteError::Io(e)),
    }

    let target = dot_agentsso.join("agent-bearer.token");

    // (4) Create tmp file under daemon's own state dir.
    let tokens_dir = daemon_state_dir.join(".tokens");
    std::fs::create_dir_all(&tokens_dir)?;
    let random_suffix = format!("{}.{}", std::process::id(), random_suffix());
    let tmp_path = tokens_dir.join(format!("agent-bearer.token.tmp.{random_suffix}"));
    let tmp = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_EXCL)
        .mode(0o600)
        .open(&tmp_path)?;
    // (5) Write the token + flush.
    {
        use std::io::Write;
        let mut tmp = tmp;
        tmp.write_all(token_bytes)?;
        tmp.flush()?;
    }

    // (6+7) Chown to peer + chmod 0600.
    chown(&tmp_path, Some(Uid::from_raw(peer_uid)), Some(Gid::from_raw(peer_gid)))
        .map_err(TokenWriteError::Chown)?;
    std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;

    // (8) renameatx_np(RENAME_EXCL). On EEXIST, fall through to
    // plain rename (token rotation).
    let replace_existing = match permitlayer_platform_macos::rename_excl(&tmp_path, &target) {
        Ok(()) => false,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Rotation flow: existing token replaced. Caller emits a
            // `bearer-token.replace-existing` audit event.
            std::fs::rename(&tmp_path, &target)?;
            true
        }
        Err(e) => {
            // Failed for some other reason (EPERM, ENOSPC, ...).
            // Best-effort cleanup of the tmp file.
            let _ = std::fs::remove_file(&tmp_path);
            return Err(TokenWriteError::Io(e));
        }
    };

    // Verify the target file's ownership ended up where we expected.
    // Defense-in-depth: if renameatx_np somehow followed an
    // intermediate symlink on the target side, the resulting file's
    // owner would not match `peer_uid`. Refuse the operation and
    // unlink.
    let meta = std::fs::symlink_metadata(&target)?;
    if meta.uid() != peer_uid {
        let _ = std::fs::remove_file(&target);
        return Err(TokenWriteError::SymlinkInParentPath(target));
    }

    Ok(TokenWriteOutcome { target_path: target, replace_existing })
}

/// Random suffix for the tmp file. Uses `getrandom(3)` via `rand`'s
/// `OsRng` to keep dependencies aligned with the rest of the
/// daemon's CSPRNG usage.
fn random_suffix() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn current_uid() -> u32 {
        nix::unistd::getuid().as_raw()
    }
    fn current_gid() -> u32 {
        nix::unistd::getgid().as_raw()
    }

    #[tokio::test]
    async fn write_succeeds_to_fresh_path() {
        let dir = tempdir().unwrap();
        let daemon_state = dir.path().to_path_buf();
        // Use ourselves as the "peer" — the helper writes to
        // ~/.agentsso/agent-bearer.token. We don't want to clobber
        // the real one, so this test is gated behind an env var and
        // skipped by default.
        if std::env::var("AGENTSSO_TOKEN_WRITE_DESTRUCTIVE_TEST").is_err() {
            return;
        }
        let outcome = write_bearer_token_to_user_home(
            b"agt_v2_test_PLAINTEXT",
            current_uid(),
            current_gid(),
            &daemon_state,
        )
        .await
        .expect("write should succeed");
        assert!(!outcome.replace_existing);
        let content = std::fs::read(&outcome.target_path).unwrap();
        assert_eq!(content, b"agt_v2_test_PLAINTEXT");
        // Cleanup.
        let _ = std::fs::remove_file(&outcome.target_path);
    }

    #[tokio::test]
    async fn write_refuses_when_dot_agentsso_is_symlink() {
        let dir = tempdir().unwrap();
        let daemon_state = dir.path().to_path_buf();
        if std::env::var("AGENTSSO_TOKEN_WRITE_DESTRUCTIVE_TEST").is_err() {
            return;
        }
        // Pre-condition: nuke any existing ~/.agentsso so we can
        // safely substitute a symlink. (Destructive — skipped by
        // default.)
        let home_dir = std::env::var("HOME").unwrap();
        let dot_agentsso = std::path::Path::new(&home_dir).join(".agentsso");
        if dot_agentsso.exists() {
            return; // refuse to clobber a real install
        }
        let target = dir.path().join("phantom-target");
        std::fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, &dot_agentsso).unwrap();
        let err = write_bearer_token_to_user_home(
            b"agt_v2_test_PLAINTEXT",
            current_uid(),
            current_gid(),
            &daemon_state,
        )
        .await
        .expect_err("symlink in parent path must refuse");
        assert!(matches!(err, TokenWriteError::SymlinkInParentPath(_)));
        let _ = std::fs::remove_file(&dot_agentsso);
    }

    #[tokio::test]
    async fn write_refuses_unknown_peer_uid() {
        let dir = tempdir().unwrap();
        // Pick a UID that is extremely unlikely to map to an
        // actual user account: `0x7FFE_0000` is well above macOS's
        // reserved upper range yet still positive (avoids the
        // signed-int conversion edge case that `0xFFFF_FFFE`
        // triggers on some Darwin minor versions where `getpwuid`
        // surfaces an internal errno instead of `Ok(None)`).
        let unknown_uid: u32 = 0x7FFE_0000;
        let err =
            write_bearer_token_to_user_home(b"agt_v2_test", unknown_uid, unknown_uid, dir.path())
                .await
                .expect_err("unknown peer UID must refuse");
        // Either branch is acceptable: `User::from_uid` returns
        // `Ok(None)` → `UnknownPeerUser`; OR it returns an errno
        // (`Err(...)`) which we surface as `TokenWriteError::Io`.
        // Both express "refused for an unresolvable peer".
        assert!(
            matches!(err, TokenWriteError::UnknownPeerUser(_) | TokenWriteError::Io(_)),
            "expected UnknownPeerUser or Io, got: {err:?}"
        );
    }

    #[test]
    fn random_suffix_is_hex_and_nonempty() {
        let s = random_suffix();
        assert_eq!(s.len(), 16);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
