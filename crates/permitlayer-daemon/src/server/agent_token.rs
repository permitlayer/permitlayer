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

use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::OwnedFd;
use std::path::{Path, PathBuf};

use nix::unistd::{Gid, Uid, User};
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
    /// Story 7.27 Round-2 review fix (P2): the `Display` impl
    /// previously included the full PathBuf (e.g.,
    /// `/Users/alice/.agentsso/agent-bearer.token`) which leaked
    /// the operator's home-dir layout / username into audit logs
    /// and JSON response bodies. The path is still carried in the
    /// variant for in-process debugging (Debug impl) but only the
    /// final filename is surfaced via Display. Operators correlate
    /// via `peer_uid` (already in the audit event payload) instead
    /// of the path.
    #[error("refusing to write through symlinked parent directory for token file `{}`", .0.file_name().and_then(|s| s.to_str()).unwrap_or("<unknown>"))]
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

    // (2+3) Acquire a dir fd to `<home>/.agentsso/` with O_NOFOLLOW |
    //       O_DIRECTORY. All subsequent ops (fchown, fchmod, renameat)
    //       run against the dir fd, so symlink defense holds across
    //       the whole sequence — an attacker swapping `<home>/.agentsso`
    //       to a symlink AFTER the openat does not affect the inode the
    //       dir fd points at, and an attacker pre-creating a symlink
    //       BEFORE the openat causes the open itself to fail with ELOOP.
    //       Story 7.27 review fix: closes the prior gap where the
    //       lstat check and `chown`+`set_permissions` were separate
    //       syscalls that followed symlinks.
    let dot_fd = open_dot_agentsso_nofollow(&dot_agentsso, peer_uid, peer_gid)?;

    // (4) Create tmp file under daemon's own state dir. The tmp file
    //     lives in `<state>/.tokens/` which is root-only-writable, so
    //     symlink defense on the tmp side is structural (no
    //     unprivileged user can manipulate this path).
    let tokens_dir = daemon_state_dir.join(".tokens");
    std::fs::create_dir_all(&tokens_dir)?;
    let tokens_fd = permitlayer_platform_macos::open_dir_nofollow(&tokens_dir)?;

    // Round-2 review fix: per-target advisory lock around the
    // tmp+rename critical section. Two concurrent `register-agent`
    // requests for the same peer UID would otherwise both fail
    // `rename_excl_at` with EEXIST and race each other on the plain-
    // `rename_at` fallback, leaving the on-disk token belonging to
    // whoever-rotated-last while both callers received a 200 with
    // their own (different) tokens. The lockfile sits in the
    // root-only-writable `.tokens/` dir, one per peer UID; the
    // `flock` is released when `_rotation_lock` drops at end of
    // scope.
    let _rotation_lock = acquire_rotation_lock(&tokens_dir, peer_uid)?;

    let tmp_name = format!("agent-bearer.token.tmp.{}.{}", std::process::id(), random_suffix());
    let tmp_path = tokens_dir.join(&tmp_name);
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

    // (6+7) Chown the tmp inode via its path (it lives in a
    //       root-only-writable dir, so path-based chown is safe here).
    nix::unistd::chown(&tmp_path, Some(Uid::from_raw(peer_uid)), Some(Gid::from_raw(peer_gid)))
        .map_err(TokenWriteError::Chown)?;
    std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;

    // (8) renameatx_np(RENAME_EXCL) anchored on dir fds. Both src and
    //     dst are resolved relative to the daemon-held dir fds, NOT
    //     via path traversal that could follow attacker-swapped
    //     symlinks. On EEXIST, emit no audit-event here (caller does)
    //     and fall through to plain `renameat` for the rotation case
    //     — also anchored on dir fds so the symlink-defense extends
    //     across the rotation flow.
    let replace_existing = match permitlayer_platform_macos::rename_excl_at(
        tokens_fd.as_raw_fd(),
        &tmp_name,
        dot_fd.as_raw_fd(),
        "agent-bearer.token",
    ) {
        Ok(()) => false,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Rotation flow: existing token replaced. Anchored
            // renameat preserves symlink defense.
            permitlayer_platform_macos::rename_at(
                tokens_fd.as_raw_fd(),
                &tmp_name,
                dot_fd.as_raw_fd(),
                "agent-bearer.token",
            )
            .map_err(TokenWriteError::Io)?;
            true
        }
        Err(e) => {
            // Failed for some other reason (EPERM, ENOSPC, ...).
            // Best-effort cleanup of the tmp file.
            let _ = std::fs::remove_file(&tmp_path);
            return Err(TokenWriteError::Io(e));
        }
    };

    // Defense-in-depth verification: the file we just renamed into
    // place must be (a) owned by the peer, (b) a regular file, and
    // (c) mode 0600 exactly. If a kernel bug or unexpected mount
    // behavior allowed the rename to land on the wrong inode, OR an
    // attacker won a race against the rename-anchoring with a peer-
    // owned FIFO/device/world-readable substitute, these checks
    // catch it. Use fstatat anchored on dir_fd so we do NOT re-
    // traverse the path.
    let meta =
        permitlayer_platform_macos::fstatat_nofollow(dot_fd.as_raw_fd(), "agent-bearer.token")?;
    let mode = meta.st_mode;
    let is_regular = (mode & libc::S_IFMT) == libc::S_IFREG;
    let perms = mode & 0o777;
    if meta.st_uid != peer_uid || !is_regular || perms != 0o600 {
        let _ =
            permitlayer_platform_macos::unlinkat_dir_fd(dot_fd.as_raw_fd(), "agent-bearer.token");
        return Err(TokenWriteError::SymlinkInParentPath(dot_agentsso.join("agent-bearer.token")));
    }

    Ok(TokenWriteOutcome { target_path: dot_agentsso.join("agent-bearer.token"), replace_existing })
}

/// Per-peer-UID advisory lockfile sitting in the daemon's
/// root-only-writable `.tokens/` dir. Acquired with `LOCK_EX` so
/// concurrent `register-agent` calls for the same peer serialize
/// across the tmp-create + rename-or-rotate critical section.
///
/// The returned `Flock<File>` releases the lock on drop (RAII). The
/// lockfile itself is left in place for next time — removing it
/// would create a TOCTOU window where two processes could each
/// open-and-flock a fresh inode.
fn acquire_rotation_lock(
    tokens_dir: &Path,
    peer_uid: u32,
) -> Result<nix::fcntl::Flock<std::fs::File>, TokenWriteError> {
    let lock_path = tokens_dir.join(format!("agent-bearer.token.lock.{peer_uid}"));
    let lock_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(&lock_path)?;
    nix::fcntl::Flock::lock(lock_file, nix::fcntl::FlockArg::LockExclusive).map_err(
        |(_file, errno)| TokenWriteError::Io(std::io::Error::from_raw_os_error(errno as i32)),
    )
}

/// Open `<home>/.agentsso/` with O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC.
/// If the dir does not exist, create it (chown peer:peer_gid, chmod
/// 0700) and then open it. The create-then-open sequence is the only
/// remaining window where symlink defense is path-based; we mitigate
/// by acquiring the dir fd immediately after create and applying
/// fchown/fchmod through the fd, never the path.
fn open_dot_agentsso_nofollow(
    dot_agentsso: &Path,
    peer_uid: u32,
    peer_gid: u32,
) -> Result<OwnedFd, TokenWriteError> {
    // Darwin returns ELOOP for symlink-to-nondir under O_NOFOLLOW,
    // ENOTDIR for symlink-to-dir under O_DIRECTORY|O_NOFOLLOW. Both
    // mean "this path traversed a symlink — refuse" for our purposes.
    fn is_symlink_refusal(err: &std::io::Error) -> bool {
        matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR))
    }
    match permitlayer_platform_macos::open_dir_nofollow(dot_agentsso) {
        Ok(fd) => {
            // Story 7.27 Round-2 review fix (P2): correct an
            // existing `.agentsso/` dir's mode/owner if a prior
            // tool created it with permissive perms or wrong
            // ownership. Self-healing: chown to the peer + chmod
            // 0o700 unconditionally. Pre-fix, an attacker who
            // could pre-create a world-readable `.agentsso/` in
            // the peer's home would see the token file inherit
            // the parent dir's loose perms (defense-in-depth on
            // parent perms was best-effort only on first-create).
            // The peer's home is peer-owned by convention; this
            // self-heal is a no-op on a healthy install.
            permitlayer_platform_macos::fchown_fd(fd.as_raw_fd(), peer_uid, peer_gid)
                .map_err(TokenWriteError::Io)?;
            permitlayer_platform_macos::fchmod_fd(fd.as_raw_fd(), 0o700)
                .map_err(TokenWriteError::Io)?;
            Ok(fd)
        }
        Err(e) if is_symlink_refusal(&e) => {
            Err(TokenWriteError::SymlinkInParentPath(dot_agentsso.to_path_buf()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Story 7.27 Round-2 review fix (P2): create the dir
            // with explicit mode 0o700 via `DirBuilder` so the
            // umask-022-default 0o755 window between create and
            // the post-open `fchmod_fd(0o700)` is closed. Pre-fix,
            // a sibling process running as the peer UID could
            // enumerate `<home>/.agentsso/` for a brief window
            // before the chmod-0o700 landed.
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(0o700).create(dot_agentsso)?;
            let fd = permitlayer_platform_macos::open_dir_nofollow(dot_agentsso).map_err(|e| {
                if is_symlink_refusal(&e) {
                    TokenWriteError::SymlinkInParentPath(dot_agentsso.to_path_buf())
                } else {
                    TokenWriteError::Io(e)
                }
            })?;
            permitlayer_platform_macos::fchown_fd(fd.as_raw_fd(), peer_uid, peer_gid)
                .map_err(TokenWriteError::Io)?;
            // Defense-in-depth: re-assert 0o700 via fchmod_fd in
            // case `DirBuilder::mode` was lossy on some macOS path
            // (it's not, but the cost of one extra syscall is
            // trivial and the fchown_fd above might have widened
            // the perms on some BSD variants).
            permitlayer_platform_macos::fchmod_fd(fd.as_raw_fd(), 0o700)
                .map_err(TokenWriteError::Io)?;
            Ok(fd)
        }
        Err(e) => Err(TokenWriteError::Io(e)),
    }
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
