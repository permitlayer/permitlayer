//! UDS control-plane listener for `/v1/control/*` routes (Story
//! 7.27 split-listener).
//!
//! On macOS the daemon binds a Unix domain socket at
//! `paths::control_socket_path()` (= `/var/run/permitlayer/control.sock`)
//! with mode 0660 owned `root:permitlayer-clients`. Every accepted
//! connection gets its kernel-attested peer UID + primary GID
//! captured via `LOCAL_PEERCRED` at accept time and exposed to
//! handlers as `ConnectInfo<PeerCredentials>`.
//!
//! On Linux + Windows this module is `#[cfg(target_os = "macos")]`-
//! only — those platforms keep the rc.21 single-listener TCP model
//! until 7.18 / 7.19 redesign them.

#![cfg(target_os = "macos")]

use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use axum::extract::connect_info::Connected;
use axum::serve::IncomingStream;
use tokio::net::UnixListener;

/// Kernel-attested peer credentials for a UDS connection.
///
/// Captured at `accept()` time via `LOCAL_PEERCRED` getsockopt —
/// cannot be spoofed by user-space code on the other end of the
/// socket. Exposed to handlers as `axum::Extension<PeerCredentials>`
/// via [`record_peer_credentials_layer`].
#[derive(Clone, Copy, Debug)]
pub struct PeerCredentials {
    /// Effective UID of the peer process at connect time.
    pub uid: u32,
    /// Primary GID (`cr_groups[0]`) of the peer process at connect
    /// time. Used for audit logging; supplementary GID checks
    /// (e.g., `permitlayer-clients` membership) are best left to
    /// the kernel via the socket's 0660 mode + group ownership.
    pub gid: u32,
}

/// Connect-info type for the UDS control listener.
///
/// Carries the kernel-attested peer credentials and a sentinel
/// `SocketAddr` (`127.0.0.1:0`) so handlers expecting
/// `ConnectInfo<SocketAddr>` + `require_loopback` (the rc.21
/// pattern, now preserved on the UDS path) continue to compile
/// without rewriting.
///
/// Story 7.27 AC #1 + #11: the sentinel-loopback approach was
/// chosen over rewriting all 14 control handlers because UDS is
/// structurally local-only — the loopback constraint is moot at
/// the kernel level. The handler-level `require_loopback` is now
/// belt-and-suspenders, satisfied by the sentinel `127.0.0.1:0`.
///
/// Future cleanup (post-rc.22): drop the `ConnectInfo<SocketAddr>`
/// extractor in favor of `Extension<PeerCredentials>` per handler.
/// 7.27 keeps the minimum-change posture.
#[derive(Clone, Debug)]
pub struct UdsConnectInfo {
    pub peer: PeerCredentials,
    pub sentinel_addr: SocketAddr,
}

impl Connected<IncomingStream<'_, UnixListener>> for UdsConnectInfo {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        // axum's `IncomingStream::io()` returns `&L::Io` which is
        // `&UnixStream` for our listener. `LOCAL_PEERCRED` is
        // captured here, at accept time, so the value cannot be
        // raced by a forked/exec'd process on the peer side after
        // the fact.
        let peer = match permitlayer_platform_macos::peer_uid_gid_from_unix_stream(stream.io()) {
            Ok((uid, gid)) => PeerCredentials { uid, gid },
            Err(e) => {
                // A failure to read peer-cred is unexpected — the
                // socket is AF_LOCAL by construction. Log and
                // surface a sentinel so handlers can refuse the
                // request without panicking. UID `u32::MAX` is
                // outside the legal Darwin UID range (capped at
                // 2³¹−1 by `<sys/types.h>`); the audit layer
                // grep-matches this as a "unknown peer" record.
                tracing::error!(
                    error = %e,
                    "LOCAL_PEERCRED failed at accept time — emitting sentinel PeerCredentials",
                );
                PeerCredentials { uid: u32::MAX, gid: u32::MAX }
            }
        };
        // Sentinel `127.0.0.1:0` so the existing `require_loopback`
        // check (each handler in `server/control.rs`) is satisfied
        // without modification. The "real" peer identity for audit
        // purposes is in `peer`, exposed via `Extension<PeerCredentials>`
        // by `record_peer_credentials_layer`.
        let sentinel_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        Self { peer, sentinel_addr }
    }
}

/// Tower middleware: read the `UdsConnectInfo` axum produced at
/// accept time and inject (a) `ConnectInfo<SocketAddr>` carrying
/// the sentinel `127.0.0.1:0` so existing rc.21 control handlers
/// keep compiling against their loopback-only guard, and (b)
/// `Extension<PeerCredentials>` so audit-emission code can grab
/// the kernel-attested peer identity without rewriting every
/// handler signature.
///
/// Also enriches the current tracing span with `peer_uid` /
/// `peer_gid` for grep-correlation against the audit log.
///
/// Story 7.27 AC #1 + #15.
pub async fn record_peer_credentials_layer(
    axum::extract::ConnectInfo(uds_info): axum::extract::ConnectInfo<UdsConnectInfo>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    tracing::Span::current().record("peer_uid", uds_info.peer.uid);
    tracing::Span::current().record("peer_gid", uds_info.peer.gid);
    // Inject `ConnectInfo<SocketAddr>` so the existing
    // `require_loopback(peer)` handler-side guard stays happy.
    req.extensions_mut().insert(axum::extract::ConnectInfo::<SocketAddr>(uds_info.sentinel_addr));
    // Inject `Extension<PeerCredentials>` so audit-emission code
    // can extract the kernel-attested identity.
    req.extensions_mut().insert(uds_info.peer);
    next.run(req).await
}

/// Bind the UDS control-plane listener and apply root-owned 0660
/// perms restricted to the `permitlayer-clients` group.
///
/// 1. If `path` already exists, refuses to start when it's a symlink
///    (defense against a hostile actor pre-creating a symlink in
///    `/var/run/permitlayer/`); otherwise unlinks the stale socket
///    file (only root can write to `/var/run/permitlayer/` per AC
///    #4, so the file we're removing was ours).
/// 2. Binds a fresh `UnixListener` at `path`.
/// 3. Chowns the socket file to `root:<group>` and chmods to 0660
///    so processes in the `permitlayer-clients` group can connect.
///
/// On failure returns an `io::Error` carrying a descriptive cause
/// the daemon's `StartError` rendering can surface to the operator.
///
/// Story 7.27 AC #11 + #4.
pub fn bind_control_listener(path: &Path, group_name: &str) -> io::Result<UnixListener> {
    let listener = bind_control_listener_no_perms(path)?;
    apply_control_socket_perms(path, group_name)?;
    Ok(listener)
}

/// Bind the UDS listener WITHOUT applying root-owned chown. Used by
/// (a) the dev/test path in `start.rs` when `AGENTSSO_PATHS__HOME`
/// is set (non-root, no `permitlayer-clients` group), and (b) the
/// non-root unit tests below. Production callers use
/// [`bind_control_listener`] which applies the perms.
pub fn bind_control_listener_no_perms(path: &Path) -> io::Result<UnixListener> {
    // (1) Symlink defense + stale-socket cleanup.
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("control-socket path is a symlink — refusing to bind: {}", path.display()),
            ));
        }
        Ok(_) => {
            // Stale socket from a previous daemon instance — remove
            // before binding. Idempotent.
            std::fs::remove_file(path)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => { /* fresh bind path */ }
        Err(e) => return Err(e),
    }

    // (2) Bind the listener.
    UnixListener::bind(path)
}

/// Chown the socket file to `root:<group>` and chmod to 0660. Split
/// out so unit tests can exercise the bind path without root.
fn apply_control_socket_perms(path: &Path, group_name: &str) -> io::Result<()> {
    use nix::unistd::{Gid, Group, chown};

    let group = Group::from_name(group_name)
        .map_err(|e| io::Error::other(format!("Group::from_name({group_name}): {e}")))?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "macOS group `{group_name}` does not exist — \
                     run `sudo agentsso service install` first"
                ),
            )
        })?;
    let gid = group.gid;

    chown(path, Some(nix::unistd::Uid::from_raw(0)), Some(Gid::from_raw(gid.as_raw())))
        .map_err(|e| io::Error::other(format!("chown(control.sock, root:{group_name}): {e}")))?;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // `tokio::net::UnixListener::bind` requires a tokio runtime;
    // these tests use `#[tokio::test]`. The runtime is purely to
    // satisfy the reactor — no async work happens beyond bind.

    #[tokio::test]
    async fn bind_refuses_symlink_at_socket_path() {
        let dir = tempdir().unwrap();
        let real_file = dir.path().join("real");
        let sock_path = dir.path().join("control.sock");
        std::fs::write(&real_file, b"").unwrap();
        std::os::unix::fs::symlink(&real_file, &sock_path).unwrap();

        // Use the no-perms variant to avoid the root-required chown.
        let err = bind_control_listener_no_perms(&sock_path).expect_err("symlink must refuse");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn bind_removes_stale_socket() {
        use std::os::unix::fs::FileTypeExt;
        let dir = tempdir().unwrap();
        let sock_path = dir.path().join("control.sock");
        // Pre-create a regular file at the path. Bind should remove
        // it and create a fresh socket. Skip the chown step (root-
        // required); we're only verifying the bind + cleanup logic.
        std::fs::write(&sock_path, b"stale").unwrap();

        let _listener =
            bind_control_listener_no_perms(&sock_path).expect("bind should remove stale + succeed");
        let meta = std::fs::symlink_metadata(&sock_path).unwrap();
        let ft = meta.file_type();
        assert!(
            ft.is_socket(),
            "expected socket, got file_type that is_socket={}, is_file={}",
            ft.is_socket(),
            ft.is_file()
        );
    }

    #[test]
    fn apply_perms_fails_on_nonexistent_group() {
        let dir = tempdir().unwrap();
        let sock_path = dir.path().join("control.sock");
        // Pre-create a file so the path exists for chown to target.
        // (We don't actually expect chown to run — the group lookup
        // fails first — but we need a real path.)
        std::fs::write(&sock_path, b"").unwrap();
        let err = apply_control_socket_perms(&sock_path, "permitlayer-no-such-group-12345-test")
            .expect_err("missing group must surface");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
