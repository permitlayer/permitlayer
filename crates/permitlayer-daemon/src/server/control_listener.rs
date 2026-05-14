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
use axum::response::IntoResponse;
use axum::serve::IncomingStream;
use tokio::net::UnixListener;

/// Kernel-attested peer credentials for a UDS connection.
///
/// Round-3 review fix (R3-C3-P1): the `PeerCredentials` struct lives
/// in `super` (`server/mod.rs`) so non-macOS callers in
/// `server/control.rs` can reference the type without `#[cfg]`
/// clutter at every site. Re-export for source-compat with macOS-only
/// callers that imported from this module.
pub use super::PeerCredentials;

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
///
/// Story 7.27 Round-2 review fix (P1): refuse with 503 when
/// `peer.uid == u32::MAX` (the `LOCAL_PEERCRED` failure sentinel
/// from `peer_uid_gid_from_unix_stream`). Without this guard,
/// downstream handlers like `register_agent_handler` would proceed
/// to mint agents under "unknown peer" — the late token-write step
/// fails but the agent + token are already persisted with no
/// kernel-attested identity in the audit log. The fix was
/// documented at story line 754 in Round-1 review but not
/// implemented; Round-2 re-review caught the gap.
///
/// Health endpoints `/health` and `/v1/health` are routed through
/// this same layer (per the `.merge(health_router).layer(...)`
/// ordering at `cli/start.rs::control_router_for_uds`). They are
/// intentionally exempted from the sentinel rejection — liveness
/// probes must work even when peer-cred capture fails so operators
/// can still detect "daemon is up but peer-cred is broken".
pub async fn record_peer_credentials_layer(
    axum::extract::ConnectInfo(uds_info): axum::extract::ConnectInfo<UdsConnectInfo>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = req.uri().path();
    let is_health_probe = path == "/health" || path == "/v1/health";
    if !is_health_probe && uds_info.peer.uid == u32::MAX {
        tracing::error!(
            event = "control.peer_cred_unavailable",
            path = %path,
            "rejecting /v1/control/* request because LOCAL_PEERCRED \
             returned the failure sentinel u32::MAX; the request \
             cannot be safely attributed to any kernel-attested peer"
        );
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "error": "control.peer_cred_unavailable",
                "message": "the daemon could not read kernel-attested peer \
                            credentials for this UDS connection; request \
                            refused for security",
            })),
        )
            .into_response();
    }
    // Story 7.27 Round-2 review fix (P1): `Span::current().record(...)`
    // moved into `require_control_token` (in `server/control.rs`)
    // because this outer layer runs ABOVE `RequestTraceLayer`, so
    // `Span::current()` here returns the ambient daemon span
    // (which doesn't declare `peer_uid`/`peer_gid` as fields).
    // The auth middleware runs INSIDE the request span where the
    // record calls actually take effect.
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
    // Story 7.27 Round-2 review fix (P3): on perms-apply failure,
    // clean up the bound socket inode before returning the error.
    // Pre-fix, a chgrp/chmod failure (e.g., `permitlayer-clients`
    // group missing) left a stale 0600 root:wheel socket file on
    // disk — `ls /var/run/permitlayer/` would show an unusable
    // socket suggesting a daemon is running. The next start cycle
    // would unlink it via the stale-cleanup branch, but operators
    // investigating the install failure see a misleading socket
    // file in the meantime.
    if let Err(e) = apply_control_socket_perms(path, group_name) {
        drop(listener);
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(listener)
}

/// Bind the UDS listener WITHOUT applying root-owned chown. Used by
/// (a) the dev/test path in `start.rs` when `AGENTSSO_PATHS__HOME`
/// is set (non-root, no `permitlayer-clients` group), and (b) the
/// non-root unit tests below. Production callers use
/// [`bind_control_listener`] which applies the perms.
///
/// Wraps the bind in a tight `umask(0o177)` window so the kernel
/// creates the socket inode mode 0600 (root:wheel) from the moment
/// it exists — never the umask-022 default 0755 window that would
/// allow any local process to `connect(2)` before
/// `apply_control_socket_perms` lands the chgrp+chmod 0660.
/// Story 7.27 review fix: P0 socket-race.
pub fn bind_control_listener_no_perms(path: &Path) -> io::Result<UnixListener> {
    // (1) Symlink defense + stale-socket cleanup.
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("control-socket path is a symlink — refusing to bind: {}", path.display()),
            ));
        }
        Ok(meta) => {
            // Round-3 review fix (R3-C3-P6): refuse non-socket file
            // types up front. The Round-2 probe accepted ANY connect
            // failure as "stale" → `remove_file`, which under
            // `AGENTSSO_PATHS__HOME` override (operator-writable
            // dir) lets an operator-equivalent process trick the
            // daemon into deleting arbitrary files at the socket
            // path (regular files, FIFOs, dangling-target sockets,
            // etc.). The symlink check above catches symlinks; this
            // check catches everything that isn't an AF_UNIX socket.
            use std::os::unix::fs::FileTypeExt;
            if !meta.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "control-socket path exists but is not an AF_UNIX socket — \
                         refusing to clobber: {}",
                        path.display()
                    ),
                ));
            }
            // Story 7.27 Round-2 review fix (P2): probe the
            // existing inode with a `connect(2)` before unlinking.
            // Under `AGENTSSO_PATHS__HOME` override (dev/test
            // mode), the dir is operator-writable and a sibling
            // process could plant an unrelated file at this path
            // — pre-fix, `remove_file` would silently delete it.
            // Worse: if a second daemon is actually running at
            // this path (PidFile bypass via separate override),
            // we'd unlink its live socket. Probe first; if
            // connect succeeds, another daemon owns this socket
            // and we refuse to start.
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        format!(
                            "another daemon appears to be listening on {} — \
                             refusing to clobber its socket. If the previous \
                             daemon crashed, remove the socket manually with \
                             `sudo rm {}` and re-run.",
                            path.display(),
                            path.display(),
                        ),
                    ));
                }
                Err(_) => {
                    // Stale socket (no live listener) — remove before
                    // binding. Idempotent.
                    tracing::info!(
                        target: "control",
                        event = "daemon.startup.stale_socket_removed",
                        path = %path.display(),
                        "removed stale control-socket from a prior daemon instance"
                    );
                    std::fs::remove_file(path)?;
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => { /* fresh bind path */ }
        Err(e) => return Err(e),
    }

    // (2) Bind the listener under a restrictive umask so the inode
    //     is created with no group/other perms. apply_control_socket_perms
    //     widens to 0660 once the group ownership is set.
    permitlayer_platform_macos::with_umask(0o177, || UnixListener::bind(path))
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
        // Round-3 review fix (R3-C3-P6) tightened bind to refuse
        // non-socket inodes at the path. Update this test to
        // pre-create an actual AF_UNIX socket inode (bind + drop
        // the listener) — that's the genuine "stale socket" case:
        // a socket inode left behind by a prior daemon that
        // exited without unlinking. Regular-file path is now
        // covered by `bind_refuses_non_socket_inode` below.
        let dir = tempdir().unwrap();
        let sock_path = dir.path().join("control.sock");

        // Create + drop a real AF_UNIX socket inode so the path
        // becomes a stale socket (no live listener).
        {
            let _stale = UnixListener::bind(&sock_path).expect("create stale socket inode");
        }

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

    #[tokio::test]
    async fn bind_refuses_non_socket_inode() {
        // Round-3 review fix (R3-C3-P6): bind must refuse to
        // clobber a non-socket inode at the configured path.
        // Pre-fix, ANY connect-probe failure caused
        // `remove_file(path)`, which under `AGENTSSO_PATHS__HOME`
        // override let an operator-equivalent process trick the
        // daemon into deleting arbitrary files (regular files,
        // FIFOs, etc.). Now we refuse with `InvalidInput`.
        let dir = tempdir().unwrap();
        let sock_path = dir.path().join("control.sock");
        std::fs::write(&sock_path, b"definitely-not-a-socket").expect("create regular file");

        let err = bind_control_listener_no_perms(&sock_path)
            .expect_err("bind must refuse non-socket inode");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        // File must still exist — we refused, we didn't delete.
        assert!(sock_path.exists(), "refusal must not delete the file");
        let contents = std::fs::read(&sock_path).unwrap();
        assert_eq!(contents, b"definitely-not-a-socket");
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
