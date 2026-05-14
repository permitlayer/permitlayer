#[cfg(target_os = "macos")]
pub mod agent_token;
pub mod conn_tracker;
pub mod control;
#[cfg(target_os = "macos")]
pub mod control_listener;
pub mod shutdown;
pub mod sighup;

/// Kernel-attested peer identity for a `/v1/control/*` request.
///
/// On macOS (Story 7.27) this is captured at `accept()` time via
/// `LOCAL_PEERCRED` getsockopt on the UDS — cannot be spoofed by
/// user-space code on the other end of the socket. Exposed to
/// handlers as `axum::Extension<PeerCredentials>` via the
/// macOS-only `control_listener::record_peer_credentials_layer`.
///
/// On Linux/Windows the UDS split-listener does not yet exist (those
/// platforms ride on the original TCP control path) so this type is
/// never inserted into the request extensions — handlers'
/// `req.extensions().get::<PeerCredentials>()` returns `None` and
/// audit events stay schema-compatible with rc.21. The type is
/// nevertheless defined cross-platform so the handlers in
/// `server/control.rs` can name it without `#[cfg]` clutter at every
/// reference site (Story 7.27 Round-3 review fix R3-C3-P1).
#[derive(Clone, Copy, Debug)]
pub struct PeerCredentials {
    /// Effective UID of the peer process at connect time.
    pub uid: u32,
    /// Effective GID of the peer process at connect time. On macOS,
    /// `cr_groups[0]` from `xucred`. Used for audit logging;
    /// supplementary GID checks (e.g., `permitlayer-clients`
    /// membership) are best left to the kernel via the socket's
    /// 0660 mode + group ownership.
    pub gid: u32,
}
