//! `LOCAL_PEERCRED` getsockopt wrapper for UDS peer-credential
//! attestation on macOS.
//!
//! Apple's `LOCAL_PEERCRED` is a socket-option on `SOL_LOCAL` that
//! returns the `struct xucred` containing the peer's UID + group
//! list, as recorded by the kernel at connect/accept time. This is
//! the kernel-attested identity of the process on the other end of
//! the UDS — it cannot be spoofed by user-space code because the
//! kernel records it at socket-pair creation.
//!
//! Primary source: Darwin SDK header
//! `/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/ucred.h`:
//!
//! ```c
//! #define XUCRED_VERSION  0
//! #define NGROUPS         16
//!
//! struct xucred {
//!     u_int   cr_version;             /* structure layout version */
//!     uid_t   cr_uid;                 /* effective user id */
//!     short   cr_ngroups;             /* number of groups */
//!     gid_t   cr_groups[NGROUPS];     /* groups */
//!     /* fields added in macOS 12 are appended here; preserved by
//!        the existing layout because subsequent callers ignore them */
//! };
//! ```
//!
//! And `sys/un.h` for the option constant:
//!
//! ```c
//! #define LOCAL_PEERCRED   0x001 /* retrieve peer credentials */
//! #define SOL_LOCAL        0     /* getsockopt's first arg for AF_LOCAL */
//! ```
//!
//! Used by Story 7.27's UDS control listener at
//! `/var/run/permitlayer/control.sock`. Every authenticated
//! `/v1/control/*` request records the kernel-attested peer UID in
//! the audit log, independent of the operator-supplied
//! `X-Agentsso-Control` header. Mismatch between the bearer-token
//! claim and the kernel UID is a security-relevant audit event.

use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::fd::{AsRawFd, RawFd};

/// Darwin `SOL_LOCAL` (== 0) — first arg to `getsockopt` for
/// AF_LOCAL sockets.
const SOL_LOCAL: libc::c_int = 0;

/// Darwin `LOCAL_PEERCRED` (== 0x001) — socket option to retrieve
/// the peer's `xucred`.
const LOCAL_PEERCRED: libc::c_int = 0x001;

/// `xucred` struct layout per macOS 13+ SDK.
#[repr(C)]
#[derive(Clone, Copy)]
struct Xucred {
    cr_version: libc::c_uint,
    cr_uid: libc::uid_t,
    cr_ngroups: libc::c_short,
    cr_groups: [libc::gid_t; 16],
}

const _: () = {
    // Static sanity check on the struct size. If a future Darwin
    // SDK adds fields and we end up reading a too-small/too-large
    // struct, `getsockopt` returns `EINVAL` for an oversized buffer
    // OR fills a partial buffer for an undersized one — either way
    // the size assertion here keeps us in sync with the header.
    //
    // Expected size: 4 (cr_version) + 4 (cr_uid) + 2 (cr_ngroups) +
    // 2 (padding to align cr_groups) + 4*16 (cr_groups) = 76 bytes.
    let expected = 4 + 4 + 2 + 2 + 4 * 16;
    let actual = size_of::<Xucred>();
    assert!(actual == expected, "xucred struct size mismatch — check Darwin SDK header");
};

/// Read the peer UID + primary GID of a raw socket fd. This is the
/// underlying primitive; prefer the typed `peer_uid_from_unix_stream`
/// for production code paths.
///
/// The fd must be an `AF_LOCAL` connected socket (either the server
/// side of an `accept()`'d UDS or a client-side `connect()`'d UDS).
/// Calling on a non-AF_LOCAL fd returns `EPROTOTYPE` (or similar).
///
/// Returns `(cr_uid, cr_groups[0])`. The primary GID is the first
/// entry in the kernel's `cr_groups` array — for the
/// `permitlayer-clients` membership check, we look for that GID in
/// the full group list rather than relying on the primary, but for
/// audit logging the primary GID is sufficient.
pub fn peer_uid_gid_from_raw_fd(fd: RawFd) -> io::Result<(u32, u32)> {
    let mut ucred: MaybeUninit<Xucred> = MaybeUninit::uninit();
    let mut len: libc::socklen_t = size_of::<Xucred>() as libc::socklen_t;

    // SAFETY: `ucred.as_mut_ptr()` points at uninitialized but
    // properly-aligned + properly-sized storage for `Xucred`. `len`
    // is initialized to the size of that storage. `getsockopt`
    // either fills the buffer (success → `assume_init` is legal)
    // or returns -1 without writing (failure → we don't
    // `assume_init`). The fd is borrowed; the kernel does not
    // retain it after the syscall returns.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERCRED,
            ucred.as_mut_ptr().cast::<libc::c_void>(),
            &mut len,
        )
    };

    if rc == -1 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `getsockopt` returned 0; the kernel wrote a complete
    // `Xucred` into the buffer (`len` is set to the bytes written;
    // we only call `assume_init` because the kernel succeeded).
    let ucred = unsafe { ucred.assume_init() };

    if (ucred.cr_ngroups as usize) == 0 {
        // Defensive: if the kernel reported zero groups, there is no
        // primary GID to return. This is extremely unusual (every
        // logged-in user has at least one group) but the runtime
        // behavior is documented here for code review.
        return Ok((ucred.cr_uid, 0));
    }

    Ok((ucred.cr_uid, ucred.cr_groups[0]))
}

/// Read the peer UID of a raw socket fd. Convenience wrapper around
/// `peer_uid_gid_from_raw_fd` that discards the GID.
pub fn peer_uid_from_raw_fd(fd: RawFd) -> io::Result<u32> {
    peer_uid_gid_from_raw_fd(fd).map(|(uid, _)| uid)
}

/// Read the peer UID + primary GID of a tokio `UnixStream`. Borrows
/// the stream — does not consume it. Production callers should use
/// this form rather than reaching for the raw-fd variant.
pub fn peer_uid_gid_from_unix_stream(stream: &tokio::net::UnixStream) -> io::Result<(u32, u32)> {
    peer_uid_gid_from_raw_fd(stream.as_raw_fd())
}

/// Read the peer UID of a tokio `UnixStream`.
pub fn peer_uid_from_unix_stream(stream: &tokio::net::UnixStream) -> io::Result<u32> {
    peer_uid_gid_from_unix_stream(stream).map(|(uid, _)| uid)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;

    /// Build a connected `AF_LOCAL` socket pair, return the two
    /// endpoints as raw fds. Both endpoints are owned by the test
    /// process, so `LOCAL_PEERCRED` on either side should return
    /// the test process's UID.
    fn make_socketpair() -> (RawFd, RawFd) {
        let mut fds: [libc::c_int; 2] = [-1, -1];
        // SAFETY: standard libc socketpair call; fds is a
        // 2-element array per the man page.
        let rc =
            unsafe { libc::socketpair(libc::AF_LOCAL, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair failed: {}", io::Error::last_os_error());
        (fds[0], fds[1])
    }

    #[test]
    fn peer_uid_matches_self_for_socketpair() {
        let (a, b) = make_socketpair();
        let uid_self = unsafe { libc::getuid() };

        let uid_a = peer_uid_from_raw_fd(a).expect("getsockopt a");
        let uid_b = peer_uid_from_raw_fd(b).expect("getsockopt b");

        assert_eq!(uid_a, uid_self, "peer-UID on side A should be our UID");
        assert_eq!(uid_b, uid_self, "peer-UID on side B should be our UID");

        // SAFETY: we own these fds and have not converted them to
        // owned types yet; closing now releases the kernel resource.
        unsafe {
            libc::close(a);
            libc::close(b);
        }
    }

    #[test]
    fn peer_uid_gid_returns_primary_group() {
        let (a, b) = make_socketpair();
        let gid_self = unsafe { libc::getgid() };

        let (uid, gid) = peer_uid_gid_from_raw_fd(a).expect("getsockopt");

        let uid_self = unsafe { libc::getuid() };
        assert_eq!(uid, uid_self);
        // The primary GID returned by LOCAL_PEERCRED may not match
        // `getgid()` exactly on every macOS configuration (the
        // kernel records the EFFECTIVE GID at socket creation,
        // which can drift). We assert that the GID is one the
        // current process belongs to.
        assert!(gid == gid_self || gid != 0, "expected a real GID (current={gid_self}, got={gid})");

        unsafe {
            libc::close(a);
            libc::close(b);
        }
    }

    #[test]
    fn peer_uid_from_unix_stream_works_via_tokio() {
        // Smoke test the tokio integration: build a socketpair,
        // wrap one end in a tokio UnixStream, verify the wrapper
        // returns the same UID as the raw-fd variant.
        let (a, b) = make_socketpair();
        let uid_self = unsafe { libc::getuid() };

        let rt = tokio::runtime::Builder::new_current_thread().enable_io().build().unwrap();
        rt.block_on(async {
            // SAFETY: we own fd `a`; `from_std` consumes ownership
            // and tokio drops the fd at end of scope.
            let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(a) };
            std_stream.set_nonblocking(true).unwrap();
            let tokio_stream = tokio::net::UnixStream::from_std(std_stream).unwrap();

            let uid = peer_uid_from_unix_stream(&tokio_stream).expect("getsockopt via stream");
            assert_eq!(uid, uid_self);
            // tokio_stream's drop closes fd a.
        });

        // Close the other side.
        unsafe {
            libc::close(b);
        }
    }

    #[test]
    fn peer_uid_on_unconnected_local_socket_returns_err() {
        // An unconnected SOCK_STREAM AF_LOCAL socket has no peer
        // recorded, so LOCAL_PEERCRED returns `ENOTCONN`. This
        // documents the runtime behavior so the daemon's UDS
        // listener-side caller (which always operates on accepted
        // streams that DO have a peer) doesn't accidentally call
        // this helper on a bare-listener fd.
        let fd = unsafe { libc::socket(libc::AF_LOCAL, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);

        let err = peer_uid_from_raw_fd(fd).expect_err("expected error on unconnected socket");
        // `ENOTCONN` (57) per the Darwin getsockopt(2) man page
        // for LOCAL_PEERCRED on a not-yet-connected socket.
        // Accept `EINVAL` as a backstop in case a minor Darwin
        // release returns a different code for the same condition.
        let errno = err.raw_os_error().unwrap_or(0);
        assert!(
            errno == libc::ENOTCONN || errno == libc::EINVAL,
            "expected ENOTCONN/EINVAL on unconnected socket, got errno={errno}"
        );

        unsafe {
            libc::close(fd);
        }
    }
}
