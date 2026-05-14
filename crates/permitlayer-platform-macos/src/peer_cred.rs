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

/// `NGROUPS` per Darwin `sys/ucred.h` — the fixed group-list length
/// in `struct xucred`. Bound this in code rather than scattering the
/// magic literal across the struct definition + static-size assertion.
const NGROUPS: usize = 16;

/// `xucred` struct layout per macOS 13+ SDK.
#[repr(C)]
#[derive(Clone, Copy)]
struct Xucred {
    cr_version: libc::c_uint,
    cr_uid: libc::uid_t,
    cr_ngroups: libc::c_short,
    cr_groups: [libc::gid_t; NGROUPS],
}

const _: () = {
    // Static sanity check on the struct size. If a future Darwin
    // SDK adds fields and we end up reading a too-small/too-large
    // struct, `getsockopt` returns `EINVAL` for an oversized buffer
    // OR fills a partial buffer for an undersized one — either way
    // the size assertion here keeps us in sync with the header.
    //
    // Expected size: 4 (cr_version) + 4 (cr_uid) + 2 (cr_ngroups) +
    // 2 (padding to align cr_groups) + 4*NGROUPS (cr_groups) = 76 bytes
    // for NGROUPS = 16.
    let expected = 4 + 4 + 2 + 2 + 4 * NGROUPS;
    let actual = size_of::<Xucred>();
    assert!(actual == expected, "xucred struct size mismatch — check Darwin SDK header");

    // Round-3 review fix: total-size match alone doesn't pin field
    // offsets. A future SDK that inserts padding before `cr_groups`
    // (e.g., 4-byte alignment quirk on an architecture variant) would
    // pass the size assert but shift `cr_groups` so our reads land on
    // the wrong bytes. Pin `cr_groups` at offset 12: 4 (cr_version) +
    // 4 (cr_uid) + 2 (cr_ngroups) + 2 (padding). `offset_of!` is
    // const-stable since Rust 1.77.
    let offset = core::mem::offset_of!(Xucred, cr_groups);
    assert!(offset == 12, "xucred cr_groups offset shifted — check Darwin SDK header");
};

/// Read the peer UID + effective GID of a raw socket fd. This is the
/// low-level primitive (also useful as a test seam for hand-rolled
/// socketpairs); production callers normally use the typed
/// [`peer_uid_gid_from_unix_stream`] sugar.
///
/// The fd must be an `AF_LOCAL` connected socket (either the server
/// side of an `accept()`'d UDS or a client-side `connect()`'d UDS).
/// Calling on a non-AF_LOCAL fd returns `ENOPROTOOPT` on Darwin
/// (`getsockopt` reports the option is not supported by the socket's
/// protocol). Calling on an unconnected (or `listen()`'d-but-not-
/// `accept()`'d) AF_LOCAL fd returns `ENOTCONN`.
///
/// Returns `(cr_uid, cr_groups[0])`. The returned GID is the
/// **effective GID** at connect time, NOT necessarily the user's
/// primary GID — Darwin's `LOCAL_PEERCRED` populates `cr_groups[0]`
/// from the credential snapshot at socket creation, which records the
/// effective GID. In the common case (no recent `setegid` / setgid
/// binary) it coincides with the primary GID, but consumers that need
/// the primary GID specifically should call
/// `nix::unistd::User::from_uid(uid).gid` instead.
pub fn peer_uid_gid_from_raw_fd(fd: RawFd) -> io::Result<(u32, u32)> {
    let mut ucred: MaybeUninit<Xucred> = MaybeUninit::uninit();

    // SAFETY: `ucred.as_mut_ptr()` points at uninitialized but
    // properly-aligned + properly-sized storage for `Xucred`.
    // `getsockopt` either fills the buffer (success → `assume_init`
    // is legal) or returns -1 without writing (failure → we don't
    // `assume_init`). The fd is borrowed; the kernel does not
    // retain it after the syscall returns.
    //
    // Story 7.27 review fix: retry on EINTR. A signal handler firing
    // during the syscall would otherwise propagate as a peer-cred
    // failure, surfacing the `u32::MAX` sentinel for an otherwise-
    // valid connection. Bound the retry loop at 8 attempts so a
    // stuck signal storm can't wedge a worker indefinitely.
    //
    // Round-2 review fix: `len` is re-initialized inside the loop so
    // that any kernel path that mutates the value-result `socklen_t`
    // before returning EINTR does not leave subsequent retries
    // requesting fewer bytes than `Xucred` needs.
    let mut attempts = 0;
    let written_len = loop {
        let mut len: libc::socklen_t = size_of::<Xucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                SOL_LOCAL,
                LOCAL_PEERCRED,
                ucred.as_mut_ptr().cast::<libc::c_void>(),
                &mut len,
            )
        };
        if rc == 0 {
            break len;
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) && attempts < 8 {
            attempts += 1;
            continue;
        }
        return Err(err);
    };

    // Round-2 review fix: validate the kernel wrote a full `Xucred`
    // before treating the buffer as initialized. A short write (future
    // Darwin shrinks the public struct) would otherwise have us read
    // `cr_groups[k..]` from uninit memory.
    if (written_len as usize) < size_of::<Xucred>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "LOCAL_PEERCRED short write: kernel wrote {} bytes, need {}",
                written_len,
                size_of::<Xucred>(),
            ),
        ));
    }

    // SAFETY: `getsockopt` returned 0 and `written_len >=
    // size_of::<Xucred>()`, so the kernel initialized the full buffer.
    let ucred = unsafe { ucred.assume_init() };

    // Round-2 review fix: `cr_ngroups` is `c_short` (signed); cast via
    // `usize` would turn negative values into `usize::MAX` and bypass
    // the zero check.
    //
    // Round-3 review fix: out-of-range `cr_ngroups` now returns an
    // explicit `InvalidData` error rather than silently substituting
    // `gid = 0`. Returning root-equivalent group for "indeterminate
    // peer cred" was a security smell: callers using the GID for audit
    // logging or authorization could mis-classify the peer as
    // root-grouped on a kernel-ABI violation. Today this branch is
    // unreachable (the size + offset asserts above pin the struct
    // layout), but defense-in-depth against future kernel changes.
    let ngroups = ucred.cr_ngroups;
    if ngroups <= 0 || (ngroups as usize) > NGROUPS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "LOCAL_PEERCRED: cr_ngroups out of range (got {ngroups}, expected 1..={NGROUPS})"
            ),
        ));
    }

    Ok((ucred.cr_uid, ucred.cr_groups[0]))
}

/// Read the peer UID of a raw socket fd. Convenience wrapper around
/// `peer_uid_gid_from_raw_fd` that discards the GID.
pub fn peer_uid_from_raw_fd(fd: RawFd) -> io::Result<u32> {
    peer_uid_gid_from_raw_fd(fd).map(|(uid, _)| uid)
}

/// Read the peer UID + effective GID of a tokio `UnixStream`. Borrows
/// the stream — does not consume it. Production callers normally use
/// this form rather than the raw-fd primitive.
///
/// "Effective GID" semantics match [`peer_uid_gid_from_raw_fd`]; see
/// that function's doc for the primary-vs-effective distinction.
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
    use std::os::fd::{FromRawFd, OwnedFd};

    /// Build a connected `AF_LOCAL` socket pair and return the two
    /// endpoints as `OwnedFd` (drop-closes-fd; leak-safe under panic).
    /// Both endpoints are owned by the test process, so
    /// `LOCAL_PEERCRED` on either side should return the test
    /// process's UID.
    fn make_socketpair() -> (OwnedFd, OwnedFd) {
        let mut fds: [libc::c_int; 2] = [-1, -1];
        // SAFETY: standard libc socketpair call; fds is a
        // 2-element array per the man page.
        let rc =
            unsafe { libc::socketpair(libc::AF_LOCAL, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair failed: {}", io::Error::last_os_error());
        // SAFETY: socketpair returned 0 and wrote two valid fds we
        // now own.
        let a = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let b = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        (a, b)
    }

    #[test]
    fn peer_uid_matches_self_for_socketpair() {
        let (a, b) = make_socketpair();
        let uid_self = unsafe { libc::getuid() };

        let uid_a = peer_uid_from_raw_fd(a.as_raw_fd()).expect("getsockopt a");
        let uid_b = peer_uid_from_raw_fd(b.as_raw_fd()).expect("getsockopt b");

        assert_eq!(uid_a, uid_self, "peer-UID on side A should be our UID");
        assert_eq!(uid_b, uid_self, "peer-UID on side B should be our UID");
    }

    #[test]
    fn peer_uid_gid_returns_effective_gid() {
        // `LOCAL_PEERCRED` records the EFFECTIVE GID at socket
        // creation. In a test process that hasn't called
        // `setegid(2)`, the effective GID equals `getegid()`. Assert
        // strict equality against `getegid()` — a buggy impl
        // returning a stale or off-by-one GID would fail this.
        let (a, _b) = make_socketpair();
        let egid_self = unsafe { libc::getegid() };
        let uid_self = unsafe { libc::getuid() };

        let (uid, gid) = peer_uid_gid_from_raw_fd(a.as_raw_fd()).expect("getsockopt");

        assert_eq!(uid, uid_self);
        assert_eq!(
            gid, egid_self,
            "LOCAL_PEERCRED returns effective GID (egid={egid_self}, got={gid})"
        );
    }

    #[test]
    fn peer_uid_from_unix_stream_works_via_tokio() {
        // Smoke test the tokio integration: build a socketpair,
        // wrap one end in a tokio UnixStream, verify the wrapper
        // returns the same UID as the raw-fd variant. The other end
        // is kept alive via the `_b` binding so its Drop closes on
        // any test-panic path.
        let (a, _b) = make_socketpair();
        let uid_self = unsafe { libc::getuid() };

        let rt = tokio::runtime::Builder::new_current_thread().enable_io().build().unwrap();
        rt.block_on(async {
            // Transfer ownership of `a` to tokio. tokio drops the fd
            // when the stream is dropped at end of scope.
            let std_stream = std::os::unix::net::UnixStream::from(a);
            std_stream.set_nonblocking(true).unwrap();
            let tokio_stream = tokio::net::UnixStream::from_std(std_stream).unwrap();

            let uid = peer_uid_from_unix_stream(&tokio_stream).expect("getsockopt via stream");
            assert_eq!(uid, uid_self);
        });
    }

    #[test]
    fn peer_uid_on_unconnected_local_socket_returns_err() {
        // An unconnected SOCK_STREAM AF_LOCAL socket has no peer
        // recorded, so LOCAL_PEERCRED returns `ENOTCONN`.
        let fd = unsafe { libc::socket(libc::AF_LOCAL, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);
        // SAFETY: socket() returned a valid fd we now own.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };

        let err = peer_uid_from_raw_fd(owned.as_raw_fd())
            .expect_err("expected error on unconnected socket");
        // `ENOTCONN` (57) per the Darwin getsockopt(2) man page
        // for LOCAL_PEERCRED on a not-yet-connected socket.
        // Accept `EINVAL` as a backstop in case a minor Darwin
        // release returns a different code for the same condition.
        let errno = err.raw_os_error().unwrap_or(0);
        assert!(
            errno == libc::ENOTCONN || errno == libc::EINVAL,
            "expected ENOTCONN/EINVAL on unconnected socket, got errno={errno}"
        );
    }

    #[test]
    fn peer_uid_on_bare_listener_fd_returns_err() {
        // Tighten coverage of the doc-comment claim: calling
        // peer_uid_from_raw_fd on a `bind()` + `listen()`'d AF_LOCAL
        // socket (without accepting a connection) must surface an
        // error — there is no peer to attest. Documents the
        // misuse-mode the daemon's UDS listener-side caller has to
        // avoid (it always operates on accepted streams).
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("listener.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let err = peer_uid_from_raw_fd(listener.as_raw_fd())
            .expect_err("expected error on bare listener fd");
        let errno = err.raw_os_error().unwrap_or(0);
        // Empirically: Darwin returns ENOTCONN; EINVAL accepted as
        // backstop. The contract that matters is "errors, does not
        // silently return a wrong UID".
        assert!(
            errno == libc::ENOTCONN || errno == libc::EINVAL,
            "expected ENOTCONN/EINVAL on bare listener fd, got errno={errno}"
        );
    }
}
