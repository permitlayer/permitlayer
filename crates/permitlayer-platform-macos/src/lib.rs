//! macOS platform integration for PermitLayer.
//!
//! Houses unsafe FFI for `renameatx_np` (token-write atomic rename
//! with `RENAME_EXCL` semantics — Story 7.27 token-write secure
//! pattern) and `LOCAL_PEERCRED` (UDS peer-cred attestation — Story
//! 7.27 control-plane caller-identity).
//!
//! Deliberately NOT under `#![forbid(unsafe_code)]`. Every other
//! workspace crate retains the policy; this crate is the isolation
//! seam for the small amount of macOS-specific FFI the rc.22
//! redesign needs. See Story 7.25 AC #11 (cross-platform-parity-
//! friendly abstractions) for the rationale.
//!
//! Story 7.26 landed this crate as empty scaffolding. Story 7.27
//! populates it with `renameatx_np` + `LOCAL_PEERCRED` wrappers,
//! both behind safe Rust APIs that callers in `permitlayer-daemon`
//! consume without writing `unsafe` themselves.
//!
//! Build target: macOS only. The `#![cfg(target_os = "macos")]`
//! at the crate root makes the entire crate vacuous on Linux +
//! Windows, which keeps the workspace compile clean on cross
//! platforms without any per-consumer `#[cfg]` gymnastics.

#![cfg(target_os = "macos")]

pub mod peer_cred;
pub mod rename_excl;

pub use peer_cred::{
    peer_uid_from_raw_fd, peer_uid_from_unix_stream, peer_uid_gid_from_raw_fd,
    peer_uid_gid_from_unix_stream,
};
pub use rename_excl::rename_excl;
