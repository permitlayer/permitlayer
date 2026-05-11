//! macOS platform integration for PermitLayer.
//!
//! Houses unsafe FFI for `renameatx_np` (token-write atomic rename
//! with `RENAME_EXCL` semantics — Story 7.27 token-write secure
//! pattern), `LOCAL_PEERCRED` (UDS peer-cred attestation — Story
//! 7.27 control-plane caller-identity), and System.keychain helpers
//! that aren't covered by the `keyring` crate's standard surface.
//!
//! Deliberately NOT under `#![forbid(unsafe_code)]`. Every other
//! workspace crate retains the policy; this crate is the isolation
//! seam for the small amount of macOS-specific FFI the rc.22
//! redesign needs. See Story 7.25 AC #11 (cross-platform-parity-
//! friendly abstractions) for the rationale.
//!
//! Story 7.26 lands this crate as empty scaffolding. Story 7.27
//! populates it with `renameatx_np` + `LOCAL_PEERCRED`
//! implementations behind the `permitlayer-core::platform`
//! traits (also future work).
//!
//! Build target: macOS only. The `#![cfg(target_os = "macos")]`
//! at the crate root makes the entire crate vacuous on Linux +
//! Windows, which keeps the workspace compile clean on cross
//! platforms without any per-consumer `#[cfg]` gymnastics.

#![cfg(target_os = "macos")]
