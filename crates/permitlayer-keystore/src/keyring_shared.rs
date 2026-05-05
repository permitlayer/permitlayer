//! Shared `keyring`-crate helpers used by every native backend.
//!
//! Story 7.6b round-1 review re-triage (2026-04-28): three near-
//! identical copies of `set_and_verify`, `read_account`,
//! `clear_account`, `set_previous_and_verify`, `delete_entry`,
//! `probe_backend`, `read_key_from_bytes`, `map_err`, and `join_err`
//! lived in `macos.rs`, `linux.rs`, and `windows.rs`. A future bug
//! fix to one platform's helper would silently miss the other two.
//!
//! This module hosts a single canonical implementation. Platform
//! adapters thread their `BACKEND` literal through as a `&'static
//! str`; everything else is identical.
//!
//! # Why a function-with-backend-param shape, not a trait
//!
//! Trait dispatch would force every helper to be a method on a type
//! the platform constructs. The platform adapters are zero-state
//! (each call constructs a fresh `keyring::Entry`), so a trait would
//! introduce a phantom `Self` with no purpose. Free functions taking
//! a `backend: &'static str` parameter are the simpler shape.
//!
//! # Async discipline
//!
//! These helpers are SYNCHRONOUS — they block on `keyring::Entry`
//! FFI. Every async caller MUST dispatch them via
//! `tokio::task::spawn_blocking` (the existing platform-adapter
//! pattern). Doing so inside the helper would force the adapter to
//! own the runtime, which complicates testing. Adapter is the right
//! seam.

#![cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]

use zeroize::{Zeroize, Zeroizing};

use crate::error::KeyStoreError;
use crate::{DeleteOutcome, MASTER_KEY_LEN};

/// Probe the keychain backend by constructing an entry against
/// `account` and attempting a read. Tolerates `NoEntry`; real
/// failures surface as `BackendUnavailable`. Any retrieved bytes are
/// zeroized immediately.
pub(crate) fn probe_backend(backend: &'static str, account: &str) -> Result<(), KeyStoreError> {
    let entry =
        keyring::Entry::new(crate::MASTER_KEY_SERVICE, account).map_err(|e| map_err(backend, e))?;
    match entry.get_secret() {
        Ok(mut bytes) => {
            bytes.zeroize();
            Ok(())
        }
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(map_err(backend, e)),
    }
}

/// Fetch the key at `account`, generating + persisting a fresh
/// random key on first call if none exists. Used by `master_key()`
/// at boot. Race-tolerant: if our `set_secret` fails (another
/// process minted a key concurrently), we adopt whatever's on disk
/// so all racers converge on one value.
pub(crate) fn fetch_or_create_master_key_at_account(
    backend: &'static str,
    account: &str,
) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, KeyStoreError> {
    let entry =
        keyring::Entry::new(crate::MASTER_KEY_SERVICE, account).map_err(|e| map_err(backend, e))?;
    match entry.get_secret() {
        Ok(mut bytes) => {
            let result = read_key_from_bytes(&bytes);
            bytes.zeroize();
            result
        }
        Err(keyring::Error::NoEntry) => {
            use rand::RngCore;
            let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
            rand::rngs::OsRng.fill_bytes(&mut *key);
            match entry.set_secret(&*key) {
                Ok(()) => {
                    let mut bytes = entry.get_secret().map_err(|e| map_err(backend, e))?;
                    let result = read_key_from_bytes(&bytes);
                    bytes.zeroize();
                    result
                }
                Err(_) => {
                    let mut bytes = entry.get_secret().map_err(|e| map_err(backend, e))?;
                    let result = read_key_from_bytes(&bytes);
                    bytes.zeroize();
                    result
                }
            }
        }
        Err(e) => Err(map_err(backend, e)),
    }
}

/// Write `key` to `account`, then read-back-verify with constant-
/// time comparison. Catches keychains that buffer writes or silently
/// discard them on permission quirks.
pub(crate) fn set_and_verify_at_account(
    backend: &'static str,
    account: &str,
    key: &[u8; MASTER_KEY_LEN],
    on_mismatch_message: &'static str,
) -> Result<(), KeyStoreError> {
    let entry =
        keyring::Entry::new(crate::MASTER_KEY_SERVICE, account).map_err(|e| map_err(backend, e))?;
    entry.set_secret(key).map_err(|e| map_err(backend, e))?;
    let mut read_back = entry.get_secret().map_err(|e| map_err(backend, e))?;
    let eq = read_back.len() == MASTER_KEY_LEN && constant_time_eq(&read_back, key);
    read_back.zeroize();
    if !eq {
        return Err(KeyStoreError::PlatformError { backend, message: on_mismatch_message.into() });
    }
    Ok(())
}

/// Read the key at `account` if it exists. Returns `Ok(None)` if
/// no entry was ever written; surfaces other errors verbatim.
pub(crate) fn read_account(
    backend: &'static str,
    account: &str,
) -> Result<Option<Zeroizing<[u8; MASTER_KEY_LEN]>>, KeyStoreError> {
    let entry =
        keyring::Entry::new(crate::MASTER_KEY_SERVICE, account).map_err(|e| map_err(backend, e))?;
    match entry.get_secret() {
        Ok(mut bytes) => {
            let result = read_key_from_bytes(&bytes);
            bytes.zeroize();
            result.map(Some)
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(map_err(backend, e)),
    }
}

/// Idempotent delete of `account`. Returns Ok regardless of whether
/// the entry existed beforehand.
pub(crate) fn clear_account(backend: &'static str, account: &str) -> Result<(), KeyStoreError> {
    let entry =
        keyring::Entry::new(crate::MASTER_KEY_SERVICE, account).map_err(|e| map_err(backend, e))?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(map_err(backend, e)),
    }
}

/// Distinguishing delete of `account`: returns `Removed` vs.
/// `AlreadyAbsent`. Used by `delete_master_key()` (operator-facing
/// uninstall flow) where the caller benefits from knowing which
/// case fired in the audit log.
pub(crate) fn delete_account(
    backend: &'static str,
    account: &str,
) -> Result<DeleteOutcome, KeyStoreError> {
    let entry =
        keyring::Entry::new(crate::MASTER_KEY_SERVICE, account).map_err(|e| map_err(backend, e))?;
    match entry.delete_credential() {
        Ok(()) => Ok(DeleteOutcome::Removed),
        Err(keyring::Error::NoEntry) => Ok(DeleteOutcome::AlreadyAbsent),
        Err(e) => Err(map_err(backend, e)),
    }
}

/// Extract a 32-byte key from a `Vec<u8>`, validating length.
fn read_key_from_bytes(bytes: &[u8]) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, KeyStoreError> {
    if bytes.len() != MASTER_KEY_LEN {
        return Err(KeyStoreError::MalformedMasterKey {
            expected_len: MASTER_KEY_LEN,
            actual_len: bytes.len(),
        });
    }
    let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    key.copy_from_slice(bytes);
    Ok(key)
}

/// Constant-time byte comparison via `subtle`. Used after read-back
/// to match the discipline expected by the rotation orchestrator
/// (which uses `subtle` for the same purpose).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Map a `keyring` error into our `KeyStoreError` typed surface.
/// `BackendUnavailable` is the auto-fallback trigger; everything
/// else surfaces as `PlatformError`.
pub(crate) fn map_err(backend: &'static str, e: keyring::Error) -> KeyStoreError {
    match e {
        keyring::Error::NoStorageAccess(source) => {
            KeyStoreError::BackendUnavailable { backend, source }
        }
        keyring::Error::PlatformFailure(source) => {
            #[cfg(target_os = "macos")]
            if let Some(routed) = classify_macos_platform_failure(backend, source.as_ref()) {
                return routed;
            }
            KeyStoreError::PlatformError { backend, message: source.to_string() }
        }
        other => KeyStoreError::PlatformError { backend, message: other.to_string() },
    }
}

/// On macOS only: pattern-match the OSStatus inside a boxed
/// `security_framework::base::Error` to recognize ACL-denial codes
/// that should trigger the auto-fallback to passphrase mode rather
/// than surfacing as opaque `PlatformError`.
///
/// `brew upgrade agentsso` invalidates the codesign-bound keychain ACL
/// because the new binary's hash differs from the old one's; without
/// this routing the daemon hard-fails on the keystore probe instead of
/// dropping to the passphrase prompt that would let an interactive
/// operator recover.
#[cfg(target_os = "macos")]
fn classify_macos_platform_failure(
    backend: &'static str,
    source: &(dyn std::error::Error + 'static),
) -> Option<KeyStoreError> {
    use security_framework::base::Error as SfError;
    let sf_err = source.downcast_ref::<SfError>()?;
    let code = sf_err.code();
    // -25308 errSecInteractionNotAllowed: Security Agent has no GUI to
    //   prompt; common after `brew upgrade` invalidates the
    //   codesign-bound ACL on the existing master-key entry.
    // -25293 errSecAuthFailed: explicit ACL denial.
    matches!(code, -25308 | -25293).then(|| KeyStoreError::BackendUnavailable {
        backend,
        // io::Error::other is the workspace's existing idiom for boxing
        // a String into `dyn Error + Send + Sync` (see telemetry/mod.rs).
        source: Box::new(std::io::Error::other(format!("{sf_err} (OSStatus {code})"))),
    })
}

/// Map a `tokio::task::JoinError` into our `KeyStoreError` surface.
/// Used by every async wrapper that dispatches to `spawn_blocking`.
pub(crate) fn join_err(backend: &'static str, e: tokio::task::JoinError) -> KeyStoreError {
    KeyStoreError::PlatformError { backend, message: format!("spawn_blocking join failed: {e}") }
}

#[cfg(all(test, target_os = "macos"))]
#[allow(clippy::panic)]
mod macos_routing_tests {
    use super::*;
    use crate::error::KeyStoreError;
    use keyring::Error::PlatformFailure;
    use security_framework::base::Error as SfError;

    #[test]
    fn macos_acl_denial_codes_route_to_backend_unavailable() {
        for code in [-25308_i32, -25293] {
            let sf_err = SfError::from_code(code);
            let keyring_err = PlatformFailure(Box::new(sf_err));
            let routed = map_err("apple", keyring_err);
            match &routed {
                KeyStoreError::BackendUnavailable { backend, source } => {
                    assert_eq!(*backend, "apple");
                    let s = source.to_string();
                    assert!(
                        s.contains(&format!("OSStatus {code}")),
                        "source string should embed OSStatus, got: {s}"
                    );
                }
                other => {
                    panic!("OSStatus {code} should route to BackendUnavailable, got {other:?}")
                }
            }
            // Pin the load-bearing Display contract: the outer error's
            // Display MUST surface the OSStatus, otherwise log_fallback's
            // `{e}` formatting in lib.rs swallows the code before it
            // reaches operator stderr.
            let displayed = routed.to_string();
            assert!(
                displayed.contains(&format!("OSStatus {code}")),
                "outer Display should embed OSStatus, got: {displayed}"
            );
        }
    }

    #[test]
    fn macos_other_platform_codes_remain_platform_error() {
        // -25299 errSecDuplicateItem — explicitly NOT an ACL denial.
        // Plan A intentionally leaves these as opaque PlatformError so a
        // misconfigured keychain doesn't silently drop the user into
        // passphrase mode.
        let sf_err = SfError::from_code(-25299);
        let keyring_err = PlatformFailure(Box::new(sf_err));
        let routed = map_err("apple", keyring_err);
        assert!(
            matches!(routed, KeyStoreError::PlatformError { .. }),
            "non-ACL codes must still surface as PlatformError, got {routed:?}",
        );
    }
}
