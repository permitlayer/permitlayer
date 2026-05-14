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

#[cfg(any(target_os = "linux", target_os = "windows"))]
use zeroize::{Zeroize, Zeroizing};

use crate::error::KeyStoreError;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use crate::{DeleteOutcome, MASTER_KEY_LEN};

/// Probe the keychain backend by constructing an entry against
/// `account` and attempting a read. Tolerates `NoEntry`; real
/// failures surface as `BackendUnavailable`. Any retrieved bytes are
/// zeroized immediately.
///
/// Linux + Windows only post-Story 7.26: macOS dispatches to its
/// own probe in `macos::MacKeyStore::new` which targets
/// System.keychain via `keyring::Entry::new_with_target("System", ...)`.
#[cfg(any(target_os = "linux", target_os = "windows"))]
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

/// Read back a value from a keychain entry that we just wrote,
/// retrying briefly to absorb the keychain's read-after-write
/// consistency window. On macOS specifically, an `entry.get_secret()`
/// immediately following a successful `entry.set_secret()` can return
/// `errSecItemNotFound` (`keyring::Error::NoEntry`) even though the
/// write succeeded — usually the next attempt sees the entry. rc.10
/// shipped without this retry and hard-failed daemon boot on a fresh
/// install when the consistency window fired.
///
/// Returns:
/// - `Ok(Some(bytes))` if any attempt saw the entry.
/// - `Ok(None)` if every attempt returned `NoEntry`. The caller
///   decides whether that's a recoverable race outcome or a fatal
///   "set silently failed" platform error.
/// - `Err(...)` for any non-`NoEntry` error from the keychain.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn read_after_write_with_retry(entry: &keyring::Entry) -> Result<Option<Vec<u8>>, keyring::Error> {
    read_after_write_with_retry_inner(|| entry.get_secret())
}

/// Closure-form of [`read_after_write_with_retry`] for unit testing.
/// Production callers thread `|| entry.get_secret()` through the
/// public wrapper above; tests can supply a closure that fails the
/// first N times and then succeeds, deterministically pinning the
/// retry behavior on every CI leg without needing a real keychain.
#[cfg(any(target_os = "linux", target_os = "windows", test))]
fn read_after_write_with_retry_inner<F>(
    mut get_secret: F,
) -> Result<Option<Vec<u8>>, keyring::Error>
where
    F: FnMut() -> Result<Vec<u8>, keyring::Error>,
{
    // 5 attempts × 50ms = 200ms total budget. There's no published
    // SLA for the Apple Keychain consistency window; rc.10 saw it
    // exceed 0ms ("immediate readback fails") and the previous draft
    // of this fix used 3×25ms (75ms total) which the implementation
    // review flagged as too thin under sustained codesign-ACL load.
    // 200ms is a round-trip noticeable to a human at boot but well
    // under any operator-facing UX threshold. If the field reports
    // exhaustion, this is the constant to tune.
    const ATTEMPTS: u32 = 5;
    const SLEEP: std::time::Duration = std::time::Duration::from_millis(50);
    for attempt in 0..ATTEMPTS {
        match get_secret() {
            Ok(bytes) => return Ok(Some(bytes)),
            Err(keyring::Error::NoEntry) => {
                if attempt + 1 < ATTEMPTS {
                    std::thread::sleep(SLEEP);
                    continue;
                }
                return Ok(None);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// Fetch the key at `account`, generating + persisting a fresh
/// random key on first call if none exists. Used by `master_key()`
/// at boot.
///
/// The returned key is always what's currently in the keychain (the
/// persistence contract `KeyStore::master_key` documents). After
/// minting, we always read back through [`read_after_write_with_retry`]
/// — that gives us:
///
/// - **Apple Keychain consistency-window tolerance.** A successful
///   `set_secret` can be followed by a `NoEntry` on the immediate
///   readback; the retry absorbs this.
/// - **Race convergence.** If two daemons race on a fresh install,
///   whichever `set_secret` won is what the readback sees, and both
///   processes return that same key.
/// - **Surfaced set errors.** If `set_secret` failed AND the readback
///   ultimately can't see any entry, the original `set_secret` error
///   (not the opaque "no entry" symptom) is what bubbles up — so an
///   operator hitting `errSecAuthFailed`, `Ambiguous`, etc. sees the
///   real cause classified through `map_err`'s normal routing
///   (including the macOS ACL-denial classification from Plan A).
#[cfg(any(target_os = "linux", target_os = "windows"))]
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
            // Attempt to persist. We hold onto any error and only
            // surface it at the end if the readback also fails to
            // see any entry — that combination ("set failed AND
            // nothing's there") means our set is the proximate
            // cause. If a racer's set succeeded in the meantime,
            // the readback will see their bytes and we converge on
            // those, ignoring our own set's error (the contract is
            // "the returned key is what's persisted," and persisted
            // bytes exist).
            let set_result = entry.set_secret(&*key);
            match read_after_write_with_retry(&entry).map_err(|e| map_err(backend, e))? {
                Some(mut bytes) => {
                    let result = read_key_from_bytes(&bytes);
                    bytes.zeroize();
                    result
                }
                None => {
                    // No entry across every retry attempt. If our
                    // `set_secret` returned an error, that error is
                    // the real cause — route through `map_err` so
                    // ACL-class denials (Plan A's
                    // `classify_macos_platform_failure` for -25308
                    // and -25293) get classified as
                    // `BackendUnavailable` with their OSStatus
                    // surfaced via `BackendUnavailable`'s
                    // `: {source}` Display, and `Ambiguous` /
                    // `Invalid` / etc surface as `PlatformError`
                    // with the keyring crate's actual error text
                    // instead of the opaque "no entry" symptom.
                    if let Err(set_err) = set_result {
                        return Err(map_err(backend, set_err));
                    }
                    // `set_secret` returned `Ok(())` but nothing's
                    // persisted — pathological case where the
                    // keychain accepted the call without committing.
                    // No underlying keyring error to route; emit a
                    // structured `PlatformError` so the operator
                    // sees a breadcrumb (visible at
                    // `AGENTSSO_LOG__LEVEL=debug` via the
                    // `error_chain` field on the bootstrap log
                    // site).
                    Err(KeyStoreError::PlatformError {
                        backend,
                        message: "set_secret returned Ok but the keychain has no entry on \
                                  read-back after retries — write did not persist (possible \
                                  silent rejection by codesign/ACL gate)"
                            .into(),
                    })
                }
            }
        }
        Err(e) => Err(map_err(backend, e)),
    }
}

/// Write `key` to `account`, then read-back-verify with constant-
/// time comparison. Catches keychains that buffer writes or silently
/// discard them on permission quirks.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) fn set_and_verify_at_account(
    backend: &'static str,
    account: &str,
    key: &[u8; MASTER_KEY_LEN],
    on_mismatch_message: &'static str,
) -> Result<(), KeyStoreError> {
    let entry =
        keyring::Entry::new(crate::MASTER_KEY_SERVICE, account).map_err(|e| map_err(backend, e))?;
    entry.set_secret(key).map_err(|e| map_err(backend, e))?;
    // Same Apple Keychain consistency window that bites the bootstrap
    // path bites here too: a bare `entry.get_secret()` immediately
    // after `set_secret` can return `NoEntry`. Use the retry helper.
    // If every retry returns `NoEntry`, the write didn't persist —
    // that's a fatal error for rotation (the daemon would proceed
    // thinking the new key was committed when it wasn't).
    let mut read_back =
        match read_after_write_with_retry(&entry).map_err(|e| map_err(backend, e))? {
            Some(bytes) => bytes,
            None => {
                return Err(KeyStoreError::PlatformError {
                    backend,
                    message: "set_secret returned Ok but the keychain has no entry on \
                              read-back after retries — write did not persist"
                        .into(),
                });
            }
        };
    let eq = read_back.len() == MASTER_KEY_LEN && constant_time_eq(&read_back, key);
    read_back.zeroize();
    if !eq {
        return Err(KeyStoreError::PlatformError { backend, message: on_mismatch_message.into() });
    }
    Ok(())
}

/// Read the key at `account` if it exists. Returns `Ok(None)` if
/// no entry was ever written; surfaces other errors verbatim.
#[cfg(any(target_os = "linux", target_os = "windows"))]
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
#[cfg(any(target_os = "linux", target_os = "windows"))]
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
#[cfg(any(target_os = "linux", target_os = "windows"))]
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
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn read_key_from_bytes(bytes: &[u8]) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, KeyStoreError> {
    if bytes.len() != MASTER_KEY_LEN {
        return Err(KeyStoreError::MalformedMasterKey {
            expected_len: MASTER_KEY_LEN,
            actual_len: bytes.len(),
            reason: crate::MalformedReason::BadLength,
        });
    }
    let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    key.copy_from_slice(bytes);
    Ok(key)
}

/// Constant-time byte comparison via `subtle`. Used after read-back
/// to match the discipline expected by the rotation orchestrator
/// (which uses `subtle` for the same purpose).
#[cfg(any(target_os = "linux", target_os = "windows"))]
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

#[cfg(test)]
#[allow(clippy::panic)]
mod read_after_write_tests {
    use super::*;
    use std::cell::Cell;

    /// rc.10's load-bearing failure mode: Apple Keychain returns
    /// `NoEntry` on a just-written entry within a brief consistency
    /// window. The retry helper must absorb this. This test is
    /// deterministic and runs on every CI leg (no real keychain
    /// needed).
    #[test]
    fn retries_through_consistency_window() {
        let attempts = Cell::new(0_u32);
        let result = read_after_write_with_retry_inner(|| {
            let n = attempts.get();
            attempts.set(n + 1);
            if n == 0 { Err(keyring::Error::NoEntry) } else { Ok(b"persisted-bytes".to_vec()) }
        });
        match result {
            Ok(Some(bytes)) => assert_eq!(bytes, b"persisted-bytes"),
            other => panic!("expected Ok(Some(bytes)), got {other:?}"),
        }
        assert_eq!(attempts.get(), 2, "should have retried exactly once");
    }

    /// Pathological case: NoEntry every time. The retry exhausts and
    /// the helper signals "the keychain is empty after all attempts"
    /// via `Ok(None)` so callers can route it to a structured error
    /// instead of leaking the raw `keyring::Error::NoEntry` Display.
    #[test]
    fn returns_none_when_all_attempts_fail() {
        let attempts = Cell::new(0_u32);
        let result = read_after_write_with_retry_inner(|| {
            let n = attempts.get();
            attempts.set(n + 1);
            Err(keyring::Error::NoEntry)
        });
        assert!(matches!(result, Ok(None)), "got {result:?}");
        assert_eq!(attempts.get(), 5, "should have tried exactly ATTEMPTS times");
    }

    /// Non-NoEntry errors propagate immediately without retry — those
    /// are real failures we shouldn't paper over with a sleep+loop.
    #[test]
    fn propagates_non_noentry_errors_without_retry() {
        let attempts = Cell::new(0_u32);
        let result = read_after_write_with_retry_inner(|| {
            attempts.set(attempts.get() + 1);
            Err(keyring::Error::Invalid("test-error".into(), "test-context".into()))
        });
        assert!(matches!(result, Err(keyring::Error::Invalid(..))), "got {result:?}");
        assert_eq!(attempts.get(), 1, "non-NoEntry errors must not retry");
    }
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
