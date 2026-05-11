//! macOS Keychain Services adapter — System.keychain backend
//! (Story 7.26, rc.22 macOS LaunchDaemon redesign).
//!
//! Persists the master key + previous master-key slot in
//! `/Library/Keychains/System.keychain` under the service id
//! `dev.permitlayer.master-key` (renamed from
//! `io.permitlayer.master-key` in Story 7.26 alongside the
//! LaunchDaemon label rename `dev.agentsso.daemon` →
//! `dev.permitlayer.daemon`).
//!
//! # Why System.keychain (not the user login.keychain)
//!
//! Per Story 7.25 (Sprint Change Proposal 2026-05-10): the rc.22
//! daemon runs as a system LaunchDaemon (root, no GUI session)
//! after `sudo agentsso service install`. The user login.keychain
//! is unwritable from a non-Aqua context (`SecurityAgent` only runs
//! in GUI sessions); System.keychain has no such constraint when
//! the caller is root.
//!
//! # Why `security add-generic-password -A` shell-out for WRITE
//!
//! The `keyring` 3.6 crate's `set_secret` hardcodes
//! `ptr::null_mut()` for the `initialAccess` parameter of
//! `SecKeychainAddGenericPassword` (verified against
//! `security-framework-2.11.1/src/os/macos/passwords.rs:288-307`),
//! which produces the default DR-bound ACL. After `brew upgrade`
//! swaps the daemon binary, the new-CDHash daemon's read returns
//! `-25308 errSecInteractionNotAllowed` (V2-EXT P1.4 empirical
//! 2026-05-10).
//!
//! `/usr/bin/security add-generic-password -A` produces an
//! `allowAllForm` ACL with no DR binding, no application list, no
//! subject form — verified in Apple's open-source `Security` tree
//! (`SecurityTool/macOS/access_utils.c:104-106`,
//! `OSX/libsecurity_keychain/lib/SecACL.cpp:172-205`,
//! `OSX/libsecurity_keychain/lib/ACL.cpp:94-111`). Cross-CDHash
//! reads succeed structurally because there's no application list
//! to compare against.
//!
//! # Why `keyring::Entry::new_with_target("System", ...)` for READ
//!
//! That's the documented keyring 3.6 idiom for non-default
//! keychain targets — verified at
//! `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/keyring-3.6.3/src/macos.rs:159-251`.
//! `MacKeychainDomain::System` → `SecPreferencesDomain::System` →
//! `SecKeychainCopyDomainDefault(kSecPreferencesDomainSystem)`.
//! Reads don't care about ACL form; `allowAllForm` lets any caller
//! through.
//!
//! # Argv exposure tradeoff for `-w <hex>`
//!
//! `security(1)` man page + `SecurityTool/macOS/keychain_add.c`
//! confirm the `-w` flag has no documented stdin form: `-w <value>`
//! puts the secret in argv (`ps auxe`-visible for milliseconds);
//! `-w` with no value triggers `getpass()` reading from `/dev/tty`
//! (not usable from a daemon). v1 accepts the argv exposure: WRITE
//! happens at install time as root, exposure window is
//! milliseconds, and the secret immediately afterward is at-rest in
//! System.keychain. The native-FFI alternative
//! (`SecAccessCreate(NULL_array)` + `SecKeychainItemCreateFromContent`)
//! is a single localized change inside this file (or moved to the
//! `permitlayer-platform-macos` crate) if a future audit requires
//! zero argv leak.
//!
//! # async discipline
//!
//! All Security.framework + `Command::output` calls are dispatched
//! via `tokio::task::spawn_blocking` so a slow keychain op (XPC
//! round-trip, syspolicy gate, etc.) cannot starve the runtime.

#![cfg(target_os = "macos")]

use std::process::Command;
use zeroize::{Zeroize, Zeroizing};

use crate::error::KeyStoreError;
use crate::keyring_shared as shared;
use crate::{
    DeleteOutcome, KeyStore, MASTER_KEY_ACCOUNT, MASTER_KEY_LEN, MASTER_KEY_PREVIOUS_ACCOUNT,
    MASTER_KEY_SERVICE,
};

const BACKEND: &str = "apple";

/// macOS keychain target literal recognized by `keyring 3.6` —
/// dispatches to `kSecPreferencesDomainSystem` via
/// `SecKeychain::default_for_domain`.
const KEYCHAIN_TARGET: &str = "System";

/// Path of the macOS System.keychain file. Used as the trailing
/// positional argument to `/usr/bin/security` invocations.
const SYSTEM_KEYCHAIN_PATH: &str = "/Library/Keychains/System.keychain";

/// macOS Keychain Services adapter — System.keychain backend.
/// Stateless; each operation constructs a fresh `keyring::Entry` or
/// shells out to `/usr/bin/security`.
pub struct MacKeyStore {
    _private: (),
}

impl MacKeyStore {
    /// Construct and probe the System.keychain backend.
    ///
    /// Probe = attempt a READ at the master-key account. Tolerates
    /// `NoEntry` (fresh install before first boot has minted the
    /// key); surfaces real errors as `BackendUnavailable`.
    pub fn new() -> Result<Self, KeyStoreError> {
        probe_system_keychain(MASTER_KEY_ACCOUNT)?;
        Ok(Self { _private: () })
    }
}

#[async_trait::async_trait]
impl KeyStore for MacKeyStore {
    async fn master_key(&self) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, KeyStoreError> {
        tokio::task::spawn_blocking(|| read_or_mint_master_key(MASTER_KEY_ACCOUNT))
            .await
            .map_err(|e| shared::join_err(BACKEND, e))?
    }

    async fn set_master_key(&self, key: &[u8; MASTER_KEY_LEN]) -> Result<(), KeyStoreError> {
        let key_copy: Zeroizing<[u8; MASTER_KEY_LEN]> = Zeroizing::new(*key);
        tokio::task::spawn_blocking(move || {
            write_then_verify_at_account(MASTER_KEY_ACCOUNT, &key_copy)
        })
        .await
        .map_err(|e| shared::join_err(BACKEND, e))?
    }

    async fn delete_master_key(&self) -> Result<DeleteOutcome, KeyStoreError> {
        tokio::task::spawn_blocking(|| delete_account(MASTER_KEY_ACCOUNT))
            .await
            .map_err(|e| shared::join_err(BACKEND, e))?
    }

    async fn set_previous_master_key(
        &self,
        previous: &[u8; MASTER_KEY_LEN],
    ) -> Result<(), KeyStoreError> {
        let prev_copy: Zeroizing<[u8; MASTER_KEY_LEN]> = Zeroizing::new(*previous);
        tokio::task::spawn_blocking(move || {
            write_then_verify_at_account(MASTER_KEY_PREVIOUS_ACCOUNT, &prev_copy)
        })
        .await
        .map_err(|e| shared::join_err(BACKEND, e))?
    }

    async fn previous_master_key(
        &self,
    ) -> Result<Option<Zeroizing<[u8; MASTER_KEY_LEN]>>, KeyStoreError> {
        tokio::task::spawn_blocking(|| read_account(MASTER_KEY_PREVIOUS_ACCOUNT))
            .await
            .map_err(|e| shared::join_err(BACKEND, e))?
    }

    async fn clear_previous_master_key(&self) -> Result<(), KeyStoreError> {
        tokio::task::spawn_blocking(|| clear_account(MASTER_KEY_PREVIOUS_ACCOUNT))
            .await
            .map_err(|e| shared::join_err(BACKEND, e))?
    }
}

// ── Private helpers ─────────────────────────────────────────────────

/// Build a `keyring::Entry` targeted at System.keychain for the
/// given account.
fn entry_for_system_keychain(account: &str) -> Result<keyring::Entry, KeyStoreError> {
    keyring::Entry::new_with_target(KEYCHAIN_TARGET, MASTER_KEY_SERVICE, account)
        .map_err(|e| shared::map_err(BACKEND, e))
}

/// Probe by attempting a single `get_secret` on the master-key
/// entry. Tolerates `NoEntry` (the fresh-install case).
fn probe_system_keychain(account: &str) -> Result<(), KeyStoreError> {
    let entry = entry_for_system_keychain(account)?;
    match entry.get_secret() {
        Ok(mut bytes) => {
            bytes.zeroize();
            Ok(())
        }
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(shared::map_err(BACKEND, e)),
    }
}

/// Read the master-key bytes at `account` if present. Bytes are
/// stored hex-encoded (per [`write_master_key_via_security_a`]'s
/// encoding contract); decode to 32 raw bytes here.
///
/// Returns `Ok(None)` when no entry exists (fresh install).
fn read_account(account: &str) -> Result<Option<Zeroizing<[u8; MASTER_KEY_LEN]>>, KeyStoreError> {
    let entry = entry_for_system_keychain(account)?;
    match entry.get_secret() {
        Ok(mut bytes) => {
            let result = decode_hex_master_key(&bytes);
            bytes.zeroize();
            result.map(Some)
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(shared::map_err(BACKEND, e)),
    }
}

/// First-boot read-before-write gate (Story 7.26 AC #1):
///
/// 1. READ — if the master key exists at `account` and decodes to
///    32 valid bytes, return it.
/// 2. CORRUPTED — if the entry exists but bytes are malformed
///    (wrong length after hex-decode), surface
///    `MalformedMasterKey` so the daemon's `StartError::MasterKeyCall`
///    path renders the operator-facing remediation banner.
/// 3. NOT FOUND — mint a fresh 32-byte key from `OsRng`, write via
///    `/usr/bin/security add-generic-password -A` (no DR-bound
///    ACL), read back to verify the write committed, return.
///
/// Audit-log emission for the first-boot mint event happens at the
/// daemon-level call site
/// (`crates/permitlayer-daemon/src/cli/start.rs::bootstrap_from_keystore`)
/// because the `permitlayer-keystore` crate cannot depend on the
/// daemon's audit module. This function emits a structured
/// `tracing::info!` event with `event = "master_key.boot.first_boot_complete"`
/// plus a fingerprint that the daemon-side caller correlates into an
/// audit record.
fn read_or_mint_master_key(
    account: &str,
) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, KeyStoreError> {
    if let Some(key) = read_account(account)? {
        tracing::info!(
            event = "master_key.boot.existing",
            fingerprint = %fingerprint(key.as_slice()),
            keychain_target = KEYCHAIN_TARGET,
            service_id = MASTER_KEY_SERVICE,
            "loaded existing master key from System.keychain"
        );
        return Ok(key);
    }

    // Fresh install: mint + write + verify.
    use rand::RngCore;
    let mut new_key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    rand::rngs::OsRng.fill_bytes(&mut *new_key);

    write_master_key_via_security_a(account, &new_key)?;

    // Defensive read-back. Catches the pathological "security exit
    // 0 but item not stored" case. Unlike rc.10's
    // read-after-write-with-retry (which absorbed an in-process
    // `keyring` API quirk), this read crosses a process boundary —
    // `/usr/bin/security` returned only after its own commit + flush,
    // so a `NoEntry` here means the write genuinely did not persist.
    match read_account(account)? {
        // P5 (Story 7.26 code review): constant-time comparison via
        // `subtle::ConstantTimeEq` to match the discipline already
        // enforced by `keyring_shared::constant_time_eq` on the
        // Linux/Windows path.
        Some(verified) if ct_eq(verified.as_slice(), new_key.as_slice()) => {
            tracing::info!(
                event = "master_key.boot.first_boot_complete",
                fingerprint = %fingerprint(new_key.as_slice()),
                keychain_target = KEYCHAIN_TARGET,
                service_id = MASTER_KEY_SERVICE,
                "minted fresh master key in System.keychain"
            );
            Ok(new_key)
        }
        // P8 (Story 7.26 code review): concurrent first-boot self-heal.
        // If the read-back returns *different* bytes, another daemon
        // raced us to mint and its key is the one persisted (our `-U`
        // upsert may have clobbered it, or its `-U` clobbered ours;
        // either way, whatever survived is the canonical entry). The
        // recovery is to re-read and use the surviving key rather than
        // forcing the operator to restart. We mint at most one extra
        // 32-byte buffer that immediately drops/zeroizes.
        Some(_) => match read_account(account)? {
            Some(canonical) => {
                tracing::info!(
                    event = "master_key.boot.first_boot_race_recovered",
                    fingerprint = %fingerprint(canonical.as_slice()),
                    keychain_target = KEYCHAIN_TARGET,
                    service_id = MASTER_KEY_SERVICE,
                    "first-boot race detected; adopted the surviving key from System.keychain"
                );
                Ok(canonical)
            }
            None => Err(KeyStoreError::PlatformError {
                backend: BACKEND,
                message: "first-boot mint read-back returned different bytes, then NoEntry on \
                          re-read — keychain state changed under us (concurrent delete?). \
                          Restart the daemon to retry the first-boot gate."
                    .into(),
            }),
        },
        None => Err(KeyStoreError::PlatformError {
            backend: BACKEND,
            message: "first-boot mint succeeded per `security` exit 0 but read-back returned \
                      NoEntry — write did not persist (possible silent rejection)"
                .into(),
        }),
    }
}

/// Constant-time byte comparison for read-back equality. Mirrors
/// [`keyring_shared::constant_time_eq`] (which is Linux/Windows-only
/// on rc.22+ and therefore not reachable from this module).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Operator-mode WRITE for `agentsso rotate-key` (post-first-boot).
/// Idempotent via `-A -U`; verifies via read-back.
fn write_then_verify_at_account(
    account: &str,
    key: &[u8; MASTER_KEY_LEN],
) -> Result<(), KeyStoreError> {
    write_master_key_via_security_a(account, key)?;
    match read_account(account)? {
        // P5 (Story 7.26 code review): constant-time read-back equality.
        Some(verified) if ct_eq(verified.as_slice(), key.as_slice()) => Ok(()),
        Some(_) => Err(KeyStoreError::PlatformError {
            backend: BACKEND,
            message: "set_master_key read-back did not match written value".into(),
        }),
        None => Err(KeyStoreError::PlatformError {
            backend: BACKEND,
            message: "set_master_key: `security` exit 0 but read-back returned NoEntry".into(),
        }),
    }
}

/// Idempotent delete (no error if entry was already absent).
fn clear_account(account: &str) -> Result<(), KeyStoreError> {
    match delete_account(account)? {
        DeleteOutcome::Removed | DeleteOutcome::AlreadyAbsent => Ok(()),
    }
}

/// Distinguishing delete: `Removed` vs `AlreadyAbsent`. Used by
/// `delete_master_key()` so the operator-facing audit log can
/// surface which case fired during `agentsso uninstall`.
fn delete_account(account: &str) -> Result<DeleteOutcome, KeyStoreError> {
    let entry = entry_for_system_keychain(account)?;
    match entry.delete_credential() {
        Ok(()) => Ok(DeleteOutcome::Removed),
        Err(keyring::Error::NoEntry) => Ok(DeleteOutcome::AlreadyAbsent),
        Err(e) => Err(shared::map_err(BACKEND, e)),
    }
}

/// WRITE the master key (or any key-shaped account) to
/// System.keychain via `/usr/bin/security add-generic-password -A`.
///
/// Encoding contract: bytes are stored hex-encoded (64 ASCII chars
/// for a 32-byte key). The READ path
/// ([`decode_hex_master_key`]) interprets the keychain bytes as hex
/// and decodes back to `[u8; 32]`. Hex was chosen because:
///
/// - `security` stores the `-w <value>` argv string verbatim (no
///   decoding); printable ASCII survives the argv string boundary
///   cleanly (no NUL, no quoting concerns).
/// - The same encoding is used for both first-boot mint and
///   Operator-mode rotation, so READ doesn't need to dispatch on
///   provenance.
///
/// Argv exposure: per `security(1)` man page + Apple
/// `SecurityTool/macOS/keychain_add.c`, `-w` has no stdin form. The
/// secret is in argv for the duration of the `security`
/// invocation (~milliseconds). See module-level doc-comment for the
/// tradeoff rationale and the FFI escape hatch.
fn write_master_key_via_security_a(
    account: &str,
    key: &[u8; MASTER_KEY_LEN],
) -> Result<(), KeyStoreError> {
    // P4 (Story 7.26 code review): write into a single pre-allocated
    // buffer using `write!` rather than per-byte `format!`+`collect`.
    // The old form allocated 32 short-lived 2-char `String`s that
    // dropped without zeroization, leaving byte fragments of the
    // master key on the freed heap. One buffer, one zeroize.
    //
    // P3 (Story 7.26 code review): wrap the buffer in a value that
    // zeroizes on Drop so EVERY exit path scrubs it — the prior
    // `?` on `Command::output()` skipped the explicit zeroize when
    // the spawn itself failed.
    use std::fmt::Write;
    struct ZeroizingHex(String);
    impl Drop for ZeroizingHex {
        fn drop(&mut self) {
            self.0.zeroize();
        }
    }
    let mut secret_hex = ZeroizingHex(String::with_capacity(MASTER_KEY_LEN * 2));
    for b in key.iter() {
        // `write!` into a `String` is infallible (the impl of
        // `fmt::Write` for `String` never returns an error), so the
        // `Result` here can be safely discarded.
        let _ = write!(&mut secret_hex.0, "{:02x}", b);
    }

    let output = Command::new("/usr/bin/security")
        // P6 (Story 7.26 code review): explicitly null stdin so the
        // daemon never blocks if `security` decides to prompt
        // (e.g., locked-keychain unlock prompt).
        .stdin(std::process::Stdio::null())
        .args([
            "add-generic-password",
            "-s",
            MASTER_KEY_SERVICE,
            "-a",
            account,
            "-A", // no DR-bound ACL (load-bearing — produces allowAllForm)
            "-U", // upsert OK; read-before-write gate is the source of truth for "first boot"
            "-w",
            secret_hex.0.as_str(),
            SYSTEM_KEYCHAIN_PATH,
        ])
        .output()
        .map_err(|e| KeyStoreError::BackendUnavailable { backend: BACKEND, source: Box::new(e) })?;
    // `secret_hex` is dropped at end-of-scope; its Drop impl zeroizes
    // the buffer regardless of which branch below returns.

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let exit = output.status.code().map_or_else(|| "signal".to_string(), |c| c.to_string());
        return Err(KeyStoreError::PlatformError {
            backend: BACKEND,
            message: format!(
                "/usr/bin/security add-generic-password -A exit={exit}: {}",
                stderr.trim()
            ),
        });
    }
    Ok(())
}

/// Decode hex bytes (`Vec<u8>` of ASCII hex chars) → `[u8; 32]`.
/// Surfaces `MalformedMasterKey` on length or character errors so
/// the daemon's existing `StartError::MasterKeyCall` rendering
/// kicks in.
fn decode_hex_master_key(
    hex_bytes: &[u8],
) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, KeyStoreError> {
    if hex_bytes.len() != MASTER_KEY_LEN * 2 {
        return Err(KeyStoreError::MalformedMasterKey {
            expected_len: MASTER_KEY_LEN * 2,
            actual_len: hex_bytes.len(),
        });
    }
    let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    for (i, chunk) in hex_bytes.chunks(2).enumerate() {
        let hi = decode_hex_nibble(chunk[0])?;
        let lo = decode_hex_nibble(chunk[1])?;
        key[i] = (hi << 4) | lo;
    }
    Ok(key)
}

fn decode_hex_nibble(c: u8) -> Result<u8, KeyStoreError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(10 + c - b'a'),
        b'A'..=b'F' => Ok(10 + c - b'A'),
        _ => Err(KeyStoreError::PlatformError {
            backend: BACKEND,
            message: format!("non-hex character 0x{c:02x} in System.keychain master-key bytes"),
        }),
    }
}

/// 8-hex-char SHA-256 prefix of `bytes` for audit-log fingerprinting.
/// Exposed via `tracing` field from
/// [`read_or_mint_master_key`]; the daemon-side caller correlates it
/// into the `MasterKeyFirstBoot` audit-event payload.
fn fingerprint(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    format!("{:02x}{:02x}{:02x}{:02x}", digest[0], digest[1], digest[2], digest[3])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn decode_hex_round_trips_known_value() {
        let raw: [u8; MASTER_KEY_LEN] = [0x42; MASTER_KEY_LEN];
        let hex_str: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
        let decoded = decode_hex_master_key(hex_str.as_bytes()).unwrap();
        assert_eq!(decoded.as_slice(), raw.as_slice());
    }

    #[test]
    fn decode_hex_rejects_short_input() {
        let err = decode_hex_master_key(b"deadbeef").unwrap_err();
        match err {
            KeyStoreError::MalformedMasterKey { expected_len, actual_len } => {
                assert_eq!(expected_len, 64);
                assert_eq!(actual_len, 8);
            }
            other => panic!("expected MalformedMasterKey, got {other:?}"),
        }
    }

    #[test]
    fn decode_hex_rejects_non_hex_char() {
        let mut bytes = vec![b'a'; 64];
        bytes[5] = b'g'; // not a hex char
        let err = decode_hex_master_key(&bytes).unwrap_err();
        assert!(matches!(err, KeyStoreError::PlatformError { .. }));
    }

    #[test]
    fn fingerprint_is_8_hex_chars() {
        let f = fingerprint(&[0u8; 32]);
        assert_eq!(f.len(), 8);
        assert!(f.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Round-trip the master key through `write_master_key_via_security_a`
    /// and `read_account`. Requires `sudo` (System.keychain WRITE
    /// requires root); gated behind `AGENTSSO_KEYCHAIN_DESTRUCTIVE_TEST=1`
    /// so a normal `cargo nextest` run on a developer's machine
    /// doesn't clobber any existing master-key entry.
    #[test]
    #[ignore = "destructive: writes to /Library/Keychains/System.keychain; run with sudo + \
                AGENTSSO_KEYCHAIN_DESTRUCTIVE_TEST=1"]
    fn master_key_round_trip_via_system_keychain() {
        if std::env::var("AGENTSSO_KEYCHAIN_DESTRUCTIVE_TEST").as_deref() != Ok("1") {
            eprintln!(
                "skipping destructive System.keychain round-trip — set \
                 AGENTSSO_KEYCHAIN_DESTRUCTIVE_TEST=1 + sudo to enable"
            );
            return;
        }
        // Use a per-test account so we don't touch the canonical
        // master entry on a dev machine that already has one.
        let test_account = "test-7-26-round-trip";
        let key: [u8; MASTER_KEY_LEN] = [0x7eu8; MASTER_KEY_LEN];

        // P7 (Story 7.26 code review): Drop-based cleanup guard so a
        // panicking assertion does not leave the test entry stranded
        // in System.keychain. The guard's Drop runs even on panic
        // unwind; failure to delete is tolerated (it'll surface as a
        // double-cleanup error from the explicit delete below, or
        // the dev can clean up by hand).
        struct CleanupGuard(&'static str);
        impl Drop for CleanupGuard {
            fn drop(&mut self) {
                let _ = delete_account(self.0);
            }
        }
        let _cleanup = CleanupGuard(test_account);

        write_master_key_via_security_a(test_account, &key).expect("write failed");
        let read_back = read_account(test_account).expect("read failed").expect("no entry");
        assert!(ct_eq(read_back.as_slice(), key.as_slice()), "round-trip bytes mismatch");

        let outcome = delete_account(test_account).expect("delete failed");
        assert_eq!(outcome, DeleteOutcome::Removed);
        // CleanupGuard re-runs delete here on scope exit — idempotent
        // (returns AlreadyAbsent), no-op on the happy path.
    }
}
