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
    async fn master_key(&self) -> Result<crate::MasterKeyOutcome, KeyStoreError> {
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
            // Story 7.27 Round-2 review fix: treat empty (0-byte) entries
            // as `NoEntry` so the mint path engages and replaces the
            // useless inode via `-U` upsert. This handles the
            // pathological "operator manually inserted `security
            // add-generic-password ... -w \"\"`" case and the
            // partially-written-entry-from-killed-`security` case.
            // Wrong-length-but-non-empty entries still surface as
            // `MalformedMasterKey` (distinct from corruption — operator
            // needs to know to investigate).
            if bytes.is_empty() {
                tracing::warn!(
                    event = "master_key.boot.empty_entry_replaced",
                    keychain_target = KEYCHAIN_TARGET,
                    service_id = MASTER_KEY_SERVICE,
                    "found empty System.keychain entry at {MASTER_KEY_SERVICE}; treating as \
                     NoEntry so the mint path overwrites it"
                );
                bytes.zeroize();
                return Ok(None);
            }
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
fn read_or_mint_master_key(account: &str) -> Result<crate::MasterKeyOutcome, KeyStoreError> {
    // Story 7.27 Round-2 review fix: serialize the read+mint+write+
    // verify sequence across processes via `flock` on a sibling
    // lockfile. The LaunchDaemon singleton model normally prevents
    // two daemons racing here, but an operator running `agentsso
    // start` standalone while the LaunchDaemon is booting (or two
    // concurrent `service install` invocations) would otherwise
    // produce dual `first_boot=true` audit emissions for one
    // keychain entry, or a silent-clobber where one daemon overwrites
    // another's freshly-minted key. The lock is dropped at end of
    // function via `Flock<File>` RAII; lockfile persists for next
    // invocation.
    let _mint_lock = acquire_mint_lock()?;

    if let Some(key) = read_account(account)? {
        tracing::info!(
            event = "master_key.boot.existing",
            fingerprint = %fingerprint(key.as_slice()),
            keychain_target = KEYCHAIN_TARGET,
            service_id = MASTER_KEY_SERVICE,
            "loaded existing master key from System.keychain"
        );
        return Ok(crate::MasterKeyOutcome::new(key, false));
    }

    // Story 7.27 Round-2 review fix: surface a clear "must run as
    // root" error BEFORE attempting `security add-generic-password`
    // against System.keychain. Reads succeed for any caller (`-A`
    // ACL); writes require root. Without this check, non-root
    // callers got a generic `PlatformError { exit=1 stderr=… }`
    // with no remediation pointer. The probe path in
    // `MacKeyStore::new` stays caller-agnostic so unprivileged
    // tooling (e.g., `agentsso status` querying daemon state) can
    // still instantiate the keystore without minting.
    if !nix::unistd::geteuid().is_root() {
        return Err(KeyStoreError::PlatformError {
            backend: BACKEND,
            message: "minting the master key in /Library/Keychains/System.keychain requires \
                      root. The LaunchDaemon installed by `sudo agentsso setup` \
                      runs the daemon as root automatically; manual `agentsso start` from a \
                      user shell will fail here. Re-run via `sudo agentsso setup` \
                      (or `sudo agentsso start` for ad-hoc dev use)."
                .into(),
        });
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
            // Story 7.27 AC #16: replace the `tracing::info!` with
            // the typed `master-key-first-boot` audit event emitted
            // at the daemon-level call site (which holds the
            // dispatcher). Keep the tracing event as a backup
            // operations-log signal — different consumer (ops grep
            // vs compliance-audit reader).
            tracing::info!(
                event = "master_key.boot.first_boot_complete",
                fingerprint = %fingerprint(new_key.as_slice()),
                keychain_target = KEYCHAIN_TARGET,
                service_id = MASTER_KEY_SERVICE,
                "minted fresh master key in System.keychain"
            );
            Ok(crate::MasterKeyOutcome::new(new_key, true))
        }
        // P8 (Story 7.26 code review): concurrent first-boot self-heal.
        // If the read-back returns *different* bytes, another daemon
        // raced us to mint and its key is the one persisted (our `-U`
        // upsert may have clobbered it, or its `-U` clobbered ours;
        // either way, whatever survived is the canonical entry). The
        // recovery is to re-read and use the surviving key rather than
        // forcing the operator to restart. We mint at most one extra
        // 32-byte buffer that immediately drops/zeroizes.
        //
        // Story 7.27: race-recovered branch reports
        // `first_boot: false` — strictly speaking we *did* mint a
        // key in this call, but the surviving entry was minted by
        // the racing daemon. Reporting `first_boot: true` would
        // cause both daemons to fire the audit event for the same
        // keychain entry. The losing daemon's audit log gets the
        // tracing event below; the daemon-level call site emits the
        // typed audit event only on the unambiguous mint path.
        Some(_) => match read_account(account)? {
            Some(canonical) => {
                tracing::info!(
                    event = "master_key.boot.first_boot_race_recovered",
                    fingerprint = %fingerprint(canonical.as_slice()),
                    keychain_target = KEYCHAIN_TARGET,
                    service_id = MASTER_KEY_SERVICE,
                    "first-boot race detected; adopted the surviving key from System.keychain"
                );
                Ok(crate::MasterKeyOutcome::new(canonical, false))
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

/// Inter-process mint serialization lock. Acquired by
/// [`read_or_mint_master_key`] around the read+mint+write+verify
/// sequence so two concurrent daemons cannot both observe `NoEntry`
/// and race to mint distinct master keys.
///
/// Lockfile lives at `/Library/Application Support/permitlayer/
/// .master-key-mint.lock` in production (root-only-writable; matches
/// `paths::daemon_state_dir(None)` resolution). In test contexts
/// without that directory, falls back to `std::env::temp_dir()` so
/// unit tests that exercise the mint path don't require root-owned
/// state dirs.
///
/// Round-3 review fix: acquisition uses bounded-retry non-blocking
/// `LockExclusiveNonblock` (10 × 100ms) instead of indefinite
/// `LockExclusive`. A stuck previous mint holder would otherwise
/// hang every subsequent daemon startup forever with no actionable
/// error; the bounded retry surfaces `MintLockTimeout` after one
/// second so operators see the lock path and the EWOULDBLOCK errno.
///
/// **NFS / SMB caveat (Round-3 review note).** `nix::fcntl::Flock`
/// uses BSD `flock(2)` on macOS, which silently degrades to a no-op
/// on remote filesystems. The state dir
/// (`/Library/Application Support/permitlayer/`) is created on local
/// APFS by `agentsso service install` and should never be
/// bind-mounted to a remote FS. Operators who do so are off-spec —
/// the lock would silently not protect mint serialization.
///
/// The returned `Flock<File>` releases the lock on Drop (RAII).
///
/// **Defense-in-depth `fstat`-after-open (Round-3 review fix).** The
/// `O_NOFOLLOW` flag refuses to traverse a symlink at the FINAL
/// component, but the parent dir is reached via standard path
/// resolution (`create_dir_all` follows symlinks). An attacker who
/// can pre-create the lockfile path as a regular file with
/// permissive perms can win on the second invocation. We `fstat` the
/// opened fd and refuse if `st_uid` is neither geteuid() nor root,
/// or if `st_mode & 0o077 != 0`. Mode-0o600 is set on creation but
/// `O_CREAT` is a no-op if the file already exists — the existing
/// file's perms survive.
fn acquire_mint_lock_at(
    state_dir: &std::path::Path,
) -> Result<nix::fcntl::Flock<std::fs::File>, KeyStoreError> {
    let lock_path = state_dir.join(".master-key-mint.lock");
    // Ensure the parent directory exists. In production this is the
    // root-owned `paths::daemon_state_dir(None)`; in tests it's a
    // tempdir we control.
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| KeyStoreError::PlatformError {
            backend: BACKEND,
            message: format!("failed to create lock-dir {}: {e}", parent.display()),
        })?;
    }
    use std::os::unix::fs::OpenOptionsExt;
    let lock_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(&lock_path)
        .map_err(|e| KeyStoreError::PlatformError {
            backend: BACKEND,
            message: format!("failed to open mint-lock {}: {e}", lock_path.display()),
        })?;

    // Round-3 review fix: post-open `fstat` to refuse hostile
    // pre-created lockfiles. A local attacker with write into the
    // state-dir's parent could plant the lockfile with mode 0o666
    // before the daemon ever runs; `O_CREAT` is a no-op when the
    // file exists, so our 0o600 mode argument never takes effect.
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: we own the fd; libc::fstat reads into a fresh
        // `libc::stat` buffer.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // Wrapped in unsafe block — single libc call, fd is borrowed
        // for the duration. Acceptable here because this crate is
        // already a documented unsafe-isolation seam below
        // `#![forbid(unsafe_code)]` on the daemon.
        let rc = unsafe { libc::fstat(lock_file.as_raw_fd(), &mut st) };
        if rc != 0 {
            return Err(KeyStoreError::PlatformError {
                backend: BACKEND,
                message: format!(
                    "fstat({}) failed: {}",
                    lock_path.display(),
                    std::io::Error::last_os_error()
                ),
            });
        }
        // SAFETY: `geteuid` is async-signal-safe and always returns.
        let euid = unsafe { libc::geteuid() };
        let owner_ok = st.st_uid == euid || st.st_uid == 0;
        let mode_bits = u32::from(st.st_mode) & 0o777;
        if !owner_ok || (mode_bits & 0o077) != 0 {
            return Err(KeyStoreError::PlatformError {
                backend: BACKEND,
                message: format!(
                    "mint-lock {} has unsafe ownership/mode (uid={}, mode=0o{mode_bits:o}); \
                     refusing to use. Remove the file and re-run after the daemon's state dir \
                     is locked down.",
                    lock_path.display(),
                    st.st_uid,
                ),
            });
        }
    }

    // Round-3 review fix: bounded retry of `LockExclusiveNonblock`
    // instead of indefinite `LockExclusive`. Surfaces a clear error
    // after ~1 second if a previous mint holder is wedged.
    const MAX_RETRIES: u32 = 10;
    const RETRY_SLEEP: std::time::Duration = std::time::Duration::from_millis(100);
    let mut file = lock_file;
    for attempt in 0..MAX_RETRIES {
        match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock) {
            Ok(flock) => return Ok(flock),
            Err((returned_file, nix::errno::Errno::EWOULDBLOCK)) => {
                file = returned_file;
                if attempt + 1 < MAX_RETRIES {
                    std::thread::sleep(RETRY_SLEEP);
                }
            }
            Err((_returned_file, errno)) => {
                return Err(KeyStoreError::PlatformError {
                    backend: BACKEND,
                    message: format!(
                        "failed to acquire mint-lock {}: errno={errno}",
                        lock_path.display()
                    ),
                });
            }
        }
    }
    Err(KeyStoreError::PlatformError {
        backend: BACKEND,
        message: format!(
            "mint-lock {} held by another process for >{}ms — a previous mint may be wedged. \
             Check for stuck `agentsso start` processes; remove the stale lockfile only if no \
             daemon is running.",
            lock_path.display(),
            (MAX_RETRIES as u128) * RETRY_SLEEP.as_millis(),
        ),
    })
}

/// Production entry point: resolves the lock dir from the canonical
/// macOS state path (or `$TMPDIR` fallback for non-root dev/test) and
/// delegates to [`acquire_mint_lock_at`]. Round-3 review fix split
/// the resolution out so tests can supply an explicit path and so
/// the `is_dir()` TOCTOU probe is no longer load-bearing.
fn acquire_mint_lock() -> Result<nix::fcntl::Flock<std::fs::File>, KeyStoreError> {
    acquire_mint_lock_at(&resolve_mint_state_dir())
}

/// Resolve the mint-lock state dir. Production: the canonical macOS
/// daemon state dir; tests/dev: `$TMPDIR`.
///
/// The production state-dir is owned by `permitlayer-core::paths`,
/// which this crate cannot depend on (would create a cycle). The
/// fallback is acceptable because in production the daemon runs as
/// root with the canonical dir already created by `service install`;
/// in tests, the per-uid `$TMPDIR` serializes same-uid races (it
/// does NOT serialize root vs user, but tests don't span that
/// boundary).
fn resolve_mint_state_dir() -> std::path::PathBuf {
    let prod = std::path::PathBuf::from("/Library/Application Support/permitlayer");
    if prod.is_dir() {
        return prod;
    }
    std::env::temp_dir()
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
///
/// Story 7.27 Round-2 review fix: write path uses
/// `/usr/bin/security add-generic-password -A` (no DR-bound ACL).
/// Delete now goes through the same `/usr/bin/security delete-
/// generic-password` CLI for symmetric write/delete semantics —
/// avoids the asymmetry where `keyring::Entry::delete_credential()`
/// applied a different ACL discipline than the `-A`-written entry
/// expected. Reads still go through the `keyring` crate (which works
/// fine for `-A` entries since `allowAllForm` permits any root
/// caller).
fn delete_account(account: &str) -> Result<DeleteOutcome, KeyStoreError> {
    let output = Command::new("/usr/bin/security")
        .stdin(std::process::Stdio::null())
        // Round-3 review fix: pin locale to C so stderr-string
        // matching (`"could not be found"`,
        // `"SecKeychainSearchCopyNext"`) works on non-English macOS.
        // Without this, the AlreadyAbsent classification falls
        // through to PlatformError on locale-translated stderr.
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .args([
            "delete-generic-password",
            "-s",
            MASTER_KEY_SERVICE,
            "-a",
            account,
            SYSTEM_KEYCHAIN_PATH,
        ])
        .output()
        .map_err(|e| KeyStoreError::BackendUnavailable { backend: BACKEND, source: Box::new(e) })?;
    if output.status.success() {
        return Ok(DeleteOutcome::Removed);
    }
    // `security delete-generic-password` returns exit 44 (also
    // exit 1 in some Darwin releases) for "item not found";
    // stderr contains `SecKeychainSearchCopyNext`/`The specified
    // item could not be found in the keychain`.
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("could not be found") || stderr.contains("SecKeychainSearchCopyNext") {
        return Ok(DeleteOutcome::AlreadyAbsent);
    }
    let exit = output.status.code().map_or_else(|| "signal".to_string(), |c| c.to_string());
    Err(KeyStoreError::PlatformError {
        backend: BACKEND,
        message: format!(
            "/usr/bin/security delete-generic-password exit={exit}: {}",
            stderr.trim()
        ),
    })
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
/// invocation (~milliseconds; under syspolicyd queue pressure can
/// stretch to seconds per `project_slow_nextest_on_macos.md`).
///
/// **Threat model (Round-2 review):** an attacker observing argv via
/// `ps auxe` during this window can recover the hex-encoded master
/// key. Practical exploitation requires (a) shell access on the box
/// during the milliseconds-to-seconds-wide write window, AND (b)
/// timing precision to catch the invocation. Mitigations:
///   - `Stdio::null()` on stdin prevents `security` from prompting
///     (which would extend the window indefinitely).
///   - System.keychain reads gate on the kernel-process layer
///     anyway — a non-root attacker who captured the hex argv can
///     decode it but cannot read the on-disk entry.
///   - The LaunchDaemon model means writes happen at most once per
///     fresh-install boot; the surface area is a brief one-time
///     window, not a recurring exposure.
///
/// Alternatives considered + rejected:
///   - stdin-via-pipe: `/usr/bin/security`'s `-w` flag has no stdin
///     form per the man page; Apple's source confirms.
///   - Native FFI via `SecKeychainAddGenericPassword` directly:
///     bypasses argv but couples to security-framework's C ABI for
///     a one-shot mint operation; not worth the maintenance burden.
///   - Base64 / raw-bytes encoding: doesn't change the argv-exposed
///     surface, just changes representation.
///
/// See module-level doc-comment for the FFI escape hatch.
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
    // Story 7.27 Round-2 review fix: use `Zeroizing<String>` directly
    // instead of a hand-rolled `ZeroizingHex` newtype. The zeroize
    // crate already provides `Zeroize` for `String` (zeroizes the
    // buffer in place) so `Zeroizing<String>` gives the same
    // single-buffer single-zeroize semantics as the local newtype
    // without the maintenance burden.
    use std::fmt::Write;
    let mut secret_hex: Zeroizing<String> =
        Zeroizing::new(String::with_capacity(MASTER_KEY_LEN * 2));
    for b in key.iter() {
        // `write!` into a `String` is infallible (the impl of
        // `fmt::Write` for `String` never returns an error), so the
        // `Result` here can be safely discarded.
        let _ = write!(&mut *secret_hex, "{:02x}", b);
    }

    // Story 7.27 Round-2 review note: `Command::output()` has no
    // timeout. A hung `/usr/bin/security` (keychain corruption,
    // syspolicyd deadlock, XPC stall) would block the
    // `spawn_blocking` worker indefinitely. Mitigations in place:
    //   - `Stdio::null()` on stdin prevents the prompt-hang case.
    //   - LaunchDaemon's `KeepAlive` + macOS launchd watchdog
    //     restart the daemon if it stops responding to launchd
    //     queries. A hung `security` will eventually surface as a
    //     watchdog kill + restart cycle.
    //   - Adding a thread-based timeout (e.g., `wait-timeout` crate)
    //     would add a new dep for a recovery scenario the LaunchDaemon
    //     watchdog already covers. Defer until ops experience shows
    //     this is a real problem.
    let output = Command::new("/usr/bin/security")
        // P6 (Story 7.26 code review): explicitly null stdin so the
        // daemon never blocks if `security` decides to prompt
        // (e.g., locked-keychain unlock prompt).
        .stdin(std::process::Stdio::null())
        // Round-3 review fix: pin locale to C so the locked-keychain
        // classifier's stderr substring matches (User interaction is
        // not allowed / errSecInteractionRequired) work on
        // non-English macOS.
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .args([
            "add-generic-password",
            "-s",
            MASTER_KEY_SERVICE,
            "-a",
            account,
            "-A", // no DR-bound ACL (load-bearing — produces allowAllForm)
            "-U", // upsert OK; read-before-write gate is the source of truth for "first boot"
            "-w",
            secret_hex.as_str(),
            SYSTEM_KEYCHAIN_PATH,
        ])
        .output()
        .map_err(|e| KeyStoreError::BackendUnavailable { backend: BACKEND, source: Box::new(e) })?;
    // `secret_hex` is dropped at end-of-scope; its Drop impl zeroizes
    // the buffer regardless of which branch below returns.

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let exit = output.status.code().map_or_else(|| "signal".to_string(), |c| c.to_string());
        // Story 7.27 Round-2 review fix: classify the locked-keychain
        // post-sleep error so operators get a clear remediation
        // pointer. `/usr/bin/security` returns generic exit=1 with
        // "User interaction is not allowed" when System.keychain is
        // locked AND `-i` (interactive prompt) cannot be used because
        // we're running headless via LaunchDaemon. The install path
        // runs `security set-keychain-settings -u` to disable
        // auto-lock; this classifier handles the regression case
        // where someone re-locked it (e.g., `security lock-keychain`
        // run by an admin script) or where install's
        // `set-keychain-settings` was skipped (MDM-restricted box).
        if stderr.contains("User interaction is not allowed")
            || stderr.contains("errSecInteractionRequired")
        {
            return Err(KeyStoreError::PlatformError {
                backend: BACKEND,
                message: format!(
                    "/Library/Keychains/System.keychain is locked and `security` cannot \
                     prompt (headless context). Remediation: re-run `sudo security \
                     set-keychain-settings -u /Library/Keychains/System.keychain` to \
                     disable auto-lock so the daemon can read across sleep/wake cycles. \
                     Original error: exit={exit}: {}",
                    stderr.trim()
                ),
            });
        }
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
///
/// Story 7.27 Round-2 review fix: non-hex characters now surface as
/// `MalformedMasterKey` (was `PlatformError`), and the per-nibble
/// loop runs to completion without early-exit so the position of a
/// malformed byte is not leakable via timing. Both changes bring the
/// classifier in line with the discipline already enforced by
/// `decode_hex_master_key`'s length check.
fn decode_hex_master_key(
    hex_bytes: &[u8],
) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, KeyStoreError> {
    if hex_bytes.len() != MASTER_KEY_LEN * 2 {
        return Err(KeyStoreError::MalformedMasterKey {
            expected_len: MASTER_KEY_LEN * 2,
            actual_len: hex_bytes.len(),
            reason: crate::MalformedReason::BadLength,
        });
    }
    let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    let mut any_bad: u8 = 0;
    for (i, chunk) in hex_bytes.chunks(2).enumerate() {
        let (hi, hi_bad) = decode_hex_nibble_ct(chunk[0]);
        let (lo, lo_bad) = decode_hex_nibble_ct(chunk[1]);
        any_bad |= hi_bad | lo_bad;
        key[i] = (hi << 4) | lo;
    }
    if any_bad != 0 {
        return Err(KeyStoreError::MalformedMasterKey {
            expected_len: MASTER_KEY_LEN * 2,
            actual_len: hex_bytes.len(),
            reason: crate::MalformedReason::BadCharacter,
        });
    }
    Ok(key)
}

/// Constant-time hex-nibble decode. Returns `(value, bad_mask)`
/// where `bad_mask == 0xFF` for invalid chars, `0x00` for valid. The
/// value field is zero on invalid chars; callers OR together
/// `bad_mask`s across the whole input and check once at the end.
///
/// `#[allow(clippy::manual_range_contains)]` because this is the
/// deliberate constant-time form — `RangeInclusive::contains` is
/// `match`-based and may branch differently across the three valid
/// ranges, which would leak position via timing.
#[allow(clippy::manual_range_contains)]
fn decode_hex_nibble_ct(c: u8) -> (u8, u8) {
    // Compute the three valid-range decodes unconditionally; mask
    // them with the in-range predicate; OR together. Any byte
    // outside `0-9a-fA-F` leaves all three branches zero and trips
    // the `bad` flag.
    //
    // Round-3 review note: `&` (bitwise AND on booleans) is
    // load-bearing for constant-time codegen — `&&` is short-circuit
    // and produces a branch that LLVM may keep, leaking position via
    // timing. Do NOT "simplify" `(c >= b'0') & (c <= b'9')` to
    // `(c >= b'0') && (c <= b'9')`. Rust permits `bool & bool` and
    // returns `bool` (since 1.27); the `as u8 * 0xFF` then yields a
    // branchless 0-or-0xFF mask.
    let in_09 = ((c >= b'0') & (c <= b'9')) as u8 * 0xFF;
    let in_af = ((c >= b'a') & (c <= b'f')) as u8 * 0xFF;
    let in_uf = ((c >= b'A') & (c <= b'F')) as u8 * 0xFF;
    // Suppress underflow for branches that don't fire: subtract only
    // under the matching mask.
    let v_09 = c.wrapping_sub(b'0') & in_09;
    let v_af = c.wrapping_sub(b'a').wrapping_add(10) & in_af;
    let v_uf = c.wrapping_sub(b'A').wrapping_add(10) & in_uf;
    let value = v_09 | v_af | v_uf;
    let any = in_09 | in_af | in_uf; // 0xFF if valid, 0 if invalid
    let bad = !any;
    (value, bad)
}

/// Domain-separated 8-hex-char fingerprint of `bytes` for audit-log
/// correlation between the keystore-side `tracing::info!` ops events
/// and the daemon-side `master-key-first-boot` audit event.
///
/// Story 7.27 Round-2 review fix: replaced raw `SHA-256(bytes)[..4]`
/// with HMAC-SHA256 keyed by the fixed domain-separator constant
/// [`FINGERPRINT_DOMAIN_SEP`]. The change preserves cross-boot
/// correlation (the load-bearing property — operators grep both
/// logs by fingerprint to confirm same key across daemon restarts).
///
/// **Threat model clarification (Round-3 review).** The domain-
/// separator is a compile-time public constant. An attacker with
/// the binary (every operator) can read it and recompute the HMAC
/// of a candidate key — computationally identical to using a public
/// salt with raw SHA-256. So this fix protects against:
///   - **code-drift**: someone refactoring the fingerprint to use
///     `SHA-256(key)` of a longer prefix in another module won't
///     match this output. The HMAC + domain separator documents the
///     intent and pins the contract.
///   - **mistaken-oracle implementations**: a future caller hashing
///     the raw key directly for logging would diverge from this
///     output, surfacing the bug in cross-correlation rather than
///     silently leaking a different oracle.
///
/// It does NOT protect against:
///   - **backup-theft attackers**: anyone with the binary can
///     replicate the HMAC; the oracle reduction is unchanged from a
///     public-salt scheme.
///   - **brute-force candidate verification**: same as above.
///
/// True "no oracle" requires a per-install random salt persisted
/// alongside the master key. That's a fingerprint-redesign story,
/// not a round-3 patch.
///
/// Output is 8 hex chars (4 bytes of HMAC truncation), matching the
/// pre-fix wire format; daemon-side `master_key_fingerprint_first8`
/// in `crates/permitlayer-daemon/src/cli/start.rs` MUST use the same
/// construction or correlation breaks.
pub const FINGERPRINT_DOMAIN_SEP: &[u8] = b"permitlayer-master-key-fingerprint";

fn fingerprint(bytes: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    // `Hmac::<Sha256>::new_from_slice` only returns `Err` for invalid
    // key length, but `Hmac` accepts arbitrary key sizes — there is
    // no failure mode for our fixed-constant `FINGERPRINT_DOMAIN_SEP`
    // input. `unwrap_or_else` over `expect()` keeps clippy's
    // expect_used lint quiet while preserving the structural
    // unreachability.
    let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(FINGERPRINT_DOMAIN_SEP) else {
        unreachable!("HMAC-SHA256 accepts arbitrary key length");
    };
    mac.update(bytes);
    let tag = mac.finalize().into_bytes();
    format!("{:02x}{:02x}{:02x}{:02x}", tag[0], tag[1], tag[2], tag[3])
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
            KeyStoreError::MalformedMasterKey { expected_len, actual_len, reason } => {
                assert_eq!(expected_len, 64);
                assert_eq!(actual_len, 8);
                // Round-3 review fix: bad-length path must report
                // `BadLength`, distinguishing from bad-character.
                assert_eq!(reason, crate::MalformedReason::BadLength);
            }
            other => panic!("expected MalformedMasterKey, got {other:?}"),
        }
    }

    #[test]
    fn decode_hex_rejects_non_hex_char() {
        let mut bytes = vec![b'a'; 64];
        bytes[5] = b'g'; // not a hex char
        let err = decode_hex_master_key(&bytes).unwrap_err();
        // Story 7.27 Round-2 review fix: non-hex chars now classify
        // as MalformedMasterKey (was PlatformError) so the daemon's
        // existing matcher routes to the consistent remediation
        // banner for "corrupted keychain entry" failures.
        // Round-3 review fix: must report `BadCharacter`, NOT
        // `BadLength`, so operator-facing renderer can say "non-hex
        // character" vs "wrong length".
        match err {
            KeyStoreError::MalformedMasterKey { expected_len, actual_len, reason } => {
                assert_eq!(expected_len, 64);
                assert_eq!(actual_len, 64, "input was the right length, just bad char");
                assert_eq!(reason, crate::MalformedReason::BadCharacter);
            }
            other => panic!("expected MalformedMasterKey, got {other:?}"),
        }
    }

    #[test]
    fn decode_hex_nibble_ct_classifies_correctly() {
        // Verify the constant-time decoder produces correct values
        // for valid chars and bad-flag for invalid.
        for c in b'0'..=b'9' {
            let (v, bad) = decode_hex_nibble_ct(c);
            assert_eq!(v, c - b'0', "digit {c:#x}");
            assert_eq!(bad, 0, "digit {c:#x} flagged bad");
        }
        for c in b'a'..=b'f' {
            let (v, bad) = decode_hex_nibble_ct(c);
            assert_eq!(v, 10 + (c - b'a'), "lower {c:#x}");
            assert_eq!(bad, 0, "lower {c:#x} flagged bad");
        }
        for c in b'A'..=b'F' {
            let (v, bad) = decode_hex_nibble_ct(c);
            assert_eq!(v, 10 + (c - b'A'), "upper {c:#x}");
            assert_eq!(bad, 0, "upper {c:#x} flagged bad");
        }
        for c in [b'g', b'/', b' ', 0u8, b'@', b'G', 0xFFu8] {
            let (_v, bad) = decode_hex_nibble_ct(c);
            assert_eq!(bad, 0xFF, "invalid char {c:#x} must flag bad");
        }
    }

    #[test]
    fn fingerprint_is_8_hex_chars() {
        let f = fingerprint(&[0u8; 32]);
        assert_eq!(f.len(), 8);
        assert!(f.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_is_hmac_not_raw_sha256() {
        // Story 7.27 Round-2 review fix: verify the fingerprint
        // genuinely uses HMAC-SHA256 with the documented domain
        // separator, NOT raw SHA-256. A regression that reverts to
        // `Sha256::digest(bytes)` would produce a different value
        // for the all-zero key; this test pins the contract.
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut expected = <Hmac<Sha256> as Mac>::new_from_slice(FINGERPRINT_DOMAIN_SEP).unwrap();
        expected.update(&[0u8; 32]);
        let expected_tag = expected.finalize().into_bytes();
        let expected_hex = format!(
            "{:02x}{:02x}{:02x}{:02x}",
            expected_tag[0], expected_tag[1], expected_tag[2], expected_tag[3],
        );
        assert_eq!(fingerprint(&[0u8; 32]), expected_hex);

        // Also assert the value is NOT the raw `SHA-256(zeros)[..4]`
        // = 0x66687aad, which a bug regressing to raw SHA-256 would
        // produce.
        assert_ne!(fingerprint(&[0u8; 32]), "66687aad");

        // Round-3 review fix: a buggy HMAC impl returning `key[..4]`
        // (or `domain_sep[..4]`, or `key XOR domain_sep[..4]`) could
        // also "differ from raw SHA-256 of all-zeros" without being a
        // correct HMAC. Add a second test vector with a non-trivial
        // key so a wrong-but-different impl gets caught.
        let nontrivial = [0x42u8; 32];
        let mut nontrivial_mac =
            <Hmac<Sha256> as Mac>::new_from_slice(FINGERPRINT_DOMAIN_SEP).unwrap();
        nontrivial_mac.update(&nontrivial);
        let nontrivial_tag = nontrivial_mac.finalize().into_bytes();
        let nontrivial_hex = format!(
            "{:02x}{:02x}{:02x}{:02x}",
            nontrivial_tag[0], nontrivial_tag[1], nontrivial_tag[2], nontrivial_tag[3],
        );
        assert_eq!(fingerprint(&nontrivial), nontrivial_hex);
        // Sanity: the two test vectors must produce different
        // fingerprints (HMAC is a function of input).
        assert_ne!(fingerprint(&[0u8; 32]), fingerprint(&nontrivial));
        // A `key[..4]` buggy impl would have returned "42424242" for
        // the non-trivial key — sanity check we're not that.
        assert_ne!(nontrivial_hex, "42424242");
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
