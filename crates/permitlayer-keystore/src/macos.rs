//! macOS Keychain Services adapter.
//!
//! Persists a single 32-byte master-key entry at
//! (`MASTER_KEY_SERVICE`, `MASTER_KEY_ACCOUNT`) via the `keyring` crate.
//! All FFI calls are dispatched through `tokio::task::spawn_blocking`
//! (AC #3) so a slow keychain operation (the OS can prompt the user,
//! talk over XPC, etc.) can never starve the async runtime.

#![cfg(target_os = "macos")]

use zeroize::{Zeroize, Zeroizing};

use crate::error::KeyStoreError;
use crate::{KeyStore, MASTER_KEY_ACCOUNT, MASTER_KEY_LEN, MASTER_KEY_SERVICE};

const BACKEND: &str = "apple";

/// macOS Keychain Services adapter. Holds no state — each operation
/// constructs a fresh `keyring::Entry` for the single master-key
/// entry.
pub struct MacKeyStore {
    _private: (),
}

impl MacKeyStore {
    /// Construct and probe the keychain backend.
    ///
    /// Returns `Err(BackendUnavailable)` if the backend cannot be
    /// reached. Makes `FallbackMode::Auto` functional.
    pub fn new() -> Result<Self, KeyStoreError> {
        probe_backend()?;
        Ok(Self { _private: () })
    }
}

#[async_trait::async_trait]
impl KeyStore for MacKeyStore {
    async fn master_key(&self) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, KeyStoreError> {
        tokio::task::spawn_blocking(fetch_or_create_master_key).await.map_err(join_err)?
    }

    async fn set_master_key(&self, key: &[u8; MASTER_KEY_LEN]) -> Result<(), KeyStoreError> {
        // Wrap in Zeroizing so the closure's copy is wiped when the
        // spawn_blocking task finishes, not left on the heap.
        let key_copy: Zeroizing<[u8; MASTER_KEY_LEN]> = Zeroizing::new(*key);
        tokio::task::spawn_blocking(move || set_and_verify(&key_copy)).await.map_err(join_err)?
    }
}

/// Write the key, then read it back and constant-time compare to
/// confirm persistence. Some keychain backends buffer writes or
/// silently discard on permission quirks; without read-back we'd
/// report success on a rotation that didn't actually take effect.
fn set_and_verify(key: &[u8; MASTER_KEY_LEN]) -> Result<(), KeyStoreError> {
    let entry = keyring::Entry::new(MASTER_KEY_SERVICE, MASTER_KEY_ACCOUNT).map_err(map_err)?;
    entry.set_secret(key).map_err(map_err)?;
    let mut read_back = entry.get_secret().map_err(map_err)?;
    let eq = read_back.len() == MASTER_KEY_LEN && constant_time_eq(&read_back, key);
    read_back.zeroize();
    if !eq {
        return Err(KeyStoreError::PlatformError {
            backend: BACKEND,
            message: "set_master_key read-back did not match written value".into(),
        });
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Probe the keychain backend by constructing an entry and attempting
/// a read. Tolerates `NoEntry`; real failures surface as
/// `BackendUnavailable`. Any retrieved bytes are zeroized immediately.
fn probe_backend() -> Result<(), KeyStoreError> {
    let entry = keyring::Entry::new(MASTER_KEY_SERVICE, MASTER_KEY_ACCOUNT).map_err(map_err)?;
    match entry.get_secret() {
        Ok(mut bytes) => {
            bytes.zeroize();
            Ok(())
        }
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(map_err(e)),
    }
}

fn fetch_or_create_master_key() -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, KeyStoreError> {
    let entry = keyring::Entry::new(MASTER_KEY_SERVICE, MASTER_KEY_ACCOUNT).map_err(map_err)?;
    match entry.get_secret() {
        Ok(mut bytes) => {
            let result = read_key_from_bytes(&bytes);
            bytes.zeroize();
            result
        }
        Err(keyring::Error::NoEntry) => {
            // First-run: generate a fresh random key, persist it,
            // then read back to detect races. If the read-back
            // differs from what we wrote, another process minted a
            // key between our `NoEntry` and our `set_secret` (and
            // their value clobbered ours OR vice versa) — adopt the
            // stored value so all racers converge on one key.
            use rand::RngCore;
            let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
            rand::rngs::OsRng.fill_bytes(&mut *key);
            match entry.set_secret(&*key) {
                Ok(()) => {
                    let mut bytes = entry.get_secret().map_err(map_err)?;
                    let result = read_key_from_bytes(&bytes);
                    bytes.zeroize();
                    result
                }
                Err(_) => {
                    let mut bytes = entry.get_secret().map_err(map_err)?;
                    let result = read_key_from_bytes(&bytes);
                    bytes.zeroize();
                    result
                }
            }
        }
        Err(e) => Err(map_err(e)),
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

fn map_err(e: keyring::Error) -> KeyStoreError {
    match e {
        keyring::Error::NoStorageAccess(source) => {
            KeyStoreError::BackendUnavailable { backend: BACKEND, source }
        }
        keyring::Error::PlatformFailure(source) => {
            KeyStoreError::PlatformError { backend: BACKEND, message: source.to_string() }
        }
        other => KeyStoreError::PlatformError { backend: BACKEND, message: other.to_string() },
    }
}

fn join_err(e: tokio::task::JoinError) -> KeyStoreError {
    KeyStoreError::PlatformError {
        backend: BACKEND,
        message: format!("spawn_blocking join failed: {e}"),
    }
}
