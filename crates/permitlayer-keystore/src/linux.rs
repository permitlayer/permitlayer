//! Linux libsecret / Secret Service adapter.
//!
//! Persists a single 32-byte master-key entry at
//! (`MASTER_KEY_SERVICE`, `MASTER_KEY_ACCOUNT`) via the `keyring`
//! crate's `linux-native-sync-persistent` backend. All FFI calls go
//! through `tokio::task::spawn_blocking` (AC #3).
//!
//! **Gotcha:** headless Linux (no desktop session, no
//! gnome-keyring-daemon) will surface `BackendUnavailable` from
//! `new()`. CI workflows must start a DBus session + unlock the
//! keyring before running the conformance suite (see
//! `.github/workflows/ci.yml`).

#![cfg(target_os = "linux")]

use zeroize::{Zeroize, Zeroizing};

use crate::error::KeyStoreError;
use crate::{KeyStore, MASTER_KEY_ACCOUNT, MASTER_KEY_LEN, MASTER_KEY_SERVICE};

const BACKEND: &str = "libsecret";

/// Linux Secret Service adapter.
pub struct LinuxKeyStore {
    _private: (),
}

impl LinuxKeyStore {
    /// Construct and probe the Secret Service backend.
    pub fn new() -> Result<Self, KeyStoreError> {
        probe_backend()?;
        Ok(Self { _private: () })
    }
}

#[async_trait::async_trait]
impl KeyStore for LinuxKeyStore {
    async fn master_key(&self) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, KeyStoreError> {
        tokio::task::spawn_blocking(fetch_or_create_master_key).await.map_err(join_err)?
    }

    async fn set_master_key(&self, key: &[u8; MASTER_KEY_LEN]) -> Result<(), KeyStoreError> {
        let key_copy: Zeroizing<[u8; MASTER_KEY_LEN]> = Zeroizing::new(*key);
        tokio::task::spawn_blocking(move || set_and_verify(&key_copy)).await.map_err(join_err)?
    }
}

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
