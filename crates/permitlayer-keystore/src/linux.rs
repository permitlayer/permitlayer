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
//!
//! Story 7.6b round-1 review re-triage: the per-helper logic was
//! extracted to `keyring_shared.rs` because it was identical across
//! `macos.rs` / `linux.rs` / `windows.rs`.

#![cfg(target_os = "linux")]

use zeroize::Zeroizing;

use crate::error::KeyStoreError;
use crate::keyring_shared as shared;
use crate::{
    DeleteOutcome, KeyStore, MASTER_KEY_ACCOUNT, MASTER_KEY_LEN, MASTER_KEY_PREVIOUS_ACCOUNT,
};

const BACKEND: &str = "libsecret";

/// Linux Secret Service adapter.
pub struct LinuxKeyStore {
    _private: (),
}

impl LinuxKeyStore {
    /// Construct and probe the Secret Service backend.
    pub fn new() -> Result<Self, KeyStoreError> {
        shared::probe_backend(BACKEND, MASTER_KEY_ACCOUNT)?;
        Ok(Self { _private: () })
    }
}

#[async_trait::async_trait]
impl KeyStore for LinuxKeyStore {
    async fn master_key(&self) -> Result<crate::MasterKeyOutcome, KeyStoreError> {
        // Story 7.27 AC #16: only macOS distinguishes first-boot vs
        // existing-key in rc.22 (System.keychain has a read-before-
        // write gate). Linux's `keyring_shared` helper internally
        // fetch-or-creates but doesn't surface the distinction —
        // reporting `first_boot: false` unconditionally is the
        // honest answer until 7.18 redesigns the Linux backend.
        let key = tokio::task::spawn_blocking(|| {
            shared::fetch_or_create_master_key_at_account(BACKEND, MASTER_KEY_ACCOUNT)
        })
        .await
        .map_err(|e| shared::join_err(BACKEND, e))??;
        Ok(crate::MasterKeyOutcome { key, first_boot: false })
    }

    async fn set_master_key(&self, key: &[u8; MASTER_KEY_LEN]) -> Result<(), KeyStoreError> {
        let key_copy: Zeroizing<[u8; MASTER_KEY_LEN]> = Zeroizing::new(*key);
        tokio::task::spawn_blocking(move || {
            shared::set_and_verify_at_account(
                BACKEND,
                MASTER_KEY_ACCOUNT,
                &key_copy,
                "set_master_key read-back did not match written value",
            )
        })
        .await
        .map_err(|e| shared::join_err(BACKEND, e))?
    }

    async fn delete_master_key(&self) -> Result<DeleteOutcome, KeyStoreError> {
        tokio::task::spawn_blocking(|| shared::delete_account(BACKEND, MASTER_KEY_ACCOUNT))
            .await
            .map_err(|e| shared::join_err(BACKEND, e))?
    }

    async fn set_previous_master_key(
        &self,
        previous: &[u8; MASTER_KEY_LEN],
    ) -> Result<(), KeyStoreError> {
        let prev_copy: Zeroizing<[u8; MASTER_KEY_LEN]> = Zeroizing::new(*previous);
        tokio::task::spawn_blocking(move || {
            shared::set_and_verify_at_account(
                BACKEND,
                MASTER_KEY_PREVIOUS_ACCOUNT,
                &prev_copy,
                "previous-slot read-back did not match written value",
            )
        })
        .await
        .map_err(|e| shared::join_err(BACKEND, e))?
    }

    async fn previous_master_key(
        &self,
    ) -> Result<Option<Zeroizing<[u8; MASTER_KEY_LEN]>>, KeyStoreError> {
        tokio::task::spawn_blocking(|| shared::read_account(BACKEND, MASTER_KEY_PREVIOUS_ACCOUNT))
            .await
            .map_err(|e| shared::join_err(BACKEND, e))?
    }

    async fn clear_previous_master_key(&self) -> Result<(), KeyStoreError> {
        tokio::task::spawn_blocking(|| shared::clear_account(BACKEND, MASTER_KEY_PREVIOUS_ACCOUNT))
            .await
            .map_err(|e| shared::join_err(BACKEND, e))?
    }
}
