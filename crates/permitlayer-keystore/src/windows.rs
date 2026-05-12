//! Windows Credential Manager / DPAPI adapter.
//!
//! Persists a single 32-byte master-key entry at
//! (`MASTER_KEY_SERVICE`, `MASTER_KEY_ACCOUNT`) via the `keyring`
//! crate's `windows-native` backend. All FFI calls go through
//! `tokio::task::spawn_blocking` (AC #3).
//!
//! Story 7.6b round-1 review re-triage: the per-helper logic was
//! extracted to `keyring_shared.rs` because it was identical across
//! `macos.rs` / `linux.rs` / `windows.rs`.

#![cfg(target_os = "windows")]

use zeroize::Zeroizing;

use crate::error::KeyStoreError;
use crate::keyring_shared as shared;
use crate::{
    DeleteOutcome, KeyStore, MASTER_KEY_ACCOUNT, MASTER_KEY_LEN, MASTER_KEY_PREVIOUS_ACCOUNT,
};

const BACKEND: &str = "windows";

/// Windows Credential Manager adapter.
pub struct WindowsKeyStore {
    _private: (),
}

impl WindowsKeyStore {
    /// Construct and probe the Credential Manager backend.
    pub fn new() -> Result<Self, KeyStoreError> {
        shared::probe_backend(BACKEND, MASTER_KEY_ACCOUNT)?;
        Ok(Self { _private: () })
    }
}

#[async_trait::async_trait]
impl KeyStore for WindowsKeyStore {
    async fn master_key(&self) -> Result<crate::MasterKeyOutcome, KeyStoreError> {
        // Story 7.27 AC #16: see Linux impl rationale — Windows
        // CredMan path reports `first_boot: false` unconditionally
        // until 7.19 redesigns the Windows backend.
        let key = tokio::task::spawn_blocking(|| {
            shared::fetch_or_create_master_key_at_account(BACKEND, MASTER_KEY_ACCOUNT)
        })
        .await
        .map_err(|e| shared::join_err(BACKEND, e))??;
        Ok(crate::MasterKeyOutcome::new(key, false))
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
