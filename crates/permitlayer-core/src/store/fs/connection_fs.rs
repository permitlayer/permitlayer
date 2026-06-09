//! Filesystem-backed `ConnectionStore` adapter (Epic 11, Story 11.9).
//!
//! Writes one TOML file per connection at
//! `{home}/connections/<id>.toml`, where `<id>` is the 26-char Crockford
//! ULID text form. Mirrors `agent_fs.rs`: atomic tempfile → fsync →
//! rename → fsync-parent, `0o600` files in a `0o700` directory,
//! skip-and-warn on malformed entries during `list`.
//!
//! # No secrets
//!
//! A `ConnectionRecord` is non-secret routing/display metadata. The
//! sealed credential material lives in `credential_fs.rs` keyed on
//! `(ConnectionId, Slot)`. Renaming a connection rewrites only this
//! metadata file and never touches the sealed bytes.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use permitlayer_credential::ConnectionId;

use crate::store::ConnectionStore;
use crate::store::connection::ConnectionRecord;
use crate::store::error::StoreError;

/// Per-process tempfile counter (see `agent_fs.rs` for rationale).
static TEMPFILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Hard cap on a single connection TOML file (records are tiny; this is
/// a generous adversarial ceiling).
const MAX_CONNECTION_FILE_BYTES: usize = 64 * 1024;

/// Filesystem-backed `ConnectionStore` rooted at `{home}/connections/`.
pub struct ConnectionFsStore {
    home: PathBuf,
}

impl ConnectionFsStore {
    /// Construct the adapter rooted at `{home}/connections/`. Creates the
    /// directory if absent (mode `0o700` on Unix).
    pub fn new(home: PathBuf) -> Result<Self, StoreError> {
        let dir = home.join("connections");
        super::create_restricted_dir(&dir, "connections")?;
        Ok(Self { home })
    }

    fn target_path(&self, id: ConnectionId) -> PathBuf {
        self.home.join("connections").join(format!("{id}.toml"))
    }

    fn tempfile_path(&self, id: ConnectionId) -> PathBuf {
        let pid = std::process::id();
        let counter = TEMPFILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let rand: u64 = {
            use rand::RngCore;
            let mut buf = [0u8; 8];
            rand::rngs::OsRng.fill_bytes(&mut buf);
            u64::from_le_bytes(buf)
        };
        self.home.join("connections").join(format!("{id}.toml.tmp.{pid}.{counter}.{rand:016x}"))
    }
}

#[async_trait]
impl ConnectionStore for ConnectionFsStore {
    async fn put(&self, record: ConnectionRecord) -> Result<(), StoreError> {
        let target = self.target_path(record.id);
        let tmp = self.tempfile_path(record.id);
        let dir = self.home.join("connections");
        let id_text = record.id.to_string();

        let toml_str =
            toml::to_string_pretty(&record).map_err(|e| StoreError::RecordSerdeFailed {
                kind: "connection",
                id: id_text,
                reason: format!("toml serialization failed: {e}"),
                source: Some(Box::new(e)),
            })?;
        let bytes = toml_str.into_bytes();

        tokio::task::spawn_blocking(move || -> Result<(), StoreError> {
            super::atomic_write(&tmp, &target, &dir, &bytes)
        })
        .await??;
        Ok(())
    }

    async fn get(&self, id: ConnectionId) -> Result<Option<ConnectionRecord>, StoreError> {
        let path = self.target_path(id);
        let id_text = id.to_string();
        tokio::task::spawn_blocking(move || -> Result<Option<ConnectionRecord>, StoreError> {
            let bytes = match read_capped(&path, MAX_CONNECTION_FILE_BYTES) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(StoreError::IoError(e)),
            };
            parse_record(&id_text, &bytes).map(Some)
        })
        .await?
    }

    async fn list(&self) -> Result<Vec<ConnectionRecord>, StoreError> {
        let dir = self.home.join("connections");
        tokio::task::spawn_blocking(move || -> Result<Vec<ConnectionRecord>, StoreError> {
            let mut out = Vec::new();
            let read_dir = match std::fs::read_dir(&dir) {
                Ok(rd) => rd,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
                Err(e) => return Err(StoreError::IoError(e)),
            };
            for entry in read_dir {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::warn!(dir = %dir.display(), error = %e, "skipping unreadable connections entry");
                        continue;
                    }
                };
                let path = entry.path();
                let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if file_name.starts_with('.') || file_name.starts_with('#') {
                    continue;
                }
                let Some(stem) = file_name.strip_suffix(".toml") else {
                    continue;
                };
                if stem.contains(".tmp.") {
                    continue;
                }
                // The stem must be a parseable ULID — otherwise skip-and-warn.
                if ConnectionId::from_ulid_str(stem).is_none() {
                    tracing::warn!(path = %path.display(), "skipping connection file with non-ULID stem");
                    continue;
                }
                let bytes = match read_capped(&path, MAX_CONNECTION_FILE_BYTES) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = %e, "skipping connection file — read failed");
                        continue;
                    }
                };
                match parse_record(stem, &bytes) {
                    Ok(rec) => out.push(rec),
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = %e, "skipping malformed connection file");
                    }
                }
            }
            Ok(out)
        })
        .await?
    }

    async fn remove(&self, id: ConnectionId) -> Result<bool, StoreError> {
        let path = self.target_path(id);
        tokio::task::spawn_blocking(move || -> Result<bool, StoreError> {
            match std::fs::remove_file(&path) {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(StoreError::IoError(e)),
            }
        })
        .await?
    }
}

fn read_capped(path: &Path, cap: usize) -> std::io::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    let mut buf = Vec::with_capacity(1024);
    (&mut file).take(cap as u64 + 1).read_to_end(&mut buf)?;
    if buf.len() > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("connection file exceeds {cap} bytes"),
        ));
    }
    Ok(buf)
}

fn parse_record(id_text: &str, bytes: &[u8]) -> Result<ConnectionRecord, StoreError> {
    let s = std::str::from_utf8(bytes).map_err(|e| StoreError::RecordSerdeFailed {
        kind: "connection",
        id: id_text.to_owned(),
        reason: format!("connection file is not valid UTF-8: {e}"),
        source: Some(Box::new(e)),
    })?;
    let rec: ConnectionRecord = toml::from_str(s).map_err(|e| StoreError::RecordSerdeFailed {
        kind: "connection",
        id: id_text.to_owned(),
        reason: format!("connection toml parse failed: {e}"),
        source: Some(Box::new(e)),
    })?;
    // Defense in depth: the filename stem must match the record's id, so
    // a renamed-on-disk file can't masquerade as a different connection.
    if rec.id.to_string() != id_text {
        return Err(StoreError::RecordSerdeFailed {
            kind: "connection",
            id: id_text.to_owned(),
            reason: format!("record id '{}' does not match filename stem '{id_text}'", rec.id),
            source: None,
        });
    }
    Ok(rec)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::store::connection::{AccountHint, ConnectionStatus, ConnectionTier};
    use chrono::Utc;
    use tempfile::TempDir;

    fn fake_record(name: &str) -> ConnectionRecord {
        ConnectionRecord {
            id: ConnectionId::generate(),
            connector_id: "google-gmail".to_owned(),
            name: name.to_owned(),
            account_hint: Some(AccountHint::new("test-user@example.com")),
            granted_scopes: vec!["https://www.googleapis.com/auth/gmail.readonly".to_owned()],
            tier: ConnectionTier::Read,
            created_at: Utc::now(),
            status: ConnectionStatus::Active,
        }
    }

    fn new_store(tmp: &TempDir) -> ConnectionFsStore {
        ConnectionFsStore::new(tmp.path().to_path_buf()).unwrap()
    }

    #[tokio::test]
    async fn round_trips_a_record() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        let rec = fake_record("austin-gmail");
        let id = rec.id;
        store.put(rec.clone()).await.unwrap();
        let got = store.get(id).await.unwrap().expect("present");
        assert_eq!(got, rec);
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        assert!(store.get(ConnectionId::generate()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn serialized_form_carries_no_secret_bytes() {
        // AC#3: the on-disk TOML must contain no ciphertext/token-like
        // fields. We assert the serialized record has only the known
        // non-secret keys.
        let rec = fake_record("austin-gmail");
        let toml_str = toml::to_string_pretty(&rec).unwrap();
        for forbidden in ["ciphertext", "token", "secret", "nonce", "sealed", "aad"] {
            assert!(
                !toml_str.to_lowercase().contains(forbidden),
                "connection record TOML must not contain '{forbidden}':\n{toml_str}"
            );
        }
    }

    #[tokio::test]
    async fn list_returns_all_and_skips_noise() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        store.put(fake_record("a")).await.unwrap();
        store.put(fake_record("b")).await.unwrap();
        let dir = tmp.path().join("connections");
        std::fs::write(dir.join(".DS_Store"), b"").unwrap();
        std::fs::write(dir.join("notaulid.toml"), b"junk").unwrap();
        let got = store.list().await.unwrap();
        assert_eq!(got.len(), 2);
    }

    #[tokio::test]
    async fn remove_returns_true_then_false() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        let rec = fake_record("a");
        let id = rec.id;
        store.put(rec).await.unwrap();
        assert!(store.remove(id).await.unwrap());
        assert!(!store.remove(id).await.unwrap());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        let rec = fake_record("a");
        let id = rec.id;
        store.put(rec).await.unwrap();
        let mode = std::fs::metadata(tmp.path().join(format!("connections/{id}.toml")))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[tokio::test]
    async fn rename_does_not_change_id_keying() {
        // AC#6 (metadata half): the connection name is mutable; the id
        // (and therefore the credential keying) is untouched by a rename.
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        let mut rec = fake_record("old-name");
        let id = rec.id;
        store.put(rec.clone()).await.unwrap();
        rec.name = "new-name".to_owned();
        store.put(rec).await.unwrap();
        let got = store.get(id).await.unwrap().expect("present");
        assert_eq!(got.name, "new-name");
        assert_eq!(got.id, id);
    }
}
