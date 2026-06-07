//! Filesystem-backed `BindingStore` adapter (Epic 11, Story 11.9).
//!
//! Writes one TOML file per agent at `{home}/bindings/<agent>.toml`,
//! holding that agent's set of `[[binding]]` entries. Mirrors
//! `agent_fs.rs`: atomic tempfile → fsync → rename → fsync-parent,
//! `0o600` files in a `0o700` directory, skip-and-warn on malformed
//! entries during `list_agents`.
//!
//! # Primary key
//!
//! `(agent, connection_id)`. An agent may hold many bindings, but never
//! two for the same connection — [`BindingStore::put_binding`] rejects a
//! duplicate with [`StoreError::BindingAlreadyExists`].
//!
//! # No secrets / bearer-immutable
//!
//! A binding references a connection by id; it carries no credential
//! material, and the binding file is wholly separate from
//! `agents/<name>.toml`, so bind/unbind can never mutate an agent's
//! bearer token (Story 11.9 AC#5).

use std::collections::{BTreeSet, HashMap};
use std::io::Read as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use permitlayer_credential::ConnectionId;
use serde::{Deserialize, Serialize};

use crate::agent::validate_agent_name;
use crate::store::BindingStore;
use crate::store::binding::Binding;
use crate::store::error::StoreError;

/// Per-process tempfile counter.
static TEMPFILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Hard cap on a single bindings TOML file. A pathological agent with
/// thousands of bindings is implausible; 256 KiB is a generous ceiling.
const MAX_BINDING_FILE_BYTES: usize = 256 * 1024;

/// On-disk TOML mirror for one agent's binding set.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BindingFile {
    agent: String,
    #[serde(default, rename = "binding")]
    bindings: Vec<Binding>,
}

/// Filesystem-backed `BindingStore` rooted at `{home}/bindings/`.
///
/// A per-agent async mutex serializes the read-modify-write of each
/// agent's file (mirrors `agent_fs.rs`'s `name_locks`), so a concurrent
/// `put_binding` + `remove` for the same agent can't lose an edit.
pub struct BindingFsStore {
    home: PathBuf,
    agent_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl BindingFsStore {
    /// Construct the adapter rooted at `{home}/bindings/` (mode `0o700`).
    pub fn new(home: PathBuf) -> Result<Self, StoreError> {
        let dir = home.join("bindings");
        super::create_restricted_dir(&dir, "bindings")?;
        Ok(Self { home, agent_locks: Mutex::new(HashMap::new()) })
    }

    fn lock_for(&self, agent: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.agent_locks.lock().unwrap_or_else(|p| p.into_inner());
        Arc::clone(
            locks.entry(agent.to_owned()).or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    }

    fn target_path(&self, agent: &str) -> PathBuf {
        self.home.join("bindings").join(format!("{agent}.toml"))
    }

    fn tempfile_path(&self, agent: &str) -> PathBuf {
        let pid = std::process::id();
        let counter = TEMPFILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let rand: u64 = {
            use rand::RngCore;
            let mut buf = [0u8; 8];
            rand::rngs::OsRng.fill_bytes(&mut buf);
            u64::from_le_bytes(buf)
        };
        self.home.join("bindings").join(format!("{agent}.toml.tmp.{pid}.{counter}.{rand:016x}"))
    }

    /// Read the current binding set for an agent (empty if file absent).
    async fn read_file(&self, agent: &str) -> Result<Vec<Binding>, StoreError> {
        let path = self.target_path(agent);
        let agent_owned = agent.to_owned();
        tokio::task::spawn_blocking(move || -> Result<Vec<Binding>, StoreError> {
            let mut file = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
                Err(e) => return Err(StoreError::IoError(e)),
            };
            let mut buf = Vec::with_capacity(1024);
            (&mut file)
                .take(MAX_BINDING_FILE_BYTES as u64 + 1)
                .read_to_end(&mut buf)
                .map_err(StoreError::IoError)?;
            if buf.len() > MAX_BINDING_FILE_BYTES {
                return Err(StoreError::IoError(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("bindings file exceeds {MAX_BINDING_FILE_BYTES} bytes"),
                )));
            }
            parse_file(&agent_owned, &buf).map(|f| f.bindings)
        })
        .await?
    }

    /// Serialize + atomic-write an agent's binding set. Removes the file
    /// instead when `bindings` is empty (no orphan empty files).
    async fn write_file(&self, agent: &str, bindings: Vec<Binding>) -> Result<(), StoreError> {
        let target = self.target_path(agent);
        if bindings.is_empty() {
            let path = target.clone();
            tokio::task::spawn_blocking(move || match std::fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(StoreError::IoError(e)),
            })
            .await??;
            return Ok(());
        }
        let tmp = self.tempfile_path(agent);
        let dir = self.home.join("bindings");
        let file = BindingFile { agent: agent.to_owned(), bindings };
        let toml_str =
            toml::to_string_pretty(&file).map_err(|e| StoreError::RecordSerdeFailed {
                kind: "binding",
                id: agent.to_owned(),
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
}

#[async_trait]
impl BindingStore for BindingFsStore {
    async fn put_binding(&self, agent: &str, binding: Binding) -> Result<(), StoreError> {
        if validate_agent_name(agent).is_err() {
            return Err(StoreError::InvalidAgentName { input: agent.to_owned() });
        }
        let lock = self.lock_for(agent);
        let _guard = lock.lock().await;

        let mut current = self.read_file(agent).await?;
        if current.iter().any(|b| b.connection_id == binding.connection_id) {
            return Err(StoreError::BindingAlreadyExists {
                agent: agent.to_owned(),
                connection_id: binding.connection_id.to_string(),
            });
        }
        current.push(binding);
        self.write_file(agent, current).await
    }

    async fn get(&self, agent: &str) -> Result<Vec<Binding>, StoreError> {
        if validate_agent_name(agent).is_err() {
            return Err(StoreError::InvalidAgentName { input: agent.to_owned() });
        }
        self.read_file(agent).await
    }

    async fn list_agents(&self) -> Result<Vec<String>, StoreError> {
        let dir = self.home.join("bindings");
        tokio::task::spawn_blocking(move || -> Result<Vec<String>, StoreError> {
            let mut out = BTreeSet::new();
            let read_dir = match std::fs::read_dir(&dir) {
                Ok(rd) => rd,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Vec::new());
                }
                Err(e) => return Err(StoreError::IoError(e)),
            };
            for entry in read_dir {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::warn!(dir = %dir.display(), error = %e, "skipping unreadable bindings entry");
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
                if validate_agent_name(stem).is_err() {
                    tracing::warn!(path = %path.display(), "skipping bindings file with invalid agent name in stem");
                    continue;
                }
                out.insert(stem.to_owned());
            }
            Ok(out.into_iter().collect())
        })
        .await?
    }

    async fn remove(&self, agent: &str, connection_id: ConnectionId) -> Result<bool, StoreError> {
        if validate_agent_name(agent).is_err() {
            return Err(StoreError::InvalidAgentName { input: agent.to_owned() });
        }
        let lock = self.lock_for(agent);
        let _guard = lock.lock().await;

        let mut current = self.read_file(agent).await?;
        let before = current.len();
        current.retain(|b| b.connection_id != connection_id);
        if current.len() == before {
            return Ok(false);
        }
        self.write_file(agent, current).await?;
        Ok(true)
    }

    async fn remove_agent(&self, agent: &str) -> Result<bool, StoreError> {
        if validate_agent_name(agent).is_err() {
            return Err(StoreError::InvalidAgentName { input: agent.to_owned() });
        }
        let lock = self.lock_for(agent);
        let _guard = lock.lock().await;
        let path = self.target_path(agent);
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

fn parse_file(agent: &str, bytes: &[u8]) -> Result<BindingFile, StoreError> {
    let s = std::str::from_utf8(bytes).map_err(|e| StoreError::RecordSerdeFailed {
        kind: "binding",
        id: agent.to_owned(),
        reason: format!("bindings file is not valid UTF-8: {e}"),
        source: Some(Box::new(e)),
    })?;
    toml::from_str(s).map_err(|e| StoreError::RecordSerdeFailed {
        kind: "binding",
        id: agent.to_owned(),
        reason: format!("bindings toml parse failed: {e}"),
        source: Some(Box::new(e)),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::store::connection::ConnectionTier;
    use tempfile::TempDir;

    fn binding(tier: ConnectionTier) -> Binding {
        Binding { connection_id: ConnectionId::generate(), tier, policy: None, alias: None }
    }

    fn new_store(tmp: &TempDir) -> BindingFsStore {
        BindingFsStore::new(tmp.path().to_path_buf()).unwrap()
    }

    #[tokio::test]
    async fn round_trips_a_binding() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        let b = binding(ConnectionTier::ReadWrite);
        store.put_binding("chuck", b.clone()).await.unwrap();
        let got = store.get("chuck").await.unwrap();
        assert_eq!(got, vec![b]);
    }

    #[tokio::test]
    async fn one_agent_holds_multiple_bindings() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        let rw = binding(ConnectionTier::ReadWrite);
        let ro = binding(ConnectionTier::Read);
        store.put_binding("chuck", rw.clone()).await.unwrap();
        store.put_binding("chuck", ro.clone()).await.unwrap();
        let got = store.get("chuck").await.unwrap();
        assert_eq!(got.len(), 2);
        assert!(got.contains(&rw));
        assert!(got.contains(&ro));
    }

    #[tokio::test]
    async fn duplicate_pk_rejected() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        let b = binding(ConnectionTier::Read);
        store.put_binding("chuck", b.clone()).await.unwrap();
        // Same connection_id, different tier → still a PK violation.
        let dup = Binding { tier: ConnectionTier::ReadWrite, ..b };
        let err = store.put_binding("chuck", dup).await.unwrap_err();
        assert!(matches!(err, StoreError::BindingAlreadyExists { .. }));
    }

    #[tokio::test]
    async fn remove_single_binding_keeps_others() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        let keep = binding(ConnectionTier::Read);
        let drop = binding(ConnectionTier::ReadWrite);
        store.put_binding("chuck", keep.clone()).await.unwrap();
        store.put_binding("chuck", drop.clone()).await.unwrap();
        assert!(store.remove("chuck", drop.connection_id).await.unwrap());
        let got = store.get("chuck").await.unwrap();
        assert_eq!(got, vec![keep]);
        // Removing the non-existent one returns false.
        assert!(!store.remove("chuck", drop.connection_id).await.unwrap());
    }

    #[tokio::test]
    async fn remove_last_binding_removes_file() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        let b = binding(ConnectionTier::Read);
        store.put_binding("chuck", b.clone()).await.unwrap();
        assert!(store.remove("chuck", b.connection_id).await.unwrap());
        assert!(!tmp.path().join("bindings/chuck.toml").exists());
        assert!(store.get("chuck").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn remove_agent_clears_all() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        store.put_binding("chuck", binding(ConnectionTier::Read)).await.unwrap();
        store.put_binding("chuck", binding(ConnectionTier::ReadWrite)).await.unwrap();
        assert!(store.remove_agent("chuck").await.unwrap());
        assert!(store.get("chuck").await.unwrap().is_empty());
        assert!(!store.remove_agent("chuck").await.unwrap());
    }

    #[tokio::test]
    async fn list_agents_enumerates() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        store.put_binding("chuck", binding(ConnectionTier::Read)).await.unwrap();
        store.put_binding("angie", binding(ConnectionTier::Read)).await.unwrap();
        let mut agents = store.list_agents().await.unwrap();
        agents.sort();
        assert_eq!(agents, vec!["angie", "chuck"]);
    }

    #[tokio::test]
    async fn get_empty_for_unknown_agent() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        assert!(store.get("nobody").await.unwrap().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        store.put_binding("chuck", binding(ConnectionTier::Read)).await.unwrap();
        let mode =
            std::fs::metadata(tmp.path().join("bindings/chuck.toml")).unwrap().permissions().mode()
                & 0o777;
        assert_eq!(mode, 0o600);
    }
}
