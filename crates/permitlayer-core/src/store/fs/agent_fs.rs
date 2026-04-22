//! Filesystem-backed `AgentIdentityStore` adapter (Story 4.4).
//!
//! Writes one TOML file per registered agent at
//! `{home}/agents/<name>.toml`. Each file is mode `0o600` on Unix; the
//! parent `agents/` directory is `0o700`. Writes use the same atomic
//! tempfile → fsync → rename → fsync-parent dance as `credential_fs.rs`
//! so a crash mid-write never leaves a half-written agent record.
//!
//! # On-disk format
//!
//! Plain TOML, hand-readable:
//!
//! ```toml
//! name = "email-triage"
//! policy_name = "email-read-only"
//! token_hash = "$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>"
//! lookup_key_hex = "<64 hex chars>"
//! created_at = "2026-04-12T18:30:00Z"
//! last_seen_at = "2026-04-12T18:35:12Z"  # omitted if never used
//! ```
//!
//! `last_seen_at` is updated best-effort by `AuthLayer` on every
//! successful authentication. Two concurrent updates from the same
//! agent racing on `put` is acceptable (last-writer-wins; the
//! timestamp granularity is millisecond and either is correct).
//!
//! # Why not sealed
//!
//! Unlike `credential_fs.rs`, agent files are NOT sealed under the
//! master key. Their contents are derived values: the Argon2id hash
//! is one-way, and the HMAC lookup key is useless without the
//! daemon's master-derived HMAC subkey (which never touches disk
//! outside the existing vault). Sealing would buy nothing
//! security-wise and would force every agent CRUD operation through
//! the vault — pointless coupling.

use std::collections::HashSet;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;

use crate::agent::{AgentIdentity, AgentIdentityRaw, validate_agent_name};
use crate::store::AgentIdentityStore;
use crate::store::error::StoreError;

/// Per-process tempfile counter. Combined with `std::process::id()` to
/// guarantee uniqueness across overlapping `put` calls.
static TEMPFILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Hard cap on the size of any single on-disk agent TOML file. Agent
/// records are tiny (under ~1 KiB in practice); 64 KiB is a generous
/// ceiling that still refuses to slurp a pathological or adversarial
/// file into memory during `list` / `get`.
const MAX_AGENT_FILE_BYTES: usize = 64 * 1024;

/// Filesystem-backed `AgentIdentityStore`.
///
/// Holds a cloned `home: PathBuf` so closures dispatched to
/// `tokio::task::spawn_blocking` can `move` the path without borrowing
/// `&self`.
///
/// `in_flight_names` is an in-process per-name guard set that prevents
/// two concurrent `put` calls for the same agent name from silently
/// clobbering each other. See `put` for the full story. The store is
/// held in an `Arc` by every caller (see `AgentIdentityStore` trait
/// object), so it does NOT implement `Clone` — cloning would fork the
/// guard set and defeat the purpose.
pub struct AgentIdentityFsStore {
    home: PathBuf,
    in_flight_names: Mutex<HashSet<String>>,
}

impl AgentIdentityFsStore {
    /// Construct the adapter rooted at `{home}/agents/`. Creates the
    /// directory if absent (mode `0o700` on Unix, atomic via
    /// `DirBuilderExt::mode`).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::IoError`] if the directory cannot be
    /// created or its permissions cannot be tightened.
    pub fn new(home: PathBuf) -> Result<Self, StoreError> {
        let agents_dir = home.join("agents");
        create_agents_dir(&agents_dir)?;
        Ok(Self { home, in_flight_names: Mutex::new(HashSet::new()) })
    }

    fn target_path(&self, name: &str) -> PathBuf {
        self.home.join("agents").join(format!("{name}.toml"))
    }

    fn tempfile_path(&self, name: &str) -> PathBuf {
        let pid = std::process::id();
        let counter = TEMPFILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        // Random suffix prevents PID-reuse collisions.
        let rand: u64 = {
            use rand::RngCore;
            let mut buf = [0u8; 8];
            rand::rngs::OsRng.fill_bytes(&mut buf);
            u64::from_le_bytes(buf)
        };
        self.home.join("agents").join(format!("{name}.toml.tmp.{pid}.{counter}.{rand:016x}"))
    }

    /// Shared atomic-write path used by both `put` (with in-flight
    /// guard) and `touch_last_seen` (best-effort, no guard). Serializes
    /// `identity` to TOML and runs the tempfile → fsync → rename →
    /// fsync-parent dance on a blocking thread.
    ///
    /// Does NOT perform the duplicate-name pre-check or the in-flight
    /// guard — those live in `put`. Callers that need overwrite
    /// semantics (like `touch_last_seen`) use this directly.
    async fn write_atomic(&self, identity: &AgentIdentity) -> Result<(), StoreError> {
        let target = self.target_path(identity.name());
        let tmp = self.tempfile_path(identity.name());
        let agents_dir = self.home.join("agents");

        let toml_str =
            toml::to_string_pretty(identity).map_err(|e| StoreError::AgentSerializationFailed {
                reason: format!("toml serialization failed: {e}"),
                source: Some(Box::new(e)),
            })?;
        let bytes = toml_str.into_bytes();

        tokio::task::spawn_blocking(move || -> Result<(), StoreError> {
            atomic_write(&tmp, &target, &agents_dir, &bytes)
        })
        .await??;

        Ok(())
    }
}

#[async_trait]
impl AgentIdentityStore for AgentIdentityFsStore {
    async fn put(&self, identity: AgentIdentity) -> Result<(), StoreError> {
        // The constructor on AgentIdentity already validated `name`,
        // but a paranoid re-check guards against future refactors that
        // bypass the constructor.
        if validate_agent_name(identity.name()).is_err() {
            return Err(StoreError::InvalidAgentName { input: identity.name().to_owned() });
        }

        // Acquire the per-name in-flight guard BEFORE the duplicate
        // pre-check. Two concurrent `put` calls for the same name
        // would otherwise both observe `NotFound`, both call
        // `atomic_write`, and the second `rename()` would silently
        // clobber the first — both callers would get `Ok(())` but the
        // earlier agent's token_hash would be lost.
        //
        // With the guard, exactly one caller enters the critical
        // section per name at a time; the other gets
        // `StoreError::ConcurrentWrite`. Once the winner finishes, a
        // later retry by the loser will observe the file and get
        // `AgentAlreadyExists`, which is the correct terminal state.
        {
            let mut set = self.in_flight_names.lock().unwrap_or_else(|p| p.into_inner());
            if !set.insert(identity.name().to_owned()) {
                return Err(StoreError::ConcurrentWrite { name: identity.name().to_owned() });
            }
        }

        // RAII guard clears the in-flight entry on ANY early return
        // (error propagation, panic unwind, successful path). Using a
        // guard rather than scattering `set.remove(...)` calls
        // guarantees we never leak an entry and permanently block a
        // name in this process.
        //
        // Poisoning recovery: if a previous `put` panicked while
        // holding the mutex, `lock()` returns `Err(PoisonError)`. We
        // still want to remove the entry — the set itself is not
        // corrupt, just the invariants of whoever panicked. Use
        // `unwrap_or_else(PoisonError::into_inner)` to salvage the
        // inner guard.
        struct InFlightGuard<'a> {
            set: &'a Mutex<HashSet<String>>,
            name: String,
        }
        impl Drop for InFlightGuard<'_> {
            fn drop(&mut self) {
                let mut set = self.set.lock().unwrap_or_else(|p| p.into_inner());
                set.remove(&self.name);
            }
        }
        let _guard = InFlightGuard { set: &self.in_flight_names, name: identity.name().to_owned() };

        // Duplicate-name pre-check. Runs on the current task (a single
        // `symlink_metadata` syscall is cheap enough not to warrant a
        // `spawn_blocking` hop). We want this check to fire BEFORE
        // `write_atomic` creates any tempfile, so a duplicate
        // `register` doesn't leave behind a garbage `.tmp` file.
        let target = self.target_path(identity.name());
        match std::fs::symlink_metadata(&target) {
            Ok(_) => {
                return Err(StoreError::AgentAlreadyExists { name: identity.name().to_owned() });
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(StoreError::IoError(e)),
        }

        self.write_atomic(&identity).await?;
        Ok(())
    }

    async fn get(&self, name: &str) -> Result<Option<AgentIdentity>, StoreError> {
        if validate_agent_name(name).is_err() {
            return Err(StoreError::InvalidAgentName { input: name.to_owned() });
        }
        let path = self.target_path(name);
        let name_owned = name.to_owned();
        tokio::task::spawn_blocking(move || -> Result<Option<AgentIdentity>, StoreError> {
            let bytes = match read_agent_file_capped(&path) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(StoreError::IoError(e)),
            };
            parse_toml_to_identity(&name_owned, &bytes).map(Some)
        })
        .await?
    }

    async fn list(&self) -> Result<Vec<AgentIdentity>, StoreError> {
        let agents_dir = self.home.join("agents");
        tokio::task::spawn_blocking(move || -> Result<Vec<AgentIdentity>, StoreError> {
            let mut out = Vec::new();
            let read_dir = match std::fs::read_dir(&agents_dir) {
                Ok(rd) => rd,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
                Err(e) => return Err(StoreError::IoError(e)),
            };
            for entry in read_dir {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        // A per-entry read_dir failure (e.g., another
                        // process raced a remove() or a permission
                        // flap) must not abort the whole listing.
                        tracing::warn!(
                            dir = %agents_dir.display(),
                            error = %e,
                            "skipping unreadable directory entry"
                        );
                        continue;
                    }
                };
                let path = entry.path();
                // Skip non-regular files, dotfiles, editor lockfiles,
                // and tempfiles. Mirrors `policy::compile::compile_from_dir`.
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
                    tracing::warn!(
                        path = %path.display(),
                        "skipping agent file with invalid name in stem"
                    );
                    continue;
                }
                // Per-file IO failures (bad perms via `chmod 000`,
                // transient EBUSY, device errors) must not abort the
                // listing — skip with a warn and keep going. This
                // matches the graceful TOML-parse fallback below.
                let bytes = match read_agent_file_capped(&path) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(
                            path = %path.display(),
                            error = %e,
                            "skipping agent file — read failed"
                        );
                        continue;
                    }
                };
                match parse_toml_to_identity(stem, &bytes) {
                    Ok(identity) => out.push(identity),
                    Err(e) => {
                        tracing::warn!(
                            path = %path.display(),
                            error = %e,
                            "skipping malformed agent file"
                        );
                    }
                }
            }
            Ok(out)
        })
        .await?
    }

    async fn remove(&self, name: &str) -> Result<bool, StoreError> {
        if validate_agent_name(name).is_err() {
            return Err(StoreError::InvalidAgentName { input: name.to_owned() });
        }
        let path = self.target_path(name);
        tokio::task::spawn_blocking(move || -> Result<bool, StoreError> {
            match std::fs::remove_file(&path) {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(StoreError::IoError(e)),
            }
        })
        .await?
    }

    async fn touch_last_seen(&self, identity: AgentIdentity) -> Result<(), StoreError> {
        // `touch_last_seen` is best-effort and runs on the hot auth
        // path. The naive implementation — serialize the caller's
        // `identity` and atomic-rewrite — has TWO races that are not
        // acceptable:
        //
        //   1. Resurrect-after-remove. If `remove(name)` lands between
        //      the caller authing and us reaching here, a blind write
        //      would re-create a file that the operator just deleted.
        //   2. Stale-snapshot clobber. If a future feature rotates
        //      `token_hash` or `lookup_key_hex` on an existing agent
        //      (the in-memory snapshot held by auth.rs predates the
        //      rotation), a blind write would overwrite the freshly
        //      rotated fields with the stale snapshot.
        //
        // Fix: read the CURRENT on-disk record, mutate only
        // `last_seen_at` (the one field touch_last_seen is supposed to
        // own), and write back. If the file has been removed
        // concurrently, silently skip — we are not in the business of
        // resurrecting deleted agents on a hot path.
        //
        // Note we do NOT take the `in_flight_names` guard here. This
        // is deliberate: `write_atomic` is called directly, not `put`.
        // A concurrent `put` for the same name is impossible in
        // practice (the agent must already be registered to auth, and
        // `put` refuses duplicates), and even if it happened the
        // atomic rename means the loser is a no-op clobber with
        // identical content modulo timestamp. A concurrent
        // `touch_last_seen` from another request on the same agent is
        // last-writer-wins on the timestamp — acceptable, the
        // timestamps are sub-millisecond and either value is correct.
        let name = identity.name().to_owned();
        let new_last_seen = identity.last_seen_at;

        let current = match self.get(&name).await? {
            Some(c) => c,
            None => {
                // Agent was removed concurrently. touch_last_seen is
                // best-effort — silently skip rather than resurrecting
                // the file.
                return Ok(());
            }
        };

        // Merge: keep every field from the ON-DISK record except
        // `last_seen_at`, which is the one field this method is
        // allowed to update. This correctly loses any stale
        // `token_hash` / `lookup_key_hex` drift in the caller's
        // snapshot.
        let mut updated = current;
        updated.last_seen_at = new_last_seen;

        self.write_atomic(&updated).await
    }
}

/// Read an agent TOML file with a hard size cap
/// (`MAX_AGENT_FILE_BYTES`). Prevents `list` / `get` from slurping a
/// pathological or adversarial file into memory. Real agent records
/// are under ~1 KiB; anything above 64 KiB is either corruption or
/// an attack and should be surfaced as `InvalidData` rather than
/// silently expanding the process working set.
fn read_agent_file_capped(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    let mut buf = Vec::with_capacity(1024);
    // Read one byte past the cap so we can distinguish "exactly at
    // the cap" from "exceeds the cap".
    (&mut file).take(MAX_AGENT_FILE_BYTES as u64 + 1).read_to_end(&mut buf)?;
    if buf.len() > MAX_AGENT_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("agent file exceeds {MAX_AGENT_FILE_BYTES} bytes"),
        ));
    }
    Ok(buf)
}

fn parse_toml_to_identity(name: &str, bytes: &[u8]) -> Result<AgentIdentity, StoreError> {
    let s = std::str::from_utf8(bytes).map_err(|e| StoreError::AgentDeserializationFailed {
        name: name.to_owned(),
        reason: format!("agent file is not valid UTF-8: {e}"),
        source: Some(Box::new(e)),
    })?;
    let raw: AgentIdentityRaw =
        toml::from_str(s).map_err(|e| StoreError::AgentDeserializationFailed {
            name: name.to_owned(),
            reason: format!("agent toml parse failed: {e}"),
            source: Some(Box::new(e)),
        })?;
    raw.into_validated().map_err(|e| StoreError::AgentDeserializationFailed {
        name: name.to_owned(),
        reason: format!("agent name validation failed: {e}"),
        source: Some(Box::new(e)),
    })
}

/// Atomic write: tempfile → fsync → rename → fsync parent dir.
fn atomic_write(tmp: &Path, target: &Path, parent: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let mut file = create_tempfile_0600(tmp)?;
    let guard = TempfileGuard { path: tmp };
    file.write_all(bytes).map_err(StoreError::IoError)?;
    file.sync_all().map_err(StoreError::IoError)?;
    drop(file);
    std::fs::rename(tmp, target).map_err(StoreError::IoError)?;
    std::mem::forget(guard);
    let dir = std::fs::File::open(parent).map_err(StoreError::IoError)?;
    dir.sync_all().map_err(StoreError::IoError)?;
    Ok(())
}

fn create_tempfile_0600(tmp: &Path) -> Result<std::fs::File, StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(tmp)
            .map_err(StoreError::IoError)
    }
    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(tmp)
            .map_err(StoreError::IoError)
    }
}

/// RAII guard that deletes a tempfile if `atomic_write` aborts before
/// the rename. Same shape as `credential_fs.rs::TempfileGuard`.
struct TempfileGuard<'a> {
    path: &'a Path,
}

impl Drop for TempfileGuard<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.path);
    }
}

/// Create the agents directory with mode `0o700` on Unix.
///
/// Mirrors `credential_fs::create_vault_dir`. Refuses to follow a
/// symlink at the agents path (a symlink redirect would silently
/// ship the registry to an attacker-controlled location).
fn create_agents_dir(dir: &Path) -> Result<(), StoreError> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).map_err(StoreError::IoError)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        match std::fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let meta = std::fs::symlink_metadata(dir).map_err(StoreError::IoError)?;
                if meta.file_type().is_symlink() {
                    return Err(StoreError::IoError(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!("agents path is a symlink (refusing to follow): {}", dir.display()),
                    )));
                }
                if !meta.is_dir() {
                    return Err(StoreError::IoError(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!("agents path exists but is not a directory: {}", dir.display()),
                    )));
                }
                use std::os::unix::fs::PermissionsExt;
                let mut perms = meta.permissions();
                perms.set_mode(0o700);
                std::fs::set_permissions(dir, perms).map_err(StoreError::IoError)?;
            }
            Err(e) => return Err(StoreError::IoError(e)),
        }
    }
    #[cfg(not(unix))]
    {
        match std::fs::create_dir(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let meta = std::fs::symlink_metadata(dir).map_err(StoreError::IoError)?;
                if meta.file_type().is_symlink() {
                    return Err(StoreError::IoError(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!("agents path is a symlink (refusing to follow): {}", dir.display()),
                    )));
                }
                if !meta.is_dir() {
                    return Err(StoreError::IoError(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!("agents path exists but is not a directory: {}", dir.display()),
                    )));
                }
            }
            Err(e) => return Err(StoreError::IoError(e)),
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tempfile::TempDir;

    fn fake_identity(name: &str) -> AgentIdentity {
        AgentIdentity::new(
            name.to_owned(),
            "default".to_owned(),
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".to_owned(),
            "00".repeat(32),
            Utc::now(),
            None,
        )
        .unwrap()
    }

    fn new_store(tmp: &TempDir) -> AgentIdentityFsStore {
        AgentIdentityFsStore::new(tmp.path().to_path_buf()).unwrap()
    }

    #[tokio::test]
    async fn put_then_get_round_trip() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        let identity = fake_identity("agent1");
        store.put(identity.clone()).await.unwrap();
        let got = store.get("agent1").await.unwrap().unwrap();
        assert_eq!(got.name(), "agent1");
        assert_eq!(got.policy_name, "default");
    }

    #[tokio::test]
    async fn get_returns_none_for_missing() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        assert!(store.get("nonexistent").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_returns_all_agents() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        store.put(fake_identity("alpha")).await.unwrap();
        store.put(fake_identity("bravo")).await.unwrap();
        store.put(fake_identity("charlie")).await.unwrap();
        let mut names: Vec<String> =
            store.list().await.unwrap().into_iter().map(|a| a.name().to_owned()).collect();
        names.sort();
        assert_eq!(names, vec!["alpha", "bravo", "charlie"]);
    }

    #[tokio::test]
    async fn list_on_empty_directory_returns_empty_vec() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        assert!(store.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn remove_returns_true_then_false() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        store.put(fake_identity("agent1")).await.unwrap();
        assert!(store.remove("agent1").await.unwrap());
        assert!(!store.remove("agent1").await.unwrap());
        assert!(store.get("agent1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn put_refuses_duplicate_name() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        store.put(fake_identity("agent1")).await.unwrap();
        let err = store.put(fake_identity("agent1")).await.unwrap_err();
        assert!(matches!(err, StoreError::AgentAlreadyExists { ref name } if name == "agent1"));
    }

    #[tokio::test]
    async fn get_rejects_invalid_agent_name() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        let err = store.get("Bad-Name").await.unwrap_err();
        assert!(matches!(err, StoreError::InvalidAgentName { .. }));
    }

    #[tokio::test]
    async fn remove_rejects_invalid_agent_name() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        let err = store.remove("../etc/passwd").await.unwrap_err();
        assert!(matches!(err, StoreError::InvalidAgentName { .. }));
    }

    #[tokio::test]
    async fn touch_last_seen_updates_timestamp_in_place() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        let mut id = fake_identity("agent1");
        store.put(id.clone()).await.unwrap();
        let before = store.get("agent1").await.unwrap().unwrap();
        assert!(before.last_seen_at.is_none());

        // Replace the in-memory copy with a stamped version.
        id.last_seen_at = Some(Utc::now());
        store.touch_last_seen(id).await.unwrap();

        let after = store.get("agent1").await.unwrap().unwrap();
        assert!(after.last_seen_at.is_some());
    }

    #[tokio::test]
    async fn list_skips_dotfiles_and_lockfiles() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        store.put(fake_identity("agent1")).await.unwrap();
        // Drop a dotfile and a lockfile alongside.
        std::fs::write(tmp.path().join("agents/.hidden.toml"), "garbage").unwrap();
        std::fs::write(tmp.path().join("agents/.#lock.toml"), "garbage").unwrap();
        let agents = store.list().await.unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].name(), "agent1");
    }

    #[tokio::test]
    async fn list_skips_malformed_agent_files() {
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        store.put(fake_identity("good")).await.unwrap();
        // Manually drop a broken file.
        std::fs::write(tmp.path().join("agents/broken.toml"), "this is not valid toml [[[")
            .unwrap();
        let agents = store.list().await.unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].name(), "good");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn agents_dir_created_with_0700_perms() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let _ = new_store(&tmp);
        let meta = std::fs::metadata(tmp.path().join("agents")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn agent_file_written_with_0600_perms() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        store.put(fake_identity("agent1")).await.unwrap();
        let meta = std::fs::metadata(tmp.path().join("agents/agent1.toml")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    #[tokio::test]
    async fn put_creates_agents_directory_if_missing() {
        let tmp = TempDir::new().unwrap();
        // Constructor creates the dir; here we verify it survives a
        // `put` call after construction.
        let store = new_store(&tmp);
        store.put(fake_identity("agent1")).await.unwrap();
        assert!(tmp.path().join("agents").exists());
    }

    #[tokio::test]
    async fn put_atomic_no_partial_file_visible_to_concurrent_get() {
        // Sanity check: after a successful put, get always returns a
        // fully-formed identity. This isn't a true race test (those
        // need fault injection), just a positive-path assertion.
        let tmp = TempDir::new().unwrap();
        let store = new_store(&tmp);
        for i in 0..20 {
            let name = format!("agent{i:02}");
            let mut id = fake_identity(&name);
            // Ensure unique lookup_key per agent so list() doesn't dedup.
            id.lookup_key_hex = format!("{:064x}", i + 1);
            store.put(id).await.unwrap();
            let got = store.get(&name).await.unwrap().unwrap();
            assert_eq!(got.name(), name);
        }
        assert_eq!(store.list().await.unwrap().len(), 20);
    }
}
