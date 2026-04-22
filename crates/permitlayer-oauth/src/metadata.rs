//! Provider-agnostic credential provenance metadata.
//!
//! Tracks which OAuth client was used, when the connection was established,
//! and which scopes were granted. This metadata is NOT encrypted — it
//! contains no secrets.
//!
//! This module also owns [`write_metadata_atomic`] — the shared helper
//! that writes `CredentialMeta` to disk via the tempfile+rename pattern.
//! Moved here from `permitlayer-daemon::cli::setup` in Story 1.14b so
//! that both the setup flow (daemon) and the refresh flow (proxy) can
//! call it. See the story's Task 3 for the rationale.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Credential provenance metadata stored alongside sealed tokens.
///
/// Written to `~/.agentsso/vault/{service}-meta.json` as plain JSON.
/// This struct is provider-agnostic and will be reused for future
/// non-Google connectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMeta {
    /// Which client type was used. Currently always `"byo"` on fresh
    /// connections. The historical value `"shared-casa"` may appear in
    /// credential metadata written by pre-0.1 daemons; records with that
    /// value require re-running `agentsso setup` to migrate.
    pub client_type: String,
    /// For BYO clients, the source file path. Absent on historical
    /// shared-casa records (which require re-setup to use).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_source: Option<String>,
    /// ISO 8601 timestamp of when the connection was established.
    pub connected_at: String,
    /// ISO 8601 timestamp of the last successful token refresh. `None`
    /// until the first refresh; refreshed credentials update this
    /// atomically via the refresh flow's meta-file write (Story 1.14b).
    /// Old meta files written before this field existed deserialize
    /// cleanly with `last_refreshed_at = None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_refreshed_at: Option<String>,
    /// Scopes that were granted during the OAuth flow.
    pub scopes: Vec<String>,
    /// Access token expiry in seconds (if provided by the server).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_secs: Option<u64>,
}

/// Errors returned by [`write_metadata_atomic`].
///
/// Uses `thiserror` rather than `anyhow` because `permitlayer-oauth`
/// is a library crate and must not pull in `anyhow` (per the workspace
/// convention documented in `permitlayer-daemon::main::4`).
///
/// Story 1.14b code-review n10 fix: previously the three distinct
/// io errors that can happen during the temp-file write phase
/// (`NamedTempFile::new_in`, `tmp.write_all`, `tmp.as_file().sync_all`)
/// all collapsed into a single `WriteTemp(io::Error)` variant. The
/// io::Error itself doesn't carry call-site context so operators
/// reading the error couldn't tell which step broke. Now split into
/// three variants — `CreateTemp`, `WriteTemp`, `SyncTemp` — so the
/// failing step is visible in the error message.
#[derive(Debug, thiserror::Error)]
pub enum WriteMetadataError {
    #[error("metadata path {path} has no parent directory")]
    ParentMissing { path: PathBuf },
    #[error("could not create parent directory {path}: {source}")]
    CreateDir { path: PathBuf, source: std::io::Error },
    #[error("could not serialize CredentialMeta: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("could not create temp metadata file in {path}: {source}")]
    CreateTemp { path: PathBuf, source: std::io::Error },
    #[error("could not write temp metadata file in {path}: {source}")]
    WriteTemp { path: PathBuf, source: std::io::Error },
    #[error("could not fsync temp metadata file in {path}: {source}")]
    SyncTemp { path: PathBuf, source: std::io::Error },
    #[error("could not persist metadata temp file to {path}: {source}")]
    Persist { path: PathBuf, source: tempfile::PersistError },
    #[error("could not set permissions on metadata file {path}: {source}")]
    Permissions { path: PathBuf, source: std::io::Error },
}

/// Atomically write a [`CredentialMeta`] JSON file.
///
/// Uses tempfile + write + fsync + rename + fsync parent to prevent
/// partial reads. Sets file mode `0o600` on Unix for consistency with
/// sealed credential files.
///
/// Moved from `permitlayer-daemon::cli::setup` in Story 1.14b so both
/// the setup flow (daemon) and the refresh flow (proxy) can share one
/// implementation. The function is deliberately synchronous — callers
/// in async contexts should wrap it in `tokio::task::spawn_blocking`
/// if the write must not block the runtime (the existing setup flow
/// is already synchronous).
pub fn write_metadata_atomic(path: &Path, meta: &CredentialMeta) -> Result<(), WriteMetadataError> {
    use std::io::Write;

    let parent = path
        .parent()
        .ok_or_else(|| WriteMetadataError::ParentMissing { path: path.to_path_buf() })?;

    std::fs::create_dir_all(parent)
        .map_err(|source| WriteMetadataError::CreateDir { path: parent.to_path_buf(), source })?;

    let json = serde_json::to_string_pretty(meta)?;

    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|source| WriteMetadataError::CreateTemp { path: parent.to_path_buf(), source })?;
    tmp.write_all(json.as_bytes())
        .map_err(|source| WriteMetadataError::WriteTemp { path: parent.to_path_buf(), source })?;
    tmp.as_file()
        .sync_all()
        .map_err(|source| WriteMetadataError::SyncTemp { path: parent.to_path_buf(), source })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        tmp.as_file().set_permissions(perms).map_err(|source| WriteMetadataError::Permissions {
            path: path.to_path_buf(),
            source,
        })?;
    }

    tmp.persist(path)
        .map_err(|e| WriteMetadataError::Persist { path: path.to_path_buf(), source: e })?;

    // Fsync parent directory for crash durability. Best-effort — log
    // and continue on failure, matching the behavior of the original
    // `daemon::cli::setup::write_metadata_atomic`.
    match std::fs::File::open(parent) {
        Ok(dir) => {
            if let Err(e) = dir.sync_all() {
                tracing::warn!(
                    path = %parent.display(),
                    error = %e,
                    "failed to fsync parent directory after metadata write"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                path = %parent.display(),
                error = %e,
                "failed to open parent directory for fsync after metadata write"
            );
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn serialize_shared_casa_meta() {
        let meta = CredentialMeta {
            client_type: "shared-casa".to_owned(),
            client_source: None,
            connected_at: "2026-04-06T12:00:00Z".to_owned(),
            last_refreshed_at: None,
            scopes: vec!["https://www.googleapis.com/auth/gmail.readonly".to_owned()],
            expires_in_secs: Some(3600),
        };

        let json = serde_json::to_string_pretty(&meta).unwrap();
        assert!(json.contains("\"client_type\": \"shared-casa\""));
        assert!(!json.contains("client_source"));
    }

    #[test]
    fn serialize_byo_meta() {
        let meta = CredentialMeta {
            client_type: "byo".to_owned(),
            client_source: Some("./my-client.json".to_owned()),
            connected_at: "2026-04-06T12:00:00Z".to_owned(),
            last_refreshed_at: None,
            scopes: vec![
                "https://www.googleapis.com/auth/gmail.readonly".to_owned(),
                "https://www.googleapis.com/auth/gmail.modify".to_owned(),
            ],
            expires_in_secs: None,
        };

        let json = serde_json::to_string_pretty(&meta).unwrap();
        assert!(json.contains("\"client_source\": \"./my-client.json\""));
        assert!(!json.contains("expires_in_secs"));
    }

    #[test]
    fn roundtrip_deserialize() {
        let meta = CredentialMeta {
            client_type: "shared-casa".to_owned(),
            client_source: None,
            connected_at: "2026-04-06T12:00:00Z".to_owned(),
            last_refreshed_at: None,
            scopes: vec!["https://www.googleapis.com/auth/gmail.readonly".to_owned()],
            expires_in_secs: Some(3600),
        };

        let json = serde_json::to_string(&meta).unwrap();
        let deserialized: CredentialMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.client_type, "shared-casa");
        assert!(deserialized.client_source.is_none());
        assert_eq!(deserialized.scopes.len(), 1);
        assert_eq!(deserialized.expires_in_secs, Some(3600));
    }

    // --- Story 1.14b AC 6: last_refreshed_at round-trip ---

    #[test]
    fn last_refreshed_at_none_is_skipped_in_output() {
        let meta = CredentialMeta {
            client_type: "shared-casa".to_owned(),
            client_source: None,
            connected_at: "2026-04-06T12:00:00Z".to_owned(),
            last_refreshed_at: None,
            scopes: vec!["https://www.googleapis.com/auth/gmail.readonly".to_owned()],
            expires_in_secs: Some(3600),
        };

        let json = serde_json::to_string(&meta).unwrap();
        assert!(
            !json.contains("last_refreshed_at"),
            "skip_serializing_if must omit the field when None; got: {json}"
        );
    }

    #[test]
    fn last_refreshed_at_some_round_trips_exactly() {
        let meta = CredentialMeta {
            client_type: "shared-casa".to_owned(),
            client_source: None,
            connected_at: "2026-04-06T12:00:00Z".to_owned(),
            last_refreshed_at: Some("2026-04-09T12:34:56Z".to_owned()),
            scopes: vec!["https://www.googleapis.com/auth/gmail.readonly".to_owned()],
            expires_in_secs: Some(3600),
        };

        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("\"last_refreshed_at\":\"2026-04-09T12:34:56Z\""));

        let deserialized: CredentialMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.last_refreshed_at.as_deref(), Some("2026-04-09T12:34:56Z"));
    }

    #[test]
    fn write_metadata_atomic_round_trip() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let path = tmpdir.path().join("vault").join("gmail-meta.json");

        let meta = CredentialMeta {
            client_type: "shared-casa".to_owned(),
            client_source: None,
            connected_at: "2026-04-10T12:00:00Z".to_owned(),
            last_refreshed_at: Some("2026-04-10T13:00:00Z".to_owned()),
            scopes: vec!["https://www.googleapis.com/auth/gmail.readonly".to_owned()],
            expires_in_secs: Some(3600),
        };

        write_metadata_atomic(&path, &meta).unwrap();

        // Parent directory was created; file exists.
        assert!(path.exists());

        // Content round-trips through serde.
        let contents = std::fs::read_to_string(&path).unwrap();
        let back: CredentialMeta = serde_json::from_str(&contents).unwrap();
        assert_eq!(back.connected_at, "2026-04-10T12:00:00Z");
        assert_eq!(back.last_refreshed_at.as_deref(), Some("2026-04-10T13:00:00Z"));

        // Unix file mode is 0o600.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "metadata file must be 0600 on Unix");
        }
    }

    #[test]
    fn write_metadata_atomic_second_write_replaces_first() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let path = tmpdir.path().join("gmail-meta.json");

        let mut meta = CredentialMeta {
            client_type: "shared-casa".to_owned(),
            client_source: None,
            connected_at: "2026-04-10T12:00:00Z".to_owned(),
            last_refreshed_at: None,
            scopes: vec!["https://www.googleapis.com/auth/gmail.readonly".to_owned()],
            expires_in_secs: Some(3600),
        };

        write_metadata_atomic(&path, &meta).unwrap();
        meta.last_refreshed_at = Some("2026-04-10T14:00:00Z".to_owned());
        write_metadata_atomic(&path, &meta).unwrap();

        let back: CredentialMeta =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            back.last_refreshed_at.as_deref(),
            Some("2026-04-10T14:00:00Z"),
            "second write must atomically replace the first"
        );
    }

    #[test]
    fn last_refreshed_at_absent_in_input_deserializes_to_none() {
        // Old meta file JSON written before Story 1.14b added the field.
        // The `#[serde(default)]` attribute makes this round-trip cleanly.
        let old_json = r#"{
            "client_type": "shared-casa",
            "connected_at": "2026-04-06T12:00:00Z",
            "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
            "expires_in_secs": 3600
        }"#;

        let deserialized: CredentialMeta = serde_json::from_str(old_json).unwrap();
        assert!(
            deserialized.last_refreshed_at.is_none(),
            "old meta files must deserialize with last_refreshed_at = None"
        );
        // Sanity: other fields still parse.
        assert_eq!(deserialized.client_type, "shared-casa");
        assert_eq!(deserialized.expires_in_secs, Some(3600));
    }
}
