//! Google OAuth client configuration: shared CASA or bring-your-own.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::OAuthError;

/// Maximum accepted size of a Google OAuth client JSON file. Google's own
/// exports are ~500 bytes; a legitimate file will never exceed a few KiB.
/// The cap guards against OOMs if `path` points at `/dev/zero` or a
/// maliciously huge file via a TOCTOU'd symlink in a shared tmp dir.
const MAX_CLIENT_JSON_BYTES: u64 = 65_536;

/// A Google OAuth client configuration, loaded from a user-provided
/// Google Cloud Console OAuth client JSON file ("bring-your-own").
///
/// A prior "shared CASA" variant was removed — permitlayer does not yet
/// have a real CASA-certified shared client, so every install must bring
/// its own OAuth credentials via `agentsso setup --oauth-client <path>`.
/// Persisted credential metadata from earlier versions may still carry
/// `client_type = "shared-casa"`; those records are treated as
/// re-setup-required rather than re-constructible.
#[derive(Debug, Clone)]
pub struct GoogleOAuthConfig {
    /// The client ID from the JSON file.
    client_id: String,
    /// The client secret (optional — PKCE-capable clients may omit it).
    client_secret: Option<String>,
    /// Path to the original JSON file (for provenance display).
    source_path: PathBuf,
}

impl GoogleOAuthConfig {
    /// Return the OAuth client ID.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Return the OAuth client secret (if any).
    #[must_use]
    pub fn client_secret(&self) -> Option<&str> {
        self.client_secret.as_deref()
    }

    /// Return a provenance tag for credential metadata display.
    ///
    /// Format: `"byo:<path>"`.
    #[must_use]
    pub fn provenance_tag(&self) -> String {
        format!("byo:{}", self.source_path.display())
    }

    /// Return the source path the config was loaded from.
    #[must_use]
    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    /// Parse a Google Cloud Console OAuth client JSON file.
    ///
    /// Supports both `"installed"` (desktop) and `"web"` client types.
    /// Only `client_id` is required; `client_secret` is optional for
    /// PKCE-capable clients.
    pub fn from_client_json(path: &Path) -> Result<Self, OAuthError> {
        let file = File::open(path)
            .map_err(|e| OAuthError::ClientJsonReadFailed { path: path.to_owned(), source: e })?;

        // Read at most MAX_CLIENT_JSON_BYTES + 1 so we can distinguish
        // "exactly the limit" (accept) from "over the limit" (reject).
        let mut contents = String::new();
        file.take(MAX_CLIENT_JSON_BYTES + 1)
            .read_to_string(&mut contents)
            .map_err(|e| OAuthError::ClientJsonReadFailed { path: path.to_owned(), source: e })?;
        if contents.len() as u64 > MAX_CLIENT_JSON_BYTES {
            return Err(OAuthError::ClientJsonInvalid {
                path: path.to_owned(),
                reason: format!("file exceeds maximum allowed size of {MAX_CLIENT_JSON_BYTES} bytes"),
            });
        }

        let json: serde_json::Value =
            serde_json::from_str(&contents).map_err(|e| OAuthError::ClientJsonInvalid {
                path: path.to_owned(),
                reason: format!("invalid JSON: {e}"),
            })?;

        // Google exports either {"installed": {...}} or {"web": {...}}.
        let client_obj = if let Some(obj) = json.get("installed") {
            obj
        } else if let Some(obj) = json.get("web") {
            tracing::warn!(
                "BYO client is a web-type OAuth client; \
                 desktop PKCE flow may not work as expected"
            );
            obj
        } else {
            return Err(OAuthError::ClientJsonInvalid {
                path: path.to_owned(),
                reason: "expected 'installed' or 'web' top-level key".to_owned(),
            });
        };

        let client_id = client_obj
            .get("client_id")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| OAuthError::ClientJsonInvalid {
                path: path.to_owned(),
                reason: "missing or empty 'client_id' field".to_owned(),
            })?
            .to_owned();

        let client_secret = client_obj
            .get("client_secret")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_owned());

        Ok(Self { client_id, client_secret, source_path: path.to_owned() })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_installed_app_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        std::fs::write(
            &path,
            r#"{
                "installed": {
                    "client_id": "123.apps.googleusercontent.com",
                    "client_secret": "GOCSPX-test-secret",
                    "project_id": "my-project"
                }
            }"#,
        )
        .unwrap();

        let config = GoogleOAuthConfig::from_client_json(&path).unwrap();
        assert_eq!(config.client_id(), "123.apps.googleusercontent.com");
        assert_eq!(config.client_secret(), Some("GOCSPX-test-secret"));
        assert_eq!(config.provenance_tag(), format!("byo:{}", path.display()));
    }

    #[test]
    fn parse_web_app_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        std::fs::write(
            &path,
            r#"{
                "web": {
                    "client_id": "456.apps.googleusercontent.com",
                    "client_secret": "GOCSPX-web-secret"
                }
            }"#,
        )
        .unwrap();

        let config = GoogleOAuthConfig::from_client_json(&path).unwrap();
        assert_eq!(config.client_id(), "456.apps.googleusercontent.com");
        assert_eq!(config.client_secret(), Some("GOCSPX-web-secret"));
    }

    #[test]
    fn parse_installed_without_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        std::fs::write(&path, r#"{"installed": {"client_id": "789.apps.googleusercontent.com"}}"#)
            .unwrap();

        let config = GoogleOAuthConfig::from_client_json(&path).unwrap();
        assert_eq!(config.client_id(), "789.apps.googleusercontent.com");
        assert!(config.client_secret().is_none());
    }

    #[test]
    fn reject_missing_client_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        std::fs::write(&path, r#"{"installed": {"project_id": "test"}}"#).unwrap();

        let err = GoogleOAuthConfig::from_client_json(&path).unwrap_err();
        assert!(format!("{err}").contains("client_id"), "error should mention client_id: {err}");
    }

    #[test]
    fn reject_oversize_file() {
        // A legitimate Google client.json is ~500 bytes; cap is 64 KiB.
        // A 100 KiB file (e.g., via symlink to /dev/zero in a shared tmp
        // dir) must be rejected before it can OOM the parser.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.json");
        let padding = "x".repeat(100_000);
        let body = format!(r#"{{"installed": {{"client_id": "x", "pad": "{padding}"}}}}"#);
        std::fs::write(&path, body).unwrap();

        let err = GoogleOAuthConfig::from_client_json(&path).unwrap_err();
        assert!(
            format!("{err}").contains("maximum allowed size"),
            "error should mention size cap: {err}"
        );
    }

    #[test]
    fn reject_nonexistent_file() {
        let path = PathBuf::from("/nonexistent/client.json");
        let err = GoogleOAuthConfig::from_client_json(&path).unwrap_err();
        assert_eq!(err.error_code(), "client_json_read_failed");
    }

    #[test]
    fn reject_invalid_json_structure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        std::fs::write(&path, r#"{"other": {"client_id": "test"}}"#).unwrap();

        let err = GoogleOAuthConfig::from_client_json(&path).unwrap_err();
        assert!(
            format!("{err}").contains("expected 'installed' or 'web'"),
            "error should mention expected keys: {err}"
        );
    }
}
