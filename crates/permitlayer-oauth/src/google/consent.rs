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

/// Validate a Google Cloud project ID against the canonical grammar
/// (Story 7.12 review P3). Per Google's documentation:
/// <https://cloud.google.com/resource-manager/docs/creating-managing-projects#identifying_projects>
///
/// > Project IDs must be 6-30 characters, start with a lowercase letter,
/// > and contain only lowercase letters, digits, and hyphens. Project
/// > IDs must not end with a hyphen.
///
/// Returns `Some(owned)` if the value matches; `None` otherwise. The
/// caller treats `None` identically to absent — the verify path's
/// remediation URL omits `?project=<id>` and the `--project` flag.
///
/// This validation is the privacy/safety boundary between the
/// untrusted on-disk `client_secret.json` and the operator-facing
/// URLs/CLI commands that the verify path constructs from the
/// project ID.
fn validate_gcp_project_id(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    if bytes.len() < 6 || bytes.len() > 30 {
        return None;
    }
    if !bytes[0].is_ascii_lowercase() {
        return None;
    }
    // Must not end with a hyphen.
    if bytes[bytes.len() - 1] == b'-' {
        return None;
    }
    if !bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-') {
        return None;
    }
    // R2-P7 round-2 review: reject consecutive hyphens. Google's
    // grammar `^[a-z][-a-z0-9]{4,28}[a-z0-9]$` does not explicitly
    // disallow consecutive hyphens, but in practice GCP rejects
    // project IDs like `a----z` at creation time. Failing here means
    // the URL/CLI never points at a non-existent project — better UX.
    if raw.contains("--") {
        return None;
    }
    Some(raw.to_owned())
}

/// A Google OAuth client configuration, loaded from a user-provided
/// Google Cloud Console OAuth client JSON file ("bring-your-own").
///
/// A prior "shared CASA" variant was removed — permitlayer does not yet
/// have a real CASA-certified shared client, so every install must bring
/// its own OAuth credentials via `agentsso setup --oauth-client <path>`.
/// Persisted credential metadata from earlier versions may still carry
/// `client_type = "shared-casa"`; those records are treated as
/// re-setup-required rather than re-constructible.
/// `Debug` is hand-written (NOT derived) so `client_secret` can never
/// leak via a `{:?}` anywhere — Story 7.35 hardening (review M3). The
/// derived impl would have printed the secret; this redacts it while
/// keeping the field's presence/absence visible for diagnostics.
#[derive(Clone)]
pub struct GoogleOAuthConfig {
    /// The client ID from the JSON file.
    client_id: String,
    /// The client secret (optional — PKCE-capable clients may omit it).
    /// Held as a plaintext `String` for the life of the config (same
    /// in-RAM window as the legacy `from_client_json` path); the
    /// redacting `Debug` impl below prevents accidental log/format
    /// disclosure.
    client_secret: Option<String>,
    /// The Google Cloud project ID from the JSON file. Optional because
    /// older or hand-edited client JSON may omit it; Google Cloud Console
    /// exports always include it for both `installed` and `web` types.
    /// Surfaced to the verify path so 403 actionable-remediation URLs
    /// (Story 7.12) can pre-fill `?project=<id>`.
    project_id: Option<String>,
    /// Path to the original JSON file (for provenance display). For a
    /// config reconstructed from a sealed bundle (Story 7.35) this is
    /// the sentinel `<sealed>` and is NEVER opened as a file.
    source_path: PathBuf,
}

impl std::fmt::Debug for GoogleOAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleOAuthConfig")
            .field("client_id", &self.client_id)
            // NEVER print the secret — only whether one is present.
            .field("client_secret", &self.client_secret.as_ref().map(|_| "<redacted>"))
            .field("project_id", &self.project_id)
            .field("source_path", &self.source_path)
            .finish()
    }
}

/// Sentinel `source_path` for a [`GoogleOAuthConfig`] reconstructed from
/// a sealed vault bundle rather than an on-disk JSON file (Story 7.35).
/// Code that would open `source_path` must treat this value as "no file"
/// — the credential lives in the vault, not on the filesystem.
pub const SEALED_SOURCE_SENTINEL: &str = "<sealed>";

/// Canonical, vault-sealed representation of a BYO OAuth client
/// (Story 7.35). Serialized to JSON and sealed via `Vault::seal` under
/// the `{service}-client` namespace so the `client_secret` is encrypted
/// at rest instead of re-read from a plaintext path on every refresh.
///
/// This type is NOT a `permitlayer-credential` newtype; keeping it out
/// of the policed set avoids expanding `xtask validate-credentials`.
/// Exposure scope, stated precisely:
/// - The serialized *bundle bytes* in transit (CLI→UDS→daemon seal,
///   and unseal→`from_sealed_bundle_bytes`) ARE wrapped in
///   `Zeroizing`/`ZeroizeOnDrop` (the `OAuthToken` seal path).
/// - `SealedClientBundle` itself and the `GoogleOAuthConfig` produced
///   by `from_sealed_bundle_bytes` hold plain `String` fields that are
///   NOT zeroized — `client_secret` lives in process heap for the
///   reconstructed config's lifetime. This in-RAM window is identical
///   to the legacy `from_client_json` path (7.35 does not regress it;
///   it removes the at-rest plaintext-on-disk exposure). The
///   `GoogleOAuthConfig` `Debug` impl is hand-written to redact the
///   secret so this window can't leak via formatting/logs.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SealedClientBundle {
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub project_id: Option<String>,
    /// Bundle format version. v1 = this shape. The reconstruction gate
    /// is intentionally strict-equality (`v != CURRENT` → hard
    /// `SealedClientBundleInvalid`, NOT an in-place migration): the
    /// single-machine scope of Story 7.35 is reset-and-reconnect, so a
    /// version bump is a deliberate breaking change that forces a
    /// re-`connect` rather than a silent misparse of an
    /// incompatible-shape bundle. (bmad-code-review F4: the prior
    /// "detect and migrate older sealed bundles" wording was
    /// contradicted by the strict-equality gate — there is no migration
    /// path by design.) `#[serde(default)]` only covers a v1 bundle
    /// written before this field existed; it does not imply
    /// cross-version tolerance.
    #[serde(default = "default_bundle_version")]
    pub v: u8,
}

fn default_bundle_version() -> u8 {
    1
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

    /// Return the Google Cloud project ID parsed from the OAuth client
    /// JSON, if present. Used by the post-OAuth verify path (Story 7.12)
    /// to pre-fill the `?project=<id>` query parameter on the
    /// console-enablement remediation URL when a 403 surfaces a
    /// `SERVICE_DISABLED` / `BILLING_DISABLED` reason.
    #[must_use]
    pub fn project_id(&self) -> Option<&str> {
        self.project_id.as_deref()
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
                reason: format!(
                    "file exceeds maximum allowed size of {MAX_CLIENT_JSON_BYTES} bytes"
                ),
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

        // Story 7.12: parse `project_id` for the verify path's actionable
        // remediation URL. Mirrors `client_secret`'s shape, plus shape
        // validation against Google's GCP project-ID grammar
        // (`^[a-z][-a-z0-9]{4,28}[a-z0-9]$`) per Story 7.12 review P3 —
        // the value flows raw into URL+gcloud rendering, so a corrupted
        // or hand-edited `client_secret.json` with whitespace, control
        // chars, or injected query parameters must not survive parse.
        // Any value that fails validation is treated identically to
        // absent (the renderer omits `?project=…` and `--project`).
        let project_id =
            client_obj.get("project_id").and_then(|v| v.as_str()).and_then(validate_gcp_project_id);

        Ok(Self { client_id, client_secret, project_id, source_path: path.to_owned() })
    }

    /// Serialize this config into the canonical [`SealedClientBundle`]
    /// JSON bytes for vault sealing (Story 7.35). The returned buffer is
    /// `Zeroizing` so the plaintext `client_secret` is scrubbed when the
    /// caller drops it (it is moved into an `OAuthToken` immediately).
    pub fn to_sealed_bundle_bytes(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, OAuthError> {
        let bundle = SealedClientBundle {
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            project_id: self.project_id.clone(),
            v: default_bundle_version(),
        };
        let bytes = serde_json::to_vec(&bundle).map_err(|e| {
            OAuthError::SealedClientBundleInvalid { reason: format!("serialize: {e}") }
        })?;
        Ok(zeroize::Zeroizing::new(bytes))
    }

    /// Reconstruct a config from the canonical [`SealedClientBundle`]
    /// JSON bytes produced by [`Self::to_sealed_bundle_bytes`] and
    /// recovered via `Vault::unseal` (Story 7.35). `source_path` is set
    /// to the [`SEALED_SOURCE_SENTINEL`] — this config must NEVER be
    /// used to open a file.
    pub fn from_sealed_bundle_bytes(bytes: &[u8]) -> Result<Self, OAuthError> {
        let bundle: SealedClientBundle = serde_json::from_slice(bytes).map_err(|e| {
            OAuthError::SealedClientBundleInvalid { reason: format!("deserialize: {e}") }
        })?;
        if bundle.v != default_bundle_version() {
            return Err(OAuthError::SealedClientBundleInvalid {
                reason: format!("unsupported bundle version {}", bundle.v),
            });
        }

        // bmad-code-review F2: the sealed-bundle reconstruction MUST
        // enforce the same field validation as `from_client_json` — the
        // two paths are documented as behaviorally identical, and a
        // decryptable-but-corrupt bundle (operator-crafted, or a future
        // bundle-version producer that relaxes validation) otherwise
        // bypasses the Story 7.12 guard. Without this:
        //  - empty `client_id` → opaque upstream-refresh failure instead
        //    of an actionable SealedClientBundleInvalid;
        //  - `client_secret == Some("")` → empty secret sent to Google's
        //    token endpoint instead of PKCE-omitted (wire divergence);
        //  - unvalidated `project_id` → re-opens the URL/`gcloud`
        //    injection vector Story 7.12 review P3 closed (the value
        //    flows raw into the 403 remediation URL + `--project`).
        if bundle.client_id.is_empty() {
            return Err(OAuthError::SealedClientBundleInvalid {
                reason: "missing or empty 'client_id' field".to_owned(),
            });
        }
        // Match `from_client_json`: empty secret ≡ absent (PKCE client).
        let client_secret = bundle.client_secret.filter(|s| !s.is_empty());
        // Match `from_client_json`: any project_id failing the GCP
        // grammar is treated identically to absent (renderer omits it).
        let project_id = bundle.project_id.as_deref().and_then(validate_gcp_project_id);

        Ok(Self {
            client_id: bundle.client_id,
            client_secret,
            project_id,
            source_path: PathBuf::from(SEALED_SOURCE_SENTINEL),
        })
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
        assert_eq!(config.project_id(), Some("my-project"));
        assert_eq!(config.provenance_tag(), format!("byo:{}", path.display()));
    }

    #[test]
    fn parse_installed_without_project_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        std::fs::write(
            &path,
            r#"{
                "installed": {
                    "client_id": "123.apps.googleusercontent.com",
                    "client_secret": "GOCSPX-test-secret"
                }
            }"#,
        )
        .unwrap();

        let config = GoogleOAuthConfig::from_client_json(&path).unwrap();
        assert!(config.project_id().is_none());
    }

    /// P3 round-1 review: `project_id` is shape-validated against
    /// Google's GCP grammar. Values containing whitespace, control
    /// chars, or query-string metacharacters are silently dropped to
    /// `None` (treated identically to absent — URL omits the param).
    #[test]
    fn rejects_project_id_with_query_string_injection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        std::fs::write(
            &path,
            r#"{
                "installed": {
                    "client_id": "x.apps.googleusercontent.com",
                    "project_id": "my-project&inject=evil"
                }
            }"#,
        )
        .unwrap();
        let config = GoogleOAuthConfig::from_client_json(&path).unwrap();
        assert!(config.project_id().is_none(), "P3: project_id with `&` must be rejected");
    }

    #[test]
    fn rejects_project_id_with_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        std::fs::write(
            &path,
            r#"{
                "installed": {
                    "client_id": "x.apps.googleusercontent.com",
                    "project_id": "my project"
                }
            }"#,
        )
        .unwrap();
        let config = GoogleOAuthConfig::from_client_json(&path).unwrap();
        assert!(config.project_id().is_none(), "P3: project_id with whitespace must be rejected");
    }

    #[test]
    fn rejects_project_id_with_uppercase() {
        // GCP project IDs are lowercase by spec.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        std::fs::write(
            &path,
            r#"{
                "installed": {
                    "client_id": "x.apps.googleusercontent.com",
                    "project_id": "MyProject"
                }
            }"#,
        )
        .unwrap();
        let config = GoogleOAuthConfig::from_client_json(&path).unwrap();
        assert!(config.project_id().is_none(), "P3: project_id must be lowercase");
    }

    #[test]
    fn rejects_project_id_too_short_or_too_long() {
        // Per Google: 6-30 characters.
        let dir = tempfile::tempdir().unwrap();
        for (label, short_id) in
            [("too short", "abc"), ("too long", "a".repeat(40).as_str())].iter()
        {
            let path = dir.path().join(format!("client_{label}.json"));
            std::fs::write(
                &path,
                format!(
                    r#"{{"installed":{{"client_id":"x.apps.googleusercontent.com","project_id":"{short_id}"}}}}"#
                ),
            )
            .unwrap();
            let config = GoogleOAuthConfig::from_client_json(&path).unwrap();
            assert!(config.project_id().is_none(), "P3: project_id length-bounded ({label})");
        }
    }

    /// R2-P7 round-2 review: consecutive hyphens are rejected (Google's
    /// project-creation API rejects them in practice; failing at parse
    /// time means the URL/CLI never points at a non-existent project).
    #[test]
    fn rejects_project_id_with_consecutive_hyphens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        std::fs::write(
            &path,
            r#"{
                "installed": {
                    "client_id": "x.apps.googleusercontent.com",
                    "project_id": "abc--xyz"
                }
            }"#,
        )
        .unwrap();
        let config = GoogleOAuthConfig::from_client_json(&path).unwrap();
        assert!(
            config.project_id().is_none(),
            "R2-P7: project_id with consecutive hyphens must be rejected"
        );
    }

    /// R3-P16 round-3 review: multiple single hyphens in project ID
    /// (the canonical Google form) is accepted. Coverage gap flagged
    /// by Edge Case Hunter #24.
    #[test]
    fn accepts_project_id_with_multiple_single_hyphens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        std::fs::write(
            &path,
            r#"{
                "installed": {
                    "client_id": "x.apps.googleusercontent.com",
                    "project_id": "my-app-prod"
                }
            }"#,
        )
        .unwrap();
        let config = GoogleOAuthConfig::from_client_json(&path).unwrap();
        assert_eq!(
            config.project_id(),
            Some("my-app-prod"),
            "R3-P16: multiple single hyphens (canonical Google form) must be accepted"
        );
    }

    #[test]
    fn rejects_project_id_ending_with_hyphen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        std::fs::write(
            &path,
            r#"{
                "installed": {
                    "client_id": "x.apps.googleusercontent.com",
                    "project_id": "my-project-"
                }
            }"#,
        )
        .unwrap();
        let config = GoogleOAuthConfig::from_client_json(&path).unwrap();
        assert!(config.project_id().is_none(), "P3: project_id ending with `-` must be rejected");
    }

    #[test]
    fn parse_installed_with_empty_project_id_treated_as_none() {
        // Empty-string `project_id` is parsed as None (mirrors client_secret).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        std::fs::write(
            &path,
            r#"{
                "installed": {
                    "client_id": "123.apps.googleusercontent.com",
                    "project_id": ""
                }
            }"#,
        )
        .unwrap();

        let config = GoogleOAuthConfig::from_client_json(&path).unwrap();
        assert!(config.project_id().is_none());
    }

    #[test]
    fn parse_web_app_json_with_project_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        std::fs::write(
            &path,
            r#"{
                "web": {
                    "client_id": "456.apps.googleusercontent.com",
                    "client_secret": "GOCSPX-web-secret",
                    "project_id": "web-project-id"
                }
            }"#,
        )
        .unwrap();

        let config = GoogleOAuthConfig::from_client_json(&path).unwrap();
        assert_eq!(config.project_id(), Some("web-project-id"));
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

    // --- Story 7.35: sealed client bundle round-trip ---

    fn cfg(client_id: &str, secret: Option<&str>, project: Option<&str>) -> GoogleOAuthConfig {
        GoogleOAuthConfig {
            client_id: client_id.to_owned(),
            client_secret: secret.map(str::to_owned),
            project_id: project.map(str::to_owned),
            source_path: std::path::PathBuf::from("/tmp/orig-client.json"),
        }
    }

    #[test]
    fn sealed_bundle_round_trip_full() {
        let c = cfg("123.apps.googleusercontent.com", Some("GOCSPX-secret"), Some("my-project"));
        let bytes = c.to_sealed_bundle_bytes().unwrap();
        let back = GoogleOAuthConfig::from_sealed_bundle_bytes(&bytes).unwrap();
        assert_eq!(back.client_id(), "123.apps.googleusercontent.com");
        assert_eq!(back.client_secret(), Some("GOCSPX-secret"));
        assert_eq!(back.project_id(), Some("my-project"));
        // Reconstructed config must carry the sealed sentinel, never a
        // real path (it must never be opened as a file).
        assert_eq!(back.source_path().to_string_lossy(), SEALED_SOURCE_SENTINEL);
    }

    #[test]
    fn sealed_bundle_round_trip_pkce_no_secret() {
        // project_id must satisfy the GCP grammar (6-30 chars) — the
        // F2 hardening makes from_sealed_bundle_bytes validate it just
        // like from_client_json, so the round-trip property only holds
        // for a value a real (validated) config could actually carry.
        let c = cfg("pkce.apps.googleusercontent.com", None, Some("pkce-proj"));
        let bytes = c.to_sealed_bundle_bytes().unwrap();
        let back = GoogleOAuthConfig::from_sealed_bundle_bytes(&bytes).unwrap();
        assert_eq!(back.client_id(), "pkce.apps.googleusercontent.com");
        assert_eq!(back.client_secret(), None);
        assert_eq!(back.project_id(), Some("pkce-proj"));
    }

    #[test]
    fn sealed_bundle_round_trip_no_project() {
        let c = cfg("noproj.apps.googleusercontent.com", Some("s"), None);
        let bytes = c.to_sealed_bundle_bytes().unwrap();
        let back = GoogleOAuthConfig::from_sealed_bundle_bytes(&bytes).unwrap();
        assert_eq!(back.client_secret(), Some("s"));
        assert_eq!(back.project_id(), None);
    }

    #[test]
    fn sealed_bundle_rejects_unknown_version() {
        let json = br#"{"client_id":"x","v":99}"#;
        let err = GoogleOAuthConfig::from_sealed_bundle_bytes(json).unwrap_err();
        assert!(
            matches!(err, OAuthError::SealedClientBundleInvalid { .. }),
            "unsupported version must be SealedClientBundleInvalid, got: {err}"
        );
    }

    #[test]
    fn sealed_bundle_rejects_garbage() {
        let err = GoogleOAuthConfig::from_sealed_bundle_bytes(b"not json").unwrap_err();
        assert!(matches!(err, OAuthError::SealedClientBundleInvalid { .. }), "got: {err}");
    }

    // ── bmad-code-review F2: from_sealed_bundle_bytes must enforce the
    //    same field validation as from_client_json (parity) ──────────

    #[test]
    fn sealed_bundle_rejects_empty_client_id() {
        // A decryptable-but-corrupt bundle with an empty client_id must
        // fail with an actionable error, not produce a config that
        // refreshes opaquely against Google with no client_id.
        let json = br#"{"client_id":"","client_secret":"s","v":1}"#;
        let err = GoogleOAuthConfig::from_sealed_bundle_bytes(json).unwrap_err();
        assert!(
            matches!(err, OAuthError::SealedClientBundleInvalid { .. }),
            "empty client_id must be SealedClientBundleInvalid, got: {err}"
        );
    }

    #[test]
    fn sealed_bundle_empty_client_secret_normalizes_to_none() {
        // Parity with from_client_json: "" ≡ absent (PKCE client). A
        // bundle carrying "client_secret":"" must NOT send an empty
        // secret to Google's token endpoint.
        let json = br#"{"client_id":"pkce.apps.googleusercontent.com","client_secret":"","v":1}"#;
        let back = GoogleOAuthConfig::from_sealed_bundle_bytes(json).unwrap();
        assert_eq!(back.client_secret(), None);
    }

    #[test]
    fn sealed_bundle_invalid_project_id_treated_as_absent() {
        // Story 7.12 review P3: project_id flows raw into the 403
        // remediation URL + `gcloud --project`. A bundle with an
        // injection-y project_id must be dropped (treated as absent),
        // identically to from_client_json — NOT carried through.
        let json =
            br#"{"client_id":"x.apps.googleusercontent.com","project_id":"p?inject=1","v":1}"#;
        let back = GoogleOAuthConfig::from_sealed_bundle_bytes(json).unwrap();
        assert_eq!(
            back.project_id(),
            None,
            "an invalid/injection project_id must be dropped, not carried into URL/CLI rendering"
        );
    }

    #[test]
    fn sealed_bundle_valid_project_id_survives() {
        // Sanity: a grammar-valid project_id is preserved (the F2
        // hardening must not reject legitimate values).
        let json =
            br#"{"client_id":"x.apps.googleusercontent.com","project_id":"my-proj-123","v":1}"#;
        let back = GoogleOAuthConfig::from_sealed_bundle_bytes(json).unwrap();
        assert_eq!(back.project_id(), Some("my-proj-123"));
    }
}
