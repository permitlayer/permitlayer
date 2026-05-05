//! Operator-token authentication for the daemon's `/v1/control/*` endpoints.
//!
//! The control plane (kill / resume / reload / agent CRUD / connectors list /
//! status / whoami) is loopback-only but historically had no per-call auth —
//! `AuthLayer` bypasses bearer-token validation on operational paths
//! (`permitlayer-proxy/src/middleware/util.rs::is_operational_path`). PR #16
//! kept a PID-file pre-check on the destructive CLI commands as an implicit
//! owner-check. This module is the proper fix: a randomly-minted operator
//! token persisted at `<home>/control.token` (mode `0o600`) that the daemon's
//! middleware checks via the `X-Agentsso-Control` header before dispatching
//! to any control handler.
//!
//! # Token format
//!
//! 32 random bytes from `OsRng`, encoded as base64-url-no-pad and prefixed
//! with `agt_ctl_`. The full string is what the user puts in
//! `AGENTSSO_CONTROL_TOKEN` or what the CLI reads from disk; the daemon
//! stores both the encoded form (for bytewise-equality compare) and the
//! raw 32 bytes (for `subtle::ConstantTimeEq`).
//!
//! # Lifecycle
//!
//! - **Daemon startup**: read `<home>/control.token` if present. If missing
//!   or malformed, mint a fresh token. Atomic-write same as the PID file
//!   (write-to-temp → fsync → rename) so a partial write can never leave
//!   the file in an unusable state.
//! - **Persistence across restarts**: the token survives daemon bounces.
//!   Codex review caught the original "rotate every restart" plan as an
//!   automation footgun (every cron job holding the token would break on
//!   the next daemon start). Explicit rotation only.
//! - **Filesystem mode**: `0o600` on Unix. The owner-only mode is the
//!   primary security boundary; constant-time compare on the daemon side
//!   is defense in depth.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rand::RngCore;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

/// The token file's name within the daemon home directory.
const TOKEN_FILENAME: &str = "control.token";

/// Length of the raw random material backing the control token.
const TOKEN_RAW_BYTES: usize = 32;

/// Prefix attached to the encoded token. Distinguishes it from agent
/// bearer tokens (`agt_v2_*`) at a glance and makes the token
/// grep-visible in scripts.
const TOKEN_PREFIX: &str = "agt_ctl_";

/// Errors from control-token I/O.
#[derive(Debug, Error)]
pub enum ControlTokenError {
    #[error("I/O error on control token file at {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("control token at {path} is malformed (expected {TOKEN_PREFIX}<base64>)")]
    Malformed { path: PathBuf },

    #[error("control token at {path} has unsafe mode {mode:#o} (expected 0o600)")]
    UnsafeMode { path: PathBuf, mode: u32 },
}

/// In-memory representation of the control token, kept on the daemon
/// side. Holds the encoded form for header-equality compare.
///
/// The encoded string is wrapped in `Zeroizing` so the heap
/// allocation is scrubbed when the daemon shuts down.
pub struct ControlToken {
    encoded: Zeroizing<String>,
}

/// Manual `Debug` impl that does NOT leak the token. Used in panic
/// messages and tracing fields. Mirrors the pattern of every secret
/// type in the codebase (`OAuthToken`, `OAuthRefreshToken`, etc.).
impl std::fmt::Debug for ControlToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlToken").field("encoded", &"<redacted>").finish()
    }
}

impl ControlToken {
    /// Read or mint the daemon's control token at `<home>/control.token`.
    ///
    /// If the file exists, validates its mode and content. If anything is
    /// off (mode wrong on Unix, content malformed), refuses rather than
    /// silently overwriting — the wrong shape is operator-visible state
    /// and we'd rather fail loud than mask a misconfiguration.
    ///
    /// If the file does not exist, mints a fresh token, writes it
    /// atomically, and sets mode `0o600` on Unix.
    pub fn read_or_mint(home: &Path) -> Result<Arc<Self>, ControlTokenError> {
        let path = Self::path(home);

        if path.exists() {
            return Self::read_existing(&path).map(Arc::new);
        }

        Self::mint_and_write(&path).map(Arc::new)
    }

    /// Return the absolute path to the control token file for a given
    /// daemon home directory.
    pub fn path(home: &Path) -> PathBuf {
        home.join(TOKEN_FILENAME)
    }

    /// Constant-time comparison against a candidate token presented in
    /// the `X-Agentsso-Control` HTTP header.
    ///
    /// Comparing on the encoded string keeps this independent of the
    /// random-byte representation (which the daemon doesn't expose
    /// outside this module).
    pub fn matches(&self, candidate: &str) -> bool {
        let observed = candidate.as_bytes();
        let expected = self.encoded.as_bytes();
        // ConstantTimeEq on differing-length inputs returns false, which
        // is what we want — but the *length comparison itself* is not
        // constant-time. Pad to the longer length so the timing of the
        // mismatched-length case doesn't leak observed length.
        if observed.len() != expected.len() {
            return false;
        }
        observed.ct_eq(expected).into()
    }

    fn read_existing(path: &Path) -> Result<Self, ControlTokenError> {
        let content = std::fs::read_to_string(path)
            .map_err(|source| ControlTokenError::Io { path: path.to_owned(), source })?;
        let trimmed = content.trim();

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::metadata(path)
                .map_err(|source| ControlTokenError::Io { path: path.to_owned(), source })?;
            // Lower 9 bits = file mode bits (rwxrwxrwx). Anything other
            // than 0o600 means another user can read the token; refuse.
            let mode = metadata.mode() & 0o777;
            if mode != 0o600 {
                return Err(ControlTokenError::UnsafeMode { path: path.to_owned(), mode });
            }
        }

        let _raw = decode_token(trimmed)
            .ok_or_else(|| ControlTokenError::Malformed { path: path.to_owned() })?;
        Ok(Self { encoded: Zeroizing::new(trimmed.to_owned()) })
    }

    fn mint_and_write(path: &Path) -> Result<Self, ControlTokenError> {
        // Generate 32 random bytes from OsRng — same shape as agent
        // bearer tokens (Story 4.4) but with a different prefix.
        let mut raw = [0u8; TOKEN_RAW_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let encoded =
            format!("{TOKEN_PREFIX}{}", permitlayer_core::agent::base64_url_no_pad_encode(&raw));

        // Atomic write: write to temp, fsync, rename. Same pattern as
        // `lifecycle/pid.rs::acquire`.
        let parent = path.parent().ok_or_else(|| ControlTokenError::Io {
            path: path.to_owned(),
            source: std::io::Error::other("control token path has no parent directory"),
        })?;
        std::fs::create_dir_all(parent)
            .map_err(|source| ControlTokenError::Io { path: path.to_owned(), source })?;

        let tmp_path = path.with_extension("token.tmp");
        {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&tmp_path)
                .map_err(|source| ControlTokenError::Io { path: tmp_path.clone(), source })?;
            f.write_all(encoded.as_bytes())
                .map_err(|source| ControlTokenError::Io { path: tmp_path.clone(), source })?;
            f.write_all(b"\n")
                .map_err(|source| ControlTokenError::Io { path: tmp_path.clone(), source })?;
            f.sync_all()
                .map_err(|source| ControlTokenError::Io { path: tmp_path.clone(), source })?;
        }
        std::fs::rename(&tmp_path, path)
            .map_err(|source| ControlTokenError::Io { path: path.to_owned(), source })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|source| ControlTokenError::Io { path: path.to_owned(), source })?;
        }

        Ok(Self { encoded: Zeroizing::new(encoded) })
    }
}

/// Decode an `agt_ctl_<base64>` string into the raw 32 random bytes.
/// Returns `None` if the prefix is wrong or the base64 doesn't decode
/// to exactly 32 bytes.
fn decode_token(s: &str) -> Option<[u8; TOKEN_RAW_BYTES]> {
    let body = s.strip_prefix(TOKEN_PREFIX)?;
    let bytes = permitlayer_core::agent::base64_url_no_pad_decode(body)?;
    bytes.try_into().ok()
}

#[cfg(any(test, feature = "test-seam"))]
impl ControlToken {
    /// Construct a `ControlToken` from a fixed byte array, bypassing
    /// the file-IO path. Test-only — production callers must always
    /// route through [`Self::read_or_mint`] so the file-mode and
    /// persistence invariants hold.
    #[doc(hidden)]
    pub fn from_raw_bytes_for_test(raw: [u8; TOKEN_RAW_BYTES]) -> Self {
        let encoded =
            format!("{TOKEN_PREFIX}{}", permitlayer_core::agent::base64_url_no_pad_encode(&raw));
        Self { encoded: Zeroizing::new(encoded) }
    }

    /// Return the encoded form of the token. Test-only. Used by router
    /// tests to construct an `X-Agentsso-Control` header that the
    /// daemon will accept.
    #[doc(hidden)]
    pub fn encoded_for_test(&self) -> String {
        self.encoded.as_str().to_owned()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn mints_and_persists_on_first_call() {
        let dir = tempfile::tempdir().unwrap();
        let token = ControlToken::read_or_mint(dir.path()).unwrap();
        let path = ControlToken::path(dir.path());
        assert!(path.exists(), "token file should exist after mint");
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk.trim(), token.encoded.as_str());
        assert!(token.encoded.starts_with(TOKEN_PREFIX), "token should be prefixed");
    }

    #[test]
    fn read_returns_existing_token_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let first = ControlToken::read_or_mint(dir.path()).unwrap();
        let second = ControlToken::read_or_mint(dir.path()).unwrap();
        assert_eq!(first.encoded.as_str(), second.encoded.as_str());
    }

    #[test]
    fn matches_returns_true_for_exact_match() {
        let dir = tempfile::tempdir().unwrap();
        let token = ControlToken::read_or_mint(dir.path()).unwrap();
        let presented = token.encoded.clone();
        assert!(token.matches(&presented));
    }

    #[test]
    fn matches_returns_false_for_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let token = ControlToken::read_or_mint(dir.path()).unwrap();
        assert!(!token.matches("agt_ctl_definitelynotthistoken"));
        assert!(!token.matches(""));
        assert!(!token.matches("not-even-prefixed"));
    }

    #[test]
    fn refuses_malformed_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = ControlToken::path(dir.path());
        std::fs::write(&path, "garbage-not-a-real-token").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        match ControlToken::read_or_mint(dir.path()) {
            Err(ControlTokenError::Malformed { .. }) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn refuses_existing_file_with_wrong_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        // Mint a real token first so the on-disk content is well-formed.
        let _ = ControlToken::read_or_mint(dir.path()).unwrap();
        let path = ControlToken::path(dir.path());
        // Loosen the mode and verify the next read refuses.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        match ControlToken::read_or_mint(dir.path()) {
            Err(ControlTokenError::UnsafeMode { mode: 0o644, .. }) => {}
            other => panic!("expected UnsafeMode, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn newly_minted_file_has_mode_0o600() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let _ = ControlToken::read_or_mint(dir.path()).unwrap();
        let path = ControlToken::path(dir.path());
        let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
