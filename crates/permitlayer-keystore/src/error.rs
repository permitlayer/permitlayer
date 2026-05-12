//! Error types for the `KeyStore` abstraction.
//!
//! Every variant is `#[non_exhaustive]`-safe at the enum level, meaning new
//! variants may be added without a semver break. Callers MUST match with a
//! `_` catch-all.
//!
//! Error chaining discipline (see `architecture.md` §Format Patterns,
//! lines 458–467): no stringification of other errors — use `#[source]`
//! chains or `#[from]`. `PlatformError::message` is the one exception and
//! carries only backend diagnostic text (never the stored secret value).

/// Reason a `MalformedMasterKey` error fired. Round-3 review fix
/// disambiguates length-mismatch from bad-character so operator-
/// facing error rendering can be specific.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MalformedReason {
    /// The decoded buffer was not `MASTER_KEY_LEN` bytes.
    BadLength,
    /// The buffer was the correct length but contained one or more
    /// bytes outside `0-9a-fA-F` (hex backend).
    BadCharacter,
}

impl std::fmt::Display for MalformedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadLength => f.write_str("bad length"),
            Self::BadCharacter => f.write_str("non-hex character"),
        }
    }
}

/// Errors returned by the keystore trait and its platform adapters.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum KeyStoreError {
    /// The requested backend could not be reached at runtime — e.g., the
    /// Linux Secret Service daemon is not running, or the keyring feature
    /// for this OS was compiled out. Callers typically fall back to the
    /// passphrase adapter.
    #[error("keychain backend '{backend}' is unavailable: {source}")]
    BackendUnavailable {
        /// Which backend failed: "apple", "libsecret", "windows", etc.
        backend: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The derived key did not unlock the persisted verifier — the user
    /// typed the wrong passphrase. Fail-closed: the daemon MUST exit
    /// rather than proceed with a mismatched key (AC #4).
    #[error("passphrase does not match the stored verifier")]
    PassphraseMismatch,

    /// The user entered an empty passphrase (zero bytes). Rejected
    /// before any Argon2id derivation happens.
    #[error("passphrase was empty")]
    EmptyPassphrase,

    /// Argon2id key derivation failed internally. This is not a "wrong
    /// passphrase" error — it's a KDF library-level failure (e.g., bad
    /// parameters).
    #[error("Argon2id key derivation failed")]
    Argon2Failed(#[from] argon2::Error),

    /// Argon2id parameter construction failed. Separate variant so
    /// callers can distinguish "bad params" from "derivation crashed".
    #[error("Argon2id parameter construction failed")]
    Argon2ParamsFailed(#[source] argon2::Error),

    /// Filesystem I/O failed while reading or writing salt / verifier.
    #[error("I/O failure accessing keystore file")]
    IoError(#[from] std::io::Error),

    /// The `keyring` crate returned an error we cannot structurally
    /// classify — e.g., a platform-specific failure we don't have a
    /// dedicated variant for. `message` carries backend diagnostic
    /// text and NEVER contains the stored secret value.
    #[error("platform keychain returned an error on '{backend}': {message}")]
    PlatformError { backend: &'static str, message: String },

    /// `set_master_key` was called on an adapter that cannot replace its
    /// key — e.g., the passphrase adapter derives its key from user
    /// input, so there is no "stored" key to overwrite. Callers should
    /// prompt the user to change their passphrase and re-construct the
    /// adapter.
    #[error("this keystore adapter does not support replacing the master key")]
    PassphraseAdapterImmutable,

    /// The OS keychain returned a secret of the wrong length or containing
    /// invalid characters. The master key is always exactly 32 bytes
    /// (64 hex chars on the macOS System.keychain backend); any deviation
    /// indicates corruption or tampering.
    ///
    /// Round-3 review fix: the previous shape conflated bad-length and
    /// bad-character failures (both reported `expected_len`/`actual_len`).
    /// A bad-char input with the right length reported `expected=64,
    /// actual=64`, which renders confusingly as "length matches but
    /// malformed why?" in operator-facing error messages.
    /// `reason: BadLength` / `reason: BadCharacter` discriminates the
    /// two cases.
    #[error("master key malformed: expected {expected_len} bytes, got {actual_len} ({reason})")]
    MalformedMasterKey { expected_len: usize, actual_len: usize, reason: MalformedReason },

    /// The daemon needed to prompt for a passphrase (because the native
    /// keychain is unavailable and `FallbackMode::Auto` is engaged) but
    /// no controlling terminal is available. Surfaces under launchd /
    /// `brew services start` / `ssh -T` — anywhere `/dev/tty` cannot
    /// be opened.
    ///
    /// Carries operator-actionable recovery guidance in its `Display`
    /// so the daemon's error banner doesn't need to special-case this
    /// variant.
    #[error(
        "passphrase prompt unavailable: no controlling terminal (run from a terminal, OR set `[keystore].fallback = \"none\"` and recover the keychain ACL manually, OR use `agentsso setup` to remint the master key)"
    )]
    PassphrasePromptUnavailable,

    /// The native keystore failed at runtime AND the lazy passphrase
    /// fallback also failed to construct. Carries both errors so the
    /// operator sees the underlying native cause AND the fallback
    /// failure in a single Display chain — instead of just the
    /// fallback error opaquely hiding the OSStatus that triggered the
    /// fallback in the first place.
    ///
    /// Common shape: native is `BackendUnavailable(-25308)`, fallback
    /// is `PassphrasePromptUnavailable` (because the daemon is running
    /// under launchd).
    #[error("native keystore unavailable ({native}) and passphrase fallback failed ({fallback})")]
    RuntimeFallbackFailed {
        #[source]
        native: Box<KeyStoreError>,
        fallback: Box<KeyStoreError>,
    },

    /// Story 7.22 sentinel: the native keystore returned
    /// `BackendUnavailable -25308` (macOS keychain ACL invalidated
    /// after a binary swap) AND the wrapper was constructed with
    /// `AclBreakRecoveryMode::Auto`. The wrapper hands this sentinel
    /// up to the daemon's boot path INSTEAD of engaging the
    /// passphrase prompt, so the boot path can verify the new
    /// binary's codesign Designated Requirement against the persisted
    /// trust anchor and auto-rekey the vault.
    ///
    /// Only `start.rs::ensure_master_key_bootstrapped` opts into
    /// `AclBreakRecoveryMode::Auto`. All non-boot CLI paths
    /// (`connect` ×2, `credentials`, `rotate-key`,
    /// `keystore-clear-previous`, `uninstall`) construct
    /// `KeystoreConfig` with `AclBreakRecoveryMode::Disabled` and
    /// inherit the existing passphrase-fallback behavior unchanged.
    ///
    /// Carries the underlying native error for forensics.
    #[error("keychain ACL invalidated by binary swap; auto-recovery required")]
    AclBreakNeedsRekey {
        #[source]
        native: Box<KeyStoreError>,
    },
}

impl KeyStoreError {
    /// Best-effort clone of self for error chaining. Used when an error
    /// must appear inside another error variant (e.g.,
    /// `RuntimeFallbackFailed`'s `native` field). The underlying types
    /// in some variants do not implement `Clone` (e.g.,
    /// `Box<dyn Error>` on `BackendUnavailable`'s source), so we
    /// stringify them rather than try to deep-clone.
    ///
    /// Linux + Windows only post-Story 7.26 (macOS no longer wraps
    /// native in FallbackKeyStore — see `fallback` module gate).
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub(crate) fn clone_for_chain(&self) -> Self {
        match self {
            Self::BackendUnavailable { backend, source } => {
                // The boxed source isn't Clone; preserve its message
                // by re-wrapping as a synthetic io::Error so the
                // OSStatus text is retained for operator visibility.
                Self::BackendUnavailable {
                    backend,
                    source: Box::new(std::io::Error::other(source.to_string())),
                }
            }
            Self::PassphraseMismatch => Self::PassphraseMismatch,
            Self::EmptyPassphrase => Self::EmptyPassphrase,
            // argon2::Error doesn't implement Clone; preserve via Display.
            Self::Argon2Failed(e) => {
                Self::PlatformError { backend: "argon2", message: e.to_string() }
            }
            Self::Argon2ParamsFailed(e) => {
                Self::PlatformError { backend: "argon2", message: e.to_string() }
            }
            Self::IoError(e) => Self::PlatformError { backend: "io", message: e.to_string() },
            Self::PlatformError { backend, message } => {
                Self::PlatformError { backend, message: message.clone() }
            }
            Self::PassphraseAdapterImmutable => Self::PassphraseAdapterImmutable,
            Self::MalformedMasterKey { expected_len, actual_len, reason } => {
                Self::MalformedMasterKey {
                    expected_len: *expected_len,
                    actual_len: *actual_len,
                    reason: *reason,
                }
            }
            Self::PassphrasePromptUnavailable => Self::PassphrasePromptUnavailable,
            Self::RuntimeFallbackFailed { native, fallback } => Self::RuntimeFallbackFailed {
                native: Box::new(native.clone_for_chain()),
                fallback: Box::new(fallback.clone_for_chain()),
            },
            Self::AclBreakNeedsRekey { native } => {
                Self::AclBreakNeedsRekey { native: Box::new(native.clone_for_chain()) }
            }
        }
    }

    /// Sentinel check used by the daemon's boot path (Story 7.22) to
    /// branch into the auto-recovery flow. True only for
    /// [`Self::AclBreakNeedsRekey`].
    pub fn is_acl_break_needs_rekey(&self) -> bool {
        matches!(self, Self::AclBreakNeedsRekey { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin Plan A's load-bearing Display contract on every CI leg.
    ///
    /// `BackendUnavailable`'s `#[error("...: {source}")]` is what carries
    /// the OSStatus from the routing layer in `keyring_shared::map_err`
    /// to operator stderr via `log_fallback`'s `eprintln!("...: {e}")`.
    /// The macOS-specific routing test in `keyring_shared.rs` already
    /// asserts the same thing — but it's gated behind
    /// `#[cfg(all(test, target_os = "macos"))]`, so a Linux contributor
    /// who refactored the format string would not trip CI. This test
    /// runs on every leg (Linux, Windows, macOS) and catches that
    /// regression class before merge.
    #[test]
    fn backend_unavailable_display_surfaces_source() {
        let sentinel = "PLAN_A_SENTINEL_OSSTATUS_-25308";
        let err = KeyStoreError::BackendUnavailable {
            backend: "test",
            source: Box::new(std::io::Error::other(sentinel)),
        };
        let displayed = err.to_string();
        assert!(
            displayed.contains(sentinel),
            "BackendUnavailable Display must surface its source — got {displayed:?}"
        );
        assert!(
            displayed.contains("test"),
            "BackendUnavailable Display must surface the backend name — got {displayed:?}"
        );
    }

    /// rc.12 contract: `RuntimeFallbackFailed` must surface BOTH the
    /// native cause AND the fallback failure in its Display. Without
    /// this, an operator under launchd would see only the fallback's
    /// `PassphrasePromptUnavailable` error and lose the OSStatus that
    /// caused the fallback to engage in the first place.
    #[test]
    fn runtime_fallback_failed_chains_both_messages() {
        let native_sentinel = "OSSTATUS_-25308_NATIVE_SENTINEL";
        let fallback_sentinel = "FALLBACK_PROMPT_SENTINEL";
        let err = KeyStoreError::RuntimeFallbackFailed {
            native: Box::new(KeyStoreError::BackendUnavailable {
                backend: "apple",
                source: Box::new(std::io::Error::other(native_sentinel)),
            }),
            fallback: Box::new(KeyStoreError::PlatformError {
                backend: "passphrase",
                message: fallback_sentinel.into(),
            }),
        };
        let displayed = err.to_string();
        assert!(
            displayed.contains(native_sentinel),
            "must surface native cause in Display — got {displayed:?}"
        );
        assert!(
            displayed.contains(fallback_sentinel),
            "must surface fallback failure in Display — got {displayed:?}"
        );
    }
}
