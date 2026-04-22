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

/// Errors returned by the keystore trait and its platform adapters.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum KeyStoreError {
    /// The requested backend could not be reached at runtime — e.g., the
    /// Linux Secret Service daemon is not running, or the keyring feature
    /// for this OS was compiled out. Callers typically fall back to the
    /// passphrase adapter.
    #[error("keychain backend '{backend}' is unavailable")]
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

    /// The OS keychain returned a secret of the wrong length. The master
    /// key is always exactly 32 bytes; any deviation indicates corruption
    /// or tampering.
    #[error("master key has wrong length: expected {expected_len} bytes, got {actual_len}")]
    MalformedMasterKey { expected_len: usize, actual_len: usize },
}
