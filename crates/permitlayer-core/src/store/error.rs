//! Error types for the credential store.
//!
//! `StoreError` is the public surface — the one error callers actually
//! match on. `EnvelopeParseError` is a nested chain carrier: every
//! failure path in the on-disk envelope parser maps to a variant of
//! this enum, which then lands as the `source` of
//! `StoreError::CorruptEnvelope`.

/// Errors returned by `CredentialStore` implementations.
///
/// Service names in error messages are safe (not credential material).
/// Sealed envelope bytes never appear in any variant's `Display` or
/// `Debug` impl.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum StoreError {
    /// Service name violates the allowlist. Returned by
    /// `validate_service_name` before the string ever becomes a
    /// filesystem path.
    #[error("service name '{input}' does not match allowlist pattern")]
    InvalidServiceName {
        /// The invalid service name (safe to echo — service names
        /// never contain credential material).
        input: String,
    },
    /// On-disk sealed envelope is malformed: truncated, overlong, bad
    /// magic, or any other structural violation caught by the parser.
    #[error("sealed envelope on disk is corrupted")]
    CorruptEnvelope {
        /// The specific parse failure.
        #[source]
        source: EnvelopeParseError,
    },
    /// Low-level filesystem I/O failure. Wraps `std::io::Error` via
    /// `#[from]` so the `?` operator lifts it automatically.
    #[error("I/O failure accessing store")]
    IoError(#[from] std::io::Error),
    /// Sealed envelope's version field is not known to this build. The
    /// store refuses to parse forward-incompatible envelopes.
    #[error("sealed envelope version {got} is not supported (expected {expected})")]
    UnsupportedVersion {
        /// The version found on the envelope.
        got: u16,
        /// The version this build knows how to parse.
        expected: u16,
    },
    /// `tokio::task::spawn_blocking` handle failed (task panicked or
    /// was cancelled). Mapped via `#[from]` so `.await?` on a blocking
    /// task handle promotes cleanly.
    #[error("blocking I/O task failed")]
    BlockingTaskJoin(#[from] tokio::task::JoinError),
    /// Audit log write failed — wraps I/O or serialization errors during
    /// append.
    #[error("audit write failed: {reason}")]
    AuditWriteFailed {
        reason: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    /// Audit log rotation failed — file rename during rotation did not
    /// succeed.
    #[error("audit rotation failed: {reason}")]
    AuditRotationFailed {
        reason: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    /// Agent name violates the allowlist (Story 4.4). Same allowlist
    /// shape as `InvalidServiceName` but the namespace is the
    /// `agents/` directory rather than `vault/`.
    #[error("agent name '{input}' does not match allowlist pattern")]
    InvalidAgentName {
        /// The invalid agent name (safe to echo — agent names never
        /// contain credential material).
        input: String,
    },
    /// Refused to overwrite an existing `agents/<name>.toml` file.
    /// Returned by `AgentIdentityStore::put` when the agent is already
    /// registered. Operator remediation: `agentsso agent remove <name>`
    /// followed by a fresh `register` to reissue the bearer token.
    #[error("agent '{name}' is already registered")]
    AgentAlreadyExists {
        /// The agent name that already exists.
        name: String,
    },
    /// Another `put` for the same agent name is already in flight in
    /// this process. Returned by `AgentIdentityFsStore::put` when a
    /// second concurrent caller races to register the same name. The
    /// losing caller should retry after the winner finishes (and will
    /// then observe `AgentAlreadyExists`, which is the correct terminal
    /// state).
    #[error("agent '{name}' has a concurrent write in flight")]
    ConcurrentWrite {
        /// The agent name whose write is already in flight.
        name: String,
    },
    /// `AgentIdentity` failed to serialize to TOML. Should never
    /// happen at runtime — every field is a primitive or `chrono`
    /// type — but the serializer is fallible by API contract so the
    /// error is propagated.
    #[error("agent identity serialization failed: {reason}")]
    AgentSerializationFailed {
        reason: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    /// `AgentIdentity` failed to deserialize from TOML. Returned when
    /// an on-disk agent file is malformed (manual edit, partial write,
    /// schema drift across versions).
    #[error("agent identity deserialization failed for '{name}': {reason}")]
    AgentDeserializationFailed {
        /// The agent name (filename stem) that failed to parse.
        name: String,
        reason: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

/// Structural parse failures for the on-disk sealed-credential envelope.
///
/// Variants carry only lengths and offsets — never envelope bytes. A
/// caller printing a `CorruptEnvelope { source }` chain sees exactly
/// which length check tripped, not the (possibly forged) header bytes
/// that produced it.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum EnvelopeParseError {
    /// The envelope is shorter than the fixed 23-byte header prefix.
    #[error("envelope truncated: needed {needed} bytes at offset {offset}, {remaining} remaining")]
    Truncated {
        /// Offset into the envelope where the read was attempted.
        offset: usize,
        /// Bytes the parser needed at that offset.
        needed: usize,
        /// Bytes actually remaining at that offset.
        remaining: usize,
    },
    /// A length field claims more bytes than exist on disk (or more
    /// than the policy cap, e.g., `MAX_PLAINTEXT_LEN + GCM_TAG_LEN`).
    #[error("length field '{field}' = {value} exceeds remaining envelope capacity {file_size}")]
    LengthFieldExceedsFile {
        /// Which length field is out of range (`aad_len` or `ct_len`).
        field: &'static str,
        /// The value the length field claimed.
        value: u64,
        /// The envelope's total size in bytes (the cap).
        file_size: u64,
    },
    /// Envelope's `nonce_len` byte is not the expected value (12 at
    /// version 1). Catches forward-incompatible envelopes before they
    /// reach `Nonce::from_slice`, which panics on wrong length.
    #[error("nonce_len = {got}, expected {expected}")]
    NonceLenMismatch {
        /// The `nonce_len` byte on the envelope.
        got: u8,
        /// The value this version expects.
        expected: u8,
    },
    /// AAD length exceeds the per-version cap (128 bytes at version 1).
    #[error("aad_len = {got} exceeds per-version cap of {max}")]
    AadTooLarge {
        /// The AAD length the envelope claimed.
        got: u32,
        /// The per-version AAD cap.
        max: u32,
    },
    /// Ciphertext length exceeds the per-version cap
    /// (`MAX_PLAINTEXT_LEN + 16`).
    #[error("ct_len = {got} exceeds per-version cap of {max}")]
    CiphertextTooLarge {
        /// The ciphertext length the envelope claimed.
        got: u32,
        /// The per-version ciphertext cap (`MAX_PLAINTEXT_LEN + 16`).
        max: u32,
    },
    /// Declared envelope layout does not reach end-of-file exactly.
    /// Catches "trailing garbage" and "short file" together.
    #[error("declared envelope size {declared} does not match file size {file_size}")]
    SizeMismatch {
        /// `23 + aad_len + ct_len`.
        declared: u64,
        /// Actual file size on disk.
        file_size: u64,
    },
}
