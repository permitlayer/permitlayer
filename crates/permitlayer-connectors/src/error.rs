//! Error types for the connector asset bundle + definition model.

/// Errors that can occur when loading, parsing, or validating connectors.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum ConnectorError {
    /// A `connector.toml` failed to deserialize into a
    /// [`ConnectorDef`](crate::ConnectorDef): invalid TOML, a missing
    /// mandatory field (e.g. `[upstream].allowed_hosts`), an unknown
    /// `trust_tier` value, or a stray/unknown key. The wrapped `toml`
    /// error names the offending field.
    #[error("connector definition parse error: {0}")]
    Parse(#[from] toml::de::Error),

    /// An embedded **built-in** connector failed load-time validation.
    /// This is a ship-time bug (a malformed built-in `connector.toml`),
    /// not a runtime condition — the registry surfaces it loudly rather
    /// than silently dropping a core connector. Host-installed
    /// validation failures are skip-and-warned, not this variant.
    #[error("built-in connector `{id}` failed validation: {reason}")]
    BuiltinInvalid {
        /// The offending built-in connector id.
        id: String,
        /// The validation error rendered as a string.
        reason: String,
    },
}
