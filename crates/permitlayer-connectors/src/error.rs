//! Error types for the built-in JS connector asset bundle.

/// Errors that can occur when loading or validating embedded JS connectors.
///
/// Variants will be added as Story 2.5 wires up Calendar/Drive connector
/// loading and Story 1.11 introduces the Gmail connector.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum ConnectorError {
    /// Placeholder variant. Real variants will be added in Stories 1.11+.
    #[error("connector error")]
    Unspecified,
}
