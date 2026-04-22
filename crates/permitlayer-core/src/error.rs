//! Top-level error type for `permitlayer-core`.
//!
//! Domain modules (store, policy, scrub, audit, agent, killswitch) will
//! expose their own error enums in their respective `error.rs` files.

/// Placeholder top-level core error. Real variants land as domain modules are
/// implemented in Stories 1.3+.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum CoreError {
    /// Placeholder variant.
    #[error("core error")]
    Unspecified,

    /// Scrubbing engine error.
    #[error(transparent)]
    Scrub(#[from] crate::scrub::ScrubError),

    /// Kill-switch domain error.
    #[error(transparent)]
    KillSwitch(#[from] crate::killswitch::KillSwitchError),

    /// Policy compile error.
    #[error(transparent)]
    Policy(#[from] crate::policy::PolicyCompileError),
}
