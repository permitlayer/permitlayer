//! Filesystem adapters for the storage traits.
//!
//! Hosts the `~/.agentsso/`-rooted adapters for credentials, audit
//! events, and agent identities. Each adapter is its own module so
//! the production crate compiles cleanly with `#![forbid(unsafe_code)]`
//! and so tests can target one adapter at a time.

pub mod agent_fs;
pub mod audit_fs;
pub mod credential_fs;

pub use agent_fs::AgentIdentityFsStore;
pub use audit_fs::AuditFsStore;
pub use credential_fs::CredentialFsStore;
