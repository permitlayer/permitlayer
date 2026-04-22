//! QuickJS plugin runtime and host API for permitlayer connectors.
//!
//! Exposes the `agentsso.*` namespace to JavaScript plugins. Story 6.1
//! builds the runtime foundation + sandbox; Stories 6.2+ layer the
//! host-API implementation, plugin loader, and scaffolder on top.
//!
//! **Semver discipline (NFR41, Story 6.5):** the JS surface exposed
//! by this crate is snapshotted in `host-api.lock` at the workspace
//! root. `cargo xtask validate-plugin-api` diffs the live surface
//! against the committed lockfile on every PR; breaking changes
//! require a major-version bump of `host_api::HOST_API_VERSION` plus
//! a CHANGELOG entry. Adding a new `agentsso.*` method requires
//! updating `host_api::JS_SURFACE` alongside the registration call.

#![forbid(unsafe_code)]

pub mod error;
pub mod host_api;
pub mod loader;
pub mod registry;
pub mod runtime;
pub(crate) mod sandbox;
pub mod scope_allowlist;

pub use error::{LoadFailureReason, PluginError};
pub use host_api::{
    DecisionDesc, FetchReq, FetchResp, HOST_API_VERSION, HostApiError, HostApiErrorCode, HostCode,
    HostServices, PluginThrownCode, PolicyEvalReq, ScopedTokenDesc, ScrubMatchDesc, ScrubResponse,
    StubHostServices, UnknownHostCode, all_error_code_names, origin_str,
};
pub use loader::{
    CannedTrustPromptReader, LoaderConfig, NoOpTrustPromptReader, TrustDecision, TrustPromptReader,
    ValidatedMetadata, load_all, load_one_from_path, validate_plugin_source,
};
pub use registry::{PluginRegistry, RegisteredConnector, TrustTier};
pub use runtime::{PluginRuntime, RuntimeConfig};
pub use scope_allowlist::{ALLOWED_SCOPES, is_allowed};
