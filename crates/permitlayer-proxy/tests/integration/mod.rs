//! Integration-test crate root for `permitlayer-proxy`.
//!
//! Story 8.8b (ripgrep-pattern collapse): every `tests/integration/<foo>.rs`
//! is a submodule of this single `[[test]] name = "integration"` binary.
//! See `tests/README.md` for the new-test-file convention.

// Inner attribute hoisted from individual submodules (Story 8.8b
// round-1 review): lint levels propagate down the module tree, so
// allowing here covers every submodule without per-file boilerplate.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod host_api_e2e;
mod mcp_conformance;
mod mcp_transport;
mod proxy_service;
mod refresh_integration;
mod ssrf_blocklist_e2e;
