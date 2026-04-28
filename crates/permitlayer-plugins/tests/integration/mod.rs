//! Integration-test crate root for `permitlayer-plugins`.
//!
//! Story 8.8b (ripgrep-pattern collapse): every `tests/integration/<foo>.rs`
//! is a submodule of this single `[[test]] name = "integration"` binary.
//! Collapsing 6 per-file binaries into 1 cuts integration-test compile
//! time and reduces macOS `syspolicyd` queue depth during cold nextest
//! runs.
//!
//! To add a new integration test: drop the `.rs` file into
//! `tests/integration/` and register it below with `mod <name>;`.
//! `autotests = false` in `Cargo.toml` disables the old "one file,
//! one binary" auto-discovery, so forgetting to register a file here
//! means it does not run — see `tests/README.md`.

// Inner attribute hoisted from individual submodules (Story 8.8b
// round-1 review): lint levels propagate down the module tree, so
// allowing here covers every submodule without per-file boilerplate.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod deny_toml_allowlist_extended;
mod host_api_surface;
mod loader;
mod sandbox_escape;
mod scope_allowlist;
mod stub_services;
