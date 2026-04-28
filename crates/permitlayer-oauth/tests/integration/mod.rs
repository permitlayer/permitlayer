//! Integration-test crate root for `permitlayer-oauth`.
//!
//! Story 8.8b (ripgrep-pattern collapse): every
//! `tests/integration/<foo>.rs` is a submodule of this single
//! `[[test]] name = "integration"` binary. `autotests = false` in
//! `Cargo.toml` disables the old one-binary-per-file auto-discovery.
//!
//! To add a new integration test: drop the `.rs` file into
//! `tests/integration/` and register it below with `mod <name>;`.
//! Forgetting to register a file means it compiles but its tests
//! never run — see `tests/README.md` for the full convention.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod google_consent;
mod oauth_flow;
mod setup_wizard;
