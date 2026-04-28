//! Integration-test crate root for `permitlayer-core`.
//!
//! Story 8.8b (ripgrep-pattern collapse): every `tests/integration/<foo>.rs`
//! is a submodule of this single `[[test]] name = "integration"` binary.
//! `kill9_recovery.rs` stays at `tests/kill9_recovery.rs` because it is
//! feature-gated on `test-seam` and cargo doesn't collapse feature-
//! gated tests into the same binary cleanly. See `tests/README.md`.

// Inner attribute hoisted from individual submodules (Story 8.8b
// round-1 review): lint levels propagate down the module tree, so
// allowing here covers every submodule without per-file boilerplate.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod audit_fs;
mod compile_fail;
mod policy_fixtures;
mod scrub_builtin_rules;
mod scrub_concurrency;
