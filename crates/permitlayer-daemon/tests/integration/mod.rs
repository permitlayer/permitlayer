//! Integration-test crate root for `permitlayer-daemon`.
//!
//! Story 8.8b (ripgrep-pattern collapse): every `tests/integration/<foo>.rs`
//! is a submodule of this single `[[test]] name = "integration"` binary.
//! Pre-collapse, this crate produced 24 test binaries — one for each
//! file in `tests/*.rs` plus the lib unit target — and each fresh test
//! binary paid macOS `syspolicyd` queue-serialization on cold nextest
//! runs. Collapsing to one integration binary is the biggest lever in
//! the workspace.
//!
//! # Shared helpers
//!
//! `tests/common/mod.rs` sits alongside this directory (not inside)
//! because it existed before Story 8.8b and we want its import path
//! to remain `crate::common::…` under the new layout. Declaring it
//! via `#[path = "../common/mod.rs"]` from here avoids moving the
//! file and makes every submodule below reach it via
//! `use crate::common::…`.
//!
//! Pre-8.8b, 10 files copy-pasted `fn free_port()` and 12 copy-pasted
//! `fn agentsso_bin()`. The collapse pass deleted those duplicates;
//! all submodules now import the canonical versions from `common`.
//!
//! To add a new integration test: drop the `.rs` file into
//! `tests/integration/` and register it below with `mod <name>;`.
//! `autotests = false` in `Cargo.toml` disables the old one-binary-
//! per-file auto-discovery, so forgetting to register a file here
//! means it does not run — see `tests/README.md`.

// Inner attribute hoisted from individual submodules (Story 8.8b
// round-1 review): lint levels propagate down the module tree, so
// allowing here covers every submodule without per-file boilerplate.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../common/mod.rs"]
mod common;

mod agent_registry_e2e;
mod approval_prompt_e2e;
mod audit_drain_on_shutdown_e2e;
mod audit_export_e2e;
mod audit_follow;
mod audit_query_e2e;
mod config_theme;
mod connectors_list_e2e;
mod connectors_new_e2e;
mod connectors_test_e2e;
mod credentials_refresh_daemon_conflict;
mod credentials_status;
mod daemon_lifecycle;
mod envelope_v1_to_v2_e2e;
mod kill_resume_e2e;
mod kill_switch_e2e;
mod logs_audit_isolation_e2e;
mod logs_command_e2e;
mod master_key_bootstrap_e2e;
mod plugin_loader_e2e;
mod policy_compile_startup;
mod policy_enforcement_e2e;
mod policy_reload_e2e;
mod rotate_key_crash_resume_e2e;
mod rotate_key_e2e;
mod scrub_explain_warnings;
mod setup_daemon_conflict;
mod status_connections_e2e;
mod uninstall_e2e;
mod update_e2e;
