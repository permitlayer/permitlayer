//! End-to-end integration test for Story 6.5's
//! `cargo xtask validate-plugin-api` subcommand.
//!
//! Boots the real `xtask` binary as a subprocess via `cargo run`,
//! runs it against the real committed `host-api.lock`, and asserts
//! the expected stdout + exit code. This is the cheapest full-circle
//! test — if the `main.rs` dispatch, the subcommand registration,
//! the surface extraction, or the committed lockfile break, this
//! test fails.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .expect("xtask manifest dir must have a parent (workspace root)")
        .to_path_buf()
}

/// AC #28: invoke `cargo xtask validate-plugin-api` end-to-end and
/// assert it exits 0 with the "up to date" message.
#[test]
fn validate_plugin_api_exits_zero_on_clean_tree() {
    let root = workspace_root();
    let out = Command::new("cargo")
        .arg("xtask")
        .arg("validate-plugin-api")
        .current_dir(&root)
        .output()
        .expect("failed to launch `cargo xtask validate-plugin-api`");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "exit code must be 0 on clean tree. stdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert!(
        stdout.contains("host-api.lock is up to date.")
            || stdout.contains("Additive or breaking change detected"),
        "expected 'up to date' or rc-stage note in stdout; got:\n{stdout}",
    );
}

/// AC #2: `cargo xtask --help` lists `validate-plugin-api` as a
/// subcommand with the documented help string.
#[test]
fn validate_plugin_api_appears_in_help() {
    let root = workspace_root();
    let out = Command::new("cargo")
        .arg("xtask")
        .arg("--help")
        .current_dir(&root)
        .output()
        .expect("failed to launch `cargo xtask --help`");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("validate-plugin-api"),
        "expected `validate-plugin-api` in help; got:\n{stdout}",
    );
}
