//! Epic 10 Story 10.2 — setup self-heal CLI-surface tests.
//!
//! ## Scope of this file vs. in-crate tests
//!
//! `permitlayer-daemon` is a **binary-only** crate (no lib target), so
//! this integration crate can exercise `setup` only as a subprocess.
//! A subprocess's stdin is naturally non-TTY, and real `setup` requires
//! root — so the *interactive root+TTY* legacy-seed heal path cannot be
//! driven from CI here. That path's load-bearing logic (canonical-parser
//! shadow detection + non-destructive archival + journal) is verified by
//! **in-crate `#[cfg(test)]` tests** in `cli/setup/mod.rs` against a real
//! tempdir filesystem; the *interactive prompt UX* is verified in the
//! epic-closeout operator pass (the same CI boundary the launchctl-
//! bootstrap path already lives behind — unverifiable locally without
//! codesigning).
//!
//! What IS covered here: the CLI-surface behaviors that need neither
//! root nor a TTY — flag wiring/conflict, `--help` discoverability, and
//! the non-root refusal / `AGENTSSO_NO_SUDO_ELEVATE` escape hatch.

#![cfg(target_os = "macos")]

use std::process::{Command, Stdio};

use crate::common::agentsso_bin;

/// Spawn `agentsso setup [args]` as a non-root subprocess with stdin
/// detached (non-TTY) and a hermetic home. Returns (exit, stdout, stderr).
fn run_setup(
    home: &std::path::Path,
    extra_env: &[(&str, &str)],
    args: &[&str],
) -> (i32, String, String) {
    let mut cmd = Command::new(agentsso_bin());
    cmd.env_clear()
        .envs(crate::common::forward_windows_required_env())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home.to_str().unwrap())
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .env("NO_COLOR", "1");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd
        .arg("setup")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to spawn agentsso setup");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn setup_non_root_with_no_sudo_elevate_refuses_requires_root() {
    // AGENTSSO_NO_SUDO_ELEVATE=1 blocks self-elevation, so a non-root
    // run refuses with the existing requires_root error (deterministic
    // — does not depend on whether the test runner is a TTY).
    let home = tempfile::tempdir().unwrap();
    let (code, _stdout, stderr) = run_setup(home.path(), &[("AGENTSSO_NO_SUDO_ELEVATE", "1")], &[]);
    // Skip if the CI runner happens to be root (then setup proceeds).
    if nix::unistd::Uid::effective().is_root() {
        eprintln!("skipping: test runner is root");
        return;
    }
    assert_ne!(code, 0, "non-root setup must refuse");
    assert!(
        stderr.contains("setup.requires_root")
            || stderr.contains("must") && stderr.contains("root"),
        "expected requires_root refusal, got: {stderr}"
    );
}

#[test]
fn setup_help_lists_the_three_new_flags() {
    let home = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_setup(home.path(), &[], &["--help"]);
    // clap prints help to stdout and exits 0.
    assert_eq!(code, 0, "setup --help should exit 0; stderr: {stderr}");
    let help = format!("{stdout}{stderr}");
    assert!(help.contains("--fresh-install"), "help must document --fresh-install");
    assert!(help.contains("--upgrade"), "help must document --upgrade");
    assert!(help.contains("--replace-binary"), "help must document --replace-binary");
}

#[test]
fn setup_fresh_install_and_upgrade_conflict_at_cli() {
    let home = tempfile::tempdir().unwrap();
    let (code, _stdout, stderr) = run_setup(home.path(), &[], &["--fresh-install", "--upgrade"]);
    assert_ne!(code, 0, "conflicting flags must fail before setup runs");
    assert!(
        stderr.contains("cannot be used with") || stderr.contains("conflict"),
        "expected a clap conflict error, got: {stderr}"
    );
}
