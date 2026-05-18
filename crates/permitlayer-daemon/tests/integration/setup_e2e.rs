//! Integration tests for `agentsso setup` (UX-overhaul Story 2).
//!
//! The full privileged `setup` flow (stage versioned binary, atomic
//! symlink swap, `launchctl bootstrap`, self-verify over the control
//! UDS, rollback) requires root + `/Library` + launchd and is
//! exercised by the operator-run real-Angie wipe+reinstall shakedown
//! (the epic validation gate), NOT CI — consistent with how the
//! root-required `service install` flow has always been verified.
//!
//! These CI-runnable tests cover the non-privileged, observable
//! surface: the `setup` subcommand is RECLAIMED as a real clap
//! command (the Story-7.13 `setup`→removed→`connect` interceptor is
//! gone), and `service install` is now a loud redirect to `setup`
//! while `service uninstall`/`status` are untouched. The
//! security-critical helpers (`atomic_symlink_swap`, `gc_old_versions`,
//! `sha256_file`, `parse_whoami_version`, `brew_path_collision`) are
//! unit-tested in-crate.

use std::process::{Command, Stdio};

use crate::common::agentsso_bin;

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(agentsso_bin())
        .env_clear()
        .envs(crate::common::forward_windows_required_env())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("NO_COLOR", "1")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to spawn agentsso");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `agentsso service install` is now a loud redirect to `setup`
/// (exit 2, structured remediation naming `sudo agentsso setup`).
#[test]
fn service_install_redirects_to_setup() {
    let (code, _stdout, stderr) = run(&["service", "install"]);
    assert_eq!(code, 2, "service install should exit 2 (loud redirect); stderr:\n{stderr}");
    assert!(
        stderr.contains("service.install.redirected"),
        "expected the redirect error_block code; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("sudo agentsso setup"),
        "redirect must name the supported command; stderr:\n{stderr}"
    );
}

/// The redirect is scoped to `install` only — `service uninstall` and
/// `service status` are NOT intercepted (they still reach clap).
#[test]
fn service_uninstall_and_status_are_not_redirected() {
    // `service status` is non-root + non-destructive; it should run
    // and NOT print the redirect block (exit code varies by host
    // state, so assert only that the redirect did NOT fire).
    let (_c, _o, stderr) = run(&["service", "status"]);
    assert!(
        !stderr.contains("service.install.redirected"),
        "service status must not hit the install→setup redirect; stderr:\n{stderr}"
    );
    // `service uninstall` without root/--yes will refuse for its own
    // reasons, but again must NOT be the redirect block.
    let (_c2, _o2, stderr2) = run(&["service", "uninstall", "--non-interactive"]);
    assert!(
        !stderr2.contains("service.install.redirected"),
        "service uninstall must not hit the install→setup redirect; stderr:\n{stderr2}"
    );
}

/// `setup` is a REAL clap subcommand now (not the old removed
/// interceptor that exited 2 pointing at `connect`). `setup --help`
/// must render clap help and exit 0, and must NOT mention the old
/// `connect`/`setup.removed` remediation.
#[test]
fn setup_is_a_real_subcommand_with_help() {
    let (code, stdout, stderr) = run(&["setup", "--help"]);
    assert_eq!(code, 0, "`setup --help` should exit 0 (real clap command); stderr:\n{stderr}");
    let help = format!("{stdout}{stderr}");
    assert!(
        help.contains("setup") && help.to_lowercase().contains("usage"),
        "expected clap usage for `setup`; got:\n{help}"
    );
    assert!(
        !help.contains("setup.removed") && !help.contains("was removed"),
        "the legacy setup→removed interceptor must be gone; got:\n{help}"
    );
}

/// `setup` appears in the top-level `--help` command list (proves it
/// was added to the clap `Commands` enum, not just interceptor-faked).
#[test]
fn setup_listed_in_top_level_help() {
    let (code, stdout, _stderr) = run(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("setup"),
        "top-level --help must list the reclaimed `setup` command; got:\n{stdout}"
    );
}
