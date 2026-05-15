//! Story 7.34 review patch: integration tests for `agentsso policy validate`.
//!
//! `policy validate` is a client-side-only command — it does not need a
//! running daemon. Tests invoke the binary directly and assert on exit
//! codes and stderr content.

use std::process::{Command, Stdio};

use crate::common::agentsso_bin;

const VALID_POLICY: &str = r#"
[[policies]]
name = "test-policy"
scopes = ["scope.read"]
resources = ["*"]
approval-mode = "auto"
"#;

fn run_validate(path: &std::path::Path) -> (i32, String, String) {
    let mut cmd = Command::new(agentsso_bin());
    cmd.arg("policy").arg("validate").arg(path);
    #[cfg(windows)]
    cmd.envs(crate::common::forward_windows_required_env());
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = cmd.output().expect("failed to spawn agentsso policy validate");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn validate_exits_zero_for_valid_policy() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("valid.toml");
    std::fs::write(&path, VALID_POLICY).unwrap();
    let (code, stdout, stderr) = run_validate(&path);
    assert_eq!(code, 0, "valid policy should exit 0; stderr: {stderr}");
    assert!(stdout.contains('\u{2713}'), "stdout should contain checkmark: {stdout}");
}

#[test]
fn validate_exits_nonzero_for_malformed_toml() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("broken.toml");
    std::fs::write(&path, "not valid toml [[[").unwrap();
    let (code, _stdout, stderr) = run_validate(&path);
    assert_ne!(code, 0, "malformed TOML should exit non-zero");
    assert!(
        stderr.contains("validation_failed"),
        "stderr should report validation_failed: {stderr}"
    );
}

#[test]
fn validate_exits_nonzero_for_missing_file() {
    let path = std::path::PathBuf::from("/does/not/exist/policy.toml");
    let (code, _stdout, stderr) = run_validate(&path);
    assert_ne!(code, 0, "missing file should exit non-zero");
    assert!(stderr.contains("file_not_found"), "stderr should report file_not_found: {stderr}");
}

#[test]
fn validate_exits_nonzero_for_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let (code, _stdout, stderr) = run_validate(tmp.path());
    assert_ne!(code, 0, "directory should exit non-zero");
    assert!(
        stderr.contains("not_a_regular_file"),
        "stderr should report not_a_regular_file: {stderr}"
    );
}
