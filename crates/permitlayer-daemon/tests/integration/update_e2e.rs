//! End-to-end integration tests for `agentsso update` — the
//! three-way version-drift detector (UX-overhaul epic, Story 3,
//! issue #58).
//!
//! These tests spawn the real `agentsso update` binary as a
//! subprocess against a `mockito`-served GitHub Releases **list**
//! endpoint (`/releases?per_page=100`). The pre-overhaul command
//! downloaded + minisign-verified + atomically swapped the binary;
//! that flow is gone (it caused the silent-stale-daemon and
//! broken-prerelease-delivery failures #58 reports). `agentsso
//! update` is now read-only: it compares the CLI's own version, the
//! latest published release, and the running daemon's reported
//! version, then exits non-zero on any drift so scripts/`doctor`
//! notice.
//!
//! The `AGENTSSO_GITHUB_API_BASE_URL` env-var seam is
//! `cfg(debug_assertions)`-gated, so it works for `cargo test`-built
//! subprocess binaries but is compiled out of release builds. Mirror
//! of the `AGENTSSO_TEST_FROZEN_DATE` pattern in
//! `cli/connectors/new.rs`.

use std::process::{Command, Stdio};

use crate::common::agentsso_bin;

/// The version baked into the running test binary's `CARGO_PKG_VERSION`.
/// The drift report compares against this.
const CURRENT_WORKSPACE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// One release object in a GitHub `/releases` list response.
fn release_obj(tag: &str, draft: bool, prerelease: bool, body: &str) -> serde_json::Value {
    serde_json::json!({
        "tag_name": tag,
        "name": format!("Release {tag}"),
        "body": body,
        "published_at": "2026-05-18T12:00:00Z",
        "draft": draft,
        "prerelease": prerelease,
        "assets": []
    })
}

/// Serialize a `/releases` list body.
fn releases_list(objs: &[serde_json::Value]) -> String {
    serde_json::Value::Array(objs.to_vec()).to_string()
}

/// Spawn `agentsso update [args]` hermetically with the GitHub API
/// pointed at `base_url` (or unset). Returns (exit_code, stdout,
/// stderr).
fn run_update(
    home: &std::path::Path,
    base_url: Option<&str>,
    args: &[&str],
) -> (i32, String, String) {
    let mut cmd = Command::new(agentsso_bin());
    cmd.env_clear()
        .envs(crate::common::forward_windows_required_env())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home.to_str().unwrap())
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .env("NO_COLOR", "1")
        .arg("update")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(u) = base_url {
        cmd.env("AGENTSSO_GITHUB_API_BASE_URL", u);
    }
    let out = cmd.output().expect("failed to spawn agentsso update");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Issue #58 core regression: every `permitlayer` release is a
/// prerelease, so the old `/releases/latest` query 404'd and the
/// updater silently no-op'd. The list endpoint + semver selection
/// must pick the highest rc and report the CLI as behind (exit 4 —
/// actionable drift), NOT mis-rank rc.9 above rc.10 lexically.
#[tokio::test]
async fn drift_report_selects_highest_prerelease_and_flags_cli_behind() {
    // Use a base version (0.9.0) unambiguously higher than ANY
    // plausible CARGO_PKG_VERSION the test binary is built at, so the
    // "CLI behind latest" finding is genuinely exercised regardless of
    // the current workspace version. rc.9 vs rc.10 also guards the
    // lexical-misrank bug (semver: rc.10 > rc.9; string-sort inverts).
    let mut server = mockito::Server::new_async().await;
    let body = releases_list(&[
        release_obj("v0.9.0-rc.34", false, true, "older"),
        release_obj("v0.9.0-rc.9", false, true, "much older"),
        release_obj("v0.9.0-rc.36", false, true, "## What's new\n- fix #58"),
        release_obj("v0.9.0-rc.10", false, true, "old"),
    ]);
    let _mock = server
        .mock("GET", "/repos/permitlayer/permitlayer/releases")
        .match_query(mockito::Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create_async()
        .await;

    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    std::fs::create_dir_all(home.join("audit")).unwrap();

    let (code, stdout, stderr) = run_update(&home, Some(&server.url()), &[]);

    // 0.9.0-rc.36 is unambiguously ahead of the test binary's
    // CARGO_PKG_VERSION → "CLI behind latest" drift → exit 4.
    assert_eq!(
        code, 4,
        "expected exit 4 (drift detected); got {code}.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("0.9.0-rc.36"),
        "expected the highest prerelease (0.9.0-rc.36) to be selected;\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("is behind the latest release"),
        "expected the explicit CLI-behind finding;\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains(CURRENT_WORKSPACE_VERSION),
        "expected the CLI version {CURRENT_WORKSPACE_VERSION} in the report;\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("drift detected"),
        "expected a 'drift detected' section;\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("brew upgrade agentsso") && stdout.contains("sudo agentsso setup"),
        "expected the remediation to name the supported upgrade path;\nstdout:\n{stdout}"
    );
}

/// A draft with a higher version must NOT be selected (unpublished —
/// not deliverable). Selection falls to the highest non-draft.
#[tokio::test]
async fn drift_report_excludes_draft_releases() {
    let mut server = mockito::Server::new_async().await;
    let body = releases_list(&[
        release_obj("v9.9.9", true, false, "draft, not deliverable"),
        release_obj("v0.3.0-rc.36", false, true, "the real one"),
    ]);
    let _mock = server
        .mock("GET", "/repos/permitlayer/permitlayer/releases")
        .match_query(mockito::Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create_async()
        .await;

    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    std::fs::create_dir_all(home.join("audit")).unwrap();

    let (_code, stdout, _stderr) = run_update(&home, Some(&server.url()), &[]);
    assert!(
        stdout.contains("0.3.0-rc.36") && !stdout.contains("9.9.9"),
        "draft v9.9.9 must not be selected; rc.36 must be;\nstdout:\n{stdout}"
    );
}

/// `agentsso update` reports the latest-release query failure as a
/// finding and exits non-zero (host not provably current) — it does
/// NOT crash or silently succeed.
#[tokio::test]
async fn drift_report_handles_release_query_failure() {
    // Nothing listening on this port.
    let bogus_url = "http://127.0.0.1:1";

    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    std::fs::create_dir_all(home.join("audit")).unwrap();

    let (code, stdout, stderr) = run_update(&home, Some(bogus_url), &[]);

    assert_eq!(
        code, 4,
        "expected exit 4 when the release check fails; got {code}.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("unknown (GitHub query failed)")
            || stdout.contains("could not determine the latest published release"),
        "expected the report to surface the failed release query;\nstdout:\n{stdout}"
    );
}

/// `agentsso update --apply` is a hard error now: it redirects to the
/// supported upgrade path (exit 3) and changes nothing.
#[tokio::test]
async fn apply_is_removed_and_redirects() {
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    std::fs::create_dir_all(home.join("audit")).unwrap();

    // No mock server needed — the redirect fires before any network.
    let (code, stdout, stderr) = run_update(&home, None, &["--apply"]);

    assert_eq!(
        code, 3,
        "expected exit 3 for the --apply redirect; got {code}.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("update_apply_removed"),
        "expected error_block code 'update_apply_removed';\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("brew upgrade agentsso") && stderr.contains("sudo agentsso setup"),
        "expected the redirect to name the supported upgrade path;\nstderr:\n{stderr}"
    );
}

/// The drift report records an audit event with the three versions
/// and the drift verdict.
#[tokio::test]
async fn drift_report_emits_audit_event() {
    let mut server = mockito::Server::new_async().await;
    let body = releases_list(&[release_obj("v0.3.0-rc.36", false, true, "notes")]);
    let _mock = server
        .mock("GET", "/repos/permitlayer/permitlayer/releases")
        .match_query(mockito::Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create_async()
        .await;

    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    std::fs::create_dir_all(home.join("audit")).unwrap();

    let (_code, _stdout, _stderr) = run_update(&home, Some(&server.url()), &[]);

    // The audit store writes under <home>/audit. Walk it for the
    // drift-report event type.
    let audit_dir = home.join("audit");
    let mut found = false;
    if let Ok(entries) = std::fs::read_dir(&audit_dir) {
        for e in entries.flatten() {
            if let Ok(contents) = std::fs::read_to_string(e.path())
                && contents.contains("update-drift-report")
            {
                found = true;
                break;
            }
        }
    }
    assert!(found, "expected an 'update-drift-report' audit event under {audit_dir:?}");
}
