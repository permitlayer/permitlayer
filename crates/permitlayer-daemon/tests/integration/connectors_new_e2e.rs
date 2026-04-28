//! End-to-end integration tests for `agentsso connectors new`
//! (Story 6.4 Task 4 — AC #3, #5, #6, #21, #22).
//!
//! These tests invoke the real `agentsso` binary as a subprocess
//! against an ephemeral `AGENTSSO_PATHS__HOME`. No daemon is
//! started — `connectors new` is fully offline.

use std::path::Path;
use std::process::{Command, Output};

use crate::common::agentsso_bin;

/// Run `agentsso connectors new <args>` with `AGENTSSO_PATHS__HOME`
/// pointed at `home`. Returns the raw `Output` for per-test
/// inspection of stdout, stderr, and exit code.
fn run_scaffolder(home: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(agentsso_bin());
    cmd.env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .env("AGENTSSO_TEST_FROZEN_DATE", "2026-04-18")
        .arg("connectors")
        .arg("new");
    for a in args {
        cmd.arg(a);
    }
    cmd.output().expect("subprocess runs")
}

#[test]
fn creates_three_files_with_correct_perms() {
    // AC #3: `connectors new my-notion` creates index.js + metadata.toml
    // + README.md under <home>/plugins/my-notion/ with 0644 perms.
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = run_scaffolder(tmp.path(), &["my-notion"]);
    assert!(
        out.status.success(),
        "exit code: {}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let plugin_dir = tmp.path().join("plugins").join("my-notion");
    assert!(plugin_dir.is_dir(), "plugin dir must exist: {plugin_dir:?}");

    for fname in ["index.js", "metadata.toml", "README.md"] {
        let fpath = plugin_dir.join(fname);
        assert!(fpath.is_file(), "{fname} must be created at {fpath:?}");
        let meta = std::fs::metadata(&fpath).unwrap();
        assert!(meta.len() > 0, "{fname} must be non-empty");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o644, "{fname} must be 0644, got {mode:o}");
        }
    }
    // Stdout mentions the three paths + the next-step command.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("index.js"));
    assert!(stdout.contains("metadata.toml"));
    assert!(stdout.contains("README.md"));
    assert!(stdout.contains("connectors test my-notion"));
}

#[test]
fn refuses_overwrite_without_force() {
    // AC #5: a pre-existing directory refuses without --force.
    let tmp = tempfile::tempdir().expect("tempdir");
    // Scaffold once.
    let out1 = run_scaffolder(tmp.path(), &["my-notion"]);
    assert!(out1.status.success());

    // Modify a file to simulate WIP.
    let marker_path = tmp.path().join("plugins").join("my-notion").join("index.js");
    std::fs::write(&marker_path, "// custom author content — do not destroy")
        .expect("write marker");

    // Scaffold again without --force.
    let out2 = run_scaffolder(tmp.path(), &["my-notion"]);
    assert!(!out2.status.success(), "second scaffold without --force must fail");
    let stderr = String::from_utf8_lossy(&out2.stderr);
    assert!(stderr.contains("connectors.new.exists"), "error block must name the code: {stderr}");

    // Marker is intact — nothing overwrote it.
    let contents = std::fs::read_to_string(&marker_path).unwrap();
    assert!(contents.contains("custom author content"));
}

#[test]
fn succeeds_with_force_after_prior_scaffold() {
    // AC #5: --force overwrites the existing directory.
    let tmp = tempfile::tempdir().expect("tempdir");
    let out1 = run_scaffolder(tmp.path(), &["my-notion"]);
    assert!(out1.status.success());

    let marker_path = tmp.path().join("plugins").join("my-notion").join("index.js");
    std::fs::write(&marker_path, "// STALE CONTENT").expect("write marker");

    let out2 = run_scaffolder(tmp.path(), &["my-notion", "--force"]);
    assert!(
        out2.status.success(),
        "second scaffold with --force must succeed: stderr={}",
        String::from_utf8_lossy(&out2.stderr)
    );

    let contents = std::fs::read_to_string(&marker_path).unwrap();
    // New template contains `export const metadata` — the stale
    // content has been replaced.
    assert!(contents.contains("export const metadata"));
    assert!(!contents.contains("STALE CONTENT"));
}

#[test]
fn rejects_invalid_name() {
    // AC #4: invalid names exit non-zero without touching the
    // filesystem.
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = run_scaffolder(tmp.path(), &["Bad-Name"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("connectors.new.invalid_name"), "stderr: {stderr}");
    // Directory must NOT exist — invalid names are rejected before
    // the filesystem is touched.
    assert!(!tmp.path().join("plugins").exists());
}

#[test]
fn rejects_invalid_scope() {
    // AC #6: invalid scope tokens exit non-zero without writing
    // any files.
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = run_scaffolder(tmp.path(), &["my-notion", "--scopes", "notion.readonly,Bad Scope"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("connectors.new.invalid_scope"), "stderr: {stderr}");
    // Directory must not have been created.
    assert!(!tmp.path().join("plugins").join("my-notion").exists());
}

#[test]
fn scopes_flag_substitutes_metadata() {
    // AC #6: `--scopes notion.readonly,notion.search,notion.write`
    // produces an index.js with the expected scopes array AND a
    // metadata.toml with the matching TOML.
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = run_scaffolder(
        tmp.path(),
        &["my-notion", "--scopes", "notion.readonly,notion.search,notion.write"],
    );
    assert!(
        out.status.success(),
        "exit: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let plugin_dir = tmp.path().join("plugins").join("my-notion");
    let index_js = std::fs::read_to_string(plugin_dir.join("index.js")).unwrap();
    assert!(
        index_js.contains("scopes: [\"notion.readonly\", \"notion.search\", \"notion.write\"]")
    );

    let metadata_toml = std::fs::read_to_string(plugin_dir.join("metadata.toml")).unwrap();
    assert!(
        metadata_toml
            .contains("scopes = [\"notion.readonly\", \"notion.search\", \"notion.write\"]")
    );
}

#[test]
fn scaffolded_plugin_passes_validate_plugin_source() {
    // AC #7 (end-to-end companion to the unit test of the same
    // name): after scaffolding, the written-to-disk index.js
    // validates through the real `validate_plugin_source` entry
    // point. Proves the disk path + the renderer produce identical
    // output.
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = run_scaffolder(tmp.path(), &["my-notion"]);
    assert!(out.status.success());

    let source =
        std::fs::read_to_string(tmp.path().join("plugins").join("my-notion").join("index.js"))
            .expect("index.js written");

    // Call the library surface directly from the test binary.
    let runtime =
        permitlayer_plugins::PluginRuntime::new_default().expect("plugin runtime must construct");
    let meta = permitlayer_plugins::validate_plugin_source(&runtime, "my-notion", &source)
        .expect("scaffolded plugin must validate");
    assert_eq!(meta.name, "my-notion");
    assert_eq!(meta.version, "0.1.0");
    assert_eq!(meta.api_version, ">=1.0");
    assert_eq!(meta.scopes, vec!["example.readonly".to_owned()]);
}

#[test]
fn readme_contains_scaffold_date() {
    // AC #21: README has a date-stamp, and AGENTSSO_TEST_FROZEN_DATE
    // (debug-only) pins it to a deterministic value for assertions.
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = run_scaffolder(tmp.path(), &["my-notion"]);
    assert!(out.status.success());

    let readme =
        std::fs::read_to_string(tmp.path().join("plugins").join("my-notion").join("README.md"))
            .unwrap();
    #[cfg(debug_assertions)]
    assert!(
        readme.contains("on 2026-04-18"),
        "debug build should honor AGENTSSO_TEST_FROZEN_DATE: {readme}"
    );
    // In release, the env var is cfg'd out; we still require a
    // YYYY-MM-DD form — any 10-char date is acceptable.
    let line = readme.lines().find(|l| l.contains("Scaffolded by")).expect("date line present");
    let tail = line.rsplit(" on ").next().unwrap().trim_end_matches('.');
    assert_eq!(tail.len(), 10, "date tail must be YYYY-MM-DD: {tail:?}");
}

#[test]
fn metadata_toml_mirrors_index_js_metadata() {
    // AC #22: metadata.toml carries matching name/version/scopes +
    // the informational comment, and parses as valid TOML.
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = run_scaffolder(tmp.path(), &["my-notion", "--scopes", "notion.read,notion.write"]);
    assert!(out.status.success());
    let toml_text =
        std::fs::read_to_string(tmp.path().join("plugins").join("my-notion").join("metadata.toml"))
            .unwrap();
    assert!(toml_text.contains("Informational only"));
    assert!(toml_text.contains("name = \"my-notion\""));
    assert!(toml_text.contains("version = \"0.1.0\""));
    assert!(toml_text.contains("scopes = [\"notion.read\", \"notion.write\"]"));

    let parsed: toml::Value =
        toml::from_str(&toml_text).expect("metadata.toml must parse as valid TOML");
    assert_eq!(parsed["name"].as_str(), Some("my-notion"));
}
