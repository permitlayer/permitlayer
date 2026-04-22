//! End-to-end integration tests for `agentsso connectors test`
//! (Story 6.4 Task 5 — AC #9-#16, #23, #24).
//!
//! These tests invoke the real `agentsso` binary as a subprocess
//! against tempdir-hosted plugin directories. No daemon is started
//! — `connectors test` is fully offline.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use crate::common::agentsso_bin;

/// Scaffold a plugin named `name` under `<tmp>/plugins/<name>/` by
/// invoking the real `agentsso connectors new` subprocess.
fn scaffold(home: &Path, name: &str) {
    let out = Command::new(agentsso_bin())
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .arg("connectors")
        .arg("new")
        .arg(name)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "scaffold failed: exit {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Write a custom `index.js` to `<home>/plugins/<name>/index.js`,
/// creating the directory tree.
fn write_plugin(home: &Path, name: &str, source: &str) -> PathBuf {
    let dir = home.join("plugins").join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("index.js");
    std::fs::write(&path, source).unwrap();
    dir
}

/// Run `agentsso connectors test <name_or_path>` and return the
/// raw output. `extra_args` lets callers pass `--json`.
fn run_tester(home: Option<&Path>, name_or_path: &str, extra_args: &[&str]) -> Output {
    let mut cmd = Command::new(agentsso_bin());
    if let Some(h) = home {
        cmd.env("AGENTSSO_PATHS__HOME", h.to_str().unwrap());
    }
    cmd.arg("connectors").arg("test").arg(name_or_path);
    for a in extra_args {
        cmd.arg(a);
    }
    cmd.output().expect("subprocess runs")
}

// -----------------------------------------------------------------
// AC #9 — bare name resolution
// -----------------------------------------------------------------

#[test]
fn bare_name_resolves_to_home_plugins() {
    let tmp = tempfile::tempdir().unwrap();
    scaffold(tmp.path(), "my-notion");
    let out = run_tester(Some(tmp.path()), "my-notion", &[]);
    assert!(
        out.status.success(),
        "exit: {}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Per-check human output includes the detail (not the literal
    // word "ok"); presence of the check name is the stable signal.
    assert!(stdout.contains("source:"));
    assert!(stdout.contains("metadata:"));
    assert!(stdout.contains("sandbox:"));
    assert!(stdout.contains("name=my-notion"));
}

#[test]
fn bare_name_missing_plugin_errors() {
    let tmp = tempfile::tempdir().unwrap();
    // No plugin scaffolded.
    let out = run_tester(Some(tmp.path()), "nonexistent", &[]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("connectors.test.plugin_not_found"), "stderr: {stderr}");
}

// -----------------------------------------------------------------
// AC #10 — path-style resolution
// -----------------------------------------------------------------

#[test]
fn absolute_path_resolves() {
    let tmp = tempfile::tempdir().unwrap();
    scaffold(tmp.path(), "my-wip");
    let plugin_dir = tmp.path().join("plugins").join("my-wip");
    // Absolute path; no AGENTSSO_PATHS__HOME env var needed.
    let out = run_tester(None, plugin_dir.to_str().unwrap(), &[]);
    assert!(
        out.status.success(),
        "exit: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn relative_path_resolves() {
    let tmp = tempfile::tempdir().unwrap();
    scaffold(tmp.path(), "my-wip");
    let plugin_dir = tmp.path().join("plugins").join("my-wip");
    // Pass `./<something>` form — use a path relative to CWD.
    let cwd = tmp.path();
    let rel = Path::new("plugins").join("my-wip");
    let mut cmd = Command::new(agentsso_bin());
    cmd.current_dir(cwd).arg("connectors").arg("test").arg(format!("./{}", rel.display()));
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "relative path test: exit {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    // plugin_dir ensures the scaffold path actually exists at the
    // absolute-path equivalent — sanity check.
    assert!(plugin_dir.is_dir());
}

// -----------------------------------------------------------------
// AC #11 — source check failures
// -----------------------------------------------------------------

#[test]
fn source_check_missing_file() {
    let tmp = tempfile::tempdir().unwrap();
    // Create dir but no index.js.
    let dir = tmp.path().join("broken-plugin");
    std::fs::create_dir_all(&dir).unwrap();
    let out = run_tester(None, dir.to_str().unwrap(), &[]);
    assert!(!out.status.success(), "must fail when index.js missing");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("source:"), "expected source check line: {stdout}");
}

#[test]
fn source_check_exceeds_cap() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("oversize");
    std::fs::create_dir_all(&dir).unwrap();
    // 1.5 MiB JS file — exceeds the 1 MiB cap.
    let big = "x".repeat(1_500_000);
    std::fs::write(dir.join("index.js"), big).unwrap();
    let out = run_tester(None, dir.to_str().unwrap(), &[]);
    assert!(!out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("1 MiB"), "expected cap mention in source check: {stdout}");
}

// -----------------------------------------------------------------
// AC #12 — metadata check failures
// -----------------------------------------------------------------

#[test]
fn metadata_check_invalid_name() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = write_plugin(
        tmp.path(),
        "badname",
        r#"export const metadata = {
    name: "Bad-Name",
    version: "0.1.0",
    apiVersion: ">=1.0",
    scopes: ["example.readonly"],
};
"#,
    );
    let out = run_tester(None, dir.to_str().unwrap(), &[]);
    assert!(!out.status.success(), "invalid name must fail");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("metadata:") && (stdout.contains("unsafe") || stdout.contains("charset")),
        "stdout should mention metadata charset violation: {stdout}"
    );
}

#[test]
fn metadata_check_commonjs_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = write_plugin(
        tmp.path(),
        "cjs-plugin",
        "module.exports = { metadata: { name: \"cjs\", version: \"0.1.0\", apiVersion: \">=1.0\", scopes: [\"example.readonly\"] } };\n",
    );
    let out = run_tester(None, dir.to_str().unwrap(), &[]);
    assert!(!out.status.success(), "CommonJS must fail");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // LoadFailureReason::NotEsm Debug form contains "NotEsm"
    assert!(
        stdout.contains("metadata:") && (stdout.contains("NotEsm") || stdout.contains("export")),
        "stdout should mention ESM rejection: {stdout}"
    );
}

// -----------------------------------------------------------------
// AC #13 — sandbox conformance
// -----------------------------------------------------------------

#[test]
fn sandbox_check_scaffold_passes() {
    // AC #13: the freshly-scaffolded plugin passes the sandbox
    // probe.
    let tmp = tempfile::tempdir().unwrap();
    scaffold(tmp.path(), "clean-plugin");
    let out = run_tester(Some(tmp.path()), "clean-plugin", &[]);
    assert!(
        out.status.success(),
        "clean scaffold must pass: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("sandbox: ok"), "sandbox must pass on scaffold: {stdout}");
}

// -----------------------------------------------------------------
// AC #14 — scope allowlist (non-blocking warning)
// -----------------------------------------------------------------

#[test]
fn scope_check_unreviewed_warns_without_failing() {
    let tmp = tempfile::tempdir().unwrap();
    // Scaffold with custom scopes not in ALLOWED_SCOPES.
    let out_new = Command::new(agentsso_bin())
        .env("AGENTSSO_PATHS__HOME", tmp.path().to_str().unwrap())
        .arg("connectors")
        .arg("new")
        .arg("notion-plugin")
        .arg("--scopes")
        .arg("notion.read")
        .output()
        .unwrap();
    assert!(out_new.status.success());

    let out = run_tester(Some(tmp.path()), "notion-plugin", &[]);
    // Exit 0 — warnings are non-blocking per epics.md:1755.
    assert!(
        out.status.success(),
        "scope warning must NOT fail exit: exit {}\nstdout {}\nstderr {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("scopes:"));
    assert!(stdout.contains("notion.read"));
    assert!(stdout.contains("marketplace"), "warning should mention marketplace review: {stdout}");
    assert!(stdout.contains("passed with"), "summary should say passed-with-warnings: {stdout}");
}

#[test]
fn scope_check_in_allowlist_passes_cleanly() {
    let tmp = tempfile::tempdir().unwrap();
    // Scaffold with gmail scopes (all in allowlist).
    let out_new = Command::new(agentsso_bin())
        .env("AGENTSSO_PATHS__HOME", tmp.path().to_str().unwrap())
        .arg("connectors")
        .arg("new")
        .arg("my-gmail")
        .arg("--scopes")
        .arg("gmail.readonly,gmail.search")
        .output()
        .unwrap();
    assert!(out_new.status.success());

    let out = run_tester(Some(tmp.path()), "my-gmail", &[]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("scopes: ok") || stdout.contains("scopes in allowlist"),
        "scopes check should pass: {stdout}"
    );
    assert!(!stdout.contains("passed with"), "no warnings expected: {stdout}");
}

// -----------------------------------------------------------------
// AC #15 — tool invocation
// -----------------------------------------------------------------

#[test]
fn no_tools_export_is_ok() {
    // Missing `tools` export is handled as zero-tools: the check
    // emits a non-blocking warn ("0 tools exported"), exit code 0.
    let tmp = tempfile::tempdir().unwrap();
    let dir = write_plugin(
        tmp.path(),
        "no-tools",
        r#"export const metadata = {
    name: "no-tools",
    version: "0.1.0",
    apiVersion: ">=1.0",
    scopes: ["example.readonly"],
};
"#,
    );
    let out = run_tester(None, dir.to_str().unwrap(), &[]);
    assert!(out.status.success(), "zero-tools plugin is non-blocking warn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("0 tools"), "aggregate should mention 0 tools: {stdout}");
}

// -----------------------------------------------------------------
// AC #16 — JSON mode
// -----------------------------------------------------------------

#[test]
fn json_mode_is_valid_json_with_locked_schema() {
    let tmp = tempfile::tempdir().unwrap();
    scaffold(tmp.path(), "json-target");
    let out = run_tester(Some(tmp.path()), "json-target", &["--json"]);
    assert!(
        out.status.success(),
        "json mode should exit 0: stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Must parse as JSON.
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON");

    // Top-level keys.
    for key in ["connector", "plugin_dir", "status", "checks", "warnings_count", "failures_count"] {
        assert!(parsed.get(key).is_some(), "missing key `{key}` in JSON: {stdout}");
    }

    // `status` is one of three enum strings.
    let status_str = parsed["status"].as_str().unwrap();
    assert!(
        ["pass", "pass-with-warnings", "fail"].contains(&status_str),
        "status must be one of the locked enum strings: {status_str}"
    );

    // Each check has `name`, `outcome`, `detail` keys.
    let checks = parsed["checks"].as_array().expect("checks must be array");
    assert!(!checks.is_empty());
    for check in checks {
        assert!(check.get("name").is_some());
        assert!(check.get("outcome").is_some());
        assert!(check.get("detail").is_some());
        let outcome = check["outcome"].as_str().unwrap();
        assert!(["ok", "warn", "error"].contains(&outcome));
    }

    // No ANSI escapes in JSON mode.
    assert!(!stdout.contains("\x1b["), "JSON mode must not emit ANSI escapes");
}

#[test]
fn json_mode_includes_warning_for_unreviewed_scope() {
    let tmp = tempfile::tempdir().unwrap();
    let _ = Command::new(agentsso_bin())
        .env("AGENTSSO_PATHS__HOME", tmp.path().to_str().unwrap())
        .arg("connectors")
        .arg("new")
        .arg("notion-plugin")
        .arg("--scopes")
        .arg("notion.read")
        .output()
        .unwrap();
    let out = run_tester(Some(tmp.path()), "notion-plugin", &["--json"]);
    assert!(out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).unwrap();
    assert_eq!(parsed["status"].as_str(), Some("pass-with-warnings"));
    assert!(parsed["warnings_count"].as_u64().unwrap() >= 1);
}

// -----------------------------------------------------------------
// AC #23 — design-system glyphs
// -----------------------------------------------------------------

#[test]
fn output_uses_design_system_glyphs() {
    let tmp = tempfile::tempdir().unwrap();
    scaffold(tmp.path(), "glyph-target");
    // NO_COLOR=1 + --color=never (not a clap flag here; we rely
    // on NO_COLOR env)
    let out = Command::new(agentsso_bin())
        .env("AGENTSSO_PATHS__HOME", tmp.path().to_str().unwrap())
        .env("NO_COLOR", "1")
        .arg("connectors")
        .arg("test")
        .arg("glyph-target")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Design-system Ok glyph is U+25CF (●).
    assert!(stdout.contains('\u{25CF}'), "expected Ok glyph `●`: {stdout}");
    // Summary glyph for pass: ✔ (U+2714) or ✕ (U+2715).
    let summary_has_check_or_x = stdout.contains('\u{2714}') || stdout.contains('\u{2715}');
    assert!(summary_has_check_or_x, "summary glyph must be ✔ or ✕: {stdout}");
}

// -----------------------------------------------------------------
// AC #24 — exit codes
// -----------------------------------------------------------------

#[test]
fn exit_0_for_pass() {
    let tmp = tempfile::tempdir().unwrap();
    scaffold(tmp.path(), "happy-path");
    let out = run_tester(Some(tmp.path()), "happy-path", &[]);
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn exit_0_for_pass_with_warnings() {
    let tmp = tempfile::tempdir().unwrap();
    let _ = Command::new(agentsso_bin())
        .env("AGENTSSO_PATHS__HOME", tmp.path().to_str().unwrap())
        .arg("connectors")
        .arg("new")
        .arg("warn-plugin")
        .arg("--scopes")
        .arg("notion.read")
        .output()
        .unwrap();
    let out = run_tester(Some(tmp.path()), "warn-plugin", &[]);
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn exit_1_for_blocking_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = write_plugin(
        tmp.path(),
        "fails",
        r#"export const metadata = {
    name: "Bad-Name",
    version: "0.1.0",
    apiVersion: ">=1.0",
    scopes: ["example.readonly"],
};
"#,
    );
    let out = run_tester(None, dir.to_str().unwrap(), &[]);
    assert_eq!(out.status.code(), Some(1));
}

// -----------------------------------------------------------------
// Review-round additions: AC-named regression locks that the initial
// implementation wired but did not pin with tests.
// -----------------------------------------------------------------

// AC #10 — dotdot path resolution as a CLI subprocess (complements
// the unit test of `resolve_plugin_dir`).
#[test]
fn dotdot_path_resolves() {
    let tmp = tempfile::tempdir().unwrap();
    // Lay out: <tmp>/outer/inner/, plugin at <tmp>/sibling/
    let outer = tmp.path().join("outer").join("inner");
    std::fs::create_dir_all(&outer).unwrap();
    let sibling_plugin = tmp.path().join("sibling");
    std::fs::create_dir_all(&sibling_plugin).unwrap();
    std::fs::write(
        sibling_plugin.join("index.js"),
        r#"export const metadata = {
    name: "sibling",
    version: "0.1.0",
    apiVersion: ">=1.0",
    scopes: ["example.readonly"],
};
export const tools = {};
"#,
    )
    .unwrap();
    // Invoke with CWD = <tmp>/outer/inner, path = ../../sibling
    let out = Command::new(agentsso_bin())
        .current_dir(&outer)
        .arg("connectors")
        .arg("test")
        .arg("../../sibling")
        .output()
        .unwrap();
    assert!(
        out.status.success() || out.status.code() == Some(0),
        "dotdot resolution failed: exit {:?}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("source: ok"),
        "expected source check to pass via dotdot path:\n{stdout}"
    );
}

// AC #11 — source check reports permission-denied detail on an
// unreadable `index.js`.
#[cfg(unix)]
#[test]
fn source_check_permission_denied() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let dir = write_plugin(tmp.path(), "denied", "export const metadata = {};");
    let index = dir.join("index.js");
    let mut perms = std::fs::metadata(&index).unwrap().permissions();
    perms.set_mode(0o000);
    std::fs::set_permissions(&index, perms).unwrap();
    // Restore perms on drop so tempdir can clean up.
    struct Restore(PathBuf);
    impl Drop for Restore {
        fn drop(&mut self) {
            if let Ok(md) = std::fs::metadata(&self.0) {
                let mut p = md.permissions();
                p.set_mode(0o644);
                let _ = std::fs::set_permissions(&self.0, p);
            }
        }
    }
    let _guard = Restore(index.clone());

    // Skip the assertion if running as root — mode 000 doesn't
    // constrain root, so the source-read would succeed.
    if std::env::var("USER").as_deref() == Ok("root") {
        eprintln!("skipping permission_denied assertion: running as root");
        return;
    }
    let out = run_tester(Some(tmp.path()), "denied", &[]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.to_lowercase().contains("permission denied")
            || combined.to_lowercase().contains("denied"),
        "expected permission-denied detail:\n{combined}"
    );
}

// AC #12 — metadata check surfaces semver parse error detail.
#[test]
fn metadata_check_bad_version() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = write_plugin(
        tmp.path(),
        "badver",
        r#"export const metadata = {
    name: "badver",
    version: "not-semver",
    apiVersion: ">=1.0",
    scopes: ["example.readonly"],
};
export const tools = {};
"#,
    );
    let out = run_tester(None, dir.to_str().unwrap(), &[]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("metadata:") && stdout.to_lowercase().contains("semver"),
        "expected metadata check to report semver parse failure:\n{stdout}"
    );
}

// AC #13 — sandbox probe detects globalThis shadowing.
#[test]
fn sandbox_check_detects_globalthis_shadowing() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = write_plugin(
        tmp.path(),
        "shadow",
        r#"globalThis.process = { rooted: true };
export const metadata = {
    name: "shadow",
    version: "0.1.0",
    apiVersion: ">=1.0",
    scopes: ["example.readonly"],
};
export const tools = {};
"#,
    );
    let out = run_tester(None, dir.to_str().unwrap(), &[]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("sandbox:"), "expected sandbox check row in output:\n{stdout}");
    assert!(
        stdout.contains("process") || stdout.to_lowercase().contains("forbidden"),
        "expected sandbox check to flag a forbidden API:\n{stdout}"
    );
}

// AC #15 — infinite-loop tool is cut off by the 5-second deadline.
#[test]
fn tool_invocation_infinite_loop_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = write_plugin(
        tmp.path(),
        "loopy",
        r#"export const metadata = {
    name: "loopy",
    version: "0.1.0",
    apiVersion: ">=1.0",
    scopes: ["example.readonly"],
};
export const tools = {
    async spin(input) {
        while (true) {}
    },
};
"#,
    );
    let out = run_tester(None, dir.to_str().unwrap(), &[]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("tools.spin:") || stdout.contains("deadline"),
        "expected per-tool deadline error in output:\n{stdout}"
    );
}

// AC #15 — tool returning a non-JSON-serializable value errors.
// `undefined` is valid in JS but is not JSON-serializable; we expect
// the check to report a failure rather than silently pass.
#[test]
fn tool_invocation_returns_undefined_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = write_plugin(
        tmp.path(),
        "undef",
        r#"export const metadata = {
    name: "undef",
    version: "0.1.0",
    apiVersion: ">=1.0",
    scopes: ["example.readonly"],
};
export const tools = {
    async dud(input) {
        return undefined;
    },
};
"#,
    );
    let out = run_tester(None, dir.to_str().unwrap(), &[]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("tools.dud:"),
        "expected per-tool row `tools.dud:` in output:\n{stdout}"
    );
}

// Zero-tools plugin passes with a non-blocking warning (decision-needed #3).
#[test]
fn zero_tools_emits_non_blocking_warning() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = write_plugin(
        tmp.path(),
        "notools",
        r#"export const metadata = {
    name: "notools",
    version: "0.1.0",
    apiVersion: ">=1.0",
    scopes: ["example.readonly"],
};
export const tools = {};
"#,
    );
    let out = run_tester(None, dir.to_str().unwrap(), &[]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("tools:") && stdout.contains("0 tools exported"),
        "expected zero-tools warning in output:\n{stdout}"
    );
}

// Decision #2 — `--scopes ""` is rejected loudly rather than silently
// replaced with the default scope.
#[test]
fn connectors_new_rejects_empty_scopes() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(agentsso_bin())
        .env("AGENTSSO_PATHS__HOME", tmp.path().to_str().unwrap())
        .arg("connectors")
        .arg("new")
        .arg("rejector")
        .arg("--scopes")
        .arg("")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("connectors.new.empty_scopes"),
        "expected empty_scopes error_block:\n{stderr}"
    );
    // No plugin dir was created.
    assert!(
        !tmp.path().join("plugins").join("rejector").exists(),
        "rejected scaffold must not create a plugin dir"
    );
}
