//! End-to-end integration tests for `agentsso doctor` (UX-overhaul
//! Story 4).
//!
//! `doctor` is a diagnose-and-(safely-)repair command. The fully
//! privileged repairs (`launchctl bootout`/`bootstrap`/`kickstart`,
//! re-pointing `/Library/PrivilegedHelperTools/agentsso`) require
//! root + `/Library` + launchd and are exercised by the operator-run
//! real-Angie wipe+reinstall shakedown — NOT CI — exactly as the
//! `setup`/`service install` privileged flows have always been
//! verified (see `setup_e2e.rs`).
//!
//! These CI-runnable tests cover the non-privileged, observable
//! surface against a temp `AGENTSSO_PATHS__HOME` (the harness sets
//! that env for the child, so test code never mutates process env —
//! this crate is `#![forbid(unsafe_code)]`):
//!
//! - `doctor` is a real clap subcommand (top-level help + `--help`).
//! - `--json` parses, has the documented schema, and the summary
//!   counts equal the `checks` array tally.
//! - non-`--fix` runs NEVER write a `doctor.fix` audit event
//!   (no-mutation invariant).
//! - the binary-integrity gate (Decision A) reports `passed:false`
//!   with a reason when there is no privileged install, and a
//!   `--fix` run under a failed gate refuses every mutation
//!   (including the otherwise-safe managed-policy rewrite) and
//!   leaves the on-disk managed file untouched.
//! - a `doctor.run` summary audit event is always emitted.
//! - exit code is non-zero whenever any check FAILs.
//!
//! The security-critical pure logic (`may_apply_fix` full truth
//! table, the per-check `FixClass` invariants, the decision helpers)
//! is unit-tested in-crate (`cli/doctor/mod.rs` `#[cfg(test)]`).

use std::process::{Command, Stdio};

use crate::common::agentsso_bin;

/// Spawn `agentsso doctor [args]` hermetically against `home`.
fn run_doctor(home: &std::path::Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(agentsso_bin())
        .env_clear()
        .envs(crate::common::forward_windows_required_env())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home.to_str().unwrap())
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .env("NO_COLOR", "1")
        .arg("doctor")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to spawn agentsso doctor");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Walk `<home>/audit/*` and return the concatenated contents.
fn read_audit(home: &std::path::Path) -> String {
    let dir = home.join("audit");
    let mut all = String::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            if let Ok(c) = std::fs::read_to_string(e.path()) {
                all.push_str(&c);
                all.push('\n');
            }
        }
    }
    all
}

/// `doctor` is a REAL clap subcommand (top-level help lists it; its
/// own `--help` renders clap usage and exits 0).
#[test]
fn doctor_is_a_real_subcommand() {
    let out = Command::new(agentsso_bin())
        .env("NO_COLOR", "1")
        .args(["--help"])
        .output()
        .expect("spawn --help");
    let top = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(top.contains("doctor"), "top-level --help must list `doctor`; got:\n{top}");

    let out2 = Command::new(agentsso_bin())
        .env("NO_COLOR", "1")
        .args(["doctor", "--help"])
        .output()
        .expect("spawn doctor --help");
    assert_eq!(out2.status.code(), Some(0), "`doctor --help` should exit 0");
    let help = format!(
        "{}{}",
        String::from_utf8_lossy(&out2.stdout),
        String::from_utf8_lossy(&out2.stderr)
    );
    assert!(help.to_lowercase().contains("usage"), "expected clap usage; got:\n{help}");
    // The three documented flags must be present.
    assert!(help.contains("--fix"), "expected --fix flag; got:\n{help}");
    assert!(help.contains("--json"), "expected --json flag; got:\n{help}");
    assert!(help.contains("--restart-ok"), "expected --restart-ok flag; got:\n{help}");
}

/// `--json` parses, carries the documented schema, and the summary
/// counts equal the `checks` array tally. There are exactly 8 checks.
#[test]
fn doctor_json_shape_and_summary_consistency() {
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    std::fs::create_dir_all(home.join("audit")).unwrap();

    let (_code, stdout, stderr) = run_doctor(&home, &["--json"]);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json must emit valid JSON: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });

    assert_eq!(v["schema"], 1, "schema must be 1");
    assert!(v["cli_version"].is_string(), "cli_version must be a string");
    assert!(v.get("daemon_version").is_some(), "daemon_version key present (may be null)");
    assert_eq!(v["fix_mode"], false, "non-fix run → fix_mode:false");
    assert_eq!(v["restart_ok"], false);
    let gate = &v["fix_integrity_gate"];
    assert!(gate["passed"].is_boolean(), "fix_integrity_gate.passed must be bool");
    assert!(
        gate["reason"].is_string() && !gate["reason"].as_str().unwrap().is_empty(),
        "fix_integrity_gate.reason must be a non-empty string (JSON contract)"
    );

    let checks = v["checks"].as_array().expect("checks array");
    assert_eq!(checks.len(), 8, "there are exactly 8 checks");

    // Every documented check id is present exactly once.
    let ids: Vec<&str> = checks.iter().map(|c| c["id"].as_str().unwrap()).collect();
    // Story 10.3: daemon_binary_missing was collapsed into
    // symlink_integrity; legacy_seed_snapshot_present took its slot.
    for expected in [
        "version_drift",
        "stale_launchd",
        "symlink_integrity",
        "managed_policy_staleness",
        "daemon_not_running",
        "no_tty_prompt_trap",
        "operator_layer_compile",
        "legacy_seed_snapshot_present",
    ] {
        assert_eq!(
            ids.iter().filter(|i| **i == expected).count(),
            1,
            "check id {expected} must appear exactly once; got {ids:?}"
        );
    }

    // Summary counts MUST equal the per-severity tally of `checks`.
    let mut pass = 0;
    let mut warn = 0;
    let mut fail = 0;
    for c in checks {
        match c["severity"].as_str().unwrap() {
            "pass" => pass += 1,
            "warn" => warn += 1,
            "fail" => fail += 1,
            other => panic!("unexpected severity {other}"),
        }
    }
    assert_eq!(v["summary"]["pass"], pass, "summary.pass must match tally");
    assert_eq!(v["summary"]["warn"], warn, "summary.warn must match tally");
    assert_eq!(v["summary"]["fail"], fail, "summary.fail must match tally");
    assert_eq!(pass + warn + fail, 8);
}

/// A non-`--fix` `doctor` run NEVER mutates: it must not write a
/// `doctor.fix` audit event, and (the load-bearing invariant) it
/// must not create/rewrite the managed-policy file. It DOES emit the
/// `doctor.run` summary event.
#[test]
fn doctor_without_fix_never_mutates() {
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    std::fs::create_dir_all(home.join("audit")).unwrap();

    let managed = home.join("policies-managed").join("default.toml");
    assert!(!managed.exists(), "precondition: managed policy absent on a fresh home");

    let (_code, _stdout, _stderr) = run_doctor(&home, &[]);

    assert!(
        !managed.exists(),
        "non-fix doctor must NOT create the managed-policy file (no-mutation invariant)"
    );
    let audit = read_audit(&home);
    assert!(
        !audit.contains("doctor.fix"),
        "non-fix doctor must NOT emit a doctor.fix audit event;\naudit:\n{audit}"
    );
    assert!(
        audit.contains("doctor.run"),
        "doctor must always emit a doctor.run summary event;\naudit:\n{audit}"
    );
}

/// Decision A: with no privileged install the binary-integrity gate
/// fails, and a `--fix` run under a failed gate must refuse EVERY
/// mutation — including the otherwise-`SafeAutomatic` managed-policy
/// rewrite. The on-disk managed file MUST stay absent, and the JSON
/// must show `fix_integrity_gate.passed:false` with a reason that
/// steers to `sudo agentsso setup`.
#[test]
fn doctor_fix_refuses_all_mutations_when_integrity_gate_fails() {
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    std::fs::create_dir_all(home.join("audit")).unwrap();

    let managed = home.join("policies-managed").join("default.toml");
    assert!(!managed.exists());

    let (code, stdout, stderr) = run_doctor(&home, &["--fix", "--json"]);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json parse failed: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });

    // No privileged install in CI ⇒ gate failed (or, off-macOS, the
    // gate is an inert-pass — in which case the managed rewrite WOULD
    // be allowed). The security-critical assertion is macOS-scoped:
    // when the gate reports failed, NOTHING was mutated.
    let gate_passed = v["fix_integrity_gate"]["passed"].as_bool().unwrap();
    let gate_reason = v["fix_integrity_gate"]["reason"].as_str().unwrap();
    assert!(!gate_reason.is_empty(), "gate reason must always be populated");

    if !gate_passed {
        // The non-bypassable Decision-A gate fired: EVERY check that
        // attempted a fix must be Refused (never Repaired/Failed),
        // and the managed file must NOT have been written.
        assert!(
            !managed.exists(),
            "integrity-gate-failed --fix MUST NOT rewrite the managed policy \
             (SafeAutomatic is still gated by Decision A)"
        );
        let checks = v["checks"].as_array().unwrap();
        for c in checks {
            if let Some(fo) = c.get("fix_outcome").filter(|f| !f.is_null()) {
                let kind = fo["kind"].as_str().unwrap();
                let severity = c["severity"].as_str().unwrap();
                // The non-bypassable Decision-A gate means NOTHING
                // mutated: no check may be `repaired` or `failed`
                // (both imply the fix body actually executed).
                assert!(
                    kind == "refused" || kind == "skipped",
                    "check {} under a FAILED integrity gate must be refused/skipped \
                     (no mutation ran), got {fo}",
                    c["id"]
                );
                // Every *failing* check (one that genuinely needed a
                // repair) must be REFUSED specifically — proving the
                // gate blocked it rather than silently doing nothing.
                if severity == "fail" {
                    assert_eq!(
                        kind, "refused",
                        "FAIL check {} must be `refused` by the integrity gate, got {fo}",
                        c["id"]
                    );
                }
            }
        }
        // And the audit trail records refusals/skips, NEVER a repair.
        let audit = read_audit(&home);
        assert!(
            !audit.contains("\"repaired\""),
            "no mutation should have been audited as repaired;\naudit:\n{audit}"
        );
        // Non-zero exit (failed checks and/or refusals).
        assert_ne!(code, 0, "doctor must exit non-zero with failures/refusals");
    }
}

/// Exit code is non-zero whenever any check FAILs. On a fresh temp
/// home with no daemon, `daemon_not_running` FAILs (cross-platform),
/// so a plain `doctor` run must exit non-zero and the human report
/// must surface a `fail` count.
#[test]
fn doctor_exits_nonzero_on_failures() {
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    std::fs::create_dir_all(home.join("audit")).unwrap();

    let (code, stdout, _stderr) = run_doctor(&home, &[]);
    assert_ne!(
        code, 0,
        "a fresh home with no daemon has at least one FAIL (daemon_not_running) → \
         non-zero exit;\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("summary:") && stdout.contains("fail"),
        "human report must include a summary line with a fail count;\nstdout:\n{stdout}"
    );
}

/// `--restart-ok` is accepted and inert without `--fix` (no mutation,
/// no `doctor.fix` audit). This pins the documented "inert without
/// --fix" contract.
#[test]
fn restart_ok_is_inert_without_fix() {
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    std::fs::create_dir_all(home.join("audit")).unwrap();

    let managed = home.join("policies-managed").join("default.toml");
    let (_code, stdout, _stderr) = run_doctor(&home, &["--restart-ok", "--json"]);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("json");
    assert_eq!(v["fix_mode"], false, "--restart-ok alone must not enable fix mode");
    assert_eq!(v["restart_ok"], true, "--restart-ok must be reflected in the report");
    assert!(!managed.exists(), "--restart-ok without --fix must not mutate");
    let audit = read_audit(&home);
    assert!(
        !audit.contains("doctor.fix"),
        "--restart-ok without --fix must not emit doctor.fix;\naudit:\n{audit}"
    );
}
