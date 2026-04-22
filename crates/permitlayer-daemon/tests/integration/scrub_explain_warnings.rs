//! Integration tests for `agentsso scrub explain` error and warning
//! paths that can only be exercised by spawning the real binary and
//! capturing stderr.
//!
//! Story 2.7 review patches:
//! - Patch 5: empty-string positional → `empty_rule_name` error with
//!   a cleaner message than the pre-patch `'no built-in rule named '''`.
//! - Patch 5: empty-string positional + `--list` → no confusing empty-
//!   quote warning; the list still renders.
//! - Patch 8: `scrub explain otp-6digit --list` → stderr warning plus
//!   stdout list (Option A codification of AC #9 — `eprintln!`-based
//!   warning rather than `tracing::warn!`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

/// Run `agentsso scrub explain` with the given args and return
/// `(exit_code, stdout, stderr)`.
fn run_scrub_explain(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_agentsso"))
        .args(["scrub", "explain"])
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn agentsso scrub explain");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let code = output.status.code().unwrap_or(-1);
    (code, stdout, stderr)
}

// ----- Option A codification: eprintln! warning on --list + positional -----

#[test]
fn scrub_explain_list_with_positional_warns_on_stderr() {
    let (code, stdout, stderr) = run_scrub_explain(&["otp-6digit", "--list"]);

    // Exit 0: the command still runs and prints the list.
    assert_eq!(code, 0, "scrub explain with --list should exit 0; stderr={stderr}");

    // Warning on stderr:
    assert!(
        stderr.contains("positional rule argument 'otp-6digit' ignored"),
        "stderr should contain positional-arg warning: stderr={stderr:?}"
    );
    assert!(
        stderr.contains("--list was also passed"),
        "stderr should explain why: stderr={stderr:?}"
    );

    // List on stdout:
    assert!(
        stdout.contains("built-in scrub rules:"),
        "stdout should contain list header: stdout={stdout:?}"
    );
    assert!(stdout.contains("otp-6digit"), "stdout should list otp-6digit");
    assert!(stdout.contains("credit-card"), "stdout should list credit-card");
}

#[test]
fn scrub_explain_list_alone_has_no_stderr_warning() {
    // Bare `--list` (no positional) must NOT emit any warning.
    let (code, stdout, stderr) = run_scrub_explain(&["--list"]);

    assert_eq!(code, 0);
    assert!(stdout.contains("built-in scrub rules:"));
    assert!(
        !stderr.contains("positional rule argument"),
        "no warning expected when --list is alone: stderr={stderr:?}"
    );
}

#[test]
fn scrub_explain_list_with_trimmed_whitespace_positional_warns_with_trimmed_value() {
    // The warning message should show the trimmed rule name, not the
    // raw input — the implementation calls `.trim()` before formatting.
    let (code, _stdout, stderr) = run_scrub_explain(&["  otp-6digit  ", "--list"]);

    assert_eq!(code, 0);
    assert!(
        stderr.contains("positional rule argument 'otp-6digit' ignored"),
        "warning should show trimmed value: stderr={stderr:?}"
    );
}

// ----- Patch 5: empty-string positional handling -----

#[test]
fn scrub_explain_empty_positional_produces_empty_rule_name_error() {
    // Story 2.7 review patch 5: the pre-patch behavior produced a
    // confusing "no built-in rule named ''" with consecutive single
    // quotes. The fix gives empty/whitespace-only arguments a dedicated
    // error_code with a cleaner message.
    let (code, _stdout, stderr) = run_scrub_explain(&[""]);

    // Exits 1 (error block path).
    assert_eq!(code, 1, "empty rule name should exit 1; stderr={stderr}");

    // New error_code is `empty_rule_name`, not `unknown_scrub_rule`.
    assert!(
        stderr.contains("empty_rule_name"),
        "stderr should contain empty_rule_name error_code: stderr={stderr:?}"
    );
    assert!(
        stderr.contains("cannot be empty or whitespace-only"),
        "stderr should explain the rule: stderr={stderr:?}"
    );
    // Must NOT contain the old confusing consecutive-quotes pattern.
    assert!(
        !stderr.contains("'''"),
        "stderr must not contain the old confusing ''' pattern: stderr={stderr:?}"
    );
}

#[test]
fn scrub_explain_whitespace_only_positional_produces_empty_rule_name_error() {
    // Same as above but with whitespace-only string (which trims to empty).
    let (code, _stdout, stderr) = run_scrub_explain(&["   "]);

    assert_eq!(code, 1);
    assert!(
        stderr.contains("empty_rule_name"),
        "whitespace-only should trigger empty_rule_name: stderr={stderr:?}"
    );
}

#[test]
fn scrub_explain_empty_positional_with_list_shows_no_warning() {
    // Story 2.7 review patch 5: empty-string positional + --list must
    // NOT emit the "positional rule argument '' ignored" warning
    // (confusing empty quotes). The list still renders.
    let (code, stdout, stderr) = run_scrub_explain(&["", "--list"]);

    assert_eq!(code, 0);
    assert!(stdout.contains("built-in scrub rules:"));
    // No confusing empty-quote warning.
    assert!(
        !stderr.contains("''"),
        "empty-string positional with --list must not produce empty-quote warning: stderr={stderr:?}"
    );
    assert!(
        !stderr.contains("positional rule argument"),
        "no positional warning for empty argument: stderr={stderr:?}"
    );
}

// ----- Happy path: normal explain still works (regression guard) -----

#[test]
fn scrub_explain_otp_6digit_still_prints_full_explain_block() {
    let (code, stdout, _stderr) = run_scrub_explain(&["otp-6digit"]);

    assert_eq!(code, 0);
    assert!(stdout.contains("rule: otp-6digit"));
    assert!(stdout.contains("placeholder:"));
    assert!(stdout.contains("<REDACTED_OTP>"));
    assert!(stdout.contains("what it catches:"));
    assert!(stdout.contains("example (live-scrubbed):"));
    assert!(stdout.contains("why permitlayer catches this:"));
}

#[test]
fn scrub_explain_trailing_whitespace_still_matches() {
    // Regression guard for Story 2.7 trim behavior.
    let (code, stdout, _stderr) = run_scrub_explain(&["otp-6digit "]);

    assert_eq!(code, 0);
    assert!(stdout.contains("rule: otp-6digit"));
}
