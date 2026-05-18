//! Integration test: `agentsso start` compiles policy files at boot
//! and fails fast on schema errors.
//!
//! Covers Story 4.1 AC #2 / AC #8 + UX-overhaul Story 1 (two-layer
//! policy model) end-to-end:
//!
//! - Happy path: the daemon writes the product bundle to the
//!   **managed** layer (`policies-managed/default.toml`) every boot,
//!   creates the **operator** layer (`policies/`) EMPTY (never
//!   seeded), compiles both via `compile_from_layers`, boots, and
//!   `/health` returns 200.
//! - Failure path: a malformed file in the **operator** layer causes
//!   the daemon to exit non-zero within a short deadline, and stderr
//!   carries the offending filename plus a diagnostic banner.
//!
//! Follows the subprocess pattern established by `daemon_lifecycle.rs`
//! and `kill_switch_e2e.rs`. Requires `--test-threads=4` or lower for
//! stable execution (Epic 3 retro line 342).

use crate::common::{DaemonTestConfig, free_port, start_daemon, wait_for_health};
use std::time::{Duration, Instant};

#[test]
fn happy_path_writes_managed_layer_empty_operator_and_boots() {
    let home = tempfile::tempdir().unwrap();
    // Config dir required by figment's Toml::file loader.
    std::fs::create_dir_all(home.path().join("config")).unwrap();

    let daemon = start_daemon(DaemonTestConfig {
        port: 0,
        home: home.path().to_path_buf(),
        ..Default::default()
    });
    let port = daemon.port;

    let booted = wait_for_health(port);
    assert!(booted, "daemon should have booted and served /health");
    crate::common::assert_daemon_pid_matches(&daemon);

    // Now that health is confirmed, shut the daemon down gracefully
    // (SIGTERM → 2s grace → SIGKILL fallback, see DaemonHandle::wait_with_output)
    // and capture its stdout. `tracing_subscriber::fmt()` writes to
    // stdout by default, so the `policies compiled` log line lands there.
    let output = daemon.wait_with_output().unwrap();
    let stdout_buf = String::from_utf8_lossy(&output.stdout).to_string();

    // UX-overhaul Story 1: the product bundle is written to the
    // MANAGED layer (`policies-managed/default.toml`) every boot...
    let managed = home.path().join("policies-managed").join("default.toml");
    assert!(
        managed.exists(),
        "daemon must write the product bundle to policies-managed/default.toml on boot"
    );
    let contents = std::fs::read_to_string(&managed).unwrap();
    assert!(contents.contains("gmail-read-only"));
    assert!(contents.contains("approval-mode"));
    // ...and the OPERATOR layer is created EMPTY and NEVER seeded
    // (this is the frozen-policy / operator-leak fix).
    let operator_dir = home.path().join("policies");
    assert!(operator_dir.is_dir(), "operator policies/ dir must be created");
    assert!(
        !operator_dir.join("default.toml").exists(),
        "operator policies/ must NOT be seeded — product content lives in the managed layer"
    );
    let operator_entries: Vec<_> =
        std::fs::read_dir(&operator_dir).unwrap().filter_map(Result::ok).collect();
    assert!(
        operator_entries.is_empty(),
        "operator policies/ must be empty on first boot, found: {:?}",
        operator_entries.iter().map(|e| e.file_name()).collect::<Vec<_>>()
    );

    // Regression-test AC #2 + AC #9: the daemon must actually have
    // compiled the seeded policies into its `PolicySet`, not just
    // written a file and ignored it. The `tracing::info!` log line
    // at `cli/start.rs` is the only observable signal from a
    // subprocess test — assert it contains the compiled count.
    //
    // `tracing_subscriber::fmt().compact()` wraps field names in
    // ANSI escape sequences by default, so a literal substring
    // match on `"policies_loaded=3"` fails. Strip ANSI before
    // asserting.
    let plain = strip_ansi(&stdout_buf);
    assert!(
        plain.contains("policies compiled (two-layer: managed + operator)"),
        "daemon stdout should contain the two-layer 'policies compiled' log line. Got: {plain}"
    );
    // The managed bundle ships 9 policies: the original 3
    // (gmail-read-only, calendar-prompt-on-write,
    // drive-research-scope-restricted) plus the 6 Epic 9 per-service
    // tier templates (gmail/calendar/drive read-only + read-write,
    // incl. the gmail-read-only-tier alias). With an EMPTY operator
    // layer the merged count must be exactly 9 — asserting the daemon
    // actually compiled the managed bundle, not just wrote it.
    assert!(
        plain.contains("policies_loaded=9"),
        "daemon should have compiled exactly 9 policies from the managed bundle. Got: {plain}"
    );
    // No operator overrides on a clean first boot (empty operator).
    assert!(
        plain.contains("operator_overrides=0"),
        "clean first boot must report zero operator overrides. Got: {plain}"
    );
}

/// Strip ANSI escape sequences from a string.
///
/// `tracing_subscriber::fmt().compact()` emits ANSI color codes
/// around field names and values (e.g. `\x1b[3mpolicies_loaded\x1b[0m`)
/// which break literal substring matches. This hand-rolled stripper
/// removes every `CSI` (`ESC [ ... final`) sequence — no regex, no
/// dependency on `strip-ansi-escapes`.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            // Consume `[`, then every parameter byte (0x30-0x3F) and
            // intermediate byte (0x20-0x2F), then one final byte
            // (0x40-0x7E). This covers the CSI sequences tracing uses.
            let _ = chars.next();
            for ch in chars.by_ref() {
                if ('\x40'..='\x7e').contains(&ch) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

// `try_wait` with `Ok(Some(_))` already reaps the child; clippy can't
// see that and flags it. The explicit `wait()` fallback on the timeout
// path is the other branch clippy's note references.
#[allow(clippy::zombie_processes)]
#[test]
fn failure_path_malformed_policy_exits_nonzero_with_diagnostic() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();

    // Pre-create a broken policy file in the OPERATOR layer BEFORE
    // the daemon boots. UX-overhaul Story 1: the daemon still writes
    // the (valid) managed bundle on boot and compiles it, then
    // compiles the operator layer — where this broken file lives.
    // `compile_from_layers` fails fast on the operator-layer parse
    // error and names the offending file, exactly as before.
    let policies_dir = home.path().join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();
    // Fixture: empty scopes array. `EmptyScopesAllowlist` is one of the
    // variants with a high-signal render banner.
    std::fs::write(
        policies_dir.join("broken.toml"),
        r#"
[[policies]]
name = "broken"
scopes = []
resources = ["*"]
approval-mode = "auto"
"#,
    )
    .unwrap();

    let port = free_port();
    // `DaemonHandle::Drop` SIGKILLs the child on scope exit, so the
    // panic path below is safe — we won't leak a daemon process even
    // if the deadline fires.
    let mut daemon = start_daemon(DaemonTestConfig {
        port,
        home: home.path().to_path_buf(),
        ..Default::default()
    });

    // The daemon must exit on its own within this deadline — we do NOT
    // kill it. If it's still alive after 3s, the fail-fast path is broken.
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut status = None;
    while Instant::now() < deadline {
        match daemon.try_wait() {
            Ok(Some(s)) => {
                status = Some(s);
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("try_wait failed: {e}"),
        }
    }
    if status.is_none() {
        panic!("daemon did not exit within 3s on malformed policy file");
    }

    let status = status.unwrap();
    assert!(!status.success(), "daemon must exit non-zero, got {status:?}");

    // Stderr should carry the diagnostic banner and the offending filename.
    // Use `wait_with_output` rather than `child_mut().stderr.take()` so
    // the drain happens via `Child::wait_with_output` which reads
    // stdout + stderr to EOF — avoiding the pipe-buffer-full race
    // where a verbose-logging daemon could block on stderr write and
    // be SIGKILLed before flushing the diagnostic banner. The child
    // has already exited (status = Some), so the SIGTERM sent by
    // wait_with_output is a harmless no-op that returns ESRCH.
    let output = daemon.wait_with_output().unwrap();
    let stderr_buf = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        stderr_buf.contains("policy compile failed"),
        "stderr should contain policy compile banner. Got: {stderr_buf}"
    );
    assert!(
        stderr_buf.contains("broken.toml"),
        "stderr should name the offending file. Got: {stderr_buf}"
    );
    assert!(
        stderr_buf.contains("scopes = []")
            || stderr_buf.contains("empty")
            || stderr_buf.contains("policy: \"broken\""),
        "stderr should surface the specific defect. Got: {stderr_buf}"
    );
}
