//! Integration test: `agentsso start` compiles policy files at boot
//! and fails fast on schema errors.
//!
//! Covers Story 4.1 AC #2 and AC #8 end-to-end:
//!
//! - Happy path: a valid `policies/default.toml` (the seeded default)
//!   compiles cleanly, the daemon boots, and `/health` returns 200.
//! - Failure path: a malformed policy file causes the daemon to exit
//!   non-zero within a short deadline, and stderr carries the
//!   offending filename plus a diagnostic banner.
//!
//! Follows the subprocess pattern established by `daemon_lifecycle.rs`
//! and `kill_switch_e2e.rs`. Requires `--test-threads=4` or lower for
//! stable execution (Epic 3 retro line 342).

use crate::common::{DaemonTestConfig, free_port, start_daemon, wait_for_health};
use std::time::{Duration, Instant};

#[test]
fn happy_path_seeds_default_toml_and_boots() {
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

    // First-run seeded the default policy file.
    let seeded = home.path().join("policies").join("default.toml");
    assert!(
        seeded.exists(),
        "daemon should have seeded ~/.agentsso/policies/default.toml on first boot"
    );
    let contents = std::fs::read_to_string(&seeded).unwrap();
    assert!(contents.contains("gmail-read-only"));
    assert!(contents.contains("approval-mode"));

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
        plain.contains("policies compiled"),
        "daemon stdout should contain 'policies compiled' tracing log line. Got: {plain}"
    );
    // The seeded default.toml ships 3 policies (gmail-read-only,
    // calendar-prompt-on-write, drive-research-scope-restricted),
    // so the compiled count must be exactly 3.
    assert!(
        plain.contains("policies_loaded=3"),
        "daemon should have compiled exactly 3 policies from seeded default.toml. Got: {plain}"
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

    // Pre-create a broken policy file BEFORE the daemon boots. Because the
    // policies directory exists, the first-run seed is skipped and our
    // broken file is the only thing the compiler sees.
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
