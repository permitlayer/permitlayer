//! End-to-end integration tests for Story 1.15 master-key bootstrap.
//!
//! Story 1.15 moves master-key provisioning from the lazy
//! `Vault::open_or_create` path into the eager
//! `ensure_master_key_bootstrapped` boot step. A keystore failure at
//! boot is now a fatal `ExitCode::from(2)` via `StartError` (bubbled
//! through `run()` and `main()`), not a silent 503
//! `agent.no_master_key` at register time.
//!
//! This test file drives two code paths:
//!
//! 1. **Fail-fast path** — `AGENTSSO_TEST_FORCE_KEYSTORE_ERROR=1`
//!    forces `ensure_master_key_bootstrapped` to return
//!    `Err(StartError::KeystoreConstruction)`, which `main()` turns
//!    into exit code 2. Covers the "daemon refuses to boot when the
//!    keystore is unavailable" invariant.
//! 2. **Real-keystore happy path** — `AGENTSSO_TEST_PASSPHRASE`
//!    routes through `PassphraseKeyStore` (Argon2id-derived key,
//!    filesystem-persisted salt/verifier). Exercises the production
//!    `bootstrap_from_keystore` path end-to-end, closing the Story
//!    1.15 review Decision 2 coverage gap (previously no test
//!    touched `bootstrap_from_keystore` end-to-end because
//!    `AGENTSSO_TEST_MASTER_KEY_HEX` short-circuited before reaching
//!    it).
//!
//! Story 8.8b round-1 review: this file used to define its own
//! private `spawn_daemon_hermetic` helper, shadowing
//! `common::start_daemon { hermetic: true, set_test_master_key:
//! false, .. }`. The dedup migration (2026-04-28) folds this file
//! into the canonical helper so future fixes (e.g., Windows clean
//! shutdown) propagate without per-file maintenance.

// Both integration tests in this file are gated `cfg(not(windows))`
// (Winsock 10106 / Argon2id contention on Windows hosted runners);
// gate the imports they consume to match.
#[cfg(not(windows))]
use std::time::{Duration, Instant};

#[cfg(not(windows))]
use crate::common::{DaemonTestConfig, free_port, start_daemon, wait_for_health};

/// AC #4: when `AGENTSSO_TEST_FORCE_KEYSTORE_ERROR=1` forces a
/// keystore construction failure, `agentsso start` exits with code 2
/// and a structured error message on stderr. This tests the
/// `StartError` → `main()` → `ExitCode::from(2)` plumbing end-to-end.
///
/// Also verifies the Drop-safety of the refactor: the PID file at
/// `~/.agentsso/pid` is removed on exit (no `std::process::exit`
/// leak) because `run()` now returns `Err` via `?` and Rust stack
/// unwinding fires `PidFile::Drop`.
///
/// Cfg-gated to `not(windows)`: hosted Windows runners under nextest
/// concurrency hit Winsock 10106 transient TCP-bind failures (port
/// reuse / TIME_WAIT cycling). Test contract is OS-agnostic; well
/// covered on Linux + macOS.
#[cfg(not(windows))]
#[test]
fn fail_fast_exit_2_when_keystore_unavailable() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    let port = free_port();

    let mut handle = start_daemon(DaemonTestConfig {
        port,
        home: home.path().to_path_buf(),
        hermetic: true,
        // This test exercises a refuse-to-boot path under the REAL
        // keystore adapter; the test seam (`AGENTSSO_TEST_MASTER_KEY_HEX`)
        // would short-circuit past it.
        set_test_master_key: false,
        extra_env: vec![("AGENTSSO_TEST_FORCE_KEYSTORE_ERROR".into(), "1".into())],
        ..Default::default()
    });

    // Give the daemon up to 5 seconds to hit the bootstrap path and
    // exit. In practice it exits within ~100ms because the bootstrap
    // is the first `master_key` call the daemon makes.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match handle.try_wait().unwrap() {
            Some(status) => {
                let output = handle.wait_with_output().unwrap();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();

                // AC #4: exit code 2 (fail-fast).
                assert_eq!(
                    status.code(),
                    Some(2),
                    "expected exit code 2 on keystore bootstrap failure, got {:?}\nstderr:\n{stderr}",
                    status.code()
                );

                // The `KeystoreConstruction` variant's banner names
                // the failure and references at least one common
                // cause so operators have a fix to try.
                assert!(
                    stderr.contains("failed to construct the platform keystore adapter"),
                    "stderr should name the keystore failure, got:\n{stderr}"
                );
                let mentions_cause = stderr.contains("libsecret")
                    || stderr.contains("secret-service")
                    || stderr.contains("keyring backend");
                assert!(
                    mentions_cause,
                    "stderr should mention a common cause (libsecret / secret-service / keyring backend), got:\n{stderr}"
                );

                // Drop-safety check: after the daemon exits, the PID
                // file should be gone (PidFile::Drop fired via stack
                // unwind). If the refactor regressed to using
                // std::process::exit, this file would still exist.
                let pid_file_path = home.path().join("pid");
                assert!(
                    !pid_file_path.exists(),
                    "PID file should be removed by PidFile::Drop on fail-fast, but still exists at {}",
                    pid_file_path.display()
                );
                return;
            }
            None => {
                if Instant::now() > deadline {
                    // `handle` Drop will SIGKILL on scope exit.
                    panic!("daemon did not exit within 5s — fail-fast bootstrap path did not fire");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// AC #1, #2, #3 (real-keystore happy path): boot the daemon with a
/// `PassphraseKeyStore` seam, wait for the health endpoint, then
/// restart the daemon with the same passphrase and verify it reuses
/// the persisted salt + verifier. This exercises the production
/// `bootstrap_from_keystore` path including:
/// - First-run key generation + atomic salt/verifier persistence
/// - Second-run salt read + Argon2id re-derivation + verifier check
/// - Idempotent `KeyStore::master_key` contract
///
/// Story 1.15 review Decision 2: closes the coverage gap where no
/// existing e2e test exercised `bootstrap_from_keystore` end-to-end
/// because `AGENTSSO_TEST_MASTER_KEY_HEX` short-circuited before
/// reaching it. This test uses a different seam that routes THROUGH
/// the real keystore code path.
///
/// Cfg-gated to `not(windows)`: uses `AGENTSSO_TEST_PASSPHRASE` →
/// PassphraseKeyStore Argon2id (m=65536, t=3, p=4). Under nextest
/// concurrency on Windows hosted runners this exceeds
/// wait_for_health timeout. Same code path is verified on Unix.
#[cfg(not(windows))]
#[test]
fn real_keystore_bootstrap_happy_path_persists_and_reuses_master_key() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    // First daemon instance: fresh install. PassphraseKeyStore
    // generates a 16-byte salt, derives the key via Argon2id, and
    // persists both the salt and an HMAC verifier to
    // ~/.agentsso/keystore/passphrase.state.
    let mut daemon_1 = start_daemon(DaemonTestConfig {
        port: 0,
        home: home.path().to_path_buf(),
        hermetic: true,
        set_test_master_key: false,
        extra_env: vec![(
            "AGENTSSO_TEST_PASSPHRASE".into(),
            "integration-test-passphrase-1.15".into(),
        )],
        ..Default::default()
    });
    let port_1 = daemon_1.port;

    // Wait for health to confirm the daemon made it past the
    // bootstrap. If `bootstrap_from_keystore` regressed, the daemon
    // would either exit(2) or never reach health.
    assert!(
        wait_for_health(port_1),
        "first daemon instance should boot successfully via PassphraseKeyStore"
    );
    crate::common::assert_daemon_pid_matches(&daemon_1);

    // Confirm the persisted state file exists — proves the real
    // keystore adapter wrote to disk, not a mocked in-memory slot.
    let state_path = home.path().join("keystore").join("passphrase.state");
    assert!(
        state_path.exists(),
        "PassphraseKeyStore should have persisted salt+verifier to {}",
        state_path.display()
    );

    // Shut down the first instance via SIGTERM (DaemonHandle::Drop
    // would SIGKILL otherwise; explicit shutdown here matches the
    // pre-migration behavior of `daemon_1.kill().unwrap(); .wait()`).
    daemon_1.shutdown_graceful(Duration::from_secs(2));
    drop(daemon_1);

    // Second daemon instance: same home dir, same passphrase. The
    // keystore should read the persisted salt, re-derive the key,
    // and verify against the stored HMAC — NO re-generation. Any
    // divergence (wrong passphrase, corrupted state, etc.) would
    // cause `bootstrap_from_keystore` to return
    // `KeyStoreError::PassphraseMismatch` and the daemon to exit 2.
    let mut daemon_2 = start_daemon(DaemonTestConfig {
        port: 0,
        home: home.path().to_path_buf(),
        hermetic: true,
        set_test_master_key: false,
        extra_env: vec![(
            "AGENTSSO_TEST_PASSPHRASE".into(),
            "integration-test-passphrase-1.15".into(),
        )],
        ..Default::default()
    });
    let port_2 = daemon_2.port;
    assert!(
        wait_for_health(port_2),
        "second daemon instance should boot successfully and re-use the persisted keystore state"
    );
    crate::common::assert_daemon_pid_matches(&daemon_2);
    daemon_2.shutdown_graceful(Duration::from_secs(2));
    drop(daemon_2);

    // State file should still exist and be unchanged.
    assert!(
        state_path.exists(),
        "PassphraseKeyStore state file should survive across daemon restarts"
    );
}
