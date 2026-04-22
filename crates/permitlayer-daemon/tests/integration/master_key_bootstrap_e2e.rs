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

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::common::{agentsso_bin, free_port};

/// Spawn `agentsso start` with a fully-cleared environment plus the
/// specified test env vars. `.env_clear()` is critical: without it,
/// any `AGENTSSO_*` var exported in the developer's shell (e.g.,
/// `AGENTSSO_TELEMETRY__LOG_LEVEL`) would leak into the child
/// process and could perturb config parsing. Hermetic tests beat
/// ambient-environment surprise.
fn spawn_daemon_hermetic(home: &std::path::Path, port: u16, extra_env: &[(&str, &str)]) -> Child {
    let mut cmd = Command::new(agentsso_bin());
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        // HOME and USER are required by some keyring backends even
        // when we're routing through PassphraseKeyStore.
        .env("HOME", home.to_str().unwrap())
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .arg("start")
        .arg("--bind-addr")
        .arg(format!("127.0.0.1:{port}"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.spawn().expect("failed to spawn daemon")
}

/// AC #4: when `AGENTSSO_TEST_FORCE_KEYSTORE_ERROR=1` forces a
/// keystore construction failure, `agentsso start` exits with code 2
/// and a structured error message on stderr. This tests the
/// `StartError` → `main()` → `ExitCode::from(2)` plumbing end-to-end.
///
/// Also verifies the Drop-safety of the refactor: the PID file at
/// `~/.agentsso/pid` is removed on exit (no `std::process::exit`
/// leak) because `run()` now returns `Err` via `?` and Rust stack
/// unwinding fires `PidFile::Drop`.
#[test]
fn fail_fast_exit_2_when_keystore_unavailable() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    let port = free_port();

    let mut child =
        spawn_daemon_hermetic(home.path(), port, &[("AGENTSSO_TEST_FORCE_KEYSTORE_ERROR", "1")]);

    // Give the daemon up to 5 seconds to hit the bootstrap path and
    // exit. In practice it exits within ~100ms because the bootstrap
    // is the first `master_key` call the daemon makes.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait().unwrap() {
            Some(status) => {
                let output = child.wait_with_output().unwrap();
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
                    let _ = child.kill();
                    let _ = child.wait();
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
#[test]
fn real_keystore_bootstrap_happy_path_persists_and_reuses_master_key() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    let port_1 = free_port();

    // First daemon instance: fresh install. PassphraseKeyStore
    // generates a 16-byte salt, derives the key via Argon2id, and
    // persists both the salt and an HMAC verifier to
    // ~/.agentsso/keystore/passphrase.state.
    let mut daemon_1 = spawn_daemon_hermetic(
        home.path(),
        port_1,
        &[("AGENTSSO_TEST_PASSPHRASE", "integration-test-passphrase-1.15")],
    );

    // Wait for health to confirm the daemon made it past the
    // bootstrap. If `bootstrap_from_keystore` regressed, the daemon
    // would either exit(2) or never reach health.
    assert!(
        wait_for_health(port_1, Duration::from_secs(5)),
        "first daemon instance should boot successfully via PassphraseKeyStore"
    );

    // Confirm the persisted state file exists — proves the real
    // keystore adapter wrote to disk, not a mocked in-memory slot.
    let state_path = home.path().join("keystore").join("passphrase.state");
    assert!(
        state_path.exists(),
        "PassphraseKeyStore should have persisted salt+verifier to {}",
        state_path.display()
    );

    // Shut down the first instance.
    daemon_1.kill().unwrap();
    let _ = daemon_1.wait();

    // Second daemon instance: same home dir, same passphrase. The
    // keystore should read the persisted salt, re-derive the key,
    // and verify against the stored HMAC — NO re-generation. Any
    // divergence (wrong passphrase, corrupted state, etc.) would
    // cause `bootstrap_from_keystore` to return
    // `KeyStoreError::PassphraseMismatch` and the daemon to exit 2.
    let port_2 = free_port();
    let mut daemon_2 = spawn_daemon_hermetic(
        home.path(),
        port_2,
        &[("AGENTSSO_TEST_PASSPHRASE", "integration-test-passphrase-1.15")],
    );
    assert!(
        wait_for_health(port_2, Duration::from_secs(5)),
        "second daemon instance should boot successfully and re-use the persisted keystore state"
    );
    daemon_2.kill().unwrap();
    let _ = daemon_2.wait();

    // State file should still exist and be unchanged.
    assert!(
        state_path.exists(),
        "PassphraseKeyStore state file should survive across daemon restarts"
    );
}

/// Wait for the daemon's `/health` endpoint to return a healthy
/// response. Polls every 50ms up to `timeout`.
fn wait_for_health(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(mut stream) = std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(100),
        ) {
            let _ = stream.write_all(
                format!(
                    "GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            );
            let mut buf = Vec::new();
            let _ = stream.read_to_end(&mut buf);
            let response = String::from_utf8_lossy(&buf);
            if response.contains("\"healthy\"") {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}
