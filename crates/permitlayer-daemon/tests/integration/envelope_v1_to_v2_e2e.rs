//! End-to-end integration tests for Story 7.6a's envelope v1 → v2
//! migration.
//!
//! The migration itself is unit-tested in
//! `cli::update::migrations::envelope_v1_to_v2::tests`
//! (cryptographic round-trip via `Vault::seal` → manual v1 splice →
//! `EnvelopeV1ToV2.apply` → `Vault::unseal`). This integration test
//! complements that by verifying the **production daemon-boot path**
//! tolerates a vault containing v1 envelopes (the
//! `decode_envelope` v1 read-fallback) without the migration having
//! run yet — the cross-boot grace window is what keeps the v0.3 →
//! v0.4 upgrade safe even if a user runs the new binary BEFORE
//! `agentsso update --apply`.
//!
//! Spec reference: `_bmad-output/implementation-artifacts/
//! 7-6a-vault-lock-and-envelope-v2.md` line 151-152 ("integration
//! test at `crates/permitlayer-daemon/tests/envelope_v1_to_v2_e2e.rs`:
//! build a fixture v1 vault [...] assert all envelopes are v2 +
//! readable + the daemon starts cleanly post-migration").
//!
//! ## What this exercises (and what it doesn't)
//!
//! - **Exercises**: `compute_active_key_id` returning `0` for a v1
//!   envelope on disk; `try_build_proxy_service`'s `.sealed`-walk
//!   detecting the credential and proceeding past the 501-stub
//!   branch; the daemon boot completing without panic.
//! - **Does NOT exercise**: the `agentsso update --apply` orchestrator
//!   itself (which would require mocking GitHub Releases API + signing
//!   a fake binary asset). The orchestrator's wiring to
//!   `apply_pending` is verified by `migrations::tests::
//!   production_registry_contains_envelope_v1_to_v2` and the
//!   migration's own tests; the `run_apply` outer flow is covered by
//!   `update_e2e.rs`.

// All top-level imports are used only by the cfg(not(windows))
// helpers below; the surviving cross-platform test
// (`daemon_refuses_to_boot_on_mixed_key_id_vault`) uses local-scope
// imports via `use crate::common::*` inside the test fn.
#[cfg(not(windows))]
use std::io::Read;
#[cfg(not(windows))]
use std::process::{Child, Command, Stdio};
#[cfg(not(windows))]
use std::time::{Duration, Instant};

#[cfg(not(windows))]
use crate::common::agentsso_bin;

/// Build a fixture v1 envelope (23-byte header, no key_id) by
/// sealing through `Vault::seal` with `key_id = 0`, then byte-
/// splicing the on-disk bytes back to v1 layout. This is the same
/// trick the migration's unit tests use; we duplicate it here
/// because the integration test cannot call `pub(crate)` items from
/// `permitlayer-core` or `permitlayer-daemon`.
#[cfg(not(windows))]
fn write_v1_envelope_fixture(vault_dir: &std::path::Path, service: &str, plaintext: &[u8]) {
    use permitlayer_core::store::fs::credential_fs::encode_envelope;
    use permitlayer_credential::OAuthToken;
    use permitlayer_vault::Vault;
    use zeroize::Zeroizing;

    let key = [0x42u8; 32];
    let vault = Vault::new(Zeroizing::new(key), 0);
    let token = OAuthToken::from_trusted_bytes(plaintext.to_vec());
    let sealed = vault.seal(service, &token).unwrap();
    let v2 = encode_envelope(&sealed);
    // v2 → v1 splice: drop the key_id byte at offset 3, bump the
    // version u16 from 2 to 1.
    let mut v1: Vec<u8> = Vec::with_capacity(v2.len() - 1);
    v1.extend_from_slice(&1u16.to_le_bytes());
    v1.push(v2[2]); // nonce_len carried
    v1.extend_from_slice(&v2[4..]); // skip key_id byte
    std::fs::create_dir_all(vault_dir).unwrap();
    std::fs::write(vault_dir.join(format!("{service}.sealed")), v1).unwrap();
}

/// Spawn `agentsso start` with a fully-cleared environment. Mirrors
/// the `master_key_bootstrap_e2e.rs::spawn_daemon_hermetic` shape so
/// the daemon's keystore route is the test seam (passphrase-derived,
/// not OS keychain).
#[cfg(not(windows))]
fn spawn_daemon_hermetic(home: &std::path::Path, extra_env: &[(&str, &str)]) -> (Child, u16) {
    let mut cmd = Command::new(agentsso_bin());
    cmd.env_clear()
        .envs(crate::common::forward_windows_required_env())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home.to_str().unwrap())
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .arg("start")
        .arg("--bind-addr")
        .arg("127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("failed to spawn daemon");
    let port = crate::common::wait_for_bound_addr(&mut child, Duration::from_secs(10)).port();
    (child, port)
}

/// Wait for the daemon's HTTP listener to come up, polling every
/// 50ms. Returns once a TCP connect to `127.0.0.1:port` succeeds, or
/// times out after `deadline`.
#[cfg(not(windows))]
fn wait_for_daemon_ready(port: u16, deadline: Duration) {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("daemon did not become ready within {deadline:?}");
}

/// Stop the spawned daemon. SIGTERM, then wait + collect stderr for
/// post-mortem assertions.
#[cfg(not(windows))]
fn stop_and_collect(mut child: Child) -> String {
    // Send SIGTERM via kill — Drop on the daemon's lifecycle state
    // releases PidFile + VaultLock cleanly.
    let _ = child.kill();
    let _ = child.wait();
    let mut stderr = String::new();
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut stderr);
    }
    stderr
}

/// AC #6 + #12 (read-side only): the daemon boots cleanly against a
/// vault containing a v1 envelope. `decode_envelope` synthesizes
/// `key_id = 0` for v1, `compute_active_key_id` returns 0, and
/// `try_build_proxy_service` detects the `.sealed` file and proceeds
/// past the 501-stub branch.
///
/// **Why this matters**: a user who upgrades the binary (v0.3 →
/// v0.4) but has not yet run `agentsso update --apply` will have a
/// vault full of v1 envelopes when the new daemon boots. Without the
/// v1 read-fallback, the daemon would refuse to read those envelopes
/// at first request — making the upgrade non-atomic (binary
/// upgraded, data not). This test pins down the grace window.
///
/// Cfg-gated to `not(windows)`: the test routes through
/// `AGENTSSO_TEST_PASSPHRASE` which exercises `PassphraseKeyStore`'s
/// Argon2id derivation (OWASP 2024 params: m=65536, t=3, p=4). On
/// Windows hosted runners under nextest contention this derivation
/// exceeds 60s wall-clock. The same envelope-v1-boot code path is
/// covered on Unix (Linux + macOS); the Windows boot path is
/// validated via release.yml::windows-publish-smoke (real install
/// from real release artifact + version-check).
#[cfg(not(windows))]
#[test]
fn daemon_boots_cleanly_with_v1_envelope_in_vault() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();

    // Seed a v1 envelope into the vault BEFORE the daemon boots.
    write_v1_envelope_fixture(&home.path().join("vault"), "gmail", b"fake-token-v1");

    let (child, port) = spawn_daemon_hermetic(
        home.path(),
        &[
            ("AGENTSSO_TEST_PASSPHRASE", "integration-test-passphrase"),
            // Disable plugin loader / scrub-rule pack download paths
            // — keep the boot hermetic.
            ("AGENTSSO_TEST_NO_PLUGINS", "1"),
        ],
    );

    // Boot must complete within 10s — the v1 envelope on disk is
    // not in the boot critical path; it's read lazily by the proxy
    // when the first request lands.
    wait_for_daemon_ready(port, Duration::from_secs(60));

    // Daemon is up; that's the assertion. Stop and collect.
    let stderr = stop_and_collect(child);

    // Sanity: no panic, no UnsupportedVersion error in the boot
    // log. (The v1 → v2 fallback is supposed to be silent.)
    assert!(
        !stderr.contains("UnsupportedVersion"),
        "v1 envelope on disk produced an UnsupportedVersion error during boot:\n{stderr}"
    );
    assert!(
        !stderr.to_lowercase().contains("panic"),
        "daemon panicked while booting against a v1 vault:\n{stderr}"
    );
}

/// AC #5 + #6 (write-side): the daemon boots against a vault
/// containing a v2 envelope (key_id = 0) and the on-disk file is
/// preserved as v2. This is the post-migration steady state.
/// Same Windows cfg-gating as `daemon_boots_cleanly_with_v1_envelope_in_vault`
/// — Argon2id derivation under nextest contention exceeds 60s on
/// hosted Windows runners.
#[cfg(not(windows))]
#[test]
fn daemon_boots_cleanly_with_v2_envelope_in_vault() {
    use permitlayer_core::store::fs::credential_fs::encode_envelope;
    use permitlayer_credential::OAuthToken;
    use permitlayer_vault::Vault;
    use zeroize::Zeroizing;

    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();

    // Seed a v2 envelope (the "post-migration" steady state).
    let key = [0x42u8; 32];
    let vault = Vault::new(Zeroizing::new(key), 0);
    let token = OAuthToken::from_trusted_bytes(b"fake-token-v2".to_vec());
    let sealed = vault.seal("gmail", &token).unwrap();
    let bytes = encode_envelope(&sealed);
    let vault_dir = home.path().join("vault");
    std::fs::create_dir_all(&vault_dir).unwrap();
    std::fs::write(vault_dir.join("gmail.sealed"), &bytes).unwrap();
    // Sanity: leading version bytes are v2.
    assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 2);

    let (child, port) = spawn_daemon_hermetic(
        home.path(),
        &[
            ("AGENTSSO_TEST_PASSPHRASE", "integration-test-passphrase"),
            ("AGENTSSO_TEST_NO_PLUGINS", "1"),
        ],
    );
    wait_for_daemon_ready(port, Duration::from_secs(60));
    let stderr = stop_and_collect(child);

    // Post-stop, the on-disk envelope must STILL be v2 (the daemon
    // should not have rewritten it on a read-only path).
    let after = std::fs::read(vault_dir.join("gmail.sealed")).unwrap();
    assert_eq!(
        u16::from_le_bytes([after[0], after[1]]),
        2,
        "v2 envelope was unexpectedly rewritten during boot"
    );

    assert!(
        !stderr.contains("UnsupportedVersion"),
        "v2 envelope produced an unexpected error during boot:\n{stderr}"
    );
}

/// Story 7.6b AC #13: the daemon refuses to boot with exit code 6
/// when the vault contains envelopes at multiple `key_id` values
/// (a previous `agentsso rotate-key` did not finish). Re-running
/// rotate-key resumes the rotation idempotently.
///
/// Story 7.6b round-1 review: migrated from the file-local
/// `spawn_daemon_hermetic` helper to the canonical
/// `crate::common::start_daemon` per the 8.8b helper-discipline
/// fence.
#[test]
fn daemon_refuses_to_boot_on_mixed_key_id_vault() {
    use crate::common::{DaemonTestConfig, free_port, start_daemon};
    use permitlayer_core::store::fs::credential_fs::encode_envelope;
    use permitlayer_credential::OAuthToken;
    use permitlayer_vault::Vault;
    use zeroize::Zeroizing;

    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();
    let vault_dir = home.path().join("vault");
    std::fs::create_dir_all(&vault_dir).unwrap();

    // Seed two envelopes at DIFFERENT key_ids (simulating a
    // partially-rotated vault — what 7.6b's mid-Phase-D crash would
    // leave on disk).
    let key = [0x42u8; 32];

    let vault_old = Vault::new(Zeroizing::new(key), 1);
    let token_old = OAuthToken::from_trusted_bytes(b"still-at-old-key".to_vec());
    let sealed_old = vault_old.seal("gmail", &token_old).unwrap();
    std::fs::write(vault_dir.join("gmail.sealed"), encode_envelope(&sealed_old)).unwrap();

    let vault_new = Vault::new(Zeroizing::new(key), 2);
    let token_new = OAuthToken::from_trusted_bytes(b"already-at-new-key".to_vec());
    let sealed_new = vault_new.seal("calendar", &token_new).unwrap();
    std::fs::write(vault_dir.join("calendar.sealed"), encode_envelope(&sealed_new)).unwrap();

    let mut handle = start_daemon(DaemonTestConfig {
        port: free_port(),
        home: home.path().to_path_buf(),
        // The mixed-key refusal fires BEFORE keystore bootstrap, but
        // start_daemon's default keystore path needs SOME bootstrap
        // env to avoid hanging on the real OS keychain. Use the
        // canonical test-master-key shortcut.
        hermetic: true,
        set_test_master_key: true,
        extra_env: vec![("AGENTSSO_TEST_NO_PLUGINS".to_owned(), "1".to_owned())],
        ..Default::default()
    });

    // Poll for the daemon to exit on its own (the boot guard fires
    // synchronously and quickly). 10s is plenty of headroom; we
    // explicitly do NOT use `wait_with_output` here because that
    // helper sends SIGTERM unconditionally, which would mask a
    // clean-exit-code-6 path with a signal-kill-None status if the
    // grace window is even briefly off.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let status = loop {
        match handle.try_wait().unwrap() {
            Some(s) => break s,
            None => {
                if std::time::Instant::now() > deadline {
                    panic!("daemon did not exit within 10s on mixed-key_id vault");
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    };

    // Drain stderr now that the process has exited. Drop the handle
    // afterward (its Drop's child.kill() is a no-op on a dead pid).
    let output = handle.wait_with_output().expect("captured stderr");
    assert_eq!(
        status.code(),
        Some(6),
        "expected exit code 6 (VaultRotationIncomplete), got {:?}; stderr:\n{}",
        status.code(),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("vault rotation incomplete") || stderr.contains("multiple key_ids"),
        "stderr should name the mixed-key_id refusal, got:\n{stderr}"
    );
}
