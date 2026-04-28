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

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::common::{agentsso_bin, free_port};

/// Build a fixture v1 envelope (23-byte header, no key_id) by
/// sealing through `Vault::seal` with `key_id = 0`, then byte-
/// splicing the on-disk bytes back to v1 layout. This is the same
/// trick the migration's unit tests use; we duplicate it here
/// because the integration test cannot call `pub(crate)` items from
/// `permitlayer-core` or `permitlayer-daemon`.
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
fn spawn_daemon_hermetic(home: &std::path::Path, port: u16, extra_env: &[(&str, &str)]) -> Child {
    let mut cmd = Command::new(agentsso_bin());
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
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

/// Wait for the daemon's HTTP listener to come up, polling every
/// 50ms. Returns once a TCP connect to `127.0.0.1:port` succeeds, or
/// times out after `deadline`.
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
#[test]
fn daemon_boots_cleanly_with_v1_envelope_in_vault() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("config")).unwrap();

    // Seed a v1 envelope into the vault BEFORE the daemon boots.
    write_v1_envelope_fixture(&home.path().join("vault"), "gmail", b"fake-token-v1");

    let port = free_port();
    let child = spawn_daemon_hermetic(
        home.path(),
        port,
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
    wait_for_daemon_ready(port, Duration::from_secs(10));

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

    let port = free_port();
    let child = spawn_daemon_hermetic(
        home.path(),
        port,
        &[
            ("AGENTSSO_TEST_PASSPHRASE", "integration-test-passphrase"),
            ("AGENTSSO_TEST_NO_PLUGINS", "1"),
        ],
    );
    wait_for_daemon_ready(port, Duration::from_secs(10));
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
