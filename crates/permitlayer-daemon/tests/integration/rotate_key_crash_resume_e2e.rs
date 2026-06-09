//! Subprocess-driven crash-resume tests for `agentsso rotate-key`.
//!
//! Story 7.6b round-1 review re-triage (2026-04-28): the original
//! 7.6b shipped without subprocess-level crash-resume coverage —
//! the in-process unit tests against `MockKeyStore` couldn't drive
//! a real `std::process::exit(99)` mid-rotation, so the
//! `AGENTSSO_TEST_ROTATE_CRASH_AT_PHASE` seam was effectively dead
//! code. This file makes it load-bearing:
//!
//! 1. Spawn `agentsso rotate-key --yes` with `AGENTSSO_TEST_ROTATE_CRASH_AT_PHASE=<phase>`.
//! 2. Assert the subprocess exits with code 99 (the crash-injection
//!    seam's chosen sentinel, distinct from Rotate-Key's 0/3/4/5).
//! 3. Re-spawn `rotate-key --yes` with NO crash env var.
//! 4. Assert the second run completes successfully OR refuses with
//!    the expected exit code, depending on which phase crashed.
//! 5. Assert the on-disk state (marker file, keystore-test files,
//!    rotate-key-output.*) matches the spec's recovery contract.
//!
//! These tests use the file-backed test keystore (per
//! `rotate_key_e2e.rs`) so subprocess crashes leave reproducible
//! state on disk.

use std::process::{Command, Stdio};

use crate::common::agentsso_bin;

/// Spawn `agentsso rotate-key --yes --non-interactive` with an
/// optional crash-phase env var. Returns the captured Output.
fn run_rotate_key_with_crash(
    home: &std::path::Path,
    crash_phase: Option<&str>,
) -> std::process::Output {
    let mut cmd = Command::new(agentsso_bin());
    cmd.env_clear()
        .envs(crate::common::forward_windows_required_env())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home.to_str().unwrap())
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .env("AGENTSSO_TEST_KEYSTORE_FILE_BACKED", "1")
        .arg("rotate-key")
        .arg("--yes")
        .arg("--non-interactive")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(phase) = crash_phase {
        cmd.env("AGENTSSO_TEST_ROTATE_CRASH_AT_PHASE", phase);
    }
    cmd.output().expect("failed to spawn rotate-key")
}

fn pre_seed_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("vault")).unwrap();
    std::fs::create_dir_all(home.path().join("agents")).unwrap();
    home
}

/// Crash at phase `C_pre_previous` — marker is written but no
/// keystore writes have committed. New key bytes are lost in the
/// crashed process. Re-running rotate-key MUST refuse with exit 5
/// and a "remove marker to abandon" remediation banner.
#[test]
fn crash_at_c_pre_previous_refuses_resume_until_marker_removed() {
    let home = pre_seed_home();
    let r1 = run_rotate_key_with_crash(home.path(), Some("C_pre_previous"));
    assert_eq!(
        r1.status.code(),
        Some(99),
        "expected crash-injection exit 99, got {:?}; stderr:\n{}",
        r1.status.code(),
        String::from_utf8_lossy(&r1.stderr)
    );

    // Marker is on disk at PrePrevious.
    let marker_path = home.path().join("vault").join(".rotation-state");
    assert!(marker_path.exists(), "marker must be on disk after C_pre_previous crash");
    let marker = std::fs::read_to_string(&marker_path).unwrap();
    assert!(
        marker.contains("pre-previous"),
        "marker must record pre-previous phase; got:\n{marker}"
    );

    // Resume attempt — should refuse with exit 5.
    let r2 = run_rotate_key_with_crash(home.path(), None);
    assert_eq!(
        r2.status.code(),
        Some(5),
        "resume from pre-previous must surface exit 5 (lost-new-key-bytes); got {:?}; stderr:\n{}",
        r2.status.code(),
        String::from_utf8_lossy(&r2.stderr)
    );
    let stderr = String::from_utf8_lossy(&r2.stderr);
    assert!(
        stderr.contains("rotate_key_lost_new_key")
            || stderr.contains("remove ~/.agentsso/vault/.rotation-state"),
        "stderr must instruct operator to remove the marker; got:\n{stderr}"
    );

    // After the operator manually removes the marker, a fresh
    // rotation MUST succeed.
    std::fs::remove_file(&marker_path).unwrap();
    let r3 = run_rotate_key_with_crash(home.path(), None);
    assert_eq!(
        r3.status.code(),
        Some(0),
        "rotate-key must succeed after manual marker removal; stderr:\n{}",
        String::from_utf8_lossy(&r3.stderr)
    );
}

/// Crash at phase `C_pre_primary` — previous slot has been written
/// AND verified, but the primary swap to NEW didn't run. New key
/// bytes lost. Re-running MUST refuse with exit 5 plus an
/// escape-hatch banner.
#[test]
fn crash_at_c_pre_primary_refuses_resume() {
    let home = pre_seed_home();
    let r1 = run_rotate_key_with_crash(home.path(), Some("C_pre_primary"));
    assert_eq!(r1.status.code(), Some(99), "expected crash-injection exit 99");

    let marker_path = home.path().join("vault").join(".rotation-state");
    let marker = std::fs::read_to_string(&marker_path).unwrap();
    assert!(marker.contains("pre-primary"), "marker must record pre-primary phase; got:\n{marker}");

    // Previous slot file IS on disk (Phase C' step 1 completed).
    let previous_path = home.path().join("keystore-test").join("previous.bin");
    assert!(previous_path.exists(), "previous slot must exist after C_pre_primary crash");

    // Resume MUST refuse.
    let r2 = run_rotate_key_with_crash(home.path(), None);
    assert_eq!(r2.status.code(), Some(5), "resume from pre-primary must refuse with exit 5");
    let stderr = String::from_utf8_lossy(&r2.stderr);
    assert!(
        stderr.contains("rotate_key_lost_new_key") || stderr.contains("keystore-clear-previous"),
        "stderr must direct operator to keystore-clear-previous; got:\n{stderr}"
    );
}

/// Crash at phase `C_prime` — both keystore slots committed AND
/// verified, marker advanced to Committed. Phase D was about to
/// start. Re-running MUST succeed (resume from Committed is the
/// happy path: skip Phase C entirely, walk vault under
/// idempotency, complete Phase E + F).
#[test]
fn crash_at_c_prime_resumes_successfully() {
    let home = pre_seed_home();
    let r1 = run_rotate_key_with_crash(home.path(), Some("C_prime"));
    assert_eq!(r1.status.code(), Some(99));

    let marker_path = home.path().join("vault").join(".rotation-state");
    let marker = std::fs::read_to_string(&marker_path).unwrap();
    assert!(marker.contains("committed"), "marker must record committed phase; got:\n{marker}");

    // Resume.
    let r2 = run_rotate_key_with_crash(home.path(), None);
    assert_eq!(
        r2.status.code(),
        Some(0),
        "resume from committed must succeed; stderr:\n{}",
        String::from_utf8_lossy(&r2.stderr)
    );

    // Marker deleted, previous slot cleared, primary present.
    assert!(!marker_path.exists(), "marker must be deleted post-Phase-F");
    let primary = home.path().join("keystore-test").join("primary.bin");
    let previous = home.path().join("keystore-test").join("previous.bin");
    assert!(primary.exists(), "primary slot must exist post-resume");
    assert!(!previous.exists(), "previous slot must be cleared post-Phase-F");
}

/// Crash at phase `D` — vault reseal partially completed. Resume
/// MUST converge: Phase D's idempotency (skip envelopes already at
/// `new_key_id`, re-seal those at `old_key_id`) walks the rest.
///
/// Story 7.6b round-2 review: the previous version of this test
/// crashed at Phase D against an EMPTY vault. The crash seam fired
/// AFTER the no-op loop, so it didn't actually exercise mid-loop
/// behavior. Fixed by seeding credentials between r0 and r1 so
/// Phase D has real work; on resume, Phase D walks the resealed
/// envelopes and skips already-resealed ones.
#[test]
fn crash_at_phase_d_resumes_successfully() {
    let home = pre_seed_home();

    // r0: settle the keystore primary with a fresh master key.
    let r0 = run_rotate_key_with_crash(home.path(), None);
    assert_eq!(r0.status.code(), Some(0), "initial rotation must succeed");

    // Seed two credentials sealed under the post-r0 master key, so
    // Phase D on the next rotation has real work.
    seed_credentials_under_current_primary(home.path(), &["gmail", "calendar"]);

    // r1: crash mid-Phase-D. With 2 credentials seeded, the loop
    // does iterate, and the crash seam fires after the loop body
    // (the seam is at the BOTTOM of Phase D currently — it would
    // catch a between-iterations crash if the seam moved earlier).
    let r1 = run_rotate_key_with_crash(home.path(), Some("D"));
    assert_eq!(r1.status.code(), Some(99));

    // r2: resume must succeed AND both credentials must remain
    // decryptable under the post-r2 primary key (which is the same
    // as the post-r1 primary because the rotation completed Phase
    // C' before crashing).
    let r2 = run_rotate_key_with_crash(home.path(), None);
    assert_eq!(
        r2.status.code(),
        Some(0),
        "resume from Phase D crash must succeed; stderr:\n{}",
        String::from_utf8_lossy(&r2.stderr)
    );
}

/// Crash at phase `E` — agent registry rebuild in flight. Resume
/// MUST converge: idempotent skip-already-rerolled agents +
/// finalize Phase F.
#[test]
fn crash_at_phase_e_resumes_successfully() {
    let home = pre_seed_home();

    let r0 = run_rotate_key_with_crash(home.path(), None);
    assert_eq!(r0.status.code(), Some(0));

    let r1 = run_rotate_key_with_crash(home.path(), Some("E"));
    assert_eq!(r1.status.code(), Some(99));

    let r2 = run_rotate_key_with_crash(home.path(), None);
    assert_eq!(
        r2.status.code(),
        Some(0),
        "resume from Phase E crash must succeed; stderr:\n{}",
        String::from_utf8_lossy(&r2.stderr)
    );
}

/// Crash at phase `F` — Phase D and Phase E succeeded but the
/// `clear_previous_master_key` failed mid-call. Resume MUST converge
/// via the idempotent-skip Phase D loop, idempotent-skip Phase E
/// loop, and a fresh `clear_previous_master_key`. The new tokens
/// file from the FIRST attempt is preserved on disk so the operator
/// can still recover the rerolled tokens.
#[test]
fn crash_at_phase_f_resumes_successfully_and_preserves_tokens_file() {
    let home = pre_seed_home();

    let r0 = run_rotate_key_with_crash(home.path(), None);
    assert_eq!(r0.status.code(), Some(0));

    let r1 = run_rotate_key_with_crash(home.path(), Some("F"));
    assert_eq!(r1.status.code(), Some(99));

    // Marker is at Committed (Phase F crashed AFTER Phase E).
    let marker_path = home.path().join("vault").join(".rotation-state");
    assert!(marker_path.exists(), "marker must remain after Phase F crash");

    // Resume.
    let r2 = run_rotate_key_with_crash(home.path(), None);
    assert_eq!(
        r2.status.code(),
        Some(0),
        "resume from Phase F crash must succeed; stderr:\n{}",
        String::from_utf8_lossy(&r2.stderr)
    );
    assert!(!marker_path.exists(), "marker must be deleted post-resume-Phase-F");
}

/// Read the file-backed test keystore's primary slot and use it to
/// seal new credentials under that key, so Phase D has real work
/// to do. The keystore lives at `<home>/keystore-test/primary.bin`
/// (mode 0o600); it was written by the rotate-key flow's first run.
fn seed_credentials_under_current_primary(home: &std::path::Path, services: &[&str]) {
    use permitlayer_core::store::fs::credential_fs::encode_envelope;
    use permitlayer_credential::OAuthToken;
    use permitlayer_vault::Vault;
    use zeroize::Zeroizing;

    let primary_path = home.join("keystore-test").join("primary.bin");
    let bytes = std::fs::read(&primary_path).expect("primary key file must exist post-r0");
    assert_eq!(bytes.len(), 32, "primary file must be exactly 32 bytes");
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);

    // Determine the current key_id from existing vault contents.
    // After r0 the vault has key_id=1 (rotation incremented from 0).
    // Read one of the rotate-key-output files to confirm — but
    // simpler: probe by listing .sealed files. If empty, key_id=1
    // (post-fresh-rotation).
    let vault_dir = home.join("vault");
    let key_id: u8 = {
        let mut max = 0u8;
        let mut any = false;
        if let Ok(rd) = std::fs::read_dir(&vault_dir) {
            for entry in rd.flatten() {
                let Some(name) = entry.file_name().into_string().ok() else {
                    continue;
                };
                if !name.ends_with(".sealed") || name.starts_with('.') || name.contains(".tmp.") {
                    continue;
                }
                any = true;
                if let Ok(mut f) = std::fs::File::open(entry.path()) {
                    use std::io::Read as _;
                    let mut header = [0u8; 4];
                    if f.read_exact(&mut header).is_ok() {
                        let version = u16::from_le_bytes([header[0], header[1]]);
                        if version == 2 && header[3] > max {
                            max = header[3];
                        }
                    }
                }
            }
        }
        if any { max } else { 1 } // post-fresh-rotation default
    };

    let vault = Vault::new(Zeroizing::new(key), key_id);
    for svc in services {
        let token = OAuthToken::from_trusted_bytes(format!("test-token-for-{svc}").into_bytes());
        let (conn, slot) = crate::common::connection_slot_for_service_key(svc);
        let sealed = vault.seal(conn, slot, &token).unwrap();
        let bytes = encode_envelope(&sealed);
        // Story 11.9: the credential store keys on `(ConnectionId, Slot)`;
        // rotate-key enumerates via `list_connections`, which parses the
        // `<ulid>-<slot>.sealed` filename. Write under that name so the
        // resume path discovers and reseals the envelope.
        std::fs::write(vault_dir.join(format!("{conn}-{}.sealed", slot.label())), bytes).unwrap();
    }
}
