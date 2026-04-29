//! Subprocess-driven end-to-end tests for `agentsso rotate-key`.
//!
//! Story 7.6b round-1 review re-triage (2026-04-28): the original
//! 7.6b shipped without a dedicated rotate-key e2e suite, deferring
//! to in-process unit tests against `MockKeyStore`. The defer was
//! rejected — these tests pin invariants the unit tests can't reach:
//!   1. Plaintext bearer tokens MUST NEVER appear on stdout
//!      (`cargo run -- rotate-key --yes` captured-output check).
//!   2. The mode-`0o600` `rotate-key-output.<pid>` file IS the only
//!      plaintext-bearing surface, post-rotation.
//!   3. The `--non-interactive` posture works (CI / scripts).
//!   4. Exit codes match the spec table (0 / 3 / 4 / 5).
//!
//! These tests use the `AGENTSSO_TEST_KEYSTORE_FILE_BACKED=1` test
//! seam (gated to `cfg(debug_assertions)` in
//! `cli::rotate_key::mod`) so they don't touch the test runner's
//! real OS keychain. The seam writes primary + previous slots to
//! `<home>/keystore-test/{primary,previous}.bin` (mode 0o600).
//!
//! Crash-resume coverage lives in `rotate_key_crash_resume_e2e.rs`.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::common::{DaemonTestConfig, agentsso_bin, free_port, start_daemon, wait_for_health};

/// Spawn `agentsso rotate-key --yes --non-interactive` headlessly
/// against the file-backed test keystore. Returns the captured
/// `Output` (status, stdout, stderr).
fn run_rotate_key(home: &std::path::Path, extra_env: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(agentsso_bin());
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home.to_str().unwrap())
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .env("AGENTSSO_TEST_KEYSTORE_FILE_BACKED", "1")
        .arg("rotate-key")
        .arg("--yes")
        .arg("--non-interactive")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to spawn rotate-key")
}

/// Pre-create the home dir + `vault/` subdir so the boot path can
/// open the vault dir without racing on `create_dir_all`. Mirrors
/// the setup the daemon would have done on a previous `start`.
fn pre_seed_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("vault")).unwrap();
    std::fs::create_dir_all(home.path().join("agents")).unwrap();
    home
}

/// AC #15 / round-1 re-triage: a successful rotation against an
/// empty vault completes with exit code 0 and writes NO plaintext
/// bearer token to stdout.
#[test]
fn rotate_key_happy_path_empty_vault_no_plaintext_in_stdout() {
    let home = pre_seed_home();
    let output = run_rotate_key(home.path(), &[]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "expected exit 0, got {:?}; stderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Round-1 re-triage invariant: the v2 token prefix `agt_v2_`
    // followed by ANY content past the prefix is plaintext leak.
    // An empty vault has zero agents, so nothing should be on
    // stdout matching this pattern.
    assert!(
        !stdout.contains("agt_v2_"),
        "stdout must not contain plaintext bearer tokens or token-shape strings; got:\n{stdout}"
    );
    assert!(
        !stderr.contains("agt_v2_"),
        "stderr must not contain plaintext bearer tokens; got:\n{stderr}"
    );

    // Sanity: the keystore-test files exist (primary written) and
    // the previous-slot file is absent (Phase F cleared).
    let primary = home.path().join("keystore-test").join("primary.bin");
    let previous = home.path().join("keystore-test").join("previous.bin");
    assert!(primary.exists(), "primary slot must exist post-rotation");
    assert!(!previous.exists(), "previous slot must be cleared by Phase F");
}

/// AC #15 / round-1 re-triage: with an agent registered, rotation
/// writes the new token to a mode-`0o600` file at
/// `<home>/rotate-key-output.<pid>`. Stdout points at that file but
/// does NOT print the token itself.
#[cfg(unix)]
#[test]
fn rotate_key_persists_tokens_to_mode_0600_file_not_stdout() {
    use std::os::unix::fs::PermissionsExt;

    let home = pre_seed_home();

    // Pre-seed an agent record. We can't easily go through the
    // daemon's register handler here (would need a running daemon
    // + auth path), so we write the agent file directly. This
    // mirrors what the daemon would have left on disk.
    pre_seed_agent(home.path(), "alice");

    let output = run_rotate_key(home.path(), &[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "expected exit 0, got {:?}; stderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    // The token-shape string `agt_v2_alice_` MUST NOT appear in
    // stdout. The `agt_v2_` literal alone (no name suffix) IS
    // allowed — it's used in the user-facing remediation banner.
    assert!(
        !stdout.contains("agt_v2_alice_"),
        "stdout must not contain the rerolled bearer token; got:\n{stdout}"
    );

    // Find the rotate-key-output file.
    let candidates: Vec<_> = std::fs::read_dir(home.path())
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with("rotate-key-output."))
        .collect();
    assert_eq!(
        candidates.len(),
        1,
        "exactly one rotate-key-output.* file must remain post-rotation; found {candidates:?}"
    );
    let tokens_path = home.path().join(&candidates[0]);

    // File mode is 0o600.
    let mode = std::fs::metadata(&tokens_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "rotate-key-output file must be mode 0o600");

    // File contains the rerolled token.
    let body = std::fs::read_to_string(&tokens_path).unwrap();
    assert!(
        body.lines().any(|l| l.starts_with("alice=agt_v2_alice_")),
        "tokens file missing alice's rerolled token; contents:\n{body}"
    );

    // Stdout DID print the file path and the operator-action banner.
    assert!(
        stdout.contains("New agent tokens written to:"),
        "stdout missing the new-tokens-file banner; got:\n{stdout}"
    );
    assert!(
        stdout.contains(tokens_path.to_str().unwrap()),
        "stdout missing the tokens-file path; got:\n{stdout}"
    );
}

/// AC #5 / round-1 re-triage: rotate-key refuses with exit code 3
/// when the vault lock is held by another process. We pre-acquire
/// the lock via `permitlayer_core::VaultLock` and then spawn
/// rotate-key — it should refuse fast.
#[test]
fn rotate_key_refuses_exit3_when_vault_lock_held() {
    let home = pre_seed_home();
    let _holder =
        permitlayer_core::VaultLock::try_acquire(home.path()).expect("test holds the lock");

    let output = run_rotate_key(home.path(), &[]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "expected exit 3 (vault lock busy), got {:?}; stderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("vault lock")
            || stderr.contains("vault-lock")
            || stderr.contains("rotate_key_vault_busy"),
        "stderr should name the lock-busy refusal; got:\n{stderr}"
    );
}

/// AC #15 / round-1 re-triage: subprocess invocation respects the
/// `--non-interactive` requirement. Spawning without `--yes` AND
/// without a tty (which subprocess tests never have) MUST refuse.
///
/// Why this matters: a CI script that drops `--yes` accidentally
/// must NOT proceed with rotation interactively (there's no human
/// to confirm).
#[test]
fn rotate_key_refuses_non_interactive_without_yes() {
    let home = pre_seed_home();
    let mut cmd = Command::new(agentsso_bin());
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home.path().to_str().unwrap())
        .env("AGENTSSO_PATHS__HOME", home.path().to_str().unwrap())
        .env("AGENTSSO_TEST_KEYSTORE_FILE_BACKED", "1")
        .arg("rotate-key") // intentionally NO --yes
        .arg("--non-interactive")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = cmd.output().expect("spawn rotate-key");
    assert_ne!(
        output.status.code(),
        Some(0),
        "rotate-key without --yes in a non-tty must NOT succeed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Round-1 re-triage: the rotate-key flow is reproducibly idempotent
/// — running `rotate-key --yes` twice in a row succeeds both times
/// (the second run sees a Phase F-completed state, no marker, no
/// previous slot, and just mints a new key). Each run produces a
/// distinct rotate-key-output.<pid> file (no stale-file collision).
#[test]
fn rotate_key_back_to_back_runs_succeed_with_distinct_output_files() {
    let home = pre_seed_home();
    pre_seed_agent(home.path(), "bob");

    // First run.
    let r1 = run_rotate_key(home.path(), &[]);
    assert_eq!(r1.status.code(), Some(0), "first rotate-key must succeed");

    // Pre-existing rotate-key-output.<pid> from run 1 must not
    // collide with run 2 — each run uses its own pid.
    let r1_files: Vec<_> = std::fs::read_dir(home.path())
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with("rotate-key-output."))
        .collect();
    assert_eq!(r1_files.len(), 1, "after run 1: 1 output file");

    // Second run.
    let r2 = run_rotate_key(home.path(), &[]);
    assert_eq!(
        r2.status.code(),
        Some(0),
        "second rotate-key must succeed; stderr:\n{}",
        String::from_utf8_lossy(&r2.stderr)
    );

    let r2_files: Vec<_> = std::fs::read_dir(home.path())
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with("rotate-key-output."))
        .collect();
    assert_eq!(r2_files.len(), 2, "after run 2: 2 output files (one per pid)");
    let _ = Instant::now() + Duration::from_secs(0); // silence unused
}

/// Pre-seed an agent record on disk so rotate-key has work to do
/// in Phase E. Mirrors the structure produced by the daemon's
/// register-agent handler.
fn pre_seed_agent(home: &std::path::Path, name: &str) {
    use chrono::Utc;
    use permitlayer_core::agent::{
        AgentIdentity, BEARER_TOKEN_BYTES, base64_url_no_pad_encode, compute_lookup_key,
        generate_bearer_token_bytes, hash_token, lookup_key_to_hex,
    };

    // Read the primary key written by the file-backed test keystore.
    // If it doesn't exist yet, mint a deterministic one and persist
    // it so rotate-key reads it as the OLD primary.
    let primary_path = home.join("keystore-test").join("primary.bin");
    std::fs::create_dir_all(home.join("keystore-test")).unwrap();
    let old_master_key = if primary_path.exists() {
        let bytes = std::fs::read(&primary_path).unwrap();
        let mut k = [0u8; 32];
        k.copy_from_slice(&bytes);
        k
    } else {
        let k = [0xAAu8; 32];
        std::fs::write(&primary_path, k).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&primary_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        k
    };

    // Derive the OLD daemon subkey via the shared HKDF info.
    use hkdf::Hkdf;
    use sha2::Sha256;
    let mut subkey = [0u8; 32];
    Hkdf::<Sha256>::new(None, &old_master_key)
        .expand(permitlayer_core::agent::AGENT_LOOKUP_HKDF_INFO, &mut subkey)
        .unwrap();

    let lookup = compute_lookup_key(&subkey, name.as_bytes());
    let _random = generate_bearer_token_bytes();
    let _ = BEARER_TOKEN_BYTES;
    let token = format!(
        "agt_v2_{name}_{}",
        base64_url_no_pad_encode(&[0u8; 32]) // shape-correct, contents irrelevant
    );
    let token_hash = hash_token(token.as_bytes()).unwrap();
    let agent = AgentIdentity::new(
        name.to_owned(),
        "default".to_owned(),
        token_hash,
        lookup_key_to_hex(&lookup),
        Utc::now(),
        None,
    )
    .unwrap();
    let toml = toml::to_string_pretty(&agent).unwrap();
    std::fs::create_dir_all(home.join("agents")).unwrap();
    std::fs::write(home.join("agents").join(format!("{name}.toml")), toml).unwrap();
}

/// AC #15 / round-2 re-triage: end-to-end auth round-trip against a
/// running daemon. Spawn daemon → register an agent (capture the
/// OLD bearer token) → make an authed request (success) → stop
/// daemon → run rotate-key (captures new tokens to file) → spawn
/// daemon again → make an authed request with the OLD token (401)
/// → make an authed request with the NEW token (200, or any non-
/// auth-failure status — the proxy may return upstream errors but
/// NOT auth.invalid_token).
///
/// Story 7.6b round-2 review: the original e2e suite asserted
/// subprocess invariants (no plaintext on stdout, file modes, exit
/// codes) but did NOT exercise the auth round-trip the spec called
/// for. This test closes that gap.
#[test]
fn auth_round_trip_against_running_daemon() {
    let home = pre_seed_home();
    std::fs::create_dir_all(home.path().join("config")).unwrap();

    // Phase 1 — boot the daemon with the file-backed test keystore.
    let port = free_port();
    let daemon_v1 = start_daemon(DaemonTestConfig {
        port,
        home: home.path().to_path_buf(),
        // We use AGENTSSO_TEST_KEYSTORE_FILE_BACKED, NOT
        // AGENTSSO_TEST_MASTER_KEY_HEX, because rotate-key needs to
        // share the same keystore — and the master-key-hex shortcut
        // is hardcoded, not file-backed.
        set_test_master_key: false,
        extra_env: vec![("AGENTSSO_TEST_KEYSTORE_FILE_BACKED".to_owned(), "1".to_owned())],
        ..Default::default()
    });
    assert!(wait_for_health(port), "daemon v1 should boot");

    // Phase 2 — register an agent through the control plane.
    let old_token = register_agent(port, "round-trip-agent", "gmail-read-only");
    assert!(
        old_token.starts_with("agt_v2_round-trip-agent_"),
        "registered token must use v2 shape with the agent name: {old_token}"
    );

    // Phase 3 — authenticated request with the OLD token. We don't
    // require a 200 (the proxy may return upstream errors), but we
    // DO require it not to be `auth.invalid_token`.
    let pre_rotation_status = authed_get_status(port, &old_token);
    if pre_rotation_status == "auth.invalid_token" {
        let diagnostic = collect_test_home_diagnostic(home.path(), "pre-rotation auth failed");
        panic!(
            "pre-rotation auth with registered token must not be rejected; got {pre_rotation_status}{diagnostic}"
        );
    }

    // Phase 4 — stop the daemon. SIGTERM via wait_with_output; the
    // VaultLock + PidFile clean up on Drop.
    let v1_output = daemon_v1.wait_with_output().expect("daemon v1 exit");
    assert!(
        !v1_output.stderr.is_empty() || v1_output.status.success(),
        "daemon v1 should have exited (status: {:?})",
        v1_output.status
    );

    // Phase 5 — run rotate-key. New tokens go to the rotate-key-
    // output.<pid> file (mode 0o600).
    let rotate_output = run_rotate_key(home.path(), &[]);
    assert_eq!(
        rotate_output.status.code(),
        Some(0),
        "rotate-key must succeed; stderr:\n{}",
        String::from_utf8_lossy(&rotate_output.stderr)
    );

    // Phase 6 — read the new token from the output file.
    let new_token = read_new_token_for_agent(home.path(), "round-trip-agent");
    assert!(
        new_token.starts_with("agt_v2_round-trip-agent_"),
        "rerolled token must keep the v2 shape: {new_token}"
    );
    assert_ne!(old_token, new_token, "rotation must produce a different token");

    // Phase 7 — re-spawn the daemon with the rotated keystore.
    let port2 = free_port();
    let daemon_v2 = start_daemon(DaemonTestConfig {
        port: port2,
        home: home.path().to_path_buf(),
        set_test_master_key: false,
        extra_env: vec![("AGENTSSO_TEST_KEYSTORE_FILE_BACKED".to_owned(), "1".to_owned())],
        ..Default::default()
    });
    assert!(wait_for_health(port2), "daemon v2 should boot post-rotation");

    // Phase 8 — OLD token now returns auth.invalid_token (its
    // token_hash no longer matches the rerolled record).
    let post_old = authed_get_status(port2, &old_token);
    assert_eq!(
        post_old, "auth.invalid_token",
        "post-rotation, OLD token must be rejected; got {post_old}"
    );

    // Phase 9 — NEW token authenticates (no auth.invalid_token).
    let post_new = authed_get_status(port2, &new_token);
    if post_new == "auth.invalid_token" {
        let diagnostic =
            collect_test_home_diagnostic(home.path(), "post-rotation NEW-token auth failed");
        let _ = daemon_v2.wait_with_output();
        panic!(
            "post-rotation, NEW token must NOT be rejected as invalid; got {post_new}{diagnostic}\nold_token={old_token}\nnew_token={new_token}"
        );
    }

    let _ = daemon_v2.wait_with_output();
}

/// Story 7.7 Task 10 diagnostic: walk the test home dir and dump
/// agent file contents + keystore-test presence so a CI-only failure
/// surfaces forensic data instead of a bare panic message. Called
/// from the auth-round-trip test on either the pre-rotation or
/// post-rotation auth-invalid_token assert.
fn collect_test_home_diagnostic(home: &std::path::Path, label: &str) -> String {
    let mut out = format!("\n=== DIAGNOSTIC: {label} ===\n");
    out.push_str(&format!("home: {}\n", home.display()));
    out.push_str("\n--- home dir tree ---\n");
    for entry in walkdir::WalkDir::new(home).into_iter().flatten() {
        let path = entry.path();
        let rel = path.strip_prefix(home).unwrap_or(path);
        let kind = if path.is_dir() {
            "DIR".to_string()
        } else {
            format!("FILE ({} bytes)", path.metadata().map(|m| m.len()).unwrap_or(0))
        };
        out.push_str(&format!("  {} {}\n", kind, rel.display()));
    }
    // Dump agent file contents (TOML, no secrets — lookup_key_hex
    // and token_hash are non-reversible).
    let agents_dir = home.join("agents");
    if agents_dir.exists() {
        out.push_str("\n--- agents/ contents ---\n");
        for entry in std::fs::read_dir(&agents_dir).into_iter().flatten().flatten() {
            let p = entry.path();
            if let Ok(s) = std::fs::read_to_string(&p) {
                out.push_str(&format!("  === {} ===\n", p.display()));
                for line in s.lines() {
                    out.push_str(&format!("    {line}\n"));
                }
            }
        }
    }
    // Dump rotate-key-output files (mode-0o600 token files written
    // by Phase E.5; safe to dump because the test environment is
    // throwaway and the diagnostic is the only path to root-cause
    // a CI-only auth failure).
    out.push_str("\n--- rotate-key-output.* files ---\n");
    for entry in std::fs::read_dir(home).into_iter().flatten().flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("rotate-key-output.") {
            let p = entry.path();
            if let Ok(s) = std::fs::read_to_string(&p) {
                out.push_str(&format!("  === {} ===\n", p.display()));
                for line in s.lines() {
                    out.push_str(&format!("    {line}\n"));
                }
            }
        }
    }
    // Dump keystore-test/ presence (NOT contents — those are
    // raw key bytes).
    let ks_dir = home.join("keystore-test");
    if ks_dir.exists() {
        out.push_str("\n--- keystore-test/ presence ---\n");
        for entry in std::fs::read_dir(&ks_dir).into_iter().flatten().flatten() {
            let p = entry.path();
            let len = p.metadata().map(|m| m.len()).unwrap_or(0);
            out.push_str(&format!("  {} ({} bytes)\n", p.display(), len));
        }
    }
    // Dump daemon log tail — the auth handler's tracing emit (denied
    // tokens, registry-rebuild stale-warns) gives us the missing
    // forensic data for register-time vs auth-time subkey divergence.
    let log_path = home.join("logs/daemon.log");
    if log_path.exists() {
        out.push_str("\n--- logs/daemon.log (last 100 lines) ---\n");
        if let Ok(s) = std::fs::read_to_string(&log_path) {
            let lines: Vec<&str> = s.lines().collect();
            let start = lines.len().saturating_sub(100);
            for line in &lines[start..] {
                out.push_str(&format!("    {line}\n"));
            }
        }
    }
    out
}

/// Register an agent via the loopback control endpoint and return
/// the bearer token. Mirrors `agent_registry_e2e.rs::register_agent`
/// but inlined here so this file is self-contained per the round-1
/// helper-discipline fence (each integration file may have its own
/// thin wrappers if they don't duplicate canonical logic).
fn register_agent(port: u16, name: &str, policy: &str) -> String {
    let body = format!(r#"{{"name":"{name}","policy_name":"{policy}"}}"#);
    let (status, resp_body) = http_post_loopback(port, "/v1/control/agent/register", &body);
    assert_eq!(
        status, 200,
        "agent register should succeed for {name} → {policy}, got {status}: {resp_body}"
    );
    let json: serde_json::Value = serde_json::from_str(&resp_body).unwrap();
    json["bearer_token"].as_str().unwrap().to_owned()
}

/// Make an authenticated GET against a tool route and return the
/// JSON `error.code` if present, or "ok" otherwise. Returning the
/// code (not the status) lets callers branch on auth-vs-policy-vs-
/// upstream errors uniformly.
fn authed_get_status(port: u16, token: &str) -> String {
    let auth_header = format!("Bearer {token}");
    let (status, body) = http_get_loopback(
        port,
        "/v1/tools/gmail/users/me",
        &[("authorization", auth_header.as_str())],
    );
    if status == 200 {
        return "ok".into();
    }
    let json: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    json["error"]["code"].as_str().unwrap_or("unknown").to_owned()
}

/// Read the rotate-key-output.<pid> file and extract the rerolled
/// bearer token for the named agent. Format is
/// `<agent_name>=<token>` per line.
fn read_new_token_for_agent(home: &std::path::Path, agent_name: &str) -> String {
    let candidates: Vec<_> = std::fs::read_dir(home)
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with("rotate-key-output."))
        .collect();
    assert!(!candidates.is_empty(), "rotate-key-output.* file must exist post-rotation");
    let path = home.join(&candidates[0]);
    let body = std::fs::read_to_string(path).unwrap();
    let prefix = format!("{agent_name}=");
    body.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(|s| s.to_owned())
        .unwrap_or_else(|| panic!("tokens file missing line for {agent_name}; contents:\n{body}"))
}

fn http_get_loopback(port: u16, path: &str, headers: &[(&str, &str)]) -> (u16, String) {
    http_request(port, "GET", path, headers, None)
}

fn http_post_loopback(port: u16, path: &str, body: &str) -> (u16, String) {
    http_request(port, "POST", path, &[], Some(body))
}

fn http_request(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> (u16, String) {
    let mut stream = std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_secs(2),
    )
    .expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let body_str = body.unwrap_or("");
    let mut req =
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n");
    if body.is_some() {
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body_str.len()
        ));
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    if !body_str.is_empty() {
        req.push_str(body_str);
    }
    stream.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let raw = String::from_utf8_lossy(&buf).to_string();
    let status = raw.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
    let resp_body = raw.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    (status, resp_body)
}
