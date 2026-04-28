//! End-to-end integration tests for the Story 6.3 plugin loader +
//! the `agentsso connectors list` CLI.
//!
//! Boots the real `agentsso` binary against an ephemeral home
//! directory, verifies that built-in connectors register and user-
//! installed plugins load (or are skipped) per the `[plugins]`
//! configuration. The harness pattern mirrors
//! `agent_registry_e2e.rs` (master-key test seam,
//! `AGENTSSO_PATHS__HOME` override, subprocess lifecycle).
//!
//! # What this covers
//!
//! - AC #15 — daemon boot populates `AppState.plugin_registry`
//!   with the three built-ins (observed via `/health`'s
//!   `connectors_registered` field).
//! - AC #15 (half) — user-installed plugin loads alongside
//!   built-ins.
//! - AC #16 + #28 — `agentsso connectors list` renders a table
//!   with the three built-in rows.
//! - AC #17 — `agentsso connectors list --json` emits valid JSON.
//! - AC #24 — `AGENTSSO_TEST_TRUST_PROMPT_CANNED_RESPONSES`
//!   drives the prompt path deterministically.

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::common::{agentsso_bin, free_port};

const TEST_MASTER_KEY_HEX: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Start the daemon with `AGENTSSO_PLUGINS__WARN_ON_FIRST_LOAD=false`
/// so the loader never blocks on a missing TTY during tests.
fn start_daemon_headless(home: &std::path::Path, port: u16) -> Child {
    Command::new(agentsso_bin())
        .arg("start")
        .arg("--bind-addr")
        .arg(format!("127.0.0.1:{port}"))
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .env("AGENTSSO_TEST_MASTER_KEY_HEX", TEST_MASTER_KEY_HEX)
        // Headless: user-installed plugins load as warn-user
        // without prompting. Built-ins are always auto-trusted
        // via the default config.
        .env("AGENTSSO_PLUGINS__WARN_ON_FIRST_LOAD", "false")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start daemon")
}

/// Start the daemon with canned trust-prompt responses (Story 6.3
/// AC #24 test seam). Used by `test_seam_drives_two_plugins_deterministically`.
fn start_daemon_with_canned_trust(home: &std::path::Path, port: u16, canned: &str) -> Child {
    Command::new(agentsso_bin())
        .arg("start")
        .arg("--bind-addr")
        .arg(format!("127.0.0.1:{port}"))
        .env("AGENTSSO_PATHS__HOME", home.to_str().unwrap())
        .env("AGENTSSO_TEST_MASTER_KEY_HEX", TEST_MASTER_KEY_HEX)
        .env("AGENTSSO_TEST_TRUST_PROMPT_CANNED_RESPONSES", canned)
        // warn_on_first_load stays at the default `true` so the
        // prompt path exercises the canned reader.
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start daemon")
}

fn wait_for_health_with_registry(port: u16, timeout: Duration) -> Option<u32> {
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
            if let Some(body_start) = response.find("\r\n\r\n") {
                let body = &response[body_start + 4..];
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(body)
                    && json["status"].as_str() == Some("healthy")
                {
                    let registered = json["connectors_registered"].as_u64().unwrap_or(0);
                    return Some(registered as u32);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn write_user_plugin(home: &std::path::Path, name: &str, source: &str) {
    let dir = home.join("plugins").join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("index.js"), source).unwrap();
}

fn minimal_plugin_source(name: &str) -> String {
    format!(
        "export const metadata = {{\n\
             name: \"{name}\",\n\
             version: \"1.0.0\",\n\
             apiVersion: \">=1.0\",\n\
             scopes: [\"test.readonly\"],\n\
             description: \"e2e test plugin\",\n\
         }};\n"
    )
}

// ---------- AC #15 (built-ins only) ----------

#[test]
fn boot_with_only_builtins_registers_three() {
    let tmp = tempfile::TempDir::new().unwrap();
    let port = free_port();
    let mut child = start_daemon_headless(tmp.path(), port);
    let registered = wait_for_health_with_registry(port, Duration::from_secs(10));
    // Shut down cleanly.
    let _ = child.kill();
    let _ = child.wait();

    let registered = registered.expect("daemon did not reach healthy state");
    assert_eq!(
        registered, 3,
        "fresh daemon with no user plugins must register exactly 3 built-ins"
    );
}

// ---------- AC #15 (user-installed) ----------

#[test]
fn boot_with_user_installed_plugin_registers_four() {
    let tmp = tempfile::TempDir::new().unwrap();
    write_user_plugin(tmp.path(), "notion", &minimal_plugin_source("notion"));

    let port = free_port();
    let mut child = start_daemon_headless(tmp.path(), port);
    let registered = wait_for_health_with_registry(port, Duration::from_secs(10));
    let _ = child.kill();
    let _ = child.wait();

    let registered = registered.expect("daemon did not reach healthy state");
    assert_eq!(registered, 4, "3 built-ins + 1 user-installed");
}

// ---------- AC #24 (canned trust prompt seam) ----------

#[test]
fn test_seam_drives_two_plugins_deterministically() {
    // Two user-installed plugins; canned decisions: Always for
    // the first, Never for the second. Expect 3 built-ins + 1
    // trusted-user = 4 total. `.trusted` must be written with
    // the first plugin's entry.
    let tmp = tempfile::TempDir::new().unwrap();
    // Plugins traversed alphabetically by the loader, so name
    // them so the ordering is predictable.
    write_user_plugin(tmp.path(), "aaa-first", &minimal_plugin_source("aaa-first"));
    write_user_plugin(tmp.path(), "zzz-last", &minimal_plugin_source("zzz-last"));

    let port = free_port();
    let mut child = start_daemon_with_canned_trust(tmp.path(), port, "always,never");
    let registered = wait_for_health_with_registry(port, Duration::from_secs(10));
    let _ = child.kill();
    let _ = child.wait();

    let registered = registered.expect("daemon did not reach healthy state");
    assert_eq!(registered, 4, "3 built-ins + 1 trusted (second plugin was denied via Never)");

    // `.trusted` must contain exactly one entry for aaa-first.
    let trusted_path = tmp.path().join("plugins").join(".trusted");
    let contents = std::fs::read_to_string(&trusted_path)
        .expect(".trusted must exist after TrustDecision::Always");
    // Strip comments + blanks; count non-empty lines.
    let entry_count =
        contents.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).count();
    assert_eq!(entry_count, 1, "only the Always plugin persists");
    assert!(contents.contains("aaa-first"), "aaa-first must appear in .trusted");
    assert!(!contents.contains("zzz-last"), "zzz-last was denied, must NOT be in .trusted");
}

// ---------- AC #14 (env-var figment override) ----------

#[test]
fn plugins_env_override() {
    // AGENTSSO_PLUGINS__WARN_ON_FIRST_LOAD=false flows through
    // figment into DaemonConfig.plugins.warn_on_first_load. Exercised
    // via the live boot path: with warn_on_first_load = false, a
    // user-installed plugin loads as warn-user (connectors_registered
    // == 4) without any interactive prompt.
    //
    // This is an explicit named test so a future regression that
    // breaks the env-var pipeline for `[plugins]` fails here rather
    // than silently changing tier assignments.
    let tmp = tempfile::TempDir::new().unwrap();
    write_user_plugin(tmp.path(), "env-test-plugin", &minimal_plugin_source("env-test-plugin"));

    let port = free_port();
    // start_daemon_headless already sets AGENTSSO_PLUGINS__WARN_ON_FIRST_LOAD=false.
    let mut child = start_daemon_headless(tmp.path(), port);
    let registered = wait_for_health_with_registry(port, Duration::from_secs(10));
    let _ = child.kill();
    let _ = child.wait();

    let registered = registered.expect("daemon did not reach healthy state");
    assert_eq!(
        registered, 4,
        "env var must propagate into plugins.warn_on_first_load (otherwise the prompt would block)"
    );
}

// ---------- AC #28 strengthening (exact row count) ----------
// moved to connectors_list_e2e.rs where the CLI output is available
