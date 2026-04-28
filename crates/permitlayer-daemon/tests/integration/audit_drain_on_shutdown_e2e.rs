//! Integration test: audit dispatcher drain on graceful shutdown (Story 8.2).
//!
//! Forensic durability acceptance gate. Exercises the scenario where
//! the scenario matters most:
//!
//! 1. Start the daemon with a functional audit store.
//! 2. Activate the kill switch via `POST /v1/control/kill`.
//! 3. Fire a burst of requests that each generate a
//!    `kill-blocked-request` audit event (pre-Story-8.2 via
//!    fire-and-forget `tokio::spawn`; Story 8.2 via the owned
//!    `AuditDispatcher`).
//! 4. Send SIGTERM and wait for graceful shutdown.
//! 5. Assert every dispatched audit event reached disk.
//!
//! Pre-Story-8.2 this test would be flaky / intermittently lose the
//! tail of the event burst because the `tokio::spawn`ed tasks were
//! orphaned when the 30-second graceful-shutdown deadline fired.

use crate::common::{DaemonTestConfig, free_port, http_get, start_daemon, wait_for_health};

use std::time::Duration;

/// Parse every `.jsonl` file under `<home>/audit/` and return all
/// events whose `event_type` matches.
fn count_events_of_type(home: &std::path::Path, event_type: &str) -> usize {
    let audit_dir = home.join("audit");
    if !audit_dir.exists() {
        return 0;
    }
    let mut count = 0;
    for entry in std::fs::read_dir(&audit_dir).unwrap().flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("jsonl") {
            continue;
        }
        let contents = std::fs::read_to_string(&path).unwrap();
        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if v.get("event_type").and_then(|s| s.as_str()) == Some(event_type) {
                count += 1;
            }
        }
    }
    count
}

/// Send N blocked requests. We use `/health` because kill-switch is
/// enforced at the kill layer which runs BEFORE auth — so no bearer
/// token is needed and every request gets a clean 403 +
/// `kill-blocked-request` audit event.
fn fire_blocked_requests(port: u16, count: usize) {
    for _ in 0..count {
        let (status, _body) = http_get(port, "/health");
        assert_eq!(status, 403, "expected 403 while kill switch is active");
    }
}

#[cfg(unix)]
#[test]
fn audit_drain_on_shutdown_preserves_all_blocked_events() {
    let home = tempfile::tempdir().unwrap();
    let port = free_port();
    let mut daemon = start_daemon(DaemonTestConfig {
        port,
        home: home.path().to_path_buf(),
        ..Default::default()
    });
    assert!(wait_for_health(port), "daemon should boot");

    // Activate the kill switch via the CLI over loopback. The control
    // endpoint is POST /v1/control/kill (non-idempotent; returns 200
    // on first activation, 409 on subsequent if already active).
    let (status, body) = crate::common::http_post(port, "/v1/control/kill", None);
    assert_eq!(status, 200, "kill activation failed: {body}");

    // Fire a burst of blocked requests. 50 is enough to exercise the
    // dispatcher under sustained load while keeping the test under 10s.
    // The pre-Story-8.2 failure mode would see ~10-20% of these lost
    // on fast shutdown; the drain ensures 100%.
    const BURST: usize = 50;
    fire_blocked_requests(port, BURST);

    // Graceful shutdown — SIGTERM with a 10-second deadline. The daemon's
    // shutdown sequence drains the audit dispatcher (5s budget) BEFORE
    // the 30-second hard deadline fires.
    let exited = daemon.shutdown_graceful(Duration::from_secs(10));
    assert!(exited, "daemon did not exit within the graceful deadline");

    let n = count_events_of_type(home.path(), "kill-blocked-request");
    assert_eq!(
        n, BURST,
        "expected {BURST} kill-blocked-request events on disk after graceful shutdown, got {n}"
    );
}
