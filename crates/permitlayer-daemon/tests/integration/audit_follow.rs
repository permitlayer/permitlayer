//! Integration test: `agentsso audit --follow` (Story 1.9 + 5.2).
//!
//! Covers:
//! - **Story 1.9 / 2.4 / 2.6 regression**:
//!   `audit_follow_renders_scrub_inline_for_v2_sample` — the v2 OTP
//!   scrub sample must continue to render through the new Story 5.2
//!   notify-based watcher pipeline without visual regression.
//! - **Story 5.2 new coverage**: live-tail via notify, rotation
//!   mid-stream, filter-narrowed follow, `--since` replay-then-follow,
//!   `--until` + `--follow` rejection, broken-pipe clean exit, Ctrl-C
//!   clean exit.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use permitlayer_core::audit::event::{AUDIT_SCHEMA_VERSION, AuditEvent, format_audit_timestamp};

fn v2_otp_audit_line() -> String {
    let json = serde_json::json!({
        "timestamp": "2026-04-09T14:23:07.142Z",
        "request_id": "01HXXXTESTULID0000000000",
        "agent_id": "openclaw-inbox",
        "service": "gmail",
        "scope": "gmail.readonly",
        "resource": "users/me/messages/abc",
        "outcome": "ok",
        "event_type": "api-call",
        "schema_version": 2,
        "extra": {
            "scrub_events": {
                "summary": { "otp-6digit": 1 },
                "samples": [
                    {
                        "rule": "otp-6digit",
                        "snippet": "Your verification code is <REDACTED_OTP>",
                        "placeholder_offset": 26,
                        "placeholder_len": 14
                    }
                ]
            }
        }
    });
    serde_json::to_string(&json).unwrap()
}

/// Maximum time to wait for the subprocess to render the expected
/// output before we give up and fail the test. Generous for CI.
const RENDER_DEADLINE: Duration = Duration::from_secs(15);

/// Poll interval between stdout checks while waiting for the rendered
/// output marker to appear.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Shut-down deadline once the render is observed (or the render
/// deadline expires): how long we wait for the subprocess to exit
/// gracefully after SIGTERM before escalating to SIGKILL.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);

/// Owns the background pipe-drainer threads and their shared output
/// buffers for a spawned subprocess. Returned by [`drain_child_streams`]
/// so the main test thread can poll `stdout_buf` for partial output
/// and later join both threads during shutdown.
struct ChildStreams {
    stdout_buf: Arc<Mutex<String>>,
    stderr_buf: Arc<Mutex<String>>,
    stdout_handle: std::thread::JoinHandle<()>,
    stderr_handle: std::thread::JoinHandle<()>,
}

/// Drain stdout/stderr into shared buffers on background threads.
fn drain_child_streams(child: &mut Child) -> ChildStreams {
    let stdout_buf = Arc::new(Mutex::new(String::new()));
    let stderr_buf = Arc::new(Mutex::new(String::new()));

    let mut child_stdout = child.stdout.take().expect("stdout piped");
    let mut child_stderr = child.stderr.take().expect("stderr piped");

    let stdout_buf_tx = Arc::clone(&stdout_buf);
    let stdout_handle = std::thread::spawn(move || {
        // Read in small chunks so the main thread can observe partial
        // output via the shared buffer before the pipe is closed.
        let mut chunk = [0u8; 1024];
        loop {
            match child_stdout.read(&mut chunk) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if let Ok(mut buf) = stdout_buf_tx.lock() {
                        buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
                    }
                }
                Err(_) => break,
            }
        }
    });

    let stderr_buf_tx = Arc::clone(&stderr_buf);
    let stderr_handle = std::thread::spawn(move || {
        let mut chunk = [0u8; 1024];
        loop {
            match child_stderr.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if let Ok(mut buf) = stderr_buf_tx.lock() {
                        buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
                    }
                }
                Err(_) => break,
            }
        }
    });

    ChildStreams { stdout_buf, stderr_buf, stdout_handle, stderr_handle }
}

/// Send SIGTERM to the subprocess. Caller must still call
/// `shutdown_and_join` to enforce the shutdown deadline.
fn send_sigterm(child: &Child) {
    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        let pid = Pid::from_raw(child.id() as i32);
        let _ = kill(pid, Signal::SIGTERM);
    }
    #[cfg(not(unix))]
    {
        // On Windows, SIGTERM is not available. Fall back to kill
        // (which is SIGKILL-equivalent); the SIGPIPE vs flush concern
        // doesn't apply because Windows pipes close differently.
        let _ = child.kill();
    }
}

/// Send SIGINT to the subprocess — the actual signal that
/// `tokio::signal::ctrl_c()` is wired to. Unix-only; Windows has no
/// direct SIGINT equivalent for this test scaffold.
///
/// P5 review patch: the existing `send_sigterm` helper doesn't
/// exercise the `ctrl_c` branch of the `tokio::select!` in
/// `run_follow`, because tokio listens for SIGINT, not SIGTERM.
/// Sending SIGTERM causes the process to exit via tokio's default
/// runtime-drop handling, not via the clean-exit `println!(); Ok(())`
/// path. This helper targets the real Ctrl-C code path.
#[cfg(unix)]
fn send_sigint(child: &Child) {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;
    let pid = Pid::from_raw(child.id() as i32);
    let _ = kill(pid, Signal::SIGINT);
}

/// Wait for the child to exit with a deadline. If it doesn't exit in
/// time, escalate to `kill()` (SIGKILL on Unix) to guarantee the test
/// runner never hangs indefinitely. Returns when the child has exited.
fn shutdown_and_join(
    child: &mut Child,
    stdout_handle: std::thread::JoinHandle<()>,
    stderr_handle: std::thread::JoinHandle<()>,
) {
    let deadline = Instant::now() + SHUTDOWN_DEADLINE;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break, // exited
            Ok(None) => {
                if Instant::now() >= deadline {
                    // Graceful SIGTERM didn't take — escalate.
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
        }
    }
    // Drain threads exit when the child closes its pipes. Join with a
    // small extra grace window; if they're still blocked (stuck read),
    // we've already force-killed the child so the pipe MUST close.
    let _ = stdout_handle.join();
    let _ = stderr_handle.join();
}

/// Spawn `agentsso audit --follow` against a tempdir with a pre-seeded
/// audit file, poll stdout until the ScrubInline render marker appears,
/// then shut down the subprocess with a bounded deadline. The test
/// fails loudly on timeout rather than hanging the CI runner.
#[test]
fn audit_follow_renders_scrub_inline_for_v2_sample() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let home = tmp.path();
    let audit_dir = home.join("audit");
    std::fs::create_dir_all(&audit_dir).expect("mkdir audit");

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let audit_file = audit_dir.join(format!("{today}.jsonl"));

    // Seed with an existing event (the follow loop seeks to end on start,
    // so we also append a new event after spawning).
    std::fs::write(&audit_file, "").expect("touch audit file");

    // Spawn the follow subprocess.
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentsso"))
        .args(["audit", "--follow"])
        .env("AGENTSSO_PATHS__HOME", home.as_os_str())
        .env("NO_COLOR", "1") // make stdout deterministic and ANSI-free
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agentsso audit --follow");

    let ChildStreams { stdout_buf, stderr_buf, stdout_handle, stderr_handle } =
        drain_child_streams(&mut child);

    // Give the subprocess enough time to start, open the file, and
    // seek to end. Cold-cache cargo-test subprocess spawn latency on
    // macOS CI parallel runners can exceed 1s; use 1.5s baseline.
    // We'll append AFTER this so the poll loop picks up the new line
    // (it seeks to End(0) on startup, so pre-seeded lines are NOT
    // replayed).
    std::thread::sleep(Duration::from_millis(1500));

    // Append a v2 OTP line that should trigger ScrubInline rendering.
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&audit_file)
            .expect("open audit file for append");
        writeln!(f, "{}", v2_otp_audit_line()).expect("write audit line");
        f.sync_all().expect("sync audit file");
    }

    // Poll stdout until the render marker appears OR the deadline
    // expires. The marker is the `<REDACTED_OTP>` substring — its
    // presence proves the follow loop saw the line AND the ScrubInline
    // renderer ran successfully.
    let render_deadline = Instant::now() + RENDER_DEADLINE;
    let mut seen_marker = false;
    while Instant::now() < render_deadline {
        if let Ok(buf) = stdout_buf.lock()
            && buf.contains("<REDACTED_OTP>")
        {
            seen_marker = true;
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }

    // Gracefully shut down regardless of whether we saw the marker.
    // `shutdown_and_join` enforces a bounded deadline and escalates
    // SIGTERM → SIGKILL if the child doesn't respond.
    send_sigterm(&child);
    shutdown_and_join(&mut child, stdout_handle, stderr_handle);

    let stdout = stdout_buf.lock().map(|b| b.clone()).unwrap_or_default();
    let stderr = stderr_buf.lock().map(|b| b.clone()).unwrap_or_default();

    assert!(
        seen_marker,
        "render marker never appeared within {RENDER_DEADLINE:?}; \
         stdout={stdout:?}; stderr={stderr:?}"
    );
    assert!(
        stdout.contains("<REDACTED_OTP>"),
        "stdout should contain REDACTED_OTP; stdout={stdout:?}; stderr={stderr:?}"
    );
    assert!(
        stdout.contains("caught: otp-6digit"),
        "stdout should contain caught label; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("why? \u{2192} agentsso scrub explain otp-6digit"),
        "stdout should contain why? affordance; stdout={stdout:?}"
    );
    // Box border char
    assert!(stdout.contains('\u{250C}'), "stdout should contain ┌; stdout={stdout:?}");
}

/// Story 5.1 migration: `agentsso audit` (without `--follow`) now
/// runs the historical query path. Against a tempdir with no audit
/// directory, it should print a structured `audit_dir_missing` error
/// block and exit non-zero. (Before Story 5.1 this command exited
/// with an `audit_query_not_implemented` stub — see the commit
/// history for the rename.)
#[test]
fn audit_query_returns_audit_dir_missing_on_fresh_tempdir() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let output = Command::new(env!("CARGO_BIN_EXE_agentsso"))
        .args(["audit"])
        .env("AGENTSSO_PATHS__HOME", tmp.path().as_os_str())
        .env("NO_COLOR", "1")
        .output()
        .expect("run agentsso audit");

    assert!(!output.status.success(), "audit query against missing audit dir should exit non-zero");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("audit_dir_missing"), "stderr should contain error_code: {stderr}");
    assert!(stderr.contains("agentsso start"), "stderr should contain remediation: {stderr}");
}

/// `agentsso audit --follow` against an empty audit dir should render
/// the empty-state block and exit cleanly (no tail loop).
#[test]
fn audit_follow_prints_empty_state_when_no_file() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let output = Command::new(env!("CARGO_BIN_EXE_agentsso"))
        .args(["audit", "--follow"])
        .env("AGENTSSO_PATHS__HOME", tmp.path().as_os_str())
        .env("NO_COLOR", "1")
        .output()
        .expect("run agentsso audit --follow");

    assert!(output.status.success(), "empty-state should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("no audit events yet for today"), "stdout: {stdout}");
    assert!(stdout.contains("agentsso start"), "stdout should contain start hint: {stdout}");
}

// ──────────────────────────────────────────────────────────────────
// Story 5.2 new coverage
// ──────────────────────────────────────────────────────────────────

/// Append one synthetic `api-call` event to today's audit file inside
/// `audit_dir`. Creates the file and parent dirs if needed. Used by
/// the Story 5.2 notify-watcher integration tests.
fn append_event(audit_dir: &Path, service: &str, outcome: &str, event_type: &str, agent: &str) {
    std::fs::create_dir_all(audit_dir).expect("mkdir audit");
    let now = chrono::Utc::now();
    let filename = format!("{}.jsonl", now.format("%Y-%m-%d"));
    let path = audit_dir.join(&filename);

    let mut event = AuditEvent::new(
        agent.to_owned(),
        service.to_owned(),
        "mail.readonly".to_owned(),
        format!("messages/{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)),
        outcome.to_owned(),
        event_type.to_owned(),
    );
    event.timestamp = format_audit_timestamp(now);
    event.schema_version = AUDIT_SCHEMA_VERSION;

    let line = serde_json::to_string(&event).unwrap();
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("open audit file for append");
    writeln!(f, "{line}").expect("write audit line");
    f.sync_all().expect("sync audit file");
}

/// Poll `stdout_buf` until `predicate` returns true or the render
/// deadline expires. Returns whether the predicate ever matched.
fn wait_for_stdout(stdout_buf: &Arc<Mutex<String>>, predicate: impl Fn(&str) -> bool) -> bool {
    let deadline = Instant::now() + RENDER_DEADLINE;
    while Instant::now() < deadline {
        if let Ok(buf) = stdout_buf.lock()
            && predicate(&buf)
        {
            return true;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    false
}

/// AC #1 + #2: the Story 5.2 `notify`-based watcher replaces the
/// 250 ms polling stub and observes new events appended by the writer.
/// This is the "watcher is wired up" smoke test — if this passes, the
/// notify crate integration is functional end-to-end for a simple
/// append.
#[test]
fn follow_streams_new_events_via_notify_watcher() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let home = tmp.path();
    let audit_dir = home.join("audit");
    std::fs::create_dir_all(&audit_dir).expect("mkdir audit");

    // Pre-seed with an existing file so the watcher resolves an
    // active_file on startup (the watcher will seek to end, so
    // pre-existing events won't be re-rendered).
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let audit_file = audit_dir.join(format!("{today}.jsonl"));
    std::fs::write(&audit_file, "").expect("touch audit file");

    let mut child = Command::new(env!("CARGO_BIN_EXE_agentsso"))
        .args(["audit", "--follow"])
        .env("AGENTSSO_PATHS__HOME", home.as_os_str())
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agentsso audit --follow");

    let ChildStreams { stdout_buf, stderr_buf, stdout_handle, stderr_handle } =
        drain_child_streams(&mut child);

    // Give the watcher time to initialize.
    std::thread::sleep(Duration::from_millis(1500));

    // Append an event that the watcher should pick up.
    append_event(&audit_dir, "gmail", "ok", "api-call", "email-triage");

    // Wait for the event to render.
    let seen = wait_for_stdout(&stdout_buf, |s| s.contains("gmail") && s.contains("api-call"));

    send_sigterm(&child);
    shutdown_and_join(&mut child, stdout_handle, stderr_handle);

    let stdout = stdout_buf.lock().map(|b| b.clone()).unwrap_or_default();
    let stderr = stderr_buf.lock().map(|b| b.clone()).unwrap_or_default();
    assert!(
        seen,
        "expected notify watcher to render new event; stdout={stdout:?}; stderr={stderr:?}"
    );
}

/// AC #3: filter flags apply to the live-tail stream. `--service=gmail`
/// should cause `calendar` events to be dropped.
#[test]
fn follow_filter_service_narrows_stream() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let home = tmp.path();
    let audit_dir = home.join("audit");
    std::fs::create_dir_all(&audit_dir).expect("mkdir audit");

    // Pre-seed so the watcher has an active file.
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let audit_file = audit_dir.join(format!("{today}.jsonl"));
    std::fs::write(&audit_file, "").expect("touch audit file");

    let mut child = Command::new(env!("CARGO_BIN_EXE_agentsso"))
        .args(["audit", "--follow", "--service=gmail"])
        .env("AGENTSSO_PATHS__HOME", home.as_os_str())
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agentsso audit --follow --service=gmail");

    let ChildStreams { stdout_buf, stderr_buf, stdout_handle, stderr_handle } =
        drain_child_streams(&mut child);

    std::thread::sleep(Duration::from_millis(1500));

    // Interleave gmail + calendar events. Filter should let gmail
    // through and drop calendar.
    append_event(&audit_dir, "gmail", "ok", "api-call", "email-triage");
    append_event(&audit_dir, "calendar", "ok", "api-call", "calendar-sync");
    append_event(&audit_dir, "gmail", "denied", "policy-violation", "email-triage");

    // Wait for at least one gmail event to appear.
    let seen_gmail = wait_for_stdout(&stdout_buf, |s| s.contains("gmail"));
    // Give calendar a little more time to NOT appear (negative
    // assertion requires letting the watcher drain).
    std::thread::sleep(Duration::from_millis(500));

    send_sigterm(&child);
    shutdown_and_join(&mut child, stdout_handle, stderr_handle);

    let stdout = stdout_buf.lock().map(|b| b.clone()).unwrap_or_default();
    let stderr = stderr_buf.lock().map(|b| b.clone()).unwrap_or_default();
    assert!(
        seen_gmail,
        "expected gmail event to render through filter; stdout={stdout:?}; stderr={stderr:?}"
    );
    assert!(
        !stdout.contains("calendar"),
        "calendar event should be filtered out; stdout={stdout:?}"
    );
}

/// AC #2 (rotation) + deferred-work.md:92 closure: rotating the
/// active file mid-stream (renaming `YYYY-MM-DD.jsonl` →
/// `YYYY-MM-DD-1.jsonl` and creating a fresh active file) must not
/// drop events. Before Story 5.2, the 250 ms polling stub kept the
/// original file handle open forever and silently missed every
/// post-rotation event.
#[test]
fn follow_handles_rotation_mid_stream() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let home = tmp.path();
    let audit_dir = home.join("audit");
    std::fs::create_dir_all(&audit_dir).expect("mkdir audit");

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let active_file = audit_dir.join(format!("{today}.jsonl"));
    std::fs::write(&active_file, "").expect("touch audit file");

    let mut child = Command::new(env!("CARGO_BIN_EXE_agentsso"))
        .args(["audit", "--follow"])
        .env("AGENTSSO_PATHS__HOME", home.as_os_str())
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agentsso audit --follow");

    let ChildStreams { stdout_buf, stderr_buf, stdout_handle, stderr_handle } =
        drain_child_streams(&mut child);

    std::thread::sleep(Duration::from_millis(1500));

    // Append a pre-rotation event so we can confirm the watcher is
    // alive.
    append_event(&audit_dir, "gmail", "ok", "api-call", "pre-rotate");
    let seen_pre = wait_for_stdout(&stdout_buf, |s| s.contains("pre-rotate"));
    assert!(seen_pre, "pre-rotation event should render");

    // Simulate rotation: rename active → rotated-out, create fresh
    // active file, write a post-rotation event into it. This mirrors
    // what `AuditFsWriter` does on a 100 MB size trigger.
    let rotated = audit_dir.join(format!("{today}-1.jsonl"));
    std::fs::rename(&active_file, &rotated).expect("rotate file");
    std::fs::write(&active_file, "").expect("create new active file");

    // Give the watcher a moment to notice the rename + create.
    std::thread::sleep(Duration::from_millis(500));

    append_event(&audit_dir, "gmail", "ok", "api-call", "post-rotate");
    let seen_post = wait_for_stdout(&stdout_buf, |s| s.contains("post-rotate"));

    send_sigterm(&child);
    shutdown_and_join(&mut child, stdout_handle, stderr_handle);

    let stdout = stdout_buf.lock().map(|b| b.clone()).unwrap_or_default();
    let stderr = stderr_buf.lock().map(|b| b.clone()).unwrap_or_default();
    assert!(
        seen_post,
        "post-rotation event should render through new active file; \
         stdout={stdout:?}; stderr={stderr:?}"
    );
}

/// P1 review patch regression: rotation after the watcher has consumed
/// pre-rotation bytes (so `active_offset > 0`) must still catch
/// post-rotation events. Before the inode-check fix, the path-equality
/// short-circuit in `refresh_active_file` left `active_offset` stale,
/// and the new file's post-rotation bytes were silently skipped if they
/// didn't exceed the stale offset.
///
/// Differs from `follow_handles_rotation_mid_stream` in that this test
/// seeds MANY pre-rotation events (so `active_offset` is non-trivial)
/// and writes a SHORT post-rotation event (so the new file length is
/// smaller than the stale offset — the exact scenario the old
/// `file_len < active_offset` fallback would catch, but this time we're
/// also proving the inode check works independently).
#[test]
fn follow_rotation_with_nonzero_preroll_offset_catches_postroll_events() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let home = tmp.path();
    let audit_dir = home.join("audit");
    std::fs::create_dir_all(&audit_dir).expect("mkdir audit");

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let active_file = audit_dir.join(format!("{today}.jsonl"));
    std::fs::write(&active_file, "").expect("touch audit file");

    let mut child = Command::new(env!("CARGO_BIN_EXE_agentsso"))
        .args(["audit", "--follow"])
        .env("AGENTSSO_PATHS__HOME", home.as_os_str())
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agentsso audit --follow");

    let ChildStreams { stdout_buf, stderr_buf, stdout_handle, stderr_handle } =
        drain_child_streams(&mut child);

    std::thread::sleep(Duration::from_millis(1500));

    // Seed 10 pre-rotation events so `active_offset` advances to
    // something substantial (each event is ~250 bytes, so offset
    // lands in the 2.5KB range).
    for i in 0..10 {
        append_event(&audit_dir, "gmail", "ok", "api-call", &format!("preroll-{i}"));
    }
    let seen_last_preroll = wait_for_stdout(&stdout_buf, |s| s.contains("preroll-9"));
    assert!(seen_last_preroll, "all pre-rotation events should render");

    // Rotate: rename active → rotated-out, create NEW empty active
    // file, and immediately write ONE short event. On Unix, the new
    // file has a new inode — the inode check (P1 fix) should
    // invalidate the stale offset and read the new file from 0.
    let rotated = audit_dir.join(format!("{today}-1.jsonl"));
    std::fs::rename(&active_file, &rotated).expect("rotate file");
    std::fs::write(&active_file, "").expect("create new active file");

    std::thread::sleep(Duration::from_millis(500));

    append_event(&audit_dir, "gmail", "ok", "api-call", "postroll-only");
    let seen_postroll = wait_for_stdout(&stdout_buf, |s| s.contains("postroll-only"));

    send_sigterm(&child);
    shutdown_and_join(&mut child, stdout_handle, stderr_handle);

    let stdout = stdout_buf.lock().map(|b| b.clone()).unwrap_or_default();
    let stderr = stderr_buf.lock().map(|b| b.clone()).unwrap_or_default();
    assert!(
        seen_postroll,
        "post-rotation event must render even when pre-rotation offset was non-zero \
         (P1 review patch regression); stdout={stdout:?}; stderr={stderr:?}"
    );
}

/// AC #5: `--until` + `--follow` is explicitly rejected BEFORE the
/// watcher is constructed. The error block must mention `--until`,
/// exit code is non-zero, and the Story 5.1 `SilentCliError` H2 fix
/// guarantees there is NO duplicate `error: ...` trailer.
#[test]
fn follow_until_rejected_with_silent_error() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let audit_dir = tmp.path().join("audit");
    std::fs::create_dir_all(&audit_dir).expect("mkdir audit");

    let output = Command::new(env!("CARGO_BIN_EXE_agentsso"))
        .args(["audit", "--follow", "--until=1h"])
        .env("AGENTSSO_PATHS__HOME", tmp.path().as_os_str())
        .env("NO_COLOR", "1")
        .output()
        .expect("run agentsso audit --follow --until=1h");

    assert!(!output.status.success(), "--follow + --until should exit non-zero");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--until"), "stderr should mention --until: {stderr}");
    assert!(
        stderr.contains("not supported with --follow"),
        "stderr should mention unsupported combination: {stderr}"
    );
    // H2 regression lock: no duplicate generic error trailer. The
    // structured error_block should be the ONLY error output.
    // `main::anyhow_to_exit_code` sees the `SilentCliError` marker
    // in the chain and suppresses its own `eprintln!("error: {e:#}")`.
    assert!(
        !stderr.contains("\nerror:"),
        "stderr should not contain duplicate 'error:' trailer: {stderr}"
    );
}

/// AC #8 + P20 review patch: anomaly hint smoke test. Uses env-var
/// overrides via the figment double-underscore convention to shrink
/// the warmup window and multiplier threshold so the test runs in
/// finite time. Marked `#[ignore]` because subprocess rate-detector
/// timing is flaky on CI under parallel load; the 15 unit tests in
/// `audit_anomaly.rs` provide the primary coverage for the
/// `AnomalyDetector::observe` logic. This test is the "wiring is
/// connected" smoke that proves `emit_hint` actually writes the
/// amber hint line to stdout in a real subprocess.
///
/// Run manually with: `cargo test --test audit_follow --
/// --ignored follow_anomaly_hint_fires`.
#[cfg(unix)]
#[test]
#[ignore]
fn follow_anomaly_hint_fires_after_warmup_and_spike() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let home = tmp.path();
    let audit_dir = home.join("audit");
    std::fs::create_dir_all(&audit_dir).expect("mkdir audit");

    // Seed baseline traffic spread across a small time window so
    // the rolling-window accumulates non-zero buckets.
    for i in 0..5 {
        append_event(&audit_dir, "gmail", "ok", "api-call", &format!("baseline-{i}"));
    }

    let mut child = Command::new(env!("CARGO_BIN_EXE_agentsso"))
        .args(["audit", "--follow"])
        .env("AGENTSSO_PATHS__HOME", home.as_os_str())
        .env("NO_COLOR", "1")
        // Shrink timing so the test doesn't wait an hour for warmup.
        .env("AGENTSSO_AUDIT__ANOMALY__BASELINE_WARMUP_SECONDS", "60")
        .env("AGENTSSO_AUDIT__ANOMALY__BASELINE_MULTIPLIER", "2.0")
        .env("AGENTSSO_AUDIT__ANOMALY__COOLDOWN_SECONDS", "0")
        .env("AGENTSSO_AUDIT__ANOMALY__MIN_SAMPLES", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agentsso audit --follow");

    let ChildStreams { stdout_buf, stderr_buf, stdout_handle, stderr_handle } =
        drain_child_streams(&mut child);

    std::thread::sleep(Duration::from_millis(1500));

    // Burst a bunch of events to trigger the spike detector.
    for i in 0..50 {
        append_event(&audit_dir, "gmail", "ok", "api-call", &format!("spike-{i}"));
    }

    // Wait for the anomaly hint line.
    let seen_hint = wait_for_stdout(&stdout_buf, |s| {
        s.contains("anomaly:") && s.contains("gmail") && s.contains("baseline")
    });

    send_sigterm(&child);
    shutdown_and_join(&mut child, stdout_handle, stderr_handle);

    let stdout = stdout_buf.lock().map(|b| b.clone()).unwrap_or_default();
    let stderr = stderr_buf.lock().map(|b| b.clone()).unwrap_or_default();
    assert!(
        seen_hint,
        "anomaly hint should appear after warmup + spike; \
         stdout={stdout:?}; stderr={stderr:?}"
    );
}

/// AC #10 + P5 review patch: SIGINT must exercise the `ctrl_c` branch
/// of the `tokio::select!` in `run_follow` and exit cleanly with
/// status 0. The previous Ctrl-C coverage used SIGTERM, which doesn't
/// fire `tokio::signal::ctrl_c()` — processes exited via tokio's
/// default runtime-drop handling, not via the clean-exit
/// `println!(); Ok(())` path. This test targets the real code path.
#[cfg(unix)]
#[test]
fn follow_ctrl_c_clean_exit() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let home = tmp.path();
    let audit_dir = home.join("audit");
    std::fs::create_dir_all(&audit_dir).expect("mkdir audit");

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let audit_file = audit_dir.join(format!("{today}.jsonl"));
    std::fs::write(&audit_file, "").expect("touch audit file");

    let mut child = Command::new(env!("CARGO_BIN_EXE_agentsso"))
        .args(["audit", "--follow"])
        .env("AGENTSSO_PATHS__HOME", home.as_os_str())
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agentsso audit --follow");

    let ChildStreams { stdout_buf, stderr_buf, stdout_handle, stderr_handle } =
        drain_child_streams(&mut child);

    // Give the watcher time to initialize and enter the event loop.
    std::thread::sleep(Duration::from_millis(1500));

    // Append one event so we know the watcher is alive and the
    // process is inside the main select loop (vs. still in startup).
    append_event(&audit_dir, "gmail", "ok", "api-call", "ctrl-c-smoke");
    let seen = wait_for_stdout(&stdout_buf, |s| s.contains("ctrl-c-smoke"));
    assert!(seen, "watcher should render before SIGINT is sent");

    // Send SIGINT — the signal `tokio::signal::ctrl_c()` actually
    // listens for.
    send_sigint(&child);

    // Wait for clean exit with bounded deadline.
    let deadline = Instant::now() + SHUTDOWN_DEADLINE;
    let mut exit_status = None;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_status = Some(status);
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => break,
        }
    }
    if exit_status.is_none() {
        // Escalate so the test harness doesn't hang.
        let _ = child.kill();
        let _ = child.wait();
    }
    let _ = stdout_handle.join();
    let _ = stderr_handle.join();

    let stdout = stdout_buf.lock().map(|b| b.clone()).unwrap_or_default();
    let stderr = stderr_buf.lock().map(|b| b.clone()).unwrap_or_default();

    let status = exit_status.expect("child must exit within SHUTDOWN_DEADLINE after SIGINT");
    assert!(
        status.success(),
        "SIGINT should trigger clean exit with status 0; \
         status={status:?}; stdout={stdout:?}; stderr={stderr:?}"
    );
}

/// AC #4: `--follow --since=1h` replays matching historical events
/// BEFORE switching to live tail. Replay uses the same Story 5.1
/// `AuditReader::query` path the historical query uses, so replay
/// results should be visually identical to `agentsso audit --since=1h`
/// output.
#[test]
fn follow_since_replays_then_tails() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let home = tmp.path();
    let audit_dir = home.join("audit");
    std::fs::create_dir_all(&audit_dir).expect("mkdir audit");

    // Seed 3 historical events BEFORE starting follow.
    append_event(&audit_dir, "gmail", "ok", "api-call", "replay-1");
    append_event(&audit_dir, "gmail", "ok", "api-call", "replay-2");
    append_event(&audit_dir, "gmail", "denied", "policy-violation", "replay-3");

    let mut child = Command::new(env!("CARGO_BIN_EXE_agentsso"))
        .args(["audit", "--follow", "--since=1h"])
        .env("AGENTSSO_PATHS__HOME", home.as_os_str())
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agentsso audit --follow --since=1h");

    let ChildStreams { stdout_buf, stderr_buf, stdout_handle, stderr_handle } =
        drain_child_streams(&mut child);

    // Wait for all three replay events to render (by agent name,
    // which is unique per seed).
    let seen_replay = wait_for_stdout(&stdout_buf, |s| {
        s.contains("replay-1") && s.contains("replay-2") && s.contains("replay-3")
    });
    assert!(seen_replay, "all three replay events should render");

    // Now append a NEW event that arrived "after replay". The
    // seen_request_ids dedup should NOT skip this (different
    // request_id); the live tail should render it.
    std::thread::sleep(Duration::from_millis(500));
    append_event(&audit_dir, "gmail", "ok", "api-call", "live-tail");
    let seen_live = wait_for_stdout(&stdout_buf, |s| s.contains("live-tail"));

    send_sigterm(&child);
    shutdown_and_join(&mut child, stdout_handle, stderr_handle);

    let stdout = stdout_buf.lock().map(|b| b.clone()).unwrap_or_default();
    let stderr = stderr_buf.lock().map(|b| b.clone()).unwrap_or_default();
    assert!(
        seen_live,
        "live-tail event should render after replay; stdout={stdout:?}; stderr={stderr:?}"
    );
}

/// AC #14: broken-pipe discipline. `agentsso audit --follow | head -n 3`
/// should render the first replay row(s), have `head` close its read
/// end, and have `agentsso` detect EPIPE on the next write and exit
/// cleanly — NOT panic, SIGPIPE-die, or deadlock.
///
/// Test strategy: seed enough replay events that the pipeline produces
/// more rows than `head` wants. `head` closes after its 3-line quota
/// is satisfied; `agentsso` then notices BrokenPipe on its next
/// `write!` and returns `Ok(())` via the `WriteStatus::BrokenPipe`
/// propagation path.
#[cfg(unix)]
#[test]
fn follow_broken_pipe_exits_cleanly() {
    use std::process::Stdio;

    let tmp = tempfile::tempdir().expect("create tempdir");
    let home = tmp.path();
    let audit_dir = home.join("audit");
    std::fs::create_dir_all(&audit_dir).expect("mkdir audit");

    // Seed 1000 events so replay output exceeds the OS pipe buffer
    // (~64 KB on macOS / Linux). Below that threshold every write
    // completes into the kernel buffer before `head` has a chance
    // to close its read side, so EPIPE never fires and the test
    // deadlocks. Above the threshold the ~1001st write blocks until
    // `head` drains — once `head` exits after 3 lines, the blocked
    // write unblocks with `BrokenPipe` and our
    // `WriteStatus::BrokenPipe` propagation path returns `Ok(())`.
    for i in 0..1000 {
        append_event(&audit_dir, "gmail", "ok", "api-call", &format!("broken-pipe-{i}"));
    }

    // Use a shell pipeline so `head` closes its read end after
    // reading 3 lines. Each rendered row spans ~2-3 terminal
    // lines (table header + data row + trailing newline), so
    // `head -n 3` satisfies its quota almost immediately.
    //
    // P27 review patch: spawn + `try_wait` polling loop with a
    // bounded 15s deadline. A regression in EPIPE detection would
    // otherwise hang CI for the full cargo-test timeout (minutes).
    // The explicit deadline fails loudly and fast.
    let script = format!(
        "{} audit --follow --since=1h --service=gmail | head -n 3",
        env!("CARGO_BIN_EXE_agentsso")
    );

    let mut child = Command::new("sh")
        .args(["-c", &script])
        .env("AGENTSSO_PATHS__HOME", home.as_os_str())
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sh pipeline");

    // Wait up to 15s for the pipeline to exit naturally.
    const BROKEN_PIPE_DEADLINE: Duration = Duration::from_secs(15);
    let deadline = Instant::now() + BROKEN_PIPE_DEADLINE;
    let mut exit_status = None;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_status = Some(status);
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => break,
        }
    }
    let hung = exit_status.is_none();
    if hung {
        // Kill the pipeline so the test harness doesn't hang.
        let _ = child.kill();
    }
    let output = child.wait_with_output().expect("collect child output");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !hung,
        "broken-pipe pipeline did not exit within {BROKEN_PIPE_DEADLINE:?} — \
         EPIPE detection regressed; stdout={stdout:?}; stderr={stderr:?}"
    );
    // Neither side should panic or leak stderr noise.
    assert!(
        !stderr.contains("panicked"),
        "follow should not panic on broken pipe; stderr={stderr}"
    );
    // `head` consumed at least one line, proving the pipeline
    // actually transmitted data before closing.
    assert!(!stdout.is_empty(), "head should receive at least one line; stdout={stdout:?}");
}
