#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Cross-process conformance test for `VaultLock` (Story 7.6a AC #1).
//!
//! The in-thread tests in `permitlayer_core::vault::lock` verify
//! single-process semantics. This test exercises the cross-PROCESS
//! property — `flock`/`LockFileEx` must guarantee mutual exclusion
//! across separate OS processes, which is the whole reason `VaultLock`
//! exists.
//!
//! # Self-spawn protocol
//!
//! The test binary re-invokes itself with the env var
//! `PERMITLAYER_VAULT_LOCK_CHILD_HOME` set to the home path the
//! parent has chosen. The child program (in `child_main`) acquires
//! the lock, writes a single byte to `<home>/child_ready` to signal
//! "I am holding the lock", then sleeps until the parent kills it.
//!
//! The parent process:
//! 1. Spawns the child with the env var.
//! 2. Polls for `<home>/child_ready` to appear (timeout: 5s).
//! 3. Calls `VaultLock::try_acquire(home)` — must return `Busy` with
//!    holder_pid = child's pid.
//! 4. Kills the child; verifies `try_acquire` now succeeds (the
//!    kernel released the lock when the child exited).

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use permitlayer_core::vault::lock::{VaultLock, VaultLockError};
use tempfile::TempDir;

const CHILD_ENV: &str = "PERMITLAYER_VAULT_LOCK_CHILD_HOME";
const READY_FILE: &str = "child_ready";
const POLL_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// The test binary's `main` entry point is set up by the harness, but
/// we hijack it via the env var: when `PERMITLAYER_VAULT_LOCK_CHILD_HOME`
/// is set, run the child role and `process::exit` before the harness
/// sees us.
///
/// Cargo's integration-test harness invokes a `#[ctor]`-equivalent
/// (the `pre_main` hook) before tests run; we use the `#[test]`
/// hook instead and gate on the env var inside each test. The
/// child role is invoked via `child_main()` from the test below.
fn child_main(home: &str) -> ! {
    let home_path = Path::new(home);
    let _guard = match VaultLock::try_acquire(home_path) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("child: failed to acquire vault lock: {e}");
            std::process::exit(2);
        }
    };
    // Signal "I'm holding the lock".
    if let Err(e) = std::fs::write(home_path.join(READY_FILE), b"ready") {
        eprintln!("child: failed to write ready file: {e}");
        std::process::exit(3);
    }
    // Sleep until the parent kills us. 60s is a generous upper bound
    // — the parent normally kills the child within a few hundred ms.
    std::thread::sleep(Duration::from_secs(60));
    std::process::exit(0);
}

/// Wait for `path` to exist or timeout. Returns true if the file
/// appeared, false on timeout.
fn wait_for_file(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    false
}

#[test]
fn vault_lock_excludes_across_processes() {
    // If we were re-invoked as the child, run the child path and
    // exit. The harness will treat us as a "passed" test from its
    // perspective because we never returned to it — actually, we
    // exit(0) which the harness sees as a passing test. But the
    // child only runs when the env var is set, which the parent
    // never sets in its own runtime — so the parent path is the
    // one that actually executes for normal `cargo test` invocations.
    if let Ok(home) = std::env::var(CHILD_ENV) {
        child_main(&home);
    }

    let tmp = TempDir::new().expect("tempdir");
    let home = tmp.path().to_path_buf();

    // Re-invoke the test binary with the env var set so the child
    // takes the `child_main` path and never returns to the harness.
    let test_bin = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(&test_bin)
        // Restrict the harness to running JUST this test in the
        // child, so the child doesn't try to spawn its own subtests.
        .arg("vault_lock_excludes_across_processes")
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_ENV, &home)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn child test binary");

    // Wait for the child to acquire the lock and write the ready
    // marker. If the child fails to spawn correctly we'll time out
    // here and fail the test.
    let ready_path = home.join(READY_FILE);
    if !wait_for_file(&ready_path, POLL_TIMEOUT) {
        let _ = child.kill();
        let output = child.wait_with_output().expect("child wait");
        panic!(
            "child did not write ready file within {POLL_TIMEOUT:?}; child stdout: {:?} stderr: {:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    let child_pid = child.id();

    // Now the lock is held by the child process. Our `try_acquire`
    // MUST return `Busy` — that's the actual safety guarantee
    // (kernel-side mutual exclusion). On Unix, holder_pid/command
    // also populate because POSIX flock is advisory: the parent
    // can open + read the lock file's metadata even though the
    // child holds the kernel lock.
    //
    // Story 7.7 / deferred-work.md:910 closure: on Windows
    // `LockFileEx` is mandatory and excludes other handles from
    // reading the locked file with a sharing violation, so
    // `read_holder_metadata` returns `(None, None)` even though
    // the lock is correctly held. Skip the metadata sub-assertions
    // on Windows; the cross-process exclusion (the actual safety
    // contract) is still enforced + verified via the Busy match.
    match VaultLock::try_acquire(&home) {
        Err(VaultLockError::Busy { holder_pid, holder_command }) => {
            #[cfg(unix)]
            {
                assert_eq!(
                    holder_pid,
                    Some(child_pid),
                    "expected child pid {child_pid} as holder, got {holder_pid:?}"
                );
                assert!(holder_command.is_some(), "holder_command should be populated");
            }
            #[cfg(not(unix))]
            {
                let _ = (holder_pid, holder_command, child_pid);
            }
        }
        Err(other) => {
            let _ = child.kill();
            panic!("expected Busy, got error {other}");
        }
        Ok(_) => {
            let _ = child.kill();
            panic!("expected Busy from cross-process acquirer; got Ok");
        }
    }

    // Kill the child and confirm the kernel released the lock.
    let _ = child.kill();
    let _ = child.wait();

    // After the child has fully exited, try_acquire must succeed.
    // Allow a short grace period for the kernel to release the
    // descriptor on macOS (Linux releases synchronously).
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut last_err: Option<VaultLockError> = None;
    while Instant::now() < deadline {
        match VaultLock::try_acquire(&home) {
            Ok(_) => return,
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(POLL_INTERVAL);
            }
        }
    }
    panic!("lock was not released after child exit; last error: {last_err:?}");
}
