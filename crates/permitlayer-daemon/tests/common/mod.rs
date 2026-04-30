//! Shared e2e test helpers.
//!
//! Rust's `tests/common/mod.rs` convention: cargo treats this file as
//! a module imported by sibling integration tests via `mod common;`,
//! NOT as its own test target (which `tests/common.rs` would be).
//! Every e2e file under `crates/permitlayer-daemon/tests/` was
//! hand-rolling these helpers before Story 8.1 consolidated them;
//! see `deferred-work-triage-2026-04-19.md` Theme 3 for the history.
//!
//! ## Guarantees the canonical helpers provide
//!
//! - [`free_port`] binds and immediately drops a listener on
//!   `127.0.0.1:0` to ask the OS for a free ephemeral port. There IS
//!   a TOCTOU window between the drop and the daemon's own bind; in
//!   practice we have not seen this race fire in CI. Tests that need
//!   deterministic ports should not use this helper.
//! - [`agentsso_bin`] resolves to the built `agentsso` binary by
//!   walking up from the integration-test harness's own path. Works
//!   under `cargo test`, `cargo test --release`, and
//!   `CARGO_TARGET_DIR`-overridden layouts.
//! - [`start_daemon`] spawns `agentsso start` with a caller-supplied
//!   [`DaemonTestConfig`]. The returned [`DaemonHandle`] owns the
//!   `std::process::Child` and SIGKILLs it on drop — this closes
//!   the "orphaned daemon on test panic" class of hygiene bug that
//!   existed across the hand-rolled copies. For tests that need the
//!   daemon's captured stdout/stderr, [`DaemonHandle::wait_with_output`]
//!   performs a graceful SIGTERM-then-SIGKILL-fallback shutdown so
//!   final log lines are flushed before capture.
//! - [`wait_for_health`] polls the daemon's `/health` endpoint with
//!   exponential backoff capped at a 10-second deadline.
//! - [`http_get`] / [`http_post`] issue minimal HTTP/1.1 requests
//!   against loopback. They do NOT call through to
//!   `cli::kill::http_get` because that module is `pub(crate)` inside
//!   `permitlayer-daemon` and integration tests live outside the
//!   crate's private scope.
//!
//! ## What this module deliberately does NOT provide
//!
//! - Retry logic beyond the existing hand-rolled copies' discipline.
//!   The baseline polls with exponential backoff and a 10s ceiling.
//! - A fluent builder with 20 config knobs. `DaemonTestConfig` is a
//!   plain struct with public fields; tests construct it with the
//!   struct-update `..Default::default()` syntax.
//! - Any cross-platform Drop-kill guarantees beyond Unix SIGKILL.
//!   Windows subprocess cleanup is Story 7.2's concern.

#![allow(
    dead_code, // different e2e files consume different subsets
    clippy::unwrap_used, // test helpers panic on invariant violation by design
    clippy::expect_used,
    clippy::panic,
)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Bind + immediately drop a listener on `127.0.0.1:0` to ask the OS
/// for a free ephemeral port.
///
/// # TOCTOU window
///
/// Between this function returning and the daemon subprocess calling
/// `bind()`, the OS may reassign the port to an unrelated process.
/// The collision window is typically ~10-50ms (daemon boot time).
/// We have not observed this race in CI across thousands of runs;
/// the ephemeral port pool (32768-60999 on Linux, 49152-65535 on
/// macOS) makes collisions rare even under `--test-threads=16`.
///
/// If the daemon's bind fails, the child process exits quickly and
/// [`wait_for_health`] returns `false` within its deadline — the test
/// then fails with a clear "daemon should have booted" assertion
/// rather than a mystery hang. No automatic retry is wired because
/// (a) the race is rare enough to not warrant the complexity, and
/// (b) the failure mode already produces a clear signal.
pub fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Resolve the path to the built `agentsso` binary.
///
/// Walks up from the integration-test harness's own `current_exe()`
/// to find the sibling `agentsso` binary in the same target directory.
/// Works under `cargo test` (`target/debug/deps/foo-HASH` →
/// `target/debug/agentsso`), `cargo test --release` (`target/release/`),
/// and `CARGO_TARGET_DIR`-overridden layouts. On Windows, appends
/// `.exe` automatically.
pub fn agentsso_bin() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // pop the test-binary filename
    path.pop(); // pop `deps/`, landing in `target/<profile>/`
    path.push("agentsso");
    if cfg!(windows) {
        path.set_extension("exe");
    }
    path
}

/// Forward Windows-required env vars to a `Command` whose env was
/// stripped via `env_clear()`. Without these, Winsock initialization
/// in the spawned process fails intermittently with
/// `WSAEPROVIDERFAILEDINIT` (Win32 OS error 10106) — Winsock's LSP
/// chain resolves DLL paths through `%SystemRoot%` / `%windir%` and
/// returns a hard error if those env vars are missing.
///
/// See [openai/codex#3311](https://github.com/openai/codex/issues/3311)
/// for the diagnosis. Forwarding the vars below is the standard
/// fix used by other Rust subprocess test harnesses on Windows.
///
/// On Unix this is a no-op (returns an empty iterator).
///
/// Use via `cmd.envs(forward_windows_required_env())` mid-chain, OR
/// call directly `for (k, v) in forward_windows_required_env() {
/// cmd.env(k, v); }` for non-chained styles.
pub fn forward_windows_required_env() -> impl Iterator<Item = (String, String)> {
    // List per Microsoft's process env documentation + Codex#3311 root-
    // cause analysis. SystemRoot is the load-bearing one for Winsock;
    // the others avoid downstream surprises in tempfile / locale code.
    const WINDOWS_REQUIRED: &[&str] =
        &["SystemRoot", "windir", "SystemDrive", "TEMP", "TMP", "USERPROFILE", "LOCALAPPDATA"];
    // The cfg below ensures Unix builds get a zero-iteration loop and
    // no `cfg(windows)` warning fires on either side.
    let vars: &[&str] = if cfg!(windows) { WINDOWS_REQUIRED } else { &[] };
    vars.iter().filter_map(|&var| std::env::var(var).ok().map(|v| (var.to_owned(), v)))
}

/// Config for [`start_daemon`]. Constructed via struct-update syntax:
///
/// ```ignore
/// start_daemon(DaemonTestConfig {
///     port,
///     home: home.path().to_path_buf(),
///     ..Default::default()
/// })
/// ```
///
/// All fields have sensible defaults that reproduce the "simple
/// daemon boot" pattern used by the majority of the hand-rolled
/// copies. The `hermetic` flag opts into the `env_clear`-based
/// discipline that `master_key_bootstrap_e2e.rs` uses, matching the
/// documented hermetic-env rationale from Story 1.15.
///
/// **Story 8.8b round-1 review (2026-04-28):** the dedup is now
/// complete — `master_key_bootstrap_e2e.rs` and `agent_registry_e2e.rs`
/// both consume `start_daemon` directly. No daemon-spawn helpers
/// shadow this one anywhere in the integration test tree.
///
/// # Env var precedence
///
/// `start_daemon` applies env vars in this order, with later writes
/// winning over earlier ones:
///
/// 1. (if `hermetic`) `env_clear()` wipes everything.
/// 2. (if `hermetic`) Preserve `PATH` + `HOME` from the parent process.
/// 3. `AGENTSSO_PATHS__HOME` from `config.home`.
/// 4. (if `set_test_master_key`) `AGENTSSO_TEST_MASTER_KEY_HEX`.
/// 5. Every entry in `config.extra_env`.
///
/// Step 5 is last, so callers can always override any default by
/// putting the var in `extra_env`. Conversely, anything set in
/// `extra_env` can be silently overwritten only if another entry in
/// `extra_env` shares its key — the loop is deterministic but a
/// duplicate key is a caller bug.
#[derive(Debug, Clone)]
pub struct DaemonTestConfig {
    /// TCP port the daemon will bind. Usually sourced from [`free_port`].
    /// Pass `0` to let the OS assign an ephemeral port atomically with
    /// the daemon's `bind` (Story 7.7 — closes the `free_port()` TOCTOU
    /// window). `start_daemon` reads the OS-assigned port from the
    /// daemon's `AGENTSSO_BOUND_ADDR=<addr>` stdout marker and stores
    /// it on `DaemonHandle.port`. Pass a concrete port only when the
    /// test specifically needs to control which port the daemon binds
    /// (rare).
    pub port: u16,
    /// `AGENTSSO_PATHS__HOME` for the child process.
    /// Must be a path whose parent exists — `start_daemon` asserts this
    /// to catch the footgun of forgetting to override the sentinel
    /// default below.
    pub home: PathBuf,
    /// Additional env vars beyond the test-master-key default. Applied
    /// LAST — see "Env var precedence" on the struct doc-comment.
    pub extra_env: Vec<(String, String)>,
    /// Additional CLI args to pass after `start --bind-addr ...`.
    pub extra_args: Vec<String>,
    /// If true, clear the child process's env before setting anything.
    /// Matches the `master_key_bootstrap_e2e.rs` discipline for tests
    /// that MUST not inherit the developer's shell `AGENTSSO_*` vars.
    /// Preserves `PATH` + `HOME` regardless, and then applies the
    /// per-config env vars per the precedence ordering above.
    pub hermetic: bool,
    /// If true, pre-set `AGENTSSO_TEST_MASTER_KEY_HEX` to the canonical
    /// deterministic test key so the daemon short-circuits past the
    /// real OS keychain lookup. Set to `false` for tests that
    /// deliberately exercise the real-keystore bootstrap path.
    /// Overridable via `extra_env` per the precedence ordering above.
    pub set_test_master_key: bool,
}

/// Sentinel path used as the `Default` value for `home`. `start_daemon`
/// asserts that `config.home` is NOT this sentinel, catching the
/// common footgun of forgetting the override via `..Default::default()`.
pub const SENTINEL_HOME: &str = "/tmp/agentsso-test-MUST-be-overridden";

impl Default for DaemonTestConfig {
    fn default() -> Self {
        Self {
            port: 0, // caller MUST override with free_port() result
            home: PathBuf::from(SENTINEL_HOME),
            extra_env: Vec::new(),
            extra_args: Vec::new(),
            hermetic: false,
            set_test_master_key: true,
        }
    }
}

/// Canonical deterministic test master key.
///
/// Keep in sync across all e2e files. When `set_test_master_key` is
/// true on [`DaemonTestConfig`], this value is exported as
/// `AGENTSSO_TEST_MASTER_KEY_HEX` so the daemon's
/// `try_build_agent_runtime` short-circuits past the real OS keychain
/// lookup. Tests exercising the real bootstrap path must set
/// `set_test_master_key: false`.
pub const TEST_MASTER_KEY_HEX: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Spawn `agentsso start` per [`DaemonTestConfig`] and return a
/// drop-safe handle.
///
/// **Story 7.7:** when `config.port == 0` (the recommended default),
/// the daemon binds atomically on an OS-assigned ephemeral port and
/// `start_daemon` reads the actual port from the
/// `AGENTSSO_BOUND_ADDR=<addr>` stdout marker. The resolved port is
/// stored on `DaemonHandle.port`. This eliminates the `free_port()`
/// TOCTOU race where a sibling nextest worker could grab a
/// pre-allocated port between `free_port`'s drop and our daemon's
/// bind. Tests that need to control the bound port (rare) can still
/// pass a concrete `port`.
///
/// # Panics
///
/// - If `config.home` is the [`SENTINEL_HOME`] sentinel — caller
///   forgot to override the default home path; running with the
///   sentinel risks two parallel tests sharing state.
/// - If the daemon's stdout closes before emitting
///   `AGENTSSO_BOUND_ADDR=` (when `port == 0`).
pub fn start_daemon(config: DaemonTestConfig) -> DaemonHandle {
    assert!(
        config.home.as_path() != Path::new(SENTINEL_HOME),
        "DaemonTestConfig::home must be overridden from the default sentinel — \
         use tempfile::tempdir() or another unique path per test",
    );

    let mut cmd = Command::new(agentsso_bin());

    if config.hermetic {
        cmd.env_clear();
        cmd.env("PATH", std::env::var("PATH").unwrap_or_default());
        cmd.env("HOME", config.home.to_str().unwrap());
        cmd.envs(forward_windows_required_env());
    }

    cmd.env("AGENTSSO_PATHS__HOME", config.home.to_str().unwrap());

    if config.set_test_master_key {
        cmd.env("AGENTSSO_TEST_MASTER_KEY_HEX", TEST_MASTER_KEY_HEX);
    }

    for (k, v) in &config.extra_env {
        cmd.env(k, v);
    }

    cmd.arg("start").arg("--bind-addr").arg(format!("127.0.0.1:{}", config.port));

    for a in &config.extra_args {
        cmd.arg(a);
    }

    let mut child =
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("failed to spawn daemon");

    let (resolved_port, captured_stdout) = if config.port == 0 {
        // Read the marker line from stdout, which is emitted
        // synchronously by `cli/start.rs` immediately after `bind`
        // returns. The post-marker stdout (tracing log lines etc.) is
        // captured into a shared buffer so `wait_with_output` can
        // surface it to tests that grep for tracing output (e.g.
        // `policy_compile_startup` expects "policies compiled").
        let (addr, buffer) = wait_for_bound_addr_capturing(&mut child, Duration::from_secs(10));
        (addr.port(), Some(buffer))
    } else {
        (config.port, None)
    };

    DaemonHandle { child: Some(child), port: resolved_port, captured_stdout }
}

/// Drop-safe handle to a daemon subprocess.
///
/// The spawned daemon is SIGKILL'd in [`Drop`], guaranteeing that no
/// orphaned daemon processes survive a test panic or early return.
/// Tests that need the exit code or captured output must call
/// [`DaemonHandle::wait_with_output`] explicitly, which consumes
/// the handle and bypasses the drop-kill.
pub struct DaemonHandle {
    child: Option<Child>,
    /// The port the daemon is bound to. Convenience field so tests
    /// can do `handle.port` instead of threading a separate variable.
    pub port: u16,
    /// Captured stdout buffer when `start_daemon` used zero-port mode
    /// (Story 7.7). The marker reader has to take `child.stdout`, so
    /// `Child::wait_with_output` would otherwise see an empty stdout.
    /// We background-buffer the post-marker bytes here and surface
    /// them on `wait_with_output`. `None` for the legacy fixed-port
    /// path where stdout was never taken.
    captured_stdout: Option<std::sync::Arc<std::sync::Mutex<Vec<u8>>>>,
}

impl DaemonHandle {
    /// Send SIGTERM (Unix) / `Child::kill` (other), wait up to 2s for
    /// graceful exit, fall back to SIGKILL, then capture stdout +
    /// stderr. Consumes the handle; drop-kill will NOT fire after this.
    ///
    /// Graceful shutdown matters because the daemon emits a flush of
    /// final log lines in its shutdown handler; SIGKILLing
    /// immediately would drop those, breaking tests that grep the
    /// captured stdout for markers like `"policies compiled"`.
    pub fn wait_with_output(mut self) -> std::io::Result<std::process::Output> {
        let mut child = self.child.take().expect("child should be present until wait_with_output");
        let captured_stdout = self.captured_stdout.take();

        #[cfg(unix)]
        {
            // SIGTERM via nix — gives the daemon up to 2 seconds to
            // flush logs + run its Drop chain. If it exits in time,
            // we capture the real output; otherwise we fall back to
            // SIGKILL so tests can't hang on a stuck daemon.
            use nix::sys::signal::{Signal, kill};
            use nix::unistd::Pid;

            let pid = Pid::from_raw(child.id() as i32);
            let _ = kill(pid, Signal::SIGTERM);

            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                match child.try_wait() {
                    Ok(Some(_)) => {
                        return finalize_output(child, captured_stdout);
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                    Err(e) => return Err(e),
                }
            }
            // Grace period expired — force-kill.
            let _ = child.kill();
        }

        #[cfg(not(unix))]
        {
            // Windows / other: no portable SIGTERM equivalent via
            // std. `Child::kill` is TerminateProcess on Windows which
            // is SIGKILL-ish; accept the log-flush loss.
            let _ = child.kill();
        }

        finalize_output(child, captured_stdout)
    }

    /// Check if the daemon has exited without blocking.
    pub fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.child.as_mut().expect("child should be present").try_wait()
    }

    /// Story 8.2: send SIGTERM and wait up to `timeout` for the daemon
    /// to exit cleanly. Returns `true` if the daemon exited within the
    /// deadline, `false` if it was still running (the existing `Drop`
    /// path will force-kill it on handle drop).
    ///
    /// Unlike [`Self::wait_with_output`], this does NOT consume the
    /// handle — callers can inspect side effects (e.g. audit files)
    /// between `shutdown_graceful` and the eventual drop.
    ///
    /// Windows: falls back to [`Child::kill`] (SIGKILL-equivalent via
    /// `TerminateProcess`). The clean-shutdown hook does not run —
    /// Story 7.2 will add a Windows-native graceful variant.
    #[cfg(unix)]
    pub fn shutdown_graceful(&mut self, timeout: Duration) -> bool {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;

        let Some(child) = self.child.as_mut() else {
            return true; // already taken by wait_with_output
        };
        let pid = Pid::from_raw(child.id() as i32);
        let _ = kill(pid, Signal::SIGTERM);

        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) => return true,
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(_) => return false,
            }
        }
        false
    }

    #[cfg(not(unix))]
    pub fn shutdown_graceful(&mut self, _timeout: Duration) -> bool {
        // Windows: no portable SIGTERM via std. Story 7.2 will add a
        // Windows-native graceful variant. Force-kill here and return
        // `false` so callers can distinguish graceful from forced exit
        // (Story 8.2 review fix F5). Previously this returned `true`
        // unconditionally, which silently papered over the absence of
        // a clean-shutdown path on Windows.
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        false
    }

    /// Return a mutable reference to the underlying child for
    /// operations that don't fit the helper API (e.g., reading stderr
    /// while the process is still running).
    pub fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("child should be present")
    }

    /// Story 7.7: child PID. Used by [`assert_daemon_pid_matches`] to
    /// confirm a `/health` response came from THIS daemon — not some
    /// other test's daemon that grabbed the same port through the
    /// `free_port` TOCTOU race.
    pub fn child_pid(&self) -> u32 {
        self.child.as_ref().expect("child should be present").id()
    }
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Ignore errors: child may have already exited, or we may
            // race with a concurrent wait. The important invariant is
            // "no orphan daemon survives this drop."
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Story 7.7: collect captured stdout (when zero-port mode took
/// `Child::stdout` for marker reading) and merge with the child's
/// own stderr. `Child::wait_with_output` would return empty stdout
/// in zero-port mode because we already drained it into our shared
/// buffer; this helper substitutes the captured bytes.
fn finalize_output(
    child: Child,
    captured_stdout: Option<std::sync::Arc<std::sync::Mutex<Vec<u8>>>>,
) -> std::io::Result<std::process::Output> {
    let raw = child.wait_with_output()?;
    if let Some(buffer) = captured_stdout {
        // Wait briefly for the background reader to finish draining
        // the now-closed pipe so its final bytes land in the buffer.
        // 100ms is plenty for the kernel to flush a closed pipe.
        std::thread::sleep(Duration::from_millis(100));
        let captured = buffer.lock().map(|b| b.clone()).unwrap_or_default();
        Ok(std::process::Output { stdout: captured, stderr: raw.stderr, status: raw.status })
    } else {
        Ok(raw)
    }
}

/// Story 7.7: read the daemon's piped stdout until the
/// `AGENTSSO_BOUND_ADDR=<addr>` marker line appears, then return the
/// parsed [`SocketAddr`]. Drains the rest of stdout in a background
/// thread so the daemon never blocks on a full pipe.
///
/// **Replaces the [`free_port`] pattern.** `free_port` pre-allocates
/// an ephemeral port via bind+drop, then the spawned daemon does its
/// own bind some 10-500ms later. Under high test concurrency
/// (especially on macOS where syspolicyd inflates subprocess startup
/// latency), another nextest worker can grab the port in that window;
/// the second daemon then spawns successfully against a *different*
/// port the OS hands it, and our test happily talks to the first
/// daemon — registering an agent on one, authenticating against the
/// other (401). See Story 7.7 dev notes for the forensic trace.
///
/// # Usage
///
/// Spawn the daemon with `--bind-addr 127.0.0.1:0` (or any
/// zero-port form). Then call this helper with the spawned `Child`.
/// Bounded by `timeout` to avoid hanging on a daemon that crashed
/// during init.
///
/// # Panics
///
/// On timeout. The caller is in the test setup phase where a clear
/// panic is more useful than a `Result` to thread upward.
///
/// # Stdout ownership
///
/// This helper **takes** `child.stdout` — subsequent calls to
/// `Child::wait_with_output` will see no stdout. Tests that consume
/// daemon stdout for grep-based assertions cannot use this helper;
/// they should either continue using [`free_port`] (if they accept
/// the race) or refactor to read stdout themselves and parse the
/// marker inline.
pub fn wait_for_bound_addr(child: &mut Child, timeout: Duration) -> SocketAddr {
    use std::io::BufRead;

    let stdout =
        child.stdout.take().expect("child.stdout must be Stdio::piped() for wait_for_bound_addr");
    let mut reader = std::io::BufReader::new(stdout);
    let deadline = Instant::now() + timeout;
    let mut line = String::new();

    while Instant::now() < deadline {
        line.clear();
        // BufRead::read_line can't natively honor the deadline. We
        // accept a worst-case "single line longer than `timeout`" hang
        // because `agentsso start` writes the marker line synchronously
        // immediately after `bind` returns, before any other stdout is
        // generated — so the caller's timeout is effectively bounded by
        // daemon-bind latency, not arbitrary stdout chatter.
        match reader.read_line(&mut line) {
            Ok(0) => panic!("daemon stdout closed before AGENTSSO_BOUND_ADDR marker"),
            Ok(_) => {
                if let Some(rest) = line.trim_end().strip_prefix("AGENTSSO_BOUND_ADDR=") {
                    let addr: SocketAddr = rest
                        .parse()
                        .unwrap_or_else(|e| panic!("malformed AGENTSSO_BOUND_ADDR={rest:?}: {e}"));
                    // Drain the remaining stdout to /dev/null so the
                    // daemon never blocks on a full kernel pipe. Use
                    // `io::sink()` (zero-alloc, swallows everything)
                    // instead of a `Vec` — a chatty daemon would
                    // otherwise grow the buffer unboundedly. The
                    // background thread exits when the daemon's stdout
                    // pipe closes, which DaemonHandle::Drop guarantees
                    // via child.kill().
                    std::thread::spawn(move || {
                        let _ = std::io::copy(&mut reader, &mut std::io::sink());
                    });
                    return addr;
                }
                // Some other startup line (logs etc); keep scanning.
            }
            Err(e) => panic!("error reading daemon stdout: {e}"),
        }
    }
    panic!("timed out after {timeout:?} waiting for AGENTSSO_BOUND_ADDR marker on daemon stdout");
}

/// Story 7.7: same as [`wait_for_bound_addr`], but instead of
/// draining post-marker stdout to `io::sink()`, capture it into a
/// shared buffer that `start_daemon` returns alongside the resolved
/// address. `wait_with_output` reads from this buffer (since
/// `Child::stdout` was already taken by the marker reader).
fn wait_for_bound_addr_capturing(
    child: &mut Child,
    timeout: Duration,
) -> (SocketAddr, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
    use std::io::BufRead;

    let stdout =
        child.stdout.take().expect("child.stdout must be Stdio::piped() for wait_for_bound_addr");
    let mut reader = std::io::BufReader::new(stdout);
    let deadline = Instant::now() + timeout;
    let mut line = String::new();

    while Instant::now() < deadline {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => panic!("daemon stdout closed before AGENTSSO_BOUND_ADDR marker"),
            Ok(_) => {
                if let Some(rest) = line.trim_end().strip_prefix("AGENTSSO_BOUND_ADDR=") {
                    let addr: SocketAddr = rest
                        .parse()
                        .unwrap_or_else(|e| panic!("malformed AGENTSSO_BOUND_ADDR={rest:?}: {e}"));
                    // Capture the post-marker stdout into a shared
                    // buffer. `wait_with_output` drains it on test
                    // teardown so grep-on-stdout patterns
                    // (`policy_compile_startup`, etc.) keep working.
                    let buffer = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
                    let buffer_thread = std::sync::Arc::clone(&buffer);
                    std::thread::spawn(move || {
                        use std::io::Read as _;
                        let mut chunk = [0u8; 8192];
                        loop {
                            match reader.read(&mut chunk) {
                                Ok(0) => break, // pipe closed
                                Ok(n) => {
                                    if let Ok(mut buf) = buffer_thread.lock() {
                                        buf.extend_from_slice(&chunk[..n]);
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    });
                    return (addr, buffer);
                }
                // Some other startup line (logs etc); keep scanning.
            }
            Err(e) => panic!("error reading daemon stdout: {e}"),
        }
    }
    panic!("timed out after {timeout:?} waiting for AGENTSSO_BOUND_ADDR marker on daemon stdout");
}

/// Story 7.7: assert that a `/health` response came from the daemon
/// owned by `handle`. Catches `free_port` TOCTOU collisions by
/// comparing the PID the daemon reports against the PID we spawned.
///
/// On mismatch this panics with both PIDs named — the diagnostic
/// you want when a previously-mystery 401-on-fresh-token blames
/// "wrong daemon" instead of "wrong code". Returns silently on
/// match.
///
/// Cheap (one HTTP GET against loopback). Safe to call after
/// [`wait_for_health`] in any test that uses [`start_daemon`].
pub fn assert_daemon_pid_matches(handle: &DaemonHandle) {
    let (status, body) = http_get(handle.port, "/health");
    assert_eq!(status, 200, "/health should return 200, got {status}: {body}");
    let json: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("/health response not JSON: {e}\nbody: {body}"));
    let reported_pid = json
        .get("pid")
        .and_then(|p| p.as_u64())
        .unwrap_or_else(|| panic!("/health response missing numeric pid field: {body}"));
    let expected_pid = u64::from(handle.child_pid());
    assert_eq!(
        reported_pid, expected_pid,
        "free_port TOCTOU: /health on port {} reported pid {reported_pid} but our \
         spawned daemon is pid {expected_pid}. Another test's daemon stole this port \
         between free_port() pre-allocation and our daemon's bind. See Story 7.7 \
         dev notes for migration to wait_for_bound_addr.",
        handle.port,
    );
}

/// Poll the daemon's `/health` endpoint until it reports status
/// `"healthy"` or the 10-second deadline expires.
///
/// Returns `true` on a healthy response; `false` on timeout or any
/// other status value. Uses exponential backoff: 50ms, 100ms, 200ms,
/// 400ms, 800ms, then capped at 800ms until deadline.
///
/// # Why a read timeout is set on the accepted stream
///
/// `connect_timeout` bounds the TCP handshake only. A daemon that
/// accepts the connection but hangs before writing the response
/// (half-open socket, mid-init stall) would otherwise block
/// `read_to_end` indefinitely and silently break the 10-second
/// deadline contract. The 500ms read timeout keeps each poll
/// bounded; the backoff loop retries the NEXT poll.
///
/// # Why JSON parse instead of substring match
///
/// The prior substring match on `"\"healthy\""` would false-positive
/// on any body containing the literal token anywhere — e.g. a JSON
/// array like `{"statuses": ["healthy", "degraded"]}`. Parsing the
/// response as JSON and asserting `status == "healthy"` removes the
/// ambiguity for zero ergonomic cost.
pub fn wait_for_health(port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut backoff = Duration::from_millis(50);

    while Instant::now() < deadline {
        if let Ok(mut stream) = TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(100),
        ) {
            // Per-poll read timeout — see module doc above.
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));

            let _ = stream.write_all(
                format!(
                    "GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            );
            let mut buf = Vec::new();
            let _ = stream.read_to_end(&mut buf);
            let response = String::from_utf8_lossy(&buf);
            // Parse body (after `\r\n\r\n` header/body separator) as JSON
            // and check the `status` field equals `"healthy"`.
            if let Some((_, body)) = response.split_once("\r\n\r\n")
                && let Ok(json) = serde_json::from_str::<serde_json::Value>(body.trim())
                && json.get("status").and_then(|s| s.as_str()) == Some("healthy")
            {
                return true;
            }
        }
        std::thread::sleep(backoff);
        backoff = std::cmp::min(backoff * 2, Duration::from_millis(800));
    }
    false
}

/// Issue an HTTP GET against the daemon and return (status_code, body).
pub fn http_get(port: u16, path: &str) -> (u16, String) {
    http_request(port, "GET", path, None)
}

/// Issue an HTTP POST with an optional body (empty if `None`) and
/// return (status_code, body).
pub fn http_post(port: u16, path: &str, body: Option<&str>) -> (u16, String) {
    http_request(port, "POST", path, body)
}

/// Issue an HTTP POST with a JSON body.
pub fn http_post_json(port: u16, path: &str, body: &serde_json::Value) -> (u16, String) {
    let body_str = body.to_string();
    http_request_with_headers(
        port,
        "POST",
        path,
        Some(&body_str),
        &[("Content-Type", "application/json")],
    )
}

fn http_request(port: u16, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    http_request_with_headers(port, method, path, body, &[])
}

fn http_request_with_headers(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
    extra_headers: &[(&str, &str)],
) -> (u16, String) {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_secs(2),
    )
    .expect("failed to connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let body_str = body.unwrap_or("");
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body_str.len(),
    );
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body_str);

    stream.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let raw = String::from_utf8_lossy(&buf).to_string();

    let status = raw.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
    // Split on `\r\n\r\n` to separate headers from body. If the split
    // fails (no response, malformed response, connection closed
    // before any bytes arrived), return the raw bytes as the body
    // so the caller's assertion message surfaces whatever diagnostic
    // signal the daemon DID produce — rather than a useless empty
    // string that looks identical across unrelated failure modes.
    let body_resp = match raw.split_once("\r\n\r\n") {
        Some((_, b)) => b.to_string(),
        None => raw, // preserve any partial/malformed response for debugging
    };
    (status, body_resp)
}

/// Convert a `127.0.0.1:<port>` string to a [`SocketAddr`].
pub fn loopback_addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

/// Canonical `&Path`-to-`&str` conversion used by env-var plumbing.
/// Panics on non-UTF8 paths; acceptable for tempdirs under tests.
pub fn path_str(p: &Path) -> &str {
    p.to_str().expect("tempdir paths are always UTF-8 in tests")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_port_returns_nonzero_ephemeral() {
        let p = free_port();
        assert!(p > 1024, "ephemeral port should be in unprivileged range, got {p}");
        assert!(p < 65535, "port must be valid u16, got {p}");
    }

    #[test]
    fn agentsso_bin_resolves_to_built_target() {
        let p = agentsso_bin();
        // The binary may not exist yet during a cold `cargo test`
        // build-and-run; we only assert the path SHAPE looks right.
        assert!(
            p.ends_with("agentsso") || p.ends_with("agentsso.exe"),
            "agentsso_bin should resolve to a binary named agentsso, got {}",
            p.display()
        );
        // The path must live UNDER a cargo `target/` directory.
        // Story 8.8b round-1 review: the original assertion checked
        // for `parent.file_name() in {"debug", "release"}`, but the
        // workspace ships `[profile.dist]` (cargo-dist release builds
        // land under `target/dist/`) and any future custom profile
        // would also fail the tight check. We still defend against
        // nested-debug-dir false positives by walking ancestors and
        // requiring SOME ancestor to be named `target` — anything
        // resolving to `/foo/debug/agentsso` without a `target/`
        // ancestor is rejected.
        let under_target = p.ancestors().any(|a| a.file_name().is_some_and(|n| n == "target"));
        assert!(
            under_target,
            "agentsso_bin path should live under a `target/` directory, got {}",
            p.display()
        );
    }

    #[test]
    #[cfg(unix)]
    fn daemon_handle_drop_kills_subprocess() {
        // Spawn a long-running `sleep 60` as a stand-in for the daemon.
        // We don't need a real daemon here — we're testing the Drop
        // behavior of DaemonHandle's kill-on-drop invariant.
        let child = Command::new("sleep").arg("60").spawn().expect("spawn sleep");
        let pid = child.id();

        {
            let _handle = DaemonHandle { child: Some(child), port: 0, captured_stdout: None };
            // Confirm the process is alive via `kill -0 <pid>`.
            let alive = Command::new("kill").arg("-0").arg(pid.to_string()).status().unwrap();
            assert!(alive.success(), "sleep process should be alive before handle drop");
        } // handle drops here, sending SIGKILL

        // Poll for up to 2 seconds for the process to disappear.
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let alive = Command::new("kill").arg("-0").arg(pid.to_string()).status().unwrap();
            if !alive.success() {
                return; // process is gone, test passes
            }
            if Instant::now() > deadline {
                panic!("process {pid} survived DaemonHandle drop beyond 2s deadline");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn loopback_addr_parses() {
        let addr = loopback_addr(12345);
        assert_eq!(addr.to_string(), "127.0.0.1:12345");
    }

    #[test]
    fn wait_for_health_times_out_on_closed_port() {
        // Grab an ephemeral port + immediately drop the listener so
        // nobody is listening. `wait_for_health` should return false
        // within its 10-second deadline.
        let port = free_port();
        let start = Instant::now();
        let healthy = wait_for_health(port);
        let elapsed = start.elapsed();

        assert!(!healthy, "wait_for_health should return false when nothing is listening");
        // Upper bound includes the 10s deadline + up to one cycle of
        // outstanding connect attempts. 11s is generous.
        assert!(
            elapsed < Duration::from_secs(11),
            "wait_for_health should respect its 10s deadline, took {elapsed:?}",
        );
    }

    // start_daemon_asserts_port_nonzero (Story 7.6b precedent) was
    // removed: Story 7.7 made `port: 0` the canonical value (the
    // daemon binds atomically and emits `AGENTSSO_BOUND_ADDR=` so
    // tests can read the resolved port). The "footgun" the assertion
    // guarded against is now the recommended pattern.

    #[test]
    #[should_panic(expected = "home must be overridden")]
    fn start_daemon_asserts_home_overridden() {
        // Constructing a DaemonTestConfig without overriding `home`
        // (default is SENTINEL_HOME) must panic — catches tests that
        // forget to supply a unique tempdir per invocation.
        let _ = start_daemon(DaemonTestConfig { port: 54321, ..Default::default() });
    }
}
