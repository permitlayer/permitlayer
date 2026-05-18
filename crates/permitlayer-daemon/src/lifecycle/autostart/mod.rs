//! Opt-in autostart at login (FR7) — registers the daemon with the
//! platform-native service manager so it starts at login.
//!
//! Three platform backends, one stable Rust API:
//! - **macOS:** LaunchAgent plist at `~/Library/LaunchAgents/dev.agentsso.daemon.plist`,
//!   loaded via `launchctl bootstrap` (modern API; the deprecated `launchctl load`
//!   form emits a warning on macOS 13+).
//! - **Linux:** systemd user unit at `~/.config/systemd/user/agentsso.service`,
//!   enabled via `systemctl --user enable --now`.
//! - **Windows:** Task Scheduler entry named `AgentSSO Daemon`, registered via
//!   `schtasks` (built-in to Windows since XP — no extra dependency).
//!
//! All three implementations share an [`Engine`] trait so unit tests can
//! mock the service-manager exec and verify the rendering and idempotency
//! logic on any host (cross-platform CI per architecture.md:404-409).
//!
//! # Cross-mechanism conflicts
//!
//! Out-of-band autostart mechanisms exist that can race with this one and
//! are surfaced by [`status`] as [`AutostartStatus::Conflict`]:
//! - macOS Homebrew's `brew services start agentsso` writes its OWN plist at
//!   `~/Library/LaunchAgents/homebrew.mxcl.agentsso.plist` (Homebrew-controlled
//!   namespace, fixed `homebrew.mxcl.*` prefix). Both active simultaneously
//!   double-binds 127.0.0.1:3820.
//! - Windows `install.ps1 -Autostart` (Story 7.2) drops a Startup-folder
//!   shortcut named `agentsso.lnk`. [`disable`] on Windows removes any stray
//!   `agentsso.lnk` alongside the Task Scheduler entry.
//! - Linux: no equivalent dual-mechanism risk — systemd-user is the only
//!   user-level mechanism.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

/// Errors that can occur during autostart disable / status.
///
/// Sealed enum — the variants reflect the operator-facing failure modes,
/// not implementation transients (those bubble up via the `#[from]` IO
/// arm). The CLI layer pattern-matches on these to render
/// [`crate::design::render::error_block`] guidance.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum AutostartError {
    /// The platform's service-manager command failed. The wrapped
    /// [`std::process::Output`]'s `stderr` is exposed via the [`Display`]
    /// impl so operators see the underlying tool's error message.
    #[error("service-manager command failed: {message}")]
    ServiceManagerFailed { message: String },

    /// The platform refused to write or remove its artifact (plist /
    /// unit file / Task XML). Wraps the underlying io error.
    #[error("filesystem operation failed")]
    Io(#[from] std::io::Error),

    /// The CLI is running on a target where this autostart code path
    /// has no implementation (today: anything that's not macOS / Linux
    /// / Windows). Returned by the unsupported-target stub `disable` /
    /// `status` paths so the CLI can render a clean error.
    ///
    /// Constructed only by the `cfg(not(any(macos, linux, windows)))`
    /// stub `disable_with` / `status_with`; on the three real platforms
    /// that constructor is `cfg`-d out, so rustc sees no construction
    /// site even though `cli::uninstall` exhaustively matches this
    /// variant. Same cross-`cfg` shape as [`AutostartStatus::Conflict`]
    /// below — scoped exactly to the platforms where the constructor is
    /// absent.
    #[cfg_attr(
        any(target_os = "macos", target_os = "linux", target_os = "windows"),
        allow(dead_code)
    )]
    #[error("autostart is not supported on this platform ({platform})")]
    UnsupportedPlatform { platform: &'static str },
}

/// Output of [`status`] — what [`disable`] would see if invoked right
/// now.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum AutostartStatus {
    /// The autostart artifact is not present / not loaded.
    Disabled,

    /// The autostart artifact is present, the platform's service manager
    /// has loaded it, and at next login it will start the daemon.
    Enabled {
        /// Filesystem location of the artifact (plist path / unit path /
        /// Task XML path). Surfaced so users / Stories 7.4 + 7.5 can
        /// detect path-binding regressions after upgrades.
        artifact_path: PathBuf,
        /// Platform-native mechanism name (`launchd` / `systemd-user` /
        /// `task-scheduler`).
        mechanism: &'static str,
        /// Absolute path to the daemon binary that the artifact will
        /// invoke at login. Story 7.5 verifies this stays stable across
        /// in-place upgrades.
        ///
        /// **P54 (code review round 5, M4):** `Option` instead of
        /// `PathBuf` so callers can distinguish "couldn't parse the
        /// embedded path out of the artifact" from "parsed an empty
        /// path." The previous `unwrap_or_default()` collapsed both
        /// to an empty `PathBuf`, breaking Story 7.5's drift-
        /// detection contract that the dev's own Task 9 cross-story
        /// note pinned ("detect binary-path drift via
        /// `status().daemon_path` vs `current_exe()`").
        daemon_path: Option<PathBuf>,
    },

    /// Two autostart mechanisms are active at the same time. Currently
    /// fires for: (macOS) brew-services + dev.agentsso.daemon plist
    /// both present; (Windows) Task Scheduler entry AND a leftover
    /// Story-7.2 `agentsso.lnk` in the Startup folder.
    ///
    /// Constructed only by `macos.rs` and `windows.rs`; the Linux
    /// systemd-user backend has no equivalent dual-mechanism state.
    /// `#[cfg_attr]` silences clippy's dead-code lint on Linux
    /// builds where neither construction site is compiled.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    Conflict {
        /// Human-readable description of the dual-mechanism state.
        detail: String,
    },
}

impl AutostartStatus {
    /// Convenience accessor — `true` only for the `Enabled` variant.
    /// Used by the setup-wizard orchestrator's closing summary
    /// (Story 7.3 Task 3).
    #[must_use]
    #[allow(dead_code)] // Used by the setup-wizard orchestrator path.
    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled { .. })
    }
}

/// The platform's service-manager exec boundary, factored out behind a
/// trait so unit tests can drive disable / status logic without
/// invoking the real `launchctl` / `systemctl` / `schtasks`.
///
/// Not part of the public API — gated `pub(crate)` so the platform
/// modules + their tests can mock it; CLI consumers go through the
/// free functions [`disable`] / [`status`] which use [`RealExec`]
/// internally.
pub(crate) trait Engine {
    /// Run the platform service-manager binary with the given args.
    /// Returns the raw [`Output`] so callers can inspect both stdout
    /// (for status parsing) and the exit status (for idempotency
    /// branching — e.g., `launchctl bootout` exit 36 = "service not
    /// loaded" is treated as success on disable).
    fn run(&self, program: &str, args: &[&str]) -> std::io::Result<Output>;
}

/// Default [`Engine`] — shells out to the real binary via
/// [`std::process::Command`]. Used by the public API.
///
/// **P37 (code review round 3):** wraps every spawn in a 30-second
/// hard timeout so a misconfigured Homebrew (slow tap eval, stuck
/// brew network call), a sluggish launchd, or a wedged systemctl
/// can't hang the autostart disable / status path indefinitely. 30s
/// is well above any reasonable service-manager response time but
/// well below what an operator would consider "broken" — they'll
/// Ctrl-C before then anyway.
pub(crate) struct RealExec;

impl Engine for RealExec {
    fn run(&self, program: &str, args: &[&str]) -> std::io::Result<Output> {
        run_with_timeout(program, args, std::time::Duration::from_secs(30))
    }
}

/// Spawn a command, drain stdout/stderr concurrently, kill if the
/// child hasn't exited within `timeout`. Pure-std — no extra crate
/// dep.
///
/// **P42 (code review round 5):** the previous implementation used
/// `try_wait`-poll-then-drain-on-exit. With piped stdio, the child
/// blocks on the first write that overflows the OS pipe buffer
/// (~64 KiB Linux, ~16 KiB macOS); we never drain, so the child
/// never makes progress, and our timeout fires falsely on tools that
/// were working correctly (e.g., `schtasks /Query` on a host with
/// hundreds of tasks). Now: spawn reader threads for stdout/stderr
/// and join them after `try_wait` reports exit. Pipes are drained
/// continuously so the buffer never fills.
///
/// **M13 deferred genuine:** placing the child in its own process
/// group (so SIGKILL reaches grandchildren) requires `pre_exec`,
/// which is `unsafe`. The crate root has `#![forbid(unsafe_code)]`,
/// which `#[allow]` cannot override at child scope. Workspace-wide
/// policy decision — same shape as D10 in the original review.
fn run_with_timeout(
    program: &str,
    args: &[&str],
    timeout: std::time::Duration,
) -> std::io::Result<Output> {
    use std::io::Read as _;
    use std::time::Instant;

    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn()?;

    // Spawn reader threads to drain pipes continuously so the child
    // never blocks on a full pipe buffer.
    let stdout_handle = child.stdout.take().map(|mut h| {
        std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
            let mut buf = Vec::new();
            h.read_to_end(&mut buf)?;
            Ok(buf)
        })
    });
    let stderr_handle = child.stderr.take().map(|mut h| {
        std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
            let mut buf = Vec::new();
            h.read_to_end(&mut buf)?;
            Ok(buf)
        })
    });

    let start = Instant::now();
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    // Drain whatever the readers captured before the
                    // SIGKILL closed the pipes (best-effort; we drop
                    // the data anyway, the timeout error is the signal).
                    if let Some(h) = stdout_handle {
                        let _ = h.join();
                    }
                    if let Some(h) = stderr_handle {
                        let _ = h.join();
                    }
                    tracing::warn!(
                        program,
                        elapsed_ms = start.elapsed().as_millis() as u64,
                        "service-manager command exceeded timeout — killed"
                    );
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("{program} did not exit within {}s — killed", timeout.as_secs()),
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    };

    let stdout = stdout_handle.and_then(|h| h.join().ok()).and_then(|r| r.ok()).unwrap_or_default();
    let stderr = stderr_handle.and_then(|h| h.join().ok()).and_then(|r| r.ok()).unwrap_or_default();
    Ok(Output { status, stdout, stderr })
}

/// Disable autostart on the host platform. Idempotent — succeeds with
/// `DisableOutcome::AlreadyDisabled` if there's nothing to remove.
pub fn disable() -> Result<DisableOutcome, AutostartError> {
    let exec = RealExec;
    let home = home_dir()?;
    disable_with(&exec, &home)
}

/// Report current autostart state. Pure query; never modifies state.
pub fn status() -> Result<AutostartStatus, AutostartError> {
    let exec = RealExec;
    let home = home_dir()?;
    status_with(&exec, &home)
}

/// Outcome of a successful [`disable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisableOutcome {
    /// The autostart artifact was found and removed.
    Removed { mechanism: &'static str, artifact_path: PathBuf },

    /// Removed the Task Scheduler entry AND a leftover Story 7.2
    /// `agentsso.lnk`. Windows only.
    #[allow(dead_code)] // Constructed only by the windows backend.
    RemovedWithShortcut { artifact_path: PathBuf, removed_shortcut: PathBuf },

    /// Nothing was registered — no-op. Idempotency.
    AlreadyDisabled,
}

// ── Platform dispatch ────────────────────────────────────────────────
//
// Each `cfg`-gated branch dispatches to the per-platform module. The
// `pub(crate)` `_with` variants take the [`Engine`] explicitly so unit
// tests can wire a mock; the public free functions above pass
// [`RealExec`].

#[cfg(target_os = "macos")]
pub(crate) fn disable_with(
    exec: &impl Engine,
    home: &Path,
) -> Result<DisableOutcome, AutostartError> {
    macos::disable(exec, home)
}

#[cfg(target_os = "macos")]
pub(crate) fn status_with(
    exec: &impl Engine,
    home: &Path,
) -> Result<AutostartStatus, AutostartError> {
    macos::status(exec, home)
}

#[cfg(target_os = "linux")]
pub(crate) fn disable_with(
    exec: &impl Engine,
    home: &Path,
) -> Result<DisableOutcome, AutostartError> {
    linux::disable(exec, home)
}

#[cfg(target_os = "linux")]
pub(crate) fn status_with(
    exec: &impl Engine,
    home: &Path,
) -> Result<AutostartStatus, AutostartError> {
    linux::status(exec, home)
}

#[cfg(target_os = "windows")]
pub(crate) fn disable_with(
    exec: &impl Engine,
    home: &Path,
) -> Result<DisableOutcome, AutostartError> {
    windows::disable(exec, home)
}

#[cfg(target_os = "windows")]
pub(crate) fn status_with(
    exec: &impl Engine,
    home: &Path,
) -> Result<AutostartStatus, AutostartError> {
    windows::status(exec, home)
}

// Unsupported-target stubs. Anything not macOS/Linux/Windows (e.g., a
// hypothetical FreeBSD target) gets a clean error rather than a build
// break.
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub(crate) fn disable_with(
    _exec: &impl Engine,
    _home: &Path,
) -> Result<DisableOutcome, AutostartError> {
    Err(AutostartError::UnsupportedPlatform { platform: std::env::consts::OS })
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub(crate) fn status_with(
    _exec: &impl Engine,
    _home: &Path,
) -> Result<AutostartStatus, AutostartError> {
    Err(AutostartError::UnsupportedPlatform { platform: std::env::consts::OS })
}

// ── Shared helpers ───────────────────────────────────────────────────

/// Render a `ServiceManagerFailed` error message from a non-success
/// [`Output`]. Trims trailing whitespace from stderr and tags the
/// invoking program for operator triage.
pub(crate) fn service_manager_failed(
    program: &str,
    args: &[&str],
    output: &Output,
) -> AutostartError {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let detail = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        format!("exit code {:?}", output.status.code())
    };
    AutostartError::ServiceManagerFailed {
        message: format!("{program} {} → {detail}", args.join(" ")),
    }
}

/// Resolve the user's home directory. Honors `AGENTSSO_PATHS__HOME` for
/// test parity with [`crate::cli::agentsso_home`] and the daemon's
/// config layer.
pub(crate) fn home_dir() -> std::io::Result<PathBuf> {
    if let Ok(override_path) = std::env::var("AGENTSSO_PATHS__HOME") {
        return Ok(PathBuf::from(override_path));
    }
    dirs::home_dir().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "cannot determine home directory")
    })
}

/// Reverse of the per-platform `xml_escape` helpers — handles the same
/// five entities (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`).
///
/// Strict parser; unknown entities pass through unchanged because we
/// don't need full XML 1.0 entity coverage — both the macOS plist and
/// the Windows Task XML are rendered by us, with our own `xml_escape`,
/// so the only entities we'll encounter on parse are the five we emit.
///
/// **P16 (code review):** lifted into `super` so both macOS
/// `parse_program_path` and Windows `parse_command_path` can call it
/// without cfg-cross-import gymnastics. Linux's systemd-user backend
/// reads `ExecStart=` directly without XML decoding, so this helper
/// is dead on Linux builds.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub(crate) fn xml_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut bytes = s.as_bytes();
    while !bytes.is_empty() {
        if bytes[0] != b'&' {
            // Push the next UTF-8 char (find its boundary).
            let head_len = utf8_char_len(bytes[0]);
            let head = &bytes[..head_len];
            out.push_str(std::str::from_utf8(head).unwrap_or(""));
            bytes = &bytes[head_len..];
            continue;
        }
        // Match one of the known entities, longest-first.
        if bytes.starts_with(b"&amp;") {
            out.push('&');
            bytes = &bytes[5..];
        } else if bytes.starts_with(b"&lt;") {
            out.push('<');
            bytes = &bytes[4..];
        } else if bytes.starts_with(b"&gt;") {
            out.push('>');
            bytes = &bytes[4..];
        } else if bytes.starts_with(b"&quot;") {
            out.push('"');
            bytes = &bytes[6..];
        } else if bytes.starts_with(b"&apos;") {
            out.push('\'');
            bytes = &bytes[6..];
        } else {
            // Unknown entity — pass the `&` through literally.
            out.push('&');
            bytes = &bytes[1..];
        }
    }
    out
}

/// UTF-8 leading-byte → char length. Used by [`xml_unescape`] to advance
/// past whole chars on the non-`&` path. Dead on Linux for the same
/// reason `xml_unescape` is.
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn utf8_char_len(b: u8) -> usize {
    match b {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 1, // continuation byte or invalid — fall back to 1
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Mockable [`Engine`] for unit tests on any platform. Records
    /// invocations and lets each test programmatically queue replies.
    #[derive(Default)]
    pub(crate) struct MockExec {
        pub(crate) calls: std::cell::RefCell<Vec<(String, Vec<String>)>>,
        pub(crate) replies: std::cell::RefCell<std::collections::VecDeque<std::io::Result<Output>>>,
    }

    impl MockExec {
        pub(crate) fn push_reply(&self, reply: std::io::Result<Output>) {
            self.replies.borrow_mut().push_back(reply);
        }
        pub(crate) fn ok(stdout: &str) -> std::io::Result<Output> {
            #[cfg(unix)]
            use std::os::unix::process::ExitStatusExt as _;
            #[cfg(windows)]
            use std::os::windows::process::ExitStatusExt as _;
            Ok(Output {
                status: std::process::ExitStatus::from_raw(0),
                stdout: stdout.as_bytes().to_vec(),
                stderr: Vec::new(),
            })
        }
        #[allow(dead_code)] // used by per-platform tests
        pub(crate) fn fail(code: i32, stderr: &str) -> std::io::Result<Output> {
            // P19 (code review): exit codes that overflow i32 << 8 (or
            // i32::MAX as u32 on Windows) silently corrupt the wait
            // status into a signal-bit field. Catch the misuse loudly.
            assert!(
                (0..=255).contains(&code),
                "MockExec::fail exit code must be in 0..=255 (got {code}); \
                 codes outside this range silently overflow on Unix wait status"
            );
            #[cfg(unix)]
            use std::os::unix::process::ExitStatusExt as _;
            #[cfg(windows)]
            use std::os::windows::process::ExitStatusExt as _;
            // Unix raw status is `(exit_code << 8)`; Windows raw is the exit code directly.
            #[cfg(unix)]
            let raw = code << 8;
            #[cfg(windows)]
            let raw = code as u32;
            Ok(Output {
                status: std::process::ExitStatus::from_raw(raw),
                stdout: Vec::new(),
                stderr: stderr.as_bytes().to_vec(),
            })
        }
    }

    impl Engine for MockExec {
        fn run(&self, program: &str, args: &[&str]) -> std::io::Result<Output> {
            self.calls
                .borrow_mut()
                .push((program.to_owned(), args.iter().map(|s| (*s).to_owned()).collect()));
            // P15 (code review): panic loudly when a test queues fewer
            // replies than the code-under-test actually invokes —
            // silently returning Ok("") would mask test bugs where a
            // platform module added an extra service-manager call but
            // the test wasn't updated to match.
            self.replies.borrow_mut().pop_front().unwrap_or_else(|| {
                panic!(
                    "MockExec ran out of queued replies for `{program} {}` — \
                     push more replies via mock.push_reply()",
                    args.join(" ")
                )
            })
        }
    }

    #[test]
    fn xml_unescape_round_trips_known_entities() {
        // Round-trip the five entities our render-side `xml_escape`
        // helpers emit. P16 (code review): without this the daemon-path
        // drift detection in Story 7.5 misreads paths containing `&`,
        // `<`, `>`, `"`, or `'`.
        assert_eq!(xml_unescape("foo &amp; bar"), "foo & bar");
        assert_eq!(xml_unescape("&lt;tag&gt;"), "<tag>");
        assert_eq!(xml_unescape("&quot;quoted&quot;"), "\"quoted\"");
        assert_eq!(xml_unescape("it&apos;s"), "it's");
        // Unknown entities pass through unchanged.
        assert_eq!(xml_unescape("&foo; bar"), "&foo; bar");
        // No-op on a vanilla string.
        assert_eq!(xml_unescape("/usr/local/bin/agentsso"), "/usr/local/bin/agentsso");
        // Empty string.
        assert_eq!(xml_unescape(""), "");
    }

    #[test]
    fn autostart_status_is_enabled_helper() {
        let disabled = AutostartStatus::Disabled;
        let conflict = AutostartStatus::Conflict { detail: "x".into() };
        let enabled = AutostartStatus::Enabled {
            artifact_path: "/tmp/x".into(),
            mechanism: "launchd",
            daemon_path: Some("/usr/local/bin/agentsso".into()),
        };
        assert!(!disabled.is_enabled());
        assert!(!conflict.is_enabled());
        assert!(enabled.is_enabled());
    }
}
