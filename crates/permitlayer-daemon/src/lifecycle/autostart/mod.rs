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
//! Three out-of-band autostart mechanisms exist that can race with this one:
//! - macOS Homebrew's `brew services start agentsso` writes its OWN plist at
//!   `~/Library/LaunchAgents/homebrew.mxcl.agentsso.plist` (Homebrew-controlled
//!   namespace, fixed `homebrew.mxcl.*` prefix). Both enabled simultaneously
//!   double-binds 127.0.0.1:3820. [`enable`] refuses with `BrewServicesActive`
//!   when it detects this. See Story 7.1 Dev Notes "Cross-reference with Story
//!   7.3 autostart".
//! - Windows `install.ps1 -Autostart` (Story 7.2) drops a Startup-folder
//!   shortcut named `agentsso.lnk`. [`enable`] on Windows removes any stray
//!   `agentsso.lnk` before writing the Task Scheduler entry. See Story 7.2 Dev
//!   Notes "Cross-story fences" item 1.
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

/// Errors that can occur during autostart enable / disable / status.
///
/// Sealed enum — the variants reflect the operator-facing failure modes,
/// not implementation transients (those bubble up via the `#[from]` IO
/// arm). The CLI layer pattern-matches on these to render
/// [`crate::design::render::error_block`] guidance.
///
/// `dead_code` allowed at the variant level: each `cfg`-gated platform
/// backend constructs only its own subset (e.g., `SystemdUnavailable`
/// is Linux-only), so cross-platform builds otherwise warn.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
#[allow(dead_code)]
pub enum AutostartError {
    /// macOS: `brew services` is currently managing the daemon. Enabling
    /// autostart would double-bind 127.0.0.1:3820. See module docs.
    #[error(
        "Homebrew is already managing agentsso via `brew services start agentsso`; \
         disable that first before enabling `agentsso autostart`"
    )]
    BrewServicesActive,

    /// Linux: the host has no functioning user-systemd (e.g., WSL1, or
    /// WSL2 without `systemd=true` in `/etc/wsl.conf`, or a minimal
    /// container). [`enable`] cannot proceed; the user has to either
    /// fix their systemd setup or use a wrapper script in a different
    /// init system.
    #[error("user-systemd is not available on this host: {detail}")]
    SystemdUnavailable { detail: String },

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
    /// / Windows). Returned by the unsupported-target stub `enable`,
    /// `disable`, `status` paths so the CLI can render a clean error.
    #[error("autostart is not supported on this platform ({platform})")]
    UnsupportedPlatform { platform: &'static str },
}

/// Output of [`status`] — what [`enable`] / [`disable`] would see if
/// invoked right now.
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
        daemon_path: PathBuf,
    },

    /// Two autostart mechanisms are active at the same time. Currently
    /// fires for: (macOS) brew-services + dev.agentsso.daemon plist
    /// both present; (Windows) Task Scheduler entry AND a leftover
    /// Story-7.2 `agentsso.lnk` in the Startup folder.
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
/// trait so unit tests can drive enable / disable / status logic
/// without invoking the real `launchctl` / `systemctl` / `schtasks`.
///
/// Not part of the public API — gated `pub(crate)` so the platform
/// modules + their tests can mock it; CLI consumers go through the
/// free functions [`enable`] / [`disable`] / [`status`] which use
/// [`RealExec`] internally.
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
/// can't hang `agentsso autostart enable` indefinitely. 30s is well
/// above any reasonable service-manager response time but well below
/// what an operator would consider "broken" — they'll Ctrl-C before
/// then anyway.
pub(crate) struct RealExec;

impl Engine for RealExec {
    fn run(&self, program: &str, args: &[&str]) -> std::io::Result<Output> {
        run_with_timeout(program, args, std::time::Duration::from_secs(30))
    }
}

/// Spawn a command + read its output, killing the process if it
/// hasn't exited within `timeout`. Pure-std implementation — no
/// extra crate dep — using `Command::spawn` + `Child::wait_timeout`
/// (manually polled because `wait_timeout` isn't on stable std yet).
///
/// Uses 100ms polling intervals which is plenty granular for
/// service-manager calls (typical wall-time: <1s).
fn run_with_timeout(
    program: &str,
    args: &[&str],
    timeout: std::time::Duration,
) -> std::io::Result<Output> {
    use std::io::Read as _;
    use std::time::Instant;

    let mut child = Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let start = Instant::now();
    loop {
        match child.try_wait()? {
            Some(status) => {
                // Process exited — drain stdout/stderr and return.
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(mut h) = child.stdout.take() {
                    let _ = h.read_to_end(&mut stdout);
                }
                if let Some(mut h) = child.stderr.take() {
                    let _ = h.read_to_end(&mut stderr);
                }
                return Ok(Output { status, stdout, stderr });
            }
            None => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
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
    }
}

/// Reject paths that aren't valid UTF-8 with a clean structured error.
///
/// **P36 (code review round 3):** the per-platform XML/plist/unit
/// renderers used `to_string_lossy()`, which silently replaces invalid
/// UTF-8 bytes with U+FFFD. The rendered artifact then embeds a path
/// the OS service manager can't resolve, and the operator sees an
/// opaque "file not found" instead of a clear "your daemon path
/// contains non-UTF-8 bytes". Pre-flight check at the public API
/// boundary so the failure surfaces before we corrupt the artifact.
pub(crate) fn require_utf8_path(p: &Path) -> std::io::Result<&str> {
    p.to_str().ok_or_else(|| {
        std::io::Error::other(format!(
            "path contains non-UTF-8 bytes: {} — autostart cannot embed this path \
             into the platform service-manager artifact (LaunchAgent plist / \
             systemd unit / Task XML are all UTF-8 formats)",
            p.display()
        ))
    })
}

/// Resolve the absolute path of the currently-running `agentsso` binary
/// to embed in the platform service-manager artifact.
///
/// **P39 (code review round 4):** behavior on each platform:
///
/// - **macOS:** `std::env::current_exe()` reads `_NSGetExecutablePath`
///   which returns the path the user invoked (preserving symlinks).
///   `/opt/homebrew/bin/agentsso` (Homebrew's stable wrapper symlink)
///   stays stable across `brew upgrade`; the underlying Cellar path
///   `/opt/homebrew/Cellar/agentsso/<version>/bin/agentsso` does NOT.
///   Empirically verified 2026-04-26 with a test binary + symlink.
///   No fix needed on macOS.
///
/// - **Windows:** `current_exe()` uses `GetModuleFileNameW` which
///   also returns the invocation path. Story 7.2's installer puts
///   `agentsso.exe` at `%LOCALAPPDATA%\Programs\agentsso\` and
///   overwrites in place on upgrade — same path, stable. No fix
///   needed on Windows.
///
/// - **Linux:** `current_exe()` reads `/proc/self/exe` which the
///   kernel ALWAYS canonicalizes through symlinks. So a Homebrew-on-
///   Linux user invoking `/home/linuxbrew/.linuxbrew/bin/agentsso`
///   gets back the canonicalized Cellar path that breaks on upgrade.
///   We try to recover the invocation path from `argv[0]` first; if
///   that's a relative path or not on PATH, we fall back to
///   `current_exe()` (the canonicalized path) and accept the upgrade-
///   drift risk that Story 7.5's `agentsso update` is designed to
///   detect via [`AutostartStatus::Enabled::daemon_path`] vs runtime
///   `current_exe()` comparison.
pub fn current_daemon_path() -> std::io::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        // Try to recover the path the user invoked us through, BEFORE
        // /proc/self/exe canonicalizes the symlink chain.
        if let Some(arg0) = std::env::args_os().next() {
            let arg0_path = PathBuf::from(&arg0);
            // If argv[0] is an absolute path AND it exists on disk,
            // prefer it (preserves Homebrew's `/home/linuxbrew/.linuxbrew/bin/agentsso`
            // wrapper-symlink path across `brew upgrade`).
            if arg0_path.is_absolute() && arg0_path.exists() {
                return Ok(arg0_path);
            }
            // If argv[0] is a bare command name (no slashes), look it
            // up on PATH — the discovered path is what shells used to
            // invoke us, which is what we want embedded.
            if !arg0_path.to_string_lossy().contains('/') {
                if let Some(paths) = std::env::var_os("PATH") {
                    for dir in std::env::split_paths(&paths) {
                        let candidate = dir.join(&arg0_path);
                        if candidate.exists() {
                            return Ok(candidate);
                        }
                    }
                }
            }
        }
        // Last-resort: canonicalized exe path (current_exe). Story 7.5
        // owns recovery from any upgrade-drift this introduces.
        std::env::current_exe()
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::current_exe()
    }
}

/// Enable autostart on the host platform. See module docs for the
/// per-platform mechanism. OPT-IN: this is only invoked when the user
/// explicitly opts in via `agentsso autostart enable` or the setup
/// wizard prompt (which defaults to no).
pub fn enable() -> Result<EnableOutcome, AutostartError> {
    let exec = RealExec;
    let home = home_dir()?;
    enable_with(&exec, &home)
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

/// Outcome of a successful [`enable`] — surfaces side effects the CLI
/// reports to the operator (e.g., "removed Story 7.2 .lnk" migrations).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnableOutcome {
    /// Autostart was registered. `mechanism` is the platform-native
    /// label (`launchd` / `systemd-user` / `task-scheduler`).
    Registered { mechanism: &'static str, artifact_path: PathBuf },

    /// Autostart was registered AND a stale Story 7.2 install-time
    /// `agentsso.lnk` shortcut was migrated away. Windows only.
    /// CLI prints a `→ migrating autostart` info line.
    #[allow(dead_code)] // Constructed only by the windows backend.
    MigratedFromStartupShortcut { artifact_path: PathBuf, removed_shortcut: PathBuf },

    /// Autostart was already enabled — no-op. Idempotency.
    AlreadyEnabled { artifact_path: PathBuf },
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
pub(crate) fn enable_with(
    exec: &impl Engine,
    home: &Path,
) -> Result<EnableOutcome, AutostartError> {
    macos::enable(exec, home)
}

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
pub(crate) fn enable_with(
    exec: &impl Engine,
    home: &Path,
) -> Result<EnableOutcome, AutostartError> {
    linux::enable(exec, home)
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
pub(crate) fn enable_with(
    exec: &impl Engine,
    home: &Path,
) -> Result<EnableOutcome, AutostartError> {
    windows::enable(exec, home)
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
pub(crate) fn enable_with(
    _exec: &impl Engine,
    _home: &Path,
) -> Result<EnableOutcome, AutostartError> {
    Err(AutostartError::UnsupportedPlatform { platform: std::env::consts::OS })
}

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
/// without cfg-cross-import gymnastics.
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
/// past whole chars on the non-`&` path.
fn utf8_char_len(b: u8) -> usize {
    match b {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 1, // continuation byte or invalid — fall back to 1
    }
}

/// Atomic file write — write to `<path>.tmp.<pid>`, fsync, rename.
/// Same pattern as [`crate::lifecycle::pid::PidFile::acquire`]'s atomic
/// PID write; lifted here so platform modules don't each reinvent it.
///
/// **P3 + P4 (code review):**
/// - The temp file is `<path>.tmp.<pid>` (not just `<path>.tmp`), so two
///   concurrent writers don't collide on the same temp path AND we can't
///   accidentally clobber a user file literally named `agentsso.tmp`.
/// - On any error after the temp file is created, we explicitly remove
///   it so we don't orphan partial content (rendered plist / unit / Task
///   XML) on disk.
pub(crate) fn write_atomic(path: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_name = match path.file_name() {
        Some(name) => format!("{}.tmp.{}", name.to_string_lossy(), std::process::id()),
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path has no filename",
            ));
        }
    };
    let tmp = path.with_file_name(tmp_name);

    let result = (|| -> std::io::Result<()> {
        // P26 (re-triage of D2): use `create_new(true)` so we refuse to
        // open if the temp path already exists (e.g., a leftover from a
        // crashed prior run, OR a symlink an attacker pre-planted to
        // point our write at /etc/passwd or similar). Defense matches
        // the parent dir's ownership/mode posture (~/.agentsso/ etc.
        // are user-owned 0700) and adds a belt to the existing
        // braces.
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();

    if result.is_err() {
        // Best-effort cleanup of the temp file on any failure — don't
        // orphan partial content on disk. Ignore the cleanup error; the
        // original error is what the caller cares about.
        let _ = std::fs::remove_file(&tmp);
    }
    result
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
    fn current_daemon_path_returns_a_path() {
        let p = current_daemon_path().unwrap();
        // Whatever it is, it must be absolute (current_exe contract).
        assert!(p.is_absolute(), "expected absolute path, got {}", p.display());
    }

    #[test]
    fn write_atomic_creates_parent_dirs_and_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("nested/deeper/output.txt");
        write_atomic(&target, "hello\n").unwrap();
        let actual = std::fs::read_to_string(&target).unwrap();
        assert_eq!(actual, "hello\n");
        // The temp file should not be left behind.
        let tmp_file = target.with_extension("tmp");
        assert!(!tmp_file.exists(), "expected {} to be removed", tmp_file.display());
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
            daemon_path: "/usr/local/bin/agentsso".into(),
        };
        assert!(!disabled.is_enabled());
        assert!(!conflict.is_enabled());
        assert!(enabled.is_enabled());
    }
}
