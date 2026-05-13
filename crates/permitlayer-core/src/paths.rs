//! Centralized path resolution for the daemon's on-disk state, logs,
//! and runtime sockets.
//!
//! Story 7.26 (Foundations) introduces this module as the single
//! source of truth for "where does the daemon put its files?" Prior
//! to rc.22, every consumer (config defaults, autostart plist
//! generation, `agentsso stop`/`kill` PID-file lookup, audit log
//! sink, `agentsso credentials` table renderer) reached for
//! `dirs::home_dir().join(".agentsso")` independently. The 7.25
//! architectural pivot to a system LaunchDaemon on macOS replaces
//! that home-directory layout with `/Library/Application
//! Support/permitlayer/`, and the swap is tractable only when one
//! function body changes instead of grepping ~7 production sites.
//!
//! # Override semantics
//!
//! Every public function accepts `home_override: Option<&Path>` as
//! its second parameter. When `Some(path)`, the function returns
//! paths rooted at `path` directly (mirroring the existing
//! `AGENTSSO_PATHS__HOME` semantics — `<override>/vault/`,
//! `<override>/logs/`, etc.). This preserves the integration-test
//! contract used in 12+ test files (e.g.,
//! `crates/permitlayer-daemon/tests/integration/daemon_lifecycle.rs`)
//! that set `AGENTSSO_PATHS__HOME=<temp_dir>` before spawning the
//! daemon binary.
//!
//! When `None`, the function returns the per-platform default:
//! - macOS: the new system paths under `/Library/Application
//!   Support/permitlayer/`, `/Library/Logs/permitlayer/`,
//!   `/var/run/permitlayer/`. Story 7.27 lands the LaunchDaemon
//!   installer that creates these directories with the correct
//!   ownership; until then they may not exist on disk for fresh
//!   installs.
//! - Linux + Windows: the legacy `~/.agentsso/...` family. Those
//!   platforms get their own redesigns in future stories; this
//!   module preserves current behavior for them.
//!
//! # Why functions, not constants
//!
//! `dirs::home_dir()` is fallible (returns `Option<PathBuf>`), and
//! `~/.agentsso/...` paths only exist after the home dir is
//! resolved. Constants would force every caller to handle the
//! resolution; a function returning `PathBuf` collapses the work
//! into one place. The `home_override` parameter then becomes the
//! test seam without needing global mutable state.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Daemon state-dir root — vault, agents, plugins, config.
///
/// On macOS (rc.22+): `/Library/Application Support/permitlayer/`.
/// Created with mode 0700 owned root:wheel by `agentsso service
/// install` (Story 7.27).
///
/// On Linux + Windows: legacy `~/.agentsso/` (those platforms get
/// dedicated redesigns in future stories).
///
/// When `home_override = Some(path)`, returns `path` directly.
/// Convenience helper that reads `AGENTSSO_PATHS__HOME` once and
/// returns it as a `PathBuf`. Centralized so all consumers
/// (`start.rs`, `kill.rs`, `status.rs`, `control.rs`, ...) use the
/// same parsing semantics — if the env-var name or normalization
/// rules ever change, this is the single edit site.
///
/// Returns `None` for: unset env var, empty string, whitespace-only
/// string. Story 7.27 Round-2 review fix (P1): pre-fix
/// `std::env::var(...).ok().map(PathBuf::from)` returned
/// `Some(PathBuf::from(""))` on `AGENTSSO_PATHS__HOME=` (operator/
/// script clearing the override, common in CI). That produced
/// relative paths everywhere downstream: `control_socket_path()`
/// became `"run/control.sock"`, `vault_dir()` became `"vault"`,
/// daemon bound in CWD, CLI connected from a different CWD, fail.
/// Treating empty/whitespace as `None` falls back to the platform-
/// default system path layout.
///
/// Round-3 review note (R3-C5-P8): the returned PathBuf is NOT
/// canonicalized — if the override points at a symlink and the
/// target is rewritten between daemon-start and CLI-start, the
/// daemon binds the socket at one realpath while the CLI connects
/// to another (the kernel resolves through symlinks on
/// `bind`/`connect`, so this usually works, but it's fragile).
/// Operators should set this to the canonical absolute path of a
/// real directory, not a symlink.
pub fn home_override() -> Option<PathBuf> {
    std::env::var("AGENTSSO_PATHS__HOME").ok().and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return None;
        }
        // Round-3 review fix (R3-C5-P1): the Round-2 fix rejected the
        // empty/whitespace case but accepted everything else verbatim,
        // including relative paths and NUL-containing strings. A
        // relative path (`AGENTSSO_PATHS__HOME=tmp/run`) flows into
        // `control_socket_path()` and the daemon `bind`s in CWD while
        // the CLI `connect`s from a different CWD — same split-brain
        // failure mode the empty-string fix closed, just one layer
        // down. A NUL byte fails with `EINVAL` deep in libc with no
        // attributable context. Reject both up front with a structured
        // warn so operators see the misconfig.
        if trimmed.contains('\0') {
            tracing::warn!(
                event = "paths.home_override.invalid",
                reason = "embedded_nul",
                "AGENTSSO_PATHS__HOME contains an embedded NUL byte; ignoring (falling back to platform default)",
            );
            return None;
        }
        let path = std::path::Path::new(trimmed);
        if !path.is_absolute() {
            tracing::warn!(
                event = "paths.home_override.invalid",
                reason = "not_absolute",
                value = trimmed,
                "AGENTSSO_PATHS__HOME must be an absolute path; ignoring (falling back to platform default). Daemon and CLI need to agree on the path regardless of CWD.",
            );
            return None;
        }
        Some(PathBuf::from(trimmed))
    })
}

pub fn daemon_state_dir(home_override: Option<&Path>) -> PathBuf {
    if let Some(p) = home_override {
        return p.to_path_buf();
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/permitlayer")
    }
    #[cfg(not(target_os = "macos"))]
    {
        legacy_dot_agentsso()
    }
}

/// Daemon log-dir.
///
/// On macOS (rc.22+): `/Library/Logs/permitlayer/`. Created with
/// mode 0750 owned root:wheel by `agentsso service install`.
///
/// On Linux + Windows: `<state_dir>/logs/`.
///
/// When `home_override = Some(path)`, returns `path/logs/`.
pub fn daemon_log_dir(home_override: Option<&Path>) -> PathBuf {
    if let Some(p) = home_override {
        return p.join("logs");
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Logs/permitlayer")
    }
    #[cfg(not(target_os = "macos"))]
    {
        legacy_dot_agentsso().join("logs")
    }
}

/// Daemon runtime-dir — control sockets, runtime state files.
///
/// On macOS (rc.22+): `/var/run/permitlayer/`. Created with mode
/// 0755 by `agentsso service install`. The OS may clean `/var/run/`
/// at boot; the daemon recreates the directory on startup if
/// missing.
///
/// On Linux: `/run/agentsso/`.
///
/// On Windows: `<state_dir>/run/`.
///
/// When `home_override = Some(path)`, returns `path/run/`.
pub fn daemon_runtime_dir(home_override: Option<&Path>) -> PathBuf {
    if let Some(p) = home_override {
        return p.join("run");
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/var/run/permitlayer")
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/run/agentsso")
    }
    #[cfg(target_os = "windows")]
    {
        legacy_dot_agentsso().join("run")
    }
}

/// Path of the control-plane Unix domain socket.
///
/// Story 7.27 lands the UDS listener; this constant is the agreed
/// path so 7.26 can centralize it without 7.27 needing to grep for
/// scattered string literals.
///
/// Not used on Windows (named-pipe path on that platform; a future
/// story decides the exact form).
pub fn control_socket_path(home_override: Option<&Path>) -> PathBuf {
    daemon_runtime_dir(home_override).join("control.sock")
}

/// MCP listener socket address — kept on loopback TCP for
/// backwards-compat with MCP clients (OpenClaw, Claude Desktop,
/// Cursor) that speak HTTP-over-TCP "streamable-http" per the MCP
/// spec and cannot connect to Unix sockets.
///
/// See Story 7.25 AC #9 (split-listener design): MCP routes stay on
/// TCP; control plane moves to UDS in Story 7.27.
pub fn mcp_listener_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 3820))
}

/// Vault directory — encrypted credential envelopes.
pub fn vault_dir(home_override: Option<&Path>) -> PathBuf {
    daemon_state_dir(home_override).join("vault")
}

/// Agents directory — agent identity records.
pub fn agents_dir(home_override: Option<&Path>) -> PathBuf {
    daemon_state_dir(home_override).join("agents")
}

/// Plugins directory — drop-in plugin loader.
pub fn plugins_dir(home_override: Option<&Path>) -> PathBuf {
    daemon_state_dir(home_override).join("plugins")
}

/// Audit log path.
pub fn audit_log_path(home_override: Option<&Path>) -> PathBuf {
    daemon_log_dir(home_override).join("audit.log")
}

/// Resolve the legacy `~/.agentsso/` path. Used by Linux + Windows
/// defaults (those platforms get dedicated redesigns later).
///
/// Falls back to a relative `.agentsso/` if `dirs::home_dir()`
/// returns `None`. The fallback matches the prior
/// `unwrap_or_else(|| PathBuf::from(".agentsso"))` pattern at the
/// call sites this module replaces — preserving exact behavior so
/// the C1 commit is a pure refactor.
#[cfg(not(target_os = "macos"))]
fn legacy_dot_agentsso() -> PathBuf {
    dirs::home_dir().map(|h| h.join(".agentsso")).unwrap_or_else(|| PathBuf::from(".agentsso"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_propagates_to_all_derived_paths() {
        let tmp = std::path::Path::new("/tmp/agentsso-test-xyz");
        let state = daemon_state_dir(Some(tmp));
        let logs = daemon_log_dir(Some(tmp));
        let run = daemon_runtime_dir(Some(tmp));
        let vault = vault_dir(Some(tmp));
        let agents = agents_dir(Some(tmp));
        let plugins = plugins_dir(Some(tmp));
        let audit = audit_log_path(Some(tmp));
        let sock = control_socket_path(Some(tmp));

        assert_eq!(state, tmp);
        assert_eq!(logs, tmp.join("logs"));
        assert_eq!(run, tmp.join("run"));
        assert_eq!(vault, tmp.join("vault"));
        assert_eq!(agents, tmp.join("agents"));
        assert_eq!(plugins, tmp.join("plugins"));
        assert_eq!(audit, tmp.join("logs").join("audit.log"));
        assert_eq!(sock, tmp.join("run").join("control.sock"));
    }

    #[test]
    fn mcp_listener_addr_is_loopback_3820() {
        let addr = mcp_listener_addr();
        assert!(addr.ip().is_loopback());
        assert_eq!(addr.port(), 3820);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_default_paths_use_library_application_support() {
        let state = daemon_state_dir(None);
        assert_eq!(state, PathBuf::from("/Library/Application Support/permitlayer"));

        let logs = daemon_log_dir(None);
        assert_eq!(logs, PathBuf::from("/Library/Logs/permitlayer"));

        let run = daemon_runtime_dir(None);
        assert_eq!(run, PathBuf::from("/var/run/permitlayer"));

        // Derived paths anchor under state_dir.
        let vault = vault_dir(None);
        assert_eq!(vault, PathBuf::from("/Library/Application Support/permitlayer/vault"));

        // control_socket_path lives under runtime_dir, not state_dir.
        let sock = control_socket_path(None);
        assert_eq!(sock, PathBuf::from("/var/run/permitlayer/control.sock"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_default_paths_use_dot_agentsso() {
        let state = daemon_state_dir(None);
        // Hard to assert exact path because it depends on $HOME, but
        // the trailing component must be `.agentsso`.
        assert_eq!(
            state.file_name().expect("daemon_state_dir must have a final component"),
            ".agentsso"
        );

        // Linux runtime dir is /run/agentsso (the systemd-canonical
        // location), not under $HOME.
        let run = daemon_runtime_dir(None);
        assert_eq!(run, PathBuf::from("/run/agentsso"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_default_paths_use_dot_agentsso() {
        let state = daemon_state_dir(None);
        assert_eq!(
            state.file_name().expect("daemon_state_dir must have a final component"),
            ".agentsso"
        );
    }
}
