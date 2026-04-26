//! Linux systemd-user backend for [`crate::lifecycle::autostart`].
//!
//! Writes a per-user unit at `~/.config/systemd/user/agentsso.service`
//! and enables it via `systemctl --user enable --now agentsso.service`.
//!
//! # Why user-systemd, not the system unit?
//!
//! PRD §389 mandates "no root/sudo required." A system unit at
//! `/etc/systemd/system/` would require `sudo systemctl enable`. The
//! user unit lives in `$XDG_CONFIG_HOME/systemd/user/` (which we
//! resolve as `~/.config/systemd/user/` per architecture.md:962) and
//! enables without elevation.
//!
//! # Linger gotcha (NOT enabled)
//!
//! By default, user-systemd sessions exit when the user logs out — the
//! daemon would die on logout, then start up again at next login. For
//! "starts at boot, runs continuously" semantics, the user needs
//! `loginctl enable-linger $USER` (one-time, requires `sudo`). We
//! deliberately DO NOT enable linger — it matches macOS LaunchAgent
//! semantics ("auto-start at login; lifecycle tied to the session"),
//! avoids the sudo prompt, and lets users opt into linger themselves
//! if they want daemon-survives-logout. Documented in
//! `docs/user-guide/install.md` per Story 7.3 Task 8.
//!
//! # Restart posture
//!
//! Mirrors the macOS-side `KeepAlive.SuccessfulExit=false` lesson from
//! Story 7.1 v0.2.1: restart on crash (`Restart=on-failure`), NOT on
//! every exit (`Restart=always`). Avoids the silent respawn-loop on
//! manual `agentsso stop`.

use std::path::{Path, PathBuf};

use super::{
    AutostartError, AutostartStatus, DisableOutcome, EnableOutcome, Engine, current_daemon_path,
    service_manager_failed, write_atomic,
};

const UNIT_NAME: &str = "agentsso.service";
const MECHANISM: &str = "systemd-user";

/// Resolve the absolute unit path under the given home dir:
/// `<home>/.config/systemd/user/agentsso.service`.
pub(crate) fn unit_path(home: &Path) -> PathBuf {
    home.join(".config").join("systemd").join("user").join(UNIT_NAME)
}

/// Render the systemd unit body for the given daemon-binary path.
///
/// Plain INI; no escaping needed beyond literal newlines (systemd does
/// NOT support `%`-expansion of arbitrary characters in `ExecStart`,
/// but absolute paths to a Rust binary are well-behaved).
///
/// `Restart=on-failure` + `RestartSec=5s` per Dev Notes — same lesson
/// as the macOS plist's `KeepAlive.SuccessfulExit=false`. Don't restart
/// on clean exit (manual `agentsso stop` shouldn't respawn-loop).
pub(crate) fn render_unit(daemon_path: &Path) -> String {
    format!(
        "\
[Unit]
Description=AgentSSO daemon (per-user autostart)
Documentation=https://github.com/permitlayer/permitlayer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={daemon} start
Restart=on-failure
RestartSec=5s
# P27 (re-triage of D12): bump LimitNOFILE above the default 1024 —
# a daemon brokering many concurrent agent connections + audit log
# writes hits the default ceiling and starts failing with EMFILE
# silently. 65536 matches the workspace-wide ceiling we already use
# for the macOS plist (LaunchAgents inherit user defaults; on
# typical macOS that's ~10240, well below the Linux default's
# squeeze). Out-of-tree operators with stricter security baselines
# can override via systemd drop-in files in
# ~/.config/systemd/user/agentsso.service.d/.
LimitNOFILE=65536
# Keep the journal entries — operator can `journalctl --user -u agentsso`.
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
",
        daemon = daemon_path.display(),
    )
}

/// Linux [`super::enable`] implementation.
pub(crate) fn enable(exec: &impl Engine, home: &Path) -> Result<EnableOutcome, AutostartError> {
    ensure_systemd_available(exec)?;

    let unit = unit_path(home);
    let daemon = current_daemon_path()?;
    // P36: reject non-UTF-8 daemon paths — `ExecStart=` can't faithfully
    // represent invalid bytes; the systemd unit is UTF-8.
    super::require_utf8_path(&daemon)?;
    // P31 (code review round 3): only return `AlreadyEnabled` when the
    // unit content is EXACTLY what we'd write. A stale unit from a
    // prior install with a different daemon path counts as a refresh,
    // not a no-op.
    let body = render_unit(&daemon);
    let unchanged = unit
        .exists()
        .then(|| std::fs::read_to_string(&unit).ok())
        .flatten()
        .map(|existing| existing == body)
        .unwrap_or(false);
    write_atomic(&unit, &body)?;

    // daemon-reload — picks up the new unit file.
    let args = ["--user", "daemon-reload"];
    let out = exec.run("systemctl", &args)?;
    if !out.status.success() {
        return Err(service_manager_failed("systemctl", &args, &out));
    }

    // enable --now: enables at next login + starts immediately.
    let args = ["--user", "enable", "--now", UNIT_NAME];
    let out = exec.run("systemctl", &args)?;
    if !out.status.success() {
        return Err(service_manager_failed("systemctl", &args, &out));
    }

    if unchanged {
        Ok(EnableOutcome::AlreadyEnabled { artifact_path: unit })
    } else {
        Ok(EnableOutcome::Registered { mechanism: MECHANISM, artifact_path: unit })
    }
}

/// Linux [`super::disable`] implementation. Idempotent.
pub(crate) fn disable(exec: &impl Engine, home: &Path) -> Result<DisableOutcome, AutostartError> {
    let unit = unit_path(home);
    if !unit.exists() {
        return Ok(DisableOutcome::AlreadyDisabled);
    }

    // disable --now: stops + removes from default.target. systemctl
    // returns 5 ("Unit not found" / "no such file") if the unit was
    // never enabled — treat as success for idempotency.
    let args = ["--user", "disable", "--now", UNIT_NAME];
    let out = exec.run("systemctl", &args)?;
    if !out.status.success() && out.status.code() != Some(5) {
        return Err(service_manager_failed("systemctl", &args, &out));
    }

    std::fs::remove_file(&unit)?;

    // P5 (code review): re-run `daemon-reload` after deleting the unit
    // file so systemd's in-memory cache drops the stale entry. Without
    // this, a follow-up `systemctl --user start agentsso.service`
    // immediately after disable would pick up the cached unit definition
    // and try to start a daemon from a now-missing file. Best-effort —
    // a daemon-reload failure here doesn't undo the disable.
    let reload_args = ["--user", "daemon-reload"];
    let _ = exec.run("systemctl", &reload_args);

    Ok(DisableOutcome::Removed { mechanism: MECHANISM, artifact_path: unit })
}

/// Linux [`super::status`] implementation.
///
/// **P35 (code review round 3):** verifies BOTH that the unit file
/// exists AND that systemd has actually enabled it (via
/// `systemctl --user is-enabled agentsso.service`). Previously we
/// only checked file presence — a leftover unit from a failed
/// `enable --now` would falsely report `Enabled` even though the
/// daemon would never auto-start.
pub(crate) fn status(exec: &impl Engine, home: &Path) -> Result<AutostartStatus, AutostartError> {
    let unit = unit_path(home);
    if !unit.exists() {
        return Ok(AutostartStatus::Disabled);
    }

    // P35: probe systemd. `is-enabled` returns 0 when the unit is
    // enabled (or `linked`/`static`/`alias`), non-zero otherwise. If
    // systemctl is unavailable, fall back to file-presence — the
    // `enable` path would have refused that host anyway.
    let probe_args = ["--user", "is-enabled", UNIT_NAME];
    let enabled_in_systemd = match exec.run("systemctl", &probe_args) {
        Ok(out) => out.status.success(),
        Err(_) => true, // systemctl missing → trust the file
    };
    if !enabled_in_systemd {
        return Ok(AutostartStatus::Disabled);
    }

    let body = std::fs::read_to_string(&unit)?;
    let daemon_path = parse_exec_start(&body).unwrap_or_default();
    Ok(AutostartStatus::Enabled { artifact_path: unit, mechanism: MECHANISM, daemon_path })
}

/// Probe whether the user's systemd manager is actually reachable.
///
/// **P11 (code review):** the previous probe ran `systemctl --user
/// --version`, which prints the systemctl client version and exits 0
/// EVEN WHEN there is no running per-user systemd manager (e.g., WSL2
/// without `[boot] systemd=true`, sysvinit container with the
/// systemctl binary still installed, fresh root-only container with no
/// `XDG_RUNTIME_DIR`). The downstream `systemctl --user enable --now`
/// then fails with the cryptic `Failed to connect to bus`.
///
/// `systemctl --user is-system-running` actually reaches the user bus
/// and returns the manager's state (`running` / `degraded` / `starting`
/// / `offline`). On hosts where the user manager isn't running it
/// fails with a clear error. We accept any status from the user
/// manager (even `degraded` is fine — that just means SOME unit
/// failed; ours is still installable).
fn ensure_systemd_available(exec: &impl Engine) -> Result<(), AutostartError> {
    let args = ["--user", "is-system-running"];
    match exec.run("systemctl", &args) {
        // `is-system-running` returns 0 only when the manager is fully
        // `running`. Any non-zero exit accompanied by a state name on
        // stdout (`degraded`, `starting`, `maintenance`) is fine — the
        // manager IS reachable. Only when stdout is empty AND the
        // command failed do we conclude the bus isn't reachable.
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
            // Reachable manager states.
            const REACHABLE: &[&str] =
                &["running", "degraded", "starting", "maintenance", "stopping"];
            if out.status.success() || REACHABLE.contains(&stdout.as_str()) {
                Ok(())
            } else {
                Err(AutostartError::SystemdUnavailable {
                    detail: if !stderr.is_empty() {
                        stderr
                    } else if !stdout.is_empty() {
                        format!("systemctl reported state: {stdout}")
                    } else {
                        format!("systemctl --user is-system-running exited {:?}", out.status.code())
                    },
                })
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(AutostartError::SystemdUnavailable {
                detail: "systemctl not on PATH (this host may have a non-systemd init system; \
                         WSL2 users: enable systemd via /etc/wsl.conf [boot] systemd=true)"
                    .to_owned(),
            })
        }
        Err(e) => Err(AutostartError::Io(e)),
    }
}

/// Parse `ExecStart=...` out of the rendered unit. The render shape is
/// always `<abs-path> start` so we strip the FINAL ` start` suffix only.
///
/// **P17 (code review):** the previous impl used `trim_end_matches`,
/// which strips ALL trailing repetitions of ` start`. A daemon path
/// like `/home/maya/dev/foo start/agentsso start` (legal directory
/// names with spaces) would be over-truncated to
/// `/home/maya/dev/foo`. `rsplit_once` removes only the last
/// occurrence, preserving any path-internal ` start` substrings.
fn parse_exec_start(body: &str) -> Option<PathBuf> {
    for line in body.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("ExecStart=") {
            // Strip exactly the trailing ` start` subcommand marker;
            // anything before it is the daemon path (which may itself
            // contain spaces or the literal substring " start").
            let path = match rest.rsplit_once(" start") {
                Some((path, "")) => path,
                _ => rest, // no trailing " start" — return the whole rest.
            };
            return Some(PathBuf::from(path));
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::tests::MockExec;
    use super::*;

    #[test]
    fn unit_renders_canonical_layout() {
        // P1: replaced an `insta::assert_snapshot!` with explicit asserts.
        // The cfg(target_os="linux") gating means snapshot files can only
        // be generated on a Linux host; insta defaults to FAIL when the
        // .snap is missing, so a macOS-developed PR + Linux CI runner
        // that hasn't seen a snapshot yet would land red. Direct
        // field-presence checks pin the same load-bearing invariants
        // without the snapshot-file lifecycle problem.
        let body = render_unit(Path::new("/usr/local/bin/agentsso"));

        // Section markers — proves the [Unit]/[Service]/[Install]
        // structure is intact.
        assert!(body.contains("[Unit]"), "missing [Unit] section");
        assert!(body.contains("[Service]"), "missing [Service] section");
        assert!(body.contains("[Install]"), "missing [Install] section");

        // Load-bearing fields — match the spec + the lessons from Story
        // 7.1 v0.2.1 hotfix (Restart=on-failure, NOT always).
        assert!(
            body.contains("ExecStart=/usr/local/bin/agentsso start"),
            "ExecStart line wrong: {body}"
        );
        assert!(body.contains("Type=simple"), "missing Type=simple");
        assert!(
            body.contains("Restart=on-failure"),
            "missing Restart=on-failure (don't restart on clean exit — Story 7.1 lesson)"
        );
        assert!(body.contains("RestartSec=5s"), "missing RestartSec=5s");
        assert!(
            body.contains("WantedBy=default.target"),
            "missing WantedBy=default.target (per-user autostart anchor)"
        );

        // Negative assertions — guard against future "tidy the unit"
        // edits that would silently regress the load-bearing posture.
        assert!(
            !body.contains("Restart=always"),
            "Restart=always reintroduces the v0.2.1 respawn-loop bug"
        );

        // P27 (re-triage of D12): pin LimitNOFILE override against the
        // systemd-user default of 1024 — easy to silently regress.
        assert!(
            body.contains("LimitNOFILE=65536"),
            "LimitNOFILE override missing — daemon will hit EMFILE under load: {body}"
        );
    }

    #[test]
    fn parse_exec_start_round_trips() {
        let body = render_unit(Path::new("/usr/local/bin/agentsso"));
        assert_eq!(parse_exec_start(&body), Some(PathBuf::from("/usr/local/bin/agentsso")));
    }

    #[test]
    fn parse_exec_start_preserves_internal_space_start() {
        // P17: a daemon path containing the literal substring ` start`
        // (legal in directory names) must NOT be over-truncated. The
        // FINAL ` start` is the subcommand marker.
        let body = render_unit(Path::new("/home/maya/dev/foo start/agentsso"));
        assert_eq!(
            parse_exec_start(&body),
            Some(PathBuf::from("/home/maya/dev/foo start/agentsso"))
        );
    }

    #[test]
    fn ensure_systemd_available_rejects_when_missing() {
        let mock = MockExec::default();
        mock.push_reply(Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no systemctl")));
        let result = ensure_systemd_available(&mock);
        assert!(matches!(result, Err(AutostartError::SystemdUnavailable { .. })));
    }

    #[test]
    fn ensure_systemd_available_passes_when_present() {
        let mock = MockExec::default();
        // `is-system-running` returns "running" + exit 0 on a happy host.
        mock.push_reply(MockExec::ok("running\n"));
        ensure_systemd_available(&mock).unwrap();
    }

    #[test]
    fn ensure_systemd_available_passes_on_degraded_state() {
        // `is-system-running` returns "degraded" + exit 1 when SOME
        // unrelated unit failed; the manager is still reachable and
        // can install our unit. P11 (code review) accepts this.
        let mock = MockExec::default();
        mock.push_reply(MockExec::fail(1, "")); // P11: but we need stdout=degraded
        // The fail() helper sets stderr but not stdout. Inject manually:
        // override the queued reply with one carrying "degraded" on stdout.
        mock.replies.borrow_mut().clear();
        let reply = {
            #[cfg(unix)]
            use std::os::unix::process::ExitStatusExt as _;
            #[cfg(windows)]
            use std::os::windows::process::ExitStatusExt as _;
            #[cfg(unix)]
            let raw = 1 << 8;
            #[cfg(windows)]
            let raw: u32 = 1;
            Ok(std::process::Output {
                status: std::process::ExitStatus::from_raw(raw),
                stdout: b"degraded\n".to_vec(),
                stderr: Vec::new(),
            })
        };
        mock.replies.borrow_mut().push_back(reply);
        ensure_systemd_available(&mock).unwrap();
    }

    #[test]
    fn ensure_systemd_available_rejects_on_offline_state() {
        // `is-system-running` returns "offline" when the user bus isn't
        // reachable — must reject with `SystemdUnavailable`.
        let mock = MockExec::default();
        let reply = {
            #[cfg(unix)]
            use std::os::unix::process::ExitStatusExt as _;
            #[cfg(windows)]
            use std::os::windows::process::ExitStatusExt as _;
            #[cfg(unix)]
            let raw = 1 << 8;
            #[cfg(windows)]
            let raw: u32 = 1;
            Ok(std::process::Output {
                status: std::process::ExitStatus::from_raw(raw),
                stdout: b"offline\n".to_vec(),
                stderr: Vec::new(),
            })
        };
        mock.replies.borrow_mut().push_back(reply);
        assert!(matches!(
            ensure_systemd_available(&mock),
            Err(AutostartError::SystemdUnavailable { .. })
        ));
    }

    #[test]
    fn enable_writes_unit_and_runs_daemon_reload_then_enable_now() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mock = MockExec::default();
        mock.push_reply(MockExec::ok("running\n")); // P11: is-system-running probe
        mock.push_reply(MockExec::ok("")); // daemon-reload
        mock.push_reply(MockExec::ok("")); // enable --now

        let outcome = enable(&mock, tmp.path()).unwrap();
        assert!(matches!(outcome, EnableOutcome::Registered { mechanism: "systemd-user", .. }));

        let calls = mock.calls.borrow();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].1, vec!["--user", "is-system-running"]);
        assert_eq!(calls[1].1, vec!["--user", "daemon-reload"]);
        assert_eq!(calls[2].1, vec!["--user", "enable", "--now", "agentsso.service"]);

        // Unit file actually written.
        let unit = unit_path(tmp.path());
        let body = std::fs::read_to_string(&unit).unwrap();
        assert!(body.contains("ExecStart="));
        assert!(body.contains("Restart=on-failure"));
    }

    #[test]
    fn disable_idempotent_when_unit_missing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mock = MockExec::default();
        let outcome = disable(&mock, tmp.path()).unwrap();
        assert!(matches!(outcome, DisableOutcome::AlreadyDisabled));
        assert!(mock.calls.borrow().is_empty());
    }

    #[test]
    fn disable_tolerates_unit_not_found_exit_5() {
        let tmp = tempfile::TempDir::new().unwrap();
        let unit = unit_path(tmp.path());
        std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
        std::fs::write(&unit, render_unit(Path::new("/x"))).unwrap();

        let mock = MockExec::default();
        mock.push_reply(MockExec::fail(
            5,
            "Failed to disable unit: Unit file agentsso.service does not exist",
        ));
        // P5: disable also fires a final `daemon-reload` (best-effort).
        mock.push_reply(MockExec::ok(""));

        let outcome = disable(&mock, tmp.path()).unwrap();
        assert!(matches!(outcome, DisableOutcome::Removed { .. }));
        assert!(!unit.exists());
    }

    #[test]
    fn status_reports_disabled_when_no_unit() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mock = MockExec::default();
        let st = status(&mock, tmp.path()).unwrap();
        assert_eq!(st, AutostartStatus::Disabled);
    }
}
