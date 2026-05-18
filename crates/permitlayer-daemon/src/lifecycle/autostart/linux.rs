//! Linux systemd-user backend for [`crate::lifecycle::autostart`].
//!
//! The autostart-managed unit lives at
//! `~/.config/systemd/user/agentsso.service`. The `enable` path that
//! wrote the unit + ran `systemctl --user enable --now` was removed;
//! this backend now only reports [`status`] and tears the unit down
//! via [`disable`].
//!
//! # Why user-systemd, not the system unit?
//!
//! PRD §389 mandates "no root/sudo required." A system unit at
//! `/etc/systemd/system/` would require `sudo systemctl disable`. The
//! user unit lives in `$XDG_CONFIG_HOME/systemd/user/` (which we
//! resolve as `~/.config/systemd/user/` per architecture.md:962) and
//! is removable without elevation.

use std::path::{Path, PathBuf};

use super::{AutostartError, AutostartStatus, DisableOutcome, Engine, service_manager_failed};

const UNIT_NAME: &str = "agentsso.service";
const MECHANISM: &str = "systemd-user";

/// Resolve the absolute unit path under the given home dir:
/// `<home>/.config/systemd/user/agentsso.service`.
pub(crate) fn unit_path(home: &Path) -> PathBuf {
    home.join(".config").join("systemd").join("user").join(UNIT_NAME)
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
    //
    // **P59 (code review round 5, M11):** if the user-systemd manager
    // is unreachable (D-Bus crashed, post-logout, container without a
    // user-bus), `systemctl --user disable` returns code 1 with
    // "Failed to connect to bus" on stderr. The previous code hard-
    // failed in that case, so the operator couldn't remove a stale
    // unit file just because the bus was offline. Now: detect the
    // bus-unreachable shape and fall through to file removal with a
    // logged warning.
    let args = ["--user", "disable", "--now", UNIT_NAME];
    let out = exec.run("systemctl", &args)?;
    if !out.status.success() && out.status.code() != Some(5) {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let bus_offline = stderr.contains("Failed to connect to bus")
            || stderr.contains("No such file or directory") && stderr.contains("dbus");
        if !bus_offline {
            return Err(service_manager_failed("systemctl", &args, &out));
        }
        tracing::warn!(
            stderr = %stderr.trim(),
            "systemctl --user disable failed because the user-bus is unreachable; \
             removing the unit file anyway so disable is idempotent"
        );
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
    // **P63 (code review round 5, D4-promoted):** reject symlinks at
    // the expected unit path — see macos.rs for rationale. The
    // autostart subsystem only writes regular files via
    // `write_atomic`; a symlink here means out-of-band edit and
    // surfacing a daemon_path through it would break Story 7.5
    // drift detection.
    let unit_present = match std::fs::symlink_metadata(&unit) {
        Ok(meta) => meta.file_type().is_file(),
        Err(_) => false,
    };
    if !unit_present {
        return Ok(AutostartStatus::Disabled);
    }

    // P35: probe systemd. `is-enabled` returns 0 + a state string
    // on stdout for any of: `enabled`, `enabled-runtime`, `linked`,
    // `linked-runtime`, `alias`, `static`, `indirect`, `generated`,
    // `transient`. Non-zero exit indicates `disabled`, `masked`, or
    // a bus failure.
    //
    // **P58 (code review round 5, M10):** the previous code matched
    // any exit-0 as "enabled", which let `static`, `linked`, and
    // `masked`-via-stdout (some systemd versions return 0 +
    // "masked" in unusual configurations) all report Enabled. But
    // `static` units lack `[Install]`, so they NEVER auto-start at
    // login — operators editing the unit to remove `[Install]`
    // would see misleading "enabled" status. Match the literal
    // `enabled` / `enabled-runtime` stdout tokens explicitly.
    let probe_args = ["--user", "is-enabled", UNIT_NAME];
    let enabled_in_systemd = match exec.run("systemctl", &probe_args) {
        Ok(out) => {
            if !out.status.success() {
                false
            } else {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let token = stdout.trim();
                token == "enabled" || token == "enabled-runtime"
            }
        }
        Err(_) => true, // systemctl missing → trust the file
    };
    if !enabled_in_systemd {
        return Ok(AutostartStatus::Disabled);
    }

    let body = std::fs::read_to_string(&unit)?;
    let daemon_path = parse_exec_start(&body);
    Ok(AutostartStatus::Enabled { artifact_path: unit, mechanism: MECHANISM, daemon_path })
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
            // Take the prefix before the FINAL ` start`. Anything
            // after ` start` is treated as additional CLI args and
            // discarded — see P46 below. If there's no ` start` at
            // all, return the whole rest (legacy fallback for
            // hand-edited units).
            //
            // **P46 (code review round 5):** the previous form
            // `match rest.rsplit_once(" start") { Some((p, "")) => p,
            //   _ => rest }` only stripped the suffix when nothing
            // followed it. A future Story-7.5 ExecStart of the form
            // `/path/agentsso start --some-flag` would then return
            // the entire line including ` start --some-flag` as the
            // daemon_path, breaking drift detection. Now we always
            // take the prefix when ` start` is present.
            let path = match rest.rsplit_once(" start") {
                Some((path, _suffix)) => path,
                None => rest,
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

    /// Build a systemd unit body in the canonical shape the (now-removed)
    /// enable path used to write, for exercising the live `parse_exec_start`
    /// (still called by `status`).
    fn unit_body(daemon_path: &str) -> String {
        format!(
            "[Unit]\n\
             Description=AgentSSO daemon (per-user autostart)\n\n\
             [Service]\n\
             Type=simple\n\
             ExecStart={daemon_path} start\n\
             Restart=on-failure\n\n\
             [Install]\n\
             WantedBy=default.target\n"
        )
    }

    #[test]
    fn parse_exec_start_round_trips() {
        let body = unit_body("/usr/local/bin/agentsso");
        assert_eq!(parse_exec_start(&body), Some(PathBuf::from("/usr/local/bin/agentsso")));
    }

    #[test]
    fn parse_exec_start_preserves_internal_space_start() {
        // P17: a daemon path containing the literal substring ` start`
        // (legal in directory names) must NOT be over-truncated. The
        // FINAL ` start` is the subcommand marker.
        let body = unit_body("/home/maya/dev/foo start/agentsso");
        assert_eq!(
            parse_exec_start(&body),
            Some(PathBuf::from("/home/maya/dev/foo start/agentsso"))
        );
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
        std::fs::write(&unit, unit_body("/x")).unwrap();

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
