//! Windows Task Scheduler backend for [`crate::lifecycle::autostart`].
//!
//! The autostart-managed per-user task is named `AgentSSO Daemon`
//! (registered via `schtasks`, built-in to Windows since XP — no extra
//! dependency, no `windows-rs` crate weight). The `enable` path that
//! registered the task + wrote its XML record was removed; this backend
//! now only reports [`status`] and tears the task down via [`disable`].
//!
//! # Startup-folder shortcut cleanup
//!
//! Story 7.2's `install.ps1 -Autostart` ships a Startup-folder
//! shortcut at `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\agentsso.lnk`
//! as install-time minimum. [`disable`] removes any stray `agentsso.lnk`
//! alongside the Task Scheduler entry, and [`status`] surfaces a
//! task + `.lnk` coexistence as [`AutostartStatus::Conflict`].

use std::path::{Path, PathBuf};

use super::{AutostartError, AutostartStatus, DisableOutcome, Engine, service_manager_failed};

const TASK_NAME: &str = "AgentSSO Daemon";
const MECHANISM: &str = "task-scheduler";

/// Resolve the on-disk path we use as a record of the registered task.
///
/// Task Scheduler stores its real state in the registry; we additionally
/// stash a copy of the rendered XML at this path so [`status`] can read
/// the embedded daemon path back out (mirrors macOS plist + Linux unit
/// patterns; lets Story 7.5 detect post-upgrade path drift).
pub(crate) fn xml_record_path(home: &Path) -> PathBuf {
    // Story 7.26 code-review round 2 (R1): this site receives the user's
    // home directory (from `autostart::home_dir()`, which returns
    // `dirs::home_dir()` — NOT a state-dir root). Routing through
    // `paths::daemon_state_dir(Some(home))` would drop the `.agentsso`
    // segment in production. Per-user Task Scheduler artifacts stay
    // anchored to the user's home dir and are intentionally exempt
    // from the centralized path module.
    home.join(".agentsso").join("autostart").join("task-scheduler.xml")
}

/// Resolve the Story 7.2 Startup-folder shortcut path. Filename pinned
/// to `agentsso.lnk` per Story 7.2 Dev Notes "Cross-story fences" item 1.
///
/// **P56 (code review round 5, M8):** the previous implementation
/// hardcoded `home/AppData/Roaming/...`. Domain-joined Windows hosts
/// often have `%APPDATA%` redirected to a network share via Folder
/// Redirection — Story 7.2's `install.ps1` reads `$env:APPDATA`, so
/// the install-time `.lnk` lives wherever APPDATA points, NOT
/// necessarily under `%USERPROFILE%`. With the old hardcoded path,
/// AC #6 (migration on `enable`) would silently fail to find +
/// remove the shortcut on redirected profiles. Now: prefer
/// `$env:APPDATA` when set, fall back to the home-relative path
/// (which is what tests pass via tempdirs).
pub(crate) fn startup_shortcut_path(home: &Path) -> PathBuf {
    // Tests pass a tempdir via `home` and rely on the produced path
    // landing inside that tempdir; honor that path under
    // `cfg(test)` regardless of whether `%APPDATA%` is set in the
    // test environment.
    if !cfg!(test)
        && let Ok(appdata) = std::env::var("APPDATA")
        && !appdata.is_empty()
    {
        return PathBuf::from(appdata)
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Startup")
            .join("agentsso.lnk");
    }
    home.join("AppData")
        .join("Roaming")
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("Startup")
        .join("agentsso.lnk")
}

/// Windows [`super::disable`] implementation. Idempotent; also removes
/// any leftover Story 7.2 `agentsso.lnk` (per AC #2 / AC #6).
pub(crate) fn disable(exec: &impl Engine, home: &Path) -> Result<DisableOutcome, AutostartError> {
    let xml_path = xml_record_path(home);
    let shortcut = startup_shortcut_path(home);

    let xml_existed = xml_path.exists();
    // P18 (code review): make `task_registered` probe best-effort here —
    // a transient WMI / RPC error on disable shouldn't strand the user
    // with leftover XML record + .lnk. Treat probe failure as "task is
    // not registered" so we still attempt to clean up the on-disk
    // artifacts. The downstream schtasks /Delete /F is itself
    // idempotent across "task does not exist" cases.
    let task_active = task_registered(exec).unwrap_or(false);
    let shortcut_existed = shortcut.exists();

    if !xml_existed && !task_active && !shortcut_existed {
        return Ok(DisableOutcome::AlreadyDisabled);
    }

    if task_active {
        // `/F` makes schtasks /Delete idempotent across "task does not
        // exist" cases — exits 0 even if the named task is missing.
        let args = ["/Delete", "/TN", TASK_NAME, "/F"];
        let out = exec.run("schtasks", &args)?;
        if !out.status.success() && !task_already_gone(&out) {
            return Err(service_manager_failed("schtasks", &args, &out));
        }
    }

    if xml_existed {
        let _ = std::fs::remove_file(&xml_path);
    }

    if shortcut_existed {
        let _ = std::fs::remove_file(&shortcut);
        return Ok(DisableOutcome::RemovedWithShortcut {
            artifact_path: xml_path,
            removed_shortcut: shortcut,
        });
    }

    Ok(DisableOutcome::Removed { mechanism: MECHANISM, artifact_path: xml_path })
}

/// Windows [`super::status`] implementation.
///
/// **P35 (code review round 3):** the `task_active` probe (which calls
/// `schtasks /Query`) IS the source of truth for whether Task
/// Scheduler has us registered — Windows already had the right
/// posture. We additionally require the XML record file to exist
/// before reporting Enabled (so we can read the embedded daemon path
/// for Story 7.5 drift detection); if the registry has the task but
/// our XML record is gone (manual cleanup, profile reset), we report
/// Enabled with a best-effort empty daemon_path rather than lying
/// Disabled.
pub(crate) fn status(exec: &impl Engine, home: &Path) -> Result<AutostartStatus, AutostartError> {
    let xml_path = xml_record_path(home);
    let task_active = task_registered(exec).unwrap_or(false);
    let shortcut = startup_shortcut_path(home);
    let shortcut_active = shortcut.exists();

    if task_active && shortcut_active {
        return Ok(AutostartStatus::Conflict {
            detail: format!(
                "both Task Scheduler entry `{TASK_NAME}` and Story 7.2 Startup-folder \
                 shortcut `{}` are active; both will fire on login and the second to \
                 start will fail to bind 127.0.0.1:3820. \
                 Run `agentsso autostart enable` again to migrate, or \
                 `agentsso autostart disable` to remove both.",
                shortcut.display()
            ),
        });
    }

    // P35: Task Scheduler registry IS the source of truth on Windows.
    // Don't report Enabled if registry says the task isn't there, even
    // if a stale XML record file exists.
    if !task_active {
        return Ok(AutostartStatus::Disabled);
    }

    let daemon_path =
        std::fs::read_to_string(&xml_path).ok().and_then(|xml| parse_command_path(&xml));
    Ok(AutostartStatus::Enabled { artifact_path: xml_path, mechanism: MECHANISM, daemon_path })
}

/// Probe `schtasks /Query /TN "AgentSSO Daemon" /FO LIST` for the
/// task's existence. Returns `false` if the task isn't registered or
/// schtasks is unavailable.
fn task_registered(exec: &impl Engine) -> Result<bool, AutostartError> {
    let args = ["/Query", "/TN", TASK_NAME];
    let out = match exec.run("schtasks", &args) {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(AutostartError::Io(e)),
    };
    Ok(out.status.success())
}

/// Detect schtasks /Delete's "task does not exist" outcome.
///
/// **P45 (code review round 5):** the previous implementation matched
/// every exit-1 from schtasks as "already gone." But schtasks /Delete
/// returns 1 for many failure modes — access-denied, RPC errors,
/// group-policy refusals, malformed args — not just "task not found."
/// Treating those as idempotent success let a corp-policy-blocked
/// delete succeed-by-error: the operator-visible Removed outcome was
/// reported but the registered task kept firing at every login.
///
/// schtasks emits the literal string `ERROR: The system cannot find
/// the file specified.` on stderr when the task doesn't exist
/// (verified on Windows 10 + 11, en-US locale). Match that token
/// alongside exit 1 so other exit-1 modes surface as
/// `ServiceManagerFailed`.
fn task_already_gone(out: &std::process::Output) -> bool {
    if out.status.code() != Some(1) {
        return false;
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Lower-case + match a stable substring that survives minor
    // wording drift across schtasks versions. The "cannot find"
    // shape is consistent on Windows 10 + 11 + Server 2019/2022.
    let s = stderr.to_lowercase();
    s.contains("cannot find") || s.contains("does not exist")
}

/// Pull the daemon path out of a rendered Task XML by finding the
/// `<Command>...</Command>` text inside `<Actions>`. Narrow scan, no
/// XML parser dep — same posture as the macOS `parse_program_path`.
///
/// **P16 (code review):** un-escapes XML entities the rendering side
/// added (`&` → `&amp;` etc.) so paths with special chars round-trip
/// correctly for Story 7.5 drift detection. Reuses the macOS
/// `xml_unescape` helper to keep the logic single-source.
fn parse_command_path(xml: &str) -> Option<PathBuf> {
    let actions_idx = xml.find("<Actions")?;
    let cmd_open = xml[actions_idx..].find("<Command>")? + actions_idx + "<Command>".len();
    let cmd_close = xml[cmd_open..].find("</Command>")? + cmd_open;
    let raw = &xml[cmd_open..cmd_close];
    let decoded = super::xml_unescape(raw);
    if decoded.is_empty() {
        return None;
    }
    Some(PathBuf::from(decoded))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::tests::MockExec;
    use super::*;

    #[test]
    fn parse_command_path_round_trips() {
        // The enable path (which rendered this Task XML) was removed;
        // this pins `parse_command_path` (still called by `status`)
        // against the canonical on-disk Task XML shape it used to write.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Actions Context="Author">
    <Exec>
      <Command>C:\bin\agentsso.exe</Command>
      <Arguments>start</Arguments>
    </Exec>
  </Actions>
</Task>
"#;
        assert_eq!(parse_command_path(xml), Some(PathBuf::from(r"C:\bin\agentsso.exe")));
    }

    #[test]
    fn disable_idempotent_when_nothing_registered() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mock = MockExec::default();
        // task_registered probe: task not found.
        mock.push_reply(MockExec::fail(1, "task not found"));

        let outcome = disable(&mock, tmp.path()).unwrap();
        assert!(matches!(outcome, DisableOutcome::AlreadyDisabled));
    }

    #[test]
    fn disable_removes_task_xml_and_shortcut_together() {
        let tmp = tempfile::TempDir::new().unwrap();
        let xml_path = xml_record_path(tmp.path());
        std::fs::create_dir_all(xml_path.parent().unwrap()).unwrap();
        std::fs::write(&xml_path, "fake xml").unwrap();
        let shortcut = startup_shortcut_path(tmp.path());
        std::fs::create_dir_all(shortcut.parent().unwrap()).unwrap();
        std::fs::write(&shortcut, b"fake .lnk").unwrap();

        let mock = MockExec::default();
        mock.push_reply(MockExec::ok("")); // task_registered: task IS active.
        mock.push_reply(MockExec::ok("")); // schtasks /Delete

        let outcome = disable(&mock, tmp.path()).unwrap();
        assert!(matches!(outcome, DisableOutcome::RemovedWithShortcut { .. }));
        assert!(!xml_path.exists());
        assert!(!shortcut.exists());
    }

    #[test]
    fn status_reports_conflict_when_task_and_shortcut_both_present() {
        let tmp = tempfile::TempDir::new().unwrap();
        let shortcut = startup_shortcut_path(tmp.path());
        std::fs::create_dir_all(shortcut.parent().unwrap()).unwrap();
        std::fs::write(&shortcut, b"fake .lnk").unwrap();

        let mock = MockExec::default();
        mock.push_reply(MockExec::ok("")); // task_registered: task IS active

        let st = status(&mock, tmp.path()).unwrap();
        assert!(matches!(st, AutostartStatus::Conflict { .. }));
    }
}
