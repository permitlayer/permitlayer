//! Windows Task Scheduler backend for [`crate::lifecycle::autostart`].
//!
//! Registers a per-user task named `AgentSSO Daemon` via `schtasks`
//! (built-in to Windows since XP — no extra dependency, no `windows-rs`
//! crate weight). Triggered at logon of the current user; runs
//! unelevated.
//!
//! # Why Task Scheduler over Startup folder?
//!
//! Story 7.2's `install.ps1 -Autostart` ships a Startup-folder
//! shortcut at `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\agentsso.lnk`
//! as install-time minimum. Task Scheduler is more robust:
//! survives roaming-profile sync (the `.lnk` doesn't), supports retry-
//! on-failure, can be set to ignore the OS's silent default kills.
//! Story 7.2's shortcut is the install-time placeholder; Story 7.3's
//! [`enable`] migrates it away (deletes the .lnk; registers the task).
//!
//! # Two silent-kill defaults this code overrides
//!
//! 1. **`ExecutionTimeLimit` defaults to `PT72H`** — after 3 days the OS
//!    forcibly terminates the task. For a long-running daemon this is a
//!    silent footgun ("works fine, then breaks at random after a long
//!    weekend"). We render `<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>`
//!    explicitly. Verified at
//!    https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-executiontimelimit.
//! 2. **`DisallowStartIfOnBatteries=true` + `StopIfGoingOnBatteries=true`**
//!    are the laptop defaults — undocking silently kills the daemon. We
//!    render both as `false` so the daemon keeps running on battery.
//!
//! Both pinned via the `insta` snapshot in tests so a future "tidy the
//! XML" edit can't silently regress them.

use std::path::{Path, PathBuf};

use super::{
    AutostartError, AutostartStatus, DisableOutcome, EnableOutcome, Engine, current_daemon_path,
    service_manager_failed, write_atomic,
};

const TASK_NAME: &str = "AgentSSO Daemon";
const MECHANISM: &str = "task-scheduler";

/// Resolve the on-disk path we use as a record of the registered task.
///
/// Task Scheduler stores its real state in the registry; we additionally
/// stash a copy of the rendered XML at this path so [`status`] can read
/// the embedded daemon path back out (mirrors macOS plist + Linux unit
/// patterns; lets Story 7.5 detect post-upgrade path drift).
pub(crate) fn xml_record_path(home: &Path) -> PathBuf {
    home.join(".agentsso").join("autostart").join("task-scheduler.xml")
}

/// Resolve the Story 7.2 Startup-folder shortcut path. Filename pinned
/// to `agentsso.lnk` per Story 7.2 Dev Notes "Cross-story fences" item 1.
pub(crate) fn startup_shortcut_path(home: &Path) -> PathBuf {
    home.join("AppData")
        .join("Roaming")
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("Startup")
        .join("agentsso.lnk")
}

/// Render the Task Scheduler XML for the given daemon-binary path.
///
/// Hand-rendered (no `quick-xml` / `windows-rs` crate dep) per Story 7.3
/// Dev Notes — the schema is stable and the snapshot test pins the
/// load-bearing fields.
pub(crate) fn render_task_xml(daemon_path: &Path, user_id: &str) -> String {
    let daemon = xml_escape(&daemon_path.to_string_lossy());
    let user = xml_escape(user_id);
    let working_dir = xml_escape(
        &daemon_path
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".into()),
    );
    // P9 (code review): the file is written as UTF-8 bytes by
    // `write_atomic`; declare UTF-8 here so strict XML parsers don't
    // reject the prologue/payload mismatch. schtasks accepts either
    // declaration in practice but UTF-8 is honest.
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>permitlayer/agentsso daemon (per-user autostart)</Description>
    <URI>\{task}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT5M</Interval>
      <Count>10</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{daemon}</Command>
      <Arguments>start</Arguments>
      <WorkingDirectory>{cwd}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"#,
        task = TASK_NAME,
        user = user,
        daemon = daemon,
        cwd = working_dir,
    )
}

fn xml_escape(s: &str) -> String {
    let mut buf = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => buf.push_str("&amp;"),
            '<' => buf.push_str("&lt;"),
            '>' => buf.push_str("&gt;"),
            '"' => buf.push_str("&quot;"),
            '\'' => buf.push_str("&apos;"),
            other => buf.push(other),
        }
    }
    buf
}

/// Windows [`super::enable`] implementation. Migrates a leftover
/// Story 7.2 Startup-folder `agentsso.lnk` away (per AC #6).
///
/// **P7 (code review):** the rendered XML is staged at a temp path and
/// only renamed to the canonical `xml_record_path` AFTER `schtasks
/// /Create` has succeeded. This prevents a state desync where a
/// schtasks failure (corp policy block, AV interference, malformed XML
/// per locale issues) would leave behind an orphan XML record that
/// `status` would then misinterpret as "Enabled" even though the task
/// was never actually registered.
pub(crate) fn enable(exec: &impl Engine, home: &Path) -> Result<EnableOutcome, AutostartError> {
    let xml_path = xml_record_path(home);
    let daemon = current_daemon_path()?;
    // P36: reject non-UTF-8 daemon paths. Task Scheduler XML is UTF-8
    // (or UTF-16 LE w/ BOM) — both faithful but our renderer outputs
    // UTF-8. Without this check, `to_string_lossy` would silently
    // rewrite the path with U+FFFD and the registered task would fail
    // to launch the daemon at logon.
    super::require_utf8_path(&daemon)?;
    let user = current_user_id()?;
    let xml = render_task_xml(&daemon, &user);

    // P7: stage the XML at a sibling temp path; do NOT write the
    // canonical xml_record_path yet. schtasks /Create reads from this
    // staged path; only on success do we rename to the final location
    // (so `status` never sees an orphan XML file from a failed enable).
    let staging = xml_path.with_file_name(format!(
        "{}.staging.{}",
        xml_path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    if let Some(parent) = staging.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&staging, &xml)?;

    // Detect prior state (for the right outcome variant).
    let already_existed = task_registered(exec)?;
    let shortcut = startup_shortcut_path(home);
    let shortcut_existed = shortcut.exists();

    // Register/refresh the task. `/F` forces overwrite if the entry
    // already exists; idempotent across re-enables.
    let staging_str = staging.to_string_lossy();
    let xml_arg: &str = &staging_str;
    let args = ["/Create", "/TN", TASK_NAME, "/XML", xml_arg, "/F"];
    let out = exec.run("schtasks", &args)?;
    if !out.status.success() {
        // schtasks failed — clean up the staging file before bailing so
        // we don't orphan a partial record.
        let _ = std::fs::remove_file(&staging);
        return Err(service_manager_failed("schtasks", &args, &out));
    }

    // schtasks succeeded — promote the staging file to the canonical
    // record path so `status` can later read the embedded daemon path
    // for Story 7.5 drift detection.
    write_atomic(&xml_path, &xml)?;
    let _ = std::fs::remove_file(&staging);

    // Migrate Story 7.2 install-time shortcut (per AC #6).
    if shortcut_existed {
        // Best-effort delete; don't fail enable if the rm fails (the
        // task is already registered + that's the load-bearing change).
        let _ = std::fs::remove_file(&shortcut);
        return Ok(EnableOutcome::MigratedFromStartupShortcut {
            artifact_path: xml_path,
            removed_shortcut: shortcut,
        });
    }

    if already_existed {
        Ok(EnableOutcome::AlreadyEnabled { artifact_path: xml_path })
    } else {
        Ok(EnableOutcome::Registered { mechanism: MECHANISM, artifact_path: xml_path })
    }
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

    let xml = std::fs::read_to_string(&xml_path).unwrap_or_default();
    let daemon_path = parse_command_path(&xml).unwrap_or_default();
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

/// Detect schtasks /Delete's "task does not exist" exit code (1).
fn task_already_gone(out: &std::process::Output) -> bool {
    matches!(out.status.code(), Some(1))
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

/// Resolve the current user as `DOMAIN\user` for the Task Scheduler
/// `<UserId>` element.
///
/// **P8 (code review):** the previous implementation fell back to the
/// literal string `"INTERACTIVE"` when env vars were missing, with a
/// comment claiming "schtasks will refuse with a clean error." That was
/// not actually true — `INTERACTIVE` is a Windows well-known SID NAME
/// that schtasks accepts in some contexts and silently registers the
/// task against the wrong principal. We now refuse explicitly with a
/// clean structured error so the operator knows what's wrong.
fn current_user_id() -> std::io::Result<String> {
    let username = std::env::var("USERNAME").map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            "cannot determine current user — USERNAME env var is not set; \
             agentsso autostart enable must run from an interactive user session",
        )
    })?;
    if let Ok(domain) = std::env::var("USERDOMAIN") {
        Ok(format!("{domain}\\{username}"))
    } else {
        Ok(username)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::tests::MockExec;
    use super::*;

    #[test]
    fn task_xml_renders_canonical_layout() {
        // P1: replaced an `insta::assert_snapshot!` with explicit asserts.
        // The cfg(target_os="windows") gating means snapshot files can
        // only be generated on a Windows host; insta defaults to FAIL
        // when the .snap is missing, so a macOS/Linux-developed PR +
        // Windows CI runner that hasn't seen a snapshot yet would land
        // red. Direct field-presence checks pin the same load-bearing
        // invariants without the snapshot-file lifecycle problem.
        let xml = render_task_xml(
            Path::new(r"C:\Users\Maya\AppData\Local\Programs\agentsso\agentsso.exe"),
            "MAYA-PC\\Maya",
        );

        // Top-level structure markers.
        assert!(xml.contains("<Task version="), "missing <Task> root element");
        assert!(xml.contains("<Triggers>"), "missing <Triggers>");
        assert!(xml.contains("<Principals>"), "missing <Principals>");
        assert!(xml.contains("<Actions"), "missing <Actions>");
        assert!(xml.contains("<LogonTrigger>"), "missing logon trigger");

        // Embedded paths + user (proves substitution worked).
        assert!(
            xml.contains(
                r"<Command>C:\Users\Maya\AppData\Local\Programs\agentsso\agentsso.exe</Command>"
            ),
            "Command path missing or mangled: {xml}"
        );
        assert!(xml.contains("<UserId>MAYA-PC\\Maya</UserId>"), "UserId missing or wrong");
        assert!(xml.contains("<Arguments>start</Arguments>"), "Arguments missing");
    }

    #[test]
    fn task_xml_pins_silent_kill_overrides() {
        let xml = render_task_xml(Path::new(r"C:\bin\agentsso.exe"), "MAYA-PC\\Maya");
        // ExecutionTimeLimit MUST be PT0S — Task Scheduler default is
        // PT72H, which silently kills the daemon after 3 days.
        assert!(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
        // Battery defaults MUST be overridden — undocking otherwise
        // silently kills the daemon.
        assert!(xml.contains("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"));
        assert!(xml.contains("<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"));
        // Restart-on-failure preserved.
        assert!(xml.contains("<RestartOnFailure>"));
    }

    #[test]
    fn parse_command_path_round_trips() {
        let xml = render_task_xml(Path::new(r"C:\bin\agentsso.exe"), "MAYA-PC\\Maya");
        assert_eq!(parse_command_path(&xml), Some(PathBuf::from(r"C:\bin\agentsso.exe")));
    }

    #[test]
    fn enable_writes_xml_and_calls_schtasks_create() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mock = MockExec::default();
        // First call: task_registered probe returns "task not found" (exit 1).
        mock.push_reply(MockExec::fail(1, "ERROR: The system cannot find the file specified."));
        // Second call: schtasks /Create /F succeeds.
        mock.push_reply(MockExec::ok(""));

        let outcome = enable(&mock, tmp.path()).unwrap();
        assert!(matches!(outcome, EnableOutcome::Registered { mechanism: "task-scheduler", .. }));

        let calls = mock.calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].1[0], "/Create");
        assert!(calls[1].1.iter().any(|a| a == "/F"));
    }

    #[test]
    fn enable_migrates_story_7_2_shortcut() {
        let tmp = tempfile::TempDir::new().unwrap();
        let shortcut = startup_shortcut_path(tmp.path());
        std::fs::create_dir_all(shortcut.parent().unwrap()).unwrap();
        std::fs::write(&shortcut, b"fake .lnk content").unwrap();

        let mock = MockExec::default();
        mock.push_reply(MockExec::fail(1, "task not found")); // task_registered probe
        mock.push_reply(MockExec::ok("")); // schtasks /Create

        let outcome = enable(&mock, tmp.path()).unwrap();
        match &outcome {
            EnableOutcome::MigratedFromStartupShortcut { removed_shortcut, .. } => {
                assert_eq!(removed_shortcut, &shortcut);
            }
            other => panic!("expected MigratedFromStartupShortcut, got {other:?}"),
        }
        // The .lnk is gone.
        assert!(!shortcut.exists());
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
