//! macOS LaunchAgent backend for [`crate::lifecycle::autostart`].
//!
//! The autostart-managed plist lives at
//! `~/Library/LaunchAgents/dev.agentsso.daemon.plist` and is loaded via
//! the **modern** `launchctl bootstrap user/$UID <plist>` API (the
//! `enable` path that wrote/bootstrapped it was removed; this backend
//! now only inspects + tears down that artifact). The widely-cited
//! `launchctl load -w <plist>` form is deprecated on macOS 13+; we
//! never used it.
//!
//! # Why `user/$UID` and not `gui/$UID` (Story 7.15)
//!
//! `gui/$UID` only exists when the user has an active GUI login
//! session, so a `bootout` against it returns `125: Domain does not
//! support specified action` over SSH or in any context where the user
//! has not logged in via the console. Story 7.15 standardized on
//! `user/$UID`, the per-user domain Apple introduced for headless /
//! SSH scenarios — it is bootstrapped by the first session of any kind
//! (gui or ssh) and persists across logout.
//!
//! # Cross-mechanism conflict detection
//!
//! Homebrew's `brew services start agentsso` writes its own plist at
//! `~/Library/LaunchAgents/homebrew.mxcl.agentsso.plist` and starts the
//! daemon under launchd. If both autostart paths are active
//! simultaneously, the second daemon to start fails its 127.0.0.1:3820
//! TCP bind. [`status`] surfaces this as [`AutostartStatus::Conflict`]
//! by probing `brew services list --json` (see
//! [`parse_brew_services_active`]); [`disable`] warns (but does not
//! block) when brew-services is also active.

use std::path::{Path, PathBuf};
use std::process::Output;

use super::{AutostartError, AutostartStatus, DisableOutcome, Engine, service_manager_failed};

/// Fixed launchd label for the `agentsso autostart`-managed plist.
///
/// Intentionally distinct from Homebrew's `homebrew.mxcl.agentsso`
/// label (Homebrew controls that namespace; not overridable). Pinned
/// per architecture.md:961 and Story 7.1 cross-reference notes.
pub(crate) const LAUNCHD_LABEL: &str = "dev.agentsso.daemon";

/// Mechanism name surfaced in [`AutostartStatus::Enabled::mechanism`]
/// and in the CLI's autostart status / disable output.
const MECHANISM: &str = "launchd";

/// Resolve the absolute plist path under the given home dir:
/// `<home>/Library/LaunchAgents/dev.agentsso.daemon.plist`.
pub(crate) fn plist_path(home: &Path) -> PathBuf {
    home.join("Library").join("LaunchAgents").join(format!("{LAUNCHD_LABEL}.plist"))
}

/// macOS [`super::disable`] implementation. Idempotent.
///
/// **P6 (code review):** if `brew services` is ALSO managing agentsso (the
/// `homebrew.mxcl.agentsso` plist), removing our own
/// `dev.agentsso.daemon` plist still leaves the daemon auto-starting at
/// every login via brew. We log a warning to stderr in that case so the
/// operator isn't surprised; we don't block the disable (their explicit
/// intent is to remove our autostart, not brew's).
///
/// Migration-unwind invariant: `disable` does NOT restore a prior
/// brew-services migration's `*.bak.<RFC3339>` file. Migration is
/// one-way by design — the backup exists so the operator can manually
/// roll back if needed (`mv ~/Library/LaunchAgents/homebrew.mxcl.agentsso.plist.bak.* \
/// ~/Library/LaunchAgents/homebrew.mxcl.agentsso.plist && brew services start agentsso`),
/// not so `disable` silently un-does the upgrade.
pub(crate) fn disable(exec: &impl Engine, home: &Path) -> Result<DisableOutcome, AutostartError> {
    let plist = plist_path(home);
    if !plist.exists() {
        return Ok(DisableOutcome::AlreadyDisabled);
    }

    let user = current_user_id()?;
    let target = format!("user/{user}/{LAUNCHD_LABEL}");
    let args = ["bootout", target.as_str()];
    let out = exec.run("launchctl", &args)?;
    if !out.status.success() && !already_unloaded(&out) {
        return Err(service_manager_failed("launchctl", &args, &out));
    }

    std::fs::remove_file(&plist)?;

    // P6: warn (don't block) when brew-services is also managing
    // agentsso — our disable doesn't touch brew's autostart and the
    // user might think they've fully disabled when they haven't.
    if brew_services_active(exec).unwrap_or(false) {
        eprintln!(
            "warning: `brew services start agentsso` is also active; \
             autostart at login will continue via Homebrew. \
             Run `brew services stop agentsso` to fully disable."
        );
    }

    Ok(DisableOutcome::Removed { mechanism: MECHANISM, artifact_path: plist })
}

/// macOS [`super::status`] implementation.
///
/// **P35 (code review round 3):** verifies BOTH that the plist file
/// exists AND that launchd has actually loaded the agent (via
/// `launchctl print user/$UID/<label>`). The previous version only
/// checked file existence — a leftover plist from a failed bootstrap
/// would falsely report `Enabled` even though the daemon would never
/// auto-start.
pub(crate) fn status(exec: &impl Engine, home: &Path) -> Result<AutostartStatus, AutostartError> {
    let plist = plist_path(home);
    // **P63 (code review round 5, D4-promoted):** a symlink at the
    // expected plist path is suspicious — the autostart subsystem
    // only ever writes regular files via `write_atomic` (which uses
    // `create_new(true)` and refuses to follow symlinks). A symlink
    // means an operator manually replaced the artifact, OR something
    // outside our control put one there. Reading through the symlink
    // would surface a `daemon_path` from an unrelated file and break
    // Story 7.5's drift detection. Treat any non-regular-file
    // artifact as Disabled.
    let plist_present = match std::fs::symlink_metadata(&plist) {
        Ok(meta) => meta.file_type().is_file(),
        Err(_) => false,
    };
    let brew_active = brew_services_active(exec).unwrap_or(false);

    // Conflict detection runs FIRST so a brew-services-active +
    // plist-present state surfaces clearly.
    if plist_present && brew_active {
        return Ok(AutostartStatus::Conflict {
            detail: format!(
                "both {LAUNCHD_LABEL} plist and `brew services` agentsso entry are active; \
                 they will both try to bind 127.0.0.1:3820 and one will fail. \
                 Run `brew services stop agentsso` OR `agentsso autostart disable`. \
                 (If you just ran `agentsso autostart enable` to migrate off brew-services, \
                 give brew ~30s for its status cache to refresh and re-check.)"
            ),
        });
    }

    if !plist_present {
        return Ok(AutostartStatus::Disabled);
    }

    // P35: probe launchd to confirm the agent is ACTUALLY loaded.
    // `launchctl print user/$UID/<label>` returns 0 when the agent is
    // loaded; non-zero (typically 113 "Could not find specified
    // service") when it isn't. If launchd doesn't know about us, the
    // file is orphaned and we report Disabled — operator can re-run
    // `agentsso autostart enable` to fix.
    let user = match current_user_id() {
        Ok(uid) => uid,
        // **P55 (code review round 5, D3-promoted):** previous code
        // fell back to "file-presence == Enabled" when uid resolution
        // failed (e.g., logged-in-as-root with no SUDO_UID). That
        // directly contradicts P35's invariant that file existence
        // is NOT authoritative — a leftover plist from a failed prior
        // install would falsely report Enabled to a root user. Now:
        // when we can't probe launchd, report Disabled and warn so
        // an operator monitoring tracing can see that a probe was
        // skipped.
        Err(_) => {
            tracing::warn!(
                "autostart status: cannot resolve uid (running as root with no SUDO_UID?); \
                 reporting Disabled — file presence alone is not authoritative"
            );
            return Ok(AutostartStatus::Disabled);
        }
    };
    let target = format!("user/{user}/{LAUNCHD_LABEL}");
    let probe_args = ["print", target.as_str()];
    let loaded = match exec.run("launchctl", &probe_args) {
        Ok(out) => out.status.success(),
        // launchctl missing entirely → can't probe; fall back to
        // file-presence (better than failing status).
        Err(_) => true,
    };
    if !loaded {
        return Ok(AutostartStatus::Disabled);
    }

    // Read the embedded daemon path back from the plist so callers can
    // detect post-upgrade path drift (Story 7.5). The plist is
    // structured XML; we do a narrow grep rather than depending on the
    // `plist` crate.
    let xml = std::fs::read_to_string(&plist)?;
    let daemon_path = parse_program_path(&xml);
    Ok(AutostartStatus::Enabled { artifact_path: plist, mechanism: MECHANISM, daemon_path })
}

/// Probe `brew services list --json` and detect a running `agentsso`
/// entry. Returns `Ok(false)` if `brew` isn't on PATH (most common
/// case for non-Homebrew users).
///
/// **P37 (code review round 3):** the production probe goes through
/// [`Engine::run`], which is implemented for [`super::RealExec`] via
/// the shared `super::run_with_timeout` helper at the module level.
/// The helper drains stdout/stderr via reader threads (P42) and
/// kills the child after 30 s. The `MockExec` test path returns
/// immediately and bypasses the timeout. The trait stays `!Sync`
/// because `MockExec`'s `RefCell` is `!Sync`.
///
/// **H6 (code review round 5):** this comment previously claimed
/// `Command::output` was used directly with a 5-second SIGKILL via
/// a `wait_with_timeout` helper that didn't exist. Updated to
/// reflect the actual `RealExec::run` + 30-second timeout.
fn brew_services_active(exec: &impl Engine) -> Result<bool, AutostartError> {
    let args = ["services", "list", "--json"];
    let out = match exec.run("brew", &args) {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(AutostartError::Io(e)),
    };
    if !out.status.success() {
        // brew exists but the subcommand failed — could be a stale
        // brew install. Don't escalate this to a hard error; the
        // worst case is missing the conflict and double-binding :3820,
        // which the daemon's own bind error already surfaces clearly.
        return Ok(false);
    }
    Ok(parse_brew_services_active(&out.stdout))
}

/// Pure parser for `brew services list --json` output. Returns true
/// when brew is actively running OR scheduled-to-run agentsso.
///
/// **P28 (code review round 3):** the canonical Homebrew status enum
/// (verified against `services/formula_wrapper.rb#status_symbol` in
/// `/opt/homebrew/Library/Homebrew/`) is:
/// `started | none | scheduled | stopped | error | unknown | other`.
/// We treat the conflict-relevant ones as "active":
/// - `started` — daemon process is running under launchd right now
/// - `scheduled` — interval/cron unit will start at the trigger time
///
/// Treated as inactive (no conflict):
/// - `stopped` — explicitly stopped via `brew services stop`
/// - `none` — never bootstrapped (file present, not loaded)
/// - `error` — last run failed; brew won't auto-restart
/// - `unknown` / `other` — pathological; if brew can't tell, we don't
///   block the user from enabling our autostart
///
/// Previous version matched the literal string `"loaded"` which is NOT
/// in the canonical brew enum and never appeared in real output —
/// dead code. This version matches the actual enum with brew-source
/// citation in the comment so future drift is grep-able.
pub(crate) fn parse_brew_services_active(stdout: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(stdout) else {
        return false;
    };
    let Some(arr) = value.as_array() else {
        return false;
    };
    arr.iter().any(|entry| {
        entry.get("name").and_then(|n| n.as_str()) == Some("agentsso")
            && entry
                .get("status")
                .and_then(|s| s.as_str())
                .map(|s| s == "started" || s == "scheduled")
                .unwrap_or(false)
    })
}

/// Pull the absolute daemon path out of a rendered plist by finding
/// the first `<string>` inside `<key>ProgramArguments</key><array>...</array>`.
///
/// Narrow text scan (no XML parser dep) — the plist layout written by
/// the (now-removed) enable path is stable and the daemon-path string
/// is the first `<string>` inside the `ProgramArguments` array.
///
/// **P16 (code review):** un-escapes XML entities the rendering side
/// added (e.g., `&` → `&amp;`). Without this, a daemon path like
/// `/Users/maya/dev/foo & bar/agentsso` round-trips broken and Story
/// 7.5's `daemon_path` drift detection misses the match.
fn parse_program_path(xml: &str) -> Option<PathBuf> {
    let key_idx = xml.find("<key>ProgramArguments</key>")?;
    let array_start = xml[key_idx..].find("<array>")? + key_idx;
    let array_end = xml[array_start..].find("</array>")? + array_start;
    let arr_body = &xml[array_start..array_end];
    let s_open = arr_body.find("<string>")? + "<string>".len();
    let s_close = arr_body[s_open..].find("</string>")? + s_open;
    let raw = &arr_body[s_open..s_close];
    let decoded = super::xml_unescape(raw);
    if decoded.is_empty() {
        return None;
    }
    Some(PathBuf::from(decoded))
}

// `xml_unescape` lives in `super` so both macOS + Windows modules can
// reach it without cfg-cross-import gymnastics.

/// Detect launchctl bootout's "service not loaded" exit code.
///
/// **P29:** verified against `launchctl error <code>` on macOS 14:
/// - **113 = "Could not find specified service"** — the canonical
///   "not loaded" code on macOS 13+.
/// - **3 = ESRCH "No such process"** — older form (the service was
///   never started OR the launchd process for the user session is
///   gone).
/// - **36 = "Operation now in progress"** — bootout is async on some
///   builds; treat as success because the bootout has been accepted.
///
/// The previous code matched `5` (`EIO`, an actual error) instead of
/// the real "not found" codes. Fixed.
fn already_unloaded(out: &Output) -> bool {
    matches!(out.status.code(), Some(113) | Some(3) | Some(36))
}

/// Resolve the macOS user uid for the `user/$UID` launchctl target.
///
/// **P2 (code review):** when the user runs `sudo agentsso autostart enable`,
/// `getuid()` returns 0 and the launchctl target would become `user/0`
/// (root's per-user domain — exists, but not what the operator intends)
/// AND the plist gets written into root's `~/Library/LaunchAgents/`, so
/// the daemon never auto-starts at the real user's login. We:
/// 1. If running as root, prefer the `SUDO_UID` env var (set by sudo) so the
///    plist + launchctl target target the real user's per-user domain.
/// 2. If `SUDO_UID` is missing while running as root (e.g., user logged in
///    as root directly), refuse with a clean `Io` error rather than ship
///    a guaranteed-broken plist.
fn current_user_id() -> std::io::Result<u32> {
    let uid = nix::unistd::getuid().as_raw();
    if uid != 0 {
        return Ok(uid);
    }
    // Running as root — recover the real uid from sudo's environment.
    // Validate that the parsed uid corresponds to a real user; a stale
    // SUDO_UID pointing at a deleted account would otherwise produce a
    // bootstrap target like `user/<bogus>` that fails launchctl with
    // exit 125 (the same failure mode this story exists to prevent).
    if let Ok(sudo_uid) = std::env::var("SUDO_UID")
        && let Ok(parsed) = sudo_uid.parse::<u32>()
        && parsed != 0
        && matches!(nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(parsed)), Ok(Some(_)))
    {
        return Ok(parsed);
    }
    Err(std::io::Error::other(
        "agentsso autostart enable refuses to register a root LaunchAgent — \
         re-run as your normal user account (sudo not required for per-user autostart)",
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::tests::MockExec;
    use super::*;

    #[test]
    fn parse_brew_services_active_started() {
        let json = br#"[{"name":"agentsso","status":"started","user":"maya","loaded":true}]"#;
        assert!(parse_brew_services_active(json));
    }

    #[test]
    fn parse_brew_services_active_scheduled() {
        // P28: `scheduled` is one of brew's canonical status values
        // (see formula_wrapper.rb#status_symbol) and means the unit
        // WILL run at a trigger time — counts as "active" for
        // conflict-detection purposes.
        let json = br#"[{"name":"agentsso","status":"scheduled","user":"maya"}]"#;
        assert!(parse_brew_services_active(json));
    }

    #[test]
    fn parse_brew_services_inactive_when_stopped() {
        let json = br#"[{"name":"agentsso","status":"stopped","user":"maya"}]"#;
        assert!(!parse_brew_services_active(json));
    }

    #[test]
    fn parse_brew_services_inactive_for_canonical_inactive_states() {
        // P28: explicitly cover the OTHER canonical brew states
        // (`none`, `error`, `unknown`, `other`) so a future brew
        // schema change is caught by a focused test.
        for state in &["none", "error", "unknown", "other"] {
            let json = format!(r#"[{{"name":"agentsso","status":"{state}"}}]"#);
            assert!(
                !parse_brew_services_active(json.as_bytes()),
                "state {state} must not block our enable"
            );
        }
    }

    #[test]
    fn parse_brew_services_inactive_when_loaded_alias_no_longer_real() {
        // P28: `loaded` is NOT in brew's canonical enum (verified
        // against formula_wrapper.rb#status_symbol on this machine,
        // 2026-04-26). The previous code matched it; this test pins
        // the "we don't match a string brew never emits" contract.
        let json = br#"[{"name":"agentsso","status":"loaded","user":"maya"}]"#;
        assert!(!parse_brew_services_active(json));
    }

    #[test]
    fn parse_brew_services_inactive_when_unrelated() {
        let json = br#"[{"name":"postgres","status":"started","user":"maya"}]"#;
        assert!(!parse_brew_services_active(json));
    }

    #[test]
    fn parse_brew_services_handles_garbage() {
        assert!(!parse_brew_services_active(b"not json"));
        assert!(!parse_brew_services_active(b"{}"));
        assert!(!parse_brew_services_active(b"null"));
    }

    #[test]
    fn parse_program_path_extracts_daemon_path() {
        // The enable path (which rendered this plist) was removed; this
        // pins `parse_program_path` (still called by `status`) against
        // the canonical on-disk plist shape it used to write.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.agentsso.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/agentsso</string>
        <string>start</string>
    </array>
</dict>
</plist>
"#;
        assert_eq!(parse_program_path(xml), Some(PathBuf::from("/usr/local/bin/agentsso")));
    }

    #[test]
    fn disable_idempotent_when_plist_missing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mock = MockExec::default();
        // No replies queued — disable should short-circuit before any exec.
        let outcome = disable(&mock, tmp.path()).unwrap();
        assert!(matches!(outcome, DisableOutcome::AlreadyDisabled));
        assert!(mock.calls.borrow().is_empty());
    }

    #[test]
    fn disable_removes_plist_when_present() {
        let tmp = tempfile::TempDir::new().unwrap();
        let plist = plist_path(tmp.path());
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::write(&plist, "<?xml plist ?>").unwrap();

        let mock = MockExec::default();
        mock.push_reply(MockExec::ok("")); // launchctl bootout: ok
        // P6: post-disable brew-services warning probe (returns empty
        // → no warning printed, but the call still happens).
        mock.push_reply(MockExec::ok("[]"));

        let outcome = disable(&mock, tmp.path()).unwrap();
        assert!(matches!(outcome, DisableOutcome::Removed { .. }));
        assert!(!plist.exists());

        // Story 7.15 AC #2: bootout target must be user/<uid>/<label>.
        let calls = mock.calls.borrow();
        let bootout_call = calls.iter().find(|c| c.0 == "launchctl" && c.1[0] == "bootout");
        let bootout_call = bootout_call.expect("expected a launchctl bootout call");
        assert!(
            bootout_call.1[1].starts_with("user/"),
            "bootout target should be user/<uid>/<label>, got {:?}",
            bootout_call.1[1]
        );
        assert!(
            !bootout_call.1[1].starts_with("gui/"),
            "bootout target must NOT use gui/ domain (Story 7.15); got {:?}",
            bootout_call.1[1]
        );
    }

    #[test]
    fn disable_tolerates_already_unloaded_exit_codes() {
        // P29: verified against `launchctl error <code>` on macOS 14 —
        // the canonical "not loaded" exit is 113 (Could not find
        // specified service), not 5 (which is I/O error).
        for code in &[113, 3, 36] {
            let tmp = tempfile::TempDir::new().unwrap();
            let plist = plist_path(tmp.path());
            std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
            std::fs::write(&plist, "<?xml plist ?>").unwrap();

            let mock = MockExec::default();
            // Simulate the exit code under test.
            mock.push_reply(MockExec::fail(*code, "Could not find specified service"));
            // P6: post-disable brew-services warning probe.
            mock.push_reply(MockExec::ok("[]"));

            let outcome = disable(&mock, tmp.path()).unwrap();
            assert!(
                matches!(outcome, DisableOutcome::Removed { .. }),
                "exit code {code} should be tolerated as 'already unloaded'"
            );
            assert!(!plist.exists(), "plist should be removed for exit code {code}");
        }
    }

    #[test]
    fn disable_propagates_real_bootout_errors() {
        // P29: verify exit 5 (EIO — a REAL error, not "not loaded") is
        // surfaced as `ServiceManagerFailed`, NOT silently swallowed
        // like the buggy old behavior.
        let tmp = tempfile::TempDir::new().unwrap();
        let plist = plist_path(tmp.path());
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::write(&plist, "<?xml plist ?>").unwrap();

        let mock = MockExec::default();
        mock.push_reply(MockExec::fail(5, "Input/output error"));
        // No brew probe — disable returns Err before reaching it.

        let result = disable(&mock, tmp.path());
        assert!(matches!(result, Err(AutostartError::ServiceManagerFailed { .. })));
        // Plist preserved on real-error path so the operator can retry.
        assert!(plist.exists(), "plist should NOT be removed on real bootout error");
    }

    #[test]
    fn status_reports_disabled_when_no_plist() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mock = MockExec::default();
        mock.push_reply(MockExec::ok("[]")); // brew probe

        let st = status(&mock, tmp.path()).unwrap();
        assert_eq!(st, AutostartStatus::Disabled);
    }

    #[test]
    fn status_reports_conflict_when_both_active() {
        let tmp = tempfile::TempDir::new().unwrap();
        let plist = plist_path(tmp.path());
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::write(&plist, "<?xml version=\"1.0\"?><plist><dict/></plist>\n").unwrap();

        let mock = MockExec::default();
        mock.push_reply(MockExec::ok(r#"[{"name":"agentsso","status":"started"}]"#));

        let st = status(&mock, tmp.path()).unwrap();
        assert!(matches!(st, AutostartStatus::Conflict { .. }));
    }
}
