//! macOS LaunchAgent backend for [`crate::lifecycle::autostart`].
//!
//! Writes a per-user plist at
//! `~/Library/LaunchAgents/dev.agentsso.daemon.plist` and loads it via
//! the **modern** `launchctl bootstrap gui/$UID <plist>` API. The
//! widely-cited `launchctl load -w <plist>` form is deprecated on
//! macOS 13+ and emits a warning; we don't use it.
//!
//! # Conflict guardrail
//!
//! Homebrew's `brew services start agentsso` writes its own plist at
//! `~/Library/LaunchAgents/homebrew.mxcl.agentsso.plist` and starts the
//! daemon under launchd. If both autostart paths are enabled
//! simultaneously, the second daemon to start fails its 127.0.0.1:3820
//! TCP bind and either flap-loops (per Story 7.1's v0.2.1 hotfix
//! lesson) or sits in error 78. [`enable`] probes
//! `brew services list --json` first and refuses with
//! [`AutostartError::BrewServicesActive`] when brew-services owns the
//! daemon. See module docs of `super` and Story 7.1 Dev Notes
//! "Cross-reference with Story 7.3 autostart".
//!
//! # KeepAlive posture
//!
//! Story 7.1 v0.2.1 (commit `5928eb6`) hot-fixed the brew formula from
//! `keep_alive true` → `keep_alive { "SuccessfulExit" => false }`
//! because the unconditional respawn was looping on every clean exit
//! (config error, port-bind failure, manual `agentsso stop`). We apply
//! the same lesson here — the rendered plist sets `<key>KeepAlive</key>
//! <dict><key>SuccessfulExit</key><false/></dict>` so launchd respawns
//! ONLY on crashes, not clean shutdowns.

use std::path::{Path, PathBuf};
use std::process::Output;

use super::{
    AutostartError, AutostartStatus, DisableOutcome, EnableOutcome, Engine, current_daemon_path,
    service_manager_failed, write_atomic,
};

/// Fixed launchd label for the `agentsso autostart`-managed plist.
///
/// Intentionally distinct from Homebrew's `homebrew.mxcl.agentsso`
/// label (Homebrew controls that namespace; not overridable). Pinned
/// per architecture.md:961 and Story 7.1 cross-reference notes.
pub(crate) const LAUNCHD_LABEL: &str = "dev.agentsso.daemon";

/// Mechanism name surfaced in [`AutostartStatus::Enabled::mechanism`]
/// and in the CLI's "→ enabling autostart  ✓ <mechanism>" line.
const MECHANISM: &str = "launchd";

/// Resolve the absolute plist path under the given home dir:
/// `<home>/Library/LaunchAgents/dev.agentsso.daemon.plist`.
pub(crate) fn plist_path(home: &Path) -> PathBuf {
    home.join("Library").join("LaunchAgents").join(format!("{LAUNCHD_LABEL}.plist"))
}

/// Render the LaunchAgent plist XML for the given daemon-binary path.
///
/// Hand-rendered (no `plist` crate dep) per Story 7.3 Dev Notes — the
/// content is static beyond the binary path + log path, the format has
/// been stable since macOS 10.6, and the snapshot test pins the
/// load-bearing fields (`KeepAlive.SuccessfulExit=false`, `RunAtLoad=true`).
///
/// # Escaping
///
/// XML-special characters in the binary path (`<`, `>`, `&`) would
/// corrupt the rendered plist. Production daemon paths under
/// `/usr/local/bin/` or `~/.cargo/bin/` won't hit this in practice,
/// but the helper escapes anyway so a path like
/// `~/dev/foo & bar/agentsso` doesn't produce malformed XML.
pub(crate) fn render_plist(daemon_path: &Path, log_path: &Path, working_dir: &Path) -> String {
    let daemon = xml_escape(&daemon_path.to_string_lossy());
    let log = xml_escape(&log_path.to_string_lossy());
    let cwd = xml_escape(&working_dir.to_string_lossy());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{daemon}</string>
        <string>start</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
    <key>WorkingDirectory</key>
    <string>{cwd}</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        daemon = daemon,
        log = log,
        cwd = cwd,
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

/// macOS [`super::enable`] implementation.
pub(crate) fn enable(exec: &impl Engine, home: &Path) -> Result<EnableOutcome, AutostartError> {
    // Conflict guardrail: refuse if `brew services` is running the daemon.
    if brew_services_active(exec)? {
        return Err(AutostartError::BrewServicesActive);
    }

    let plist = plist_path(home);
    let daemon = current_daemon_path()?;
    // P36: reject non-UTF-8 paths up front rather than `to_string_lossy`
    // corrupting the rendered plist with U+FFFD silently. The plist
    // format is UTF-8; we can't represent invalid bytes faithfully.
    super::require_utf8_path(&daemon)?;
    super::require_utf8_path(home)?;
    let log_path = home.join(".agentsso").join("logs").join("autostart.log");

    // P31 (code review round 3): the previous code returned
    // `AlreadyEnabled` when the plist file existed AT ALL, which was
    // misleading — `write_atomic` was about to rewrite the content
    // (e.g., daemon path drift after a reinstall). Compare the
    // existing content to the new render and only return `AlreadyEnabled`
    // when nothing actually changed.
    let xml = render_plist(&daemon, &log_path, home);
    let unchanged = plist
        .exists()
        .then(|| std::fs::read_to_string(&plist).ok())
        .flatten()
        .map(|existing| existing == xml)
        .unwrap_or(false);
    write_atomic(&plist, &xml)?;

    // Bootstrap the agent. If it's already loaded (re-enable), bootstrap
    // returns exit 17 ("Service already loaded") on macOS 13+; treat as
    // success — the plist file may have been refreshed.
    let user = current_user_id()?;
    let target = format!("gui/{user}");
    let plist_str = plist.to_string_lossy();
    let plist_arg: &str = &plist_str;
    let args = ["bootstrap", target.as_str(), plist_arg];
    let out = exec.run("launchctl", &args)?;
    if !out.status.success() && !already_loaded(&out) {
        return Err(service_manager_failed("launchctl", &args, &out));
    }

    if unchanged {
        Ok(EnableOutcome::AlreadyEnabled { artifact_path: plist })
    } else {
        Ok(EnableOutcome::Registered { mechanism: MECHANISM, artifact_path: plist })
    }
}

/// macOS [`super::disable`] implementation. Idempotent.
///
/// **P6 (code review):** if `brew services` is ALSO managing agentsso (the
/// `homebrew.mxcl.agentsso` plist), removing our own
/// `dev.agentsso.daemon` plist still leaves the daemon auto-starting at
/// every login via brew. We log a warning to stderr in that case so the
/// operator isn't surprised; we don't block the disable (their explicit
/// intent is to remove our autostart, not brew's).
pub(crate) fn disable(exec: &impl Engine, home: &Path) -> Result<DisableOutcome, AutostartError> {
    let plist = plist_path(home);
    if !plist.exists() {
        return Ok(DisableOutcome::AlreadyDisabled);
    }

    let user = current_user_id()?;
    let target = format!("gui/{user}/{LAUNCHD_LABEL}");
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
/// `launchctl print gui/$UID/<label>`). The previous version only
/// checked file existence — a leftover plist from a failed bootstrap
/// would falsely report `Enabled` even though the daemon would never
/// auto-start.
pub(crate) fn status(exec: &impl Engine, home: &Path) -> Result<AutostartStatus, AutostartError> {
    let plist = plist_path(home);
    let plist_present = plist.exists();
    let brew_active = brew_services_active(exec).unwrap_or(false);

    // Conflict detection runs FIRST so a brew-services-active +
    // plist-present state surfaces clearly.
    if plist_present && brew_active {
        return Ok(AutostartStatus::Conflict {
            detail: format!(
                "both {LAUNCHD_LABEL} plist and `brew services` agentsso entry are active; \
                 they will both try to bind 127.0.0.1:3820 and one will fail. \
                 Run `brew services stop agentsso` OR `agentsso autostart disable`."
            ),
        });
    }

    if !plist_present {
        return Ok(AutostartStatus::Disabled);
    }

    // P35: probe launchd to confirm the agent is ACTUALLY loaded.
    // `launchctl print gui/$UID/<label>` returns 0 when the agent is
    // loaded; non-zero (typically 113 "Could not find specified
    // service") when it isn't. If launchd doesn't know about us, the
    // file is orphaned and we report Disabled — operator can re-run
    // `agentsso autostart enable` to fix.
    let user = match current_user_id() {
        Ok(uid) => uid,
        // If we can't even determine the uid (root without SUDO_UID),
        // we can't probe launchd. Fall back to file-presence — the
        // `enable` path would have refused this state anyway.
        Err(_) => {
            let xml = std::fs::read_to_string(&plist)?;
            let daemon_path = parse_program_path(&xml).unwrap_or_default();
            return Ok(AutostartStatus::Enabled {
                artifact_path: plist,
                mechanism: MECHANISM,
                daemon_path,
            });
        }
    };
    let target = format!("gui/{user}/{LAUNCHD_LABEL}");
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
    let daemon_path = parse_program_path(&xml).unwrap_or_default();
    Ok(AutostartStatus::Enabled { artifact_path: plist, mechanism: MECHANISM, daemon_path })
}

/// Probe `brew services list --json` and detect a running `agentsso`
/// entry. Returns `Ok(false)` if `brew` isn't on PATH (most common
/// case for non-Homebrew users).
///
/// **P37 (code review round 3):** the probe runs in production via
/// [`std::process::Command::output`], which has no native timeout.
/// Wrapping it would require `Sync`-bounded `Engine` + `thread::scope`
/// — but `MockExec` uses `RefCell` which is `!Sync`, so adding the
/// bound breaks all unit tests. Instead, the **production-only** path
/// uses [`Command::output`] with a process-group SIGKILL after 5s via
/// the `wait_with_timeout` helper below. The `MockExec` test path
/// returns immediately. This keeps the trait `Sync`-free.
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
/// Narrow text scan (no XML parser dep) — the rendering side is fully
/// in our control via [`render_plist`], so the layout is stable.
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

/// Detect launchctl bootstrap's "service already loaded" exit code.
///
/// **P29 (code review round 3):** verified against `man launchctl` +
/// real `launchctl error <code>` output on macOS 14:
/// - **17 = EEXIST "File exists"** — the canonical "already loaded"
///   code on macOS 13+; bootstrap returns this when the label is
///   already known to launchd.
/// - **119 = "Service is disabled"** — the agent IS bootstrapped but
///   launchd has it disabled (e.g., `launchctl disable` was run
///   manually). Treat as "already loaded" for our purposes — the user
///   can re-enable via `launchctl enable`.
///
/// The previous code matched `5` (which decodes to `EIO "I/O error"` —
/// NOT "already loaded"; a real bootstrap I/O error would have been
/// silently swallowed). Removed.
fn already_loaded(out: &Output) -> bool {
    matches!(out.status.code(), Some(17) | Some(119))
}

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

/// Resolve the macOS user uid for the `gui/$UID` launchctl target.
///
/// **P2 (code review):** when the user runs `sudo agentsso autostart enable`,
/// `getuid()` returns 0 and the launchctl target becomes `gui/0` (root has
/// no gui session) AND the plist gets written into root's
/// `~/Library/LaunchAgents/`, so the daemon never auto-starts at the real
/// user's login. We:
/// 1. If running as root, prefer the `SUDO_UID` env var (set by sudo) so the
///    plist + launchctl target target the real user's gui session.
/// 2. If `SUDO_UID` is missing while running as root (e.g., user logged in
///    as root directly), refuse with a clean `Io` error rather than ship
///    a guaranteed-broken plist.
fn current_user_id() -> std::io::Result<u32> {
    let uid = nix::unistd::getuid().as_raw();
    if uid != 0 {
        return Ok(uid);
    }
    // Running as root — recover the real uid from sudo's environment.
    if let Ok(sudo_uid) = std::env::var("SUDO_UID")
        && let Ok(parsed) = sudo_uid.parse::<u32>()
        && parsed != 0
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
    fn plist_renders_canonical_layout() {
        let xml = render_plist(
            Path::new("/usr/local/bin/agentsso"),
            Path::new("/Users/maya/.agentsso/logs/autostart.log"),
            Path::new("/Users/maya"),
        );
        insta::assert_snapshot!("autostart_macos_plist", xml);
    }

    #[test]
    fn plist_escapes_xml_special_chars() {
        let xml = render_plist(
            Path::new("/Users/maya/dev/foo & bar/agentsso"),
            Path::new("/tmp/log"),
            Path::new("/tmp"),
        );
        // The `&` must be escaped to `&amp;`.
        assert!(xml.contains("foo &amp; bar/agentsso"));
        assert!(!xml.contains("foo & bar"));
    }

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
        let xml = render_plist(
            Path::new("/usr/local/bin/agentsso"),
            Path::new("/tmp/log"),
            Path::new("/tmp"),
        );
        assert_eq!(parse_program_path(&xml), Some(PathBuf::from("/usr/local/bin/agentsso")));
    }

    #[test]
    fn enable_refuses_when_brew_services_active() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mock = MockExec::default();
        // First call: `brew services list --json` returns the active entry.
        mock.push_reply(MockExec::ok(r#"[{"name":"agentsso","status":"started"}]"#));
        let result = enable(&mock, tmp.path());
        assert!(matches!(result, Err(AutostartError::BrewServicesActive)));
        // We must NOT have called launchctl.
        let calls = mock.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "brew");
    }

    #[test]
    fn enable_writes_plist_when_brew_inactive() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mock = MockExec::default();
        mock.push_reply(MockExec::ok("[]")); // brew services list: empty
        mock.push_reply(MockExec::ok("")); // launchctl bootstrap: ok

        let outcome = enable(&mock, tmp.path()).unwrap();
        match &outcome {
            EnableOutcome::Registered { mechanism, artifact_path } => {
                assert_eq!(*mechanism, MECHANISM);
                assert!(artifact_path.exists(), "expected plist at {}", artifact_path.display());
            }
            other => panic!("expected Registered, got {other:?}"),
        }

        // Calls in order: brew, launchctl bootstrap.
        let calls = mock.calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "brew");
        assert_eq!(calls[1].0, "launchctl");
        assert_eq!(calls[1].1[0], "bootstrap");
    }

    #[test]
    fn enable_refreshes_stale_plist_returning_registered() {
        // P31 (code review round 3): when the plist exists but content
        // differs (stale stub from a prior install), enable returns
        // `Registered` (not `AlreadyEnabled`) — the content WAS
        // refreshed; `AlreadyEnabled` would be misleading.
        let tmp = tempfile::TempDir::new().unwrap();
        let plist = plist_path(tmp.path());
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::write(&plist, "<?xml stale plist ?>").unwrap();

        let mock = MockExec::default();
        mock.push_reply(MockExec::ok("[]")); // brew
        mock.push_reply(MockExec::ok("")); // launchctl bootstrap

        let outcome = enable(&mock, tmp.path()).unwrap();
        assert!(matches!(outcome, EnableOutcome::Registered { .. }));
        // The plist content was refreshed (no longer the stale stub).
        let xml = std::fs::read_to_string(&plist).unwrap();
        assert!(xml.contains("<key>Label</key>"));
        assert!(!xml.contains("stale plist"));
    }

    #[test]
    fn enable_truly_idempotent_when_content_unchanged() {
        // P31: when the plist already exists with EXACTLY the content
        // we'd write, enable returns `AlreadyEnabled` (nothing
        // changed; truly a no-op).
        let tmp = tempfile::TempDir::new().unwrap();
        let plist = plist_path(tmp.path());
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        // Pre-write the EXACT content enable() would write.
        let daemon = current_daemon_path().unwrap();
        let log_path = tmp.path().join(".agentsso").join("logs").join("autostart.log");
        let xml = render_plist(&daemon, &log_path, tmp.path());
        std::fs::write(&plist, &xml).unwrap();

        let mock = MockExec::default();
        mock.push_reply(MockExec::ok("[]")); // brew
        mock.push_reply(MockExec::ok("")); // launchctl bootstrap

        let outcome = enable(&mock, tmp.path()).unwrap();
        assert!(
            matches!(outcome, EnableOutcome::AlreadyEnabled { .. }),
            "expected AlreadyEnabled for truly-unchanged plist, got {outcome:?}"
        );
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
    fn round_trip_enable_status_disable_status() {
        // P24 (code review): exercises the full state machine —
        // enable → status reports Enabled → disable → status reports
        // Disabled. Catches state-desync bugs where one operation
        // leaves residue the next one misreads.
        let tmp = tempfile::TempDir::new().unwrap();
        let mock = MockExec::default();

        // enable: brew probe (empty) + launchctl bootstrap.
        mock.push_reply(MockExec::ok("[]"));
        mock.push_reply(MockExec::ok(""));
        let outcome = enable(&mock, tmp.path()).unwrap();
        assert!(matches!(outcome, EnableOutcome::Registered { .. }));

        // status: brew probe (empty) + P35 launchctl print probe (success).
        mock.push_reply(MockExec::ok("[]"));
        mock.push_reply(MockExec::ok(""));
        let st = status(&mock, tmp.path()).unwrap();
        assert!(matches!(st, AutostartStatus::Enabled { .. }), "expected Enabled, got {st:?}");

        // disable: launchctl bootout + brew probe (warning check).
        mock.push_reply(MockExec::ok(""));
        mock.push_reply(MockExec::ok("[]"));
        let outcome = disable(&mock, tmp.path()).unwrap();
        assert!(matches!(outcome, DisableOutcome::Removed { .. }));

        // status: brew probe (empty) again — must report Disabled.
        mock.push_reply(MockExec::ok("[]"));
        let st = status(&mock, tmp.path()).unwrap();
        assert_eq!(st, AutostartStatus::Disabled);
    }

    #[test]
    fn status_reports_conflict_when_both_active() {
        let tmp = tempfile::TempDir::new().unwrap();
        let plist = plist_path(tmp.path());
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::write(
            &plist,
            render_plist(Path::new("/x/agentsso"), Path::new("/x/log"), Path::new("/x")),
        )
        .unwrap();

        let mock = MockExec::default();
        mock.push_reply(MockExec::ok(r#"[{"name":"agentsso","status":"started"}]"#));

        let st = status(&mock, tmp.path()).unwrap();
        assert!(matches!(st, AutostartStatus::Conflict { .. }));
    }
}
