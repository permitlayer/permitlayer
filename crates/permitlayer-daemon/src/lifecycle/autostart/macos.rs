//! macOS LaunchAgent backend for [`crate::lifecycle::autostart`].
//!
//! Writes a per-user plist at
//! `~/Library/LaunchAgents/dev.agentsso.daemon.plist` and loads it via
//! the **modern** `launchctl bootstrap user/$UID <plist>` API. The
//! widely-cited `launchctl load -w <plist>` form is deprecated on
//! macOS 13+ and emits a warning; we don't use it.
//!
//! # Why `user/$UID` and not `gui/$UID` (Story 7.15)
//!
//! Story 7.3 originally targeted `gui/$UID`. That domain only exists
//! when the user has an active GUI login session, so the bootstrap
//! call returns `125: Domain does not support specified action` over
//! SSH or in any context where the user has not logged in via the
//! console. Story 7.15 re-targets to `user/$UID`, the per-user domain
//! Apple introduced specifically for headless / SSH scenarios — it is
//! bootstrapped by the first session of any kind (gui or ssh) and
//! persists across logout. Same plist, same per-user keychain access,
//! same threat model — only the launchctl bootstrap target changes.
//!
//! # Brew-services migration (Story 7.16)
//!
//! Homebrew's `brew services start agentsso` writes its own plist at
//! `~/Library/LaunchAgents/homebrew.mxcl.agentsso.plist` and starts the
//! daemon under launchd. If both autostart paths are enabled
//! simultaneously, the second daemon to start fails its 127.0.0.1:3820
//! TCP bind and either flap-loops (per Story 7.1's v0.2.1 hotfix
//! lesson) or sits in error 78.
//!
//! **Pre-rc.16 behavior:** [`enable`] probed `brew services list --json`
//! first and refused with [`AutostartError::BrewServicesActive`] when
//! brew-services owned the daemon. The operator had to manually run
//! `brew services stop agentsso` before re-running.
//!
//! **rc.16 behavior (Story 7.16):** [`enable`] now MIGRATES the
//! brew-managed state to our user-domain LaunchAgent automatically. Two
//! independent detection signals back the migration decision: (a) brew
//! status probe, (b) plist-on-disk inspection. If the plist on disk
//! doesn't match the canonical brew-managed shape (label +
//! `<ProgramArguments>[0]` referencing the agentsso binary), enable
//! refuses with [`AutostartError::BrewMigrationRefused`] rather than
//! auto-removing a hand-rolled config. The original
//! `AutostartError::BrewServicesActive` variant is preserved on the enum
//! for backward compatibility but is no longer produced by this module.
//! See [`decide_brew_migration`] for the decision matrix.
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
//!
//! # LimitLoadToSessionType (Story 7.21)
//!
//! Without this key, launchd defaults a LaunchAgent's allowed session
//! type to `Aqua` (per the launchd-dev archive thread on errno 134:
//! <https://launchd-dev.macosforge.narkive.com/7s3ELd8z/cause-of-service-cannot-load-in-requested-session>).
//! `launchctl bootstrap user/$UID` from an SSH session — which is the
//! `Background` session type — refuses to load an `Aqua`-typed agent
//! and surfaces errno 134 ("Service cannot load in requested session"),
//! reported to userspace as errno 5 ("Bootstrap failed: Input/output error").
//!
//! Story 7.16 fixed the *domain* (`gui/$UID` → `user/$UID`) but did NOT
//! set the session-type filter, so the rc.16 plist still hit errno 134
//! on Angie's macOS 15.7.5 box (verified 2026-05-08, SSH-only).
//!
//! Our chosen value is `[Background, Aqua]`:
//!
//! - `Background` covers SSH-only sessions and is the load-bearing fix.
//! - `Aqua` preserves rc.16 GUI-desktop behavior (a normal Terminal.app
//!   session inside a logged-in macOS desktop).
//! - `LoginWindow` is deliberately EXCLUDED: the daemon depends on the
//!   per-user login keychain to unseal the master key, and the login
//!   keychain isn't unlocked until the user has signed in. Combined
//!   with `KeepAlive.SuccessfulExit=false`, loading at LoginWindow
//!   would put the daemon into a respawn loop against a locked
//!   keychain *before* the user has any way to interact with it. See
//!   README:151,171-205 for the keychain-ACL recovery story.
//!
//! Mirrors Apple's `com.apple.cfprefsd.xpc.agent.plist` (uses
//! `Background`) for the SSH path and Apple's general-purpose user-agent
//! pattern for the GUI path. NOT mirroring `com.apple.ctkd` (which
//! includes `LoginWindow`) — ctkd is a CryptoTokenKit XPC agent that
//! must run pre-login by design (the OS may need to talk to a smart
//! card before login itself), which is not our threat model.
//!
//! # rc.16 → rc.17 upgrade: bootout before bootstrap
//!
//! launchd reads a LaunchAgent plist at *bootstrap* time and caches the
//! parsed properties. Rewriting the plist file alone does NOT push
//! changes through to the live registration. So when `enable()` detects
//! plist content drift (the existing P31 plist-content-comparison at
//! line 235-240 below) and rewrites the file, it MUST also issue a
//! `launchctl bootout user/$UID/<label>` before the bootstrap call so
//! the new content is actually loaded. Without this, the rc.16 → rc.17
//! upgrade leaves a stale launchd registration with the rc.16-default
//! `Aqua` filter; the on-disk file would be correct but SSH-only
//! bootstrap would continue to fail until the next reboot.

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
/// load-bearing fields (`KeepAlive.SuccessfulExit=false`, `RunAtLoad=true`,
/// `LimitLoadToSessionType=[Background, Aqua]` — Story 7.21).
///
/// # LimitLoadToSessionType
///
/// See module-level docs. The exact value `[Background, Aqua]` is
/// asserted by an independent test
/// (`render_plist_session_type_value_is_background_aqua_only`) in
/// addition to the byte-for-byte `insta` snapshot — both must agree, and
/// changing the value requires updating both tests in lockstep.
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
    <key>LimitLoadToSessionType</key>
    <array>
        <string>Background</string>
        <string>Aqua</string>
    </array>
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
    // Story 7.16 Task 2: brew-services migration. Replaces the previous
    // refuse-on-conflict path with a migrate-or-refuse-with-validation
    // decision. Two independent detection signals: (a) brew status probe,
    // (b) plist-on-disk inspection. The plist signal is load-bearing
    // because over SSH `brew services list` itself can be unreliable
    // (gui-domain probes that 125-fail mid-query); the plist file is the
    // authoritative artifact regardless of what brew's status reports.
    let brew_active = brew_services_active(exec)?;
    let plist_inspection = inspect_brew_plist_path(home)?;
    let daemon = current_daemon_path()?;
    match decide_brew_migration(brew_active, plist_inspection.as_ref(), &daemon) {
        BrewMigrationDecision::Skip => {}
        BrewMigrationDecision::Refuse { reason } => {
            return Err(AutostartError::BrewMigrationRefused { message: reason });
        }
        BrewMigrationDecision::Migrate { reason: _ } => {
            execute_brew_migration(exec, plist_inspection.as_ref())?;
        }
    }

    let plist = plist_path(home);
    // P36: reject non-UTF-8 paths up front rather than `to_string_lossy`
    // corrupting the rendered plist with U+FFFD silently. The plist
    // format is UTF-8; we can't represent invalid bytes faithfully.
    // (`daemon` resolved earlier for the brew-migration decision; reuse.)
    super::require_utf8_path(&daemon)?;
    super::require_utf8_path(home)?;
    // Story 7.26 code-review round 2 (R1): this site receives the user's
    // home directory (from `autostart::home_dir()`, which returns
    // `dirs::home_dir()` — NOT a state-dir root). Routing through
    // `paths::daemon_log_dir(Some(home))` would drop the `.agentsso`
    // segment in production (`/Users/alice/logs/autostart.log` instead
    // of `/Users/alice/.agentsso/logs/autostart.log`) because the
    // override contract anchors at the state-dir root. AC #5's
    // centralization target is the daemon state dir (which moves to
    // `/Library/Application Support/permitlayer/` under the rc.22
    // LaunchDaemon model); per-user LaunchAgent log files stay
    // anchored to the user's home dir and are intentionally exempt
    // from the centralized path module.
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
    let target = format!("user/{user}");
    let plist_str = plist.to_string_lossy();
    let plist_arg: &str = &plist_str;

    // Story 7.21: when the on-disk plist content changed, the LIVE
    // launchd registration may still hold the previous content (launchd
    // reads the plist at bootstrap time and caches the parsed
    // properties). Force a bootout BEFORE the bootstrap so the new
    // content is actually picked up.
    //
    // Canonical case: rc.16 → rc.17 upgrade. rc.16 left a launchd
    // registration with the default `LimitLoadToSessionType=Aqua`.
    // rc.17's render adds the explicit `[Background, Aqua]` value.
    // Without this bootout, an operator who runs `agentsso autostart
    // enable` after `brew upgrade` would see the file refreshed (P31
    // detection above) and `bootstrap` return "already loaded" (exit
    // 17, treated as success), but the live registration would still
    // be the rc.16-default `Aqua` — so SSH-only bootstrap would
    // continue to fail with errno 134 until the next reboot.
    //
    // bootout returning errno 3 (`Boot-out failed: 3: No such process`)
    // means the agent wasn't actually loaded; that's fine — there's
    // nothing to refresh, and the subsequent bootstrap will register
    // from scratch. Any non-3, non-success exit is a real launchctl
    // failure and short-circuits with a structured error.
    //
    // Skip bootout when `unchanged == true` — re-running enable on a
    // truly-idempotent path shouldn't churn launchd state.
    if !unchanged {
        let bootout_target = format!("user/{user}/{LAUNCHD_LABEL}");
        let bootout_args = ["bootout", bootout_target.as_str()];
        let bootout_out = exec.run("launchctl", &bootout_args)?;
        if !bootout_out.status.success() && !already_unloaded(&bootout_out) {
            return Err(service_manager_failed("launchctl", &bootout_args, &bootout_out));
        }
    }

    let args = ["bootstrap", target.as_str(), plist_arg];
    let out = exec.run("launchctl", &args)?;
    if !out.status.success() && !already_loaded(&out) {
        // **P44 (code review round 5):** exit 119 ("Service is disabled")
        // means the agent IS bootstrapped but launchd has it disabled
        // (operator ran `launchctl disable` manually at some point). The
        // daemon will NOT start at login until we clear that flag. The
        // previous code conflated 119 with "already loaded" and silently
        // reported success — direct AC #1 violation. Now: detect 119,
        // run `launchctl enable user/$UID/<label>` to clear the flag,
        // then recover. Bootstrap is not re-run because the agent is
        // already known to launchd; clearing the disable is enough.
        if out.status.code() == Some(119) {
            // Bootstrap is not re-run because the agent is already known to
            // launchd; clearing the disable flag is enough. Invariant: this
            // assumes the existing registration's plist path matches the
            // path we just rendered — which holds because LAUNCHD_LABEL is
            // a workspace constant (`dev.agentsso.daemon`) stable across
            // all RC versions. If a future story renames the label, this
            // recovery path needs to re-bootstrap.
            let enable_target = format!("user/{user}/{LAUNCHD_LABEL}");
            let enable_args = ["enable", enable_target.as_str()];
            let enable_out = exec.run("launchctl", &enable_args)?;
            if !enable_out.status.success() {
                return Err(service_manager_failed("launchctl", &enable_args, &enable_out));
            }
        } else {
            return Err(service_manager_failed("launchctl", &args, &out));
        }
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

// ─── Story 7.16 Task 2: brew-services migration ────────────────────────
//
// `agentsso autostart enable` previously refused (returning
// `AutostartError::BrewServicesActive`) when brew-services was managing
// the daemon. Story 7.16 changes this to a migrate-or-refuse decision so
// existing rc.≤15 users can upgrade in place without manual cleanup.
//
// Two independent detection signals back the decision:
// 1. `brew_services_active` — parses `brew services list --json`
// 2. `inspect_brew_plist_path` — direct plist inspection
//
// The plist signal is load-bearing because over SSH the brew status
// probe itself can be unreliable (gui-domain probes that 125-fail in
// SSH context). The plist file at
// `~/Library/LaunchAgents/homebrew.mxcl.agentsso.plist` is the
// authoritative artifact regardless of what brew's status reports.

/// Result of inspecting the brew-managed plist on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BrewPlistInspection {
    /// Absolute path to the plist file.
    pub file_path: PathBuf,
    /// Value of the `<Label>` key (expected: `homebrew.mxcl.agentsso`).
    pub label: String,
    /// First entry of `<ProgramArguments>` (expected: a path that
    /// matches the `agentsso` binary we'd write the new plist for).
    pub program_args_first: PathBuf,
}

/// Decision returned by [`decide_brew_migration`]. The caller branches
/// on this to either skip (no migration needed), execute the migration
/// (clean state for a fresh user-domain bootstrap), or refuse with an
/// actionable error (the plist on disk doesn't match what we expect, so
/// auto-removing it would be an operator footgun).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BrewMigrationDecision {
    /// No brew-services state detected; proceed straight to user-domain bootstrap.
    Skip,
    /// Brew-managed state detected and validated; execute the migration.
    Migrate { reason: BrewMigrationReason },
    /// Brew-managed state detected but its shape is unexpected (hand-rolled
    /// plist with same label, or program-args pointing at a different binary).
    /// Refuse rather than auto-clean — operator must investigate manually.
    Refuse { reason: String },
}

/// Which signal(s) triggered a migration. Informational; included in the
/// stderr log line so an operator can correlate with their box's prior state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BrewMigrationReason {
    /// `brew services list --json` reported agentsso as `started`/`scheduled`,
    /// but no plist on disk (pathological — brew claims active without an artifact).
    BrewServicesActive,
    /// Plist on disk validates as a brew-managed agentsso plist; brew's
    /// status either says inactive or couldn't be probed.
    PlistOnDisk,
    /// Both signals positive — the canonical case for an rc.≤15 → rc.16 upgrade.
    Both,
}

/// Inspect `~/Library/LaunchAgents/homebrew.mxcl.agentsso.plist`. Returns
/// `Ok(None)` when the file doesn't exist (the common case for first-time
/// installs); `Ok(Some(inspection))` when a plist is present and its
/// `<Label>` + `<ProgramArguments>[0]` could be extracted.
///
/// Uses narrow string-scan parsing (NOT a `plist` crate dep — verified
/// 2026-05-07 that no such dep is in the workspace, and adding one for a
/// single use is bad ROI). Mirrors the simplicity of [`parse_program_path`]
/// above. Returns `Ok(None)` if the plist exists but key extraction fails
/// — the file is malformed enough that we can't make a confident decision,
/// and the safest action is to skip migration (operator's hand-rolled
/// config stays untouched).
pub(crate) fn inspect_brew_plist_path(home: &Path) -> std::io::Result<Option<BrewPlistInspection>> {
    // Per-user `brew services` writes to `~/Library/LaunchAgents/`.
    // System-wide `sudo brew services` writes to `/Library/LaunchAgents/`
    // — that path is intentionally NOT inspected here: rc.16's onboarding
    // flow assumes per-user installs (single-operator threat model;
    // `current_user_id` already refuses to ship a root LaunchAgent),
    // and a system-wide brew install is administered by a different
    // user account that wouldn't be running `agentsso autostart enable`
    // from their own session in the first place.
    let path = home.join("Library/LaunchAgents/homebrew.mxcl.agentsso.plist");
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let xml = match std::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(_) => return Ok(None), // malformed; skip migration safely
    };

    // Extract <Label>VALUE</Label> following <key>Label</key>.
    let label = match extract_plist_string_after_key(xml, "Label") {
        Some(s) => s,
        None => return Ok(None),
    };

    // Extract first <string> inside <ProgramArguments> array. Reuse
    // `parse_program_path`'s pattern (line 415) for symmetry.
    let program_args_first = match extract_plist_program_args_first(xml) {
        Some(p) => p,
        None => return Ok(None),
    };

    Ok(Some(BrewPlistInspection { file_path: path, label, program_args_first }))
}

/// Find `<key>NAME</key>\s*<string>VALUE</string>` and return VALUE
/// (XML-unescaped). Returns `None` on parse failure.
///
/// The next non-whitespace token after the key MUST be `<string>` — a
/// boolean (`<true/>`/`<false/>`), an array, a dict, or another key
/// rejects the match. Without this guard the function would skip past
/// non-string values to find a later `<string>` belonging to a
/// different key (review finding 2026-05-07).
fn extract_plist_string_after_key(xml: &str, key: &str) -> Option<String> {
    let key_marker = format!("<key>{key}</key>");
    let key_idx = xml.find(&key_marker)?;
    let after_key = &xml[key_idx + key_marker.len()..];
    let trimmed = after_key.trim_start();
    if !trimmed.starts_with("<string>") {
        return None;
    }
    let s_open = "<string>".len();
    let s_close = trimmed[s_open..].find("</string>")? + s_open;
    let raw = &trimmed[s_open..s_close];
    let decoded = super::xml_unescape(raw);
    if decoded.is_empty() {
        return None;
    }
    Some(decoded)
}

/// Find `<key>ProgramArguments</key>\s*<array>\s*<string>FIRST</string>...`
/// and return FIRST as a `PathBuf`. Returns `None` on parse failure.
/// Mirrors [`parse_program_path`] (line 415) but operates on the
/// brew-managed plist (which may have a different overall shape).
fn extract_plist_program_args_first(xml: &str) -> Option<PathBuf> {
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

/// Path equality that tolerates the macOS Homebrew Cellar↔opt-bin
/// symlink layout. The brew plist embeds the stable `opt_bin` path
/// (e.g., `/opt/homebrew/bin/agentsso` → symlink to
/// `/opt/homebrew/Cellar/agentsso/<ver>/bin/agentsso`), but
/// [`current_daemon_path`] resolves through `current_exe()` which
/// returns the canonicalized Cellar path on macOS. A naive `==`
/// comparison would refuse legitimate migrations on every brew
/// upgrade. We try `canonicalize` on both sides; if either fails to
/// resolve (e.g., binary already removed mid-upgrade), fall back to
/// byte-exact equality so a real path drift still triggers `Refuse`.
fn same_binary(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => false,
    }
}

/// Pure decision logic. Caller passes in the two signals and the path to
/// the agentsso binary the new plist will reference; this returns a
/// [`BrewMigrationDecision`] to dispatch on.
///
/// The decision matrix:
///
/// | brew_active | plist_inspection | Decision |
/// |-------------|------------------|----------|
/// | false       | None             | `Skip` (no brew-managed state) |
/// | false       | matches binary   | `Migrate { PlistOnDisk }` (leftover plist) |
/// | false       | mismatched binary | `Refuse` (hand-rolled or stale) |
/// | true        | None             | `Migrate { BrewServicesActive }` (brew claims active, no plist — pathological but recoverable) |
/// | true        | matches binary   | `Migrate { Both }` (canonical rc.≤15 upgrade case) |
/// | true        | mismatched binary | `Refuse` (confused state) |
///
/// "Matches binary" means `<Label> == "homebrew.mxcl.agentsso"` AND
/// `<ProgramArguments>[0]` is the same path as `expected_binary`. Both
/// must validate; either failing → `Refuse`.
pub(crate) fn decide_brew_migration(
    brew_active: bool,
    plist_inspection: Option<&BrewPlistInspection>,
    expected_binary: &Path,
) -> BrewMigrationDecision {
    match (brew_active, plist_inspection) {
        (false, None) => BrewMigrationDecision::Skip,
        (true, None) => {
            BrewMigrationDecision::Migrate { reason: BrewMigrationReason::BrewServicesActive }
        }
        (brew_state, Some(insp)) => {
            // Validate the plist's shape regardless of brew_active.
            if insp.label != "homebrew.mxcl.agentsso" {
                return BrewMigrationDecision::Refuse {
                    reason: format!(
                        "{} <Label> is '{}', expected 'homebrew.mxcl.agentsso'. \
                         This looks like a hand-rolled plist; refusing to migrate. \
                         Move it aside manually and re-run.",
                        insp.file_path.display(),
                        insp.label
                    ),
                };
            }
            if !same_binary(&insp.program_args_first, expected_binary) {
                return BrewMigrationDecision::Refuse {
                    reason: format!(
                        "{} <ProgramArguments>[0] is '{}', expected '{}'. \
                         This looks like a stale or hand-rolled plist; refusing to migrate. \
                         Move it aside manually and re-run.",
                        insp.file_path.display(),
                        insp.program_args_first.display(),
                        expected_binary.display()
                    ),
                };
            }
            // Both validations pass.
            BrewMigrationDecision::Migrate {
                reason: if brew_state {
                    BrewMigrationReason::Both
                } else {
                    BrewMigrationReason::PlistOnDisk
                },
            }
        }
    }
}

/// Execute the migration: stop brew-services (best-effort), bootout the
/// gui-domain LaunchAgent (tolerating exit 125 in SSH contexts where the
/// gui domain itself doesn't exist), and rename the plist to a timestamped
/// backup file.
///
/// Idempotency: this helper is only called when [`decide_brew_migration`]
/// returns `Migrate`, which requires a brew signal (status-active OR
/// inspectable plist on disk). After a successful run, the original plist
/// has been renamed to a backup path so a subsequent
/// [`inspect_brew_plist_path`] call returns `None`; combined with brew's
/// status going inactive after `services stop`, the next `enable`
/// invocation takes the `Skip` branch in `decide_brew_migration` and
/// this helper is not invoked at all. (If an operator manually restores
/// a fresh brew plist between runs, a NEW timestamped backup is created
/// on the second run — backup paths use nanosecond-precision RFC3339
/// stamps via `chrono::SecondsFormat::AutoSi`, so collisions are not
/// realistic.)
pub(crate) fn execute_brew_migration(
    exec: &impl Engine,
    plist_inspection: Option<&BrewPlistInspection>,
) -> Result<(), AutostartError> {
    // Step 1: brew services stop agentsso (best-effort). Tolerate
    // non-zero exit; brew may not be on PATH at all (rare; e.g.,
    // operator manually installed a brew plist without homebrew),
    // and even if it is, "service is already stopped" is a non-error
    // outcome we don't want to fail on.
    let _ = exec.run("brew", &["services", "stop", "agentsso"]);

    // Step 2: launchctl bootout gui/$UID/homebrew.mxcl.agentsso.
    // Tolerate 113 (not loaded), 3 (ESRCH — older form), 36
    // (operation in progress — bootout is async). Exit 125 is
    // tolerated ONLY when stderr identifies the gui-domain-absent
    // case ("Domain does not support specified action") — narrowing
    // the tolerance prevents masking a real permission-denied 125
    // (which would surface as a different stderr message).
    //
    // Concurrency invariant: a still-pending bootout on
    // `gui/$UID/homebrew.mxcl.agentsso` (label `homebrew.mxcl.agentsso`)
    // cannot race the subsequent bootstrap into
    // `user/$UID/dev.agentsso.daemon` — different label, different
    // domain — so exit 36 is safe to tolerate without ordering.
    let user = current_user_id()?;
    let target = format!("gui/{user}/homebrew.mxcl.agentsso");
    let bootout_args = ["bootout", target.as_str()];
    if let Ok(out) = exec.run("launchctl", &bootout_args)
        && !out.status.success()
    {
        let code = out.status.code();
        let stderr = String::from_utf8_lossy(&out.stderr);
        let tolerated = match code {
            Some(113) | Some(3) | Some(36) => true,
            Some(125) => stderr.contains("Domain does not support specified action"),
            _ => false,
        };
        if !tolerated {
            return Err(service_manager_failed("launchctl", &bootout_args, &out));
        }
    }

    // Step 3: rename the plist to a timestamped backup, IF a plist
    // was inspected. (When `BrewMigrationReason::BrewServicesActive`
    // fires without a plist, there's nothing to back up — brew claimed
    // active but the artifact is missing.)
    if let Some(insp) = plist_inspection {
        let backup_path = backup_path_for(&insp.file_path);
        std::fs::rename(&insp.file_path, &backup_path)
            .map_err(|source| AutostartError::BrewMigrationFailed { source })?;
        tracing::info!(
            backup_path = %backup_path.display(),
            "migrated from brew-services autostart to user-domain LaunchAgent (brew plist backed up)"
        );
    } else {
        tracing::info!(
            "migrated from brew-services autostart to user-domain LaunchAgent (no brew plist found on disk; brew status alone reported active)"
        );
    }

    Ok(())
}

/// Compute the backup path for a brew-managed plist:
/// `<original>.bak.<RFC3339-timestamp>`.
///
/// Uses `chrono::Utc::now().to_rfc3339()` (chrono is already in
/// workspace deps per `Cargo.toml:153`). The RFC 3339 format includes
/// colons (`2026-05-07T20:15:30Z`) — these are valid filename
/// characters on macOS and Linux but NOT on Windows; this code path
/// is `#[cfg(target_os = "macos")]` only so that's not a concern.
fn backup_path_for(original: &Path) -> PathBuf {
    let ts = chrono::Utc::now().to_rfc3339();
    let mut backup = original.to_path_buf();
    let name = original
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "homebrew.mxcl.agentsso.plist".to_owned());
    backup.set_file_name(format!("{name}.bak.{ts}"));
    backup
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
///
/// **P44 (round 5):** exit 119 ("Service is disabled") was previously
/// matched here as success — but a disabled service does NOT start at
/// login, so we silently violated AC #1. The bootstrap path now
/// detects 119 separately and runs `launchctl enable` to clear the
/// flag before reporting success.
fn already_loaded(out: &Output) -> bool {
    matches!(out.status.code(), Some(17))
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
    fn plist_renders_canonical_layout() {
        let xml = render_plist(
            Path::new("/usr/local/bin/agentsso"),
            Path::new("/Users/maya/.agentsso/logs/autostart.log"),
            Path::new("/Users/maya"),
        );
        insta::assert_snapshot!("autostart_macos_plist", xml);
    }

    /// Story 7.21: independently asserts the exact `LimitLoadToSessionType`
    /// value. `insta::assert_snapshot!` accepts whatever the renderer
    /// emits — if a future change accidentally uses `cargo insta accept`
    /// on a wrong value (e.g., dropping `Background`, adding `LoginWindow`),
    /// the snapshot test alone wouldn't catch it. This test independently
    /// pins what we *want* the renderer to emit.
    #[test]
    fn render_plist_session_type_value_is_background_aqua_only() {
        let xml = render_plist(
            Path::new("/usr/local/bin/agentsso"),
            Path::new("/tmp/log"),
            Path::new("/tmp"),
        );
        // The exact substring is whitespace-sensitive to match the
        // 4-space indent the renderer uses; if the renderer's
        // indentation ever changes, both this test and the snapshot
        // need updating in lockstep.
        let expected = "    <key>LimitLoadToSessionType</key>\n    <array>\n        <string>Background</string>\n        <string>Aqua</string>\n    </array>\n";
        assert!(
            xml.contains(expected),
            "rendered plist must contain LimitLoadToSessionType=[Background, Aqua] exactly. \
             Got XML:\n{xml}"
        );
        // Defense in depth: ensure no `LoginWindow` snuck in. If a
        // future story decides LoginWindow is OK after all, that
        // story's plan needs to update this test AND the docstring
        // in `macos.rs` explaining why the keychain-pre-login hazard
        // is no longer load-bearing.
        assert!(
            !xml.contains("<string>LoginWindow</string>"),
            "LimitLoadToSessionType must NOT include LoginWindow — see render_plist docstring \
             for the keychain-pre-login + KeepAlive respawn-loop hazard rationale. XML:\n{xml}"
        );
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
    fn enable_migrates_when_brew_services_active_with_no_plist_on_disk() {
        // Story 7.16 Task 2: previously this test asserted refusal
        // (`Err(AutostartError::BrewServicesActive)`). New behavior:
        // brew claims active but no plist on disk → Migrate
        // (BrewMigrationReason::BrewServicesActive); execute migration
        // (brew-stop + launchctl bootout, both best-effort), then
        // proceed with the user-domain bootstrap. The old refusal
        // path is no longer produced by `enable()`.
        let tmp = tempfile::TempDir::new().unwrap();
        let mock = MockExec::default();
        // brew services list --json (returns active)
        mock.push_reply(MockExec::ok(r#"[{"name":"agentsso","status":"started"}]"#));
        // Migration step 1: brew services stop agentsso (best-effort; mock OK)
        mock.push_reply(MockExec::ok(""));
        // Migration step 2: launchctl bootout gui/<uid>/homebrew.mxcl.agentsso
        // — over SSH this returns exit 125; mock that to verify tolerance.
        mock.push_reply(MockExec::fail(125, "Domain does not support specified action"));
        // Story 7.21: bootout-before-bootstrap on plist content drift
        // (the on-disk plist is being newly written, so it differs from
        // any pre-existing content — the unchanged-detection in enable()
        // returns false and the bootout fires). errno 3 is the
        // expected idempotent case (no prior registration to bootout).
        mock.push_reply(MockExec::fail(3, "Boot-out failed: 3: No such process"));
        // Bootstrap proceeds normally.
        mock.push_reply(MockExec::ok(""));

        let outcome = enable(&mock, tmp.path()).unwrap();
        match &outcome {
            EnableOutcome::Registered { mechanism, artifact_path } => {
                assert_eq!(*mechanism, MECHANISM);
                assert!(artifact_path.exists());
            }
            other => panic!("expected Registered after migration, got {other:?}"),
        }

        // Assert call sequence: brew-list + brew-stop + launchctl-bootout
        // (gui/<uid>/homebrew.mxcl.agentsso, the brew-managed plist) +
        // launchctl-bootout (user/<uid>/<our-label>, Story 7.21
        // bootout-before-bootstrap on content drift) + launchctl-bootstrap.
        let calls = mock.calls.borrow();
        assert_eq!(
            calls.len(),
            5,
            "expected 5 calls (brew list, brew stop, brew-managed bootout, our-label bootout, our bootstrap), got {calls:?}"
        );
        assert_eq!(calls[0].0, "brew");
        assert_eq!(calls[0].1[0], "services");
        assert_eq!(calls[0].1[1], "list");
        assert_eq!(calls[1].0, "brew");
        assert_eq!(calls[1].1[0], "services");
        assert_eq!(calls[1].1[1], "stop");
        assert_eq!(calls[2].0, "launchctl");
        assert_eq!(calls[2].1[0], "bootout");
        // Story 7.16: bootout target is gui/<uid>/homebrew.mxcl.agentsso
        // (the brew-managed plist's domain — gui, NOT user) because we're
        // un-bootstrapping brew's prior registration.
        assert!(
            calls[2].1[1].starts_with("gui/"),
            "brew-managed bootout target should be gui/<uid>/homebrew.mxcl.agentsso, got {:?}",
            calls[2].1[1]
        );
        // Story 7.21: bootout our user-domain registration before
        // bootstrap, so the new plist content is loaded fresh.
        assert_eq!(calls[3].0, "launchctl");
        assert_eq!(calls[3].1[0], "bootout");
        assert!(
            calls[3].1[1].starts_with("user/"),
            "our-label bootout target should be user/<uid>/<our-label>, got {:?}",
            calls[3].1[1]
        );
        assert!(
            calls[3].1[1].ends_with(LAUNCHD_LABEL),
            "our-label bootout target should end with the agentsso label, got {:?}",
            calls[3].1[1]
        );
        assert_eq!(calls[4].0, "launchctl");
        assert_eq!(calls[4].1[0], "bootstrap");
        // Story 7.16 AC #2: bootstrap target is user/<uid>.
        assert!(
            calls[4].1[1].starts_with("user/"),
            "bootstrap target should be user/<uid>, got {:?}",
            calls[4].1[1]
        );
    }

    #[test]
    fn enable_writes_plist_when_brew_inactive() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mock = MockExec::default();
        mock.push_reply(MockExec::ok("[]")); // brew services list: empty
        // Story 7.21: bootout-before-bootstrap fires because no plist
        // exists on disk → unchanged=false → bootout. errno 3 ("No
        // such process") is the expected idempotent outcome here.
        mock.push_reply(MockExec::fail(3, "Boot-out failed: 3: No such process"));
        mock.push_reply(MockExec::ok("")); // launchctl bootstrap: ok

        let outcome = enable(&mock, tmp.path()).unwrap();
        match &outcome {
            EnableOutcome::Registered { mechanism, artifact_path } => {
                assert_eq!(*mechanism, MECHANISM);
                assert!(artifact_path.exists(), "expected plist at {}", artifact_path.display());
            }
            other => panic!("expected Registered, got {other:?}"),
        }

        // Calls in order: brew, launchctl bootout (Story 7.21), launchctl bootstrap.
        let calls = mock.calls.borrow();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].0, "brew");
        assert_eq!(calls[1].0, "launchctl");
        assert_eq!(calls[1].1[0], "bootout");
        assert_eq!(calls[2].0, "launchctl");
        assert_eq!(calls[2].1[0], "bootstrap");
        // Story 7.15 AC #2: launchctl target MUST be user/<uid>, never
        // gui/<uid>. The gui/ domain only exists for active GUI login
        // sessions and returns exit 125 over SSH.
        assert!(
            calls[2].1[1].starts_with("user/"),
            "bootstrap target should be user/<uid>, got {:?}",
            calls[2].1[1]
        );
        assert!(
            !calls[2].1[1].starts_with("gui/"),
            "bootstrap target must NOT use gui/ domain (Story 7.15 regression guard); got {:?}",
            calls[2].1[1]
        );
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
        // Story 7.21: bootout-before-bootstrap fires because the
        // pre-existing plist content differs from the renderer output.
        mock.push_reply(MockExec::ok("")); // launchctl bootout (the stale registration cleared)
        mock.push_reply(MockExec::ok("")); // launchctl bootstrap

        let outcome = enable(&mock, tmp.path()).unwrap();
        assert!(matches!(outcome, EnableOutcome::Registered { .. }));
        // The plist content was refreshed (no longer the stale stub).
        let xml = std::fs::read_to_string(&plist).unwrap();
        assert!(xml.contains("<key>Label</key>"));
        assert!(!xml.contains("stale plist"));
    }

    #[test]
    fn enable_boots_out_stale_registration_on_plist_content_change() {
        // Story 7.21 Task 1.6: when the on-disk plist content changes
        // (rc.16 → rc.17 upgrade is the canonical case), enable() must
        // `launchctl bootout user/<uid>/<label>` BEFORE `launchctl
        // bootstrap`. Otherwise the live launchd registration keeps the
        // rc.16-default Aqua filter even though the on-disk file now has
        // [Background, Aqua] — the on-disk plist would be correct but
        // SSH-only bootstrap would still fail with errno 134 until next
        // reboot.
        //
        // Repro setup: pre-write a stale plist (anything different from
        // the current renderer output triggers the content-drift path).
        let tmp = tempfile::TempDir::new().unwrap();
        let plist = plist_path(tmp.path());
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::write(&plist, "<?xml stale rc.16 plist ?>").unwrap();

        let mock = MockExec::default();
        // brew services list: empty (skip migration path).
        mock.push_reply(MockExec::ok("[]"));
        // Story 7.21: bootout returning errno 3 (`Boot-out failed: 3:
        // No such process`) is the expected idempotent case — we don't
        // know whether the agent was loaded, so we always try, and
        // tolerate the not-loaded outcome. Mock that here.
        mock.push_reply(MockExec::fail(3, "Boot-out failed: 3: No such process"));
        // launchctl bootstrap proceeds.
        mock.push_reply(MockExec::ok(""));

        enable(&mock, tmp.path()).unwrap();

        let calls = mock.calls.borrow();
        // Expect 3 calls: brew list, launchctl bootout, launchctl bootstrap.
        assert_eq!(
            calls.len(),
            3,
            "expected 3 calls (brew list, launchctl bootout, launchctl bootstrap), got {calls:?}"
        );
        assert_eq!(calls[0].0, "brew");
        // Story 7.21: bootout MUST come before bootstrap on content drift.
        assert_eq!(calls[1].0, "launchctl");
        assert_eq!(calls[1].1[0], "bootout");
        assert!(
            calls[1].1[1].starts_with("user/"),
            "bootout target should be user/<uid>/<label>, got {:?}",
            calls[1].1[1]
        );
        assert!(
            calls[1].1[1].ends_with(LAUNCHD_LABEL),
            "bootout target should end with the agentsso label, got {:?}",
            calls[1].1[1]
        );
        assert_eq!(calls[2].0, "launchctl");
        assert_eq!(calls[2].1[0], "bootstrap");
    }

    #[test]
    fn enable_skips_bootout_when_plist_content_unchanged() {
        // Story 7.21: when the on-disk plist content is byte-for-byte
        // identical to what we'd write, enable() returns
        // AlreadyEnabled and MUST NOT churn launchd state with a
        // bootout. (See `enable_truly_idempotent_when_content_unchanged`
        // for the broader idempotence invariant; this test pins the
        // bootout-skip subset.)
        let tmp = tempfile::TempDir::new().unwrap();
        let plist = plist_path(tmp.path());
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        let daemon = current_daemon_path().unwrap();
        let log_path = tmp.path().join(".agentsso").join("logs").join("autostart.log");
        let xml = render_plist(&daemon, &log_path, tmp.path());
        std::fs::write(&plist, &xml).unwrap();

        let mock = MockExec::default();
        mock.push_reply(MockExec::ok("[]")); // brew
        mock.push_reply(MockExec::ok("")); // launchctl bootstrap

        enable(&mock, tmp.path()).unwrap();

        let calls = mock.calls.borrow();
        // Expect exactly 2 calls: brew list + launchctl bootstrap. NO bootout.
        assert_eq!(calls.len(), 2, "expected 2 calls (brew list, bootstrap), got {calls:?}");
        assert_eq!(calls[0].0, "brew");
        assert_eq!(calls[1].0, "launchctl");
        assert_eq!(calls[1].1[0], "bootstrap");
        // The middle slot should NOT be a bootout.
        for call in calls.iter() {
            if call.0 == "launchctl" {
                assert_ne!(
                    call.1[0], "bootout",
                    "Story 7.21: enable() must NOT bootout when plist content is unchanged"
                );
            }
        }
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
    fn round_trip_enable_status_disable_status() {
        // P24 (code review): exercises the full state machine —
        // enable → status reports Enabled → disable → status reports
        // Disabled. Catches state-desync bugs where one operation
        // leaves residue the next one misreads.
        let tmp = tempfile::TempDir::new().unwrap();
        let mock = MockExec::default();

        // enable: brew probe (empty) + Story 7.21 bootout-before-bootstrap + launchctl bootstrap.
        mock.push_reply(MockExec::ok("[]"));
        mock.push_reply(MockExec::fail(3, "Boot-out failed: 3: No such process"));
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

        // Story 7.15 AC #2: end-to-end check — every launchctl call in
        // this round-trip used user/<uid> domain, NEVER gui/<uid>.
        // This is the regression-guard that catches a flip back to
        // gui/ at any of the three call sites (bootstrap, print,
        // bootout) or any future addition.
        let calls = mock.calls.borrow();
        for (cmd, args) in calls.iter() {
            if cmd != "launchctl" {
                continue;
            }
            // launchctl args: [verb, target, ...]. target is at index 1.
            if let Some(target) = args.get(1) {
                assert!(
                    !target.starts_with("gui/"),
                    "launchctl call used gui/ domain (Story 7.15 regression): {cmd} {args:?}"
                );
                if target.contains('/') {
                    // Skip non-domain args (e.g., file paths). Real
                    // launchctl targets always start with the domain.
                    let starts_with_domain = target.starts_with("user/")
                        || target.starts_with("system/")
                        || target.starts_with("/"); // file path arg
                    assert!(
                        starts_with_domain,
                        "launchctl target should be user/<uid>... (Story 7.15); got {:?}",
                        target
                    );
                }
            }
        }
    }

    /// Story 7.15 AC #2: explicit regression guard — assert no `gui/`
    /// domain reference exists in the production code path's launchctl
    /// invocations. This is a separate test from the round-trip's
    /// in-line assertion so a single test name maps to the regression
    /// concern (easier to find when triaging a future failure).
    #[test]
    fn enable_targets_user_domain_at_all_call_sites() {
        // Exercise enable → status (probe) → disable, then check
        // every recorded launchctl call's target arg.
        let tmp = tempfile::TempDir::new().unwrap();
        let mock = MockExec::default();

        // enable
        mock.push_reply(MockExec::ok("[]")); // brew probe
        // Story 7.21: bootout-before-bootstrap on content drift.
        mock.push_reply(MockExec::fail(3, "Boot-out failed: 3: No such process"));
        mock.push_reply(MockExec::ok("")); // launchctl bootstrap
        enable(&mock, tmp.path()).unwrap();

        // status (probes launchctl print)
        mock.push_reply(MockExec::ok("[]")); // brew probe
        mock.push_reply(MockExec::ok("")); // launchctl print
        status(&mock, tmp.path()).unwrap();

        // disable
        mock.push_reply(MockExec::ok("")); // launchctl bootout
        mock.push_reply(MockExec::ok("[]")); // brew probe
        disable(&mock, tmp.path()).unwrap();

        // Walk every launchctl call's target. The target arg is
        // args[1] for bootstrap/bootout/print (verb at args[0],
        // target at args[1]).
        let calls = mock.calls.borrow();
        let launchctl_calls: Vec<_> = calls.iter().filter(|c| c.0 == "launchctl").collect();
        // Story 7.21: 4 launchctl calls now — Story-7.21 bootout pre-bootstrap +
        // bootstrap + status' print + disable's bootout.
        assert_eq!(
            launchctl_calls.len(),
            4,
            "expected 4 launchctl calls (Story 7.21 bootout, bootstrap, print, bootout); got {launchctl_calls:?}"
        );
        for (_, args) in &launchctl_calls {
            let target = &args[1];
            assert!(
                target.starts_with("user/"),
                "launchctl target must start with user/ (Story 7.15); got {target:?}"
            );
            assert!(
                !target.contains("gui/"),
                "launchctl target contains gui/ — Story 7.15 regression: {target:?}"
            );
        }
    }

    /// Story 7.15 AC #2: regression guard against the 119-recovery
    /// path. When bootstrap returns exit 119 (Service is disabled),
    /// the recovery `launchctl enable` call MUST also target user/.
    #[test]
    fn enable_119_recovery_uses_user_domain_target() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mock = MockExec::default();

        mock.push_reply(MockExec::ok("[]")); // brew probe
        // Story 7.21: bootout-before-bootstrap fires on content drift.
        mock.push_reply(MockExec::fail(3, "Boot-out failed: 3: No such process"));
        mock.push_reply(MockExec::fail(119, "Service is disabled")); // bootstrap
        mock.push_reply(MockExec::ok("")); // launchctl enable (recovery)

        let outcome = enable(&mock, tmp.path()).unwrap();
        assert!(matches!(outcome, EnableOutcome::Registered { .. }));

        let calls = mock.calls.borrow();
        let enable_recovery = calls.iter().find(|c| c.0 == "launchctl" && c.1[0] == "enable");
        let enable_recovery = enable_recovery.expect("expected launchctl enable recovery call");
        let target = &enable_recovery.1[1];
        assert!(
            target.starts_with("user/"),
            "119-recovery enable target should start with user/ (Story 7.15); got {target:?}"
        );
        assert!(
            !target.starts_with("gui/"),
            "119-recovery enable target must NOT use gui/ (Story 7.15); got {target:?}"
        );
    }

    // ─── Story 7.16 Task 2 brew-migration tests ────────────────────────

    /// Helper: write a brew-shaped plist into a tempdir's
    /// `Library/LaunchAgents/` for use as a Story 7.16 migration fixture.
    /// `program_args_first` is what the plist's `<ProgramArguments>[0]`
    /// will reference; pass `current_daemon_path()` to simulate a
    /// canonical brew-managed plist that validates, or any other path to
    /// simulate a hand-rolled plist that should be refused.
    fn write_brew_plist_fixture(home: &Path, label: &str, program_args_first: &Path) -> PathBuf {
        let plist_path = home.join("Library/LaunchAgents/homebrew.mxcl.agentsso.plist");
        std::fs::create_dir_all(plist_path.parent().unwrap()).unwrap();
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>start</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
"#,
            label,
            program_args_first.display()
        );
        std::fs::write(&plist_path, xml).unwrap();
        plist_path
    }

    /// Story 7.16 AC #4: pure decision-matrix coverage. No exec calls.
    /// Exercises `decide_brew_migration` against the 6 cases from the
    /// docstring's matrix.
    #[test]
    fn decide_brew_migration_decision_matrix() {
        let expected = Path::new("/usr/local/bin/agentsso");
        let valid = BrewPlistInspection {
            file_path: PathBuf::from("/Users/x/Library/LaunchAgents/homebrew.mxcl.agentsso.plist"),
            label: "homebrew.mxcl.agentsso".to_owned(),
            program_args_first: expected.to_path_buf(),
        };
        let bad_label =
            BrewPlistInspection { label: "homebrew.mxcl.evil".to_owned(), ..valid.clone() };
        let bad_args = BrewPlistInspection {
            program_args_first: PathBuf::from("/usr/bin/false"),
            ..valid.clone()
        };

        // Row 1: brew_active=false, no plist → Skip.
        assert_eq!(decide_brew_migration(false, None, expected), BrewMigrationDecision::Skip);

        // Row 2: brew_active=false, valid plist → Migrate{PlistOnDisk}.
        assert_eq!(
            decide_brew_migration(false, Some(&valid), expected),
            BrewMigrationDecision::Migrate { reason: BrewMigrationReason::PlistOnDisk }
        );

        // Row 3: brew_active=false, bad-label plist → Refuse.
        assert!(matches!(
            decide_brew_migration(false, Some(&bad_label), expected),
            BrewMigrationDecision::Refuse { .. }
        ));

        // Row 4: brew_active=true, no plist → Migrate{BrewServicesActive}.
        assert_eq!(
            decide_brew_migration(true, None, expected),
            BrewMigrationDecision::Migrate { reason: BrewMigrationReason::BrewServicesActive }
        );

        // Row 5: brew_active=true, valid plist → Migrate{Both}.
        assert_eq!(
            decide_brew_migration(true, Some(&valid), expected),
            BrewMigrationDecision::Migrate { reason: BrewMigrationReason::Both }
        );

        // Row 6: brew_active=true, bad-args plist → Refuse.
        assert!(matches!(
            decide_brew_migration(true, Some(&bad_args), expected),
            BrewMigrationDecision::Refuse { .. }
        ));
    }

    /// Story 7.16 Task 2: full enable() with a valid brew-managed plist
    /// on disk and brew status reporting active. Asserts the migration
    /// path executes (brew-stop → bootout → plist-rename-to-backup) and
    /// then the user-domain bootstrap succeeds. The plist file should
    /// no longer exist at its primary path; a `*.bak.<timestamp>` file
    /// should exist alongside it.
    #[test]
    fn migration_backs_up_plist_before_user_domain_bootstrap() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Fixture: brew plist on disk with the canonical label + a
        // program-args path matching current_daemon_path(). This
        // makes decide_brew_migration return Migrate{Both} (when
        // combined with the active brew status below).
        let daemon = current_daemon_path().unwrap();
        let original_plist =
            write_brew_plist_fixture(tmp.path(), "homebrew.mxcl.agentsso", &daemon);

        let mock = MockExec::default();
        // brew services list --json (returns active)
        mock.push_reply(MockExec::ok(r#"[{"name":"agentsso","status":"started"}]"#));
        // Migration: brew services stop
        mock.push_reply(MockExec::ok(""));
        // Migration: launchctl bootout (mock OK to simulate console-with-gui-domain box)
        mock.push_reply(MockExec::ok(""));
        // Story 7.21: bootout-before-bootstrap on content drift (our
        // user-domain plist is being newly written, so unchanged=false).
        mock.push_reply(MockExec::fail(3, "Boot-out failed: 3: No such process"));
        // User-domain bootstrap
        mock.push_reply(MockExec::ok(""));

        let outcome = enable(&mock, tmp.path()).unwrap();
        assert!(matches!(outcome, EnableOutcome::Registered { .. }));

        // Original plist file should NO LONGER exist at its primary path.
        assert!(!original_plist.exists(), "original brew plist should have been renamed to backup");
        // A backup file MUST exist in the same directory matching `*.bak.*`.
        let backup_dir = original_plist.parent().unwrap();
        let backup_count = std::fs::read_dir(backup_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name().to_string_lossy().contains("homebrew.mxcl.agentsso.plist.bak.")
            })
            .count();
        assert_eq!(backup_count, 1, "expected exactly one backup file in {}", backup_dir.display());
    }

    /// Story 7.16 Task 2: brew status is unreliable (over SSH) and
    /// returns false despite a valid plist on disk. The plist signal
    /// alone should drive the migration. Mirrors the SSH-context case
    /// where `brew services list` itself fails or returns stale data.
    #[test]
    fn migration_uses_plist_path_when_brew_status_unreliable() {
        let tmp = tempfile::TempDir::new().unwrap();
        let daemon = current_daemon_path().unwrap();
        let original_plist =
            write_brew_plist_fixture(tmp.path(), "homebrew.mxcl.agentsso", &daemon);

        let mock = MockExec::default();
        // brew services list returns empty (status probe failed/empty)
        mock.push_reply(MockExec::ok("[]"));
        // Even without brew_active, the plist on disk drives Migrate{PlistOnDisk}.
        // Migration: brew stop (best-effort)
        mock.push_reply(MockExec::ok(""));
        // Migration: launchctl bootout (brew-managed gui-domain plist)
        mock.push_reply(MockExec::ok(""));
        // Story 7.21: bootout-before-bootstrap on content drift (our user-domain plist).
        mock.push_reply(MockExec::fail(3, "Boot-out failed: 3: No such process"));
        // User-domain bootstrap
        mock.push_reply(MockExec::ok(""));

        let outcome = enable(&mock, tmp.path()).unwrap();
        assert!(matches!(outcome, EnableOutcome::Registered { .. }));
        assert!(!original_plist.exists(), "plist should have been backed up");
    }

    /// Story 7.16 Task 2: launchctl bootout returns exit 125 (gui domain
    /// unavailable in SSH context). Migration must tolerate this and
    /// proceed with the plist rename + user-domain bootstrap. This is
    /// the canonical SSH-on-Angie's-box failure mode that the original
    /// rc.15 surfaced (just on a different launchctl invocation).
    #[test]
    fn migration_tolerates_bootout_exit_125() {
        let tmp = tempfile::TempDir::new().unwrap();
        let daemon = current_daemon_path().unwrap();
        let original_plist =
            write_brew_plist_fixture(tmp.path(), "homebrew.mxcl.agentsso", &daemon);

        let mock = MockExec::default();
        mock.push_reply(MockExec::ok(r#"[{"name":"agentsso","status":"started"}]"#));
        mock.push_reply(MockExec::ok("")); // brew stop
        // launchctl bootout returns exit 125 — gui domain not bootstrapped
        // (this is exactly the failure mode rc.15 hit on Angie's box for the
        // bootstrap call; here we hit it on the migration's bootout).
        mock.push_reply(MockExec::fail(125, "Domain does not support specified action"));
        // Story 7.21: bootout-before-bootstrap on content drift.
        mock.push_reply(MockExec::fail(3, "Boot-out failed: 3: No such process"));
        mock.push_reply(MockExec::ok("")); // user-domain bootstrap

        let outcome = enable(&mock, tmp.path()).unwrap();
        assert!(matches!(outcome, EnableOutcome::Registered { .. }));
        assert!(!original_plist.exists(), "plist should still be backed up despite bootout 125");
    }

    /// Story 7.16 review-finding regression: bootout exit-125 is
    /// tolerated ONLY when stderr identifies the gui-domain-absent
    /// case. A 125 with a different message (e.g., a permission
    /// failure that happens to share the code) must surface as
    /// `service_manager_failed`, not be silently swallowed.
    #[test]
    fn migration_does_not_tolerate_unrelated_125_failures() {
        let tmp = tempfile::TempDir::new().unwrap();
        let daemon = current_daemon_path().unwrap();
        write_brew_plist_fixture(tmp.path(), "homebrew.mxcl.agentsso", &daemon);

        let mock = MockExec::default();
        mock.push_reply(MockExec::ok(r#"[{"name":"agentsso","status":"started"}]"#));
        mock.push_reply(MockExec::ok("")); // brew stop
        // 125 with stderr that does NOT match the gui-domain-absent
        // signature — must surface as an error rather than be tolerated.
        mock.push_reply(MockExec::fail(125, "Operation not permitted"));

        let result = enable(&mock, tmp.path());
        assert!(
            matches!(result, Err(AutostartError::ServiceManagerFailed { .. })),
            "expected ServiceManagerFailed for 125 with non-gui-domain stderr, got {result:?}"
        );
    }

    /// Story 7.16 review-finding regression: real brew plists embed
    /// the stable `opt_bin` symlink path (e.g.,
    /// `/opt/homebrew/bin/agentsso`), while [`current_daemon_path`]
    /// resolves through `current_exe()` and returns the canonicalized
    /// Cellar target. A naive `==` would refuse legitimate migrations
    /// on every brew upgrade. [`same_binary`] canonicalizes both
    /// sides; this test pins that behavior by setting up an actual
    /// symlink and pointing the brew plist at it.
    #[test]
    fn migration_accepts_symlinked_program_args_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Real binary (stand in for the Cellar-resolved daemon path).
        let real_bin = tmp.path().join("Cellar/agentsso/0.3.0/bin/agentsso");
        std::fs::create_dir_all(real_bin.parent().unwrap()).unwrap();
        std::fs::write(&real_bin, b"#!/bin/sh\nexit 0\n").unwrap();
        // Symlink mimicking brew's opt_bin layout.
        let opt_bin_dir = tmp.path().join("opt/homebrew/bin");
        std::fs::create_dir_all(&opt_bin_dir).unwrap();
        let symlink_path = opt_bin_dir.join("agentsso");
        std::os::unix::fs::symlink(&real_bin, &symlink_path).unwrap();

        // Brew plist embeds the symlink path. `expected_binary`
        // (what current_daemon_path would return) is the real Cellar
        // target — distinct PathBuf, but canonicalize-equal.
        let inspection = BrewPlistInspection {
            file_path: tmp.path().join("Library/LaunchAgents/homebrew.mxcl.agentsso.plist"),
            label: "homebrew.mxcl.agentsso".to_owned(),
            program_args_first: symlink_path.clone(),
        };

        // Sanity-check the test setup: byte-exact comparison would refuse.
        assert_ne!(symlink_path, real_bin, "test fixture invalid: paths happen to be byte-equal");

        // Decision should be Migrate, not Refuse.
        let decision = decide_brew_migration(true, Some(&inspection), &real_bin);
        assert!(
            matches!(decision, BrewMigrationDecision::Migrate { .. }),
            "expected Migrate for canonicalize-equal paths, got {decision:?}"
        );
    }

    /// Story 7.16 Task 2: plist on disk has the brew label but its
    /// `<ProgramArguments>[0]` does NOT match our daemon binary —
    /// likely a stale or hand-rolled config. Migration must REFUSE
    /// with `BrewMigrationRefused` and leave the plist file untouched
    /// so the operator can investigate.
    #[test]
    fn migration_refuses_when_plist_program_args_unrecognized() {
        let tmp = tempfile::TempDir::new().unwrap();
        let original_plist = write_brew_plist_fixture(
            tmp.path(),
            "homebrew.mxcl.agentsso",
            // NOT the current_daemon_path() — simulates a hand-rolled
            // plist pointing at a different binary.
            Path::new("/usr/bin/false"),
        );
        let plist_bytes_before = std::fs::read(&original_plist).unwrap();

        let mock = MockExec::default();
        // brew probe (doesn't matter — refusal happens regardless)
        mock.push_reply(MockExec::ok("[]"));

        let result = enable(&mock, tmp.path());
        assert!(matches!(result, Err(AutostartError::BrewMigrationRefused { .. })));

        // CRITICAL: plist file must be UNTOUCHED. Hand-rolled config preserved.
        assert!(original_plist.exists(), "refused migration must NOT touch the plist file");
        let plist_bytes_after = std::fs::read(&original_plist).unwrap();
        assert_eq!(plist_bytes_after, plist_bytes_before, "plist contents must be byte-identical");

        // No launchctl calls should have been made.
        let calls = mock.calls.borrow();
        let launchctl_calls: Vec<_> = calls.iter().filter(|c| c.0 == "launchctl").collect();
        assert!(
            launchctl_calls.is_empty(),
            "refused migration must NOT call launchctl, got {launchctl_calls:?}"
        );
    }

    /// Story 7.16 Task 2: plist on disk has a different `<Label>` value
    /// (e.g., operator copied the homebrew namespace for a different
    /// service). Same refusal semantics as the bad-args case.
    #[test]
    fn migration_refuses_when_plist_label_mismatched() {
        let tmp = tempfile::TempDir::new().unwrap();
        let daemon = current_daemon_path().unwrap();
        let original_plist = write_brew_plist_fixture(
            tmp.path(),
            // NOT "homebrew.mxcl.agentsso" — defensive against a copy-paste.
            "homebrew.mxcl.somethingelse",
            &daemon,
        );
        let plist_bytes_before = std::fs::read(&original_plist).unwrap();

        let mock = MockExec::default();
        mock.push_reply(MockExec::ok("[]"));

        let result = enable(&mock, tmp.path());
        assert!(matches!(result, Err(AutostartError::BrewMigrationRefused { .. })));

        // Plist preserved.
        assert!(original_plist.exists());
        assert_eq!(std::fs::read(&original_plist).unwrap(), plist_bytes_before);
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
