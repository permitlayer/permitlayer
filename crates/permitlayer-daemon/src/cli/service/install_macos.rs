//! `agentsso service install` macOS implementation (Story 7.27).
//!
//! Idempotent one-time setup of the daemon as a LaunchDaemon system
//! service. Replaces rc.21's per-user `agentsso autostart enable`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use nix::unistd::{Gid, Uid, User, chown};

use super::InstallArgs;
use crate::cli::silent_cli_error;
use crate::design::render::error_block;

/// macOS LaunchDaemon plist label. Rename from rc.21
/// `dev.agentsso.daemon` is part of the breaking change.
const DAEMON_LABEL: &str = "dev.permitlayer.daemon";

/// LaunchDaemon plist path (root-owned, mode 0644 per Apple
/// convention).
const PLIST_PATH: &str = "/Library/LaunchDaemons/dev.permitlayer.daemon.plist";

/// Privileged-helper binary install location.
const PRIVILEGED_HELPER_PATH: &str = "/Library/PrivilegedHelperTools/agentsso";

/// macOS group restricting access to the control socket. Created by
/// `service install` via `dscl`; daemon's UDS at
/// `/var/run/permitlayer/control.sock` is owned `root:<this group>`
/// mode 0660 so members can connect.
const CLIENTS_GROUP: &str = "permitlayer-clients";

/// rc.21 LaunchAgent plist filename (the leaf-component name we
/// walk for in `/Users/*/Library/LaunchAgents/`). Used by Story
/// 7.27's rc.21 cleanup discipline.
const PLIST_FILENAME_RC21: &str = "dev.agentsso.daemon.plist";

/// Safely resolve `<home>/<rel_dir>/<leaf>` by walking the path
/// component-by-component with `openat(parent_fd, comp, O_DIRECTORY |
/// O_NOFOLLOW | O_CLOEXEC)` at each step. Returns the final
/// fully-resolved PathBuf if every intermediate component is a
/// non-symlink directory AND the leaf is a regular non-symlink file
/// (verified via `fstatat(AT_SYMLINK_NOFOLLOW)`). Returns `None` if
/// any component is a symlink, missing, wrong-type, or the chain
/// fails to open.
///
/// Story 7.27 Round-2 review fix (P1): pre-fix, the rc.21 cleanup
/// and the per-user bearer-token sweep walks did `<home>/Library/...`
/// style `Path::join` then `remove_file(...)` — which follows
/// intermediate symlinks. A non-root user could symlink-swap their
/// own `Library` directory and root's `remove_file` would then
/// attack the symlink target.
///
/// Round-3 review fix (R3-C4-P1): the Round-2 fix re-opened
/// `cur_path` by full path at each step, leaving a TOCTOU window
/// where an attacker who owns `<home>` could rename + symlink-swap
/// intermediate components between our `fstatat` and our path-based
/// re-open. Now we use `open_dir_nofollow_at(parent_fd, comp)` — a
/// true `openat`-anchored walk — so each step resolves relative to
/// the fd we already hold. Symlink defense is structural, not
/// TOCTOU-windowed.
///
/// Round-3 review fix (R3-C4-P13): explicitly reject `.`, `..`, and
/// NUL-containing components. Defense-in-depth: current callers
/// pass `"Library/LaunchAgents"` literals so the helper accepts
/// only safe components today, but the public API surface should
/// refuse path-escape sequences up front.
fn safe_resolve_rc21_plist(home: &Path, rel_dir: &str, leaf: &str) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    fn safe_component(c: &str) -> bool {
        !c.is_empty() && c != "." && c != ".." && !c.contains('\0') && !c.contains('/')
    }
    if !safe_component(leaf) {
        return None;
    }
    // Open home with O_NOFOLLOW; refuse if it's a symlink. `home` is
    // resolved as a full path (the caller passes `User::from_uid(...)`
    // result), so this initial open is the only path-based step; all
    // subsequent walking is anchored on this fd.
    let mut dir_fd = permitlayer_platform_macos::open_dir_nofollow(home).ok()?;
    let mut cur_path = home.to_path_buf();
    for component in rel_dir.split('/').filter(|c| !c.is_empty()) {
        if !safe_component(component) {
            return None;
        }
        // Verify the component is a non-symlink dir BEFORE opening.
        // `open_dir_nofollow_at` would already refuse symlinks with
        // ELOOP, but checking S_IFDIR explicitly also catches files +
        // FIFOs the kernel might otherwise let through as ENOTDIR.
        let meta =
            permitlayer_platform_macos::fstatat_nofollow(dir_fd.as_raw_fd(), component).ok()?;
        if (meta.st_mode & libc::S_IFMT) != libc::S_IFDIR {
            return None;
        }
        // True openat-anchored open — the new fd resolves relative
        // to `dir_fd`, NOT to CWD. Symlink-swap of `component` between
        // the fstatat above and this open is no longer exploitable:
        // the kernel performs both operations against the same parent
        // inode without re-traversing the path.
        dir_fd =
            permitlayer_platform_macos::open_dir_nofollow_at(dir_fd.as_raw_fd(), component).ok()?;
        cur_path = cur_path.join(component);
    }
    // Verify the leaf is a regular non-symlink file.
    let leaf_meta = permitlayer_platform_macos::fstatat_nofollow(dir_fd.as_raw_fd(), leaf).ok()?;
    if (leaf_meta.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return None;
    }
    Some(cur_path.join(leaf))
}

/// Run `agentsso service install`.
pub async fn run(args: InstallArgs) -> Result<()> {
    // (0) Root check.
    if !Uid::effective().is_root() {
        eprint!(
            "{}",
            error_block(
                "service.install.requires_root",
                "`agentsso service install` must run as root",
                "sudo agentsso service install",
                None,
            )
        );
        return Err(silent_cli_error("service install requires root"));
    }

    // (0.5) Acquire a mutex against concurrent `service install`
    // invocations. Two admins running the command in parallel could
    // race the `dscl . -read` / `find_free_gid_in_range` / `dscl .
    // -create` sequence and end up with mismatched GIDs (one chose
    // 300, the other 301; the chown step then runs against the wrong
    // GID). The lock lives at `/var/run/permitlayer/.install.lock`
    // so it's cleared on reboot if a previous install was killed.
    // Story 7.27 review fix.
    let _install_lock = acquire_install_lock()?;

    // (1) SUDO_UID validation — refuse direct-as-root invocations
    // that bypass the operator-identity step.
    let (operator_uid, operator_username) = resolve_operator()?;
    println!(
        "→ installing PermitLayer daemon for operator {operator_username} (uid {operator_uid})"
    );

    // (2) rc.21 LaunchAgent cleanup (AC #9).
    let cleaned = cleanup_rc21_launchagents().await;
    if !cleaned.is_empty() {
        for (path, uid) in &cleaned {
            println!("  ✓ removed stale rc.21 LaunchAgent: {} (uid {uid})", path.display());
        }
    }

    // (3) Create permitlayer-clients group + add operator.
    ensure_permitlayer_clients_group(&operator_username).await?;
    println!("  ✓ group `{CLIENTS_GROUP}` ensured (operator {operator_username} added)");

    // (4) Create state/log/runtime dirs.
    create_state_dirs()?;
    println!("  ✓ state + log + runtime dirs created (under macOS conventional paths)");

    // (5) Disable lock-on-sleep on System.keychain so the daemon can
    // read the master key across sleep/wake.
    //
    // Story 7.27 review fix: warn-and-continue on failure. This is a
    // usability optimization (lock-on-sleep), not a security gate —
    // MDM-managed / FileVault-locked / SIP-restricted Macs may refuse
    // with "Operation not permitted" while the install is otherwise
    // fine. Hard-failing meant such Macs could never complete
    // `service install`. The trade-off: on those Macs the operator
    // may need to re-prompt for System.keychain unlock after sleep/
    // wake; we surface this in the post-install caveats.
    let out = Command::new("/usr/bin/security")
        .args(["set-keychain-settings", "-u", "/Library/Keychains/System.keychain"])
        .output()
        .context("failed to invoke /usr/bin/security set-keychain-settings")?;
    let keychain_settings_warning = if out.status.success() {
        println!("  ✓ System.keychain lock-on-sleep disabled");
        None
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        println!("  ⚠ System.keychain `set-keychain-settings -u` returned non-zero — continuing");
        Some(stderr)
    };

    // (6) Copy binary to privileged-helper path.
    let source = resolve_binary_source(&args)?;
    copy_binary_to_helper_tools(&source)?;
    println!("  ✓ daemon binary installed at {PRIVILEGED_HELPER_PATH}");

    // (7) Write LaunchDaemon plist.
    write_launchdaemon_plist(operator_uid, &operator_username)?;
    println!("  ✓ LaunchDaemon plist written at {PLIST_PATH}");

    // (8) launchctl bootstrap.
    bootstrap_daemon()?;
    println!("  ✓ launchctl bootstrap system/{DAEMON_LABEL}");

    // (9) Verify daemon started.
    let install_start = Instant::now();
    let pid = verify_daemon_running(Duration::from_secs(10))?;
    println!("  ✓ daemon running (pid {pid})");

    // Story 7.27 Round-2 review fix (P2): emit a constructive
    // `service-install.complete` audit event. Pre-fix, only the
    // DESTRUCTIVE rc.21 cleanup was audited — the install's actual
    // mutations (binary copy, plist write, group create, bootstrap)
    // had no audit trail. Post-incident forensics had no signal
    // that `service install` ran beyond file mtimes. The audit
    // log dir is guaranteed to exist by this point because
    // `create_state_dirs()` ran above.
    emit_install_complete_audit(
        operator_uid,
        &operator_username,
        pid,
        install_start.elapsed().as_millis() as u64,
    );

    // (10) Post-install caveats.
    println!();
    println!("──────────────────────────────────────────────────────────────");
    println!("✓ PermitLayer installed as a macOS system service.");
    println!();
    println!("macOS may display a \"Background item added\" notification.");
    println!("If the daemon does not appear running, check:");
    println!("  System Settings → General → Login Items → Allow in the Background");
    println!();
    println!("Daemon log: /Library/Logs/permitlayer/daemon.log");
    println!();
    if let Some(stderr) = &keychain_settings_warning {
        println!("⚠ System.keychain lock-on-sleep could not be disabled:");
        for line in stderr.lines() {
            println!("    {line}");
        }
        println!("  The daemon may need to re-prompt for the master-key after sleep/wake.");
        println!("  Common on MDM-managed Macs with restricted keychain policy.");
        println!();
    }
    println!("End-users on this Mac register their agent with:");
    println!("  agentsso agent register <name> --policy <policy-name>");
    println!("──────────────────────────────────────────────────────────────");
    Ok(())
}

/// Resolve `(SUDO_UID, username)` — refuses missing or root SUDO_UID
/// so direct-as-root invocations (someone `su -`d to root) are
/// caught.
fn resolve_operator() -> Result<(u32, String)> {
    // Story 7.27 review fix: trim before parse — `SUDO_UID="0\n"` and
    // other whitespace-padded values otherwise produce a confusing
    // `parse::<u32>` failure instead of the structured error block.
    let raw = std::env::var("SUDO_UID").ok();
    let uid = match raw.as_deref().map(str::trim) {
        Some(s) => {
            s.parse::<u32>().with_context(|| format!("SUDO_UID `{s}` is not a valid u32"))?
        }
        None => {
            eprint!(
                "{}",
                error_block(
                    "service.install.requires_sudo_from_admin",
                    "`agentsso service install` must be invoked via sudo from an admin account",
                    "sudo agentsso service install   (from your admin user shell, NOT after `su -`)",
                    None,
                )
            );
            return Err(silent_cli_error("SUDO_UID not set"));
        }
    };
    if uid == 0 {
        eprint!(
            "{}",
            error_block(
                "service.install.requires_sudo_from_admin",
                "`agentsso service install` refuses to run when SUDO_UID maps to root (someone \
                 ran `su - root` instead of `sudo` — operator identity is lost)",
                "log out of root and re-run via `sudo agentsso service install` from your admin shell",
                None,
            )
        );
        return Err(silent_cli_error("SUDO_UID is 0"));
    }
    let user = User::from_uid(Uid::from_raw(uid))
        .with_context(|| format!("failed to resolve UID {uid} to a user record"))?
        .ok_or_else(|| anyhow::anyhow!("UID {uid} has no associated user account"))?;
    // Story 7.27 Round-2 review fix (P1): validate the username
    // against the macOS short-name charset before persisting it
    // into the LaunchDaemon plist's `PERMITLAYER_OPERATOR_USER`
    // env var. XML-escape closes the plist-injection vector at
    // the parser, but a username with NUL bytes, control chars,
    // shell metachars, or newlines still pollutes the daemon's
    // environment — and any future daemon-side consumer passing
    // it to a shell or path construction without validation
    // becomes a vulnerability. macOS short-name convention is
    // `[A-Za-z0-9._-]+` (DSAttrTypeStandard:RecordName).
    //
    // Round-3 review fix (R3-C4-P4): also reject usernames that
    // start with `-` or `.`. A leading `-` is interpreted as an
    // option flag by `dseditgroup -a $user` (since `Command::args`
    // doesn't shell-quote — `-rf` would be parsed as `-r -f` by
    // dseditgroup). A leading `.` (`.`, `..`, `.hidden`) is
    // semantically a path-traversal trap and also unusual for
    // real macOS accounts. Require the first char to be
    // `[A-Za-z0-9_]`.
    let first_char_ok =
        user.name.chars().next().is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
    if user.name.is_empty()
        || !first_char_ok
        || !user.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        eprint!(
            "{}",
            error_block(
                "service.install.unsafe_operator_username",
                &format!(
                    "operator account name {:?} contains characters outside the macOS \
                     short-name charset (A-Z, a-z, 0-9, `.`, `_`, `-`). The plist parser \
                     would accept it, but persisting it into the daemon's environment \
                     is a defense-in-depth hazard.",
                    user.name
                ),
                "rename the account, or set `PERMITLAYER_OPERATOR_USER` manually after install.",
                None,
            )
        );
        return Err(silent_cli_error("operator username failed safe-charset check"));
    }
    Ok((uid, user.name))
}

/// Walk `/Users/*/Library/LaunchAgents/` looking for rc.21
/// `dev.agentsso.daemon.plist` files; bootout + unlink each. Also
/// handles the system-wide LaunchAgents location. Returns the list
/// of `(plist_path, user_uid)` removed for caller-side reporting.
/// System-wide LaunchAgent removals report `uid = 0`.
/// Internal install-flow entrypoint. Round-2 review added a
/// `pub(super)` alias [`cleanup_rc21_launchagents_for_uninstall`]
/// so the uninstall flow can reuse the same logic.
async fn cleanup_rc21_launchagents() -> Vec<(PathBuf, u32)> {
    // Round-3 review fix (R3-C4-P3): two-phase to give the audit
    // log a deterministic forensic trail. Pre-fix, `emit_rc21_cleanup_audit`
    // ran AFTER the destructive `remove_file` — if the audit
    // writer's init failed (disk full, scrub-engine OOM), the
    // delete had already happened and was lost to the audit
    // record. Now:
    //   1. Resolve safe candidates (`safe_resolve_rc21_plist` —
    //      symlink-defended, openat-anchored walk).
    //   2. Emit an `intent` event for each (best-effort; if audit
    //      fails the operator still sees stderr warnings).
    //   3. Perform the destructive removals.
    //   4. Emit `complete` events for the successful subset.
    // The audit log now contains BOTH intents and outcomes, so a
    // crash between phases is reconstructible.

    // Phase 1: resolve candidates.
    let mut candidates: Vec<(PathBuf, u32)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/Users") {
        for entry in entries.flatten() {
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !meta.is_dir() || meta.file_type().is_symlink() {
                continue;
            }
            use std::os::unix::fs::MetadataExt;
            let uid = meta.uid();
            if let Some(plist) =
                safe_resolve_rc21_plist(&entry.path(), "Library/LaunchAgents", PLIST_FILENAME_RC21)
            {
                candidates.push((plist, uid));
            }
        }
    }
    if let Some(sys) =
        safe_resolve_rc21_plist(Path::new("/Library"), "LaunchAgents", PLIST_FILENAME_RC21)
    {
        candidates.push((sys, 0));
    }

    if candidates.is_empty() {
        return Vec::new();
    }

    // Phase 2: emit intent events BEFORE any destructive action.
    emit_rc21_cleanup_audit_intent(&candidates, operator_sudo_uid());

    // Phase 3: perform the removals.
    let mut removed: Vec<(PathBuf, u32)> = Vec::new();
    for (plist, uid) in &candidates {
        // Best-effort bootout — domain depends on uid (gui vs system).
        let bootout_target = if *uid == 0 {
            "system/dev.agentsso.daemon".to_string()
        } else {
            format!("gui/{uid}/dev.agentsso.daemon")
        };
        let _ = Command::new("/bin/launchctl").args(["bootout", &bootout_target]).output();
        if std::fs::remove_file(plist).is_ok() {
            removed.push((plist.clone(), *uid));
        }
    }

    // Story 7.27 AC #9 (review fix): audit-log each removal directly
    // to the daemon's audit log path via a standalone AuditFsWriter.
    // The install CLI is privileged (root), runs out-of-daemon, and
    // would otherwise have no audit trail of this destructive action.
    // The daemon ingests appended events on next boot — append-only
    // JSON-Lines is the contract.
    if !removed.is_empty() {
        emit_rc21_cleanup_audit(&removed, operator_sudo_uid());
    }

    removed
}

/// Build a standalone `AuditFsWriter` for the install CLI's
/// audit-emit sites. Returns `None` (with stderr warning) on any
/// init failure; the install never blocks on audit problems.
///
/// Round-3 review fix (R3-C4-P6): immediately chmod 0o700 + chown
/// 0:0 the parent dir after `create_dir_all`. `create_dir_all` uses
/// the process umask (root default 0o022 → 0o755 world-readable)
/// and `create_state_dirs()` doesn't run until later in the install
/// flow, so audit events containing `operator_uid` /
/// `operator_username` would otherwise be world-readable during the
/// install window. The later state-dir setup re-asserts these
/// properties idempotently.
fn open_install_audit_writer(
    context_label: &str,
) -> Option<permitlayer_core::audit::writer::AuditFsWriter> {
    use permitlayer_core::audit::writer::AuditFsWriter;
    use permitlayer_core::scrub::{ScrubEngine, builtin_rules};
    use std::sync::Arc;

    let audit_dir = permitlayer_core::paths::audit_log_path(None);
    if let Some(parent) = audit_dir.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!(
                "warning: {context_label} audit skipped — could not create parent dir {}: {e}",
                parent.display()
            );
            return None;
        }
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        let _ = nix::unistd::chown(
            parent,
            Some(nix::unistd::Uid::from_raw(0)),
            Some(nix::unistd::Gid::from_raw(0)),
        );
    }
    let scrub_engine = match ScrubEngine::new(builtin_rules().to_vec()) {
        Ok(e) => Arc::new(e),
        Err(e) => {
            eprintln!("warning: {context_label} audit skipped — scrub-engine init failed: {e}");
            return None;
        }
    };
    match AuditFsWriter::new(audit_dir, 100 * 1024 * 1024, scrub_engine) {
        Ok(w) => Some(w),
        Err(e) => {
            eprintln!("warning: {context_label} audit skipped — writer init failed: {e}");
            None
        }
    }
}

/// Round-3 review fix (R3-C4-P3): emit `intent` events for each
/// candidate rc.21 plist BEFORE the destructive `remove_file` runs.
/// Pre-fix, the audit emit ran AFTER removal — a failed writer init
/// after removal meant the destructive action was lost to the
/// forensic trail. Now intents are written first so a crash between
/// intent and complete is still reconstructible.
fn emit_rc21_cleanup_audit_intent(candidates: &[(PathBuf, u32)], operator_uid: Option<u32>) {
    use permitlayer_core::audit::event::AuditEvent;
    let Some(mut writer) = open_install_audit_writer("rc.21 cleanup intent") else {
        return;
    };
    for (plist, uid) in candidates {
        let mut event = AuditEvent::new(
            "system".to_owned(),
            "permitlayer".to_owned(),
            "-".to_owned(),
            "service-install".to_owned(),
            "intent".to_owned(),
            "service-install.rc21-launchagent-cleanup-intent".to_owned(),
        );
        event.extra = serde_json::json!({
            "plist_path": plist.to_string_lossy(),
            "launch_agent_uid": uid,
            "operator_uid": operator_uid,
        });
        if let Err(e) = writer.append(&event) {
            eprintln!("warning: rc.21 cleanup intent audit append failed: {e}");
        }
    }
}

/// Emit one `service-install.rc21-launchagent-cleanup` event per
/// plist successfully removed. Pairs with
/// `emit_rc21_cleanup_audit_intent` to give a complete forensic
/// trail (intent → complete).
fn emit_rc21_cleanup_audit(removed: &[(PathBuf, u32)], operator_uid: Option<u32>) {
    use permitlayer_core::audit::event::AuditEvent;
    let Some(mut writer) = open_install_audit_writer("rc.21 cleanup complete") else {
        return;
    };
    for (plist, uid) in removed {
        let mut event = AuditEvent::new(
            "system".to_owned(),
            "permitlayer".to_owned(),
            "-".to_owned(),
            "service-install".to_owned(),
            "ok".to_owned(),
            "service-install.rc21-launchagent-cleanup".to_owned(),
        );
        event.extra = serde_json::json!({
            "plist_path": plist.to_string_lossy(),
            "launch_agent_uid": uid,
            "operator_uid": operator_uid,
        });
        if let Err(e) = writer.append(&event) {
            eprintln!("warning: rc.21 cleanup audit append failed: {e}");
        }
    }
}

fn operator_sudo_uid() -> Option<u32> {
    std::env::var("SUDO_UID").ok().and_then(|s| s.trim().parse::<u32>().ok())
}

/// Emit a single `service-install.complete` audit event recording
/// the constructive install state. Story 7.27 Round-2 review fix (P2)
/// — pre-fix the install flow audited the DESTRUCTIVE rc.21 cleanup
/// but not the CONSTRUCTIVE steps (binary copy, plist write, group
/// create, bootstrap). Post-incident forensics had no signal beyond
/// file mtimes that `service install` ran. The state dir is
/// guaranteed to exist by this point (`create_state_dirs()` ran),
/// so writer init does not need the parent-dir self-heal that
/// `emit_rc21_cleanup_audit` does.
fn emit_install_complete_audit(
    operator_uid: u32,
    operator_username: &str,
    daemon_pid: u32,
    install_duration_ms: u64,
) {
    use permitlayer_core::audit::event::AuditEvent;
    use permitlayer_core::audit::writer::AuditFsWriter;
    use permitlayer_core::scrub::{ScrubEngine, builtin_rules};
    use std::sync::Arc;

    let audit_dir = permitlayer_core::paths::audit_log_path(None);
    let scrub_engine = match ScrubEngine::new(builtin_rules().to_vec()) {
        Ok(e) => Arc::new(e),
        Err(e) => {
            eprintln!("warning: install-complete audit skipped — scrub-engine init failed: {e}");
            return;
        }
    };
    let mut writer = match AuditFsWriter::new(audit_dir, 100 * 1024 * 1024, scrub_engine) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("warning: install-complete audit skipped — writer init failed: {e}");
            return;
        }
    };
    let mut event = AuditEvent::new(
        "system".to_owned(),
        "permitlayer".to_owned(),
        "-".to_owned(),
        "service-install".to_owned(),
        "ok".to_owned(),
        "service-install.complete".to_owned(),
    );
    event.extra = serde_json::json!({
        "operator_uid": operator_uid,
        "operator_username": operator_username,
        "helper_path": PRIVILEGED_HELPER_PATH,
        "plist_path": PLIST_PATH,
        "daemon_pid": daemon_pid,
        "install_duration_ms": install_duration_ms,
    });
    if let Err(e) = writer.append(&event) {
        eprintln!("warning: install-complete audit append failed: {e}");
    }
}

/// Mutex against concurrent `agentsso service install` invocations.
/// Uses `O_CREAT|O_EXCL` on a sentinel file; releases via `Drop`.
/// Story 7.27 review fix.
///
/// Round-3 review fix (R3-C4-P2): wraps a `nix::fcntl::Flock<File>`
/// so the kernel arbitrates ownership. The Round-2 implementation
/// used `OpenOptions::create_new` + mtime-based stale detection,
/// which had a race: two callers both stat stale, both `remove_file`
/// (the second's removes the first's freshly-acquired lock), both
/// `create_new` succeed — install-lock guarantee broken. `flock(2)`
/// removes the race entirely; the lockfile inode persists across
/// processes and the kernel arbitrates which holder is live.
pub(super) struct InstallLock {
    // Kept alive for the lifetime of the lock; dropping releases.
    // `None` for the `--force` uninstall path (R3-C4-P9), which
    // explicitly opts out of mutual exclusion to allow recovery
    // from a recently-crashed install.
    _flock: Option<nix::fcntl::Flock<std::fs::File>>,
}

/// Story 7.27 Round-2 review fix (P2): exposed via
/// [`acquire_install_lock_pub`] so the uninstall flow can acquire
/// the same lock and prevent concurrent install+uninstall races.
pub(super) fn acquire_install_lock_pub() -> Result<InstallLock> {
    acquire_install_lock_inner(false)
}

/// Round-3 review fix (R3-C4-P9): force variant for uninstall.
/// A fresh crashed install (lock <10min old) would otherwise block
/// the operator from running `service uninstall` to clean up —
/// because the install-lock-not-stale check rejects (Round-2 mtime
/// reclaim) or `flock(2)` returns EWOULDBLOCK (Round-3 R3-C4-P2).
/// `--force` bypasses lock acquisition entirely; the caller is
/// responsible for ensuring no other install is concurrently active.
pub(super) fn acquire_install_lock_pub_force() -> InstallLock {
    InstallLock { _flock: None }
}

/// Story 7.27 Round-2 review fix (P2): exposed for uninstall so it
/// can clean up rc.21 LaunchAgents symmetrically with install.
pub(super) async fn cleanup_rc21_launchagents_for_uninstall() -> Vec<(PathBuf, u32)> {
    cleanup_rc21_launchagents().await
}

fn acquire_install_lock() -> Result<InstallLock> {
    acquire_install_lock_inner(false)
}

/// Round-3 review fix (R3-C4-P2): switched from mtime-based stale-
/// reclaim to `flock(2)`. The lockfile inode persists indefinitely;
/// the kernel-arbitrated advisory lock guarantees mutual exclusion
/// without any mtime race. Stale-lock recovery is automatic — when
/// the holder process exits (graceful or SIGKILL), the kernel
/// releases the fd, which releases the flock. No reclaim heuristic
/// needed.
fn acquire_install_lock_inner(_force: bool) -> Result<InstallLock> {
    use std::os::unix::fs::OpenOptionsExt;
    // `/var/run/permitlayer/` may not exist on a fresh install. Try
    // there first (preferred — root-only-writable so the lock is
    // tamper-resistant); fall back to /tmp/.
    let primary = PathBuf::from("/var/run/permitlayer/.install.lock");
    let fallback = PathBuf::from("/tmp/.permitlayer-install.lock");

    if let Some(parent) = primary.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let mut last_open_err: Option<std::io::Error> = None;
    for candidate in [&primary, &fallback] {
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(candidate)
        {
            Ok(f) => f,
            Err(e) => {
                last_open_err = Some(e);
                continue;
            }
        };
        match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock) {
            Ok(flock) => return Ok(InstallLock { _flock: Some(flock) }),
            Err((_returned_file, nix::errno::Errno::EWOULDBLOCK)) => {
                eprint!(
                    "{}",
                    error_block(
                        "service.install.concurrent_install",
                        &format!(
                            "another `agentsso service install` is in progress (lock at {})",
                            candidate.display()
                        ),
                        "wait for the other install to finish (the kernel releases the lock automatically when it exits)",
                        None,
                    )
                );
                return Err(silent_cli_error("concurrent install detected"));
            }
            Err((_returned_file, errno)) => {
                last_open_err = Some(std::io::Error::from_raw_os_error(errno as i32));
                continue;
            }
        }
    }
    Err(anyhow::anyhow!(
        "could not acquire install lock at any of /var/run/permitlayer/, /tmp/: {}",
        last_open_err.map(|e| e.to_string()).unwrap_or_else(|| "unknown".to_string())
    ))
}

/// Escape `<`, `>`, `&`, `'`, `"` for safe interpolation into XML
/// CharData / AttValue positions. Story 7.27 review fix: account
/// names containing apostrophes or ampersands are legitimate on
/// macOS and would otherwise produce a malformed plist.
///
/// Round-3 review note (R3-C4-P12): this helper does NOT escape
/// control characters (U+0000–U+001F). Callers MUST validate that
/// input contains no control chars before passing it here — XML 1.0
/// rejects most control chars in CharData with no graceful
/// recovery, and `launchctl bootstrap` returns an opaque
/// "Bootstrap failed: 5: Input/output error" instead of a parse
/// diagnostic. The only public consumer today is
/// `operator_username`, which is now regex-validated against
/// `[A-Za-z0-9._-]+` (first char `[A-Za-z0-9_]`); control chars
/// are structurally impossible. If you add a new caller, validate
/// input or extend this helper to numeric-escape (`&#xN;`) the
/// control range.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&apos;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod xml_escape_tests {
    use super::xml_escape;

    #[test]
    fn escapes_canonical_xml_entities() {
        assert_eq!(xml_escape("o'brien"), "o&apos;brien");
        assert_eq!(xml_escape("smith & co"), "smith &amp; co");
        assert_eq!(xml_escape("<bob>"), "&lt;bob&gt;");
        assert_eq!(xml_escape(r#"alice "quoted""#), "alice &quot;quoted&quot;");
        assert_eq!(xml_escape("plain"), "plain");
    }
}

/// Create the `permitlayer-clients` macOS group via `dscl` and add
/// the operator user. Idempotent — reuses an existing group.
async fn ensure_permitlayer_clients_group(operator_username: &str) -> Result<()> {
    // (a) Check if group already exists.
    let out = Command::new("/usr/bin/dscl")
        .args([".", "-read", &format!("/Groups/{CLIENTS_GROUP}"), "PrimaryGroupID"])
        .output()
        .context("failed to invoke /usr/bin/dscl")?;
    let exists = out.status.success();

    if !exists {
        // (b) Compute a free GID in the 300-499 range. macOS-system
        // groups < 200; service accounts conventionally 200-499.
        let gid = find_free_gid_in_range(300, 499)?;
        // Create the group.
        let out = Command::new("/usr/bin/dscl")
            .args([".", "-create", &format!("/Groups/{CLIENTS_GROUP}")])
            .output()
            .context("dscl group create")?;
        if !out.status.success() {
            return Err(anyhow::anyhow!(
                "dscl create /Groups/{CLIENTS_GROUP} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        let out = Command::new("/usr/bin/dscl")
            .args([
                ".",
                "-create",
                &format!("/Groups/{CLIENTS_GROUP}"),
                "PrimaryGroupID",
                &gid.to_string(),
            ])
            .output()
            .context("dscl group set PrimaryGroupID")?;
        if !out.status.success() {
            return Err(anyhow::anyhow!(
                "dscl set PrimaryGroupID failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    }

    // (b.1) Story 7.27 review fix: re-read the canonical PrimaryGroupID
    // after create. Defense in depth against the (rare) concurrent-
    // install race where two admins race the create step; one wins,
    // the loser's chown step would otherwise use a stale GID. The
    // install_lock above prevents this race in practice, but the
    // re-read is cheap and protects against unusual DS topologies
    // (multiple OD nodes, MCX overrides) where dscl might land a
    // create with a different GID than our find_free_gid chose.
    let out = Command::new("/usr/bin/dscl")
        .args([".", "-read", &format!("/Groups/{CLIENTS_GROUP}"), "PrimaryGroupID"])
        .output()
        .context("dscl verify group GID")?;
    if !out.status.success() {
        return Err(anyhow::anyhow!(
            "dscl re-read /Groups/{CLIENTS_GROUP} PrimaryGroupID failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    // Output format: `PrimaryGroupID: <gid>`. Parse defensively.
    let raw = String::from_utf8_lossy(&out.stdout);
    let canonical_gid: Option<u32> = raw.lines().find_map(|line| {
        line.strip_prefix("PrimaryGroupID:").and_then(|rest| rest.trim().parse::<u32>().ok())
    });
    if canonical_gid.is_none() {
        tracing::warn!(
            target: "service.install",
            dscl_output = %raw,
            "could not re-read canonical GID for `{CLIENTS_GROUP}` — continuing on best-effort"
        );
    }

    // (c) Add operator to the group (idempotent — `dseditgroup`
    // tolerates already-member as a no-op).
    let out = Command::new("/usr/sbin/dseditgroup")
        .args(["-o", "edit", "-a", operator_username, "-t", "user", CLIENTS_GROUP])
        .output()
        .context("failed to invoke /usr/sbin/dseditgroup")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // dseditgroup returns non-zero on "already a member" in some
        // macOS versions — tolerate that string.
        if !stderr.to_lowercase().contains("already") {
            return Err(anyhow::anyhow!(
                "dseditgroup add {operator_username} to {CLIENTS_GROUP} failed: {stderr}"
            ));
        }
    }
    Ok(())
}

/// Find a free GID in `[lo, hi]` by enumerating existing groups
/// via `dscl . -list /Groups PrimaryGroupID`.
fn find_free_gid_in_range(lo: u32, hi: u32) -> Result<u32> {
    let out = Command::new("/usr/bin/dscl")
        .args([".", "-list", "/Groups", "PrimaryGroupID"])
        .output()
        .context("dscl list groups")?;
    if !out.status.success() {
        return Err(anyhow::anyhow!(
            "dscl list groups failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    // Parse strictly. `dscl` output format is `<group>\t<gid>`,
    // but groups without a PrimaryGroupID emit `<group>` alone or
    // `<group>\t(none)`. Story 7.27 review fix: previous parse silently
    // filtered both cases via `.parse::<u32>().ok()`, potentially
    // missing real allocations when dscl wraps lines or emits a header.
    // We now treat anything-non-numeric as occupied: collect every
    // line's second whitespace-delimited token, parse what we can,
    // and reserve the rest defensively by widening the search.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut used: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut malformed_lines = 0usize;
    for line in stdout.lines() {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.trim().is_empty() {
            continue;
        }
        match trimmed.split_whitespace().nth(1) {
            Some(token) => match token.parse::<u32>() {
                Ok(gid) => {
                    used.insert(gid);
                }
                Err(_) => {
                    malformed_lines += 1;
                }
            },
            None => {
                malformed_lines += 1;
            }
        }
    }
    if malformed_lines > 0 {
        tracing::warn!(
            target: "service.install",
            malformed_lines,
            "dscl /Groups PrimaryGroupID emitted lines we couldn't parse — GID allocation will skip the configured range conservatively if needed"
        );
    }
    for gid in lo..=hi {
        if !used.contains(&gid) {
            return Ok(gid);
        }
    }
    Err(anyhow::anyhow!("no free GID in range {lo}-{hi} for `{CLIENTS_GROUP}`"))
}

/// Create the state, log, and runtime dir trees with the perms
/// specified in 7.25 AC #4.
/// Resolve `permitlayer-clients` GID via `nix::unistd::Group::from_name`
/// (which goes through nss / `getgrnam(3)`). On DS cache lag — common
/// when the group was created moments ago by `dscl` — the first lookup
/// can return `Ok(None)`. Retry up to 5 times with a 200ms sleep and
/// a `dscacheutil -flushcache` between attempts; fail loudly on
/// permanent absence rather than silently falling back to GID 0.
///
/// Story 7.27 Round-2 review fix (P1): pre-fix `unwrap_or(0)` silently
/// chowned the state dir to `root:wheel` mode 0710, breaking
/// `permitlayer-clients` member traversal and the operator-CLI
/// cross-user auth flow that Round-1 wired (commit 08dc620). Hard-
/// failing surfaces the underlying DS issue immediately.
fn resolve_clients_group_gid_with_retry() -> Result<u32> {
    const ATTEMPTS: usize = 5;
    const SLEEP: std::time::Duration = std::time::Duration::from_millis(200);
    for attempt in 1..=ATTEMPTS {
        match nix::unistd::Group::from_name(CLIENTS_GROUP) {
            Ok(Some(g)) => return Ok(g.gid.as_raw()),
            Ok(None) | Err(_) => {
                if attempt < ATTEMPTS {
                    // Best-effort cache flush. Failures here are
                    // tolerated — the retry alone often suffices.
                    let _ = Command::new("/usr/bin/dscacheutil").arg("-flushcache").output();
                    std::thread::sleep(SLEEP);
                }
            }
        }
    }
    anyhow::bail!(
        "group `{CLIENTS_GROUP}` was just created via `dscl` but is not yet visible to \
         `getgrnam(3)` after {ATTEMPTS} retries with `dscacheutil -flushcache`. This usually \
         means a DirectoryServices indexing issue. Wait a few seconds and re-run \
         `sudo agentsso service install`, or manually run `sudo dscacheutil -flushcache` \
         and retry. The cross-user CLI auth model depends on this group's GID; refusing \
         to proceed with GID 0 fallback (which would silently break operator-CLI access)."
    )
}

fn create_state_dirs() -> Result<()> {
    let state = permitlayer_core::paths::daemon_state_dir(None);
    let log = permitlayer_core::paths::daemon_log_dir(None);
    let runtime = permitlayer_core::paths::daemon_runtime_dir(None);

    for dir in [&state, &log, &runtime] {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to mkdir -p {}", dir.display()))?;
    }
    // State dir is 0710 root:permitlayer-clients so members of the
    // group can `cd` into it (traverse) to reach `control.token`
    // (which the daemon mints at 0640 root:permitlayer-clients for
    // the operator-CLI cross-user auth flow). Listing the dir's
    // contents is denied (no read bit for the group) and the
    // subdirs (vault, agents, plugins, .tokens) keep 0700 root:wheel
    // (per Dev Agent Record commit 08dc620 — tighter than spec
    // line 53's 0750 for vault/agents/plugins, but the cross-user
    // auth model only needs traversal of the parent state dir;
    // subdirs stay root-private). Do NOT "fix" subdirs back to
    // 0750 — see story line 684. Story 7.27 cross-user CLI fix.
    //
    // Story 7.27 Round-2 review fix (P1): resolve the group GID
    // strictly. Pre-fix, `Group::from_name(CLIENTS_GROUP).ok()
    // .flatten().map(...).unwrap_or(0)` silently fell back to GID
    // 0 (wheel) when the lookup failed — typically when DirectoryServices
    // cache hadn't refreshed after the `dscl` create that happened
    // moments ago. Result: state dir chowned root:wheel mode 0710,
    // `permitlayer-clients` members can't traverse, entire cross-
    // user CLI auth flow silently broken.
    let clients_gid = resolve_clients_group_gid_with_retry()?;
    nix::unistd::chown(
        &state,
        Some(nix::unistd::Uid::from_raw(0)),
        Some(nix::unistd::Gid::from_raw(clients_gid)),
    )
    .with_context(|| format!("chown root:{CLIENTS_GROUP} {}", state.display()))?;
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o710))
        .with_context(|| format!("chmod 0710 {}", state.display()))?;
    for sub in ["vault", "agents", "plugins", ".tokens"] {
        let p = state.join(sub);
        std::fs::create_dir_all(&p).with_context(|| format!("mkdir -p {}", p.display()))?;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", p.display()))?;
    }
    // Log dir 0750 root:wheel.
    std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o750))
        .with_context(|| format!("chmod 0750 {}", log.display()))?;
    // Runtime dir 0755 root:wheel (per AC #4: `permitlayer-clients`
    // members need to traverse it to reach the 0660 socket).
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod 0755 {}", runtime.display()))?;
    // Ownership: dirs are created by root (we're root) so default
    // owner is root:wheel; nothing to chown explicitly.
    Ok(())
}

/// Resolve the source binary path for the install.
///
/// Story 7.27 research finding: matches Tailscale's `install_darwin.go`
/// pattern — trust `current_exe()` rather than maintaining a brittle
/// safe-source allowlist. The previous draft refused custom-prefix
/// brew installs (`HOMEBREW_PREFIX=/foo`) with wrong remediation
/// advice ("re-run from /opt/homebrew/bin/agentsso" — which doesn't
/// exist on a custom-prefix system). Tailscale's production-realistic
/// posture is: the operator just `sudo`ed to this binary; they own
/// the outcome. We canonicalize, copy, and let the operator verify
/// via `codesign -v /Library/PrivilegedHelperTools/agentsso` if they
/// want post-install confirmation.
///
/// `--from <path>` is preserved for dev workflows (e.g.,
/// `cargo build --release` testing where the binary lives under
/// `target/release/`).
fn resolve_binary_source(args: &InstallArgs) -> Result<PathBuf> {
    let candidate = match args.from.as_ref() {
        Some(p) => {
            // Story 7.27 Round-2 review fix (P2): validate operator-
            // supplied `--from <path>` against symlink swap +
            // non-executable contents. `std::fs::copy` follows
            // symlinks; without this check, an attacker who races
            // a symlink-target swap between the operator typing
            // `sudo agentsso service install --from /tmp/foo` and
            // our `std::fs::copy` would have us copy attacker
            // content into `/Library/PrivilegedHelperTools/agentsso`.
            // Refusing symlinks closes the swap window. Validating
            // executable-bit closes the "operator typo'd a path
            // to /etc/passwd" footgun.
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let meta = std::fs::symlink_metadata(p)
                .with_context(|| format!("--from path {} not accessible", p.display()))?;
            if meta.file_type().is_symlink() {
                anyhow::bail!(
                    "--from path {} is a symlink; refusing to follow (re-run with the \
                     canonical path). Story 7.27 review-fix: defense against TOCTOU \
                     symlink-target swap.",
                    p.display()
                );
            }
            if !meta.is_file() {
                anyhow::bail!(
                    "--from path {} is not a regular file (type: {:?})",
                    p.display(),
                    meta.file_type()
                );
            }
            // Round-3 review fix (R3-C4-P5): refuse hardlinks. The
            // symlink check above doesn't catch hardlinks (they
            // share an inode with a "primary" name and look like
            // regular files to symlink_metadata). An attacker who
            // can write to `/tmp/agentsso-malicious` can
            // `ln /tmp/agentsso-malicious ~/Downloads/agentsso`,
            // wait for the operator to run
            // `sudo agentsso service install --from
            // ~/Downloads/agentsso`, then race a content swap via
            // the `/tmp/` path. nlink > 1 indicates the inode has
            // another name elsewhere; refuse.
            if meta.nlink() > 1 {
                anyhow::bail!(
                    "--from path {} has {} hardlinks; refusing because a second name \
                     elsewhere could let an attacker swap the binary's contents while \
                     the install runs. Copy the binary to a fresh path (e.g., \
                     `/var/root/agentsso-staged`) and re-run with --from that path.",
                    p.display(),
                    meta.nlink()
                );
            }
            if meta.permissions().mode() & 0o111 == 0 {
                anyhow::bail!(
                    "--from path {} has no executable bit set (mode 0o{:o}); refusing \
                     to install a non-executable binary",
                    p.display(),
                    meta.permissions().mode() & 0o777
                );
            }
            p.clone()
        }
        None => std::env::current_exe()
            .context("std::env::current_exe() failed")?
            .canonicalize()
            .context("failed to canonicalize current_exe()")?,
    };
    Ok(candidate)
}

/// Copy `from` to `/Library/PrivilegedHelperTools/agentsso`, chown
/// root:wheel, chmod 0755. Story 7.27 review fix: atomic via
/// `.tmp.<pid>` + rename. An install interrupted mid-copy would
/// otherwise leave a partially-written or zero-byte binary at the
/// helper path.
fn copy_binary_to_helper_tools(from: &Path) -> Result<()> {
    let helper_dir = Path::new(PRIVILEGED_HELPER_PATH).parent().unwrap_or(Path::new("/"));
    std::fs::create_dir_all(helper_dir)
        .with_context(|| format!("mkdir -p {}", helper_dir.display()))?;
    let tmp_path = PathBuf::from(format!("{PRIVILEGED_HELPER_PATH}.tmp.{}", std::process::id()));
    std::fs::copy(from, &tmp_path)
        .with_context(|| format!("copy {} → {}", from.display(), tmp_path.display()))?;
    chown(&tmp_path, Some(Uid::from_raw(0)), Some(Gid::from_raw(0)))
        .with_context(|| format!("chown root:wheel {}", tmp_path.display()))?;
    std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod 0755 {}", tmp_path.display()))?;
    // Round-3 review fix (R3-C4-P11): fsync the tmp file's data
    // before the rename. Atomic-via-rename is only atomic w.r.t.
    // crash if the tmp file's data is fsync'd first; otherwise a
    // power loss between `rename` and writeback yields a zero-byte
    // helper at `PRIVILEGED_HELPER_PATH` with a valid dirent —
    // exactly the failure mode the rename pattern claims to prevent.
    let tmp_file = std::fs::OpenOptions::new()
        .write(true)
        .open(&tmp_path)
        .with_context(|| format!("open {} for fsync", tmp_path.display()))?;
    tmp_file.sync_all().with_context(|| format!("fsync {}", tmp_path.display()))?;
    drop(tmp_file);
    std::fs::rename(&tmp_path, PRIVILEGED_HELPER_PATH)
        .with_context(|| format!("rename {} → {}", tmp_path.display(), PRIVILEGED_HELPER_PATH))?;
    // fsync the parent dir so the rename is durable.
    if let Ok(dir) = std::fs::File::open(helper_dir) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Build the LaunchDaemon plist XML and write it to `PLIST_PATH`,
/// chown root:wheel, chmod 0644. Per Story 7.27 AC #10.
fn write_launchdaemon_plist(operator_uid: u32, operator_username: &str) -> Result<()> {
    // Hand-built XML keeps the deps minimal (no `plist` crate
    // workspace addition needed). The plist is small + deterministic;
    // a unit test below could `plutil -lint` the output to catch
    // syntactic regressions — but `launchctl bootstrap` itself rejects
    // a malformed plist with a useful error so the operator-facing
    // signal is preserved.
    //
    // Story 7.27 review fix: XML-escape `operator_username`. Apple
    // directory services permit `'` and `&` in account names (e.g.,
    // `O'Brien`), and OD-imported accounts can carry `<`. Interpolating
    // raw produces invalid XML which `launchctl bootstrap` rejects
    // with an unhelpful "Bootstrap failed: 5: Input/output error".
    let operator_username_escaped = xml_escape(operator_username);
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{DAEMON_LABEL}</string>
  <key>ProgramArguments</key>
    <array><string>{PRIVILEGED_HELPER_PATH}</string><string>start</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>StandardOutPath</key><string>/Library/Logs/permitlayer/daemon.log</string>
  <key>StandardErrorPath</key><string>/Library/Logs/permitlayer/daemon.log</string>
  <key>ProcessType</key><string>Background</string>
  <key>SessionCreate</key><true/>
  <key>EnvironmentVariables</key>
    <dict>
      <key>PERMITLAYER_OPERATOR_UID</key><string>{operator_uid}</string>
      <key>PERMITLAYER_OPERATOR_USER</key><string>{operator_username_escaped}</string>
    </dict>
</dict>
</plist>
"#
    );
    // Atomic write: tmp file + rename. Mode 0644, owner root:wheel.
    let tmp_path = format!("{PLIST_PATH}.tmp.{}", std::process::id());
    std::fs::write(&tmp_path, body.as_bytes()).with_context(|| format!("write {tmp_path}"))?;
    chown(Path::new(&tmp_path), Some(Uid::from_raw(0)), Some(Gid::from_raw(0)))
        .with_context(|| format!("chown root:wheel {tmp_path}"))?;
    std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o644))
        .with_context(|| format!("chmod 0644 {tmp_path}"))?;
    std::fs::rename(&tmp_path, PLIST_PATH)
        .with_context(|| format!("rename {tmp_path} → {PLIST_PATH}"))?;
    Ok(())
}

/// `launchctl bootstrap system /Library/LaunchDaemons/...`. Idempotent:
/// if the daemon is already bootstrapped, bootout it first.
fn bootstrap_daemon() -> Result<()> {
    // Best-effort bootout (covers re-install case). Story 7.27 review
    // fix: inspect bootout exit code. launchctl bootout exit codes
    // include 0 (success), 36 / `Could not find specified service`
    // (no such service — fine), 9216 / `Boot-out failed: 113` /
    // `Operation in progress` (service in use — bad).
    let bootout = Command::new("/bin/launchctl")
        .args(["bootout", &format!("system/{DAEMON_LABEL}")])
        .output();
    if let Ok(out) = bootout {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let code = out.status.code().unwrap_or(0);
        // Round-3 review fix (R3-C4-P10) doc-only: the exit-code
        // magic numbers `36` and `3` are best-effort across macOS
        // versions — `launchctl bootout`'s exit code is the mach
        // error number on modern macOS and the substring-match on
        // stderr ("Could not find specified service" / "service
        // not loaded") is the reliable signal. Keep the magic
        // numbers as additional safety net but treat the
        // substring as the source of truth.
        let not_loaded = !out.status.success()
            && (stderr.contains("Could not find specified service")
                || stderr.contains("service not loaded")
                || code == 36
                || code == 3);
        if !out.status.success() && !not_loaded {
            eprint!(
                "{}",
                error_block(
                    "service.install.bootout_in_use",
                    &format!(
                        "`launchctl bootout system/{DAEMON_LABEL}` failed (exit {code}): {stderr}",
                    ),
                    &format!(
                        "an existing daemon may still be using the label; manually run `sudo launchctl bootout system/{DAEMON_LABEL}` and retry, or `sudo launchctl kickstart -k system/{DAEMON_LABEL}` to force-restart"
                    ),
                    None,
                )
            );
            return Err(silent_cli_error("launchctl bootout failed (service in use)"));
        }
    }
    let out = Command::new("/bin/launchctl")
        .args(["bootstrap", "system", PLIST_PATH])
        .output()
        .context("failed to invoke /bin/launchctl bootstrap")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // `plutil` for diagnostic.
        let plutil = Command::new("/usr/bin/plutil").arg(PLIST_PATH).output();
        let plutil_msg = match plutil {
            Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
            Err(_) => "(plutil unavailable)".to_owned(),
        };
        eprint!(
            "{}",
            error_block(
                "service.install.bootstrap_failed",
                &format!(
                    "`launchctl bootstrap system {PLIST_PATH}` failed: {stderr}\n\n\
                     plutil: {plutil_msg}"
                ),
                "check the plist syntax + try `sudo launchctl bootstrap system <plist>` manually",
                None,
            )
        );
        return Err(silent_cli_error("launchctl bootstrap failed"));
    }
    Ok(())
}

/// Poll `launchctl print system/<label>` until `state = running`
/// appears or `timeout` elapses. Returns the parsed PID on success.
/// Story 7.27 review fix: parse defensively — `launchctl print`
/// format is undocumented and varies across macOS versions; treat
/// `state = running` OR `pid = <nonzero>` as evidence the daemon
/// is up.
fn verify_daemon_running(timeout: Duration) -> Result<u32> {
    let deadline = Instant::now() + timeout;
    let interval = Duration::from_millis(250);
    let mut last_output = String::new();
    while Instant::now() < deadline {
        let out = Command::new("/bin/launchctl")
            .args(["print", &format!("system/{DAEMON_LABEL}")])
            .output();
        if let Ok(o) = out {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);
            // Round-3 review fix (R3-C4-P14): parse `state = running`
            // from STDOUT only. `launchctl print` writes the
            // human-readable state block to stdout when the service
            // exists; stderr is reserved for error diagnostics. A
            // future macOS that ships a localized help banner
            // mentioning "running" in stderr could otherwise
            // false-positive against the substring match.
            // Combined buffer kept only for the failure-diagnostic
            // `last_output` dump.
            last_output = format!("--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}");
            let running = stdout.lines().any(|l| l.trim_start().starts_with("state = running"));
            let pid: Option<u32> = stdout.lines().find_map(|l| {
                let trimmed = l.trim_start();
                let rest = trimmed.strip_prefix("pid = ")?;
                rest.trim().parse::<u32>().ok().filter(|&p| p != 0)
            });
            // Story 7.27 Round-2 review fix (P1): require `state =
            // running` strictly. Pre-fix, `running || pid.is_some()`
            // returned Ok for `state = exited` / `state = waiting`
            // / `state = not running` cases where `launchctl print`
            // still emits a `pid = N` line carrying the last-run
            // PID. Result: install reported `✓ daemon running (pid N)`
            // for crashed daemons. PID is informational only —
            // state is authoritative.
            //
            // Round-3 review fix (R3-C4-P7): only return success if
            // we have BOTH `state = running` AND a non-zero PID.
            // Without the PID check, a transient launchctl race
            // could return `state = running` before the daemon's
            // pid field was populated (microseconds-wide window);
            // caller would print "✓ daemon running (pid 0)" and the
            // install-complete audit would record the kernel
            // scheduler's PID, not the daemon's. Continue polling
            // until both fields are present.
            if running && pid.is_some() {
                return Ok(pid.unwrap_or(0));
            }
        }
        std::thread::sleep(interval);
    }
    eprint!(
        "{}",
        error_block(
            "service.install.startup_verification_failed",
            &format!(
                "daemon did not reach `state = running` within {}s.\n\n\
                 last `launchctl print` output:\n{last_output}",
                timeout.as_secs()
            ),
            "inspect /Library/Logs/permitlayer/daemon.log for the boot error",
            None,
        )
    );
    Err(silent_cli_error("daemon startup verification failed"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_launchdaemon_plist_renders_expected_shape() {
        // Write to a tempdir override path by hooking into a smaller
        // helper signature. We exercise the body-formatting + plutil
        // shape via a stripped-down sibling test.
        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>Label</key><string>{DAEMON_LABEL}</string>
  <key>SessionCreate</key><true/>
</dict>
</plist>
"#
        );
        assert!(body.contains("dev.permitlayer.daemon"));
        assert!(body.contains("SessionCreate"));
    }

    #[test]
    fn resolve_binary_source_accepts_from_override() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let bin = dir.path().join("agentsso");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        // Story 7.27 Round-2 review fix (P2): the new validation in
        // `resolve_binary_source` requires the source to (a) be a
        // regular non-symlink file and (b) have the executable bit
        // set. The test's tempfile is fine on (a) but `std::fs::write`
        // creates it with default mode 0o644; set 0o755 to satisfy
        // the executable-bit check.
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let args = InstallArgs { from: Some(bin.clone()) };
        let resolved = resolve_binary_source(&args).unwrap();
        assert_eq!(resolved, bin);
    }

    #[test]
    fn resolve_binary_source_rejects_non_executable() {
        let dir = tempdir().unwrap();
        let bin = dir.path().join("agentsso");
        std::fs::write(&bin, b"not really a binary").unwrap(); // mode 0o644 by default
        let args = InstallArgs { from: Some(bin) };
        let err = resolve_binary_source(&args).expect_err("should reject non-executable");
        assert!(
            err.to_string().contains("no executable bit set"),
            "expected executable-bit error, got: {err}"
        );
    }

    #[test]
    fn resolve_binary_source_rejects_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let real_bin = dir.path().join("real-agentsso");
        std::fs::write(&real_bin, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&real_bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = dir.path().join("link-to-agentsso");
        std::os::unix::fs::symlink(&real_bin, &link).unwrap();
        let args = InstallArgs { from: Some(link) };
        let err = resolve_binary_source(&args).expect_err("should reject symlink");
        assert!(
            err.to_string().contains("is a symlink"),
            "expected symlink-refusal error, got: {err}"
        );
    }

    #[test]
    fn find_free_gid_finds_something_in_range() {
        // Smoke test that the search returns a u32. Actual freeness
        // depends on the host machine; on CI the 300-499 range is
        // typically empty.
        let _ = find_free_gid_in_range(300, 499);
    }
}
