//! `agentsso service uninstall` macOS implementation (Story 7.27).
//!
//! Idempotent reverse of `service install`. Missing components are
//! NOT errors — `service uninstall` after a partially-installed
//! state always succeeds (operator can re-run safely).

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;
use nix::unistd::Uid;

use super::{DAEMON_LABEL, LAUNCHD_PLIST_PATH, UninstallArgs};
use crate::cli::silent_cli_error;
use crate::design::render::error_block;

const PLIST_PATH: &str = LAUNCHD_PLIST_PATH;
const PRIVILEGED_HELPER_PATH: &str = "/Library/PrivilegedHelperTools/agentsso";
const CLIENTS_GROUP: &str = "permitlayer-clients";

pub async fn run(args: UninstallArgs) -> Result<()> {
    if !Uid::effective().is_root() {
        eprint!(
            "{}",
            error_block(
                "service.uninstall.requires_root",
                "`agentsso service uninstall` must run as root",
                "sudo agentsso service uninstall",
                None,
            )
        );
        return Err(silent_cli_error("service uninstall requires root"));
    }

    // Story 7.27 Round-2 review fix (P2): acquire the install-lock
    // so concurrent install+uninstall invocations don't race on
    // state-dir + dscl operations. Reuse the install-side helper.
    //
    // Round-3 review fix (R3-C4-P9): `--force` bypasses the
    // install-lock so an operator can clean up after a crashed
    // install. Without `--force`, a fresh crashed install (kernel
    // hasn't yet released the lock fd, or the lockfile reflects a
    // wedged process) blocks recovery — uninstall waits forever
    // for a lock that may never release. `--force` skips the
    // acquisition entirely and accepts the (operator-acknowledged)
    // risk of racing another install.
    let _install_lock = if args.force {
        eprintln!("→ `--force` specified: skipping install-lock acquisition");
        crate::cli::service::install_macos::acquire_install_lock_pub_force()
    } else {
        crate::cli::service::install_macos::acquire_install_lock_pub()?
    };

    // Story 7.27 Round-2 review fix (P2): clean up rc.21
    // LaunchAgents BEFORE the rc.22 bootout, mirroring the install
    // path. Pre-fix, uninstall only torn down `dev.permitlayer.daemon`
    // — any rc.21 LaunchAgents that survived rc.21→rc.22 migration
    // would remain loaded as orphans. Now uninstall is fully
    // symmetric with install's rc.21 cleanup.
    let rc21_cleaned =
        crate::cli::service::install_macos::cleanup_rc21_launchagents_for_uninstall().await;
    if !rc21_cleaned.is_empty() {
        for (path, uid) in &rc21_cleaned {
            println!("  ✓ removed stale rc.21 LaunchAgent: {} (uid {uid})", path.display());
        }
    }

    // (1) Stop + remove the LaunchDaemon.
    // Story 7.27 Round-2 review fix (P2): capture the bootout exit
    // code. Pre-fix, `let _ = ...` silently discarded the result —
    // if bootout returned 9216 (service in use), the daemon was
    // still running but uninstall proceeded to remove the plist
    // and helper binary, orphaning the running process. Now we
    // tolerate 0 + 36/"not loaded" as success, and surface 9216
    // + other non-zero exits as a fatal error with remediation.
    let bootout_out = Command::new("/bin/launchctl")
        .args(["bootout", &format!("system/{DAEMON_LABEL}")])
        .output();
    match bootout_out {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            let code = out.status.code().unwrap_or(-1);
            let stderr = String::from_utf8_lossy(&out.stderr);
            // Round-3 review fix (R3-C4-P10) doc-only: substring
            // match on stderr is the reliable cross-version signal;
            // exit codes `36`/`3` are best-effort fallbacks.
            let not_loaded = code == 36
                || code == 3
                || stderr.contains("Could not find specified service")
                || stderr.contains("service not loaded");
            if !not_loaded {
                eprint!(
                    "{}",
                    error_block(
                        "service.uninstall.bootout_in_use",
                        &format!(
                            "`launchctl bootout system/{DAEMON_LABEL}` failed (exit {code}): {stderr}"
                        ),
                        &format!(
                            "the daemon may still be in use; run `sudo launchctl kickstart -k system/{DAEMON_LABEL}` to force-restart, then re-run uninstall, OR manually `sudo launchctl bootout system/{DAEMON_LABEL}`"
                        ),
                        None,
                    )
                );
                return Err(silent_cli_error("launchctl bootout failed during uninstall"));
            }
            // Not-loaded is fine — daemon was already gone.
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to invoke launchctl bootout (continuing best-effort)");
        }
    }
    if Path::new(PLIST_PATH).exists() {
        if let Err(e) = std::fs::remove_file(PLIST_PATH) {
            tracing::warn!(error = %e, path = PLIST_PATH, "failed to remove plist (continuing)");
        } else {
            println!("  ✓ removed LaunchDaemon plist");
        }
    }

    // (2) Remove privileged helper binary. Story 7.27 review fix:
    // restructure the if/else-if/else so the success-path "removed"
    // line actually prints (the prior chain landed the success case
    // in the "already gone" branch).
    //
    // Symlink model: `PRIVILEGED_HELPER_PATH` is now a symlink to a
    // versioned `agentsso-<semver>` sibling. Tear down the symlink
    // itself, then every `agentsso-<semver>` versioned binary plus
    // any `agentsso.tmp` / `agentsso-*.tmp.*` staging crumbs left by
    // an interrupted atomic stage. A legacy pre-symlink install has
    // a regular file at the path — handle that case as before.
    let helper = Path::new(PRIVILEGED_HELPER_PATH);
    match std::fs::symlink_metadata(helper) {
        Ok(meta) if meta.file_type().is_symlink() => {
            match std::fs::remove_file(helper) {
                Ok(()) => println!("  ✓ removed privileged helper symlink"),
                Err(e) => {
                    tracing::warn!(error = %e, path = PRIVILEGED_HELPER_PATH, "failed to remove helper symlink");
                }
            }
            if let Some(helper_dir) = helper.parent()
                && let Ok(entries) = std::fs::read_dir(helper_dir)
            {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    if is_versioned_helper_binary(&name) || is_helper_staging_crumb(&name) {
                        let path = entry.path();
                        match std::fs::remove_file(&path) {
                            Ok(()) => println!("  ✓ removed {}", path.display()),
                            Err(e) => {
                                tracing::warn!(error = %e, path = %path.display(), "failed to remove helper binary/crumb");
                            }
                        }
                    }
                }
            }
        }
        Ok(_) => {
            // Legacy pre-symlink install: a regular file at the path.
            match std::fs::remove_file(helper) {
                Ok(()) => println!("  ✓ removed privileged helper binary"),
                Err(e) => {
                    tracing::warn!(error = %e, path = PRIVILEGED_HELPER_PATH, "failed to remove helper binary");
                }
            }
        }
        Err(_) => {
            // Not present — idempotent no-op (uninstall after a
            // partially-installed state always succeeds).
        }
    }

    // (3) Delete master-key entry from System.keychain (best-effort).
    // Story 7.27 review fix: use the canonical MASTER_KEY_ACCOUNT
    // constant rather than hardcoding "master" — keeps the two sites
    // in sync if the account name ever changes.
    let _ = Command::new("/usr/bin/security")
        .args([
            "delete-generic-password",
            "-s",
            permitlayer_keystore::MASTER_KEY_SERVICE,
            "-a",
            permitlayer_keystore::MASTER_KEY_ACCOUNT,
            "/Library/Keychains/System.keychain",
        ])
        .output();
    println!("  ✓ master-key entry removed from System.keychain (if present)");

    // (4) Remove state, log, runtime dirs.
    //
    // NOTE: Story 1's managed-policy dir is
    // `daemon_state_dir().join("policies-managed")` — a child of the
    // daemon state dir removed here. The `remove_dir_all` below
    // therefore transitively wipes `policies-managed/` already; no
    // separate removal step is needed (and adding one would be a
    // redundant double-remove). Do NOT "fix" this by adding an
    // explicit policies-managed removal.
    for dir in [
        permitlayer_core::paths::daemon_state_dir(None),
        permitlayer_core::paths::daemon_log_dir(None),
        permitlayer_core::paths::daemon_runtime_dir(None),
    ] {
        if dir.exists() {
            if let Err(e) = std::fs::remove_dir_all(&dir) {
                tracing::warn!(error = %e, path = %dir.display(), "failed to remove dir");
            } else {
                println!("  ✓ removed {}", dir.display());
            }
        }
    }

    // (5) Delete permitlayer-clients group.
    // Story 7.27 Round-2 review fix (P2): capture the dscl exit
    // code so the user-facing message reflects reality. Pre-fix,
    // `let _ = ...` always printed `✓ removed group` regardless
    // of whether delete succeeded or the group was absent.
    let dscl_out = Command::new("/usr/bin/dscl")
        .args([".", "-delete", &format!("/Groups/{CLIENTS_GROUP}")])
        .output();
    match dscl_out {
        Ok(out) if out.status.success() => {
            println!("  ✓ removed group `{CLIENTS_GROUP}`");
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            // dscl returns non-zero with stderr like "DS Error: -14136"
            // when the group does not exist — treat as absent.
            if stderr.contains("eDSRecordNotFound")
                || stderr.contains("-14136")
                || stderr.contains("does not exist")
            {
                println!("  ✓ group `{CLIENTS_GROUP}` already absent");
            } else {
                println!(
                    "  warning: failed to remove group `{CLIENTS_GROUP}` (dscl exit {}: {}); \
                     continuing best-effort. Run `sudo dscl . -delete /Groups/{CLIENTS_GROUP}` \
                     manually if needed.",
                    out.status.code().unwrap_or(-1),
                    stderr.trim()
                );
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to invoke dscl delete (continuing best-effort)");
        }
    }

    // (6) Walk /Users/* removing per-user agent-bearer.token files.
    let removed_tokens = remove_per_user_bearer_tokens();
    if removed_tokens > 0 {
        println!("  ✓ removed {removed_tokens} per-user agent-bearer.token file(s)");
    }

    println!();
    println!("──────────────────────────────────────────────────────────────");
    println!("✓ PermitLayer system service uninstalled.");
    println!();
    println!("Preserved (intentionally — operator may want them):");
    println!("  • the `agentsso` binary at /usr/local/bin/agentsso");
    println!("    (run `brew uninstall agentsso` to remove)");
    println!("  • rc.21 vault at ~/.agentsso/vault/ (if any)");
    println!("    — remove manually with `rm -rf ~/.agentsso/` for a clean slate");
    println!("──────────────────────────────────────────────────────────────");
    Ok(())
}

/// True for `agentsso-<semver-ish>` versioned helper binaries (the
/// symlink targets installed under
/// `/Library/PrivilegedHelperTools/`). "Semver-ish" is intentionally
/// loose — accept the `agentsso-` prefix followed by a non-empty
/// version-like tail whose chars are `[0-9A-Za-z._+-]` (covers
/// `0.3.0`, `0.3.0-rc.36`, build metadata). Deliberately excludes
/// the bare `agentsso` symlink name (no `-` suffix) and staging
/// crumbs (handled separately by `is_helper_staging_crumb`).
fn is_versioned_helper_binary(name: &str) -> bool {
    let Some(tail) = name.strip_prefix("agentsso-") else {
        return false;
    };
    if tail.is_empty() {
        return false;
    }
    // A `.tmp.` infix means it's a staging crumb, not a finished
    // versioned binary — let `is_helper_staging_crumb` own it.
    if tail.contains(".tmp.") {
        return false;
    }
    tail.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

/// True for atomic-stage staging crumbs left by an interrupted
/// install: `agentsso.tmp` (legacy single-name stage) or
/// `agentsso-*.tmp.*` (the `<dest>.tmp.<pid>` pattern that
/// `stage_file_atomic` writes before the rename).
fn is_helper_staging_crumb(name: &str) -> bool {
    name == "agentsso.tmp"
        || name.starts_with("agentsso.tmp.")
        || (name.starts_with("agentsso-") && name.contains(".tmp."))
}

fn remove_per_user_bearer_tokens() -> u32 {
    let mut count = 0u32;
    let Ok(entries) = std::fs::read_dir("/Users") else { return 0 };
    for entry in entries.flatten() {
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_dir() || meta.file_type().is_symlink() {
            continue;
        }
        // Story 7.27 Round-2 review fix (P1): walk to the token
        // file via `openat` chain so intermediate symlinks
        // (`/Users/me/.agentsso` → `/etc/...`) are rejected. Mirrors
        // the install-side rc.21 cleanup safe-resolve.
        let token = match safe_resolve_token(&entry.path()) {
            Some(p) => p,
            None => continue,
        };
        if std::fs::remove_file(&token).is_ok() {
            count += 1;
        }
    }
    count
}

/// Safely resolve `<home>/.agentsso/agent-bearer.token`. Returns the
/// final path only if every intermediate component is a non-symlink
/// directory AND the leaf is a regular non-symlink file. See
/// `install_macos::safe_resolve_rc21_plist` for the threat-model
/// commentary; this is the uninstall-side analogue.
fn safe_resolve_token(home: &Path) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    // Round-3 review fix (R3-C4-P8): refuse if `home` itself is a
    // symlink before walking. The install side already does this via
    // `safe_resolve_rc21_plist`'s initial `open_dir_nofollow(home)`
    // (ELOOP on symlink); the Round-2 uninstall side missed the
    // explicit check at the home level. Add it here so an attacker
    // who plants `/Users/me` as a symlink to `/etc/` does not lead
    // the token sweep into deleting `/etc/agentsso/...`.
    let home_meta = std::fs::symlink_metadata(home).ok()?;
    if home_meta.file_type().is_symlink() {
        return None;
    }
    // Round-3 review fix (R3-C4-P1): true openat-anchored walk.
    // The Round-2 implementation re-opened `.agentsso` by full path
    // after the fstatat check, leaving a TOCTOU window. Now we use
    // `open_dir_nofollow_at(home_fd, ".agentsso")` so the new fd
    // resolves relative to the home fd we already hold.
    let home_fd = permitlayer_platform_macos::open_dir_nofollow(home).ok()?;
    let dot_meta =
        permitlayer_platform_macos::fstatat_nofollow(home_fd.as_raw_fd(), ".agentsso").ok()?;
    if (dot_meta.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return None;
    }
    let dot_fd =
        permitlayer_platform_macos::open_dir_nofollow_at(home_fd.as_raw_fd(), ".agentsso").ok()?;
    let leaf_meta =
        permitlayer_platform_macos::fstatat_nofollow(dot_fd.as_raw_fd(), "agent-bearer.token")
            .ok()?;
    if (leaf_meta.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return None;
    }
    Some(home.join(".agentsso").join("agent-bearer.token"))
}
