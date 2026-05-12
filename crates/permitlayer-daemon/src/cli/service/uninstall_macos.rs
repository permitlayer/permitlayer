//! `agentsso service uninstall` macOS implementation (Story 7.27).
//!
//! Idempotent reverse of `service install`. Missing components are
//! NOT errors — `service uninstall` after a partially-installed
//! state always succeeds (operator can re-run safely).

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;
use nix::unistd::Uid;

use super::UninstallArgs;
use crate::cli::silent_cli_error;
use crate::design::render::error_block;

const DAEMON_LABEL: &str = "dev.permitlayer.daemon";
const PLIST_PATH: &str = "/Library/LaunchDaemons/dev.permitlayer.daemon.plist";
const PRIVILEGED_HELPER_PATH: &str = "/Library/PrivilegedHelperTools/agentsso";
const CLIENTS_GROUP: &str = "permitlayer-clients";

pub async fn run(_args: UninstallArgs) -> Result<()> {
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
    // state-dir + dscl operations. Reuse the install-side helper
    // — same lock file (`/var/run/permitlayer/.install.lock` or
    // `/tmp/.permitlayer-install.lock` fallback), same stale-lock
    // mtime detection. Lock drops at end of `run()` via RAII.
    let _install_lock = crate::cli::service::install_macos::acquire_install_lock_pub()?;

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
    let helper = Path::new(PRIVILEGED_HELPER_PATH);
    if helper.exists() {
        match std::fs::remove_file(helper) {
            Ok(()) => println!("  ✓ removed privileged helper binary"),
            Err(e) => {
                tracing::warn!(error = %e, path = PRIVILEGED_HELPER_PATH, "failed to remove helper binary");
            }
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
    let dot_agentsso_path = home.join(".agentsso");
    let dot_meta = permitlayer_platform_macos::fstatat_nofollow(
        permitlayer_platform_macos::open_dir_nofollow(home).ok()?.as_raw_fd(),
        ".agentsso",
    )
    .ok()?;
    if (dot_meta.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return None;
    }
    let dot_fd = permitlayer_platform_macos::open_dir_nofollow(&dot_agentsso_path).ok()?;
    let leaf_meta =
        permitlayer_platform_macos::fstatat_nofollow(dot_fd.as_raw_fd(), "agent-bearer.token")
            .ok()?;
    if (leaf_meta.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return None;
    }
    Some(dot_agentsso_path.join("agent-bearer.token"))
}
