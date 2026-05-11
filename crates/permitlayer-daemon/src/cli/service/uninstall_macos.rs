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

    // (1) Stop + remove the LaunchDaemon.
    let _ = Command::new("/bin/launchctl")
        .args(["bootout", &format!("system/{DAEMON_LABEL}")])
        .output();
    if Path::new(PLIST_PATH).exists() {
        if let Err(e) = std::fs::remove_file(PLIST_PATH) {
            tracing::warn!(error = %e, path = PLIST_PATH, "failed to remove plist (continuing)");
        } else {
            println!("  ✓ removed LaunchDaemon plist");
        }
    }

    // (2) Remove privileged helper binary.
    if Path::new(PRIVILEGED_HELPER_PATH).exists()
        && let Err(e) = std::fs::remove_file(PRIVILEGED_HELPER_PATH)
    {
        tracing::warn!(error = %e, path = PRIVILEGED_HELPER_PATH, "failed to remove helper binary");
    } else if !Path::new(PRIVILEGED_HELPER_PATH).exists() {
        // already gone
    } else {
        println!("  ✓ removed privileged helper binary");
    }

    // (3) Delete master-key entry from System.keychain (best-effort).
    let _ = Command::new("/usr/bin/security")
        .args([
            "delete-generic-password",
            "-s",
            permitlayer_keystore::MASTER_KEY_SERVICE,
            "-a",
            "master",
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
    let _ = Command::new("/usr/bin/dscl")
        .args([".", "-delete", &format!("/Groups/{CLIENTS_GROUP}")])
        .output();
    println!("  ✓ removed group `{CLIENTS_GROUP}` (if present)");

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
        let token: PathBuf = entry.path().join(".agentsso/agent-bearer.token");
        if token.exists() && std::fs::remove_file(&token).is_ok() {
            count += 1;
        }
    }
    count
}
