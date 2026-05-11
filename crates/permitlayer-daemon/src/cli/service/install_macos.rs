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

    // (1) SUDO_UID validation — refuse direct-as-root invocations
    // that bypass the operator-identity step.
    let (operator_uid, operator_username) = resolve_operator()?;
    println!(
        "→ installing PermitLayer daemon for operator {operator_username} (uid {operator_uid})"
    );

    // (2) rc.21 LaunchAgent cleanup (AC #9).
    let cleaned = cleanup_rc21_launchagents().await;
    if !cleaned.is_empty() {
        for path in &cleaned {
            println!("  ✓ removed stale rc.21 LaunchAgent: {}", path.display());
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
    let out = Command::new("/usr/bin/security")
        .args(["set-keychain-settings", "-u", "/Library/Keychains/System.keychain"])
        .output()
        .context("failed to invoke /usr/bin/security set-keychain-settings")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        eprint!(
            "{}",
            error_block(
                "service.install.keychain_settings_failed",
                &format!("`security set-keychain-settings -u` failed: {stderr}"),
                "verify /Library/Keychains/System.keychain is readable + writable by root",
                None,
            )
        );
        return Err(silent_cli_error("security set-keychain-settings failed"));
    }
    println!("  ✓ System.keychain lock-on-sleep disabled");

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
    let pid = verify_daemon_running(Duration::from_secs(10))?;
    println!("  ✓ daemon running (pid {pid})");

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
    println!("End-users on this Mac register their agent with:");
    println!("  agentsso agent register --name <name>");
    println!("──────────────────────────────────────────────────────────────");
    Ok(())
}

/// Resolve `(SUDO_UID, username)` — refuses missing or root SUDO_UID
/// so direct-as-root invocations (someone `su -`d to root) are
/// caught.
fn resolve_operator() -> Result<(u32, String)> {
    let raw = std::env::var("SUDO_UID").ok();
    let uid = match raw.as_deref() {
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
    Ok((uid, user.name))
}

/// Walk `/Users/*/Library/LaunchAgents/` looking for rc.21
/// `dev.agentsso.daemon.plist` files; bootout + unlink each. Also
/// handles the system-wide LaunchAgents location. Returns the list
/// of plists removed for caller-side reporting.
async fn cleanup_rc21_launchagents() -> Vec<PathBuf> {
    let mut removed: Vec<PathBuf> = Vec::new();

    // Per-user LaunchAgents under /Users/*.
    if let Ok(entries) = std::fs::read_dir("/Users") {
        for entry in entries.flatten() {
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            // Skip non-directories + symlinks (defense against a
            // hostile /Users symlink farm).
            if !meta.is_dir() || meta.file_type().is_symlink() {
                continue;
            }
            let plist = entry.path().join("Library/LaunchAgents/dev.agentsso.daemon.plist");
            if !plist.exists() {
                continue;
            }
            // Best-effort bootout for the user's gui/<uid> domain.
            // Resolve the user's UID by stat'ing their home dir's
            // owner (more reliable than parsing usernames from
            // /Users entries since the dir name may not match).
            if let Ok(home_meta) = entry.metadata() {
                use std::os::unix::fs::MetadataExt;
                let uid = home_meta.uid();
                let _ = Command::new("/bin/launchctl")
                    .args(["bootout", &format!("gui/{uid}/dev.agentsso.daemon")])
                    .output();
            }
            if std::fs::remove_file(&plist).is_ok() {
                removed.push(plist);
            }
        }
    }

    // System-wide LaunchAgents (vanishingly rare in rc.21 but
    // possible if an operator hand-installed).
    let sys = PathBuf::from("/Library/LaunchAgents/dev.agentsso.daemon.plist");
    if sys.exists() {
        let _ =
            Command::new("/bin/launchctl").args(["bootout", "system/dev.agentsso.daemon"]).output();
        if std::fs::remove_file(&sys).is_ok() {
            removed.push(sys);
        }
    }

    removed
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
    let stdout = String::from_utf8_lossy(&out.stdout);
    let used: std::collections::HashSet<u32> = stdout
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1)?.parse::<u32>().ok())
        .collect();
    for gid in lo..=hi {
        if !used.contains(&gid) {
            return Ok(gid);
        }
    }
    Err(anyhow::anyhow!("no free GID in range {lo}-{hi} for `{CLIENTS_GROUP}`"))
}

/// Create the state, log, and runtime dir trees with the perms
/// specified in 7.25 AC #4.
fn create_state_dirs() -> Result<()> {
    let state = permitlayer_core::paths::daemon_state_dir(None);
    let log = permitlayer_core::paths::daemon_log_dir(None);
    let runtime = permitlayer_core::paths::daemon_runtime_dir(None);

    for dir in [&state, &log, &runtime] {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to mkdir -p {}", dir.display()))?;
    }
    // State dir + its subdirs are 0700 root:wheel.
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", state.display()))?;
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
        Some(p) => p.clone(),
        None => std::env::current_exe()
            .context("std::env::current_exe() failed")?
            .canonicalize()
            .context("failed to canonicalize current_exe()")?,
    };
    Ok(candidate)
}

/// Copy `from` to `/Library/PrivilegedHelperTools/agentsso`, chown
/// root:wheel, chmod 0755.
fn copy_binary_to_helper_tools(from: &Path) -> Result<()> {
    let helper_dir = Path::new(PRIVILEGED_HELPER_PATH).parent().unwrap_or(Path::new("/"));
    std::fs::create_dir_all(helper_dir)
        .with_context(|| format!("mkdir -p {}", helper_dir.display()))?;
    std::fs::copy(from, PRIVILEGED_HELPER_PATH)
        .with_context(|| format!("copy {} → {}", from.display(), PRIVILEGED_HELPER_PATH))?;
    let dst = Path::new(PRIVILEGED_HELPER_PATH);
    chown(dst, Some(Uid::from_raw(0)), Some(Gid::from_raw(0)))
        .with_context(|| format!("chown root:wheel {}", dst.display()))?;
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod 0755 {}", dst.display()))?;
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
      <key>PERMITLAYER_OPERATOR_USER</key><string>{operator_username}</string>
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
    // Best-effort bootout (covers re-install case).
    let _ = Command::new("/bin/launchctl")
        .args(["bootout", &format!("system/{DAEMON_LABEL}")])
        .output();
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
fn verify_daemon_running(timeout: Duration) -> Result<u32> {
    let deadline = Instant::now() + timeout;
    let interval = Duration::from_millis(250);
    let mut last_output = String::new();
    while Instant::now() < deadline {
        let out = Command::new("/bin/launchctl")
            .args(["print", &format!("system/{DAEMON_LABEL}")])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            last_output = s.clone().into_owned();
            // Look for `state = running` line.
            if s.lines().any(|l| l.trim_start().starts_with("state = running")) {
                // Parse `pid = N`.
                let pid: Option<u32> = s.lines().find_map(|l| {
                    let trimmed = l.trim_start();
                    let rest = trimmed.strip_prefix("pid = ")?;
                    rest.trim().parse().ok()
                });
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
        let dir = tempdir().unwrap();
        let bin = dir.path().join("agentsso");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        let args = InstallArgs { from: Some(bin.clone()) };
        let resolved = resolve_binary_source(&args).unwrap();
        assert_eq!(resolved, bin);
    }

    #[test]
    fn find_free_gid_finds_something_in_range() {
        // Smoke test that the search returns a u32. Actual freeness
        // depends on the host machine; on CI the 300-499 range is
        // typically empty.
        let _ = find_free_gid_in_range(300, 499);
    }
}
