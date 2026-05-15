//! `agentsso service` — manage the daemon as a macOS system service
//! (rc.22 model).
//!
//! Three subcommands:
//! - `agentsso service install` — root-required one-time setup:
//!   creates the `permitlayer-clients` group, the dir tree under
//!   `/Library/Application Support/permitlayer/` +
//!   `/Library/Logs/permitlayer/` + `/var/run/permitlayer/`, copies
//!   the binary to `/Library/PrivilegedHelperTools/agentsso`, writes
//!   the LaunchDaemon plist at `/Library/LaunchDaemons/dev.permitlayer.daemon.plist`,
//!   disables lock-on-sleep on System.keychain, tears down rc.21
//!   LaunchAgents, and `launchctl bootstrap`s the new daemon.
//! - `agentsso service uninstall` — root-required reverse of
//!   install. Idempotent.
//! - `agentsso service status` — no-root state report.
//!
//! Replaces `agentsso autostart enable/disable/status` from rc.21.
//! Per Story 7.25 "burn the boats" direction (Sprint Change Proposal
//! 2026-05-10), no alias — the old verb is removed and a
//! help-redirecting interceptor in `main.rs` catches stale
//! invocations.

use std::path::PathBuf;

use clap::{Args, Subcommand};

/// macOS LaunchDaemon label used by `agentsso service install` and
/// foreground-start collision diagnostics.
pub(crate) const DAEMON_LABEL: &str = "dev.permitlayer.daemon";

/// macOS LaunchDaemon plist path installed by `agentsso service install`.
pub(crate) const LAUNCHD_PLIST_PATH: &str = "/Library/LaunchDaemons/dev.permitlayer.daemon.plist";

#[derive(Args, Debug)]
pub struct ServiceArgs {
    #[command(subcommand)]
    pub command: ServiceCommand,
}

#[derive(Subcommand, Debug)]
pub enum ServiceCommand {
    /// Install the daemon as a macOS system service. Requires root
    /// (`sudo`). Creates `/Library/LaunchDaemons/dev.permitlayer.daemon.plist`,
    /// the `permitlayer-clients` group, the state/log/runtime dirs,
    /// and bootstraps the LaunchDaemon. Idempotent.
    Install(InstallArgs),

    /// Stop and remove the daemon system service. Requires root.
    /// Reverses `install` cleanly (idempotent — missing components
    /// are not errors).
    Uninstall(UninstallArgs),

    /// Report system-service state. No root required.
    Status,
}

#[derive(Args, Debug)]
pub struct InstallArgs {
    /// Override the source binary path. The default resolves
    /// `std::env::current_exe()` and canonicalizes it. No allowlist
    /// of "safe" source locations is enforced — the operator owns the
    /// outcome (Tailscale precedent; previous brew-prefix allowlist
    /// produced wrong remediations on Macs with custom
    /// `HOMEBREW_PREFIX`). Use this flag for `cargo build --release`
    /// testing.
    #[arg(long)]
    pub from: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct UninstallArgs {
    /// Bypass the install-lock acquisition. Use when a previous
    /// `service install` crashed leaving the lock held and you
    /// need to clean up. Round-3 review fix (R3-C4-P9): without
    /// `--force`, a fresh crashed install (lock held by a dead
    /// process for less than the kernel's grace) blocks recovery
    /// — uninstall waits forever for a lock that may never
    /// release. With `--force`, uninstall proceeds without
    /// mutual-exclusion guarantees.
    #[arg(long)]
    pub force: bool,
}

#[cfg(target_os = "macos")]
mod install_macos;
#[cfg(target_os = "macos")]
mod status_macos;
#[cfg(target_os = "macos")]
mod uninstall_macos;

/// Dispatch `agentsso service <subcommand>`.
///
/// On non-macOS platforms emits a structured error block pointing
/// the operator at the platform-native autostart mechanism (those
/// platform redesigns are 7.18 / 7.19).
pub async fn run(args: ServiceArgs) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        match args.command {
            ServiceCommand::Install(a) => install_macos::run(a).await,
            ServiceCommand::Uninstall(a) => uninstall_macos::run(a).await,
            ServiceCommand::Status => status_macos::run().await,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = args;
        eprint!(
            "{}",
            crate::design::render::error_block(
                "service.platform_not_supported",
                "`agentsso service` is only implemented on macOS in rc.22",
                "Linux + Windows platform redesigns are future stories. \
                 See docs/user-guide/install.md for platform-native autostart.",
                None,
            )
        );
        Err(crate::cli::silent_cli_error(
            "`agentsso service` is not supported on this platform yet",
        ))
    }
}
