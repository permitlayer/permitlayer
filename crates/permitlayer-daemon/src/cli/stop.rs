use std::path::PathBuf;

use crate::config::{CliOverrides, DaemonConfig};
use crate::design::render::{self, error_block};
use crate::design::terminal::ColorSupport;
use crate::design::theme::Theme;
use crate::lifecycle::pid::PidFile;

pub fn run() -> anyhow::Result<()> {
    let home = resolve_home();
    // Route output through the shared CLI palette (errors → stderr via
    // `error_block`, success → `success_headline`), matching the one
    // idiom every other command uses instead of bare `eprintln!`/
    // `println!`.
    let support = ColorSupport::detect();
    let theme = Theme::load(&home);

    // Read PID from file.
    let pid = match PidFile::read(&home)? {
        Some(pid) => pid,
        None => {
            eprint!(
                "{}",
                error_block(
                    "stop.daemon_not_running",
                    "daemon not running (no PID file)",
                    "start it with:  agentsso start",
                    None,
                )
            );
            std::process::exit(3);
        }
    };

    // Check if the process is actually alive.
    if !PidFile::is_daemon_running(&home)? {
        eprint!(
            "{}",
            error_block(
                "stop.daemon_not_running",
                &format!("daemon not running (stale PID file for PID {pid})"),
                "start it with:  agentsso start",
                None,
            )
        );
        // Clean up the stale PID file.
        let pid_path = home.join("agentsso.pid");
        let _ = std::fs::remove_file(pid_path);
        std::process::exit(3);
    }

    // Validate PID range before signaling.
    let raw_pid = match i32::try_from(pid) {
        Ok(p) if p > 0 => p,
        _ => {
            eprint!(
                "{}",
                error_block(
                    "stop.invalid_pid",
                    &format!("invalid PID {pid} in PID file (out of range)"),
                    "remove the corrupt PID file, then:  agentsso start",
                    None,
                )
            );
            std::process::exit(3);
        }
    };

    // Send SIGTERM.
    #[cfg(not(unix))]
    {
        let _ = (raw_pid, &theme, support);
        eprint!(
            "{}",
            error_block(
                "stop.unsupported_platform",
                "stop command is not supported on this platform",
                "stop the daemon process manually",
                None,
            )
        );
        std::process::exit(1);
    }

    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        kill(Pid::from_raw(raw_pid), Signal::SIGTERM)?;

        // Wait for PID file to disappear (up to 10s).
        let pid_path = home.join("agentsso.pid");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if !pid_path.exists() {
                // Success chrome → stderr (matches the connect/quickstart
                // idiom; stop has no machine payload for stdout).
                eprint!("{}", render::success_headline("daemon stopped", &theme, support));
                return Ok(());
            }
            if std::time::Instant::now() > deadline {
                eprint!(
                    "{}",
                    error_block(
                        "stop.unclean_shutdown",
                        "daemon did not shut down cleanly within 10 seconds",
                        "check the daemon's tracing log; it may still be flushing",
                        None,
                    )
                );
                std::process::exit(3);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

/// Resolve the agentsso home directory from config (defaults → TOML → env).
fn resolve_home() -> PathBuf {
    DaemonConfig::load(&CliOverrides::default())
        .map(|c| c.paths.home)
        .unwrap_or_else(|_| permitlayer_core::paths::daemon_state_dir(None))
}
