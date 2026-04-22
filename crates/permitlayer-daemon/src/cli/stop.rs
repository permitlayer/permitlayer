use std::path::PathBuf;

use crate::config::{CliOverrides, DaemonConfig};
use crate::lifecycle::pid::PidFile;

pub fn run() -> anyhow::Result<()> {
    let home = resolve_home();

    // Read PID from file.
    let pid = match PidFile::read(&home)? {
        Some(pid) => pid,
        None => {
            eprintln!("daemon not running (no PID file)");
            std::process::exit(3);
        }
    };

    // Check if the process is actually alive.
    if !PidFile::is_daemon_running(&home)? {
        eprintln!("daemon not running (stale PID file for PID {pid})");
        // Clean up the stale PID file.
        let pid_path = home.join("agentsso.pid");
        let _ = std::fs::remove_file(pid_path);
        std::process::exit(3);
    }

    // Validate PID range before signaling.
    let raw_pid = match i32::try_from(pid) {
        Ok(p) if p > 0 => p,
        _ => {
            eprintln!("invalid PID {pid} in PID file (out of range)");
            std::process::exit(3);
        }
    };

    // Send SIGTERM.
    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        kill(Pid::from_raw(raw_pid), Signal::SIGTERM)?;
    }
    #[cfg(not(unix))]
    {
        let _ = raw_pid;
        eprintln!("stop command is not supported on this platform");
        std::process::exit(1);
    }

    // Wait for PID file to disappear (up to 10s).
    let pid_path = home.join("agentsso.pid");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if !pid_path.exists() {
            println!("daemon stopped");
            return Ok(());
        }
        if std::time::Instant::now() > deadline {
            eprintln!("warning: daemon did not shut down cleanly within 10 seconds");
            std::process::exit(3);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Resolve the agentsso home directory from config (defaults → TOML → env).
fn resolve_home() -> PathBuf {
    DaemonConfig::load(&CliOverrides::default()).map(|c| c.paths.home).unwrap_or_else(|_| {
        dirs::home_dir().map(|h| h.join(".agentsso")).unwrap_or_else(|| PathBuf::from(".agentsso"))
    })
}
