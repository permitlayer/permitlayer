//! `agentsso service status` macOS implementation (Story 7.27).
//!
//! No-root state report. Prints structured status block with
//! daemon state (`running` / `stopped` / `not-installed`), PID,
//! UDS control-socket reachability, log path.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use anyhow::Result;
use tokio::time::timeout;

const DAEMON_LABEL: &str = "dev.permitlayer.daemon";
const PLIST_PATH: &str = "/Library/LaunchDaemons/dev.permitlayer.daemon.plist";

pub async fn run() -> Result<()> {
    let installed = Path::new(PLIST_PATH).exists();

    let (state, pid) = if installed { read_launchctl_state() } else { ("not-installed", None) };

    let sock_status = if installed {
        let sock_path = permitlayer_core::paths::control_socket_path(None);
        probe_uds_reachability(&sock_path).await
    } else {
        "n/a".to_owned()
    };

    println!("PermitLayer service status");
    println!("──────────────────────────────────────────────────────────────");
    println!("  state:        {state}");
    if let Some(pid) = pid {
        println!("  pid:          {pid}");
    }
    println!("  plist:        {PLIST_PATH} ({})", if installed { "present" } else { "absent" });
    println!("  control sock: {sock_status}");
    println!("  log:          /Library/Logs/permitlayer/daemon.log");
    println!("──────────────────────────────────────────────────────────────");
    Ok(())
}

fn read_launchctl_state() -> (&'static str, Option<u32>) {
    let out =
        Command::new("/bin/launchctl").args(["print", &format!("system/{DAEMON_LABEL}")]).output();
    let Ok(o) = out else { return ("unknown", None) };
    if !o.status.success() {
        return ("stopped", None);
    }
    let stdout = String::from_utf8_lossy(&o.stdout);
    let state = stdout.lines().find_map(|l| {
        let t = l.trim_start();
        t.strip_prefix("state = ").map(str::trim)
    });
    let pid: Option<u32> = stdout
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("pid = ").and_then(|s| s.trim().parse().ok()));
    let mapped = match state {
        Some("running") => "running",
        Some(_) => "stopped",
        None => "unknown",
    };
    (mapped, pid)
}

async fn probe_uds_reachability(path: &Path) -> String {
    if !path.exists() {
        return format!("unreachable: socket file missing at {}", path.display());
    }
    match timeout(Duration::from_millis(100), tokio::net::UnixStream::connect(path)).await {
        Ok(Ok(_)) => format!("reachable ({})", path.display()),
        Ok(Err(e)) => format!("unreachable: {e}"),
        Err(_) => format!("unreachable: connect timed out (>100ms) at {}", path.display()),
    }
}
