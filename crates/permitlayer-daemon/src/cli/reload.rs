//! `agentsso reload` — trigger a hot-swap reload of daemon config and policies.
//!
//! Story 4.2 upgraded this from a fire-and-forget SIGHUP sender to a
//! control-plane HTTP POST to `POST /v1/control/reload`, which returns
//! a JSON response with the policy diff so the CLI can display what
//! changed. Falls back to SIGHUP on connection failure (backward compat
//! with older daemons that don't have the endpoint) or on non-Unix
//! platforms (where SIGHUP isn't available and the control endpoint is
//! the only reload path).

use anyhow::Result;
use serde::Deserialize;

use crate::cli::kill::{
    http_post_empty_json_via, load_daemon_config_or_default_with_warn, resolve_control_endpoint,
};
use crate::lifecycle::pid::PidFile;

/// Deserialization target for the JSON body of a successful
/// `POST /v1/control/reload` response.
///
/// `agents_loaded` uses `#[serde(default)]` so older daemons that
/// pre-date Story 4.4 (and therefore don't emit the field) still
/// parse cleanly. In that case the CLI renders "0 agents".
#[derive(Debug, Deserialize)]
struct ReloadResponseView {
    #[allow(dead_code)]
    status: String,
    policies_loaded: usize,
    added: usize,
    modified: usize,
    unchanged: usize,
    removed: usize,
    #[serde(default)]
    agents_loaded: usize,
}

/// Deserialization target for the JSON body of a failed
/// `POST /v1/control/reload` response.
#[derive(Debug, Deserialize)]
struct ReloadErrorView {
    #[allow(dead_code)]
    status: String,
    message: String,
}

pub async fn run() -> Result<()> {
    let config = load_daemon_config_or_default_with_warn("reload");
    let home = config.paths.home.clone();

    // No PID-file pre-check — Plan B's operator-token auth on
    // `/v1/control/*` is the canonical gate. The HTTP path's failure
    // mode handles the genuine "no daemon" case (and the SIGHUP
    // fallback below handles backward-compat with pre-Story-4.2 daemons).

    let endpoint = resolve_control_endpoint(&config);
    let _bind_addr = config.http.bind_addr;
    let token = crate::cli::kill::read_control_token(&home);
    match http_post_empty_json_via(&endpoint, "/v1/control/reload", token.as_deref()).await {
        Ok(body) => handle_reload_response(&body)?,
        Err(_) => {
            // Control endpoint unavailable — fall back to SIGHUP.
            // This covers backward compat with daemons that predate
            // Story 4.2 (no /v1/control/reload endpoint) and also
            // covers connection-refused when the daemon is starting up.
            tracing::debug!(
                endpoint = %endpoint,
                "control endpoint unavailable, falling back to SIGHUP"
            );
            send_sighup_fallback(&home)?;
        }
    }

    Ok(())
}

/// Parse and display the JSON response from `/v1/control/reload`.
///
/// Returns `Ok(())` on success, or an `Err` with a non-zero exit code
/// suggestion on failure. Avoids calling `process::exit` directly so
/// the function is testable.
fn handle_reload_response(body: &str) -> Result<()> {
    // Try the success shape first.
    if let Ok(resp) = serde_json::from_str::<ReloadResponseView>(body) {
        println!(
            "\u{2713} {} policies, {} agents loaded \u{00b7} {} policy added, {} modified, {} unchanged, {} removed",
            resp.policies_loaded,
            resp.agents_loaded,
            resp.added,
            resp.modified,
            resp.unchanged,
            resp.removed
        );
        return Ok(());
    }

    // Try the error shape.
    if let Ok(err) = serde_json::from_str::<ReloadErrorView>(body) {
        eprintln!("error: policy reload failed");
        eprintln!("  {}", err.message);
        std::process::exit(2);
    }

    // Unparseable response — protocol mismatch.
    anyhow::bail!("unexpected response from daemon: {body}");
}

/// Send SIGHUP to the daemon as a fallback when the control endpoint
/// is unavailable. This is the pre-Story-4.2 behavior.
fn send_sighup_fallback(home: &std::path::Path) -> Result<()> {
    let pid = match PidFile::read(home)? {
        Some(pid) => pid,
        None => {
            eprintln!("daemon not running (no PID file)");
            std::process::exit(3);
        }
    };

    let raw_pid = match i32::try_from(pid) {
        Ok(p) if p > 0 => p,
        _ => {
            eprintln!("invalid PID {pid} in PID file (out of range)");
            std::process::exit(3);
        }
    };

    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        kill(Pid::from_raw(raw_pid), Signal::SIGHUP)?;
        println!("configuration reload requested (PID {pid})");
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = raw_pid;
        eprintln!(
            "reload command is not supported on this platform (no SIGHUP) and the control endpoint is unavailable"
        );
        std::process::exit(1);
    }
}
