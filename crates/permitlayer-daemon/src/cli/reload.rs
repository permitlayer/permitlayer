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
    #[serde(default)]
    policy_scan_path: String,
    #[serde(default)]
    policy_scan_empty_warning: Option<String>,
    #[serde(default)]
    config_reload_error: Option<String>,
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

/// The reload success headline. Pure so the "one outcome, not six facts"
/// shape is unit-testable without capturing stdout.
fn reload_headline(policies_loaded: usize, agents_loaded: usize) -> String {
    format!("reload OK ({policies_loaded} policies, {agents_loaded} agents)")
}

/// Parse and display the JSON response from `/v1/control/reload`.
///
/// Returns `Ok(())` on success, or an `Err` with a non-zero exit code
/// suggestion on failure. Avoids calling `process::exit` directly so
/// the function is testable.
fn handle_reload_response(body: &str) -> Result<()> {
    // Try the success shape first.
    if let Ok(resp) = serde_json::from_str::<ReloadResponseView>(body) {
        // Rule of Silence + hierarchy: one outcome headline, then at most
        // one secondary diff line — not six facts crammed into the
        // headline with `·` separators.
        let support = crate::design::terminal::ColorSupport::detect();
        let theme = crate::design::theme::Theme::default();
        print!(
            "{}",
            crate::design::render::success_headline(
                &reload_headline(resp.policies_loaded, resp.agents_loaded),
                &theme,
                support,
            )
        );
        // Secondary detail (dim): the diff, only when something actually
        // changed (a pure no-op reload doesn't need the zeros), plus the
        // scanned path when present.
        let changed = resp.added + resp.modified + resp.removed > 0;
        let mut detail: Vec<String> = Vec::new();
        if changed {
            detail.push(format!(
                "changes: {} added, {} modified, {} unchanged, {} removed",
                resp.added, resp.modified, resp.unchanged, resp.removed
            ));
        }
        if !resp.policy_scan_path.is_empty() {
            detail.push(format!("scanned: {}", resp.policy_scan_path));
        }
        if !detail.is_empty() {
            let refs: Vec<&str> = detail.iter().map(String::as_str).collect();
            print!("{}", crate::design::render::detail_block(&refs, &theme, support));
        }
        // Real warnings stay on stderr as their own warning lines (not
        // appended to the success headline).
        if let Some(warn) = resp.policy_scan_empty_warning {
            eprintln!("  warning: {warn}");
        }
        if let Some(err) = resp.config_reload_error {
            eprintln!("  warning: config reload failed — {err}");
        }
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn reload_headline_is_one_outcome_not_six_facts() {
        // Rule of Silence: the headline names the outcome + the two
        // top-line counts, NOT the full added/modified/unchanged/removed
        // diff (that moved to a secondary detail line).
        let h = reload_headline(3, 5);
        assert_eq!(h, "reload OK (3 policies, 5 agents)");
        // The diff stats must NOT be in the headline.
        assert!(!h.contains("added"));
        assert!(!h.contains("modified"));
        assert!(!h.contains("removed"));
    }
}
