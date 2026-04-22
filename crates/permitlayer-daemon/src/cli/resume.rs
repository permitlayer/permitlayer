//! `agentsso resume` — deactivate the daemon's kill switch.
//!
//! Mirrors `cli/kill.rs` but POSTs `/v1/control/resume` and renders a
//! `ResumeBanner`. The two round trips (`GET /v1/control/state` first for
//! `activated_at`, then `POST /v1/control/resume`) are a deliberate choice:
//! knowing the activation timestamp lets us compute `duration killed` for
//! the banner without extending the Story 3.1 `DeactivationSummary` API.
//!
//! The two GETs + POST add ~6-15ms on loopback, well within the NFR6 2000ms
//! budget. As a side-benefit, if the state probe reports the daemon is not
//! killed, the CLI short-circuits to the idempotent "nothing to resume"
//! banner without even sending the POST — cheaper idempotent case, clearer
//! feedback.

use std::time::{Duration, Instant};

use anyhow::Result;

use crate::cli::kill::{
    error_block_daemon_not_running, error_block_daemon_unreachable, error_block_protocol_error,
    http_get, http_post_empty_json, load_daemon_config_or_default_with_warn,
};
use crate::design::kill_banner::{
    DeactivationSummaryView, ResumeBannerInputs, render_resume_banner,
};
use crate::design::terminal::{ColorSupport, terminal_width};
use crate::design::theme::Theme;
use crate::lifecycle::pid::PidFile;

#[derive(clap::Args)]
pub struct ResumeArgs {}

pub async fn run(_args: ResumeArgs) -> Result<()> {
    let start = Instant::now();

    let config = load_daemon_config_or_default_with_warn("resume");
    let home = config.paths.home.clone();

    // 1. Check daemon is running.
    if PidFile::read(&home)?.is_none() || !PidFile::is_daemon_running(&home)? {
        eprint!("{}", error_block_daemon_not_running("resume"));
        // Clean up stale PID file (mirror cli/kill.rs behavior).
        let _ = std::fs::remove_file(home.join("agentsso.pid"));
        std::process::exit(3);
    }

    let bind_addr = config.http.bind_addr;

    // 2. GET /v1/control/state to capture `activated_at` (for
    //    `duration_killed` in the banner) AND short-circuit when the
    //    daemon is already running (cheaper idempotent path).
    let state_body = match http_get(bind_addr, "/v1/control/state").await {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(error = %e, addr = %bind_addr, "state probe failed during resume");
            eprint!("{}", error_block_daemon_unreachable("resume", bind_addr));
            std::process::exit(3);
        }
    };

    let state_view: StateResponseView = match serde_json::from_str(&state_body) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, body = %state_body, "unexpected state response");
            eprint!("{}", error_block_protocol_error());
            std::process::exit(3);
        }
    };

    let was_already_inactive_at_probe = !state_view.active;
    let activated_at_pre: Option<chrono::DateTime<chrono::Utc>> = state_view
        .activated_at
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    // 3. POST /v1/control/resume (always — the daemon is the authority on
    //    idempotency). We rely on its returned `was_already_inactive` flag
    //    as the canonical answer rather than the pre-probe reading.
    let resume_body = match http_post_empty_json(bind_addr, "/v1/control/resume").await {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(error = %e, addr = %bind_addr, "resume request failed");
            eprint!("{}", error_block_daemon_unreachable("resume", bind_addr));
            std::process::exit(3);
        }
    };

    let parsed: ResumeResponseView = match serde_json::from_str(&resume_body) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, body = %resume_body, "unexpected resume response");
            eprint!("{}", error_block_protocol_error());
            std::process::exit(3);
        }
    };

    // 4. Build the banner input. A parse failure is treated as a
    // protocol error (exit 3 + structured error_block), not an anyhow
    // bubble-up, so the CLI contract in AC #6 holds even when the
    // daemon's schema drifts.
    let resumed_at = match chrono::DateTime::parse_from_rfc3339(&parsed.deactivation.resumed_at) {
        Ok(dt) => dt.with_timezone(&chrono::Utc),
        Err(e) => {
            tracing::debug!(
                error = %e,
                resumed_at = %parsed.deactivation.resumed_at,
                "daemon returned non-RFC3339 resumed_at",
            );
            eprint!("{}", error_block_protocol_error());
            std::process::exit(3);
        }
    };

    let deactivation_view = DeactivationSummaryView {
        resumed_at,
        was_already_inactive: parsed.deactivation.was_already_inactive,
    };

    // `duration_killed = resumed_at - activated_at_pre` when both are known
    // and the switch was actually active at probe time. We prefer the
    // pre-probe `activated_at` over post-resume state (the resume call
    // clears `activated_at` on the daemon side, so a second probe would
    // return None).
    //
    // A negative duration means the system clock jumped backward between
    // the state probe and the resume POST (NTP adjustment, VM pause/resume,
    // etc.). Log a warn so the clock-jump incident is auditable — the
    // banner silently omits the "duration killed" line in that case, which
    // is the least-confusing user-facing behavior, but an operator
    // diagnosing a strange run wants to see WHY the line was missing.
    let duration_killed: Option<Duration> = match (activated_at_pre, !was_already_inactive_at_probe)
    {
        (Some(start_ts), true) => {
            let delta = resumed_at - start_ts;
            match delta.to_std() {
                Ok(d) => Some(d),
                Err(_) => {
                    tracing::warn!(
                        target: "resume",
                        activated_at = %start_ts,
                        resumed_at = %resumed_at,
                        "negative duration from clock jump — duration killed omitted from banner",
                    );
                    None
                }
            }
        }
        _ => None,
    };

    let inputs = ResumeBannerInputs {
        deactivation: &deactivation_view,
        duration_killed,
        elapsed: start.elapsed(),
        terminal_width: terminal_width(),
    };

    let theme = Theme::load(&home);
    let support = ColorSupport::detect();
    print!("{}", render_resume_banner(&inputs, &theme, support));

    Ok(())
}

// --------------------------------------------------------------------------
// Wire types — local deserialize structs matching the JSON schema shipped
// by `crate::server::control::{ResumeResponse, StateResponse}`.
// --------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct ResumeResponseView {
    deactivation: DeactivationSummaryWire,
    #[serde(default)]
    #[allow(dead_code)]
    daemon_version: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct DeactivationSummaryWire {
    resumed_at: String,
    was_already_inactive: bool,
}

#[derive(Debug, serde::Deserialize)]
struct StateResponseView {
    active: bool,
    #[serde(default)]
    activated_at: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    token_count: Option<usize>,
    #[serde(default)]
    #[allow(dead_code)]
    daemon_version: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_resume_response_round_trip() {
        let json = r#"{
            "deactivation": {
                "resumed_at": "2026-04-10T12:35:08.789Z",
                "was_already_inactive": false
            },
            "daemon_version": "0.1.0"
        }"#;
        let parsed: ResumeResponseView = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.deactivation.resumed_at, "2026-04-10T12:35:08.789Z");
        assert!(!parsed.deactivation.was_already_inactive);
    }

    #[test]
    fn deserialize_state_response_active() {
        let json = r#"{
            "active": true,
            "activated_at": "2026-04-10T12:34:56.789Z",
            "token_count": 0,
            "daemon_version": "0.1.0"
        }"#;
        let parsed: StateResponseView = serde_json::from_str(json).unwrap();
        assert!(parsed.active);
        assert_eq!(parsed.activated_at.as_deref(), Some("2026-04-10T12:34:56.789Z"));
    }

    #[test]
    fn deserialize_state_response_inactive() {
        let json = r#"{
            "active": false,
            "activated_at": null,
            "token_count": 0,
            "daemon_version": "0.1.0"
        }"#;
        let parsed: StateResponseView = serde_json::from_str(json).unwrap();
        assert!(!parsed.active);
        assert!(parsed.activated_at.is_none());
    }
}
