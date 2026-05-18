//! `agentsso update` — version-drift detector (no in-place swap).
//!
//! **UX-overhaul epic (Story 3, issue #58).** This command used to
//! download → minisign-verify → atomically swap the running binary.
//! That model produced the exact failure #58 reports: it queried
//! GitHub's `/releases/latest`, which excludes every prerelease, and
//! *all* `permitlayer` releases are prereleases — so the self-updater
//! could never find anything and silently no-op'd while the operator
//! believed it worked.
//!
//! The install/upgrade keystone is now `brew upgrade agentsso && sudo
//! agentsso setup` (Story 2's versioned-symlink + minisign-verify
//! path). `agentsso update` is demoted to a **three-way drift
//! report**: it compares
//!
//! 1. the **CLI** binary's own `CARGO_PKG_VERSION` (this process),
//! 2. the **latest published release** on GitHub (highest semver
//!    among non-draft tags — see [`github::select_latest`]), and
//! 3. the **running daemon**'s `whoami.version` over the control UDS,
//!
//! prints the exact remediation, and exits non-zero when any pair
//! disagrees so scripts and `doctor` can react. `--apply` is now a
//! hard error that points at the supported upgrade path; it never
//! mutates the filesystem.
//!
//! On-disk schema migration (the `migrations/` framework) moved to
//! the daemon boot path (`cli::start::run`) — see `cli::migrations`.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Args;

use crate::cli::kill::{self, ControlEndpoint};
use crate::design::render;
use crate::design::terminal::ColorSupport;

mod github;

// ── Typed exit-code markers ─────────────────────────────────────────
//
// Drift detection only needs two non-success codes now that the
// apply/swap/migration path is gone. Same downcast pattern as
// `uninstall`/`rotate-key` so `main.rs::update_to_exit_code` can
// route without a fragile substring scan.

/// Exit-code 3 marker — caller asked for a removed capability
/// (`--apply`) or the binary is package-manager-managed; the command
/// has redirected them to the supported upgrade path and changed
/// nothing.
#[derive(Debug)]
pub(crate) struct UpdateExitCode3;

impl std::fmt::Display for UpdateExitCode3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("update: redirected to supported upgrade path")
    }
}

impl std::error::Error for UpdateExitCode3 {}

/// Exit-code 4 marker — actionable non-success: version drift was
/// detected, OR the latest-release query failed. Both mean "this
/// host is not known-current"; a script/CI gate should treat either
/// as "needs attention" rather than success.
#[derive(Debug)]
pub(crate) struct UpdateExitCode4;

impl std::fmt::Display for UpdateExitCode4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("update: drift detected or release check failed")
    }
}

impl std::error::Error for UpdateExitCode4 {}

fn exit3() -> anyhow::Error {
    anyhow::Error::new(UpdateExitCode3).context(crate::cli::SilentCliError)
}

fn exit4() -> anyhow::Error {
    anyhow::Error::new(UpdateExitCode4).context(crate::cli::SilentCliError)
}

// ── Glyph helpers (mirror cli::uninstall) ───────────────────────────

struct Glyphs {
    arrow: &'static str,
    check: &'static str,
    warn: &'static str,
}

fn glyphs() -> Glyphs {
    match ColorSupport::detect() {
        ColorSupport::NoColor => Glyphs { arrow: "->", check: "[ok]", warn: "[!]" },
        _ => Glyphs {
            arrow: "\u{2192}", // →
            check: "\u{2713}", // ✓
            warn: "\u{26A0}",  // ⚠
        },
    }
}

// ── CLI args ────────────────────────────────────────────────────────

/// Arguments for `agentsso update`.
#[derive(Args, Debug, Default, Clone)]
pub struct UpdateArgs {
    /// REMOVED. `agentsso update` no longer swaps the binary in
    /// place. Passing `--apply` prints the supported upgrade command
    /// and exits non-zero without changing anything.
    #[arg(long)]
    pub apply: bool,

    /// Accepted for backward-compatible invocation only; ignored.
    /// The drift report is read-only and never prompts.
    #[arg(long, hide = true)]
    pub yes: bool,

    /// Accepted for backward-compatible invocation only; ignored.
    #[arg(long, hide = true)]
    pub non_interactive: bool,
}

// ── Entry point ─────────────────────────────────────────────────────

/// Run the `update` subcommand.
pub async fn run(args: UpdateArgs) -> Result<()> {
    let _guards =
        crate::telemetry::init_tracing("info", None, 30).context("tracing init failed")?;

    if args.apply {
        eprint!(
            "{}",
            render::error_block(
                "update_apply_removed",
                "`agentsso update --apply` was removed. In-place binary swap is no \
                 longer how agentsso upgrades — it caused silent stale-daemon and \
                 broken-prerelease-delivery failures (issue #58).",
                "brew upgrade agentsso && sudo agentsso setup",
                None,
            )
        );
        return Err(exit3());
    }

    run_drift_report().await
}

// ── Three-way drift report ──────────────────────────────────────────

/// What we learned about the running daemon.
enum DaemonState {
    /// Daemon answered `whoami` with this version string.
    Running { version: String },
    /// Daemon is not reachable over the control plane (not running,
    /// not installed, or control token missing). Not an error for
    /// the report — it IS a finding.
    Unreachable { why: String },
}

async fn run_drift_report() -> Result<()> {
    let g = glyphs();
    let cli_version = env!("CARGO_PKG_VERSION").to_owned();

    // Best-effort audit emission — we have a home dir + audit store
    // even when the daemon isn't running.
    let home = super::agentsso_home()?;
    let audit_store = build_audit_store(&home).await.ok();

    // 1. Latest published release.
    let latest = match github::fetch_latest_release(&cli_version).await {
        Ok(r) => Some(r),
        Err(e) => {
            tracing::warn!(target: "update", error = %e, "latest-release query failed");
            None
        }
    };
    let latest_version = latest.as_ref().map(|r| r.version().to_owned());
    let latest_is_prerelease = latest.as_ref().map(|r| r.prerelease).unwrap_or(false);
    let latest_name = latest.as_ref().and_then(|r| r.name.clone());
    let latest_published = latest.as_ref().and_then(|r| r.published_at.clone());

    // 2. Running daemon version over the control UDS (best-effort —
    //    unreachable is a finding, not a failure of this command).
    let daemon = probe_daemon_version(&home).await;

    // 3. Render the report.
    println!();
    println!("{} agentsso version drift report", g.arrow);
    println!("    CLI (this binary):    {cli_version}");
    match &latest_version {
        Some(v) => {
            let tag = if latest_is_prerelease { " (prerelease)" } else { "" };
            println!("    latest release:       {v}{tag}");
            if let Some(name) = &latest_name {
                println!("      title:              {name}");
            }
            if let Some(pub_at) = &latest_published {
                println!("      published:          {pub_at}");
            }
        }
        None => println!("    latest release:       {} unknown (GitHub query failed)", g.warn),
    }
    match &daemon {
        DaemonState::Running { version } => {
            println!("    running daemon:       {version}");
        }
        DaemonState::Unreachable { why } => {
            println!("    running daemon:       {} unreachable ({why})", g.warn);
        }
    }
    println!();

    // Drift analysis. Any disagreement among the three known values
    // is drift; an unknown latest or an unreachable daemon is also a
    // non-success finding (the host is not provably current).
    let daemon_version = match &daemon {
        DaemonState::Running { version } => Some(version.clone()),
        DaemonState::Unreachable { .. } => None,
    };

    let mut findings: Vec<String> = Vec::new();

    if let Some(latest_v) = &latest_version {
        if github::compare_versions(&cli_version, latest_v) == std::cmp::Ordering::Less {
            findings.push(format!("CLI {cli_version} is behind the latest release {latest_v}"));
        }
        if let Some(dv) = &daemon_version
            && github::compare_versions(dv, latest_v) == std::cmp::Ordering::Less
        {
            findings.push(format!("running daemon {dv} is behind the latest release {latest_v}"));
        }
    } else {
        findings.push("could not determine the latest published release".to_owned());
    }

    if let Some(dv) = &daemon_version {
        if dv != &cli_version {
            findings.push(format!(
                "CLI {cli_version} and running daemon {dv} disagree (restart-after-upgrade gap)"
            ));
        }
    } else if let DaemonState::Unreachable { why } = &daemon {
        findings.push(format!("running daemon is not reachable: {why}"));
    }

    emit_drift_report(
        audit_store.as_deref(),
        &cli_version,
        latest_version.as_deref(),
        daemon_version.as_deref(),
        &findings,
    )
    .await;

    if findings.is_empty() {
        println!("{} no drift  {} CLI, latest release, and daemon all agree", g.arrow, g.check);
        return Ok(());
    }

    println!("{} drift detected:", g.warn);
    for f in &findings {
        println!("    - {f}");
    }
    println!();
    println!("{} remediation:", g.arrow);
    println!("    1. brew upgrade agentsso          # update the CLI/binary");
    println!(
        "    2. sudo agentsso setup            # re-stage + restart the daemon, version-verified"
    );
    println!(
        "    (curl|sh install path: re-run the installer from https://github.com/permitlayer/permitlayer, then `sudo agentsso setup`)"
    );
    println!();

    // Non-zero exit so scripts / `doctor` notice. SilentCliError is
    // attached so main.rs doesn't print a duplicate generic error
    // line on top of the structured report above.
    Err(exit4())
}

/// Probe the running daemon's `whoami.version` over the control
/// endpoint. Unreachable is reported as a [`DaemonState`], not an
/// `Err` — a down daemon is a legitimate (and useful) finding for a
/// drift report.
async fn probe_daemon_version(home: &Path) -> DaemonState {
    use crate::config::{CliOverrides, DaemonConfig};

    let config = DaemonConfig::load(&CliOverrides::default()).unwrap_or_default();
    let endpoint = kill::resolve_control_endpoint(&config);
    let control_token = kill::read_control_token(home);

    match kill::http_get_via(&endpoint, "/v1/control/whoami", control_token.as_deref()).await {
        Ok(body) => match parse_whoami_version(&body) {
            Some(version) => DaemonState::Running { version },
            None => DaemonState::Unreachable {
                why: "control plane responded but the whoami body had no version field".to_owned(),
            },
        },
        // Endpoint match mirrors `kill::ControlEndpoint`'s own
        // exhaustiveness shape: `Tcp` is unconditional, `Uds` is
        // `cfg(unix)`-gated (no constructor on non-Unix).
        Err(_) => DaemonState::Unreachable {
            why: match endpoint {
                ControlEndpoint::Tcp(addr) => {
                    format!("control endpoint {addr} not answering — daemon not running")
                }
                #[cfg(unix)]
                ControlEndpoint::Uds(_) => {
                    "control UDS not answering — daemon not running or not installed".to_owned()
                }
            },
        },
    }
}

/// Pull `version` out of a `/v1/control/whoami` JSON body. The
/// server-side `WhoamiResponse` is `Serialize`-only, so the client
/// parses with `serde_json::Value` rather than sharing the struct.
fn parse_whoami_version(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get("version")?.as_str().map(str::to_owned)
}

// ── Audit emission ──────────────────────────────────────────────────
//
// Additive `event_type`; reuses the v2 schema (audit/event.rs:30
// commits to forward-compat for additive fields). The apply-flow
// events are gone with the apply flow.

async fn build_audit_store(home: &Path) -> Result<Arc<dyn permitlayer_core::store::AuditStore>> {
    use permitlayer_core::scrub::{ScrubEngine, builtin_rules};
    use permitlayer_core::store::fs::AuditFsStore;

    let scrub_engine = Arc::new(
        ScrubEngine::new(builtin_rules().to_vec())
            .map_err(|e| anyhow::anyhow!("scrub engine creation failed: {e}"))?,
    );
    let audit_dir = home.join("audit");
    let store = AuditFsStore::new(audit_dir, 100_000_000, scrub_engine)
        .map_err(|e| anyhow::anyhow!("audit store creation failed: {e}"))?;
    Ok(Arc::new(store))
}

async fn emit_drift_report(
    store: Option<&dyn permitlayer_core::store::AuditStore>,
    cli_version: &str,
    latest_version: Option<&str>,
    daemon_version: Option<&str>,
    findings: &[String],
) {
    let extra = serde_json::json!({
        "cli_version": cli_version,
        "latest_version": latest_version,
        "daemon_version": daemon_version,
        "drift_detected": !findings.is_empty(),
        "findings": findings,
    });
    let outcome = if findings.is_empty() { "ok" } else { "drift" };
    let mut event = permitlayer_core::audit::event::AuditEvent::new(
        "cli".into(),
        "update".into(),
        String::new(),
        "update".into(),
        outcome.into(),
        "update-drift-report".into(),
    );
    event.extra = extra;
    if let Some(s) = store
        && let Err(e) = s.append(event).await
    {
        tracing::warn!(target: "update", error = %e, "audit emit failed (best-effort)");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn typed_exit_markers_implement_error() {
        let e: Box<dyn std::error::Error> = Box::new(UpdateExitCode3);
        assert!(e.to_string().contains("redirected"));
        let e: Box<dyn std::error::Error> = Box::new(UpdateExitCode4);
        assert!(e.to_string().contains("drift"));
    }

    #[test]
    fn parse_whoami_version_extracts_version() {
        let body = r#"{"pid":1234,"version":"0.3.0-rc.36"}"#;
        assert_eq!(parse_whoami_version(body), Some("0.3.0-rc.36".to_owned()));
    }

    #[test]
    fn parse_whoami_version_none_on_missing_field() {
        assert_eq!(parse_whoami_version(r#"{"pid":1}"#), None);
        assert_eq!(parse_whoami_version("not json"), None);
        // version present but not a string
        assert_eq!(parse_whoami_version(r#"{"version":42}"#), None);
    }
}
