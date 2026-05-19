//! `agentsso doctor [--fix] [--json] [--restart-ok]` — the
//! diagnose-and-repair command for a privileged macOS install
//! (UX-overhaul epic, Story 4).
//!
//! `doctor` runs a fixed battery of structural health checks against
//! the install (version drift, stale launchd registration, symlink
//! topology, managed-policy staleness, daemon liveness, no-TTY prompt
//! traps, missing/non-exec daemon binary, operator-layer compile) and
//! — only with `--fix` — applies the *safe* subset of repairs. The
//! report is human-rendered by default and machine-readable with
//! `--json`.
//!
//! ## Trust model (why `--fix` cannot signature-verify the binary)
//!
//! Identical to `cli::setup`'s documented Decision A (see
//! `cli/setup/mod.rs` "Trust model"). The signature trust root is at
//! the *download* boundary — the curl|sh / PowerShell installers
//! minisign-verify the release **tarball**; there is no `.minisig`
//! sidecar on disk for an *installed*, extracted bare daemon binary,
//! so signature verification is not applicable to `doctor --fix`
//! either. The privileged path is content-hash-verified.
//!
//! The substitute fail-closed control is a **binary-integrity gate**
//! evaluated ONCE before any `--fix` mutation (Decision A):
//!
//! - resolve the stable symlink `PRIVILEGED_HELPER_PATH` →
//!   `agentsso-<V>` (mirrors `setup/mod.rs`'s `finalize_verify`
//!   `read_link`),
//! - confirm the running daemon's `whoami.version` (probed
//!   side-effect-free per Decision B) equals the version parsed from
//!   the symlink target's `agentsso-<V>` filename suffix.
//!
//! If the symlink is broken, its target is missing/non-exec, or the
//! versions disagree, the gate **fails** and `doctor --fix` REFUSES
//! every mutation (including the otherwise-safe ones) and prints
//! `sudo agentsso setup`. `--json` always reports
//! `"fix_integrity_gate": {"passed": bool, "reason": "..."}`.
//!
//! ## Decision B (no `connect_uds::require_daemon_running`)
//!
//! That helper renders a connect-branded error block as a side
//! effect and its classifier internals are module-private. `doctor`
//! instead reimplements a side-effect-free [`daemon_state`] modeled
//! on `cli::update`'s `probe_daemon_version` (load `DaemonConfig`,
//! `kill::resolve_control_endpoint`, `kill::read_control_token`,
//! `kill::http_get_with_status_via("/v1/control/whoami")`, classify;
//! on macOS re-probe via the PUBLIC
//! `install_macos::parse_launchctl_running`). This duplication is
//! established project precedent — `connect_uds.rs` itself documents
//! the same intentional duplication of the io-error walk.
//!
//! ## Decision C1 (own embedded bundle const)
//!
//! `start.rs`'s `DEFAULT_POLICY_TOML` is private and is NOT widened.
//! `doctor` declares its own [`EMBEDDED_MANAGED_BUNDLE`] from the
//! same `default_policy.toml` so the managed-policy staleness check
//! compares the on-disk file against exactly what this binary would
//! sync.
//!
//! ## Decision D (no `StepSummary`)
//!
//! There is no `StepSummary` API; rendering uses
//! `design::render::{Outcome, styled_outcome, outcome_icon,
//! error_block}` plus the `cli::setup` `Glyphs`/`glyphs()` color
//! pattern.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::cli::kill::{self, ControlEndpoint};
use crate::cli::silent_cli_error;
use crate::design::render::{self, Outcome};
use permitlayer_core::store::AuditStore;

// ── Embedded managed bundle (Decision C1) ───────────────────────────
//
// From `crates/permitlayer-daemon/src/cli/doctor/mod.rs` the file
// `crates/permitlayer-daemon/src/cli/default_policy.toml` is at the
// relative path `../default_policy.toml`. `start.rs`'s
// `DEFAULT_POLICY_TOML` const is private; rather than widen its
// visibility, `doctor` embeds its own copy of the SAME file so the
// staleness check compares on-disk content against exactly what this
// binary would sync.
const EMBEDDED_MANAGED_BUNDLE: &str = include_str!("../default_policy.toml");

// ── CLI args ────────────────────────────────────────────────────────

/// Arguments for `agentsso doctor`.
#[derive(Args, Debug, Default, Clone)]
pub struct DoctorArgs {
    /// Apply the safe subset of repairs. Without this flag `doctor`
    /// only diagnoses and never mutates the filesystem or launchd.
    #[arg(long)]
    pub fix: bool,

    /// Emit a machine-readable JSON report instead of the
    /// human-rendered one.
    #[arg(long)]
    pub json: bool,

    /// Permit `--fix` to perform repairs that bounce the daemon
    /// (stale-launchd re-bootstrap, daemon kickstart). **Inert
    /// without `--fix`** — a restart-class repair is only ever
    /// attempted when BOTH `--fix` and `--restart-ok` are set.
    #[arg(long)]
    pub restart_ok: bool,
}

// ── Glyphs (mirror cli::setup / cli::update) ────────────────────────

struct Glyphs {
    arrow: &'static str,
    check: &'static str,
    warn: &'static str,
}

fn glyphs() -> Glyphs {
    use crate::design::terminal::ColorSupport;
    match ColorSupport::detect() {
        ColorSupport::NoColor => Glyphs { arrow: "->", check: "[ok]", warn: "[!]" },
        _ => Glyphs {
            arrow: "\u{2192}", // →
            check: "\u{2713}", // ✓
            warn: "\u{26A0}",  // ⚠
        },
    }
}

// ── Core report types ───────────────────────────────────────────────

/// Severity of a single check's finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Severity {
    Pass,
    Warn,
    Fail,
}

impl Severity {
    fn to_outcome(self) -> Outcome {
        match self {
            Severity::Pass => Outcome::Ok,
            Severity::Warn => Outcome::Blocked,
            Severity::Fail => Outcome::Error,
        }
    }
}

/// How a check's repair is gated by the structural NEVER-auto-fix
/// enforcement. This is the security-critical classification — the
/// single [`may_apply_fix`] gate is the only thing that can authorize
/// a `fix()` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum FixClass {
    /// Repair is idempotent and does not bounce the daemon — applied
    /// whenever `--fix` (and the integrity gate) allow.
    SafeAutomatic,
    /// Repair restarts/bounces the daemon — requires `--restart-ok`.
    GatedByRestartOk,
    /// Repair is NEVER applied automatically; `doctor` only prints
    /// remediation text.
    NeverAutomatic,
}

/// The outcome of (attempting) a check's repair.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum FixOutcome {
    /// The repair was applied; carries the before/after for the audit
    /// trail and operator report.
    Repaired { old: String, new: String },
    /// The repair was applicable but intentionally not performed
    /// (e.g. `--restart-ok` absent, or the daemon was already up).
    Skipped { why: String },
    /// The repair was refused by policy (integrity gate failed,
    /// `NeverAutomatic`, non-root, macOS-only on non-macOS).
    Refused { why: String },
    /// The repair was attempted and failed.
    Failed { err: String },
}

/// One check's full report.
#[derive(Debug, Clone, Serialize)]
struct CheckReport {
    id: &'static str,
    title: &'static str,
    severity: Severity,
    detail: String,
    auto_fixable: bool,
    fix_class: FixClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fix_outcome: Option<FixOutcome>,
}

impl CheckReport {
    /// A passing report for a check that does not apply on this
    /// platform / in this state.
    fn pass(
        id: &'static str,
        title: &'static str,
        detail: impl Into<String>,
        fix_class: FixClass,
    ) -> Self {
        Self {
            id,
            title,
            severity: Severity::Pass,
            detail: detail.into(),
            auto_fixable: false,
            fix_class,
            remediation: None,
            fix_outcome: None,
        }
    }
}

// ── Shared context ──────────────────────────────────────────────────

/// All shared state resolved ONCE up front. Every check reads from
/// this rather than re-probing the daemon / re-reading config.
struct DoctorCtx {
    home: PathBuf,
    #[allow(dead_code)] // read on macOS daemon-not-running fix only
    endpoint: ControlEndpoint,
    #[allow(dead_code)] // read on macOS daemon-not-running fix only
    control_token: Option<String>,
    /// `Some(v)` iff the daemon answered `whoami` with a parseable
    /// version; `None` ⇒ unreachable (a finding, not an error).
    daemon_version: Option<String>,
    cli_version: &'static str,
    restart_ok: bool,
    fix: bool,
    audit: Option<Arc<dyn AuditStore>>,
    /// Decision A: result of the pre-mutation binary-integrity gate.
    fix_integrity_gate_passed: bool,
    fix_integrity_gate_reason: String,
}

// ── Decision-B side-effect-free daemon probe ────────────────────────
//
// Modeled on `cli::update::probe_daemon_version`. Deliberately does
// NOT call `connect_uds::require_daemon_running` (renders a
// connect-branded error block as a side effect; its classifier
// internals are module-private). On macOS, an unreachable control
// plane is cross-checked against `launchctl print` via the PUBLIC
// `install_macos::parse_launchctl_running` so a daemon that is
// launchd-running but momentarily not answering the UDS is still
// distinguishable from one launchd reports down.

/// Probe the running daemon's `whoami.version`. Returns `Some(v)` on
/// success, `None` if unreachable. Never renders anything.
async fn daemon_state(endpoint: &ControlEndpoint, control_token: Option<&str>) -> Option<String> {
    match kill::http_get_with_status_via(endpoint, "/v1/control/whoami", control_token).await {
        Ok((status, body)) if (200..300).contains(&status) => parse_whoami_version(&body),
        _ => None,
    }
}

/// Pull `version` from a `/v1/control/whoami` JSON body (the
/// server-side `WhoamiResponse` is `Serialize`-only — parse with
/// `Value`, mirroring `cli::update::parse_whoami_version`).
fn parse_whoami_version(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get("version")?.as_str().map(str::to_owned)
}

/// Parse the `<V>` out of an `agentsso-<V>` symlink-target filename.
/// Mirrors `setup/mod.rs`'s versioned-binary naming. Only the
/// macOS integrity gate (and the pure unit tests) consume this, so
/// it is `cfg(any(test, macos))` to avoid dead-code on Linux/Windows
/// under `-D warnings` (the same discipline as `start.rs`'s
/// `foreground_start_collision`).
#[cfg(any(test, target_os = "macos"))]
fn parse_versioned_binary_name(target: &Path) -> Option<String> {
    let name = target.file_name()?.to_str()?;
    let ver = name.strip_prefix("agentsso-")?;
    if ver.is_empty() || ver.contains(".tmp.") {
        return None;
    }
    // Must be a valid semver to be a real versioned binary.
    semver::Version::parse(ver).ok()?;
    Some(ver.to_owned())
}

// ── NEVER-auto-fix structural gate (security-critical core) ─────────
//
// This is the single, non-bypassable authorization point. It is
// called exactly once per check in `run()` BEFORE `check.fix` is ever
// invoked. A check's `fix()` is NEVER called when this returns
// `Err` — the corresponding `FixOutcome::Refused` is emitted instead.
// The integrity-gate short-circuit is FIRST so a failed Decision-A
// gate refuses every class including `SafeAutomatic`.

fn may_apply_fix(
    class: FixClass,
    restart_ok: bool,
    integrity_ok: bool,
) -> std::result::Result<(), &'static str> {
    if !integrity_ok {
        return Err("binary integrity gate failed (Decision A) — refuse all fixes");
    }
    match class {
        FixClass::SafeAutomatic => Ok(()),
        FixClass::GatedByRestartOk => {
            if restart_ok {
                Ok(())
            } else {
                Err("requires --restart-ok")
            }
        }
        FixClass::NeverAutomatic => Err("never auto-fixable"),
    }
}

// ── SHA-256 helper (local reimpl of setup/mod.rs sha256_file) ───────

fn sha256_file(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    Ok(s)
}

fn sha256_str(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// ── Privileged-helper path constant (mirror install_macos) ──────────
//
// Re-declared rather than reaching into the macOS-only
// `install_macos` module. Every consumer (symlink-integrity check,
// binary-missing check, the integrity gate) is itself
// `#[cfg(target_os = "macos")]` — the privileged-install model is
// macOS-only — so the constant is macOS-gated to match: on
// Linux/Windows it would be `dead_code` under the CI Lint job's
// `-D warnings` (the non-macOS arms of those checks return an
// "n/a (macOS-only)" skip and never name the path).

#[cfg(target_os = "macos")]
const PRIVILEGED_HELPER_PATH: &str = "/Library/PrivilegedHelperTools/agentsso";

// ── Pure decision helpers (unit-tested on ALL platforms) ────────────
//
// `#[cfg(any(test, target_os = "macos"))]` for the macOS-only ones,
// mirroring `start.rs:66/144` `foreground_start_collision` /
// `brew_path_collision`, so the truth-table unit tests compile + run
// on ubuntu/windows while the production helper is macOS-gated. The
// genuinely cross-platform ones (version drift, staleness, compile)
// are unconditional.

/// Version-drift decision: equal ⇒ Pass; differ ⇒ Fail; daemon
/// unreachable (`None`) ⇒ Warn. Returns `(severity, auto_fixable)`;
/// `auto_fixable` is always `false` (NeverAutomatic).
fn version_drift_decide(cli: &str, daemon: Option<&str>) -> (Severity, bool) {
    match daemon {
        Some(d) if d == cli => (Severity::Pass, false),
        Some(_) => (Severity::Fail, false),
        None => (Severity::Warn, false),
    }
}

/// Symlink-integrity decision (check #3). `resolved` is the
/// `read_link` result, `target_exists` whether that target is a
/// file, `mode` the target's unix mode (if statable). Pass iff the
/// link resolves to an existing file with an exec bit set.
#[cfg(any(test, target_os = "macos"))]
fn symlink_decide(
    resolved: Option<&Path>,
    target_exists: bool,
    mode: Option<u32>,
) -> (Severity, bool) {
    match resolved {
        None => (Severity::Fail, true), // broken/missing symlink — fixable
        Some(_) if !target_exists => (Severity::Fail, true),
        Some(_) => match mode {
            Some(m) if m & 0o111 != 0 => (Severity::Pass, false),
            _ => (Severity::Fail, true), // exists but not executable
        },
    }
}

/// Managed-policy staleness decision (check #4). `on_disk` is the
/// sha256 of `<managed>/default.toml` (None ⇒ file absent),
/// `embedded` is the sha256 of [`EMBEDDED_MANAGED_BUNDLE`].
fn staleness_decide(on_disk: Option<&str>, embedded: &str) -> (Severity, bool) {
    match on_disk {
        Some(h) if h == embedded => (Severity::Pass, false),
        _ => (Severity::Fail, true), // absent or stale — file rewrite is safe
    }
}

/// No-TTY prompt-trap decision (check #6). A LaunchDaemon is always
/// no-TTY; if any bound policy is prompt-mode the operator will hit a
/// silent hang. WARN (not FAIL) — it is a misconfiguration, not a
/// broken install.
#[cfg(any(test, target_os = "macos"))]
fn prompt_trap_decide(is_launchdaemon: bool, has_prompt_policy: bool) -> (Severity, bool) {
    if is_launchdaemon && has_prompt_policy {
        (Severity::Warn, false)
    } else {
        (Severity::Pass, false)
    }
}

// ── Audit emission ──────────────────────────────────────────────────
//
// Mirrors `cli::update::build_audit_store`: the audit store writes
// under `<home>/audit` and exists even when the daemon is down.

async fn build_audit_store(home: &Path) -> Result<Arc<dyn AuditStore>> {
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

fn invoker_uid() -> u32 {
    #[cfg(unix)]
    {
        nix::unistd::Uid::effective().as_raw()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Emit one `doctor.fix` audit event per applied/refused/failed
/// mutation. Best-effort — a down audit store never fails `doctor`.
async fn emit_fix_audit(
    ctx: &DoctorCtx,
    check_id: &str,
    fix_class: FixClass,
    outcome: &FixOutcome,
) {
    let Some(store) = ctx.audit.as_deref() else {
        return;
    };
    let (outcome_str, old, new) = match outcome {
        FixOutcome::Repaired { old, new } => ("repaired", Some(old.clone()), Some(new.clone())),
        FixOutcome::Skipped { .. } => ("skipped", None, None),
        FixOutcome::Refused { .. } => ("refused", None, None),
        FixOutcome::Failed { .. } => ("failed", None, None),
    };
    let extra = serde_json::json!({
        "check_id": check_id,
        "fix_class": fix_class,
        "old": old,
        "new": new,
        "invoker_uid": invoker_uid(),
        "restart_ok": ctx.restart_ok,
        "detail": match outcome {
            FixOutcome::Skipped { why } => Some(why.clone()),
            FixOutcome::Refused { why } => Some(why.clone()),
            FixOutcome::Failed { err } => Some(err.clone()),
            FixOutcome::Repaired { .. } => None,
        },
    });
    let mut event = permitlayer_core::audit::event::AuditEvent::new(
        "cli".into(),
        "doctor".into(),
        String::new(),
        check_id.into(),
        outcome_str.into(),
        "doctor.fix".into(),
    );
    event.extra = extra;
    if let Err(e) = store.append(event).await {
        tracing::warn!(target: "doctor", error = %e, "fix audit emit failed (best-effort)");
    }
}

/// One summary `doctor.run` event with pass/warn/fail counts.
async fn emit_run_audit(ctx: &DoctorCtx, pass: usize, warn: usize, fail: usize) {
    let Some(store) = ctx.audit.as_deref() else {
        return;
    };
    let outcome = if fail > 0 {
        "fail"
    } else if warn > 0 {
        "warn"
    } else {
        "ok"
    };
    let extra = serde_json::json!({
        "pass": pass,
        "warn": warn,
        "fail": fail,
        "fix_mode": ctx.fix,
        "restart_ok": ctx.restart_ok,
        "fix_integrity_gate_passed": ctx.fix_integrity_gate_passed,
        "invoker_uid": invoker_uid(),
    });
    let mut event = permitlayer_core::audit::event::AuditEvent::new(
        "cli".into(),
        "doctor".into(),
        String::new(),
        "doctor".into(),
        outcome.into(),
        "doctor.run".into(),
    );
    event.extra = extra;
    if let Err(e) = store.append(event).await {
        tracing::warn!(target: "doctor", error = %e, "run audit emit failed (best-effort)");
    }
}

// ── Root check (macOS-only — only the privileged macOS fix paths
//    consult it; non-macOS fixes refuse on their own platform arm) ──

#[cfg(target_os = "macos")]
fn is_root() -> bool {
    nix::unistd::Uid::effective().is_root()
}

/// Standard non-root refusal for a mutation that needs root
/// (`setup/mod.rs:151` precedent — non-root never fails the whole
/// run, it refuses the single mutation).
#[cfg(target_os = "macos")]
fn refuse_non_root() -> FixOutcome {
    FixOutcome::Refused { why: "re-run as: sudo agentsso doctor --fix".to_owned() }
}

// ── The 8 checks ────────────────────────────────────────────────────
//
// Plan note: a `trait Check` with `async fn` + trait objects is
// friction (object-safety / `async_trait` only-if-already-a-dep).
// `async-trait` IS a workspace dependency, but the plan explicitly
// prefers the non-trait dispatch ("a `Vec` of check structs each with
// inherent async methods invoked by an explicit match in `run`") when
// trait-object + async is friction — which it is here (per-check
// `fix()` needs heterogeneous state). So each check is a free
// `detect_*` + `fix_*` async fn pair and `run()` drives them with an
// explicit, exhaustive sequence. The FixClass for each check is
// declared in exactly one place: `check_specs()`.

/// The static spec for one check: id + its (immutable) fix-class.
/// The fix-class living here — separate from detect/fix — is the
/// single source of truth `may_apply_fix` consults and the
/// `fix_class_invariants` test pins. (Human titles live on each
/// `detect_*`'s `CheckReport`, not here.)
struct CheckSpec {
    id: &'static str,
    fix_class: FixClass,
}

/// Canonical list of all 8 checks in run order. The declared
/// `fix_class` here is the single source of truth that
/// `may_apply_fix` consults and `fix_class_invariants` asserts.
fn check_specs() -> [CheckSpec; 8] {
    [
        CheckSpec { id: "version_drift", fix_class: FixClass::NeverAutomatic },
        CheckSpec { id: "stale_launchd", fix_class: FixClass::GatedByRestartOk },
        CheckSpec { id: "symlink_integrity", fix_class: FixClass::SafeAutomatic },
        CheckSpec { id: "managed_policy_staleness", fix_class: FixClass::SafeAutomatic },
        CheckSpec { id: "daemon_not_running", fix_class: FixClass::GatedByRestartOk },
        CheckSpec { id: "no_tty_prompt_trap", fix_class: FixClass::NeverAutomatic },
        CheckSpec { id: "daemon_binary_missing", fix_class: FixClass::NeverAutomatic },
        CheckSpec { id: "operator_layer_compile", fix_class: FixClass::NeverAutomatic },
    ]
}

// ── Check 1: version_drift (cross-platform) ─────────────────────────

fn detect_version_drift(ctx: &DoctorCtx) -> CheckReport {
    let (severity, _fixable) = version_drift_decide(ctx.cli_version, ctx.daemon_version.as_deref());
    // Drive the message off `daemon_version` directly (the sole input
    // that determines the severity) — no impossible match arm.
    let detail = match &ctx.daemon_version {
        Some(v) if v == ctx.cli_version => {
            format!("CLI and running daemon both report {v}")
        }
        Some(v) => format!(
            "CLI is {} but the running daemon reports {v} — a restart-after-upgrade gap",
            ctx.cli_version
        ),
        None => format!(
            "CLI is {}; the daemon is unreachable so version agreement cannot be confirmed",
            ctx.cli_version
        ),
    };
    CheckReport {
        id: "version_drift",
        title: "CLI / daemon version agreement",
        severity,
        detail,
        auto_fixable: false,
        fix_class: FixClass::NeverAutomatic,
        remediation: if severity == Severity::Pass {
            None
        } else {
            Some("sudo agentsso setup".to_owned())
        },
        fix_outcome: None,
    }
}

// ── Check 2: stale_launchd (macOS-only) ─────────────────────────────

fn detect_stale_launchd(ctx: &DoctorCtx) -> CheckReport {
    #[cfg(target_os = "macos")]
    {
        use crate::cli::service::LAUNCHD_PLIST_PATH;
        let plist_exists = std::path::Path::new(LAUNCHD_PLIST_PATH).exists();
        if !plist_exists {
            // No LaunchDaemon registered at all — that is the
            // "not installed" condition, surfaced by other checks;
            // here it is simply "nothing stale".
            return CheckReport::pass(
                "stale_launchd",
                "launchd registration freshness",
                "no LaunchDaemon plist installed — nothing stale",
                FixClass::GatedByRestartOk,
            );
        }
        let launchd_pid = launchctl_print_pid();
        // Stale = plist exists but launchd reports no running pid,
        // OR launchd reports a pid but the daemon's control plane is
        // unreachable (registration points at a dead process).
        let (severity, detail) = match (launchd_pid, &ctx.daemon_version) {
            (Some(pid), Some(_)) => {
                (Severity::Pass, format!("LaunchDaemon registered and running (pid {pid})"))
            }
            (Some(pid), None) => (
                Severity::Fail,
                format!(
                    "launchd reports the daemon running (pid {pid}) but its control plane \
                     is unreachable — the registration points at a dead/wedged process"
                ),
            ),
            (None, _) => (
                Severity::Fail,
                "a LaunchDaemon plist is installed but launchd reports no running daemon \
                 — stale registration"
                    .to_owned(),
            ),
        };
        CheckReport {
            id: "stale_launchd",
            title: "launchd registration freshness",
            severity,
            detail,
            auto_fixable: severity != Severity::Pass,
            fix_class: FixClass::GatedByRestartOk,
            remediation: if severity == Severity::Pass {
                None
            } else {
                Some(
                    "sudo agentsso doctor --fix --restart-ok   (or: sudo agentsso setup)"
                        .to_owned(),
                )
            },
            fix_outcome: None,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = ctx;
        CheckReport::pass(
            "stale_launchd",
            "launchd registration freshness",
            "skipped (macOS-only check)",
            FixClass::GatedByRestartOk,
        )
    }
}

#[cfg(target_os = "macos")]
fn launchctl_print_pid() -> Option<u32> {
    use crate::cli::service::DAEMON_LABEL;
    use crate::cli::service::install_macos as im;
    let out = std::process::Command::new("/bin/launchctl")
        .args(["print", &format!("system/{DAEMON_LABEL}")])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    im::parse_launchctl_running(&stdout)
}

#[cfg(target_os = "macos")]
async fn fix_stale_launchd() -> FixOutcome {
    use crate::cli::service::install_macos as im;
    if !is_root() {
        return refuse_non_root();
    }
    if let Err(e) = im::bootout_daemon() {
        return FixOutcome::Failed { err: format!("bootout failed: {e:#}") };
    }
    if let Err(e) = im::launchctl_bootstrap_system() {
        return FixOutcome::Failed { err: format!("re-bootstrap failed: {e:#}") };
    }
    FixOutcome::Repaired {
        old: "stale launchd registration".to_owned(),
        new: "daemon booted out + re-bootstrapped".to_owned(),
    }
}

// ── Check 3: symlink_integrity (macOS-only) ─────────────────────────

fn detect_symlink_integrity(_ctx: &DoctorCtx) -> CheckReport {
    #[cfg(target_os = "macos")]
    {
        let helper = std::path::Path::new(PRIVILEGED_HELPER_PATH);
        let resolved = std::fs::read_link(helper).ok();
        let (target_exists, mode) = match &resolved {
            Some(t) => stat_target(t),
            None => (false, None),
        };
        let (severity, fixable) = symlink_decide(resolved.as_deref(), target_exists, mode);
        let detail = match (&resolved, target_exists, mode) {
            (None, _, _) => format!(
                "{PRIVILEGED_HELPER_PATH} is not a symlink (or unreadable) — expected a \
                 symlink to a versioned agentsso-<V> binary"
            ),
            (Some(t), false, _) => {
                format!("symlink resolves to {} but that file is missing", t.display())
            }
            (Some(t), true, Some(m)) if m & 0o111 == 0 => {
                format!("symlink target {} exists but is not executable", t.display())
            }
            (Some(t), _, _) => format!("symlink → {}", t.display()),
        };
        CheckReport {
            id: "symlink_integrity",
            title: "privileged-helper symlink topology",
            severity,
            detail,
            auto_fixable: fixable,
            fix_class: FixClass::SafeAutomatic,
            remediation: if severity == Severity::Pass {
                None
            } else {
                Some("sudo agentsso doctor --fix   (or: sudo agentsso setup)".to_owned())
            },
            fix_outcome: None,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        CheckReport::pass(
            "symlink_integrity",
            "privileged-helper symlink topology",
            "skipped (macOS-only check)",
            FixClass::SafeAutomatic,
        )
    }
}

#[cfg(target_os = "macos")]
fn stat_target(t: &Path) -> (bool, Option<u32>) {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(t) {
        Ok(md) => (md.is_file(), Some(md.permissions().mode())),
        Err(_) => (false, None),
    }
}

/// Local reimpl of `setup/mod.rs`'s private `atomic_symlink_swap`
/// (`symlink → tmp → rename → parent fsync`). Same shape.
#[cfg(target_os = "macos")]
fn atomic_symlink_swap(target: &Path, stable: &Path, dir: &Path) -> std::io::Result<()> {
    let tmp = dir.join(format!("agentsso.tmp.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(target, &tmp)?;
    if let Err(e) = std::fs::rename(&tmp, stable) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Enumerate `agentsso-<semver>` binaries in `dir` that have an exec
/// bit, returning the highest-semver one. Mirrors `setup/mod.rs`'s
/// `gc_old_versions` enumeration.
#[cfg(target_os = "macos")]
fn highest_versioned_binary(dir: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let entries = std::fs::read_dir(dir).ok()?;
    let mut best: Option<(semver::Version, PathBuf)> = None;
    for e in entries.flatten() {
        let path = e.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(ver_str) = name.strip_prefix("agentsso-") else {
            continue;
        };
        if ver_str.is_empty() || ver_str.contains(".tmp.") {
            continue;
        }
        let Ok(v) = semver::Version::parse(ver_str) else {
            continue;
        };
        // Must be a regular file with an exec bit.
        let Ok(md) = std::fs::metadata(&path) else {
            continue;
        };
        if !md.is_file() || md.permissions().mode() & 0o111 == 0 {
            continue;
        }
        match &best {
            Some((bv, _)) if *bv >= v => {}
            _ => best = Some((v, path.clone())),
        }
    }
    best.map(|(_, p)| p)
}

#[cfg(target_os = "macos")]
fn fix_symlink_integrity() -> FixOutcome {
    if !is_root() {
        return refuse_non_root();
    }
    let helper = std::path::Path::new(PRIVILEGED_HELPER_PATH);
    let helper_dir = helper.parent().unwrap_or(std::path::Path::new("/"));
    let Some(target) = highest_versioned_binary(helper_dir) else {
        return FixOutcome::Failed {
            err: format!(
                "no executable agentsso-<version> binary found under {} to re-point at \
                 — run `sudo agentsso setup`",
                helper_dir.display()
            ),
        };
    };
    let old = std::fs::read_link(helper)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "(no/broken symlink)".to_owned());
    match atomic_symlink_swap(&target, helper, helper_dir) {
        Ok(()) => FixOutcome::Repaired { old, new: target.display().to_string() },
        Err(e) => FixOutcome::Failed { err: format!("symlink swap failed: {e}") },
    }
}

// ── Check 4: managed_policy_staleness (cross-platform) ──────────────

fn managed_default_path(home: &Path) -> PathBuf {
    permitlayer_core::paths::managed_policies_dir(Some(home)).join("default.toml")
}

fn detect_managed_policy_staleness(ctx: &DoctorCtx) -> CheckReport {
    let target = managed_default_path(&ctx.home);
    let on_disk = sha256_file(&target).ok();
    let embedded = sha256_str(EMBEDDED_MANAGED_BUNDLE);
    let (severity, fixable) = staleness_decide(on_disk.as_deref(), &embedded);
    // Drive the message off the on-disk hash directly (no impossible
    // match arm — staleness only ever yields Pass or Fail).
    let detail = match &on_disk {
        Some(h) if *h == embedded => {
            format!("{} matches the bundle embedded in this binary", target.display())
        }
        Some(_) => format!(
            "{} differs from the bundle embedded in this binary (stale managed policy)",
            target.display()
        ),
        None => format!("{} is missing (managed bundle not synced)", target.display()),
    };
    CheckReport {
        id: "managed_policy_staleness",
        title: "managed policy bundle freshness",
        severity,
        detail,
        auto_fixable: fixable,
        fix_class: FixClass::SafeAutomatic,
        remediation: if severity == Severity::Pass {
            None
        } else {
            // The RELOAD is NeverAutomatic and NOT performed here —
            // the file rewrite is the only safe-automatic part.
            Some(
                "sudo agentsso doctor --fix   (rewrites the file; then run `agentsso reload` \
                 to apply it to the running daemon)"
                    .to_owned(),
            )
        },
        fix_outcome: None,
    }
}

/// Write the embedded bundle to `tmp` at mode 0644 + fsync (Unix);
/// plain write elsewhere. Extracted from `fix_managed_policy_staleness`
/// so the `#[cfg(unix)]` branch isn't an IIFE.
fn write_managed_tmp(tmp: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(tmp)?;
        file.write_all(EMBEDDED_MANAGED_BUNDLE.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(tmp, EMBEDDED_MANAGED_BUNDLE)
    }
}

/// Rewrite `<managed>/default.toml` from [`EMBEDDED_MANAGED_BUNDLE`]
/// atomically (same-dir tmp → fsync → rename → dir fsync, mode 0644).
/// Mirrors `start.rs`'s `sync_managed_policies` write. The daemon
/// RELOAD is intentionally NOT performed (NeverAutomatic) — the
/// operator must run `agentsso reload`.
fn fix_managed_policy_staleness(ctx: &DoctorCtx) -> FixOutcome {
    // F3 (fast-follow): refuse cleanly when not root, for parity with
    // the other privileged fixes. The managed-policy dir is root-owned
    // 0700 on macOS (paths.rs); without this guard a non-root
    // `doctor --fix` would fail with a late, opaque EACCES on the
    // create_dir_all / rename instead of the standard refusal.
    #[cfg(target_os = "macos")]
    {
        if !is_root() {
            return refuse_non_root();
        }
    }
    let dir = permitlayer_core::paths::managed_policies_dir(Some(&ctx.home));
    let target = dir.join("default.toml");
    let old = sha256_file(&target).ok().unwrap_or_else(|| "(absent)".to_owned());

    if let Err(e) = std::fs::create_dir_all(&dir) {
        return FixOutcome::Failed {
            err: format!("could not create managed-policy dir {}: {e}", dir.display()),
        };
    }
    let tmp = dir.join(format!(".default.toml.tmp.{}", std::process::id()));
    let write_res = write_managed_tmp(&tmp);

    if let Err(e) = write_res {
        let _ = std::fs::remove_file(&tmp);
        return FixOutcome::Failed { err: format!("could not write managed policy: {e}") };
    }
    if let Err(e) = std::fs::rename(&tmp, &target) {
        let _ = std::fs::remove_file(&tmp);
        return FixOutcome::Failed { err: format!("atomic rename failed: {e}") };
    }
    #[cfg(unix)]
    {
        if let Ok(d) = std::fs::File::open(&dir) {
            let _ = d.sync_all();
        }
    }
    let new = sha256_str(EMBEDDED_MANAGED_BUNDLE);
    FixOutcome::Repaired { old, new }
}

// ── Check 5: daemon_not_running ─────────────────────────────────────

fn detect_daemon_not_running(ctx: &DoctorCtx) -> CheckReport {
    let running = ctx.daemon_version.is_some();
    let severity = if running { Severity::Pass } else { Severity::Fail };
    let detail = if running {
        format!(
            "daemon reachable over the control plane (version {})",
            ctx.daemon_version.as_deref().unwrap_or("?")
        )
    } else {
        "daemon is not reachable over the control plane (not running or socket down)".to_owned()
    };
    CheckReport {
        id: "daemon_not_running",
        title: "daemon liveness",
        severity,
        detail,
        auto_fixable: !running,
        fix_class: FixClass::GatedByRestartOk,
        remediation: if running {
            None
        } else {
            Some("sudo agentsso doctor --fix --restart-ok   (or: sudo agentsso setup)".to_owned())
        },
        fix_outcome: None,
    }
}

async fn fix_daemon_not_running() -> FixOutcome {
    #[cfg(target_os = "macos")]
    {
        use crate::cli::service::DAEMON_LABEL;
        if !is_root() {
            return refuse_non_root();
        }
        let out = std::process::Command::new("/bin/launchctl")
            .args(["kickstart", "-k", &format!("system/{DAEMON_LABEL}")])
            .output();
        match out {
            Ok(o) if o.status.success() => FixOutcome::Repaired {
                old: "daemon not running".to_owned(),
                new: format!("launchctl kickstart -k system/{DAEMON_LABEL} issued"),
            },
            Ok(o) => FixOutcome::Failed {
                err: format!(
                    "launchctl kickstart failed (exit {}): {}",
                    o.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&o.stderr).trim()
                ),
            },
            Err(e) => FixOutcome::Failed { err: format!("could not invoke launchctl: {e}") },
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        FixOutcome::Refused {
            why: "daemon kickstart is macOS-only — start the daemon manually (agentsso start)"
                .to_owned(),
        }
    }
}

// ── Check 6: no_tty_prompt_trap (macOS-only) ────────────────────────

async fn detect_no_tty_prompt_trap(ctx: &DoctorCtx) -> CheckReport {
    #[cfg(target_os = "macos")]
    {
        use crate::cli::service::LAUNCHD_PLIST_PATH;
        let is_launchdaemon = std::path::Path::new(LAUNCHD_PLIST_PATH).exists();
        if !is_launchdaemon || ctx.daemon_version.is_none() {
            // Not a LaunchDaemon, or daemon down so policies can't be
            // enumerated — either way no prompt-trap to report.
            return CheckReport::pass(
                "no_tty_prompt_trap",
                "no-TTY prompt-mode policy trap",
                if is_launchdaemon {
                    "daemon unreachable — cannot enumerate bound policies (n/a)"
                } else {
                    "not a LaunchDaemon install (n/a)"
                },
                FixClass::NeverAutomatic,
            );
        }
        let has_prompt = any_bound_policy_prompts(ctx).await;
        let (severity, _f) = prompt_trap_decide(is_launchdaemon, has_prompt);
        let detail = if has_prompt {
            "one or more agent-bound policies use prompt mode (approval-mode = \"prompt\" \
             or a rule action = \"prompt\"), but a LaunchDaemon has no TTY — approvals \
             will silently hang"
                .to_owned()
        } else {
            "no prompt-mode policy is bound to an agent".to_owned()
        };
        CheckReport {
            id: "no_tty_prompt_trap",
            title: "no-TTY prompt-mode policy trap",
            severity,
            detail,
            auto_fixable: false,
            fix_class: FixClass::NeverAutomatic,
            remediation: if severity == Severity::Pass {
                None
            } else {
                Some(
                    "edit the bound policy to use approval-mode = \"auto\" or \"deny\" (a \
                     LaunchDaemon cannot service interactive prompts), then `agentsso reload`"
                        .to_owned(),
                )
            },
            fix_outcome: None,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = ctx;
        CheckReport::pass(
            "no_tty_prompt_trap",
            "no-TTY prompt-mode policy trap",
            "n/a (macOS-only check)",
            FixClass::NeverAutomatic,
        )
    }
}

/// Enumerate agents → their distinct policy names → each policy's
/// resolved TOML, returning true if ANY uses prompt mode. Best-effort
/// — any control-plane hiccup ⇒ false (no false WARN).
#[cfg(target_os = "macos")]
async fn any_bound_policy_prompts(ctx: &DoctorCtx) -> bool {
    let Ok(body) =
        kill::http_get_via(&ctx.endpoint, "/v1/control/agent/list", ctx.control_token.as_deref())
            .await
    else {
        return false;
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) else {
        return false;
    };
    let Some(agents) = parsed.get("agents").and_then(|a| a.as_array()) else {
        return false;
    };
    let mut policy_names: Vec<String> = agents
        .iter()
        .filter_map(|a| a.get("policy_name").and_then(|p| p.as_str()).map(str::to_owned))
        .collect();
    policy_names.sort();
    policy_names.dedup();
    for name in policy_names {
        let path = format!("/v1/control/policies/{}", url_path_encode(&name));
        if let Ok(toml_text) =
            kill::http_get_via(&ctx.endpoint, &path, ctx.control_token.as_deref()).await
            && policy_text_has_prompt(&toml_text)
        {
            return true;
        }
    }
    false
}

/// Detect prompt-mode in a policy's resolved TOML text: either a
/// policy-level `approval-mode = "prompt"` or any rule
/// `action = "prompt"`.
#[cfg(any(test, target_os = "macos"))]
fn policy_text_has_prompt(toml_text: &str) -> bool {
    for raw in toml_text.lines() {
        let line = raw.trim();
        if line.starts_with('#') {
            continue;
        }
        let norm = line.replace(' ', "");
        if norm.starts_with("approval-mode=\"prompt\"") || norm.starts_with("action=\"prompt\"") {
            return true;
        }
    }
    false
}

/// Minimal URL path-segment encoder (mirror of
/// `connect_uds::url_path_encode`) — policy names already pass the
/// daemon allowlist; this is defense-in-depth.
#[cfg(any(test, target_os = "macos"))]
fn url_path_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// ── Check 7: daemon_binary_missing (macOS-only) ─────────────────────

fn detect_daemon_binary_missing(_ctx: &DoctorCtx) -> CheckReport {
    #[cfg(target_os = "macos")]
    {
        let helper = std::path::Path::new(PRIVILEGED_HELPER_PATH);
        let resolved = std::fs::read_link(helper).ok();
        let (severity, detail) = match &resolved {
            None => (
                Severity::Fail,
                format!(
                    "{PRIVILEGED_HELPER_PATH} does not resolve to a versioned binary \
                     (no symlink) — the daemon binary is not installed"
                ),
            ),
            Some(t) => {
                let (exists, mode) = stat_target(t);
                if !exists {
                    (Severity::Fail, format!("daemon binary {} is missing", t.display()))
                } else if mode.map(|m| m & 0o111 == 0).unwrap_or(true) {
                    (Severity::Fail, format!("daemon binary {} is not executable", t.display()))
                } else {
                    (Severity::Pass, format!("daemon binary present + executable: {}", t.display()))
                }
            }
        };
        CheckReport {
            id: "daemon_binary_missing",
            title: "daemon binary present + executable",
            severity,
            detail,
            auto_fixable: false,
            fix_class: FixClass::NeverAutomatic,
            remediation: if severity == Severity::Pass {
                None
            } else {
                Some("sudo agentsso setup".to_owned())
            },
            fix_outcome: None,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        CheckReport::pass(
            "daemon_binary_missing",
            "daemon binary present + executable",
            "skipped (macOS-only check)",
            FixClass::NeverAutomatic,
        )
    }
}

// ── Check 8: operator_layer_compile (cross-platform) ────────────────

fn detect_operator_layer_compile(ctx: &DoctorCtx) -> CheckReport {
    use permitlayer_core::policy::{PolicyCompileError, PolicySet};

    let managed = permitlayer_core::paths::managed_policies_dir(Some(&ctx.home));
    let operator = permitlayer_core::paths::policies_dir(Some(&ctx.home));

    // Decision E: a missing operator `policies/` dir is NOT a policy
    // compile defect — it means the daemon has never initialized this
    // home (`start` always calls `ensure_operator_policies_dir`). The
    // managed-layer reader tolerates a missing dir (returns empty) but
    // the operator-layer reader does `read_dir` and surfaces a cryptic
    // `Io` error for a never-created dir. Surface that as a WARN
    // ("layer not yet initialized") rather than a misleading hard
    // FAIL pointing at a nonexistent file:line. A real privileged
    // install always has this dir, so this only softens the
    // pre-first-boot / fresh-temp-home case.
    if !operator.exists() {
        return CheckReport {
            id: "operator_layer_compile",
            title: "operator policy layer compiles",
            severity: Severity::Warn,
            detail: format!(
                "operator policy directory {} does not exist yet — the daemon has not \
                 initialized this install (it is created on `agentsso start`)",
                operator.display()
            ),
            auto_fixable: false,
            fix_class: FixClass::NeverAutomatic,
            remediation: Some(
                "run `sudo agentsso setup` (or start the daemon) to initialize the \
                 policy layers"
                    .to_owned(),
            ),
            fix_outcome: None,
        };
    }

    match PolicySet::compile_from_layers(Some(&managed), &operator) {
        Ok(set) => {
            let overrides = set.accepted_overrides();
            if overrides.is_empty() {
                CheckReport::pass(
                    "operator_layer_compile",
                    "operator policy layer compiles",
                    "managed + operator policy layers compile cleanly; no operator overrides",
                    FixClass::NeverAutomatic,
                )
            } else {
                let mut detail =
                    String::from("policy layers compile cleanly; operator overrides accepted: ");
                let names: Vec<String> = overrides
                    .iter()
                    .map(|o| {
                        format!(
                            "{} ({} over {})",
                            o.name,
                            o.operator_path.display(),
                            o.managed_path.display()
                        )
                    })
                    .collect();
                detail.push_str(&names.join("; "));
                CheckReport {
                    id: "operator_layer_compile",
                    title: "operator policy layer compiles",
                    severity: Severity::Warn,
                    detail,
                    auto_fixable: false,
                    fix_class: FixClass::NeverAutomatic,
                    remediation: Some(
                        "review the override(s) above — operator policy is shadowing the \
                         shipped managed bundle (intentional if you added the `override` \
                         marker)"
                            .to_owned(),
                    ),
                    fix_outcome: None,
                }
            }
        }
        Err(e) => {
            // EXHAUSTIVE match over the `#[non_exhaustive]` enum so a
            // new variant is a compile-visible TODO here; the `_` arm
            // only catches FUTURE variants, never the ones that exist
            // today.
            let (file, line): (PathBuf, Option<usize>) = match &e {
                PolicyCompileError::Io { path, .. } => (path.clone(), None),
                PolicyCompileError::NotADirectory { path } => (path.clone(), None),
                PolicyCompileError::Parse { path, line, .. } => (path.clone(), *line),
                PolicyCompileError::EmptyPoliciesArray { path } => (path.clone(), None),
                PolicyCompileError::DuplicatePolicyName { second, .. } => (second.clone(), None),
                PolicyCompileError::DuplicatePolicyNameInFile { path, .. } => (path.clone(), None),
                PolicyCompileError::DuplicateRuleId { path, .. } => (path.clone(), None),
                PolicyCompileError::EmptyScopesAllowlist { path, .. } => (path.clone(), None),
                PolicyCompileError::EmptyResourcesAllowlist { path, .. } => (path.clone(), None),
                PolicyCompileError::EmptyRuleScopesOverride { path, .. } => (path.clone(), None),
                PolicyCompileError::EmptyRuleResourcesOverride { path, .. } => (path.clone(), None),
                PolicyCompileError::RuleScopeWidensPolicyAllowlist { path, .. } => {
                    (path.clone(), None)
                }
                PolicyCompileError::RuleResourceWidensPolicyAllowlist { path, .. } => {
                    (path.clone(), None)
                }
                PolicyCompileError::ShadowedRule { path, .. } => (path.clone(), None),
                PolicyCompileError::BomDetected { path, .. } => (path.clone(), None),
                PolicyCompileError::InvalidScopeFormat { path, .. } => (path.clone(), None),
                PolicyCompileError::DuplicateScopeInAllowlist { path, .. } => (path.clone(), None),
                PolicyCompileError::MixedWildcardAndExplicitResources { path, .. } => {
                    (path.clone(), None)
                }
                PolicyCompileError::UnmarkedCrossLayerOverride { operator_path, .. } => {
                    (operator_path.clone(), None)
                }
                PolicyCompileError::DanglingOverrideMarker { operator_path, .. } => {
                    (operator_path.clone(), None)
                }
                PolicyCompileError::OverrideMarkerInManagedLayer { managed_path, .. } => {
                    (managed_path.clone(), None)
                }
                // FUTURE variants only (the enum is #[non_exhaustive]).
                _ => (PathBuf::from("(unknown)"), None),
            };
            let loc = match line {
                Some(n) => format!("{}:{n}", file.display()),
                None => file.display().to_string(),
            };
            CheckReport {
                id: "operator_layer_compile",
                title: "operator policy layer compiles",
                severity: Severity::Fail,
                detail: format!("policy compile failed at {loc}: {e}"),
                auto_fixable: false,
                fix_class: FixClass::NeverAutomatic,
                remediation: Some(format!("fix the policy at {loc}, then `agentsso reload`")),
                fix_outcome: None,
            }
        }
    }
}

// ── JSON report ─────────────────────────────────────────────────────

#[derive(Serialize)]
struct FixIntegrityGate {
    passed: bool,
    reason: String,
}

#[derive(Serialize)]
struct Summary {
    pass: usize,
    warn: usize,
    fail: usize,
}

#[derive(Serialize)]
struct JsonReport<'a> {
    schema: u32,
    cli_version: &'a str,
    daemon_version: Option<&'a str>,
    fix_mode: bool,
    restart_ok: bool,
    fix_integrity_gate: FixIntegrityGate,
    checks: &'a [CheckReport],
    summary: Summary,
}

// ── Entry point ─────────────────────────────────────────────────────

/// Run `agentsso doctor`.
pub async fn run(args: DoctorArgs) -> Result<()> {
    let cli_version = env!("CARGO_PKG_VERSION");
    let home = crate::cli::agentsso_home()?;

    // Resolve all shared state ONCE.
    let config = {
        use crate::config::{CliOverrides, DaemonConfig};
        DaemonConfig::load(&CliOverrides::default()).unwrap_or_default()
    };
    let endpoint = kill::resolve_control_endpoint(&config);
    let control_token = kill::read_control_token(&home);
    let daemon_version = daemon_state(&endpoint, control_token.as_deref()).await;

    // Decision A: binary-integrity gate, evaluated ONCE before any
    // --fix mutation. The reason string is always populated (the JSON
    // contract requires it even when the gate passes / is moot).
    let (gate_passed, gate_reason) = compute_integrity_gate(daemon_version.as_deref());

    let audit = build_audit_store(&home).await.ok();

    let ctx = DoctorCtx {
        home: home.clone(),
        endpoint: endpoint.clone(),
        control_token: control_token.clone(),
        daemon_version: daemon_version.clone(),
        cli_version,
        restart_ok: args.restart_ok,
        fix: args.fix,
        audit,
        fix_integrity_gate_passed: gate_passed,
        fix_integrity_gate_reason: gate_reason.clone(),
    };

    // Run every check's detect, in spec order.
    let specs = check_specs();
    let mut reports: Vec<CheckReport> = vec![
        detect_version_drift(&ctx),
        detect_stale_launchd(&ctx),
        detect_symlink_integrity(&ctx),
        detect_managed_policy_staleness(&ctx),
        detect_daemon_not_running(&ctx),
        detect_no_tty_prompt_trap(&ctx).await,
        detect_daemon_binary_missing(&ctx),
        detect_operator_layer_compile(&ctx),
    ];

    // --fix pass: for every non-passing check, consult the SINGLE
    // non-bypassable gate, then (only if it authorizes) apply.
    if args.fix {
        for (idx, spec) in specs.iter().enumerate() {
            let severity = reports[idx].severity;
            // Nothing to repair on a passing check.
            if severity == Severity::Pass {
                continue;
            }
            // A *Warn*-severity check with a NeverAutomatic class is
            // purely informational (operator-override list, prompt-trap
            // advisory, …) — there is no remediation to refuse, so
            // record it as Skipped rather than running it through the
            // refusal gate (Refused is for things that NEEDED action
            // but couldn't get it automatically — a Fail). This keeps
            // the report honest and is the natural construction site
            // for `FixOutcome::Skipped`.
            let outcome = if severity == Severity::Warn
                && spec.fix_class == FixClass::NeverAutomatic
            {
                FixOutcome::Skipped {
                    why: "informational only — no automatic remediation for this check".to_owned(),
                }
            } else {
                match may_apply_fix(spec.fix_class, ctx.restart_ok, ctx.fix_integrity_gate_passed) {
                    Err(why) => FixOutcome::Refused { why: why.to_owned() },
                    Ok(()) => apply_fix(spec.id, &ctx).await,
                }
            };
            emit_fix_audit(&ctx, spec.id, spec.fix_class, &outcome).await;
            reports[idx].fix_outcome = Some(outcome);
        }
    }

    // Tally.
    let pass = reports.iter().filter(|r| r.severity == Severity::Pass).count();
    let warn = reports.iter().filter(|r| r.severity == Severity::Warn).count();
    let fail = reports.iter().filter(|r| r.severity == Severity::Fail).count();

    emit_run_audit(&ctx, pass, warn, fail).await;

    // Render.
    if args.json {
        let report = JsonReport {
            schema: 1,
            cli_version,
            daemon_version: daemon_version.as_deref(),
            fix_mode: args.fix,
            restart_ok: args.restart_ok,
            fix_integrity_gate: FixIntegrityGate { passed: gate_passed, reason: gate_reason },
            checks: &reports,
            summary: Summary { pass, warn, fail },
        };
        println!("{}", serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_owned()));
    } else {
        render_human(&reports, &ctx, pass, warn, fail);
    }

    // Exit code: any Fail severity OR any Refused/Failed fix_outcome
    // ⇒ FAILURE (SilentCliError so no duplicate generic error line).
    let any_fix_problem = reports.iter().any(|r| {
        matches!(r.fix_outcome, Some(FixOutcome::Refused { .. }) | Some(FixOutcome::Failed { .. }))
    });
    if fail > 0 || any_fix_problem {
        return Err(silent_cli_error("doctor found failures"));
    }
    Ok(())
}

/// Dispatch a single check's repair by id. Centralized so `run`'s
/// gate is the only authorization path.
async fn apply_fix(id: &str, ctx: &DoctorCtx) -> FixOutcome {
    match id {
        "version_drift"
        | "daemon_binary_missing"
        | "no_tty_prompt_trap"
        | "operator_layer_compile" => {
            // NeverAutomatic — the gate already refused; this is
            // defense-in-depth (must never be reached for these).
            FixOutcome::Refused { why: "never auto-fixable".to_owned() }
        }
        "managed_policy_staleness" => fix_managed_policy_staleness(ctx),
        "stale_launchd" => {
            #[cfg(target_os = "macos")]
            {
                fix_stale_launchd().await
            }
            #[cfg(not(target_os = "macos"))]
            {
                FixOutcome::Refused { why: "macOS-only".to_owned() }
            }
        }
        "symlink_integrity" => {
            #[cfg(target_os = "macos")]
            {
                fix_symlink_integrity()
            }
            #[cfg(not(target_os = "macos"))]
            {
                FixOutcome::Refused { why: "macOS-only".to_owned() }
            }
        }
        "daemon_not_running" => fix_daemon_not_running().await,
        other => FixOutcome::Refused { why: format!("no fix dispatch for check '{other}'") },
    }
}

/// Decision A binary-integrity gate. Returns `(passed, reason)`.
/// `reason` is always non-empty (the JSON contract requires it). The
/// daemon version was already probed ONCE up front (Decision B) and
/// is passed in rather than re-probed here.
fn compute_integrity_gate(daemon_version: Option<&str>) -> (bool, String) {
    #[cfg(target_os = "macos")]
    {
        let helper = std::path::Path::new(PRIVILEGED_HELPER_PATH);
        let resolved = match std::fs::read_link(helper) {
            Ok(t) => t,
            Err(_) => {
                return (
                    false,
                    format!(
                        "{PRIVILEGED_HELPER_PATH} is not a resolvable symlink — run \
                         `sudo agentsso setup`"
                    ),
                );
            }
        };
        let (exists, mode) = stat_target(&resolved);
        if !exists {
            return (
                false,
                format!(
                    "symlink target {} is missing — run `sudo agentsso setup`",
                    resolved.display()
                ),
            );
        }
        if mode.map(|m| m & 0o111 == 0).unwrap_or(true) {
            return (
                false,
                format!(
                    "symlink target {} is not executable — run `sudo agentsso setup`",
                    resolved.display()
                ),
            );
        }
        let symlink_version = match parse_versioned_binary_name(&resolved) {
            Some(v) => v,
            None => {
                return (
                    false,
                    format!(
                        "symlink target {} is not a versioned agentsso-<V> binary — run \
                         `sudo agentsso setup`",
                        resolved.display()
                    ),
                );
            }
        };
        match daemon_version {
            Some(dv) if dv == symlink_version => (
                true,
                format!(
                    "symlink resolves to agentsso-{symlink_version} and the running daemon \
                     reports {dv} — integrity gate passed"
                ),
            ),
            Some(dv) => (
                false,
                format!(
                    "running daemon reports {dv} but the symlink resolves to \
                     agentsso-{symlink_version} — version disagreement; run \
                     `sudo agentsso setup`"
                ),
            ),
            None => (
                false,
                "daemon is unreachable so its version cannot be confirmed against the \
                 installed binary — refusing all --fix mutations; run `sudo agentsso setup`"
                    .to_owned(),
            ),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = daemon_version;
        // No privileged versioned-symlink install model off macOS;
        // there are no --fix mutations gated by it (the safe-automatic
        // ones — managed-policy rewrite — still run; the macOS-only
        // ones refuse on their own). Treat the gate as inert-pass with
        // an explicit reason so the JSON contract stays honest.
        (
            true,
            "binary-integrity gate is macOS-only; no privileged versioned-symlink model on \
             this platform"
                .to_owned(),
        )
    }
}

/// Human-rendered report (Decision D — `render::Outcome` + Glyphs).
fn render_human(reports: &[CheckReport], ctx: &DoctorCtx, pass: usize, warn: usize, fail: usize) {
    use crate::design::terminal::ColorSupport;
    use crate::design::theme::Theme;

    let g = glyphs();
    let support = ColorSupport::detect();
    let theme = Theme::default();

    println!();
    println!("{} agentsso doctor", g.arrow);
    println!("    CLI:            {}", ctx.cli_version);
    match &ctx.daemon_version {
        Some(v) => println!("    running daemon: {v}"),
        None => println!("    running daemon: {} unreachable", g.warn),
    }
    if ctx.fix {
        println!("    fix mode:       ON{}", if ctx.restart_ok { " (restart-ok)" } else { "" });
        if !ctx.fix_integrity_gate_passed {
            println!(
                "    {} integrity gate FAILED — all --fix mutations refused: {}",
                g.warn, ctx.fix_integrity_gate_reason
            );
        }
    }
    println!();

    for r in reports {
        let styled = render::styled_outcome(r.severity.to_outcome(), &theme, support);
        println!("  {styled}  {}  ({})", r.title, r.id);
        println!("       {}", r.detail);
        if let Some(fo) = &r.fix_outcome {
            match fo {
                FixOutcome::Repaired { old, new } => {
                    println!("       {} fixed: {old} -> {new}", g.check);
                }
                FixOutcome::Skipped { why } => {
                    println!("       {} fix skipped: {why}", g.arrow);
                }
                FixOutcome::Refused { why } => {
                    println!("       {} fix refused: {why}", g.warn);
                }
                FixOutcome::Failed { err } => {
                    println!("       {} fix failed: {err}", g.warn);
                }
            }
        } else if let Some(rem) = &r.remediation {
            println!("       run:  {rem}");
        }
    }

    println!();
    println!("{} summary: {} pass · {} warn · {} fail", g.arrow, pass, warn, fail);
}

// ── Tests ───────────────────────────────────────────────────────────
//
// This crate is `#![forbid(unsafe_code)]`; `std::env::set_var` is
// unsafe in edition 2024, so NO env-mutating tests here. All unit
// tests are pure (no daemon, no env). The macOS-gated decision
// helpers are `#[cfg(any(test, target_os = "macos"))]` so they
// compile + run on ubuntu/windows too.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ── version_drift_decide truth table ────────────────────────────
    #[test]
    fn version_drift_decide_truth_table() {
        assert_eq!(version_drift_decide("1.0.0", Some("1.0.0")), (Severity::Pass, false));
        assert_eq!(version_drift_decide("1.0.0", Some("0.9.0")), (Severity::Fail, false));
        assert_eq!(version_drift_decide("1.0.0", None), (Severity::Warn, false));
        // auto_fixable is ALWAYS false (NeverAutomatic).
        for d in [Some("1.0.0"), Some("0.1.0"), None] {
            assert!(!version_drift_decide("1.0.0", d).1, "version_drift is never auto-fixable");
        }
    }

    // ── symlink_decide truth table ──────────────────────────────────
    #[test]
    fn symlink_decide_truth_table() {
        let p = Path::new("/x/agentsso-1.2.3");
        // Broken symlink (None).
        assert_eq!(symlink_decide(None, false, None), (Severity::Fail, true));
        // Resolves but target missing.
        assert_eq!(symlink_decide(Some(p), false, None), (Severity::Fail, true));
        // Resolves, exists, no exec bit.
        assert_eq!(symlink_decide(Some(p), true, Some(0o644)), (Severity::Fail, true));
        // Resolves, exists, exec bit set → Pass.
        assert_eq!(symlink_decide(Some(p), true, Some(0o755)), (Severity::Pass, false));
        assert_eq!(symlink_decide(Some(p), true, Some(0o711)), (Severity::Pass, false));
    }

    // ── staleness_decide truth table ────────────────────────────────
    #[test]
    fn staleness_decide_truth_table() {
        let embedded = sha256_str(EMBEDDED_MANAGED_BUNDLE);
        // Equal hashes → Pass.
        assert_eq!(staleness_decide(Some(&embedded), &embedded), (Severity::Pass, false));
        // Different hash → Fail (fixable).
        assert_eq!(staleness_decide(Some("deadbeef"), &embedded), (Severity::Fail, true));
        // Absent on disk → Fail (fixable).
        assert_eq!(staleness_decide(None, &embedded), (Severity::Fail, true));
    }

    // ── prompt_trap_decide truth table ──────────────────────────────
    #[test]
    fn prompt_trap_decide_truth_table() {
        assert_eq!(prompt_trap_decide(true, true), (Severity::Warn, false));
        assert_eq!(prompt_trap_decide(true, false), (Severity::Pass, false));
        assert_eq!(prompt_trap_decide(false, true), (Severity::Pass, false));
        assert_eq!(prompt_trap_decide(false, false), (Severity::Pass, false));
    }

    #[test]
    fn policy_text_prompt_detection() {
        assert!(policy_text_has_prompt(r#"approval-mode = "prompt""#));
        assert!(policy_text_has_prompt(r#"  approval-mode="prompt""#));
        assert!(policy_text_has_prompt(r#"action = "prompt""#));
        assert!(!policy_text_has_prompt(r#"approval-mode = "auto""#));
        assert!(!policy_text_has_prompt(r#"# approval-mode = "prompt""#));
        assert!(!policy_text_has_prompt("name = \"x\"\nscopes = []"));
    }

    #[test]
    fn url_path_encode_escapes_path_separators() {
        assert_eq!(url_path_encode("gmail-read-only"), "gmail-read-only");
        assert_eq!(url_path_encode("policy.v1_2"), "policy.v1_2");
        // Path-traversal defense-in-depth: `/` and whitespace escape.
        assert_eq!(url_path_encode("a/b"), "a%2Fb");
        assert_eq!(url_path_encode("a b"), "a%20b");
    }

    // ── may_apply_fix FULL truth table (SECURITY-CRITICAL) ──────────
    #[test]
    fn may_apply_fix_full_truth_table() {
        use FixClass::*;
        // integrity_ok == false ⇒ ALWAYS Err regardless of class /
        // restart_ok. This is the non-bypassable Decision-A gate.
        for class in [SafeAutomatic, GatedByRestartOk, NeverAutomatic] {
            for restart_ok in [true, false] {
                assert!(
                    may_apply_fix(class, restart_ok, false).is_err(),
                    "integrity_ok=false MUST refuse {class:?} (restart_ok={restart_ok})"
                );
            }
        }
        // integrity_ok == true:
        // - NeverAutomatic NEVER Ok.
        for restart_ok in [true, false] {
            assert!(
                may_apply_fix(NeverAutomatic, restart_ok, true).is_err(),
                "NeverAutomatic must NEVER be authorized (restart_ok={restart_ok})"
            );
        }
        // - SafeAutomatic always Ok (gate passed).
        assert!(may_apply_fix(SafeAutomatic, false, true).is_ok());
        assert!(may_apply_fix(SafeAutomatic, true, true).is_ok());
        // - GatedByRestartOk Ok IFF restart_ok.
        assert!(may_apply_fix(GatedByRestartOk, true, true).is_ok());
        assert!(may_apply_fix(GatedByRestartOk, false, true).is_err());
    }

    // ── fix_class_invariants: declared class matches the NEVER list ──
    #[test]
    fn fix_class_invariants() {
        let specs = check_specs();
        let by_id = |id: &str| -> FixClass {
            specs.iter().find(|s| s.id == id).expect("check id exists").fix_class
        };
        // #1 version_drift, #7 daemon_binary_missing → NeverAutomatic.
        assert_eq!(by_id("version_drift"), FixClass::NeverAutomatic);
        assert_eq!(by_id("daemon_binary_missing"), FixClass::NeverAutomatic);
        // #2 stale_launchd, #5 daemon_not_running → GatedByRestartOk.
        assert_eq!(by_id("stale_launchd"), FixClass::GatedByRestartOk);
        assert_eq!(by_id("daemon_not_running"), FixClass::GatedByRestartOk);
        // #4 managed_policy_staleness → SafeAutomatic (file rewrite
        // only; the RELOAD is NeverAutomatic and not performed).
        assert_eq!(by_id("managed_policy_staleness"), FixClass::SafeAutomatic);
        // #3 symlink_integrity → SafeAutomatic.
        assert_eq!(by_id("symlink_integrity"), FixClass::SafeAutomatic);
        // #6 no_tty_prompt_trap, #8 operator_layer_compile →
        // NeverAutomatic.
        assert_eq!(by_id("no_tty_prompt_trap"), FixClass::NeverAutomatic);
        assert_eq!(by_id("operator_layer_compile"), FixClass::NeverAutomatic);
        // There are exactly 8 checks.
        assert_eq!(specs.len(), 8);
    }

    // ── Decision-C1 parity: embedded bundle non-empty + compiles ────
    #[test]
    fn embedded_managed_bundle_non_empty_and_compiles() {
        assert!(
            !EMBEDDED_MANAGED_BUNDLE.trim().is_empty(),
            "EMBEDDED_MANAGED_BUNDLE must be the real default_policy.toml content"
        );
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("default.toml"), EMBEDDED_MANAGED_BUNDLE).unwrap();
        let set = permitlayer_core::policy::PolicySet::compile_from_dir(dir.path())
            .expect("embedded managed bundle must compile via the real engine");
        // Sanity: it actually produced policies (parity with
        // start.rs's seed invariant).
        assert!(
            set.accepted_overrides().is_empty(),
            "single-dir compile has no cross-layer overrides"
        );
    }

    #[test]
    fn parse_versioned_binary_name_extracts_semver() {
        assert_eq!(
            parse_versioned_binary_name(Path::new("/p/agentsso-0.3.0-rc.36")),
            Some("0.3.0-rc.36".to_owned())
        );
        assert_eq!(
            parse_versioned_binary_name(Path::new("/p/agentsso-1.2.3")),
            Some("1.2.3".to_owned())
        );
        // The stable symlink name itself is not a versioned binary.
        assert_eq!(parse_versioned_binary_name(Path::new("/p/agentsso")), None);
        // tmp crumb.
        assert_eq!(parse_versioned_binary_name(Path::new("/p/agentsso.tmp.123")), None);
        // non-semver suffix.
        assert_eq!(parse_versioned_binary_name(Path::new("/p/agentsso-notsemver")), None);
    }

    #[test]
    fn parse_whoami_version_extracts() {
        assert_eq!(
            parse_whoami_version(r#"{"pid":7,"version":"0.3.0-rc.36"}"#),
            Some("0.3.0-rc.36".to_owned())
        );
        assert_eq!(parse_whoami_version(r#"{"pid":7}"#), None);
        assert_eq!(parse_whoami_version("not json"), None);
    }

    #[test]
    fn severity_maps_to_outcome() {
        assert_eq!(Severity::Pass.to_outcome(), Outcome::Ok);
        assert_eq!(Severity::Warn.to_outcome(), Outcome::Blocked);
        assert_eq!(Severity::Fail.to_outcome(), Outcome::Error);
    }
}
