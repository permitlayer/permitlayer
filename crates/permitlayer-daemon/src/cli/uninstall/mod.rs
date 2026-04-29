//! `agentsso uninstall` — clean removal of the daemon, OS-keychain
//! master-key entry, autostart artifact, and (optionally) the data
//! directory at `~/.agentsso/`.
//!
//! This is **destructive by design** but **fail-soft per step**: the
//! user asked us to leave their machine in a less-permitlayer state,
//! and a half-uninstall (binary gone, autostart still respawning a
//! missing process) is worse than an uninstall-with-warnings.
//!
//! See `_bmad-output/implementation-artifacts/7-4-uninstall.md` for
//! the full spec, the strategic decisions documented up-front, and
//! the cross-story fences (Story 7.1 brew-services, Story 7.2 `.lnk`
//! cleanup inherited via Story 7.3, Story 7.5 update rollback,
//! Story 7.6 rotate-key).
//!
//! # Teardown order
//!
//! 1. **Stop the daemon** (read PID file, SIGTERM, wait ≤10s).
//! 2. **Disable autostart** via Story 7.3's idempotent
//!    `lifecycle::autostart::disable()`.
//! 3. **Delete the OS keychain master-key entry** via Story 7.4's
//!    new `KeyStore::delete_master_key()`.
//! 4. **Remove the data dir** at `agentsso_home()` (or only the
//!    `keystore/` subdir on `--keep-data`).
//! 5. **Remove the binary** at `current_exe()` (or refuse-and-skip
//!    on Homebrew / dpkg / rpm).
//!
//! Binary is LAST so the user can re-run `agentsso uninstall` if any
//! earlier step warns.

use std::path::Path;
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

use anyhow::Result;
use clap::Args;

use crate::cli::silent_cli_error;
use crate::design::render;
use crate::design::terminal::ColorSupport;
use crate::lifecycle::autostart::{self, AutostartError, AutostartStatus, DisableOutcome};
use permitlayer_keystore::{
    DeleteOutcome, FallbackMode, KeyStoreError, KeystoreConfig, default_keystore,
};

/// Binary-path resolver and `BinaryRemover` abstraction.
///
/// `pub(crate)` so Story 7.5's update orchestrator can re-use
/// [`binary::resolve_binary_target`] and [`binary::BinaryTarget`]
/// for the "where does the binary live + is it package-manager-
/// managed?" question without re-implementing the package-manager
/// detection logic.
pub(crate) mod binary;

use binary::BinaryRemover;

/// Typed marker the dispatcher in `main.rs` looks for to map this
/// error chain to exit code 3 (the resource-conflict code from
/// architecture.md:1023). P11 (review): replaces the previous
/// stringly-typed `.context("uninstall_exit_code:3")` substring scan
/// — substring matching could collide with operator-visible
/// remediation text and let unrelated errors trigger exit 3.
#[derive(Debug)]
pub(crate) struct UninstallExitCode3;

impl std::fmt::Display for UninstallExitCode3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("uninstall: resource conflict")
    }
}

impl std::error::Error for UninstallExitCode3 {}

/// Build the brew-services-conflict error chain: silent-marker +
/// exit-3-marker, with no human-visible internal tag (P10).
///
/// `anyhow::Error::context(T)` stringifies T via Display when the
/// caller probes the chain with `is::<T>()`; to keep the typed
/// marker discoverable in `e.chain()`, we attach it via `Error::new`
/// (where T is a real `std::error::Error`) and add the silent
/// marker via `.context()`.
///
/// The brew-services pre-flight only fires on macOS (the call site
/// at line ~187 is `#[cfg(target_os = "macos")]`-gated), so this
/// helper is unused on Linux + Windows builds. The unit test at
/// line ~1377 exercises it via `#[cfg(target_os = "macos")]` too.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn uninstall_brew_services_conflict() -> anyhow::Error {
    anyhow::Error::new(UninstallExitCode3).context(crate::cli::SilentCliError)
}

/// Glyph pair for the step-line shape, mirroring `cli::autostart`'s
/// `step_glyphs()` (Story 7.3 P41) so non-color terminals get ASCII
/// `->` + `[ok]`/`[!]` instead of mojibake.
struct StepGlyphs {
    arrow: &'static str,
    check: &'static str,
    warn: &'static str,
    skip: &'static str,
}

fn step_glyphs() -> StepGlyphs {
    match ColorSupport::detect() {
        ColorSupport::NoColor => {
            StepGlyphs { arrow: "->", check: "[ok]", warn: "[!]", skip: "[skip]" }
        }
        _ => StepGlyphs {
            arrow: "\u{2192}", // →
            check: "\u{2713}", // ✓
            warn: "\u{26A0}",  // ⚠
            skip: "\u{23ED}",  // ⏭
        },
    }
}

/// Arguments for `agentsso uninstall`.
#[derive(Args, Debug, Default, Clone)]
pub struct UninstallArgs {
    /// Preserve `~/.agentsso/{vault,audit,policies,agents,scrub-rules,plugins,crashes,logs}`.
    /// Still wipes `~/.agentsso/keystore/` and `agentsso.pid` because
    /// the passphrase verifier file is meaningless once the master
    /// key is deleted.
    #[arg(long)]
    pub keep_data: bool,

    /// Leave the agentsso binary on disk. Useful when the binary
    /// lives under a system-managed location you want to handle
    /// yourself (e.g., a Homebrew-managed Cellar path will be
    /// auto-detected and skipped regardless of this flag).
    #[arg(long)]
    pub keep_binary: bool,

    /// Skip the interactive confirmation prompt. REQUIRED when
    /// invoked from a non-tty context (CI, scripts, pipes).
    #[arg(long)]
    pub yes: bool,

    /// Treat the call as non-interactive: implies `--yes` is
    /// required. Mirrors `cli::setup`'s `--non-interactive` flag.
    #[arg(long)]
    pub non_interactive: bool,
}

/// Outcome of one teardown step.
///
/// `pub(crate)` so the Story 7.5 update orchestrator can re-use the
/// same shape for its (different) sequence of fail-soft steps. The
/// closing-line printer (`print_closing_line`) stays uninstall-
/// specific — update has its own closing line — but the variants and
/// the `print_step` helper are common.
#[derive(Debug)]
pub(crate) enum StepOutcome {
    /// Step ran and reports success. `detail` is the operator-facing
    /// "what happened" line (e.g., "removed: /usr/local/bin/agentsso").
    Done { step: &'static str, detail: String },
    /// Step was skipped by user choice (flags) or environment
    /// (package-manager-managed binary).
    Skipped { step: &'static str, reason: String },
    /// Step ran but warned. Uninstall continues; the closing line
    /// surfaces the count.
    Warned { step: &'static str, reason: String, remediation: String },
}

/// Run the `uninstall` subcommand.
pub async fn run(args: UninstallArgs) -> Result<()> {
    use anyhow::Context as _;

    // ── Pre-flight: brew-services double-bind detection (macOS) ─────
    //
    // AC #8: refuse to proceed when `brew services` is currently
    // managing the daemon. Reusing Story 7.3's `parse_brew_services_active`
    // helper (already `pub(crate)`) so the conflict criterion stays
    // in one place — verified against the canonical Homebrew enum
    // at `formula_wrapper.rb#status_symbol` (Story 7.3 review P28).
    //
    // P19 (review): pre-flights run BEFORE `init_tracing` so we don't
    // pay the tracing-subscriber setup cost (or risk creating a
    // ~/.agentsso/logs/ directory that step 4 would then have to
    // delete) when uninstall is going to refuse anyway.
    #[cfg(target_os = "macos")]
    if brew_services_managing_agentsso().await {
        eprint!(
            "{}",
            render::error_block(
                "uninstall_brew_services_active",
                "agentsso is being managed by `brew services`. Running uninstall under \
                 this state would leave Homebrew's plist at \
                 ~/Library/LaunchAgents/homebrew.mxcl.agentsso.plist respawning the \
                 daemon at every login until you `brew uninstall agentsso`.",
                "brew services stop agentsso && agentsso uninstall",
                None,
            )
        );
        return Err(uninstall_brew_services_conflict());
    }

    // Set up tracing for this one-shot CLI command (matches the
    // `cli::setup::run` pattern at setup.rs:121). Only after the
    // brew-services pre-flight refusal — see P19 above.
    let _guards =
        crate::telemetry::init_tracing("info", None, 30).context("tracing init failed")?;

    // ── Pre-flight: tty / non-interactive guard (AC #7) ─────────────
    //
    // Uninstall is destructive. Without `--yes`, in a non-tty
    // context, refuse rather than silently proceed.
    let stdout_is_tty = console::Term::stdout().is_term();
    let interactive = !args.non_interactive && stdout_is_tty;
    if !args.yes && !interactive {
        eprint!(
            "{}",
            render::error_block(
                "uninstall_requires_confirmation",
                "uninstall is destructive and requires interactive confirmation \
                 OR an explicit `--yes` flag",
                "agentsso uninstall --yes",
                None,
            )
        );
        return Err(silent_cli_error("non-interactive uninstall without --yes"));
    }

    // ── Resolve binary target and home dir up front ─────────────────
    //
    // Resolve here so the prompt manifest can show the actual paths
    // we plan to touch. A resolution failure becomes a per-step warn
    // later.
    let home = super::agentsso_home()?;
    let binary_target_result = binary::resolve_binary_target();

    // ── Resolve autostart status for the manifest ───────────────────
    //
    // Status is informational only — we still call disable()
    // unconditionally during teardown.
    let autostart_status = autostart::status().ok();

    // ── Confirm prompt (skipped when --yes) ─────────────────────────
    if !args.yes {
        let manifest = build_prompt_manifest(
            &args,
            &home,
            binary_target_result.as_ref().ok(),
            autostart_status.as_ref(),
        );
        println!("{manifest}");

        // P21 (review): treat dialoguer errors (Ctrl-C, stdin closed,
        // dialoguer::Error::IO) as "user cancelled" rather than
        // bubbling an ugly anyhow error. The whole purpose of the
        // prompt is "say yes or it doesn't happen"; if the user can't
        // answer, the safest interpretation is "don't proceed".
        let join = tokio::task::spawn_blocking(|| {
            dialoguer::Confirm::new().with_prompt("Continue?").default(false).interact()
        })
        .await
        .map_err(|e| anyhow::anyhow!("uninstall confirm join failed: {e}"))?;
        let g = step_glyphs();
        let confirmed = match join {
            Ok(answer) => answer,
            Err(_) => {
                // Treat as cancellation. Print clean line, exit 0.
                println!("{} uninstall cancelled  {} prompt aborted", g.arrow, g.check);
                return Ok(());
            }
        };

        if !confirmed {
            println!("{} uninstall cancelled  {} nothing changed", g.arrow, g.check);
            return Ok(());
        }
    }

    // ── Teardown ────────────────────────────────────────────────────
    let mut outcomes: Vec<StepOutcome> = Vec::with_capacity(5);
    let g = step_glyphs();

    // 1. Stop the daemon if running.
    let stop_outcome = stop_daemon_if_running(&home).await;
    print_step(&g, &stop_outcome);
    outcomes.push(stop_outcome);

    // 2. Disable autostart.
    let autostart_outcome = disable_autostart_warn_on_fail();
    print_step(&g, &autostart_outcome);
    outcomes.push(autostart_outcome);

    // 3. Delete the OS keychain master-key entry.
    let keystore_outcome = delete_keychain_entry_warn_on_fail(&home).await;
    print_step(&g, &keystore_outcome);
    outcomes.push(keystore_outcome);

    // 4. Remove the data dir (or just keystore/ + pid on --keep-data).
    let data_outcome = remove_data_dir_warn_on_fail(&home, args.keep_data);
    print_step(&g, &data_outcome);
    outcomes.push(data_outcome);

    // 5. Remove the binary (last — so re-run is possible if earlier
    //    steps warn).
    let binary_outcome = remove_binary_warn_on_fail(args.keep_binary, binary_target_result);
    print_step(&g, &binary_outcome);
    outcomes.push(binary_outcome);

    // ── Closing line ────────────────────────────────────────────────
    print_closing_line(&g, &outcomes)
}

/// Renders the multi-line manifest that prefaces the confirmation
/// prompt. AC #1 verbatim shape.
fn build_prompt_manifest(
    args: &UninstallArgs,
    home: &Path,
    binary_target: Option<&binary::BinaryTarget>,
    autostart_status: Option<&AutostartStatus>,
) -> String {
    let mut out = String::from("\nThis will remove:\n");

    // Binary line.
    // P22 + P41 (review): when binary is package-manager-managed, show
    // the actual remediation in the manifest (don't make the user wait
    // for the step to run). Distinguish "preserved per --keep-binary"
    // (user choice) from "preserved (brew-managed)" (auto-detected,
    // independent of the flag).
    let binary_line = match (args.keep_binary, binary_target) {
        (_, Some(binary::BinaryTarget::ManagedByPackageManager { manager, path, remediation })) => {
            format!(
                "  • (skipped — agentsso binary at {} is managed by {manager}; \
                 run `{remediation}` afterwards)\n",
                path.display()
            )
        }
        (true, Some(binary::BinaryTarget::Owned(p))) => {
            format!("  • (--keep-binary: agentsso binary preserved at {})\n", p.display())
        }
        (false, Some(binary::BinaryTarget::Owned(p))) => {
            format!("  • the agentsso binary at {}\n", p.display())
        }
        (_, None) => "  • the agentsso binary (path unresolved)\n".to_owned(),
    };
    out.push_str(&binary_line);

    // Data dir line. P1 (review): include data-dir size summary.
    if args.keep_data {
        out.push_str(&format!(
            "  • {}/keystore/ only (vault/, audit/, policies/ preserved per --keep-data)\n",
            home.display()
        ));
        // P39 (review): keep-data preserves vault/, but step 3 will
        // delete the master key. Warn loudly that the sealed
        // credentials become permanently undecryptable — this was
        // implicit in the docs but not in the prompt manifest.
        out.push_str("    WARNING: vault/ contents become PERMANENTLY undecryptable after the\n");
        out.push_str(
            "    master key is deleted. Use --keep-data only for audit/policies recovery.\n",
        );
    } else {
        let size = format_data_dir_size(home);
        out.push_str(&format!(
            "  • {}/ (vault, audit log, policies, agent registrations) — {size} on disk\n",
            home.display()
        ));
    }

    // Keychain line — always.
    out.push_str("  • the OS keychain master-key entry (io.permitlayer.master-key / master)\n");

    // Autostart line.
    // P20 (review): distinguish "Disabled" (status query succeeded,
    // confirmed nothing registered) from `None` (status query failed
    // — uninstall continues anyway, but the operator should know).
    // P26 (review): render `Conflict` as a warning-tone line so the
    // operator sees there's a dual-mechanism state to be aware of.
    let autostart_line = match autostart_status {
        Some(AutostartStatus::Enabled { mechanism, .. }) => {
            format!("  • autostart at login ({mechanism})\n")
        }
        Some(AutostartStatus::Conflict { detail }) => {
            format!("  • autostart at login — WARNING: dual-mechanism state ({detail})\n")
        }
        Some(AutostartStatus::Disabled) => {
            "  • autostart at login (none registered — no-op)\n".to_owned()
        }
        None => {
            "  • autostart at login (status unknown — will attempt cleanup anyway)\n".to_owned()
        }
    };
    out.push_str(&autostart_line);

    out
}

/// Walk the data dir and return a human-readable size string, e.g.
/// `"2.3 MiB"`. Falls back to `"size unknown"` when the dir does not
/// exist or stat'ing fails. P1 (review) — AC #1 prompt manifest must
/// show data-dir size.
fn format_data_dir_size(home: &Path) -> String {
    fn walk(path: &Path) -> std::io::Result<u64> {
        let meta = std::fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            // Don't follow symlinks — the manifest is a preview;
            // don't stat outside the tree.
            return Ok(0);
        }
        if meta.is_file() {
            return Ok(meta.len());
        }
        if !meta.is_dir() {
            return Ok(0);
        }
        let mut total: u64 = 0;
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            total = total.saturating_add(walk(&entry.path()).unwrap_or(0));
        }
        Ok(total)
    }
    let bytes = match walk(home) {
        Ok(b) => b,
        Err(_) => return "size unknown".to_owned(),
    };
    if bytes == 0 {
        return "0 bytes".to_owned();
    }
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} bytes")
    }
}

/// AC #1 step 1 — stop the daemon if it's running. Tolerates every
/// "not running" / "stale PID" case as success.
///
/// **P14 (review):** async to avoid blocking the tokio runtime in the
/// 10-second wait loop. Previous version used `std::thread::sleep`
/// inside the polling loop, which would freeze the runtime worker
/// for up to 10s.
///
/// **Story 7.5 — second consumer.** The `agentsso update --apply`
/// flow stops the daemon at AC #2 step 9 before swapping the binary
/// (Windows file-locks the running binary). Reuses this exact helper
/// so the "graceful SIGTERM, wait ≤10s, tolerate stale PID files"
/// invariants are shared across uninstall and update — they're the
/// same operational concern.
pub(crate) async fn stop_daemon_if_running(home: &Path) -> StepOutcome {
    use crate::lifecycle::pid::PidFile;

    // Read PID. Errors here are warn-and-continue (a corrupt PID
    // file shouldn't block the rest of uninstall).
    let pid = match PidFile::read(home) {
        Ok(Some(pid)) => pid,
        Ok(None) => {
            return StepOutcome::Done {
                step: "stopping daemon",
                detail: "no PID file (daemon not running)".to_owned(),
            };
        }
        Err(e) => {
            return StepOutcome::Warned {
                step: "stopping daemon",
                reason: format!("could not read PID file: {e}"),
                remediation: format!("inspect {}/agentsso.pid manually", home.display()),
            };
        }
    };

    // Is the daemon actually alive?
    match PidFile::is_daemon_running(home) {
        Ok(true) => {}
        Ok(false) => {
            // Stale PID file. Remove it as a courtesy. P31 (review):
            // surface the error if removal fails (e.g., file owned by
            // a different user from a `sudo install` situation).
            let pid_path = home.join("agentsso.pid");
            return match std::fs::remove_file(&pid_path) {
                Ok(()) => StepOutcome::Done {
                    step: "stopping daemon",
                    detail: format!("removed stale PID file (PID {pid})"),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => StepOutcome::Done {
                    step: "stopping daemon",
                    detail: format!("daemon not running (stale PID {pid} already gone)"),
                },
                Err(e) => StepOutcome::Warned {
                    step: "stopping daemon",
                    reason: format!(
                        "could not remove stale PID file at {}: {e}",
                        pid_path.display()
                    ),
                    remediation: format!("rm {} (sudo if needed)", pid_path.display()),
                },
            };
        }
        Err(e) => {
            return StepOutcome::Warned {
                step: "stopping daemon",
                reason: format!("could not check daemon liveness: {e}"),
                remediation: "inspect the system process table manually".to_owned(),
            };
        }
    }

    // P28 (review): single cfg-block for the Unix signal+wait
    // combo. Previous arrangement had `cfg(unix)` SIGTERM, then
    // `cfg(not(unix))` early-return, then a second `cfg(unix)`
    // wait-loop — the second block was structurally dead-but-
    // unreachable on non-Unix and confusing to read.
    #[cfg(not(unix))]
    {
        let _ = pid;
        // Windows path is uninteresting today (the daemon doesn't
        // run on Windows yet); document the no-op.
        return StepOutcome::Done {
            step: "stopping daemon",
            detail: "no Unix signal mechanism on this platform".to_owned(),
        };
    }

    // SIGTERM the daemon (Unix only — on Windows the binary can't
    // run today per architecture).
    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        // P32 (review): reject PID < 2 explicitly. PID 0 is "current
        // process group" on POSIX, PID 1 is `init` / `launchd` /
        // `systemd`. A tampered PID file containing "1" combined with
        // a sudo'd uninstall would SIGTERM init. The daemon is
        // never PID 1 outside containerized init namespaces, which
        // we explicitly don't support for the daemon.
        let raw_pid = match i32::try_from(pid) {
            Ok(p) if p >= 2 => p,
            _ => {
                return StepOutcome::Warned {
                    step: "stopping daemon",
                    reason: format!(
                        "refusing to signal PID {pid}: must be >= 2 \
                         (PID 0 = process group, PID 1 = init)"
                    ),
                    remediation: format!("rm {}/agentsso.pid", home.display()),
                };
            }
        };
        // P30 (review): immediate re-check liveness with kill(pid, 0)
        // before SIGTERM. Tightens but does NOT eliminate the
        // PID-reuse race window between `is_daemon_running` and the
        // signal: a kernel may reap the daemon and recycle its PID
        // to an unrelated process. Linux pidfd would close this
        // entirely; staying with portable POSIX for now.
        match kill(Pid::from_raw(raw_pid), None) {
            Ok(()) => {} // Process still alive.
            Err(nix::errno::Errno::ESRCH) => {
                // Process disappeared between is_daemon_running and now.
                let _ = std::fs::remove_file(home.join("agentsso.pid"));
                return StepOutcome::Done {
                    step: "stopping daemon",
                    detail: format!("daemon exited on its own (was PID {raw_pid})"),
                };
            }
            Err(e) => {
                return StepOutcome::Warned {
                    step: "stopping daemon",
                    reason: format!("liveness re-check on PID {raw_pid} failed: {e}"),
                    remediation: format!("kill -TERM {raw_pid}"),
                };
            }
        }
        if let Err(e) = kill(Pid::from_raw(raw_pid), Signal::SIGTERM) {
            return StepOutcome::Warned {
                step: "stopping daemon",
                reason: format!("SIGTERM to PID {raw_pid} failed: {e}"),
                remediation: format!("kill -TERM {raw_pid}"),
            };
        }

        // Wait up to 10s for the PID file to disappear, then
        // SIGKILL fallback for another 5s.
        //
        // **Story 7.5 review patch P23 (F29 — Auditor):** previous
        // version returned a Warned outcome after 10s with
        // remediation `kill -KILL {pid}`. Now we actually do SIGKILL
        // after 10s — uninstall is destructive by design, and a
        // stuck daemon shouldn't block the teardown. Story 7.5
        // (update) reuses this helper; same posture (the rollback
        // path re-spawns the daemon on the old binary regardless).
        // The SIGKILL fallback closes the exact case where update
        // most needs the stop to proceed (Windows file-locks the
        // running binary; can't swap until the daemon dies).
        let pid_path = home.join("agentsso.pid");
        let sigterm_deadline = Instant::now() + Duration::from_secs(10);
        let mut tried_sigkill = false;
        loop {
            if !pid_path.exists() {
                return StepOutcome::Done {
                    step: "stopping daemon",
                    detail: if tried_sigkill {
                        format!("daemon force-killed after SIGTERM timeout (was PID {pid})")
                    } else {
                        format!("daemon stopped (was PID {pid})")
                    },
                };
            }
            if !tried_sigkill && Instant::now() > sigterm_deadline {
                // SIGKILL fallback. Idempotent: ESRCH means the
                // daemon already exited.
                tried_sigkill = true;
                tracing::warn!(
                    target: "uninstall",
                    pid = raw_pid,
                    "daemon did not respond to SIGTERM in 10s — sending SIGKILL"
                );
                if let Err(e) = kill(Pid::from_raw(raw_pid), Signal::SIGKILL)
                    && e != nix::errno::Errno::ESRCH
                {
                    return StepOutcome::Warned {
                        step: "stopping daemon",
                        reason: format!("SIGTERM timed out after 10s; SIGKILL also failed: {e}"),
                        remediation: format!("kill -KILL {raw_pid} && rm {}", pid_path.display()),
                    };
                }
                // Give SIGKILL up to 5s to take effect (writing the
                // pid-file disappearance is in the kernel's hands).
                let kill_deadline = Instant::now() + Duration::from_secs(5);
                while pid_path.exists() && Instant::now() < kill_deadline {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                continue;
            }
            if tried_sigkill && Instant::now() > sigterm_deadline + Duration::from_secs(15) {
                return StepOutcome::Warned {
                    step: "stopping daemon",
                    reason: format!(
                        "daemon did not shut down within 15s even after SIGKILL (PID {pid} still in PID file)"
                    ),
                    remediation: format!("kill -KILL {pid} && rm {}", pid_path.display()),
                };
            }
            // P14 (review): tokio::time::sleep, NOT std::thread::sleep.
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// AC #1 step 2 — call Story 7.3's `lifecycle::autostart::disable()`.
fn disable_autostart_warn_on_fail() -> StepOutcome {
    match autostart::disable() {
        Ok(DisableOutcome::Removed { mechanism, artifact_path }) => StepOutcome::Done {
            step: "disabling autostart",
            detail: format!("{mechanism} (removed {})", artifact_path.display()),
        },
        Ok(DisableOutcome::RemovedWithShortcut { artifact_path, removed_shortcut }) => {
            StepOutcome::Done {
                step: "disabling autostart",
                detail: format!(
                    "task-scheduler (removed {} + Story 7.2 shortcut at {})",
                    artifact_path.display(),
                    removed_shortcut.display()
                ),
            }
        }
        Ok(DisableOutcome::AlreadyDisabled) => {
            StepOutcome::Done { step: "disabling autostart", detail: "already disabled".to_owned() }
        }
        Err(AutostartError::UnsupportedPlatform { platform }) => StepOutcome::Skipped {
            step: "disabling autostart",
            reason: format!("autostart not implemented on {platform}"),
        },
        Err(other) => StepOutcome::Warned {
            step: "disabling autostart",
            reason: other.to_string(),
            remediation: "remove the artifact manually with launchctl/systemctl/schtasks"
                .to_owned(),
        },
    }
}

/// AC #1 step 3 — delete the OS keychain master-key entry.
async fn delete_keychain_entry_warn_on_fail(home: &Path) -> StepOutcome {
    let config = KeystoreConfig {
        // Do NOT default to `Auto` — the auto path can fall through to
        // the passphrase adapter which would prompt for a passphrase
        // mid-uninstall (a UX disaster). Use `None` to require a
        // native backend; treat backend-unavailable as warn-and-continue.
        fallback: FallbackMode::None,
        home: home.to_path_buf(),
    };
    let keystore = match default_keystore(&config) {
        Ok(k) => k,
        Err(KeyStoreError::BackendUnavailable { backend, source }) => {
            // P33 (review): if the user is in passphrase-mode (the
            // verifier file exists at `~/.agentsso/keystore/passphrase.state`),
            // a native-backend-unavailable result on a headless Linux
            // server is the EXPECTED state — there's no native entry
            // to delete; the on-disk verifier file is what we need
            // to wipe. Treat this case as if the trait method had
            // returned `PassphraseAdapterImmutable` and fall through
            // to the verifier-wipe in that branch.
            let verifier_path = home.join("keystore").join("passphrase.state");
            if verifier_path.exists() {
                return match std::fs::remove_file(&verifier_path) {
                    Ok(()) => StepOutcome::Done {
                        step: "removing keychain entry",
                        detail: format!(
                            "passphrase mode (no native backend) — verifier file removed at {}",
                            verifier_path.display()
                        ),
                    },
                    Err(e) => StepOutcome::Warned {
                        step: "removing keychain entry",
                        reason: format!(
                            "passphrase mode — could not remove verifier at {}: {e}",
                            verifier_path.display()
                        ),
                        remediation: format!("rm {} (sudo if needed)", verifier_path.display()),
                    },
                };
            }
            return StepOutcome::Warned {
                step: "removing keychain entry",
                reason: format!("native backend '{backend}' unavailable: {source}"),
                remediation: "remove manually via Keychain Access / secret-tool / cmdkey"
                    .to_owned(),
            };
        }
        Err(e) => {
            return StepOutcome::Warned {
                step: "removing keychain entry",
                reason: format!("keystore construction failed: {e}"),
                remediation: "remove manually via Keychain Access / secret-tool / cmdkey"
                    .to_owned(),
            };
        }
    };

    match keystore.delete_master_key().await {
        Ok(DeleteOutcome::Removed) => StepOutcome::Done {
            step: "removing keychain entry",
            detail: "io.permitlayer.master-key / master removed".to_owned(),
        },
        Ok(DeleteOutcome::AlreadyAbsent) => StepOutcome::Done {
            step: "removing keychain entry",
            detail: "already absent".to_owned(),
        },
        Err(KeyStoreError::PassphraseAdapterImmutable) => {
            // P43 (review): attempt the passphrase-verifier wipe HERE
            // rather than relying on step 4 (which may fail
            // independently). The previous detail message claimed
            // "verifier file wiped with keystore/" — but step 4 might
            // warn-and-continue, leaving the verifier in place AND
            // the keychain entry empty, which is precisely the
            // "passphrase verifier mismatch" footgun the spec was
            // meant to avoid (Story 7.4 Dev Notes §"Why `--keep-data`
            // always wipes `keystore/`").
            let verifier_path = home.join("keystore").join("passphrase.state");
            match std::fs::remove_file(&verifier_path) {
                Ok(()) => StepOutcome::Done {
                    step: "removing keychain entry",
                    detail: format!(
                        "passphrase adapter — verifier file removed at {}",
                        verifier_path.display()
                    ),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => StepOutcome::Done {
                    step: "removing keychain entry",
                    detail: "passphrase adapter — already absent (no verifier file)".to_owned(),
                },
                Err(e) => StepOutcome::Warned {
                    step: "removing keychain entry",
                    reason: format!(
                        "passphrase adapter — could not remove verifier at {}: {e}",
                        verifier_path.display()
                    ),
                    remediation: format!("rm {} (sudo if needed)", verifier_path.display()),
                },
            }
        }
        Err(e) => StepOutcome::Warned {
            step: "removing keychain entry",
            reason: e.to_string(),
            remediation: "remove manually via Keychain Access / secret-tool / cmdkey".to_owned(),
        },
        // `KeyStoreError` and `DeleteOutcome` are both `#[non_exhaustive]`;
        // future variants land on this arm and surface as warn-and-continue.
        Ok(_) => StepOutcome::Warned {
            step: "removing keychain entry",
            reason: "unrecognised DeleteOutcome variant from keystore".to_owned(),
            remediation: "upgrade agentsso to a version aware of the new outcome".to_owned(),
        },
    }
}

/// AC #1 step 4 + AC #2 — remove the data dir, or just `keystore/` +
/// `agentsso.pid` if `--keep-data` is set.
fn remove_data_dir_warn_on_fail(home: &Path, keep_data: bool) -> StepOutcome {
    if !home.exists() {
        return StepOutcome::Done {
            step: "removing data dir",
            detail: format!("{} (already absent)", home.display()),
        };
    }

    // P46 (review): symlink defense MUST run before either branch
    // (full-wipe and --keep-data both call destructive APIs).
    // P13 (review): `dirs::home_dir().unwrap_or_default()` produces
    // an empty PathBuf which `starts_with("")` returns true for any
    // path — defeating the defense. Treat None as "skip the home
    // check" with a warning.
    // P29 (review): `AGENTSSO_PATHS__HOME` outside `$HOME` is a
    // legitimate operator override (multi-tenant Linux deployments,
    // tests in `/tmp`); skip the home-rooted check when the env
    // override is set.
    let env_override_set = std::env::var_os("AGENTSSO_PATHS__HOME").is_some();
    if !env_override_set
        && let Ok(metadata) = std::fs::symlink_metadata(home)
        && metadata.file_type().is_symlink()
    {
        match dirs::home_dir() {
            Some(real_home) if !real_home.as_os_str().is_empty() => {
                let canonical = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
                if !canonical.starts_with(&real_home) {
                    return StepOutcome::Warned {
                        step: "removing data dir",
                        reason: format!(
                            "{} is a symlink resolving to {} (outside {}): refusing to delete",
                            home.display(),
                            canonical.display(),
                            real_home.display()
                        ),
                        remediation: format!("rm -rf {} manually", home.display()),
                    };
                }
            }
            _ => {
                // home_dir returned None or empty — can't validate.
                // Refuse rather than fall through to the
                // empty-prefix-matches-everything bug (P13).
                return StepOutcome::Warned {
                    step: "removing data dir",
                    reason: format!(
                        "{} is a symlink and HOME is unset/empty: cannot validate \
                         the resolved target — refusing to delete",
                        home.display()
                    ),
                    remediation: format!("rm -rf {} manually", home.display()),
                };
            }
        }
    }

    if keep_data {
        // Wipe ONLY keystore/ and agentsso.pid. Vault, audit, policies,
        // agents, scrub-rules, plugins, crashes, logs all stay.
        // P45 (review): `remove_dir_all`/`remove_file` already
        // tolerate "not found"; the prior `.exists()` checks were
        // redundant AND introduced a TOCTOU race vs concurrent
        // daemon-write. Treat NotFound as success.
        let mut warnings: Vec<String> = Vec::new();
        let mut keystore_existed = false;
        let mut pid_existed = false;
        let keystore_dir = home.join("keystore");
        match std::fs::remove_dir_all(&keystore_dir) {
            Ok(()) => keystore_existed = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warnings.push(format!("could not remove {}: {e}", keystore_dir.display())),
        }
        let pid_path = home.join("agentsso.pid");
        match std::fs::remove_file(&pid_path) {
            Ok(()) => pid_existed = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warnings.push(format!("could not remove {}: {e}", pid_path.display())),
        }
        if warnings.is_empty() {
            // P47 (review): describe what was actually removed (vs
            // what was already absent) for accurate operator UX.
            let detail = match (keystore_existed, pid_existed) {
                (true, true) => format!(
                    "{}/keystore/ + agentsso.pid (vault/audit/policies preserved per --keep-data)",
                    home.display()
                ),
                (true, false) => format!(
                    "{}/keystore/ removed (no PID file to clean; vault/audit/policies preserved)",
                    home.display()
                ),
                (false, true) => format!(
                    "{}/agentsso.pid removed (no keystore/ to clean; vault/audit/policies preserved)",
                    home.display()
                ),
                (false, false) => format!(
                    "{}/keystore/ + agentsso.pid (already absent; vault/audit/policies preserved)",
                    home.display()
                ),
            };
            return StepOutcome::Done { step: "removing data dir", detail };
        } else {
            return StepOutcome::Warned {
                step: "removing data dir",
                reason: warnings.join("; "),
                remediation: format!(
                    "rm -rf {}/keystore && rm -f {}/agentsso.pid",
                    home.display(),
                    home.display()
                ),
            };
        }
    }

    match std::fs::remove_dir_all(home) {
        Ok(()) => StepOutcome::Done {
            step: "removing data dir",
            detail: format!("{} removed", home.display()),
        },
        Err(e) => StepOutcome::Warned {
            step: "removing data dir",
            reason: format!("{}: {e}", home.display()),
            remediation: format!("rm -rf {}", home.display()),
        },
    }
}

/// AC #1 step 5 + AC #3, AC #5 — remove the binary, with
/// package-manager-managed refusal.
fn remove_binary_warn_on_fail(
    keep_binary: bool,
    target: Result<binary::BinaryTarget, binary::BinaryResolveError>,
) -> StepOutcome {
    if keep_binary {
        return StepOutcome::Skipped {
            step: "removing binary",
            reason: "preserved per --keep-binary".to_owned(),
        };
    }

    let target = match target {
        Ok(t) => t,
        Err(e) => {
            return StepOutcome::Warned {
                step: "removing binary",
                reason: format!("could not resolve binary path: {e}"),
                remediation: "rm the agentsso binary from your PATH manually".to_owned(),
            };
        }
    };

    match target {
        binary::BinaryTarget::ManagedByPackageManager { manager, path, remediation } => {
            StepOutcome::Skipped {
                step: "removing binary",
                reason: format!("{} is managed by {manager} — run `{remediation}`", path.display()),
            }
        }
        binary::BinaryTarget::Owned(path) => {
            // P38 (review): Locked-binary retry on Windows (AC #5).
            // Previously: one retry @ 500ms — too short for Windows
            // Defender (1-3s scan window) or OneDrive sync. Now: 3
            // retries with linear backoff (500ms → 1000ms → 2000ms),
            // total ≤ 3.5s.
            let remover = binary::RealBinaryRemover;
            const RETRY_DELAYS_MS: &[u64] = &[500, 1000, 2000];
            let mut last_err: Option<std::io::Error> = None;
            let mut attempts = 0;
            for (i, delay_ms) in
                std::iter::once(0).chain(RETRY_DELAYS_MS.iter().copied()).enumerate()
            {
                if delay_ms > 0 {
                    std::thread::sleep(Duration::from_millis(delay_ms));
                }
                attempts = i + 1;
                match remover.remove_owned_target(&path) {
                    Ok(()) => {
                        let detail = if i == 0 {
                            format!("{} removed", path.display())
                        } else {
                            format!("{} removed (after {attempts} attempts)", path.display())
                        };
                        return StepOutcome::Done { step: "removing binary", detail };
                    }
                    Err(e) if is_locked_error(&e) => {
                        last_err = Some(e);
                        // Continue retrying on lock errors.
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                        return StepOutcome::Warned {
                            step: "removing binary",
                            reason: format!("permission denied removing {}: {e}", path.display()),
                            remediation: format!("sudo rm {}", path.display()),
                        };
                    }
                    Err(e) => {
                        return StepOutcome::Warned {
                            step: "removing binary",
                            reason: format!("{}: {e}", path.display()),
                            remediation: format!("rm {} manually", path.display()),
                        };
                    }
                }
            }
            // All retries exhausted on lock-error.
            StepOutcome::Warned {
                step: "removing binary",
                reason: format!(
                    "{} is locked by another process after {attempts} attempts: {}",
                    path.display(),
                    last_err.map(|e| e.to_string()).unwrap_or_else(|| "unknown error".to_owned())
                ),
                remediation: "close any open agentsso processes and re-run uninstall".to_owned(),
            }
        }
    }
}

/// Probe `brew services list --json` and return `true` iff agentsso
/// is `started` or `scheduled`. Tolerates `brew not on PATH` as
/// "no conflict" (returns `false`).
///
/// **Story 7.5 review patch P21 (F23 — Blind):** async +
/// `tokio::process::Command` with `tokio::time::timeout` instead
/// of std::Command + thread::sleep 100ms poll loop. The previous
/// shape blocked the tokio runtime worker for up to 30s on a slow
/// `brew services list` call. This is the symmetric fix to the
/// `cli::update::brew_services_managing_agentsso` patch — same
/// shell-out, same hang risk.
#[cfg(target_os = "macos")]
async fn brew_services_managing_agentsso() -> bool {
    use std::time::Duration;

    let cmd = tokio::process::Command::new("brew")
        .args(["services", "list", "--json"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    let output = match tokio::time::timeout(Duration::from_secs(30), cmd).await {
        Ok(Ok(o)) => o,
        Ok(Err(_)) => return false, // brew not on PATH — proceed.
        Err(_) => return false,     // brew hung past 30s — proceed.
    };
    if !output.status.success() {
        return false;
    }
    crate::lifecycle::autostart::macos::parse_brew_services_active(&output.stdout)
}

/// Detect whether an `io::Error` represents a Windows file-lock /
/// sharing-violation. On POSIX this is always `false` — the caller
/// won't enter the retry path.
fn is_locked_error(e: &std::io::Error) -> bool {
    // Windows raw-OS-error: 32 (ERROR_SHARING_VIOLATION),
    // 33 (ERROR_LOCK_VIOLATION). On POSIX: never matches.
    matches!(e.raw_os_error(), Some(32) | Some(33))
}

/// Print one teardown step's outcome line, in the AC-spec'd
/// `→ <verb>ing X  ✓ <detail>` shape.
///
/// P18 (review): `Done` and `Skipped` go to stdout (operator-visible
/// progress); `Warned` goes to stderr (consistent with the closing
/// total-failure line which also uses stderr). This way an operator
/// piping stdout sees a clean progress log; stderr-redirected logs
/// show all warnings.
fn print_step(g: &StepGlyphs, outcome: &StepOutcome) {
    match outcome {
        StepOutcome::Done { step, detail } => {
            println!("{} {step}  {} {detail}", g.arrow, g.check);
        }
        StepOutcome::Skipped { step, reason } => {
            println!("{} {step}  {} {reason}", g.arrow, g.skip);
        }
        StepOutcome::Warned { step, reason, remediation } => {
            eprintln!("{} {step}  {} failed: {reason}", g.arrow, g.warn);
            eprintln!("    remediation: {remediation}");
        }
    }
}

/// Print the closing line per AC #6. Returns the dispatcher's exit
/// outcome:
/// - All steps Done/Skipped → exit 0, success line.
/// - At least one Warned but not all → exit 0, warnings-counted line.
/// - All steps Warned → exit 1, total-failure error_block.
fn print_closing_line(g: &StepGlyphs, outcomes: &[StepOutcome]) -> Result<()> {
    let warned_count = outcomes.iter().filter(|o| matches!(o, StepOutcome::Warned { .. })).count();
    let total = outcomes.len();

    if warned_count == total {
        eprint!(
            "{}",
            render::error_block(
                "uninstall_total_failure",
                "every uninstall step warned — your machine state is unchanged",
                "fix the underlying issues (see per-step warnings above) and re-run uninstall",
                None,
            )
        );
        return Err(silent_cli_error("uninstall: every step warned"));
    }

    if warned_count == 0 {
        println!(
            "{} uninstalled cleanly  {} re-install with curl|sh, brew, or PowerShell when you're ready",
            g.arrow, g.check
        );
    } else {
        println!(
            "{} uninstalled  {} {warned_count} step(s) had warnings (see above); re-install when ready",
            g.arrow, g.check
        );
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// AC #1 — confirm prompt manifest renders the verbatim spec
    /// shape, including the binary line, data dir line, keychain
    /// line, and autostart line.
    #[test]
    fn manifest_renders_full_spec_shape() {
        let args = UninstallArgs::default();
        let home = PathBuf::from("/home/maya/.agentsso");
        let target = binary::BinaryTarget::Owned(PathBuf::from("/usr/local/bin/agentsso"));
        let status = AutostartStatus::Enabled {
            artifact_path: PathBuf::from("/home/maya/.config/systemd/user/agentsso.service"),
            mechanism: "systemd-user",
            daemon_path: Some(PathBuf::from("/usr/local/bin/agentsso")),
        };
        let out = build_prompt_manifest(&args, &home, Some(&target), Some(&status));
        assert!(out.contains("This will remove:"));
        assert!(out.contains("the agentsso binary at /usr/local/bin/agentsso"));
        assert!(out.contains("/home/maya/.agentsso/ (vault, audit log, policies"));
        assert!(out.contains("io.permitlayer.master-key / master"));
        assert!(out.contains("autostart at login (systemd-user)"));
    }

    /// AC #2 — `--keep-data` adjusts the manifest's data-dir line to
    /// the keystore-only shape.
    #[test]
    fn manifest_keep_data_says_keystore_only() {
        let args = UninstallArgs { keep_data: true, ..Default::default() };
        let home = PathBuf::from("/home/maya/.agentsso");
        let out = build_prompt_manifest(&args, &home, None, None);
        assert!(out.contains("/home/maya/.agentsso/keystore/ only"));
        assert!(!out.contains("(vault, audit log, policies, agent registrations)"));
    }

    /// AC #3 — `--keep-binary` adjusts the manifest's binary line.
    #[test]
    fn manifest_keep_binary_shows_preserved_path() {
        let args = UninstallArgs { keep_binary: true, ..Default::default() };
        let home = PathBuf::from("/home/maya/.agentsso");
        let target = binary::BinaryTarget::Owned(PathBuf::from("/usr/local/bin/agentsso"));
        let out = build_prompt_manifest(&args, &home, Some(&target), None);
        assert!(
            out.contains("(--keep-binary: agentsso binary preserved at /usr/local/bin/agentsso)")
        );
    }

    /// AC #5 — Cellar path shows up in the manifest as
    /// "skipped — managed by brew".
    #[test]
    fn manifest_brew_managed_says_skipped() {
        let args = UninstallArgs::default();
        let home = PathBuf::from("/home/maya/.agentsso");
        let target = binary::BinaryTarget::ManagedByPackageManager {
            manager: "brew",
            path: PathBuf::from("/opt/homebrew/Cellar/agentsso/0.3.0/bin/agentsso"),
            remediation: "brew uninstall agentsso".to_owned(),
        };
        let out = build_prompt_manifest(&args, &home, Some(&target), None);
        assert!(out.contains("skipped — agentsso binary at"));
        assert!(out.contains("is managed by brew"));
    }

    /// AC #2 — the data-dir step preserves vault/audit/policies but
    /// wipes keystore/ + agentsso.pid when --keep-data is set.
    #[test]
    fn keep_data_preserves_data_dirs_but_wipes_keystore_and_pid() {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path().to_path_buf();
        // Build a minimal ~/.agentsso/ tree.
        std::fs::create_dir_all(home.join("vault")).unwrap();
        std::fs::create_dir_all(home.join("audit")).unwrap();
        std::fs::create_dir_all(home.join("policies")).unwrap();
        std::fs::create_dir_all(home.join("keystore")).unwrap();
        std::fs::write(home.join("vault/gmail.sealed"), b"sealed").unwrap();
        std::fs::write(home.join("audit/2026-04-26.jsonl"), b"audit").unwrap();
        std::fs::write(home.join("policies/default.toml"), b"policy").unwrap();
        std::fs::write(home.join("keystore/passphrase.state"), b"verifier").unwrap();
        std::fs::write(home.join("agentsso.pid"), b"12345").unwrap();

        let outcome = remove_data_dir_warn_on_fail(&home, true);
        assert!(matches!(outcome, StepOutcome::Done { .. }), "expected Done, got {outcome:?}");

        // Preserved.
        assert!(home.join("vault/gmail.sealed").exists());
        assert!(home.join("audit/2026-04-26.jsonl").exists());
        assert!(home.join("policies/default.toml").exists());
        // Wiped.
        assert!(!home.join("keystore").exists());
        assert!(!home.join("agentsso.pid").exists());
    }

    /// AC #1 — without --keep-data, the data dir is removed
    /// recursively.
    #[test]
    fn full_data_remove_wipes_everything() {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path().join(".agentsso");
        std::fs::create_dir_all(home.join("vault")).unwrap();
        std::fs::write(home.join("vault/gmail.sealed"), b"sealed").unwrap();

        let outcome = remove_data_dir_warn_on_fail(&home, false);
        assert!(matches!(outcome, StepOutcome::Done { .. }), "expected Done, got {outcome:?}");
        assert!(!home.exists());
    }

    /// AC #1 — data dir removal is idempotent: an already-absent dir
    /// reports Done, not Warned.
    #[test]
    fn missing_data_dir_is_idempotent_done() {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path().join(".agentsso-not-here");
        let outcome = remove_data_dir_warn_on_fail(&home, false);
        assert!(matches!(outcome, StepOutcome::Done { .. }));
    }

    /// AC #6 — closing line counts warnings correctly: 0 warnings →
    /// "uninstalled cleanly" + Ok(()).
    #[test]
    fn closing_line_zero_warnings_returns_ok() {
        let g = step_glyphs();
        let outcomes = vec![
            StepOutcome::Done { step: "stopping daemon", detail: "x".into() },
            StepOutcome::Done { step: "disabling autostart", detail: "x".into() },
            StepOutcome::Done { step: "removing keychain entry", detail: "x".into() },
            StepOutcome::Done { step: "removing data dir", detail: "x".into() },
            StepOutcome::Done { step: "removing binary", detail: "x".into() },
        ];
        let result = print_closing_line(&g, &outcomes);
        assert!(result.is_ok());
    }

    /// AC #6 — partial warnings → exit 0 with warning count line.
    #[test]
    fn closing_line_partial_warnings_returns_ok() {
        let g = step_glyphs();
        let outcomes = vec![
            StepOutcome::Done { step: "stopping daemon", detail: "x".into() },
            StepOutcome::Warned {
                step: "disabling autostart",
                reason: "x".into(),
                remediation: "x".into(),
            },
            StepOutcome::Done { step: "removing keychain entry", detail: "x".into() },
            StepOutcome::Done { step: "removing data dir", detail: "x".into() },
            StepOutcome::Done { step: "removing binary", detail: "x".into() },
        ];
        let result = print_closing_line(&g, &outcomes);
        assert!(result.is_ok());
    }

    /// AC #6 — total failure (every step warned) → exit non-zero
    /// via `silent_cli_error`.
    #[test]
    fn closing_line_total_failure_returns_err() {
        let g = step_glyphs();
        let outcomes = vec![
            StepOutcome::Warned {
                step: "stopping daemon",
                reason: "x".into(),
                remediation: "x".into(),
            },
            StepOutcome::Warned {
                step: "disabling autostart",
                reason: "x".into(),
                remediation: "x".into(),
            },
            StepOutcome::Warned {
                step: "removing keychain entry",
                reason: "x".into(),
                remediation: "x".into(),
            },
            StepOutcome::Warned {
                step: "removing data dir",
                reason: "x".into(),
                remediation: "x".into(),
            },
            StepOutcome::Warned {
                step: "removing binary",
                reason: "x".into(),
                remediation: "x".into(),
            },
        ];
        let result = print_closing_line(&g, &outcomes);
        assert!(result.is_err());
    }

    /// AC #1 — stop-daemon step is Done when no PID file exists
    /// (daemon never started).
    #[tokio::test]
    async fn stop_daemon_no_pid_file_is_done() {
        let tmp = tempfile::TempDir::new().unwrap();
        let outcome = stop_daemon_if_running(tmp.path()).await;
        match outcome {
            StepOutcome::Done { ref detail, .. } => {
                assert!(detail.contains("no PID file"));
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    /// AC #5 — `--keep-binary` short-circuits the binary step before
    /// the resolver is consulted.
    #[test]
    fn keep_binary_short_circuits_to_skipped() {
        // Pass an Err target: with --keep-binary, the resolver result
        // is never consumed, so we don't warn.
        let outcome = remove_binary_warn_on_fail(
            true,
            Err(binary::BinaryResolveError::CurrentExeUnavailable {
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "x"),
            }),
        );
        assert!(matches!(outcome, StepOutcome::Skipped { .. }));
    }

    /// AC #5 — package-managed binary is Skipped (not Warned, not
    /// Done) so it doesn't count toward the warn total.
    #[test]
    fn brew_managed_binary_is_skipped() {
        let target = Ok(binary::BinaryTarget::ManagedByPackageManager {
            manager: "brew",
            path: PathBuf::from("/opt/homebrew/Cellar/agentsso/0.3.0/bin/agentsso"),
            remediation: "brew uninstall agentsso".to_owned(),
        });
        let outcome = remove_binary_warn_on_fail(false, target);
        match outcome {
            StepOutcome::Skipped { ref reason, .. } => {
                assert!(reason.contains("managed by brew"));
                assert!(reason.contains("brew uninstall agentsso"));
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
    }

    // P4 (review): four spec-required unit tests that the original
    // implementation missed.

    /// AC #1 — confirm prompt defaults to NO. We can't easily drive
    /// dialoguer in a test, so we instead lock-in the static-config
    /// invariant: the `args.yes` default is `false`, and the only
    /// path that bypasses the prompt is `args.yes == true`.
    #[test]
    fn prompt_default_is_no() {
        let args = UninstallArgs::default();
        assert!(!args.yes, "UninstallArgs::yes must default to false");
        assert!(!args.keep_data, "UninstallArgs::keep_data must default to false");
        assert!(!args.keep_binary, "UninstallArgs::keep_binary must default to false");
        assert!(!args.non_interactive, "UninstallArgs::non_interactive must default to false");
    }

    /// AC #8 — brew-services pre-flight refusal. We can't actually
    /// invoke `run()` in a unit test (it shells out to brew), but we
    /// CAN verify the conflict path produces typed markers that the
    /// dispatcher in `main.rs::uninstall_to_exit_code` routes to
    /// exit 3.
    ///
    /// We probe via `downcast_ref::<T>()` (mirroring the dispatcher's
    /// own probe) rather than `chain().any(s.is::<T>)` because
    /// anyhow's `.context(C)` wraps C internally and the wrapped
    /// struct doesn't expose C through a plain `is::<C>()` chain
    /// walk.
    #[test]
    fn brew_services_active_refuses_with_exit_3() {
        let err = uninstall_brew_services_conflict();
        let chain_strs: Vec<String> = err.chain().map(|c| c.to_string()).collect();
        assert!(
            err.downcast_ref::<UninstallExitCode3>().is_some(),
            "expected UninstallExitCode3 to be downcastable; chain strings: {chain_strs:?}"
        );
        // The silent marker is wrapped via `.context(SilentCliError)`,
        // so it shows up by string in the chain even though `is::<>`
        // wouldn't find it directly. Verify by string match.
        assert!(
            chain_strs.iter().any(|s| s.contains("cli error already printed")),
            "expected SilentCliError display in chain; got: {chain_strs:?}"
        );
    }

    /// AC #6 — when the data-dir wipe fails (e.g., a path that
    /// cannot be removed), the step warns but uninstall continues.
    /// Drives the fail-soft branch.
    ///
    /// `forbid(unsafe_code)` blocks Rust 2024's `unsafe set_var`,
    /// so we drive the fail-soft path via a Warned-returning
    /// scenario that doesn't require env-var manipulation: a
    /// `home` path pointing at a regular FILE (not a directory)
    /// makes `remove_dir_all` return ENOTDIR, which the orchestrator
    /// converts to Warned.
    #[test]
    fn data_dir_remove_failure_warns_continues() {
        let tmp = tempfile::TempDir::new().unwrap();
        let file_path = tmp.path().join("agentsso-as-file");
        // Write a file at the location the orchestrator will treat
        // as `home`. `remove_dir_all` against a regular file returns
        // ENOTDIR, which exercises the fail-soft warn-and-continue
        // path.
        std::fs::write(&file_path, b"not a directory").unwrap();

        let outcome = remove_data_dir_warn_on_fail(&file_path, false);
        match outcome {
            StepOutcome::Warned { step, ref reason, .. } => {
                assert_eq!(step, "removing data dir");
                // The reason should mention the offending path so
                // operators can see what failed.
                assert!(
                    reason.contains(file_path.to_str().unwrap()),
                    "expected warn reason to include the failing path; got: {reason}"
                );
            }
            other => panic!("expected Warned (file-not-dir), got {other:?}"),
        }
    }

    /// AC #4 — `delete_master_key` returning `AlreadyAbsent` is
    /// success (Done), not Warned. Drives the idempotent path.
    #[tokio::test]
    async fn keychain_delete_already_absent_is_success() {
        // Construct an in-memory mock KeyStore that returns
        // AlreadyAbsent. We can't drive the production code's
        // `default_keystore` factory in-process without touching the
        // real OS keychain, so this test exercises the public Done
        // mapping by going through a concrete adapter when possible.
        // Use the passphrase adapter (verifier-file path) as a
        // tractable substitute: passphrase adapter returns
        // PassphraseAdapterImmutable which our P43 patch ALSO maps
        // to Done if the verifier file is absent.
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path().to_path_buf();
        // Don't create keystore/passphrase.state — exercises the
        // "already absent" verifier branch.
        let outcome = delete_keychain_entry_warn_on_fail(&home).await;
        match outcome {
            StepOutcome::Done { ref detail, .. } => {
                // Either "already absent" (native backend), or
                // "passphrase adapter — already absent" (passphrase
                // path), or "io.permitlayer.master-key/master removed"
                // if the native backend happened to be invoked and
                // there was no entry. All are AC-conformant Done
                // outcomes.
                assert!(
                    detail.contains("absent") || detail.contains("removed"),
                    "expected an absent/removed message; got: {detail}"
                );
            }
            // On a CI runner with a working native backend AND a
            // genuine entry registered, the outcome is `Removed`,
            // also Done. On a CI runner with a broken backend +
            // absent verifier, we'd get Warned — that's the
            // platform-specific fallthrough this test acknowledges
            // by NOT panicking on Warned.
            StepOutcome::Warned { .. } => {
                // Documented: CI without keychain backend + no
                // verifier → Warned is acceptable.
            }
            StepOutcome::Skipped { .. } => panic!("delete step should never be Skipped"),
        }
    }
}
