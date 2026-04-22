//! `agentsso audit` — filterable historical query + live-tail +
//! one-shot export audit log viewer.
//!
//! # Story evolution
//!
//! - **Story 1.9** shipped the `--follow` live tail scaffold (250 ms
//!   poll of `<today>.jsonl`).
//! - **Story 5.1** added the filterable historical query path and the
//!   shared [`permitlayer_core::audit::reader::AuditReader`] primitive
//!   (`AuditFilter`, `scrub_count_for`, `parse_duration`, rotation-
//!   aware file enumeration) plus the design-system `table` + `audit
//!   _row_cells` + `AuditFooter` surface.
//! - **Story 5.2** replaced the Story 1.9 poll with a `notify`-backed
//!   watcher, added rolling-window anomaly detection, and filter-aware
//!   live tail. Promoted `build_filter_from_args`, `parse_time_arg`,
//!   `resolve_audit_dir`, and `resolve_home` to `pub(super)` so
//!   follow-mode could reuse them.
//! - **Story 5.3** adds `--export=<path>` and `--format=json|csv` for
//!   one-shot forensic-artifact export. Dispatch is in
//!   [`run`] and delegates to
//!   [`crate::cli::audit_export::run_export`]. Reuses `build_filter
//!   _from_args` + `AuditReader::query` identically to the query path,
//!   but writes a filtered event set to disk (JSON array or RFC 4180
//!   CSV) instead of to the terminal. `--export + --follow` is
//!   rejected at argument-validation time.
//!
//! # Command dispatch
//!
//! - `agentsso audit` with no flags → historical query, shows last
//!   100 events with a "showing last 100 events · use --since=24h
//!   for more" hint
//! - `agentsso audit --since=<dur> [--service=<name>] [...]` →
//!   historical query with filters
//! - `agentsso audit --follow [--since=<dur>] [filters]` → live tail
//!   (Story 5.2: filter-aware + optional `--since` replay)
//! - `agentsso audit --export=<path> [filters]` → one-shot export
//!   (Story 5.3)

use std::io::Write;
use std::path::PathBuf;

use permitlayer_core::audit::reader::{AuditFilter, AuditReader, AuditReaderError, parse_duration};
use tracing::warn;

// `AuditEvent` is only referenced by the tests module below (via
// `super::*`) and `scrub_count_for` is also test-only now that the
// main render path lives in `audit_follow`. Importing them under
// `#[cfg(test)]` keeps release-build imports tight.
#[cfg(test)]
use permitlayer_core::audit::event::AuditEvent;
#[cfg(test)]
use permitlayer_core::audit::reader::scrub_count_for;

use crate::cli::{agentsso_home, silent_cli_error};
use crate::config::{CliOverrides, DaemonConfig};
use crate::design::render::{
    AuditFooter, TableCell, audit_row_cells, audit_row_headers, empty_state, error_block, table,
};
use crate::design::terminal::{ColorSupport, TableLayout};
use crate::design::theme::Theme;

#[derive(clap::Args, Debug, Default)]
pub struct AuditArgs {
    /// Time range start: duration (30m, 24h, 7d, 2w) or RFC 3339 timestamp.
    #[arg(long)]
    pub since: Option<String>,

    /// Time range end: duration-ago (same semantics as --since) or RFC 3339.
    #[arg(long)]
    pub until: Option<String>,

    /// Filter by service (repeatable: --service=gmail --service=calendar).
    #[arg(long, action = clap::ArgAction::Append)]
    pub service: Vec<String>,

    /// Filter by agent name (repeatable).
    #[arg(long, action = clap::ArgAction::Append)]
    pub agent: Vec<String>,

    /// Filter by outcome (repeatable): ok, denied, error, scrubbed,
    /// already-active, already-inactive.
    #[arg(long, action = clap::ArgAction::Append)]
    pub outcome: Vec<String>,

    /// Filter by event type (repeatable): api-call, policy-violation,
    /// kill-activated, approval-granted, etc.
    #[arg(long = "event-type", action = clap::ArgAction::Append)]
    pub event_type: Vec<String>,

    /// Maximum rows to display (default 100 when no other filters).
    /// With --follow, applies to --since replay only — the live tail
    /// is unbounded (Ctrl-C exits). With --export, caps the exported
    /// event count at N (same semantics as the query path).
    #[arg(long)]
    pub limit: Option<usize>,

    /// Disable automatic paging via `less -R` when stdout is a TTY.
    /// Ignored with --follow (follow mode never pages) and with
    /// --export (export writes to a file, not a pager).
    #[arg(long)]
    pub no_pager: bool,

    /// Tail today's audit log and render new events live. Honors all
    /// filter flags (--service, --agent, --outcome, --event-type).
    /// --since replays matching history before switching to the live
    /// tail. --until is rejected (incompatible with live tail).
    /// Ctrl-C exits cleanly.
    #[arg(long)]
    pub follow: bool,

    /// Export filtered events to the given file path. Format is
    /// inferred from the path extension (.json / .csv), or pass
    /// --format to override. Incompatible with --follow.
    #[arg(long)]
    pub export: Option<PathBuf>,

    /// Explicit export format (overrides path extension inference):
    /// json or csv. Ignored when --export is not set.
    #[arg(long, value_parser = ["json", "csv"])]
    pub format: Option<String>,

    /// Allow overwriting an existing destination file. Default
    /// behavior refuses to overwrite and suggests --force.
    #[arg(long)]
    pub force: bool,
}

/// Entry point for `agentsso audit`.
pub async fn run(args: AuditArgs) -> anyhow::Result<()> {
    // Story 5.3: reject --export + --follow BEFORE any work is done.
    // Export is a one-shot snapshot; follow is an unbounded live tail.
    // The two semantics don't compose. Error fires here (not inside
    // run_export or run_follow) so a more-specific error wins over
    // either branch's generic rejection.
    if args.follow && args.export.is_some() {
        eprint!(
            "{}",
            error_block(
                "invalid_flag_combination",
                "--export is not supported with --follow",
                "follow mode is a live stream; export is a one-shot snapshot. drop one.",
                None,
            )
        );
        return Err(silent_cli_error("--export not supported with --follow"));
    }
    // Story 5.3: export dispatches into the `audit_export` module,
    // reusing `build_filter_from_args` and `AuditReader::query` from
    // Stories 5.1/5.2.
    if args.export.is_some() {
        return super::audit_export::run_export(args).await;
    }
    // Follow mode dispatches into the Story 5.2 `notify`-based
    // watcher + anomaly detector. Filters, `--since` replay, and
    // `--until` rejection are all handled inside `run_follow`.
    if args.follow {
        return super::audit_follow::run_follow(args).await;
    }
    run_query(args).await
}

/// Run the historical query path (Story 5.1).
async fn run_query(args: AuditArgs) -> anyhow::Result<()> {
    // 1. Resolve the audit directory.
    let audit_dir = resolve_audit_dir()?;
    if !audit_dir.exists() {
        eprint!(
            "{}",
            error_block(
                "audit_dir_missing",
                &format!("audit directory not found at {}", audit_dir.display()),
                "agentsso start",
                None,
            )
        );
        // H2: structured error already printed; suppress the generic
        // follow-up line `anyhow_to_exit_code` would otherwise add.
        return Err(silent_cli_error(format!(
            "audit directory not found at {}",
            audit_dir.display()
        )));
    }

    // 2. Parse filters into the shared `AuditFilter`.
    let filter = build_filter_from_args(&args)?;
    let was_any_filter = filter.is_active();

    // 3. Default behavior when no filter flag was passed:
    //    - apply an implicit `--since=24h` bound so the reader's
    //      file-level date filter kicks in (M5 fix: default query no
    //      longer scans the full 90-day retention)
    //    - apply a default `--limit=100` when the user didn't specify
    //      their own
    //    The caller may still pass `--limit=50` without narrowing
    //    time/service/etc., in which case `was_any_filter` is still
    //    `false` (M2 fix: `is_active()` no longer treats `limit` as
    //    a filter axis) and the hint still prints.
    let mut effective_filter = filter.clone();
    let default_applied = !was_any_filter;
    if default_applied {
        // M5: 24h implicit time bound to avoid scanning the full
        // retention. Matches the `use --since=24h for more` hint.
        if effective_filter.since.is_none() {
            effective_filter.since = Some(chrono::Utc::now() - chrono::Duration::hours(24));
        }
        if effective_filter.limit.is_none() {
            effective_filter.limit = Some(100);
        }
    }

    // 4. Query.
    let reader = AuditReader::new(audit_dir);
    let events = match reader.query(&effective_filter) {
        Ok(e) => e,
        Err(AuditReaderError::AuditDirMissing { path }) => {
            // Race between our own check above and the query — very
            // unlikely but handled for completeness.
            eprint!(
                "{}",
                error_block(
                    "audit_dir_missing",
                    &format!("audit directory not found at {}", path.display()),
                    "agentsso start",
                    None,
                )
            );
            return Err(silent_cli_error(format!(
                "audit directory not found at {}",
                path.display()
            )));
        }
        Err(AuditReaderError::Io { path, source }) => {
            eprint!(
                "{}",
                error_block(
                    "audit_io_error",
                    &format!("failed to read audit log at {}: {source}", path.display()),
                    "check ~/.agentsso/audit/ permissions",
                    None,
                )
            );
            return Err(silent_cli_error(format!(
                "audit I/O error at {}: {source}",
                path.display()
            )));
        }
    };

    // 5. Empty result: print empty_state and exit 0.
    if events.is_empty() {
        print!(
            "{}",
            empty_state(
                "no events matched these filters",
                "widen the range: agentsso audit --since=24h",
            )
        );
        return Ok(());
    }

    // 6. Render the table + footer.
    let theme = Theme::load(&resolve_home()?);
    let support = ColorSupport::detect();
    let layout = TableLayout::detect();

    let rows: Vec<Vec<TableCell>> = events.iter().map(|e| audit_row_cells(e, layout)).collect();
    let table_str = table(audit_row_headers(layout), &rows, layout, &theme, support)?;
    let footer = AuditFooter::from_events(&events);

    // 7. Assemble output (table + blank line + footer + optional hint).
    //    L16 fix: caller owns the leading indent on the footer line.
    let mut output = String::with_capacity(table_str.len() + 256);
    output.push_str(&table_str);
    output.push('\n');
    output.push_str("  ");
    output.push_str(&footer.render());
    output.push('\n');
    if default_applied {
        // Default-behavior hint: only when no filter flags were
        // passed. Imperative/declarative voice per §11.4.
        // Respects the user's `--limit` if they passed one, otherwise
        // the default of 100.
        let limit = effective_filter.limit.unwrap_or(100);
        output.push('\n');
        output.push_str(&format!(
            "  showing last {limit} events \u{00B7} use --since=24h for more\n"
        ));
    }

    // 8. Emit to stdout, optionally via pager.
    emit_output(&output, args.no_pager);
    Ok(())
}

/// Build an `AuditFilter` from the CLI args, parsing `--since` /
/// `--until` and validating `--outcome` / `--limit` values.
pub(super) fn build_filter_from_args(args: &AuditArgs) -> anyhow::Result<AuditFilter> {
    let mut filter = AuditFilter::new();

    if let Some(ref since_str) = args.since {
        filter.since = Some(parse_time_arg(since_str, "--since")?);
    }
    if let Some(ref until_str) = args.until {
        // `--until=<duration>` interpreted as "duration ago" for
        // symmetry with `--since`. Absolute RFC 3339 timestamps
        // interpreted literally.
        filter.until = Some(parse_time_arg(until_str, "--until")?);
    }
    // Sanity check: since must be <= until if both are set.
    if let (Some(since), Some(until)) = (filter.since, filter.until)
        && since > until
    {
        eprint!(
            "{}",
            error_block(
                "invalid_time_range",
                "--since must be earlier than --until",
                "swap the values or drop one of them",
                None,
            )
        );
        return Err(silent_cli_error("invalid time range: since > until"));
    }

    filter.services = args.service.clone();
    filter.agents = args.agent.clone();

    // Validate --outcome values against the known set.
    // L17: kept in lockstep with `design::render::outcome_from_str`.
    // `allowed` is a forward-compat synonym for `ok` that `outcome_from_str`
    // already accepts, so we accept it here too even though no current
    // event emitter writes it — that way the two lists can't silently
    // drift and a future event source using `allowed` remains filterable.
    const VALID_OUTCOMES: &[&str] =
        &["ok", "allowed", "denied", "error", "scrubbed", "already-active", "already-inactive"];
    for outcome in &args.outcome {
        if !VALID_OUTCOMES.contains(&outcome.as_str()) {
            eprint!(
                "{}",
                error_block(
                    "invalid_outcome",
                    &format!("'{outcome}' is not a valid outcome"),
                    "use one of: ok, denied, error, scrubbed, already-active, already-inactive",
                    None,
                )
            );
            return Err(silent_cli_error(format!("invalid --outcome value: {outcome}")));
        }
    }
    filter.outcomes = args.outcome.clone();
    filter.event_types = args.event_type.clone();

    // M8: reject `--limit=0` explicitly. A zero limit accepted by clap
    // would produce an empty `events` Vec that renders as the
    // "no events matched" empty_state — misleading when the user
    // literally asked for zero rows. Bounce with a structured error.
    if let Some(0) = args.limit {
        eprint!(
            "{}",
            error_block(
                "invalid_limit",
                "--limit=0 returns no rows by definition",
                "use --limit=1 or higher",
                None,
            )
        );
        return Err(silent_cli_error("invalid --limit value: 0"));
    }
    filter.limit = args.limit;

    Ok(filter)
}

/// Parse a time argument (either a duration-ago like `30m`/`24h`/`7d`
/// or an absolute RFC 3339 timestamp).
///
/// H1 + H2 fixes: uses `checked_sub_signed` instead of the `Sub`
/// operator so chrono overflows surface as a structured
/// `invalid_duration` error instead of panicking the CLI. All error
/// paths emit a structured `error_block` and wrap the returned
/// `anyhow::Error` with [`silent_cli_error`] so `anyhow_to_exit_code`
/// doesn't print a duplicate generic `error: ...` line.
/// Parse a `--since`/`--until` argument into a UTC timestamp.
///
/// Accepts an RFC 3339 absolute timestamp OR a duration-ago token
/// (`30m`, `24h`, `7d`, `2w`). Invalid input emits an
/// `invalid_duration` error block and returns `silent_cli_error`.
///
/// Promoted to `pub(crate)` by Story 5.4 so `cli::logs` can reuse the
/// same parse rules + error voice.
pub(crate) fn parse_time_arg(
    s: &str,
    flag_name: &str,
) -> anyhow::Result<chrono::DateTime<chrono::Utc>> {
    use chrono::Utc;

    // Try absolute RFC 3339 first. If it parses cleanly, use it.
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }

    // Otherwise interpret as a duration-ago.
    let emit_invalid = |detail: String| -> anyhow::Error {
        eprint!(
            "{}",
            error_block(
                "invalid_duration",
                &format!("could not parse {flag_name} value '{s}': {detail}"),
                "examples: --since=30m --since=24h --since=7d --since=2026-04-14T00:00:00Z",
                None,
            )
        );
        silent_cli_error(format!("could not parse {flag_name}='{s}': {detail}"))
    };

    let dur = match parse_duration(s) {
        Ok(d) => d,
        Err(e) => return Err(emit_invalid(e.to_string())),
    };

    let chrono_dur = match chrono::Duration::from_std(dur) {
        Ok(d) => d,
        Err(_) => return Err(emit_invalid("duration too large to represent".into())),
    };

    // H1: `Utc::now() - chrono_dur` expands to `checked_sub_signed(rhs)
    // .expect("overflowed")` — a panic we must not expose to operators.
    // Use `checked_sub_signed` directly and map overflow to the
    // structured error.
    match Utc::now().checked_sub_signed(chrono_dur) {
        Some(dt) => Ok(dt),
        None => Err(emit_invalid("duration overflows representable time range".into())),
    }
}

/// Emit rendered output to stdout, optionally via `less -R`.
///
/// When stdout is a TTY and `--no-pager` is not set, pipe through
/// `less -R` (which preserves ANSI color escapes). Otherwise write
/// directly to stdout with broken-pipe-safe `writeln!` (the locked
/// stdout + swallow-EPIPE pattern matches the existing follow loop
/// precedent at `render_event_line`).
///
/// Promoted to `pub(crate)` by Story 5.4 so `cli::logs` can share the
/// same pager semantics as `cli::audit`.
pub(crate) fn emit_output(output: &str, no_pager: bool) {
    use std::io::IsTerminal;

    let use_pager = !no_pager && std::io::stdout().is_terminal();

    if use_pager {
        // Try to spawn `less -R`. If it's not found or fails to
        // launch, fall back to direct stdout (warn in tracing, not
        // as an error).
        match std::process::Command::new("less")
            .arg("-R")
            .stdin(std::process::Stdio::piped())
            .spawn()
        {
            Ok(mut child) => {
                if let Some(mut stdin) = child.stdin.take() {
                    // Ignore write errors — less may close early on
                    // Ctrl-C or `q`.
                    let _ = stdin.write_all(output.as_bytes());
                }
                // Wait for `less` to exit before returning so the
                // terminal is properly restored.
                //
                // L11: inspect the pager exit status. If the pager
                // failed to launch the interactive UI at all (exit
                // status != 0 and stdin write failed), fall back to
                // direct stdout so the operator doesn't stare at an
                // empty terminal thinking the query found nothing.
                match child.wait() {
                    Ok(status) if status.success() => return,
                    Ok(status) => {
                        warn!(
                            exit_status = ?status,
                            "pager 'less' exited non-zero; falling back to direct stdout"
                        );
                    }
                    Err(e) => {
                        warn!(error = %e, "wait() on pager 'less' failed; falling back to direct stdout");
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to spawn pager 'less'; falling back to direct stdout");
            }
        }
    }

    // Direct stdout, broken-pipe-safe.
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(output.as_bytes());
    let _ = out.flush();
}

// `run_follow`, `follow_loop`, `render_event_line`, `sample_is_renderable`,
// and `today_filename` all moved to `cli/audit_follow.rs` in Story 5.2
// when the Story 1.9 250ms polling scaffold was replaced with a
// `notify`-based filesystem watcher. See `audit_follow::run_follow` for
// the new entry point dispatched by `run` above.

pub(super) fn resolve_home() -> anyhow::Result<PathBuf> {
    // L9: honor the daemon config layer just like `resolve_audit_dir`
    // so the theme is loaded from the same `paths.home` the audit
    // files are read from. Falls back to `agentsso_home()` (env var
    // or dirs::home_dir) if config loading fails — the operator's
    // theme choice is not worth blocking the whole query on a
    // config parse error.
    match DaemonConfig::load(&CliOverrides::default()) {
        Ok(config) => Ok(config.paths.home),
        Err(_) => agentsso_home(),
    }
}

pub(super) fn resolve_audit_dir() -> anyhow::Result<PathBuf> {
    // Respect daemon config (honors AGENTSSO_PATHS__HOME via figment).
    // Propagate parse errors instead of silently defaulting: a broken
    // config should surface as an error, not tail the wrong directory.
    let config = DaemonConfig::load(&CliOverrides::default())?;
    Ok(config.paths.home.join("audit"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ----- scrub_count_for v1/v2 shape fallback (Story 2.6 review patch) -----
    //
    // `render_event_line`, `today_filename`, and `sample_is_renderable`
    // tests moved to `cli/audit_follow.rs` in Story 5.2 along with the
    // functions themselves.

    #[test]
    fn scrub_count_for_v2_reads_summary() {
        let mut event = AuditEvent::new(
            "a".into(),
            "s".into(),
            "sc".into(),
            "r".into(),
            "ok".into(),
            "api-call".into(),
        );
        event.schema_version = 2;
        event.extra = serde_json::json!({
            "scrub_events": {
                "summary": { "otp-6digit": 3, "email": 2 },
                "samples": []
            }
        });
        assert_eq!(scrub_count_for(&event), 5);
    }

    #[test]
    fn scrub_count_for_v1_reads_flat_map() {
        let mut event = AuditEvent::new(
            "a".into(),
            "s".into(),
            "sc".into(),
            "r".into(),
            "ok".into(),
            "api-call".into(),
        );
        event.schema_version = 1;
        event.extra = serde_json::json!({
            "scrub_events": { "otp-6digit": 3, "email": 2 }
        });
        // v1 flat shape — total is 5, not 0.
        assert_eq!(scrub_count_for(&event), 5);
    }

    #[test]
    fn scrub_count_for_missing_extra_returns_zero() {
        let event = AuditEvent::new(
            "a".into(),
            "s".into(),
            "sc".into(),
            "r".into(),
            "ok".into(),
            "api-call".into(),
        );
        assert_eq!(scrub_count_for(&event), 0);
    }

    #[test]
    fn scrub_count_for_v1_with_unexpected_summary_key_prefers_summary() {
        // Defensive path: v1 event that happens to have been written
        // with the v2 shape (e.g. the schema_version bump was missed).
        let mut event = AuditEvent::new(
            "a".into(),
            "s".into(),
            "sc".into(),
            "r".into(),
            "ok".into(),
            "api-call".into(),
        );
        event.schema_version = 1;
        event.extra = serde_json::json!({
            "scrub_events": {
                "summary": { "otp-6digit": 7 },
                "samples": []
            }
        });
        assert_eq!(scrub_count_for(&event), 7);
    }

    // ─────────────────────────────────────────────────────────────
    // Dispatch logic (Story 5.3 AC #16 + Task 1.4)
    // ─────────────────────────────────────────────────────────────

    /// H5 / Task 1.4 / AC #16: `--export` + `--follow` is rejected
    /// at argument-validation time. Error chain must carry
    /// `SilentCliError` and the internal description must mention
    /// both flags.
    #[test]
    fn run_rejects_export_with_follow_combination() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();

        let args = AuditArgs {
            follow: true,
            export: Some(std::path::PathBuf::from("out.json")),
            ..AuditArgs::default()
        };

        let err = runtime.block_on(run(args)).unwrap_err();
        assert!(
            err.chain().any(|s| s.is::<crate::cli::SilentCliError>()),
            "error chain must carry SilentCliError (no duplicate trailer)"
        );
        let msg = format!("{err:#}");
        assert!(
            msg.contains("--export") && msg.contains("--follow"),
            "error message must mention both --export and --follow: {msg}"
        );
    }

    /// H5 / AC #16: when `--export` is set (without `--follow`),
    /// dispatch routes into the export module. We can't exercise
    /// the full export path here without a real audit dir, but we
    /// can confirm that dispatch REACHES the export module by
    /// running with a non-existent audit dir + a destination whose
    /// parent doesn't exist — the `export_parent_missing` error
    /// block is unique to `audit_export::validate_destination` and
    /// proves dispatch landed in the right branch.
    #[test]
    fn export_flag_dispatches_to_audit_export_module() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();

        let args = AuditArgs {
            export: Some(std::path::PathBuf::from("/definitely-does-not-exist/deeper/out.json")),
            ..AuditArgs::default()
        };

        let err = runtime.block_on(run(args)).unwrap_err();
        assert!(err.chain().any(|s| s.is::<crate::cli::SilentCliError>()));
        let msg = format!("{err:#}");
        // `export parent directory missing` is the unique string
        // from `audit_export::validate_destination`'s
        // `export_parent_missing` path — proves dispatch routed to
        // the export module, not the query or follow path.
        assert!(
            msg.contains("export parent directory missing"),
            "dispatch should have landed in audit_export::run_export; got: {msg}"
        );
    }
}
