//! `agentsso status` — daemon health snapshot, active-connection
//! table, and live-watch tail (FR83).
//!
//! # Story evolution
//!
//! - Pre-Story-5.5: one-shot summary backed by `/health`.
//! - Story 5.5: `--connections` table backed by the new
//!   `/v1/control/connections` endpoint, and `--watch` redraw loop.
//!
//! # Dispatch matrix
//!
//! | flags                              | path                              |
//! |------------------------------------|-----------------------------------|
//! | (none) / `--json`                  | existing `/health` summary        |
//! | `--connections`                    | one-shot connections table        |
//! | `--connections --json`             | connections JSON, no table render |
//! | `--connections --watch`            | redraw loop (Ctrl-C exits)        |
//! | `--watch` alone                    | rejected — `invalid_flag_combination` |
//! | `--connections --watch --json`     | rejected — `invalid_flag_combination` |
//!
//! # Why clear-screen, not ratatui
//!
//! `ratatui` is not in the workspace and adding it for one screen
//! would be ~40 transitive crates and a new ownership model
//! (alternate-screen + raw-mode + draw frames). UX-DR13 says
//! "auto-updating, keyboard-interruptible" — raw ANSI clear-screen
//! (`\x1b[2J\x1b[H`) + reprint satisfies both, matching the
//! simplicity of Story 5.2's `audit --follow` (which also avoids
//! ratatui).

use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::cli::silent_cli_error;
use crate::config::{CliOverrides, DaemonConfig};
use crate::design::format::{format_count, format_duration, format_timestamp};
use crate::design::render::{TableCell, empty_state, error_block, table};
use crate::design::terminal::{ColorSupport, TableLayout, styled};
use crate::design::theme::Theme;
use crate::lifecycle::pid::PidFile;

#[derive(clap::Args)]
pub struct StatusArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Show a table of currently-active agent connections instead of
    /// the one-shot daemon summary.
    #[arg(long)]
    pub connections: bool,

    /// Re-render the connections table on a 2s interval until Ctrl-C.
    /// Implies `--connections`; rejected without it.
    #[arg(long)]
    pub watch: bool,
}

pub async fn run(args: StatusArgs) -> anyhow::Result<()> {
    // -- Argument validation (must precede the PID guard so an
    //    obviously invalid invocation fails fast even when the
    //    daemon isn't running) --

    if args.watch && !args.connections {
        eprint!(
            "{}",
            error_block(
                "invalid_flag_combination",
                "--watch requires --connections",
                // M9 review patch: spec mandates "run: " prefix on
                // remediation strings (matches AC #12's symmetric
                // hint and the rest of the daemon's CLI vocabulary).
                "run: agentsso status --connections --watch",
                None,
            )
        );
        return Err(silent_cli_error("--watch requires --connections"));
    }
    if args.watch && args.json {
        eprint!(
            "{}",
            error_block(
                "invalid_flag_combination",
                "--watch and --json cannot be combined",
                "for a JSON event stream use: agentsso audit --follow --format=json",
                None,
            )
        );
        return Err(silent_cli_error("--watch and --json cannot be combined"));
    }

    let config = DaemonConfig::load(&CliOverrides::default()).unwrap_or_default();
    let home = config.paths.home.clone();

    // -- PID guard: applies to ALL paths (summary, connections, watch).
    let pid = match PidFile::read(&home)? {
        Some(pid) => pid,
        None => {
            eprintln!("daemon not running");
            std::process::exit(3);
        }
    };
    if !PidFile::is_daemon_running(&home)? {
        eprintln!("daemon not running (stale PID file for PID {pid})");
        std::process::exit(3);
    }

    let bind_addr = config.http.bind_addr;

    if args.connections && args.watch {
        return run_watch_loop(args.json, bind_addr).await;
    }
    if args.connections {
        return run_connections_once(args.json, bind_addr).await;
    }

    // Default: existing one-shot health summary.
    match fetch_health(bind_addr).await {
        Ok(mut body) => {
            // Story 7.7 P19: `/health` no longer exposes PID (LAN-leak
            // fix). The status CLI already has the PID from the local
            // PID file; inject it into the JSON output so operator
            // tooling that grepped `parsed["pid"]` keeps working.
            if let Some(obj) = body.as_object_mut() {
                obj.insert("pid".to_owned(), serde_json::json!(pid));
            }
            if args.json {
                println!("{}", serde_json::to_string_pretty(&body).unwrap_or_default());
            } else {
                print_human_status(&body, pid);
            }
        }
        Err(_) => print_fallback_status(pid, bind_addr, args.json),
    }
    Ok(())
}

// --------------------------------------------------------------------------
// /health summary path (pre-Story-5.5 behavior, preserved verbatim).
// --------------------------------------------------------------------------

/// Minimal HTTP GET to the /health endpoint using raw TCP.
/// The entire operation (connect + write + read) is bounded by a 5s timeout.
async fn fetch_health(addr: SocketAddr) -> anyhow::Result<serde_json::Value> {
    tokio::time::timeout(std::time::Duration::from_secs(5), fetch_health_inner(addr))
        .await
        .map_err(|_| anyhow::anyhow!("health check timed out after 5 seconds"))?
}

async fn fetch_health_inner(addr: SocketAddr) -> anyhow::Result<serde_json::Value> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut stream = TcpStream::connect(addr).await?;

    let request = format!("GET /health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let response = String::from_utf8_lossy(&response);

    // Parse the JSON body (everything after the blank line in HTTP response).
    let body_start = response.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let body = &response[body_start..];
    let value: serde_json::Value = serde_json::from_str(body)?;
    Ok(value)
}

fn print_human_status(body: &serde_json::Value, pid: u32) {
    let status = body["status"].as_str().unwrap_or("unknown");
    let uptime_secs = body["uptime_seconds"].as_u64().unwrap_or(0);
    let addr = body["bind_addr"].as_str().unwrap_or("unknown");
    let connections = body["active_connections"].as_u64().unwrap_or(0);
    let version = body["version"].as_str().unwrap_or("unknown");

    let uptime = format_duration(std::time::Duration::from_secs(uptime_secs));
    let conn_display = format_count(connections);

    println!("  status:       {status}");
    println!("  pid:          {pid}");
    println!("  uptime:       {uptime}");
    println!("  bind_addr:    {addr}");
    println!("  connections:  {conn_display}");
    println!("  version:      {version}");
}

fn print_fallback_status(pid: u32, bind_addr: SocketAddr, json: bool) {
    if json {
        let obj = serde_json::json!({
            "status": "running",
            "pid": pid,
            "bind_addr": bind_addr.to_string(),
            "note": "health endpoint unreachable, showing basic info"
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
    } else {
        println!("  status:       running (health endpoint unreachable)");
        println!("  pid:          {pid}");
        println!("  bind_addr:    {bind_addr}");
    }
}

// --------------------------------------------------------------------------
// /v1/control/connections client + table render (Story 5.5).
// --------------------------------------------------------------------------

/// Deserialization-side companion of `server::control::ConnectionRow`.
/// Also `Serialize` so the `--connections --json` path can re-emit the
/// response verbatim (the field set is identical to the daemon-side
/// `ConnectionRow`, and round-tripping keeps the two shapes locked).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ConnectionRow {
    pub agent_name: String,
    pub policy_name: String,
    pub connected_since: String,
    pub last_request_at: String,
    pub total_requests: u64,
    pub req_per_min: u64,
    pub req_per_hour: u64,
    #[serde(default)]
    pub baseline_per_min: Option<f64>,
    #[serde(default)]
    pub multiplier: Option<f64>,
}

/// Deserialization-side companion of `server::control::ConnectionsResponse`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ConnectionsResponse {
    pub connections: Vec<ConnectionRow>,
    pub generated_at: String,
}

/// Fetch the connections snapshot via the existing raw-TCP HTTP
/// helper used for all other control endpoints.
///
/// **M4 review patch:** uses the status-aware helper so a 4xx/5xx
/// response (e.g. `403 forbidden_not_loopback` when the daemon's
/// bind address is misconfigured to a non-loopback interface) is
/// surfaced as the daemon's actual error, not as a `serde_json`
/// "missing field" deserialization failure.
async fn fetch_connections(addr: SocketAddr) -> anyhow::Result<ConnectionsResponse> {
    let (status, body) =
        crate::cli::kill::http_get_with_status(addr, "/v1/control/connections").await?;
    if !(200..300).contains(&status) {
        // Try to extract the daemon's structured error code; fall
        // back to the raw body if unparseable. The control plane's
        // error shape is `{"error": {"code": "...", ...}}`.
        let code = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(|e| e.get("code"))
                    .and_then(|c| c.as_str())
                    .map(|s| s.to_owned())
            })
            .unwrap_or_else(|| format!("HTTP {status}"));
        return Err(anyhow::anyhow!("daemon returned {status}: {code}"));
    }
    let response: ConnectionsResponse = serde_json::from_str(&body)?;
    Ok(response)
}

async fn run_connections_once(json: bool, addr: SocketAddr) -> anyhow::Result<()> {
    let response = match fetch_connections(addr).await {
        Ok(r) => r,
        Err(e) => {
            eprint!(
                "{}",
                error_block(
                    "connections_endpoint_unreachable",
                    &format!("could not reach /v1/control/connections: {e}"),
                    "verify the daemon is up: agentsso status",
                    None,
                )
            );
            return Err(silent_cli_error(format!("connections endpoint unreachable: {e}")));
        }
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&response).map_err(anyhow::Error::from)?);
        return Ok(());
    }

    let layout = TableLayout::detect();
    let support = ColorSupport::detect();
    let theme = Theme::default();
    let rendered = render_connections_table(
        &response.connections,
        &response.generated_at,
        layout,
        &theme,
        support,
    );
    print!("{rendered}");
    Ok(())
}

/// Render the connections table (or the empty-state block) as a
/// String. Pure function — no I/O — so the watch loop can call it on
/// every redraw without re-detecting terminal capabilities each tick.
pub(crate) fn render_connections_table(
    rows: &[ConnectionRow],
    generated_at: &str,
    layout: TableLayout,
    theme: &Theme,
    support: ColorSupport,
) -> String {
    if rows.is_empty() {
        return empty_state(
            "no agents connected yet",
            "register with:  agentsso agent register <name>",
        );
    }

    let mut out = String::with_capacity(512);
    let tokens = theme.tokens();

    let (headers, body): (Vec<&str>, Vec<Vec<TableCell>>) = match layout {
        TableLayout::Narrow => {
            let headers = vec!["AGENT", "REQ/MIN", "LAST"];
            let body = rows
                .iter()
                .map(|r| {
                    vec![
                        TableCell::Plain(r.agent_name.clone()),
                        req_per_min_cell(r, theme, support),
                        TableCell::Plain(format_relative_or_iso(&r.last_request_at)),
                    ]
                })
                .collect();
            (headers, body)
        }
        TableLayout::Standard => {
            let headers = vec!["AGENT", "POLICY", "CONNECTED", "REQ/MIN", "REQ/HOUR", "LAST"];
            let body = rows
                .iter()
                .map(|r| {
                    vec![
                        TableCell::Plain(r.agent_name.clone()),
                        TableCell::Plain(r.policy_name.clone()),
                        TableCell::Plain(format_relative_or_iso(&r.connected_since)),
                        req_per_min_cell(r, theme, support),
                        TableCell::Plain(format_count(r.req_per_hour)),
                        TableCell::Plain(format_relative_or_iso(&r.last_request_at)),
                    ]
                })
                .collect();
            (headers, body)
        }
        TableLayout::Wide => {
            let headers =
                vec!["AGENT", "POLICY", "CONNECTED", "REQ/MIN", "REQ/HOUR", "LAST", "TOTAL"];
            let body = rows
                .iter()
                .map(|r| {
                    vec![
                        TableCell::Plain(r.agent_name.clone()),
                        TableCell::Plain(r.policy_name.clone()),
                        TableCell::Plain(format_relative_or_iso(&r.connected_since)),
                        req_per_min_cell(r, theme, support),
                        TableCell::Plain(format_count(r.req_per_hour)),
                        TableCell::Plain(format_relative_or_iso(&r.last_request_at)),
                        TableCell::Plain(format_count(r.total_requests)),
                    ]
                })
                .collect();
            (headers, body)
        }
    };

    match table(&headers, &body, layout, theme, support) {
        Ok(t) => out.push_str(&t),
        Err(e) => {
            // Arity mismatch is a programming error in this module —
            // fail loud rather than silently rendering nothing.
            out.push_str(&format!("\n  table render error: {e}\n"));
        }
    }

    // Footer (UX §11.4 declarative voice).
    let footer = format!(
        "  {} agents connected · refreshed {}",
        rows.len(),
        format_relative_or_iso(generated_at),
    );
    out.push_str(&styled(&footer, tokens.muted, support));
    out.push('\n');

    out
}

/// Build the `REQ/MIN` cell.
///
/// Decision matrix:
/// - No baseline yet (insufficient samples): plain count
/// - Multiplier ≥ 1.5: `"<N>x baseline"` styled with warn-accent
///   (UX-DR18 — surfaces unusual activity)
/// - Multiplier < 1.5: raw rate as a plain count
///
/// **M10 review patch:** gates on the wire `multiplier` value
/// directly rather than string-suffix-matching `format_rate`'s
/// output. The prior approach coupled cell styling to the formatter
/// crate's exact output string — a future formatter change could
/// silently disable the warn-styling with no test catching it.
fn req_per_min_cell(row: &ConnectionRow, theme: &Theme, support: ColorSupport) -> TableCell {
    let tokens = theme.tokens();
    match (row.baseline_per_min, row.multiplier) {
        (Some(baseline), Some(mult)) if mult >= 1.5 => {
            let rendered = crate::design::format::format_rate(row.req_per_min as f64, baseline);
            TableCell::Plain(styled(&rendered, tokens.warn, support))
        }
        _ => TableCell::Plain(format_count(row.req_per_min)),
    }
}

/// Render an RFC 3339 timestamp using the design-system relative-or-
/// absolute helper. Falls back to the raw string on parse failure so a
/// daemon that sent unexpected output doesn't crash the table.
fn format_relative_or_iso(rfc3339: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .map(|dt| format_timestamp(dt.with_timezone(&chrono::Utc)))
        .unwrap_or_else(|_| rfc3339.to_owned())
}

// --------------------------------------------------------------------------
// --watch redraw loop (Story 5.5).
// --------------------------------------------------------------------------

const WATCH_INTERVAL_SECS: u64 = 2;

/// Punctuation used in operator-facing one-line strings. Centralised
/// so a future swap to ASCII (for terminals without UTF-8 — Windows
/// cmd.exe, stripped Docker images) is a one-line change.
///
/// **L4 review patch.**
const SEP: &str = " · ";

async fn run_watch_loop(_json: bool, addr: SocketAddr) -> anyhow::Result<()> {
    use std::io::{ErrorKind, IsTerminal, Write};

    // `_json` is always false here (Args dispatcher rejects --watch
    // --json upstream). The leading `_` flags the intent.
    let support = ColorSupport::detect();
    let theme = Theme::default();
    // **M3 review patch:** only emit the screen-clear ANSI when
    // stdout is actually a terminal — piping through `tee` or into a
    // log file would otherwise fill the destination with control
    // sequences.
    let stdout_is_tty = std::io::stdout().is_terminal();

    let mut interval = tokio::time::interval(Duration::from_secs(WATCH_INTERVAL_SECS));
    // **M7 review patch:** if a fetch takes >2s, the next two ticks
    // would otherwise fire back-to-back (Tokio's default `Burst`).
    // `Skip` re-anchors the schedule so we never burst-coalesce.
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                // **M3:** TTY-gated clear-screen + cursor home.
                if stdout_is_tty {
                    print!("\x1b[2J\x1b[H");
                }
                // **M6 review patch:** re-detect TableLayout each
                // tick so SIGWINCH terminal resizes adapt without a
                // restart.
                let layout = TableLayout::detect();
                match fetch_connections(addr).await {
                    Ok(response) => {
                        let rendered = render_connections_table(
                            &response.connections,
                            &response.generated_at,
                            layout,
                            &theme,
                            support,
                        );
                        print!("{rendered}");
                    }
                    Err(e) => {
                        // Single-line transient error so the loop can
                        // recover when the daemon restarts.
                        let line = format!(
                            "  fetch failed: {e}{SEP}retrying in {WATCH_INTERVAL_SECS}s"
                        );
                        println!("{}", styled(&line, theme.tokens().warn, support));
                    }
                }
                // Flush so the redraw is visible before the next tick.
                // **L6 review patch:** broken pipe (operator piped
                // through `head`, etc.) → exit cleanly instead of
                // looping forever on an unflushable stdout. Other
                // I/O errors are non-fatal; let the loop try the
                // next tick and surface via the fetch path if they
                // persist.
                if let Err(e) = std::io::stdout().flush()
                    && e.kind() == ErrorKind::BrokenPipe
                {
                    return Ok(());
                }
            }
            _ = tokio::signal::ctrl_c() => {
                // **M1 review patch:** emit the cursor-show ANSI
                // (`\x1b[?25h`) the spec requires on Ctrl-C exit, in
                // addition to the trailing newline. Some terminals
                // hide the cursor when the alternate-screen-style
                // clear-screen pattern repaints — explicit show keeps
                // the post-exit prompt's cursor visible. Only emit it
                // when stdout is a TTY (same gate as the clear-screen
                // emit above).
                if stdout_is_tty {
                    print!("\x1b[?25h");
                }
                println!();
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Minimal harness for parsing `StatusArgs` via clap so we exercise
    /// the same arg-validation code path the production binary does.
    #[derive(clap::Parser)]
    struct TestCli {
        #[command(subcommand)]
        cmd: TestCommands,
    }

    #[derive(clap::Subcommand)]
    enum TestCommands {
        Status(StatusArgs),
    }

    fn parse(args: &[&str]) -> StatusArgs {
        let mut argv = vec!["test", "status"];
        argv.extend_from_slice(args);
        let parsed = TestCli::parse_from(argv);
        match parsed.cmd {
            TestCommands::Status(s) => s,
        }
    }

    #[test]
    fn parse_args_default_no_flags() {
        let s = parse(&[]);
        assert!(!s.json);
        assert!(!s.connections);
        assert!(!s.watch);
    }

    #[test]
    fn parse_args_connections_alone() {
        let s = parse(&["--connections"]);
        assert!(s.connections);
        assert!(!s.watch);
    }

    #[test]
    fn parse_args_connections_with_watch() {
        let s = parse(&["--connections", "--watch"]);
        assert!(s.connections);
        assert!(s.watch);
    }

    #[test]
    fn parse_args_watch_alone_parses_but_dispatch_rejects() {
        // clap accepts the combination; rejection happens in `run`.
        let s = parse(&["--watch"]);
        assert!(s.watch);
        assert!(!s.connections);
    }

    fn empty_response() -> ConnectionsResponse {
        ConnectionsResponse {
            connections: Vec::new(),
            generated_at: "2026-04-16T14:56:43Z".to_owned(),
        }
    }

    fn one_row(req_per_min: u64, baseline: Option<f64>, multiplier: Option<f64>) -> ConnectionRow {
        ConnectionRow {
            agent_name: "agent-alpha".to_owned(),
            policy_name: "default".to_owned(),
            connected_since: "2026-04-16T13:42:18Z".to_owned(),
            last_request_at: "2026-04-16T14:56:41Z".to_owned(),
            total_requests: 8421,
            req_per_min,
            req_per_hour: 412,
            baseline_per_min: baseline,
            multiplier,
        }
    }

    #[test]
    fn render_connections_table_empty_state_matches_ux_spec() {
        let rendered = render_connections_table(
            &[],
            "2026-04-16T14:56:43Z",
            TableLayout::Standard,
            &Theme::default(),
            ColorSupport::NoColor,
        );
        // §11.6 empty-state shape: contains the description and the
        // exact populate command, NOT a table header.
        assert!(rendered.contains("no agents connected yet"));
        assert!(rendered.contains("agentsso agent register <name>"));
        assert!(!rendered.contains("AGENT"), "empty state must not render the AGENT header");
    }

    #[test]
    fn render_connections_table_standard_layout_has_six_columns() {
        let rows = vec![one_row(5, Some(4.0), Some(1.25))];
        let rendered = render_connections_table(
            &rows,
            "2026-04-16T14:56:43Z",
            TableLayout::Standard,
            &Theme::default(),
            ColorSupport::NoColor,
        );
        for header in ["AGENT", "POLICY", "CONNECTED", "REQ/MIN", "REQ/HOUR", "LAST"] {
            assert!(rendered.contains(header), "Standard layout must include {header}");
        }
        assert!(!rendered.contains("TOTAL"), "Standard layout must NOT include TOTAL");
        assert!(rendered.contains("agent-alpha"));
        assert!(rendered.contains("1 agents connected"));
    }

    #[test]
    fn render_connections_table_narrow_layout_has_three_columns() {
        let rows = vec![one_row(5, Some(4.0), Some(1.25))];
        let rendered = render_connections_table(
            &rows,
            "2026-04-16T14:56:43Z",
            TableLayout::Narrow,
            &Theme::default(),
            ColorSupport::NoColor,
        );
        for header in ["AGENT", "REQ/MIN", "LAST"] {
            assert!(rendered.contains(header), "Narrow layout must include {header}");
        }
        for omitted in ["POLICY", "CONNECTED", "REQ/HOUR", "TOTAL"] {
            assert!(!rendered.contains(omitted), "Narrow layout must NOT include {omitted}");
        }
    }

    #[test]
    fn render_connections_table_wide_layout_has_seven_columns() {
        let rows = vec![one_row(5, Some(4.0), Some(1.25))];
        let rendered = render_connections_table(
            &rows,
            "2026-04-16T14:56:43Z",
            TableLayout::Wide,
            &Theme::default(),
            ColorSupport::NoColor,
        );
        for header in ["AGENT", "POLICY", "CONNECTED", "REQ/MIN", "REQ/HOUR", "LAST", "TOTAL"] {
            assert!(rendered.contains(header), "Wide layout must include {header}");
        }
    }

    #[test]
    fn req_per_min_cell_high_multiplier_uses_baseline_format() {
        // 12 req/min vs 0.27 baseline = 44.4× → format_rate returns
        // "44x baseline".
        let row = one_row(12, Some(0.27), Some(44.4));
        let cell = req_per_min_cell(&row, &Theme::default(), ColorSupport::NoColor);
        let TableCell::Plain(rendered) = cell else { panic!("expected Plain cell") };
        assert!(
            rendered.contains("baseline"),
            "high-multiplier cell must include baseline marker: got {rendered:?}"
        );
    }

    #[test]
    fn req_per_min_cell_low_multiplier_renders_raw_rate() {
        // 5 req/min vs 4.0 baseline = 1.25× ≤ 1.5 → format_rate
        // returns the raw value.
        let row = one_row(5, Some(4.0), Some(1.25));
        let cell = req_per_min_cell(&row, &Theme::default(), ColorSupport::NoColor);
        let TableCell::Plain(rendered) = cell else { panic!("expected Plain cell") };
        assert!(
            !rendered.contains("baseline"),
            "low-multiplier cell must NOT include baseline marker: got {rendered:?}"
        );
    }

    #[test]
    fn req_per_min_cell_no_baseline_renders_raw_count() {
        // No baseline data yet → render the raw count.
        let row = one_row(7, None, None);
        let cell = req_per_min_cell(&row, &Theme::default(), ColorSupport::NoColor);
        let TableCell::Plain(rendered) = cell else { panic!("expected Plain cell") };
        assert_eq!(rendered, "7");
    }

    #[test]
    fn render_connections_table_no_color_emits_no_ansi_escapes() {
        let rows = vec![one_row(12, Some(0.27), Some(44.4))];
        let rendered = render_connections_table(
            &rows,
            "2026-04-16T14:56:43Z",
            TableLayout::Standard,
            &Theme::default(),
            ColorSupport::NoColor,
        );
        assert!(
            !rendered.contains('\x1b'),
            "NoColor support must produce zero ANSI escapes — got: {rendered:?}"
        );
    }

    #[test]
    fn empty_response_helper_constructs_default_shape() {
        // Sanity check that the test helper produces what the empty-
        // state path consumes — guards against future test bitrot.
        let r = empty_response();
        assert!(r.connections.is_empty());
        assert_eq!(r.generated_at, "2026-04-16T14:56:43Z");
    }
}
