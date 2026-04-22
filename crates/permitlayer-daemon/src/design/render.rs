//! Outcome icons, error blocks, empty-state rendering, field truncation,
//! and the adaptive [`table`] primitive used by `agentsso audit` (Story
//! 5.1) and the targets of a follow-up migration — `cli/agent.rs::list_agents`
//! and `cli/credentials.rs::list_credentials`, which currently hand-roll
//! their own column widths.

use std::fmt::Write;

use permitlayer_core::audit::event::AuditEvent;
use permitlayer_core::audit::reader::scrub_count_for;

use crate::design::terminal::{ColorSupport, TableLayout, styled};
use crate::design::theme::Theme;

/// Semantic outcome categories used for icon + color mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Ok / allowed / success — teal.
    Ok,
    /// Blocked / scrubbed — amber.
    Blocked,
    /// Error / crash — coral-red.
    Error,
}

/// Non-color indicator icon for an outcome.
///
/// These Unicode glyphs ALWAYS appear regardless of color support (UX-DR7).
pub fn outcome_icon(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Ok => "\u{25CF}",      // ●
        Outcome::Blocked => "\u{25B2}", // ▲
        Outcome::Error => "\u{2715}",   // ✕
    }
}

/// Text label for an outcome.
fn outcome_label(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Ok => "ok",
        Outcome::Blocked => "blocked",
        Outcome::Error => "error",
    }
}

/// Render an outcome with semantic color + icon + text label.
pub fn styled_outcome(outcome: Outcome, theme: &Theme, support: ColorSupport) -> String {
    let tokens = theme.tokens();
    let color = match outcome {
        Outcome::Ok => tokens.accent,
        Outcome::Blocked => tokens.warn,
        Outcome::Error => tokens.danger,
    };
    let icon = outcome_icon(outcome);
    let label = outcome_label(outcome);
    let text = format!("{icon} {label}");
    styled(&text, color, support)
}

/// Render a structured CLI error block.
///
/// Format (UX-DR20):
/// ```text
///   ⚠  config_invalid
///      ~/.agentsso/policies/default.toml:14 · expected "allow" | "deny" | "prompt"
///      run:  agentsso policy validate default
/// ```
pub fn error_block(code: &str, message: &str, remediation: &str, location: Option<&str>) -> String {
    let mut buf = String::with_capacity(256);
    writeln!(buf, "  \u{26A0}  {code}").ok();
    if let Some(loc) = location {
        writeln!(buf, "     {loc} \u{00B7} {message}").ok();
    } else {
        writeln!(buf, "     {message}").ok();
    }
    writeln!(buf, "     run:  {remediation}").ok();
    buf
}

/// Render an empty-state message with the Scute glyph.
///
/// Format (UX-DR22):
/// ```text
///   ◖  no agents registered yet
///
///      register with:  agentsso agent register <name>
/// ```
pub fn empty_state(description: &str, command: &str) -> String {
    let mut buf = String::with_capacity(128);
    writeln!(buf, "  \u{25D6}  {description}").ok();
    writeln!(buf).ok();
    writeln!(buf, "     {command}").ok();
    buf
}

/// Truncate a field to `max_width` characters, appending `\u{2026}` (…) if truncated.
pub fn truncate_field(text: &str, max_width: usize) -> String {
    if max_width == 0 {
        return String::new();
    }
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max_width {
        text.to_owned()
    } else {
        let mut s: String = chars[..max_width - 1].iter().collect();
        s.push('\u{2026}');
        s
    }
}

// ──────────────────────────────────────────────────────────────────
// Adaptive table primitive (Story 5.1)
// ──────────────────────────────────────────────────────────────────

/// A single cell in a [`table`] row.
///
/// Split from plain `String` so the outcome column can be rendered
/// with the semantic color strip (teal/amber/red) while other columns
/// stay plain. The caller builds `Outcome(Outcome)` for outcome cells
/// and `Plain(String)` for everything else — `table` dispatches on the
/// variant at render time.
#[derive(Debug, Clone)]
pub enum TableCell {
    /// Plain text cell, truncated via [`truncate_field`] if it
    /// exceeds the column width.
    Plain(String),
    /// Outcome cell: renders as "icon label" via [`styled_outcome`],
    /// honoring `ColorSupport` and falling back to the non-color icon
    /// + label form on `NoColor`.
    Outcome(Outcome),
}

impl TableCell {
    /// The "display width" of this cell — used for column-width
    /// computation. For `Outcome` cells, this is always the width of
    /// the icon + space + label string (e.g. `● ok` = 4 chars); the
    /// ANSI color escape bytes are NOT counted because terminals
    /// don't render them as visible width.
    fn display_width(&self) -> usize {
        match self {
            Self::Plain(s) => s.chars().count(),
            Self::Outcome(o) => {
                // Icon (1 char) + space (1 char) + label.
                // Labels are "ok", "blocked", "error" — widths 2/7/5.
                2 + outcome_label(*o).chars().count()
            }
        }
    }

    /// Render this cell with the given column width. Plain cells
    /// truncate via [`truncate_field`]; Outcome cells always render
    /// at full width (their width is already accounted for in
    /// `display_width`). Outcome cells embed ANSI escape bytes when
    /// `support != NoColor` — the padding caller must use
    /// `display_width` for alignment, not `render(...).chars().count()`.
    fn render(&self, width: usize, theme: &Theme, support: ColorSupport) -> String {
        match self {
            Self::Plain(s) => truncate_field(s, width),
            Self::Outcome(o) => styled_outcome(*o, theme, support),
        }
    }
}

/// Errors from building a [`table`] call — surfaces invariant
/// violations that the caller should fix rather than catching at
/// runtime.
#[derive(Debug, thiserror::Error)]
pub enum TableError {
    /// A row had a different number of cells than `headers.len()`.
    #[error("row {row} has {actual} cells but headers have {expected}")]
    RowArity { row: usize, expected: usize, actual: usize },
}

/// Render an adaptive multi-column table.
///
/// # Layout rules
///
/// - Column widths are computed as `max(header, max(row cells))` for
///   each column, bounded by the terminal width the `layout` reports.
/// - If total width exceeds the terminal (per `layout`'s implied
///   width bucket), plain columns are truncated proportionally via
///   [`truncate_field`]. Outcome columns are never truncated — they
///   are always exactly `2 + label.len()` wide.
/// - Inter-column padding is 2 spaces (matching the existing
///   `cli/audit.rs` renderer precedent).
/// - Header row is rendered with a dim color from the theme; data
///   rows render cells as specified (Plain = truncated, Outcome =
///   styled via [`styled_outcome`]).
///
/// # Story 4.4 debt closure
///
/// This primitive closes the `render::table` deferred debt from
/// `deferred-work.md:26` (Story 4.4 `agent list` hand-rolled layout).
/// A follow-up mini-PR should migrate `cli/agent.rs::list_agents` and
/// `cli/credentials.rs::list_credentials` to use this function.
///
/// # Errors
///
/// Returns [`TableError::RowArity`] if any row has a different
/// number of cells than `headers.len()`. This is a caller bug; panic
/// vs `Result` is a judgment call, and `Result` lets callers decide
/// to `?` it into their own error type.
pub fn table(
    headers: &[&str],
    rows: &[Vec<TableCell>],
    layout: TableLayout,
    theme: &Theme,
    support: ColorSupport,
) -> Result<String, TableError> {
    // Empty table: return empty string. The caller should use
    // `empty_state` for "no data" messaging — the primitive itself
    // is silent on empty input.
    if headers.is_empty() {
        return Ok(String::new());
    }

    // Validate row arity.
    for (i, row) in rows.iter().enumerate() {
        if row.len() != headers.len() {
            return Err(TableError::RowArity {
                row: i,
                expected: headers.len(),
                actual: row.len(),
            });
        }
    }

    // Compute per-column max display width (header + all cells).
    let num_cols = headers.len();
    let mut col_widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            col_widths[i] = col_widths[i].max(cell.display_width());
        }
    }

    // Apply layout width budget. The budget is the terminal width
    // for the layout bucket; Narrow = 79, Standard = 120, Wide =
    // 200 (caller-chosen). Padding between columns is 2 spaces, so
    // the total rendered width is sum(col_widths) + 2 * (num_cols - 1).
    let budget: usize = match layout {
        TableLayout::Narrow => 79,
        TableLayout::Standard => 120,
        TableLayout::Wide => 200,
    };
    let padding_total = 2 * num_cols.saturating_sub(1);
    let content_budget = budget.saturating_sub(padding_total);

    let total_width: usize = col_widths.iter().sum();
    if total_width > content_budget {
        // Shrink plain-text columns proportionally to fit the
        // budget. Outcome cells' widths are fixed (they're small
        // and already minimal — ●/▲/✕ + space + label).
        //
        // First pass: classify columns as "flexible" (any Plain
        // cell in that column) vs "fixed" (all Outcome cells).
        let mut is_fixed = vec![true; num_cols];
        for row in rows {
            for (i, cell) in row.iter().enumerate() {
                if matches!(cell, TableCell::Plain(_)) {
                    is_fixed[i] = false;
                }
            }
        }
        // If a column has no rows, treat it as flexible (header-only).
        if rows.is_empty() {
            is_fixed.iter_mut().for_each(|f| *f = false);
        }

        let fixed_width: usize =
            col_widths.iter().enumerate().filter(|(i, _)| is_fixed[*i]).map(|(_, w)| *w).sum();
        let flex_budget = content_budget.saturating_sub(fixed_width);
        let flex_total: usize =
            col_widths.iter().enumerate().filter(|(i, _)| !is_fixed[*i]).map(|(_, w)| *w).sum();

        if flex_total > 0 && flex_budget < flex_total {
            // Shrink each flexible column proportionally.
            for (i, w) in col_widths.iter_mut().enumerate() {
                if !is_fixed[i] {
                    let shrunk = (*w * flex_budget) / flex_total.max(1);
                    // Minimum 3 chars so truncation leaves at least "a…".
                    *w = shrunk.max(3);
                }
            }
        }
    }

    // Render the table.
    let mut buf = String::with_capacity(256);
    let tokens = theme.tokens();

    // Header row — dimmed via the muted token.
    for (i, header) in headers.iter().enumerate() {
        if i > 0 {
            buf.push_str("  ");
        }
        let padded = format!("{:width$}", header, width = col_widths[i]);
        buf.push_str(&styled(&padded, tokens.muted, support));
    }
    buf.push('\n');

    // Data rows.
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i > 0 {
                buf.push_str("  ");
            }
            let rendered = cell.render(col_widths[i], theme, support);
            // For alignment: pad with spaces up to display_width. We
            // need to use the CELL's display width (not rendered
            // character count) because Outcome cells' ANSI escape
            // bytes inflate the char count.
            let cell_width = cell.display_width();
            buf.push_str(&rendered);
            if cell_width < col_widths[i] {
                for _ in cell_width..col_widths[i] {
                    buf.push(' ');
                }
            }
        }
        buf.push('\n');
    }

    Ok(buf)
}

// ──────────────────────────────────────────────────────────────────
// Audit row helper (Story 5.1 Task 3)
// ──────────────────────────────────────────────────────────────────

/// Map an outcome string from an [`AuditEvent`] to the semantic
/// [`Outcome`] enum used by the renderer.
///
/// Matches the mapping established by the Story 1.9 follow loop:
/// - `ok`, `allowed` → `Outcome::Ok` (teal)
/// - `denied`, `scrubbed` → `Outcome::Blocked` (amber)
/// - Story 3.3 idempotent returns `already-active`, `already-inactive`
///   → `Outcome::Ok` (teal) because they represent successful no-ops,
///   not errors
/// - Everything else → `Outcome::Error` (coral-red)
#[must_use]
pub fn outcome_from_str(s: &str) -> Outcome {
    match s {
        "ok" | "allowed" | "already-active" | "already-inactive" => Outcome::Ok,
        "denied" | "scrubbed" => Outcome::Blocked,
        _ => Outcome::Error,
    }
}

/// Return the header strings for an audit-row table at the given
/// layout. Used by both the query command and any snapshot test that
/// wants to assert on the canonical column order.
///
/// Narrow (<80 cols): 3-column — time, service, outcome
/// Standard (80-120): 6-column — time, service, resource, outcome, agent, event_type
/// Wide (>120): 8-column — adds scope, request_id (short form, 8 chars)
#[must_use]
pub fn audit_row_headers(layout: TableLayout) -> &'static [&'static str] {
    match layout {
        TableLayout::Narrow => &["time", "service", "outcome"],
        TableLayout::Standard => &["time", "service", "resource", "outcome", "agent", "event"],
        TableLayout::Wide => {
            &["time", "service", "scope", "resource", "outcome", "agent", "event", "req"]
        }
    }
}

/// Convert an [`AuditEvent`] into the [`TableCell`] row for the given
/// layout. Used by the `agentsso audit` historical query to feed
/// [`table`].
///
/// Extracts the `HH:MM:SS` time column from the RFC 3339 timestamp
/// (`[11..19]` of the canonical format), maps the `outcome` string
/// via [`outcome_from_str`], and selects the visible columns per
/// [`audit_row_headers`]. For the Wide layout, the `request_id` is
/// truncated to the first 8 characters for a compact display — the
/// full ULID is always available via JSON export.
///
/// Insta-snapshot-tested for every [`AuditEvent`] `event_type`
/// currently emitted in the codebase (Story 5.1 AC #14), which also
/// closes the deferred Story 4.5 approval-event snapshot debt.
#[must_use]
pub fn audit_row_cells(event: &AuditEvent, layout: TableLayout) -> Vec<TableCell> {
    // L6: the canonical audit timestamp is strict RFC 3339 ASCII so
    // byte indexing at [11..19] is normally safe, but a tampered
    // event may carry a non-ASCII timestamp. Extract by chars to
    // avoid a silent full-string fallback that misaligns the table.
    // Fall back to the first 8 chars of whatever we got on total
    // failure.
    let time: String =
        if event.timestamp.is_char_boundary(11) && event.timestamp.is_char_boundary(19) {
            event.timestamp[11..19].to_owned()
        } else {
            event.timestamp.chars().skip(11).take(8).collect()
        };
    let outcome = outcome_from_str(&event.outcome);

    // Request ID short form for Wide layout: first 8 chars of the
    // ULID. ULIDs are 26 chars total; the first 10 are the
    // timestamp prefix (monotonic per-ms), so 8 chars gives enough
    // uniqueness for on-screen correlation while staying compact.
    let req_short = event.request_id.chars().take(8).collect::<String>();

    match layout {
        TableLayout::Narrow => vec![
            TableCell::Plain(time),
            TableCell::Plain(event.service.clone()),
            TableCell::Outcome(outcome),
        ],
        TableLayout::Standard => vec![
            TableCell::Plain(time),
            TableCell::Plain(event.service.clone()),
            TableCell::Plain(event.resource.clone()),
            TableCell::Outcome(outcome),
            TableCell::Plain(event.agent_id.clone()),
            TableCell::Plain(event.event_type.clone()),
        ],
        TableLayout::Wide => vec![
            TableCell::Plain(time),
            TableCell::Plain(event.service.clone()),
            TableCell::Plain(event.scope.clone()),
            TableCell::Plain(event.resource.clone()),
            TableCell::Outcome(outcome),
            TableCell::Plain(event.agent_id.clone()),
            TableCell::Plain(event.event_type.clone()),
            TableCell::Plain(req_short),
        ],
    }
}

/// Footer aggregation counters for a set of audit events.
///
/// Matches the canonical §6.1 Interaction 4 mock format:
/// `412 calls · 7 allowed · 405 blocked · 0 scrubs` — middle-dot
/// separators, counts ≥1000 get thousand-separators per UX-DR18.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuditFooter {
    pub total: u64,
    pub allowed: u64,
    pub blocked: u64,
    pub errors: u64,
    pub scrubs: u64,
}

impl AuditFooter {
    /// Aggregate over a slice of audit events. `allowed` counts
    /// events whose outcome maps to `Outcome::Ok`; `blocked` counts
    /// events whose outcome maps to `Outcome::Blocked`; `errors`
    /// counts events whose outcome maps to `Outcome::Error`; `scrubs`
    /// sums `scrub_count_for(event)` across all matched events.
    #[must_use]
    pub fn from_events(events: &[AuditEvent]) -> Self {
        let mut f = Self::default();
        for event in events {
            f.total += 1;
            match outcome_from_str(&event.outcome) {
                Outcome::Ok => f.allowed += 1,
                Outcome::Blocked => f.blocked += 1,
                Outcome::Error => f.errors += 1,
            }
            f.scrubs += scrub_count_for(event);
        }
        f
    }

    /// Render the footer line per §6.1 Interaction 4:
    ///
    /// ```text
    /// 412 calls · 7 allowed · 405 blocked · 0 errors · 0 scrubs
    /// ```
    ///
    /// The caller is responsible for any leading indent — this method
    /// renders just the content so callers that don't want a two-space
    /// gutter (tests, alternative layouts) aren't forced into one.
    ///
    /// Counts ≥1000 get thousand-separator commas (UX-DR18): `12,847`.
    ///
    /// The `errors` bucket is rendered explicitly so
    /// `allowed + blocked + errors == total` visibly sums. M3 fix:
    /// before Story 5.1 code review, `errors` was tracked internally
    /// but never rendered, so a 5-event query containing 2 errors
    /// displayed `"5 calls · 0 allowed · 0 blocked · 0 scrubs"`.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "{} calls \u{00B7} {} allowed \u{00B7} {} blocked \u{00B7} {} errors \u{00B7} {} scrubs",
            format_count(self.total),
            format_count(self.allowed),
            format_count(self.blocked),
            format_count(self.errors),
            format_count(self.scrubs),
        )
    }
}

/// Format a non-negative count with thousand-separator commas when
/// ≥1000, matching UX-DR18. Numbers under 1000 render plain.
#[must_use]
pub fn format_count(n: u64) -> String {
    if n < 1000 {
        return n.to_string();
    }
    // Insert commas every 3 digits from the right.
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let first_chunk = bytes.len() % 3;
    if first_chunk > 0 {
        out.push_str(&s[..first_chunk]);
    }
    for (i, chunk) in bytes[first_chunk..].chunks(3).enumerate() {
        if i > 0 || first_chunk > 0 {
            out.push(',');
        }
        // chunk is guaranteed ASCII digits (u64::to_string never
        // produces non-ASCII), so from_utf8 is infallible. The
        // workspace denies `clippy::expect_used`, so we `unwrap_or`
        // to an empty string — the fallback branch is unreachable
        // but the lint has no way to know that.
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn outcome_icons_are_correct() {
        assert_eq!(outcome_icon(Outcome::Ok), "●");
        assert_eq!(outcome_icon(Outcome::Blocked), "▲");
        assert_eq!(outcome_icon(Outcome::Error), "✕");
    }

    #[test]
    fn styled_outcome_no_color() {
        let result = styled_outcome(Outcome::Ok, &Theme::Carapace, ColorSupport::NoColor);
        assert_eq!(result, "● ok");
    }

    #[test]
    fn error_block_with_location() {
        let result = error_block(
            "config_invalid",
            "expected \"allow\" | \"deny\" | \"prompt\"",
            "agentsso policy validate default",
            Some("~/.agentsso/policies/default.toml:14"),
        );
        assert!(result.contains("\u{26A0}"));
        assert!(result.contains("config_invalid"));
        assert!(result.contains("run:"));
        assert!(result.contains("default.toml:14"));
    }

    #[test]
    fn error_block_without_location() {
        let result = error_block("auth_failed", "token expired", "agentsso setup gmail", None);
        assert!(result.contains("auth_failed"));
        assert!(result.contains("token expired"));
        assert!(!result.contains("\u{00B7}"));
    }

    #[test]
    fn empty_state_includes_glyph() {
        let result = empty_state(
            "no agents registered yet",
            "register with:  agentsso agent register <name>",
        );
        assert!(result.contains("\u{25D6}"));
        assert!(result.contains("no agents registered"));
        assert!(result.contains("agentsso agent register"));
    }

    #[test]
    fn truncate_short_unchanged() {
        assert_eq!(truncate_field("hello", 10), "hello");
    }

    #[test]
    fn truncate_long_with_ellipsis() {
        assert_eq!(truncate_field("hello world", 5), "hell\u{2026}");
    }

    #[test]
    fn truncate_exact_length() {
        assert_eq!(truncate_field("hello", 5), "hello");
    }

    #[test]
    fn truncate_zero_width() {
        assert_eq!(truncate_field("hello", 0), "");
    }

    #[test]
    fn truncate_width_one() {
        assert_eq!(truncate_field("hello", 1), "\u{2026}");
    }

    // ── table primitive (Story 5.1) ──────────────────────────────

    #[test]
    fn table_cell_display_width_plain() {
        assert_eq!(TableCell::Plain("hello".into()).display_width(), 5);
        assert_eq!(TableCell::Plain("".into()).display_width(), 0);
        assert_eq!(TableCell::Plain("café".into()).display_width(), 4);
    }

    #[test]
    fn table_cell_display_width_outcome() {
        // Icon (1) + space (1) + label
        assert_eq!(TableCell::Outcome(Outcome::Ok).display_width(), 4); // "● ok"
        assert_eq!(TableCell::Outcome(Outcome::Blocked).display_width(), 9); // "▲ blocked"
        assert_eq!(TableCell::Outcome(Outcome::Error).display_width(), 7); // "✕ error"
    }

    #[test]
    fn table_empty_headers_returns_empty_string() {
        let result =
            table(&[], &[], TableLayout::Standard, &Theme::Carapace, ColorSupport::NoColor);
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn table_no_rows_renders_only_headers() {
        let result = table(
            &["time", "service", "outcome"],
            &[],
            TableLayout::Standard,
            &Theme::Carapace,
            ColorSupport::NoColor,
        )
        .unwrap();
        assert!(result.contains("time"));
        assert!(result.contains("service"));
        assert!(result.contains("outcome"));
        // Exactly one line (the header), no data rows.
        assert_eq!(result.lines().count(), 1);
    }

    #[test]
    fn table_single_row_renders_correctly() {
        let result = table(
            &["time", "service", "outcome"],
            &[vec![
                TableCell::Plain("15:02:14".into()),
                TableCell::Plain("gmail".into()),
                TableCell::Outcome(Outcome::Ok),
            ]],
            TableLayout::Standard,
            &Theme::Carapace,
            ColorSupport::NoColor,
        )
        .unwrap();
        // Header line + data line
        assert_eq!(result.lines().count(), 2);
        assert!(result.contains("15:02:14"));
        assert!(result.contains("gmail"));
        assert!(result.contains("● ok"));
    }

    #[test]
    fn table_multiple_rows_all_rendered() {
        let rows = vec![
            vec![
                TableCell::Plain("15:02:14".into()),
                TableCell::Plain("gmail".into()),
                TableCell::Outcome(Outcome::Ok),
            ],
            vec![
                TableCell::Plain("15:02:15".into()),
                TableCell::Plain("calendar".into()),
                TableCell::Outcome(Outcome::Blocked),
            ],
            vec![
                TableCell::Plain("15:02:16".into()),
                TableCell::Plain("drive".into()),
                TableCell::Outcome(Outcome::Error),
            ],
        ];
        let result = table(
            &["time", "service", "outcome"],
            &rows,
            TableLayout::Standard,
            &Theme::Carapace,
            ColorSupport::NoColor,
        )
        .unwrap();
        assert_eq!(result.lines().count(), 4); // header + 3 rows
        assert!(result.contains("gmail"));
        assert!(result.contains("calendar"));
        assert!(result.contains("drive"));
        assert!(result.contains("● ok"));
        assert!(result.contains("▲ blocked"));
        assert!(result.contains("✕ error"));
    }

    #[test]
    fn table_row_arity_mismatch_errors() {
        let result = table(
            &["time", "service", "outcome"],
            &[vec![
                TableCell::Plain("15:02:14".into()),
                TableCell::Plain("gmail".into()),
                // Missing the outcome column
            ]],
            TableLayout::Standard,
            &Theme::Carapace,
            ColorSupport::NoColor,
        );
        assert!(matches!(result, Err(TableError::RowArity { row: 0, expected: 3, actual: 2 })));
    }

    #[test]
    fn table_narrow_layout_shrinks_plain_columns() {
        // Narrow = 79 col budget. Create a row with a very long plain
        // field that would blow past the budget.
        let long_text: String = "x".repeat(200);
        let result = table(
            &["time", "message", "outcome"],
            &[vec![
                TableCell::Plain("15:02:14".into()),
                TableCell::Plain(long_text),
                TableCell::Outcome(Outcome::Ok),
            ]],
            TableLayout::Narrow,
            &Theme::Carapace,
            ColorSupport::NoColor,
        )
        .unwrap();
        // The long text should be truncated with an ellipsis.
        assert!(result.contains('\u{2026}'), "long text should be truncated: {result}");
        // Outcome column is never truncated.
        assert!(result.contains("● ok"));
    }

    #[test]
    fn table_wide_layout_fits_everything() {
        // Wide = 200 col budget. Rows should render without truncation.
        let result = table(
            &["time", "service", "scope", "resource", "agent", "outcome"],
            &[vec![
                TableCell::Plain("15:02:14".into()),
                TableCell::Plain("gmail".into()),
                TableCell::Plain("mail.readonly".into()),
                TableCell::Plain("messages/123".into()),
                TableCell::Plain("email-triage".into()),
                TableCell::Outcome(Outcome::Ok),
            ]],
            TableLayout::Wide,
            &Theme::Carapace,
            ColorSupport::NoColor,
        )
        .unwrap();
        // No ellipsis at Wide budget for these short fields.
        assert!(!result.contains('\u{2026}'));
        assert!(result.contains("mail.readonly"));
        assert!(result.contains("messages/123"));
        assert!(result.contains("email-triage"));
    }

    #[test]
    fn table_nocolor_has_no_ansi_escapes() {
        let result = table(
            &["time", "outcome"],
            &[vec![TableCell::Plain("15:02:14".into()), TableCell::Outcome(Outcome::Ok)]],
            TableLayout::Standard,
            &Theme::Carapace,
            ColorSupport::NoColor,
        )
        .unwrap();
        assert!(!result.contains('\x1b'), "NoColor must not produce ANSI escapes: {result:?}");
    }

    #[test]
    fn table_truecolor_wraps_outcome_with_ansi() {
        let result = table(
            &["outcome"],
            &[vec![TableCell::Outcome(Outcome::Ok)]],
            TableLayout::Standard,
            &Theme::Carapace,
            ColorSupport::TrueColor,
        )
        .unwrap();
        assert!(result.contains("\x1b["), "TrueColor should inject ANSI escapes: {result:?}");
    }

    // ── audit_row helpers (Story 5.1 Task 3) ─────────────────────

    fn sample_event(event_type: &str, outcome: &str) -> AuditEvent {
        let mut e = AuditEvent::new(
            "email-triage".into(),
            "gmail".into(),
            "mail.readonly".into(),
            "messages/123".into(),
            outcome.into(),
            event_type.into(),
        );
        // Stable timestamp for snapshots.
        e.timestamp = "2026-04-14T15:02:14.123Z".into();
        e.request_id = "01JABCDEFGHJKMNPQRSTVWXYZ2".into();
        e
    }

    #[test]
    fn outcome_from_str_maps_ok_variants() {
        assert_eq!(outcome_from_str("ok"), Outcome::Ok);
        assert_eq!(outcome_from_str("allowed"), Outcome::Ok);
        assert_eq!(outcome_from_str("already-active"), Outcome::Ok);
        assert_eq!(outcome_from_str("already-inactive"), Outcome::Ok);
    }

    #[test]
    fn outcome_from_str_maps_blocked_variants() {
        assert_eq!(outcome_from_str("denied"), Outcome::Blocked);
        assert_eq!(outcome_from_str("scrubbed"), Outcome::Blocked);
    }

    #[test]
    fn outcome_from_str_defaults_to_error() {
        assert_eq!(outcome_from_str(""), Outcome::Error);
        assert_eq!(outcome_from_str("unknown"), Outcome::Error);
        assert_eq!(outcome_from_str("timeout"), Outcome::Error);
    }

    #[test]
    fn audit_row_headers_narrow_has_3_columns() {
        assert_eq!(audit_row_headers(TableLayout::Narrow).len(), 3);
    }

    #[test]
    fn audit_row_headers_standard_has_6_columns() {
        assert_eq!(audit_row_headers(TableLayout::Standard).len(), 6);
    }

    #[test]
    fn audit_row_headers_wide_has_8_columns() {
        assert_eq!(audit_row_headers(TableLayout::Wide).len(), 8);
    }

    #[test]
    fn audit_row_cells_narrow_extracts_3_cells() {
        let event = sample_event("api-call", "ok");
        let cells = audit_row_cells(&event, TableLayout::Narrow);
        assert_eq!(cells.len(), 3);
        // Time column extracted from timestamp[11..19]
        assert!(matches!(&cells[0], TableCell::Plain(s) if s == "15:02:14"));
        assert!(matches!(&cells[1], TableCell::Plain(s) if s == "gmail"));
        assert!(matches!(cells[2], TableCell::Outcome(Outcome::Ok)));
    }

    #[test]
    fn audit_row_cells_standard_extracts_6_cells() {
        let event = sample_event("policy-violation", "denied");
        let cells = audit_row_cells(&event, TableLayout::Standard);
        assert_eq!(cells.len(), 6);
        assert!(matches!(&cells[0], TableCell::Plain(s) if s == "15:02:14"));
        assert!(matches!(&cells[1], TableCell::Plain(s) if s == "gmail"));
        assert!(matches!(&cells[2], TableCell::Plain(s) if s == "messages/123"));
        assert!(matches!(cells[3], TableCell::Outcome(Outcome::Blocked)));
        assert!(matches!(&cells[4], TableCell::Plain(s) if s == "email-triage"));
        assert!(matches!(&cells[5], TableCell::Plain(s) if s == "policy-violation"));
    }

    #[test]
    fn audit_row_cells_wide_extracts_8_cells_with_req_short() {
        let event = sample_event("api-call", "ok");
        let cells = audit_row_cells(&event, TableLayout::Wide);
        assert_eq!(cells.len(), 8);
        // Request ID short form is first 8 chars of the ULID.
        assert!(matches!(&cells[7], TableCell::Plain(s) if s == "01JABCDE"));
    }

    #[test]
    fn audit_row_cells_maps_already_active_to_ok() {
        // Story 3.3 kill/resume idempotent outcome maps to Outcome::Ok
        // (successful no-op, not an error).
        let event = sample_event("kill-activated", "already-active");
        let cells = audit_row_cells(&event, TableLayout::Narrow);
        assert!(matches!(cells[2], TableCell::Outcome(Outcome::Ok)));
    }

    // ── AuditFooter + format_count (Story 5.1 Task 3) ────────────

    #[test]
    fn format_count_below_1000_plain() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(42), "42");
        assert_eq!(format_count(999), "999");
    }

    #[test]
    fn format_count_1000_and_above_gets_commas() {
        assert_eq!(format_count(1000), "1,000");
        assert_eq!(format_count(12_847), "12,847");
        assert_eq!(format_count(1_234_567), "1,234,567");
    }

    #[test]
    fn audit_footer_empty_events_returns_zero_counts() {
        let footer = AuditFooter::from_events(&[]);
        assert_eq!(footer.total, 0);
        assert_eq!(footer.allowed, 0);
        assert_eq!(footer.blocked, 0);
        assert_eq!(footer.errors, 0);
        assert_eq!(footer.scrubs, 0);
    }

    #[test]
    fn audit_footer_counts_by_outcome_bucket() {
        let events = vec![
            sample_event("api-call", "ok"),
            sample_event("api-call", "ok"),
            sample_event("policy-violation", "denied"),
            sample_event("api-call", "scrubbed"),
            sample_event("api-call", "error"),
        ];
        let footer = AuditFooter::from_events(&events);
        assert_eq!(footer.total, 5);
        assert_eq!(footer.allowed, 2);
        assert_eq!(footer.blocked, 2); // denied + scrubbed
        assert_eq!(footer.errors, 1);
    }

    #[test]
    fn audit_footer_sums_scrub_counts() {
        let mut e1 = sample_event("api-call", "ok");
        e1.extra = serde_json::json!({
            "scrub_events": { "summary": { "otp": 2, "email": 1 }, "samples": [] }
        });
        let mut e2 = sample_event("api-call", "scrubbed");
        e2.extra = serde_json::json!({
            "scrub_events": { "summary": { "bearer_token": 3 }, "samples": [] }
        });
        let footer = AuditFooter::from_events(&[e1, e2]);
        assert_eq!(footer.scrubs, 6); // 2 + 1 + 3
    }

    #[test]
    fn audit_footer_render_format_matches_canonical_mock() {
        let footer = AuditFooter { total: 412, allowed: 7, blocked: 405, errors: 0, scrubs: 0 };
        let rendered = footer.render();
        // Matches §6.1 Interaction 4 canonical mock with middle-dot
        // separators. M3 fix: `errors` is now rendered explicitly so
        // allowed+blocked+errors sums to total visibly. L16 fix: no
        // leading indent — the caller owns layout.
        assert_eq!(
            rendered,
            "412 calls \u{00B7} 7 allowed \u{00B7} 405 blocked \u{00B7} 0 errors \u{00B7} 0 scrubs"
        );
    }

    #[test]
    fn audit_footer_render_applies_thousand_separators() {
        let footer = AuditFooter {
            total: 12_847,
            allowed: 1_234,
            blocked: 11_613,
            errors: 0,
            scrubs: 2_500,
        };
        let rendered = footer.render();
        assert!(rendered.contains("12,847 calls"));
        assert!(rendered.contains("1,234 allowed"));
        assert!(rendered.contains("11,613 blocked"));
        assert!(rendered.contains("0 errors"));
        assert!(rendered.contains("2,500 scrubs"));
    }

    #[test]
    fn audit_footer_render_includes_errors_bucket() {
        // M3 regression guard: a 5-event query with 2 errors must
        // render those 2 errors in the footer. Before the fix,
        // `errors` was tracked in the struct but never printed.
        let footer = AuditFooter { total: 5, allowed: 1, blocked: 2, errors: 2, scrubs: 0 };
        let rendered = footer.render();
        assert!(rendered.contains("5 calls"));
        assert!(rendered.contains("1 allowed"));
        assert!(rendered.contains("2 blocked"));
        assert!(rendered.contains("2 errors"));
        assert!(rendered.contains("0 scrubs"));
    }

    // ── Insta snapshots for every event_type (Story 4.5 debt closure) ──

    // Snapshot tests render the Standard-layout audit row for each
    // event_type currently emitted in the codebase. Closes Story 4.5's
    // deferred insta-snapshot debt (deferred-work.md:18) in passing.
    //
    // NoColor mode so snapshots are stable across terminal
    // environments.

    fn snapshot_event(event_type: &str, outcome: &str) -> String {
        let event = sample_event(event_type, outcome);
        let cells = audit_row_cells(&event, TableLayout::Standard);
        table(
            audit_row_headers(TableLayout::Standard),
            &[cells],
            TableLayout::Standard,
            &Theme::Carapace,
            ColorSupport::NoColor,
        )
        .unwrap()
    }

    #[test]
    fn snapshot_api_call_ok() {
        insta::assert_snapshot!(snapshot_event("api-call", "ok"));
    }

    #[test]
    fn snapshot_api_call_denied() {
        insta::assert_snapshot!(snapshot_event("api-call", "denied"));
    }

    #[test]
    fn snapshot_api_call_error() {
        insta::assert_snapshot!(snapshot_event("api-call", "error"));
    }

    #[test]
    fn snapshot_api_call_scrubbed() {
        insta::assert_snapshot!(snapshot_event("api-call", "scrubbed"));
    }

    #[test]
    fn snapshot_token_refresh_ok() {
        insta::assert_snapshot!(snapshot_event("token-refresh", "ok"));
    }

    #[test]
    fn snapshot_policy_violation_denied() {
        insta::assert_snapshot!(snapshot_event("policy-violation", "denied"));
    }

    #[test]
    fn snapshot_agent_registered_ok() {
        insta::assert_snapshot!(snapshot_event("agent-registered", "ok"));
    }

    #[test]
    fn snapshot_agent_removed_ok() {
        insta::assert_snapshot!(snapshot_event("agent-removed", "ok"));
    }

    #[test]
    fn snapshot_agent_auth_denied() {
        insta::assert_snapshot!(snapshot_event("agent-auth-denied", "denied"));
    }

    #[test]
    fn snapshot_kill_activated_ok() {
        insta::assert_snapshot!(snapshot_event("kill-activated", "ok"));
    }

    #[test]
    fn snapshot_kill_activated_already_active() {
        insta::assert_snapshot!(snapshot_event("kill-activated", "already-active"));
    }

    #[test]
    fn snapshot_kill_resumed_ok() {
        insta::assert_snapshot!(snapshot_event("kill-resumed", "ok"));
    }

    #[test]
    fn snapshot_kill_blocked_request_denied() {
        insta::assert_snapshot!(snapshot_event("kill-blocked-request", "denied"));
    }

    #[test]
    fn snapshot_approval_granted_ok() {
        insta::assert_snapshot!(snapshot_event("approval-granted", "ok"));
    }

    #[test]
    fn snapshot_approval_denied() {
        insta::assert_snapshot!(snapshot_event("approval-denied", "denied"));
    }

    #[test]
    fn snapshot_approval_timeout_denied() {
        insta::assert_snapshot!(snapshot_event("approval-timeout", "denied"));
    }

    #[test]
    fn snapshot_approval_unavailable_denied() {
        insta::assert_snapshot!(snapshot_event("approval-unavailable", "denied"));
    }

    #[test]
    fn snapshot_policy_reloaded_ok() {
        insta::assert_snapshot!(snapshot_event("policy-reloaded", "ok"));
    }
}
