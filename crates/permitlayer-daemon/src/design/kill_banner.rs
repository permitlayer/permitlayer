//! `KillBanner` and `ResumeBanner` — the high-confidence CLI banners
//! rendered after `agentsso kill` / `agentsso resume`.
//!
//! Matches UX-DR11 / §6.1 Interaction 3 of the UX spec: teal power glyph,
//! amber full-width separator, activation timestamp, token count, cause,
//! resume instruction, and elapsed time.
//!
//! # Color semantics (UX-DR4 + Epic 2 retro action item #3)
//!
//! - Teal `--accent` for the power glyph `⏻`.
//! - Amber `--warn` for the separator border and the interior banner lines.
//! - Dim `--text-2` for the `elapsed:` footer.
//! - Coral-red `--danger` is **forbidden**. "The guard is up" is not
//!   "something broke". Forbidden-color tests assert absence across all
//!   three themes.
//!
//! # Timestamp format
//!
//! Every timestamp uses `%Y-%m-%dT%H:%M:%S%.3fZ` — the audit-log format from
//! `crates/permitlayer-core/src/audit/event.rs`. We deliberately do NOT use
//! `chrono::DateTime::to_rfc3339` because its `+00:00` offset breaks
//! operator grep-correlation between the banner and the audit log.
//!
//! # Deferred fields (Story 3.2 vs Story 3.3)
//!
//! - `audit_written: bool` — always `false` in Story 3.2 (Story 3.2 writes
//!   no audit events). Story 3.3 flips it to `true` when the audit write
//!   succeeds, at which point the renderer adds the `✓ kill event written
//!   to audit` bullet line.
//! - `in_flight_cancelled: Option<usize>` — always `None` in Story 3.2.
//!   The banner omits the "in-flight requests cancelled" line entirely
//!   rather than printing a zero. A future story that plumbs cancellation
//!   tokens through `UpstreamHttpClient` will set `Some(n)` and the
//!   renderer will show the line.
//!
//! Field defaults (`false` / `None`) are intentionally chosen so the
//! renderer degrades to the Story-3.2 behavior without needing a special
//! case; Story 3.3 only has to flip the booleans.

use chrono::{DateTime, Utc};
use std::time::Duration;
use unicode_width::UnicodeWidthStr;

use crate::design::format::format_count;
use crate::design::terminal::{ColorSupport, styled};
use crate::design::theme::Theme;

// --------------------------------------------------------------------------
// Input view structs.
//
// We mirror `permitlayer_core::killswitch::{ActivationSummary,
// DeactivationSummary}` here rather than depend on the core type directly.
// That keeps the renderer testable with synthetic data and prevents
// accidental coupling between the design module and the core crate.
// --------------------------------------------------------------------------

/// Mirror of `permitlayer_core::killswitch::ActivationSummary` for rendering,
/// plus the kill-reason wire label (carried on the daemon's control response
/// alongside the core summary — see `server::control::SerializableActivationSummary`).
#[derive(Debug, Clone)]
pub struct ActivationSummaryView {
    pub tokens_invalidated: usize,
    pub activated_at: DateTime<Utc>,
    pub was_already_active: bool,
    /// Kebab-case label for the kill reason, e.g. `"user-initiated"`. See
    /// [`kill_reason_label`] for the single-source-of-truth mapping.
    pub reason: String,
}

/// Mirror of `permitlayer_core::killswitch::DeactivationSummary` for rendering.
#[derive(Debug, Clone)]
pub struct DeactivationSummaryView {
    pub resumed_at: DateTime<Utc>,
    pub was_already_inactive: bool,
}

/// Inputs to the kill banner renderer.
#[derive(Debug, Clone)]
pub struct BannerInputs<'a> {
    pub activation: &'a ActivationSummaryView,
    /// Whether the audit event for this kill was written. Story 3.2 always
    /// passes `false`. Story 3.3 flips this to `true` when it adds the
    /// audit write path.
    pub audit_written: bool,
    /// Number of in-flight requests cancelled by this activation. `None`
    /// omits the line entirely (Story 3.2 behavior). `Some(n)` emits
    /// `✓ <n> in-flight request(s) cancelled`.
    pub in_flight_cancelled: Option<usize>,
    /// CLI wall-clock elapsed time — shown in the banner footer.
    pub elapsed: Duration,
    /// Detected terminal width in cells. Clamped to `[40, 120]` for
    /// separator rendering; `0` falls back to `64`.
    pub terminal_width: u16,
}

/// Inputs to the resume banner renderer.
#[derive(Debug, Clone)]
pub struct ResumeBannerInputs<'a> {
    pub deactivation: &'a DeactivationSummaryView,
    /// `resumed_at - activated_at`, if known. The CLI computes this by
    /// calling `GET /v1/control/state` before the resume POST. `None` skips
    /// the "duration killed" line.
    pub duration_killed: Option<Duration>,
    pub elapsed: Duration,
    pub terminal_width: u16,
}

// --------------------------------------------------------------------------
// Constants.
// --------------------------------------------------------------------------

/// Teal power glyph. Story 3.1 Gotcha note: non-color glyph, preserved in
/// `NO_COLOR` mode.
const POWER_GLYPH: &str = "\u{23FB}"; // ⏻

/// Amber separator character. U+2550 BOX DRAWINGS DOUBLE HORIZONTAL.
const SEPARATOR_CHAR: char = '\u{2550}'; // ═

/// Minimum separator width in cells. Below this, the banner looks
/// comically short even on narrow terminals.
const MIN_WIDTH: u16 = 40;

/// Maximum separator width in cells. Above this, the banner looks
/// comically stretched on wide terminals.
const MAX_WIDTH: u16 = 120;

/// Fallback when `terminal_width == 0` (detection failed).
const FALLBACK_WIDTH: u16 = 64;

// --------------------------------------------------------------------------
// Public renderers.
// --------------------------------------------------------------------------

/// Render the kill banner as a multi-line string.
///
/// Idempotent activation (the switch was already killed) produces a short
/// one-line banner instead of the full ceremony. First-time activation
/// produces the full §6.1 Interaction 3 layout.
#[must_use]
pub fn render_kill_banner(inputs: &BannerInputs, theme: &Theme, support: ColorSupport) -> String {
    let tokens = theme.tokens();
    let accent = tokens.accent; // teal — power glyph
    let warn = tokens.warn; // amber — separator + interior
    let dim = tokens.text_2; // tertiary — elapsed footer

    let mut buf = String::with_capacity(512);

    // --- Short form: idempotent no-op activation ---
    if inputs.activation.was_already_active {
        buf.push_str("  ");
        buf.push_str(&styled(POWER_GLYPH, accent, support));
        buf.push_str("  daemon was already in kill state (idempotent)\n");
        buf.push('\n');
        buf.push_str("  ");
        buf.push_str(&styled(
            &format!("elapsed: {}", format_elapsed(inputs.elapsed)),
            dim,
            support,
        ));
        buf.push('\n');
        return buf;
    }

    // --- Full form: first-time activation ---
    let width = resolve_separator_width(inputs.terminal_width);
    let separator = build_separator(width);

    // Line 1: "  ⏻  killing daemon…"
    buf.push_str("  ");
    buf.push_str(&styled(POWER_GLYPH, accent, support));
    buf.push_str("  killing daemon\u{2026}\n");
    buf.push('\n');

    // Bullet: "  ✓ N active token(s) invalidated"
    let token_label = plural(inputs.activation.tokens_invalidated, "token", "tokens");
    buf.push_str("  ");
    buf.push_str(&styled(
        &format!(
            "\u{2713} {} active {} invalidated",
            format_count(inputs.activation.tokens_invalidated as u64),
            token_label
        ),
        warn,
        support,
    ));
    buf.push('\n');

    // Optional bullet: "  ✓ N in-flight request(s) cancelled" (Story 3.2 always None)
    if let Some(n) = inputs.in_flight_cancelled {
        let label = plural(n, "request", "requests");
        buf.push_str("  ");
        buf.push_str(&styled(
            &format!("\u{2713} {} in-flight {} cancelled", format_count(n as u64), label),
            warn,
            support,
        ));
        buf.push('\n');
    }

    // Optional bullet: "  ✓ kill event written to audit" (Story 3.2 always false)
    if inputs.audit_written {
        buf.push_str("  ");
        buf.push_str(&styled("\u{2713} kill event written to audit", warn, support));
        buf.push('\n');
    }
    buf.push('\n');

    // Separator: amber ═══…═══
    buf.push_str("  ");
    buf.push_str(&styled(&separator, warn, support));
    buf.push('\n');

    // Interior lines:
    let ts = format_audit_timestamp(inputs.activation.activated_at);
    buf.push_str("    ");
    buf.push_str(&styled(&format!("DAEMON KILLED \u{00B7} {ts}"), warn, support));
    buf.push('\n');
    buf.push_str("    ");
    buf.push_str(&styled(
        &format!("cause: {}", kill_reason_label(&inputs.activation.reason)),
        warn,
        support,
    ));
    buf.push('\n');
    buf.push_str("    ");
    buf.push_str(&styled("new requests will receive HTTP 403", warn, support));
    buf.push('\n');
    buf.push_str("    ");
    buf.push_str(&styled("resume with:  agentsso resume", warn, support));
    buf.push('\n');

    // Separator again
    buf.push_str("  ");
    buf.push_str(&styled(&separator, warn, support));
    buf.push('\n');
    buf.push('\n');

    // Footer: "  elapsed: 1.18s"
    buf.push_str("  ");
    buf.push_str(&styled(&format!("elapsed: {}", format_elapsed(inputs.elapsed)), dim, support));
    buf.push('\n');

    buf
}

/// Render the resume banner.
///
/// Idempotent resume (the switch was already inactive) produces a short
/// "nothing to resume" banner. First-time resume produces the full form.
#[must_use]
pub fn render_resume_banner(
    inputs: &ResumeBannerInputs,
    theme: &Theme,
    support: ColorSupport,
) -> String {
    let tokens = theme.tokens();
    let accent = tokens.accent;
    let warn = tokens.warn;
    let dim = tokens.text_2;

    let mut buf = String::with_capacity(256);

    if inputs.deactivation.was_already_inactive {
        buf.push_str("  ");
        buf.push_str(&styled(POWER_GLYPH, accent, support));
        buf.push_str("  daemon was not in kill state \u{2014} nothing to resume\n");
        buf.push('\n');
        buf.push_str("  ");
        buf.push_str(&styled(
            &format!("elapsed: {}", format_elapsed(inputs.elapsed)),
            dim,
            support,
        ));
        buf.push('\n');
        return buf;
    }

    // Full form
    buf.push_str("  ");
    buf.push_str(&styled(POWER_GLYPH, accent, support));
    buf.push_str("  daemon resumed\n");
    buf.push('\n');

    let ts = format_audit_timestamp(inputs.deactivation.resumed_at);
    buf.push_str("    ");
    buf.push_str(&styled(&format!("RESUMED \u{00B7} {ts}"), warn, support));
    buf.push('\n');

    if let Some(d) = inputs.duration_killed {
        buf.push_str("    ");
        buf.push_str(&styled(&format!("duration killed: {}", format_elapsed(d)), warn, support));
        buf.push('\n');
    }
    buf.push('\n');

    buf.push_str("  ");
    buf.push_str(&styled(&format!("elapsed: {}", format_elapsed(inputs.elapsed)), dim, support));
    buf.push('\n');

    buf
}

// --------------------------------------------------------------------------
// Helpers.
// --------------------------------------------------------------------------

/// Clamp the detected terminal width into `[MIN_WIDTH, MAX_WIDTH]`, with a
/// fallback of `FALLBACK_WIDTH` when detection returned `0`.
fn resolve_separator_width(terminal_width: u16) -> u16 {
    if terminal_width == 0 {
        return FALLBACK_WIDTH;
    }
    terminal_width.clamp(MIN_WIDTH, MAX_WIDTH)
}

/// Build a separator string `N` cells wide using `SEPARATOR_CHAR`.
///
/// Uses explicit cell-width iteration rather than `str::repeat` so that
/// future changes to `SEPARATOR_CHAR` cannot silently change the visible
/// width through a multi-byte / multi-cell character swap. For `═` (1 cell
/// per char, 3 bytes), one char per cell. Verified by the separator-width
/// tests.
fn build_separator(cells: u16) -> String {
    let mut s = String::with_capacity(cells as usize * 3);
    let mut used_cells: u16 = 0;
    let glyph_cells = UnicodeWidthStr::width(SEPARATOR_CHAR.to_string().as_str());
    // `══════════` — glyph_cells is 1 for U+2550, so this loop runs `cells`
    // times. For a 2-cell glyph, it would halve naturally.
    while used_cells + glyph_cells as u16 <= cells {
        s.push(SEPARATOR_CHAR);
        used_cells += glyph_cells as u16;
    }
    s
}

/// Singular/plural helper.
fn plural<'a>(n: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if n == 1 { singular } else { plural }
}

/// Map a kill-reason wire label (as sent by the daemon in
/// `SerializableActivationSummary.reason`) to the string the banner shows
/// after `cause:`.
///
/// Currently these are identical (`"user-initiated"` on the wire →
/// `"user-initiated"` in the banner), but the indirection exists so a
/// future variant with a terse wire label like `"policy-trip"` can display
/// a friendlier `"policy tripwire"` in the banner without touching the
/// daemon-side serialization path.
///
/// Unknown labels fall through as-is. A pre-3.2 daemon running against a
/// 3.2+ CLI will send no `reason` field, the CLI will default to
/// `"unknown"` via `serde(default)`, and the banner will display
/// `"cause: unknown"` — accurate and diagnostic.
pub fn kill_reason_label(wire: &str) -> &str {
    match wire {
        "user-initiated" => "user-initiated",
        other => other,
    }
}

/// Format a `Duration` for banner display:
///
/// - `<9.95s`: `1.18s` (millisecond precision, 2 decimal places)
/// - `9.95s..60s`: `12s` (whole seconds)
/// - `>=60s`: `1m 34s`
///
/// The sub-second bucket cuts off at **9950ms**, not 10000ms, to avoid a
/// rendering glitch at the boundary: `9999ms` used to round up to
/// `"10.00s"` via the `{:.2}` branch while `10000ms` printed as `"10s"`
/// via the next bucket, producing an apparent "later kill took less time"
/// visual. Clamping the sub-second bucket to `< 9950ms` keeps the handoff
/// monotonic — `9949ms` → `"9.95s"`, `9950ms` → `"10s"`.
fn format_elapsed(d: Duration) -> String {
    let total_ms = d.as_millis();
    if total_ms < 9_950 {
        let secs = d.as_secs_f64();
        format!("{secs:.2}s")
    } else if total_ms < 60_000 {
        // Round to nearest whole second to match operator expectations
        // at the boundary (9950ms should read as "10s", not "9s").
        let rounded_secs = (total_ms + 500) / 1000;
        format!("{rounded_secs}s")
    } else {
        let total = d.as_secs();
        let minutes = total / 60;
        let seconds = total % 60;
        format!("{minutes}m {seconds}s")
    }
}

/// Format a UTC datetime as `%Y-%m-%dT%H:%M:%S%.3fZ` (audit-log format).
fn format_audit_timestamp(ts: DateTime<Utc>) -> String {
    ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

// --------------------------------------------------------------------------
// Tests.
// --------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed_timestamp() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 4, 10, 12, 34, 56).unwrap() + chrono::Duration::milliseconds(789)
    }

    fn sample_activation(tokens: usize, already_active: bool) -> ActivationSummaryView {
        ActivationSummaryView {
            tokens_invalidated: tokens,
            activated_at: fixed_timestamp(),
            was_already_active: already_active,
            reason: "user-initiated".to_owned(),
        }
    }

    fn sample_inputs<'a>(activation: &'a ActivationSummaryView) -> BannerInputs<'a> {
        BannerInputs {
            activation,
            audit_written: false,
            in_flight_cancelled: None,
            elapsed: Duration::from_millis(1180),
            terminal_width: 64,
        }
    }

    fn sample_deactivation(already_inactive: bool) -> DeactivationSummaryView {
        DeactivationSummaryView {
            resumed_at: fixed_timestamp() + chrono::Duration::seconds(12),
            was_already_inactive: already_inactive,
        }
    }

    fn sample_resume_inputs<'a>(
        deactivation: &'a DeactivationSummaryView,
    ) -> ResumeBannerInputs<'a> {
        ResumeBannerInputs {
            deactivation,
            duration_killed: Some(Duration::from_secs(12)),
            elapsed: Duration::from_millis(840),
            terminal_width: 64,
        }
    }

    // --- Kill banner: field coverage ---
    // NOTE: These snapshot tests hardcode `Theme::Carapace`. The
    // `Theme::load` → render integration path is covered by
    // `load_fallback_for_kill_banner_render_bypass` below (Story 8.6 AC #5).

    #[test]
    fn banner_contains_required_fields() {
        let activation = sample_activation(3, false);
        let inputs = sample_inputs(&activation);
        let out = render_kill_banner(&inputs, &Theme::Carapace, ColorSupport::NoColor);

        assert!(out.contains("killing daemon\u{2026}"), "missing 'killing daemon…': {out}");
        assert!(out.contains("3 active tokens invalidated"), "missing token line: {out}");
        assert!(
            out.contains("DAEMON KILLED \u{00B7} 2026-04-10T12:34:56.789Z"),
            "missing header: {out}"
        );
        assert!(out.contains("cause: user-initiated"), "missing cause line: {out}");
        assert!(out.contains("new requests will receive HTTP 403"), "missing HTTP hint: {out}");
        assert!(out.contains("resume with:  agentsso resume"), "missing resume hint: {out}");
        assert!(out.contains("elapsed: 1.18s"), "missing elapsed line: {out}");
    }

    #[test]
    fn banner_singular_token_label() {
        let activation = sample_activation(1, false);
        let inputs = sample_inputs(&activation);
        let out = render_kill_banner(&inputs, &Theme::Carapace, ColorSupport::NoColor);
        assert!(out.contains("1 active token invalidated"), "singular agreement failed: {out}");
        assert!(!out.contains("1 active tokens invalidated"), "plural leaked in singular case");
    }

    #[test]
    fn banner_plural_token_label() {
        let activation = sample_activation(2, false);
        let inputs = sample_inputs(&activation);
        let out = render_kill_banner(&inputs, &Theme::Carapace, ColorSupport::NoColor);
        assert!(out.contains("2 active tokens invalidated"), "plural agreement failed: {out}");
    }

    #[test]
    fn banner_zero_tokens_still_renders_line() {
        // Load-bearing: the current codebase never populates the token
        // registry, so every activation reads 0. The line must remain
        // visible — suppressing it would be a lie by omission.
        let activation = sample_activation(0, false);
        let inputs = sample_inputs(&activation);
        let out = render_kill_banner(&inputs, &Theme::Carapace, ColorSupport::NoColor);
        assert!(out.contains("0 active tokens invalidated"), "zero line suppressed: {out}");
    }

    #[test]
    fn banner_idempotent_short_form() {
        let activation = sample_activation(0, true);
        let inputs = sample_inputs(&activation);
        let out = render_kill_banner(&inputs, &Theme::Carapace, ColorSupport::NoColor);
        assert!(
            out.contains("already in kill state (idempotent)"),
            "missing idempotent line: {out}"
        );
        assert!(!out.contains("DAEMON KILLED"), "full-form leaked into idempotent case: {out}");
        assert!(out.contains("elapsed:"), "elapsed footer missing: {out}");
    }

    // --- Forbidden color tests (the key Epic 2 retro action item) ---

    #[test]
    fn banner_carapace_never_uses_danger_token() {
        // Carapace --danger = #EF6F6C → 239,111,108
        let activation = sample_activation(3, false);
        let inputs = sample_inputs(&activation);
        let out = render_kill_banner(&inputs, &Theme::Carapace, ColorSupport::TrueColor);
        assert!(
            !out.contains("\x1b[38;2;239;111;108m"),
            "Carapace --danger leaked into kill banner: {out:?}"
        );
    }

    #[test]
    fn banner_molt_never_uses_danger_token() {
        // Molt --danger = #DC2626 → 220,38,38
        let activation = sample_activation(3, false);
        let inputs = sample_inputs(&activation);
        let out = render_kill_banner(&inputs, &Theme::Molt, ColorSupport::TrueColor);
        assert!(
            !out.contains("\x1b[38;2;220;38;38m"),
            "Molt --danger leaked into kill banner: {out:?}"
        );
    }

    #[test]
    fn banner_tidepool_never_uses_danger_token() {
        // Tidepool --danger = #F38BA8 → 243,139,168
        let activation = sample_activation(3, false);
        let inputs = sample_inputs(&activation);
        let out = render_kill_banner(&inputs, &Theme::Tidepool, ColorSupport::TrueColor);
        assert!(
            !out.contains("\x1b[38;2;243;139;168m"),
            "Tidepool --danger leaked into kill banner: {out:?}"
        );
    }

    #[test]
    fn banner_uses_warn_token_in_true_color() {
        // Carapace --warn = #F5B454 → 245,180,84
        let activation = sample_activation(3, false);
        let inputs = sample_inputs(&activation);
        let out = render_kill_banner(&inputs, &Theme::Carapace, ColorSupport::TrueColor);
        assert!(
            out.contains("\x1b[38;2;245;180;84m"),
            "Carapace --warn not present in banner TrueColor output: {out:?}"
        );
    }

    #[test]
    fn banner_uses_accent_token_for_power_glyph() {
        // Carapace --accent = #2DD4BF → 45,212,191
        let activation = sample_activation(3, false);
        let inputs = sample_inputs(&activation);
        let out = render_kill_banner(&inputs, &Theme::Carapace, ColorSupport::TrueColor);
        assert!(
            out.contains("\x1b[38;2;45;212;191m"),
            "Carapace --accent not present in banner TrueColor output: {out:?}"
        );
    }

    // --- NO_COLOR preserves glyph ---

    #[test]
    fn banner_no_color_mode_preserves_glyph() {
        let activation = sample_activation(3, false);
        let inputs = sample_inputs(&activation);
        let out = render_kill_banner(&inputs, &Theme::Carapace, ColorSupport::NoColor);
        assert!(out.contains(POWER_GLYPH), "power glyph stripped in NoColor mode: {out}");
        assert!(!out.contains('\x1b'), "ANSI escape in NoColor mode: {out:?}");
    }

    // --- Separator width handling ---

    #[test]
    fn separator_width_clamped_to_min() {
        let activation = sample_activation(3, false);
        let mut inputs = sample_inputs(&activation);
        inputs.terminal_width = 20; // below MIN_WIDTH
        let out = render_kill_banner(&inputs, &Theme::Carapace, ColorSupport::NoColor);
        let sep_line = out
            .lines()
            .find(|l| l.trim_start().starts_with(SEPARATOR_CHAR))
            .expect("no separator line found");
        let cells = UnicodeWidthStr::width(sep_line.trim_start());
        assert_eq!(cells as u16, MIN_WIDTH, "expected clamp to MIN_WIDTH: {cells}");
    }

    #[test]
    fn separator_width_clamped_to_max() {
        let activation = sample_activation(3, false);
        let mut inputs = sample_inputs(&activation);
        inputs.terminal_width = 200; // above MAX_WIDTH
        let out = render_kill_banner(&inputs, &Theme::Carapace, ColorSupport::NoColor);
        let sep_line = out
            .lines()
            .find(|l| l.trim_start().starts_with(SEPARATOR_CHAR))
            .expect("no separator line found");
        let cells = UnicodeWidthStr::width(sep_line.trim_start());
        assert_eq!(cells as u16, MAX_WIDTH, "expected clamp to MAX_WIDTH: {cells}");
    }

    #[test]
    fn separator_width_handles_zero() {
        let activation = sample_activation(3, false);
        let mut inputs = sample_inputs(&activation);
        inputs.terminal_width = 0;
        let out = render_kill_banner(&inputs, &Theme::Carapace, ColorSupport::NoColor);
        let sep_line = out
            .lines()
            .find(|l| l.trim_start().starts_with(SEPARATOR_CHAR))
            .expect("no separator line found");
        let cells = UnicodeWidthStr::width(sep_line.trim_start());
        assert_eq!(cells as u16, FALLBACK_WIDTH, "expected fallback width: {cells}");
    }

    #[test]
    fn separator_within_bounds_preserved() {
        let activation = sample_activation(3, false);
        let mut inputs = sample_inputs(&activation);
        inputs.terminal_width = 80;
        let out = render_kill_banner(&inputs, &Theme::Carapace, ColorSupport::NoColor);
        let sep_line = out
            .lines()
            .find(|l| l.trim_start().starts_with(SEPARATOR_CHAR))
            .expect("no separator line found");
        let cells = UnicodeWidthStr::width(sep_line.trim_start());
        assert_eq!(cells, 80, "expected 80 cells: {cells}");
    }

    // --- Elapsed formatting ---

    #[test]
    fn elapsed_sub_second_formatted_with_ms() {
        assert_eq!(format_elapsed(Duration::from_millis(180)), "0.18s");
        assert_eq!(format_elapsed(Duration::from_millis(1180)), "1.18s");
    }

    #[test]
    fn elapsed_mid_range_formatted_as_whole_seconds() {
        assert_eq!(format_elapsed(Duration::from_secs(12)), "12s");
        assert_eq!(format_elapsed(Duration::from_secs(59)), "59s");
    }

    #[test]
    fn elapsed_long_formatted_as_m_s() {
        assert_eq!(format_elapsed(Duration::from_secs(60)), "1m 0s");
        assert_eq!(format_elapsed(Duration::from_secs(94)), "1m 34s");
    }

    #[test]
    fn elapsed_boundary_9s_sub_second_branch() {
        // Just under the 9.95s cutoff — stays in sub-second format.
        assert_eq!(format_elapsed(Duration::from_millis(9_940)), "9.94s");
        // At/above the cutoff — flips to whole-second format. Critical
        // regression: 9999ms used to round up to "10.00s" (sub-second
        // {:.2}) while 10000ms printed as "10s" (whole-second bucket),
        // producing a visual "later kill took less time" glitch.
        assert_eq!(format_elapsed(Duration::from_millis(9_950)), "10s");
        assert_eq!(format_elapsed(Duration::from_millis(9_999)), "10s");
        assert_eq!(format_elapsed(Duration::from_millis(10_000)), "10s");
    }

    // --- Resume banner ---

    #[test]
    fn resume_banner_short_form_idempotent() {
        let deactivation = sample_deactivation(true);
        let inputs = sample_resume_inputs(&deactivation);
        let out = render_resume_banner(&inputs, &Theme::Carapace, ColorSupport::NoColor);
        assert!(out.contains("nothing to resume"), "missing nothing-to-resume: {out}");
        assert!(!out.contains("RESUMED \u{00B7}"), "full-form leaked: {out}");
    }

    #[test]
    fn resume_banner_full_form_contains_duration_killed() {
        let deactivation = sample_deactivation(false);
        let inputs = sample_resume_inputs(&deactivation);
        let out = render_resume_banner(&inputs, &Theme::Carapace, ColorSupport::NoColor);
        assert!(out.contains("daemon resumed"), "missing header: {out}");
        assert!(out.contains("RESUMED \u{00B7}"), "missing RESUMED line: {out}");
        assert!(out.contains("duration killed: 12s"), "missing duration_killed: {out}");
        assert!(out.contains("elapsed:"), "missing elapsed: {out}");
    }

    #[test]
    fn resume_banner_full_form_omits_duration_killed_when_none() {
        let deactivation = sample_deactivation(false);
        let mut inputs = sample_resume_inputs(&deactivation);
        inputs.duration_killed = None;
        let out = render_resume_banner(&inputs, &Theme::Carapace, ColorSupport::NoColor);
        assert!(!out.contains("duration killed"), "duration_killed leaked when None: {out}");
    }

    #[test]
    fn resume_banner_never_uses_danger_token() {
        let deactivation = sample_deactivation(false);
        let inputs = sample_resume_inputs(&deactivation);
        for theme in [Theme::Carapace, Theme::Molt, Theme::Tidepool] {
            let out = render_resume_banner(&inputs, &theme, ColorSupport::TrueColor);
            // Spot-check each theme's danger token
            let danger_hex = match theme {
                Theme::Carapace => "\x1b[38;2;239;111;108m",
                Theme::Molt => "\x1b[38;2;220;38;38m",
                Theme::Tidepool => "\x1b[38;2;243;139;168m",
            };
            assert!(
                !out.contains(danger_hex),
                "{theme:?} --danger leaked into resume banner: {out:?}"
            );
        }
    }

    #[test]
    fn resume_banner_no_color_preserves_glyph() {
        let deactivation = sample_deactivation(false);
        let inputs = sample_resume_inputs(&deactivation);
        let out = render_resume_banner(&inputs, &Theme::Carapace, ColorSupport::NoColor);
        assert!(out.contains(POWER_GLYPH), "power glyph stripped: {out}");
        assert!(!out.contains('\x1b'), "ANSI escape in NoColor: {out:?}");
    }

    // --- Snapshot tests (insta) ---

    #[test]
    fn kill_banner_carapace_snapshot() {
        let activation = sample_activation(3, false);
        let inputs = sample_inputs(&activation);
        let out = render_kill_banner(&inputs, &Theme::Carapace, ColorSupport::NoColor);
        insta::assert_snapshot!("kill_banner_carapace_no_color", out);
    }

    #[test]
    fn kill_banner_molt_snapshot() {
        let activation = sample_activation(3, false);
        let inputs = sample_inputs(&activation);
        let out = render_kill_banner(&inputs, &Theme::Molt, ColorSupport::NoColor);
        insta::assert_snapshot!("kill_banner_molt_no_color", out);
    }

    #[test]
    fn kill_banner_tidepool_snapshot() {
        let activation = sample_activation(3, false);
        let inputs = sample_inputs(&activation);
        let out = render_kill_banner(&inputs, &Theme::Tidepool, ColorSupport::NoColor);
        insta::assert_snapshot!("kill_banner_tidepool_no_color", out);
    }

    #[test]
    fn resume_banner_carapace_snapshot() {
        let deactivation = sample_deactivation(false);
        let inputs = sample_resume_inputs(&deactivation);
        let out = render_resume_banner(&inputs, &Theme::Carapace, ColorSupport::NoColor);
        insta::assert_snapshot!("resume_banner_carapace_no_color", out);
    }

    #[test]
    fn resume_banner_molt_snapshot() {
        let deactivation = sample_deactivation(false);
        let inputs = sample_resume_inputs(&deactivation);
        let out = render_resume_banner(&inputs, &Theme::Molt, ColorSupport::NoColor);
        insta::assert_snapshot!("resume_banner_molt_no_color", out);
    }

    #[test]
    fn resume_banner_tidepool_snapshot() {
        let deactivation = sample_deactivation(false);
        let inputs = sample_resume_inputs(&deactivation);
        let out = render_resume_banner(&inputs, &Theme::Tidepool, ColorSupport::NoColor);
        insta::assert_snapshot!("resume_banner_tidepool_no_color", out);
    }

    // --- Plural helper sanity ---

    #[test]
    fn plural_helper() {
        assert_eq!(plural(0, "token", "tokens"), "tokens");
        assert_eq!(plural(1, "token", "tokens"), "token");
        assert_eq!(plural(2, "token", "tokens"), "tokens");
    }

    #[test]
    fn kill_reason_label_known_variant() {
        assert_eq!(kill_reason_label("user-initiated"), "user-initiated");
    }

    #[test]
    fn kill_reason_label_unknown_wire_passes_through() {
        // Pre-3.2 daemons + future variants without an explicit mapping
        // should fall through with the raw wire label. The banner shows
        // "cause: unknown" or "cause: some-new-variant" — still diagnostic.
        assert_eq!(kill_reason_label("unknown"), "unknown");
        assert_eq!(kill_reason_label("policy-tripwire"), "policy-tripwire");
    }

    #[test]
    fn banner_cause_line_uses_reason_label() {
        // Build a view with a non-default reason to prove the renderer
        // doesn't hardcode "user-initiated" anywhere.
        let mut activation = sample_activation(3, false);
        activation.reason = "policy-tripwire".to_owned();
        let inputs = sample_inputs(&activation);
        let out = render_kill_banner(&inputs, &Theme::Carapace, ColorSupport::NoColor);
        assert!(out.contains("cause: policy-tripwire"), "missing custom cause: {out}");
        assert!(!out.contains("cause: user-initiated"), "hardcoded label leaked: {out}");
    }

    #[test]
    fn banner_cause_line_unknown_reason_renders_verbatim() {
        let mut activation = sample_activation(3, false);
        activation.reason = "unknown".to_owned();
        let inputs = sample_inputs(&activation);
        let out = render_kill_banner(&inputs, &Theme::Carapace, ColorSupport::NoColor);
        assert!(out.contains("cause: unknown"), "missing unknown cause line: {out}");
    }

    #[test]
    fn audit_timestamp_format() {
        let ts = fixed_timestamp();
        assert_eq!(format_audit_timestamp(ts), "2026-04-10T12:34:56.789Z");
    }

    /// Story 8.6 AC #5 — close the "banner tests bypass `Theme::load`"
    /// gap from the Story 3.2 review. Prove that `Theme::load`
    /// actually consults `<home>/config/ui.toml` by first writing a
    /// valid non-default theme (`molt`) and asserting the round-trip
    /// returns `Theme::Molt` — a pure-fallback impl (one that ignored
    /// its argument) would fail this step. Then overwrite with an
    /// invalid value and verify the fallback path feeds
    /// `render_kill_banner` end-to-end.
    ///
    /// Uses subset-matching instead of a new insta snapshot so the
    /// existing `kill_banner_carapace_snapshot` stays the canonical
    /// rendering contract.
    #[test]
    fn load_fallback_for_kill_banner_render_bypass() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let config_dir = tmp.path().join("config");
        std::fs::create_dir_all(&config_dir).expect("mkdir config");
        let ui_toml = config_dir.join("ui.toml");

        // Step 1: write a valid non-default theme and confirm
        // Theme::load round-trips it. Proves the function reads the
        // file — a hypothetical bug that always returns the default
        // would be caught here.
        std::fs::write(&ui_toml, "theme = \"molt\"\n").expect("write ui.toml");
        assert_eq!(
            Theme::load(tmp.path()),
            Theme::Molt,
            "Theme::load must read ui.toml (valid theme must round-trip)"
        );

        // Step 2: overwrite with an invalid theme value. Theme::load
        // reads the file but cannot match "notatheme", so the
        // fallback returns Theme::Carapace.
        std::fs::write(&ui_toml, "theme = \"notatheme\"\n").expect("overwrite ui.toml");
        let theme = Theme::load(tmp.path());
        assert_eq!(theme, Theme::Carapace, "invalid theme must fall back to Carapace");

        // Step 3: the fallback theme renders a full kill banner
        // end-to-end without panicking or producing empty output.
        let activation = sample_activation(3, false);
        let inputs = sample_inputs(&activation);
        let out = render_kill_banner(&inputs, &theme, ColorSupport::NoColor);

        assert!(out.contains("killing daemon\u{2026}"), "missing 'killing daemon…': {out}");
        assert!(
            out.contains("DAEMON KILLED \u{00B7} 2026-04-10T12:34:56.789Z"),
            "missing header: {out}"
        );
        assert!(out.contains("resume with:  agentsso resume"), "missing resume hint: {out}");
    }
}
