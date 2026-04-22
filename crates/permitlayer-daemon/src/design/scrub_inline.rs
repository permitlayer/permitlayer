//! `ScrubInline` — the viral-moment CLI renderer for a single scrub event.
//!
//! Renders a [`ScrubSample`] as a boxed, amber-highlighted inline quote
//! with an arrow pointing at the redacted span, a `caught:` label, and a
//! `why?` affordance pointing at `agentsso scrub explain <rule>`.
//!
//! This is the `ScrubInline` component called out in UX-DR12 / §6.1
//! Interaction 2 of the UX spec — the first-scrub-event screenshot Maya
//! shares on Twitter.
//!
//! # Color semantics (UX-DR4)
//!
//! All amber highlights — placeholder substring, box border, `caught:`
//! label — use the `--warn` theme token (`#F5B454` in Carapace). The
//! `why?` line uses `--text-2` (tertiary text). Coral-red `--danger` is
//! **forbidden** in scrub rendering; a unit test asserts no `--danger`
//! ANSI bytes appear in any scrub render path.

use permitlayer_core::scrub::ScrubSample;
use unicode_width::UnicodeWidthStr;

use crate::design::render::truncate_field;
use crate::design::terminal::{ColorSupport, styled};
use crate::design::theme::Theme;

/// Left-pad in the §6.1 mock: box aligns under the audit-row timestamp column.
const LEFT_PAD: usize = 11;

/// Interior text width of the box — the width of the text column between
/// `│ ` (left border + space padding) and ` │` (space padding + right
/// border). The outer box is `INTERIOR_WIDTH + 4` cells wide: two border
/// chars + two padding spaces + `INTERIOR_WIDTH` cells of content. The
/// horizontal border runs `INTERIOR_WIDTH + 2` dashes between `┌` and `┐`
/// so it visually spans the padding spaces too.
const INTERIOR_WIDTH: usize = 44;

/// Number of dashes between `┌` and `┐` (and `└`/`┘`).
const BORDER_DASHES: usize = INTERIOR_WIDTH + 2;

/// Render a single [`ScrubSample`] using the §6.1 Interaction 2 layout.
///
/// Returns a multi-line string:
///
/// ```text
///            ┌────────────────────────────────────────────┐
///            │ {snippet_with_amber_placeholder}           │
///            │                    ↑                       │
///            │              caught: otp-6digit            │
///            └────────────────────────────────────────────┘
///            why? → agentsso scrub explain otp-6digit
/// ```
///
/// All color application is delegated to [`crate::design::terminal::styled`],
/// which honors the `ColorSupport` detection from Story 1.13 (`NO_COLOR`
/// fallback, ANSI-256, ANSI-16).
#[must_use]
pub fn render_scrub_inline(sample: &ScrubSample, theme: &Theme, support: ColorSupport) -> String {
    let tokens = theme.tokens();
    let warn = tokens.warn; // amber — placeholder, border, caught:
    let dim = tokens.text_2; // tertiary text — why? line

    // Compose a windowed snippet that fits in INTERIOR_WIDTH cells while
    // preserving the placeholder in the visible region.
    let (visible_snippet, visible_placeholder_char_start, visible_placeholder_char_len) =
        fit_snippet(
            &sample.snippet,
            sample.placeholder_offset,
            sample.placeholder_len,
            INTERIOR_WIDTH,
        );

    let left = " ".repeat(LEFT_PAD);
    let border_line: String = "\u{2500}".repeat(BORDER_DASHES); // ─

    let mut buf = String::with_capacity(512);

    // Top border: ┌────…────┐
    buf.push_str(&left);
    buf.push_str(&styled(&format!("\u{250C}{border_line}\u{2510}"), warn, support));
    buf.push('\n');

    // Snippet row: │ {snippet with amber placeholder} │  (padded to INTERIOR_WIDTH)
    buf.push_str(&left);
    buf.push_str(&styled("\u{2502}", warn, support)); // │
    buf.push(' ');
    buf.push_str(&render_snippet_row(
        &visible_snippet,
        visible_placeholder_char_start,
        visible_placeholder_char_len,
        warn,
        support,
    ));
    buf.push(' ');
    buf.push_str(&styled("\u{2502}", warn, support));
    buf.push('\n');

    // Arrow row: │       ↑                           │
    // `visible_placeholder_char_start` is a character offset into the
    // snippet, but display position must use the *cell width* of the
    // text before the placeholder.
    let cells_before = cells_in_char_range(&visible_snippet, 0, visible_placeholder_char_start);
    let placeholder_cells = cells_in_char_range(
        &visible_snippet,
        visible_placeholder_char_start,
        visible_placeholder_char_start + visible_placeholder_char_len,
    );
    // Arrow lands under the visual center of the placeholder.
    let arrow_col = cells_before + placeholder_cells.saturating_sub(1) / 2;
    let arrow_padding = " ".repeat(arrow_col.min(INTERIOR_WIDTH.saturating_sub(1)));
    let trailing_spaces = INTERIOR_WIDTH.saturating_sub(arrow_col + 1);

    buf.push_str(&left);
    buf.push_str(&styled("\u{2502}", warn, support));
    buf.push(' ');
    buf.push_str(&arrow_padding);
    buf.push('\u{2191}'); // ↑
    buf.push_str(&" ".repeat(trailing_spaces));
    buf.push(' ');
    buf.push_str(&styled("\u{2502}", warn, support));
    buf.push('\n');

    // Caught row: │            caught: otp-6digit         │
    //
    // Rule names are short today (≤11 chars for every built-in rule),
    // but a future custom rule could exceed `INTERIOR_WIDTH` and
    // overflow the box. Truncate the full "caught: <rule>" string to
    // fit inside the interior; `truncate_field` appends `…` when it
    // cuts. Char-count truncation is sufficient here because rule
    // names are kebab-case ASCII — no wide-char hazard.
    let caught_text_full = format!("caught: {}", sample.rule);
    let caught_text = truncate_field(&caught_text_full, INTERIOR_WIDTH);
    let caught_cells = UnicodeWidthStr::width(caught_text.as_str());
    // Center the caught text under the arrow, clamped to interior
    // bounds. `saturating_sub` on usize naturally floors at 0 — no
    // `.max(0)` needed.
    let caught_start = arrow_col.saturating_sub(caught_cells / 2);
    let caught_start = caught_start.min(INTERIOR_WIDTH.saturating_sub(caught_cells));
    let caught_trailing = INTERIOR_WIDTH.saturating_sub(caught_start + caught_cells);

    buf.push_str(&left);
    buf.push_str(&styled("\u{2502}", warn, support));
    buf.push(' ');
    buf.push_str(&" ".repeat(caught_start));
    buf.push_str(&styled(&caught_text, warn, support));
    buf.push_str(&" ".repeat(caught_trailing));
    buf.push(' ');
    buf.push_str(&styled("\u{2502}", warn, support));
    buf.push('\n');

    // Bottom border: └────…────┘
    buf.push_str(&left);
    buf.push_str(&styled(&format!("\u{2514}{border_line}\u{2518}"), warn, support));
    buf.push('\n');

    // Why line: dim text
    buf.push_str(&left);
    let why_line = format!("why? \u{2192} agentsso scrub explain {}", sample.rule);
    buf.push_str(&styled(&why_line, dim, support));
    buf.push('\n');

    buf
}

/// Render a single snippet row, applying amber color ONLY to the
/// placeholder substring. Pads with spaces to exactly `INTERIOR_WIDTH`
/// terminal cells.
fn render_snippet_row(
    snippet: &str,
    placeholder_char_start: usize,
    placeholder_char_len: usize,
    warn: &str,
    support: ColorSupport,
) -> String {
    let chars: Vec<char> = snippet.chars().collect();
    let before: String = chars[..placeholder_char_start].iter().collect();
    let placeholder: String = chars
        [placeholder_char_start..placeholder_char_start + placeholder_char_len]
        .iter()
        .collect();
    let after: String = chars[placeholder_char_start + placeholder_char_len..].iter().collect();

    let used_cells = UnicodeWidthStr::width(snippet);
    let pad = INTERIOR_WIDTH.saturating_sub(used_cells);

    let mut row = String::with_capacity(snippet.len() + pad + 32);
    row.push_str(&before);
    row.push_str(&styled(&placeholder, warn, support));
    row.push_str(&after);
    row.push_str(&" ".repeat(pad));
    row
}

/// Fit a snippet into a fixed cell width while keeping the placeholder
/// visible. Returns `(visible_snippet, placeholder_char_start_in_visible,
/// placeholder_char_len_in_visible)`.
///
/// Strategy:
/// 1. If the full snippet already fits in `max_cells`, return it unchanged.
/// 2. Otherwise, re-window around the placeholder: take `max_cells` cells
///    centered on the placeholder, biased to the right so surrounding
///    context is visible. Truncate with `…` on the overflow side.
fn fit_snippet(
    snippet: &str,
    placeholder_byte_offset: usize,
    placeholder_byte_len: usize,
    max_cells: usize,
) -> (String, usize, usize) {
    // Compute placeholder in character-offset terms.
    let placeholder_char_start = snippet[..placeholder_byte_offset].chars().count();
    let placeholder_char_end =
        snippet[..placeholder_byte_offset + placeholder_byte_len].chars().count();
    let placeholder_char_len = placeholder_char_end - placeholder_char_start;

    if UnicodeWidthStr::width(snippet) <= max_cells {
        return (snippet.to_owned(), placeholder_char_start, placeholder_char_len);
    }

    // Snippet too wide — re-window. Keep the whole placeholder and as
    // much surrounding context as fits, biased so there's breathing
    // room on both sides when possible.
    let chars: Vec<char> = snippet.chars().collect();

    // Start with just the placeholder.
    let mut start = placeholder_char_start;
    let mut end = placeholder_char_end;
    let placeholder_cells: usize =
        chars[start..end].iter().map(|c| UnicodeWidthStr::width(c.to_string().as_str())).sum();

    if placeholder_cells >= max_cells {
        // Pathological: placeholder alone exceeds the budget. Walk the
        // placeholder char-by-char and include as many cells as fit.
        // `max_cells` is a terminal-cell budget, NOT an iterator-item
        // count — a wide-char (CJK, emoji) placeholder can fit fewer
        // chars than `max_cells` and still exactly fill the interior.
        let mut truncated = String::new();
        let mut used: usize = 0;
        let mut chars_kept: usize = 0;
        for c in chars[start..end].iter() {
            let w = UnicodeWidthStr::width(c.to_string().as_str());
            if used + w > max_cells {
                break;
            }
            truncated.push(*c);
            used += w;
            chars_kept += 1;
        }
        return (truncated, 0, chars_kept);
    }

    let mut budget = max_cells - placeholder_cells;
    // Expand alternately left and right, favoring left slightly so the
    // placeholder sits visually right of center.
    while budget > 0 && (start > 0 || end < chars.len()) {
        if start > 0 {
            let w = UnicodeWidthStr::width(chars[start - 1].to_string().as_str());
            if w <= budget {
                start -= 1;
                budget -= w;
                continue;
            }
        }
        if end < chars.len() {
            let w = UnicodeWidthStr::width(chars[end].to_string().as_str());
            if w <= budget {
                end += 1;
                budget -= w;
                continue;
            }
        }
        break;
    }

    let visible: String = chars[start..end].iter().collect();
    let new_placeholder_start = placeholder_char_start - start;
    (visible, new_placeholder_start, placeholder_char_len)
}

/// Sum the cell widths of the characters in `s[char_start..char_end]`.
fn cells_in_char_range(s: &str, char_start: usize, char_end: usize) -> usize {
    s.chars()
        .skip(char_start)
        .take(char_end - char_start)
        .map(|c| UnicodeWidthStr::width(c.to_string().as_str()))
        .sum()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn sample() -> ScrubSample {
        ScrubSample {
            rule: "otp-6digit".into(),
            snippet: "Your verification code is <REDACTED_OTP>".into(),
            // byte offset of "<REDACTED_OTP>" within the snippet
            placeholder_offset: 26,
            placeholder_len: 14,
        }
    }

    #[test]
    fn render_no_color_contains_all_elements() {
        let s = sample();
        let out = render_scrub_inline(&s, &Theme::Carapace, ColorSupport::NoColor);

        // Box border chars
        assert!(out.contains("\u{250C}"), "missing ┌: {out}");
        assert!(out.contains("\u{2510}"), "missing ┐: {out}");
        assert!(out.contains("\u{2514}"), "missing └: {out}");
        assert!(out.contains("\u{2518}"), "missing ┘: {out}");
        assert!(out.contains("\u{2500}"), "missing ─: {out}");
        assert!(out.contains("\u{2502}"), "missing │: {out}");
        // Arrow
        assert!(out.contains("\u{2191}"), "missing ↑: {out}");
        // Placeholder, caught, why
        assert!(out.contains("<REDACTED_OTP>"));
        assert!(out.contains("caught: otp-6digit"));
        assert!(out.contains("why? \u{2192} agentsso scrub explain otp-6digit"));

        // NoColor → no ANSI escapes
        assert!(!out.contains('\x1b'), "NoColor output should not contain ANSI: {out:?}");
    }

    #[test]
    fn render_truecolor_has_amber_ansi_escapes() {
        let s = sample();
        let out = render_scrub_inline(&s, &Theme::Carapace, ColorSupport::TrueColor);

        // Amber warn token is #F5B454 → 245, 180, 84 in TrueColor ANSI.
        assert!(
            out.contains("\x1b[38;2;245;180;84m"),
            "expected amber ANSI (245,180,84) in output: {out:?}"
        );
    }

    #[test]
    fn render_truecolor_never_uses_danger_token() {
        // UX-DR4 invariant: scrub rendering must never use coral-red --danger.
        // Carapace --danger is #EF6F6C → 239,111,108 in TrueColor ANSI.
        let s = sample();
        let out = render_scrub_inline(&s, &Theme::Carapace, ColorSupport::TrueColor);
        assert!(
            !out.contains("\x1b[38;2;239;111;108m"),
            "coral-red --danger leaked into scrub rendering: {out:?}"
        );

        // Also check Molt and Tidepool themes.
        let molt = render_scrub_inline(&s, &Theme::Molt, ColorSupport::TrueColor);
        let tidepool = render_scrub_inline(&s, &Theme::Tidepool, ColorSupport::TrueColor);
        // Molt --danger = #DC2626 → 220,38,38
        assert!(!molt.contains("\x1b[38;2;220;38;38m"), "Molt --danger leaked: {molt:?}");
        // Tidepool --danger = #F38BA8 → 243,139,168
        assert!(
            !tidepool.contains("\x1b[38;2;243;139;168m"),
            "Tidepool --danger leaked: {tidepool:?}"
        );
    }

    #[test]
    fn render_multiple_themes_all_render() {
        let s = sample();
        for theme in [Theme::Carapace, Theme::Molt, Theme::Tidepool] {
            let out = render_scrub_inline(&s, &theme, ColorSupport::NoColor);
            assert!(out.contains("<REDACTED_OTP>"), "theme {theme}: {out}");
            assert!(out.contains("caught: otp-6digit"), "theme {theme}: {out}");
        }
    }

    #[test]
    fn render_places_arrow_under_placeholder() {
        let s = sample();
        let out = render_scrub_inline(&s, &Theme::Carapace, ColorSupport::NoColor);
        let lines: Vec<&str> = out.lines().collect();
        // 6 lines: top border, snippet, arrow, caught, bottom border, why?
        assert_eq!(lines.len(), 6, "expected 6 lines: {lines:?}");

        // Snippet row: line index 1.
        let snippet_line = lines[1];
        // Find the byte index of the first `<`, then convert to cell column.
        let lt_byte = snippet_line.find('<').expect("snippet contains <");
        let lt_col = UnicodeWidthStr::width(&snippet_line[..lt_byte]);

        // Arrow row: line index 2.
        let arrow_line = lines[2];
        let arrow_byte = arrow_line.find('\u{2191}').expect("arrow line contains ↑");
        let arrow_col = UnicodeWidthStr::width(&arrow_line[..arrow_byte]);

        // The arrow should land inside the placeholder span.
        let placeholder_end_col = lt_col + UnicodeWidthStr::width("<REDACTED_OTP>");
        assert!(
            arrow_col >= lt_col && arrow_col < placeholder_end_col,
            "arrow col {arrow_col} not inside placeholder [{lt_col}, {placeholder_end_col}): {out}"
        );
    }

    #[test]
    fn render_pads_interior_to_fixed_width() {
        let s = sample();
        let out = render_scrub_inline(&s, &Theme::Carapace, ColorSupport::NoColor);
        let lines: Vec<&str> = out.lines().collect();

        // All 5 first lines (border, snippet, arrow, caught, border) should
        // be the same visible width in NoColor mode (no ANSI to strip).
        let border_cells = UnicodeWidthStr::width(lines[0]);
        for (i, line) in lines.iter().take(5).enumerate() {
            let w = UnicodeWidthStr::width(*line);
            assert_eq!(
                w, border_cells,
                "line {i} width {w} != border width {border_cells}: {line:?}"
            );
        }
    }

    #[test]
    fn render_truncates_long_snippet_but_keeps_placeholder() {
        let sample = ScrubSample {
            rule: "otp-6digit".into(),
            snippet: "x".repeat(100) + "<REDACTED_OTP>" + &"y".repeat(100),
            placeholder_offset: 100,
            placeholder_len: 14,
        };
        let out = render_scrub_inline(&sample, &Theme::Carapace, ColorSupport::NoColor);
        // Placeholder must still be visible even though the snippet vastly
        // exceeds INTERIOR_WIDTH.
        assert!(out.contains("<REDACTED_OTP>"), "placeholder dropped: {out}");
    }

    #[test]
    fn render_handles_placeholder_at_start() {
        let sample = ScrubSample {
            rule: "otp-6digit".into(),
            snippet: "<REDACTED_OTP> at the start".into(),
            placeholder_offset: 0,
            placeholder_len: 14,
        };
        let out = render_scrub_inline(&sample, &Theme::Carapace, ColorSupport::NoColor);
        assert!(out.contains("<REDACTED_OTP>"));
        assert!(out.contains("caught: otp-6digit"));
    }

    #[test]
    fn render_handles_placeholder_at_end() {
        let sample = ScrubSample {
            rule: "otp-6digit".into(),
            snippet: "ends with <REDACTED_OTP>".into(),
            placeholder_offset: 10,
            placeholder_len: 14,
        };
        let out = render_scrub_inline(&sample, &Theme::Carapace, ColorSupport::NoColor);
        assert!(out.contains("<REDACTED_OTP>"));
    }

    #[test]
    fn scrub_inline_no_color_snapshot() {
        let s = sample();
        let out = render_scrub_inline(&s, &Theme::Carapace, ColorSupport::NoColor);
        insta::assert_snapshot!("scrub_inline_no_color", out);
    }

    #[test]
    fn scrub_inline_truecolor_snapshot() {
        let s = sample();
        let out = render_scrub_inline(&s, &Theme::Carapace, ColorSupport::TrueColor);
        insta::assert_snapshot!("scrub_inline_truecolor", out);
    }

    // ----- Review patch: pathological placeholder cell-width handling -----

    #[test]
    fn fit_snippet_pathological_branch_respects_cell_width_not_char_count() {
        // Placeholder composed of wide emoji chars, each 2 cells wide.
        // With max_cells=5, we can fit at most 2 chars (4 cells); char
        // count 5 would produce a 10-cell string that overflows the box.
        let wide: String = "\u{1F600}\u{1F601}\u{1F602}\u{1F603}\u{1F604}".to_string();
        let placeholder_byte_len = wide.len();
        let (visible, offset, len) = super::fit_snippet(&wide, 0, placeholder_byte_len, 5);
        let cells = UnicodeWidthStr::width(visible.as_str());
        assert!(
            cells <= 5,
            "pathological branch should respect cell budget, got {cells} cells: {visible:?}"
        );
        assert_eq!(offset, 0);
        // `len` is a char count; the kept chars should equal what fit.
        assert_eq!(visible.chars().count(), len);
    }

    #[test]
    fn render_scrub_inline_handles_long_rule_name_without_panic() {
        // Separately tested by the caught-label truncation patch, but
        // also verify fit_snippet's pathological branch doesn't panic
        // when fed a degenerate sample.
        let s = ScrubSample {
            rule: "custom".into(),
            snippet: "<REDACTED_CUSTOM_0>".into(),
            placeholder_offset: 0,
            placeholder_len: "<REDACTED_CUSTOM_0>".len(),
        };
        let out = render_scrub_inline(&s, &Theme::Carapace, ColorSupport::NoColor);
        assert!(out.contains("<REDACTED_CUSTOM_0>"));
    }

    #[test]
    fn render_caught_label_truncates_long_rule_names_without_overflowing_box() {
        // Rule name longer than INTERIOR_WIDTH - "caught: ".len() (= 36).
        // Without the truncate_field guard, the caught row would be
        // wider than the 46-cell box border and break the layout.
        let long_rule = "a-very-very-long-future-custom-rule-name-that-exceeds-fifty-chars";
        let s = ScrubSample {
            rule: long_rule.into(),
            snippet: "Your verification code is <REDACTED_OTP>".into(),
            placeholder_offset: 26,
            placeholder_len: 14,
        };
        let out = render_scrub_inline(&s, &Theme::Carapace, ColorSupport::NoColor);

        // Every rendered line (border, snippet, arrow, caught, border)
        // must be the same visible width. If the caught line overflowed
        // the box, the widths would differ.
        let lines: Vec<&str> = out.lines().collect();
        let expected_width = UnicodeWidthStr::width(lines[0]); // top border
        for (i, line) in lines.iter().take(5).enumerate() {
            let w = UnicodeWidthStr::width(*line);
            assert_eq!(
                w, expected_width,
                "line {i} width {w} differs from border width {expected_width} — \
                 caught label truncation failed: {line:?}"
            );
        }
        // Truncation marker should appear in the caught row.
        assert!(out.contains('\u{2026}'), "truncated caught label should contain ellipsis: {out}");
    }
}
