//! Maps the design system's hex color tokens into `ratatui` `Color`s,
//! honoring the detected [`ColorSupport`] downgrade.
//!
//! [`crate::design::tokens::ThemeTokens`] fields are hex `&'static str`
//! literals (e.g. `"#2DD4BF"`) and `design::terminal::styled()` consumes
//! them to emit ANSI *escape sequences* — useless to ratatui, which needs
//! a `Color` value. So this file is the one place that turns a token hex
//! into a `Color`, reusing the design module's `parse_hex` /
//! `rgb_to_ansi256` rather than re-implementing them.
//!
//! `Color` is quarantined here: no other `cli/ui` file imports
//! `ratatui::style::Color` directly.

use ratatui::style::{Color, Modifier, Style};

use crate::design::terminal::{ColorSupport, parse_hex, rgb_channel_bits, rgb_to_ansi256};

/// Convert a `#RRGGBB` token into a ratatui [`Color`] for the given
/// support level. `NoColor` collapses to [`Color::Reset`] (the terminal
/// default) — views differentiate by glyph + layout, not color, when
/// color is unavailable.
pub fn color(hex: &str, support: ColorSupport) -> Color {
    match support {
        ColorSupport::NoColor => Color::Reset,
        ColorSupport::TrueColor => {
            let (r, g, b) = parse_hex(hex);
            Color::Rgb(r, g, b)
        }
        ColorSupport::Ansi256 => {
            let (r, g, b) = parse_hex(hex);
            Color::Indexed(rgb_to_ansi256(r, g, b))
        }
        ColorSupport::Ansi16 => {
            let (r, g, b) = parse_hex(hex);
            rgb_to_named16(r, g, b)
        }
    }
}

/// A foreground [`Style`] for the token. Convenience over [`color`].
pub fn fg(hex: &str, support: ColorSupport) -> Style {
    Style::default().fg(color(hex, support))
}

/// A dim/muted foreground style — used for secondary list text. Falls
/// back to the `DIM` modifier under `NoColor` so the visual hierarchy
/// survives a colorless terminal.
pub fn dim(hex: &str, support: ColorSupport) -> Style {
    match support {
        ColorSupport::NoColor => Style::default().add_modifier(Modifier::DIM),
        _ => Style::default().fg(color(hex, support)),
    }
}

/// Map RGB to a ratatui named 16-color. ratatui owns the actual ANSI
/// emission for its `Color` enum, so (unlike `design::rgb_to_ansi16`,
/// which returns raw escape numbers) we pick the nearest *named* color —
/// but the channel/brightness classification is shared via
/// [`rgb_channel_bits`], not duplicated.
fn rgb_to_named16(r: u8, g: u8, b: u8) -> Color {
    let (r_on, g_on, b_on, bright) = rgb_channel_bits(r, g, b);

    match (r_on, g_on, b_on, bright) {
        (false, false, false, false) => Color::Black,
        (false, false, false, true) => Color::DarkGray,
        (true, false, false, false) => Color::Red,
        (true, false, false, true) => Color::LightRed,
        (false, true, false, false) => Color::Green,
        (false, true, false, true) => Color::LightGreen,
        (true, true, false, false) => Color::Yellow,
        (true, true, false, true) => Color::LightYellow,
        (false, false, true, false) => Color::Blue,
        (false, false, true, true) => Color::LightBlue,
        (true, false, true, false) => Color::Magenta,
        (true, false, true, true) => Color::LightMagenta,
        (false, true, true, false) => Color::Cyan,
        (false, true, true, true) => Color::LightCyan,
        (true, true, true, false) => Color::Gray,
        (true, true, true, true) => Color::White,
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn no_color_is_reset() {
        assert_eq!(color("#2DD4BF", ColorSupport::NoColor), Color::Reset);
    }

    #[test]
    fn truecolor_is_rgb() {
        assert_eq!(color("#2DD4BF", ColorSupport::TrueColor), Color::Rgb(0x2D, 0xD4, 0xBF));
    }

    #[test]
    fn ansi256_is_indexed() {
        match color("#2DD4BF", ColorSupport::Ansi256) {
            Color::Indexed(_) => {}
            other => panic!("expected Indexed, got {other:?}"),
        }
    }

    #[test]
    fn ansi16_maps_teal_to_a_cyanish_named_color() {
        // #2DD4BF is a teal/cyan — green+blue dominant.
        let c = color("#2DD4BF", ColorSupport::Ansi16);
        assert!(matches!(c, Color::Cyan | Color::LightCyan));
    }

    #[test]
    fn dim_under_no_color_uses_modifier() {
        let s = dim("#6B7280", ColorSupport::NoColor);
        assert!(s.add_modifier.contains(Modifier::DIM));
    }
}
