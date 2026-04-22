//! Terminal capability detection: color support, width, and layout selection.

use std::sync::OnceLock;

/// Detected terminal color capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorSupport {
    TrueColor,
    Ansi256,
    Ansi16,
    NoColor,
}

static COLOR_SUPPORT: OnceLock<ColorSupport> = OnceLock::new();

impl ColorSupport {
    /// Detect and cache terminal color support.
    ///
    /// Detection order (per spec):
    /// 1. `NO_COLOR` env var present (any value, including empty) → NoColor
    /// 2. `COLORTERM=truecolor` or `COLORTERM=24bit` → TrueColor
    /// 3. Check `TERM` for `256color` → Ansi256
    /// 4. Fallback → Ansi16
    pub fn detect() -> Self {
        *COLOR_SUPPORT.get_or_init(Self::detect_inner)
    }

    fn detect_inner() -> Self {
        // NO_COLOR standard: any value (including empty) disables color.
        if std::env::var_os("NO_COLOR").is_some() {
            return Self::NoColor;
        }

        if let Ok(ct) = std::env::var("COLORTERM") {
            let ct_lower = ct.to_ascii_lowercase();
            if ct_lower == "truecolor" || ct_lower == "24bit" {
                return Self::TrueColor;
            }
        }

        if let Ok(term) = std::env::var("TERM")
            && term.contains("256color")
        {
            return Self::Ansi256;
        }

        Self::Ansi16
    }
}

/// Terminal width in columns, with fallback to 80.
pub fn terminal_width() -> u16 {
    crossterm::terminal::size().map(|(cols, _rows)| cols).unwrap_or(80)
}

/// Column layout for audit tables based on terminal width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableLayout {
    /// < 80 cols: time, service, outcome
    Narrow,
    /// 80–120 cols: time, service, scope, resource, agent, outcome
    Standard,
    /// > 120 cols: all columns including policy + duration
    Wide,
}

impl TableLayout {
    /// Determine the layout from terminal width.
    pub fn from_width(width: u16) -> Self {
        if width < 80 {
            Self::Narrow
        } else if width <= 120 {
            Self::Standard
        } else {
            Self::Wide
        }
    }

    /// Current layout based on live terminal detection.
    pub fn detect() -> Self {
        Self::from_width(terminal_width())
    }
}

/// Apply color to text based on color support level.
///
/// `color` is a hex string like `"#2DD4BF"`. Returns the styled text with
/// appropriate ANSI escape codes, or plain text for NoColor.
pub fn styled(text: &str, color: &str, support: ColorSupport) -> String {
    match support {
        ColorSupport::NoColor => text.to_owned(),
        ColorSupport::TrueColor => {
            let (r, g, b) = parse_hex(color);
            format!("\x1b[38;2;{r};{g};{b}m{text}\x1b[0m")
        }
        ColorSupport::Ansi256 => {
            let (r, g, b) = parse_hex(color);
            let idx = rgb_to_ansi256(r, g, b);
            format!("\x1b[38;5;{idx}m{text}\x1b[0m")
        }
        ColorSupport::Ansi16 => {
            let (r, g, b) = parse_hex(color);
            let code = rgb_to_ansi16(r, g, b);
            format!("\x1b[{code}m{text}\x1b[0m")
        }
    }
}

/// Parse a `#RRGGBB` hex string into (R, G, B) bytes.
///
/// Returns `(0, 0, 0)` if the string is too short or contains invalid hex digits.
fn parse_hex(hex: &str) -> (u8, u8, u8) {
    let hex = hex.strip_prefix('#').unwrap_or(hex);
    if hex.len() < 6 {
        return (0, 0, 0);
    }
    let r = u8::from_str_radix(&hex[0..2], 16).unwrap_or(0);
    let g = u8::from_str_radix(&hex[2..4], 16).unwrap_or(0);
    let b = u8::from_str_radix(&hex[4..6], 16).unwrap_or(0);
    (r, g, b)
}

/// Map RGB to nearest ANSI-256 color index.
fn rgb_to_ansi256(r: u8, g: u8, b: u8) -> u8 {
    // Check if it's close to a greyscale value.
    if r == g && g == b {
        if r < 8 {
            return 16;
        }
        if r > 248 {
            return 231;
        }
        return ((r as f64 - 8.0) / 247.0 * 24.0).round() as u8 + 232;
    }

    // Map to the 6x6x6 color cube (indices 16–231).
    let ri = ((r as f64) / 255.0 * 5.0).round() as u8;
    let gi = ((g as f64) / 255.0 * 5.0).round() as u8;
    let bi = ((b as f64) / 255.0 * 5.0).round() as u8;
    16 + 36 * ri + 6 * gi + bi
}

/// Map RGB to the nearest ANSI-16 color code (30–37, 90–97).
fn rgb_to_ansi16(r: u8, g: u8, b: u8) -> u8 {
    // Simple luminance-based mapping to the 16-color palette.
    let lum = 0.299 * r as f64 + 0.587 * g as f64 + 0.114 * b as f64;
    let bright = lum > 128.0;

    // Determine dominant channel for hue bucket.
    let max = r.max(g).max(b);
    let threshold = max / 2;

    let r_on = r > threshold;
    let g_on = g > threshold;
    let b_on = b > threshold;

    let base: u8 = match (r_on, g_on, b_on) {
        (false, false, false) => 30, // black
        (true, false, false) => 31,  // red
        (false, true, false) => 32,  // green
        (true, true, false) => 33,   // yellow
        (false, false, true) => 34,  // blue
        (true, false, true) => 35,   // magenta
        (false, true, true) => 36,   // cyan
        (true, true, true) => 37,    // white
    };

    if bright { base + 60 } else { base }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_values() {
        assert_eq!(parse_hex("#2DD4BF"), (0x2D, 0xD4, 0xBF));
        assert_eq!(parse_hex("#000000"), (0, 0, 0));
        assert_eq!(parse_hex("#FFFFFF"), (255, 255, 255));
        assert_eq!(parse_hex("FF0000"), (255, 0, 0));
    }

    #[test]
    fn parse_hex_short_input_returns_zero() {
        assert_eq!(parse_hex(""), (0, 0, 0));
        assert_eq!(parse_hex("#"), (0, 0, 0));
        assert_eq!(parse_hex("#FF"), (0, 0, 0));
        assert_eq!(parse_hex("ABC"), (0, 0, 0));
    }

    #[test]
    fn table_layout_thresholds() {
        assert_eq!(TableLayout::from_width(40), TableLayout::Narrow);
        assert_eq!(TableLayout::from_width(79), TableLayout::Narrow);
        assert_eq!(TableLayout::from_width(80), TableLayout::Standard);
        assert_eq!(TableLayout::from_width(100), TableLayout::Standard);
        assert_eq!(TableLayout::from_width(120), TableLayout::Standard);
        assert_eq!(TableLayout::from_width(121), TableLayout::Wide);
        assert_eq!(TableLayout::from_width(200), TableLayout::Wide);
    }

    #[test]
    fn styled_no_color_returns_plain() {
        assert_eq!(styled("hello", "#FF0000", ColorSupport::NoColor), "hello");
    }

    #[test]
    fn styled_truecolor_wraps_ansi() {
        let result = styled("ok", "#2DD4BF", ColorSupport::TrueColor);
        assert!(result.starts_with("\x1b[38;2;45;212;191m"));
        assert!(result.ends_with("\x1b[0m"));
        assert!(result.contains("ok"));
    }

    #[test]
    fn styled_ansi256_wraps_escape() {
        let result = styled("ok", "#2DD4BF", ColorSupport::Ansi256);
        assert!(result.starts_with("\x1b[38;5;"));
        assert!(result.ends_with("\x1b[0m"));
    }

    #[test]
    fn styled_ansi16_wraps_escape() {
        let result = styled("ok", "#2DD4BF", ColorSupport::Ansi16);
        assert!(result.contains("\x1b["));
        assert!(result.ends_with("\x1b[0m"));
    }

    #[test]
    fn detect_returns_a_valid_variant() {
        // OnceLock caches the first result, so this test just verifies
        // the public API doesn't panic. The cached value depends on the
        // CI environment's env vars.
        let support = ColorSupport::detect();
        assert!(matches!(
            support,
            ColorSupport::TrueColor
                | ColorSupport::Ansi256
                | ColorSupport::Ansi16
                | ColorSupport::NoColor
        ));
    }

    #[test]
    fn ansi256_greyscale() {
        // Pure black should map to index 16.
        assert_eq!(rgb_to_ansi256(0, 0, 0), 16);
        // Pure white should map to index 231.
        assert_eq!(rgb_to_ansi256(255, 255, 255), 231);
    }
}
