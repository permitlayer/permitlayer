//! Glyph set with an ASCII fallback for non-Unicode terminals.
//!
//! `design/` has NO glyph/ASCII-fallback table — its convention is
//! "keep the Unicode glyph even in NoColor" (UX-DR7), which is about
//! *color*, not Unicode capability. The TUI overrides that for one
//! narrow reason: over a reduced `TERM` / non-UTF-8 locale (the SSH
//! headless story in the plan's manual smoke step 5), box-drawing and
//! status dots render as mojibake. So the TUI carries its own pairs and
//! a capability probe that is **orthogonal to `ColorSupport`** — a
//! TrueColor terminal under a non-UTF-8 `LANG` still wants ASCII glyphs.

/// Resolved glyph set for the session, chosen once at startup.
#[derive(Debug, Clone, Copy)]
pub struct Glyphs {
    /// Active / healthy status dot.
    pub dot_on: &'static str,
    /// Inactive status dot.
    pub dot_off: &'static str,
    /// Selected-row marker.
    pub selected: &'static str,
    /// List bullet.
    pub bullet: &'static str,
    /// Detail key/value arrow (rule `id → action`).
    pub arrow: &'static str,
}

const UNICODE: Glyphs =
    Glyphs { dot_on: "●", dot_off: "○", selected: "›", bullet: "•", arrow: "→" };

const ASCII: Glyphs = Glyphs { dot_on: "*", dot_off: "o", selected: ">", bullet: "-", arrow: "->" };

impl Glyphs {
    /// Choose the glyph set from the live locale environment.
    pub fn detect() -> Self {
        if locale_is_utf8(read_locale().as_deref()) { UNICODE } else { ASCII }
    }

    /// The ASCII fallback set — used by snapshot tests for stable,
    /// terminal-independent output. Test-only: production code chooses via
    /// [`Glyphs::detect`].
    #[cfg(test)]
    pub fn ascii() -> Self {
        ASCII
    }
}

/// Read the most specific locale variable that is set (`LC_ALL`, then
/// `LC_CTYPE`, then `LANG`).
fn read_locale() -> Option<String> {
    for var in ["LC_ALL", "LC_CTYPE", "LANG"] {
        if let Ok(v) = std::env::var(var)
            && !v.is_empty()
        {
            return Some(v);
        }
    }
    None
}

/// Whether a locale string indicates UTF-8. Conservative: if no locale
/// is set at all we assume *not* UTF-8 and fall back to ASCII (safer for
/// dumb pipes / minimal SSH environments).
fn locale_is_utf8(locale: Option<&str>) -> bool {
    match locale {
        Some(l) => {
            let l = l.to_ascii_lowercase();
            l.contains("utf-8") || l.contains("utf8")
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_locale_selects_unicode() {
        assert!(locale_is_utf8(Some("en_US.UTF-8")));
        assert!(locale_is_utf8(Some("C.utf8")));
        assert!(locale_is_utf8(Some("de_DE.UTF8")));
    }

    #[test]
    fn non_utf8_locale_selects_ascii() {
        assert!(!locale_is_utf8(Some("C")));
        assert!(!locale_is_utf8(Some("POSIX")));
        assert!(!locale_is_utf8(Some("en_US.ISO8859-1")));
    }

    #[test]
    fn unset_locale_falls_back_to_ascii() {
        assert!(!locale_is_utf8(None));
    }

    #[test]
    fn glyph_sets_are_distinct() {
        assert_ne!(UNICODE.dot_on, ASCII.dot_on);
        assert_ne!(UNICODE.arrow, ASCII.arrow);
    }
}
