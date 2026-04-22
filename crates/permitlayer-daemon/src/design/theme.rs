//! Theme selection, persistence, and token lookup.

use std::path::Path;
use std::str::FromStr;

use crate::design::tokens::{self, ThemeTokens};

/// The three shipped themes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Theme {
    /// Dark teal — default.
    #[default]
    Carapace,
    /// Warm-parchment light.
    Molt,
    /// Catppuccin-adjacent dark.
    Tidepool,
}

impl Theme {
    /// Return the generated token struct for this theme.
    pub fn tokens(self) -> &'static ThemeTokens {
        match self {
            Self::Carapace => &tokens::CARAPACE,
            Self::Molt => &tokens::MOLT,
            Self::Tidepool => &tokens::TIDEPOOL,
        }
    }

    /// Canonical lowercase name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Carapace => "carapace",
            Self::Molt => "molt",
            Self::Tidepool => "tidepool",
        }
    }

    /// Load the persisted theme from `<home>/config/ui.toml`.
    /// Falls back to [`Theme::Carapace`] if the file is missing or invalid.
    pub fn load(home: &Path) -> Self {
        let path = home.join("config").join("ui.toml");
        let Ok(contents) = std::fs::read_to_string(&path) else {
            return Self::default();
        };
        let Ok(table) = contents.parse::<toml::Table>() else {
            return Self::default();
        };
        table
            .get("theme")
            .and_then(|v| v.as_str())
            .and_then(|s| Self::from_str(s).ok())
            .unwrap_or_default()
    }

    /// Persist the theme to `<home>/config/ui.toml`.
    pub fn save(home: &Path, theme: Theme) -> std::io::Result<()> {
        let dir = home.join("config");
        std::fs::create_dir_all(&dir)?;
        let content = format!("theme = \"{}\"\n", theme.name());
        std::fs::write(dir.join("ui.toml"), content)
    }
}

impl FromStr for Theme {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "carapace" => Ok(Self::Carapace),
            "molt" => Ok(Self::Molt),
            "tidepool" => Ok(Self::Tidepool),
            _ => Err(format!("unknown theme: {s}")),
        }
    }
}

impl std::fmt::Display for Theme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn default_is_carapace() {
        assert_eq!(Theme::default(), Theme::Carapace);
    }

    #[test]
    fn from_str_case_insensitive() {
        assert_eq!(Theme::from_str("Molt").ok(), Some(Theme::Molt));
        assert_eq!(Theme::from_str("TIDEPOOL").ok(), Some(Theme::Tidepool));
        assert_eq!(Theme::from_str("CARAPACE").ok(), Some(Theme::Carapace));
        assert!(Theme::from_str("invalid").is_err());
    }

    #[test]
    fn tokens_return_correct_accent() {
        assert_eq!(Theme::Carapace.tokens().accent, "#2DD4BF");
        assert_eq!(Theme::Molt.tokens().accent, "#0D9488");
        assert_eq!(Theme::Tidepool.tokens().accent, "#94E2D5");
    }

    #[test]
    fn load_fallback_on_missing_file() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        assert_eq!(Theme::load(tmp.path()), Theme::Carapace);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        Theme::save(tmp.path(), Theme::Molt).expect("save");
        assert_eq!(Theme::load(tmp.path()), Theme::Molt);
    }

    #[test]
    fn load_fallback_on_invalid_toml() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let config_dir = tmp.path().join("config");
        std::fs::create_dir_all(&config_dir).expect("mkdir");
        std::fs::write(config_dir.join("ui.toml"), "not valid {{{").expect("write");
        assert_eq!(Theme::load(tmp.path()), Theme::Carapace);
    }

    #[test]
    fn load_fallback_on_invalid_theme_value() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let config_dir = tmp.path().join("config");
        std::fs::create_dir_all(&config_dir).expect("mkdir");
        std::fs::write(config_dir.join("ui.toml"), "theme = \"notatheme\"\n").expect("write");
        assert_eq!(Theme::load(tmp.path()), Theme::Carapace);
    }
}
