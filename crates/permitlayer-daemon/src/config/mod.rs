pub mod schema;

pub use schema::{CliOverrides, DaemonConfig, HttpOverrides, LogOverrides};

use std::fmt;
use std::path::PathBuf;

/// Configuration error with structured fields for user-facing display.
///
/// This is a daemon-only error type (not in a library crate). It implements
/// `std::error::Error` + `Display` for `anyhow` compatibility at `main()`.
pub struct ConfigError {
    pub error_code: &'static str,
    pub config_path: Option<PathBuf>,
    pub config_key: Option<String>,
    pub message: String,
    pub remediation: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // UX spec §11.1 structured error format:
        //   ⚠  config_invalid
        //      ~/.agentsso/config/daemon.toml · key 'http.bind_addr' is not valid
        //      run:  agentsso start --help
        write!(f, "  \u{26a0}  {}", self.error_code)?;
        if let Some(ref path) = self.config_path {
            write!(f, "\n     {}", path.display())?;
            if let Some(ref key) = self.config_key {
                write!(f, " \u{00b7} key '{key}'")?;
            }
            write!(f, " \u{00b7} {}", self.message)?;
        } else {
            write!(f, "\n     {}", self.message)?;
        }
        write!(f, "\n     run:  {}", self.remediation)
    }
}

impl fmt::Debug for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for ConfigError {}

impl ConfigError {
    /// Convert a figment extraction error into our structured error format.
    pub fn from_figment(err: figment::Error, toml_path: &std::path::Path) -> Self {
        // Extract the key path from the figment error's metadata if available.
        let config_key = err.path.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(".");
        let config_key = if config_key.is_empty() { None } else { Some(config_key) };

        Self {
            error_code: "config_invalid",
            config_path: Some(toml_path.to_owned()),
            config_key,
            message: err.to_string(),
            remediation: "agentsso start --help".to_owned(),
        }
    }
}
