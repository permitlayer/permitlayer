//! `agentsso config set|get|list` — manage user-facing CLI configuration.
//!
//! Configuration is stored in `~/.agentsso/config/ui.toml`, separate from the
//! daemon's runtime config (`daemon.toml`). The daemon does NOT need to be
//! running for config commands.

use clap::{Args, Subcommand};

use crate::design::theme::Theme;

/// Arguments for `agentsso config <subcommand>`.
#[derive(Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

/// Available config subcommands.
#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Set a configuration value (e.g., `agentsso config set theme=molt`).
    Set {
        /// Key=value pair to set.
        assignment: String,
    },
    /// Get a configuration value (e.g., `agentsso config get theme`).
    Get {
        /// The configuration key to read.
        key: String,
    },
    /// List all user-configurable settings.
    List,
}

/// Run the `config` subcommand.
pub fn run(args: ConfigArgs) -> anyhow::Result<()> {
    let home = super::agentsso_home()?;

    match args.command {
        ConfigCommand::Set { assignment } => {
            let (key, value) = parse_assignment(&assignment)?;
            match key {
                "theme" => {
                    let theme: Theme = value.parse().map_err(|e: String| {
                        anyhow::anyhow!("{e}. valid themes: carapace, molt, tidepool")
                    })?;
                    Theme::save(&home, theme)?;
                    println!("  theme set to {value}");
                }
                _ => {
                    anyhow::bail!(
                        "unknown config key: {key}. run `agentsso config list` to see available keys"
                    );
                }
            }
        }
        ConfigCommand::Get { key } => match key.as_str() {
            "theme" => {
                let theme = Theme::load(&home);
                println!("{theme}");
            }
            _ => {
                anyhow::bail!(
                    "unknown config key: {key}. run `agentsso config list` to see available keys"
                );
            }
        },
        ConfigCommand::List => {
            let theme = Theme::load(&home);
            println!("  theme = {theme}  (carapace | molt | tidepool)");
        }
    }

    Ok(())
}

/// Parse a `key=value` assignment string.
fn parse_assignment(s: &str) -> anyhow::Result<(&str, &str)> {
    let (key, value) =
        s.split_once('=').ok_or_else(|| anyhow::anyhow!("expected key=value format, got: {s}"))?;
    let key = key.trim();
    let value = value.trim();
    if key.is_empty() || value.is_empty() {
        anyhow::bail!("expected key=value format, got: {s}");
    }
    Ok((key, value))
}
