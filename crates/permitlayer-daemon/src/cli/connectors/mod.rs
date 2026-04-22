//! `agentsso connectors` subcommand family.
//!
//! Three offline-capable subcommands:
//!
//! - [`list`] — enumerate the daemon's plugin registry via the
//!   loopback control plane. **Requires a running daemon.**
//! - [`new`] — scaffold a new connector into `~/.agentsso/plugins/`.
//!   **Offline; no daemon required.**
//! - [`test_cmd`] — validate a connector standalone (metadata,
//!   sandbox, scopes, tool invocation). **Offline; no daemon
//!   required.**
//!
//! The module layout mirrors the other multi-subcommand CLI
//! families in the daemon (`audit`, `agent`): a thin
//! [`ConnectorsArgs`] wrapper + [`ConnectorCommand`] enum with one
//! variant per subcommand, all dispatched by [`run`].

use anyhow::Result;
use clap::{Args, Subcommand};

pub mod list;
pub mod new;
pub mod test_cmd;

/// Top-level `connectors` subcommand wrapper.
#[derive(Args)]
pub struct ConnectorsArgs {
    #[command(subcommand)]
    pub command: ConnectorCommand,
}

#[derive(Subcommand)]
pub enum ConnectorCommand {
    /// List every registered connector plugin (built-in +
    /// user-installed) with version, trust tier, scopes, and
    /// short source hash.
    List(list::ListArgs),
    /// Scaffold a new connector into `~/.agentsso/plugins/<name>/`
    /// with a ready-to-edit template `index.js` + `metadata.toml` +
    /// `README.md`. Offline; no daemon required.
    #[command(long_about = "Scaffold a new connector plugin into ~/.agentsso/plugins/<name>/.\n\n\
The generated template includes a minimal `hello` tool that demonstrates\n\
the `agentsso.*` host API (oauth, policy, http, scrub). Run\n\
`agentsso connectors test <name>` to validate before restarting the daemon.\n\n\
Examples:\n  \
agentsso connectors new my-notion\n  \
agentsso connectors new my-notion --scopes notion.readonly,notion.search\n  \
agentsso connectors new existing --force")]
    New(new::NewArgs),
    /// Validate a connector plugin offline: metadata shape, sandbox
    /// conformance, scope review, tool-invocation smoke test.
    /// Offline; no daemon required.
    #[command(
        name = "test",
        long_about = "Validate a connector plugin offline.\n\n\
Checks run in order: source read → metadata validation → sandbox conformance\n\
→ scope allowlist → tool invocation (against stub host services). Exit 0 on\n\
pass or pass-with-warnings, exit 1 on any blocking failure.\n\n\
Examples:\n  \
agentsso connectors test my-notion                  # resolves to ~/.agentsso/plugins/my-notion/\n  \
agentsso connectors test ./my-wip-plugin/           # relative path\n  \
agentsso connectors test /tmp/experimental-plugin/  # absolute path\n  \
agentsso connectors test my-notion --json           # machine-readable JSON"
    )]
    Test(test_cmd::TestArgs),
}

pub async fn run(args: ConnectorsArgs) -> Result<()> {
    match args.command {
        ConnectorCommand::List(a) => list::list_connectors(a).await,
        ConnectorCommand::New(a) => new::run(a).await,
        ConnectorCommand::Test(a) => test_cmd::run(a).await,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use clap::CommandFactory;

    /// Harness that gives clap a binary name so `Command::command`
    /// produces a fully-named structure.
    #[derive(clap::Parser)]
    #[command(name = "agentsso", no_binary_name = true)]
    struct Cli {
        #[command(subcommand)]
        _cmd: super::ConnectorCommand,
    }

    #[test]
    fn new_subcommand_help_contains_examples_block() {
        // AC #25: `agentsso connectors new --help` includes an
        // `Examples:` block.
        let cmd = Cli::command();
        let new_sub = cmd
            .get_subcommands()
            .find(|s| s.get_name() == "new")
            .expect("new subcommand must exist");
        let help = new_sub.clone().render_long_help().to_string();
        assert!(help.contains("Examples:"), "new --help should contain Examples:\n{help}");
        assert!(help.contains("agentsso connectors new"));
    }

    #[test]
    fn test_subcommand_help_contains_examples_block() {
        // AC #25: `agentsso connectors test --help` includes an
        // `Examples:` block with both bare-name + path forms.
        let cmd = Cli::command();
        let test_sub = cmd
            .get_subcommands()
            .find(|s| s.get_name() == "test")
            .expect("test subcommand must exist");
        let help = test_sub.clone().render_long_help().to_string();
        assert!(help.contains("Examples:"), "test --help should contain Examples:\n{help}");
        assert!(help.contains("agentsso connectors test my-notion"));
        // Path-style example — use the `./` form which is
        // unambiguous in the help text.
        assert!(help.contains("./"), "help should show a relative-path example:\n{help}");
    }

    #[test]
    fn connectors_command_has_three_variants() {
        // AC #1: clap registers three subcommands (`list`, `new`,
        // `test`) on ConnectorCommand. Tests via
        // CommandFactory::command() — a regression that dropped one
        // variant would fail here.
        let cmd = Cli::command();
        let sub_names: Vec<&str> = cmd.get_subcommands().map(clap::Command::get_name).collect();
        assert!(sub_names.contains(&"list"), "subcommands: {sub_names:?}");
        assert!(sub_names.contains(&"new"), "subcommands: {sub_names:?}");
        assert!(sub_names.contains(&"test"), "subcommands: {sub_names:?}");
        assert_eq!(sub_names.len(), 3, "expected exactly 3 subcommands, got: {sub_names:?}");
    }
}
