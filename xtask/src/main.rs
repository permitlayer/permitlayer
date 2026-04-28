//! Custom build tasks for permitlayer.
//!
//! Run via `cargo xtask <subcommand>`.

// xtask is a developer CLI tool, not production runtime code. Panicking
// on malformed input is the standard error-reporting pattern here.
#![allow(clippy::expect_used, clippy::panic)]

use anyhow::Result;
use clap::{Parser, Subcommand};

mod bench_check;
mod check_test_registrations;
mod contrast;
mod release;
mod scrub_corpus;
mod validate_credentials;
mod validate_plugin_api;

#[derive(Parser)]
#[command(name = "xtask", about = "Custom build tasks for permitlayer")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate that credential types have no forbidden derives.
    ValidateCredentials {
        /// Path to the permitlayer-credential crate source directory.
        /// Defaults to `crates/permitlayer-credential/src` relative to the
        /// workspace root.
        #[arg(long)]
        path: Option<std::path::PathBuf>,
    },
    /// Build release artifacts using dist (local testing).
    Release,
    /// Validate WCAG 2.2 AA contrast ratios for design token color pairs.
    ContrastCheck,
    /// Run the scrub rule corpus to validate detection and false positive rates.
    ScrubCorpus,
    /// Validate that the JS plugin host API surface matches the
    /// committed host-api.lock snapshot. Run with --update to refresh
    /// the lockfile after an additive change.
    ValidatePluginApi {
        /// Rewrite host-api.lock with the current surface on an
        /// additive change. Breaking changes still fail regardless
        /// of this flag; the error message points at the
        /// `HOST_API_VERSION` major bump path.
        #[arg(long)]
        update: bool,
    },
    /// Run all workspace criterion benchmarks and compare each against
    /// the baseline in `xtask/src/bench_check/baselines.toml`. Exits 0
    /// on success; with `--enforce`, exits 1 if any bench exceeds 3×
    /// baseline headroom. See Story 8.6 AC #1–#3.
    BenchCheck {
        /// Fail if any bench's mean exceeds 3× its committed baseline.
        /// Without this flag, the command runs the benches and prints
        /// the comparison table without gating.
        #[arg(long)]
        enforce: bool,
    },
    /// Story 8.8b registration-discipline guard. Walks every refactored
    /// crate's `tests/integration/` and asserts every `.rs` file is
    /// registered in `mod.rs`. Catches the silent-exclusion footgun
    /// `autotests = false` introduces.
    CheckTestRegistrations,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ValidateCredentials { path } => validate_credentials::run(path.as_deref()),
        Command::Release => release::run(),
        Command::ContrastCheck => contrast::run(),
        Command::ScrubCorpus => scrub_corpus::run(),
        Command::ValidatePluginApi { update } => validate_plugin_api::run(update),
        Command::BenchCheck { enforce } => bench_check::run(enforce),
        Command::CheckTestRegistrations => check_test_registrations::run(),
    }
}
