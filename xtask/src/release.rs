//! `cargo xtask release` — wrapper around `dist build` for local release testing.

use anyhow::{Context, Result, bail};
use std::process::Command;

pub fn run() -> Result<()> {
    // Validate that dist is installed
    let version_output = Command::new("dist").arg("--version").output().context(
        "failed to run `dist --version`. Install it with: cargo install cargo-dist@0.31",
    )?;

    if !version_output.status.success() {
        bail!("dist --version failed. Install cargo-dist with: cargo install cargo-dist@0.31");
    }

    let version_str = String::from_utf8_lossy(&version_output.stdout);
    println!("Using {}", version_str.trim());

    // Run dist build for all artifacts
    println!("Running dist build...");
    let status = Command::new("dist")
        .args(["build", "--artifacts=all"])
        .status()
        .context("failed to run `dist build`")?;

    if !status.success() {
        bail!("dist build failed with exit code: {}", status);
    }

    println!("Release artifacts built successfully.");
    println!("Check target/distrib/ for the built artifacts.");

    Ok(())
}
