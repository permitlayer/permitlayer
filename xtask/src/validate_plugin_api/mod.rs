//! `cargo xtask validate-plugin-api` — Story 6.5's host-API
//! semver gate.
//!
//! Reads the live `permitlayer-plugins::host_api` surface via `syn`,
//! diffs it against the committed `host-api.lock` at the workspace
//! root, and enforces the NFR41 contract: breaking changes require
//! a major-version bump of `HOST_API_VERSION`, additive changes
//! get a note + `--update` path, and no change at all passes clean.
//!
//! The rc qualifier on `HOST_API_VERSION` (1.0.0-rc.1) puts the
//! gate in "update-freely" mode — any change is permitted, the
//! xtask just emits the diff + refreshes the lockfile on `--update`.
//! The rc → 1.0 flip is what turns the gate binding.

pub mod lockfile;
pub mod surface;

use anyhow::{Result, bail};

use self::lockfile::{diff, emit, lockfile_path, parse};
use self::surface::{SurfaceDescription, default_host_api_dir, extract};

/// Entry point called from `xtask/src/main.rs`.
///
/// Returns:
/// - `Ok(())` — surface matches committed lock (or additive with
///   note, or rc-stage update, or major bump detected).
/// - `Err(...)` — breaking change without a major bump. The error
///   is designed to render as the standard anyhow CLI output.
pub fn run(update: bool) -> Result<()> {
    let host_api_dir = default_host_api_dir();
    let live = extract(&host_api_dir)?;

    let lock_path = lockfile_path();
    let rc_mode = is_rc_qualifier(&live.version);

    if rc_mode {
        println!(
            "rc-stage surface (pre-release); breaking changes are permitted until the rc qualifier is dropped."
        );
    }

    // No committed lockfile yet — this is the first-ever run. Emit
    // and either write (on --update) or report what the user needs
    // to do.
    if !lock_path.exists() {
        println!("host-api.lock does not exist at {}", lock_path.display());
        if update {
            write_lockfile(&live)?;
            println!(
                "host-api.lock created at {}. Include it in your PR. Consider adding a CHANGELOG entry under the Added section.",
                lock_path.display()
            );
            return Ok(());
        }
        println!(
            "Run `cargo xtask validate-plugin-api --update` to create it, then commit the file."
        );
        return Ok(());
    }

    let committed_content = std::fs::read_to_string(&lock_path)?;
    let committed = parse(&committed_content)?;
    let d = diff(&committed, &live);

    // No change at all.
    if d.is_empty() {
        println!("host-api.lock is up to date.");
        return Ok(());
    }

    // Detect major-version bump unlocking breaking changes.
    if let Some((old, new)) = &d.version_change
        && major_increased(old, new)
    {
        println!(
            "Major version bump detected ({old} → {new}). Writing full new surface to host-api.lock."
        );
        if update {
            write_lockfile(&live)?;
            println!(
                "host-api.lock updated. Include it in your PR. Consider adding a CHANGELOG entry under the Removed or Changed section, with a Deprecated note for the previous behavior if applicable."
            );
            return Ok(());
        }
        // Without `--update`, the committed lockfile stays stale.
        // Exit non-zero so CI blocks the merge until the author
        // commits the refreshed lock — otherwise a stale lock would
        // pass every subsequent CI run silently, defeating the gate.
        let rendered = d.render();
        bail!(
            "Major version bump detected ({old} → {new}) but host-api.lock is stale.\n\nDiff:\n{rendered}\nre-run with --update to refresh host-api.lock, then commit the file."
        );
    }

    if d.is_purely_additive() || rc_mode {
        if rc_mode {
            println!("Additive or breaking change detected (rc-stage; unconstrained).");
        } else {
            println!("Additive change detected (non-breaking).");
        }
        println!("Diff:\n{}", d.render());
        if update {
            write_lockfile(&live)?;
            println!(
                "host-api.lock updated. Include it in your PR. Consider adding a CHANGELOG entry under the Added section."
            );
            return Ok(());
        }
        println!("run 'cargo xtask validate-plugin-api --update' to refresh host-api.lock.");
        return Ok(());
    }

    // If we got here, the diff has removals/signature changes AND
    // there was no major bump AND we're not in rc-mode. That's a
    // breaking change the gate rejects.
    let rendered = d.render();
    let msg = format!(
        "BREAKING CHANGE: removed or changed host-API surface without a major-version bump of HOST_API_VERSION.\n\nDiff:\n{rendered}\nTo proceed: bump HOST_API_VERSION to the next major version AND add a Removed entry to CHANGELOG.md."
    );
    // --update does NOT override breaking changes.
    if update {
        bail!("{msg}\n\n--update does not override breaking changes; bump HOST_API_VERSION first.");
    }
    bail!(msg);
}

fn is_rc_qualifier(version: &str) -> bool {
    match semver::Version::parse(version) {
        Ok(v) => !v.pre.is_empty(),
        Err(_) => false,
    }
}

fn major_increased(old: &str, new: &str) -> bool {
    let parse_major = |s: &str| semver::Version::parse(s).ok().map(|v| v.major);
    match (parse_major(old), parse_major(new)) {
        (Some(a), Some(b)) => b > a,
        _ => false,
    }
}

fn write_lockfile(desc: &SurfaceDescription) -> Result<()> {
    let path = lockfile_path();
    let content = emit(desc);
    // Atomic write: stage to `<path>.tmp` then rename. Guarantees that
    // a SIGINT / power loss between truncate and write never leaves
    // `host-api.lock` as a 0-byte file (which would fail the next
    // parse with a confusing "missing ## version" error).
    let tmp = path.with_extension("lock.tmp");
    std::fs::write(&tmp, content.as_bytes())?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

// Cross-link so test modules can reach internals.
#[cfg(test)]
mod tests;
