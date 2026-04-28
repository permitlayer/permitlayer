//! `cargo xtask check-test-registrations` — Story 8.8b registration-
//! discipline guard.
//!
//! Story 8.8b collapsed each refactored crate's integration tests into
//! a single `[[test]] name = "integration"` binary with `autotests =
//! false`. Under that layout, dropping a `.rs` file into
//! `tests/integration/` is NOT enough — it must ALSO be registered in
//! `tests/integration/mod.rs` via `mod <name>;`. Forgetting step 2
//! means the file compiles but its tests never run, producing zero
//! failure signal.
//!
//! This guard walks every refactored crate's `tests/integration/`
//! directory and asserts every `.rs` filename appears as a `mod`
//! declaration in `mod.rs`. Run as part of `cargo xtask` so the
//! check runs in CI and in the dev pre-commit loop.
//!
//! See `_bmad-output/implementation-artifacts/8-8b-collapse-integration-tests.md`
//! Review Findings (round 1, 2026-04-28) for the rationale.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow, bail};

/// Crates that adopted the Story 8.8b layout. Each is expected to have
/// `tests/integration/mod.rs` and one or more `tests/integration/*.rs`
/// files registered as submodules.
const REFACTORED_CRATES: &[&str] = &[
    "permitlayer-core",
    "permitlayer-daemon",
    "permitlayer-oauth",
    "permitlayer-plugins",
    "permitlayer-proxy",
];

pub fn run() -> Result<()> {
    let workspace_root = workspace_root()?;
    let mut total_errors = 0usize;

    for crate_name in REFACTORED_CRATES {
        let integration_dir =
            workspace_root.join("crates").join(crate_name).join("tests").join("integration");

        if !integration_dir.exists() {
            bail!(
                "{crate_name}: expected `{}` to exist (Story 8.8b layout), but it does not",
                integration_dir.display()
            );
        }

        let issues = check_crate(&integration_dir)
            .with_context(|| format!("{crate_name}: check_crate failed"))?;

        if issues.is_empty() {
            println!("✓ {crate_name}: all submodules registered");
        } else {
            for issue in &issues {
                eprintln!("✗ {crate_name}: {issue}");
            }
            total_errors += issues.len();
        }
    }

    if total_errors > 0 {
        bail!(
            "test-registration check failed: {total_errors} issue(s) across {} crate(s). \
             Add `mod <name>;` to the relevant `tests/integration/mod.rs` per the Story 8.8b convention.",
            REFACTORED_CRATES.len()
        );
    }

    Ok(())
}

/// For a single crate's `tests/integration/` dir, return a list of
/// human-readable issue strings. Empty Vec means the crate is clean.
fn check_crate(integration_dir: &Path) -> Result<Vec<String>> {
    let mod_rs = integration_dir.join("mod.rs");
    if !mod_rs.exists() {
        return Ok(vec![format!("missing `tests/integration/mod.rs` (Story 8.8b crate root)")]);
    }

    let mod_contents = std::fs::read_to_string(&mod_rs)
        .with_context(|| format!("failed to read {}", mod_rs.display()))?;

    // Collect declared submodules from mod.rs. Match lines that look
    // like `mod foo;` or `mod foo {` (the latter is rare but legal).
    // We deliberately do NOT use the `syn` crate — string parsing is
    // sufficient for the limited shape `mod.rs` files take, and it
    // keeps xtask's dep graph small.
    //
    // `#[path = "..."] mod foo;` declarations are SKIPPED — these
    // point at a source file outside `tests/integration/` (the daemon
    // crate's `mod common;` is the canonical example, redirecting to
    // `tests/common/mod.rs`). Including them would produce false
    // positives ("file not on disk inside `tests/integration/`").
    let lines: Vec<&str> = mod_contents.lines().collect();
    let mut declared: BTreeSet<String> = BTreeSet::new();
    for (i, raw) in lines.iter().enumerate() {
        let line = raw.trim();
        let Some(name) = parse_mod_decl(line) else { continue };
        // Look back for an immediately-preceding `#[path = "..."]`
        // attribute (skipping blank/comment lines). If present, this
        // mod declaration redirects to a file outside our walk and
        // should be ignored.
        let mut j = i;
        let path_attr_above = loop {
            if j == 0 {
                break false;
            }
            j -= 1;
            let prev = lines[j].trim();
            if prev.is_empty() || prev.starts_with("//") {
                continue;
            }
            break prev.starts_with("#[path");
        };
        if path_attr_above {
            continue;
        }
        declared.insert(name);
    }

    // Collect `.rs` files actually present in the directory (excluding
    // `mod.rs` itself and any subdirectory contents — submodule
    // discovery walks one level deep only).
    let present: BTreeSet<String> = std::fs::read_dir(integration_dir)
        .with_context(|| format!("failed to read_dir {}", integration_dir.display()))?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if !path.is_file() {
                return None;
            }
            let name = path.file_name()?.to_str()?.to_owned();
            if name == "mod.rs" {
                return None;
            }
            // Strip `.rs` to match what `mod foo;` declarations name.
            name.strip_suffix(".rs").map(str::to_owned)
        })
        .collect();

    let mut issues = Vec::new();

    // Files on disk but not declared in mod.rs → silent-exclusion footgun.
    for missing_decl in present.difference(&declared) {
        issues.push(format!(
            "file `{missing_decl}.rs` exists on disk but is NOT registered in `mod.rs` — \
             tests in that file will SILENTLY NOT RUN. Add `mod {missing_decl};` to mod.rs."
        ));
    }

    // Declared in mod.rs but no file on disk → build failure (caught by
    // cargo) but worth surfacing here too with a clearer message.
    for missing_file in declared.difference(&present) {
        issues.push(format!(
            "mod.rs declares `mod {missing_file};` but no `{missing_file}.rs` (or \
             `{missing_file}/mod.rs`) exists on disk."
        ));
    }

    Ok(issues)
}

/// Parse a single line of source; if it's a `mod foo;` declaration,
/// return `Some("foo")`. Returns `None` for anything else (comments,
/// `use` statements, etc.).
///
/// We accept both `mod foo;` and `mod foo {` (rare but legal);
/// `pub mod foo` would also match but it's never used in `mod.rs`
/// crate roots in this workspace — surface it anyway as a registered
/// submodule so we don't spuriously flag it as missing.
fn parse_mod_decl(line: &str) -> Option<String> {
    let stripped =
        line.strip_prefix("pub ").or_else(|| line.strip_prefix("pub(crate) ")).unwrap_or(line);
    let after_mod = stripped.strip_prefix("mod ")?;
    // Take chars up to the first `;`, `{`, or whitespace.
    let name: String = after_mod.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
    if name.is_empty() {
        return None;
    }
    Some(name)
}

/// Locate the workspace root by walking up from xtask's manifest dir
/// until a `Cargo.toml` containing `[workspace]` is found.
fn workspace_root() -> Result<PathBuf> {
    let mut cur = Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    loop {
        let cargo_toml = cur.join("Cargo.toml");
        if cargo_toml.exists() {
            let contents = std::fs::read_to_string(&cargo_toml)
                .with_context(|| format!("read {}", cargo_toml.display()))?;
            if contents.contains("[workspace]") {
                return Ok(cur);
            }
        }
        if !cur.pop() {
            return Err(anyhow!(
                "could not locate workspace root (no [workspace] Cargo.toml found above {})",
                env!("CARGO_MANIFEST_DIR")
            ));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_mod_decl() {
        assert_eq!(parse_mod_decl("mod foo;"), Some("foo".to_owned()));
        assert_eq!(parse_mod_decl("mod foo_bar;"), Some("foo_bar".to_owned()));
        assert_eq!(parse_mod_decl("mod foo {"), Some("foo".to_owned()));
    }

    #[test]
    fn parses_visibility_prefixed_mod_decl() {
        assert_eq!(parse_mod_decl("pub mod foo;"), Some("foo".to_owned()));
        assert_eq!(parse_mod_decl("pub(crate) mod foo;"), Some("foo".to_owned()));
    }

    #[test]
    fn rejects_non_mod_lines() {
        assert_eq!(parse_mod_decl("// mod commented_out;"), None);
        assert_eq!(parse_mod_decl("use crate::common;"), None);
        assert_eq!(parse_mod_decl("fn foo() {}"), None);
        assert_eq!(parse_mod_decl(""), None);
        assert_eq!(parse_mod_decl("mod ;"), None); // empty name
    }

    #[test]
    fn workspace_root_resolves() {
        let root = workspace_root().unwrap();
        assert!(root.join("Cargo.toml").exists());
        assert!(root.join("crates").exists());
    }

    /// Smoke test: the live workspace must pass the registration check
    /// (otherwise this xtask itself would have shipped broken).
    #[test]
    fn live_workspace_passes_registration_check() {
        run().expect("workspace registration check should pass");
    }
}
