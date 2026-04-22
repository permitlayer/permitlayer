//! Story 6.3 AC #26: grep-assert on `deny.toml`.
//!
//! The plugin loader at `crates/permitlayer-plugins/src/loader.rs`
//! depends on `permitlayer-connectors::builtin_connectors()` — the
//! `[bans.deny-multiple-versions].wrappers` entry for
//! `permitlayer-connectors` must therefore list `permitlayer-plugins`.
//! This test reads `deny.toml` verbatim and pins the allowlist
//! against future refactors that accidentally drop the entry.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

fn deny_toml_path() -> PathBuf {
    // Walk up from `crates/permitlayer-plugins/` to the workspace
    // root. `CARGO_MANIFEST_DIR` points at the crate dir at test
    // compile time.
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = crate_dir.parent().unwrap().parent().unwrap();
    workspace_root.join("deny.toml")
}

#[test]
fn deny_toml_allows_plugins_to_wrap_connectors() {
    let contents = fs::read_to_string(deny_toml_path()).expect("read deny.toml");

    // Find the `permitlayer-connectors` wrappers block. The block
    // is identified by the literal crate name followed by `wrappers`
    // on subsequent lines up to the next `}`. Parsing TOML here
    // would be overkill for a grep assertion.
    let needle = "{ crate = \"permitlayer-connectors\"";
    let start = contents
        .find(needle)
        .expect("deny.toml must contain a wrappers entry for permitlayer-connectors");
    let end = contents[start..].find("] }").expect("wrappers entry must close with `] }`") + start;
    let block = &contents[start..=end];

    assert!(
        block.contains("\"permitlayer-plugins\""),
        "deny.toml permitlayer-connectors wrappers must include permitlayer-plugins; got: {block}"
    );
    // Also pin the original proxy entry so this test catches a
    // regression that accidentally replaces rather than appends.
    assert!(
        block.contains("\"permitlayer-proxy\""),
        "deny.toml permitlayer-connectors wrappers must continue to include permitlayer-proxy; got: {block}"
    );
}
