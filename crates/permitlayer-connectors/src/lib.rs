//! Built-in JS connectors (Gmail, Calendar, Drive) embedded as
//! compile-time assets.
//!
//! Epic 6 embeds three built-in connectors under `src/js/<name>/
//! index.js`; each file is pulled into the daemon binary via
//! [`include_str!`] so the JS source cannot be tampered with
//! post-distribution (epics.md:1723-1726).
//!
//! Story 6.3 ships the embedding mechanism + placeholder JS files
//! (metadata-only — the JS port of the tools implementations lands
//! in a future story). The proxy's hand-rolled Rust MCP services
//! at `crates/permitlayer-proxy/src/transport/mcp/{gmail,calendar,
//! drive}.rs` remain the production dispatch path for these
//! services until the JS port story lands.
//!
//! The loader in `permitlayer-plugins` consumes
//! [`builtin_connectors`] during daemon boot; it is the canonical
//! (and currently only) consumer of this surface. Adding a new
//! built-in connector requires adding a new `src/js/<name>/
//! index.js` file AND a new entry to the [`BUILTIN_CONNECTORS`]
//! array below — the loader picks it up automatically on the next
//! build.
//!
//! **Writing a third-party connector?** Use `agentsso connectors
//! new <name>` (Story 6.4) — it scaffolds a ready-to-edit template
//! under `~/.agentsso/plugins/<name>/` with the same `metadata`
//! shape used here. Validate with `agentsso connectors test <name>`
//! before restarting the daemon.

#![forbid(unsafe_code)]

pub mod error;

pub use error::ConnectorError;

/// A built-in connector — one of Gmail/Calendar/Drive — shipped
/// as an embedded JS asset in the daemon binary.
///
/// `name` matches the connector's `metadata.name` export. The
/// loader's metadata validator will reject a built-in whose
/// `metadata.name` does not match this field (defense against a
/// ship-time typo). `source` is the UTF-8 text of the connector's
/// `index.js` — `include_str!` produces a `&'static str` at
/// compile time.
#[derive(Debug, Clone, Copy)]
pub struct BuiltinConnector {
    /// Canonical connector name. Lowercase alphanumeric + `-`.
    pub name: &'static str,

    /// Raw JS source (UTF-8 text). `&'static str` rather than
    /// `&'static [u8]` because the loader's rquickjs entry point
    /// accepts `&str` natively and the architecture's
    /// `include_bytes!` suggestion at architecture.md:1172 is
    /// directional — `include_str!` is the same compile-time
    /// embed with a nicer text-oriented type.
    pub source: &'static str,
}

/// Every built-in connector shipped with this binary.
///
/// The loader in `permitlayer-plugins` iterates this slice during
/// boot; ordering is not load-bearing (the plugin registry is a
/// `BTreeMap` keyed by name, so iteration order at the
/// control-plane surface is always alphabetical).
pub const BUILTIN_CONNECTORS: &[BuiltinConnector] = &[
    BuiltinConnector { name: "google-gmail", source: include_str!("js/google-gmail/index.js") },
    BuiltinConnector {
        name: "google-calendar",
        source: include_str!("js/google-calendar/index.js"),
    },
    BuiltinConnector { name: "google-drive", source: include_str!("js/google-drive/index.js") },
];

/// Enumerate every built-in connector shipped with this binary.
///
/// The return value is a `&'static` slice — zero-allocation, safe
/// to iterate from any thread. The loader in `permitlayer-plugins`
/// is the canonical consumer.
#[must_use]
pub fn builtin_connectors() -> &'static [BuiltinConnector] {
    BUILTIN_CONNECTORS
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn builtin_connectors_has_three_entries() {
        let all = builtin_connectors();
        assert_eq!(all.len(), 3, "Story 6.3 ships exactly three built-ins");
        let names: Vec<&str> = all.iter().map(|c| c.name).collect();
        assert!(names.contains(&"google-gmail"));
        assert!(names.contains(&"google-calendar"));
        assert!(names.contains(&"google-drive"));
    }

    #[test]
    fn every_builtin_source_starts_with_export_const_metadata() {
        // AC #3: placeholder shape invariant. The loader expects
        // the metadata export; a future contributor who rewrites
        // a placeholder in CommonJS (`module.exports = ...`)
        // would regress FR41 ("metadata/auth/tools interface").
        for c in builtin_connectors() {
            assert!(
                c.source.contains("export const metadata = {"),
                "{}: source must contain `export const metadata = {{`; got first 200 bytes: {:?}",
                c.name,
                &c.source[..c.source.len().min(200)]
            );
        }
    }

    #[test]
    fn builtin_connector_is_32_bytes_on_64_bit() {
        // Two `&'static str` pointers (ptr + len), each 16 bytes
        // on 64-bit platforms. This test pins the size so a
        // future refactor that accidentally adds a heavy field
        // to `BuiltinConnector` (hashmap, Vec, etc.) fails fast
        // — the const slice discipline is load-bearing.
        #[cfg(target_pointer_width = "64")]
        assert_eq!(std::mem::size_of::<BuiltinConnector>(), 32);
    }

    #[test]
    fn builtin_connector_names_match_metadata_names() {
        // The loader validates `metadata.name` matches the
        // `BuiltinConnector.name` field. Pre-empt that check
        // here so a ship-time typo in the JS file surfaces at
        // `cargo test` time instead of at daemon boot.
        for c in builtin_connectors() {
            let expected_line = format!("name: \"{}\"", c.name);
            assert!(
                c.source.contains(&expected_line),
                "{}: source must declare `{expected_line}`; got first 400 bytes: {:?}",
                c.name,
                &c.source[..c.source.len().min(400)]
            );
        }
    }

    #[test]
    fn builtin_connector_names_are_unique() {
        // Ship-time regression guard per review decision 6: a
        // duplicate entry in BUILTIN_CONNECTORS would silently
        // cause one built-in to overwrite another at registry
        // construction. Catch it at `cargo test` time rather
        // than at daemon boot.
        use std::collections::BTreeSet;
        let mut seen = BTreeSet::new();
        for c in builtin_connectors() {
            assert!(
                seen.insert(c.name),
                "duplicate built-in connector name `{}` in BUILTIN_CONNECTORS",
                c.name
            );
        }
    }
}
