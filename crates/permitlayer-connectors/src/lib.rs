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
//!
//! ## Connector-definition model ([`def`])
//!
//! Epic 11 introduces a declarative [`ConnectorDef`] (`connector.toml`)
//! that collapses a connector's identity, auth, upstream, scope vocab,
//! access tiers, and tool catalog into one artifact. Story 11.1 ships
//! the typed model + serde deserialization only; the registry +
//! load-time validator (11.3) and the built-in defs (11.2) follow, with
//! the proxy reading from it in Phase 2. The JS-embed surface below is
//! orthogonal and unchanged.

#![forbid(unsafe_code)]

pub mod def;
pub mod error;
pub mod registry;
pub mod validate;

pub use def::{
    AuthSpec, ConnectorDef, ConnectorMeta, TierBundle, ToolDef, TrustTier, UpstreamSpec,
};
pub use error::ConnectorError;
pub use registry::{ConnectorRegistry, ResolvedConnector};
pub use validate::{ValidationError, validate_def};

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

/// The embedded `connector.toml` source for each built-in connector
/// (Story 11.2). Paired `(id, toml_source)`; the id must equal the
/// `[connector].id` inside the TOML (asserted by test + the 11.3
/// validator). These are the **declarative spine** of the hybrid
/// dispatch model: identity, auth, upstream + `allowed_hosts`, scope
/// vocab, tier bundles, and tool *metadata*. Per-tool handler logic
/// (response shaping, attachments, validation, query building) lives
/// in Rust keyed by tool name and is wired in Story 11.4 — it is
/// deliberately NOT expressed here.
const BUILTIN_CONNECTOR_DEFS_SRC: &[(&str, &str)] = &[
    ("google-gmail", include_str!("defs/google-gmail.toml")),
    ("google-calendar", include_str!("defs/google-calendar.toml")),
    ("google-drive", include_str!("defs/google-drive.toml")),
];

/// Parse and return the embedded built-in [`ConnectorDef`]s.
///
/// Distinct from [`builtin_connectors`] (the JS-embed surface): this
/// is the connector-*definition* surface that Epic 11 Phase 2 reads
/// for routing/scope/tier/tool metadata.
///
/// # Errors
///
/// Returns [`ConnectorError::Parse`] if any embedded def fails to
/// deserialize. A shipped built-in failing to parse is a ship-time
/// bug, not a runtime condition — the test suite exercises this so a
/// malformed embedded TOML fails `cargo nextest`, not daemon boot.
pub fn builtin_connector_defs() -> Result<Vec<ConnectorDef>, ConnectorError> {
    BUILTIN_CONNECTOR_DEFS_SRC.iter().map(|(_, src)| ConnectorDef::from_toml_str(src)).collect()
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

    // ---- Story 11.2: built-in connector *defs* (declarative spine) ----

    fn defs() -> Vec<ConnectorDef> {
        builtin_connector_defs().expect("all three embedded built-in defs must parse")
    }

    fn def_by_id(id: &str) -> ConnectorDef {
        defs().into_iter().find(|d| d.connector.id == id).unwrap_or_else(|| panic!("no def {id}"))
    }

    #[test]
    fn all_three_builtin_defs_parse() {
        // AC #1.
        let all = defs();
        assert_eq!(all.len(), 3);
        let ids: Vec<&str> = all.iter().map(|d| d.connector.id.as_str()).collect();
        assert!(ids.contains(&"google-gmail"));
        assert!(ids.contains(&"google-calendar"));
        assert!(ids.contains(&"google-drive"));
    }

    #[test]
    fn def_ids_match_embed_table_and_are_unique() {
        // AC #6: the (id, src) pairing's id == the parsed [connector].id,
        // and ids are unique.
        use std::collections::BTreeSet;
        let mut seen = BTreeSet::new();
        for (declared_id, src) in BUILTIN_CONNECTOR_DEFS_SRC {
            let def = ConnectorDef::from_toml_str(src).expect("embedded def parses");
            assert_eq!(&def.connector.id, declared_id, "embed-table id must equal [connector].id");
            assert!(seen.insert(*declared_id), "duplicate built-in def id {declared_id}");
        }
    }

    #[test]
    fn gmail_tiers_pin_to_todays_scope_sets() {
        // AC #2: read == [gmail.readonly]; read-write == readonly+send+compose+modify
        // (== read_write_scopes_for_service("gmail") in oauth/google/scopes.rs).
        let g = def_by_id("google-gmail");
        assert_eq!(
            g.tiers.get("read").map(TierBundle::scopes),
            Some(&["gmail.readonly".to_owned()][..])
        );
        assert_eq!(
            g.tiers.get("read-write").map(TierBundle::scopes),
            Some(
                &[
                    "gmail.readonly".to_owned(),
                    "gmail.send".to_owned(),
                    "gmail.compose".to_owned(),
                    "gmail.modify".to_owned(),
                ][..]
            )
        );
        // gmail.metadata is in the vocab but in no tier (matches scopes.rs).
        assert!(g.scopes.contains_key("gmail.metadata"));
        assert!(!g.tiers.values().any(|t| t.scopes().iter().any(|s| s == "gmail.metadata")));
    }

    #[test]
    fn calendar_and_drive_readwrite_equals_read() {
        // AC #3: calendar/drive read-write tiers == their read tiers (today's
        // back-compat).
        for id in ["google-calendar", "google-drive"] {
            let d = def_by_id(id);
            assert_eq!(
                d.tiers.get("read").map(TierBundle::scopes),
                d.tiers.get("read-write").map(TierBundle::scopes),
                "{id}: read-write tier must equal read tier"
            );
        }
    }

    #[test]
    fn base_url_host_in_allowed_hosts() {
        // AC #4.
        for d in defs() {
            let host = d.upstream.base_url.host_str().expect("base_url has a host");
            assert!(
                d.upstream.allowed_hosts.iter().any(|h| h == host),
                "{}: base_url host {host} must be in allowed_hosts {:?}",
                d.connector.id,
                d.upstream.allowed_hosts
            );
        }
    }

    #[test]
    fn all_builtins_are_built_in_tier_with_no_operator_config() {
        // AC #5: trust_tier=built-in; only google hosts; no secrets (the model
        // has no secret field, but assert the allowed_hosts/base_url stay on
        // google domains so no operator-specific endpoint leaked in).
        for d in defs() {
            assert_eq!(d.connector.trust_tier, TrustTier::BuiltIn);
            for h in &d.upstream.allowed_hosts {
                assert!(h.ends_with("googleapis.com"), "{}: non-google host {h}", d.connector.id);
            }
            assert!(d.auth.auth_url.host_str().is_some_and(|h| h.ends_with("google.com")));
        }
    }

    #[test]
    fn tool_metadata_is_self_consistent() {
        // AC #7: every required_scope ∈ [scopes]; every tier scope ∈ [scopes];
        // tool counts == 26/12/8; spot-check key tools.
        let expected_counts = [("google-gmail", 26), ("google-calendar", 12), ("google-drive", 8)];
        for (id, n) in expected_counts {
            let d = def_by_id(id);
            assert_eq!(d.tools.len(), n, "{id}: expected {n} tools");
            for t in &d.tools {
                assert!(
                    d.scopes.contains_key(&t.required_scope),
                    "{id}: tool {} required_scope {} not in [scopes]",
                    t.name,
                    t.required_scope
                );
            }
            for (tier, bundle) in &d.tiers {
                for s in bundle.scopes() {
                    assert!(
                        d.scopes.contains_key(s),
                        "{id}: tier {tier} scope {s} not in [scopes]"
                    );
                }
            }
        }
        // Spot-check the metadata extraction against the live handler table.
        let g = def_by_id("google-gmail");
        let send = g.tools.iter().find(|t| t.name == "gmail.messages.send").expect("send tool");
        assert_eq!((send.required_scope.as_str(), send.method.as_str()), ("gmail.send", "POST"));
        let cal = def_by_id("google-calendar");
        let del = cal.tools.iter().find(|t| t.name == "calendar.events.delete").expect("delete");
        assert_eq!(
            (del.required_scope.as_str(), del.method.as_str()),
            ("calendar.events", "DELETE")
        );
        let dr = def_by_id("google-drive");
        let create = dr.tools.iter().find(|t| t.name == "drive.files.create").expect("create");
        assert_eq!(
            (create.required_scope.as_str(), create.method.as_str()),
            ("drive.file", "POST")
        );
        let about = dr.tools.iter().find(|t| t.name == "drive.about.get").expect("about");
        assert_eq!(about.required_scope, "drive.readonly");
    }
}
