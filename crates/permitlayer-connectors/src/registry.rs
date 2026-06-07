//! The [`ConnectorRegistry`] — the single place the daemon resolves a
//! connector by id (Story 11.3).
//!
//! Mirrors the `ArcSwap<BTreeMap>` discipline of
//! `permitlayer_plugins::PluginRegistry`, but holds validated
//! [`ConnectorDef`]s rather than JS plugins. Built-in connectors are
//! embedded ([`crate::builtin_connector_defs`], `trust_tier = BuiltIn`);
//! host-installed connectors are discovered from
//! `connectors/<id>/connector.toml` on disk (`trust_tier =
//! HostInstalled`) with **no recompile** (FR89).
//!
//! ## Load policy
//!
//! - **Built-ins are a ship-time invariant**: a built-in that fails to
//!   parse or validate panics the test suite (caught by 11.2/11.3
//!   tests), so [`ConnectorRegistry::load`] treats a built-in failure as
//!   a hard error — it should never happen in a shipped binary.
//! - **Host-installed defs are skip-and-warned**: one malformed or
//!   invalid third-party connector is logged and skipped; it never takes
//!   down the daemon and never blocks the built-ins from loading
//!   (FR89/FR90, AC#8).
//! - **Built-in wins on id collision**: a host-installed connector that
//!   reuses a built-in id is rejected (warn-logged), never silently
//!   shadowing the built-in (AC#6).
//!
//! ## Hot swap
//!
//! The registry is wrapped in `ArcSwap`. [`ConnectorRegistry::reload`]
//! rebuilds from the embedded built-ins + a fresh disk scan and swaps
//! atomically; a reader holding a [`ConnectorRegistry::snapshot`] keeps
//! its `Arc` across the swap (mid-call readers are unaffected, AC#7).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tracing::warn;

use crate::def::{ConnectorDef, TrustTier};
use crate::validate::validate_def;

/// A connector that has been parsed, validated, and recorded in the
/// registry, tagged with the trust tier it was loaded under.
#[derive(Debug, Clone)]
pub struct ResolvedConnector {
    /// The validated connector definition.
    pub def: ConnectorDef,
}

impl ResolvedConnector {
    /// The connector's stable id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.def.connector.id
    }

    /// The trust tier from the def's `[connector].trust_tier`.
    #[must_use]
    pub fn trust_tier(&self) -> TrustTier {
        self.def.connector.trust_tier
    }

    /// Resolve an access tier (`read` / `read-write` / a custom tier name)
    /// to the **full OAuth scope URIs** it grants, in tier-declaration
    /// order (Story 11.7).
    ///
    /// Each scope short name in the tier's bundle is mapped through the
    /// connector's `[scopes]` vocabulary to its full URI. Returns `None`
    /// if the tier is not declared by this connector; the caller maps that
    /// to "unknown access tier". A short name present in a tier but absent
    /// from `[scopes]` is impossible for a validated def (the 11.3
    /// validator rejects it at load), so it is silently skipped here rather
    /// than surfaced — a defensive no-op, not a supported path.
    #[must_use]
    pub fn tier_scope_uris(&self, tier: &str) -> Option<Vec<&str>> {
        let bundle = self.def.tiers.get(tier)?;
        Some(
            bundle
                .scopes()
                .iter()
                .filter_map(|short| self.def.scopes.get(short).map(String::as_str))
                .collect(),
        )
    }
}

/// Map a route/CLI **selector** to its canonical connector id (Story 11.7).
///
/// The CLI + MCP-route vocabulary stays the bare service name
/// (`gmail`/`calendar`/`drive`) for client compatibility; the registry
/// keys on the canonical id (`google-gmail`/…). A selector that is already
/// a canonical id passes through unchanged. Returns `None` for an
/// unrecognized selector.
///
/// This is the single home for the alias mapping — `permitlayer-proxy`'s
/// `selector_to_connector_id` delegates here so the proxy and the daemon
/// CLI can never disagree on what `gmail` resolves to.
#[must_use]
pub fn canonical_selector_id(selector: &str) -> Option<&'static str> {
    match selector {
        "gmail" | "google-gmail" => Some("google-gmail"),
        "calendar" | "google-calendar" => Some("google-calendar"),
        "drive" | "google-drive" => Some("google-drive"),
        _ => None,
    }
}

/// Registry of connector definitions keyed by id.
///
/// Wrapped in `ArcSwap` so [`Self::reload`] can replace the whole map
/// atomically (e.g. on SIGHUP) without restarting the daemon.
pub struct ConnectorRegistry {
    inner: ArcSwap<BTreeMap<String, Arc<ResolvedConnector>>>,
}

impl ConnectorRegistry {
    /// Build a registry from the embedded built-ins plus any
    /// host-installed connectors discovered under `connectors_dir`.
    ///
    /// `connectors_dir` is the directory that holds
    /// `<id>/connector.toml` subdirectories (the daemon passes
    /// `permitlayer_core::paths::connectors_dir(..)`). `None` — or a
    /// path that does not exist — means "built-ins only", which is the
    /// normal state on a system with no third-party connectors.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ConnectorError`] only if a **built-in** fails to
    /// parse — a ship-time bug. Host-installed failures are skipped and
    /// warned, never surfaced as an error.
    pub fn load(connectors_dir: Option<&Path>) -> Result<Self, crate::ConnectorError> {
        let mut map: BTreeMap<String, Arc<ResolvedConnector>> = BTreeMap::new();

        // Built-ins first — they win every id collision.
        for def in crate::builtin_connector_defs()? {
            let id = def.connector.id.clone();
            // A built-in failing validation is a ship-time bug; surface
            // it loudly rather than silently dropping a core connector.
            if let Err(e) = validate_def(&def, &id) {
                return Err(crate::ConnectorError::BuiltinInvalid { id, reason: e.to_string() });
            }
            map.insert(id, Arc::new(ResolvedConnector { def }));
        }

        if let Some(dir) = connectors_dir {
            Self::scan_host_installed(dir, &mut map);
        }

        Ok(Self { inner: ArcSwap::from_pointee(map) })
    }

    /// Build a registry directly from a set of definitions, keyed by each
    /// def's `[connector].id`. No validation and no disk scan.
    ///
    /// Intended for tests and embedding scenarios that need a registry
    /// pointing at non-default upstreams (e.g. a mock server). Production
    /// boot uses [`Self::load`]. A later def with a duplicate id wins
    /// (last-write), unlike `load`'s built-in-wins policy — callers
    /// constructing test registries control the input set.
    #[must_use]
    pub fn from_defs(defs: impl IntoIterator<Item = ConnectorDef>) -> Self {
        let map: BTreeMap<String, Arc<ResolvedConnector>> = defs
            .into_iter()
            .map(|def| (def.connector.id.clone(), Arc::new(ResolvedConnector { def })))
            .collect();
        Self { inner: ArcSwap::from_pointee(map) }
    }

    /// Scan `dir/<id>/connector.toml`, validating each and inserting
    /// `HostInstalled` connectors. Malformed/invalid/colliding defs are
    /// skip-and-warned (never fatal). Built-ins already in `map` win id
    /// collisions.
    fn scan_host_installed(dir: &Path, map: &mut BTreeMap<String, Arc<ResolvedConnector>>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return, // absent connectors dir is normal.
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some(dir_id) = path.file_name().and_then(|n| n.to_str()).map(str::to_owned) else {
                continue;
            };
            let toml_path = path.join("connector.toml");
            let src = match std::fs::read_to_string(&toml_path) {
                Ok(s) => s,
                Err(e) => {
                    warn!(connector = %dir_id, error = %e, "skipping host-installed connector: cannot read connector.toml");
                    continue;
                }
            };
            let def = match ConnectorDef::from_toml_str(&src) {
                Ok(d) => d,
                Err(e) => {
                    warn!(connector = %dir_id, error = %e, "skipping host-installed connector: parse error");
                    continue;
                }
            };
            if let Err(e) = validate_def(&def, &dir_id) {
                warn!(connector = %dir_id, error = %e, "skipping host-installed connector: validation failed");
                continue;
            }
            if map.contains_key(&dir_id) {
                warn!(
                    connector = %dir_id,
                    "skipping host-installed connector: id collides with a built-in (built-in wins)"
                );
                continue;
            }
            map.insert(dir_id, Arc::new(ResolvedConnector { def }));
        }
    }

    /// Atomically rebuild the registry from the built-ins + a fresh
    /// disk scan and swap it in. Readers holding a [`Self::snapshot`]
    /// keep their old `Arc` until they drop it.
    ///
    /// # Errors
    ///
    /// Same contract as [`Self::load`] — only a built-in parse/validate
    /// failure errors.
    pub fn reload(&self, connectors_dir: Option<&Path>) -> Result<(), crate::ConnectorError> {
        let rebuilt = Self::load(connectors_dir)?;
        self.inner.store(rebuilt.inner.load_full());
        Ok(())
    }

    /// Snapshot the current contents. The `Arc` outlives a concurrent
    /// swap via `ArcSwap`'s discipline.
    #[must_use]
    pub fn snapshot(&self) -> Arc<BTreeMap<String, Arc<ResolvedConnector>>> {
        self.inner.load_full()
    }

    /// Resolve one connector by id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<Arc<ResolvedConnector>> {
        self.snapshot().get(id).cloned()
    }

    /// Resolve one connector by a route/CLI **selector** — either a bare
    /// alias (`gmail`) or a canonical id (`google-gmail`) — via
    /// [`canonical_selector_id`] (Story 11.7).
    ///
    /// Returns `None` if the selector is unrecognized *or* the resolved id
    /// is not registered (e.g. a built-in alias whose connector somehow
    /// failed to load — never the case for a shipped binary).
    #[must_use]
    pub fn resolve_selector(&self, selector: &str) -> Option<Arc<ResolvedConnector>> {
        let id = canonical_selector_id(selector)?;
        self.get(id)
    }

    /// The set of route/CLI selectors this registry can resolve, in
    /// deterministic (sorted-by-canonical-id) order (Story 11.7).
    ///
    /// Used for the CLI's "unsupported service" error message so it lists
    /// the live connector set rather than a hand-maintained constant. Each
    /// built-in is surfaced under its bare alias (`gmail`), the form users
    /// type; host-installed connectors surface under their canonical id
    /// (no bare alias exists for them).
    #[must_use]
    pub fn selectors(&self) -> Vec<&'static str> {
        // BTreeMap → ids already sorted. Map each known built-in id back to
        // its bare alias; anything else (host-installed) keeps its id.
        self.snapshot()
            .keys()
            .map(|id| match id.as_str() {
                "google-gmail" => "gmail",
                "google-calendar" => "calendar",
                "google-drive" => "drive",
                _ => "",
            })
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Number of registered connectors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.snapshot().len()
    }

    /// Whether the registry is empty (never true for a shipped binary —
    /// the built-ins always load).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl std::fmt::Debug for ConnectorRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let snap = self.snapshot();
        f.debug_struct("ConnectorRegistry")
            .field("len", &snap.len())
            .field("ids", &snap.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn host_installed_toml(id: &str) -> String {
        format!(
            r#"
[connector]
id = "{id}"
display_name = "Host Conn"
version = "0.1.0"
trust_tier = "host-installed"

[auth]
flavor = "oauth2"
auth_url = "https://accounts.example.com/auth"
token_url = "https://accounts.example.com/token"

[upstream]
base_url = "https://api.example.com/v1/"
allowed_hosts = ["api.example.com"]

[scopes]
"thing.read" = "https://api.example.com/auth/thing.read"

[tiers]
read = ["thing.read"]

[[tools]]
name = "thing.list"
required_scope = "thing.read"
method = "GET"
path = "things"
"#
        )
    }

    fn write_connector(root: &Path, id: &str, toml: &str) {
        let dir = root.join(id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("connector.toml"), toml).unwrap();
    }

    #[test]
    fn loads_three_builtins_resolvable_by_id() {
        // AC #1.
        let reg = ConnectorRegistry::load(None).unwrap();
        assert_eq!(reg.len(), 3);
        for id in ["google-gmail", "google-calendar", "google-drive"] {
            let c = reg.get(id).unwrap_or_else(|| panic!("missing {id}"));
            assert_eq!(c.id(), id);
            assert_eq!(c.trust_tier(), TrustTier::BuiltIn);
        }
    }

    #[test]
    fn discovers_host_installed_no_recompile() {
        // AC #2 + FR89.
        let tmp = tempfile::tempdir().unwrap();
        write_connector(tmp.path(), "acme-widgets", &host_installed_toml("acme-widgets"));
        let reg = ConnectorRegistry::load(Some(tmp.path())).unwrap();
        let c = reg.get("acme-widgets").expect("host-installed resolvable");
        assert_eq!(c.trust_tier(), TrustTier::HostInstalled);
        assert_eq!(reg.len(), 4); // 3 builtins + 1 host-installed.
    }

    #[test]
    fn invalid_host_installed_is_skipped_builtins_survive() {
        // AC #8: a bad host-installed def (tool scope not in vocab) is
        // skipped; built-ins still load.
        let tmp = tempfile::tempdir().unwrap();
        let bad = host_installed_toml("bad-conn")
            .replace("required_scope = \"thing.read\"", "required_scope = \"thing.absent\"");
        write_connector(tmp.path(), "bad-conn", &bad);
        let reg = ConnectorRegistry::load(Some(tmp.path())).unwrap();
        assert!(reg.get("bad-conn").is_none(), "invalid def must be skipped");
        assert_eq!(reg.len(), 3, "built-ins still load");
    }

    #[test]
    fn dir_id_mismatch_is_skipped() {
        // AC #5: [connector].id != directory id → skipped.
        let tmp = tempfile::tempdir().unwrap();
        // Directory is "wrong-dir" but the toml declares "acme-widgets".
        write_connector(tmp.path(), "wrong-dir", &host_installed_toml("acme-widgets"));
        let reg = ConnectorRegistry::load(Some(tmp.path())).unwrap();
        assert!(reg.get("acme-widgets").is_none());
        assert!(reg.get("wrong-dir").is_none());
        assert_eq!(reg.len(), 3);
    }

    #[test]
    fn host_installed_cannot_shadow_builtin() {
        // AC #6: a host-installed def reusing a built-in id is rejected;
        // the built-in (BuiltIn tier) survives.
        let tmp = tempfile::tempdir().unwrap();
        write_connector(tmp.path(), "google-gmail", &host_installed_toml("google-gmail"));
        let reg = ConnectorRegistry::load(Some(tmp.path())).unwrap();
        let gmail = reg.get("google-gmail").unwrap();
        assert_eq!(gmail.trust_tier(), TrustTier::BuiltIn, "built-in must win");
        assert_eq!(reg.len(), 3);
    }

    #[test]
    fn reload_picks_up_new_connector_and_snapshot_is_stable() {
        // AC #7.
        let tmp = tempfile::tempdir().unwrap();
        let reg = ConnectorRegistry::load(Some(tmp.path())).unwrap();
        assert_eq!(reg.len(), 3);
        // A reader takes a snapshot BEFORE the new connector lands.
        let pre = reg.snapshot();

        write_connector(tmp.path(), "late-conn", &host_installed_toml("late-conn"));
        reg.reload(Some(tmp.path())).unwrap();

        assert!(reg.get("late-conn").is_some(), "reload picks up the new connector");
        assert_eq!(reg.len(), 4);
        // The pre-swap snapshot still reflects the old contents.
        assert_eq!(pre.len(), 3);
        assert!(!pre.contains_key("late-conn"));
    }

    #[test]
    fn absent_connectors_dir_is_builtins_only() {
        let reg = ConnectorRegistry::load(Some(Path::new("/nonexistent/path/xyz"))).unwrap();
        assert_eq!(reg.len(), 3);
    }

    // ---- Story 11.7: selector + tier→scope resolution ----

    #[test]
    fn canonical_selector_id_maps_aliases_and_ids() {
        assert_eq!(canonical_selector_id("gmail"), Some("google-gmail"));
        assert_eq!(canonical_selector_id("google-gmail"), Some("google-gmail"));
        assert_eq!(canonical_selector_id("calendar"), Some("google-calendar"));
        assert_eq!(canonical_selector_id("drive"), Some("google-drive"));
        assert_eq!(canonical_selector_id("nope"), None);
        assert_eq!(canonical_selector_id(""), None);
    }

    #[test]
    fn resolve_selector_and_selectors_list() {
        let reg = ConnectorRegistry::load(None).unwrap();
        assert_eq!(reg.resolve_selector("gmail").unwrap().id(), "google-gmail");
        assert_eq!(reg.resolve_selector("google-drive").unwrap().id(), "google-drive");
        assert!(reg.resolve_selector("slack").is_none());
        // Deterministic, bare-alias form, sorted by canonical id.
        assert_eq!(reg.selectors(), vec!["calendar", "drive", "gmail"]);
    }

    /// AC #1 — the drift tripwire. Registry tier resolution must return the
    /// EXACT OAuth scope URIs (and order) that `oauth/google/scopes.rs`'s
    /// deleted `default_scopes_for_service` / `read_write_scopes_for_service`
    /// returned. The literal URIs below are copied from the `scopes.rs`
    /// constants (`GMAIL_READONLY` etc.); if a connector.toml tier or the
    /// `[scopes]` vocab is edited and this drifts, this test fails.
    #[test]
    fn tier_scope_uris_pin_to_legacy_scope_sets() {
        let reg = ConnectorRegistry::load(None).unwrap();

        const GMAIL_READONLY: &str = "https://www.googleapis.com/auth/gmail.readonly";
        const GMAIL_SEND: &str = "https://www.googleapis.com/auth/gmail.send";
        const GMAIL_COMPOSE: &str = "https://www.googleapis.com/auth/gmail.compose";
        const GMAIL_MODIFY: &str = "https://www.googleapis.com/auth/gmail.modify";
        const CALENDAR_READONLY: &str = "https://www.googleapis.com/auth/calendar.readonly";
        const CALENDAR_EVENTS: &str = "https://www.googleapis.com/auth/calendar.events";
        const DRIVE_READONLY: &str = "https://www.googleapis.com/auth/drive.readonly";
        const DRIVE_FILE: &str = "https://www.googleapis.com/auth/drive.file";

        let gmail = reg.resolve_selector("gmail").unwrap();
        assert_eq!(gmail.tier_scope_uris("read").unwrap(), vec![GMAIL_READONLY]);
        assert_eq!(
            gmail.tier_scope_uris("read-write").unwrap(),
            vec![GMAIL_READONLY, GMAIL_SEND, GMAIL_COMPOSE, GMAIL_MODIFY]
        );

        let calendar = reg.resolve_selector("calendar").unwrap();
        let cal_expected = vec![CALENDAR_READONLY, CALENDAR_EVENTS];
        assert_eq!(calendar.tier_scope_uris("read").unwrap(), cal_expected);
        assert_eq!(calendar.tier_scope_uris("read-write").unwrap(), cal_expected);

        let drive = reg.resolve_selector("drive").unwrap();
        let drive_expected = vec![DRIVE_READONLY, DRIVE_FILE];
        assert_eq!(drive.tier_scope_uris("read").unwrap(), drive_expected);
        assert_eq!(drive.tier_scope_uris("read-write").unwrap(), drive_expected);

        // Unknown tier → None (caller maps to an error, never an empty grant).
        assert!(gmail.tier_scope_uris("admin").is_none());
    }

    #[test]
    fn non_dir_and_missing_toml_entries_are_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        // A stray file (not a dir) and an empty dir (no connector.toml).
        std::fs::write(tmp.path().join("README.md"), "ignore me").unwrap();
        std::fs::create_dir_all(tmp.path().join("empty-conn")).unwrap();
        let reg = ConnectorRegistry::load(Some(tmp.path())).unwrap();
        assert_eq!(reg.len(), 3);
    }
}
