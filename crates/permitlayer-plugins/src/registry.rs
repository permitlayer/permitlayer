//! The [`PluginRegistry`] holds the set of loaded connector plugins.
//!
//! Built-in connectors (embedded via
//! [`permitlayer_connectors::builtin_connectors`]) and user-installed
//! connectors (loaded from `~/.agentsso/plugins/`) both land here with
//! a [`TrustTier`] annotation that distinguishes them. The
//! `[plugins]` config section on [`crate::loader::LoaderConfig`]
//! controls whether built-ins are auto-trusted and whether
//! user-installed plugins trigger the first-load prompt.
//!
//! Story 6.3 uses the read side of the registry only —
//! [`PluginRegistry::snapshot`] returns a shared `Arc` that callers
//! read without cloning the whole map. The swap side is reserved
//! for a future `agentsso connectors reload` story so the registry
//! can be hot-swapped without tearing down the QuickJS runtime.

use std::collections::BTreeMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::Serialize;

/// Trust tier for a loaded connector. Determines whether the
/// first-load prompt fires and whether the connector is eligible
/// for auto-dispatch in the future request path.
///
/// **Serialization is kebab-case** — the wire shape is
/// `"builtin"`, `"trusted-user"`, `"warn-user"`. The kebab form
/// matches the JSON surface exposed by the control plane (and by
/// `agentsso connectors list --json`) and is stable across 1.x;
/// adding a new variant is a breaking change to the CLI output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustTier {
    /// Embedded via [`permitlayer_connectors::builtin_connectors`].
    /// Always trusted; never prompts. Operators who want to audit
    /// built-ins can set `plugins.auto_trust_builtins = false` in
    /// `DaemonConfig` to force an interactive prompt on boot.
    Builtin,

    /// User-installed plugin whose sha256 matches a line in
    /// `~/.agentsso/plugins/.trusted`. No prompt; the operator has
    /// explicitly acknowledged this source.
    TrustedUser,

    /// User-installed plugin whose sha256 does NOT match any
    /// `.trusted` entry. The first-load WARN fired and the plugin
    /// was allowed to proceed (either interactively approved with
    /// `TrustDecision::Once` or silently allowed because
    /// `warn_on_first_load = false`). The annotation persists in
    /// the registry so `agentsso connectors list` can show
    /// `warn-user` in the Trust column.
    WarnUser,
}

/// A connector that has been parsed, metadata-validated, and
/// recorded into the registry.
///
/// The `source` field is kept for the future request-dispatch path
/// (dispatching to `agentsso.tools.<toolName>` will re-evaluate
/// this source in a fresh Context per call per
/// [`crate::runtime::PluginRuntime`]'s per-call isolation model).
/// `source` is deliberately NOT serialized — the CLI and control
/// plane should never transport plugin source over the wire.
#[derive(Debug, Clone, Serialize)]
pub struct RegisteredConnector {
    /// Canonical connector name. Matches the `metadata.name` field
    /// exported by the plugin's `index.js`. Validated at load time
    /// to be lowercase alphanumeric + `-` + `_`, 2..=64 chars, no
    /// path-traversal chars or ASCII control chars (see
    /// `crate::loader::validate_metadata`).
    pub name: String,

    /// Semver-parseable version string from `metadata.version`.
    /// The loader verifies `semver::Version::parse` succeeds before
    /// registering; the string form is preserved verbatim so
    /// `agentsso connectors list` can render what the plugin
    /// author wrote.
    pub version: String,

    /// Scopes the connector requests (e.g. `["gmail.readonly",
    /// "gmail.search"]`). Surfaced via `agentsso connectors list`
    /// so operators can verify before trusting. Each scope matches
    /// the policy engine's scope-allowlist regex `[a-z][a-z0-9._-]{0,63}`.
    pub scopes: Vec<String>,

    /// Optional human-readable description. Truncated at display
    /// time (not at load time); the full string up to 512 chars is
    /// preserved verbatim for JSON output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Trust tier at load time. Changes to the `.trusted` file on
    /// disk do NOT retroactively update this field — a daemon
    /// restart is required (consistent with every other
    /// config-changes-require-reload boundary in the codebase).
    pub trust_tier: TrustTier,

    /// Raw JS source. Kept in-memory for the future request path
    /// (dispatching tools will re-eval this in a fresh Context per
    /// call per the Story 6.1 per-call-isolation comment on
    /// `PluginRuntime::with_context`).
    ///
    /// NEVER serialized — the CLI and control plane should never
    /// transport plugin source over the wire.
    #[serde(skip)]
    pub source: Arc<str>,

    /// Hex-encoded lowercase sha256 of `source`. Displayed as a
    /// short prefix in `agentsso connectors list` and used as the
    /// `.trusted` match key for user-installed plugins. The string
    /// is exactly 64 hex chars; a mismatch on disk invalidates the
    /// trust entry and re-triggers the first-load prompt on the
    /// next boot (defense against silent malicious updates).
    pub source_sha256_hex: String,
}

/// Registry keyed by connector name. Name uniqueness is enforced
/// at load time — a user-installed plugin that collides with a
/// built-in name gets a WARN and is rejected (the built-in wins).
///
/// Wrapped in `ArcSwap` so a future `agentsso connectors reload`
/// can replace the registry atomically without tearing down the
/// runtime. Story 6.3 uses only the read side
/// ([`Self::snapshot`]); the swap API is a future-story surface
/// kept private for now (add `pub fn swap(&self, new: ...)` when a
/// caller needs it).
pub struct PluginRegistry {
    inner: ArcSwap<BTreeMap<String, Arc<RegisteredConnector>>>,
}

impl PluginRegistry {
    /// Build a new registry from a pre-populated map. The loader
    /// ([`crate::loader::load_all`]) is the only production caller;
    /// unit tests construct empty or small maps directly.
    #[must_use]
    pub fn new(initial: BTreeMap<String, Arc<RegisteredConnector>>) -> Self {
        Self { inner: ArcSwap::from_pointee(initial) }
    }

    /// Snapshot the current registry contents. Returns an `Arc`
    /// over the `BTreeMap` so callers can iterate without cloning
    /// the whole thing; the `Arc` outlives a concurrent swap via
    /// `ArcSwap`'s hazard-pointer discipline.
    #[must_use]
    pub fn snapshot(&self) -> Arc<BTreeMap<String, Arc<RegisteredConnector>>> {
        self.inner.load_full()
    }

    /// Number of registered connectors. Cheap — reads the Arc's
    /// internal len.
    #[must_use]
    pub fn len(&self) -> usize {
        self.snapshot().len()
    }

    /// Whether the registry is empty. The expected state on a
    /// daemon where `permitlayer-connectors` ships no built-ins
    /// AND the operator has not installed any user plugins — this
    /// is a valid boot configuration (the daemon still runs and
    /// the CLI renders an empty-state message).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Fetch one connector by canonical name. Returns `None` when
    /// the name is not registered. Name comparison is
    /// case-sensitive per the lowercase-charset constraint.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Arc<RegisteredConnector>> {
        self.snapshot().get(name).cloned()
    }
}

impl std::fmt::Debug for PluginRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let snap = self.snapshot();
        f.debug_struct("PluginRegistry")
            .field("len", &snap.len())
            .field("names", &snap.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn mk_registered(name: &str) -> RegisteredConnector {
        RegisteredConnector {
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
            scopes: vec!["test.readonly".to_owned()],
            description: None,
            trust_tier: TrustTier::Builtin,
            source: Arc::<str>::from("export const metadata = {};"),
            source_sha256_hex: "0".repeat(64),
        }
    }

    #[test]
    fn empty_registry_is_empty_and_has_zero_len() {
        let r = PluginRegistry::new(BTreeMap::new());
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert!(r.get("anything").is_none());
    }

    #[test]
    fn registry_get_returns_registered_connector() {
        let mut m = BTreeMap::new();
        m.insert("a".to_owned(), Arc::new(mk_registered("a")));
        let r = PluginRegistry::new(m);
        assert_eq!(r.len(), 1);
        assert!(r.get("a").is_some());
        assert!(r.get("nonexistent").is_none());
        // The returned value is an Arc clone — structural equality.
        let got = r.get("a").unwrap();
        assert_eq!(got.name, "a");
        assert_eq!(got.trust_tier, TrustTier::Builtin);
    }

    #[test]
    fn trust_tier_serializes_kebab_case() {
        assert_eq!(serde_json::to_string(&TrustTier::Builtin).unwrap(), "\"builtin\"");
        assert_eq!(serde_json::to_string(&TrustTier::TrustedUser).unwrap(), "\"trusted-user\"");
        assert_eq!(serde_json::to_string(&TrustTier::WarnUser).unwrap(), "\"warn-user\"");
    }

    #[test]
    fn trust_tier_has_exactly_three_variants_and_derives_copy_eq() {
        // Compile-time proof of the derives (AC #1).
        fn _accepts_copy<T: Copy>(_: T) {}
        fn _accepts_eq<T: Eq>(_: T) {}
        fn _accepts_serialize<T: Serialize>(_: T) {}
        _accepts_copy(TrustTier::Builtin);
        _accepts_eq(TrustTier::Builtin);
        _accepts_serialize(TrustTier::Builtin);

        // Runtime proof that matching is exhaustive with three
        // variants — adding a new variant without updating this
        // match would fail to compile, enforcing the 3-variant
        // invariant (AC #1).
        let all = [TrustTier::Builtin, TrustTier::TrustedUser, TrustTier::WarnUser];
        for t in all {
            let label = match t {
                TrustTier::Builtin => "builtin",
                TrustTier::TrustedUser => "trusted-user",
                TrustTier::WarnUser => "warn-user",
            };
            assert!(!label.is_empty());
        }
    }

    #[test]
    fn registered_connector_serialize_skips_source() {
        let c = mk_registered("a");
        let json = serde_json::to_value(&c).unwrap();
        // `source` MUST NOT appear in the serialized form — the CLI
        // and control plane never transport plugin source.
        assert!(json.get("source").is_none(), "source must not serialize: {json}");
        // The hash DOES serialize — operators need it to verify
        // against `.trusted` entries.
        assert!(json.get("source_sha256_hex").is_some());
        assert_eq!(json.get("name").unwrap().as_str(), Some("a"));
        assert_eq!(json.get("trust_tier").unwrap().as_str(), Some("builtin"));
    }

    #[test]
    fn registered_connector_serialize_skips_description_when_none() {
        let c = mk_registered("a");
        let json = serde_json::to_value(&c).unwrap();
        assert!(json.get("description").is_none(), "None description must be skipped: {json}");
    }

    #[test]
    fn registered_connector_serialize_includes_description_when_some() {
        let mut c = mk_registered("a");
        c.description = Some("a helpful connector".to_owned());
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(json.get("description").unwrap().as_str(), Some("a helpful connector"));
    }

    #[test]
    fn plugin_registry_debug_renders_length_and_names() {
        let mut m = BTreeMap::new();
        m.insert("zeta".to_owned(), Arc::new(mk_registered("zeta")));
        m.insert("alpha".to_owned(), Arc::new(mk_registered("alpha")));
        let r = PluginRegistry::new(m);
        let s = format!("{r:?}");
        assert!(s.contains("len: 2"));
        // BTreeMap iteration order is deterministic alphabetical —
        // Debug output reflects that.
        assert!(s.contains("alpha"));
        assert!(s.contains("zeta"));
        let alpha_pos = s.find("alpha").unwrap();
        let zeta_pos = s.find("zeta").unwrap();
        assert!(alpha_pos < zeta_pos, "BTreeMap must render alphabetical: {s}");
    }
}
