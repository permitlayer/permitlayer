//! Connector-definition typed model (`connector.toml` schema).
//!
//! Story 11.1 introduces the declarative connector definition that
//! Epic 11 collapses onto a single source of truth. Today a "service"
//! (`gmail`/`calendar`/`drive`) is encoded across five disjoint sites:
//! the MCP route key, the `base_urls` map
//! (`permitlayer-proxy/src/upstream/http_client.rs`), the
//! `SUPPORTED_SERVICES` enums, the scope vocab
//! (`permitlayer-oauth/src/google/scopes.rs`), and the per-`*McpServer`
//! tool lists. A [`ConnectorDef`] expresses all of that as one
//! declarative artifact.
//!
//! This module is the **data shape only**: typed model + serde
//! deserialization + a parse-error path. There is no registry, no
//! load-time validator, and no consumer reads it yet — those land in
//! Stories 11.2 (built-ins as data) and 11.3 (registry + validator),
//! with the proxy switching over in Phase 2.
//!
//! ## No-secrets discipline
//!
//! [`AuthSpec`] holds OAuth endpoint URLs and an optional **public**
//! client id only — never a client secret. The model carries no
//! operator-specific or deployment-specific config; every default comes
//! from the TOML the operator (or the embedded built-in) supplies, not
//! from a hardcoded fallback in the type. This mirrors the
//! "no operator config in shipped defaults" rule that governs the rest
//! of the credential surface.

use std::collections::BTreeMap;

use serde::Deserialize;
use url::Url;

use crate::error::ConnectorError;

/// A complete connector definition: identity, auth, upstream, scope
/// vocabulary, access tiers, and the tool catalog.
///
/// Deserialized from a `connector.toml`. The `#[serde(deny_unknown_fields)]`
/// guard on each section turns a typo'd or stray key into a typed parse
/// error rather than a silent drop — a connector author who misnames a
/// field finds out at load, not at first dispatch.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorDef {
    /// `[connector]` — identity + trust tier.
    pub connector: ConnectorMeta,

    /// `[auth]` — OAuth flavor + endpoints (no secrets).
    pub auth: AuthSpec,

    /// `[upstream]` — base URL + mandatory host allowlist.
    pub upstream: UpstreamSpec,

    /// `[scopes]` — vocabulary mapping short name → full OAuth scope URI.
    ///
    /// `BTreeMap` for deterministic iteration order (used later by the
    /// validator and by tier resolution).
    pub scopes: BTreeMap<String, String>,

    /// `[tiers]` — access tier name (`read`/`read-write`/custom) → list
    /// of scope **short names** drawn from `[scopes]`.
    pub tiers: BTreeMap<String, TierBundle>,

    /// `[[tools]]` — the connector's tool catalog.
    #[serde(default)]
    pub tools: Vec<ToolDef>,
}

/// `[connector]` section: stable identity and trust tier.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorMeta {
    /// Stable connector id (lowercase alphanumeric + `-`), e.g.
    /// `google-gmail`. The load-time validator (11.3) cross-checks this
    /// against the directory / metadata id.
    pub id: String,

    /// Human-readable display name, e.g. `Gmail`.
    pub display_name: String,

    /// Connector definition version (free-form semver-ish string).
    pub version: String,

    /// Trust tier — gates the stricter SSRF rules (11.6) and is surfaced
    /// in `connection inspect` (11.13).
    pub trust_tier: TrustTier,
}

/// Connector trust tier.
///
/// `BuiltIn` connectors ship embedded in the daemon binary; `HostInstalled`
/// connectors are discovered from `connectors/<id>/` on disk and get the
/// stricter per-call SSRF posture (https-only + private-range denial)
/// introduced in Story 11.6 (NFR52/NFR53). No `Default` — an unknown or
/// missing `trust_tier` is a typed parse error, never a silent fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustTier {
    /// Shipped embedded in the daemon binary (tamper-proof).
    BuiltIn,
    /// Discovered from the host filesystem (no recompile, FR89).
    HostInstalled,
}

/// `[auth]` section: OAuth flavor + endpoints.
///
/// Holds **no client secret**. `default_client` is an optional *public*
/// OAuth client id (the installed-app client); the secret half of the
/// dance never lives in a connector def — the Rust host performs the
/// OAuth exchange so secrets never cross into connector JS (NFR53).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSpec {
    /// Auth flavor, e.g. `oauth2`. Validated against a known set by the
    /// load-time validator (11.3), not here.
    pub flavor: String,

    /// OAuth authorization endpoint.
    pub auth_url: Url,

    /// OAuth token endpoint.
    pub token_url: Url,

    /// Optional **public** default client id. Never a secret.
    #[serde(default)]
    pub default_client: Option<String>,
}

/// `[upstream]` section: where API calls go, and the host allowlist that
/// bounds them.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamSpec {
    /// Base URL that tool path templates join onto.
    pub base_url: Url,

    /// **Mandatory** host allowlist. Every resolved upstream host is
    /// re-checked against this on each dispatch (FR91/NFR52, Story 11.6).
    /// Required by the schema: omitting it is a typed parse error naming
    /// the field (AC #2) — there is no permissive default.
    pub allowed_hosts: Vec<String>,
}

/// A tier's scope bundle: the list of scope **short names** (keys into
/// `[scopes]`) granted at that tier.
///
/// A newtype over `Vec<String>` rather than a bare alias so the tier
/// table reads as `tier-name -> bundle` and so future per-tier metadata
/// (a description, say) has a home without a schema break.
#[derive(Debug, Clone, Deserialize)]
#[serde(transparent)]
pub struct TierBundle(pub Vec<String>);

impl TierBundle {
    /// The scope short names in this tier.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.0
    }
}

/// A single tool in the connector's catalog (`[[tools]]`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDef {
    /// Tool name as advertised over MCP, e.g. `gmail_list_messages`.
    pub name: String,

    /// The scope **short name** (a `[scopes]` key) this tool requires.
    /// The validator (11.3) rejects a tool whose `required_scope` is not
    /// in the connector's `[scopes]` vocabulary.
    pub required_scope: String,

    /// HTTP method (`GET`/`POST`/...). Held as a string here; validated
    /// against the known set by the load-time validator, not the model.
    pub method: String,

    /// Path template joined onto `[upstream].base_url`, e.g.
    /// `users/me/messages`.
    pub path: String,

    /// MCP input schema — arbitrary JSON, held as a `serde_json::Value`
    /// so the model does not over-specify the schema shape. rmcp wiring
    /// consumes this in Story 11.4.
    #[serde(default)]
    pub input_schema: serde_json::Value,
}

impl ConnectorDef {
    /// Parse a `ConnectorDef` from `connector.toml` text.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::Parse`] if the text is not valid TOML or
    /// does not match the schema — including a missing mandatory field
    /// (e.g. `[upstream].allowed_hosts`), an unknown `trust_tier` value, or
    /// a stray/unknown key in any section. The wrapped `toml` error names
    /// the offending field.
    pub fn from_toml_str(s: &str) -> Result<Self, ConnectorError> {
        toml::from_str(s).map_err(ConnectorError::from)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A representative fixture exercising every section + a GET and a
    /// POST tool. Kept inline so the parse tests are self-contained.
    const GMAIL_FIXTURE: &str = r#"
[connector]
id = "google-gmail"
display_name = "Gmail"
version = "1.0.0"
trust_tier = "built-in"

[auth]
flavor = "oauth2"
auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
token_url = "https://oauth2.googleapis.com/token"

[upstream]
base_url = "https://gmail.googleapis.com/gmail/v1/"
allowed_hosts = ["gmail.googleapis.com"]

[scopes]
"gmail.readonly" = "https://www.googleapis.com/auth/gmail.readonly"
"gmail.send" = "https://www.googleapis.com/auth/gmail.send"

[tiers]
read = ["gmail.readonly"]
read-write = ["gmail.readonly", "gmail.send"]

[[tools]]
name = "gmail_list_messages"
required_scope = "gmail.readonly"
method = "GET"
path = "users/me/messages"
input_schema = { type = "object", properties = {} }

[[tools]]
name = "gmail_send_message"
required_scope = "gmail.send"
method = "POST"
path = "users/me/messages/send"
"#;

    #[test]
    fn full_fixture_deserializes() {
        let def = ConnectorDef::from_toml_str(GMAIL_FIXTURE).expect("fixture parses");
        assert_eq!(def.connector.id, "google-gmail");
        assert_eq!(def.connector.display_name, "Gmail");
        assert_eq!(def.connector.version, "1.0.0");
        assert_eq!(def.connector.trust_tier, TrustTier::BuiltIn);
        assert_eq!(def.auth.flavor, "oauth2");
        assert_eq!(def.upstream.base_url.host_str(), Some("gmail.googleapis.com"));
        assert_eq!(def.upstream.allowed_hosts, vec!["gmail.googleapis.com".to_owned()]);
        assert_eq!(def.scopes.len(), 2);
        assert_eq!(
            def.scopes.get("gmail.readonly").map(String::as_str),
            Some("https://www.googleapis.com/auth/gmail.readonly")
        );
        assert_eq!(
            def.tiers.get("read").map(TierBundle::scopes),
            Some(&["gmail.readonly".to_owned()][..])
        );
        assert_eq!(def.tools.len(), 2);
    }

    #[test]
    fn missing_allowed_hosts_is_a_typed_error_naming_the_field() {
        let toml = GMAIL_FIXTURE.replace("allowed_hosts = [\"gmail.googleapis.com\"]\n", "");
        let err = ConnectorDef::from_toml_str(&toml).expect_err("missing allowed_hosts must fail");
        let msg = err.to_string();
        assert!(msg.contains("allowed_hosts"), "error must name the missing field; got: {msg}");
    }

    #[test]
    fn unknown_trust_tier_is_a_typed_error() {
        let toml = GMAIL_FIXTURE.replace("trust_tier = \"built-in\"", "trust_tier = \"trusted\"");
        let err = ConnectorDef::from_toml_str(&toml).expect_err("unknown trust_tier must fail");
        // serde's enum error enumerates the valid variants.
        let msg = err.to_string();
        assert!(
            msg.contains("trust_tier")
                || msg.contains("built-in")
                || msg.contains("host-installed"),
            "error should reference the trust_tier field or its variants; got: {msg}"
        );
    }

    #[test]
    fn host_installed_trust_tier_parses() {
        let toml =
            GMAIL_FIXTURE.replace("trust_tier = \"built-in\"", "trust_tier = \"host-installed\"");
        let def = ConnectorDef::from_toml_str(&toml).expect("host-installed parses");
        assert_eq!(def.connector.trust_tier, TrustTier::HostInstalled);
    }

    #[test]
    fn tool_entries_round_trip_all_fields() {
        let def = ConnectorDef::from_toml_str(GMAIL_FIXTURE).unwrap();
        let get = def.tools.iter().find(|t| t.name == "gmail_list_messages").expect("GET tool");
        assert_eq!(get.required_scope, "gmail.readonly");
        assert_eq!(get.method, "GET");
        assert_eq!(get.path, "users/me/messages");
        assert_eq!(get.input_schema.get("type").and_then(|v| v.as_str()), Some("object"));

        let post = def.tools.iter().find(|t| t.name == "gmail_send_message").expect("POST tool");
        assert_eq!(post.required_scope, "gmail.send");
        assert_eq!(post.method, "POST");
        assert_eq!(post.path, "users/me/messages/send");
        // No input_schema supplied → defaults to JSON null, not an error.
        assert!(post.input_schema.is_null());
    }

    #[test]
    fn unknown_section_key_is_rejected() {
        // deny_unknown_fields: a stray key in [connector] is a typed error,
        // not a silent drop.
        let toml = GMAIL_FIXTURE
            .replace("version = \"1.0.0\"", "version = \"1.0.0\"\nsecret_token = \"oops\"");
        let err = ConnectorDef::from_toml_str(&toml).expect_err("stray key must fail");
        assert!(err.to_string().contains("secret_token"), "error names the stray key: {err}");
    }

    #[test]
    fn auth_spec_has_no_secret_field() {
        // AC #5: the model carries no secrets. A connector.toml that tries
        // to declare a client secret is rejected (deny_unknown_fields), and
        // the only client material is the optional *public* default_client.
        let toml = GMAIL_FIXTURE.replace(
            "token_url = \"https://oauth2.googleapis.com/token\"",
            "token_url = \"https://oauth2.googleapis.com/token\"\nclient_secret = \"sshh\"",
        );
        let err = ConnectorDef::from_toml_str(&toml).expect_err("client_secret must be rejected");
        assert!(err.to_string().contains("client_secret"), "secret rejected: {err}");
    }

    #[test]
    fn model_bakes_in_no_host_or_path_defaults() {
        // AC #5: defaults come only from the TOML. A def with no tools and
        // empty-but-present required sections must NOT invent an upstream
        // host or path. (allowed_hosts present-but-empty is a validator
        // concern in 11.3, not a parse default here.)
        let minimal = r#"
[connector]
id = "x"
display_name = "X"
version = "0"
trust_tier = "built-in"

[auth]
flavor = "oauth2"
auth_url = "https://example.com/auth"
token_url = "https://example.com/token"

[upstream]
base_url = "https://api.example.com/"
allowed_hosts = ["api.example.com"]

[scopes]

[tiers]
"#;
        let def = ConnectorDef::from_toml_str(minimal).expect("minimal parses");
        assert!(def.tools.is_empty());
        assert_eq!(def.upstream.base_url.host_str(), Some("api.example.com"));
        // No google/operator host leaked in from a default.
        assert!(!def.upstream.allowed_hosts.iter().any(|h| h.contains("google")));
    }
}
