//! Shared helpers for the proxy integration tests (Story 11.5).
//!
//! After Story 11.5 the upstream base URL comes from the connector
//! registry, not a hardcoded `base_urls` map. Tests that dispatch to a
//! mock server build a registry whose connector `base_url`s point at the
//! mock via [`connector_registry_with`]; tests that never dispatch use
//! [`default_connector_registry`] (the embedded built-ins).

use std::sync::Arc;

use permitlayer_connectors::{ConnectorDef, ConnectorRegistry};

/// A connector registry over the embedded built-in defs (real Google
/// upstreams). Use for tests that construct a `ProxyService` but never
/// dispatch upstream.
pub fn default_connector_registry() -> Arc<ConnectorRegistry> {
    Arc::new(ConnectorRegistry::load(None).expect("built-in defs load"))
}

/// Build a connector registry where the named built-in services' defs
/// have their `base_url` (and `allowed_hosts`) replaced by the given
/// mock URLs — a 1:1 replacement for the old `base_urls` map.
///
/// `overrides` is a list of `(bare_service_name, base_url)` pairs, e.g.
/// `[("gmail", "http://127.0.0.1:1234/")]`. The bare name is mapped to
/// the canonical connector id (`gmail` → `google-gmail`). Services not
/// overridden keep their embedded (real-Google) upstream.
pub fn connector_registry_with(overrides: &[(&str, &str)]) -> Arc<ConnectorRegistry> {
    fn id_for(svc: &str) -> &str {
        match svc {
            "gmail" => "google-gmail",
            "calendar" => "google-calendar",
            "drive" => "google-drive",
            other => other,
        }
    }
    let base = ConnectorRegistry::load(None).expect("built-in defs load");
    let defs: Vec<ConnectorDef> = base
        .snapshot()
        .values()
        .map(|c| {
            let mut def = c.def.clone();
            if let Some((_, url)) =
                overrides.iter().find(|(svc, _)| id_for(svc) == def.connector.id)
            {
                let parsed = url::Url::parse(url).expect("override base_url parses");
                if let Some(host) = parsed.host_str() {
                    def.upstream.allowed_hosts = vec![host.to_owned()];
                }
                def.upstream.base_url = parsed;
            }
            def
        })
        .collect();
    Arc::new(ConnectorRegistry::from_defs(defs))
}

/// Test-side replica of `ProxyService::legacy_connection_id_for_service`
/// (Story 11.10). These integration tests construct `ProxyService` WITHOUT
/// wiring binding stores, so the proxy resolves the connection id from the
/// bare `service` string via that private fallback. The fallback is private
/// to the lib, so its byte-identical derivation is replicated here for the
/// mocks to seed credentials under the same `(ConnectionId, Slot)` key the
/// request path reads. Deleted when these tests seed real bindings.
#[must_use]
pub fn legacy_connection_id_for_service(service: &str) -> permitlayer_credential::ConnectionId {
    use sha2::{Digest, Sha256};
    const SHIM_DOMAIN: &[u8] = b"permitlayer-connectionid-shim-v1:";
    let mut hasher = Sha256::new();
    hasher.update(SHIM_DOMAIN);
    hasher.update(service.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    permitlayer_credential::ConnectionId::from_bytes(bytes)
}

/// Test-side replica of the proxy's former
/// `conn_shim::connection_slot_for_service_key` (Story 11.10): decompose a
/// legacy `service` key (`gmail`, `gmail-refresh`, `gmail-client`) into
/// `(ConnectionId, Slot)` using [`legacy_connection_id_for_service`].
#[must_use]
pub fn legacy_connection_slot_for_service_key(
    service_key: &str,
) -> (permitlayer_credential::ConnectionId, permitlayer_credential::Slot) {
    use permitlayer_credential::Slot;
    let (base, slot) = if let Some(b) = service_key.strip_suffix("-refresh") {
        (b, Slot::Refresh)
    } else if let Some(b) = service_key.strip_suffix("-client") {
        (b, Slot::Client)
    } else {
        (service_key, Slot::Access)
    };
    (legacy_connection_id_for_service(base), slot)
}
