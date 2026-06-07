//! Shared `(agent, selector) → binding` matcher (Story 11.10).
//!
//! Two call sites need the SAME binding match, with the SAME precedence,
//! against the SAME stores:
//!
//! - [`AuthService`](crate::middleware::auth) (middleware) — resolves the
//!   binding so it can stamp the binding's `policy` into the
//!   `AgentPolicyBinding` request extension, making the binding's policy
//!   visible to `PolicyLayer` + the approval engine (which run BEFORE the
//!   proxy service). A miss stamps an empty policy and lets `handle_inner`
//!   produce the authoritative `binding.not_found` 403 — the deny stays in
//!   one place.
//! - [`ProxyService::resolve_connection`](crate::service) (service) — the
//!   authoritative resolver that also runs the tier ∩ granted-scope gate
//!   and returns the `ConnectionId` used for credential keying.
//!
//! Factoring the match here keeps the precedence (alias → connection name
//! → id text) and the Revoked-skip identical across both, so the policy
//! the middleware stamps always describes the binding `handle_inner` will
//! resolve.

use std::sync::Arc;

use permitlayer_core::store::binding::Binding;
use permitlayer_core::store::connection::{ConnectionRecord, ConnectionStatus};
use permitlayer_core::store::{BindingStore, ConnectionStore, StoreError};

/// Match precedence for resolving a request `selector` to one of an
/// agent's bindings (Story 11.10): connection `alias`, then connection
/// `name`, then the connection id's canonical text form. Revoked
/// connections never match (default-deny).
///
/// Returns `Ok(Some((binding, connection)))` on a match, `Ok(None)` when
/// the agent holds no live binding addressable by `selector`, or
/// `Err(StoreError)` if a store read fails (the caller maps that to its
/// own error type).
///
/// `bindings` is taken by value so the matched `Binding` can be returned
/// without a clone; callers that need the agent's full set elsewhere
/// should clone before calling.
pub(crate) async fn match_binding(
    bindings: Vec<Binding>,
    connection_store: &Arc<dyn ConnectionStore>,
    selector: &str,
) -> Result<Option<(Binding, ConnectionRecord)>, StoreError> {
    // Pass 1: alias. Only this binding's record is read.
    for b in &bindings {
        if b.alias.as_deref() == Some(selector) {
            if let Some(rec) = connection_store.get(b.connection_id).await?
                && rec.status != ConnectionStatus::Revoked
            {
                return Ok(Some((b.clone(), rec)));
            }
            // An alias hit on an absent/revoked connection does not fall
            // through to name/id matching — the alias is the address.
            return Ok(None);
        }
    }

    // Pass 2: connection name. Pass 3: id text. Both need the record.
    for b in &bindings {
        let Some(rec) = connection_store.get(b.connection_id).await? else {
            continue;
        };
        if rec.status == ConnectionStatus::Revoked {
            continue;
        }
        if rec.name == selector || rec.id.to_string() == selector {
            return Ok(Some((b.clone(), rec)));
        }
    }

    Ok(None)
}

/// Convenience wrapper: load the agent's bindings then [`match_binding`].
/// Returns the matched `(binding, connection)` or `Ok(None)` on a miss.
pub(crate) async fn resolve_agent_binding(
    binding_store: &Arc<dyn BindingStore>,
    connection_store: &Arc<dyn ConnectionStore>,
    agent: &str,
    selector: &str,
) -> Result<Option<(Binding, ConnectionRecord)>, StoreError> {
    let bindings = binding_store.get(agent).await?;
    match_binding(bindings, connection_store, selector).await
}

/// Extract the connection selector from a proxy request path. The
/// selector is the connection address — the first path segment after
/// `/mcp/` or `/v1/tools/` (NOT the lossy `derive_service_and_resource`
/// known-service mapping, since a selector may be an alias, a connection
/// name, or a ULID none of which is a fixed built-in service name).
///
/// Returns `None` for `/mcp` / `/mcp/` (no selector segment) and for any
/// path that does not address a connection.
#[must_use]
pub(crate) fn selector_from_path(path: &str) -> Option<&str> {
    let path = path.split('?').next().unwrap_or("");
    let rest = path.strip_prefix("/mcp/").or_else(|| path.strip_prefix("/v1/tools/"))?;
    let rest = rest.trim_start_matches('/');
    let seg = match rest.find('/') {
        Some(idx) => &rest[..idx],
        None => rest,
    };
    if seg.is_empty() { None } else { Some(seg) }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn selector_from_mcp_and_rest_paths() {
        assert_eq!(selector_from_path("/mcp/gmail"), Some("gmail"));
        assert_eq!(selector_from_path("/mcp/chuck-gmail/users/me"), Some("chuck-gmail"));
        assert_eq!(selector_from_path("/v1/tools/calendar/events"), Some("calendar"));
        assert_eq!(selector_from_path("/v1/tools/drive"), Some("drive"));
        // ULID-style selector survives verbatim (not mapped to a service).
        assert_eq!(
            selector_from_path("/mcp/01ARZ3NDEKTSV4RRFFQ69G5FAV/x"),
            Some("01ARZ3NDEKTSV4RRFFQ69G5FAV")
        );
    }

    #[test]
    fn selector_none_for_bare_and_unaddressed() {
        assert_eq!(selector_from_path("/mcp"), None);
        assert_eq!(selector_from_path("/mcp/"), None);
        assert_eq!(selector_from_path("/healthz"), None);
        assert_eq!(selector_from_path("/v1/control/agent/list"), None);
    }
}
