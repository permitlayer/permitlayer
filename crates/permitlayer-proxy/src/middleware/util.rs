//! Shared helpers for the tower middleware chain.
//!
//! This module hosts the small predicates and constants that more than
//! one middleware layer needs to agree on. The motivating example is
//! [`is_operational_path`] — both `AuthLayer` (Story 4.4) and
//! `PolicyLayer` (Story 4.3) bypass the same allowlist of operational
//! endpoints. Keeping the list here is the single source of truth so a
//! future story can't accidentally widen one layer's bypass without
//! widening the other's.

/// Return `true` if the request path is an operational endpoint that
/// should bypass agent authentication AND policy evaluation.
///
/// Operational endpoints are health probes, readiness checks, and
/// loopback-only control-plane routes. Anything not in this allowlist
/// is subject to bearer-token auth (`AuthLayer`) and policy enforcement
/// (`PolicyLayer`) — including unknown / unrouted paths, which fail
/// fast with 401 / 403.
///
/// **Why one allowlist for two layers?** Auth and policy share the
/// same security posture: both must protect every API call to upstream
/// services, neither must protect operational endpoints. Splitting the
/// list would let a future refactor widen one bypass without the
/// other, creating a defense-in-depth gap.
///
/// The query string is stripped defensively before matching.
#[must_use]
pub fn is_operational_path(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or("");
    matches!(
        path,
        "/health"
            | "/v1/health"
            | "/v1/control/kill"
            | "/v1/control/resume"
            | "/v1/control/reload"
            | "/v1/control/state"
            | "/v1/control/agent/register"
            | "/v1/control/agent/list"
            | "/v1/control/agent/remove"
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn health_paths_are_operational() {
        assert!(is_operational_path("/health"));
        assert!(is_operational_path("/v1/health"));
    }

    #[test]
    fn kill_resume_reload_are_operational() {
        assert!(is_operational_path("/v1/control/kill"));
        assert!(is_operational_path("/v1/control/resume"));
        assert!(is_operational_path("/v1/control/reload"));
        assert!(is_operational_path("/v1/control/state"));
    }

    #[test]
    fn agent_control_routes_are_operational() {
        // Story 4.4: the new agent CRUD endpoints are loopback-only
        // and must NOT require bearer-token auth (the operator is the
        // one running `agentsso agent register` to mint the first
        // token).
        assert!(is_operational_path("/v1/control/agent/register"));
        assert!(is_operational_path("/v1/control/agent/list"));
        assert!(is_operational_path("/v1/control/agent/remove"));
    }

    #[test]
    fn tool_routes_are_not_operational() {
        assert!(!is_operational_path("/v1/tools/gmail/users/me/messages"));
        assert!(!is_operational_path("/mcp"));
        assert!(!is_operational_path("/mcp/calendar"));
    }

    #[test]
    fn unknown_paths_are_not_operational() {
        // Defense in depth: unknown means "evaluate, then probably deny."
        assert!(!is_operational_path("/random/path"));
        assert!(!is_operational_path("/admin"));
        assert!(!is_operational_path("/"));
    }

    #[test]
    fn query_string_is_stripped_defensively() {
        // URI::path() already strips the query in production, but
        // is_operational_path defends against direct callers.
        assert!(is_operational_path("/health?foo=bar"));
        assert!(is_operational_path("/v1/control/kill?cause=test"));
        // A query string trick must not let an attacker bypass auth
        // for a tool path.
        assert!(!is_operational_path("/v1/tools/gmail/users?healthy=true"));
    }
}
