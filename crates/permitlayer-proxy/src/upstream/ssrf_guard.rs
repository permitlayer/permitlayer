//! Per-call resolved-host SSRF guard for upstream connector dispatch
//! (Story 11.6, FR91 / NFR52).
//!
//! Runs inside [`crate::upstream::http_client::UpstreamClient::dispatch`]
//! after `base_url.join(path)`, before any bytes leave the process.
//! Two layers:
//!
//! 1. **All connectors — host allowlist (FR91).** The resolved URL's
//!    host must be in the connector's `allowed_hosts`. A connector
//!    `base_url` + a crafted path (e.g. a `@evil.com` userinfo or a
//!    scheme-relative escape) that changes the resolved host is rejected,
//!    default-deny.
//! 2. **Host-installed connectors — range + scheme denial (NFR52).** A
//!    `HostInstalled` connector must use `https` and must not resolve (as
//!    an IP literal) to a loopback / link-local / metadata / all-zeros /
//!    RFC1918-private / IPv6-ULA address — unless `allow_private_upstream`
//!    is set (the `--allow-private-upstream` escape hatch). `BuiltIn`
//!    connectors are unaffected beyond layer 1.
//!
//! **Scope (matches the existing plugin blocklist posture):** the IP
//! range checks are **IP-literal** on the resolved host. Full
//! DNS-resolution SSRF — a domain in `allowed_hosts` that resolves to a
//! private IP — is the documented deferred area; the host allowlist
//! (layer 1, default-deny) is the primary host defense, and built-in
//! `allowed_hosts` are validated at load (Story 11.3).

use std::net::{Ipv4Addr, Ipv6Addr};

use permitlayer_connectors::TrustTier;

use crate::error::ProxyError;
use crate::plugin_host_services::ssrf_blocklist;

/// The per-call SSRF inputs bundled for [`crate::upstream::UpstreamClient::dispatch`]:
/// the connector's host allowlist, its trust tier, and the operator's
/// `--allow-private-upstream` escape hatch. Borrowed (`&[String]`) so no
/// allocation per dispatch.
#[derive(Debug, Clone, Copy)]
pub struct UpstreamGuard<'a> {
    /// The connector's mandatory host allowlist.
    pub allowed_hosts: &'a [String],
    /// The connector's trust tier (gates the host-installed strict rules).
    pub trust_tier: TrustTier,
    /// Operator escape hatch — allow http + private ranges for
    /// host-installed connectors. Default `false`.
    pub allow_private_upstream: bool,
}

/// Check the resolved upstream `url` against the connector's SSRF policy.
///
/// `service` is the bare label for error/audit attribution. `trust_tier`
/// gates the stricter host-installed rules. `allow_private_upstream` is
/// the operator escape hatch (default `false`).
///
/// # Errors
///
/// [`ProxyError::UpstreamHostBlocked`] if the resolved host is outside
/// `allowed_hosts`, or (host-installed) the URL is non-https or hits a
/// denied IP range without the escape hatch.
pub fn check_upstream(
    service: &str,
    url: &url::Url,
    allowed_hosts: &[String],
    trust_tier: TrustTier,
    allow_private_upstream: bool,
) -> Result<(), ProxyError> {
    // Layer 1 — host allowlist (all connectors, default-deny).
    let host = url.host_str().ok_or_else(|| ProxyError::UpstreamHostBlocked {
        service: service.to_owned(),
        reason: "resolved URL has no host".to_owned(),
    })?;
    if !allowed_hosts.iter().any(|h| h == host) {
        return Err(ProxyError::UpstreamHostBlocked {
            service: service.to_owned(),
            reason: format!("resolved host `{host}` is not in the connector's allowed_hosts"),
        });
    }

    // Layer 2 — host-installed strictness (NFR52).
    if trust_tier == TrustTier::HostInstalled && !allow_private_upstream {
        if url.scheme() != "https" {
            return Err(ProxyError::UpstreamHostBlocked {
                service: service.to_owned(),
                reason: format!(
                    "host-installed connector must use https (got `{}`); pass --allow-private-upstream to override",
                    url.scheme()
                ),
            });
        }
        if let Some(reason) = denied_private_range(url) {
            return Err(ProxyError::UpstreamHostBlocked {
                service: service.to_owned(),
                reason: format!(
                    "host-installed connector resolves to a denied range ({reason}); pass --allow-private-upstream to override"
                ),
            });
        }
    }

    Ok(())
}

/// Return `Some(reason)` if the URL's host is an IP literal in a denied
/// range for host-installed connectors. This is the existing
/// loopback/link-local/metadata/all-zeros blocklist, extended with
/// RFC1918 private and IPv6 ULA ranges — which the plugin blocklist
/// deliberately allows, but host-installed upstreams must not reach by
/// default.
fn denied_private_range(url: &url::Url) -> Option<&'static str> {
    // Reuse the shared loopback/link-local/metadata/all-zeros literal set.
    if ssrf_blocklist::is_blocked_destination(url).is_some() {
        return Some("loopback/link-local/metadata");
    }
    match url.host()? {
        url::Host::Ipv4(ip) => is_private_ipv4(ip).then_some("rfc1918-private"),
        url::Host::Ipv6(ip) => is_ula_ipv6(ip).then_some("ipv6-ula"),
        url::Host::Domain(_) => None,
    }
}

/// RFC 1918 private IPv4 ranges: `10/8`, `172.16/12`, `192.168/16`.
fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
}

/// IPv6 Unique Local Address space `fc00::/7`.
fn is_ula_ipv6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn url(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    const GMAIL_HOSTS: &[&str] = &["gmail.googleapis.com"];

    fn hosts(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn host_in_allowlist_passes_for_builtin() {
        // AC #1, #5.
        let u = url("https://gmail.googleapis.com/gmail/v1/users/me/messages");
        assert!(
            check_upstream("gmail", &u, &hosts(GMAIL_HOSTS), TrustTier::BuiltIn, false).is_ok()
        );
    }

    #[test]
    fn host_not_in_allowlist_is_blocked() {
        // AC #1.
        let u = url("https://evil.example.com/x");
        let err = check_upstream("gmail", &u, &hosts(GMAIL_HOSTS), TrustTier::BuiltIn, false)
            .unwrap_err();
        assert!(matches!(err, ProxyError::UpstreamHostBlocked { .. }));
        assert_eq!(err.error_code(), "upstream.host_blocked");
    }

    #[test]
    fn userinfo_host_escape_is_blocked() {
        // AC #2 (FR91): a base_url+path that resolves to `@evil.com`
        // changes the host away from the allowlisted one → blocked.
        let u = url("https://gmail.googleapis.com@evil.com/path");
        // The resolved host is evil.com, not gmail.googleapis.com.
        assert_eq!(u.host_str(), Some("evil.com"));
        let err = check_upstream("gmail", &u, &hosts(GMAIL_HOSTS), TrustTier::BuiltIn, false)
            .unwrap_err();
        assert!(matches!(err, ProxyError::UpstreamHostBlocked { .. }));
    }

    #[test]
    fn host_installed_private_ip_denied_by_default() {
        // AC #3. The host is the (allowlisted) IP literal itself.
        for (addr, _why) in [
            ("https://127.0.0.1/x", "loopback"),
            ("https://169.254.169.254/x", "metadata"),
            ("https://10.0.0.5/x", "rfc1918"),
            ("https://192.168.1.1/x", "rfc1918"),
            ("https://172.16.0.1/x", "rfc1918"),
        ] {
            let u = url(addr);
            let host = u.host_str().unwrap().to_owned();
            let err =
                check_upstream("acme", &u, &[host], TrustTier::HostInstalled, false).unwrap_err();
            assert!(
                matches!(err, ProxyError::UpstreamHostBlocked { .. }),
                "{addr} should be denied for host-installed"
            );
        }
    }

    #[test]
    fn host_installed_private_ip_allowed_with_flag() {
        // AC #3 escape hatch.
        let u = url("https://10.0.0.5/x");
        assert!(
            check_upstream("acme", &u, &["10.0.0.5".to_owned()], TrustTier::HostInstalled, true)
                .is_ok()
        );
    }

    #[test]
    fn host_installed_http_denied_unless_flag() {
        // AC #4.
        let u = url("http://api.acme.com/x");
        let err = check_upstream(
            "acme",
            &u,
            &["api.acme.com".to_owned()],
            TrustTier::HostInstalled,
            false,
        )
        .unwrap_err();
        assert!(matches!(err, ProxyError::UpstreamHostBlocked { .. }));
        // With the flag, http is allowed.
        assert!(
            check_upstream(
                "acme",
                &u,
                &["api.acme.com".to_owned()],
                TrustTier::HostInstalled,
                true
            )
            .is_ok()
        );
    }

    #[test]
    fn builtin_unaffected_by_range_and_scheme_rules() {
        // AC #5: a BuiltIn connector is only subject to layer 1. An http
        // built-in URL (hypothetical) or a private IP passes as long as
        // the host is allowlisted — the strict rules are host-installed
        // only. (Built-ins ship https google hosts in practice.)
        let u = url("http://10.0.0.5/x");
        assert!(
            check_upstream("x", &u, &["10.0.0.5".to_owned()], TrustTier::BuiltIn, false).is_ok()
        );
    }

    #[test]
    fn ipv6_ula_denied_for_host_installed() {
        let u = url("https://[fd00::1]/x");
        let host = u.host_str().unwrap().to_owned();
        let err = check_upstream("acme", &u, &[host], TrustTier::HostInstalled, false).unwrap_err();
        assert!(matches!(err, ProxyError::UpstreamHostBlocked { .. }));
    }
}
