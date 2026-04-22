//! SSRF defense-in-depth blocklist for `agentsso.http.fetch`.
//!
//! Checks URLs against a hard-coded list of cloud-metadata and loopback
//! IP ranges **before** policy evaluation. This is defense-in-depth: even
//! when `http.allow = ["*"]` permits the request, the blocklist rejects
//! destination IPs that could expose instance metadata credentials.
//!
//! **Scope:** IP-literal checks only (Story 8.3 MVP). Domain-based
//! resolution defense (e.g., `metadata.google.internal`) requires a
//! reqwest resolver hook and is explicitly deferred. An attacker cannot
//! weaponize a domain name without also controlling DNS resolution; the
//! most common attack vector is a hardcoded IP literal.
//!
//! **Blocked ranges:**
//! - `169.254.0.0/16` — link-local (superset of IMDS v1 endpoints for
//!   AWS, GCP, and Azure)
//! - `127.0.0.0/8` — IPv4 loopback
//! - `0.0.0.0` — all-zeros (signals mis-configured or adversarial URL)
//! - `::1` — IPv6 loopback
//! - `fd00:ec2::254` — AWS IMDS v2 over IPv6. **Note:** this is a single
//!   address. AWS routes `fd00:ec2::/32` as its link-local IPv6 space inside
//!   VPCs, but only this specific endpoint is blocked in the MVP; other
//!   addresses within that `/32` are not blocked.
//! - `::ffff:169.254.169.254` — IPv4-mapped form of the primary IMDS addr
//!
//! **Out of scope (RFC 1918 and ULA):** RFC 1918 private ranges
//! (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and IPv6 ULA
//! (`fc00::/7`) are **NOT** blocked. In cloud VPC deployments, internal
//! services are reachable at these addresses and legitimate plugin use
//! cases exist. Domain-resolution-based SSRF (e.g.,
//! `metadata.google.internal`) is also out of scope for the MVP
//! IP-literal-only blocklist.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Reason why a destination was blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReason {
    /// IP falls in `169.254.0.0/16` (link-local / cloud-metadata range).
    LinkLocalOrMetadata,
    /// IPv4 loopback (`127.0.0.0/8`).
    Ipv4Loopback,
    /// `0.0.0.0` exact.
    AllZeros,
    /// IPv6 loopback `::1`.
    Ipv6Loopback,
    /// AWS IMDS v2 over IPv6 (`fd00:ec2::254`).
    AwsIpv6Metadata,
    /// IPv4-mapped form of `169.254.169.254`.
    Ipv4MappedMetadata,
}

impl BlockReason {
    /// Short stable string for the audit event `extra.reason` field.
    pub fn as_audit_reason(&self) -> &'static str {
        match self {
            BlockReason::LinkLocalOrMetadata => "metadata_endpoint_blocklist",
            BlockReason::Ipv4Loopback => "metadata_endpoint_blocklist",
            BlockReason::AllZeros => "metadata_endpoint_blocklist",
            BlockReason::Ipv6Loopback => "metadata_endpoint_blocklist",
            BlockReason::AwsIpv6Metadata => "metadata_endpoint_blocklist",
            BlockReason::Ipv4MappedMetadata => "metadata_endpoint_blocklist",
        }
    }
}

/// Check whether the URL's host resolves to a blocked IP literal.
///
/// Returns `Some(BlockReason)` if the destination is on the blocklist,
/// `None` if the request should proceed.
///
/// Only IP literals are checked — domain names are passed through.
/// See module doc for rationale.
pub fn is_blocked_destination(url: &url::Url) -> Option<BlockReason> {
    match url.host()? {
        url::Host::Ipv4(ip) => is_blocked_ipv4(ip),
        url::Host::Ipv6(ip) => is_blocked_ipv6(ip),
        url::Host::Domain(_) => None,
    }
}

fn is_blocked_ipv4(ip: Ipv4Addr) -> Option<BlockReason> {
    let octets = ip.octets();
    // 169.254.0.0/16 — link-local / cloud-metadata superset
    if octets[0] == 169 && octets[1] == 254 {
        return Some(BlockReason::LinkLocalOrMetadata);
    }
    // 127.0.0.0/8 — loopback
    if octets[0] == 127 {
        return Some(BlockReason::Ipv4Loopback);
    }
    // 0.0.0.0
    if ip == Ipv4Addr::UNSPECIFIED {
        return Some(BlockReason::AllZeros);
    }
    None
}

fn is_blocked_ipv6(ip: Ipv6Addr) -> Option<BlockReason> {
    // ::1 — loopback
    if ip == Ipv6Addr::LOCALHOST {
        return Some(BlockReason::Ipv6Loopback);
    }
    // fd00:ec2::254 — AWS IMDS v2 IPv6
    const AWS_IPV6_IMDS: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);
    if ip == AWS_IPV6_IMDS {
        return Some(BlockReason::AwsIpv6Metadata);
    }
    // ::ffff:169.254.169.254 — IPv4-mapped metadata address
    if let Some(mapped) = ip.to_ipv4_mapped()
        && let Some(reason) = is_blocked_ipv4(mapped)
    {
        return Some(match reason {
            BlockReason::LinkLocalOrMetadata => BlockReason::Ipv4MappedMetadata,
            other => other,
        });
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn url(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    #[test]
    fn blocks_aws_gcp_azure_imds_v1() {
        let u = url("http://169.254.169.254/latest/meta-data/");
        assert!(is_blocked_destination(&u).is_some());
    }

    #[test]
    fn blocks_full_link_local_range() {
        let u = url("http://169.254.0.1/foo");
        assert!(is_blocked_destination(&u).is_some());
        let u2 = url("http://169.254.255.255/foo");
        assert!(is_blocked_destination(&u2).is_some());
    }

    #[test]
    fn blocks_ecs_task_metadata() {
        let u = url("http://169.254.170.2/v2/metadata");
        assert!(is_blocked_destination(&u).is_some());
    }

    #[test]
    fn blocks_aws_ipv6_metadata() {
        let u = url("http://[fd00:ec2::254]/latest/meta-data/");
        assert!(is_blocked_destination(&u).is_some());
    }

    #[test]
    fn blocks_ipv4_loopback() {
        assert!(is_blocked_destination(&url("http://127.0.0.1/foo")).is_some());
        assert!(is_blocked_destination(&url("http://127.1.2.3/foo")).is_some());
    }

    #[test]
    fn blocks_ipv6_loopback() {
        assert!(is_blocked_destination(&url("http://[::1]/foo")).is_some());
    }

    #[test]
    fn blocks_all_zeros() {
        assert!(is_blocked_destination(&url("http://0.0.0.0/foo")).is_some());
    }

    #[test]
    fn blocks_ipv4_mapped_metadata() {
        assert!(is_blocked_destination(&url("http://[::ffff:169.254.169.254]/foo")).is_some());
    }

    #[test]
    fn allows_public_ipv4() {
        assert!(is_blocked_destination(&url("http://8.8.8.8/dns-query")).is_none());
        assert!(is_blocked_destination(&url("http://1.1.1.1/")).is_none());
        assert!(is_blocked_destination(&url("http://192.168.1.1/")).is_none());
    }

    #[test]
    fn allows_public_ipv6() {
        assert!(is_blocked_destination(&url("http://[2001:4860:4860::8888]/")).is_none());
    }

    #[test]
    fn allows_domain_names_not_checked() {
        // Domain names pass through — DNS-resolution-based defense is deferred.
        assert!(is_blocked_destination(&url("http://metadata.google.internal/")).is_none());
        assert!(is_blocked_destination(&url("http://example.com/")).is_none());
    }
}
