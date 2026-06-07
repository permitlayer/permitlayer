//! Connection identity + credential slot — the crypto-v2 keying domain
//! (Epic 11, Story 11.8).
//!
//! Replaces the overloaded `service` string (with its `-refresh` /
//! `-client` suffixes) as the vault's keying material. A sealed credential
//! is keyed on `(ConnectionId, Slot)`:
//!
//! - [`ConnectionId`] — a 16-byte ULID identifying ONE connection (one
//!   upstream account on one connector). Minted by the `ConnectionStore`
//!   in Story 11.9; until then call sites use
//!   [`ConnectionId::from_service_shim`] (see its docs).
//! - [`Slot`] — which credential within the connection: `Access`,
//!   `Refresh`, or `Client`. Each slot derives a DISTINCT subkey under
//!   the same connection (the `-refresh` / `-client` string suffixes are
//!   gone).
//!
//! ## Not credential-secret types
//!
//! `ConnectionId` and `Slot` are **identifiers**, not secret material —
//! so unlike [`crate::OAuthToken`] et al. they freely derive `Copy` /
//! `Eq` / `Hash` / `Debug` / `Display`. The `validate-credentials` xtask
//! guards only the four secret types by name; these are outside that set
//! by design.

use core::fmt;

/// A 16-byte connection identifier (ULID-shaped) — the v2 vault keying
/// root (Story 11.8).
///
/// One `ConnectionId` ⇔ one connection: a single upstream account bound
/// to a single connector. The vault derives a distinct subkey per
/// `(ConnectionId, Slot)`, so two connections' credentials are
/// cryptographically isolated even on the same connector (NFR51).
///
/// The canonical 26-char Crockford-base32 ULID text form is produced by
/// [`Display`]; the raw 16 bytes (used directly in the HKDF `info` / AEAD
/// `aad` domain) come from [`Self::as_bytes`].
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct ConnectionId([u8; 16]);

impl ConnectionId {
    /// Wrap 16 raw bytes as a `ConnectionId`. The bytes are the ULID's
    /// big-endian 128-bit value; this constructor does not interpret or
    /// validate the timestamp/randomness split.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The raw 16 bytes — fed directly into the vault's v2 keying domain
    /// (`b"permitlayer-vault-v2:" || id_bytes || b":" || slot_byte`).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// **11.8→11.9 bridge — deterministic shim from a service name.**
    ///
    /// The real per-connection ULIDs are minted by the `ConnectionStore`
    /// in Story 11.9. Until then, callers that only hold a legacy
    /// `service` string (e.g. `"gmail"`) derive a STABLE id from it so the
    /// vault can key on `(ConnectionId, Slot)` today without inventing the
    /// store early.
    ///
    /// The id is a domain-separated SHA-256 of the service name, truncated
    /// to 16 bytes — a pure function of the input, so it is 1:1 with the
    /// service name. That means cross-connection isolation in 11.8 is the
    /// per-connection analog of today's per-service isolation; true
    /// distinct-account ULIDs arrive with the `ConnectionStore` in 11.9,
    /// which REPLACES every call to this shim.
    ///
    /// The `SHIM_DOMAIN` prefix guarantees a shim id can never collide
    /// with a real ULID's value space by accident in tests that mix both.
    #[doc(hidden)]
    #[must_use]
    pub fn from_service_shim(service: &str) -> Self {
        use sha2::{Digest, Sha256};
        const SHIM_DOMAIN: &[u8] = b"permitlayer-connectionid-shim-v1:";
        let mut hasher = Sha256::new();
        hasher.update(SHIM_DOMAIN);
        hasher.update(service.as_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        Self(bytes)
    }
}

impl fmt::Display for ConnectionId {
    /// Render as a 26-character Crockford-base32 ULID string (uppercase,
    /// no padding) — the canonical text form for logs and the
    /// `connection inspect` surface (Story 11.13).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Crockford base32 alphabet (excludes I, L, O, U).
        const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        // 128 bits → 26 base32 chars (the top char encodes only 2 bits).
        let mut value: u128 = u128::from_be_bytes(self.0);
        let mut buf = [0u8; 26];
        for slot in buf.iter_mut().rev() {
            *slot = ALPHABET[(value & 0x1f) as usize];
            value >>= 5;
        }
        // SAFETY-free: ALPHABET is ASCII, so buf is valid UTF-8.
        f.write_str(core::str::from_utf8(&buf).unwrap_or("<invalid-ulid>"))
    }
}

/// Which credential within a connection a sealed envelope holds
/// (Story 11.8). Each slot derives a distinct vault subkey under the same
/// [`ConnectionId`], replacing the v1 `-refresh` / `-client` service-name
/// suffixes.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Slot {
    /// Short-lived OAuth access token.
    Access,
    /// Long-lived OAuth refresh token.
    Refresh,
    /// Sealed BYO OAuth client bundle (Story 7.35's `{service}-client`).
    Client,
}

impl Slot {
    /// The single domain byte that distinguishes this slot inside the v2
    /// keying domain. Stable on-wire/on-disk values — do NOT renumber
    /// (a change re-keys every existing envelope of that slot).
    #[must_use]
    pub const fn slot_byte(self) -> u8 {
        match self {
            Slot::Access => 0x01,
            Slot::Refresh => 0x02,
            Slot::Client => 0x03,
        }
    }

    /// A short, log-safe label for error/audit messages.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Slot::Access => "access",
            Slot::Refresh => "refresh",
            Slot::Client => "client",
        }
    }
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// **11.8→11.9 bridge — decompose a legacy `service` key string into
/// `(ConnectionId, Slot)`.**
///
/// Pre-v2 call sites encoded the slot as a suffix on the service string:
/// `"gmail"` = access, `"gmail-refresh"` = refresh, `"gmail-client"` =
/// client. This splits that convention back apart so the vault can key on
/// `(ConnectionId, Slot)`:
///
/// - strip a trailing `-refresh` / `-client` to recover the base service,
/// - map the suffix (or its absence) to the [`Slot`],
/// - shim the base service to a [`ConnectionId`] via
///   [`ConnectionId::from_service_shim`].
///
/// Story 11.9 replaces every caller of this with a real store-issued
/// `(ConnectionId, Slot)` and deletes this bridge.
#[doc(hidden)]
#[must_use]
pub fn connection_slot_from_service_key(service_key: &str) -> (ConnectionId, Slot) {
    let (base, slot) = if let Some(b) = service_key.strip_suffix("-refresh") {
        (b, Slot::Refresh)
    } else if let Some(b) = service_key.strip_suffix("-client") {
        (b, Slot::Client)
    } else {
        (service_key, Slot::Access)
    };
    (ConnectionId::from_service_shim(base), slot)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn as_bytes_round_trips_from_bytes() {
        let raw = [7u8; 16];
        let id = ConnectionId::from_bytes(raw);
        assert_eq!(id.as_bytes(), &raw);
    }

    #[test]
    fn from_service_shim_is_deterministic() {
        assert_eq!(
            ConnectionId::from_service_shim("gmail"),
            ConnectionId::from_service_shim("gmail")
        );
    }

    #[test]
    fn from_service_shim_distinguishes_services() {
        assert_ne!(
            ConnectionId::from_service_shim("gmail"),
            ConnectionId::from_service_shim("calendar")
        );
        // The slot suffixes are NOT part of the connection id under v2 —
        // but the shim takes whatever string it's given, so callers must
        // strip the suffix first. These are different inputs → different
        // ids, which is exactly why the caller strips before shimming.
        assert_ne!(
            ConnectionId::from_service_shim("gmail"),
            ConnectionId::from_service_shim("gmail-refresh")
        );
    }

    #[test]
    fn display_is_26_char_crockford_base32() {
        let id = ConnectionId::from_bytes([0u8; 16]);
        let s = id.to_string();
        assert_eq!(s.len(), 26);
        assert_eq!(s, "00000000000000000000000000");
        // All-ones (top 2 bits set on the leading char).
        let id_max = ConnectionId::from_bytes([0xffu8; 16]);
        let s_max = id_max.to_string();
        assert_eq!(s_max.len(), 26);
        assert!(s_max.bytes().all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b)));
    }

    #[test]
    fn slot_bytes_are_distinct_and_stable() {
        assert_eq!(Slot::Access.slot_byte(), 0x01);
        assert_eq!(Slot::Refresh.slot_byte(), 0x02);
        assert_eq!(Slot::Client.slot_byte(), 0x03);
        let all = [Slot::Access, Slot::Refresh, Slot::Client];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.slot_byte(), b.slot_byte());
            }
        }
    }

    #[test]
    fn slot_labels() {
        assert_eq!(Slot::Access.label(), "access");
        assert_eq!(Slot::Refresh.to_string(), "refresh");
        assert_eq!(Slot::Client.label(), "client");
    }

    #[test]
    fn service_key_decomposes_into_connection_and_slot() {
        let (id_access, slot_access) = connection_slot_from_service_key("gmail");
        let (id_refresh, slot_refresh) = connection_slot_from_service_key("gmail-refresh");
        let (id_client, slot_client) = connection_slot_from_service_key("gmail-client");
        // Same base service → same connection id across all three slots.
        assert_eq!(id_access, id_refresh);
        assert_eq!(id_access, id_client);
        assert_eq!(id_access, ConnectionId::from_service_shim("gmail"));
        // Suffix → slot.
        assert_eq!(slot_access, Slot::Access);
        assert_eq!(slot_refresh, Slot::Refresh);
        assert_eq!(slot_client, Slot::Client);
        // A different base service → a different connection id.
        let (id_cal, _) = connection_slot_from_service_key("calendar");
        assert_ne!(id_access, id_cal);
    }
}
