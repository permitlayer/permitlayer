//! Connection identity + credential slot — the crypto-v2 keying domain
//! (Epic 11, Story 11.8).
//!
//! Replaces the overloaded `service` string (with its `-refresh` /
//! `-client` suffixes) as the vault's keying material. A sealed credential
//! is keyed on `(ConnectionId, Slot)`:
//!
//! - [`ConnectionId`] — a 16-byte ULID identifying ONE connection (one
//!   upstream account on one connector). Minted by the `ConnectionStore`
//!   (Story 11.9); parsed back from its canonical 26-char text form via
//!   [`ConnectionId::from_ulid_str`].
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

    /// Generate a fresh random `ConnectionId` (the 16-byte ULID value
    /// space; this constructor fills all 128 bits from the OS RNG rather
    /// than splitting timestamp/randomness, which is sufficient for a
    /// collision-free unique identifier). Used by the `ConnectionStore`
    /// (Story 11.9 / `connection add` in 11.13) to mint one id per
    /// connection.
    ///
    /// `OsRng` panics on entropy failure — the same fail-stop policy the
    /// vault uses for nonce generation (OS RNG failure is catastrophic
    /// and non-recoverable).
    #[must_use]
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Parse a `ConnectionId` from its canonical 26-character Crockford
    /// base32 ULID text form (the inverse of [`Display`]). Used by the
    /// `CredentialStore` to recover ids from `<ulid>-<slot>.sealed`
    /// filenames and by `connection inspect`/CLI selectors (Story 11.13).
    ///
    /// Returns `None` if `s` is not exactly 26 chars, contains a character
    /// outside the Crockford alphabet (no `I`/`L`/`O`/`U`; uppercase only),
    /// or is non-canonical — a leading char > `7` would overflow the 128-bit
    /// value (the top char carries only 2 meaningful bits), so it is
    /// rejected rather than silently truncated. This guarantees the
    /// round-trip invariant `from_ulid_str(s).map(|id| id.to_string()) ==
    /// Some(s)` for every accepted `s`.
    #[must_use]
    pub fn from_ulid_str(s: &str) -> Option<Self> {
        if s.len() != 26 {
            return None;
        }
        let mut value: u128 = 0;
        for (pos, &b) in s.as_bytes().iter().enumerate() {
            let digit = match b {
                b'0'..=b'9' => b - b'0',
                b'A'..=b'H' => b - b'A' + 10,
                b'J' | b'K' => b - b'J' + 18,
                b'M' | b'N' => b - b'M' + 20,
                b'P'..=b'T' => b - b'P' + 22,
                b'V'..=b'Z' => b - b'V' + 27,
                _ => return None,
            };
            // 26 base32 chars encode 130 bits but a ConnectionId is only
            // 128: the LEADING char carries just 2 meaningful bits (its
            // top 3 are unused), so the canonical leading digit is 0..=7.
            // F5 fix (review 2026-06-07): reject any leading digit > 7 —
            // otherwise `value = (value << 5) | digit` would silently
            // truncate the overflowing bits via u128 wraparound, aliasing a
            // non-canonical string (e.g. "8ZZ…") onto the SAME id as its
            // canonical form ("0ZZ…") and breaking the round-trip invariant
            // `from_ulid_str(s).map(to_string) == Some(s)`. The 25 trailing
            // chars use all 5 bits, so only `pos == 0` is constrained.
            if pos == 0 && digit > 0x07 {
                return None;
            }
            value = (value << 5) | u128::from(digit);
        }
        Some(Self(value.to_be_bytes()))
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

impl Slot {
    /// Parse a slot from its [`label`](Slot::label) text form (the
    /// inverse of `label()`). Used by the `CredentialStore` to recover the
    /// slot from a `<ulid>-<slot>.sealed` filename.
    #[must_use]
    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "access" => Some(Slot::Access),
            "refresh" => Some(Slot::Refresh),
            "client" => Some(Slot::Client),
            _ => None,
        }
    }
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
    fn generate_produces_distinct_ids() {
        // Two fresh ids are distinct with overwhelming probability
        // (128-bit random space). A collision here is a ~2^-128 event,
        // so a single inequality is a sound smoke test.
        assert_ne!(ConnectionId::generate(), ConnectionId::generate());
    }

    #[test]
    fn from_ulid_str_round_trips_display() {
        let id = ConnectionId::from_bytes([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ]);
        let text = id.to_string();
        let parsed = ConnectionId::from_ulid_str(&text).expect("canonical ULID parses");
        assert_eq!(parsed, id);
        // A freshly generated id also survives the text round-trip.
        let fresh = ConnectionId::generate();
        assert_eq!(ConnectionId::from_ulid_str(&fresh.to_string()), Some(fresh));
    }

    #[test]
    fn from_ulid_str_rejects_malformed() {
        assert_eq!(ConnectionId::from_ulid_str(""), None);
        assert_eq!(ConnectionId::from_ulid_str("tooshort"), None);
        // 26 chars but an out-of-alphabet letter (I/L/O/U excluded).
        assert_eq!(ConnectionId::from_ulid_str("0000000000000000000000000I"), None);
        // 27 chars.
        assert_eq!(ConnectionId::from_ulid_str("000000000000000000000000000"), None);
    }

    #[test]
    fn from_ulid_str_rejects_non_canonical_leading_char() {
        // F5: the leading char carries only 2 meaningful bits, so a
        // canonical leading digit is 0..=7. A leading digit > 7 (e.g. '8',
        // or letters which map to >=10) would overflow 128 bits and alias
        // onto a canonical id; it must be REJECTED, not silently truncated.
        let trailing = "Z".repeat(25);
        // '0'..='7' are the only valid leading chars.
        assert!(ConnectionId::from_ulid_str(&format!("7{trailing}")).is_some());
        for bad_lead in ['8', '9', 'A', 'Z'] {
            assert_eq!(
                ConnectionId::from_ulid_str(&format!("{bad_lead}{trailing}")),
                None,
                "leading '{bad_lead}' must be rejected (non-canonical / overflows 128 bits)"
            );
        }
    }

    #[test]
    fn from_ulid_str_round_trip_invariant_holds_for_all_accepted() {
        // F5: every string from_ulid_str ACCEPTS must round-trip through
        // Display unchanged — proving no non-canonical aliasing remains.
        for _ in 0..256 {
            let id = ConnectionId::generate();
            let text = id.to_string();
            let parsed = ConnectionId::from_ulid_str(&text).expect("canonical parses");
            assert_eq!(parsed.to_string(), text, "round-trip must be exact");
        }
        // And the historically-aliasing pair no longer both parse: only
        // the canonical "0ZZ…" is accepted; "8ZZ…" is rejected.
        let canonical = format!("0{}", "Z".repeat(25));
        let non_canonical = format!("8{}", "Z".repeat(25));
        assert!(ConnectionId::from_ulid_str(&canonical).is_some());
        assert_eq!(ConnectionId::from_ulid_str(&non_canonical), None);
    }

    #[test]
    fn slot_from_label_round_trips() {
        for slot in [Slot::Access, Slot::Refresh, Slot::Client] {
            assert_eq!(Slot::from_label(slot.label()), Some(slot));
        }
        assert_eq!(Slot::from_label("nope"), None);
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
}
