//! Sequencing bridge — `service` string -> `(ConnectionId, Slot)`.
//! Story 11.9 deleted the public bridge in permitlayer-credential; the
//! control-plane seal API still holds a bare `service` string until
//! Story 11.12 reshapes it to take connection_id + slot. This local shim
//! reproduces the byte-identical derivation so the gate stays green and
//! credentials round-trip with the proxy (which has the same shim).
//! DELETED by Story 11.12 (control-plane) / confirmed gone by 11.16 sweep.
use permitlayer_credential::{ConnectionId, Slot};

pub fn connection_id_for_service(service: &str) -> ConnectionId {
    use sha2::{Digest, Sha256};
    const SHIM_DOMAIN: &[u8] = b"permitlayer-connectionid-shim-v1:";
    let mut hasher = Sha256::new();
    hasher.update(SHIM_DOMAIN);
    hasher.update(service.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    ConnectionId::from_bytes(bytes)
}

pub fn connection_slot_for_service_key(service_key: &str) -> (ConnectionId, Slot) {
    let (base, slot) = if let Some(b) = service_key.strip_suffix("-refresh") {
        (b, Slot::Refresh)
    } else if let Some(b) = service_key.strip_suffix("-client") {
        (b, Slot::Client)
    } else {
        (service_key, Slot::Access)
    };
    (connection_id_for_service(base), slot)
}
