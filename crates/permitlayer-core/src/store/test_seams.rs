//! Test seam for the `AgentIdentityStore` trait.
//!
//! Records `put` / `touch_last_seen` invocations for assertion in unit
//! tests. Gated behind the `test-seam` feature (also accessible via
//! `#[cfg(test)]` within `permitlayer-core` itself).
//!
//! If you need this from another crate, add
//! `permitlayer-core = { ..., features = ["test-seam"] }` to that
//! crate's `[dev-dependencies]`.
//!
//! # Construction-site invariant
//!
//! `MockAgentStore` is the ONLY type in this module. Future test-seams
//! for `CredentialStore` or `AuditStore` should live here too so that
//! inter-crate test helpers have a single well-known import path.

#![cfg(any(test, feature = "test-seam"))]
#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use crate::agent::AgentIdentity;
use crate::store::{AgentIdentityStore, StoreError};

/// In-memory no-op `AgentIdentityStore` for tests that exercise the
/// last-seen-at update path. All writes succeed silently; `get` always
/// returns `None`; `list` always returns `[]`; `remove` always returns
/// `false`. Only `touch_last_seen` records the identity name so callers
/// can assert the method was invoked.
#[derive(Default, Clone)]
pub struct MockAgentStore {
    pub touched: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl AgentIdentityStore for MockAgentStore {
    async fn put(&self, _identity: AgentIdentity) -> Result<(), StoreError> {
        Ok(())
    }

    async fn get(&self, _name: &str) -> Result<Option<AgentIdentity>, StoreError> {
        Ok(None)
    }

    async fn list(&self) -> Result<Vec<AgentIdentity>, StoreError> {
        Ok(vec![])
    }

    async fn remove(&self, _name: &str) -> Result<bool, StoreError> {
        Ok(false)
    }

    async fn touch_last_seen(&self, identity: AgentIdentity) -> Result<(), StoreError> {
        self.touched.lock().unwrap().push(identity.name().to_owned());
        Ok(())
    }
}
