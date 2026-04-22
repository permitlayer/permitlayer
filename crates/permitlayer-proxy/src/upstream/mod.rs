//! Upstream HTTP dispatch for proxied API calls.

pub mod http_client;

pub use http_client::{UpstreamClient, UpstreamResponse};
