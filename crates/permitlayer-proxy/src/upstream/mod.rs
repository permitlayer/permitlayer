//! Upstream HTTP dispatch for proxied API calls.

pub mod http_client;

pub use http_client::{MAX_ATTACHMENT_BODY, MAX_RESPONSE_BODY, UpstreamClient, UpstreamResponse};
