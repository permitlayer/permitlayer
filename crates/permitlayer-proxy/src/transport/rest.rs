//! REST transport adapter.
//!
//! This module re-exports `ProxyService::into_router()` from Story 1.10.
//! REST and MCP share the same `ProxyService::handle` core — MCP tools
//! call `handle()` directly, REST routes call `handle()` via the existing
//! `proxy_handler`. No code duplication.

pub use crate::service::ProxyService;
