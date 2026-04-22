//! Transport adapters: MCP (Streamable HTTP) and REST.
//!
//! Both transports share the same `ProxyService::handle` core — the MCP
//! adapter builds `ProxyRequest` from MCP tool calls, the REST adapter
//! builds `ProxyRequest` from axum HTTP requests.

pub mod mcp;
pub mod rest;
