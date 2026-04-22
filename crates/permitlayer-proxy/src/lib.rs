//! Tower middleware chain and transport adapters for permitlayer.
//!
//! Hosts `Proxy::handle(ProxyRequest) -> ProxyResponse` plus the middleware
//! stack (kill switch, auth, agent identity, policy, audit, trace) and the
//! MCP/REST transport adapters. Implementation lands across Epics 1-3.

#![forbid(unsafe_code)]

pub mod error;
pub mod middleware;
pub mod plugin_host_services;
pub mod refresh_flow;
pub mod request;
pub mod response;
pub mod service;
pub mod token;
pub mod transport;
pub mod upstream;

pub use error::ProxyError;
pub use plugin_host_services::ProxyHostServices;
pub use request::ProxyRequest;
pub use response::ProxyResponse;
pub use service::ProxyService;
pub use token::ScopedTokenIssuer;
