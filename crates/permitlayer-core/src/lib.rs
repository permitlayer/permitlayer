//! Core traits and types for permitlayer.
//!
//! This crate hosts the storage abstraction, policy engine, scrubbing engine,
//! audit log, agent identity registry, and kill switch. Domain modules land
//! across Stories 1.3-4.x.

#![forbid(unsafe_code)]

pub mod agent;
pub mod audit;
pub mod error;
pub mod killswitch;
pub mod policy;
pub mod scrub;
pub mod store;

pub use error::CoreError;
