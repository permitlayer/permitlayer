//! Core traits and types for permitlayer.
//!
//! This crate hosts the storage abstraction, policy engine, scrubbing engine,
//! audit log, agent identity registry, and kill switch. Domain modules land
//! across Stories 1.3-4.x.

#![forbid(unsafe_code)]

// Story 7.11 review-round-2 Q3: production RELEASE builds MUST NOT
// enable the `test-seam` feature. The seam exposes fault-injection
// helpers (e.g. `agent_fs::test_seam::RenameFailGuard`) that are
// gated on `cfg(any(test, all(feature = "test-seam", debug_assertions)))`.
// Release-mode `cargo build --features test-seam` would otherwise
// compile production binaries with the injection branch live. This
// compile-time guard makes the "release builds cannot reach the
// failure-injection branch" claim mechanically enforced rather than
// aspirational.
//
// Story 7.11 review-round-3 #4: this gate catches `--release` only.
// A debug build with `--features test-seam` still compiles. That's
// intentional — debug-with-feature is the canonical workflow for
// running integration tests across crates that import from a feature-
// gated seam. The runtime defense for "debug binary accidentally
// shipped to production" is a `tracing::warn!` at daemon boot when
// the seam is compiled in (see `permitlayer-daemon::cli::start::run`)
// plus the `debug_assertions` gate on the seam itself, which
// effectively requires both `--features test-seam` AND `debug` AND
// for the binary to be running with debug_assertions enabled. A
// release-profile binary cannot activate the seam regardless of
// feature flag — that's the load-bearing invariant.
#[cfg(all(feature = "test-seam", not(debug_assertions)))]
compile_error!(
    "the `test-seam` feature must NOT be enabled in release builds. \
     If you need to run integration tests against this crate, build \
     with `cargo test --features test-seam` (debug profile) instead."
);

pub mod agent;
pub mod audit;
pub mod error;
pub mod files;
pub mod killswitch;
pub mod paths;
pub mod policy;
pub mod scrub;
pub mod store;
pub mod vault;

pub use error::CoreError;
pub use vault::lock::{VaultLock, VaultLockError};
