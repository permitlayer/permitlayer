//! Policy engine — compiled IR + evaluator for `~/.agentsso/policies/*.toml`.
//!
//! This module owns the Story 4.1 scope: TOML schema types, the
//! compile step that turns `[[policies]]` arrays into a `PolicySet` IR,
//! and the fail-closed `PolicySet::evaluate` entry point. Stories 4.2+
//! add hot-swap reload (`engine.rs`, `reload.rs`) and wire the IR into
//! the tower middleware chain.
//!
//! # Layering
//!
//! - `schema.rs` — `#[derive(serde::Deserialize)]` types that shape
//!   raw TOML text. No semantics beyond structural validation.
//! - `compile.rs` — `PolicySet`, `CompiledPolicy`, `CompiledRule`, and
//!   `ResourceMatcher` IR types plus the `compile_from_str` /
//!   `compile_from_dir` entry points. Does all semantic validation
//!   (duplicate detection, scope-format checks, empty-array refusal).
//! - `eval.rs` — `EvalRequest`, `Decision` (the public return type),
//!   and `PolicySet::evaluate` implementation. No state beyond the
//!   IR snapshot the caller hands in.
//! - `error.rs` — `PolicyCompileError` surfaced by the load path.
//!
//! # Default-deny invariant
//!
//! Every branch of `PolicySet::evaluate` that does not explicitly
//! return `Allow` or `Prompt` returns `Deny`. A missing policy, a
//! scope outside the allowlist, and a resource outside the allowlist
//! all produce `Deny` variants with stable `rule_id` strings so
//! Story 4.3's `PolicyLayer` can surface the specific reason in HTTP
//! 403 response bodies. Unknown branches never return `Allow`.

pub mod compile;
pub mod error;
pub mod eval;
pub mod schema;

pub use compile::{
    CompiledPolicy, CompiledRule, PolicySet, PolicySetDiff, ResourceMatcher, RuleAction,
};
pub use error::PolicyCompileError;
pub use eval::{ApprovalMode, Decision, EvalRequest};
