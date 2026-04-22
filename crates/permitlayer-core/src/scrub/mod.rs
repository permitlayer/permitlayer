//! Content scrubbing engine with two-pass pattern matching.
//!
//! # Two-pass architecture (Decision 5C)
//!
//! Running every regex rule against every byte of input is O(n * r) where
//! n is input length and r is rule count. This module uses a two-pass
//! design to achieve O(n) scanning regardless of rule count:
//!
//! # Audit payload (Story 2.6, schema v2)
//!
//! When the proxy writes an audit event after scrubbing a response, the
//! `extra.scrub_events` field carries a `{summary, samples}` object:
//!
//! ```jsonc
//! {
//!   "scrub_events": {
//!     "summary": { "otp-6digit": 1 },
//!     "samples": [
//!       {
//!         "rule": "otp-6digit",
//!         "snippet": "Your verification code is <REDACTED_OTP>",
//!         "placeholder_offset": 26,
//!         "placeholder_len": 14
//!       }
//!     ]
//!   }
//! }
//! ```
//!
//! `samples` is bounded to 3 entries × ±48-byte windows (~110 bytes
//! each, ~330 bytes total) so JSONL line size stays predictable.
//! Every `snippet` is sliced from [`ScrubResult::output`] — the
//! already-scrubbed text — so no raw sensitive content can leak into
//! the audit log through this field. The scrub-before-log pass in
//! [`crate::audit::writer`] is a no-op on samples for the same reason.
//!
//! **Pass 1 — Aho-Corasick literal scan:** All literal prefixes/keywords
//! from every registered [`ScrubRule`] are compiled into a single
//! [`aho_corasick::AhoCorasick`] automaton. This automaton scans the
//! input in a single O(n) pass, identifying candidate regions where
//! sensitive content *might* exist. For inputs with no sensitive content
//! (the common case), only this pass runs.
//!
//! **Pass 2 — Regex confirmation:** For each Aho-Corasick hit, the
//! corresponding rule's [`regex::Regex`] is applied to a bounded window
//! (512 bytes) around the hit location. Only confirmed matches are
//! replaced with typed [`Placeholder`] values.
//!
//! # Overlap resolution
//!
//! When multiple rules match overlapping regions, the engine resolves
//! deterministically: longest match wins. On ties (same span length),
//! the rule with the lower index (earlier in the rules list) wins.
//!
//! # Concurrency
//!
//! [`ScrubEngine`] is immutable after construction and implements
//! `Send + Sync`. The expected usage is `Arc<ScrubEngine>` shared
//! across concurrent request handlers.

pub mod engine;
pub mod error;
pub mod placeholder;
pub mod rule;
pub mod rules;

pub use engine::{ScrubEngine, ScrubMatch, ScrubResult, ScrubSample};
pub use error::ScrubError;
pub use placeholder::Placeholder;
pub use rule::ScrubRule;
pub use rules::{builtin_rules, luhn_check};
