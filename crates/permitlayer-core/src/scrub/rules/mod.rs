//! Built-in scrub rule pack.
//!
//! Compiled-in rules for detecting and redacting OTP codes, password reset
//! URLs, bearer tokens, JWTs, and common PII types. These rules are
//! tamper-resistant — they cannot be modified without replacing the binary.

mod bearer;
mod otp;
mod pii;
mod reset_link;

use std::sync::LazyLock;

use super::rule::ScrubRule;

// Re-export Luhn check for post-filter use by consumers of the rule pack.
pub use pii::luhn_check;

/// Compiled-in rule set, allocated exactly once via `LazyLock`.
///
/// Order: OTP → reset-link → bearer → PII (stable across calls).
///
/// # Panics
///
/// The lazy initializer panics if any built-in regex fails to compile.
/// This is a programmer error — all patterns are validated by the
/// `builtin_rules_stable_nonempty` unit test.
static BUILTIN_RULES: LazyLock<Vec<ScrubRule>> = LazyLock::new(|| {
    let mut rules = Vec::new();
    rules.extend(otp::otp_rules());
    rules.extend(reset_link::reset_link_rules());
    rules.extend(bearer::bearer_rules());
    rules.extend(pii::pii_rules());
    rules
});

/// Returns a reference to the compiled built-in scrub rules.
///
/// The slice is initialized at most once and reused on every subsequent call.
#[must_use]
pub fn builtin_rules() -> &'static [ScrubRule] {
    &BUILTIN_RULES
}
