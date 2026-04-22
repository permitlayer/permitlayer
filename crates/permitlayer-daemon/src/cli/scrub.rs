//! `agentsso scrub` — inspect the built-in scrub rule pack.
//!
//! Currently implements a single action, `explain`, which describes
//! each built-in rule (what it matches, example input, rationale) and
//! demonstrates the live engine on a known input so users can see the
//! placeholder that the rule produces. The `why? → agentsso scrub
//! explain <rule>` affordance in `ScrubInline` output points here.

use permitlayer_core::scrub::{Placeholder, ScrubEngine, builtin_rules};

use crate::design::render::{error_block, truncate_field};
use crate::design::terminal::{ColorSupport, styled};
use crate::design::theme::Theme;

#[derive(clap::Args, Debug)]
pub struct ScrubArgs {
    #[command(subcommand)]
    pub action: ScrubAction,
}

#[derive(clap::Subcommand, Debug)]
pub enum ScrubAction {
    /// Explain a built-in scrub rule, or `--list` to see all rules.
    Explain {
        /// Rule name (e.g., `otp-6digit`, `reset-link`, `email`).
        /// Omit with `--list` to show every built-in rule.
        rule: Option<String>,

        /// List every built-in rule and its placeholder.
        #[arg(long)]
        list: bool,
    },
}

/// Static description table for every built-in rule.
///
/// Fields: `(rule_name, placeholder, description, example_input, rationale)`.
///
/// `example_input` is passed to the **live** `ScrubEngine` at explain
/// time, so the rendered example is always self-redacted and will
/// surface a test failure if a rule's pattern drifts away from catching
/// its documented example.
type RuleEntry = (&'static str, Placeholder, &'static str, &'static str, &'static str);

const RULE_DESCRIPTIONS: &[RuleEntry] = &[
    (
        "otp-6digit",
        Placeholder::Otp,
        "Six-digit one-time passcode preceded by a context word (\"verification code\", \"passcode\", \"otp\", \"pin\").",
        "Your verification code is 123456",
        "OTPs in an agent's context window let prompt-injection attackers complete sign-ins on the user's behalf.",
    ),
    (
        "otp-8digit",
        Placeholder::Otp,
        "Eight-digit OTP with the same context-word triggers as the 6-digit rule.",
        "Your verification code is 12345678",
        "Some banks and SaaS issuers use 8-digit codes; same attack surface as the 6-digit case.",
    ),
    (
        "reset-link",
        Placeholder::ResetLink,
        "Password-reset URLs from common email providers and SaaS senders.",
        "Click https://accounts.example.com/password/reset?token=abc123 to reset your password",
        "A reset link inside an agent's context is a single-click account takeover.",
    ),
    (
        "bearer",
        Placeholder::Bearer,
        "OAuth2 bearer tokens prefixed with `Bearer `.",
        "Authorization: Bearer ya29.A0AfH6SMBx_abcdef1234567890",
        "Bearer tokens grant API access without further authentication.",
    ),
    (
        "jwt",
        Placeholder::Jwt,
        "JSON Web Tokens (three base64url segments separated by dots).",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        "JWTs often contain sub claims, scopes, and signed assertions that shouldn't leak into agent context.",
    ),
    (
        "email",
        Placeholder::Email,
        "Email addresses (RFC-shaped).",
        "Contact alice@example.com for details",
        "PII baseline. Policies can opt out per-service when email management IS the agent's job.",
    ),
    (
        "phone",
        Placeholder::Phone,
        "US-format phone numbers.",
        "Call 555-123-4567 if you have questions",
        "PII baseline.",
    ),
    (
        "ssn",
        Placeholder::Ssn,
        "US Social Security numbers (NNN-NN-NNNN).",
        "SSN: 123-45-6789",
        "High-impact PII; never belongs in agent context under any policy.",
    ),
    (
        "credit-card",
        Placeholder::CreditCard,
        "Credit card numbers (13-19 digits, Luhn-validated) adjacent to a context word like `card`, `visa`, `mastercard`, or `amex`.",
        "visa 4111 1111 1111 1111",
        "Financial PII and PCI-scope hazard.",
    ),
];

/// Entry point for `agentsso scrub`.
pub fn run(args: ScrubArgs) -> anyhow::Result<()> {
    match args.action {
        ScrubAction::Explain { rule, list } => run_explain(rule.as_deref(), list),
    }
}

fn run_explain(rule: Option<&str>, list_flag: bool) -> anyhow::Result<()> {
    let support = ColorSupport::detect();
    let theme = Theme::default();

    // With --list, show the full list. If a positional rule was ALSO
    // passed AND it's non-empty after trimming, warn that it was
    // ignored (Story 2.7 AC #9 codified via Option A of the review).
    //
    // We use `eprintln!` instead of `tracing::warn!` because `scrub
    // explain` is a pure read-only command that does not initialize a
    // tracing subscriber — a `tracing::warn!` would be a silent no-op.
    // Story 2.7 review: skip the warning when the dropped argument is
    // empty/whitespace-only so we don't emit confusing `''` quotes.
    if list_flag {
        if let Some(dropped) = rule {
            let trimmed = dropped.trim();
            if !trimmed.is_empty() {
                eprintln!(
                    "warning: positional rule argument '{trimmed}' ignored because --list was also passed"
                );
            }
        }
        print_list(&theme, support);
        return Ok(());
    }

    // No --list and no positional rule → default to list output.
    let Some(rule_name) = rule else {
        print_list(&theme, support);
        return Ok(());
    };

    // Trim whitespace so "otp-6digit " (trailing space from copy-paste)
    // still matches the lookup table (Story 2.7 AC #9).
    let rule_name = rule_name.trim();

    // Story 2.7 review patch: give empty/whitespace-only arguments a
    // dedicated error_code with a cleaner message instead of falling
    // through to `unknown_scrub_rule 'no built-in rule named '''`
    // which produces confusing consecutive single quotes.
    if rule_name.is_empty() {
        eprint!(
            "{}",
            error_block(
                "empty_rule_name",
                "rule name cannot be empty or whitespace-only",
                "agentsso scrub explain --list",
                None,
            )
        );
        std::process::exit(1);
    }

    match lookup_rule_entry(rule_name) {
        Some((name, placeholder, description, example_input, rationale)) => {
            print_explain(
                name,
                *placeholder,
                description,
                example_input,
                rationale,
                &theme,
                support,
            );
            Ok(())
        }
        None => {
            eprint!(
                "{}",
                error_block(
                    "unknown_scrub_rule",
                    &format!("no built-in rule named '{rule_name}'"),
                    "agentsso scrub explain --list",
                    None,
                )
            );
            std::process::exit(1);
        }
    }
}

/// Look up a rule entry by name, with whitespace tolerance.
///
/// Extracted as a pure helper so it can be unit-tested without going
/// through stdout-writing paths. Empty or whitespace-only names return
/// `None` (the caller renders the `unknown_scrub_rule` error block).
///
/// Story 2.7 AC #9.
fn lookup_rule_entry(rule_name: &str) -> Option<&'static RuleEntry> {
    let trimmed = rule_name.trim();
    if trimmed.is_empty() {
        return None;
    }
    RULE_DESCRIPTIONS.iter().find(|(name, ..)| *name == trimmed)
}

fn print_list(theme: &Theme, support: ColorSupport) {
    println!("built-in scrub rules:");
    println!();
    for (name, placeholder, _, _, _) in RULE_DESCRIPTIONS {
        let placeholder_styled = styled(&placeholder.to_string(), theme.tokens().warn, support);
        println!("  {name:<14} \u{2192} {placeholder_styled}");
    }
}

fn print_explain(
    rule: &str,
    placeholder: Placeholder,
    description: &str,
    example_input: &str,
    rationale: &str,
    theme: &Theme,
    support: ColorSupport,
) {
    // Build a live engine for the example demonstration. Using the real
    // engine (rather than a hardcoded "before"/"after" string pair) means
    // the example is always consistent with the shipped rules — if a
    // rule's pattern drifts, the unit test below catches it.
    let engine = match ScrubEngine::new(builtin_rules().to_vec()) {
        Ok(e) => e,
        Err(e) => {
            eprint!(
                "{}",
                error_block(
                    "scrub_engine_init_failed",
                    &format!("could not initialise built-in scrub engine: {e}"),
                    "agentsso scrub explain --list",
                    None,
                )
            );
            std::process::exit(1);
        }
    };
    let scrubbed = engine.scrub(example_input).output;

    let placeholder_styled = styled(&placeholder.to_string(), theme.tokens().warn, support);

    println!("rule: {rule}");
    println!("placeholder: {placeholder_styled}");
    println!();
    println!("what it catches:");
    println!("  {description}");
    println!();
    println!("example (live-scrubbed):");
    println!("  in:  {}", truncate_field(example_input, 60));
    println!("  out: {scrubbed}");
    println!();
    println!("why permitlayer catches this:");
    println!("  {rationale}");
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn every_builtin_rule_has_a_description_entry() {
        let rules = builtin_rules();
        for rule in rules {
            assert!(
                RULE_DESCRIPTIONS.iter().any(|(name, ..)| *name == rule.name),
                "rule '{}' has no entry in RULE_DESCRIPTIONS",
                rule.name
            );
        }
    }

    #[test]
    fn every_description_entry_matches_a_builtin_rule() {
        let rule_names: std::collections::HashSet<_> =
            builtin_rules().iter().map(|r| r.name.clone()).collect();
        for (name, ..) in RULE_DESCRIPTIONS {
            assert!(
                rule_names.contains(*name),
                "RULE_DESCRIPTIONS entry '{name}' does not match any built-in rule"
            );
        }
    }

    #[test]
    fn every_example_input_is_scrubbed_by_live_engine() {
        // Load the real engine and confirm each documented example
        // actually triggers its rule. Prevents shipping stale examples.
        let engine = ScrubEngine::new(builtin_rules().to_vec()).unwrap();
        for (name, placeholder, _, example_input, _) in RULE_DESCRIPTIONS {
            let result = engine.scrub(example_input);
            assert!(
                result.output != *example_input,
                "rule '{name}' example input should be scrubbed but was unchanged: {example_input}"
            );
            assert!(
                result.output.contains(&placeholder.to_string()),
                "rule '{name}' example should contain placeholder {placeholder:?} after scrub, got: {}",
                result.output
            );
        }
    }

    #[test]
    fn list_is_in_stable_order() {
        // First rule is otp-6digit, last is credit-card, per the table.
        assert_eq!(RULE_DESCRIPTIONS[0].0, "otp-6digit");
        assert_eq!(RULE_DESCRIPTIONS.last().unwrap().0, "credit-card");
    }

    #[test]
    fn explain_table_length_matches_builtin_rule_count() {
        assert_eq!(
            RULE_DESCRIPTIONS.len(),
            builtin_rules().len(),
            "table length drifted from builtin_rules() count"
        );
    }

    // ----- Story 2.7 Task 8: lookup_rule_entry whitespace + unknown -----

    #[test]
    fn lookup_rule_entry_exact_match() {
        let entry = lookup_rule_entry("otp-6digit");
        assert!(entry.is_some(), "exact match should succeed");
        assert_eq!(entry.unwrap().0, "otp-6digit");
    }

    #[test]
    fn lookup_rule_entry_trims_trailing_whitespace() {
        // Copy-paste commonly appends a trailing space.
        let entry = lookup_rule_entry("otp-6digit ");
        assert!(entry.is_some(), "trailing-space lookup should succeed after trim");
        assert_eq!(entry.unwrap().0, "otp-6digit");
    }

    #[test]
    fn lookup_rule_entry_trims_leading_whitespace() {
        let entry = lookup_rule_entry("  otp-6digit");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().0, "otp-6digit");
    }

    #[test]
    fn lookup_rule_entry_trims_both_sides() {
        let entry = lookup_rule_entry("  otp-6digit  ");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().0, "otp-6digit");
    }

    #[test]
    fn lookup_rule_entry_empty_string_returns_none() {
        assert!(lookup_rule_entry("").is_none());
    }

    #[test]
    fn lookup_rule_entry_whitespace_only_returns_none() {
        assert!(lookup_rule_entry("   ").is_none());
        assert!(lookup_rule_entry("\t").is_none());
        assert!(lookup_rule_entry("\n").is_none());
    }

    #[test]
    fn lookup_rule_entry_unknown_rule_returns_none() {
        assert!(lookup_rule_entry("bogus-rule").is_none());
        assert!(lookup_rule_entry("otp-99digit").is_none());
    }
}
