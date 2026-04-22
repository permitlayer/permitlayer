//! Two-pass content scrubbing engine.
//!
//! See the [module-level documentation](super) for the two-pass architecture
//! overview and overlap resolution semantics.

use std::collections::BTreeMap;
use std::ops::Range;

use aho_corasick::AhoCorasick;
use serde::{Deserialize, Serialize};

use super::error::ScrubError;
use super::placeholder::Placeholder;
use super::rule::ScrubRule;

/// Maximum byte window around an aho-corasick hit for regex confirmation.
/// Prevents regex backtracking on huge inputs.
const REGEX_WINDOW_BYTES: usize = 512;

/// Two-pass content scrubbing engine.
///
/// Pass 1: An [`AhoCorasick`] automaton scans the input for literal
/// prefixes/keywords from all registered rules. This is O(n) in input
/// length regardless of rule count.
///
/// Pass 2: For each aho-corasick hit, the corresponding rule's
/// [`regex::Regex`] is run on a bounded window around the hit to
/// confirm and extract the exact match span. Only confirmed matches
/// are replaced.
///
/// The engine is immutable after construction (`Arc<ScrubEngine>` is the
/// expected usage) and safe for concurrent use from multiple request handlers.
///
/// # Overlap resolution
///
/// When two rules match overlapping regions, the resolution is deterministic:
/// longest match wins. If two matches have the same span length, the rule
/// with the lower index (earlier in the constructor's `rules` Vec) wins.
pub struct ScrubEngine {
    automaton: AhoCorasick,
    rules: Vec<ScrubRule>,
    /// Maps each pattern index in the automaton to all rule indices that
    /// share that literal. This handles the case where multiple rules
    /// register the same literal string.
    pattern_to_rule: Vec<Vec<usize>>,
}

// Safety: all fields are Send + Sync by construction.
static_assertions::assert_impl_all!(ScrubEngine: Send, Sync);

impl ScrubEngine {
    /// Build a new scrub engine from a set of rules.
    ///
    /// Collects all literal strings, builds the aho-corasick automaton,
    /// and stores the pattern-to-rule mapping.
    ///
    /// # Errors
    ///
    /// Returns [`ScrubError::AhoCorasickBuild`] if the automaton cannot
    /// be constructed.
    pub fn new(rules: Vec<ScrubRule>) -> Result<Self, ScrubError> {
        // Deduplicate literals: multiple rules can share the same literal.
        // We map each unique literal (case-folded) to all rule indices.
        let mut literal_to_rules: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (rule_idx, rule) in rules.iter().enumerate() {
            for lit in &rule.literals {
                literal_to_rules.entry(lit.to_ascii_lowercase()).or_default().push(rule_idx);
            }
        }

        // Build flat literal list and pattern_to_rule mapping for the
        // deduplicated set. Each unique literal gets one automaton pattern.
        let mut unique_literals: Vec<String> = Vec::new();
        let mut pattern_to_rule: Vec<Vec<usize>> = Vec::new();
        for (lit, rule_indices) in &literal_to_rules {
            unique_literals.push(lit.clone());
            pattern_to_rule.push(rule_indices.clone());
        }

        let automaton = aho_corasick::AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(&unique_literals)
            .map_err(|source| ScrubError::AhoCorasickBuild { source })?;

        Ok(Self { automaton, rules, pattern_to_rule })
    }

    /// Scrub the input string, returning the redacted output and match details.
    #[must_use]
    pub fn scrub(&self, input: &str) -> ScrubResult {
        if input.is_empty() || self.rules.is_empty() {
            return ScrubResult {
                output: input.to_string(),
                matches: Vec::new(),
                original_len: input.len(),
            };
        }

        // Pass 1: collect aho-corasick hits, deduplicated by (rule_index, region).
        let mut candidate_regions: Vec<(usize, Range<usize>)> = Vec::new();
        for mat in self.automaton.find_iter(input) {
            let rule_indices = &self.pattern_to_rule[mat.pattern().as_usize()];
            let hit_start = mat.start();
            let hit_end = mat.end();

            // Build a bounded window around the hit for regex confirmation.
            let window_start = hit_start.saturating_sub(REGEX_WINDOW_BYTES);
            let window_end = (hit_end + REGEX_WINDOW_BYTES).min(input.len());

            // Clamp to UTF-8 char boundaries.
            let window_start = clamp_to_char_boundary(input, window_start, Direction::Back);
            let window_end = clamp_to_char_boundary(input, window_end, Direction::Forward);

            // Emit a candidate for every rule that registered this literal.
            for &rule_idx in rule_indices {
                // Deduplicate: skip if we already have a candidate for the same
                // rule covering an overlapping window.
                let dominated = candidate_regions.iter().any(|(idx, region)| {
                    *idx == rule_idx && region.start <= window_start && region.end >= window_end
                });
                if !dominated {
                    candidate_regions.push((rule_idx, window_start..window_end));
                }
            }
        }

        // Pass 2: regex confirmation on each candidate region.
        // If the pattern has a capture group 1, we replace only that group;
        // otherwise we replace the full match (group 0).
        let mut confirmed: Vec<ScrubMatch> = Vec::new();
        for (rule_idx, window) in &candidate_regions {
            let rule = &self.rules[*rule_idx];
            let window_str = &input[window.clone()];

            for caps in rule.pattern.captures_iter(window_str) {
                // Prefer group 1 if it exists; fall back to group 0.
                // Group 0 is guaranteed to exist for any successful capture.
                let Some(m) = caps.get(1).or_else(|| caps.get(0)) else {
                    continue;
                };
                let matched_text = m.as_str();

                // Apply validator if present.
                if let Some(validator) = rule.validator
                    && !validator(matched_text)
                {
                    continue;
                }

                let abs_start = window.start + m.start();
                let abs_end = window.start + m.end();
                confirmed.push(ScrubMatch {
                    span: abs_start..abs_end,
                    placeholder: rule.placeholder,
                    rule_name: rule.name.clone(),
                    rule_index: *rule_idx,
                });
            }
        }

        // Sort by start offset, then resolve overlaps.
        confirmed.sort_by(|a, b| {
            a.span
                .start
                .cmp(&b.span.start)
                .then_with(|| {
                    // Longer match wins: sort descending by length so the
                    // longest match at the same start position comes first.
                    let a_len = a.span.end - a.span.start;
                    let b_len = b.span.end - b.span.start;
                    b_len.cmp(&a_len) // descending
                })
                .then_with(|| a.rule_index.cmp(&b.rule_index))
        });

        let resolved = resolve_overlaps(confirmed);

        // Build output string.
        let mut output = String::with_capacity(input.len());
        let mut cursor = 0;
        for m in &resolved {
            if m.span.start > cursor {
                output.push_str(&input[cursor..m.span.start]);
            }
            output.push_str(&m.placeholder.to_string());
            cursor = m.span.end;
        }
        if cursor < input.len() {
            output.push_str(&input[cursor..]);
        }

        ScrubResult { output, matches: resolved, original_len: input.len() }
    }

    /// Scrub a byte slice, validating UTF-8 first.
    ///
    /// # Errors
    ///
    /// Returns [`ScrubError::InvalidUtf8`] if the input is not valid UTF-8.
    pub fn scrub_bytes(&self, input: &[u8]) -> Result<ScrubResult, ScrubError> {
        let s = std::str::from_utf8(input).map_err(|_| ScrubError::InvalidUtf8)?;
        Ok(self.scrub(s))
    }
}

/// Resolve overlapping matches: longest match wins; on tie, lower rule index wins.
fn resolve_overlaps(sorted: Vec<ScrubMatch>) -> Vec<ScrubMatch> {
    let mut result: Vec<ScrubMatch> = Vec::new();
    for m in sorted {
        if let Some(last) = result.last()
            && m.span.start < last.span.end
        {
            // Overlap: the first one in sorted order already wins
            // (it's either earlier-starting or longer/lower-index).
            continue;
        }
        result.push(m);
    }
    result
}

#[derive(Debug, Clone, Copy)]
enum Direction {
    Back,
    Forward,
}

/// Clamp a byte index to a valid UTF-8 character boundary.
fn clamp_to_char_boundary(s: &str, index: usize, dir: Direction) -> usize {
    if index >= s.len() {
        return s.len();
    }
    if s.is_char_boundary(index) {
        return index;
    }
    match dir {
        Direction::Back => {
            // Walk backwards to find a char boundary.
            let mut i = index;
            while i > 0 && !s.is_char_boundary(i) {
                i -= 1;
            }
            i
        }
        Direction::Forward => {
            // Walk forwards to find a char boundary.
            let mut i = index;
            while i < s.len() && !s.is_char_boundary(i) {
                i += 1;
            }
            i
        }
    }
}

/// Result of scrubbing a single input.
#[derive(Debug, Clone)]
pub struct ScrubResult {
    /// The scrubbed output with placeholders replacing matched content.
    pub output: String,
    /// Details of every match found (for audit events).
    pub matches: Vec<ScrubMatch>,
    /// Length of the original input in bytes.
    pub original_len: usize,
}

impl ScrubResult {
    /// Returns `true` if no sensitive content was found.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.matches.is_empty()
    }

    /// Number of matches found.
    #[must_use]
    pub fn match_count(&self) -> usize {
        self.matches.len()
    }

    /// Returns rule_name -> count for audit events.
    #[must_use]
    pub fn summary(&self) -> BTreeMap<String, usize> {
        let mut map = BTreeMap::new();
        for m in &self.matches {
            *map.entry(m.rule_name.clone()).or_insert(0) += 1;
        }
        map
    }

    /// Extract up to `max_samples` contextual snippets for audit-event
    /// enrichment, one per distinct rule, choosing the lowest-offset match
    /// per rule for determinism.
    ///
    /// Each returned [`ScrubSample`] carries a UTF-8-safe ±`window_bytes`
    /// window around the placeholder **taken from the already-scrubbed
    /// output**, never from the raw input. The `placeholder_offset` and
    /// `placeholder_len` fields are byte offsets within `snippet`, so the
    /// renderer can compute arrow positioning from the snippet alone.
    ///
    /// Overlapping-rule dedup is already applied by the engine's overlap
    /// resolver; this method only dedupes across the already-resolved
    /// match set by taking the earliest remaining match per rule name.
    ///
    /// The order of returned samples matches the order rules first appear
    /// in `self.matches` (which is sorted by original-input offset).
    #[must_use]
    pub fn samples(&self, max_samples: usize, window_bytes: usize) -> Vec<ScrubSample> {
        if max_samples == 0 || self.matches.is_empty() {
            return Vec::new();
        }

        // Walk matches in stable order; map original-input offsets to
        // output offsets using a running delta. `matches` is sorted by
        // `span.start` ascending (see `scrub()`), which is the invariant
        // we rely on.
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut samples: Vec<ScrubSample> = Vec::new();
        let mut delta: isize = 0;

        for m in &self.matches {
            let placeholder_str = m.placeholder.to_string();
            let placeholder_len = placeholder_str.len();
            let match_len = m.span.end - m.span.start;

            // Output offset = original start + cumulative delta so far.
            // `delta` is the signed difference (placeholder bytes − match
            // bytes) accumulated from all previous matches.
            let output_offset = (m.span.start as isize + delta) as usize;

            // Update delta for the next iteration.
            delta += placeholder_len as isize - match_len as isize;

            if seen.contains(&m.rule_name) {
                continue;
            }
            if samples.len() >= max_samples {
                continue;
            }

            // Compute a window around the placeholder in `self.output`.
            let window_start_raw = output_offset.saturating_sub(window_bytes);
            let window_end_raw = output_offset
                .saturating_add(placeholder_len)
                .saturating_add(window_bytes)
                .min(self.output.len());

            let window_start =
                clamp_to_char_boundary(&self.output, window_start_raw, Direction::Back);
            let window_end =
                clamp_to_char_boundary(&self.output, window_end_raw, Direction::Forward);

            let snippet = self.output[window_start..window_end].to_string();
            // Offset of the placeholder *within the snippet*.
            let placeholder_offset_in_snippet = output_offset - window_start;

            tracing::debug!(
                rule = %m.rule_name,
                snippet_len = snippet.len(),
                placeholder_offset = placeholder_offset_in_snippet,
                placeholder_len,
                "scrub sample emitted"
            );

            samples.push(ScrubSample {
                rule: m.rule_name.clone(),
                snippet,
                placeholder_offset: placeholder_offset_in_snippet,
                placeholder_len,
            });
            seen.insert(m.rule_name.clone());
        }

        samples
    }
}

/// A contextual snippet around a single scrub match, suitable for
/// inline rendering in the CLI (see `ScrubInline` component).
///
/// The `snippet` is always sliced from the **scrubbed** output, never
/// from raw input — any sensitive content that would appear inside the
/// window has already been replaced with typed placeholders by the
/// engine. `placeholder_offset` and `placeholder_len` are byte offsets
/// within `snippet` identifying the specific placeholder this sample
/// highlights.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScrubSample {
    /// Rule name that produced this match (e.g., `"otp-6digit"`).
    pub rule: String,
    /// Scrubbed context window around the placeholder.
    pub snippet: String,
    /// Byte offset of the placeholder within `snippet`.
    pub placeholder_offset: usize,
    /// Byte length of the placeholder within `snippet`.
    pub placeholder_len: usize,
}

/// A single match within the scrubbed input.
#[derive(Debug, Clone)]
pub struct ScrubMatch {
    /// Byte offset range in the original input.
    pub span: Range<usize>,
    /// The placeholder type used for replacement.
    pub placeholder: Placeholder,
    /// The rule name that produced this match (for audit).
    pub rule_name: String,
    /// Internal: rule index for overlap resolution.
    rule_index: usize,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Helper: build an OTP rule for testing.
    fn otp_rule() -> ScrubRule {
        ScrubRule::new(
            "otp-6digit",
            vec![
                "code is".to_string(),
                "code:".to_string(),
                "verification code".to_string(),
                "passcode".to_string(),
            ],
            r"(?i)(?:code(?:\s+is)?|verification\s+code|passcode)\s*[:=]?\s*(\d{6})\b",
            Placeholder::Otp,
        )
        .unwrap()
    }

    /// Helper: build a bearer token rule for testing.
    fn bearer_rule() -> ScrubRule {
        ScrubRule::new(
            "bearer",
            vec!["bearer".to_string()],
            r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*",
            Placeholder::Bearer,
        )
        .unwrap()
    }

    #[test]
    fn test_empty_input_returns_empty() {
        let engine = ScrubEngine::new(vec![otp_rule()]).unwrap();
        let result = engine.scrub("");
        assert_eq!(result.output, "");
        assert!(result.matches.is_empty());
        assert_eq!(result.original_len, 0);
    }

    #[test]
    fn test_no_rules_passthrough() {
        let engine = ScrubEngine::new(vec![]).unwrap();
        let input = "Your code is 123456.";
        let result = engine.scrub(input);
        assert_eq!(result.output, input);
        assert!(result.matches.is_empty());
    }

    #[test]
    fn test_single_literal_match() {
        let engine = ScrubEngine::new(vec![otp_rule()]).unwrap();
        let result = engine.scrub("Your verification code is 987654 please use it.");
        assert!(result.output.contains("<REDACTED_OTP>"), "output: {}", result.output);
        assert!(!result.output.contains("987654"));
        assert_eq!(result.match_count(), 1);
        assert_eq!(result.matches[0].rule_name, "otp-6digit");
    }

    #[test]
    fn test_multiple_rules_different_placeholders() {
        let engine = ScrubEngine::new(vec![otp_rule(), bearer_rule()]).unwrap();
        let input = "Your code is 123456. Auth: Bearer abc123token.";
        let result = engine.scrub(input);
        assert!(result.output.contains("<REDACTED_OTP>"));
        assert!(result.output.contains("<REDACTED_BEARER>"));
        assert_eq!(result.match_count(), 2);
    }

    #[test]
    fn test_overlapping_matches_longest_wins() {
        // Two rules that could match overlapping regions. The longer match wins.
        let short_rule =
            ScrubRule::new("short", vec!["abc".to_string()], r"abc\d{3}", Placeholder::Custom(0))
                .unwrap();
        let long_rule =
            ScrubRule::new("long", vec!["abc".to_string()], r"abc\d{6}", Placeholder::Custom(1))
                .unwrap();
        let engine = ScrubEngine::new(vec![short_rule, long_rule]).unwrap();
        let result = engine.scrub("prefix abc123456 suffix");
        // The longer match (abc123456) should win.
        assert_eq!(result.match_count(), 1);
        assert_eq!(result.matches[0].rule_name, "long");
    }

    #[test]
    fn test_adjacent_matches_no_merge() {
        let engine = ScrubEngine::new(vec![otp_rule()]).unwrap();
        let input = "code is 111111 and code is 222222";
        let result = engine.scrub(input);
        assert_eq!(result.match_count(), 2);
        assert!(!result.output.contains("111111"));
        assert!(!result.output.contains("222222"));
    }

    #[test]
    fn test_case_insensitive_literal_match() {
        let engine = ScrubEngine::new(vec![otp_rule()]).unwrap();
        let result = engine.scrub("YOUR CODE IS 654321 thanks");
        assert!(result.output.contains("<REDACTED_OTP>"));
        assert!(!result.output.contains("654321"));
    }

    #[test]
    fn test_regex_confirmation_rejects_false_positive() {
        let engine = ScrubEngine::new(vec![otp_rule()]).unwrap();
        // Contains the literal "code is" but followed by text, not 6 digits.
        let result = engine.scrub("The code is not a number here.");
        assert!(result.is_clean());
        assert_eq!(result.output, "The code is not a number here.");
    }

    #[test]
    fn test_large_input_no_match() {
        let engine = ScrubEngine::new(vec![otp_rule()]).unwrap();
        let input = "Lorem ipsum dolor sit amet. ".repeat(4000); // ~112KB
        let result = engine.scrub(&input);
        assert!(result.is_clean());
        assert_eq!(result.output, input);
    }

    #[test]
    fn test_unicode_input_preserved() {
        let engine = ScrubEngine::new(vec![otp_rule()]).unwrap();
        let input = "Your code is 123456. Japanese: \u{65E5}\u{672C}\u{8A9E}. Korean: \u{D55C}\u{AD6D}\u{C5B4}. Emoji: \u{1F60A}";
        let result = engine.scrub(input);
        assert!(result.output.contains("<REDACTED_OTP>"));
        assert!(result.output.contains("\u{65E5}\u{672C}\u{8A9E}"));
        assert!(result.output.contains("\u{D55C}\u{AD6D}\u{C5B4}"));
        assert!(result.output.contains("\u{1F60A}"));
    }

    #[test]
    fn test_scrub_result_is_clean() {
        let engine = ScrubEngine::new(vec![otp_rule()]).unwrap();

        let clean = engine.scrub("nothing sensitive here");
        assert!(clean.is_clean());
        assert_eq!(clean.match_count(), 0);

        let dirty = engine.scrub("code is 999888");
        assert!(!dirty.is_clean());
        assert_eq!(dirty.match_count(), 1);
    }

    #[test]
    fn test_scrub_result_summary() {
        let engine = ScrubEngine::new(vec![otp_rule(), bearer_rule()]).unwrap();
        let input = "code is 111111 and code is 222222 and Bearer tok123";
        let result = engine.scrub(input);
        let summary = result.summary();
        assert_eq!(summary.get("otp-6digit"), Some(&2));
        assert_eq!(summary.get("bearer"), Some(&1));
    }

    #[test]
    fn test_scrub_bytes_valid_utf8() {
        let engine = ScrubEngine::new(vec![otp_rule()]).unwrap();
        let input = b"code is 123456";
        let result = engine.scrub_bytes(input);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.output.contains("<REDACTED_OTP>"));
    }

    #[test]
    fn test_scrub_bytes_invalid_utf8() {
        let engine = ScrubEngine::new(vec![otp_rule()]).unwrap();
        let input: &[u8] = &[0xFF, 0xFE, 0x00, 0x01];
        let result = engine.scrub_bytes(input);
        assert!(result.is_err());
        match result.unwrap_err() {
            ScrubError::InvalidUtf8 => {}
            other => panic!("expected InvalidUtf8, got: {other:?}"),
        }
    }

    // ----- ScrubResult::samples tests (Story 2.6) -----

    /// Helper: build an email (PII) rule for cross-rule sample tests.
    fn email_rule() -> ScrubRule {
        ScrubRule::new(
            "email",
            vec!["@".to_string()],
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            Placeholder::Email,
        )
        .unwrap()
    }

    #[test]
    fn samples_returns_at_most_max_samples() {
        let engine = ScrubEngine::new(vec![otp_rule(), bearer_rule(), email_rule()]).unwrap();
        let input = "code is 111111. Authorization: Bearer abc123token. Contact alice@example.com";
        let result = engine.scrub(input);
        // 3 distinct rules fired, but request only 2.
        let samples = result.samples(2, 48);
        assert_eq!(samples.len(), 2, "samples: {samples:?}");
    }

    #[test]
    fn samples_dedupes_to_lowest_offset_per_rule() {
        let engine = ScrubEngine::new(vec![otp_rule()]).unwrap();
        let input = "code is 111111 and code is 222222";
        let result = engine.scrub(input);
        assert_eq!(result.match_count(), 2);
        let samples = result.samples(5, 48);
        // Only one sample per rule.
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].rule, "otp-6digit");
        // The snippet should come from the region around the first match.
        // The first match is "code is 111111" → replaced with "code is <REDACTED_OTP>".
        // So the earliest placeholder is at offset 8 in output.
        assert!(samples[0].snippet.contains("<REDACTED_OTP>"));
        // Because window is ±48 bytes, both placeholders likely fall into the
        // window — but we're asserting the ANCHOR of this sample is the first
        // match (placeholder_offset points at the first occurrence).
        let po = samples[0].placeholder_offset;
        let pl = samples[0].placeholder_len;
        assert_eq!(&samples[0].snippet[po..po + pl], "<REDACTED_OTP>");
    }

    #[test]
    fn samples_snippet_window_is_clamped_to_char_boundaries() {
        // Build an input where the ±48-byte window would fall inside a
        // multi-byte UTF-8 sequence if not clamped. Pad with 4-byte emoji
        // characters on both sides so byte arithmetic lands mid-codepoint.
        let engine = ScrubEngine::new(vec![otp_rule()]).unwrap();
        let pad = "\u{1F600}\u{1F601}\u{1F602}\u{1F603}".repeat(10); // 160 bytes of emoji
        let input = format!("{pad}code is 123456{pad}");
        let result = engine.scrub(&input);
        assert_eq!(result.match_count(), 1);
        let samples = result.samples(1, 48);
        assert_eq!(samples.len(), 1);
        // The snippet must be valid UTF-8 (implicit via String) AND the
        // placeholder offset must land on a char boundary.
        let s = &samples[0];
        assert!(s.snippet.is_char_boundary(s.placeholder_offset));
        assert!(s.snippet.is_char_boundary(s.placeholder_offset + s.placeholder_len));
        assert_eq!(
            &s.snippet[s.placeholder_offset..s.placeholder_offset + s.placeholder_len],
            "<REDACTED_OTP>"
        );
    }

    #[test]
    fn samples_snippet_is_already_scrubbed() {
        // When the window around an OTP includes an email, the email must
        // already be scrubbed in the sample snippet — samples slice from
        // `self.output`, never raw input.
        let engine = ScrubEngine::new(vec![otp_rule(), email_rule()]).unwrap();
        let input = "code is 123456 — contact alice@example.com for help";
        let result = engine.scrub(input);
        assert_eq!(result.match_count(), 2);
        let samples = result.samples(5, 64);
        // The OTP sample's snippet should include the email as <REDACTED_EMAIL>,
        // not the raw alice@example.com.
        let otp_sample = samples.iter().find(|s| s.rule == "otp-6digit").expect("otp sample");
        assert!(otp_sample.snippet.contains("<REDACTED_OTP>"));
        assert!(
            !otp_sample.snippet.contains("alice@example.com"),
            "raw email leaked into sample snippet: {}",
            otp_sample.snippet
        );
    }

    #[test]
    fn samples_placeholder_offset_within_snippet_is_correct() {
        let engine = ScrubEngine::new(vec![otp_rule()]).unwrap();
        let result = engine.scrub("Your verification code is 987654 please enter it");
        let samples = result.samples(1, 48);
        assert_eq!(samples.len(), 1);
        let s = &samples[0];
        assert_eq!(
            &s.snippet[s.placeholder_offset..s.placeholder_offset + s.placeholder_len],
            "<REDACTED_OTP>"
        );
    }

    #[test]
    fn samples_at_string_start_no_underflow() {
        // Placeholder at offset 0 of output: window start clamps to 0.
        let engine = ScrubEngine::new(vec![otp_rule()]).unwrap();
        let result = engine.scrub("code is 123456 and more");
        let samples = result.samples(1, 48);
        assert_eq!(samples.len(), 1);
        let s = &samples[0];
        // Snippet should start at the beginning of the output.
        assert!(s.snippet.starts_with("code is <REDACTED_OTP>"));
    }

    #[test]
    fn samples_at_string_end_no_overflow() {
        // Placeholder near end: window extends past output, must clamp.
        let engine = ScrubEngine::new(vec![otp_rule()]).unwrap();
        // Short input, placeholder near the end.
        let result = engine.scrub("text code is 987654");
        let samples = result.samples(1, 256);
        assert_eq!(samples.len(), 1);
        let s = &samples[0];
        // Snippet should be clamped to the actual output length.
        assert!(s.snippet.ends_with("<REDACTED_OTP>"));
    }

    #[test]
    fn samples_zero_max_returns_empty() {
        let engine = ScrubEngine::new(vec![otp_rule()]).unwrap();
        let result = engine.scrub("code is 123456");
        let samples = result.samples(0, 48);
        assert!(samples.is_empty());
    }

    #[test]
    fn samples_clean_input_returns_empty() {
        let engine = ScrubEngine::new(vec![otp_rule()]).unwrap();
        let result = engine.scrub("nothing sensitive here");
        let samples = result.samples(3, 48);
        assert!(samples.is_empty());
    }

    #[test]
    fn samples_serializes_to_json() {
        // Sanity check: ScrubSample round-trips through serde_json.
        let sample = ScrubSample {
            rule: "otp-6digit".into(),
            snippet: "code is <REDACTED_OTP>".into(),
            placeholder_offset: 8,
            placeholder_len: 14,
        };
        let json = serde_json::to_string(&sample).unwrap();
        let back: ScrubSample = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sample);
    }
}
