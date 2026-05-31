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
        //
        // Each match span's edges are clamped off the interior of any
        // JSON backslash escape they bisect (`clamp_off_escape`): the
        // start moves back to an escape's opening `\`, the end moves
        // forward past it. Without this, a PII match that clips a
        // `\uXXXX` (e.g. Gmail's `<` for HTML `<`) would leave a
        // partial escape in the spliced output and produce invalid JSON
        // — the deterministic `format=full` parse failure. Clamping
        // redacts at most one extra adjacent escape, which is safe.
        let mut output = String::with_capacity(input.len());
        let mut cursor = 0;
        for m in &resolved {
            let start = clamp_off_escape(input, m.span.start, Direction::Back);
            let end = clamp_off_escape(input, m.span.end, Direction::Forward);
            // A prior match may have already consumed past this one's
            // (clamped) start; skip if so to keep `cursor` monotonic.
            if end <= cursor {
                continue;
            }
            if start > cursor {
                output.push_str(&input[cursor..start]);
            }
            output.push_str(&m.placeholder.to_string());
            cursor = end;
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

/// Move a cut index off the *interior* of a JSON-style backslash escape.
///
/// The scrubber rebuilds output by slicing `input` at match-span
/// boundaries and splicing in placeholders. When the scrubbed text is
/// serialized JSON (e.g. a Gmail `messages.get` response), string values
/// contain backslash escapes — `\"`, `\\`, `\n`, … (2 chars) and
/// `\uXXXX` (6 chars). Gmail JSON-escapes HTML `<`/`>`/`&` as
/// `<`/`>`/`&`, which are dense in HTML email bodies. If a
/// match span's start or end lands *inside* one of those escapes, the
/// rebuild emits a partial/orphaned escape and the result is invalid
/// JSON (the deterministic "invalid escape at line N column M" the proxy
/// hit on `format=full`).
///
/// This clamps `index` to a safe edge of any escape it bisects:
/// - `Direction::Back` (used for the kept-prefix cut = `span.start`):
///   move to the escape's opening `\`, so the whole escape falls into the
///   redacted span rather than being half-kept.
/// - `Direction::Forward` (used for the resume point = `span.end`): move
///   past the escape's end, so the suffix resumes on a clean boundary.
///
/// Redacting slightly more is always safe; emitting invalid JSON is not.
/// On text with no backslash escapes the function is a no-op, so non-JSON
/// scrub inputs are unaffected.
///
/// `index` is assumed to already be on a UTF-8 char boundary (callers run
/// [`clamp_to_char_boundary`] first); escapes are pure ASCII so the two
/// clamps compose.
fn clamp_off_escape(s: &str, index: usize, dir: Direction) -> usize {
    if index == 0 || index >= s.len() {
        return index;
    }
    let bytes = s.as_bytes();

    // Find the escape sequence (if any) whose interior contains `index`.
    // An escape begins at an *unescaped* backslash: one preceded by an
    // even number of consecutive backslashes (0, 2, …). Scan backwards a
    // bounded distance — an escape is at most 6 bytes (`\uXXXX`), so the
    // governing `\` is within 5 bytes before `index`.
    let lo = index.saturating_sub(5);
    for bs in (lo..index).rev() {
        if bytes[bs] != b'\\' {
            continue;
        }
        // Parity: count consecutive backslashes immediately before `bs`.
        // Odd total run length ending at `bs` ⇒ this `\` is unescaped and
        // opens an escape; even ⇒ it is itself the second half of a `\\`
        // pair (e.g. the literal-backslash case `\\u003c`) and opens
        // nothing.
        let mut run = 1usize;
        let mut j = bs;
        while j > 0 && bytes[j - 1] == b'\\' {
            run += 1;
            j -= 1;
        }
        if run.is_multiple_of(2) {
            // `bs` is an escaped backslash, not an escape opener. The
            // index is not inside an escape governed by this `\`.
            continue;
        }
        // `bs` opens an escape. Determine its length: `\uXXXX` is 6,
        // everything else (`\"`, `\\`, `\n`, …) is 2.
        let esc_len = if bytes.get(bs + 1) == Some(&b'u') { 6 } else { 2 };
        let esc_end = bs + esc_len;
        // Interior iff strictly between the opening `\` and the end. At
        // `index == bs` or `index == esc_end` the cut is already safe.
        if index > bs && index < esc_end {
            return match dir {
                Direction::Back => bs,
                Direction::Forward => esc_end.min(s.len()),
            };
        }
        // The nearest preceding unescaped `\` doesn't cover `index`; no
        // closer opener can either (we scanned the whole 5-byte window).
        break;
    }
    index
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

    // ── JSON-escape-safety (the Gmail format=full corruption fix) ────
    // (reuses the `email_rule()` helper defined earlier in this module)

    /// Assert the scrub output is valid JSON when used as a string value.
    /// (The real corruption manifested as `serde_json::from_str` rejecting
    /// the proxy's whole-response JSON; wrapping the scrubbed fragment as a
    /// JSON string value reproduces the same parser at the same layer.)
    fn assert_valid_as_json_string(scrubbed: &str) {
        let doc = format!("{{\"v\":\"{scrubbed}\"}}");
        serde_json::from_str::<serde_json::Value>(&doc)
            .unwrap_or_else(|e| panic!("scrubbed output is not valid JSON: {e}\n  doc: {doc}"));
    }

    #[test]
    fn escape_then_email_start_side_clamp_stays_valid_json() {
        // THE reproducing case. A `<` escape (Gmail's JSON for HTML
        // `<`) immediately followed by an email: the email local-part
        // class matches `u003cuser@…`, so the match STARTS at the `u`
        // right after the `\`. Pre-fix, the prefix cut ended on a lone
        // `\` → `\<REDACTED_EMAIL>` → invalid JSON escape. The clamp
        // moves the start back to the `\`, redacting the leading escape
        // with the email (safe over-redaction).
        let engine = ScrubEngine::new(vec![email_rule()]).unwrap();
        // bytes: \ u 0 0 3 c u s e r @ e x a m p l e . c o m
        let input = "\\u003cuser@example.com x";
        let result = engine.scrub(input);
        assert!(!result.output.contains("user@example.com"), "email leaked: {}", result.output);
        assert!(result.output.contains("<REDACTED_EMAIL>"), "not redacted: {}", result.output);
        assert_valid_as_json_string(&result.output);
        // No orphaned/partial escape remains (the leading `<` was
        // consumed into the redaction, not left dangling).
        assert!(!result.output.contains("\\<"), "dangling escape: {}", result.output);
    }

    #[test]
    fn escape_after_email_end_side_stays_valid_json() {
        // Control + end-side: an email FOLLOWED by a `>` escape. The
        // email match ends at the `\` (a safe boundary), so this was
        // already valid pre-fix; assert the fix doesn't break it and the
        // trailing escape survives.
        let engine = ScrubEngine::new(vec![email_rule()]).unwrap();
        let input = "a@example.com\\u003eTAIL";
        let result = engine.scrub(input);
        assert!(!result.output.contains("a@example.com"));
        assert!(result.output.contains("<REDACTED_EMAIL>"));
        assert_valid_as_json_string(&result.output);
        assert!(
            result.output.contains("\\u003eTAIL"),
            "trailing escape corrupted: {}",
            result.output
        );
    }

    #[test]
    fn escaped_backslash_then_text_not_treated_as_escape() {
        // `\\u003c` is a LITERAL backslash followed by "u003c" — not a
        // `<` escape. Parity must not over-redact or mis-clamp here.
        let engine = ScrubEngine::new(vec![email_rule()]).unwrap();
        let input = r"a@b.com\\u003cTAIL";
        let result = engine.scrub(input);
        assert_valid_as_json_string(&result.output);
        assert!(result.output.contains("<REDACTED_EMAIL>"));
        // The literal `\\` + `u003cTAIL` after the email is preserved
        // verbatim (the clamp must not swallow it).
        assert!(result.output.contains(r"\\u003cTAIL"), "tail corrupted: {}", result.output);
    }

    #[test]
    fn two_char_escape_adjacent_to_match_not_split() {
        // `\"` / `\n` adjacent to a match must stay paired.
        let engine = ScrubEngine::new(vec![email_rule()]).unwrap();
        let input = r"a@b.com\nNext line\twith tab";
        let result = engine.scrub(input);
        assert_valid_as_json_string(&result.output);
        assert!(result.output.contains(r"\n"), "newline escape split: {}", result.output);
    }

    #[test]
    fn clamp_off_escape_is_noop_on_plaintext() {
        // No backslashes ⇒ the clamp changes nothing; scrub output is
        // byte-identical to the pre-fix behavior (prefix + placeholder +
        // suffix at the raw match boundaries).
        let engine = ScrubEngine::new(vec![email_rule()]).unwrap();
        let input = "from alice@example.org to bob, see attached";
        let result = engine.scrub(input);
        assert_eq!(result.output, "from <REDACTED_EMAIL> to bob, see attached");
    }

    #[test]
    fn clamp_off_escape_unit() {
        // `<` = 6 bytes (backslash,u,0,0,3,c). An index in its
        // interior (1..6) clamps: Back→0 (the `\`), Forward→6 (past it).
        let s = "\\u003c"; // bytes: \ u 0 0 3 c
        assert_eq!(s.len(), 6);
        assert_eq!(clamp_off_escape(s, 3, Direction::Back), 0);
        assert_eq!(clamp_off_escape(s, 3, Direction::Forward), 6);
        // At the boundary index 1 (right after the `\`, still interior)
        // → Back 0. Index 0 (the `\` itself) is not interior → unchanged.
        assert_eq!(clamp_off_escape(s, 1, Direction::Back), 0);
        // A 2-char escape `\n` at the start of "a\nb": index 2 is inside.
        let t = "a\\nb";
        assert_eq!(clamp_off_escape(t, 2, Direction::Back), 1);
        assert_eq!(clamp_off_escape(t, 2, Direction::Forward), 3);
        // Escaped backslash `\\` (run length 2 = even) opens nothing.
        let u = "a\\\\b";
        assert_eq!(clamp_off_escape(u, 3, Direction::Back), 3);
    }
}
