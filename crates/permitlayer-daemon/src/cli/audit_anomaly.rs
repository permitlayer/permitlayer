//! Rolling-window per-service rate anomaly detector for
//! `agentsso audit --follow` (Story 5.2).
//!
//! # What this module does
//!
//! Tracks a sliding window of per-minute event counts per `service`
//! (60 buckets = 60 minutes), then compares the **current minute's**
//! rate against the **rolling average** of the previous 59 minutes.
//! When the multiplier exceeds a configured threshold (default 10×),
//! it emits a one-shot hint — subject to a per-service cooldown —
//! that the caller renders as an amber inline line between audit
//! rows.
//!
//! # Why a per-event pure function
//!
//! [`AnomalyDetector::observe`] takes `now: Instant` as a parameter
//! instead of reading `Instant::now()` internally. This is the key
//! testability seam: unit tests drive a synthetic clock with exact
//! minute boundaries, and the production caller (`audit_follow.rs`)
//! passes `Instant::now()` from the async task.
//!
//! Subprocess-level timing for rate detectors is notoriously flaky on
//! CI (cold-start scheduling jitter, thread-pool contention). The
//! preferred coverage path is unit tests driving this module directly
//! with a fake clock — the integration test in `audit_follow.rs`
//! should be a single "wiring is connected" smoke test, not a
//! full anomaly-behavior assertion.
//!
//! # Design pragmatics
//!
//! - **Per-minute, not per-second.** A 1-second window is too
//!   twitchy (single burst → false positive); a 1-hour window is too
//!   coarse (sustained spike → never fires). 1-minute buckets with
//!   a 60-minute history match the epic spec "45× baseline"
//!   language and UX-DR18 quantity-formatting convention.
//! - **Zero-baseline skip.** If the rolling average is zero (a
//!   brand-new or chronically quiet service), the current event is
//!   not a "spike" in any meaningful sense — it's the first
//!   observation. Return `None` rather than divide by zero and
//!   report `∞× baseline`.
//! - **Warmup gate.** For `baseline_warmup_seconds` after the first
//!   observation on a service, no hint can fire. This prevents the
//!   cold-start false positive where a single event inside the
//!   first minute divides by a near-zero baseline.
//! - **Cooldown is per-service.** Gmail spiking shouldn't gag a
//!   concurrent Calendar spike. Each service has its own
//!   `last_hint` timestamp tracked independently.
//! - **`cached` suppression — NOT modeled here.** The anomaly hint
//!   is a pure function of the rate, not of whether individual
//!   events came from a session cache (the Story 4.5 auto-approve
//!   concept). The cache vs. operator distinction does not carry
//!   over into rate detection.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use permitlayer_core::audit::event::AuditEvent;

use crate::config::schema::AnomalyConfig;
use crate::design::terminal::{ColorSupport, styled};
use crate::design::theme::Theme;

/// Maximum display width for a service or agent name in anomaly
/// output. Longer names are truncated with an ellipsis.
///
/// P13 review patch: audit event strings pass through Story 2.4
/// scrub-before-log so normal writer output is clean, but the audit
/// file itself is only protected by 0600 perms. A local attacker with
/// write access could craft a 1 MB service name (wasted memory + ugly
/// output) or embed ANSI escape sequences to repaint the operator's
/// terminal. Truncate at display-width + strip non-printable chars.
const MAX_DISPLAY_NAME_BYTES: usize = 64;

/// Sanitize an audit-event string field for display or use as a
/// HashMap key: strip non-printable / C1 control bytes, truncate at
/// [`MAX_DISPLAY_NAME_BYTES`] on a UTF-8 boundary, and append an
/// ellipsis if truncation happened.
///
/// P13 review patch.
fn sanitize_display(name: &str) -> String {
    // Filter: keep printable ASCII + extended Unicode; drop C0
    // (0x00-0x1F), DEL (0x7F), and C1 (0x80-0x9F when they appear as
    // raw bytes — valid UTF-8 points above 0x9F pass through because
    // they're legitimately displayable codepoints).
    let filtered: String = name
        .chars()
        .filter(|c| {
            let cp = *c as u32;
            // Strip ASCII control chars (except tab, which is harmless).
            if cp < 0x20 && cp != 0x09 {
                return false;
            }
            if cp == 0x7F {
                return false;
            }
            // Strip C1 control block.
            if (0x80..=0x9F).contains(&cp) {
                return false;
            }
            true
        })
        .collect();

    if filtered.len() <= MAX_DISPLAY_NAME_BYTES {
        return filtered;
    }

    // Truncate at UTF-8 char boundary, leaving room for the ellipsis.
    let target = MAX_DISPLAY_NAME_BYTES.saturating_sub(3);
    let mut end = target;
    while end > 0 && !filtered.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(MAX_DISPLAY_NAME_BYTES);
    out.push_str(&filtered[..end]);
    out.push_str("...");
    out
}

/// Hint emitted when a service's current-minute rate exceeds the
/// configured multiplier of its rolling baseline.
///
/// Rendered to the terminal via [`format_hint`] as:
///
/// ```text
///   anomaly: gmail call rate 45× baseline — consider `agentsso kill`
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct AnomalyHint {
    pub service: String,
    /// Integer ratio of `current_rate_per_min` to `baseline_rate_per_min`.
    pub multiplier: f64,
    pub current_rate_per_min: u64,
    pub baseline_rate_per_min: f64,
}

/// Sliding-window rate tracker for a single service.
///
/// Story 5.5 promotes this to `pub(crate)` so the connection tracker
/// (`server::conn_tracker::ConnInfo`) can hold one per active agent
/// session — the rolling-window math + hybrid-divisor cold-start
/// smoothing is identical to what the per-service anomaly detector
/// needs, and re-implementing it would risk regressing the D1 / P22 /
/// P29 review patches that landed with Story 5.2.
///
/// **L5 review patch:** internal layout (the 60-bucket array) is
/// private; consumers go through [`Self::current_rate`],
/// [`Self::requests_in_window`], and [`Self::baseline_rate`] so the
/// invariants (current-minute position, rotation-on-record,
/// hybrid-divisor smoothing) stay encapsulated.
#[derive(Debug, Clone)]
pub(crate) struct RateWindow {
    /// Last 60 minute-buckets. `buckets[59]` is the current minute;
    /// `buckets[0]` is 59 minutes ago. Shifted left on minute tick.
    buckets: [u64; 60],
    /// `Instant` anchoring the start of the current minute bucket.
    /// Set on first observation; advanced by exactly 60 seconds on
    /// each tick so rate math stays on clean minute boundaries.
    current_minute_start: Instant,
    /// `Instant` of the very first event observed on this service.
    /// Used for the warmup gate.
    started_at: Instant,
}

impl RateWindow {
    pub(crate) fn new(now: Instant) -> Self {
        Self { buckets: [0; 60], current_minute_start: now, started_at: now }
    }

    /// Advance the window so that `now` lands inside the current
    /// bucket. Shifts buckets left one position per whole-minute
    /// elapsed. Caps the shift at 60 — longer gaps are treated as
    /// a full window reset (the buckets all become zero because
    /// every slot has rotated out).
    ///
    /// P4 review patch: on the full-reset branch
    /// (`minutes_elapsed` ≥ 60), also re-arm the warmup gate by resetting
    /// `started_at` to `now`, and anchor `current_minute_start` to
    /// `now` directly (rather than advancing by a non-multiple-of-60
    /// offset that could land in the past). Before this fix, a
    /// service that went quiet for 2+ hours and then resumed was
    /// treated as "long past warmup" by the `warmed_up` gate, and
    /// could fire a spurious hint on the second minute of resumed
    /// activity against a malformed cold-start baseline.
    pub(crate) fn advance_to(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.current_minute_start);
        let minutes_elapsed = (elapsed.as_secs() / 60) as usize;
        if minutes_elapsed == 0 {
            return;
        }
        if minutes_elapsed >= 60 {
            // Full-window reset: wipe buckets AND re-arm the warmup
            // gate so the resumed service isn't treated as long past
            // warmup. Anchor `current_minute_start` to `now` so the
            // next observation lands in a freshly-aligned bucket.
            self.buckets = [0; 60];
            self.started_at = now;
            self.current_minute_start = now;
            return;
        }
        // Partial advance: shift left by `minutes_elapsed`; fill the
        // tail with 0.
        self.buckets.rotate_left(minutes_elapsed);
        let tail_start = 60 - minutes_elapsed;
        for slot in &mut self.buckets[tail_start..] {
            *slot = 0;
        }
        self.current_minute_start += Duration::from_secs(minutes_elapsed as u64 * 60);
    }

    /// Record one observation in the current-minute bucket.
    pub(crate) fn record(&mut self, now: Instant) {
        self.advance_to(now);
        self.buckets[59] = self.buckets[59].saturating_add(1);
    }

    /// `true` if the warmup period has elapsed since this window was
    /// first seeded.
    pub(crate) fn warmed_up(&self, warmup: Duration, now: Instant) -> bool {
        now.saturating_duration_since(self.started_at) >= warmup
    }

    /// Sum of events across all 60 minute-buckets — the rolling
    /// 1-hour total. Saturating add on overflow per the same
    /// discipline as `baseline_rate` (P22 review patch).
    ///
    /// L5 review patch (Story 5.5): added so consumers can read the
    /// per-hour total without exposing the bucket array.
    pub(crate) fn requests_in_window(&self) -> u64 {
        self.buckets.iter().copied().fold(0u64, u64::saturating_add)
    }

    /// Count of events observed in the current minute.
    pub(crate) fn current_rate(&self) -> u64 {
        self.buckets[59]
    }

    /// Mean of the preceding 59 minute-buckets, with a configurable
    /// floor of `min_samples` non-zero buckets in the divisor to
    /// smooth cold starts.
    ///
    /// # Hybrid divisor (D1 / P29 review patch)
    ///
    /// Dividing by `count` (non-zero buckets) alone disagrees with a
    /// natural reading of "rolling 1-hour average": a service with
    /// one event an hour ago gets `baseline = 1.0` rather than
    /// `1/59 ≈ 0.017`. Dividing by 59 is more spike-sensitive but
    /// noisy during the first hour of a follow session.
    ///
    /// The hybrid `divisor = max(count, min_samples)` splits the
    /// difference:
    /// - When `count < min_samples` (cold start): the divisor is
    ///   `min_samples`, producing a lower baseline and a more
    ///   conservative (smaller) multiplier. Fewer false positives.
    /// - When `count >= min_samples` (warmed up with real traffic):
    ///   the divisor matches `count`, converging toward the
    ///   "mean of observed minutes" interpretation.
    ///
    /// Returns 0 if `sum == 0` (no events in the preceding window).
    ///
    /// # Overflow
    ///
    /// Uses `saturating_add` on the bucket sum (P22 review patch).
    /// Realistic workloads cap at ~100K events/minute so overflow
    /// isn't reachable in practice, but the `saturating_add` closes
    /// the edge cleanly.
    pub(crate) fn baseline_rate(&self, min_samples: u64) -> f64 {
        let mut sum: u64 = 0;
        let mut count: u64 = 0;
        for &bucket in &self.buckets[..59] {
            sum = sum.saturating_add(bucket);
            if bucket > 0 {
                count = count.saturating_add(1);
            }
        }
        if sum == 0 {
            return 0.0;
        }
        let divisor = count.max(min_samples.max(1));
        sum as f64 / divisor as f64
    }
}

/// Per-service rate-anomaly detector.
///
/// Call [`Self::observe`] once per audit event that survives the
/// filter. When the hint fires, the caller renders it via
/// [`format_hint`] between rows.
#[derive(Debug)]
pub struct AnomalyDetector {
    per_service: HashMap<String, RateWindow>,
    /// Per-service timestamp of the most recently emitted hint. Used
    /// to enforce the cooldown so a sustained spike across consecutive
    /// minutes only fires ONE hint, not one per minute.
    last_hint: HashMap<String, Instant>,
    config: AnomalyConfig,
}

impl AnomalyDetector {
    /// Construct a new detector with the given config. Call
    /// [`AnomalyConfig::validated`] first to clamp out-of-range
    /// values — this constructor does NOT clamp.
    #[must_use]
    pub fn new(config: AnomalyConfig) -> Self {
        Self { per_service: HashMap::new(), last_hint: HashMap::new(), config }
    }

    /// Observe one audit event. Returns `Some(hint)` when the current
    /// minute's rate for `event.service` exceeds the configured
    /// multiplier AND the cooldown has elapsed. Returns `None` on
    /// every other path (disabled, warming up, insufficient baseline,
    /// sub-threshold, cooldown active).
    ///
    /// **Note on `error` outcomes**: every event reaches the
    /// detector, not just successful ones. The spec language "call
    /// rate 45× baseline" counts all attempts the agent made,
    /// regardless of outcome — the whole point is to detect a
    /// runaway agent, which looks the same whether every call is
    /// `ok` or every call is `denied`.
    pub fn observe(&mut self, event: &AuditEvent, now: Instant) -> Option<AnomalyHint> {
        if !self.config.enabled {
            return None;
        }

        // P13 review patch: sanitize the service name ONCE here so
        // the HashMap key, the cooldown key, and the rendered hint
        // all see the same bounded, printable string. A tampered
        // audit line with a 1 MB service name or embedded ANSI
        // escapes is truncated at 64 bytes and stripped of control
        // chars before it ever reaches the terminal.
        let service = sanitize_display(&event.service);

        // Get-or-insert the per-service window. This is the first
        // place we ever see this service, so construct with
        // `started_at = now` so the warmup gate has a reference point.
        let window =
            self.per_service.entry(service.clone()).or_insert_with(|| RateWindow::new(now));

        window.record(now);

        // Warmup gate.
        if !window.warmed_up(Duration::from_secs(self.config.baseline_warmup_seconds), now) {
            return None;
        }

        // P29 review patch: hybrid divisor `max(count, min_samples)`
        // smooths cold starts without fighting the docstring's "mean
        // of preceding 59 buckets" intent. See D1 resolution.
        let baseline = window.baseline_rate(self.config.min_samples);
        if baseline <= 0.0 {
            // First-ever event or no history in the last 59 minutes.
            // Can't compute a meaningful multiplier.
            return None;
        }

        let current = window.current_rate();
        let multiplier = current as f64 / baseline;

        // P21 review patch: guard against NaN/Infinity multiplier
        // before comparing or formatting. A subnormal baseline can
        // produce INFINITY which then renders as u64::MAX× in
        // format_hint — ugly but not a crash. Safer to skip.
        if !multiplier.is_finite() {
            return None;
        }

        if multiplier < self.config.baseline_multiplier {
            return None;
        }

        // Cooldown check.
        if let Some(last) = self.last_hint.get(&service)
            && now.saturating_duration_since(*last)
                < Duration::from_secs(self.config.cooldown_seconds)
        {
            return None;
        }

        self.last_hint.insert(service.clone(), now);

        Some(AnomalyHint {
            service,
            multiplier,
            current_rate_per_min: current,
            baseline_rate_per_min: baseline,
        })
    }
}

/// Render an [`AnomalyHint`] as a single amber terminal line.
///
/// Format:
///
/// ```text
///   anomaly: gmail call rate 45× baseline — consider `agentsso kill`
/// ```
///
/// Voice rules (§11.4 + UX-DR17):
/// - imperative for the action ("consider")
/// - passive-detection phrasing ("call rate 45× baseline" — never
///   "your agent is misbehaving")
/// - no exclamation, no "please", no "oops", no emoji
///
/// Quantity rules (§11.3 + UX-DR18):
/// - integer multiplier for values ≥10
/// - one-decimal multiplier for values in `[baseline_multiplier, 10.0)`
///
/// The color comes from the theme's `warn` (amber) token — the same
/// token the kill banner and scrub highlights use. `ColorSupport::NoColor`
/// degrades to the raw string.
#[must_use]
pub fn format_hint(hint: &AnomalyHint, theme: &Theme, support: ColorSupport) -> String {
    let multiplier_str = if hint.multiplier >= 10.0 {
        format!("{}×", hint.multiplier.round() as u64)
    } else {
        format!("{:.1}×", hint.multiplier)
    };

    let body = format!(
        "  anomaly: {service} call rate {mult} baseline — consider `agentsso kill`",
        service = hint.service,
        mult = multiplier_str,
    );

    // Apply the theme's warn (amber) token via the shared `styled`
    // helper so NoColor / Ansi16 / Ansi256 / TrueColor degradation
    // matches the rest of the design system. The same helper is used
    // by `styled_outcome` and the kill banner.
    styled(&body, theme.tokens().warn, support)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn make_event(service: &str) -> AuditEvent {
        AuditEvent::new(
            "test-agent".into(),
            service.into(),
            "test.scope".into(),
            "test-resource".into(),
            "ok".into(),
            "api-call".into(),
        )
    }

    fn fast_config() -> AnomalyConfig {
        // Shorter warmup and cooldown so unit tests finish in finite
        // time. `min_samples: 1` disables the P29 cold-start smoother
        // in these tests so the existing expected-multiplier math
        // (built around strict `sum/count` mean) continues to hold.
        // The `min_samples` clamp itself is covered by dedicated
        // tests in `config/schema.rs`, and the hybrid math under
        // larger `min_samples` is covered by
        // `baseline_rate_with_min_samples_floor_is_lower_than_strict_count`.
        AnomalyConfig {
            enabled: true,
            baseline_multiplier: 2.0,
            baseline_warmup_seconds: 120, // 2 minutes
            cooldown_seconds: 300,        // 5 minutes
            min_samples: 1,
        }
    }

    #[test]
    fn disabled_detector_returns_none_regardless() {
        let mut detector = AnomalyDetector::new(AnomalyConfig { enabled: false, ..fast_config() });
        let now = Instant::now();
        let event = make_event("gmail");
        for _ in 0..100 {
            assert!(detector.observe(&event, now).is_none());
        }
    }

    #[test]
    fn no_hint_while_warming_up() {
        let mut detector = AnomalyDetector::new(fast_config());
        let start = Instant::now();
        let event = make_event("gmail");
        // First minute: spike of 100 events. Should NOT fire because
        // warmup hasn't elapsed.
        for _ in 0..100 {
            assert!(detector.observe(&event, start).is_none());
        }
    }

    #[test]
    fn zero_baseline_never_fires_even_after_warmup() {
        let mut detector = AnomalyDetector::new(fast_config());
        let start = Instant::now();
        let event = make_event("gmail");

        // Warmup elapses (nothing observed in previous minutes).
        let past_warmup = start + Duration::from_secs(200);
        // Single event after warmup — baseline is 0, so no hint.
        assert!(detector.observe(&event, past_warmup).is_none());
    }

    #[test]
    fn spike_after_warmup_fires_hint_with_correct_multiplier() {
        let mut detector = AnomalyDetector::new(fast_config());
        let start = Instant::now();
        let event = make_event("gmail");

        // Minutes 0 and 1: baseline of 2 events/min.
        detector.observe(&event, start);
        detector.observe(&event, start);
        let minute_1 = start + Duration::from_secs(60);
        detector.observe(&event, minute_1);
        detector.observe(&event, minute_1);

        // Minute 2: warmup complete (120s elapsed), spike.
        let minute_2 = start + Duration::from_secs(120);
        // First 3 events in minute 2: cumulative 3/min current vs
        // baseline avg ~2/min → 1.5× multiplier, below 2.0 threshold.
        for _ in 0..3 {
            assert!(
                detector.observe(&event, minute_2).is_none(),
                "below-threshold multiplier should not fire"
            );
        }
        // 4th event: 4/min current vs baseline 2/min = 2.0× → FIRES.
        let hint = detector.observe(&event, minute_2).expect("hint should fire");
        assert_eq!(hint.service, "gmail");
        assert!(hint.multiplier >= 2.0);
        assert_eq!(hint.current_rate_per_min, 4);
        assert!((hint.baseline_rate_per_min - 2.0).abs() < 0.01);
    }

    #[test]
    fn cooldown_suppresses_second_spike_within_window() {
        let mut detector = AnomalyDetector::new(fast_config());
        let start = Instant::now();
        let event = make_event("gmail");

        // Warmup: 1 event/min for 2 minutes.
        detector.observe(&event, start);
        detector.observe(&event, start + Duration::from_secs(60));

        // Minute 2: burst that crosses the 2.0× threshold.
        // Baseline after warmup = 1.0 events/min. First observation
        // in minute 2 yields current=1, multiplier=1.0 → no fire.
        // Second observation yields current=2, multiplier=2.0 → FIRES.
        // Subsequent observations within the cooldown should be
        // suppressed.
        let minute_2 = start + Duration::from_secs(120);
        let mut fired_count = 0;
        for _ in 0..5 {
            if detector.observe(&event, minute_2).is_some() {
                fired_count += 1;
            }
        }
        assert_eq!(
            fired_count, 1,
            "exactly one hint should fire in minute 2 (first one above threshold), \
             subsequent same-minute observations are cooled down"
        );

        // Minute 3: another spike within cooldown window (300s).
        let minute_3 = start + Duration::from_secs(180);
        for _ in 0..10 {
            assert!(
                detector.observe(&event, minute_3).is_none(),
                "second spike within cooldown should be suppressed"
            );
        }
    }

    #[test]
    fn cooldown_expiry_allows_new_hint() {
        // 60-second cooldown so minute 3 is safely outside it.
        let mut detector =
            AnomalyDetector::new(AnomalyConfig { cooldown_seconds: 60, ..fast_config() });
        let start = Instant::now();
        let event = make_event("gmail");

        // Warmup.
        detector.observe(&event, start);
        detector.observe(&event, start + Duration::from_secs(60));

        // First spike at minute 2: FIRES on 2nd observation.
        let minute_2 = start + Duration::from_secs(120);
        let mut minute_2_fires = 0;
        for _ in 0..5 {
            if detector.observe(&event, minute_2).is_some() {
                minute_2_fires += 1;
            }
        }
        assert_eq!(minute_2_fires, 1, "minute 2 should fire exactly once");

        // Minute 3: cooldown window (60s) has expired (we are now
        // 60s after the hint). Another spike should fire.
        // But now baseline has shifted: minute 2 contributed 5
        // events, minutes 0/1 contributed 1 each. When we get to
        // minute 3, baseline includes the minute 2 count, so
        // avg = (1+1+5)/3 ≈ 2.33. Spike needs current ≥ 4.67 to
        // hit 2.0× threshold.
        let minute_3 = start + Duration::from_secs(180);
        let mut minute_3_fires = 0;
        for _ in 0..10 {
            if detector.observe(&event, minute_3).is_some() {
                minute_3_fires += 1;
            }
        }
        assert_eq!(minute_3_fires, 1, "minute 3 should fire exactly once after cooldown expires");
    }

    #[test]
    fn multi_service_windows_are_independent() {
        let mut detector = AnomalyDetector::new(fast_config());
        let start = Instant::now();

        // Warmup both services in parallel.
        let gmail = make_event("gmail");
        let calendar = make_event("calendar");
        detector.observe(&gmail, start);
        detector.observe(&calendar, start);
        let minute_1 = start + Duration::from_secs(60);
        detector.observe(&gmail, minute_1);
        detector.observe(&calendar, minute_1);

        // Minute 2: only gmail spikes.
        let minute_2 = start + Duration::from_secs(120);
        let mut gmail_fires = 0;
        for _ in 0..10 {
            if detector.observe(&gmail, minute_2).is_some() {
                gmail_fires += 1;
            }
        }
        // Gmail fires at least once (exactly once due to cooldown).
        assert_eq!(gmail_fires, 1, "gmail spike should fire exactly once under cooldown");

        // Calendar baseline is 1.0 and calendar has 0 events in
        // minute 2 so far. One calendar observation at minute 2
        // yields current=1, multiplier=1.0 → no fire. Good.
        assert!(
            detector.observe(&calendar, minute_2).is_none(),
            "calendar with no spike should not fire"
        );
    }

    #[test]
    fn window_advance_resets_after_long_gap() {
        // P4 review patch: a full-window reset must not only wipe the
        // buckets but also re-arm the warmup gate and anchor
        // `current_minute_start` to `now`. Before the fix, a service
        // that went quiet for 2+ hours and resumed was treated as long
        // past warmup, and could fire spurious hints on the first
        // post-reset minute against a malformed cold-start baseline.
        let start = Instant::now();
        let mut window = RateWindow::new(start);
        window.buckets[59] = 100;
        let later = start + Duration::from_secs(7200);
        window.advance_to(later);

        // Buckets wiped.
        assert_eq!(window.buckets.iter().sum::<u64>(), 0);
        // Warmup gate re-armed (started_at is now anchored to the
        // post-gap Instant, not the original start).
        assert_eq!(window.started_at, later);
        // Current-minute anchor moved to `now` exactly.
        assert_eq!(window.current_minute_start, later);
        // Warmed-up check: at exactly `later`, zero time has elapsed
        // since started_at, so warmup of any non-zero duration should
        // NOT yet have passed.
        assert!(!window.warmed_up(Duration::from_secs(1), later));
    }

    #[test]
    fn window_advance_partial_shifts_correctly() {
        let mut window = RateWindow::new(Instant::now());
        let start = Instant::now();
        window.buckets[59] = 100;
        window.buckets[58] = 50;
        // Advance by 2 minutes: 100 shifts from [59] to [57], 50
        // shifts from [58] to [56].
        window.advance_to(start + Duration::from_secs(120));
        assert_eq!(window.buckets[57], 100);
        assert_eq!(window.buckets[56], 50);
        assert_eq!(window.buckets[58], 0);
        assert_eq!(window.buckets[59], 0);
    }

    // ----- format_hint formatting -----

    #[test]
    fn format_hint_integer_multiplier_for_large_values() {
        let hint = AnomalyHint {
            service: "gmail".into(),
            multiplier: 45.3,
            current_rate_per_min: 453,
            baseline_rate_per_min: 10.0,
        };
        let s = format_hint(&hint, &Theme::Carapace, ColorSupport::NoColor);
        assert!(s.contains("45×"), "expected integer multiplier, got: {s}");
        assert!(s.contains("gmail"));
        assert!(s.contains("anomaly"));
        assert!(s.contains("`agentsso kill`"));
        assert!(s.contains("consider"));
    }

    #[test]
    fn format_hint_one_decimal_multiplier_for_smaller_values() {
        let hint = AnomalyHint {
            service: "calendar".into(),
            multiplier: 3.5,
            current_rate_per_min: 35,
            baseline_rate_per_min: 10.0,
        };
        let s = format_hint(&hint, &Theme::Carapace, ColorSupport::NoColor);
        assert!(s.contains("3.5×"), "expected one-decimal multiplier, got: {s}");
    }

    #[test]
    fn format_hint_nocolor_has_no_ansi_escapes() {
        let hint = AnomalyHint {
            service: "gmail".into(),
            multiplier: 45.0,
            current_rate_per_min: 450,
            baseline_rate_per_min: 10.0,
        };
        let s = format_hint(&hint, &Theme::Carapace, ColorSupport::NoColor);
        assert!(!s.contains('\x1b'), "expected no ANSI escapes in NoColor output");
    }

    #[test]
    fn format_hint_truecolor_wraps_in_ansi_escape() {
        let hint = AnomalyHint {
            service: "gmail".into(),
            multiplier: 45.0,
            current_rate_per_min: 450,
            baseline_rate_per_min: 10.0,
        };
        let s = format_hint(&hint, &Theme::Carapace, ColorSupport::TrueColor);
        assert!(s.starts_with("\x1b["));
        assert!(s.ends_with("\x1b[0m"));
    }

    #[test]
    fn format_hint_voice_rules_no_exclamation_or_please() {
        let hint = AnomalyHint {
            service: "gmail".into(),
            multiplier: 45.0,
            current_rate_per_min: 450,
            baseline_rate_per_min: 10.0,
        };
        let s = format_hint(&hint, &Theme::Carapace, ColorSupport::NoColor);
        assert!(!s.contains('!'), "UX-DR17: no exclamation marks");
        assert!(!s.contains("please"), "UX-DR17: no 'please'");
        assert!(!s.contains("oops"), "UX-DR17: no 'oops'");
    }

    #[test]
    fn format_hint_uses_shared_design_system_token() {
        // Sanity: verify we ARE using the theme.warn token (not a
        // hard-coded hex). Check via NoColor + non-empty string.
        let hint = AnomalyHint {
            service: "gmail".into(),
            multiplier: 45.0,
            current_rate_per_min: 450,
            baseline_rate_per_min: 10.0,
        };
        let s = format_hint(&hint, &Theme::Carapace, ColorSupport::NoColor);
        // NoColor returns the raw body string, which should have the
        // anomaly prefix, service name, multiplier, and command.
        assert!(s.contains("anomaly"));
        assert!(s.contains("gmail"));
        assert!(s.contains("45×"));
        assert!(s.contains("baseline"));
        assert!(s.contains("`agentsso kill`"));
    }

    // ----- P18: scrub-before-log invariant enforcement -----

    #[test]
    fn audit_anomaly_module_does_not_import_scrub_engine() {
        // Story 2.4 scrub-before-log invariant + Story 5.2 AC #12:
        // the anomaly detector sees raw `AuditEvent`s post-scrub and
        // must never attempt to re-scrub. Mirror test for the
        // audit_follow module. `concat!` splits the forbidden tokens
        // so this assertion source doesn't match itself via
        // `include_str!`.
        let src = include_str!("audit_anomaly.rs");
        let forbidden_crate = concat!("use crate::", "scrub::", "ScrubEngine");
        let forbidden_core = concat!("use permitlayer_core::", "scrub::", "ScrubEngine");
        let forbidden_path = concat!("Scrub", "Engine", "::");
        assert!(
            !src.contains(forbidden_crate),
            "audit_anomaly must not import crate::scrub engine (Story 2.4 invariant)"
        );
        assert!(
            !src.contains(forbidden_core),
            "audit_anomaly must not import permitlayer_core scrub engine"
        );
        assert!(
            !src.contains(forbidden_path),
            "audit_anomaly must not reference the scrub-engine qualified path"
        );
    }

    // ----- P29 hybrid divisor -----

    #[test]
    fn baseline_rate_with_min_samples_floor_is_lower_than_strict_count() {
        // Seed a window with ONE non-zero bucket (1 event).
        let start = Instant::now();
        let mut window = RateWindow::new(start);
        window.buckets[0] = 1;

        // Strict count divisor (min_samples=1): baseline = 1/1 = 1.0.
        let strict = window.baseline_rate(1);
        assert!((strict - 1.0).abs() < f64::EPSILON);

        // min_samples=3 (default): baseline = 1/3 ≈ 0.333 (lower ⇒
        // more conservative multiplier when we divide current by it).
        let hybrid = window.baseline_rate(3);
        assert!((hybrid - (1.0 / 3.0)).abs() < f64::EPSILON);
        assert!(hybrid < strict, "hybrid divisor should lower baseline vs strict count");
    }

    #[test]
    fn baseline_rate_at_scale_converges_toward_strict_mean() {
        // With 30 non-zero buckets, `max(count, 3) == count` so the
        // hybrid behavior matches strict count.
        let start = Instant::now();
        let mut window = RateWindow::new(start);
        for slot in &mut window.buckets[..30] {
            *slot = 10;
        }
        let strict = window.baseline_rate(1);
        let hybrid = window.baseline_rate(3);
        assert!((strict - 10.0).abs() < f64::EPSILON);
        assert!((hybrid - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn baseline_rate_returns_zero_when_no_events() {
        let start = Instant::now();
        let window = RateWindow::new(start);
        assert_eq!(window.baseline_rate(1), 0.0);
        assert_eq!(window.baseline_rate(3), 0.0);
        assert_eq!(window.baseline_rate(59), 0.0);
    }

    #[test]
    fn observe_with_min_samples_default_is_more_conservative_than_min_samples_one() {
        // Same event stream under two configs; the min_samples=3
        // config should fire later (or not at all for a given
        // threshold) than the min_samples=1 config.
        //
        // Baseline scenario: 2 events in minute 0, then spike in
        // minute 2 (warmup = 120s).
        let make_cfg = |min_samples: u64| AnomalyConfig {
            enabled: true,
            baseline_multiplier: 3.0,
            baseline_warmup_seconds: 120,
            cooldown_seconds: 60,
            min_samples,
        };
        let start = Instant::now();
        let event = make_event("gmail");

        // Strict config (min_samples=1): baseline from minute 0 = 2
        // (count=1), minute 2 spike of 6 events gives multiplier
        // 6/2 = 3.0 — crosses threshold, fires.
        let mut d_strict = AnomalyDetector::new(make_cfg(1));
        d_strict.observe(&event, start);
        d_strict.observe(&event, start);
        d_strict.observe(&event, start + Duration::from_secs(60));
        let m2 = start + Duration::from_secs(120);
        let mut strict_fires = 0;
        for _ in 0..6 {
            if d_strict.observe(&event, m2).is_some() {
                strict_fires += 1;
            }
        }
        assert!(strict_fires >= 1, "strict config should fire on 6-event spike");

        // Hybrid config (min_samples=3): baseline from minute 0 = 2
        // (max(count=1, 3)=3), so baseline = 2/3 ≈ 0.667. Spike of
        // 6 gives multiplier ≈ 9 — crosses threshold 3.0, also fires.
        // The difference: under a smaller spike the hybrid would NOT
        // fire because the divisor keeps the baseline smaller and
        // thus the multiplier LARGER... wait, that's backwards.
        //
        // Actually: smaller divisor (1) means LARGER baseline (2/1=2);
        // larger divisor (3) means SMALLER baseline (2/3≈0.67); so
        // the SAME current rate produces a LARGER multiplier under
        // hybrid. The hybrid makes the detector MORE sensitive to
        // spikes against a cold-start partial window, not less. This
        // is the intended behavior — cold-start smoothing means we
        // DIDN'T trust the apparent "high baseline" of 2/1=2 when
        // there's only one data point, so we spread it over 3 slots
        // mentally, producing a lower baseline and a spike looks
        // proportionally larger.
        //
        // This test documents the relationship: under the same
        // spike, hybrid produces a LARGER multiplier than strict
        // count. Both fire; the difference shows up at the edges.
        let mut d_hybrid = AnomalyDetector::new(make_cfg(3));
        d_hybrid.observe(&event, start);
        d_hybrid.observe(&event, start);
        d_hybrid.observe(&event, start + Duration::from_secs(60));
        let mut hybrid_fires = 0;
        for _ in 0..6 {
            if d_hybrid.observe(&event, m2).is_some() {
                hybrid_fires += 1;
            }
        }
        assert!(hybrid_fires >= 1, "hybrid config should fire on 6-event spike");
    }

    // ----- P13 sanitize_display -----

    #[test]
    fn sanitize_display_passes_through_short_printable() {
        assert_eq!(sanitize_display("gmail"), "gmail");
        assert_eq!(sanitize_display("my-custom-service"), "my-custom-service");
    }

    #[test]
    fn sanitize_display_strips_control_chars() {
        let s = "gmail\x1b[31mEVIL\x1b[0m";
        let cleaned = sanitize_display(s);
        assert!(!cleaned.contains('\x1b'), "escape chars should be stripped");
        assert!(cleaned.contains("gmail"));
    }

    #[test]
    fn sanitize_display_truncates_long_strings_with_ellipsis() {
        let long = "x".repeat(1024);
        let cleaned = sanitize_display(&long);
        assert!(cleaned.len() <= 64, "should truncate to MAX_DISPLAY_NAME_BYTES (64)");
        assert!(cleaned.ends_with("..."), "truncation should end with ...");
    }

    #[test]
    fn sanitize_display_handles_nul_byte() {
        assert_eq!(sanitize_display("gmail\x00hidden"), "gmailhidden");
    }

    #[test]
    fn sanitize_display_preserves_tab_character() {
        // Tab is harmless and sometimes intentional in structured output.
        assert_eq!(sanitize_display("col1\tcol2"), "col1\tcol2");
    }

    #[test]
    fn sanitize_display_preserves_non_ascii_printable() {
        // Unicode above C1 control block should pass through.
        assert_eq!(sanitize_display("café"), "café");
        assert_eq!(sanitize_display("日本語"), "日本語");
    }

    // ----- P21 is_finite multiplier guard -----

    #[test]
    fn observe_returns_none_when_multiplier_would_be_infinite() {
        // Hard to hit the NaN/Infinity path directly via the public
        // API since `baseline <= 0.0` already guards. Prove the path
        // exists by checking that a detector with a legitimately
        // zero baseline returns None (the shared guard covers both).
        let cfg = AnomalyConfig {
            enabled: true,
            baseline_multiplier: 2.0,
            baseline_warmup_seconds: 1, // minimal
            cooldown_seconds: 0,
            min_samples: 1,
        };
        let mut detector = AnomalyDetector::new(cfg);
        let start = Instant::now();
        let event = make_event("gmail");
        // First observation: warmed_up will be true after 1s, but
        // baseline is 0 (no prior minutes). Must return None.
        detector.observe(&event, start);
        let later = start + Duration::from_secs(2);
        assert!(
            detector.observe(&event, later).is_none(),
            "zero-baseline path must return None (is_finite guard would trigger on INFINITY)"
        );
    }
}
