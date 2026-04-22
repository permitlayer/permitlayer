//! Concurrency integration test for `ScrubEngine`.
//!
//! Verifies that 50 concurrent scrub calls on the same `Arc<ScrubEngine>`
//! produce deterministic, identical results with no race conditions.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use permitlayer_core::scrub::{Placeholder, ScrubEngine, ScrubRule};

/// Build a test engine with a realistic OTP rule.
fn build_test_engine() -> Arc<ScrubEngine> {
    let otp_rule = ScrubRule::new(
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
    .unwrap();

    Arc::new(ScrubEngine::new(vec![otp_rule]).unwrap())
}

/// Build a 100KB payload with known OTP-like patterns scattered throughout.
fn build_100kb_payload() -> String {
    let base = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ";
    let mut payload = String::with_capacity(100 * 1024);
    let mut i = 0;
    while payload.len() < 100 * 1024 {
        if i % 500 == 100 {
            payload.push_str("Your verification code is 123456. ");
        } else if i % 500 == 300 {
            payload.push_str("The passcode 654321 was sent. ");
        } else {
            payload.push_str(base);
        }
        i += 1;
    }
    payload
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_50_concurrent_scrubs_are_deterministic() {
    let engine = build_test_engine();
    let input = build_100kb_payload();

    // Reference result from a single-threaded scrub.
    let reference = engine.scrub(&input);

    let mut handles = Vec::with_capacity(50);
    for _ in 0..50 {
        let engine = Arc::clone(&engine);
        let input = input.clone();
        handles.push(tokio::spawn(async move { engine.scrub(&input) }));
    }

    let mut results = Vec::with_capacity(50);
    for handle in handles {
        results.push(handle.await.expect("task should not panic"));
    }

    // All 50 results must be identical to the reference.
    for (i, result) in results.iter().enumerate() {
        assert_eq!(result.output, reference.output, "result {i} output differs from reference");
        assert_eq!(result.match_count(), reference.match_count(), "result {i} match count differs");
        for (j, (a, b)) in result.matches.iter().zip(reference.matches.iter()).enumerate() {
            assert_eq!(a.span, b.span, "result {i} match {j} span differs");
            assert_eq!(a.rule_name, b.rule_name, "result {i} match {j} rule_name differs");
            assert_eq!(a.placeholder, b.placeholder, "result {i} match {j} placeholder differs");
        }
    }
}
