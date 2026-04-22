//! Criterion benchmarks for `ScrubEngine`.
//!
//! CI threshold enforcement: These benchmarks use criterion's statistical
//! comparison for detecting regressions between runs. A separate CI step
//! (Story 2.3 or later) can gate on regression. For now, benchmarks must
//! exist and run without error via `cargo bench -p permitlayer-core`.

#![allow(clippy::expect_used)]

use criterion::{Criterion, criterion_group, criterion_main};
use permitlayer_core::scrub::{Placeholder, ScrubEngine, ScrubRule, builtin_rules};

/// Build the OTP test rule.
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
    .expect("otp rule should compile")
}

/// Build a bearer token test rule.
fn bearer_rule() -> ScrubRule {
    ScrubRule::new(
        "bearer",
        vec!["bearer".to_string()],
        r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*",
        Placeholder::Bearer,
    )
    .expect("bearer rule should compile")
}

/// Build a test engine with sample rules.
fn build_engine() -> ScrubEngine {
    ScrubEngine::new(vec![otp_rule(), bearer_rule()]).expect("engine should build")
}

/// Generate a payload of approximately `size` bytes of lorem ipsum.
fn generate_clean_payload(size: usize) -> String {
    let base = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
                Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \
                Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris. ";
    let mut payload = String::with_capacity(size);
    while payload.len() < size {
        payload.push_str(base);
    }
    payload.truncate(size);
    payload
}

/// Generate a payload with sensitive patterns injected at regular intervals.
fn generate_sparse_payload(size: usize, pattern_count: usize) -> String {
    let base = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ";
    let patterns = [
        "Your verification code is 123456. ",
        "The passcode 654321 was sent to your device. ",
        "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.test_token. ",
        "Enter code: 987654 to proceed. ",
        "Your code is 111222 for login. ",
    ];
    let mut payload = String::with_capacity(size);
    let interval = size / (pattern_count + 1);
    let mut next_inject = interval;
    let mut pattern_idx = 0;

    while payload.len() < size {
        if payload.len() >= next_inject && pattern_idx < pattern_count {
            payload.push_str(patterns[pattern_idx % patterns.len()]);
            pattern_idx += 1;
            next_inject += interval;
        } else {
            payload.push_str(base);
        }
    }
    payload.truncate(size);
    payload
}

/// Generate a payload with dense sensitive patterns.
fn generate_dense_payload(size: usize, pattern_count: usize) -> String {
    let patterns = [
        "Your verification code is 123456. ",
        "The passcode 654321 was sent. ",
        "code: 111222 ",
        "Bearer abc123token. ",
        "code is 999888 ok. ",
    ];
    let filler = "Some text. ";
    let mut payload = String::with_capacity(size);
    let mut i = 0;
    let mut injected = 0;

    while payload.len() < size {
        if injected < pattern_count && i % 3 == 0 {
            payload.push_str(patterns[injected % patterns.len()]);
            injected += 1;
        } else {
            payload.push_str(filler);
        }
        i += 1;
    }
    payload.truncate(size);
    payload
}

/// Build the full built-in rule set engine (9 rules).
fn build_full_engine() -> ScrubEngine {
    ScrubEngine::new(builtin_rules().to_vec()).expect("builtin rules should build")
}

fn bench_scrub(c: &mut Criterion) {
    let engine = build_engine();

    // 100KB benchmarks
    let clean_100kb = generate_clean_payload(100 * 1024);
    c.bench_function("scrub_100kb_no_matches", |b| {
        b.iter(|| engine.scrub(&clean_100kb));
    });

    let sparse_100kb = generate_sparse_payload(100 * 1024, 5);
    c.bench_function("scrub_100kb_sparse_matches", |b| {
        b.iter(|| engine.scrub(&sparse_100kb));
    });

    let dense_100kb = generate_dense_payload(100 * 1024, 50);
    c.bench_function("scrub_100kb_dense_matches", |b| {
        b.iter(|| engine.scrub(&dense_100kb));
    });

    // 1MB benchmarks
    let clean_1mb = generate_clean_payload(1024 * 1024);
    c.bench_function("scrub_1mb_no_matches", |b| {
        b.iter(|| engine.scrub(&clean_1mb));
    });

    let sparse_1mb = generate_sparse_payload(1024 * 1024, 10);
    c.bench_function("scrub_1mb_sparse_matches", |b| {
        b.iter(|| engine.scrub(&sparse_1mb));
    });

    // Overhead measurements
    c.bench_function("scrub_empty", |b| {
        b.iter(|| engine.scrub(""));
    });

    c.bench_function("scrub_small_10b", |b| {
        b.iter(|| engine.scrub("hello wor!"));
    });

    // --- Full built-in ruleset benchmarks (9 rules) ---
    let full_engine = build_full_engine();

    let clean_100kb_full = generate_clean_payload(100 * 1024);
    c.bench_function("scrub_full_ruleset_100kb_clean", |b| {
        b.iter(|| full_engine.scrub(&clean_100kb_full));
    });

    let sparse_100kb_full = generate_sparse_payload(100 * 1024, 5);
    c.bench_function("scrub_full_ruleset_100kb_sparse", |b| {
        b.iter(|| full_engine.scrub(&sparse_100kb_full));
    });

    let clean_1mb_full = generate_clean_payload(1024 * 1024);
    c.bench_function("scrub_full_ruleset_1mb_clean", |b| {
        b.iter(|| full_engine.scrub(&clean_1mb_full));
    });

    let sparse_1mb_full = generate_sparse_payload(1024 * 1024, 10);
    c.bench_function("scrub_full_ruleset_1mb_sparse", |b| {
        b.iter(|| full_engine.scrub(&sparse_1mb_full));
    });
}

criterion_group!(benches, bench_scrub);
criterion_main!(benches);
