//! Criterion benchmarks for `PolicySet::evaluate`.
//!
//! AC #3 / NFR4: policy evaluation must be <10ms p99 at 100 policies
//! on in-memory rules. This benchmark generates 100 synthetic policies
//! into a `TempDir`, compiles them, and measures `evaluate` under
//! four request shapes:
//!
//! - `hit_first_rule_allow` — best case; the first rule (allow-reads)
//!   fires on the first policy. No rule walking beyond index 0.
//! - `hit_last_rule_deny` — worst case for rule walk; the request
//!   targets the LAST rule (`deny-admin-N`) in a middle-indexed
//!   policy, forcing the evaluator to walk past two non-matching
//!   rules before finding the match. This is the rule-walk tail
//!   that the NFR4 budget protects against.
//! - `policy_fallthrough_allow` — no rule matches (scope is in the
//!   policy allowlist but no rule's overrides cover it), so the
//!   evaluator walks every rule AND falls through to the policy-
//!   level approval-mode default. Also a worst-case rule-walk path.
//! - `unmatched_policy` — default-deny path; builds a `Deny` variant
//!   with allocated strings, which is the most expensive common
//!   outcome.
//!
//! Thresholds are NOT yet enforced in CI — criterion runs
//! informationally to establish a baseline. Story 4.1 Dev Notes
//! records the measured p99 in Completion Notes; CI gating moves
//! to a follow-up once variance is known.
//!
//! Criterion reports the *mean* point-estimate per iteration; Story
//! 4.1 Dev Notes narrated early values as "p99" which was a
//! terminology misnomer. The <10ms NFR4 budget applies to p99
//! request latency in a production pipeline and is not directly
//! comparable to these synthetic-microbench mean values; the current
//! ~27–110 ns mean measurements are ~5 orders of magnitude under
//! the NFR4 budget, so the terminology mismatch is informational —
//! see Story 8.6 AC #2 (`cargo xtask bench-check --enforce`) for the
//! 3× headroom regression guard, which is enforced locally. CI
//! wiring is deferred until the project has a git remote; operators
//! run the harness pre-commit or as a pre-push hook.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use criterion::{Criterion, criterion_group, criterion_main};

use permitlayer_core::policy::{EvalRequest, PolicySet};

/// Generate `count` synthetic policies into `dir`, one file per policy.
///
/// Each policy has:
/// - 5 scopes (`service-N.read`, `service-N.write`, `service-N.meta`,
///   `service-N.admin`, `service-N.ping`) — the last one is in the
///   allowlist but not covered by any rule, so requests against it
///   exercise the rule-walk fall-through to the policy-level default.
/// - 3 rules (allow reads, prompt writes, deny admin) — disjoint
///   scope overrides so no shadow detection fires.
/// - resource allowlist of 3 explicit resources.
///
/// The shape is chosen to stress the evaluator's hot path: multi-rule
/// walks, scope allowlist membership checks, resource matcher hits,
/// and the full rule-walk fall-through to the policy-level default.
fn generate_hundred_policies(dir: &Path, count: usize) {
    for i in 0..count {
        let src = format!(
            r#"
[[policies]]
name = "policy-{i:03}"
scopes = ["service-{i}.read", "service-{i}.write", "service-{i}.meta", "service-{i}.admin", "service-{i}.ping"]
resources = ["primary-{i}", "secondary-{i}", "tertiary-{i}"]
approval-mode = "auto"

[[policies.rules]]
id = "allow-reads-{i}"
scopes = ["service-{i}.read", "service-{i}.meta"]
action = "allow"

[[policies.rules]]
id = "prompt-writes-{i}"
scopes = ["service-{i}.write"]
action = "prompt"

[[policies.rules]]
id = "deny-admin-{i}"
scopes = ["service-{i}.admin"]
action = "deny"
"#
        );
        let path = dir.join(format!("policy-{i:03}.toml"));
        std::fs::write(&path, src).unwrap();
    }
}

fn bench_policy_eval(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    generate_hundred_policies(dir.path(), 100);
    let policy_set =
        PolicySet::compile_from_dir(dir.path()).expect("100 synthetic policies must compile");
    assert_eq!(policy_set.len(), 100);

    // Best case: the first rule (allow-reads) fires on the first
    // policy after an O(1) HashMap lookup. Rule walk stops at index 0.
    let hit_first_rule_allow = EvalRequest {
        policy_name: "policy-000".to_owned(),
        scope: "service-0.read".to_owned(),
        resource: Some("primary-0".to_owned()),
    };
    // Worst case for rule walk: the last rule (deny-admin) matches
    // on a middle-indexed policy (forces HashMap lookup to a non-
    // zero bucket), so the evaluator walks past `allow-reads` and
    // `prompt-writes` before finding `deny-admin`. This is the
    // p99-tail scenario the NFR4 budget is for.
    let hit_last_rule_deny = EvalRequest {
        policy_name: "policy-050".to_owned(),
        scope: "service-50.admin".to_owned(),
        resource: Some("tertiary-50".to_owned()),
    };
    // Fall-through: the scope is in the policy allowlist but no
    // rule's overrides cover it. The evaluator walks every rule
    // (all three miss) AND then falls through to the policy-level
    // approval-mode default. Also a full rule walk plus the scope
    // allowlist + resource allowlist checks.
    let policy_fallthrough_allow = EvalRequest {
        policy_name: "policy-099".to_owned(),
        scope: "service-99.ping".to_owned(),
        resource: Some("primary-99".to_owned()),
    };
    // Default-deny path: builds a `Deny` variant with allocated
    // strings — the most expensive common outcome.
    let unmatched = EvalRequest {
        policy_name: "policy-does-not-exist".to_owned(),
        scope: "service-x.read".to_owned(),
        resource: None,
    };

    c.bench_function("policy_eval_100_policies_hit_first_rule_allow", |b| {
        b.iter(|| policy_set.evaluate(std::hint::black_box(&hit_first_rule_allow)))
    });
    c.bench_function("policy_eval_100_policies_hit_last_rule_deny", |b| {
        b.iter(|| policy_set.evaluate(std::hint::black_box(&hit_last_rule_deny)))
    });
    c.bench_function("policy_eval_100_policies_fallthrough_allow", |b| {
        b.iter(|| policy_set.evaluate(std::hint::black_box(&policy_fallthrough_allow)))
    });
    c.bench_function("policy_eval_100_policies_unmatched_deny", |b| {
        b.iter(|| policy_set.evaluate(std::hint::black_box(&unmatched)))
    });
}

criterion_group!(benches, bench_policy_eval);
criterion_main!(benches);
