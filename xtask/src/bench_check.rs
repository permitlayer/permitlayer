//! Criterion benchmark regression harness.
//!
//! Invokes `cargo bench -p permitlayer-core --bench <target>` for each
//! entry in [`BENCH_TARGETS`] (see [`run_cargo_bench`] for why the
//! invocation is narrowed to named bench targets rather than
//! `--workspace`), parses criterion's `target/criterion/<bench>/new/
//! estimates.json` for each name in [`BENCH_NAMES`], and compares the
//! measured mean walltime against a committed baseline in
//! `xtask/src/bench_check/baselines.toml`. A 3× headroom multiplier
//! is applied in `--enforce` mode — measurements that exceed
//! `3.0 × baseline_mean_ns` cause the command to exit 1.
//!
//! The 3× multiplier is deliberately loose. Hard-gating on raw
//! per-bench walltimes is flake-prone under any kind of host-noise
//! variance (thermal throttling, background tasks, hardware upgrade).
//! This harness catches algorithmic regressions — e.g. someone
//! replacing aho-corasick with a linear scan — without firing on
//! day-to-day noise.
//!
//! Enforcement is local-only: this is the regression surface
//! operators run before commits or as a pre-push hook. CI wiring is
//! deferred until the project has a git remote. Tighter NFR2/NFR4
//! per-budget gating (2 ms / 10 ms) is separately deferred to Epic 7.
//!
//! See Story 8.6 AC #1–#3 and `baselines.toml` for the benchmark set.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

/// Multiplier over `baseline_mean_ns` that triggers an enforce-mode failure.
///
/// Sized for VM-noise tolerance on shared GitHub Actions runners; see
/// module-level docs for the rationale.
const HEADROOM_MULTIPLIER: f64 = 3.0;

const BASELINES_TOML: &str = include_str!("bench_check/baselines.toml");

/// The 15 criterion benches shipped by `permitlayer-core` as of Story 8.6.
///
/// Keeping the list explicit (rather than globbing `target/criterion/`)
/// means a bench that fails to build surfaces as a "missing estimates.json"
/// error rather than a silent skip.
const BENCH_NAMES: &[&str] = &[
    "scrub_100kb_no_matches",
    "scrub_100kb_sparse_matches",
    "scrub_100kb_dense_matches",
    "scrub_1mb_no_matches",
    "scrub_1mb_sparse_matches",
    "scrub_empty",
    "scrub_small_10b",
    "scrub_full_ruleset_100kb_clean",
    "scrub_full_ruleset_100kb_sparse",
    "scrub_full_ruleset_1mb_clean",
    "scrub_full_ruleset_1mb_sparse",
    "policy_eval_100_policies_hit_first_rule_allow",
    "policy_eval_100_policies_hit_last_rule_deny",
    "policy_eval_100_policies_fallthrough_allow",
    "policy_eval_100_policies_unmatched_deny",
];

/// Narrow view into criterion's `new/estimates.json` — only the field we need.
#[derive(Debug, Deserialize)]
struct CriterionEstimates {
    mean: Estimate,
}

#[derive(Debug, Deserialize)]
struct Estimate {
    point_estimate: f64,
}

/// Result of comparing a single bench against its baseline.
#[derive(Debug, Clone)]
struct BenchResult {
    name: String,
    measured_ns: f64,
    baseline_ns: Option<f64>,
}

impl BenchResult {
    fn ratio(&self) -> Option<f64> {
        self.baseline_ns.map(|b| self.measured_ns / b)
    }

    fn exceeds_headroom(&self) -> bool {
        match self.ratio() {
            Some(r) => r > HEADROOM_MULTIPLIER,
            None => false,
        }
    }
}

/// Run the bench-check harness.
///
/// When `enforce` is false, the command only runs the benches and
/// prints a comparison table; exit is always 0 unless a bench fails
/// to build or emit estimates.
///
/// When `enforce` is true, the command additionally fails if any
/// bench's measured mean exceeds `HEADROOM_MULTIPLIER × baseline`.
pub fn run(enforce: bool) -> Result<()> {
    let workspace_root = workspace_root()?;
    let target_dir = workspace_root.join("target").join("criterion");
    let baselines = load_baselines(BASELINES_TOML)?;

    // Purge prior-run `new/estimates.json` files so a bench that
    // silently fails to re-run (rename, filter-out, feature-gated
    // away) surfaces as "failed to read estimates.json" rather than
    // reporting stale numbers.
    purge_stale_estimates(&target_dir)?;

    run_cargo_bench(&workspace_root)?;

    let mut results: Vec<BenchResult> = Vec::with_capacity(BENCH_NAMES.len());
    for name in BENCH_NAMES {
        let measured_ns = read_estimate(&target_dir, name)?;
        if !measured_ns.is_finite() || measured_ns < 0.0 {
            bail!(
                "bench `{name}` reported non-finite or negative mean ({measured_ns}); \
                 criterion output may be corrupted — re-run `cargo xtask bench-check`"
            );
        }
        let baseline_ns = baselines.get(*name).copied();
        results.push(BenchResult { name: (*name).to_owned(), measured_ns, baseline_ns });
    }

    let table = format_table(&results);
    println!("{table}");

    if enforce {
        let regressions: Vec<&BenchResult> =
            results.iter().filter(|r| r.exceeds_headroom()).collect();
        if !regressions.is_empty() {
            println!();
            println!(
                "❌ {} bench(es) exceeded {}× baseline headroom.",
                regressions.len(),
                HEADROOM_MULTIPLIER
            );
            println!(
                "   Run `cargo xtask bench-check` (without --enforce) to regenerate \
                 `xtask/src/bench_check/baselines.toml` if the regression is intentional."
            );
            bail!("bench regression detected");
        }
    }

    Ok(())
}

/// Remove `target/criterion/<bench>/new/` for every known bench name.
///
/// Without this, a bench that is silently filtered out of a subsequent
/// `cargo bench` invocation (rename, `#[cfg(feature = ...)]` gate,
/// criterion group reshuffle) leaves prior-run `estimates.json` in
/// place and the harness reads stale numbers. Purging before
/// `run_cargo_bench` forces every bench to produce fresh output or
/// surface as a clear "failed to read" error in [`read_estimate`].
fn purge_stale_estimates(target_dir: &Path) -> Result<()> {
    for name in BENCH_NAMES {
        let new_dir = target_dir.join(name).join("new");
        if new_dir.is_dir() {
            std::fs::remove_dir_all(&new_dir)
                .with_context(|| format!("failed to purge stale {}", new_dir.display()))?;
        }
    }
    Ok(())
}

/// Parse the baselines TOML into a `name → mean_ns` map.
///
/// Rejects non-finite (NaN, ±Inf) and non-positive baselines. A zero
/// baseline would divide-by-zero in [`BenchResult::ratio`] and
/// produce `inf`, tripping enforce with a misleading error; a negative
/// baseline is nonsensical for walltime.
fn load_baselines(contents: &str) -> Result<BTreeMap<String, f64>> {
    #[derive(Deserialize)]
    struct Root {
        #[serde(default)]
        benches: BTreeMap<String, f64>,
    }
    let root: Root = toml::from_str(contents).context("failed to parse baselines.toml")?;
    for (name, ns) in &root.benches {
        if !ns.is_finite() || *ns <= 0.0 {
            bail!(
                "baselines.toml: bench `{name}` has invalid value {ns} \
                 (must be a positive finite number of nanoseconds)"
            );
        }
    }
    Ok(root.benches)
}

/// Parse `target/criterion/<bench>/new/estimates.json` and return the mean.
fn read_estimate(target_dir: &Path, bench_name: &str) -> Result<f64> {
    let path = target_dir.join(bench_name).join("new").join("estimates.json");
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    parse_estimate(&contents)
}

/// Parse criterion estimates JSON; exposed as a free function for unit tests.
fn parse_estimate(contents: &str) -> Result<f64> {
    let parsed: CriterionEstimates =
        serde_json::from_str(contents).context("failed to parse criterion estimates.json")?;
    Ok(parsed.mean.point_estimate)
}

/// Bench target names registered by `permitlayer-core`'s Cargo.toml.
const BENCH_TARGETS: &[&str] = &["scrub_bench", "policy_bench"];

/// Spawn `cargo bench` against the known bench targets.
///
/// Targets are named explicitly (rather than using `-p permitlayer-core`
/// bare, or `--benches`) because bare `cargo bench` forwards the `--`
/// flags to EVERY bench binary the target set expands to, including
/// default-harness ones from `--lib` / `--tests`. Those binaries reject
/// criterion flags like `--save-baseline`, which fails the whole
/// command. `--bench <name>` limits the target set to the two
/// harness-false criterion binaries.
///
/// Also avoids `--workspace`: release-mode builds of the daemon crate
/// trip `#[forbid(unsafe_code)]` on a `#[cfg(not(debug_assertions))]`
/// test that intentionally calls `std::env::set_var` inside an unsafe
/// block. That pre-existing concern is orthogonal to bench coverage,
/// which lives entirely in `permitlayer-core` today.
fn run_cargo_bench(workspace_root: &Path) -> Result<()> {
    // Honor `$CARGO` — when xtask is driven by an outer `cargo xtask`,
    // cargo exports the exact binary that launched us. Using that
    // same binary avoids toolchain mismatches where `PATH` resolves
    // to a different `cargo` than the one that built xtask.
    let cargo: OsString = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    for target in BENCH_TARGETS {
        let status = Command::new(&cargo)
            .arg("bench")
            .arg("-p")
            .arg("permitlayer-core")
            .arg("--bench")
            .arg(target)
            .arg("--")
            .arg("--save-baseline")
            .arg("current")
            .current_dir(workspace_root)
            .status()
            .with_context(|| format!("failed to spawn `cargo bench --bench {target}`"))?;
        if !status.success() {
            bail!("`cargo bench --bench {target}` exited with status {status}");
        }
    }
    Ok(())
}

/// Format the bench-vs-baseline comparison as a plain-text table.
fn format_table(results: &[BenchResult]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{:<52} {:>14} {:>14} {:>8} {:<6}\n",
        "bench", "measured(ms)", "baseline(ms)", "ratio", "status"
    ));
    out.push_str(&"-".repeat(96));
    out.push('\n');
    for r in results {
        let measured_ms = r.measured_ns / 1_000_000.0;
        let (baseline_ms_s, ratio_s, status_s) = match r.baseline_ns {
            Some(b) => {
                let ratio = r.measured_ns / b;
                let status = if ratio > HEADROOM_MULTIPLIER { "FAIL" } else { "OK" };
                (format!("{:.6}", b / 1_000_000.0), format!("{ratio:.2}"), status)
            }
            None => ("-".to_owned(), "-".to_owned(), "NOBASE"),
        };
        out.push_str(&format!(
            "{:<52} {:>14.6} {:>14} {:>8} {:<6}\n",
            r.name, measured_ms, baseline_ms_s, ratio_s, status_s
        ));
    }
    out
}

/// Locate the workspace root by walking up until a `Cargo.toml` that
/// defines a `[workspace]` table is found. Cargo already does this
/// for `cargo bench`, but we need the path for the `target/criterion/`
/// walk.
///
/// Uses a real TOML parse rather than string-matching `[workspace]`
/// so comments, string literals, and `[workspace.metadata.*]` tables
/// in leaf-crate manifests do not false-positive as the root.
fn workspace_root() -> Result<PathBuf> {
    let start = std::env::current_dir().context("failed to read current directory")?;
    let mut current = start.as_path();
    loop {
        let candidate = current.join("Cargo.toml");
        if candidate.is_file()
            && let Ok(contents) = std::fs::read_to_string(&candidate)
            && let Ok(table) = contents.parse::<toml::Table>()
            && table.get("workspace").is_some()
        {
            return Ok(current.to_path_buf());
        }
        match current.parent() {
            Some(parent) => current = parent,
            None => {
                return Err(anyhow!("could not locate workspace root from {}", start.display()));
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const FIXTURE_ESTIMATES: &str = r#"{
        "mean": {
            "confidence_interval": {"confidence_level":0.95,"lower_bound":100.0,"upper_bound":110.0},
            "point_estimate": 105.25,
            "standard_error": 0.5
        },
        "median": {"confidence_interval":{"confidence_level":0.95,"lower_bound":100.0,"upper_bound":110.0},"point_estimate": 104.0, "standard_error": 0.5},
        "median_abs_dev": {"confidence_interval":{"confidence_level":0.95,"lower_bound":1.0,"upper_bound":2.0},"point_estimate": 1.5, "standard_error": 0.1},
        "slope": {"confidence_interval":{"confidence_level":0.95,"lower_bound":1.0,"upper_bound":2.0},"point_estimate": 1.2, "standard_error": 0.1},
        "std_dev": {"confidence_interval":{"confidence_level":0.95,"lower_bound":0.1,"upper_bound":0.2},"point_estimate": 0.15, "standard_error": 0.01}
    }"#;

    #[test]
    fn parse_estimate_reads_mean_point_estimate() {
        let mean = parse_estimate(FIXTURE_ESTIMATES).expect("parse should succeed");
        assert!((mean - 105.25).abs() < 1e-9);
    }

    #[test]
    fn parse_estimate_rejects_malformed_json() {
        let err = parse_estimate("not-json").expect_err("parse should fail");
        assert!(err.to_string().contains("criterion estimates"));
    }

    #[test]
    fn headroom_multiplier_is_three() {
        // Guard against someone tightening the multiplier without
        // moving the explicit Epic 7 re-deferral note alongside.
        assert!((HEADROOM_MULTIPLIER - 3.0).abs() < 1e-9);
    }

    #[test]
    fn exceeds_headroom_passes_at_exactly_three_x() {
        let r = BenchResult { name: "t".to_owned(), measured_ns: 300.0, baseline_ns: Some(100.0) };
        assert!(!r.exceeds_headroom(), "3.0× baseline must NOT fail");
        let ratio = r.ratio().expect("ratio present");
        assert!((ratio - 3.0).abs() < 1e-9);
    }

    #[test]
    fn exceeds_headroom_fails_just_over_three_x() {
        let r = BenchResult { name: "t".to_owned(), measured_ns: 300.01, baseline_ns: Some(100.0) };
        assert!(r.exceeds_headroom(), "3.01× baseline must FAIL");
    }

    #[test]
    fn exceeds_headroom_no_baseline_never_fails() {
        let r = BenchResult { name: "t".to_owned(), measured_ns: 999_999.0, baseline_ns: None };
        assert!(!r.exceeds_headroom(), "missing baseline must not trip enforce");
    }

    #[test]
    fn load_baselines_parses_benches_table() {
        let toml = r#"
            [benches]
            foo = 1000.0
            bar = 2500.5
        "#;
        let baselines = load_baselines(toml).expect("parse succeeds");
        assert_eq!(baselines.get("foo").copied(), Some(1000.0));
        assert_eq!(baselines.get("bar").copied(), Some(2500.5));
    }

    #[test]
    fn load_baselines_tolerates_empty_or_missing_table() {
        let baselines = load_baselines("").expect("empty is valid");
        assert!(baselines.is_empty());
    }

    #[test]
    fn committed_baselines_cover_every_bench() {
        // This test guards AC #2: every bench name the runner walks
        // must exist in the committed baselines.toml, otherwise
        // --enforce becomes silently useless.
        let baselines = load_baselines(BASELINES_TOML).expect("baselines.toml parses");
        for name in BENCH_NAMES {
            assert!(
                baselines.contains_key(*name),
                "baselines.toml is missing an entry for `{name}` — \
                 run `cargo xtask bench-check` and commit the output",
            );
        }
    }

    #[test]
    fn format_table_prints_fail_marker_when_over_headroom() {
        let results = vec![BenchResult {
            name: "regressed".to_owned(),
            measured_ns: 500.0,
            baseline_ns: Some(100.0),
        }];
        let rendered = format_table(&results);
        assert!(rendered.contains("regressed"));
        assert!(rendered.contains("FAIL"));
    }

    #[test]
    fn format_table_prints_nobase_when_baseline_missing() {
        let results = vec![BenchResult {
            name: "newbench".to_owned(),
            measured_ns: 500.0,
            baseline_ns: None,
        }];
        let rendered = format_table(&results);
        assert!(rendered.contains("newbench"));
        assert!(rendered.contains("NOBASE"));
    }

    #[test]
    fn load_baselines_rejects_zero_negative_or_non_finite() {
        for (label, value) in
            [("zero", "0.0"), ("negative", "-5.0"), ("nan", "nan"), ("inf", "inf")]
        {
            let toml = format!("[benches]\nfoo = {value}");
            let err = load_baselines(&toml)
                .unwrap_err_or_else(|_| panic!("{label} baseline must be rejected"));
            assert!(
                err.to_string().contains("foo"),
                "{label}: error must name the offending bench: {err}"
            );
        }
    }

    #[test]
    fn committed_baselines_only_reference_known_benches() {
        // Symmetric guard for `committed_baselines_cover_every_bench`:
        // a baseline entry for a deleted/renamed bench silently rots
        // otherwise. Both directions must hold.
        let baselines = load_baselines(BASELINES_TOML).expect("baselines.toml parses");
        for name in baselines.keys() {
            assert!(
                BENCH_NAMES.contains(&name.as_str()),
                "baselines.toml has a stale entry for `{name}` — \
                 remove it if the bench was renamed or deleted",
            );
        }
    }

    #[test]
    fn bench_targets_cover_every_bench_name() {
        // Catch drift between BENCH_NAMES (individual benchmarks) and
        // BENCH_TARGETS (criterion harness binaries). A bench name
        // whose prefix doesn't match any target means the runner will
        // never produce estimates for it — the `read_estimate` call
        // would fail with a confusing "missing file" error instead of
        // flagging the underlying list drift.
        for name in BENCH_NAMES {
            let matched = BENCH_TARGETS.iter().any(|target| {
                // Harness name is the common prefix: `scrub_bench`
                // carries names starting `scrub_`; `policy_bench`
                // carries names starting `policy_`.
                let stem = target.trim_end_matches("_bench");
                name.starts_with(&format!("{stem}_"))
            });
            assert!(
                matched,
                "bench name `{name}` does not match any BENCH_TARGETS prefix — \
                 add a harness or adjust the name",
            );
        }
    }

    // Helper used by `load_baselines_rejects_zero_negative_or_non_finite`.
    trait ResultExt<T> {
        fn unwrap_err_or_else<F: FnOnce(&T)>(self, f: F) -> anyhow::Error;
    }
    impl<T: std::fmt::Debug> ResultExt<T> for Result<T> {
        fn unwrap_err_or_else<F: FnOnce(&T)>(self, f: F) -> anyhow::Error {
            match self {
                Ok(v) => {
                    f(&v);
                    unreachable!("expected Err, got Ok({v:?})");
                }
                Err(e) => e,
            }
        }
    }
}
