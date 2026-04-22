//! Corpus runner for validating scrub rule detection and false positive rates.
//!
//! Loads true-positive and true-negative sample files from
//! `test-fixtures/scrub-corpus/` and runs them through the built-in
//! scrub engine.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use permitlayer_core::scrub::{ScrubEngine, builtin_rules};

/// Detection rate threshold (true positive rate).
const MIN_DETECTION_RATE: f64 = 0.99;
/// Maximum false positive rate.
const MAX_FP_RATE: f64 = 0.01;

pub fn run() -> Result<()> {
    let workspace_root = workspace_root()?;
    let corpus_dir = workspace_root.join("test-fixtures/scrub-corpus");

    if !corpus_dir.exists() {
        bail!("corpus directory not found: {}", corpus_dir.display());
    }

    let rules = builtin_rules();
    let engine = ScrubEngine::new(rules.to_vec()).context("failed to build scrub engine")?;

    println!("=== Scrub Corpus Runner ===\n");

    // --- True positives ---
    let tp_dir = corpus_dir.join("true-positives");
    let tp_results = run_corpus(&engine, &tp_dir, "true-positives")?;

    let tp_total = tp_results.total;
    let tp_detected = tp_results.detected;
    let tp_rate = if tp_total > 0 { tp_detected as f64 / tp_total as f64 } else { 0.0 };

    println!("\n--- True Positives ---");
    println!("  Files tested: {tp_total}");
    println!("  Files with matches: {tp_detected}");
    println!("  Detection rate: {:.1}%", tp_rate * 100.0);

    if !tp_results.failures.is_empty() {
        println!("  MISSED files:");
        for f in &tp_results.failures {
            println!("    - {f}");
        }
    }

    // Per-rule stats
    println!("\n  Per-rule detection:");
    for (rule, count) in &tp_results.rule_counts {
        println!("    {rule}: {count} matches");
    }

    // --- True negatives ---
    let tn_dir = corpus_dir.join("true-negatives");
    let tn_results = run_corpus(&engine, &tn_dir, "true-negatives")?;

    let tn_total = tn_results.total;
    let tn_false_positives = tn_results.detected;
    let fp_rate = if tn_total > 0 { tn_false_positives as f64 / tn_total as f64 } else { 0.0 };

    println!("\n--- True Negatives ---");
    println!("  Files tested: {tn_total}");
    println!("  Files with false positives: {tn_false_positives}");
    println!("  False positive rate: {:.1}%", fp_rate * 100.0);

    if !tn_results.false_positive_details.is_empty() {
        println!("  FALSE POSITIVE files:");
        for (file, rules) in &tn_results.false_positive_details {
            println!("    - {file}: {}", rules.join(", "));
        }
    }

    // --- Threshold check ---
    println!("\n=== Thresholds ===");
    let mut pass = true;

    if tp_rate < MIN_DETECTION_RATE {
        println!(
            "  FAIL: Detection rate {:.1}% < {:.1}% threshold",
            tp_rate * 100.0,
            MIN_DETECTION_RATE * 100.0
        );
        pass = false;
    } else {
        println!(
            "  PASS: Detection rate {:.1}% >= {:.1}%",
            tp_rate * 100.0,
            MIN_DETECTION_RATE * 100.0
        );
    }

    if fp_rate > MAX_FP_RATE {
        println!("  FAIL: FP rate {:.1}% > {:.1}% threshold", fp_rate * 100.0, MAX_FP_RATE * 100.0);
        pass = false;
    } else {
        println!("  PASS: FP rate {:.1}% <= {:.1}%", fp_rate * 100.0, MAX_FP_RATE * 100.0);
    }

    if !pass {
        bail!("corpus validation FAILED — see details above");
    }

    println!("\nAll corpus checks passed.");
    Ok(())
}

struct CorpusResults {
    total: usize,
    detected: usize,
    failures: Vec<String>,
    false_positive_details: Vec<(String, Vec<String>)>,
    rule_counts: BTreeMap<String, usize>,
}

fn run_corpus(engine: &ScrubEngine, dir: &Path, label: &str) -> Result<CorpusResults> {
    let mut results = CorpusResults {
        total: 0,
        detected: 0,
        failures: Vec::new(),
        false_positive_details: Vec::new(),
        rule_counts: BTreeMap::new(),
    };

    if !dir.exists() {
        bail!("{label} directory not found: {}", dir.display());
    }

    let mut entries: Vec<_> = fs::read_dir(dir)
        .with_context(|| format!("failed to read {label} directory"))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|ext| ext.to_str()) == Some("txt"))
        .collect();

    entries.sort_by_key(|e| e.file_name());

    if entries.is_empty() {
        bail!("{label} directory has no .txt files: {}", dir.display());
    }

    for entry in &entries {
        let path = entry.path();
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;

        let result = engine.scrub(&content);
        results.total += 1;

        if result.is_clean() {
            if label == "true-positives" {
                results.failures.push(filename);
            }
        } else {
            results.detected += 1;
            let summary = result.summary();
            for (rule, count) in &summary {
                *results.rule_counts.entry(rule.clone()).or_insert(0) += count;
            }
            if label == "true-negatives" {
                let rule_names: Vec<String> = summary.keys().cloned().collect();
                results.false_positive_details.push((filename, rule_names));
            }
        }
    }

    Ok(results)
}

fn workspace_root() -> Result<std::path::PathBuf> {
    // xtask is at `<workspace>/xtask/`, binary runs from workspace root
    // via `cargo xtask`. Use CARGO_MANIFEST_DIR or walk up from current dir.
    if let Ok(dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let xtask_dir = Path::new(&dir);
        if let Some(parent) = xtask_dir.parent() {
            return Ok(parent.to_path_buf());
        }
    }
    // Fallback: current directory
    std::env::current_dir().context("failed to get current directory")
}
