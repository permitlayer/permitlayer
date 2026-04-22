//! Unit tests for Story 6.5 `validate_plugin_api` xtask.
//!
//! End-to-end tests that boot the real `cargo xtask` subprocess live
//! in `xtask/tests/plugin_api_check.rs`. These tests exercise the
//! extraction, parse/emit round-trip, and diff engines directly
//! without shelling out.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use super::lockfile::{LOCKFILE_HEADER, diff, emit, parse};
use super::surface::{SurfaceDescription, default_host_api_dir, extract};

// ─────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────

fn sample_surface() -> SurfaceDescription {
    SurfaceDescription {
        version: "1.0.0-rc.1".to_owned(),
        js_surface: BTreeSet::from_iter([
            "agentsso.deprecated : object".to_owned(),
            "agentsso.http.fetch(url: string, options?: FetchOptions) -> Promise<FetchResponse>"
                .to_owned(),
            "agentsso.oauth.getToken(service: string, scope: string) -> Promise<ScopedToken>"
                .to_owned(),
            "agentsso.version : string (read-only)".to_owned(),
        ]),
        error_codes: BTreeSet::from_iter([
            "oauth.scope_denied".to_owned(),
            "oauth.unknown_service".to_owned(),
            "version.malformed_requirement".to_owned(),
        ]),
        host_services_methods: BTreeSet::from_iter([
            "fn current_plugin_name(&self) -> String".to_owned(),
            "fn issue_scoped_token(&self, service: &str, scope: &str) -> Result<ScopedTokenDesc, HostApiError>".to_owned(),
        ]),
        dto_shapes: BTreeSet::from_iter([
            "DecisionDesc::Allow".to_owned(),
            "ScopedTokenDesc { bearer: String }".to_owned(),
        ]),
    }
}

fn sample_with_added_error_code() -> SurfaceDescription {
    let mut s = sample_surface();
    s.error_codes.insert("oauth.state_mismatch".to_owned());
    s
}

fn sample_with_removed_js_surface() -> SurfaceDescription {
    let mut s = sample_surface();
    s.js_surface.remove("agentsso.deprecated : object");
    s
}

fn sample_with_major_bump() -> SurfaceDescription {
    let mut s = sample_surface();
    s.version = "2.0.0".to_owned();
    s
}

fn sample_without_rc() -> SurfaceDescription {
    let mut s = sample_surface();
    s.version = "1.0.0".to_owned();
    s
}

// ─────────────────────────────────────────────────────────────────
// Extraction tests — live plugin crate source (the real one!)
// ─────────────────────────────────────────────────────────────────

#[test]
fn extract_live_surface_succeeds() {
    // Read the real `permitlayer-plugins` source tree and assert the
    // basic shape. This is the test that catches a future
    // refactor breaking the extractor — if `HostServices` gets
    // renamed or a DTO moves, extraction fails with a helpful
    // message.
    let dir = default_host_api_dir();
    assert!(dir.exists(), "host_api dir must exist for tests: {}", dir.display());
    let desc = extract(&dir).expect("extract must succeed on live tree");

    // HOST_API_VERSION pinned at 1.0.0-rc.1 per Story 6.5 AC #1.
    assert_eq!(desc.version, "1.0.0-rc.1");

    // JS_SURFACE has exactly 10 entries at 1.0.0-rc.1.
    assert_eq!(desc.js_surface.len(), 10, "expected 10 JS surface entries at 1.0.0-rc.1");

    // 20 named error-code variants (19 pre-8.3 + http.blocked_metadata_endpoint).
    assert_eq!(desc.error_codes.len(), 20, "expected 20 named error-code variants");

    // 7 methods on HostServices trait.
    assert_eq!(desc.host_services_methods.len(), 7, "expected 7 HostServices trait methods");

    // DTO shapes: 6 structs + 3 enum variants (DecisionDesc).
    assert_eq!(
        desc.dto_shapes.len(),
        9,
        "expected 9 DTO shape lines (6 structs + 3 enum variants)"
    );
}

#[test]
fn extract_surface_completes_under_200ms() {
    // AC #24: The surface-extraction inner function runs in <200ms
    // on the real plugin-crate tree. Ensures CI cost stays trivial.
    let dir = default_host_api_dir();
    let start = std::time::Instant::now();
    let _ = extract(&dir).expect("extract");
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_millis(200),
        "extract() took {elapsed:?}; expected < 200ms",
    );
}

// ─────────────────────────────────────────────────────────────────
// Emit / parse round-trip
// ─────────────────────────────────────────────────────────────────

#[test]
fn emit_is_deterministic_across_repeated_runs() {
    // AC #15: emit output is byte-stable across repeated runs on
    // the same input.
    let desc = sample_surface();
    let runs: Vec<String> = (0..5).map(|_| emit(&desc)).collect();
    for (i, r) in runs.iter().enumerate().skip(1) {
        assert_eq!(r, &runs[0], "run #{i} differs from run #0");
    }
}

#[test]
fn emit_uses_lf_line_endings_only() {
    // AC #15: no CRLF.
    let desc = sample_surface();
    let out = emit(&desc);
    assert!(!out.contains('\r'), "emit output must not contain CR");
}

#[test]
fn emit_starts_with_header() {
    let desc = sample_surface();
    let out = emit(&desc);
    assert!(out.starts_with(LOCKFILE_HEADER), "emit output must begin with LOCKFILE_HEADER");
}

#[test]
fn emit_ends_with_trailing_newline() {
    let desc = sample_surface();
    let out = emit(&desc);
    assert!(out.ends_with('\n'), "emit output must end with LF");
    assert!(!out.ends_with("\n\n"), "emit output must end with exactly one trailing LF (AC #3)");
}

#[test]
fn emit_and_parse_round_trip() {
    let desc = sample_surface();
    let text = emit(&desc);
    let parsed = parse(&text).expect("parse must succeed");
    assert_eq!(parsed, desc, "round-trip must preserve the surface exactly");
}

#[test]
fn parse_rejects_unknown_section() {
    let content =
        format!("{}\n## version\nHOST_API_VERSION = 1.0.0\n\n## bogus\nentry\n", LOCKFILE_HEADER);
    let err = parse(&content).unwrap_err();
    assert!(
        err.to_string().contains("unknown section"),
        "expected 'unknown section' error, got: {err}",
    );
}

// ----- Story 8.4 AC #5: lockfile comment stripping -----

#[test]
fn lockfile_comment_lines_are_ignored() {
    // A comment line between two valid sections must not trigger an error.
    let content = format!(
        "{}\n## version\nHOST_API_VERSION = 1.0.0\n\n# this is a comment\n## js_surface\nfoo()\n\n## error_codes\n## host_services_trait\n## dto_shapes\n",
        LOCKFILE_HEADER
    );
    let result = parse(&content);
    assert!(result.is_ok(), "comment lines between sections must be ignored, got: {result:?}");
}

// ----- Story 8.4 AC #6: unknown section lists valid sections -----

#[test]
fn lockfile_unknown_section_error_lists_valid_sections() {
    let content = format!(
        "{}\n## version\nHOST_API_VERSION = 1.0.0\n\n## bogus_section\nentry\n",
        LOCKFILE_HEADER
    );
    let err = parse(&content).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("bogus_section") && msg.contains("valid sections"),
        "error message must name the bad section and list valid sections, got: {msg}"
    );
    // All five valid section names must be in the message.
    for section in &["version", "js_surface", "error_codes", "host_services_trait", "dto_shapes"] {
        assert!(msg.contains(section), "valid sections must include {section}, got: {msg}");
    }
}

#[test]
fn parse_rejects_missing_version() {
    // Empty file → missing `## version`.
    let err = parse("").unwrap_err();
    assert!(err.to_string().contains("missing `## version`"), "got: {err}");
}

// ─────────────────────────────────────────────────────────────────
// Diff engine
// ─────────────────────────────────────────────────────────────────

#[test]
fn diff_of_identical_surfaces_is_empty() {
    let d = diff(&sample_surface(), &sample_surface());
    assert!(d.is_empty());
    assert!(d.is_purely_additive());
    assert!(!d.has_removals());
}

#[test]
fn diff_added_error_code_is_additive() {
    let d = diff(&sample_surface(), &sample_with_added_error_code());
    assert!(!d.is_empty());
    assert!(d.is_purely_additive(), "added error code must be purely additive");
    assert!(!d.has_removals());
    assert_eq!(d.added_error_codes, vec!["oauth.state_mismatch".to_owned()]);
    assert!(d.removed_error_codes.is_empty());
}

#[test]
fn diff_removed_js_surface_is_breaking() {
    let d = diff(&sample_surface(), &sample_with_removed_js_surface());
    assert!(!d.is_empty());
    assert!(!d.is_purely_additive(), "removed surface is NOT purely additive");
    assert!(d.has_removals());
    assert_eq!(d.removed_js_surface, vec!["agentsso.deprecated : object".to_owned()]);
}

#[test]
fn diff_major_bump_flagged_in_version_change() {
    let d = diff(&sample_surface(), &sample_with_major_bump());
    assert!(d.version_change.is_some());
    let (old, new) = d.version_change.unwrap();
    assert_eq!(old, "1.0.0-rc.1");
    assert_eq!(new, "2.0.0");
}

// ─────────────────────────────────────────────────────────────────
// run() — end-to-end via HOST_API_LOCK_PATH seam
// ─────────────────────────────────────────────────────────────────

/// Serialize runs of `run(...)` that touch the `HOST_API_LOCK_PATH`
/// env var — concurrent tests would race on the global env.
fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    let m = GUARD.get_or_init(|| Mutex::new(()));
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Temporarily override `HOST_API_LOCK_PATH` to a path inside a
/// scratch dir, run the closure, then restore the env.
fn with_lockfile_path<F, R>(path: &std::path::Path, f: F) -> R
where
    F: FnOnce() -> R,
{
    let _g = serial_guard();
    let key = "HOST_API_LOCK_PATH";
    let prev = std::env::var(key).ok();
    // Safety: test-only single-threaded env mutation guarded by
    // `serial_guard()` above. Edition 2024 marks `set_var`/`remove_var`
    // unsafe for good reason in general; our serialization keeps the
    // test hermetic.
    unsafe {
        std::env::set_var(key, path);
    }
    let out = f();
    unsafe {
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
    out
}

#[test]
fn check_passes_on_untouched_surface() {
    // Point HOST_API_LOCK_PATH at a freshly-emitted lockfile that
    // matches the LIVE plugin crate — run() should succeed.
    let temp = tempdir();
    let lock_path = temp.join("host-api.lock");

    // Emit the live surface into the scratch path.
    let live = extract(&default_host_api_dir()).expect("extract");
    std::fs::write(&lock_path, emit(&live)).expect("write scratch lock");

    with_lockfile_path(&lock_path, || {
        super::run(false).expect("run must succeed on matching lockfile");
    });
}

#[test]
fn run_check_at_rc_stage_tolerates_breaking_change() {
    // AC #21: during rc qualifier, breaking changes are permitted.
    // The live surface IS at rc; if we fabricate a committed
    // lockfile missing an entry (i.e., the "live surface has more"),
    // run() should still succeed (additive drift at rc-stage is
    // always OK).
    let temp = tempdir();
    let lock_path = temp.join("host-api.lock");

    // Start from the live surface, then remove one JS_SURFACE entry
    // to simulate an earlier rc that had fewer methods.
    let live = extract(&default_host_api_dir()).expect("extract");
    let mut smaller = live.clone();
    // Remove whichever entry sorts first — stable across runs.
    if let Some(first) = smaller.js_surface.iter().next().cloned() {
        smaller.js_surface.remove(&first);
    }
    std::fs::write(&lock_path, emit(&smaller)).expect("write scratch lock");

    with_lockfile_path(&lock_path, || {
        super::run(false).expect("rc-stage additive drift must not fail");
    });
}

#[test]
fn update_rewrites_lockfile_on_additive_change() {
    // AC #9: --update on an additive drift writes the refreshed
    // lockfile. At rc-stage the gate treats any change as additive,
    // so the same test covers AC #9 shape.
    let temp = tempdir();
    let lock_path = temp.join("host-api.lock");

    let live = extract(&default_host_api_dir()).expect("extract");
    let mut smaller = live.clone();
    if let Some(first) = smaller.js_surface.iter().next().cloned() {
        smaller.js_surface.remove(&first);
    }
    let original_content = emit(&smaller);
    std::fs::write(&lock_path, &original_content).expect("seed scratch lock");

    with_lockfile_path(&lock_path, || {
        super::run(true).expect("--update must succeed");
    });

    // File must now match the live surface.
    let updated = std::fs::read_to_string(&lock_path).expect("read updated lock");
    assert_eq!(updated, emit(&live), "lockfile content must equal emit(live) after --update");
    assert_ne!(updated, original_content, "--update must actually change the file");
}

#[test]
fn run_handles_missing_lockfile_without_update() {
    // Reports that the file is missing + tells the user how to
    // create it. Does NOT create the file.
    let temp = tempdir();
    let lock_path = temp.join("host-api.lock");
    assert!(!lock_path.exists());

    with_lockfile_path(&lock_path, || {
        super::run(false).expect("reporting missing lock is not an error");
    });

    assert!(!lock_path.exists(), "check-only run must NOT create the lockfile");
}

#[test]
fn run_creates_missing_lockfile_on_update() {
    let temp = tempdir();
    let lock_path = temp.join("host-api.lock");
    assert!(!lock_path.exists());

    with_lockfile_path(&lock_path, || {
        super::run(true).expect("--update must create the lockfile");
    });
    assert!(lock_path.exists(), "--update must create the lockfile");
}

// Simulated non-rc tests — these fabricate a committed lockfile with
// `HOST_API_VERSION = 1.0.0` (the rc-qualifier gate's post-rc behavior)
// and drive run() against the live surface (which IS at rc.1). The
// diff sees both a version change AND (because rc < 1.0 canonically)
// possible surface drift. We cover the "major bump detected" + the
// "purely additive" branches by controlling the committed-side
// surface precisely.

#[test]
fn run_major_bump_emits_note_without_update() {
    // Committed lockfile is at 1.0.0; simulate a future major bump
    // by fabricating a live surface at 2.0.0 (we can't flip the
    // real crate, so we do the diff-engine check directly here and
    // assert the expected branch).
    use super::lockfile::diff;
    let committed = sample_without_rc(); // 1.0.0
    let live = sample_with_major_bump(); // 2.0.0
    let d = diff(&committed, &live);
    assert!(d.version_change.is_some());
    let (old, new) = d.version_change.clone().unwrap();
    assert_eq!(old, "1.0.0");
    assert_eq!(new, "2.0.0");
    // Sanity: diff is NOT empty; version change alone is a change.
    assert!(!d.is_empty());
}

fn tempdir() -> std::path::PathBuf {
    // Hand-rolled tempdir so xtask doesn't need to add `tempfile` —
    // a single scratch dir per test under the crate's target dir.
    let base = std::env::temp_dir().join(format!(
        "xtask-validate-plugin-api-{}-{}",
        std::process::id(),
        rand_suffix(),
    ));
    std::fs::create_dir_all(&base).unwrap();
    TempDir { path: base.clone() }.leak_path()
}

/// Minimal tempdir helper that leaks on drop so tests see the path
/// for the lifetime of the test (the OS cleans `/tmp` eventually).
struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn leak_path(self) -> std::path::PathBuf {
        let p = self.path.clone();
        // Intentionally drop without removing; `tempfile` crate is
        // not in xtask's dep set and this path is <1 KiB of scratch
        // text per test, collected by OS /tmp sweep.
        std::mem::forget(self);
        p
    }
}

fn rand_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    format!("{:x}", nanos ^ std::process::id())
}

// ─────────────────────────────────────────────────────────────────
// Grep-assert tests (AC #14, #23)
// ─────────────────────────────────────────────────────────────────

#[test]
fn surface_uses_syn_not_regex() {
    // AC #14: surface.rs uses syn (not regex) for Rust-source
    // parsing. The one exception the story carves out is string
    // searches in guardrail tests, NOT the production extractor.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let source =
        std::fs::read_to_string(format!("{manifest_dir}/src/validate_plugin_api/surface.rs"))
            .unwrap();
    assert!(
        !source.contains("regex::Regex") && !source.contains("::Regex::"),
        "surface.rs must not use regex for parsing Rust source",
    );
}

#[test]
fn xtask_does_not_depend_on_rquickjs_or_plugins_crate() {
    // AC #23: running the xtask must not require booting rquickjs
    // or linking the plugins crate. Check the xtask Cargo.toml.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let cargo = std::fs::read_to_string(format!("{manifest_dir}/Cargo.toml")).unwrap();
    assert!(!cargo.contains("rquickjs"), "xtask/Cargo.toml must not depend on rquickjs",);
    assert!(
        !cargo.contains("permitlayer-plugins"),
        "xtask/Cargo.toml must not depend on permitlayer-plugins",
    );
}

#[test]
fn xtask_depends_on_semver_from_workspace() {
    // AC #22: semver is added to xtask's deps, sourced from the
    // workspace manifest.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let cargo = std::fs::read_to_string(format!("{manifest_dir}/Cargo.toml")).unwrap();
    assert!(
        cargo.contains("semver.workspace = true"),
        "xtask/Cargo.toml must include `semver.workspace = true`",
    );
}

#[test]
fn ci_workflow_runs_validate_plugin_api() {
    // AC #19: .github/workflows/ci.yml has a plugin-api job running
    // `cargo xtask validate-plugin-api`.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    // `<workspace>/.github/workflows/ci.yml`; xtask manifest sits one
    // level below workspace root.
    let path = format!("{manifest_dir}/../.github/workflows/ci.yml");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("failed to read {path} — expected CI workflow"));
    assert!(content.contains("plugin-api:"), "ci.yml must declare a `plugin-api` job",);
    assert!(
        content.contains("cargo xtask validate-plugin-api"),
        "ci.yml must invoke `cargo xtask validate-plugin-api`",
    );
}

#[test]
fn host_api_lock_is_tracked_in_git() {
    // AC #27: host-api.lock must not be gitignored.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    // .gitignore lives at the workspace root.
    let path = format!("{manifest_dir}/../.gitignore");
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        !content.lines().any(|l| l.trim() == "host-api.lock"),
        ".gitignore must not list host-api.lock",
    );
}

#[test]
fn initial_lockfile_content_matches_fixture() {
    // AC #3: the committed host-api.lock byte-matches the golden
    // fixture at test-fixtures/host-api.lock.golden. The fixture
    // evolves deliberately alongside the real lockfile (a future
    // story that adds a host-API method will update both in the
    // same PR).
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::PathBuf::from(format!("{manifest_dir}/.."));
    let real = workspace_root.join("host-api.lock");
    let golden = workspace_root.join("test-fixtures").join("host-api.lock.golden");

    let real_content =
        std::fs::read_to_string(&real).expect("host-api.lock must exist at workspace root");
    let golden_content = std::fs::read_to_string(&golden).expect("golden fixture must exist");
    assert_eq!(
        real_content, golden_content,
        "host-api.lock drifted from test-fixtures/host-api.lock.golden; update both together",
    );
}

#[test]
fn changelog_exists_with_rc1_entry() {
    // AC #18: CHANGELOG.md at workspace root with the 1.0.0-rc.1 entry.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../CHANGELOG.md");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("expected CHANGELOG.md at workspace root"));
    assert!(content.contains("## [Unreleased]"), "CHANGELOG must have an ## [Unreleased] section",);
    assert!(content.contains("## [1.0.0-rc.1]"), "CHANGELOG must have a ## [1.0.0-rc.1] entry",);
    assert!(
        content.contains("Keep a Changelog 1.1.0"),
        "CHANGELOG must cite the Keep a Changelog 1.1.0 format",
    );
    assert!(
        content.contains("### Added"),
        "CHANGELOG rc entry must have an `### Added` subsection",
    );
}

// ─────────────────────────────────────────────────────────────────
// Spec-named run() branch coverage (ACs #2, #5-#8, #10, #11, #20, #21)
// ─────────────────────────────────────────────────────────────────

/// AC #2: `validate-plugin-api` subcommand registered in `xtask/src/main.rs`.
#[test]
fn subcommand_is_registered() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let main_src = std::fs::read_to_string(format!("{manifest_dir}/src/main.rs")).unwrap();
    assert!(
        main_src.contains("ValidatePluginApi"),
        "xtask/src/main.rs must declare the `ValidatePluginApi` subcommand variant",
    );
    assert!(
        main_src.contains("validate_plugin_api::run"),
        "xtask/src/main.rs must dispatch to `validate_plugin_api::run`",
    );
}

/// AC #5: a removed JS_SURFACE entry against a non-rc surface flags
/// the diff as breaking (has removals). We assert at the diff-engine
/// level because the real live crate is at rc and `run()` enters
/// rc-mode regardless of the committed version — tests that drive
/// `run()` through the non-rc breaking path would require mutating
/// the live `HOST_API_VERSION`, which Story 6.5 AC #1 forbids.
#[test]
fn check_fails_on_missing_js_surface_entry() {
    let mut committed = sample_without_rc(); // 1.0.0
    committed.js_surface.insert("agentsso.ghost.method() -> void".to_owned());
    let live = sample_without_rc();
    let d = diff(&committed, &live);
    assert!(d.has_removals(), "removed js_surface entry must surface as a removal");
    assert!(!d.is_purely_additive(), "diff is NOT purely additive");
    assert!(
        d.removed_js_surface.iter().any(|s| s.contains("ghost.method")),
        "diff must name the removed entry",
    );
}

/// AC #6: a removed error-code variant surfaces as a removal
/// (breaking at non-rc). Asserted at the diff-engine level; see
/// note on `check_fails_on_missing_js_surface_entry` for why.
#[test]
fn check_fails_on_removed_error_code() {
    let mut committed = sample_without_rc();
    committed.error_codes.insert("oauth.retired_code".to_owned());
    let live = sample_without_rc();
    let d = diff(&committed, &live);
    assert!(d.has_removals());
    assert!(d.removed_error_codes.iter().any(|c| c == "oauth.retired_code"));
}

/// AC #7: a changed method signature surfaces as paired
/// removed-old + added-new entries in the diff (NOT a single
/// "signature changed" line). Asserted at the diff-engine level.
#[test]
fn check_fails_on_changed_method_signature() {
    let new_sig =
        "agentsso.http.fetch(url: string, options?: FetchOptions) -> Promise<FetchResponse>";
    let old_sig = "agentsso.http.fetch(request: FetchRequest) -> Promise<FetchResponse>";

    let mut committed = sample_without_rc();
    // `sample_surface` base already contains the new_sig — remove it
    // from committed so this test simulates the pre-change world.
    committed.js_surface.remove(new_sig);
    committed.js_surface.insert(old_sig.to_owned());

    let live = sample_without_rc();

    let d = diff(&committed, &live);
    assert!(d.removed_js_surface.iter().any(|s| s == old_sig), "old line in removed");
    assert!(d.added_js_surface.iter().any(|s| s == new_sig), "new line in added");
}

/// AC #8: an additive change (live has a NEW entry not in committed)
/// against a non-rc committed lock exits 0 with an additive note.
///
/// We simulate this by making the committed lock non-rc with FEWER
/// entries than live; the diff engine sees the live "extras" as
/// additions.
#[test]
fn check_passes_on_additive_change_with_note() {
    let temp = tempdir();
    let lock_path = temp.join("host-api.lock");

    let live = extract(&default_host_api_dir()).expect("extract");
    let mut committed = live.clone();
    committed.version = "1.0.0".to_owned();
    // Remove one entry from the committed snapshot; live "added" it.
    if let Some(first) = committed.js_surface.iter().next().cloned() {
        committed.js_surface.remove(&first);
    }
    std::fs::write(&lock_path, emit(&committed)).expect("seed lock");

    // rc-mode is determined from the LIVE version (1.0.0-rc.1), so the
    // gate is in rc-stage. We still want to exercise the additive
    // branch — confirm run() returns Ok regardless.
    with_lockfile_path(&lock_path, || {
        super::run(false).expect("additive change must not fail");
    });
}

/// AC #10: `--update` does NOT override a breaking change. Asserted
/// via source-grep since the live crate is at rc (rc-mode short-
/// circuits the non-rc breaking-change path that this AC describes).
/// The grep proves `run()` contains the AC-required message AND the
/// `bail!` that enforces non-zero exit under `--update`.
#[test]
fn update_still_fails_on_breaking_change() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let run_src =
        std::fs::read_to_string(format!("{manifest_dir}/src/validate_plugin_api/mod.rs")).unwrap();
    assert!(
        run_src
            .contains("--update does not override breaking changes; bump HOST_API_VERSION first."),
        "run() must emit the AC #10 --update-override-rejection message verbatim",
    );
    // The same branch must `bail!` (not `println!` + Ok) so the
    // exit code is non-zero.
    assert!(
        run_src.contains("if update {\n        bail!"),
        "run() must bail! (not print-and-return-Ok) when --update is used on a breaking change",
    );
}

/// AC #11: a major-version bump unlocks breaking changes; with `--update`
/// the lockfile is rewritten and exit code is 0.
#[test]
fn major_bump_unlocks_breaking_change() {
    use super::lockfile::parse;
    let temp = tempdir();
    let lock_path = temp.join("host-api.lock");

    // Committed at 1.0.0 with a made-up surface entry; live IS at rc.1
    // so we fabricate a synthetic committed lock with HOST_API_VERSION
    // of 0.9.0 so the live 1.0.0-rc.1 represents a major bump (0 → 1).
    let live = extract(&default_host_api_dir()).expect("extract");
    let mut committed = live.clone();
    committed.version = "0.9.0".to_owned();
    // Add a "retired" entry that the live tree doesn't have — this
    // would be breaking at a non-major bump, but the major bump
    // unlocks it.
    committed.error_codes.insert("legacy.retired".to_owned());
    std::fs::write(&lock_path, emit(&committed)).expect("seed lock");

    with_lockfile_path(&lock_path, || {
        super::run(true).expect("major bump + --update must succeed");
    });

    // File now reflects the live surface (no more `legacy.retired`).
    let updated = std::fs::read_to_string(&lock_path).unwrap();
    let parsed = parse(&updated).expect("updated lock must parse");
    assert_eq!(parsed.version, "1.0.0-rc.1");
    assert!(!parsed.error_codes.contains("legacy.retired"));
}

/// AC #20: `--update` stdout mentions the CHANGELOG reminder. We verify
/// by reading the `run()` source (CHANGELOG strings are static literals
/// the test can grep) since we don't capture stdout in unit tests.
#[test]
fn update_mentions_changelog_reminder() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let run_src =
        std::fs::read_to_string(format!("{manifest_dir}/src/validate_plugin_api/mod.rs")).unwrap();
    assert!(
        run_src.contains("Consider adding a CHANGELOG entry under the Added section."),
        "run() must emit the additive-change CHANGELOG reminder",
    );
    assert!(
        run_src.contains(
            "Consider adding a CHANGELOG entry under the Removed or Changed section, with a Deprecated note for the previous behavior if applicable."
        ),
        "run() must emit the breaking-change CHANGELOG reminder",
    );
}

/// AC #21: the rc qualifier puts the gate in update-freely mode. A
/// breaking change under rc is permitted; the first stdout line is the
/// rc-stage note.
#[test]
fn rc_qualifier_permits_breaking_changes_without_major_bump() {
    let temp = tempdir();
    let lock_path = temp.join("host-api.lock");

    // Live surface is at 1.0.0-rc.1. Fabricate a committed lock that
    // has an EXTRA error-code variant the live tree doesn't — a
    // breaking change at 1.0.0, but rc-mode permits it.
    let live = extract(&default_host_api_dir()).expect("extract");
    let mut committed = live.clone();
    committed.error_codes.insert("oauth.rc_only_code".to_owned());
    std::fs::write(&lock_path, emit(&committed)).expect("seed lock");

    with_lockfile_path(&lock_path, || {
        super::run(false).expect("rc-stage breaking diff must NOT bail");
    });

    // Also assert the run() source contains the AC #21 literal first-
    // line wording (it runs before any diff branch).
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let run_src =
        std::fs::read_to_string(format!("{manifest_dir}/src/validate_plugin_api/mod.rs")).unwrap();
    assert!(
        run_src.contains(
            "rc-stage surface (pre-release); breaking changes are permitted until the rc qualifier is dropped."
        ),
        "run() must emit the AC #21 rc-stage note verbatim",
    );
}
