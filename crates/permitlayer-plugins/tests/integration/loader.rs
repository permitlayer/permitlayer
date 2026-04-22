//! Integration tests for the Story 6.3 plugin loader.
//!
//! Each test exercises the full [`load_all`] path against a
//! real `PluginRuntime` and a tempdir-backed plugins directory.
//! The runtime is constructed per-test because the per-process
//! `rquickjs::Runtime` carries state (interrupt flags, heap
//! allocator) — sharing across parallel tests would produce
//! false-positive timeout / OOM results.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use permitlayer_plugins::{
    CannedTrustPromptReader, LoaderConfig, PluginError, PluginRuntime, TrustDecision,
    TrustPromptReader, TrustTier, load_all, load_one_from_path, validate_plugin_source,
};

// ----- Helpers -----

/// Produce a fresh `PluginRuntime` with default config. One
/// per test to avoid cross-test interference on the shared C
/// runtime.
fn mk_runtime() -> PluginRuntime {
    PluginRuntime::new_default().expect("plugin runtime must construct")
}

/// Produce a `LoaderConfig` pointing at a fresh tempdir subtree.
/// The returned `TempDir` must be held for the test's duration
/// — dropping it deletes the directory.
fn mk_config(
    auto_trust_builtins: bool,
    warn_on_first_load: bool,
) -> (tempfile::TempDir, LoaderConfig) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let plugins_dir = tmp.path().join("plugins");
    let trusted_path = plugins_dir.join(".trusted");
    let cfg = LoaderConfig { auto_trust_builtins, warn_on_first_load, plugins_dir, trusted_path };
    (tmp, cfg)
}

/// Write a user-installed plugin at `<plugins_dir>/<name>/index.js`
/// with the provided JS source. Creates parent dirs as needed.
/// Returns the absolute `index.js` path.
fn write_plugin(plugins_dir: &Path, name: &str, source: &str) -> PathBuf {
    let dir = plugins_dir.join(name);
    fs::create_dir_all(&dir).expect("create plugin dir");
    let file = dir.join("index.js");
    fs::write(&file, source).expect("write index.js");
    file
}

/// Minimal valid metadata JS source for a plugin named `name`.
fn minimal_plugin_source(name: &str) -> String {
    format!(
        r#"export const metadata = {{
    name: "{name}",
    version: "1.0.0",
    apiVersion: ">=1.0",
    scopes: ["test.readonly"],
    description: "test plugin {name}",
}};
"#
    )
}

/// sha256 of the given source, hex-encoded lowercase. Reproduces
/// the loader's internal hashing so tests can pre-compute
/// `.trusted` entries.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let d = h.finalize();
    let mut out = String::with_capacity(64);
    for b in d {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

struct NoOp;
impl TrustPromptReader for NoOp {
    fn prompt(&self, _: &str, _: &Path, _: &str) -> TrustDecision {
        TrustDecision::NoPromptAvailable
    }
}

/// Counting wrapper that records how many times the inner reader
/// was invoked. Lets tests assert that the prompt path is (or
/// isn't) reached.
struct CountingReader {
    inner: Arc<dyn TrustPromptReader>,
    count: std::sync::atomic::AtomicUsize,
}
impl CountingReader {
    fn new(inner: Arc<dyn TrustPromptReader>) -> Self {
        Self { inner, count: std::sync::atomic::AtomicUsize::new(0) }
    }
    fn count(&self) -> usize {
        self.count.load(std::sync::atomic::Ordering::Acquire)
    }
}
impl TrustPromptReader for CountingReader {
    fn prompt(&self, n: &str, p: &Path, h: &str) -> TrustDecision {
        self.count.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.inner.prompt(n, p, h)
    }
}

// ----- AC #4 -----

#[test]
fn load_all_with_only_builtins_registers_three_connectors() {
    // AC #4: `auto_trust_builtins = true`, no plugins dir, expect
    // 3 built-ins as TrustTier::Builtin.
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    // Note: `cfg.plugins_dir` does NOT exist yet (fresh tempdir).
    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let registry = load_all(&rt, cfg, reader).expect("load_all succeeds with only built-ins");

    assert_eq!(registry.len(), 3);
    for name in ["google-gmail", "google-calendar", "google-drive"] {
        let c = registry.get(name).unwrap_or_else(|| panic!("built-in {name} registered"));
        assert_eq!(c.name, name);
        assert_eq!(c.trust_tier, TrustTier::Builtin);
        assert!(!c.version.is_empty(), "{name} must have a version");
        assert!(!c.scopes.is_empty(), "{name} must declare scopes");
        assert_eq!(c.source_sha256_hex.len(), 64);
        assert!(
            c.source_sha256_hex.bytes().all(|b| b.is_ascii_hexdigit()),
            "sha256 hex for {name} must be hex: {}",
            c.source_sha256_hex
        );
    }
}

// ----- AC #5 -----

#[test]
fn user_installed_plugin_loads_as_warn_user_when_prompt_disabled() {
    // AC #5: `warn_on_first_load = false` + valid user-installed
    // plugin → WarnUser tier, no prompt, no `.trusted` write.
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    write_plugin(&cfg.plugins_dir, "notion", &minimal_plugin_source("notion"));

    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let counter = Arc::new(CountingReader::new(reader));
    let counter_clone: Arc<dyn TrustPromptReader> = counter.clone();

    let registry = load_all(&rt, cfg.clone(), counter_clone).expect("load_all succeeds");

    assert_eq!(registry.len(), 4, "3 builtins + notion");
    let notion = registry.get("notion").expect("notion registered");
    assert_eq!(notion.trust_tier, TrustTier::WarnUser);

    // Prompt was never called (warn_on_first_load=false → no
    // prompt path exercised).
    assert_eq!(counter.count(), 0);

    // `.trusted` must NOT be written on the no-prompt path.
    assert!(
        !cfg.trusted_path.exists(),
        ".trusted must not be created when prompt path is disabled"
    );
}

// ----- AC #6 -----

#[test]
fn user_installed_plugin_loads_as_trusted_user_when_sha256_matches() {
    // AC #6: sha256 in `.trusted` → TrustedUser tier. Prompt is
    // NOT called.
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, true);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    let source = minimal_plugin_source("notion");
    write_plugin(&cfg.plugins_dir, "notion", &source);

    // Pre-seed .trusted with the correct hash.
    let hash = sha256_hex(source.as_bytes());
    fs::write(&cfg.trusted_path, format!("notion {hash}\n")).unwrap();

    let counter = Arc::new(CountingReader::new(Arc::new(NoOp) as Arc<dyn TrustPromptReader>));
    let counter_clone: Arc<dyn TrustPromptReader> = counter.clone();
    let registry = load_all(&rt, cfg, counter_clone).expect("load_all succeeds");

    let notion = registry.get("notion").expect("notion registered");
    assert_eq!(notion.trust_tier, TrustTier::TrustedUser);
    assert_eq!(counter.count(), 0, "prompt must not fire for trusted entries");
}

// ----- AC #7 -----

#[test]
fn rotated_plugin_content_invalidates_trust_and_triggers_prompt() {
    // AC #7: `.trusted` contains old sha, plugin source has new
    // sha → prompt fires, TrustDecision::Once → WarnUser,
    // `.trusted` UNCHANGED.
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, true);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    // Plugin file has the NEW content.
    let new_source = minimal_plugin_source("notion");
    write_plugin(&cfg.plugins_dir, "notion", &new_source);

    // `.trusted` has a stale hash for a DIFFERENT content.
    let stale_hash = sha256_hex(b"different old content");
    let initial_trusted = format!("notion {stale_hash}\n");
    fs::write(&cfg.trusted_path, &initial_trusted).unwrap();

    let canned = Arc::new(CannedTrustPromptReader::new(vec![TrustDecision::Once]));
    let counter = Arc::new(CountingReader::new(canned));
    let counter_clone: Arc<dyn TrustPromptReader> = counter.clone();
    let registry = load_all(&rt, cfg.clone(), counter_clone).expect("load_all succeeds");

    let notion = registry.get("notion").expect("notion registered");
    assert_eq!(notion.trust_tier, TrustTier::WarnUser);
    assert_eq!(counter.count(), 1, "prompt must fire exactly once on rotation");

    // `.trusted` unchanged because the operator chose Once, not
    // Always.
    let after = fs::read_to_string(&cfg.trusted_path).unwrap();
    assert_eq!(after, initial_trusted, ".trusted must be untouched for Once decision");
}

// ----- AC #8 -----

#[test]
fn trust_always_appends_line_atomically() {
    // AC #8: TrustDecision::Always on a fresh dir → .trusted
    // written with one line + 0600 perms + idempotent on re-load.
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, true);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    let source = minimal_plugin_source("notion");
    write_plugin(&cfg.plugins_dir, "notion", &source);
    assert!(!cfg.trusted_path.exists(), "precondition: no .trusted");

    let canned = Arc::new(CannedTrustPromptReader::new(vec![TrustDecision::Always]));
    let canned_for_first_load: Arc<dyn TrustPromptReader> = canned;
    let registry = load_all(&rt, cfg.clone(), canned_for_first_load).unwrap();
    let notion = registry.get("notion").unwrap();
    assert_eq!(notion.trust_tier, TrustTier::TrustedUser);

    let trusted_contents = fs::read_to_string(&cfg.trusted_path).unwrap();
    let expected_hash = sha256_hex(source.as_bytes());
    assert_eq!(trusted_contents, format!("notion {expected_hash}\n"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&cfg.trusted_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode must be 0600; got {mode:o}");
    }

    // Second load: TrustedUser, no duplicate line, prompt NOT
    // called.
    let canned2 = Arc::new(CannedTrustPromptReader::new(vec![])); // empty queue
    let counter = Arc::new(CountingReader::new(canned2));
    let counter_clone: Arc<dyn TrustPromptReader> = counter.clone();
    let registry2 = load_all(&rt, cfg.clone(), counter_clone).unwrap();
    assert_eq!(registry2.get("notion").unwrap().trust_tier, TrustTier::TrustedUser);
    assert_eq!(counter.count(), 0, "prompt must not re-fire on subsequent load");

    let trusted_contents2 = fs::read_to_string(&cfg.trusted_path).unwrap();
    assert_eq!(
        trusted_contents2, trusted_contents,
        "subsequent load must not append a duplicate line"
    );
}

// ----- AC #9 -----

#[test]
fn trust_never_skips_plugin_and_logs_denial() {
    // AC #9: TrustDecision::Never → connector not in registry,
    // `.trusted` untouched.
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, true);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    write_plugin(&cfg.plugins_dir, "evil-notion", &minimal_plugin_source("evil-notion"));

    let canned: Arc<dyn TrustPromptReader> =
        Arc::new(CannedTrustPromptReader::new(vec![TrustDecision::Never]));
    let registry = load_all(&rt, cfg.clone(), canned).unwrap();

    assert_eq!(registry.len(), 3, "only built-ins remain");
    assert!(registry.get("evil-notion").is_none());
    assert!(!cfg.trusted_path.exists(), ".trusted must not be created on Never");
}

// ----- AC #10 -----

#[test]
fn metadata_invalid_missing_name() {
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    // Missing `name` field (violates the first required field).
    write_plugin(
        &cfg.plugins_dir,
        "broken",
        r#"export const metadata = {
    version: "1.0.0",
    apiVersion: ">=1.0",
    scopes: [],
};
"#,
    );

    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let registry = load_all(&rt, cfg, reader).unwrap();
    // Failure is non-fatal for user-installed plugins; the bad
    // plugin is simply absent.
    assert!(registry.get("broken").is_none());
    assert_eq!(registry.len(), 3, "only built-ins");
}

#[test]
fn metadata_invalid_bad_version() {
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    write_plugin(
        &cfg.plugins_dir,
        "bad-semver",
        r#"export const metadata = {
    name: "bad-semver",
    version: "not-semver",
    apiVersion: ">=1.0",
    scopes: [],
};
"#,
    );
    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let registry = load_all(&rt, cfg, reader).unwrap();
    assert!(registry.get("bad-semver").is_none());
}

#[test]
fn metadata_invalid_missing_api_version() {
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    write_plugin(
        &cfg.plugins_dir,
        "no-apiv",
        r#"export const metadata = {
    name: "no-apiv",
    version: "1.0.0",
    scopes: [],
};
"#,
    );
    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let registry = load_all(&rt, cfg, reader).unwrap();
    assert!(registry.get("no-apiv").is_none());
}

#[test]
fn metadata_invalid_scopes_not_array() {
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    write_plugin(
        &cfg.plugins_dir,
        "bad-scopes",
        r#"export const metadata = {
    name: "bad-scopes",
    version: "1.0.0",
    apiVersion: ">=1.0",
    scopes: "should.be.an.array",
};
"#,
    );
    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let registry = load_all(&rt, cfg, reader).unwrap();
    assert!(registry.get("bad-scopes").is_none());
}

// ----- AC #11 -----

#[test]
fn metadata_rejects_unsafe_name_slash() {
    // Directory names containing `/` cannot exist on most
    // filesystems, so the test instead declares a `metadata.name`
    // with the forbidden char via a valid directory name that
    // mismatches. The metadata-validator path rejects the unsafe
    // `metadata.name` irrespective of the directory name.
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    write_plugin(
        &cfg.plugins_dir,
        "evil",
        r#"export const metadata = {
    name: "evil/escape",
    version: "1.0.0",
    apiVersion: ">=1.0",
    scopes: [],
};
"#,
    );
    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let registry = load_all(&rt, cfg, reader).unwrap();
    assert!(registry.get("evil").is_none(), "unsafe name in metadata rejected");
    assert!(registry.get("evil/escape").is_none(), "unsafe name never reaches registry");
}

#[test]
fn metadata_rejects_unsafe_name_dotdot() {
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    write_plugin(
        &cfg.plugins_dir,
        "parent-traversal",
        r#"export const metadata = {
    name: "..",
    version: "1.0.0",
    apiVersion: ">=1.0",
    scopes: [],
};
"#,
    );
    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let registry = load_all(&rt, cfg, reader).unwrap();
    assert!(registry.get("..").is_none());
    assert!(registry.get("parent-traversal").is_none());
}

#[test]
fn metadata_rejects_unsafe_name_newline() {
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    write_plugin(
        &cfg.plugins_dir,
        "injected",
        "export const metadata = {\n\
            name: \"evil\\nfake-log-line\",\n\
            version: \"1.0.0\",\n\
            apiVersion: \">=1.0\",\n\
            scopes: [],\n\
         };\n",
    );
    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let registry = load_all(&rt, cfg, reader).unwrap();
    assert!(registry.get("injected").is_none());
    assert!(registry.get("evil\nfake-log-line").is_none());
}

#[test]
fn metadata_rejects_unsafe_name_null_byte() {
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    write_plugin(
        &cfg.plugins_dir,
        "nulled",
        "export const metadata = {\n\
            name: \"a\\x00b\",\n\
            version: \"1.0.0\",\n\
            apiVersion: \">=1.0\",\n\
            scopes: [],\n\
         };\n",
    );
    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let registry = load_all(&rt, cfg, reader).unwrap();
    assert!(registry.get("nulled").is_none());
}

// ----- AC #12 -----

#[test]
fn builtin_failure_is_fatal_user_installed_failure_is_not() {
    // AC #12 (user-installed half): invalid user plugin coexists
    // with valid user plugin; load_all returns Ok with only the
    // valid one registered.
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();

    // Valid plugin.
    write_plugin(&cfg.plugins_dir, "notion", &minimal_plugin_source("notion"));
    // Invalid plugin: missing metadata.
    write_plugin(
        &cfg.plugins_dir,
        "broken",
        "// this plugin exports nothing; `export` statement present\n\
         export const otherThing = 1;\n",
    );

    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let registry = load_all(&rt, cfg, reader).unwrap();
    assert!(registry.get("notion").is_some(), "valid plugin registered");
    assert!(registry.get("broken").is_none(), "invalid plugin skipped");
    // Built-ins + notion = 4.
    assert_eq!(registry.len(), 4);
}

// Built-in-failure-is-fatal is proven by construction: the three
// placeholder JS files all produce valid metadata, and their
// `builtin_connector_names_match_metadata_names` unit test in
// `permitlayer-connectors` guards against ship-time regression.
// A dedicated runtime "inject bad built-in" test would require a
// test hook on `builtin_connectors()` which is out of scope for
// Story 6.3 (would itself be a shipped-binary attack surface).

// ----- AC #13 -----

#[test]
fn user_installed_cannot_shadow_builtin() {
    // AC #13: user-installed plugin with the same directory name
    // as a built-in is skipped with WARN; registry keeps the
    // built-in.
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    // User tries to shadow google-gmail.
    write_plugin(&cfg.plugins_dir, "google-gmail", &minimal_plugin_source("google-gmail"));

    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let registry = load_all(&rt, cfg, reader).unwrap();
    // Still 3 entries (built-ins).
    assert_eq!(registry.len(), 3);
    let gmail = registry.get("google-gmail").expect("built-in survives");
    assert_eq!(gmail.trust_tier, TrustTier::Builtin);
    // The source hash must match the EMBEDDED built-in, not the
    // on-disk user plugin (different file → different hash).
    // Compute what the user-installed plugin's hash WOULD have
    // been and assert it does NOT match the registered one.
    let user_source = minimal_plugin_source("google-gmail");
    let user_hash = sha256_hex(user_source.as_bytes());
    assert_ne!(
        gmail.source_sha256_hex, user_hash,
        "registered source must be the embedded built-in, not the user-installed shadow"
    );
}

// ----- AC #20 -----

#[test]
fn missing_plugins_dir_is_non_fatal() {
    // AC #20: plugins_dir does NOT exist → only built-ins.
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    assert!(!cfg.plugins_dir.exists(), "precondition: no plugins dir");
    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let registry = load_all(&rt, cfg, reader).expect("missing dir is non-fatal");
    assert_eq!(registry.len(), 3);
}

// ----- AC #21 -----

#[test]
fn invalid_trusted_lines_are_ignored_not_fatal() {
    // AC #21: `.trusted` contains garbage + one valid entry →
    // valid entry honored, garbage lines ignored, load succeeds.
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, true);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    let source = minimal_plugin_source("notion");
    write_plugin(&cfg.plugins_dir, "notion", &source);

    let real_hash = sha256_hex(source.as_bytes());
    // `.trusted` with assorted garbage + the one real entry.
    fs::write(
        &cfg.trusted_path,
        format!(
            "totally invalid syntax\n\
             notion abc\n\
             {}\n\
             notion {real_hash}\n\
             UPPERCASE ignored\n",
            "another bogus line"
        ),
    )
    .unwrap();

    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let registry = load_all(&rt, cfg, reader).unwrap();
    let notion = registry.get("notion").unwrap();
    assert_eq!(notion.trust_tier, TrustTier::TrustedUser);
}

// ----- AC #22 -----

#[test]
fn trusted_file_honors_comments_and_blank_lines() {
    // AC #22: `.trusted` with comments + blank lines parses the
    // real entry.
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, true);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    let source = minimal_plugin_source("notion");
    write_plugin(&cfg.plugins_dir, "notion", &source);

    let real_hash = sha256_hex(source.as_bytes());
    fs::write(
        &cfg.trusted_path,
        format!("# header comment\n\nnotion {real_hash}\n\n# trailing comment\n"),
    )
    .unwrap();

    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let registry = load_all(&rt, cfg, reader).unwrap();
    assert_eq!(
        registry.get("notion").unwrap().trust_tier,
        TrustTier::TrustedUser,
        "comments and blank lines must not interfere with the valid entry"
    );
}

// ----- Bonus: empty plugins dir (no subdirs, no .trusted) ------

#[test]
fn empty_plugins_dir_is_non_fatal() {
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, true);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    // No plugins, no .trusted.
    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let registry = load_all(&rt, cfg, reader).unwrap();
    assert_eq!(registry.len(), 3);
}

// ----- Bonus: hidden dir is skipped silently -----

#[test]
fn hidden_directory_is_skipped() {
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    // `.hidden` dir — must be ignored without warning.
    write_plugin(&cfg.plugins_dir, ".hidden", &minimal_plugin_source("hidden"));
    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let registry = load_all(&rt, cfg, reader).unwrap();
    assert_eq!(registry.len(), 3, "hidden dir ignored");
}

// ----- Bonus: dir without index.js is skipped silently -----

#[test]
fn directory_without_index_js_is_skipped() {
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    let dir = cfg.plugins_dir.join("wip");
    fs::create_dir_all(&dir).unwrap();
    // Note: no index.js — operator may have renamed / not yet
    // created it.
    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let registry = load_all(&rt, cfg, reader).unwrap();
    assert_eq!(registry.len(), 3, "index.js-less dir ignored silently");
}

// ----- Bonus: invalid scope charset rejected -----

#[test]
fn metadata_invalid_scopes_charset() {
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    write_plugin(
        &cfg.plugins_dir,
        "bad-scope-chars",
        r#"export const metadata = {
    name: "bad-scope-chars",
    version: "1.0.0",
    apiVersion: ">=1.0",
    scopes: ["Uppercase.Scope"],
};
"#,
    );
    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let registry = load_all(&rt, cfg, reader).unwrap();
    assert!(registry.get("bad-scope-chars").is_none());
}

// ----- Bonus: description too long is rejected -----

#[test]
fn metadata_description_over_512_chars_is_rejected() {
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    let long = "a".repeat(600);
    write_plugin(
        &cfg.plugins_dir,
        "verbose",
        &format!(
            r#"export const metadata = {{
    name: "verbose",
    version: "1.0.0",
    apiVersion: ">=1.0",
    scopes: [],
    description: "{long}",
}};
"#
        ),
    );
    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let registry = load_all(&rt, cfg, reader).unwrap();
    assert!(registry.get("verbose").is_none());
}

// ----- Bonus: non-ESM source is rejected -----

#[test]
fn non_esm_plugin_is_rejected_with_clear_message() {
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    // CommonJS-style — no `export` statement. Rejected quickly
    // before the QuickJS module compile.
    write_plugin(
        &cfg.plugins_dir,
        "commonjs-plugin",
        "module.exports = { metadata: { name: 'commonjs-plugin' } };\n",
    );
    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let registry = load_all(&rt, cfg, reader).unwrap();
    assert!(registry.get("commonjs-plugin").is_none());
}

// ----- Bonus: metadata.name mismatch with dir name rejected -----

#[test]
fn metadata_name_mismatch_with_dir_name_is_rejected() {
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    write_plugin(
        &cfg.plugins_dir,
        "notion",
        &minimal_plugin_source("different-name"), // mismatched
    );
    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let registry = load_all(&rt, cfg, reader).unwrap();
    assert!(registry.get("notion").is_none());
    assert!(registry.get("different-name").is_none());
}

// Compile-time smoke: `load_all` returns the advertised error
// type. This pins the public surface so a future refactor that
// changes the error type fails compile instead of silently
// breaking downstream callers.
#[test]
fn load_all_returns_result_of_plugin_error() {
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let res: Result<permitlayer_plugins::PluginRegistry, PluginError> = load_all(&rt, cfg, reader);
    assert!(res.is_ok());
}

// ==========================================================
// Review-patched tests (2026-04-18)
// ==========================================================

// ----- AC #8 split: discrete second-load idempotence test -----

#[test]
fn trust_always_second_load_is_idempotent() {
    // First load with Always decision writes a `.trusted` entry.
    // Second load with the SAME content must not re-prompt and
    // must not duplicate the entry. This is a discrete test (the
    // `trust_always_appends_line_atomically` test also exercises
    // second-load behavior, but the spec names this as its own
    // AC assertion).
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, true);

    write_plugin(&cfg.plugins_dir, "notion", &minimal_plugin_source("notion"));
    let reader1 = Arc::new(CannedTrustPromptReader::new(vec![TrustDecision::Always]));
    let r1 = load_all(&rt, cfg.clone(), reader1 as Arc<dyn TrustPromptReader>).unwrap();
    assert_eq!(r1.get("notion").unwrap().trust_tier, TrustTier::TrustedUser);

    let trusted_contents_1 = fs::read_to_string(&cfg.trusted_path).unwrap();
    assert_eq!(trusted_contents_1.lines().count(), 1, "first load writes exactly one line");

    // Second load with a reader that panics if called — proves
    // the prompt path is not re-entered.
    struct PanicReader;
    impl TrustPromptReader for PanicReader {
        fn prompt(&self, _: &str, _: &Path, _: &str) -> TrustDecision {
            panic!("prompt must not be called on second load when entry is trusted");
        }
    }
    let reader2: Arc<dyn TrustPromptReader> = Arc::new(PanicReader);
    let r2 = load_all(&rt, cfg.clone(), reader2).unwrap();
    assert_eq!(r2.get("notion").unwrap().trust_tier, TrustTier::TrustedUser);

    let trusted_contents_2 = fs::read_to_string(&cfg.trusted_path).unwrap();
    assert_eq!(trusted_contents_1, trusted_contents_2, "second load must not mutate .trusted");
}

// ----- Built-in trust-check invariant (decision-driven) -----

#[test]
fn builtin_requires_trusted_entry_when_auto_trust_disabled() {
    // With auto_trust_builtins = false and no `.trusted` entries,
    // the daemon must refuse to boot — built-ins are never
    // silently dropped. (Review decision 3: option 2.)
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(false, false);
    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let res = load_all(&rt, cfg, reader);
    match res {
        Err(PluginError::TrustCheckFailed { connector, detail }) => {
            assert!(
                ["google-gmail", "google-calendar", "google-drive"].contains(&connector.as_str()),
                "error must name a built-in: got {connector}"
            );
            assert!(
                detail.contains("auto_trust_builtins"),
                "detail must cite the config flag: {detail}"
            );
        }
        other => {
            panic!("expected TrustCheckFailed for missing built-in trust entry, got {other:?}")
        }
    }
}

#[test]
fn builtin_loads_when_trusted_entry_matches_and_auto_trust_disabled() {
    // Pre-seed `.trusted` with the built-in's content hash. The
    // loader should honor it (no prompt) and register the built-in.
    use permitlayer_connectors::builtin_connectors;

    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(false, false);
    fs::create_dir_all(&cfg.plugins_dir).unwrap();

    // Seed `.trusted` with every built-in.
    let mut trusted = String::new();
    for b in builtin_connectors() {
        let h = sha256_hex(b.source.as_bytes());
        trusted.push_str(&format!("{} {h}\n", b.name));
    }
    fs::write(&cfg.trusted_path, trusted).unwrap();

    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let reg = load_all(&rt, cfg, reader).expect("load_all must succeed when .trusted is complete");
    assert_eq!(reg.len(), 3, "all three built-ins register when trusted");
    for name in ["google-gmail", "google-calendar", "google-drive"] {
        assert_eq!(reg.get(name).unwrap().trust_tier, TrustTier::Builtin);
    }
}

// ----- Source size cap (decision-driven) -----

#[test]
fn user_installed_source_exceeding_cap_is_rejected_gracefully() {
    // A 2 MiB plugin (above the 1 MiB cap) must NOT crash the
    // daemon. The specific connector is skipped; built-ins
    // still register.
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    // Pad the minimal source with a large string literal that
    // brings total size above 1 MiB.
    let padding_chars = 2 * 1024 * 1024;
    let padding = "a".repeat(padding_chars);
    let source = format!(
        r#"export const metadata = {{
    name: "fat",
    version: "1.0.0",
    apiVersion: ">=1.0",
    scopes: ["example.read"],
    description: "x",
}};
// {padding}
"#
    );
    write_plugin(&cfg.plugins_dir, "fat", &source);

    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let reg = load_all(&rt, cfg, reader).expect("oversized plugin must not crash the daemon");
    assert!(reg.get("fat").is_none(), "oversized plugin must be skipped, not registered");
    assert_eq!(reg.len(), 3, "all three built-ins still register");
}

// ----- Symlink rejection (decision-driven) -----

#[test]
#[cfg(unix)]
fn symlinked_plugin_dir_is_skipped_with_warn() {
    // Set up a real plugin target outside `plugins_dir`, then
    // symlink `plugins_dir/notion` → the real dir. Loader must
    // refuse to follow the symlink.
    let rt = mk_runtime();
    let (tmp, cfg) = mk_config(true, false);
    let real_target = tmp.path().join("evil");
    fs::create_dir_all(&real_target).unwrap();
    fs::write(real_target.join("index.js"), minimal_plugin_source("notion")).unwrap();
    fs::create_dir_all(&cfg.plugins_dir).unwrap();
    let link_path = cfg.plugins_dir.join("notion");
    std::os::unix::fs::symlink(&real_target, &link_path).unwrap();

    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let reg = load_all(&rt, cfg, reader).unwrap();
    assert!(reg.get("notion").is_none(), "symlinked plugin directory must not be followed");
    assert_eq!(reg.len(), 3, "built-ins still register");
}

#[test]
#[cfg(unix)]
fn symlinked_index_js_is_skipped_with_warn() {
    // The plugin directory itself is a real dir, but `index.js`
    // is a symlink to content outside the plugins dir. The
    // loader must refuse to follow the inner symlink.
    let rt = mk_runtime();
    let (tmp, cfg) = mk_config(true, false);
    let real_source = tmp.path().join("real-index.js");
    fs::write(&real_source, minimal_plugin_source("notion")).unwrap();
    let plugin_dir = cfg.plugins_dir.join("notion");
    fs::create_dir_all(&plugin_dir).unwrap();
    std::os::unix::fs::symlink(&real_source, plugin_dir.join("index.js")).unwrap();

    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let reg = load_all(&rt, cfg, reader).unwrap();
    assert!(reg.get("notion").is_none(), "symlinked index.js must not be followed");
}

// ----- Tighter export sniff (decision-driven patch) -----

#[test]
fn commonjs_export_in_string_literal_is_still_rejected_as_not_esm() {
    // A CommonJS plugin that contains "export " inside a string
    // literal — the previous naive substring sniff would have
    // accepted it and then failed with a generic JsSyntax error.
    // The tightened sniff walks lines, skips `//` comments, and
    // requires `export` followed by a keyword or `{`.
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    let source = r#"// this plugin can export nothing
module.exports = { metadata: { name: "cjs", description: "I can export things" } };
"#;
    write_plugin(&cfg.plugins_dir, "cjs", source);

    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let reg = load_all(&rt, cfg, reader).unwrap();
    assert!(reg.get("cjs").is_none(), "CommonJS plugin must be rejected");
}

#[test]
fn export_with_tab_whitespace_is_accepted() {
    // Real ESM with a tab after `export` — the old naive
    // `contains("export ")` rejected this; the tightened sniff
    // accepts it.
    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    let source = "export\tconst metadata = {\n  name: \"tabby\",\n  version: \"1.0.0\",\n  apiVersion: \">=1.0\",\n  scopes: [\"a.b\"],\n};\n";
    write_plugin(&cfg.plugins_dir, "tabby", source);

    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let reg = load_all(&rt, cfg, reader).unwrap();
    assert!(reg.get("tabby").is_some(), "ESM plugin with tab-separated `export` must be accepted");
}

// ----- AC #25: every built-in parses cleanly through validator -----

#[test]
fn every_builtin_parses_cleanly_through_loader_metadata_validator() {
    // AC #25 pins: every shipped built-in JS passes
    // `parse_and_validate_metadata` (via the live loader). A
    // ship-time regression that breaks a placeholder JS file
    // (missing field, bad semver, wrong apiVersion shape) fails
    // here — not just at daemon boot.
    use permitlayer_connectors::builtin_connectors;

    let rt = mk_runtime();
    let (_tmp, cfg) = mk_config(true, false);
    // Auto-trust mode so every built-in loads without consulting
    // `.trusted`; the sole gate is metadata validation.
    let reader: Arc<dyn TrustPromptReader> = Arc::new(NoOp);
    let reg = load_all(&rt, cfg, reader).expect("every built-in must pass metadata validation");

    // Sanity: the registry contains every built-in name.
    for b in builtin_connectors() {
        let entry = reg.get(b.name).unwrap_or_else(|| {
            panic!("built-in {} did not register — metadata must be valid", b.name)
        });
        // Sanity-check each built-in carries real metadata (no
        // empty version, non-empty scope list).
        assert!(!entry.version.is_empty(), "{}: version must be non-empty", b.name);
        assert!(!entry.scopes.is_empty(), "{}: scopes must be non-empty", b.name);
        assert_eq!(entry.trust_tier, TrustTier::Builtin);
        assert_eq!(entry.source_sha256_hex.len(), 64);
    }
}

// ----- Story 6.4: public wrapper tests (AC #8) -----

#[test]
fn validate_plugin_source_accepts_minimal_metadata() {
    let rt = mk_runtime();
    let source = minimal_plugin_source("my-plugin");
    let meta =
        validate_plugin_source(&rt, "my-plugin", &source).expect("valid metadata must parse");
    assert_eq!(meta.name, "my-plugin");
    assert_eq!(meta.version, "1.0.0");
    assert_eq!(meta.api_version, ">=1.0");
    assert_eq!(meta.scopes, vec!["test.readonly".to_owned()]);
    assert!(meta.description.is_some());
}

#[test]
fn validate_plugin_source_rejects_invalid_name() {
    // AC #8: the validator surfaces the same detail string operators
    // grep for in daemon logs — here we assert that an uppercase
    // `name` yields `MetadataInvalid` with a charset-violation
    // detail.
    let rt = mk_runtime();
    let source = r#"export const metadata = {
    name: "Bad-Name",
    version: "0.1.0",
    apiVersion: ">=1.0",
    scopes: ["test.readonly"],
};
"#;
    let err = validate_plugin_source(&rt, "bad", source).expect_err("uppercase name must reject");
    match err {
        PluginError::MetadataInvalid { detail, .. } => {
            assert!(
                detail.contains("unsafe character") || detail.contains("charset"),
                "detail should describe the charset violation: {detail}"
            );
        }
        other => panic!("expected MetadataInvalid, got {other:?}"),
    }
}

#[test]
fn load_one_from_path_warn_user_tier() {
    // AC #8: the standalone loader returns a RegisteredConnector
    // tagged WarnUser (there is no .trusted to consult).
    let rt = mk_runtime();
    let tmp = tempfile::tempdir().expect("tempdir");
    let plugin_dir = tmp.path().join("my-plugin");
    fs::create_dir_all(&plugin_dir).expect("mkdir");
    let source = minimal_plugin_source("my-plugin");
    fs::write(plugin_dir.join("index.js"), &source).expect("write index.js");

    let connector = load_one_from_path(&rt, &plugin_dir).expect("load_one_from_path must succeed");
    assert_eq!(connector.name, "my-plugin");
    assert_eq!(connector.trust_tier, TrustTier::WarnUser);
    assert_eq!(connector.source_sha256_hex, sha256_hex(source.as_bytes()));
    assert!(!connector.scopes.is_empty());
}

#[test]
fn load_one_from_path_missing_index_js_errors() {
    // AC #8: a plugin directory without index.js surfaces a clean
    // PluginError::PluginLoadFailed (not a panic).
    let rt = mk_runtime();
    let tmp = tempfile::tempdir().expect("tempdir");
    let plugin_dir = tmp.path().join("empty-plugin");
    fs::create_dir_all(&plugin_dir).expect("mkdir");

    let err = load_one_from_path(&rt, &plugin_dir).expect_err("missing index.js must error");
    match err {
        PluginError::PluginLoadFailed { .. } => (),
        other => panic!("expected PluginLoadFailed, got {other:?}"),
    }
}

#[test]
fn load_one_from_path_accepts_mismatched_dir_and_metadata_name() {
    // AC #8 nuance: unlike the daemon loader, the standalone path
    // does NOT require metadata.name to match the directory
    // basename (CLI users often work in WIP dirs).
    let rt = mk_runtime();
    let tmp = tempfile::tempdir().expect("tempdir");
    let plugin_dir = tmp.path().join("wip-dir-name");
    fs::create_dir_all(&plugin_dir).expect("mkdir");
    let source = minimal_plugin_source("final-connector-name");
    fs::write(plugin_dir.join("index.js"), &source).expect("write index.js");

    let connector = load_one_from_path(&rt, &plugin_dir).expect("must load despite name mismatch");
    assert_eq!(connector.name, "final-connector-name");
}
