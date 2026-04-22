//! Plugin loader: discovers built-in + user-installed connectors,
//! validates each via a sandbox-only [`PluginRuntime::with_context`]
//! metadata parse, emits the first-load WARN for user-installed
//! plugins whose sha256 is not in `~/.agentsso/plugins/.trusted`,
//! and builds the [`PluginRegistry`].
//!
//! # Non-goals
//!
//! - **No host API registration at load time.** The loader uses
//!   [`PluginRuntime::with_context`] (sandbox only), never
//!   [`PluginRuntime::with_host_api`]. Host-API registration
//!   happens at request-dispatch time (a future story). This keeps
//!   the loader free of the Story 6.2 AD4 `spawn_blocking` calling
//!   contract — load is a pure-Rust path invoked from
//!   `daemon::run`.
//! - **No request dispatch.** Loading a plugin registers it in the
//!   [`PluginRegistry`]; actually serving traffic through plugin
//!   code is a separate future story.
//!
//! # Failure policy
//!
//! - Built-in connector failure → **fatal** ([`PluginError::PluginLoadFailed`]).
//!   A built-in whose metadata fails validation is a shipped-binary
//!   bug; the daemon refuses to boot rather than silently skipping it.
//! - User-installed connector failure → **non-fatal**. The specific
//!   connector is skipped (a `tracing::warn!` records the reason);
//!   the daemon still boots with the remaining connectors.
//!
//! # Anti-escape posture at load time
//!
//! Metadata parsing runs inside [`PluginRuntime::with_context`] — a
//! fresh sandboxed context with the Story 6.1 Function-constructor
//! neuter and the Story 6.2 intrinsics set. The plugin JS executes
//! during the parse, so a malicious plugin could throw, consume CPU
//! until interrupted, or attempt sandbox escape. The sandbox wall
//! wall + the `ExecutionDeadlineExceeded` interrupt handler + the
//! serde round-trip below are three independent defenses:
//!
//! 1. **Sandbox wall (`crate::sandbox::install_sandbox`):** Function constructor neutered; no `require`,
//!    `process`, `eval` at top level, etc.
//! 2. **Interrupt handler:** pathological plugins that loop forever
//!    during metadata parse get a `LoadFailureReason::Timeout`.
//! 3. **Serde round-trip:** plugin-controlled JS values are reserialized
//!    through `serde_json::Value` → typed `RawMetadata` before
//!    validation, so an attacker cannot smuggle non-serializable
//!    objects (Symbols, Proxies, functions masquerading as strings)
//!    past the typed field constraints.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// DoS-hardening cap for plugin source file size. Real plugins are
/// ~100 KB; 1 MiB is ~10× that. Exceeding the cap surfaces as
/// [`LoadFailureReason::SourceTooLarge`] rather than OOM.
const PLUGIN_SOURCE_MAX_BYTES: u64 = 1 << 20;

use permitlayer_connectors::BuiltinConnector;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::PluginError;
use crate::error::LoadFailureReason;
use crate::registry::{PluginRegistry, RegisteredConnector, TrustTier};
use crate::runtime::PluginRuntime;

// -------------------------------------------------------------
// Public surface
// -------------------------------------------------------------

/// Loader configuration, sourced from the `[plugins]` section of
/// `DaemonConfig`. Taken by value so callers construct it inline
/// without holding a reference back into `DaemonConfig`.
#[derive(Debug, Clone)]
pub struct LoaderConfig {
    /// When `true`, built-in connectors register as
    /// [`TrustTier::Builtin`] without consulting the prompter.
    /// When `false`, built-ins go through the same prompt path
    /// as user-installed plugins — useful for audit-conscious
    /// operators who want to explicitly acknowledge every
    /// connector shipping with the binary.
    pub auto_trust_builtins: bool,

    /// When `true`, user-installed plugins whose sha256 is not in
    /// `.trusted` trigger the [`TrustPromptReader`] interactive
    /// path. When `false`, they load as [`TrustTier::WarnUser`]
    /// without a prompt (the WARN log line still fires, honoring
    /// epics.md:1716's "continues with a warning annotation"
    /// language for headless deployments).
    pub warn_on_first_load: bool,

    /// Absolute path to the plugins directory. The loader does NOT
    /// create this directory — a missing directory is the expected
    /// state on a fresh daemon and means "no user-installed
    /// plugins; register only built-ins."
    pub plugins_dir: PathBuf,

    /// Absolute path to `<plugins_dir>/.trusted`. Loader reads at
    /// start to classify user-installed plugins; writes when
    /// [`TrustDecision::Always`] is chosen.
    pub trusted_path: PathBuf,
}

/// Contract for the first-load prompt. The production impl lives
/// in the daemon crate (`crates/permitlayer-daemon/src/cli/
/// connectors_prompt.rs`) because it depends on TTY + stdin I/O,
/// which `permitlayer-plugins` is kept free of. A canned impl
/// ([`CannedTrustPromptReader`]) is provided for deterministic
/// tests.
pub trait TrustPromptReader: Send + Sync {
    /// Called once per unknown user-installed plugin during
    /// [`load_all`]. The return value controls both whether the
    /// plugin loads AND whether a `.trusted` entry is persisted.
    fn prompt(
        &self,
        connector_name: &str,
        source_path: &Path,
        source_sha256_hex: &str,
    ) -> TrustDecision;
}

/// Operator's decision at the first-load prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDecision {
    /// Load the plugin AND persist a `.trusted` entry so future
    /// boots don't re-prompt.
    Always,
    /// Load the plugin this time; do NOT persist. The next boot
    /// will re-prompt.
    Once,
    /// Refuse to load the plugin. The connector is skipped (the
    /// daemon still boots); a denial WARN is logged.
    Never,
    /// No TTY available or `warn_on_first_load = false`. Load
    /// the plugin AND classify as [`TrustTier::WarnUser`] — consistent
    /// with the "user plugins are best-effort" posture from
    /// epics.md:1712.
    NoPromptAvailable,
}

/// Canned test-only [`TrustPromptReader`] that returns responses
/// from a queue in order. Exhausted queue yields
/// [`TrustDecision::NoPromptAvailable`] — matches the production
/// TTY reader's posture under EOF / timeout.
pub struct CannedTrustPromptReader {
    queue: Mutex<std::collections::VecDeque<TrustDecision>>,
}

impl CannedTrustPromptReader {
    /// Build a reader from an ordered list of responses. The
    /// first `prompt` call returns the first element, etc.
    #[must_use]
    pub fn new(responses: Vec<TrustDecision>) -> Self {
        Self { queue: Mutex::new(responses.into()) }
    }

    /// Number of responses that would still be consumed. Useful
    /// for assertions (`assert_eq!(reader.remaining(), 0)` proves
    /// every canned decision was consumed in order).
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.queue.lock().map(|q| q.len()).unwrap_or(0)
    }
}

impl TrustPromptReader for CannedTrustPromptReader {
    fn prompt(
        &self,
        _connector_name: &str,
        _source_path: &Path,
        _source_sha256_hex: &str,
    ) -> TrustDecision {
        self.queue
            .lock()
            .ok()
            .and_then(|mut q| q.pop_front())
            .unwrap_or(TrustDecision::NoPromptAvailable)
    }
}

/// No-op trust prompter for tests that want to exercise the
/// non-prompt branch (`warn_on_first_load = false` OR the
/// trusted-user branch where the prompter is never called).
/// Calling `prompt` always returns [`TrustDecision::NoPromptAvailable`]
/// — if a test sees a non-zero call count on this reader, the
/// loader is reaching the prompt path unexpectedly.
pub struct NoOpTrustPromptReader;

impl TrustPromptReader for NoOpTrustPromptReader {
    fn prompt(
        &self,
        _connector_name: &str,
        _source_path: &Path,
        _source_sha256_hex: &str,
    ) -> TrustDecision {
        TrustDecision::NoPromptAvailable
    }
}

/// Main entry point. Call once from the daemon's boot path after
/// the [`PluginRuntime`] is constructed.
///
/// # Errors
///
/// Returns [`PluginError::PluginLoadFailed`] when a **built-in**
/// connector fails to load — that is a shipped-binary bug and the
/// daemon should refuse to boot. User-installed connector failures
/// are logged at WARN level and the connector is skipped; they do
/// NOT propagate as an `Err` (the returned registry is `Ok(...)`
/// with the valid subset).
pub fn load_all(
    runtime: &PluginRuntime,
    config: LoaderConfig,
    prompter: Arc<dyn TrustPromptReader>,
) -> Result<PluginRegistry, PluginError> {
    // 1. Load the trusted set (gracefully ignores missing / malformed entries).
    let trusted_set = parse_trusted_file(&config.trusted_path);

    let mut registered: BTreeMap<String, Arc<RegisteredConnector>> = BTreeMap::new();
    let mut builtin_names: BTreeSet<String> = BTreeSet::new();

    // 2. Built-ins — FATAL on failure. Duplicate names in the
    //    const slice are also fatal (shipped-binary regression
    //    catch).
    for builtin in permitlayer_connectors::builtin_connectors() {
        match load_builtin(runtime, *builtin, &trusted_set, &config) {
            Ok(c) => {
                if !builtin_names.insert(c.name.clone()) {
                    tracing::error!(
                        connector = %c.name,
                        "duplicate built-in connector name — refusing to boot"
                    );
                    return Err(PluginError::PluginLoadFailed {
                        connector: c.name,
                        reason: LoadFailureReason::DuplicateBuiltin,
                    });
                }
                registered.insert(c.name.clone(), Arc::new(c));
            }
            Err(e) => {
                tracing::error!(
                    connector = builtin.name,
                    error = %e,
                    "built-in connector failed to load — refusing to boot"
                );
                return Err(e);
            }
        }
    }

    // 3. User-installed — NON-fatal per connector.
    if config.plugins_dir.is_dir() {
        // Refuse to follow a symlinked plugins_dir — operators who
        // want a shared dir should set `plugins_dir` explicitly.
        if is_symlink(&config.plugins_dir) {
            tracing::warn!(
                plugins_dir = %config.plugins_dir.display(),
                "plugins_dir is a symlink; refusing to follow (set plugins_dir to the real path instead); skipping user plugins"
            );
            return Ok(PluginRegistry::new(registered));
        }
        let mut entries: Vec<PathBuf> = match fs::read_dir(&config.plugins_dir) {
            Ok(it) => {
                let mut out: Vec<PathBuf> = Vec::new();
                for entry_result in it {
                    match entry_result {
                        Ok(e) => out.push(e.path()),
                        Err(e) => {
                            // Surface racing-fs errors so operators
                            // can diagnose why a plugin "isn't loading"
                            // — silent `filter_map(|r| r.ok())` drops
                            // are a debugging dead end.
                            tracing::warn!(
                                plugins_dir = %config.plugins_dir.display(),
                                error = %e,
                                "plugins directory entry failed to read; skipping that entry"
                            );
                        }
                    }
                }
                out
            }
            Err(e) => {
                tracing::warn!(
                    plugins_dir = %config.plugins_dir.display(),
                    error = %e,
                    "failed to read plugins directory; only built-in connectors will be loaded"
                );
                Vec::new()
            }
        };
        // Deterministic traversal — same order across boots so
        // test-seam canned prompts line up with plugin discovery.
        entries.sort();

        for path in entries {
            // Refuse to follow symlinked plugin directories — an
            // adversary who can write `/tmp/evil/index.js` and
            // persuade the operator to symlink it into
            // `~/.agentsso/plugins/` would otherwise get their code
            // hashed and registered. Legit shared-dir use cases
            // should set `plugins_dir` explicitly.
            if is_symlink(&path) {
                tracing::warn!(
                    path = %path.display(),
                    "plugin directory is a symlink; refusing to follow; skipping"
                );
                continue;
            }
            if !path.is_dir() {
                continue;
            }
            let dir_name = match path.file_name().and_then(|s| s.to_str()) {
                Some(n) => n.to_owned(),
                None => {
                    tracing::warn!(
                        path = %path.display(),
                        "plugins directory entry has non-UTF-8 name; skipping"
                    );
                    continue;
                }
            };
            // Skip hidden dirs (`.trusted` is a file but e.g. `.git`
            // / `.DS_Store` dirs may appear in operator workflows).
            if dir_name.starts_with('.') {
                continue;
            }

            let index_js = path.join("index.js");
            // Refuse to read a symlinked index.js for the same
            // reason we refuse symlinked dirs.
            if is_symlink(&index_js) {
                tracing::warn!(
                    connector = %dir_name,
                    path = %index_js.display(),
                    "index.js is a symlink; refusing to follow; skipping connector"
                );
                continue;
            }
            if !index_js.is_file() {
                // Operator-in-progress scaffolding — not a loader
                // error. Skip silently so `agentsso connectors new`
                // (Story 6.4) can run mid-edit without polluting
                // operator logs.
                continue;
            }

            match load_user_installed(
                runtime,
                &dir_name,
                &index_js,
                &trusted_set,
                &builtin_names,
                &config,
                prompter.as_ref(),
            ) {
                Ok(Some(c)) => {
                    registered.insert(c.name.clone(), Arc::new(c));
                }
                Ok(None) => {
                    // Skipped (name collision, TrustDecision::Never,
                    // hidden-dir filter, etc.) — already logged.
                }
                Err(e) => {
                    tracing::warn!(
                        connector = %dir_name,
                        error = %e,
                        "user-installed connector failed to load; skipping (daemon still boots)"
                    );
                }
            }
        }
    } else {
        tracing::info!(
            plugins_dir = %config.plugins_dir.display(),
            "plugins directory not present — only built-in connectors will be loaded"
        );
    }

    // 4. Prune stale .trusted entries for connectors no longer on disk.
    // Only prune if the trusted file exists — nothing to do otherwise.
    let live_names: std::collections::HashSet<&str> =
        registered.keys().map(|s| s.as_str()).collect();
    prune_stale_trusted_entries(&config.trusted_path, &live_names);

    Ok(PluginRegistry::new(registered))
}

/// Remove `.trusted` entries whose connector directory no longer exists.
///
/// Reads the current `.trusted` file, filters to entries whose name is
/// in `live_names`, and rewrites via the same atomic write-temp-rename
/// discipline as [`persist_trust_entry`]. Comments and blank lines are
/// preserved. A `tracing::info!` logs the pruned names.
///
/// Errors are non-fatal — a failure to prune is just a stale file; the
/// caller still boots cleanly.
fn prune_stale_trusted_entries(trusted_path: &Path, live_names: &std::collections::HashSet<&str>) {
    // Read existing contents; bail silently if the file doesn't exist.
    let contents = match fs::read_to_string(trusted_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            tracing::warn!(
                path = %trusted_path.display(),
                error = %e,
                "failed to read .trusted for pruning; skipping prune"
            );
            return;
        }
    };

    let mut pruned_names: Vec<String> = Vec::new();
    let kept_lines: Vec<&str> = contents
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            // Keep comments and blank lines unchanged.
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return true;
            }
            let mut iter = trimmed.split_whitespace();
            if let Some(name) = iter.next()
                && !live_names.contains(name)
            {
                pruned_names.push(name.to_owned());
                return false;
            }
            true
        })
        .collect();
    // Reconstruct with a single trailing newline — `lines()` strips
    // terminators so we re-add them via join. A trailing newline on the
    // last line is conventional and avoids accumulating blank lines on
    // repeated prune cycles.
    let kept =
        if kept_lines.is_empty() { String::new() } else { format!("{}\n", kept_lines.join("\n")) };

    if pruned_names.is_empty() {
        return;
    }

    tracing::info!(
        target: "plugin_loader",
        count = pruned_names.len(),
        names = ?pruned_names,
        "pruned stale .trusted entries for removed connectors"
    );

    // Atomic rewrite via temp-rename.
    let parent = match trusted_path.parent() {
        Some(p) => p,
        None => {
            tracing::warn!("trusted_path has no parent; cannot prune");
            return;
        }
    };
    let tmp_path =
        parent.join(format!(".trusted.{}.{}.tmp", std::process::id(), tmp_suffix_counter()));
    let mut open_opts = fs::OpenOptions::new();
    open_opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_opts.mode(0o600);
    }
    let write_result = (|| -> Result<(), std::io::Error> {
        let mut f = open_opts.open(&tmp_path)?;
        f.write_all(kept.as_bytes())?;
        f.sync_all()?;
        fs::rename(&tmp_path, trusted_path)?;
        #[cfg(unix)]
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp_path);
        tracing::warn!(
            path = %trusted_path.display(),
            error = %e,
            "failed to rewrite .trusted after pruning; stale entries remain"
        );
    }
}

// -------------------------------------------------------------
// Story 6.4 public wrappers for standalone CLI tooling
// (`agentsso connectors new` + `agentsso connectors test`)
// -------------------------------------------------------------

/// Validate a plugin's JS source against the same metadata rules the
/// daemon loader applies at boot.
///
/// This is a thin, stable wrapper over the internal
/// `parse_and_validate_metadata` routine — promoted to the public
/// surface in Story 6.4 so `agentsso connectors test` runs the
/// **exact** validator the daemon uses (no shadow implementation, no
/// divergence risk). Errors map 1:1 to [`PluginError::MetadataInvalid`]
/// / [`PluginError::PluginLoadFailed`] with the same detail strings
/// operators already grep for in daemon logs.
///
/// # Side effects
///
/// Allocates and runs a single fresh sandboxed [`rquickjs::Context`]
/// inside `runtime` (via [`PluginRuntime::with_context`]); no host API
/// is registered. No filesystem, no network, no `.trusted`
/// consultation. Pure source-in → metadata-out.
///
/// # Example
///
/// ```ignore
/// use permitlayer_plugins::{validate_plugin_source, PluginRuntime};
/// let rt = PluginRuntime::new_default().unwrap();
/// let source = "export const metadata = { name: \"my-plugin\", version: \"0.1.0\", apiVersion: \">=1.0\", scopes: [\"example.readonly\"] };";
/// let meta = validate_plugin_source(&rt, "my-plugin", source).unwrap();
/// assert_eq!(meta.name, "my-plugin");
/// ```
pub fn validate_plugin_source(
    runtime: &PluginRuntime,
    connector: &str,
    source: &str,
) -> Result<ValidatedMetadata, PluginError> {
    parse_and_validate_metadata(runtime, connector, source)
}

/// Load and validate a single plugin directory **without** consulting
/// `.trusted`, prompting, or writing anything to disk.
///
/// Reads `<plugin_dir>/index.js` (capped at 1 MiB per the loader's
/// DoS posture), hashes it, calls [`validate_plugin_source`], and
/// returns a [`RegisteredConnector`] tagged [`TrustTier::WarnUser`]
/// (the tier the standalone tester uses because there is no daemon
/// boot to consult a `.trusted` allowlist).
///
/// Intended for CLI tooling that wants to validate a plugin
/// offline — typically `agentsso connectors test`. Unlike
/// [`load_all`], this function:
///
/// - does **not** require the plugin's `metadata.name` to match
///   `<plugin_dir>`'s basename (CLI users often point at WIP
///   directories with arbitrary names);
/// - does **not** enforce the built-in name-collision check
///   (standalone tester has no registry to consult);
/// - does **not** persist or consult `.trusted`;
/// - does **not** invoke any [`TrustPromptReader`].
///
/// # Example
///
/// ```ignore
/// use permitlayer_plugins::{load_one_from_path, PluginRuntime};
/// use std::path::Path;
/// let rt = PluginRuntime::new_default().unwrap();
/// let connector = load_one_from_path(&rt, Path::new("/tmp/my-plugin")).unwrap();
/// assert!(!connector.source_sha256_hex.is_empty());
/// ```
pub fn load_one_from_path(
    runtime: &PluginRuntime,
    plugin_dir: &Path,
) -> Result<RegisteredConnector, PluginError> {
    let index_js = plugin_dir.join("index.js");
    // Use the directory's basename as the connector label for error
    // messages. Falls back to a placeholder for degenerate paths
    // (trailing `/`, root `/`, etc.) — the validator's own error
    // strings still identify the file.
    let label = plugin_dir.file_name().and_then(|s| s.to_str()).unwrap_or("<unknown>").to_owned();
    let source = read_source_capped(&index_js, PLUGIN_SOURCE_MAX_BYTES, &label)?;
    let source_sha256_hex = sha256_hex(source.as_bytes());
    let metadata = parse_and_validate_metadata(runtime, &label, &source)?;
    Ok(RegisteredConnector {
        name: metadata.name,
        version: metadata.version,
        scopes: metadata.scopes,
        description: metadata.description,
        trust_tier: TrustTier::WarnUser,
        source: Arc::<str>::from(source),
        source_sha256_hex,
    })
}

// -------------------------------------------------------------
// Trusted-file parsing + persistence
// -------------------------------------------------------------

/// Parse `.trusted` into a set of `(name, sha256_hex)` pairs.
///
/// Malformed lines are logged at WARN level with their line
/// number and skipped; a corrupted `.trusted` should never block
/// boot (operators can delete it to reset the allowlist).
/// `#`-comments and blank lines are honored. A missing file is
/// equivalent to an empty set — the expected state on first-ever
/// boot.
fn parse_trusted_file(path: &Path) -> BTreeSet<(String, String)> {
    let raw = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return BTreeSet::new(),
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "failed to read .trusted file; treating as empty allowlist"
            );
            return BTreeSet::new();
        }
    };
    let mut out = BTreeSet::new();
    for (lineno, raw_line) in raw.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut iter = line.split_whitespace();
        let name = match iter.next() {
            Some(n) => n,
            None => continue,
        };
        let hash = match iter.next() {
            Some(h) => h,
            None => {
                tracing::warn!(
                    path = %path.display(),
                    lineno = lineno + 1,
                    "malformed .trusted line (missing sha256); skipping"
                );
                continue;
            }
        };
        // Guard against attacker-controlled control chars in the
        // `name` field — the loader already validates metadata.name
        // against the same charset, but `.trusted` is also operator-
        // editable so defense-in-depth here is free.
        if !is_valid_connector_name(name) {
            tracing::warn!(
                path = %path.display(),
                lineno = lineno + 1,
                "malformed .trusted line (invalid connector name); skipping"
            );
            continue;
        }
        if !is_valid_sha256_hex(hash) {
            tracing::warn!(
                path = %path.display(),
                lineno = lineno + 1,
                "malformed .trusted line (invalid sha256 hex); skipping"
            );
            continue;
        }
        out.insert((name.to_owned(), hash.to_ascii_lowercase()));
    }
    out
}

/// Persist a `(connector, sha256_hex)` pair to `.trusted`
/// atomically via write-temp-rename. Idempotent — if the pair is
/// already present, no write happens.
///
/// File mode on Unix is 0600 (same discipline as vault + agent
/// files). The parent directory must already exist; the caller
/// (typically [`load_all`]) is responsible for ensuring the
/// plugins directory is present.
fn persist_trust_entry(
    trusted_path: &Path,
    name: &str,
    sha256_hex: &str,
) -> Result<(), std::io::Error> {
    // Read existing contents verbatim so operator-written comments
    // and blank lines survive the rewrite.
    let existing = match fs::read_to_string(trusted_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };

    // Fast-path idempotence: parse current entries and bail if
    // the pair is already recorded.
    let already_present =
        existing.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).any(|l| {
            let mut iter = l.split_whitespace();
            matches!(
                (iter.next(), iter.next()),
                (Some(n), Some(h)) if n == name && h.eq_ignore_ascii_case(sha256_hex)
            )
        });
    if already_present {
        return Ok(());
    }

    // Build the new contents — ensure a trailing newline on the
    // prior contents before appending so the new entry is on its
    // own line.
    let mut new_contents = existing;
    if !new_contents.is_empty() && !new_contents.ends_with('\n') {
        new_contents.push('\n');
    }
    new_contents.push_str(name);
    new_contents.push(' ');
    new_contents.push_str(&sha256_hex.to_ascii_lowercase());
    new_contents.push('\n');

    // Atomic write-temp-rename. Temp file name is
    // `.trusted.<pid>.tmp` in the same directory so the rename is
    // cheap (same filesystem guaranteed). Parent must exist.
    let parent = trusted_path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "trusted_path has no parent directory",
        )
    })?;
    if !parent.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "parent of trusted_path does not exist",
        ));
    }
    // Temp name includes pid + a monotonic nanosecond counter so
    // two concurrent calls (e.g. a future reload path) never
    // collide on the same temp path.
    let tmp_path =
        parent.join(format!(".trusted.{}.{}.tmp", std::process::id(), tmp_suffix_counter()));

    let mut open_opts = fs::OpenOptions::new();
    open_opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_opts.mode(0o600);
    }
    {
        let mut f = open_opts.open(&tmp_path)?;
        f.write_all(new_contents.as_bytes())?;
        f.sync_all()?;
    }
    // Best-effort enforce mode (some filesystems ignore
    // `create_new` mode bits).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        // Ignore error — a best-effort tighten; failure to chmod
        // is rare and the file is still safer than a missing
        // allowlist.
        let _ = fs::set_permissions(&tmp_path, perms);
    }
    if let Err(e) = fs::rename(&tmp_path, trusted_path) {
        // Rename failed — try to clean up the temp file so it
        // doesn't accumulate across crashes.
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    // fsync the parent directory so the rename is crash-consistent
    // on Linux (without this, a power loss between rename and
    // journal flush can leave `.trusted` missing). No-op on
    // platforms where dir fsync is not meaningful.
    #[cfg(unix)]
    {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Per-process monotonic counter for temp-file suffix uniqueness.
///
/// Only the combination pid + counter is used; nanoseconds would
/// work too but a counter is deterministic and test-friendly.
fn tmp_suffix_counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

// -------------------------------------------------------------
// Built-in + user-installed load paths
// -------------------------------------------------------------

fn load_builtin(
    runtime: &PluginRuntime,
    builtin: BuiltinConnector,
    trusted_set: &BTreeSet<(String, String)>,
    config: &LoaderConfig,
) -> Result<RegisteredConnector, PluginError> {
    let source = builtin.source;
    let source_sha256_hex = sha256_hex(source.as_bytes());
    let connector = builtin.name.to_owned();

    // Parse + validate metadata. Any failure here is a fatal
    // shipped-binary bug — propagate up to `load_all` which
    // converts it into boot-refusal.
    let metadata = parse_and_validate_metadata(runtime, &connector, source)?;

    // Sanity-check the JS file's `metadata.name` matches the
    // `BuiltinConnector.name` field. A mismatch is a shipped-
    // binary bug.
    if metadata.name != connector {
        return Err(PluginError::MetadataInvalid {
            connector: connector.clone(),
            detail: format!(
                "built-in connector dir name `{connector}` does not match \
                 metadata.name `{}`",
                metadata.name
            ),
        });
    }

    // Built-ins: trust is NOT interactive. Either `auto_trust_builtins`
    // is true (ship-default — always trusted) or the operator has
    // pre-seeded a matching `.trusted` entry. Anything else is a
    // fatal configuration error so a stray keystroke at boot can't
    // silently disable Gmail. The prompt path exists only for
    // user-installed plugins.
    if !config.auto_trust_builtins {
        let pair = (connector.clone(), source_sha256_hex.clone());
        if !trusted_set.contains(&pair) {
            return Err(PluginError::TrustCheckFailed {
                connector: connector.clone(),
                detail: format!(
                    "auto_trust_builtins = false but no matching `.trusted` entry for \
                     built-in `{connector}` (sha256={short}); either set \
                     auto_trust_builtins = true or add `{connector} {hex}` to \
                     {path}",
                    short = short_sha(&source_sha256_hex),
                    hex = source_sha256_hex,
                    path = config.trusted_path.display()
                ),
            });
        }
    }

    Ok(RegisteredConnector {
        name: metadata.name,
        version: metadata.version,
        scopes: metadata.scopes,
        description: metadata.description,
        trust_tier: TrustTier::Builtin,
        source: Arc::<str>::from(source),
        source_sha256_hex,
    })
}

fn load_user_installed(
    runtime: &PluginRuntime,
    dir_name: &str,
    index_js: &Path,
    trusted_set: &BTreeSet<(String, String)>,
    builtin_names: &BTreeSet<String>,
    config: &LoaderConfig,
    prompter: &dyn TrustPromptReader,
) -> Result<Option<RegisteredConnector>, PluginError> {
    if !is_valid_connector_name(dir_name) {
        tracing::warn!(
            connector = %dir_name,
            "user-installed plugin directory name contains unsafe characters; skipping"
        );
        return Ok(None);
    }
    if builtin_names.contains(dir_name) {
        tracing::warn!(
            connector = %dir_name,
            source = %index_js.display(),
            reason = "name collides with builtin",
            "user-installed plugin shadows a built-in connector; skipping (built-in wins)"
        );
        return Ok(None);
    }

    let source = read_source_capped(index_js, PLUGIN_SOURCE_MAX_BYTES, dir_name)?;
    let source_sha256_hex = sha256_hex(source.as_bytes());

    let metadata = parse_and_validate_metadata(runtime, dir_name, &source)?;

    // Defense-in-depth: the metadata.name must also match the
    // directory name. Disallow plugins declaring a different
    // `name` in metadata vs on disk — prevents a user plugin at
    // `~/.agentsso/plugins/harmless/index.js` from registering
    // itself as `google-gmail` and shadowing the built-in via the
    // name-collision check above (which only looks at
    // `dir_name`).
    if metadata.name != dir_name {
        return Err(PluginError::MetadataInvalid {
            connector: dir_name.to_owned(),
            detail: format!(
                "metadata.name `{}` does not match directory name `{dir_name}`",
                metadata.name
            ),
        });
    }

    // Post-metadata-validation: re-check name-collision with
    // built-ins (since a malicious plugin could declare
    // `metadata.name = "google-gmail"` but have a different dir
    // name).
    if builtin_names.contains(&metadata.name) {
        tracing::warn!(
            connector = %dir_name,
            claimed_name = %metadata.name,
            "user-installed plugin metadata.name shadows a built-in; skipping"
        );
        return Ok(None);
    }

    let trusted_pair = (dir_name.to_owned(), source_sha256_hex.clone());
    let is_trusted = trusted_set.contains(&trusted_pair);

    let trust_tier = if is_trusted {
        TrustTier::TrustedUser
    } else if !config.warn_on_first_load {
        // Headless deployment: log + load as WarnUser without
        // asking. The WARN is still emitted so operators see the
        // first-load event in their log pipeline.
        tracing::warn!(
            connector = %dir_name,
            source = %index_js.display(),
            sha256 = %short_sha(&source_sha256_hex),
            "loading user-installed plugin for the first time — review its source at {path}",
            path = index_js.display()
        );
        TrustTier::WarnUser
    } else {
        // Full prompt path.
        tracing::warn!(
            connector = %dir_name,
            source = %index_js.display(),
            sha256 = %short_sha(&source_sha256_hex),
            "loading user-installed plugin for the first time — review its source at {path}",
            path = index_js.display()
        );
        match prompter.prompt(dir_name, index_js, &source_sha256_hex) {
            TrustDecision::Always => {
                if let Err(e) =
                    persist_trust_entry(&config.trusted_path, dir_name, &source_sha256_hex)
                {
                    tracing::warn!(
                        connector = %dir_name,
                        error = %e,
                        "failed to persist trust entry; continuing load as warn-user"
                    );
                    TrustTier::WarnUser
                } else {
                    TrustTier::TrustedUser
                }
            }
            TrustDecision::Once => TrustTier::WarnUser,
            TrustDecision::Never => {
                tracing::warn!(
                    connector = %dir_name,
                    action = "denied",
                    "operator denied first-load prompt; skipping connector"
                );
                return Ok(None);
            }
            TrustDecision::NoPromptAvailable => TrustTier::WarnUser,
        }
    };

    Ok(Some(RegisteredConnector {
        name: metadata.name,
        version: metadata.version,
        scopes: metadata.scopes,
        description: metadata.description,
        trust_tier,
        source: Arc::<str>::from(source),
        source_sha256_hex,
    }))
}

// -------------------------------------------------------------
// Metadata parse + validation
// -------------------------------------------------------------

/// Typed shape of the validated `metadata` export. Distinct from
/// [`RegisteredConnector`] because this struct represents the
/// parse-time shape (no trust_tier, no source, no hash — those
/// are filled in by the caller).
///
/// Story 6.4 promotes this to `pub` so [`validate_plugin_source`]
/// can return it to CLI callers (e.g. `agentsso connectors test`).
/// Fields are `pub` for direct destructuring; the struct remains
/// `#[non_exhaustive]` so adding fields in 1.x is additive.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ValidatedMetadata {
    /// Validated connector name (lowercase alphanumeric + `-` + `_`,
    /// 2..=64 chars, no path-traversal).
    pub name: String,
    /// Validated semver version string.
    pub version: String,
    /// Validated `>=MAJOR.MINOR` API-version requirement.
    pub api_version: String,
    /// Validated scope list (each entry matches `^[a-z][a-z0-9._-]{0,63}$`).
    pub scopes: Vec<String>,
    /// Optional description (≤512 chars).
    pub description: Option<String>,
}

/// Raw shape from `serde_json::from_value` — mirrors the JS
/// object structure exactly, including optional fields and
/// permissive typing (all strings / bools; the post-deserialize
/// validation enforces the real constraints).
#[derive(Debug, Deserialize)]
struct RawMetadata {
    name: Option<String>,
    version: Option<String>,
    #[serde(rename = "apiVersion")]
    api_version: Option<String>,
    scopes: Option<serde_json::Value>,
    description: Option<String>,
}

fn parse_and_validate_metadata(
    runtime: &PluginRuntime,
    connector: &str,
    source: &str,
) -> Result<ValidatedMetadata, PluginError> {
    // Quick sniff: require a top-level `export` statement. The
    // loader rejects CommonJS-shaped plugins with a clear error
    // (per the story spec — CommonJS support is a 1.1 additive).
    // This check runs BEFORE the QuickJS parse so the operator
    // gets the specific NotEsm error rather than a generic syntax
    // error for `module.exports`. The sniff walks each line, skips
    // `//` comment lines and blank lines, and accepts a line that
    // starts with `export` followed by a keyword (`const`, `let`,
    // `var`, `function`, `class`, `default`, `async`) or `{`. This
    // avoids the false-positive on `// export something` and the
    // false-negative on `export\t` / `export{foo}`.
    if !has_top_level_export(source) {
        return Err(PluginError::PluginLoadFailed {
            connector: connector.to_owned(),
            reason: LoadFailureReason::NotEsm,
        });
    }

    let connector_owned = connector.to_owned();
    let raw = runtime.with_context(|ctx| {
        // Capture the original `JSON.stringify` reference BEFORE
        // evaluating the plugin source. The plugin's top-level code
        // can reassign `globalThis.JSON` or `globalThis.JSON.stringify`
        // to a function that returns attacker-chosen JSON text,
        // which would make the serde round-trip read a fake
        // metadata shape while the real `metadata` export is
        // different. Binding the function now — before any plugin
        // code runs — pins the real implementation.
        let globals = ctx.globals();
        let json_obj: rquickjs::Object<'_> = globals.get("JSON").map_err(PluginError::from)?;
        let stringify: rquickjs::Function<'_> =
            json_obj.get("stringify").map_err(PluginError::from)?;

        // Declare + evaluate the source as a module named after
        // the connector. The name is load-time-only (rquickjs uses
        // it for error messages); it does not need to match the
        // eventual registered connector name.
        let module_name = format!("<permitlayer:{connector_owned}>");
        let declared =
            rquickjs::Module::declare(ctx.clone(), module_name.as_str(), source).map_err(|e| {
                // Declare failure indicates either a syntax error
                // or a non-ESM source that the quick-sniff above
                // didn't catch. Map to JsSyntax + wrap in
                // PluginLoadFailed at the outer layer.
                PluginError::PluginLoadFailed {
                    connector: connector_owned.clone(),
                    reason: LoadFailureReason::JsSyntax(e),
                }
            })?;

        let (evaluated, promise) = declared.eval().map_err(|e| PluginError::PluginLoadFailed {
            connector: connector_owned.clone(),
            reason: LoadFailureReason::JsSyntax(e),
        })?;
        // Drive the eval promise to completion so any top-level
        // await / synchronous export side effects land. Our
        // metadata-only placeholders have nothing to await, so
        // this completes in O(microtask-pump).
        let _: () = promise.finish().map_err(|e| PluginError::PluginLoadFailed {
            connector: connector_owned.clone(),
            reason: LoadFailureReason::JsSyntax(e),
        })?;

        // Fetch the `metadata` named export. Missing export -> MissingMetadata.
        let metadata_value: rquickjs::Value<'_> =
            evaluated.get::<_, rquickjs::Value<'_>>("metadata").map_err(|_| {
                PluginError::PluginLoadFailed {
                    connector: connector_owned.clone(),
                    reason: LoadFailureReason::MissingMetadata,
                }
            })?;

        // `JSON.stringify`-then-`serde_json::from_str` round-trip
        // normalizes plugin-controlled JS values to a safe Rust-side
        // shape. Non-serializable values (Symbols, Proxies,
        // functions, Undefined) surface as either `JSON.stringify`
        // returning undefined OR the serde parse failing — both
        // produce `MetadataInvalid`. The `stringify` we invoke here
        // is the pre-eval reference captured above, so a plugin
        // that replaces `globalThis.JSON.stringify` in its top-level
        // code cannot control the JSON text we parse.
        let json_string_value: rquickjs::Value<'_> =
            stringify.call((metadata_value,)).map_err(PluginError::from)?;
        let json_text: String = if let Some(js_str) = json_string_value.as_string() {
            js_str.to_string().map_err(PluginError::from)?
        } else {
            // `JSON.stringify(undefined)` returns `undefined` (not
            // a string). Same posture for values that contain a
            // function or a circular ref that throws during
            // stringify.
            return Err(PluginError::MetadataInvalid {
                connector: connector_owned.clone(),
                detail: "metadata is not a plain serializable object (JSON.stringify returned non-string)"
                    .to_owned(),
            });
        };
        let json_value: serde_json::Value = serde_json::from_str(&json_text).map_err(|e| {
            PluginError::MetadataInvalid {
                connector: connector_owned.clone(),
                detail: format!("metadata round-trip through JSON failed: {e}"),
            }
        })?;
        Ok(json_value)
    })?;

    // Reject if metadata is not an object.
    if !raw.is_object() {
        return Err(PluginError::MetadataInvalid {
            connector: connector.to_owned(),
            detail: "metadata must be an object".to_owned(),
        });
    }

    let parsed: RawMetadata =
        serde_json::from_value(raw).map_err(|e| PluginError::MetadataInvalid {
            connector: connector.to_owned(),
            detail: format!("metadata deserialize failed: {e}"),
        })?;

    validate_metadata(connector, parsed)
}

fn validate_metadata(connector: &str, raw: RawMetadata) -> Result<ValidatedMetadata, PluginError> {
    let name = raw.name.ok_or_else(|| PluginError::MetadataInvalid {
        connector: connector.to_owned(),
        detail: "name is required".to_owned(),
    })?;
    if !is_valid_connector_name(&name) {
        return Err(PluginError::MetadataInvalid {
            connector: connector.to_owned(),
            detail: "name contains unsafe character or violates charset (lowercase alphanumeric + - _ , 2..=64 chars)"
                .to_owned(),
        });
    }

    let version = raw.version.ok_or_else(|| PluginError::MetadataInvalid {
        connector: connector.to_owned(),
        detail: "version is required".to_owned(),
    })?;
    if let Err(e) = semver::Version::parse(&version) {
        return Err(PluginError::MetadataInvalid {
            connector: connector.to_owned(),
            detail: format!("version failed semver parse: {e}"),
        });
    }

    let api_version = raw.api_version.ok_or_else(|| PluginError::MetadataInvalid {
        connector: connector.to_owned(),
        detail: "apiVersion is required".to_owned(),
    })?;
    if !is_valid_api_version(&api_version) {
        return Err(PluginError::MetadataInvalid {
            connector: connector.to_owned(),
            detail: format!("apiVersion `{api_version}` must match `>=MAJOR.MINOR` shape"),
        });
    }

    let scopes_value = raw.scopes.ok_or_else(|| PluginError::MetadataInvalid {
        connector: connector.to_owned(),
        detail: "scopes is required".to_owned(),
    })?;
    let scopes_arr = scopes_value.as_array().ok_or_else(|| PluginError::MetadataInvalid {
        connector: connector.to_owned(),
        detail: "scopes must be an array of strings".to_owned(),
    })?;
    let mut scopes: Vec<String> = Vec::with_capacity(scopes_arr.len());
    for (idx, v) in scopes_arr.iter().enumerate() {
        let s = v.as_str().ok_or_else(|| PluginError::MetadataInvalid {
            connector: connector.to_owned(),
            detail: format!("scopes[{idx}] is not a string"),
        })?;
        if !is_valid_scope(s) {
            return Err(PluginError::MetadataInvalid {
                connector: connector.to_owned(),
                detail: format!(
                    "scopes[{idx}] `{s}` violates charset (^[a-z][a-z0-9._-]{{0,63}}$)"
                ),
            });
        }
        scopes.push(s.to_owned());
    }

    let description = match raw.description {
        None => None,
        Some(s) if s.len() > 512 => {
            return Err(PluginError::MetadataInvalid {
                connector: connector.to_owned(),
                detail: format!("description must be ≤512 chars; got {}", s.len()),
            });
        }
        Some(s) => Some(s),
    };

    Ok(ValidatedMetadata { name, version, api_version, scopes, description })
}

// -------------------------------------------------------------
// Small helpers (charset checks, hashing)
// -------------------------------------------------------------

/// Best-effort check that `source` contains a top-level ES-module
/// `export` statement. Walks each line, skips `//` line comments
/// and blank lines, and returns true on the first line whose
/// stripped prefix starts with `export` followed by a keyword
/// (`const`, `let`, `var`, `function`, `class`, `default`, `async`)
/// or `{`. Does NOT attempt to parse multi-line `/* */` block
/// comments — a pathological source that hides `export` behind a
/// block comment will fall through to the QuickJS declare error,
/// which is still a clear signal.
fn has_top_level_export(source: &str) -> bool {
    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix("export") else {
            continue;
        };
        // The next char after `export` must be whitespace or `{`
        // to be a valid ESM export statement.
        match rest.chars().next() {
            Some(c) if c.is_whitespace() => return true,
            Some('{') => return true,
            _ => continue,
        }
    }
    false
}

fn is_valid_connector_name(s: &str) -> bool {
    let len = s.len();
    if !(2..=64).contains(&len) {
        return false;
    }
    let bytes = s.as_bytes();
    // First char must be lowercase ASCII letter. Digit-leading
    // names are rejected to stay compatible with JS-identifier
    // conventions (SDK doc-gen, future npm-style scoped package
    // names) and to match the `connectors new` scaffolder's
    // stricter-by-default posture.
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    for &b in bytes {
        let ok = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_';
        if !ok {
            return false;
        }
    }
    // Defense-in-depth against path-traversal / log-injection —
    // `is_ascii_lowercase()` already rejects `.`, `/`, `\`,
    // control chars, but assert explicitly so any future charset
    // expansion catches the regression.
    !s.contains("..") && !s.contains('/') && !s.contains('\\')
}

fn is_valid_scope(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    for &b in &bytes[1..] {
        let ok =
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'_';
        if !ok {
            return false;
        }
    }
    true
}

fn is_valid_api_version(s: &str) -> bool {
    // Minimum shape `>=MAJOR.MINOR`: literal `>=`, one or more
    // digits, `.`, one or more digits. Matches the shape the host
    // API's `agentsso.versionMeetsRequirement` accepts at 1.0.0.
    let rest = match s.strip_prefix(">=") {
        Some(r) => r,
        None => return false,
    };
    let dot = match rest.find('.') {
        Some(d) => d,
        None => return false,
    };
    let (major, minor_dot) = rest.split_at(dot);
    let minor = &minor_dot[1..];
    !major.is_empty()
        && !minor.is_empty()
        && major.bytes().all(|b| b.is_ascii_digit())
        && minor.bytes().all(|b| b.is_ascii_digit())
}

fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    // Format as lowercase hex without pulling in the `hex` crate.
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        // `write!` on a String never fails.
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Render the first 12 characters of `full` with an ellipsis.
///
/// Uses `chars().take(12)` rather than byte-slicing so a caller
/// that passes a non-ASCII string does not trigger a char-boundary
/// panic. In practice `full` is always an ASCII sha256 hex string,
/// but the defensive code costs nothing.
fn short_sha(full: &str) -> String {
    let mut out: String = full.chars().take(12).collect();
    if full.chars().count() > 12 {
        out.push('…');
    }
    out
}

/// Returns true if `path` is a symlink. Uses `symlink_metadata` so
/// the check does not follow the link. Any I/O error (path does
/// not exist, permission denied) returns false — the caller is
/// expected to re-check via `is_dir()` / `is_file()` which will
/// surface the concrete error.
fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).map(|m| m.file_type().is_symlink()).unwrap_or(false)
}

/// Read a plugin source file with a byte cap. Reads up to
/// `limit + 1` bytes; if the file contained more than `limit`
/// bytes, returns [`LoadFailureReason::SourceTooLarge`]. Otherwise
/// returns the UTF-8 decoded source.
fn read_source_capped(path: &Path, limit: u64, connector: &str) -> Result<String, PluginError> {
    let file = fs::File::open(path).map_err(|e| PluginError::PluginLoadFailed {
        connector: connector.to_owned(),
        reason: LoadFailureReason::Io(e),
    })?;
    // `take(limit + 1)` so we can detect a file that is exactly
    // `limit + 1` bytes (genuine overflow) vs one that is exactly
    // `limit` bytes (genuine accept).
    let mut buf = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut buf).map_err(|e| {
        PluginError::PluginLoadFailed {
            connector: connector.to_owned(),
            reason: LoadFailureReason::Io(e),
        }
    })?;
    if buf.len() as u64 > limit {
        return Err(PluginError::PluginLoadFailed {
            connector: connector.to_owned(),
            reason: LoadFailureReason::SourceTooLarge { limit },
        });
    }
    String::from_utf8(buf).map_err(|e| PluginError::PluginLoadFailed {
        connector: connector.to_owned(),
        reason: LoadFailureReason::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("plugin source is not valid UTF-8: {e}"),
        )),
    })
}

// -------------------------------------------------------------
// Tests
// -------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn canned_reader_returns_queued_decisions_in_order() {
        let r = CannedTrustPromptReader::new(vec![
            TrustDecision::Always,
            TrustDecision::Once,
            TrustDecision::Never,
        ]);
        assert_eq!(r.prompt("a", Path::new("x"), "0"), TrustDecision::Always);
        assert_eq!(r.prompt("b", Path::new("x"), "0"), TrustDecision::Once);
        assert_eq!(r.prompt("c", Path::new("x"), "0"), TrustDecision::Never);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn canned_reader_exhausts_to_no_prompt_available() {
        // AC #23: empty queue -> NoPromptAvailable (matches TTY
        // reader's EOF / timeout posture). Tests that a misconfigured
        // canned queue doesn't deadlock the loader.
        let r = CannedTrustPromptReader::new(vec![TrustDecision::Always]);
        assert_eq!(r.prompt("a", Path::new("x"), "0"), TrustDecision::Always);
        assert_eq!(r.prompt("b", Path::new("x"), "0"), TrustDecision::NoPromptAvailable);
        assert_eq!(r.prompt("c", Path::new("x"), "0"), TrustDecision::NoPromptAvailable);
    }

    #[test]
    fn no_op_reader_always_returns_no_prompt_available() {
        let r = NoOpTrustPromptReader;
        assert_eq!(r.prompt("a", Path::new("x"), "0"), TrustDecision::NoPromptAvailable);
    }

    #[test]
    fn is_valid_connector_name_rejects_unsafe_chars() {
        // AC #11: path-traversal / log-injection chars.
        assert!(!is_valid_connector_name("../escape"));
        assert!(!is_valid_connector_name("evil/name"));
        assert!(!is_valid_connector_name("back\\slash"));
        assert!(!is_valid_connector_name("with newline\n"));
        assert!(!is_valid_connector_name("with null\0"));
        assert!(!is_valid_connector_name(".hidden"));
        assert!(!is_valid_connector_name("Uppercase"));
        // Digit-leading names are rejected to match the scaffolder
        // and avoid JS-identifier friction downstream.
        assert!(!is_valid_connector_name("2fa-helper"));
        assert!(!is_valid_connector_name("42"));
        // Too short / too long.
        assert!(!is_valid_connector_name(""));
        assert!(!is_valid_connector_name("a"));
        assert!(!is_valid_connector_name(&"a".repeat(65)));
        // Valid shapes.
        assert!(is_valid_connector_name("notion"));
        assert!(is_valid_connector_name("google-gmail"));
        assert!(is_valid_connector_name("my_internal_tool"));
        assert!(is_valid_connector_name("v2-notion-2024"));
        assert!(is_valid_connector_name("ab"));
    }

    #[test]
    fn is_valid_scope_matches_policy_engine_charset() {
        assert!(is_valid_scope("gmail.readonly"));
        assert!(is_valid_scope("gmail.search"));
        assert!(is_valid_scope("http.fetch"));
        assert!(is_valid_scope("a"));
        // Violations.
        assert!(!is_valid_scope(""));
        assert!(!is_valid_scope("Uppercase.scope"));
        assert!(!is_valid_scope(".leading-dot"));
        assert!(!is_valid_scope("with spaces"));
        assert!(!is_valid_scope(&"a".repeat(65)));
    }

    #[test]
    fn is_valid_api_version_accepts_ge_major_minor() {
        assert!(is_valid_api_version(">=1.0"));
        assert!(is_valid_api_version(">=0.9"));
        assert!(is_valid_api_version(">=2.5"));
        // Rejections.
        assert!(!is_valid_api_version("1.0"));
        assert!(!is_valid_api_version(">=1"));
        assert!(!is_valid_api_version(">=v1.0"));
        assert!(!is_valid_api_version(">1.0"));
        assert!(!is_valid_api_version(""));
    }

    #[test]
    fn sha256_hex_roundtrips_through_is_valid() {
        let h = sha256_hex(b"hello world");
        assert_eq!(h.len(), 64);
        assert!(is_valid_sha256_hex(&h));
        // Known value — pins against a future refactor that
        // accidentally hashes the struct repr instead of the
        // bytes.
        assert_eq!(h, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }

    #[test]
    fn is_valid_sha256_hex_rejects_non_hex_and_wrong_length() {
        assert!(!is_valid_sha256_hex(""));
        assert!(!is_valid_sha256_hex("abcd"));
        assert!(!is_valid_sha256_hex(&"x".repeat(64))); // `x` isn't hex
        assert!(is_valid_sha256_hex(&"a".repeat(64)));
        assert!(is_valid_sha256_hex(&"A".repeat(64))); // uppercase accepted
    }

    #[test]
    fn parse_trusted_file_honors_comments_and_blank_lines() {
        // AC #22
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(".trusted");
        let valid_hash = "a".repeat(64);
        fs::write(&p, format!("# header comment\n\nnotion {valid_hash}\n\n# trailing comment\n"))
            .unwrap();
        let set = parse_trusted_file(&p);
        assert_eq!(set.len(), 1);
        assert!(set.contains(&("notion".to_owned(), valid_hash)));
    }

    #[test]
    fn parse_trusted_file_ignores_malformed_lines_not_fatal() {
        // AC #21: garbage lines don't block load.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(".trusted");
        let valid_hash = "b".repeat(64);
        fs::write(
            &p,
            format!(
                "totally invalid syntax\n\
                 notion abc\n\
                 another bogus\n\
                 valid-plugin {valid_hash}\n\
                 Uppercase {valid_hash}\n\
                 valid-name {} \n",
                "not-hex-content".repeat(5)
            ),
        )
        .unwrap();
        let set = parse_trusted_file(&p);
        // Only the one properly-formed entry survives.
        assert_eq!(set.len(), 1);
        assert!(set.contains(&("valid-plugin".to_owned(), valid_hash)));
    }

    #[test]
    fn parse_trusted_file_missing_file_is_empty_set() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("never-written.trusted");
        let set = parse_trusted_file(&p);
        assert!(set.is_empty());
    }

    #[test]
    fn persist_trust_entry_creates_file_with_entry() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(".trusted");
        let hash = "c".repeat(64);
        persist_trust_entry(&p, "notion", &hash).unwrap();
        let contents = fs::read_to_string(&p).unwrap();
        assert_eq!(contents, format!("notion {hash}\n"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "mode must be 0600; got {mode:o}");
        }
    }

    #[test]
    fn persist_trust_entry_is_idempotent_on_same_pair() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(".trusted");
        let hash = "d".repeat(64);
        persist_trust_entry(&p, "notion", &hash).unwrap();
        persist_trust_entry(&p, "notion", &hash).unwrap();
        let contents = fs::read_to_string(&p).unwrap();
        assert_eq!(contents, format!("notion {hash}\n"), "duplicate write must be a no-op");
    }

    #[test]
    fn persist_trust_entry_appends_new_pair_preserving_existing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(".trusted");
        let h1 = "1".repeat(64);
        let h2 = "2".repeat(64);
        persist_trust_entry(&p, "notion", &h1).unwrap();
        persist_trust_entry(&p, "slack", &h2).unwrap();
        let contents = fs::read_to_string(&p).unwrap();
        assert!(contents.contains(&format!("notion {h1}")), "preserved first entry");
        assert!(contents.contains(&format!("slack {h2}")), "appended second entry");
    }

    #[test]
    fn short_sha_truncates_at_12_with_ellipsis() {
        let h = "abcdef0123456789".to_owned() + &"0".repeat(48);
        let s = short_sha(&h);
        assert_eq!(s, "abcdef012345…");
    }

    // ---- Grep-assert that the loader source does NOT reference `with_host_api` ----

    #[test]
    fn loader_source_does_not_reference_with_host_api() {
        // AC #19: load-time sandbox is the Story 6.1 empty-`agentsso`
        // object; host-API registration happens at request-dispatch
        // time (future story). This keeps the loader free of the
        // Story 6.2 AD4 `spawn_blocking` calling-contract. A grep
        // assert pins the invariant against future refactoring.
        //
        // The grep tolerates occurrences inside comments (so the
        // doc-block explaining why we ban the calls is allowed)
        // AND inside test-source self-references (the test
        // function's own name contains the banned token as a
        // substring, as does the string-literal search-term list
        // below). Any NON-comment / NON-test-source production
        // line that references `with_host_api` or
        // `register_host_api` is the regression this test is
        // designed to catch.
        let source = include_str!("loader.rs");
        // `mod tests` start line — everything beyond it is
        // `#[cfg(test)]`-gated and therefore not production code.
        let tests_mod_start = source
            .lines()
            .position(|l| l.trim_start().starts_with("mod tests"))
            .expect("mod tests should exist");
        for forbidden in &["with_host_api", "register_host_api"] {
            for (line_no_zero, line) in source.lines().enumerate() {
                if !line.contains(forbidden) {
                    continue;
                }
                if line_no_zero >= tests_mod_start {
                    continue;
                }
                let trimmed = line.trim_start();
                let is_doc = trimmed.starts_with("//!") || trimmed.starts_with("//");
                assert!(
                    is_doc,
                    "loader.rs line {} references `{forbidden}` outside a comment: {line}",
                    line_no_zero + 1
                );
            }
        }
    }

    #[test]
    fn prune_trusted_removes_entry_for_missing_connector() {
        let dir = tempfile::tempdir().unwrap();
        let trusted_path = dir.path().join(".trusted");

        // Seed .trusted with two entries: "notion" and "gmail".
        // Only "gmail" has a corresponding directory (simulating it
        // being a live connector). "notion" has no dir → stale.
        std::fs::write(
            &trusted_path,
            "gmail abc123def456abc123def456abc123def456abc123def456abc123def456ab\n\
             notion def456abc123def456abc123def456abc123def456abc123def456abc12300\n",
        )
        .unwrap();

        // live_names contains only "gmail".
        let mut live_names = std::collections::HashSet::new();
        live_names.insert("gmail");

        prune_stale_trusted_entries(&trusted_path, &live_names);

        let after = std::fs::read_to_string(&trusted_path).unwrap();
        assert!(after.contains("gmail"), "gmail entry must be kept");
        assert!(!after.contains("notion"), "notion entry must be pruned");
    }

    #[test]
    fn prune_trusted_no_op_when_all_live() {
        let dir = tempfile::tempdir().unwrap();
        let trusted_path = dir.path().join(".trusted");
        std::fs::write(
            &trusted_path,
            "gmail abc123def456abc123def456abc123def456abc123def456abc123def456ab\n",
        )
        .unwrap();

        let mut live_names = std::collections::HashSet::new();
        live_names.insert("gmail");

        prune_stale_trusted_entries(&trusted_path, &live_names);

        let after = std::fs::read_to_string(&trusted_path).unwrap();
        assert!(after.contains("gmail"), "gmail entry must remain");
    }

    #[test]
    fn prune_trusted_no_op_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let trusted_path = dir.path().join(".trusted");
        // File does not exist — should not panic.
        let live_names = std::collections::HashSet::new();
        prune_stale_trusted_entries(&trusted_path, &live_names);
        assert!(!trusted_path.exists(), "no file should be created");
    }
}
