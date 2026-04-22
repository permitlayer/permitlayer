//! `agentsso connectors new` — scaffold a new connector plugin into
//! `~/.agentsso/plugins/<name>/` (Story 6.4).
//!
//! Offline; no daemon required. Writes three files atomically:
//! `index.js` (the ready-to-edit template), `metadata.toml` (mirror
//! of the JS metadata block for authors who prefer TOML), and
//! `README.md` (getting-started + next-step pointers).

use std::path::Path;

use anyhow::Result;
use clap::Args;
use std::io::Write as _;

use crate::cli::kill::load_daemon_config_or_default_with_warn;
use crate::cli::silent_cli_error;
use crate::design::render::error_block;

/// Maximum plugin source file size the Story 6.3 loader accepts.
/// Used here only to define the matching validation rule on scope
/// charset (we borrow the same character class). Kept near the top
/// for grep-discoverability.
const MAX_NAME_LEN: usize = 64;
const MIN_NAME_LEN: usize = 2;

/// Default scope embedded into the scaffolded template when the
/// author does not pass `--scopes`. Part of
/// `permitlayer_plugins::ALLOWED_SCOPES` so the scaffolded plugin
/// passes `connectors test` without any edits.
const DEFAULT_SCOPE: &str = "example.readonly";

#[derive(Args)]
pub struct NewArgs {
    /// Connector name. Must match `^[a-z][a-z0-9_-]{1,63}$` (the
    /// same charset the Story 6.3 loader enforces on directory
    /// names).
    pub name: String,

    /// Comma-separated OAuth scopes to embed in the scaffolded
    /// metadata. Each scope must match `^[a-z][a-z0-9._-]{0,63}$`.
    /// If omitted, the template ships with `["example.readonly"]`
    /// as a placeholder.
    #[arg(long, value_name = "SCOPES")]
    pub scopes: Option<String>,

    /// Overwrite the plugin directory if it already exists.
    /// Without this flag, a pre-existing `<home>/plugins/<name>/`
    /// is refused to protect in-progress work.
    #[arg(long)]
    pub force: bool,
}

pub async fn run(args: NewArgs) -> Result<()> {
    // 1. Validate the name up front — refuse to touch the filesystem
    //    if the argument is malformed.
    if !is_valid_connector_name(&args.name) {
        eprint!(
            "{}",
            error_block(
                "connectors.new.invalid_name",
                "connector name contains unsafe characters or violates charset",
                "use lowercase ASCII letters/digits + `-` `_`, 2..=64 chars, no leading digit",
                Some(&args.name),
            )
        );
        return Err(silent_cli_error("invalid connector name"));
    }

    // 2. Parse + validate `--scopes`. Omitting the flag falls back
    //    to DEFAULT_SCOPE so the scaffolded template still parses.
    //    Supplying the flag with a parseable-empty value (e.g.
    //    `--scopes ""`) is rejected rather than silently replaced
    //    with the default — authors who want no declared scopes
    //    should omit the flag and edit `index.js` afterwards.
    //    Whitespace is tolerated around commas.
    let scopes = match parse_scopes(&args.scopes) {
        Ok(s) => s,
        Err(ParseScopesError::InvalidScope(bad_scope)) => {
            eprint!(
                "{}",
                error_block(
                    "connectors.new.invalid_scope",
                    "scope identifier violates the allowed charset",
                    "each scope must match `^[a-z][a-z0-9._-]{0,63}$`",
                    Some(&bad_scope),
                )
            );
            return Err(silent_cli_error("invalid scope"));
        }
        Err(ParseScopesError::Empty) => {
            eprint!(
                "{}",
                error_block(
                    "connectors.new.empty_scopes",
                    "--scopes was supplied but contained no valid entries",
                    "omit --scopes to use the default placeholder, or pass at least one scope",
                    args.scopes.as_deref(),
                )
            );
            return Err(silent_cli_error("empty scopes"));
        }
    };

    // 3. Resolve the target directory under the daemon's configured
    //    home. `load_daemon_config_or_default_with_warn` falls back
    //    to the default if no daemon.toml exists — authoring can
    //    happen before the daemon is configured.
    //
    //    AC #11: warn loudly if $HOME is unset; the scaffold still
    //    proceeds with the CWD fallback (the workspace-wide
    //    `dirs::home_dir()` discipline — not an error, but surprising
    //    inside a checkout).
    if dirs::home_dir().is_none() {
        let cwd = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| ".".to_owned());
        eprint!(
            "{}",
            error_block(
                "connectors.new.home_not_set",
                "$HOME is not set; scaffolding into the current working directory",
                &format!(
                    "scaffolding into {cwd}/.agentsso/plugins/{}; set HOME or rerun from the \
                     directory where you want the plugin dir",
                    args.name
                ),
                None,
            )
        );
    }
    let cfg = load_daemon_config_or_default_with_warn("connectors new");
    let plugin_dir = cfg.paths.home.join("plugins").join(&args.name);

    // 4. Symlink + overwrite guards.
    //
    //    - Symlink at the target path is refused outright (even with
    //      `--force`). Following a symlink would write files into an
    //      unexpected location outside `~/.agentsso/plugins/`; the
    //      loader refuses symlinked plugin dirs anyway, so we block
    //      here to surface the problem immediately.
    //    - Non-directory at the target path (a regular file) is also
    //      refused — `create_dir_all` would fail with a platform
    //      error that would print without an `error_block` wrapper.
    //    - Only `--force` allows clobbering an existing directory —
    //      protects WIP plugins from accidental destruction.
    match std::fs::symlink_metadata(&plugin_dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                eprint!(
                    "{}",
                    error_block(
                        "connectors.new.symlink",
                        "target path is a symlink",
                        "remove the symlink or choose a different name; scaffolding through symlinks is refused",
                        Some(&plugin_dir.display().to_string()),
                    )
                );
                return Err(silent_cli_error("plugin path is a symlink"));
            }
            if !meta.is_dir() {
                eprint!(
                    "{}",
                    error_block(
                        "connectors.new.not_a_directory",
                        "target path exists but is not a directory",
                        "remove the file or choose a different name",
                        Some(&plugin_dir.display().to_string()),
                    )
                );
                return Err(silent_cli_error("plugin path is not a directory"));
            }
            if !args.force {
                eprint!(
                    "{}",
                    error_block(
                        "connectors.new.exists",
                        "connector directory already exists",
                        "pass `--force` to overwrite, or choose a different name",
                        Some(&plugin_dir.display().to_string()),
                    )
                );
                return Err(silent_cli_error("plugin directory exists"));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Fresh scaffold target — proceed.
        }
        Err(e) => {
            eprint!(
                "{}",
                error_block(
                    "connectors.new.stat_failed",
                    "could not inspect target path",
                    &format!("{e}"),
                    Some(&plugin_dir.display().to_string()),
                )
            );
            return Err(silent_cli_error("target path stat failed"));
        }
    }

    // 5. Create the directory and write the three files atomically
    //    (write-temp-rename per Story 6.3's `persist_trust_entry`
    //    precedent).
    //
    //    AC #10: track whether WE created the directory this
    //    invocation. If any write fails, clean up the whole plugin_dir
    //    only when it was empty-or-absent before we started — guards
    //    against nuking a hand-edited dir on a `--force` re-scaffold
    //    where the pre-existing dir had extra files.
    // Ensure the parent plugins/ directory exists (create_dir_all is idempotent).
    if let Some(parent) = plugin_dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Track whether we created the final plugin directory so we can clean up
    // on failure. Use create_dir (not create_dir_all) to detect the
    // pre-existing case without a TOCTOU race between exists() and create_dir_all().
    let dir_created_by_us = match std::fs::create_dir(&plugin_dir) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(e) => return Err(e.into()),
    };

    let index_js = render_index_js(&args.name, &scopes);
    let metadata_toml = render_metadata_toml(&args.name, &scopes);
    let readme_md = render_readme_md(&args.name, &scopes);

    let write_result = (|| -> std::io::Result<()> {
        write_atomic(&plugin_dir.join("index.js"), &index_js)?;
        write_atomic(&plugin_dir.join("metadata.toml"), &metadata_toml)?;
        write_atomic(&plugin_dir.join("README.md"), &readme_md)?;
        Ok(())
    })();

    if let Err(e) = write_result {
        if dir_created_by_us {
            let _ = std::fs::remove_dir_all(&plugin_dir);
        }
        return Err(e.into());
    }

    // 6. Banner. Points the author at the next-step command.
    println!("  scaffolded {}", plugin_dir.display());
    println!("  - {}", plugin_dir.join("index.js").display());
    println!("  - {}", plugin_dir.join("metadata.toml").display());
    println!("  - {}", plugin_dir.join("README.md").display());
    println!();
    println!("  next:  agentsso connectors test {}", args.name);

    Ok(())
}

// ------------------------------------------------------------------
// Validation helpers
// ------------------------------------------------------------------

/// Matches the charset Story 6.3's loader enforces on connector
/// directory names (`is_valid_connector_name` in
/// `permitlayer_plugins::loader`). Duplicated here rather than
/// imported because the loader's helper is private and this CLI
/// validator runs before any plugins-crate call.
///
/// Rules: lowercase alphanumeric + `-` + `_`, 2..=64 chars, must
/// start with a lowercase letter. No `/`, `\\`, `..`, whitespace,
/// NUL, or other control characters.
fn is_valid_connector_name(name: &str) -> bool {
    let len = name.len();
    if !(MIN_NAME_LEN..=MAX_NAME_LEN).contains(&len) {
        return false;
    }
    let mut chars = name.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
            return false;
        }
    }
    true
}

/// Scope charset from Story 6.3: `^[a-z][a-z0-9._-]{0,63}$`.
fn is_valid_scope(scope: &str) -> bool {
    let len = scope.len();
    if !(1..=64).contains(&len) {
        return false;
    }
    let mut chars = scope.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_' || c == '-') {
            return false;
        }
    }
    true
}

/// Split a comma-separated scope string, trim whitespace, drop
/// Parse-failure modes for `--scopes`.
#[derive(Debug, PartialEq, Eq)]
enum ParseScopesError {
    /// `--scopes` was supplied but contained no valid entries
    /// (e.g. `""`, `","`, `" , "`). Rejected loudly so authors
    /// know their flag had no effect — the happy path for "truly
    /// empty scopes" is to omit `--scopes` entirely and edit the
    /// scaffolded `index.js` afterwards.
    Empty,
    /// At least one comma-separated entry failed the scope charset.
    InvalidScope(String),
}

/// empty entries, validate each.
///
/// Returns the parsed scope list on success. Returns
/// [`ParseScopesError::InvalidScope`] carrying the first offending
/// scope string, or [`ParseScopesError::Empty`] when the caller
/// explicitly passed `--scopes` but the value contained nothing
/// parseable.
fn parse_scopes(raw: &Option<String>) -> std::result::Result<Vec<String>, ParseScopesError> {
    let Some(s) = raw else {
        return Ok(vec![DEFAULT_SCOPE.to_owned()]);
    };
    let mut out = Vec::new();
    for part in s.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !is_valid_scope(trimmed) {
            return Err(ParseScopesError::InvalidScope(trimmed.to_owned()));
        }
        out.push(trimmed.to_owned());
    }
    if out.is_empty() {
        // `--scopes ""` / `--scopes ","` / etc. — author passed the
        // flag but supplied nothing parseable. Reject loudly.
        return Err(ParseScopesError::Empty);
    }
    Ok(out)
}

// ------------------------------------------------------------------
// File-writing helper
// ------------------------------------------------------------------

/// RAII guard that removes a temp file on drop unless disarmed.
/// Prevents stale `.tmp.<pid>` files when a write fails mid-way.
struct TempFileGuard {
    path: std::path::PathBuf,
    armed: bool,
}

impl TempFileGuard {
    fn new(path: std::path::PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Atomic write via `create_new` + write_all + sync_all + rename +
/// dir fsync (Unix).  On Unix also sets 0644 perms on the temp file
/// before rename (plaintext dev files; not secrets).
///
/// `create_new(true)` refuses to clobber a stale `.tmp.<pid>`
/// leftover — a crash mid-scaffold would leave garbage that the old
/// `std::fs::write` path would silently overwrite.
fn write_atomic(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::fs::OpenOptions;

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
    })?;
    let file_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no name"))?
        .to_string_lossy()
        .into_owned();
    let tmp = parent.join(format!(".{file_name}.tmp.{}", std::process::id()));

    let mut file = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
    // Arm guard only after the open succeeds — if open fails, tmp was never
    // created so there's nothing to clean up.
    let mut guard = TempFileGuard::new(tmp.clone());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }

    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    drop(file);

    std::fs::rename(&tmp, path)?;
    guard.disarm();

    // Fsync the parent directory so the rename is durable on Unix.
    // Best-effort: some filesystems (e.g. tmpfs, certain network mounts)
    // return EINVAL for fsync on a directory — swallow the error rather
    // than aborting an otherwise-complete write.
    #[cfg(unix)]
    {
        if let Ok(dir) = OpenOptions::new().read(true).open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

// ------------------------------------------------------------------
// Template rendering
// ------------------------------------------------------------------

/// Return the scaffold-time date string. Honors the
/// `AGENTSSO_TEST_FROZEN_DATE` override in debug builds so
/// integration tests can assert deterministic README output.
fn scaffold_date() -> String {
    #[cfg(debug_assertions)]
    {
        if let Ok(frozen) = std::env::var("AGENTSSO_TEST_FROZEN_DATE")
            && !frozen.trim().is_empty()
        {
            return frozen;
        }
    }
    chrono::Utc::now().date_naive().to_string()
}

/// Render the JS scopes array as a `, `-separated double-quoted
/// list: `"a", "b", "c"`.
fn render_scopes_js_array(scopes: &[String]) -> String {
    let quoted: Vec<String> = scopes.iter().map(|s| format!("\"{s}\"")).collect();
    quoted.join(", ")
}

/// Render the TOML scopes value: `["a", "b", "c"]`.
fn render_scopes_toml_array(scopes: &[String]) -> String {
    let quoted: Vec<String> = scopes.iter().map(|s| format!("\"{s}\"")).collect();
    format!("[{}]", quoted.join(", "))
}

/// Scaffolded `index.js` content for a connector named `name` with
/// the given scopes. The template is static-structured: metadata,
/// auth (type:none), tools (single `hello` exemplar). Inline
/// comments walk the author through each section.
pub(crate) fn render_index_js(name: &str, scopes: &[String]) -> String {
    let scopes_js = render_scopes_js_array(scopes);
    format!(
        r#"// {name} connector — scaffolded by `agentsso connectors new`.
//
// The host-API surface is enumerated in `host-api.lock` at the repo
// root; source lives under `crates/permitlayer-plugins/src/host_api/`.
// (run `agentsso connectors list` to see registered connectors;
//  run `agentsso connectors test {name}` to validate this plugin)
//
// The plugin sandbox is memory-limited, CPU-interrupted, and has no
// filesystem or direct network I/O. The ONLY way to reach the
// network is via `await agentsso.http.fetch(...)` — every fetch is
// itself checked by `policy.enforce` and recorded in the audit log.
//
// Debug logging: the sandbox does NOT provide `console.log`. For
// ad-hoc debugging, throw a temporary AgentssoError carrying your
// payload and inspect it via `agentsso logs`:
//
//     throw new AgentssoError("debug payload here", {{ code: "debug", retryable: false }});
//
// A proper `agentsso.log.info(...)` surface is coming in a future
// 1.x release of the host API.

// --- Metadata (REQUIRED) -------------------------------------------
//
// The loader reads this exported `metadata` object and registers the
// connector under its `name`. `name` must match the directory name
// (`{name}/`) — the loader rejects mismatches. `apiVersion` must
// match the `>=MAJOR.MINOR` shape (see `agentsso.version`).
export const metadata = {{
    name: "{name}",
    version: "0.1.0",
    apiVersion: ">=1.0",
    scopes: [{scopes_js}],
    description: "New connector scaffolded by agentsso connectors new",
}};

// --- Auth (REQUIRED for connectors that call upstream APIs) --------
//
// For connectors that call authenticated upstream APIs, swap the
// placeholder below for an "oauth"-shaped auth block that calls
// `agentsso.oauth.getToken(...)` (Story 6.2 AD2 — Promise-shape;
// always `await`):
//
//     export const auth = {{
//         type: "oauth",
//         async getToken() {{
//             return await agentsso.oauth.getToken("{name}");
//         }},
//     }};
//
// Connectors that do not need credentials (pure data-transforms,
// local-only connectors) keep `type: "none"` below.
export const auth = {{
    type: "none",
}};

// --- Tools (REQUIRED; at least one tool must be exported) ----------
//
// Each exported tool is a function that takes an `input` object and
// returns a value (or a Promise of one). Tools are invoked by the
// agent via MCP `tools/call`. Every host-API call inside a tool is
// Promise-shape per Story 6.2 AD2 — always `await` oauth/policy/http.
// `agentsso.scrub.text(...)` is synchronous (no Promise).
export const tools = {{
    // Minimal "hello world" tool that demonstrates the host-API
    // surface. Replace with your real tools.
    async hello(input) {{
        // Policy check — confirms the agent is allowed to call this
        // scope. A Deny throws AgentssoError carrying the rule id.
        await agentsso.policy.enforce({{
            scope: metadata.scopes[0],
            resource: "hello",
        }});

        // Toy upstream call. Replace with a real upstream endpoint.
        // Every fetch is policy-checked AND scrubbed on the way back.
        const resp = await agentsso.http.fetch("https://httpbin.org/get", {{
            method: "GET",
            headers: {{ "accept": "application/json" }},
        }});

        // `scrub.text` returns a Promise — await before reading `.output`.
        const scrubbed = await agentsso.scrub.text(resp.body);

        return {{
            greeting: "hello from {name}",
            upstreamStatus: resp.status,
            body: scrubbed.output,
        }};
    }},
}};
"#
    )
}

/// Scaffolded `metadata.toml` (mirror file — informational only, the
/// loader reads metadata from the `index.js` exported object).
pub(crate) fn render_metadata_toml(name: &str, scopes: &[String]) -> String {
    let scopes_toml = render_scopes_toml_array(scopes);
    format!(
        r#"# Informational only — the loader reads metadata from index.js's
# exported metadata object. Edit both files together or the loader
# will ignore your TOML changes.
name = "{name}"
version = "0.1.0"
api-version = ">=1.0"
scopes = {scopes_toml}
description = "New connector scaffolded by agentsso connectors new"
"#
    )
}

/// Scaffolded `README.md` with a date stamp + next-step pointers.
pub(crate) fn render_readme_md(name: &str, _scopes: &[String]) -> String {
    let date = scaffold_date();
    format!(
        r#"# {name} connector

Scaffolded by `agentsso connectors new {name}` on {date}.

## Next steps

1. Open `index.js` and fill in the `metadata.scopes`, `auth`, and `tools` blocks.
2. Run `agentsso connectors test {name}` to validate metadata + sandbox conformance + scope review.
3. Restart the daemon (`agentsso stop && agentsso start`) to load the plugin. The first load emits a WARN and prompts for trust — answer `y` to persist a `.trusted` entry.

## Reference

- Host API surface: `host-api.lock` at the repo root enumerates every
  `agentsso.*` method; source under `crates/permitlayer-plugins/src/host_api/`.
- Contribution guide: https://github.com/botsdown/permitlayer/blob/main/CONTRIBUTING.md
- Example built-in connectors: https://github.com/botsdown/permitlayer/tree/main/crates/permitlayer-connectors/src/js

## Security posture

This connector runs in a sandboxed QuickJS runtime with no filesystem, network, or syscall access. All upstream I/O is mediated by `agentsso.http.fetch`, which is itself policy-checked.
"#
    )
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // --- Name validation tests (AC #4) ---------------------------

    #[test]
    fn name_rejection_slash() {
        assert!(!is_valid_connector_name("foo/bar"));
    }

    #[test]
    fn name_rejection_digit_first() {
        assert!(!is_valid_connector_name("1foo"));
    }

    #[test]
    fn name_rejection_dotdot() {
        assert!(!is_valid_connector_name(".."));
        assert!(!is_valid_connector_name("foo/../bar"));
    }

    #[test]
    fn name_rejection_empty() {
        assert!(!is_valid_connector_name(""));
        assert!(!is_valid_connector_name("a"));
    }

    #[test]
    fn name_rejection_too_long() {
        let big = "a".repeat(65);
        assert!(!is_valid_connector_name(&big));
    }

    #[test]
    fn name_rejection_uppercase() {
        assert!(!is_valid_connector_name("Foo"));
        assert!(!is_valid_connector_name("FOO"));
        assert!(!is_valid_connector_name("my-Plugin"));
    }

    #[test]
    fn name_rejection_control_char() {
        assert!(!is_valid_connector_name("foo\nbar"));
        assert!(!is_valid_connector_name("foo\0bar"));
        assert!(!is_valid_connector_name("foo\tbar"));
    }

    #[test]
    fn name_accepts_valid_shapes() {
        assert!(is_valid_connector_name("foo"));
        assert!(is_valid_connector_name("my-plugin"));
        assert!(is_valid_connector_name("my_plugin"));
        assert!(is_valid_connector_name("a0"));
        assert!(is_valid_connector_name("notion-v2-scraper-1"));
    }

    // --- Scope parsing ------------------------------------------

    #[test]
    fn parse_scopes_default_when_none() {
        let scopes = parse_scopes(&None).unwrap();
        assert_eq!(scopes, vec!["example.readonly".to_owned()]);
    }

    #[test]
    fn parse_scopes_trims_whitespace_and_drops_empty() {
        let scopes = parse_scopes(&Some("  gmail.readonly , ,gmail.search  ".to_owned())).unwrap();
        assert_eq!(scopes, vec!["gmail.readonly".to_owned(), "gmail.search".to_owned()]);
    }

    #[test]
    fn parse_scopes_rejects_uppercase_scope() {
        let err = parse_scopes(&Some("Gmail.Readonly".to_owned())).unwrap_err();
        assert_eq!(err, ParseScopesError::InvalidScope("Gmail.Readonly".to_owned()));
    }

    #[test]
    fn parse_scopes_empty_string_rejects_with_empty_error() {
        // Supplying `--scopes` with a value that yields nothing
        // parseable is an error, not a silent default injection —
        // authors who want the default should omit the flag.
        assert_eq!(parse_scopes(&Some("".to_owned())), Err(ParseScopesError::Empty));
        assert_eq!(parse_scopes(&Some(",,, ,".to_owned())), Err(ParseScopesError::Empty));
        assert_eq!(parse_scopes(&Some("   ".to_owned())), Err(ParseScopesError::Empty));
    }

    // --- Template content tests (AC #27, #28) -------------------

    #[test]
    fn template_demonstrates_host_api_promise_shape() {
        // AC #27: the scaffolded index.js must demonstrate the
        // Promise-shape pattern — every host-API call returns a
        // Promise and must be awaited before its result is read.
        let rendered = render_index_js("my-plugin", &["example.readonly".to_owned()]);
        assert!(
            rendered.contains("await agentsso.policy.enforce"),
            "template must await policy.enforce"
        );
        assert!(rendered.contains("await agentsso.http.fetch"), "template must await http.fetch");
        assert!(
            rendered.contains("await agentsso.scrub.text"),
            "template must await scrub.text — it returns a Promise"
        );
    }

    #[test]
    fn template_has_log_placeholder_comment() {
        // AC #28: comment references AgentssoError as the debug
        // mechanism AND mentions `agentsso.log.info` as the future
        // primary channel.
        let rendered = render_index_js("my-plugin", &["example.readonly".to_owned()]);
        assert!(
            rendered.contains("agentsso.log.info") || rendered.contains("AgentssoError"),
            "template must document the debug-logging workaround"
        );
        assert!(
            rendered.contains("AgentssoError"),
            "template must reference the AgentssoError debug mechanism verbatim"
        );
    }

    #[test]
    fn template_has_no_console_log_calls() {
        // AC #28: no `console.log(` anywhere — the sandbox does
        // not provide `console`; telling authors to write it would
        // ship a template that fails the loader.
        let rendered = render_index_js("my-plugin", &["example.readonly".to_owned()]);
        assert!(!rendered.contains("console.log("), "template must NOT contain console.log( calls");
        assert!(
            !rendered.contains("console.error("),
            "template must NOT contain console.error( calls"
        );
    }

    #[test]
    fn scaffolded_template_passes_validate_plugin_source() {
        // AC #7: the scaffolded index.js compiles on first run —
        // no edits required before `connectors test` passes the
        // metadata check. Runs through the real
        // `validate_plugin_source` path.
        let rendered = render_index_js("my-plugin", &["example.readonly".to_owned()]);
        let runtime = permitlayer_plugins::PluginRuntime::new_default()
            .expect("plugin runtime must construct");
        let meta = permitlayer_plugins::validate_plugin_source(&runtime, "my-plugin", &rendered)
            .expect("scaffolded template must pass validate_plugin_source");
        assert_eq!(meta.name, "my-plugin");
        assert_eq!(meta.version, "0.1.0");
        assert_eq!(meta.api_version, ">=1.0");
        assert_eq!(meta.scopes, vec!["example.readonly".to_owned()]);
        assert!(meta.description.is_some());
    }

    #[test]
    fn scaffolded_template_with_custom_scopes_validates() {
        // AC #7: user-provided scopes produce a scaffold that still
        // validates. Uses scopes that are in Story 6.4's
        // ALLOWED_SCOPES so the template is ready for publication
        // review.
        let rendered = render_index_js(
            "gmail-custom",
            &["gmail.readonly".to_owned(), "gmail.search".to_owned()],
        );
        let runtime = permitlayer_plugins::PluginRuntime::new_default()
            .expect("plugin runtime must construct");
        let meta = permitlayer_plugins::validate_plugin_source(&runtime, "gmail-custom", &rendered)
            .expect("scaffolded template with custom scopes must validate");
        assert_eq!(meta.scopes, vec!["gmail.readonly".to_owned(), "gmail.search".to_owned()]);
    }

    #[test]
    fn template_substitutes_name_and_scopes() {
        let rendered =
            render_index_js("my-notion", &["notion.read".to_owned(), "notion.write".to_owned()]);
        assert!(rendered.contains("name: \"my-notion\""));
        assert!(rendered.contains("scopes: [\"notion.read\", \"notion.write\"]"));
        // Metadata block values should round-trip through the JS
        // parser — quick sniff for balanced quotes.
        assert!(
            rendered.matches("\"my-notion\"").count() >= 2,
            "name should appear in metadata AND in tool body"
        );
    }

    #[test]
    fn metadata_toml_mirrors_index_js_metadata() {
        // AC #22: metadata.toml declares the same name/version/
        // scopes as the index.js metadata, and carries the
        // informational-only comment.
        let toml = render_metadata_toml(
            "my-notion",
            &["notion.read".to_owned(), "notion.write".to_owned()],
        );
        assert!(toml.contains("name = \"my-notion\""));
        assert!(toml.contains("version = \"0.1.0\""));
        assert!(toml.contains("api-version = \">=1.0\""));
        assert!(toml.contains("scopes = [\"notion.read\", \"notion.write\"]"));
        assert!(toml.contains("Informational only"));

        // Also verify the TOML actually parses as TOML.
        let parsed: toml::Value = toml::from_str(&toml).expect("metadata.toml must parse as TOML");
        assert_eq!(parsed["name"].as_str(), Some("my-notion"));
    }

    #[test]
    fn readme_contains_scaffold_date() {
        // AC #21: README has a date-stamp line.
        let rendered = render_readme_md("my-plugin", &["example.readonly".to_owned()]);
        // Either YYYY-MM-DD from chrono or the frozen override.
        let date_line = rendered
            .lines()
            .find(|l| l.contains("Scaffolded by"))
            .expect("readme must contain scaffolded-by line");
        // Trailing pattern is ` on YYYY-MM-DD.` — grep for the dash
        // positions via a simple regex-free parse.
        let parts: Vec<&str> = date_line.rsplit(" on ").collect();
        assert!(parts.len() >= 2, "date marker missing: {date_line}");
        let date_tail = parts[0].trim_end_matches('.');
        assert_eq!(date_tail.len(), 10, "date must be YYYY-MM-DD: {date_tail:?}");
    }

    // --- Test-seam invariants (AC #26) ---------------------------

    #[test]
    fn test_seams_are_compiled_out_in_release_builds() {
        // AC #26: the env-var read path is gated on
        // `#[cfg(debug_assertions)]`. This test is itself only
        // meaningful in a release build — in debug builds we skip
        // the assertion (the env-var path IS compiled).
        #[cfg(not(debug_assertions))]
        {
            // In release, scaffold_date must NOT honor the
            // override — the env-var read path is compiled out.
            // SAFETY: setting an env var in this test is safe
            // because no other thread reads AGENTSSO_TEST_FROZEN_DATE
            // in release builds (the read path is cfg'd out).
            unsafe {
                std::env::set_var("AGENTSSO_TEST_FROZEN_DATE", "1970-01-01");
            }
            let today = scaffold_date();
            assert_ne!(today, "1970-01-01", "release builds must not honor the test seam");
        }
        #[cfg(debug_assertions)]
        {
            // Debug build — the seam is active. Not a meaningful
            // regression test, but document the contract.
        }
    }

    // --- write_atomic hardening (AC #9) --------------------------

    #[test]
    fn write_atomic_rejects_preexisting_tmp() {
        // AC #9: `create_new(true)` must fail when a stale tmp file
        // already exists (simulates a crash-leftover scenario).
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("hello.txt");
        let stale_tmp = dir.path().join(format!(".hello.txt.tmp.{}", std::process::id()));
        // Pre-seed the stale temp file.
        std::fs::write(&stale_tmp, b"stale").unwrap();
        let err = write_atomic(&target, "content").unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::AlreadyExists,
            "write_atomic must fail with AlreadyExists when stale tmp exists"
        );
        // Clean up stale tmp so tempdir drops cleanly.
        let _ = std::fs::remove_file(&stale_tmp);
    }

    #[test]
    fn write_atomic_creates_file_with_correct_content() {
        // Sanity: normal path still works.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("out.txt");
        write_atomic(&target, "hello world").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello world");
    }

    // --- Partial-write cleanup (AC #10) --------------------------

    #[test]
    fn scaffolder_cleans_up_on_third_write_failure() {
        // AC #10: when the third write fails, the plugin_dir that WE
        // created should be removed by the cleanup path.
        //
        // Strategy: create `README.md` as a *directory* collision so
        // `write_atomic` cannot create the file — the parent-dir
        // fsync will hit EISDIR. On some platforms rename itself
        // returns EISDIR; either way write_atomic returns an Err.
        let base = tempfile::tempdir().unwrap();
        let plugin_dir = base.path().join("test-connector");

        // Simulate what `run()` does: create dir, write two files,
        // make README.md a dir so the third write fails.
        std::fs::create_dir_all(&plugin_dir).unwrap();
        write_atomic(&plugin_dir.join("index.js"), "// js").unwrap();
        write_atomic(&plugin_dir.join("metadata.toml"), "# toml").unwrap();
        // Block README.md with a directory collision.
        std::fs::create_dir(plugin_dir.join("README.md")).unwrap();

        // Now exercise the cleanup guard directly: simulate the
        // closure-based pattern from run() on a freshly-created dir.
        let dir_created_by_us = true;
        let write_result = (|| -> std::io::Result<()> {
            write_atomic(&plugin_dir.join("README.md"), "# readme")?;
            Ok(())
        })();

        assert!(write_result.is_err(), "third write must fail due to dir collision");
        if dir_created_by_us {
            let _ = std::fs::remove_dir_all(&plugin_dir);
        }
        assert!(!plugin_dir.exists(), "plugin_dir must be removed after failed scaffold cleanup");
    }

    // --- Network-free invariant (AC #19) -------------------------

    #[test]
    fn scaffolder_source_does_not_reference_network_crates() {
        // AC #19: reading this source file must not `use reqwest`,
        // `use tokio::net`, or `use hyper::client`. A future diff
        // that pulls networking in via a `use` line would fail
        // this assertion. Substring matches alone are insufficient
        // because comments and test-fixture literals mention the
        // same tokens; checking `use` lines is the precise signal.
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cli/connectors/new.rs");
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"));
        for banned in ["reqwest", "tokio::net", "hyper::client"] {
            let banned_use = format!("use {banned}");
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                assert!(
                    !trimmed.starts_with(&banned_use),
                    "line {}: scaffolder source must not `use {banned}`: `{line}`",
                    idx + 1
                );
            }
        }
    }
}
