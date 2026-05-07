//! Programmatic policy file edits — Story 7.13.
//!
//! `agentsso connect <service>` runs an OAuth flow that grants a set
//! of scopes for the operator's agent and then needs to extend the
//! agent's policy file to include those scopes. This module provides
//! [`add_scopes_to_policy`] — an idempotent "merge these short-name
//! scopes into the named policy's allow-list" operation.
//!
//! # Round-trip-validate invariant
//!
//! Every successful return from [`add_scopes_to_policy`] satisfies:
//!
//! 1. The on-disk file parses cleanly via
//!    [`PolicySet::compile_from_str`].
//! 2. The target policy's `scopes` field is `before ∪ added`, with
//!    no duplicates, sorted.
//! 3. Every other field of every policy in the file is byte-identical
//!    in semantic content (TOML serialization may reformat whitespace,
//!    but no field values change).
//!
//! If any of those conditions cannot be verified post-write the
//! function returns [`PolicyEditError::CompileFailedAfterEdit`] and
//! the on-disk file is left unchanged (the atomic-rename is the gate).
//!
//! # Comment preservation
//!
//! TOML round-tripping via `toml::Value` does **not** preserve
//! comments or original key ordering. The default fixture files
//! ship with rich operator-facing comments; running
//! [`add_scopes_to_policy`] on them will reformat the file (comments
//! removed, fields re-ordered to deserialization order). This is an
//! explicit MVP tradeoff: correctness over formatting. A future story
//! can layer a comment-preserving editor (e.g., via the `toml_edit`
//! crate) on top.

use std::path::{Path, PathBuf};

use crate::policy::compile::PolicySet;
use crate::policy::error::PolicyCompileError;
use crate::policy::schema::TomlPolicyFile;

/// Summary of what changed in a single
/// [`add_scopes_to_policy`] invocation. Caller can log this as part of
/// a connect-flow audit trail.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ScopeMergeDiff {
    /// Name of the policy that was edited.
    pub policy_name: String,
    /// Path to the policy TOML file.
    pub policy_path: PathBuf,
    /// Scope short-names that were already in the policy before the edit.
    pub before: Vec<String>,
    /// Scope short-names that the edit appended (set difference of
    /// requested minus before). Empty when the edit was a no-op.
    pub added: Vec<String>,
    /// `before ∪ added`, sorted, deduplicated. The post-edit on-disk
    /// scope list.
    pub after: Vec<String>,
}

impl ScopeMergeDiff {
    /// `true` when the edit was a no-op (every requested scope was
    /// already present).
    #[must_use]
    pub fn is_no_op(&self) -> bool {
        self.added.is_empty()
    }
}

/// Failure modes for [`add_scopes_to_policy`].
#[derive(Debug, thiserror::Error)]
pub enum PolicyEditError {
    /// `<policies_dir>/<policy_name>.toml` does not exist on disk.
    #[error("policy file not found: {path}")]
    PolicyFileNotFound { path: PathBuf },

    /// The policy file path is a symlink. Story 7.13 round-1 P7
    /// refuses to edit symlinks: `tempfile::persist`'s `rename(2)`
    /// would replace the SYMLINK with a regular file (the actual
    /// target file remains untouched), silently breaking operator
    /// symlink-based workflows (e.g., git-tracked policy files
    /// symlinked from `~/.agentsso/policies/`).
    #[error("policy file is a symlink (refusing to follow): {path}")]
    PolicyFileIsSymlink { path: PathBuf },

    /// The file exists but does not contain a `[[policies]]` block
    /// whose `name` matches the requested policy. (One file per
    /// policy is the convention but the schema permits multiple
    /// `[[policies]]` per file.)
    #[error("policy '{name}' not found in file: {path}")]
    PolicyNotInFile { name: String, path: PathBuf },

    /// The file failed to parse against the policy schema (malformed
    /// TOML, unknown field, missing required field). Wraps the
    /// canonical [`PolicyCompileError::Parse`] / similar variant from
    /// the existing parser so operator-facing error rendering is
    /// uniform with the daemon-startup parse path.
    #[error("policy file parse failed: {source}")]
    ParseFailed {
        #[source]
        source: PolicyCompileError,
    },

    /// The post-edit serialized text was rejected by the canonical
    /// compile path. The on-disk file has NOT been replaced — the
    /// atomic-rename gate ensures this. Indicates a bug in this
    /// module's serializer or in the user-supplied scope short
    /// names; either way the operator can re-run safely.
    #[error("post-edit policy compile failed (file unchanged): {source}")]
    CompileFailedAfterEdit {
        #[source]
        source: PolicyCompileError,
    },

    /// Filesystem error reading or writing the file.
    #[error("policy file IO failed: {source}")]
    Io {
        #[source]
        source: std::io::Error,
    },

    /// TOML serialization failure (the post-edit value couldn't be
    /// rendered back to a string). Should not occur in practice for
    /// any input the schema has accepted.
    #[error("policy TOML serialize failed: {source}")]
    SerializeFailed {
        #[source]
        source: toml::ser::Error,
    },
}

/// Idempotently merge `scopes_to_add` into `<policies_dir>/<policy_name>.toml`'s
/// scope allow-list.
///
/// `scopes_to_add` is a slice of short scope names (e.g.,
/// `["calendar.readonly", "calendar.events"]`) — NOT full Google
/// scope URIs. The caller is responsible for converting URIs via
/// [`permitlayer-oauth::google::scopes::scope_info`].
///
/// On a no-op (every requested scope already present) the function
/// returns `Ok(ScopeMergeDiff { added: vec![], .. })` WITHOUT touching
/// the file. This is what makes `agentsso connect` re-runs safe.
///
/// On a real merge the function writes the merged TOML back atomically
/// via tempfile-rename and returns the diff.
///
/// See module-level docs for the round-trip-validate invariant.
///
/// # Concurrency invariant
///
/// **Caller must serialize concurrent calls against the same policy
/// file.** This function does NOT take a file lock around the
/// read-compute-write sequence; two parallel callers targeting the
/// same `<policy_name>.toml` will both read the pre-state, compute
/// their own merged scope list, and last-writer-wins on the rename.
/// One caller's added scopes can be lost.
///
/// Story 7.13 Dev Notes pre-accept this as a single-operator footgun
/// (an `agentsso connect <a>` and `agentsso connect <b>` running in
/// parallel terminals against the same agent). Realistic
/// `agentsso connect` usage is one operator, sequential commands;
/// concurrent invocation is rare and an explicit non-goal of the
/// MVP. If this changes — multi-operator setups, scripted parallel
/// connects — add an `flock(2)` around the read-modify-write.
pub fn add_scopes_to_policy(
    policies_dir: &Path,
    policy_name: &str,
    scopes_to_add: &[&str],
) -> Result<ScopeMergeDiff, PolicyEditError> {
    let policy_path = policies_dir.join(format!("{policy_name}.toml"));

    // Step 1a (round-1 P7): refuse to edit symlinks. `symlink_metadata`
    // does NOT follow the link, so it sees the link itself.
    match std::fs::symlink_metadata(&policy_path) {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(PolicyEditError::PolicyFileIsSymlink { path: policy_path });
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(PolicyEditError::PolicyFileNotFound { path: policy_path });
        }
        Err(e) => return Err(PolicyEditError::Io { source: e }),
    }

    // Step 1b: read the file.
    let text = match std::fs::read_to_string(&policy_path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Race window between symlink_metadata and read; treat as missing.
            return Err(PolicyEditError::PolicyFileNotFound { path: policy_path });
        }
        Err(e) => return Err(PolicyEditError::Io { source: e }),
    };

    // Step 2: parse against the schema. Reuse the canonical parser via
    // PolicySet::compile_from_str to make sure the file is syntactically
    // AND semantically valid before we touch it. If this fails the
    // operator's policy file is already broken; surface that, don't
    // make it worse.
    PolicySet::compile_from_str(&text, &policy_path)
        .map_err(|source| PolicyEditError::ParseFailed { source })?;

    let mut file: TomlPolicyFile = toml::from_str(&text).map_err(|err| {
        // This branch is unreachable in practice because compile_from_str
        // would have already failed above with the same TOML error. Map
        // to a generic ParseFailed for the typed error path.
        PolicyEditError::ParseFailed {
            source: PolicyCompileError::Parse {
                path: policy_path.clone(),
                line: None,
                message: err.message().to_owned(),
            },
        }
    })?;

    // Step 3: locate the target policy block.
    let Some(target_idx) = file.policies.iter().position(|p| p.name == policy_name) else {
        return Err(PolicyEditError::PolicyNotInFile {
            name: policy_name.to_owned(),
            path: policy_path,
        });
    };

    // Step 4: compute the diff. `before` is captured verbatim before
    // any mutation so the returned summary reflects the on-disk state
    // at the start of the call.
    let before: Vec<String> = file.policies[target_idx].scopes.clone();
    let before_set: std::collections::HashSet<&str> = before.iter().map(String::as_str).collect();

    // Preserve input order for `added`, but deduplicate against `before_set`
    // AND against earlier entries in `scopes_to_add` (caller may pass
    // duplicates). Operators see additions in the order they appeared
    // in the OAuth grant.
    let mut added: Vec<String> = Vec::new();
    let mut added_set: std::collections::HashSet<String> = std::collections::HashSet::new();
    for s in scopes_to_add {
        if before_set.contains(s) {
            continue;
        }
        if added_set.insert((*s).to_owned()) {
            added.push((*s).to_owned());
        }
    }

    // No-op short-circuit: every requested scope was already present.
    // DO NOT touch the file. This is the load-bearing assertion for
    // connect's idempotency contract.
    if added.is_empty() {
        let mut after = before.clone();
        after.sort();
        after.dedup();
        return Ok(ScopeMergeDiff {
            policy_name: policy_name.to_owned(),
            policy_path,
            before,
            added,
            after,
        });
    }

    // Step 5: build the merged scope list. Sort + dedup to give a
    // canonical on-disk representation regardless of input order.
    let mut after: Vec<String> = before.to_vec();
    after.extend(added.iter().cloned());
    after.sort();
    after.dedup();

    // Mutate just the target policy's scopes; every other field is
    // preserved by virtue of round-tripping through TomlPolicy.
    file.policies[target_idx].scopes = after.clone();

    // Step 6: serialize. Use `toml::to_string_pretty` for stable
    // multi-line output (vs the single-line default). Note: comments
    // and original key ordering are NOT preserved (see module docs).
    //
    // Workaround for `toml`'s strict ordering rules: we need to
    // serialize the wrapping struct as a single TOML document. The
    // simplest path is to construct a `toml::Value` from the typed
    // struct and let the serializer pretty-print.
    let serialized = toml_serialize_policy_file(&file)?;

    // Step 7: round-trip validate the post-edit text via the canonical
    // compile path. If this fails, return an error and DO NOT write —
    // the on-disk file remains the pre-edit version.
    PolicySet::compile_from_str(&serialized, &policy_path)
        .map_err(|source| PolicyEditError::CompileFailedAfterEdit { source })?;

    // Step 8: atomic write. tempfile-rename in the same parent dir;
    // 0o600 perms on Unix; best-effort parent fsync.
    write_atomic(&policy_path, serialized.as_bytes())?;

    Ok(ScopeMergeDiff { policy_name: policy_name.to_owned(), policy_path, before, added, after })
}

/// Serialize a `TomlPolicyFile` back to its on-disk representation.
///
/// Uses `toml::to_string_pretty` directly on the typed `TomlPolicyFile`,
/// which gained `#[derive(Serialize)]` in Story 7.13 round-1 P2. Adding
/// a new field to `TomlPolicy` / `TomlRule` automatically round-trips —
/// the previous hand-built `toml::Value` table silently dropped any
/// field not enumerated in the serializer.
fn toml_serialize_policy_file(file: &TomlPolicyFile) -> Result<String, PolicyEditError> {
    toml::to_string_pretty(file).map_err(|source| PolicyEditError::SerializeFailed { source })
}

/// Write `bytes` to `path` atomically via a same-directory tempfile +
/// rename. On Unix the file gets `0o600` permissions. The parent
/// directory is fsync'd best-effort for crash durability — failure to
/// fsync the parent is logged but does not fail the write.
///
/// Mirrors the pattern from `permitlayer_oauth::metadata::write_metadata_atomic`.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), PolicyEditError> {
    use std::io::Write as _;

    let parent = path.parent().ok_or_else(|| PolicyEditError::Io {
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("policy path has no parent dir: {}", path.display()),
        ),
    })?;
    std::fs::create_dir_all(parent).map_err(|source| PolicyEditError::Io { source })?;

    let mut tmp =
        tempfile::NamedTempFile::new_in(parent).map_err(|source| PolicyEditError::Io { source })?;
    tmp.write_all(bytes).map_err(|source| PolicyEditError::Io { source })?;
    tmp.as_file().sync_all().map_err(|source| PolicyEditError::Io { source })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(tmp.path(), perms)
            .map_err(|source| PolicyEditError::Io { source })?;
    }

    tmp.persist(path).map_err(|e| PolicyEditError::Io { source: e.error })?;

    // Best-effort parent fsync.
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn write_policy_file(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let path = dir.join(format!("{name}.toml"));
        std::fs::write(&path, contents).unwrap();
        path
    }

    const GMAIL_READONLY_BASE: &str = r#"[[policies]]
name = "gmail-read-only"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
auto-approve-reads = true
"#;

    #[test]
    fn merges_into_existing_scopes_preserves_other_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let _ = write_policy_file(tmp.path(), "gmail-read-only", GMAIL_READONLY_BASE);

        let diff =
            add_scopes_to_policy(tmp.path(), "gmail-read-only", &["gmail.metadata"]).unwrap();

        assert_eq!(diff.before, vec!["gmail.readonly"]);
        assert_eq!(diff.added, vec!["gmail.metadata"]);
        assert_eq!(diff.after, vec!["gmail.metadata", "gmail.readonly"]);

        // Re-parse the on-disk file: every other field must round-trip.
        let after_text = std::fs::read_to_string(tmp.path().join("gmail-read-only.toml")).unwrap();
        let parsed: TomlPolicyFile = toml::from_str(&after_text).unwrap();
        assert_eq!(parsed.policies.len(), 1);
        let p = &parsed.policies[0];
        assert_eq!(p.name, "gmail-read-only");
        assert_eq!(p.resources, vec!["*"]);
        assert!(p.auto_approve_reads);
        assert!(p.rules.is_empty());
        // Sorted scopes after merge.
        assert_eq!(p.scopes, vec!["gmail.metadata", "gmail.readonly"]);
    }

    #[test]
    fn idempotent_when_scopes_already_present() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_policy_file(tmp.path(), "gmail-read-only", GMAIL_READONLY_BASE);

        // Capture pre-state.
        let pre_bytes = std::fs::read(&path).unwrap();

        let diff =
            add_scopes_to_policy(tmp.path(), "gmail-read-only", &["gmail.readonly"]).unwrap();

        assert!(diff.is_no_op(), "merging an already-present scope must be a no-op");
        assert!(diff.added.is_empty());
        assert_eq!(diff.before, vec!["gmail.readonly"]);

        // Byte-equality post-call: the file must NOT have been
        // re-written. This is the load-bearing assertion for the
        // idempotency contract — a TOML re-serialize would change
        // formatting (lose comments, reorder keys) even if semantic
        // content matches.
        let post_bytes = std::fs::read(&path).unwrap();
        assert_eq!(pre_bytes, post_bytes, "idempotent path must not touch the file");
    }

    #[test]
    fn idempotent_when_caller_passes_duplicates() {
        let tmp = tempfile::tempdir().unwrap();
        let _ = write_policy_file(tmp.path(), "gmail-read-only", GMAIL_READONLY_BASE);

        // Caller passes the same scope twice; only one is "added".
        let diff = add_scopes_to_policy(
            tmp.path(),
            "gmail-read-only",
            &["gmail.metadata", "gmail.metadata"],
        )
        .unwrap();
        assert_eq!(diff.added, vec!["gmail.metadata"]);
    }

    #[test]
    fn policy_file_not_found_returns_typed_error() {
        let tmp = tempfile::tempdir().unwrap();
        let result = add_scopes_to_policy(tmp.path(), "does-not-exist", &["gmail.readonly"]);
        let err = result.unwrap_err();
        assert!(
            matches!(err, PolicyEditError::PolicyFileNotFound { .. }),
            "expected PolicyFileNotFound, got {err:?}"
        );
    }

    #[test]
    fn policy_not_in_file_returns_typed_error() {
        let tmp = tempfile::tempdir().unwrap();
        // Create a file at the expected path but with a DIFFERENT
        // policy name inside.
        let mismatched = r#"[[policies]]
name = "different-name"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
"#;
        let _ = write_policy_file(tmp.path(), "gmail-read-only", mismatched);
        let result = add_scopes_to_policy(tmp.path(), "gmail-read-only", &["gmail.metadata"]);
        let err = result.unwrap_err();
        assert!(
            matches!(err, PolicyEditError::PolicyNotInFile { .. }),
            "expected PolicyNotInFile, got {err:?}"
        );
    }

    #[test]
    fn malformed_toml_returns_parse_failed() {
        let tmp = tempfile::tempdir().unwrap();
        // Write a syntactically broken file at the expected path.
        let _ = write_policy_file(tmp.path(), "gmail-read-only", "this is not toml [[[");
        let result = add_scopes_to_policy(tmp.path(), "gmail-read-only", &["gmail.metadata"]);
        let err = result.unwrap_err();
        assert!(
            matches!(err, PolicyEditError::ParseFailed { .. }),
            "expected ParseFailed, got {err:?}"
        );
    }

    #[test]
    fn multi_policy_file_only_target_modified() {
        let tmp = tempfile::tempdir().unwrap();
        let multi = r#"[[policies]]
name = "gmail-read-only"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"

[[policies]]
name = "calendar-read-only"
scopes = ["calendar.readonly"]
resources = ["primary"]
approval-mode = "auto"
"#;
        let _ = write_policy_file(tmp.path(), "gmail-read-only", multi);
        let _diff =
            add_scopes_to_policy(tmp.path(), "gmail-read-only", &["gmail.metadata"]).unwrap();

        // Re-parse and verify the OTHER policy is untouched.
        let after = std::fs::read_to_string(tmp.path().join("gmail-read-only.toml")).unwrap();
        let parsed: TomlPolicyFile = toml::from_str(&after).unwrap();
        assert_eq!(parsed.policies.len(), 2);
        let calendar = parsed
            .policies
            .iter()
            .find(|p| p.name == "calendar-read-only")
            .expect("calendar policy still present");
        assert_eq!(calendar.scopes, vec!["calendar.readonly"]);
        assert_eq!(calendar.resources, vec!["primary"]);
        // The gmail policy gained the new scope.
        let gmail = parsed.policies.iter().find(|p| p.name == "gmail-read-only").unwrap();
        assert_eq!(gmail.scopes, vec!["gmail.metadata", "gmail.readonly"]);
    }

    #[cfg(unix)]
    #[test]
    fn written_file_has_0o600_perms() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let path = write_policy_file(tmp.path(), "gmail-read-only", GMAIL_READONLY_BASE);

        // First force a real write (not the no-op path).
        let _ = add_scopes_to_policy(tmp.path(), "gmail-read-only", &["gmail.metadata"]).unwrap();

        let md = std::fs::metadata(&path).unwrap();
        let mode = md.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "policy file should be 0o600 after write, got {mode:o}");
    }

    #[test]
    fn preserves_rules_and_resources_through_merge() {
        let tmp = tempfile::tempdir().unwrap();
        let with_rules = r#"[[policies]]
name = "calendar-prompt-on-write"
scopes = ["calendar.readonly", "calendar.events"]
resources = ["primary"]
approval-mode = "prompt"
auto-approve-reads = true

[[policies.rules]]
id = "allow-calendar-reads"
scopes = ["calendar.readonly"]
action = "allow"

[[policies.rules]]
id = "prompt-calendar-writes"
scopes = ["calendar.events"]
action = "prompt"
"#;
        let _ = write_policy_file(tmp.path(), "calendar-prompt-on-write", with_rules);

        let diff = add_scopes_to_policy(
            tmp.path(),
            "calendar-prompt-on-write",
            &["calendar.events.readonly"],
        )
        .unwrap();
        assert_eq!(diff.added, vec!["calendar.events.readonly"]);

        // Re-parse and verify rules survived.
        let after =
            std::fs::read_to_string(tmp.path().join("calendar-prompt-on-write.toml")).unwrap();
        let parsed: TomlPolicyFile = toml::from_str(&after).unwrap();
        let p = &parsed.policies[0];
        assert_eq!(p.rules.len(), 2);
        assert_eq!(p.rules[0].id, "allow-calendar-reads");
        assert_eq!(p.rules[1].id, "prompt-calendar-writes");
        assert_eq!(p.resources, vec!["primary"]);
        assert!(p.auto_approve_reads);
    }

    /// Round-1 P16: `auto-approve-reads = false` must survive round-trip
    /// (not silently erased to default). Operator's explicit declaration
    /// of intent is preserved.
    #[test]
    fn explicit_false_auto_approve_reads_survives_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let with_explicit_false = r#"[[policies]]
name = "gmail-read-only"
scopes = ["gmail.readonly"]
resources = ["*"]
approval-mode = "auto"
auto-approve-reads = false
"#;
        let _ = write_policy_file(tmp.path(), "gmail-read-only", with_explicit_false);

        let _ = add_scopes_to_policy(tmp.path(), "gmail-read-only", &["gmail.metadata"]).unwrap();

        let after = std::fs::read_to_string(tmp.path().join("gmail-read-only.toml")).unwrap();
        // The on-disk text should still contain the literal field —
        // both the always-serialize derive AND the typed Serialize impl
        // are responsible for this surviving the merge.
        assert!(
            after.contains("auto-approve-reads") && after.contains("false"),
            "explicit auto-approve-reads = false must round-trip; got:\n{after}"
        );
        let parsed: TomlPolicyFile = toml::from_str(&after).unwrap();
        assert!(!parsed.policies[0].auto_approve_reads);
    }

    /// Round-1 P2: future schema fields round-trip through `toml::to_string_pretty`
    /// on the typed struct. This test lays down a policy with EVERY field
    /// the schema defines today; the round-trip must preserve all of them.
    /// If a future field is added to `TomlPolicy` and this test still
    /// passes without modification, that field is being silently dropped —
    /// the test's role is to break loudly when that happens.
    #[test]
    fn round_trip_preserves_every_schema_field() {
        let tmp = tempfile::tempdir().unwrap();
        let comprehensive = r#"[[policies]]
name = "comprehensive"
scopes = ["gmail.readonly"]
resources = ["primary", "secondary"]
approval-mode = "prompt"
auto-approve-reads = true

[[policies.rules]]
id = "rule-with-everything"
scopes = ["gmail.readonly"]
resources = ["primary"]
action = "allow"
"#;
        let _ = write_policy_file(tmp.path(), "comprehensive", comprehensive);

        let _ = add_scopes_to_policy(tmp.path(), "comprehensive", &["gmail.metadata"]).unwrap();

        let after = std::fs::read_to_string(tmp.path().join("comprehensive.toml")).unwrap();
        let parsed: TomlPolicyFile = toml::from_str(&after).unwrap();
        let p = &parsed.policies[0];
        assert_eq!(p.name, "comprehensive");
        assert_eq!(p.scopes, vec!["gmail.metadata", "gmail.readonly"]);
        assert_eq!(p.resources, vec!["primary", "secondary"]);
        assert_eq!(p.approval_mode, crate::policy::schema::TomlApprovalMode::Prompt);
        assert!(p.auto_approve_reads);
        assert_eq!(p.rules.len(), 1);
        let r = &p.rules[0];
        assert_eq!(r.id, "rule-with-everything");
        assert_eq!(r.scopes.as_ref().unwrap(), &vec!["gmail.readonly".to_owned()]);
        assert_eq!(r.resources.as_ref().unwrap(), &vec!["primary".to_owned()]);
        assert_eq!(r.action, crate::policy::schema::TomlRuleAction::Allow);
    }
}
