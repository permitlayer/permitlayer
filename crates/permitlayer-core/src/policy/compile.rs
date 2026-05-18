//! Compile `TomlPolicyFile` → `PolicySet` IR, and evaluate against it.
//!
//! The IR lives here (not in `schema.rs`) because the compiled types
//! are what every downstream caller actually works with: the schema
//! types exist only to bridge TOML bytes → semantic values. Keeping
//! them in separate files makes the "build IR once, walk many times"
//! invariant visually obvious.
//!
//! # Hot-path discipline
//!
//! `PolicySet::evaluate` MUST NOT allocate in the common path. The
//! current implementation allocates for the error path only (when
//! building a `Decision::Deny` with owned strings). The Story 4.1
//! benchmark proves this is under the NFR4 10ms p99 budget at 100
//! policies; if it ever drifts, profile before re-architecting.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::error::PolicyCompileError;
use super::eval::{ApprovalMode, Decision, EvalRequest};
use super::schema::{TomlPolicy, TomlPolicyFile, TomlRule, TomlRuleAction};

/// Rule ID used by default-deny when the agent is bound to a policy
/// name not present in the `PolicySet`. Also used by `evaluate` when
/// the policy lookup misses.
const DEFAULT_DENY_UNMATCHED_POLICY: &str = "default-deny-unmatched-policy";
/// Rule ID used when a scope is not in the policy's allowlist.
const DEFAULT_DENY_SCOPE: &str = "default-deny-scope-out-of-allowlist";
/// Rule ID used when a resource is not in the policy's allowlist.
const DEFAULT_DENY_RESOURCE: &str = "default-deny-resource-out-of-allowlist";
/// Rule ID used when the policy-level `approval-mode = "prompt"`
/// default produces a prompt decision for an unmatched rule.
///
/// Re-exported so downstream crates (e.g., `permitlayer-proxy`'s
/// `PolicyService`) can distinguish policy-level fall-through prompts
/// from explicit operator-written rule-level prompts. Story 4.5's
/// `auto-approve-reads` short-circuit only fires for the fall-through
/// case to avoid silently overriding explicit operator intent.
pub const DEFAULT_PROMPT_APPROVAL_MODE: &str = "default-prompt-approval-mode";
/// Rule ID used when the policy-level `approval-mode = "deny"`
/// default produces a deny decision for an unmatched rule.
const DEFAULT_DENY_APPROVAL_MODE: &str = "default-deny-approval-mode";

/// Maximum allowed scope identifier length in structural validation.
const MAX_SCOPE_LEN: usize = 128;

/// Compiled, evaluation-ready policy set.
///
/// This is what lives in `Arc<ArcSwap<PolicySet>>` at runtime. Stories
/// 4.2+ produce new instances via [`PolicySet::compile_from_dir`] on
/// reload and atomically swap the old one out. Story 4.1 only
/// produces instances at startup.
#[derive(Debug, Default)]
pub struct PolicySet {
    /// Map from policy name → compiled policy. The `HashMap` is the
    /// pre-hashed lookup structure AC #3 calls for — O(1) contains
    /// checks in the hot path with no allocation when the lookup hits.
    policies: HashMap<String, CompiledPolicy>,
    /// Map from policy name → the file path it was compiled from.
    /// Populated by `compile_from_dir` and `compile_from_str` so the
    /// control plane can answer `policy list` with real source paths.
    /// Story 7.34 AC #3. For an accepted cross-layer override the
    /// origin is the **operator** file (the winning definition), so
    /// reload/diff/`policy list` stay correct.
    origins: HashMap<String, PathBuf>,
    /// UX-overhaul Story 1: accepted operator overrides of managed
    /// (product) policies, in deterministic (sorted) order. Each is a
    /// policy where an operator file carried an explicit
    /// `override = "<name>"` marker matching a managed policy of the
    /// same name. The daemon emits a `policy.operator_override` audit
    /// event per entry and `doctor` surfaces them. Empty for the
    /// single-layer `compile_from_dir`/`compile_from_str` paths.
    accepted_overrides: Vec<OverrideRecord>,
}

/// One accepted cross-layer operator override (UX-overhaul Story 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverrideRecord {
    /// The policy name the operator intentionally shadowed.
    pub name: String,
    /// The managed (product) file whose policy was shadowed.
    pub managed_path: PathBuf,
    /// The operator file that won (the active definition).
    pub operator_path: PathBuf,
}

/// One policy in the compiled IR.
#[derive(Debug, PartialEq)]
pub struct CompiledPolicy {
    /// Stable name, carried through to `Decision` outputs.
    pub name: String,
    /// Set of scope strings the policy allows. `HashSet` for O(1)
    /// membership checks in the hot path.
    pub scope_allowlist: HashSet<String>,
    /// Resource allowlist, possibly `All` when the policy whitelisted `*`.
    pub resource_allowlist: ResourceMatcher,
    /// Policy-level default approval disposition.
    pub approval_mode: ApprovalMode,
    /// Rules in declaration order. Evaluation walks them left-to-right
    /// and returns the first match.
    pub compiled_rules: Vec<CompiledRule>,
    /// Whether `auto-approve-reads = true` was set. When the policy's
    /// `approval_mode` is `Prompt`, `PolicyLayer` consults this flag
    /// (via [`CompiledPolicy::is_readonly_scope`]) to bypass the TTY
    /// prompt for read-style scopes (`.readonly`, `.metadata`) while
    /// still prompting on writes. Story 4.5's implementation lives in
    /// `permitlayer_proxy::middleware::policy::PolicyService::call`.
    pub auto_approve_reads: bool,
}

impl CompiledPolicy {
    /// Return `true` when `scope` is a read-style OAuth scope.
    ///
    /// Story 4.5's `auto-approve-reads` short-circuit uses this to
    /// bypass TTY prompts on reads while still prompting on writes.
    /// The classifier is intentionally a simple suffix match because
    /// every Google Workspace OAuth scope that maps to a read-only
    /// operation ends in either `.readonly` or `.metadata` (see
    /// `permitlayer-oauth::google::scopes`). User-defined scopes that
    /// follow the same convention also work.
    ///
    /// A future richer classifier could walk per-service scope
    /// metadata, but for MVP the suffix heuristic is sufficient and
    /// stable.
    #[must_use]
    pub fn is_readonly_scope(&self, scope: &str) -> bool {
        // Reject degenerate input: a bare suffix like `.readonly` is
        // not a scope, and an empty string is never readonly.
        if scope == ".readonly" || scope == ".metadata" || scope.is_empty() {
            return false;
        }
        scope.ends_with(".readonly") || scope.ends_with(".metadata")
    }

    /// Serialize back to the TOML schema representation.
    ///
    /// Story 7.34 AC #1: `policy show` needs to emit the resolved
    /// in-memory policy as TOML. Reverse-mapping preserves every field
    /// the parser normalised, including defaults.
    #[must_use]
    pub fn to_toml_policy(&self) -> super::schema::TomlPolicy {
        let mut scopes: Vec<String> = self.scope_allowlist.iter().cloned().collect();
        scopes.sort();
        let resources = match &self.resource_allowlist {
            ResourceMatcher::All => vec!["*".to_owned()],
            ResourceMatcher::Allowlist(set) => {
                let mut v: Vec<String> = set.iter().cloned().collect();
                v.sort();
                v
            }
        };
        let rules: Vec<super::schema::TomlRule> =
            self.compiled_rules.iter().map(|r| r.to_toml_rule()).collect();
        super::schema::TomlPolicy {
            name: self.name.clone(),
            scopes,
            resources,
            approval_mode: self.approval_mode.into(),
            rules,
            auto_approve_reads: self.auto_approve_reads,
            // The override marker is an operator-file authoring
            // concern consumed at compile time; the resolved
            // in-memory policy carries no marker (round-tripping a
            // compiled policy must not re-emit `override`).
            r#override: None,
        }
    }
}

/// One rule in the compiled IR.
#[derive(Debug, PartialEq)]
pub struct CompiledRule {
    /// Stable string identifier, surfaced verbatim in HTTP 403 bodies.
    pub id: String,
    /// When `Some`, narrows the scopes this rule matches. When `None`,
    /// the rule inherits the enclosing policy's scope allowlist.
    pub scope_overrides: Option<HashSet<String>>,
    /// When `Some`, narrows the resources this rule matches. When
    /// `None`, the rule inherits the enclosing policy's resource matcher.
    pub resource_overrides: Option<ResourceMatcher>,
    /// What happens when this rule matches.
    pub action: RuleAction,
}

impl CompiledRule {
    /// Serialize back to the TOML schema representation.
    ///
    /// Story 7.34 AC #1: `policy show` needs to emit the resolved
    /// in-memory policy as TOML. Reverse-mapping preserves every field
    /// the parser normalised.
    #[must_use]
    pub fn to_toml_rule(&self) -> super::schema::TomlRule {
        super::schema::TomlRule {
            id: self.id.clone(),
            scopes: self.scope_overrides.as_ref().map(|s| {
                let mut v: Vec<String> = s.iter().cloned().collect();
                v.sort();
                v
            }),
            resources: self.resource_overrides.as_ref().map(|r| match r {
                ResourceMatcher::All => vec!["*".to_owned()],
                ResourceMatcher::Allowlist(set) => {
                    let mut v: Vec<String> = set.iter().cloned().collect();
                    v.sort();
                    v
                }
            }),
            action: self.action.into(),
        }
    }
}

/// Rule-level action. 1:1 with `schema::TomlRuleAction` but lives
/// in the compile layer.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RuleAction {
    /// Explicit allow carved out of a stricter policy default.
    Allow,
    /// Explicit prompt, overriding the policy default.
    Prompt,
    /// Explicit deny, taking precedence over any broader allow.
    Deny,
}

impl From<TomlRuleAction> for RuleAction {
    fn from(v: TomlRuleAction) -> Self {
        match v {
            TomlRuleAction::Allow => Self::Allow,
            TomlRuleAction::Prompt => Self::Prompt,
            TomlRuleAction::Deny => Self::Deny,
        }
    }
}

impl From<RuleAction> for TomlRuleAction {
    fn from(v: RuleAction) -> Self {
        match v {
            RuleAction::Allow => Self::Allow,
            RuleAction::Prompt => Self::Prompt,
            RuleAction::Deny => Self::Deny,
        }
    }
}

/// Resource-matching strategy.
///
/// `All` ships the common `resources = ["*"]` case — no allocation,
/// no hashing, O(1) match. `Allowlist` is a `HashSet` for exact match
/// lookups. Glob patterns are a deferred future variant.
#[derive(Debug, PartialEq)]
pub enum ResourceMatcher {
    /// `resources = ["*"]` — matches any resource, including `None`.
    All,
    /// `resources = ["primary", "secondary"]` — matches the explicit
    /// set only. An `EvalRequest` with `resource: None` never matches
    /// an `Allowlist` variant — callers that want "no resource dimension"
    /// must model that as an explicit allowlist entry or use `All`.
    Allowlist(HashSet<String>),
}

impl ResourceMatcher {
    fn matches(&self, resource: Option<&str>) -> bool {
        match self {
            Self::All => true,
            Self::Allowlist(set) => match resource {
                Some(r) => set.contains(r),
                None => false,
            },
        }
    }
}

impl PolicySet {
    /// Construct an empty `PolicySet`. Every `evaluate` call against
    /// the empty set returns `Decision::Deny` with the
    /// `default-deny-unmatched-policy` rule ID — the daemon's
    /// startup-time placeholder before any files are compiled, and
    /// the target the fail-closed middleware falls back to when the
    /// policies directory is empty.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Number of compiled policies in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.policies.len()
    }

    /// Whether the set contains zero policies.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    /// Return the names of all compiled policies.
    ///
    /// Used by Story 4.3's default-policy-resolution heuristic (single-
    /// policy shortcut) and by diff/debug tooling. The order is
    /// arbitrary (HashMap iteration order).
    #[must_use]
    pub fn policy_names(&self) -> Vec<String> {
        self.policies.keys().cloned().collect()
    }

    /// Look up a compiled policy by name. Used by tests and debug
    /// tooling; the hot path goes through `evaluate` instead.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&CompiledPolicy> {
        self.policies.get(name)
    }

    /// Look up the origin path for a policy by name.
    ///
    /// Story 7.34 AC #3: the control plane needs to report which file
    /// each policy came from. Returns `None` when the policy is not in
    /// the set or when the set was built without origin tracking.
    #[must_use]
    pub fn origin(&self, name: &str) -> Option<&PathBuf> {
        self.origins.get(name)
    }

    /// Accepted operator overrides of managed policies (UX-overhaul
    /// Story 1), deterministically ordered by policy name. The daemon
    /// emits one `policy.operator_override` audit event per entry and
    /// `doctor` surfaces them. Empty for single-layer compiles.
    #[must_use]
    pub fn accepted_overrides(&self) -> &[OverrideRecord] {
        &self.accepted_overrides
    }

    /// Compile every `*.toml` file in `dir` into a single `PolicySet`.
    ///
    /// Files are processed in alphabetical order so error output is
    /// deterministic. Duplicate policy names ACROSS files are a hard
    /// error (FR15 fail-fast). A missing directory surfaces as
    /// [`PolicyCompileError::Io`]; an existing path that is not a
    /// directory surfaces as [`PolicyCompileError::NotADirectory`].
    ///
    /// Dotfiles (`.foo.toml`) and editor lockfiles (`.#foo.toml`) are
    /// skipped — editors frequently create these during active editing
    /// and their contents are not valid TOML. The extension match is
    /// case-insensitive so `Default.TOML` exported from a Windows
    /// workflow is still picked up.
    ///
    /// # Errors
    ///
    /// Returns the first compile error encountered. Subsequent files
    /// are not processed — fail-fast is the point.
    pub fn compile_from_dir(dir: &Path) -> Result<Self, PolicyCompileError> {
        // Single-layer compile = the operator layer with no managed
        // layer. Preserves every historical caller/test verbatim
        // (intra-dir duplicate name still fatal; no override marker
        // is meaningful without a managed layer to override).
        Self::compile_from_layers(None, dir)
    }

    /// UX-overhaul Story 1: the new compile core. Compile a **managed
    /// (product)** layer and an **operator** layer into one set with
    /// fail-closed cross-layer rules.
    ///
    /// - `managed_dir`: the shipped/bundled product layer
    ///   (`policies-managed/`). `None` ⇒ single-layer mode (used by
    ///   [`compile_from_dir`]); the managed set is empty.
    /// - `operator_dir`: the operator-authored layer (`policies/`).
    ///
    /// Rules (all fail-closed — the prior draft's "log INFO and
    /// shadow" was rejected by security review):
    /// - Intra-layer duplicate policy name (within one dir) is
    ///   **fatal** (`DuplicatePolicyName`), unchanged from before.
    /// - A managed policy carrying an `override` marker is **fatal**
    ///   (`OverrideMarkerInManagedLayer`) — the product never
    ///   overrides.
    /// - An operator policy whose `name` also exists in the managed
    ///   layer is accepted **only** if it carries
    ///   `override = "<its own name>"`; the operator definition then
    ///   wins and an [`OverrideRecord`] is recorded. An unmarked
    ///   same-name collision is **fatal**
    ///   (`UnmarkedCrossLayerOverride`).
    /// - An operator policy carrying `override = "<x>"` where `<x>`
    ///   is not the policy's own name OR no managed policy named
    ///   `<x>` exists is **fatal** (`DanglingOverrideMarker`).
    /// - A non-colliding operator policy is added as-is.
    ///
    /// `origins` records the **winning** file (operator path for an
    /// accepted override) so reload/diff/`policy list`/Story-4
    /// reporting stay correct.
    ///
    /// # Errors
    ///
    /// First compile or layering-rule violation encountered.
    pub fn compile_from_layers(
        managed_dir: Option<&Path>,
        operator_dir: &Path,
    ) -> Result<Self, PolicyCompileError> {
        let mut set = Self::default();
        let mut origin_for_name: HashMap<String, PathBuf> = HashMap::new();

        // ── Managed layer ───────────────────────────────────────────
        // Compiled first so it's the baseline the operator layer
        // overrides. A managed policy that carries an `override`
        // marker is a build-time bug → fatal.
        if let Some(md) = managed_dir {
            for (path, raw) in read_layer_policies_optional(md)? {
                if raw.r#override.is_some() {
                    return Err(PolicyCompileError::OverrideMarkerInManagedLayer {
                        name: raw.name,
                        managed_path: path,
                    });
                }
                if let Some(first) = origin_for_name.get(&raw.name) {
                    return Err(PolicyCompileError::DuplicatePolicyName {
                        name: raw.name,
                        first: first.clone(),
                        second: path,
                    });
                }
                let compiled = compile_one(raw, &path)?;
                origin_for_name.insert(compiled.name.clone(), path.clone());
                set.policies.insert(compiled.name.clone(), compiled);
            }
        }
        // Snapshot the managed names so operator-layer collision
        // checks reference the product layer specifically (not other
        // operator files).
        let managed_names: HashMap<String, PathBuf> = origin_for_name.clone();

        // ── Operator layer ──────────────────────────────────────────
        let mut overrides: Vec<OverrideRecord> = Vec::new();
        let mut operator_seen: HashSet<String> = HashSet::new();
        for (path, raw) in read_layer_policies(operator_dir)? {
            // Intra-operator-layer duplicate (across operator files)
            // stays fatal — unchanged invariant.
            if !operator_seen.insert(raw.name.clone()) {
                let first = origin_for_name.get(&raw.name).cloned().unwrap_or_else(|| path.clone());
                return Err(PolicyCompileError::DuplicatePolicyName {
                    name: raw.name,
                    first,
                    second: path,
                });
            }

            let managed_hit = managed_names.get(&raw.name).cloned();
            match (&raw.r#override, managed_hit) {
                // Operator policy collides with a managed policy.
                (Some(marker), Some(managed_path)) => {
                    // Marker MUST equal the policy's own name (an
                    // override targets itself across the layer).
                    if marker != &raw.name {
                        return Err(PolicyCompileError::DanglingOverrideMarker {
                            name: raw.name.clone(),
                            target: marker.clone(),
                            operator_path: path,
                        });
                    }
                    // Accepted override: operator definition wins.
                    overrides.push(OverrideRecord {
                        name: raw.name.clone(),
                        managed_path,
                        operator_path: path.clone(),
                    });
                    let compiled = compile_one(raw, &path)?;
                    origin_for_name.insert(compiled.name.clone(), path.clone());
                    set.policies.insert(compiled.name.clone(), compiled);
                }
                // Operator policy collides with managed BUT no marker
                // → fail-closed (no silent shadow).
                (None, Some(managed_path)) => {
                    return Err(PolicyCompileError::UnmarkedCrossLayerOverride {
                        name: raw.name,
                        operator_path: path,
                        managed_path,
                    });
                }
                // Marker present but nothing in the managed layer to
                // override (or marker != own name) → dangling.
                (Some(marker), None) => {
                    return Err(PolicyCompileError::DanglingOverrideMarker {
                        name: raw.name.clone(),
                        target: marker.clone(),
                        operator_path: path,
                    });
                }
                // Plain operator policy, no collision.
                (None, None) => {
                    if let Some(first) = origin_for_name.get(&raw.name) {
                        return Err(PolicyCompileError::DuplicatePolicyName {
                            name: raw.name,
                            first: first.clone(),
                            second: path,
                        });
                    }
                    let compiled = compile_one(raw, &path)?;
                    origin_for_name.insert(compiled.name.clone(), path.clone());
                    set.policies.insert(compiled.name.clone(), compiled);
                }
            }
        }

        overrides.sort_by(|a, b| a.name.cmp(&b.name));
        set.origins = origin_for_name;
        set.accepted_overrides = overrides;
        Ok(set)
    }

    /// Compile a single TOML file contents string into a `PolicySet`.
    ///
    /// Used by `compile_from_dir` once per file and by unit tests
    /// that want to assert compile behavior without touching the
    /// filesystem. `origin` is the path reported in error variants.
    ///
    /// # Errors
    ///
    /// Returns a [`PolicyCompileError`] if parsing fails, the file is
    /// empty, or any validation rule is violated.
    pub fn compile_from_str(text: &str, origin: &Path) -> Result<Self, PolicyCompileError> {
        if text.starts_with('\u{feff}') {
            return Err(PolicyCompileError::BomDetected { path: origin.to_path_buf() });
        }
        let parsed = parse_file(text, origin)?;
        if parsed.policies.is_empty() {
            return Err(PolicyCompileError::EmptyPoliciesArray { path: origin.to_path_buf() });
        }
        let mut set = Self::default();
        for raw in parsed.policies {
            if set.policies.contains_key(&raw.name) {
                return Err(PolicyCompileError::DuplicatePolicyNameInFile {
                    name: raw.name,
                    path: origin.to_path_buf(),
                });
            }
            let compiled = compile_one(raw, origin)?;
            let name = compiled.name.clone();
            set.policies.insert(name.clone(), compiled);
            set.origins.insert(name, origin.to_path_buf());
        }
        Ok(set)
    }

    /// Evaluate a request against the compiled IR.
    ///
    /// Always returns a [`Decision`] — never a `Result`. Evaluation
    /// failures surface as `Decision::Deny`, preserving fail-closed
    /// semantics at the type level so Story 4.3's `PolicyLayer` cannot
    /// accidentally bypass a denial by unwrapping a `Result`.
    ///
    /// # Invariants enforced at compile time
    ///
    /// `compile_one` guarantees that every rule's scope/resource
    /// overrides are subsets of the enclosing policy's allowlist, so
    /// the hot-path matcher can consult the override alone without
    /// defensively re-checking the policy allowlist on every call.
    /// A rule can only narrow, never widen, the policy's reach.
    #[must_use]
    pub fn evaluate(&self, req: &EvalRequest) -> Decision {
        let Some(policy) = self.policies.get(&req.policy_name) else {
            return Decision::Deny {
                policy_name: req.policy_name.clone(),
                rule_id: DEFAULT_DENY_UNMATCHED_POLICY.to_owned(),
                denied_scope: Some(req.scope.clone()),
                denied_resource: req.resource.clone(),
            };
        };

        for rule in &policy.compiled_rules {
            if rule_matches(rule, policy, req) {
                return decision_from_rule_action(rule, policy, req);
            }
        }

        if !policy.scope_allowlist.contains(&req.scope) {
            return Decision::Deny {
                policy_name: policy.name.clone(),
                rule_id: DEFAULT_DENY_SCOPE.to_owned(),
                denied_scope: Some(req.scope.clone()),
                denied_resource: None,
            };
        }
        if !policy.resource_allowlist.matches(req.resource.as_deref()) {
            return Decision::Deny {
                policy_name: policy.name.clone(),
                rule_id: DEFAULT_DENY_RESOURCE.to_owned(),
                denied_scope: None,
                denied_resource: req.resource.clone(),
            };
        }

        match policy.approval_mode {
            ApprovalMode::Auto => Decision::Allow,
            ApprovalMode::Prompt => Decision::Prompt {
                policy_name: policy.name.clone(),
                rule_id: DEFAULT_PROMPT_APPROVAL_MODE.to_owned(),
            },
            // Policy-wide deny is not scope-specific — the scope was
            // allowed by the allowlist, so populating `denied_scope`
            // here would send operators chasing a phantom scope
            // violation. The policy name and well-known rule_id are
            // enough to explain the denial.
            ApprovalMode::Deny => Decision::Deny {
                policy_name: policy.name.clone(),
                rule_id: DEFAULT_DENY_APPROVAL_MODE.to_owned(),
                denied_scope: None,
                denied_resource: None,
            },
        }
    }

    /// Compare two `PolicySet` instances and return a summary of what
    /// changed. Used by the reload handler to build the "✓ N policies
    /// loaded · X added, Y modified, Z unchanged" output required by
    /// AC #4, and by the `policy-reloaded` audit event.
    #[must_use]
    pub fn diff(&self, previous: &PolicySet) -> PolicySetDiff {
        let mut added: Vec<String> = Vec::new();
        let mut modified: Vec<String> = Vec::new();
        let mut unchanged: Vec<String> = Vec::new();
        let mut removed: Vec<String> = Vec::new();

        for (name, new_policy) in &self.policies {
            match previous.policies.get(name) {
                None => added.push(name.clone()),
                Some(old_policy) => {
                    if new_policy == old_policy {
                        unchanged.push(name.clone());
                    } else {
                        modified.push(name.clone());
                    }
                }
            }
        }
        for name in previous.policies.keys() {
            if !self.policies.contains_key(name) {
                removed.push(name.clone());
            }
        }

        // Sort for deterministic output.
        added.sort();
        modified.sort();
        unchanged.sort();
        removed.sort();

        PolicySetDiff { policies_loaded: self.policies.len(), added, modified, unchanged, removed }
    }
}

/// Summary of differences between two `PolicySet` instances.
///
/// Built by [`PolicySet::diff`] and serialized into the reload
/// control-plane response and the `policy-reloaded` audit event's
/// `extra` field.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PolicySetDiff {
    /// Number of policies in the new (current) set.
    pub policies_loaded: usize,
    /// Policy names present in the new set but absent from the old.
    pub added: Vec<String>,
    /// Policy names present in both sets but with different compiled content.
    pub modified: Vec<String>,
    /// Policy names present in both sets with identical compiled content.
    pub unchanged: Vec<String>,
    /// Policy names present in the old set but absent from the new.
    pub removed: Vec<String>,
}

/// Return `true` if a directory entry should be considered as a
/// candidate policy file.
///
/// Excludes:
/// - paths without a filename (defensive; `read_dir` never yields these)
/// - dotfiles (`.foo.toml`, `.#foo.toml` Emacs lockfiles, etc.)
/// - any file whose extension, lowercased, is not exactly `toml`
pub(crate) fn is_candidate_policy_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if name.starts_with('.') {
        return false;
    }
    let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
        return false;
    };
    ext.eq_ignore_ascii_case("toml")
}

/// Read + parse every candidate policy file in one layer directory,
/// returning `(file_path, policy)` pairs in deterministic
/// (file-sorted, then in-file declaration) order.
///
/// Performs the per-file invariants that are layer-independent:
/// directory-exists/is-a-dir, dotfile/lockfile skipping, BOM
/// rejection, empty-`[[policies]]` rejection, and **intra-file**
/// duplicate-name rejection. Cross-file and cross-layer name
/// semantics are the caller's ([`PolicySet::compile_from_layers`])
/// responsibility — that's where the managed/operator override
/// rules live.
///
/// **Strict** directory contract, **unchanged from the historical
/// `compile_from_dir`**: a path that exists but is not a directory
/// is `NotADirectory`; a missing/unreadable directory surfaces as
/// `Io`. This preserves the
/// `compile_from_dir_reports_io_error_for_missing_dir` contract —
/// `compile_from_dir` (public API) and the **operator** layer use
/// this strict form: a missing operator `policies/` is a real
/// misconfiguration the daemon should not paper over.
///
/// The **managed** layer uses [`read_layer_policies_optional`]
/// instead: a `Some(managed_dir)` that does not yet exist on disk
/// is the legitimate "no product bundle synced yet" state — it
/// occurs on a control-plane reload before the first
/// `sync_managed_policies` and in router unit tests that construct
/// the handler without a full daemon boot. Treating that as `Io`
/// (the bug that surfaced 8 control-plane test failures) is wrong;
/// an absent managed layer is simply an empty managed layer. A
/// managed path that exists-but-is-broken (not a dir, unreadable)
/// is still a hard error there.
fn read_layer_policies(
    dir: &Path,
) -> Result<Vec<(PathBuf, crate::policy::schema::TomlPolicy)>, PolicyCompileError> {
    if dir.exists() && !dir.is_dir() {
        return Err(PolicyCompileError::NotADirectory { path: dir.to_path_buf() });
    }
    let entries = std::fs::read_dir(dir)
        .map_err(|source| PolicyCompileError::Io { path: dir.to_path_buf(), source })?;

    let mut toml_files: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|source| PolicyCompileError::Io { path: dir.to_path_buf(), source })?;
        let path = entry.path();
        if !is_candidate_policy_file(&path) {
            continue;
        }
        toml_files.push(path);
    }
    toml_files.sort();

    let mut out: Vec<(PathBuf, crate::policy::schema::TomlPolicy)> = Vec::new();
    for path in toml_files {
        let text = std::fs::read_to_string(&path)
            .map_err(|source| PolicyCompileError::Io { path: path.clone(), source })?;
        if text.starts_with('\u{feff}') {
            return Err(PolicyCompileError::BomDetected { path: path.clone() });
        }
        let parsed = parse_file(&text, &path)?;
        if parsed.policies.is_empty() {
            return Err(PolicyCompileError::EmptyPoliciesArray { path: path.clone() });
        }
        let mut seen_in_file: HashSet<String> = HashSet::new();
        for raw in parsed.policies {
            if !seen_in_file.insert(raw.name.clone()) {
                return Err(PolicyCompileError::DuplicatePolicyNameInFile {
                    name: raw.name,
                    path: path.clone(),
                });
            }
            out.push((path.clone(), raw));
        }
    }
    Ok(out)
}

/// Like [`read_layer_policies`] but treats a **missing** directory as
/// an empty layer (returns `Ok(vec![])`) instead of `Io`.
///
/// Used ONLY for the managed layer in
/// [`PolicySet::compile_from_layers`]: an absent `policies-managed/`
/// means "no product bundle synced to disk yet", which is a valid
/// state on a control-plane reload that races the first
/// `sync_managed_policies`, and in router unit tests that build the
/// handler without a full daemon boot. A managed path that EXISTS
/// but is broken (not a directory, unreadable mid-scan) is still a
/// hard error — only the does-not-exist case is downgraded to empty.
fn read_layer_policies_optional(
    dir: &Path,
) -> Result<Vec<(PathBuf, crate::policy::schema::TomlPolicy)>, PolicyCompileError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    read_layer_policies(dir)
}

fn parse_file(text: &str, path: &Path) -> Result<TomlPolicyFile, PolicyCompileError> {
    toml::from_str::<TomlPolicyFile>(text).map_err(|err| {
        let line = err.span().map(|span| byte_offset_to_line(text, span.start));
        PolicyCompileError::Parse {
            path: path.to_path_buf(),
            line,
            message: err.message().to_owned(),
        }
    })
}

fn byte_offset_to_line(text: &str, offset: usize) -> usize {
    // 1-based line number at the given byte offset. Counts `\n` bytes
    // before the offset. Clamp the offset in case a broken TOML error
    // reports a span past the end of the input.
    let end = offset.min(text.len());
    let mut line = 1usize;
    for &b in text.as_bytes()[..end].iter() {
        if b == b'\n' {
            line += 1;
        }
    }
    line
}

fn compile_one(raw: TomlPolicy, path: &Path) -> Result<CompiledPolicy, PolicyCompileError> {
    // Scope allowlist: non-empty, well-formed, no duplicates.
    if raw.scopes.is_empty() {
        return Err(PolicyCompileError::EmptyScopesAllowlist {
            policy: raw.name,
            path: path.to_path_buf(),
        });
    }
    let mut scope_allowlist: HashSet<String> = HashSet::with_capacity(raw.scopes.len());
    for scope in &raw.scopes {
        validate_scope_format(scope, &raw.name, path)?;
        if !scope_allowlist.insert(scope.clone()) {
            return Err(PolicyCompileError::DuplicateScopeInAllowlist {
                policy: raw.name,
                scope: scope.clone(),
                path: path.to_path_buf(),
            });
        }
    }

    // Resource allowlist: non-empty, no mixed wildcard+explicit.
    if raw.resources.is_empty() {
        return Err(PolicyCompileError::EmptyResourcesAllowlist {
            policy: raw.name,
            path: path.to_path_buf(),
        });
    }
    let resource_allowlist = compile_policy_resource_matcher(&raw.resources, &raw.name, path)?;

    // Rules: unique IDs, non-empty overrides, subset of policy allowlists.
    let mut seen_rule_ids: HashSet<String> = HashSet::new();
    let mut compiled_rules: Vec<CompiledRule> = Vec::with_capacity(raw.rules.len());
    for rule in raw.rules {
        if !seen_rule_ids.insert(rule.id.clone()) {
            return Err(PolicyCompileError::DuplicateRuleId {
                policy: raw.name,
                rule_id: rule.id,
                path: path.to_path_buf(),
            });
        }
        let compiled = compile_rule(rule, &raw.name, &scope_allowlist, &resource_allowlist, path)?;
        compiled_rules.push(compiled);
    }

    // Shadow detection: a later rule whose effective scope AND
    // resource match sets are fully subsumed by an earlier rule is
    // unreachable. Walk pairs (every earlier rule vs. every later
    // one) and reject on the first violation.
    //
    // Effective sets: `scope_overrides` if present, else the policy's
    // `scope_allowlist`; likewise for resources. For shadowing
    // purposes we compare the concrete sets the rule would match.
    for (later_idx, later_rule) in compiled_rules.iter().enumerate().skip(1) {
        for earlier_rule in &compiled_rules[..later_idx] {
            if rule_is_shadowed(earlier_rule, later_rule, &scope_allowlist, &resource_allowlist) {
                return Err(PolicyCompileError::ShadowedRule {
                    policy: raw.name,
                    earlier_rule_id: earlier_rule.id.clone(),
                    later_rule_id: later_rule.id.clone(),
                    path: path.to_path_buf(),
                });
            }
        }
    }

    Ok(CompiledPolicy {
        name: raw.name,
        scope_allowlist,
        resource_allowlist,
        approval_mode: ApprovalMode::from(raw.approval_mode),
        compiled_rules,
        auto_approve_reads: raw.auto_approve_reads,
    })
}

fn compile_rule(
    raw: TomlRule,
    policy_name: &str,
    policy_scopes: &HashSet<String>,
    policy_resources: &ResourceMatcher,
    path: &Path,
) -> Result<CompiledRule, PolicyCompileError> {
    // Scope override: reject empty (dead rule), validate each format,
    // reject any scope not in the policy allowlist (widening).
    let scope_overrides = match raw.scopes {
        None => None,
        Some(scopes) => {
            if scopes.is_empty() {
                return Err(PolicyCompileError::EmptyRuleScopesOverride {
                    policy: policy_name.to_owned(),
                    rule_id: raw.id,
                    path: path.to_path_buf(),
                });
            }
            let mut set: HashSet<String> = HashSet::with_capacity(scopes.len());
            for scope in &scopes {
                validate_scope_format(scope, policy_name, path)?;
                if !policy_scopes.contains(scope) {
                    return Err(PolicyCompileError::RuleScopeWidensPolicyAllowlist {
                        policy: policy_name.to_owned(),
                        rule_id: raw.id,
                        scope: scope.clone(),
                        path: path.to_path_buf(),
                    });
                }
                set.insert(scope.clone());
            }
            Some(set)
        }
    };

    // Resource override: reject empty, reject mixed wildcard+explicit,
    // reject explicit resources not in the policy allowlist (widening).
    // If the policy-level matcher is `All`, any rule override is
    // narrowing by definition — the widening check is a no-op.
    let resource_overrides = match raw.resources {
        None => None,
        Some(resources) => {
            if resources.is_empty() {
                return Err(PolicyCompileError::EmptyRuleResourcesOverride {
                    policy: policy_name.to_owned(),
                    rule_id: raw.id,
                    path: path.to_path_buf(),
                });
            }
            reject_mixed_wildcard(&resources, policy_name, path)?;
            // When the rule says `resources = ["*"]` it is explicitly
            // opting into whatever the policy allows. If the policy
            // is wildcard-open the match set is unchanged; if the
            // policy is narrowed to an allowlist, the rule's "*"
            // would widen the effective match set back to everything,
            // which IS a widening bug. Reject `resources = ["*"]` on
            // a rule unless the policy is also wildcard-open.
            let rule_wildcard = resources.iter().any(|s| s == "*");
            if rule_wildcard && !matches!(policy_resources, ResourceMatcher::All) {
                return Err(PolicyCompileError::RuleResourceWidensPolicyAllowlist {
                    policy: policy_name.to_owned(),
                    rule_id: raw.id,
                    resource: "*".to_owned(),
                    path: path.to_path_buf(),
                });
            }
            if !rule_wildcard && let ResourceMatcher::Allowlist(allow) = policy_resources {
                for r in &resources {
                    if !allow.contains(r) {
                        return Err(PolicyCompileError::RuleResourceWidensPolicyAllowlist {
                            policy: policy_name.to_owned(),
                            rule_id: raw.id,
                            resource: r.clone(),
                            path: path.to_path_buf(),
                        });
                    }
                }
            }
            Some(build_resource_matcher(resources))
        }
    };

    Ok(CompiledRule { id: raw.id, scope_overrides, resource_overrides, action: raw.action.into() })
}

/// Compile a policy-level `resources = [...]` into a `ResourceMatcher`,
/// rejecting mixed wildcard+explicit entries.
///
/// Callers have already verified that `raw` is non-empty.
fn compile_policy_resource_matcher(
    raw: &[String],
    policy_name: &str,
    path: &Path,
) -> Result<ResourceMatcher, PolicyCompileError> {
    reject_mixed_wildcard(raw, policy_name, path)?;
    Ok(build_resource_matcher(raw.to_vec()))
}

/// Reject `["*", "explicit"]`-style resource allowlists.
///
/// The previous implementation folded these to `All` silently,
/// discarding the explicit entries. Operators writing
/// `resources = ["*", "internal-only"]` expecting "wildcard plus
/// explicit additions" got pure wildcard and lost the narrowing
/// intent. Now it's a hard error.
fn reject_mixed_wildcard(
    raw: &[String],
    policy_name: &str,
    path: &Path,
) -> Result<(), PolicyCompileError> {
    let has_wildcard = raw.iter().any(|s| s == "*");
    if has_wildcard && raw.len() > 1 {
        return Err(PolicyCompileError::MixedWildcardAndExplicitResources {
            policy: policy_name.to_owned(),
            wildcard: "*".to_owned(),
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

/// Build a `ResourceMatcher` from a pre-validated `Vec<String>`.
///
/// Caller must have already rejected empty vecs and mixed-wildcard
/// cases. `["*"]` yields `ResourceMatcher::All`; everything else
/// becomes an `Allowlist(HashSet)`.
fn build_resource_matcher(raw: Vec<String>) -> ResourceMatcher {
    if raw.len() == 1 && raw[0] == "*" {
        ResourceMatcher::All
    } else {
        ResourceMatcher::Allowlist(raw.into_iter().collect())
    }
}

fn rule_matches(rule: &CompiledRule, policy: &CompiledPolicy, req: &EvalRequest) -> bool {
    // Compile-time invariant (enforced by `compile_one` +
    // `compile_rule`): rule overrides are subsets of the enclosing
    // policy's allowlist. This means consulting the override alone
    // is safe — there is no path where the override accepts a value
    // the policy allowlist rejects.
    let scope_match = match &rule.scope_overrides {
        Some(set) => set.contains(&req.scope),
        None => policy.scope_allowlist.contains(&req.scope),
    };
    if !scope_match {
        return false;
    }
    match &rule.resource_overrides {
        Some(matcher) => matcher.matches(req.resource.as_deref()),
        None => policy.resource_allowlist.matches(req.resource.as_deref()),
    }
}

/// Return `true` if `later` is fully shadowed by `earlier`.
///
/// A rule is fully shadowed when every request that matches the
/// later rule would also match the earlier rule — so the later
/// rule's action can never fire. We compute the effective scope and
/// resource match sets (override if present, else policy-level) and
/// check the subset relation. We do NOT flag rules that have the
/// same action as the earlier rule (redundant but not dangerous).
fn rule_is_shadowed(
    earlier: &CompiledRule,
    later: &CompiledRule,
    policy_scopes: &HashSet<String>,
    policy_resources: &ResourceMatcher,
) -> bool {
    // If actions match, shadowing is redundant but not a bug.
    if earlier.action == later.action {
        return false;
    }
    // Scopes: `None` means "inherit policy allowlist"; resolved to
    // the same set for both rules in that case.
    let earlier_scopes = earlier.scope_overrides.as_ref().unwrap_or(policy_scopes);
    let later_scopes = later.scope_overrides.as_ref().unwrap_or(policy_scopes);
    if !later_scopes.is_subset(earlier_scopes) {
        return false;
    }
    // Resources: slightly more complex because `ResourceMatcher` has
    // two variants. Use a helper that knows how to compare them.
    let earlier_res = earlier.resource_overrides.as_ref().unwrap_or(policy_resources);
    let later_res = later.resource_overrides.as_ref().unwrap_or(policy_resources);
    resource_matcher_is_subset(later_res, earlier_res)
}

/// Return `true` if every resource matched by `narrow` is also
/// matched by `wide`.
fn resource_matcher_is_subset(narrow: &ResourceMatcher, wide: &ResourceMatcher) -> bool {
    match (narrow, wide) {
        // Anything is a subset of `All`.
        (_, ResourceMatcher::All) => true,
        // `All` is only a subset of `All`.
        (ResourceMatcher::All, ResourceMatcher::Allowlist(_)) => false,
        // Allowlist ⊆ Allowlist is standard set subset.
        (ResourceMatcher::Allowlist(n), ResourceMatcher::Allowlist(w)) => n.is_subset(w),
    }
}

fn decision_from_rule_action(
    rule: &CompiledRule,
    policy: &CompiledPolicy,
    req: &EvalRequest,
) -> Decision {
    match rule.action {
        RuleAction::Allow => Decision::Allow,
        RuleAction::Prompt => {
            Decision::Prompt { policy_name: policy.name.clone(), rule_id: rule.id.clone() }
        }
        // Populate `denied_scope` / `denied_resource` from the live
        // request so operators debugging a 403 can see exactly what
        // was denied — UX-DR21 intent. Previously hardcoded to None.
        RuleAction::Deny => Decision::Deny {
            policy_name: policy.name.clone(),
            rule_id: rule.id.clone(),
            denied_scope: Some(req.scope.clone()),
            denied_resource: req.resource.clone(),
        },
    }
}

/// Structural scope-format validator.
///
/// The Dev Notes of Story 4.1 spell out the rules:
/// - non-empty, max 128 characters
/// - lowercase alphanumeric plus `.` and `-` only
/// - no leading or trailing separator
///
/// This is a hand-rolled validator (no regex) matching the style
/// established by `store::validate::validate_service_name`. Semantic
/// validation against real OAuth scopes is out of scope for Story 4.1
/// — that is Epic 2 connector territory.
fn validate_scope_format(scope: &str, policy: &str, path: &Path) -> Result<(), PolicyCompileError> {
    let invalid = || PolicyCompileError::InvalidScopeFormat {
        scope: scope.to_owned(),
        policy: policy.to_owned(),
        path: path.to_path_buf(),
    };
    if scope.is_empty() || scope.len() > MAX_SCOPE_LEN {
        return Err(invalid());
    }
    let bytes = scope.as_bytes();
    if is_separator(bytes[0]) || is_separator(bytes[bytes.len() - 1]) {
        return Err(invalid());
    }
    for &b in bytes {
        if !(b.is_ascii_lowercase() || b.is_ascii_digit() || is_separator(b)) {
            return Err(invalid());
        }
    }
    Ok(())
}

#[inline]
fn is_separator(b: u8) -> bool {
    b == b'.' || b == b'-'
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p(name: &str) -> PathBuf {
        PathBuf::from(format!("/test/{name}.toml"))
    }

    const GMAIL_READ_ONLY: &str = r#"
        [[policies]]
        name = "gmail-read-only"
        scopes = ["gmail.readonly", "gmail.metadata"]
        resources = ["*"]
        approval-mode = "auto"
    "#;

    #[test]
    fn empty_policy_set_denies_everything() {
        let set = PolicySet::empty();
        let req = EvalRequest {
            policy_name: "whatever".to_owned(),
            scope: "gmail.readonly".to_owned(),
            resource: None,
        };
        match set.evaluate(&req) {
            Decision::Deny { rule_id, .. } => {
                assert_eq!(rule_id, DEFAULT_DENY_UNMATCHED_POLICY);
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn compiles_minimal_policy() {
        let set = PolicySet::compile_from_str(GMAIL_READ_ONLY, &p("gmail")).unwrap();
        assert_eq!(set.len(), 1);
        let p = set.get("gmail-read-only").unwrap();
        assert!(p.scope_allowlist.contains("gmail.readonly"));
        assert!(p.scope_allowlist.contains("gmail.metadata"));
        assert!(matches!(p.resource_allowlist, ResourceMatcher::All));
        assert_eq!(p.approval_mode, ApprovalMode::Auto);
        assert!(p.compiled_rules.is_empty());
    }

    #[test]
    fn evaluate_allow_scope_in_allowlist() {
        let set = PolicySet::compile_from_str(GMAIL_READ_ONLY, &p("gmail")).unwrap();
        let req = EvalRequest {
            policy_name: "gmail-read-only".to_owned(),
            scope: "gmail.readonly".to_owned(),
            resource: None,
        };
        assert_eq!(set.evaluate(&req), Decision::Allow);
    }

    #[test]
    fn evaluate_deny_scope_out_of_allowlist() {
        let set = PolicySet::compile_from_str(GMAIL_READ_ONLY, &p("gmail")).unwrap();
        let req = EvalRequest {
            policy_name: "gmail-read-only".to_owned(),
            scope: "gmail.modify".to_owned(),
            resource: None,
        };
        match set.evaluate(&req) {
            Decision::Deny { rule_id, denied_scope, .. } => {
                assert_eq!(rule_id, DEFAULT_DENY_SCOPE);
                assert_eq!(denied_scope.as_deref(), Some("gmail.modify"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_deny_unmatched_policy() {
        let set = PolicySet::compile_from_str(GMAIL_READ_ONLY, &p("gmail")).unwrap();
        let req = EvalRequest {
            policy_name: "nope".to_owned(),
            scope: "gmail.readonly".to_owned(),
            resource: None,
        };
        match set.evaluate(&req) {
            Decision::Deny { rule_id, policy_name, .. } => {
                assert_eq!(rule_id, DEFAULT_DENY_UNMATCHED_POLICY);
                assert_eq!(policy_name, "nope");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_rule_deny_overrides_allow_policy() {
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["gmail.readonly", "gmail.modify"]
            resources = ["*"]
            approval-mode = "auto"

            [[policies.rules]]
            id = "deny-modify"
            scopes = ["gmail.modify"]
            action = "deny"
        "#;
        let set = PolicySet::compile_from_str(src, &p("p")).unwrap();
        let req = EvalRequest {
            policy_name: "p".to_owned(),
            scope: "gmail.modify".to_owned(),
            resource: None,
        };
        match set.evaluate(&req) {
            Decision::Deny { rule_id, .. } => assert_eq!(rule_id, "deny-modify"),
            other => panic!("expected Deny, got {other:?}"),
        }
        let allow_req = EvalRequest {
            policy_name: "p".to_owned(),
            scope: "gmail.readonly".to_owned(),
            resource: None,
        };
        assert_eq!(set.evaluate(&allow_req), Decision::Allow);
    }

    #[test]
    fn evaluate_rule_prompt() {
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["calendar.events"]
            resources = ["primary"]
            approval-mode = "auto"

            [[policies.rules]]
            id = "prompt-writes"
            action = "prompt"
        "#;
        let set = PolicySet::compile_from_str(src, &p("p")).unwrap();
        let req = EvalRequest {
            policy_name: "p".to_owned(),
            scope: "calendar.events".to_owned(),
            resource: Some("primary".to_owned()),
        };
        match set.evaluate(&req) {
            Decision::Prompt { rule_id, policy_name } => {
                assert_eq!(rule_id, "prompt-writes");
                assert_eq!(policy_name, "p");
            }
            other => panic!("expected Prompt, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_resource_out_of_allowlist() {
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["calendar.events"]
            resources = ["primary"]
            approval-mode = "auto"
        "#;
        let set = PolicySet::compile_from_str(src, &p("p")).unwrap();
        let req = EvalRequest {
            policy_name: "p".to_owned(),
            scope: "calendar.events".to_owned(),
            resource: Some("family".to_owned()),
        };
        match set.evaluate(&req) {
            Decision::Deny { rule_id, denied_resource, .. } => {
                assert_eq!(rule_id, DEFAULT_DENY_RESOURCE);
                assert_eq!(denied_resource.as_deref(), Some("family"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_policy_level_prompt_default() {
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["calendar.events"]
            resources = ["*"]
            approval-mode = "prompt"
        "#;
        let set = PolicySet::compile_from_str(src, &p("p")).unwrap();
        let req = EvalRequest {
            policy_name: "p".to_owned(),
            scope: "calendar.events".to_owned(),
            resource: None,
        };
        match set.evaluate(&req) {
            Decision::Prompt { rule_id, .. } => {
                assert_eq!(rule_id, DEFAULT_PROMPT_APPROVAL_MODE);
            }
            other => panic!("expected Prompt, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_policy_level_deny_default() {
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["calendar.events"]
            resources = ["*"]
            approval-mode = "deny"
        "#;
        let set = PolicySet::compile_from_str(src, &p("p")).unwrap();
        let req = EvalRequest {
            policy_name: "p".to_owned(),
            scope: "calendar.events".to_owned(),
            resource: None,
        };
        match set.evaluate(&req) {
            Decision::Deny { rule_id, .. } => {
                assert_eq!(rule_id, DEFAULT_DENY_APPROVAL_MODE);
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn compile_rejects_empty_scopes() {
        let src = r#"
            [[policies]]
            name = "p"
            scopes = []
            resources = ["*"]
            approval-mode = "auto"
        "#;
        let err = PolicySet::compile_from_str(src, &p("p")).unwrap_err();
        assert!(matches!(err, PolicyCompileError::EmptyScopesAllowlist { .. }));
    }

    #[test]
    fn compile_rejects_duplicate_rule_ids() {
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["x.read"]
            resources = ["*"]
            approval-mode = "auto"

            [[policies.rules]]
            id = "dup"
            action = "deny"

            [[policies.rules]]
            id = "dup"
            action = "allow"
        "#;
        let err = PolicySet::compile_from_str(src, &p("p")).unwrap_err();
        match err {
            PolicyCompileError::DuplicateRuleId { rule_id, policy, .. } => {
                assert_eq!(rule_id, "dup");
                assert_eq!(policy, "p");
            }
            other => panic!("expected DuplicateRuleId, got {other:?}"),
        }
    }

    #[test]
    fn compile_rejects_duplicate_policy_names_single_file() {
        let src = r#"
            [[policies]]
            name = "dup"
            scopes = ["x.read"]
            resources = ["*"]
            approval-mode = "auto"

            [[policies]]
            name = "dup"
            scopes = ["y.read"]
            resources = ["*"]
            approval-mode = "auto"
        "#;
        let err = PolicySet::compile_from_str(src, &p("p")).unwrap_err();
        // Intra-file duplicates use the dedicated variant so the
        // diagnostic doesn't lie about "first defined in X, redefined
        // in X" with the same path printed twice.
        match err {
            PolicyCompileError::DuplicatePolicyNameInFile { name, path } => {
                assert_eq!(name, "dup");
                assert_eq!(path, p("p"));
            }
            other => panic!("expected DuplicatePolicyNameInFile, got {other:?}"),
        }
    }

    #[test]
    fn compile_rejects_invalid_scope_format_uppercase() {
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["Gmail.Read"]
            resources = ["*"]
            approval-mode = "auto"
        "#;
        let err = PolicySet::compile_from_str(src, &p("p")).unwrap_err();
        match err {
            PolicyCompileError::InvalidScopeFormat { scope, .. } => {
                assert_eq!(scope, "Gmail.Read");
            }
            other => panic!("expected InvalidScopeFormat, got {other:?}"),
        }
    }

    #[test]
    fn compile_rejects_invalid_scope_format_leading_dot() {
        let src = r#"
            [[policies]]
            name = "p"
            scopes = [".gmail"]
            resources = ["*"]
            approval-mode = "auto"
        "#;
        let err = PolicySet::compile_from_str(src, &p("p")).unwrap_err();
        assert!(matches!(err, PolicyCompileError::InvalidScopeFormat { .. }));
    }

    #[test]
    fn compile_rejects_invalid_scope_format_too_long() {
        let long = "a".repeat(129);
        let src = format!(
            r#"
            [[policies]]
            name = "p"
            scopes = ["{long}"]
            resources = ["*"]
            approval-mode = "auto"
        "#
        );
        let err = PolicySet::compile_from_str(&src, &p("p")).unwrap_err();
        assert!(matches!(err, PolicyCompileError::InvalidScopeFormat { .. }));
    }

    #[test]
    fn compile_rejects_parse_error_reports_line_number() {
        // Unterminated string on line 5: three blank lines, then
        // `[[policies]]` on line 4, then `name = "broken` on line 5.
        // The toml-rs parser reports the span on the broken string.
        let src = "\n\n\n[[policies]]\nname = \"broken\n";
        let err = PolicySet::compile_from_str(src, &p("broken")).unwrap_err();
        match err {
            PolicyCompileError::Parse { line, .. } => {
                // The unterminated string is on line 5, so the parser
                // span should start at or after line 5. Accept 5 or
                // later (the parser may report the newline that
                // terminated the file, not the opening quote).
                let n = line.expect("expected line number from span");
                assert!(n >= 5, "expected line >= 5 (unterminated string on line 5), got {n}");
                assert!(n <= 7, "line too far past end of input ({n})");
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn compile_rejects_empty_policies_array() {
        let src = "policies = []";
        let err = PolicySet::compile_from_str(src, &p("empty")).unwrap_err();
        assert!(matches!(err, PolicyCompileError::EmptyPoliciesArray { .. }));
    }

    #[test]
    fn rule_with_resource_override_narrows_policy() {
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["calendar.events"]
            resources = ["*"]
            approval-mode = "auto"

            [[policies.rules]]
            id = "only-primary-write"
            resources = ["primary"]
            action = "prompt"
        "#;
        let set = PolicySet::compile_from_str(src, &p("p")).unwrap();
        // Request hits the override (primary) → prompt.
        let primary = EvalRequest {
            policy_name: "p".to_owned(),
            scope: "calendar.events".to_owned(),
            resource: Some("primary".to_owned()),
        };
        assert!(matches!(set.evaluate(&primary), Decision::Prompt { .. }));
        // Request misses the override (family) → falls through to policy-level
        // auto/allow because the policy-level matcher still accepts `*`.
        let family = EvalRequest {
            policy_name: "p".to_owned(),
            scope: "calendar.events".to_owned(),
            resource: Some("family".to_owned()),
        };
        assert_eq!(set.evaluate(&family), Decision::Allow);
    }

    #[test]
    fn compile_from_dir_sorts_files_and_detects_cross_file_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.toml");
        let b = dir.path().join("b.toml");
        std::fs::write(
            &a,
            r#"
                [[policies]]
                name = "dup"
                scopes = ["x.read"]
                resources = ["*"]
                approval-mode = "auto"
            "#,
        )
        .unwrap();
        std::fs::write(
            &b,
            r#"
                [[policies]]
                name = "dup"
                scopes = ["y.read"]
                resources = ["*"]
                approval-mode = "auto"
            "#,
        )
        .unwrap();
        let err = PolicySet::compile_from_dir(dir.path()).unwrap_err();
        match err {
            PolicyCompileError::DuplicatePolicyName { name, first, second } => {
                assert_eq!(name, "dup");
                assert_eq!(first, a);
                assert_eq!(second, b);
            }
            other => panic!("expected DuplicatePolicyName, got {other:?}"),
        }
    }

    #[test]
    fn compile_from_dir_reports_io_error_for_missing_dir() {
        let missing = std::path::Path::new("/this/does/not/exist/abc123");
        let err = PolicySet::compile_from_dir(missing).unwrap_err();
        assert!(matches!(err, PolicyCompileError::Io { .. }));
    }

    #[test]
    fn compile_from_dir_ignores_non_toml_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("README.md"), "# not a policy").unwrap();
        std::fs::write(
            dir.path().join("p.toml"),
            r#"
                [[policies]]
                name = "ok"
                scopes = ["x.read"]
                resources = ["*"]
                approval-mode = "auto"
            "#,
        )
        .unwrap();
        let set = PolicySet::compile_from_dir(dir.path()).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.get("ok").is_some());
    }

    #[test]
    fn byte_offset_to_line_counts_newlines() {
        assert_eq!(byte_offset_to_line("abc", 0), 1);
        assert_eq!(byte_offset_to_line("abc\ndef", 4), 2);
        assert_eq!(byte_offset_to_line("a\nb\nc", 3), 2);
        // Offset at final newline → that newline is counted → line 2.
        assert_eq!(byte_offset_to_line("a\n", 2), 2);
        // Offset past end of text is clamped.
        assert_eq!(byte_offset_to_line("abc", 999), 1);
    }

    #[test]
    fn resource_matcher_all_matches_none_resource() {
        let m = ResourceMatcher::All;
        assert!(m.matches(None));
        assert!(m.matches(Some("anything")));
    }

    #[test]
    fn resource_matcher_allowlist_does_not_match_none() {
        let m = ResourceMatcher::Allowlist(["primary".to_owned()].into_iter().collect());
        assert!(!m.matches(None));
        assert!(m.matches(Some("primary")));
        assert!(!m.matches(Some("family")));
    }

    // ---------------------------------------------------------------
    // Post-review hardening tests
    //
    // The following tests cover the fix pass applied after the
    // adversarial review on 2026-04-11:
    // - Rule scope/resource override widening (HIGH)
    // - Empty scopes/resources overrides and policy-level resources (HIGH)
    // - Mixed wildcard+explicit in resources (HIGH)
    // - Duplicate scopes in allowlist (MED)
    // - Shadow detection (MED)
    // - NotADirectory variant (MED)
    // - Dotfile / case-insensitive extension handling (MED/LOW)
    // - Rule Deny populates denied_scope/resource (MED)
    // - Policy-level deny does NOT report denied_scope (MED)
    // ---------------------------------------------------------------

    #[test]
    fn rule_scope_override_outside_policy_allowlist_is_rejected() {
        // Regression test for the HIGH-severity rule-widening bug:
        // a rule with `scopes = ["gmail.send"], action = "allow"` on
        // a policy with `scopes = ["gmail.readonly"]` used to
        // silently widen the allowlist. Now it's a hard error.
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["gmail.readonly"]
            resources = ["*"]
            approval-mode = "auto"

            [[policies.rules]]
            id = "sneak-send"
            scopes = ["gmail.send"]
            action = "allow"
        "#;
        let err = PolicySet::compile_from_str(src, &p("p")).unwrap_err();
        match err {
            PolicyCompileError::RuleScopeWidensPolicyAllowlist {
                rule_id, scope, policy, ..
            } => {
                assert_eq!(rule_id, "sneak-send");
                assert_eq!(scope, "gmail.send");
                assert_eq!(policy, "p");
            }
            other => panic!("expected RuleScopeWidensPolicyAllowlist, got {other:?}"),
        }
    }

    #[test]
    fn rule_resource_override_outside_policy_allowlist_is_rejected() {
        // Symmetric to the scope case: a rule's resource override
        // must be a subset of the policy's resource allowlist when
        // the policy is narrowed. Policy `resources = ["primary"]`
        // + rule `resources = ["family"]` is a widening bug.
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["calendar.events"]
            resources = ["primary"]
            approval-mode = "prompt"

            [[policies.rules]]
            id = "sneak-family"
            resources = ["family"]
            action = "allow"
        "#;
        let err = PolicySet::compile_from_str(src, &p("p")).unwrap_err();
        match err {
            PolicyCompileError::RuleResourceWidensPolicyAllowlist { rule_id, resource, .. } => {
                assert_eq!(rule_id, "sneak-family");
                assert_eq!(resource, "family");
            }
            other => panic!("expected RuleResourceWidensPolicyAllowlist, got {other:?}"),
        }
    }

    #[test]
    fn rule_resource_wildcard_on_narrow_policy_is_rejected() {
        // A rule saying `resources = ["*"]` on a policy narrowed to
        // an explicit list widens the effective match set from the
        // policy's few resources back to "any resource" — that's a
        // widening bug, caught by the dedicated branch.
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["calendar.events"]
            resources = ["primary"]
            approval-mode = "auto"

            [[policies.rules]]
            id = "sneak-wildcard"
            resources = ["*"]
            action = "allow"
        "#;
        let err = PolicySet::compile_from_str(src, &p("p")).unwrap_err();
        match err {
            PolicyCompileError::RuleResourceWidensPolicyAllowlist { rule_id, resource, .. } => {
                assert_eq!(rule_id, "sneak-wildcard");
                assert_eq!(resource, "*");
            }
            other => panic!("expected RuleResourceWidensPolicyAllowlist, got {other:?}"),
        }
    }

    #[test]
    fn rule_resource_wildcard_on_wildcard_policy_is_accepted() {
        // A rule saying `resources = ["*"]` on a policy that is
        // ALSO wildcard-open is a no-op, not widening — the match
        // set is unchanged. Must compile cleanly.
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["calendar.events"]
            resources = ["*"]
            approval-mode = "prompt"

            [[policies.rules]]
            id = "also-wildcard"
            resources = ["*"]
            action = "allow"
        "#;
        let set = PolicySet::compile_from_str(src, &p("p")).unwrap();
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn empty_rule_scopes_override_is_rejected() {
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["x.read"]
            resources = ["*"]
            approval-mode = "auto"

            [[policies.rules]]
            id = "dead-rule"
            scopes = []
            action = "deny"
        "#;
        let err = PolicySet::compile_from_str(src, &p("p")).unwrap_err();
        match err {
            PolicyCompileError::EmptyRuleScopesOverride { rule_id, policy, .. } => {
                assert_eq!(rule_id, "dead-rule");
                assert_eq!(policy, "p");
            }
            other => panic!("expected EmptyRuleScopesOverride, got {other:?}"),
        }
    }

    #[test]
    fn empty_rule_resources_override_is_rejected() {
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["x.read"]
            resources = ["*"]
            approval-mode = "auto"

            [[policies.rules]]
            id = "dead-rule"
            resources = []
            action = "deny"
        "#;
        let err = PolicySet::compile_from_str(src, &p("p")).unwrap_err();
        assert!(matches!(err, PolicyCompileError::EmptyRuleResourcesOverride { .. }));
    }

    #[test]
    fn empty_policy_resources_is_rejected() {
        // Symmetric to EmptyScopesAllowlist — a policy with
        // `resources = []` silently bricks itself (every request
        // falls through to default-deny-resource-out-of-allowlist).
        // Must be rejected at compile time.
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["x.read"]
            resources = []
            approval-mode = "auto"
        "#;
        let err = PolicySet::compile_from_str(src, &p("p")).unwrap_err();
        match err {
            PolicyCompileError::EmptyResourcesAllowlist { policy, .. } => {
                assert_eq!(policy, "p");
            }
            other => panic!("expected EmptyResourcesAllowlist, got {other:?}"),
        }
    }

    #[test]
    fn mixed_wildcard_and_explicit_resources_is_rejected() {
        // `resources = ["*", "internal-only"]` used to silently fold
        // to `ResourceMatcher::All`, discarding `internal-only`.
        // Now it's a hard error.
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["x.read"]
            resources = ["*", "internal-only"]
            approval-mode = "auto"
        "#;
        let err = PolicySet::compile_from_str(src, &p("p")).unwrap_err();
        match err {
            PolicyCompileError::MixedWildcardAndExplicitResources { policy, wildcard, .. } => {
                assert_eq!(policy, "p");
                assert_eq!(wildcard, "*");
            }
            other => panic!("expected MixedWildcardAndExplicitResources, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_scope_in_allowlist_is_rejected() {
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["gmail.readonly", "gmail.readonly"]
            resources = ["*"]
            approval-mode = "auto"
        "#;
        let err = PolicySet::compile_from_str(src, &p("p")).unwrap_err();
        match err {
            PolicyCompileError::DuplicateScopeInAllowlist { scope, policy, .. } => {
                assert_eq!(scope, "gmail.readonly");
                assert_eq!(policy, "p");
            }
            other => panic!("expected DuplicateScopeInAllowlist, got {other:?}"),
        }
    }

    #[test]
    fn shadowed_later_rule_is_rejected() {
        // The first rule allows every request against `x.read`. The
        // second rule tries to deny the same scope — but it can
        // never fire because the first rule always matches first.
        // Without shadow detection this compiles silently and the
        // operator thinks `x.read` is denied while it is actually
        // allowed.
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["x.read"]
            resources = ["*"]
            approval-mode = "auto"

            [[policies.rules]]
            id = "allow-read"
            action = "allow"

            [[policies.rules]]
            id = "deny-read"
            action = "deny"
        "#;
        let err = PolicySet::compile_from_str(src, &p("p")).unwrap_err();
        match err {
            PolicyCompileError::ShadowedRule { earlier_rule_id, later_rule_id, policy, .. } => {
                assert_eq!(earlier_rule_id, "allow-read");
                assert_eq!(later_rule_id, "deny-read");
                assert_eq!(policy, "p");
            }
            other => panic!("expected ShadowedRule, got {other:?}"),
        }
    }

    #[test]
    fn non_shadowed_later_rule_is_accepted() {
        // Two rules with disjoint scope overrides — the later rule
        // is NOT shadowed because its match set doesn't intersect
        // the earlier rule's.
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["x.read", "x.write"]
            resources = ["*"]
            approval-mode = "auto"

            [[policies.rules]]
            id = "allow-read"
            scopes = ["x.read"]
            action = "allow"

            [[policies.rules]]
            id = "deny-write"
            scopes = ["x.write"]
            action = "deny"
        "#;
        let set = PolicySet::compile_from_str(src, &p("p")).unwrap();
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn same_action_rules_not_flagged_as_shadow() {
        // Two rules with the same action are redundant but not
        // dangerous — explicitly allowed to compile.
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["x.read"]
            resources = ["*"]
            approval-mode = "auto"

            [[policies.rules]]
            id = "deny-a"
            action = "deny"

            [[policies.rules]]
            id = "deny-b"
            action = "deny"
        "#;
        let set = PolicySet::compile_from_str(src, &p("p")).unwrap();
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn not_a_directory_for_regular_file_path() {
        let tmp = tempfile::tempdir().unwrap();
        let not_a_dir = tmp.path().join("i-am-a-file.toml");
        std::fs::write(&not_a_dir, "").unwrap();
        let err = PolicySet::compile_from_dir(&not_a_dir).unwrap_err();
        match err {
            PolicyCompileError::NotADirectory { path } => {
                assert_eq!(path, not_a_dir);
            }
            other => panic!("expected NotADirectory, got {other:?}"),
        }
    }

    #[test]
    fn compile_from_dir_skips_dotfiles_and_editor_lockfiles() {
        // Emacs lockfile names like `.#default.toml` match the TOML
        // extension but are not valid TOML and must not be compiled.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".#default.toml"),
            "this is not valid TOML — emacs lockfile",
        )
        .unwrap();
        std::fs::write(dir.path().join(".hidden.toml"), "not valid TOML either").unwrap();
        std::fs::write(
            dir.path().join("real.toml"),
            r#"
                [[policies]]
                name = "real"
                scopes = ["x.read"]
                resources = ["*"]
                approval-mode = "auto"
            "#,
        )
        .unwrap();
        let set = PolicySet::compile_from_dir(dir.path()).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.get("real").is_some());
    }

    #[test]
    fn compile_from_dir_accepts_uppercase_extension() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("uppercase.TOML"),
            r#"
                [[policies]]
                name = "ok"
                scopes = ["x.read"]
                resources = ["*"]
                approval-mode = "auto"
            "#,
        )
        .unwrap();
        let set = PolicySet::compile_from_dir(dir.path()).unwrap();
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn rule_deny_populates_denied_scope_and_resource() {
        // Regression test for the MED finding that `decision_from_rule_action`
        // hardcoded `denied_scope: None, denied_resource: None`.
        // Explicit rule denies should surface the live request values.
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["calendar.events"]
            resources = ["primary"]
            approval-mode = "auto"

            [[policies.rules]]
            id = "deny-writes"
            action = "deny"
        "#;
        let set = PolicySet::compile_from_str(src, &p("p")).unwrap();
        let req = EvalRequest {
            policy_name: "p".to_owned(),
            scope: "calendar.events".to_owned(),
            resource: Some("primary".to_owned()),
        };
        match set.evaluate(&req) {
            Decision::Deny { rule_id, denied_scope, denied_resource, .. } => {
                assert_eq!(rule_id, "deny-writes");
                assert_eq!(denied_scope.as_deref(), Some("calendar.events"));
                assert_eq!(denied_resource.as_deref(), Some("primary"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_level_deny_does_not_report_denied_scope() {
        // Regression test for the MED finding that the
        // approval-mode = "deny" fallthrough was reporting
        // `denied_scope: Some(req.scope)` even though the scope
        // WAS in the allowlist. Now reports None because the
        // denial is policy-wide, not scope-specific.
        let src = r#"
            [[policies]]
            name = "p"
            scopes = ["calendar.events"]
            resources = ["*"]
            approval-mode = "deny"
        "#;
        let set = PolicySet::compile_from_str(src, &p("p")).unwrap();
        let req = EvalRequest {
            policy_name: "p".to_owned(),
            scope: "calendar.events".to_owned(),
            resource: Some("primary".to_owned()),
        };
        match set.evaluate(&req) {
            Decision::Deny { rule_id, denied_scope, denied_resource, .. } => {
                assert_eq!(rule_id, DEFAULT_DENY_APPROVAL_MODE);
                assert_eq!(denied_scope, None, "scope was allowlisted — denial is policy-wide");
                assert_eq!(denied_resource, None);
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    // -- PolicySet::diff tests --

    #[test]
    fn diff_empty_to_populated_reports_all_added() {
        let old = PolicySet::empty();
        let new = PolicySet::compile_from_str(GMAIL_READ_ONLY, &p("g")).unwrap();
        let diff = new.diff(&old);
        assert_eq!(diff.policies_loaded, 1);
        assert_eq!(diff.added, vec!["gmail-read-only"]);
        assert!(diff.modified.is_empty());
        assert!(diff.unchanged.is_empty());
        assert!(diff.removed.is_empty());
    }

    #[test]
    fn diff_populated_to_empty_reports_all_removed() {
        let old = PolicySet::compile_from_str(GMAIL_READ_ONLY, &p("g")).unwrap();
        let new = PolicySet::empty();
        let diff = new.diff(&old);
        assert_eq!(diff.policies_loaded, 0);
        assert!(diff.added.is_empty());
        assert!(diff.modified.is_empty());
        assert!(diff.unchanged.is_empty());
        assert_eq!(diff.removed, vec!["gmail-read-only"]);
    }

    #[test]
    fn diff_same_reports_all_unchanged() {
        let a = PolicySet::compile_from_str(GMAIL_READ_ONLY, &p("g")).unwrap();
        let b = PolicySet::compile_from_str(GMAIL_READ_ONLY, &p("g")).unwrap();
        let diff = b.diff(&a);
        assert_eq!(diff.policies_loaded, 1);
        assert!(diff.added.is_empty());
        assert!(diff.modified.is_empty());
        assert_eq!(diff.unchanged, vec!["gmail-read-only"]);
        assert!(diff.removed.is_empty());
    }

    #[test]
    fn diff_modified_scope_detected() {
        let old = PolicySet::compile_from_str(GMAIL_READ_ONLY, &p("g")).unwrap();
        // Change the scope allowlist.
        let src = r#"
            [[policies]]
            name = "gmail-read-only"
            scopes = ["gmail.readonly", "gmail.metadata", "gmail.labels"]
            resources = ["*"]
            approval-mode = "auto"
        "#;
        let new = PolicySet::compile_from_str(src, &p("g")).unwrap();
        let diff = new.diff(&old);
        assert_eq!(diff.modified, vec!["gmail-read-only"]);
        assert!(diff.added.is_empty());
        assert!(diff.unchanged.is_empty());
    }

    #[test]
    fn diff_mixed_add_modify_remove() {
        let old_src = r#"
            [[policies]]
            name = "kept-same"
            scopes = ["x.read"]
            resources = ["*"]
            approval-mode = "auto"

            [[policies]]
            name = "will-change"
            scopes = ["y.read"]
            resources = ["*"]
            approval-mode = "auto"

            [[policies]]
            name = "will-remove"
            scopes = ["z.read"]
            resources = ["*"]
            approval-mode = "auto"
        "#;
        let new_src = r#"
            [[policies]]
            name = "kept-same"
            scopes = ["x.read"]
            resources = ["*"]
            approval-mode = "auto"

            [[policies]]
            name = "will-change"
            scopes = ["y.read", "y.write"]
            resources = ["*"]
            approval-mode = "prompt"

            [[policies]]
            name = "brand-new"
            scopes = ["w.read"]
            resources = ["*"]
            approval-mode = "auto"
        "#;
        let old = PolicySet::compile_from_str(old_src, &p("old")).unwrap();
        let new = PolicySet::compile_from_str(new_src, &p("new")).unwrap();
        let diff = new.diff(&old);
        assert_eq!(diff.policies_loaded, 3);
        assert_eq!(diff.added, vec!["brand-new"]);
        assert_eq!(diff.modified, vec!["will-change"]);
        assert_eq!(diff.unchanged, vec!["kept-same"]);
        assert_eq!(diff.removed, vec!["will-remove"]);
    }

    // ── Story 4.5: CompiledPolicy::is_readonly_scope ───────────────

    /// Build a minimal `CompiledPolicy` for the read-scope classifier
    /// tests. The classifier never reads any other field so the
    /// defaults are fine.
    fn make_test_policy() -> CompiledPolicy {
        CompiledPolicy {
            name: "test".to_owned(),
            scope_allowlist: HashSet::new(),
            resource_allowlist: ResourceMatcher::All,
            approval_mode: ApprovalMode::Prompt,
            compiled_rules: Vec::new(),
            auto_approve_reads: true,
        }
    }

    #[test]
    fn is_readonly_scope_matches_google_readonly_suffixes() {
        let p = make_test_policy();
        assert!(p.is_readonly_scope("gmail.readonly"));
        assert!(p.is_readonly_scope("gmail.metadata"));
        assert!(p.is_readonly_scope("calendar.readonly"));
        assert!(p.is_readonly_scope("drive.readonly"));
        assert!(p.is_readonly_scope("drive.metadata"));
    }

    #[test]
    fn is_readonly_scope_rejects_write_scopes() {
        let p = make_test_policy();
        assert!(!p.is_readonly_scope("gmail.modify"));
        assert!(!p.is_readonly_scope("gmail.send"));
        assert!(!p.is_readonly_scope("calendar.events"));
        assert!(!p.is_readonly_scope("drive.file"));
    }

    #[test]
    fn is_readonly_scope_rejects_service_name_alone() {
        let p = make_test_policy();
        // No suffix — just a service name — is not a scope.
        assert!(!p.is_readonly_scope("gmail"));
        assert!(!p.is_readonly_scope("calendar"));
    }

    #[test]
    fn is_readonly_scope_rejects_empty_and_bare_suffix() {
        let p = make_test_policy();
        assert!(!p.is_readonly_scope(""));
        // Bare suffix (no service prefix) is degenerate input; reject.
        assert!(!p.is_readonly_scope(".readonly"));
        assert!(!p.is_readonly_scope(".metadata"));
    }

    #[test]
    fn is_readonly_scope_accepts_user_defined_service_with_convention() {
        // User-defined scopes that follow the convention work too.
        let p = make_test_policy();
        assert!(p.is_readonly_scope("my-service.readonly"));
        assert!(p.is_readonly_scope("internal-api.metadata"));
    }

    #[test]
    fn is_readonly_scope_is_case_sensitive() {
        // OAuth scopes are case-sensitive; uppercase does not match.
        let p = make_test_policy();
        assert!(!p.is_readonly_scope("gmail.READONLY"));
        assert!(!p.is_readonly_scope("Gmail.Readonly"));
    }

    // ----- Story 8.4 AC #4: BOM detection -----

    #[test]
    fn compile_from_file_bom_returns_bom_detected_error() {
        let tmp = tempfile::tempdir().unwrap();
        // UTF-8 BOM prefix (\xEF\xBB\xBF) followed by valid TOML content.
        let bom_toml = "\u{feff}[[policies]]\nname = \"p\"\nscopes = [\"gmail.readonly\"]\nresources = [\"*\"]\napproval-mode = \"auto\"\n";
        let policy_path = tmp.path().join("bom_policy.toml");
        std::fs::write(&policy_path, bom_toml.as_bytes()).unwrap();

        let err = PolicySet::compile_from_dir(tmp.path()).unwrap_err();
        assert!(
            matches!(err, PolicyCompileError::BomDetected { .. }),
            "expected BomDetected error, got: {err:?}"
        );
        if let PolicyCompileError::BomDetected { path } = err {
            assert_eq!(path, policy_path, "BomDetected path should point at the BOM file");
        }
    }

    #[test]
    fn compile_from_str_bom_returns_bom_detected_error() {
        let bom_toml = "\u{feff}[[policies]]\nname = \"p\"\nscopes = [\"gmail.readonly\"]\nresources = [\"*\"]\napproval-mode = \"auto\"\n";
        let origin = std::path::Path::new("inline.toml");
        let err = PolicySet::compile_from_str(bom_toml, origin).unwrap_err();
        assert!(
            matches!(err, PolicyCompileError::BomDetected { .. }),
            "expected BomDetected error from compile_from_str, got: {err:?}"
        );
    }

    // Story 7.34: origin tracking and reverse serialization tests.

    #[test]
    fn compile_from_str_tracks_origin() {
        let origin = std::path::Path::new("/test/a.toml");
        let set = PolicySet::compile_from_str(GMAIL_READ_ONLY, origin).unwrap();
        assert_eq!(set.origin("gmail-read-only"), Some(&origin.to_path_buf()));
    }

    #[test]
    fn compile_from_str_multi_policy_tracks_each_origin() {
        let src = r#"
            [[policies]]
            name = "p1"
            scopes = ["a"]
            resources = ["*"]
            approval-mode = "auto"

            [[policies]]
            name = "p2"
            scopes = ["b"]
            resources = ["*"]
            approval-mode = "auto"
        "#;
        let origin = std::path::Path::new("/test/default.toml");
        let set = PolicySet::compile_from_str(src, origin).unwrap();
        assert_eq!(set.origin("p1"), Some(&origin.to_path_buf()));
        assert_eq!(set.origin("p2"), Some(&origin.to_path_buf()));
    }

    #[test]
    fn to_toml_policy_round_trip() {
        let origin = std::path::Path::new("/test/a.toml");
        let set = PolicySet::compile_from_str(GMAIL_READ_ONLY, origin).unwrap();
        let compiled = set.get("gmail-read-only").unwrap();
        let toml = compiled.to_toml_policy();
        assert_eq!(toml.name, "gmail-read-only");
        assert_eq!(toml.scopes, vec!["gmail.metadata", "gmail.readonly"]);
        assert_eq!(toml.resources, vec!["*"]);
        assert_eq!(toml.approval_mode, super::super::schema::TomlApprovalMode::Auto);
        assert!(!toml.auto_approve_reads);
    }

    #[test]
    fn to_toml_policy_with_rules_round_trip() {
        let src = r#"
            [[policies]]
            name = "calendar-prompt"
            scopes = ["calendar.readonly", "calendar.events"]
            resources = ["primary"]
            approval-mode = "prompt"
            auto-approve-reads = true

            [[policies.rules]]
            id = "allow-reads"
            scopes = ["calendar.readonly"]
            action = "allow"

            [[policies.rules]]
            id = "deny-deletes"
            action = "deny"
        "#;
        let set = PolicySet::compile_from_str(src, &p("c")).unwrap();
        let compiled = set.get("calendar-prompt").unwrap();
        let toml = compiled.to_toml_policy();
        assert_eq!(toml.name, "calendar-prompt");
        assert_eq!(toml.approval_mode, super::super::schema::TomlApprovalMode::Prompt);
        assert!(toml.auto_approve_reads);
        assert_eq!(toml.rules.len(), 2);
        assert_eq!(toml.rules[0].id, "allow-reads");
        assert_eq!(toml.rules[0].scopes, Some(vec!["calendar.readonly".to_owned()]));
        assert_eq!(toml.rules[0].action, super::super::schema::TomlRuleAction::Allow);
        assert_eq!(toml.rules[1].id, "deny-deletes");
        assert_eq!(toml.rules[1].scopes, None);
        assert_eq!(toml.rules[1].resources, None);
        assert_eq!(toml.rules[1].action, super::super::schema::TomlRuleAction::Deny);
    }

    // ── Story 9.4: per-service tier templates ────────────────────────

    /// The shipped test fixture (`test-fixtures/policies/default.toml`)
    /// and the bundled seed (`default_policy.toml`) after Epic 9.
    const FIXTURE_DEFAULT_TOML: &str =
        include_str!("../../../../test-fixtures/policies/default.toml");
    const BUNDLED_DEFAULT_TOML: &str =
        include_str!("../../../permitlayer-daemon/src/cli/default_policy.toml");

    /// AC #5/#6: the shipped fixture compiles and contains exactly the
    /// 3 original + 6 Epic-9 per-service tier policies = 9.
    #[test]
    fn epic9_default_toml_compiles_with_all_policies() {
        let set = PolicySet::compile_from_str(FIXTURE_DEFAULT_TOML, &p("default.toml"))
            .expect("expanded default.toml must compile");
        for name in [
            "gmail-read-only",
            "calendar-prompt-on-write",
            "drive-research-scope-restricted",
            "gmail-read-write",
            "calendar-read-only",
            "calendar-read-write",
            "drive-read-only",
            "drive-read-write",
            "gmail-read-only-tier",
        ] {
            assert!(set.get(name).is_some(), "policy {name} must be present");
        }
        assert_eq!(set.len(), 9, "expected exactly 9 policies in the shipped default.toml");
    }

    /// AC #2: every `{svc}-read-only` tier denies its service's write
    /// scope via the compile-time allowlist (default-deny).
    #[test]
    fn epic9_read_only_tiers_deny_writes() {
        let set = PolicySet::compile_from_str(FIXTURE_DEFAULT_TOML, &p("default.toml")).unwrap();
        for (policy, write_scope) in [
            ("calendar-read-only", "calendar.events"),
            ("drive-read-only", "drive.file"),
            ("gmail-read-only-tier", "gmail.modify"),
        ] {
            let req = EvalRequest {
                policy_name: policy.to_owned(),
                scope: write_scope.to_owned(),
                resource: Some("anything".to_owned()),
            };
            match set.evaluate(&req) {
                Decision::Deny { rule_id, .. } => {
                    assert_eq!(
                        rule_id, DEFAULT_DENY_SCOPE,
                        "{policy} must default-deny {write_scope}"
                    );
                }
                other => panic!("{policy}+{write_scope}: expected Deny, got {other:?}"),
            }
        }
    }

    /// AC #3: every `{svc}-read-write` tier ALLOWS a representative read
    /// scope and PROMPTS a representative write scope (prompt-on-write
    /// default posture — the charter's hard requirement).
    #[test]
    fn epic9_read_write_tiers_allow_reads_prompt_writes() {
        let set = PolicySet::compile_from_str(FIXTURE_DEFAULT_TOML, &p("default.toml")).unwrap();
        // (policy, read_scope, write_scope, expected prompt rule id)
        let cases = [
            ("gmail-read-write", "gmail.readonly", "gmail.send", "prompt-gmail-writes"),
            ("gmail-read-write", "gmail.metadata", "gmail.modify", "prompt-gmail-writes"),
            (
                "calendar-read-write",
                "calendar.readonly",
                "calendar.events",
                "prompt-calendar-writes",
            ),
            ("drive-read-write", "drive.readonly", "drive.file", "prompt-drive-writes"),
        ];
        for (policy, read_scope, write_scope, prompt_rule) in cases {
            let read_req = EvalRequest {
                policy_name: policy.to_owned(),
                scope: read_scope.to_owned(),
                resource: Some("anything".to_owned()),
            };
            assert!(
                matches!(set.evaluate(&read_req), Decision::Allow),
                "{policy}: read scope {read_scope} must be allowed (auto-approved)"
            );
            let write_req = EvalRequest {
                policy_name: policy.to_owned(),
                scope: write_scope.to_owned(),
                resource: Some("anything".to_owned()),
            };
            match set.evaluate(&write_req) {
                Decision::Prompt { rule_id, policy_name } => {
                    assert_eq!(rule_id, prompt_rule, "{policy} write must hit {prompt_rule}");
                    assert_eq!(policy_name, policy);
                }
                other => {
                    panic!("{policy}+{write_scope}: expected Prompt, got {other:?}")
                }
            }
        }
    }

    /// AC #6: the bundled seed and the test fixture have IDENTICAL
    /// policy definitions (comments may differ). This closes the
    /// silent-drift risk — a different security posture shipping in the
    /// binary than the tests verify. Compares the compiled
    /// `to_toml_policy()` of every policy in both files.
    #[test]
    fn epic9_bundled_and_fixture_policy_sets_are_identical() {
        let fixture =
            PolicySet::compile_from_str(FIXTURE_DEFAULT_TOML, &p("fixture.toml")).unwrap();
        let bundled =
            PolicySet::compile_from_str(BUNDLED_DEFAULT_TOML, &p("bundled.toml")).unwrap();
        let names = [
            "gmail-read-only",
            "calendar-prompt-on-write",
            "drive-research-scope-restricted",
            "gmail-read-write",
            "calendar-read-only",
            "calendar-read-write",
            "drive-read-only",
            "drive-read-write",
            "gmail-read-only-tier",
        ];
        for name in names {
            let f = fixture
                .get(name)
                .unwrap_or_else(|| panic!("fixture missing {name}"))
                .to_toml_policy();
            let b = bundled
                .get(name)
                .unwrap_or_else(|| panic!("bundled missing {name}"))
                .to_toml_policy();
            assert_eq!(f.name, b.name, "{name}: name");
            assert_eq!(f.scopes, b.scopes, "{name}: scopes drifted between the two files");
            assert_eq!(f.resources, b.resources, "{name}: resources drifted");
            assert_eq!(f.approval_mode, b.approval_mode, "{name}: approval-mode drifted");
            assert_eq!(
                f.auto_approve_reads, b.auto_approve_reads,
                "{name}: auto-approve-reads drifted"
            );
            assert_eq!(f.rules.len(), b.rules.len(), "{name}: rule count drifted");
            for (fr, br) in f.rules.iter().zip(b.rules.iter()) {
                assert_eq!(fr.id, br.id, "{name}: rule id drifted");
                assert_eq!(fr.scopes, br.scopes, "{name}: rule {} scopes drifted", fr.id);
                assert_eq!(fr.action, br.action, "{name}: rule {} action drifted", fr.id);
            }
        }
        // And neither file silently grew/shrank relative to the other.
        // Count actual `[[policies]]` TOML table headers (a trimmed
        // line equal to the header), NOT raw substring occurrences —
        // the latter also matches the literal "[[policies]]" inside
        // explanatory comments, which is not a policy and differs
        // between the two files by design (the bundled file has more
        // prose). This is the real invariant: equal table-header count.
        let header_count = |s: &str| s.lines().filter(|l| l.trim() == "[[policies]]").count();
        let fixture_n = header_count(FIXTURE_DEFAULT_TOML);
        assert_eq!(
            fixture_n,
            header_count(BUNDLED_DEFAULT_TOML),
            "the two default-policy files have a different number of [[policies]] blocks"
        );
        // Cross-check: the header count must match the compiled
        // policy-set size we just walked, so a stray header (or a
        // commented-out block) can't pass silently.
        assert_eq!(
            fixture_n,
            names.len(),
            "[[policies]] header count must equal the {} policies the test enumerates",
            names.len()
        );
    }

    /// UX-overhaul Story 1 — the **actual** by-construction guard
    /// against the `angie-*` incident class (an autonomous-write
    /// policy leaking into the shipped product seed).
    ///
    /// Invariant: NO policy in the embedded/bundled default policy
    /// set may have `approval-mode = "auto"` together with ANY write
    /// scope in its scope allowlist. A policy that auto-approves AND
    /// allows a write scope can send mail / mutate calendars /
    /// delete Drive files with zero human gate — exactly the posture
    /// `feedback_no_operator_config_in_shipped_defaults` exists to
    /// prevent. This test is CI-blocking: it fails the build if such
    /// a policy is ever (re-)introduced into `cli/default_policy.toml`
    /// or `test-fixtures/policies/default.toml`.
    ///
    /// The write-scope set is the Google Workspace mutation surface
    /// permitlayer brokers. A future connector adding a write scope
    /// MUST extend this list in the same change (the CODEOWNERS gate
    /// on the two policy files forces that review).
    #[test]
    fn bundled_seed_has_no_auto_approve_with_write_scope() {
        // Any scope whose grant lets the agent MUTATE user data with
        // no human approval when the policy is `approval-mode=auto`.
        const WRITE_SCOPES: &[&str] =
            &["gmail.send", "gmail.compose", "gmail.modify", "calendar.events", "drive.file"];
        // Scope strings in policies are frequently fully-qualified
        // Google OAuth URLs (e.g.
        // `https://www.googleapis.com/auth/gmail.send`); match by
        // suffix so both the short form and the URL form are caught.
        let is_write_scope = |scope: &str| {
            WRITE_SCOPES.iter().any(|w| scope == *w || scope.ends_with(&format!("/{w}")))
        };

        for (label, src) in [("bundled", BUNDLED_DEFAULT_TOML), ("fixture", FIXTURE_DEFAULT_TOML)] {
            let set = PolicySet::compile_from_str(src, &p("default.toml"))
                .unwrap_or_else(|e| panic!("{label} default policy must compile: {e:?}"));
            for name in set.policy_names() {
                let pol = set.get(&name).expect("named policy present");
                if pol.approval_mode != ApprovalMode::Auto {
                    continue;
                }
                let offending: Vec<&String> =
                    pol.scope_allowlist.iter().filter(|s| is_write_scope(s)).collect();
                assert!(
                    offending.is_empty(),
                    "{label} default policy {name:?} has approval-mode=auto AND write \
                     scope(s) {offending:?} — an autonomous-write policy must NEVER ship \
                     in the product seed (the angie-* incident class). Move operator-\
                     specific autonomous-write tiers to host-local operator policy."
                );
            }
        }
    }

    // ── UX-overhaul Story 1: two-layer compile ──────────────────────

    /// Write `contents` to `<dir>/<name>.toml`, creating `dir`.
    fn write_policy_file(dir: &Path, name: &str, contents: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(format!("{name}.toml")), contents).unwrap();
    }

    const MANAGED_GMAIL_RO: &str = r#"
        [[policies]]
        name = "gmail-read-only"
        scopes = ["gmail.readonly"]
        resources = ["*"]
        approval-mode = "auto"
    "#;

    #[test]
    fn layers_merge_managed_and_operator_disjoint_names() {
        let tmp = tempfile::tempdir().unwrap();
        let managed = tmp.path().join("policies-managed");
        let operator = tmp.path().join("policies");
        write_policy_file(&managed, "default", MANAGED_GMAIL_RO);
        write_policy_file(
            &operator,
            "ops",
            r#"
            [[policies]]
            name = "ops-calendar"
            scopes = ["calendar.readonly"]
            resources = ["*"]
            approval-mode = "prompt"
            "#,
        );
        let set = PolicySet::compile_from_layers(Some(&managed), &operator).unwrap();
        assert!(set.get("gmail-read-only").is_some(), "managed policy present");
        assert!(set.get("ops-calendar").is_some(), "operator policy present");
        assert!(set.accepted_overrides().is_empty(), "no overrides for disjoint names");
        // Origin tracks the actual file each came from.
        assert!(set.origin("gmail-read-only").unwrap().ends_with("default.toml"));
        assert!(set.origin("ops-calendar").unwrap().ends_with("ops.toml"));
    }

    #[test]
    fn unmarked_cross_layer_collision_is_fatal() {
        let tmp = tempfile::tempdir().unwrap();
        let managed = tmp.path().join("policies-managed");
        let operator = tmp.path().join("policies");
        write_policy_file(&managed, "default", MANAGED_GMAIL_RO);
        // Same name, NO override marker → fail-closed.
        write_policy_file(
            &operator,
            "shadow",
            r#"
            [[policies]]
            name = "gmail-read-only"
            scopes = ["gmail.send"]
            resources = ["*"]
            approval-mode = "auto"
            "#,
        );
        let err = PolicySet::compile_from_layers(Some(&managed), &operator).unwrap_err();
        match err {
            PolicyCompileError::UnmarkedCrossLayerOverride { name, .. } => {
                assert_eq!(name, "gmail-read-only");
            }
            other => panic!("expected UnmarkedCrossLayerOverride, got {other:?}"),
        }
    }

    #[test]
    fn marked_override_wins_and_is_recorded() {
        let tmp = tempfile::tempdir().unwrap();
        let managed = tmp.path().join("policies-managed");
        let operator = tmp.path().join("policies");
        write_policy_file(&managed, "default", MANAGED_GMAIL_RO);
        write_policy_file(
            &operator,
            "shadow",
            r#"
            [[policies]]
            name = "gmail-read-only"
            override = "gmail-read-only"
            scopes = ["gmail.readonly", "gmail.metadata"]
            resources = ["primary"]
            approval-mode = "prompt"
            "#,
        );
        let set = PolicySet::compile_from_layers(Some(&managed), &operator).unwrap();
        // Operator definition fully REPLACES the managed one:
        // approval-mode is now the operator's `prompt`, not the
        // managed `auto`.
        let pol = set.get("gmail-read-only").expect("present");
        assert_eq!(pol.approval_mode, ApprovalMode::Prompt);
        // Origin points at the OPERATOR file (the winning def).
        assert!(set.origin("gmail-read-only").unwrap().ends_with("shadow.toml"));
        // Exactly one accepted override, recorded with both paths.
        let ov = set.accepted_overrides();
        assert_eq!(ov.len(), 1);
        assert_eq!(ov[0].name, "gmail-read-only");
        assert!(ov[0].managed_path.ends_with("default.toml"));
        assert!(ov[0].operator_path.ends_with("shadow.toml"));
    }

    #[test]
    fn override_marker_must_equal_own_name() {
        let tmp = tempfile::tempdir().unwrap();
        let managed = tmp.path().join("policies-managed");
        let operator = tmp.path().join("policies");
        write_policy_file(&managed, "default", MANAGED_GMAIL_RO);
        // Marker names a DIFFERENT policy than this one → dangling.
        write_policy_file(
            &operator,
            "shadow",
            r#"
            [[policies]]
            name = "gmail-read-only"
            override = "some-other-policy"
            scopes = ["gmail.readonly"]
            resources = ["*"]
            approval-mode = "prompt"
            "#,
        );
        let err = PolicySet::compile_from_layers(Some(&managed), &operator).unwrap_err();
        assert!(
            matches!(err, PolicyCompileError::DanglingOverrideMarker { .. }),
            "expected DanglingOverrideMarker, got {err:?}"
        );
    }

    #[test]
    fn override_marker_with_no_managed_target_is_dangling() {
        let tmp = tempfile::tempdir().unwrap();
        let managed = tmp.path().join("policies-managed");
        let operator = tmp.path().join("policies");
        write_policy_file(&managed, "default", MANAGED_GMAIL_RO);
        // override = own name, but NO managed policy of that name.
        write_policy_file(
            &operator,
            "ops",
            r#"
            [[policies]]
            name = "not-in-managed"
            override = "not-in-managed"
            scopes = ["calendar.readonly"]
            resources = ["*"]
            approval-mode = "prompt"
            "#,
        );
        let err = PolicySet::compile_from_layers(Some(&managed), &operator).unwrap_err();
        match err {
            PolicyCompileError::DanglingOverrideMarker { name, target, .. } => {
                assert_eq!(name, "not-in-managed");
                assert_eq!(target, "not-in-managed");
            }
            other => panic!("expected DanglingOverrideMarker, got {other:?}"),
        }
    }

    #[test]
    fn override_marker_in_managed_layer_is_fatal() {
        let tmp = tempfile::tempdir().unwrap();
        let managed = tmp.path().join("policies-managed");
        let operator = tmp.path().join("policies");
        // The PRODUCT bundle must never override anything.
        write_policy_file(
            &managed,
            "default",
            r#"
            [[policies]]
            name = "gmail-read-only"
            override = "gmail-read-only"
            scopes = ["gmail.readonly"]
            resources = ["*"]
            approval-mode = "auto"
            "#,
        );
        std::fs::create_dir_all(&operator).unwrap();
        let err = PolicySet::compile_from_layers(Some(&managed), &operator).unwrap_err();
        assert!(
            matches!(err, PolicyCompileError::OverrideMarkerInManagedLayer { .. }),
            "expected OverrideMarkerInManagedLayer, got {err:?}"
        );
    }

    #[test]
    fn intra_operator_layer_duplicate_name_still_fatal() {
        let tmp = tempfile::tempdir().unwrap();
        let managed = tmp.path().join("policies-managed");
        let operator = tmp.path().join("policies");
        write_policy_file(&managed, "default", MANAGED_GMAIL_RO);
        write_policy_file(
            &operator,
            "a",
            r#"
            [[policies]]
            name = "dup"
            scopes = ["calendar.readonly"]
            resources = ["*"]
            approval-mode = "prompt"
            "#,
        );
        write_policy_file(
            &operator,
            "b",
            r#"
            [[policies]]
            name = "dup"
            scopes = ["drive.readonly"]
            resources = ["*"]
            approval-mode = "prompt"
            "#,
        );
        let err = PolicySet::compile_from_layers(Some(&managed), &operator).unwrap_err();
        assert!(
            matches!(err, PolicyCompileError::DuplicatePolicyName { .. }),
            "expected DuplicatePolicyName, got {err:?}"
        );
    }

    #[test]
    fn compile_from_dir_is_single_layer_equivalent() {
        // Back-compat: compile_from_dir == compile_from_layers(None, dir).
        let tmp = tempfile::tempdir().unwrap();
        let operator = tmp.path().join("policies");
        write_policy_file(&operator, "p", MANAGED_GMAIL_RO);
        let via_dir = PolicySet::compile_from_dir(&operator).unwrap();
        let via_layers = PolicySet::compile_from_layers(None, &operator).unwrap();
        assert_eq!(via_dir.policy_names().len(), via_layers.policy_names().len());
        assert!(via_dir.get("gmail-read-only").is_some());
        assert!(via_layers.accepted_overrides().is_empty());
    }

    #[test]
    fn empty_operator_layer_yields_only_managed() {
        let tmp = tempfile::tempdir().unwrap();
        let managed = tmp.path().join("policies-managed");
        let operator = tmp.path().join("policies");
        write_policy_file(&managed, "default", MANAGED_GMAIL_RO);
        std::fs::create_dir_all(&operator).unwrap(); // empty operator dir
        let set = PolicySet::compile_from_layers(Some(&managed), &operator).unwrap();
        assert_eq!(set.policy_names(), vec!["gmail-read-only".to_owned()]);
        assert!(set.accepted_overrides().is_empty());
    }
}
