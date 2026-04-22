//! Validate that credential types declare no forbidden derives and do
//! declare `ZeroizeOnDrop`.
//!
//! Enforces security invariants required by Story 1.1 AC #3. The policed
//! types are:
//!
//! - `SealedCredential`
//! - `OAuthToken`
//! - `OAuthRefreshToken`
//! - `AgentBearerToken`
//!
//! For each policed type the validator parses every `.rs` file in the
//! credential crate source via [`syn::parse_file`], walks the AST looking
//! for matching `ItemStruct`s, and verifies:
//!
//! 1. The set of `#[derive(...)]` traits includes `ZeroizeOnDrop`.
//! 2. The set contains NONE of the forbidden traits.
//! 3. No `#[cfg_attr(..., derive(...))]` attribute is attached (feature-gated
//!    derives on credential types are forbidden outright).
//! 4. The type is defined either exactly once, or twice under mutually
//!    exclusive `#[cfg]` predicates.
//!
//! **Why `syn` instead of regex:** credential discipline is a security gate.
//! Regex-based scanners cannot distinguish Rust syntax from text patterns
//! inside strings, comments, and macro arguments, which means every
//! iteration finds new bypass vectors. `syn` IS the Rust lexer+parser the
//! compiler team maintains — it cannot be fooled by string literals,
//! comments, `r#raw_identifiers`, `cfg_attr` smuggling, or split attribute
//! blocks.
//!
//! This validator is defense-in-breadth for the derive gate. Defense-in-
//! depth lives in the `permitlayer-credential` crate itself via
//! `static_assertions::assert_not_impl_any!` (catches manually-written
//! `impl Clone for …` that this scanner, by construction, cannot see).

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use syn::{Attribute, Item, ItemStruct, Meta, Visibility, punctuated::Punctuated};
use walkdir::WalkDir;

/// The credential types that must satisfy the discipline rules.
const POLICED_TYPES: &[&str] =
    &["SealedCredential", "OAuthToken", "OAuthRefreshToken", "AgentBearerToken"];

/// Derives that must NEVER appear on a policed credential type.
///
/// Rationale:
/// - `Debug`/`Display` leak token material via formatting
/// - `Clone`/`Copy` defeat zeroization (bitwise copy escapes drop)
/// - `Serialize`/`Deserialize` let tokens cross IO boundaries
/// - `PartialEq`/`Eq` enable timing-attack-friendly `==` on secret bytes
/// - `Hash`/`PartialOrd`/`Ord` use secret bytes as map/set keys
/// - `Default` conjures empty credentials from thin air
/// - `From`/`Into`/`TryFrom`/`TryInto` let credentials be produced from
///   untyped bytes via generic trait machinery
/// - `AsRef`/`AsMut`/`Borrow`/`BorrowMut`/`Deref`/`DerefMut` auto-expose
///   the inner bytes through trait coercion
const FORBIDDEN_DERIVES: &[&str] = &[
    "Debug",
    "Display",
    "Clone",
    "Copy",
    "Serialize",
    "Deserialize",
    "PartialEq",
    "Eq",
    "Hash",
    "PartialOrd",
    "Ord",
    "Default",
    "From",
    "Into",
    "TryFrom",
    "TryInto",
    "AsRef",
    "AsMut",
    "Borrow",
    "BorrowMut",
    "Deref",
    "DerefMut",
];

/// Derive that MUST appear on every policed credential type.
const REQUIRED_DERIVE: &str = "ZeroizeOnDrop";

/// Macro invocations permitted at item-level in credential source. These
/// macros are known to expand to compile-time assertions or other non-type
/// items — not to policed type definitions.
const ALLOWED_MACROS: &[&str] = &["assert_not_impl_any", "assert_impl_all", "assert_eq_size"];

/// Record of one policed-struct discovery.
#[derive(Debug)]
struct Definition {
    file: PathBuf,
    cfg_predicate: Option<String>,
}

/// Run the validator against the given path (defaults to
/// `crates/permitlayer-credential/src` relative to the current working
/// directory). Returns `Ok(())` if all policed types are clean, otherwise
/// returns an error describing every violation found.
///
/// The validator **fails closed**: any error during file walking, reading,
/// or parsing is propagated and causes the check to fail.
pub fn run(path: Option<&Path>) -> Result<()> {
    let default = PathBuf::from("crates/permitlayer-credential/src");
    let root = path.unwrap_or(&default);

    if !root.exists() {
        bail!("credential source directory not found: {}", root.display());
    }

    let mut violations: Vec<String> = Vec::new();
    let mut found: BTreeMap<&'static str, Vec<Definition>> = BTreeMap::new();

    for entry in WalkDir::new(root).into_iter().filter_entry(|e| {
        // Skip hidden directories (.git, .vscode) and build output (target/)
        // that could legitimately appear if the validator is pointed at a
        // workspace root instead of crates/.../src.
        let name = e.file_name().to_string_lossy();
        !(name.starts_with('.') || name == "target")
    }) {
        let entry = entry.with_context(|| format!("walking {}", root.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let entry_path = entry.path();
        if entry_path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let src = std::fs::read_to_string(entry_path)
            .with_context(|| format!("reading {}", entry_path.display()))?;

        // Fail closed: any parse failure aborts the entire check.
        let file =
            syn::parse_file(&src).with_context(|| format!("parsing {}", entry_path.display()))?;

        inspect_items(&file.items, entry_path, &mut violations, &mut found);
    }

    // Every policed type must be defined exactly once, or twice under
    // mutually-exclusive cfg predicates.
    for ty in POLICED_TYPES {
        let defs = found.get(ty).map_or(&[][..], Vec::as_slice);
        match defs.len() {
            0 => violations.push(format!(
                "type `{ty}` was not found in {} — every policed credential type must be defined",
                root.display()
            )),
            1 => {}
            _ if mutually_exclusive_cfgs(defs) => {}
            n => {
                let locations: Vec<String> =
                    defs.iter().map(|d| d.file.display().to_string()).collect();
                violations.push(format!(
                    "type `{ty}` is defined {n} times without mutually-exclusive cfgs: [{}]",
                    locations.join(", ")
                ));
            }
        }
    }

    if !violations.is_empty() {
        for v in &violations {
            eprintln!("credential validation violation: {v}");
        }
        bail!("credential type discipline check failed: {} violation(s)", violations.len());
    }

    println!("credential type discipline OK: {} policed types verified", POLICED_TYPES.len());
    Ok(())
}

/// Walk a list of top-level items (or nested module items) and check every
/// `ItemStruct` whose name matches a policed type.
fn inspect_items(
    items: &[Item],
    file: &Path,
    violations: &mut Vec<String>,
    found: &mut BTreeMap<&'static str, Vec<Definition>>,
) {
    for item in items {
        match item {
            Item::Struct(s) => inspect_struct(s, file, violations, found),
            // Recurse into inline modules so nested definitions are checked.
            Item::Mod(m) => {
                if let Some((_, inner_items)) = &m.content {
                    inspect_items(inner_items, file, violations, found);
                }
            }
            // Item::Macro: macro invocations that could expand to policed
            // types are invisible to syn. Flag any occurrence NOT on the
            // allowlist so a human reviews it. The allowlist contains
            // macros that expand to non-type items (assertions, etc.).
            Item::Macro(m) => {
                let macro_name =
                    m.mac.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
                if !ALLOWED_MACROS.contains(&macro_name.as_str()) {
                    violations.push(format!(
                        "{}: macro invocation `{}!` in credential source — \
                         macro-generated items cannot be audited for credential \
                         discipline (allowed: {})",
                        file.display(),
                        macro_name,
                        ALLOWED_MACROS.join(", ")
                    ));
                }
            }
            // Item::Verbatim: syn 2.0's fallback for syntax it cannot parse
            // into a typed variant. Future Rust syntax could land here and
            // silently hide a policed struct. Fail closed.
            Item::Verbatim(tokens) => {
                violations.push(format!(
                    "{}: unrecognized item syntax `{}` — update `syn` or add \
                     explicit handling before landing this code",
                    file.display(),
                    // Show a bounded snippet so diagnostics stay readable.
                    truncate(&tokens.to_string(), 120)
                ));
            }
            // Item::Type: `type Alias = Other;` can rename a non-policed
            // struct to a policed name, decoupling the scanner-visible
            // definition from the in-use name.
            Item::Type(t) => {
                let name = t.ident.to_string();
                if POLICED_TYPES.iter().any(|p| *p == name) {
                    violations.push(format!(
                        "{}: `type {name} = …` aliases a policed credential \
                         name — aliases are not allowed",
                        file.display()
                    ));
                }
            }
            // Item::Use: `pub use other::Foo as OAuthToken;` re-exports a
            // foreign type under a policed name.
            Item::Use(u) => {
                check_use_tree(&u.tree, file, violations);
            }
            _ => {}
        }
    }
}

/// Recurse into a `use` tree looking for any `as` rename that binds a policed
/// identifier to something else. Plain `pub use module::PolicedName` is a
/// legitimate re-export (lib.rs does this for its own submodules) and is
/// NOT flagged — we only block renames that attach a policed identifier to
/// an arbitrary source.
fn check_use_tree(tree: &syn::UseTree, file: &Path, violations: &mut Vec<String>) {
    use syn::UseTree;
    match tree {
        UseTree::Rename(r) => {
            let renamed = r.rename.to_string();
            if POLICED_TYPES.iter().any(|p| *p == renamed) {
                let original = r.ident.to_string();
                violations.push(format!(
                    "{}: `use … {original} as {renamed}` re-exports under a \
                     policed credential name — aliases are not allowed",
                    file.display()
                ));
            }
        }
        UseTree::Path(p) => check_use_tree(&p.tree, file, violations),
        UseTree::Group(g) => {
            for sub in &g.items {
                check_use_tree(sub, file, violations);
            }
        }
        UseTree::Name(_) | UseTree::Glob(_) => {}
    }
}

/// Truncate `s` to `max` chars, appending `…` if truncated.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let prefix: String = s.chars().take(max).collect();
        format!("{prefix}…")
    }
}

/// Check a single struct definition for credential-discipline compliance.
fn inspect_struct(
    s: &ItemStruct,
    file: &Path,
    violations: &mut Vec<String>,
    found: &mut BTreeMap<&'static str, Vec<Definition>>,
) {
    // `syn::Ident::to_string` normalizes raw identifiers: `r#Debug` becomes
    // the string "Debug", so `r#`-prefix smuggling is impossible.
    let name = s.ident.to_string();
    let Some(&policed) = POLICED_TYPES.iter().find(|p| **p == name) else {
        return;
    };

    // Record this discovery — even if it has violations, so duplicate
    // counting is accurate.
    found.entry(policed).or_default().push(Definition {
        file: file.to_path_buf(),
        cfg_predicate: extract_cfg_predicate(&s.attrs),
    });

    // Visibility: policed types must be `pub` (or `pub(crate)`, `pub(in …)`).
    // A module-private definition in the credential crate would be
    // unreachable to other crates and is a signal of an accidental
    // refactor. `pub(self)` has identical reachability to `Inherited`
    // (module-private) so we reject it too.
    let vis_module_private = match &s.vis {
        Visibility::Inherited => true,
        Visibility::Restricted(r) => r.path.is_ident("self"),
        _ => false,
    };
    if vis_module_private {
        violations.push(format!(
            "{}: type `{name}` must be declared `pub` (or `pub(crate)`/`pub(in …)`) — \
             module-private visibility blocks cross-crate use of this credential",
            file.display()
        ));
    }

    // Collect the set of derived traits and check for cfg_attr smuggling.
    let mut derives: Vec<String> = Vec::new();
    for attr in &s.attrs {
        match &attr.meta {
            // `#[derive(Trait, Other::Trait, …)]`
            Meta::List(list) if list.path.is_ident("derive") => {
                match list
                    .parse_args_with(Punctuated::<syn::Path, syn::Token![,]>::parse_terminated)
                {
                    Ok(parsed) => {
                        for path in parsed {
                            if let Some(seg) = path.segments.last() {
                                // `seg.ident` is a `syn::Ident` — raw idents
                                // are already normalized by syn's lexer.
                                derives.push(seg.ident.to_string());
                            }
                        }
                    }
                    Err(e) => {
                        violations
                            .push(format!("{}: malformed derive on `{name}`: {e}", file.display()));
                    }
                }
            }
            // `#[cfg_attr(predicate, derive(...))]` — forbidden on policed types.
            Meta::List(list) if list.path.is_ident("cfg_attr") => {
                if cfg_attr_contains_derive(list) {
                    violations.push(format!(
                        "{}: type `{name}` uses `#[cfg_attr(..., derive(...))]` — \
                         feature-gated derives on credential types are forbidden",
                        file.display()
                    ));
                }
            }
            _ => {}
        }
    }

    // Reject forbidden derives.
    for forbidden in FORBIDDEN_DERIVES {
        if derives.iter().any(|d| d == forbidden) {
            violations.push(format!(
                "{}: type `{name}` has forbidden derive `{forbidden}`",
                file.display()
            ));
        }
    }

    // Require `ZeroizeOnDrop`.
    if !derives.iter().any(|d| d == REQUIRED_DERIVE) {
        violations.push(format!(
            "{}: type `{name}` is missing required derive `{REQUIRED_DERIVE}`",
            file.display()
        ));
    }
}

/// Structurally determine whether a `#[cfg_attr(...)]` attribute's argument
/// list contains a `derive(...)` meta, including when nested inside another
/// `cfg_attr(...)`. Parses the inner token stream as a comma-separated list
/// of metas: the first is the cfg predicate, the rest are the attributes to
/// apply when the predicate holds.
///
/// Rustc expands nested `cfg_attr(a, cfg_attr(b, derive(X)))` recursively,
/// so we must too — otherwise the check is easy to bypass.
fn cfg_attr_contains_derive(list: &syn::MetaList) -> bool {
    let Ok(inner) = list.parse_args_with(Punctuated::<Meta, syn::Token![,]>::parse_terminated)
    else {
        // If we cannot parse the cfg_attr contents, fail closed: treat it as
        // if it contained a derive so the violation fires and a human
        // reviews it.
        return true;
    };
    // Skip the first meta (the cfg predicate), inspect the rest.
    inner.iter().skip(1).any(|meta| match meta {
        Meta::List(inner_list) if inner_list.path.is_ident("derive") => true,
        // Nested cfg_attr: recurse.
        Meta::List(inner_list) if inner_list.path.is_ident("cfg_attr") => {
            cfg_attr_contains_derive(inner_list)
        }
        _ => false,
    })
}

/// Extract the token-string of any `#[cfg(...)]` attribute on the struct,
/// for mutually-exclusive duplicate detection.
fn extract_cfg_predicate(attrs: &[Attribute]) -> Option<String> {
    attrs.iter().find_map(|a| match &a.meta {
        Meta::List(l) if l.path.is_ident("cfg") => Some(l.tokens.to_string()),
        _ => None,
    })
}

/// Conservative heuristic: return true iff exactly two definitions exist
/// with cfg predicates of the form `P` and `not(P)`. Any more complex
/// mutual-exclusion arrangement (target_os matrices, nested `all`/`any`)
/// is rejected — contributors must get architect sign-off before widening
/// this.
fn mutually_exclusive_cfgs(defs: &[Definition]) -> bool {
    if defs.len() != 2 {
        return false;
    }
    let (Some(a), Some(b)) = (defs[0].cfg_predicate.as_deref(), defs[1].cfg_predicate.as_deref())
    else {
        return false;
    };
    // Normalize by stripping whitespace, then check `not(P)` / `P` pairing.
    let a: String = a.chars().filter(|c| !c.is_whitespace()).collect();
    let b: String = b.chars().filter(|c| !c.is_whitespace()).collect();
    a == format!("not({b})") || b == format!("not({a})")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests;
