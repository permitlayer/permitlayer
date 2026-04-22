//! Extract the semver-locked host-API surface from the
//! `permitlayer-plugins` crate source via `syn`.
//!
//! The extraction is pure source-reading: we DO NOT load the plugins
//! crate as a runtime dep (that would pull in rquickjs + its C
//! toolchain). Everything we need is readable as plain Rust syntax
//! because Story 6.2's "introspectable from pure Rust" invariant
//! promises it (see `6-2-plugin-host-api.md:201-207`).
//!
//! # Extraction sources
//!
//! 1. `host_api/mod.rs` — `HOST_API_VERSION` literal (`ItemConst`),
//!    `JS_SURFACE` slice content (`ItemConst` whose expression is an
//!    array literal of `&str`).
//! 2. `host_api/services.rs` — `HostServices` trait method signatures
//!    (`ItemTrait`), the DTOs (`ItemStruct` for `ScopedTokenDesc`,
//!    `PolicyEvalReq`, `ScrubResponse`, `ScrubMatchDesc`, `FetchReq`,
//!    `FetchResp`; `ItemEnum` for `DecisionDesc`), and the full list
//!    of named `HostApiErrorCode` variants via the `all_error_code_names`
//!    function (we read its body's string literals).
//!
//! Non-surface items (`Default` impls, `#[cfg(test)] mod tests`,
//! private helpers, doc-comments) are deliberately ignored.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use quote::ToTokens;
use syn::{
    Expr, ExprArray, ExprLit, Fields, File, Item, ItemConst, ItemEnum, ItemFn, ItemStruct,
    ItemTrait, Lit, TraitItem, Variant, Visibility,
};

/// Stable description of the host-API surface at a point in time.
/// Lockfile emit + diff operate on instances of this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceDescription {
    /// The `HOST_API_VERSION` literal, e.g. `"1.0.0-rc.1"`.
    pub version: String,
    /// Signatures of the `agentsso.*` methods / properties exposed
    /// to JS plugins. Sourced from `JS_SURFACE`.
    pub js_surface: BTreeSet<String>,
    /// `HostApiErrorCode` named-variant `Display` strings. Sourced
    /// from `all_error_code_names`.
    pub error_codes: BTreeSet<String>,
    /// Rendered method signatures from the `HostServices` trait.
    pub host_services_methods: BTreeSet<String>,
    /// Rendered shapes of the DTO structs + enums.
    pub dto_shapes: BTreeSet<String>,
}

/// Where to read the live plugin crate from. Defaults to
/// `<workspace>/crates/permitlayer-plugins/src/host_api`.
pub fn default_host_api_dir() -> PathBuf {
    // `CARGO_MANIFEST_DIR` for xtask is `<workspace>/xtask`. Climb
    // one up and dive into the plugin crate.
    let xtask_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root =
        xtask_dir.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| xtask_dir.clone());
    workspace_root.join("crates").join("permitlayer-plugins").join("src").join("host_api")
}

/// Parse `host_api/mod.rs` + `host_api/services.rs` into a
/// [`SurfaceDescription`].
pub fn extract(host_api_dir: &Path) -> Result<SurfaceDescription> {
    let mod_rs = host_api_dir.join("mod.rs");
    let services_rs = host_api_dir.join("services.rs");

    let mod_file = parse_file(&mod_rs)?;
    let services_file = parse_file(&services_rs)?;

    let version = extract_host_api_version(&mod_file)
        .context("extracting HOST_API_VERSION from host_api/mod.rs")?;
    let js_surface =
        extract_js_surface(&mod_file).context("extracting JS_SURFACE from host_api/mod.rs")?;
    let error_codes = extract_error_codes(&services_file)
        .context("extracting error_code names from host_api/services.rs")?;
    let host_services_methods = extract_host_services_trait(&services_file)
        .context("extracting HostServices trait from host_api/services.rs")?;
    let dto_shapes = extract_dto_shapes(&services_file)
        .context("extracting DTO shapes from host_api/services.rs")?;

    Ok(SurfaceDescription { version, js_surface, error_codes, host_services_methods, dto_shapes })
}

fn parse_file(path: &Path) -> Result<File> {
    let contents =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    syn::parse_file(&contents).with_context(|| format!("parsing {} as Rust syntax", path.display()))
}

fn is_public(vis: &Visibility) -> bool {
    matches!(vis, Visibility::Public(_))
}

/// Read `pub const HOST_API_VERSION: &str = "<lit>";` from mod.rs.
fn extract_host_api_version(file: &File) -> Result<String> {
    for item in &file.items {
        if let Item::Const(c) = item
            && c.ident == "HOST_API_VERSION"
        {
            if let Expr::Lit(ExprLit { lit: Lit::Str(s), .. }) = c.expr.as_ref() {
                return Ok(s.value());
            }
            bail!("HOST_API_VERSION found but its expression is not a string literal");
        }
    }
    Err(anyhow!("HOST_API_VERSION const not found"))
}

/// Read `pub const JS_SURFACE: &[&str] = &[...];` from mod.rs.
fn extract_js_surface(file: &File) -> Result<BTreeSet<String>> {
    for item in &file.items {
        if let Item::Const(c) = item
            && c.ident == "JS_SURFACE"
        {
            return read_str_array_const(c);
        }
    }
    Err(anyhow!("JS_SURFACE const not found"))
}

/// Read the string-literal content of an `ItemConst` whose expression
/// is a `&[...]` array (or a reference to an array).
fn read_str_array_const(c: &ItemConst) -> Result<BTreeSet<String>> {
    let array = unwrap_array_expr(c.expr.as_ref())
        .ok_or_else(|| anyhow!("const `{}` is not a reference to an array literal", c.ident))?;
    let mut set = BTreeSet::new();
    for elem in &array.elems {
        if let Expr::Lit(ExprLit { lit: Lit::Str(s), .. }) = elem {
            set.insert(s.value());
        } else {
            bail!("non-string-literal element in `{}`", c.ident);
        }
    }
    Ok(set)
}

fn unwrap_array_expr(expr: &Expr) -> Option<&ExprArray> {
    match expr {
        Expr::Array(a) => Some(a),
        Expr::Reference(r) => unwrap_array_expr(r.expr.as_ref()),
        _ => None,
    }
}

/// Read `pub fn all_error_code_names() -> Vec<&'static str>` from
/// services.rs and return the set of string literals it vec-inits.
///
/// Implementation strategy: walk the function body looking for
/// `vec![ "a", "b", ... ]` macro invocations. The function is
/// deliberately shaped with a single `vec!` literal + a sort call
/// so this walker stays simple. If a future refactor changes the
/// body shape, update this walker alongside — the unit test catches
/// the drift.
fn extract_error_codes(file: &File) -> Result<BTreeSet<String>> {
    for item in &file.items {
        if let Item::Fn(f) = item
            && f.sig.ident == "all_error_code_names"
            && is_public(&f.vis)
        {
            return read_vec_macro_strings(f);
        }
    }
    Err(anyhow!("all_error_code_names() function not found"))
}

fn read_vec_macro_strings(f: &ItemFn) -> Result<BTreeSet<String>> {
    for stmt in &f.block.stmts {
        if let syn::Stmt::Local(local) = stmt
            && let Some(init) = &local.init
            && let Some(set) = try_extract_vec_literal(init.expr.as_ref())?
        {
            return Ok(set);
        }
    }
    Err(anyhow!(
        "all_error_code_names() body shape not recognized (expected a `let names = vec![...]`)"
    ))
}

fn try_extract_vec_literal(expr: &Expr) -> Result<Option<BTreeSet<String>>> {
    if let Expr::Macro(m) = expr {
        let path = &m.mac.path;
        if path.is_ident("vec") {
            let tokens = m.mac.tokens.clone();
            let parsed: syn::punctuated::Punctuated<Expr, syn::Token![,]> =
                syn::parse::Parser::parse2(
                    syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated,
                    tokens,
                )?;
            let mut set = BTreeSet::new();
            for e in parsed {
                if let Expr::Lit(ExprLit { lit: Lit::Str(s), .. }) = e {
                    set.insert(s.value());
                } else {
                    bail!("non-string-literal element inside `vec![...]`");
                }
            }
            return Ok(Some(set));
        }
    }
    Ok(None)
}

/// Render every method in the `pub trait HostServices` as a stable
/// signature string.
fn extract_host_services_trait(file: &File) -> Result<BTreeSet<String>> {
    for item in &file.items {
        if let Item::Trait(t) = item
            && t.ident == "HostServices"
            && is_public(&t.vis)
        {
            return render_trait(t);
        }
    }
    Err(anyhow!("pub trait HostServices not found"))
}

fn render_trait(t: &ItemTrait) -> Result<BTreeSet<String>> {
    let mut set = BTreeSet::new();
    for it in &t.items {
        if let TraitItem::Fn(f) = it {
            set.insert(render_trait_fn_sig(&f.sig));
        }
    }
    Ok(set)
}

fn render_trait_fn_sig(sig: &syn::Signature) -> String {
    // Convert the full signature to its source-text form via `syn`'s
    // token-stream round-trip, then normalize whitespace.
    let tokens = sig.to_token_stream().to_string();
    normalize_tokens(&tokens)
}

/// Canonicalize whitespace in a token-stream stringification. `syn`'s
/// `ToTokens` + `TokenStream::to_string` inserts a space between every
/// punctuation token (e.g. `Vec < String >`, `& self`). We collapse to
/// the conventional source-text shape so the lockfile is diffable by
/// humans without jumping through hoops.
fn normalize_tokens(s: &str) -> String {
    // Pass 1: collapse consecutive whitespace to single space.
    let mut collapsed = String::with_capacity(s.len());
    let mut prev_space = false;
    for ch in s.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                collapsed.push(' ');
            }
            prev_space = true;
        } else {
            collapsed.push(ch);
            prev_space = false;
        }
    }
    let collapsed = collapsed.trim().to_owned();

    // Pass 2: strip stray spaces around punctuation. Order matters —
    // apply `::` first (spaces both sides) then single-sided ones.
    let mut out = collapsed;
    let rules: &[(&str, &str)] = &[
        (" :: ", "::"),
        (":: ", "::"),
        (" ::", "::"),
        (" < ", "<"),
        (" > ", ">"),
        ("< ", "<"),
        (" >", ">"),
        (" , ", ", "),
        (" ,", ","),
        (" ( ", "("),
        ("( ", "("),
        (" )", ")"),
        ("& ", "&"),
        (" ;", ";"),
        (" : ", ": "),
        (" ' ", " '"),
    ];
    for (from, to) in rules {
        out = out.replace(from, to);
    }
    // Pass 3: strip accidental space-before-open-paren introduced
    // by `fn foo (arg)`. `syn` emits `fn foo ( &self )` which passes
    // 2 reduces to `fn foo(&self)` above — except when tokens stream
    // bumps the paren against the name (`fn foo`+`(`). Collapse
    // `<ident> (` → `<ident>(` once more.
    out = out.replace(" (", "(").replace(",)", ")").replace(", )", ")");
    out
}

/// Extract DTO shapes for the struct + enum types that carry data
/// across the JS marshalling boundary. Skipping `HostApiError`
/// (implementation-side error struct, not part of the JS surface
/// contract — plugins see `AgentssoError` in JS, not this Rust type).
fn extract_dto_shapes(file: &File) -> Result<BTreeSet<String>> {
    const DTO_STRUCTS: &[&str] = &[
        "ScopedTokenDesc",
        "PolicyEvalReq",
        "ScrubResponse",
        "ScrubMatchDesc",
        "FetchReq",
        "FetchResp",
    ];
    const DTO_ENUMS: &[&str] = &["DecisionDesc"];

    let mut out = BTreeSet::new();
    let mut found: BTreeSet<String> = BTreeSet::new();
    for item in &file.items {
        match item {
            Item::Struct(s) if is_public(&s.vis) => {
                if DTO_STRUCTS.iter().any(|n| s.ident == *n) {
                    out.insert(render_struct(s));
                    found.insert(s.ident.to_string());
                }
            }
            Item::Enum(e) if is_public(&e.vis) => {
                if DTO_ENUMS.iter().any(|n| e.ident == *n) {
                    for line in render_enum(e) {
                        out.insert(line);
                    }
                    found.insert(e.ident.to_string());
                }
            }
            _ => {}
        }
    }
    for expected in DTO_STRUCTS.iter().chain(DTO_ENUMS.iter()) {
        if !found.contains(*expected) {
            bail!(
                "expected DTO `{}` not found in services.rs — rename or missing pub visibility?",
                expected,
            );
        }
    }
    Ok(out)
}

fn render_struct(s: &ItemStruct) -> String {
    let name = s.ident.to_string();
    let mut field_strs: Vec<String> = Vec::new();
    if let Fields::Named(fn_) = &s.fields {
        for f in &fn_.named {
            if matches!(f.vis, Visibility::Public(_)) {
                let fname = f.ident.as_ref().map(|i| i.to_string()).unwrap_or_default();
                let ty = normalize_tokens(&f.ty.to_token_stream().to_string());
                field_strs.push(format!("{fname}: {ty}"));
            }
        }
    }
    field_strs.sort();
    if field_strs.is_empty() {
        format!("{name} {{}}")
    } else {
        format!("{name} {{ {} }}", field_strs.join(", "))
    }
}

fn render_enum(e: &ItemEnum) -> Vec<String> {
    let mut out = Vec::new();
    for v in &e.variants {
        out.push(render_variant(&e.ident.to_string(), v));
    }
    out
}

fn render_variant(enum_name: &str, v: &Variant) -> String {
    let base = format!("{enum_name}::{}", v.ident);
    match &v.fields {
        Fields::Unit => base,
        Fields::Named(fn_) => {
            let mut field_strs: Vec<String> = fn_
                .named
                .iter()
                .map(|f| {
                    let fname = f.ident.as_ref().map(|i| i.to_string()).unwrap_or_default();
                    let ty = normalize_tokens(&f.ty.to_token_stream().to_string());
                    format!("{fname}: {ty}")
                })
                .collect();
            field_strs.sort();
            format!("{base} {{ {} }}", field_strs.join(", "))
        }
        Fields::Unnamed(fu) => {
            let types: Vec<String> = fu
                .unnamed
                .iter()
                .map(|f| normalize_tokens(&f.ty.to_token_stream().to_string()))
                .collect();
            format!("{base}({})", types.join(", "))
        }
    }
}
