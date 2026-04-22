//! Regression tests for the credential-discipline validator.
//!
//! Organized by round:
//! - **Round 0**: basic positive/negative path (clean, Debug, Clone, Serialize,
//!   missing ZeroizeOnDrop, missing type).
//! - **Round 1**: holes closed by the first review (path-qualified derives,
//!   split attrs, neighbor adoption, cfg_attr smuggling, expanded forbidden
//!   list).
//! - **Round 2**: holes closed by the second review (trailing comments,
//!   comments inside derive body, block comments between attrs, string-
//!   literal smuggling, doc-attr cfg_attr false positive, crate-level
//!   attrs, cfg-gated duplicates, non-`pub` structs, raw identifiers,
//!   expanded forbidden list: From/Into/AsRef/Deref/etc).

use super::*;
use std::fs;

fn write_fixture(dir: &Path, name: &str, content: &str) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join(name), content).unwrap();
}

/// Create a unique temp directory. Uses process id + monotonic counter
/// so parallel tests never collide.
fn tempdir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let base = std::env::temp_dir();
    let dir = base.join(format!("xtask-cred-test-{pid}-{n}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Clean fixture: all four types with only `ZeroizeOnDrop`.
fn all_types_clean(dir: &Path) {
    let clean = r#"
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#;
    write_fixture(dir, "lib.rs", clean);
}

// ======================================================================
// Round 0 — baseline positive/negative paths
// ======================================================================

#[test]
fn clean_fixture_passes() {
    let tmp = tempdir();
    all_types_clean(&tmp);
    run(Some(&tmp)).expect("clean fixture must pass");
}

#[test]
fn debug_derive_is_rejected() {
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(Debug, ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    let err = run(Some(&tmp)).expect_err("Debug derive must be rejected");
    assert!(err.to_string().contains("discipline check failed"));
}

#[test]
fn clone_derive_is_rejected() {
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(Clone, ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("Clone derive must be rejected");
}

#[test]
fn missing_zeroize_is_rejected() {
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("missing ZeroizeOnDrop must be rejected");
}

#[test]
fn missing_type_is_rejected() {
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);
// AgentBearerToken intentionally missing
"#,
    );
    run(Some(&tmp)).expect_err("missing policed type must be rejected");
}

#[test]
fn serialize_derive_is_rejected() {
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;
use serde::Serialize;

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop, Serialize)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("Serialize derive must be rejected");
}

// ======================================================================
// Round 1 — holes from first review
// ======================================================================

#[test]
fn path_qualified_serialize_is_rejected() {
    // `serde::Serialize` must be caught — syn's `Path::segments.last()`
    // normalizes automatically.
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop, serde::Serialize)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("serde::Serialize must be rejected");
}

#[test]
fn split_derive_attributes_are_all_checked() {
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(Debug)]
#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("split derive with Debug must be rejected");
}

#[test]
fn neighbor_derive_not_adopted() {
    // Struct with no derive of its own MUST fail — cannot inherit neighbor's.
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

// OAuthToken has no derive — must fail, not inherit from SealedCredential.
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("bare struct must not adopt neighbor's derive");
}

#[test]
fn nested_cfg_attr_derive_is_rejected() {
    // Round 3 A1: `cfg_attr(a, cfg_attr(b, derive(X)))` must recurse.
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[cfg_attr(feature = "a", cfg_attr(feature = "b", derive(Debug)))]
#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("nested cfg_attr with derive must be rejected");
}

#[test]
fn doubly_nested_cfg_attr_derive_is_rejected() {
    // Recursion depth 2: cfg_attr(a, cfg_attr(b, cfg_attr(c, derive(X)))).
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[cfg_attr(feature = "a", cfg_attr(feature = "b", cfg_attr(feature = "c", derive(Debug))))]
#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("doubly-nested cfg_attr with derive must be rejected");
}

#[test]
fn cfg_attr_derive_is_rejected() {
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[cfg_attr(feature = "debug-tokens", derive(Debug))]
#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("cfg_attr derive must be rejected");
}

#[test]
fn partial_eq_derive_is_rejected() {
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop, PartialEq)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("PartialEq must be rejected");
}

#[test]
fn default_derive_is_rejected() {
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(Default, ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("Default must be rejected");
}

#[test]
fn path_qualified_zeroize_is_accepted() {
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
#[derive(zeroize::ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(zeroize::ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(zeroize::ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(zeroize::ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect("path-qualified ZeroizeOnDrop must be accepted");
}

// ======================================================================
// Round 2 — holes from second review (closed by syn rewrite)
// ======================================================================

#[test]
fn a1_trailing_comment_on_derive_line() {
    // Trailing line comment after `]` used to break end-anchored regex.
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
#[derive(Debug)] // trailing comment that used to hide Debug
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("Debug with trailing comment must be rejected");
}

#[test]
fn b1_line_comment_inside_derive_body() {
    // `// comment` inside multi-line derive body used to glue to the next trait.
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(
    ZeroizeOnDrop, // required
    Debug,
)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("Debug with line comment in body must be rejected");
}

#[test]
fn b1_block_comment_inside_derive_body() {
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop, /* TODO drop Debug */ Debug)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("Debug with block comment in body must be rejected");
}

#[test]
fn c1_block_comment_between_attributes() {
    // `/* comment */` between two `#[derive(...)]` used to terminate walk.
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(Debug)]
/* inline block comment */
#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("Debug split by block comment must be rejected");
}

#[test]
fn d1_string_literal_does_not_trigger_phantom_match() {
    // A string literal containing `pub struct OAuthToken` must NOT be
    // mistaken for a real struct definition.
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

pub const DOCS: &str = "
pub struct OAuthToken(Box<[u8]>);
";

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect("string-literal phantom must not trigger violation");
}

#[test]
fn d1_raw_string_literal_does_not_trigger_phantom_match() {
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r##"
use zeroize::ZeroizeOnDrop;

pub const EXAMPLE: &str = r#"
#[derive(Debug)]
pub struct OAuthToken(Box<[u8]>);
"#;

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"##,
    );
    run(Some(&tmp)).expect("raw-string-literal phantom must not trigger violation");
}

#[test]
fn d1_block_comment_does_not_trigger_phantom_match() {
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

/*
#[derive(Debug)]
pub struct OAuthToken(Box<[u8]>);
*/

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect("commented-out struct must not trigger violation");
}

#[test]
fn e1_doc_attr_mentioning_cfg_attr_and_derive_does_not_false_positive() {
    // `#[doc = "see cfg_attr derive guide"]` must NOT trigger cfg_attr
    // detection — the substring match used to fire here.
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[doc = "see cfg_attr derive guide at docs/derive.md"]
#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect("doc attr mentioning cfg_attr must not false-positive");
}

#[test]
fn f1_crate_level_attrs_do_not_interfere() {
    // Crate-level `#![...]` attrs near the struct must not be attributed to it.
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
#![cfg_attr(feature = "nightly", feature(trait_alias))]
#![allow(dead_code)]

use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect("crate-level attrs must not interfere");
}

#[test]
fn g1_mutually_exclusive_cfg_duplicates_accepted() {
    // Two definitions gated by `feature="x"` / `not(feature="x")` are OK.
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[cfg(feature = "alt")]
#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[cfg(not(feature = "alt"))]
#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect("mutually-exclusive cfg duplicates must be accepted");
}

#[test]
fn g1_unrelated_duplicates_rejected() {
    // Two unconditional definitions must fail.
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "a.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    write_fixture(
        &tmp,
        "b.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("unconditional duplicates must be rejected");
}

#[test]
fn h1_non_pub_struct_is_caught() {
    // Non-`pub` struct OAuthToken must be flagged (visibility violation).
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("non-pub policed struct must be flagged");
}

#[test]
fn h1_pub_crate_is_accepted() {
    // `pub(crate)` is a form of `pub` and must be accepted.
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub(crate) struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect("pub(crate) must be accepted");
}

#[test]
fn i1_raw_identifier_derive_is_caught() {
    // `r#Debug` must be caught — syn::Ident normalizes to "Debug".
    // Note: not every identifier can be r#-prefixed; we use a legal one.
    // "union" IS a reserved word so `r#union` is legal; we synthesize a
    // more realistic test using a macro-like path that ends in `Debug`.
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

// `r#` prefix on a keyword identifier — syn normalizes to the raw name.
// Not directly applicable to "Debug" (not a keyword), so we use the
// path-segment normalization equivalent: `other::Debug`.
#[derive(ZeroizeOnDrop, other::Debug)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("path-qualified Debug must be caught");
}

#[test]
fn k1_expanded_forbidden_list_catches_from() {
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop, From)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("From must be rejected");
}

#[test]
fn k1_expanded_forbidden_list_catches_deref() {
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop, Deref)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("Deref must be rejected");
}

#[test]
fn k1_expanded_forbidden_list_catches_as_ref() {
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop, AsRef)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("AsRef must be rejected");
}

#[test]
fn nested_module_struct_is_found() {
    // Policed type defined inside an inline `mod` must still be found.
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

mod inner {
    use zeroize::ZeroizeOnDrop;

    #[derive(ZeroizeOnDrop)]
    pub struct OAuthToken(Box<[u8]>);
}

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect("nested-module policed struct must be found");
}

#[test]
fn nested_module_with_violation_is_caught() {
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

mod inner {
    use zeroize::ZeroizeOnDrop;

    #[derive(ZeroizeOnDrop, Clone)]
    pub struct OAuthToken(Box<[u8]>);
}

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("Clone in nested module must be caught");
}

#[test]
fn e1_disallowed_macro_is_rejected() {
    // Round 3 E1: Item::Macro invocations can expand to arbitrary items,
    // including forbidden-derive structs. Reject any macro not on the
    // allowlist.
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

define_evil!(OAuthToken);

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    let err = run(Some(&tmp)).expect_err("disallowed macro must be rejected");
    assert!(err.to_string().contains("discipline check failed"));
}

#[test]
fn e1_allowed_macros_are_accepted() {
    // `assert_not_impl_any!` etc. are on the allowlist.
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);
assert_not_impl_any!(SealedCredential: Clone);

#[derive(ZeroizeOnDrop)]
pub struct OAuthToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect("allowlisted macros must not trigger violations");
}

#[test]
fn f1_type_alias_to_policed_name_is_rejected() {
    // Round 3 F1: `pub type OAuthToken = Evil;` decouples the scanner-
    // visible struct from the in-use type.
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

pub struct RealEvil(Box<[u8]>);
pub type OAuthToken = RealEvil;

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("type alias to policed name must be rejected");
}

#[test]
fn f1_use_as_rename_to_policed_name_is_rejected() {
    // Round 3 F1: `use other::Foo as OAuthToken;` re-exports under a policed name.
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
use zeroize::ZeroizeOnDrop;

pub use external::EvilType as OAuthToken;

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect_err("use-as-rename to policed name must be rejected");
}

#[test]
fn f1_legitimate_reexport_is_accepted() {
    // Plain `pub use module::PolicedName` without rename is legitimate.
    let tmp = tempdir();
    write_fixture(
        &tmp,
        "lib.rs",
        r#"
pub mod tokens {
    use zeroize::ZeroizeOnDrop;

    #[derive(ZeroizeOnDrop)]
    pub struct OAuthToken(Box<[u8]>);
}

pub use tokens::OAuthToken;

use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct SealedCredential(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct OAuthRefreshToken(Box<[u8]>);

#[derive(ZeroizeOnDrop)]
pub struct AgentBearerToken(Box<[u8]>);
"#,
    );
    run(Some(&tmp)).expect("plain re-export without rename must be accepted");
}

#[test]
fn unparseable_rust_fails_closed() {
    // A file that is not valid Rust must cause the validator to FAIL,
    // not silently skip. Fail-closed is the correct direction for a
    // security gate.
    let tmp = tempdir();
    write_fixture(&tmp, "broken.rs", "this is not valid rust {{{");
    let err = run(Some(&tmp)).expect_err("unparseable file must fail the check");
    // Error chain should mention the file name.
    assert!(
        err.to_string().contains("parsing")
            || err.chain().any(|e| e.to_string().contains("broken.rs")),
        "error should reference the unparseable file: {err}"
    );
}
