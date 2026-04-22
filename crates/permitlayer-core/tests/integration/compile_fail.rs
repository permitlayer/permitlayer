//! Compile-fail proof that `CredentialStore::put` refuses plaintext
//! credential types and accepts only `SealedCredential`.
//!
//! This test is the compile-time counterpart to the runtime credential
//! discipline (`cargo xtask validate-credentials`): even if an
//! attacker or a careless dev tried to slip a plaintext token across
//! the storage boundary, the type system rejects it before code can
//! run.
//!
//! # On committed `.stderr` snapshots
//!
//! trybuild 1.x requires a matching `.stderr` file for every
//! `compile_fail` case — on first run it writes a `wip/` snapshot and
//! then fails the test, rather than silently accepting any diagnostic.
//! The project keeps these snapshots short and stable (type names +
//! error codes only, no spans that drift between Rust versions) so
//! toolchain bumps cost at most a `TRYBUILD=overwrite` re-record.
//!
//! Local iteration: `TRYBUILD=overwrite cargo test -p permitlayer-core
//! --test compile_fail` regenerates snapshots in place.

#[test]
fn store_rejects_plaintext_types() {
    let t = trybuild::TestCases::new();
    t.pass("tests/store_compile_fail/pass/*.rs");
    t.compile_fail("tests/store_compile_fail/fail/*.rs");
}
