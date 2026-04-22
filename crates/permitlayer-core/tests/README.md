# Integration tests for `permitlayer-core`

## Layout (Story 8.8b, collapsed)

```
tests/
├── README.md                ← this file
├── kill9_recovery.rs        ← feature-gated (test-seam); stays separate
├── store_compile_fail/      ← trybuild fixtures (pass/fail subdirs)
└── integration/
    ├── mod.rs               ← crate root: declares all submodules
    ├── snapshots/           ← insta snapshot storage
    ├── audit_fs.rs
    ├── compile_fail.rs      ← trybuild driver (references tests/store_compile_fail/)
    ├── policy_fixtures.rs   ← insta snapshots
    ├── scrub_builtin_rules.rs
    └── scrub_concurrency.rs
```

Default-feature integration tests live in ONE binary named `integration`.
The feature-gated `kill9_recovery.rs` stays its own binary because it
only compiles under `--features test-seam` and collapsing feature-gated
files into a shared parent binary is awkward.

## insta snapshots

Snapshots live under `tests/integration/snapshots/` (moved from
`tests/snapshots/` during the 8.8b collapse). insta resolves snapshot
paths relative to the test source file's directory, so the move is
symmetric with the source-file move.

## trybuild fixtures

The `store_compile_fail/` directory stays at `tests/store_compile_fail/`.
`compile_fail.rs` references it via `CARGO_MANIFEST_DIR`-relative
string paths (`tests/store_compile_fail/pass/*.rs`), unaffected by the
source-file move into `tests/integration/`.

## Adding a new integration test

1. Drop the file into `tests/integration/<name>.rs`.
2. Register it in `tests/integration/mod.rs` with `mod <name>;`.

`autotests = false` in `Cargo.toml` disables cargo's auto-discovery.
Forgetting step 2 means the file compiles but its tests never run.

## Running a single test

```sh
cargo test --test integration <module>::<test>
cargo nextest run -p permitlayer-core -E 'test(<pattern>)'
```

To run the feature-gated `kill9_recovery` test:

```sh
cargo nextest run -p permitlayer-core --features test-seam
```
