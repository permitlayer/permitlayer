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

## Tests that stay separate (and why)

Two integration tests deliberately live OUTSIDE `tests/integration/`
as their own `[[test]]` entries in `Cargo.toml`. Both have specific
reasons that future "cleanup" passes MUST NOT undo:

- **`tests/kill9_recovery.rs`** — feature-gated (`required-features =
  ["test-seam"]`). Only compiles under `--features test-seam`;
  collapsing feature-gated files into a shared parent binary makes
  the gate awkward (every other test would also pay the
  feature-build cost on `--all-features` runs).
- **`tests/vault_lock_conformance.rs`** — self-spawns the test
  binary via `std::env::current_exe()` to verify cross-process
  flock semantics. The child process branch is gated on
  `PERMITLAYER_VAULT_LOCK_CHILD_HOME` and exits 0 immediately when
  set. If this file were collapsed into `integration`, the
  re-invoked child would run inside the same binary that holds
  every other integration test — and the child's `process::exit(0)`
  would silently mask any real failures during normal runs.
  Keeping it a separate binary preserves the invariant that
  "child re-invocation runs ONLY this test."

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
