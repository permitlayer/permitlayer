# Integration tests for `permitlayer-plugins`

## Layout (Story 8.8b, collapsed)

```
tests/
├── README.md               ← this file
└── integration/
    ├── mod.rs              ← crate root: declares all submodules
    ├── deny_toml_allowlist_extended.rs
    ├── host_api_surface.rs
    ├── loader.rs
    ├── sandbox_escape.rs
    ├── scope_allowlist.rs
    └── stub_services.rs
```

All integration tests live in ONE binary named `integration`, not the
default "one binary per `tests/*.rs`" fan-out. Cargo's own book
[recommends this pattern][1] for workspaces with many integration
tests; ripgrep ships it (see their [`Cargo.toml`][2]).

[1]: https://doc.rust-lang.org/cargo/reference/cargo-targets.html#integration-tests
[2]: https://github.com/BurntSushi/ripgrep/blob/master/Cargo.toml

## Adding a new integration test

1. Drop the file into `tests/integration/<name>.rs`.
2. Register it in `tests/integration/mod.rs` with `mod <name>;`.

Forgetting step 2 means the file compiles but its tests never run —
`autotests = false` in `Cargo.toml` disables cargo's auto-discovery of
`tests/*.rs`.

## Running a single test

Old idiom (one binary per file): `cargo test --test loader -- my_test`.

New idiom:
```sh
cargo test --test integration loader::my_test
cargo nextest run -p permitlayer-plugins -E 'test(my_test)'
```

nextest's `test()` filter matches on the full module path (e.g.
`integration::loader::my_test`), so partial matches still work.
