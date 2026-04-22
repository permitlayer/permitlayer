# Integration tests for `permitlayer-proxy`

## Layout (Story 8.8b, collapsed)

All integration tests live in ONE binary named `integration`. Drop a
new `.rs` file into `tests/integration/` and register it in
`tests/integration/mod.rs` with `mod <name>;`. `autotests = false` in
`Cargo.toml` disables the old one-binary-per-file auto-discovery.

Rationale and prior art: see `crates/permitlayer-plugins/tests/README.md`.

## Running a single test

```sh
cargo test --test integration <module>::<test>
cargo nextest run -p permitlayer-proxy -E 'test(<pattern>)'
```
