# Integration tests for `permitlayer-daemon`

## Layout (Story 8.8b, collapsed)

```
tests/
├── README.md                ← this file
├── common/
│   └── mod.rs               ← shared helpers (free_port, agentsso_bin, DaemonHandle, …)
└── integration/
    ├── mod.rs               ← crate root: declares all submodules + common
    ├── agent_registry_e2e.rs
    ├── approval_prompt_e2e.rs
    ├── audit_drain_on_shutdown_e2e.rs
    ├── audit_export_e2e.rs
    ├── audit_follow.rs
    ├── audit_query_e2e.rs
    ├── config_theme.rs
    ├── connectors_list_e2e.rs
    ├── connectors_new_e2e.rs
    ├── connectors_test_e2e.rs
    ├── credentials_status.rs
    ├── daemon_lifecycle.rs
    ├── kill_resume_e2e.rs
    ├── kill_switch_e2e.rs
    ├── logs_audit_isolation_e2e.rs
    ├── logs_command_e2e.rs
    ├── master_key_bootstrap_e2e.rs
    ├── plugin_loader_e2e.rs
    ├── policy_compile_startup.rs
    ├── policy_enforcement_e2e.rs
    ├── policy_reload_e2e.rs
    ├── scrub_explain_warnings.rs
    └── status_connections_e2e.rs
```

All 23 integration tests live in ONE binary named `integration`. The
shared `common/mod.rs` is declared via `#[path = "../common/mod.rs"] mod
common;` in `integration/mod.rs`, so submodules import helpers as
`use crate::common::{free_port, agentsso_bin, …}`.

Pre-Story-8.8b, this crate had 23 separate integration test binaries
and 10 copies of `fn free_port()` + 12 copies of `fn agentsso_bin()`
scattered across test files. The collapse eliminated all duplicates.

## Adding a new integration test

1. Drop the file into `tests/integration/<name>.rs`.
2. Register it in `tests/integration/mod.rs` with `mod <name>;`.
3. Import shared helpers via `use crate::common::{…};`.

`autotests = false` in `Cargo.toml` disables the old auto-discovery.
Forgetting step 2 means the file compiles but its tests never run.

## Shared helpers in `common/mod.rs`

Public exports include:

- `free_port() -> u16`
- `agentsso_bin() -> PathBuf`
- `start_daemon(DaemonTestConfig) -> DaemonHandle`
- `DaemonHandle` (with `Drop` that SIGKILLs the subprocess)
- `wait_for_health(port) -> bool`
- `http_get`, `http_post`, `http_post_json`
- `loopback_addr`, `path_str`
- `TEST_MASTER_KEY_HEX`, `SENTINEL_HOME`

Some submodules define their own local HTTP helpers (e.g.
`approval_prompt_e2e.rs` has its own `http_get`/`http_post`/`http_request`
because the Story 4.5 tests need response bodies rather than the
default status-only helpers). Local helpers take precedence over
`common::*` inside the module they're defined in.

## Running a single test

```sh
cargo test --test integration <module>::<test>
cargo nextest run -p permitlayer-daemon -E 'test(<pattern>)'
```

Example: run only `approval_prompt_e2e::approval_timeout_*`:

```sh
cargo nextest run -p permitlayer-daemon -E 'test(approval_timeout)'
```
