# Changelog

All notable changes to permitlayer are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Two versions live in this repo**, with independent cadences:

- The **`agentsso` binary / workspace version** is pinned in `Cargo.toml`
  (`workspace.package.version`) and follows the project's own release
  timeline.
- The **plugin host-API version** (`HOST_API_VERSION` in
  `permitlayer-plugins`) is what this changelog tracks, section by
  section. It's the contract that connector plugins compile against.

They are intentionally decoupled — a binary release can ship without a
host-API bump, and a host-API bump can land mid-binary-version.

This changelog is also the reference document for the NFR41 plugin-API
semver contract: deprecated host-API methods MUST appear in a
`Deprecated` section with the removal timeline, and a `Removed` entry
is required when a method is dropped in a major bump.

## [Unreleased]

_No unreleased host-API changes yet._

## [1.0.0-rc.1] - 2026-04-18

First release-candidate of the connector-plugin host API surface
(`agentsso.*` in JS). Pre-release; the surface may still iterate
before `1.0.0` proper is locked. NFR41's 6-month deprecation window
applies once the rc qualifier is dropped; changes during the rc stage
are permitted without a major-version bump.

### Added

- **`host-api.lock`** committed at the workspace root — a plain-text
  snapshot of the host-API surface that Story 6.5's new
  `cargo xtask validate-plugin-api` recomputes on every PR and
  diffs against the committed file. Breaking drift fails CI; additive
  drift prints a reminder to run the xtask with `--update` and commit
  the refreshed lockfile.
- **`cargo xtask validate-plugin-api`** xtask subcommand (with an
  optional `--update` flag) that walks the `permitlayer-plugins`
  crate source via `syn`, extracts the semver-locked surface (the
  `HOST_API_VERSION` constant, the `JS_SURFACE` method list, the
  `HostApiErrorCode` variant set, the `HostServices` trait signatures,
  and the DTO shapes crossing the JS marshalling boundary), and
  serializes them to `host-api.lock`. The rc qualifier on
  `HOST_API_VERSION` puts the gate in "update-freely" mode — once
  `1.0.0` lands, breaking changes require an explicit major bump.
- **`plugin-api` CI job** (`.github/workflows/ci.yml`) — a dedicated
  GitHub Actions job that runs `cargo xtask validate-plugin-api` on
  every PR. Fails the PR status check on a breaking change that was
  not accompanied by a major bump.
- **`permitlayer-plugins::host_api::JS_SURFACE`** — a hand-curated
  `&[&str]` const that enumerates every `agentsso.*` surface entry.
  Adding a new method requires two coordinated edits (register +
  add-to-JS_SURFACE); a guardrail unit test catches drift.
- **`permitlayer-plugins::host_api::services::all_error_code_names()`**
  — deterministic enumeration of every named `HostApiErrorCode`
  variant's `Display` string. Consumed by the xtask; also exposes
  the round-trippable invariant via a unit test.
- **`agentsso.deprecated` namespace** — empty frozen object installed
  by `host_api::register_host_api` as scaffolding for the NFR41
  6-month-deprecation-window contract. 1.x stories that deprecate a
  host-API method register a warning-wrapper via
  `host_api::deprecated::install_deprecated` so operators see a
  single `tracing::warn!` line per method per daemon lifetime.
- **`host_api::deprecated::DeprecationWarnEmitter` trait +
  `TracingDeprecationWarnEmitter` default impl** — service layer for
  the rate-limited deprecation warn. Unused at 1.0.0-rc.1; unit-tested
  to prove the machinery works before 1.x consumers land.
- **This `CHANGELOG.md`** — the NFR41 contract reference document.

### Notes

- `HOST_API_VERSION` stays at `"1.0.0-rc.1"` after this release. The
  `1.0.0-rc.1` → `"1.0.0"` transition happens in a separate PR after
  operators have had a chance to write against the rc surface; the
  rc → 1.0 flip is deliberately not bundled with the snapshot-gate
  introduction so bugs in either change are easier to bisect.
