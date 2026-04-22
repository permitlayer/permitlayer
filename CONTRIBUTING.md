# Contributing to permitlayer

Thanks for your interest. permitlayer is pre-1.0 and moves quickly — opening
an issue to discuss non-trivial changes before you start coding will save
everyone round-trips.

## Ground rules

- **Security reports:** do not file public issues. See [SECURITY.md](SECURITY.md).
- **License:** by submitting a contribution you agree it's MIT-licensed.
- **Scope:** small, focused PRs beat grand refactors. If a change touches
  multiple crates, a design sketch in an issue first is appreciated.

## Dev setup

See the "Development setup" section of the [README](README.md). Summary:

1. `./scripts/bootstrap.sh` — one-time toolchain + nextest + lld install.
2. On macOS: enable Developer Tools for your terminal so XProtect doesn't
   stall test runs (`sudo spctl developer-mode enable-terminal`, then toggle
   your terminal in System Settings → Privacy & Security → Developer Tools).
3. `cargo nextest run --workspace` — fast test suite (Keychain conformance
   tests are in the `full` profile).

## The gates a PR must clear

- `cargo nextest run --workspace` — unit + integration tests.
- `cargo fmt --all --check` and `cargo clippy --workspace --all-targets`.
- `cargo xtask validate-credentials` — enforces the trait discipline on
  the 4 policed credential types (SealedCredential, OAuthToken,
  OAuthRefreshToken, AgentBearerToken). New code that derives Serialize /
  Debug / Display / Clone on these will fail this gate.
- `cargo xtask validate-plugin-api` — snapshots the plugin host API surface
  against `host-api.lock`. Breaking drift without a major bump fails CI;
  additive drift prints a reminder to run with `--update` and commit the
  refreshed lockfile.

## CODEOWNERS

Paths under `crates/permitlayer-credential/`, `xtask/src/validate_credentials/`,
`deny.toml`, `Cargo.toml`, and `rust-toolchain.toml` require review from the
credential-security owner listed in `.github/CODEOWNERS`. This is deliberate
— the orphan rule doesn't prevent a credential crate from implementing
dangerous traits on its own types, so these paths get human review beyond
the automated gates.

## Architecture decision records

Non-trivial architectural choices are captured as ADRs under
[`docs/adrs/`](docs/adrs/). If you're proposing a design that deviates from
an existing ADR, either update that ADR in the same PR or propose a
superseding one.

## Commits and PRs

- Reasonable commit messages (imperative mood, one-line summary, optional
  body explaining the *why*).
- Link the issue the PR resolves when one exists.
- Fill in the PR description — what changed, why, how it was tested.

## Connector plugins

If you're adding a built-in connector (under
`crates/permitlayer-connectors/src/js/`), scaffold with
`agentsso connectors new`. The host-API surface is enumerated in the
[`host-api.lock`](host-api.lock) file at the repo root and the
matching Rust source under `crates/permitlayer-plugins/src/host_api/`.
The lockfile is enforced by the `plugin-api` CI job — breaking drift
fails the build.
