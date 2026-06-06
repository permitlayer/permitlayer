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

_No changes yet._

## [1.2.2] - 2026-06-06 — `agentsso` binary

Patch release. Fixes a macOS upgrade failure that could leave the daemon
down. Workspace / binary version bump 1.2.1 → 1.2.2; the plugin host-API
surface keeps its independent cadence (unchanged).

### Fixed

- **`sudo agentsso setup --upgrade` on a long-uptime macOS daemon no
  longer fails and leaves the daemon down.** After `launchctl bootout`,
  launchd's service-domain release lags proportional to prior uptime, so
  the immediately-following `launchctl bootstrap` could return `Bootstrap
  failed: 5: Input/output error`. The existing retry budget was too short
  for a multi-hour-uptime daemon, and when the forward bootstrap exhausted
  it, setup's rollback exhausted the same budget too
  (`setup.rollback_incomplete`, `rebootstrapped=false`). setup (and
  `doctor`'s stale-launchd fix) now poll until the label is fully released
  before bootstrapping, with the existing retry kept as a backstop.

## [1.2.1] - 2026-06-05 — `agentsso` binary

Patch release. Fixes the read-write onboarding path (`quickstart` /
`connect --read-write` now actually grant write access) and removes the
inert MCP scope header. Workspace / binary version bump 1.2.0 → 1.2.1;
the plugin host-API surface keeps its independent cadence (unchanged).

### Fixed

- **`agentsso quickstart <service> --read-write` / `agentsso connect
  --read-write` now request the write OAuth scopes from Google.**
  Previously `--read-write` bound the agent to the `<svc>-read-write`
  policy but the OAuth consent still requested only read-only scopes, so
  the sealed credential could not write — every send/modify returned
  `scope-insufficient`. The access level now flows into the OAuth grant
  (`gmail.send`/`compose`/`modify` for Gmail), and re-running over an
  existing read-only credential re-prompts to add the write scopes.
- `agentsso connect --read-write` against a `-read-only` policy (or a
  `-read-write` policy without the flag) now warns before OAuth instead
  of failing silently at request time. Custom (non-suffixed) policy
  names carry no tier signal and are left unwarned.

### Changed

- **The MCP config snippet emitted by `quickstart`/`connect` no longer
  carries an `x-agentsso-scope` header.** On the `/mcp` path the daemon
  derives each tool's required scope server-side and never read the
  client header, so it was inert and — by implying one scope governs
  every call — misleading. The snippet now carries only the bearer. (The
  REST `/v1/tools/*` path still requires the `x-agentsso-scope` header
  per request; that path is unaffected.)
- The `connect`/`quickstart` success summary now shows the full granted
  scope set, and the extend-existing-agent flow points operators at
  `agentsso agent rotate <agent>` to obtain a usable bearer. A note now
  warns that credentials are shared per-service across all agents.

## [1.0.0] - 2026-05-28 — `agentsso` binary

First stable release of the `agentsso` binary. This is a workspace /
binary version bump only; the plugin host-API surface remains at
`1.0.0-rc.1` (next section) with its own independent cadence.

The road from `0.3.0-rc.1` (April 2026) to `1.0.0` shipped four
overlapping epics. The highlights below summarize the user-visible
surface at 1.0; per-rc release notes for every step along the way are
preserved on
[GitHub Releases](https://github.com/permitlayer/permitlayer/releases).

### Highlights

- **macOS as a system service.** The daemon ships as a root
  LaunchDaemon at `/Library/LaunchDaemons/dev.permitlayer.daemon.plist`,
  installed via `sudo agentsso setup`. The control plane (`agent
  register`, `kill`, `resume`, `status --connections`) lives on a Unix
  domain socket at `/var/run/permitlayer/control.sock` gated to the
  `permitlayer-clients` group. The MCP data plane (`/mcp/*`) lives on
  TCP loopback at `127.0.0.1:3820`. Per-service routes
  (`/mcp/{gmail,calendar,drive}`); bare `/mcp` is not a route.
- **`sudo agentsso setup` is the canonical install + upgrade verb.**
  Idempotent, self-healing (re-stages the privileged binary,
  re-bootstraps wedged LaunchDaemons), and detects/repairs the
  daemon-crashing legacy-policy shadow from earlier rc lines. The
  older `agentsso service install` verb still works as a loud
  redirect. `sudo agentsso uninstall` is the matching one-step
  teardown.
- **`agentsso quickstart <service> --read|--read-write --oauth-client
  <json>` is the one-command agent connect.** Registers the agent
  under the matching shipped policy
  (`{gmail,calendar,drive}-{read-only,read-write}`), drives the OAuth
  flow, seals tokens into the OS keychain, and emits an MCP config
  snippet (with `transport: streamable-http`, the bearer token, and
  the `x-agentsso-scope` header all baked in). Idempotent —
  re-running rebinds scope and rotates credentials cleanly. The
  underlying `agent register` and `connect <service>` verbs still
  exist for advanced use.
- **`agentsso doctor [--fix] [--json] [--restart-ok]`** — diagnostic
  command with truthful findings, legacy-seed snapshot garbage
  collection, and an actionable `--fix` mode.
- **Multi-service agents with per-agent policy materialization.** One
  agent can be extended onto Gmail, Calendar, and Drive — the daemon
  composes the per-agent policy from the matching shipped tiers.
- **`agentsso update`** is a drift detector (it reports whether the
  installed binary matches the latest published release); the upgrade
  path is `brew upgrade permitlayer/tap/agentsso && sudo agentsso
  setup`.
- **Connector capability coverage.** Read/write tiers across
  Gmail (26 MCP tools, including the `gmail.attachments.get` /
  `gmail.messages.get` two-step flow), Calendar (12), and Drive (8).
  Headless daemon — no human-in-the-loop approval; access is binary
  per the bound policy tier.
- **OAuth onboarding for non-local browsers.** `--headless`
  (paste-redirect) for SSH sessions and `--device-flow` (RFC 8628
  with TV/Limited-Input OAuth clients) for fully-headless CI / cloud
  provisioning.
- **Cross-user provisioning.** Daemon-runs-as-root vs.
  end-user-account split documented and reliable. The
  `permitlayer-clients` group + `dseditgroup` flow handles the
  multi-operator case.
- **Bring-your-own OAuth credentials.** Desktop-app client JSON sealed
  into the encrypted vault on `quickstart`; the `client_id`,
  `client_secret`, and refresh token never leave the machine.
- **Response scrub engine.** Built-in rules for bearer tokens, JWTs,
  OTPs, password-reset links, emails, phones, SSNs, credit cards —
  redacted with one-way `<REDACTED_*>` placeholders before responses
  reach the agent.
- **Tamper-evident audit log** with `agentsso audit
  [--limit N] [--follow] [--export=audit.csv]`.
- **Kill switch.** `agentsso kill` flips the daemon into refuse-all
  mode (HTTP 403 `kill_switch_active`); `agentsso resume` restores.
- **Connector plugins** run sandboxed in an embedded QuickJS runtime.
  Author your own with `agentsso connectors new`.
- **OpenClaw skill.** `clawhub install agentsso-gateway` drops an
  agent-facing skill that documents the policy/scrub/audit model and
  the non-obvious tool flows (Gmail attachments two-step,
  base64url decoding, `calendar.events.update` PUT semantics).

### Notes for users upgrading from the rc track

- `brew upgrade permitlayer/tap/agentsso && sudo agentsso setup` is
  the upgrade path. No flag changes; no operator-policy migration
  needed — `setup` auto-heals the legacy-seed shadow if any
  rc.31-era operator `policies/default.toml` is still on disk.
- The MCP config snippet emitted by `quickstart` is what your MCP
  client (OpenClaw / Claude Desktop / Cursor) consumes. If you
  hand-built an MCP config against pre-overhaul docs, re-run
  `agentsso quickstart <service> --mcp-config-out <path>` to get the
  current shape (per-service URL, `streamable-http` transport,
  bearer + scope headers).
- The bundled brew formula's `caveats` text was refreshed for 1.0
  (post-install hint now leads with `setup` + `quickstart`, not the
  old `service install` + `agent register` + `connect` three-step).

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
