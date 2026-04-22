# ADR 0001: Kill switch control plane — loopback HTTP POST on a carved-out router

- **Status:** Accepted
- **Date:** 2026-04-11
- **Deciders:** Story 3.2 (`agentsso kill` / `agentsso resume`) implementation
- **Relates to:** FR61-FR66, NFR6, NFR17, Epic 2 retrospective critical prep item #3
- **Supersedes:** n/a (first ADR in this repo)

## Context

Story 3.1 shipped the `KillSwitch` type, the `KillSwitchLayer` tower middleware, and the `daemon_killed` 403 response body. It deliberately left a question open: how does `agentsso kill` (a short-lived CLI process) tell a running daemon (a long-lived HTTP server process) to flip the atomic flag?

The Epic 2 retrospective flagged this as a critical prep item for Epic 3:

> Decide on control plane for `agentsso kill` ↔ daemon: control socket? HTTP POST to a privileged endpoint? In-process signal? Architecture spec is silent.

Constraints:

- **NFR6** — kill activation must complete in under 2 seconds end-to-end (CLI invocation → daemon state change → CLI banner render).
- **FR62** — kill must preserve stored OAuth refresh tokens. The control plane must not touch the vault.
- **Portability** — the daemon targets macOS, Linux, and Windows (Story 7.2). Any solution must work on all three.
- **Kill-switch carve-out** — the control endpoint must keep working when the daemon is killed. If `resume` can't reach the daemon while it's in kill state, the kill switch is a one-way door and violates FR63.
- **Security** — the control endpoint must not become a remote unauthenticated kill switch if someone misconfigures `bind_addr` to a non-loopback interface.

## Decision

**HTTP POST to loopback-only control endpoints on the main daemon port, served from a separate axum router that is merged into the app after the main middleware layer.**

Concretely:

- **Routes:**
  - `POST /v1/control/kill`   → calls `KillSwitch::activate(UserInitiated)`, returns `ActivationSummary`
  - `POST /v1/control/resume` → calls `KillSwitch::deactivate()`, returns `DeactivationSummary`
  - `GET  /v1/control/state`  → reports `is_active()`, `activated_at()`, `token_count()`
- **Transport:** the same TCP listener the daemon already binds for MCP/REST (`127.0.0.1:3820` by default).
- **Router separation:** `server::control::router()` returns an axum `Router` with its own `ControlState` (just `Arc<KillSwitch>`) and **no middleware**. It is merged into the main app in `cli/start.rs` **after** `.layer(middleware)` has been applied to the main router, so control routes sit outside `KillSwitchLayer`.
- **Loopback guard:** each handler extracts `axum::extract::ConnectInfo<SocketAddr>` and returns `403 forbidden_not_loopback` if `peer.ip().is_loopback() == false`. `cli/start.rs` serves the app via `axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())` to enable the extractor.
- **Response shape:** daemon-side wrapper structs (`SerializableActivationSummary`, `SerializableDeactivationSummary`) serialize `activated_at` / `resumed_at` as RFC 3339 strings with millisecond precision and `Z` suffix — the same format the audit log uses, so operators can grep-correlate control responses with audit entries.
- **CLI:** `cli::kill` and `cli::resume` drive raw TCP → HTTP/1.1 requests with a 1500ms deadline, matching the pattern in `cli::status`. CLI startup (100-300ms) + HTTP round trip (~5ms on loopback) + banner render (~10ms) totals 150-350ms typical, well inside NFR6's 2000ms budget.

## Alternatives considered

### Unix domain socket on `~/.agentsso/agentsso.sock`

- **Pros:** filesystem permissions are a stronger access boundary than a loopback IP check; no port conflict with localhost services.
- **Cons:** Windows does not support Unix domain sockets in the `tokio::net::UnixStream` sense until very recent Win10 builds, and `axum` / `hyper` would need a second listener implementation. No meaningful security gain over loopback + `is_loopback()` check given the single-user-per-machine trust model (see `memory/project_openclaw_landscape.md`). **Rejected** — doubles the listener surface area without a concrete benefit, and hurts portability.

### POSIX signal (SIGUSR1 / SIGUSR2) from CLI to PID

- **Pros:** `agentsso stop` / `agentsso reload` already use signals (`SIGTERM` / `SIGHUP`). Minimal new code.
- **Cons:** signal-safe code paths cannot easily carry metadata. The CLI needs structured response data (`ActivationSummary.tokens_invalidated`, `activated_at`, `was_already_active`) to render the banner — a signal can wake a handler but can't return a payload. You'd need a secondary IPC channel to carry the result back, at which point the signal adds complexity without simplifying anything. Windows signal semantics are also weaker than POSIX, and the no-op-on-Windows hedges in `stop.rs` / `reload.rs` are painful. **Rejected** — structured response data is a hard requirement for the `KillBanner` UX; signals can't deliver it cleanly.

### Dedicated privileged control port (e.g., `127.0.0.1:3821`)

- **Pros:** stricter separation between public API and control plane.
- **Cons:** more port conflict surface area, more configuration (what port? configurable? clash with what?), and no real security gain over a loopback-only endpoint on the existing port. **Rejected** — extra surface for no benefit.

### gRPC control plane

- **Pros:** typed, schema-first.
- **Cons:** pulls in a second RPC stack (tonic + prost) for three endpoints that ship ~50 lines of handler code each. **Rejected** — over-engineering for the scope.

## Consequences

### Positive

1. **Kill-switch carve-out is explicit and tested.** The `control_router` is merged after `.layer(middleware)`, and an integration test (`tests/kill_resume_e2e.rs::control_resume_bypasses_kill_middleware`) fires `POST /v1/control/resume` against a killed daemon and asserts 200 rather than 403.
2. **No new deps.** Everything runs on the existing axum / tokio / serde stack. No new listener code, no new parsing, no new dev-deps for tests.
3. **Operator grep-correlation is preserved.** The control responses use the audit-log timestamp format (`%Y-%m-%dT%H:%M:%S%.3fZ`), so a `grep` for the activation timestamp finds both the control response and the `kill-activated` audit event (once Story 3.3 writes the audit event).
4. **NFR6 budget has ample headroom.** Measured typical round trip is 150-350ms; NFR6 budget is 2000ms. Tail latency test asserts 3 sequential kills all complete within the budget.
5. **Future-compatible with Tier 3 multi-tenant mode.** The control router is a deliberately small module that a future multi-tenant deployment can extend with token-based auth without disturbing the single-user-per-daemon MVP semantics.

### Negative

1. **The loopback guard is inline in each handler, not a layer.** Adding a new control endpoint means remembering to call `require_loopback(peer)?` at the top. A future `ControlLayer` could enforce this generically, but for three endpoints the duplication is preferable to adding a parallel middleware stack that could drift from `assemble_middleware`. Mitigation: a unit test per endpoint verifies the 403 fires from a non-loopback peer.
2. **Daemon version skew is possible.** `KillResponse.daemon_version = env!("CARGO_PKG_VERSION")` is the *daemon's* version at compile time; a stale daemon running against a newer CLI will report its own (older) version. This is a *feature* — it surfaces version skew during operator troubleshooting — but it does mean the CLI has to tolerate an older schema. Schema changes on the control endpoints should be additive-only, enforced by test.
3. **Non-localhost binds become more dangerous.** If a user runs the daemon with `--bind-addr 0.0.0.0:3820` (against the warning in `start.rs:227`), the main /mcp / /v1/tools routes are exposed to the network. The control endpoints are gated by the loopback runtime check and will 403 non-loopback peers, so they stay safe — but `/health` and the main proxy surface do not have equivalent protection. This is a pre-existing concern; Story 3.2 does not make it worse, but it does mean the loopback guard on control endpoints is load-bearing defense-in-depth, not a nice-to-have.
4. **`setup` now depends on the control endpoint for its kill-state check.** If a future refactor moves `/v1/control/state` or changes its schema, `cli/setup.rs` must be updated. Mitigation: the `probe_daemon_kill_state_or_exit` helper fails open on any probe error — a broken probe does not block setup.

## Implementation notes

- The control router is built by `crate::server::control::router(Arc<KillSwitch>)` and merged in `cli/start.rs` immediately after the main router's `.layer(middleware)`. Any future work that builds the main router differently must also call `router()` for the control plane, or the control endpoints go missing.
- The `ControlState` struct holds only `Arc<KillSwitch>`. It is deliberately distinct from `cli::start::AppState` so the control surface cannot grow a transitive dependency on daemon-wide state.
- `SerializableActivationSummary` and `SerializableDeactivationSummary` live on the daemon side (`server/control.rs`), not in `permitlayer-core`. `permitlayer-core` stays free of `serde` and web framework concerns per AR33 / AR34.
- **Story 3.2 writes no audit events.** `kill_handler` / `resume_handler` leave `TODO(Story 3.3)` comments at the points where Story 3.3 will emit `kill-activated` / `kill-resumed` audit events. The `BannerInputs.audit_written` field defaults to `false` in Story 3.2 and Story 3.3 will flip it to `true` without a banner code change.

## References

- `crates/permitlayer-daemon/src/server/control.rs` — handler + router + tests
- `crates/permitlayer-daemon/src/cli/start.rs` — router merge + `into_make_service_with_connect_info`
- `crates/permitlayer-daemon/src/cli/kill.rs` — CLI client + shared HTTP helpers
- `crates/permitlayer-daemon/src/cli/resume.rs` — CLI client (with state-probe round trip for `duration_killed`)
- `crates/permitlayer-daemon/src/cli/setup.rs` — `probe_daemon_kill_state_or_exit`
- `crates/permitlayer-daemon/src/design/kill_banner.rs` — `KillBanner` / `ResumeBanner` renderers
- `crates/permitlayer-daemon/tests/kill_resume_e2e.rs` — subprocess integration tests
