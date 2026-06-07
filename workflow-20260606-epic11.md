# Epic 11 — Connector / Connection / Binding — Workflow Log

**Started:** 2026-06-06
**Branch:** `feat/epic-11-connector-connection-binding`
**Driver:** dev-workflow-orchestrator (full BMAD lifecycle, autonomous)

## Operating directives (confirmed with Austin 2026-06-06)
- **Fully autonomous** across all 17 stories; override per-phase BMAD pauses. Stop only for genuinely critical/blocking questions.
- **11.11 PoC GO/NO-GO**: auto-proceed into Phase 4 if all PoC acceptance criteria pass locally; stop only on NO-GO (defects found).
- **Commit at each story** (separate per-story commits, no squash — matches "one PR per epic" but commits accrue on the branch).
- **No release.** No tag, no brew publish, no PR merge. Local tests only.
- **Local gate** for every Rust edit: `cargo nextest run --features test-seam` + `cargo fmt --check` + `cargo clippy --all-features -D warnings`. Proxy-only runs OMIT `--features test-seam` (test-seam not on proxy).

## Per-story lifecycle
For each story N: create-story (spec file) → dev-story (implement) → code-review → fix → commit. Each story file: `_bmad-output/implementation-artifacts/11-N-<slug>.md`.

## Phase / story status

### Phase 1 — Connector-def format + registry + validator
- [x] 11.1 — Connector-definition format (`connector.toml` schema + typed model) ✅ committed
- [x] 11.2 — Express built-in Gmail/Calendar/Drive as connector defs (embedded) ✅ committed (hybrid: metadata only)
- [x] 11.3 — Connector registry + load-time validator + host-installed discovery ✅ committed

### Phase 2 — Proxy reads from registry
- [x] 11.4 — Generic `ConnectorMcpServer` + dynamic `/mcp/{selector}` route ✅ committed (hybrid: ConnectorMcpService resolver; 3 servers retained as handler registry; mcp_conformance unchanged; host-installed passthrough stubbed for follow-up)
- [x] 11.5 — `UpstreamClient::dispatch` takes resolved connector; delete `base_urls` ✅ committed (registry threaded into ProxyService; from_client test ctor; refresh-test virtual-clock fix)
- [x] 11.6 — Per-call resolved-host SSRF enforcement (FR91 / NFR52) ✅ committed (ssrf_guard: host-allowlist all + host-installed https/range deny; UpstreamHostBlocked 403)
- [ ] 11.7 — Scope vocab + tier resolution from def; retire `scopes.rs` match + `SUPPORTED_SERVICES` ×3

### Phase 3 — Connection / Binding + crypto v2 (PoC gate)
- [ ] 11.8 — Crypto v2 domain: ConnectionId + Slot keying (NFR51)
- [ ] 11.9 — CredentialStore re-key + ConnectionStore + BindingStore; drop `policy_name`
- [ ] 11.10 — Request-time authz: bearer→agent→binding→connection→connector→tier
- [ ] 11.11 — **PoC GO/NO-GO gate** (auto-proceed if green)

### Phase 4 — CLI re-split + control-plane seal API
- [ ] 11.12 — Control-plane seal API: `{service}` → `connection_id` + `slot`
- [ ] 11.13 — `connection add`/`list`/`inspect`/`revoke`
- [ ] 11.14 — `bind`/`unbind`/`agent bindings`
- [ ] 11.15 — Re-pointed `quickstart`

### Phase 5 — Clean-install + multi-account validation
- [ ] 11.16 — Clean-install path (v2-only)
- [ ] 11.17 — Multi-account e2e validation on angie-2 (Chuck) — live angie pass is operator-run

## Decision / event log
- 2026-06-06: Branch created off main @ 1b9211b. Epic doc is `ready-for-dev`. No 11.x story files exist yet — creating them per story.
- 2026-06-06: **11.1 done + committed** (5f46819). `ConnectorDef` typed model in permitlayer-connectors; gate green.
- 2026-06-06: **CRITICAL ARCHITECTURE QUESTION raised at 11.2.** The epic plan treats built-in tool catalogs as declarative data, but the real `*McpServer` tools are hand-written Rust: 36 typed param structs, ~160 bespoke-logic call sites (query-string building, resource-id/calendar-id validation, JSON body coercion, 552-line Gmail response shaper, attachment-bytes-to-disk). A pure connector.toml `[[tools]]` can't reproduce that without either regressing behavior or building an unscoped declarative engine. Austin chose: **do web research to determine the best long-term / highest-UX / lowest-maintenance / most-compatible architecture** before implementing. Launched deep-research workflow (run wf_1c3f4177-d06). 11.2 BLOCKED on the research outcome + an architecture decision (likely an epic-doc amendment to 11.2/11.4/11.7).
- 2026-06-06: **Phase 1 complete** (11.1/11.2/11.3 committed: 5f46819, 9db5bed, 150757f). **11.4 committed** (9431242) — the load-bearing rewrite; mcp_conformance UNCHANGED (355 proxy + 1290 daemon tests green). Autonomous override added to CLAUDE.md per Austin ("don't stop").
- 2026-06-06: **11.5 in progress** — design: thread `Arc<ConnectorRegistry>` into `ProxyService` so `service.rs` resolves `req.service`→connector→`upstream.base_url`/`allowed_hosts`; `dispatch` takes the upstream spec; delete `base_urls` map + `with_client_and_urls`. The registry field also serves 11.7/11.10. Many test constructors of UpstreamClient/ProxyService will need updating.
- 2026-06-06: **Research complete** (24/25 claims confirmed 3-0; 21 sources). Verdict: **HYBRID is the dominant, lowest-risk pattern.** Declarative owns identity/auth/routing/scope/tier/tool-advertisement; CODE owns the per-endpoint long tail (param→query, validation, body coercion, response shaping, attachments). Nango is the canonical hybrid (declarative auth+proxy routing, code sync/actions). n8n's own docs mandate code style for pagination/custom-request/response-transform. Pure-declarative has a hard ceiling (confirmed 3-0). Third-party trust: WASI capability-sandbox or out-of-process RPC. Recommendation written for Austin's decision.
