# Permitlayer / AgentSSO: Product Summary & Agent Identity Analysis

**Date:** April 7, 2026 (original); appended April 9, 2026
**Status:** Internal memo

> **2026-04-09 addendum.** After this memo was written, we ran the first successful end-to-end shakedown through a real MCP client (OpenClaw) against a real Google Workspace account. That session surfaced three new classes of finding: (1) integration-mechanics issues between permitlayer and OpenClaw, including a compatibility bug we shipped a fix for; (2) two open bugs in permitlayer itself that block unattended operation; (3) a concrete view of OpenClaw's documented threat model and the agent-identity competitive landscape, including the real MolTrust RFC and its reference implementation. The findings extend — not contradict — the identity hierarchy and V0/V1/V2 framing above. New sections are appended after the original "Sources" block as:
>
> - **OpenClaw landscape and threat model (2026-04-09)**
> - **The agent-identity competitive landscape (2026-04-09)**
> - **E2E shakedown: what shipped, what's broken (2026-04-09)**
> - **Research-hygiene note (2026-04-09)**

---

## What Permitlayer Is

Permitlayer (product name: AgentSSO) is an open-core identity and secure data access layer for AI agents. It sits between an agent and the external services it needs to access — Gmail, Calendar, Drive, Slack, GitHub — acting as a gateway that holds credentials, issues short-lived scoped tokens, enforces access policy, scrubs sensitive content, and provides a kill switch.

The open-source core is a Rust workspace of nine crates covering the full stack: type-safe credential primitives with hardware-backed zeroization (`permitlayer-credential`), an encrypted vault using AES-256-GCM/HKDF/Argon2 (`permitlayer-vault`), OS-native keyring integration (`permitlayer-keystore`), OAuth 2.1 client flows (`permitlayer-oauth`), an MCP-compatible proxy (`permitlayer-proxy`), a daemon with Axum/Tokio (`permitlayer-daemon`), and plugin/connector systems for extensibility.

The managed service layer (not yet built) adds hosted vaulting, one-click OAuth for Google/Microsoft, approval flows, audit trails, enriched agent-first APIs (semantic email search, thread summarization), and support.

**MVP target:** OpenClaw integration, Google Workspace (Gmail, Calendar, Drive), kill switch, OTP/reset-link scrubbing, basic audit logs.

**Business model:** Freemium. Free tier (2–3 sources, 1 agent), individual ($4–8/mo), team ($10–15/mo), enterprise custom.

**Primary market:** Consumer and prosumer users running personal AI agents — a segment underserved by the enterprise-heavy incumbents (CyberArk, Auth0, Composio, Arcade).

---

## The Problem: Who Is Calling the Gateway?

Permitlayer's current authentication model is bearer-token-based. A user runs `agentsso agent register`, the system generates an `AgentBearerToken`, and the agent presents it on every request. The middleware chain extracts the token, maps it to an `agent_id`, and enforces policy. Scoped HMAC-SHA256 tokens with 60-second TTLs are issued per-operation on top of that.

This model answers: *does the caller possess a valid credential?*

It does not answer: *is the caller actually the agent it claims to be?*

A bearer token stolen from a config file, exfiltrated by a malicious plugin, or extracted via prompt injection grants the attacker full impersonation rights. The token authenticates the session, not the entity.

This is not unique to Permitlayer — it is the central unsolved problem in agent identity. Every competitor in the space (Auth0 Token Vault, Composio, Arcade, Peta.io) has the same gap. But whoever closes it first has a genuine moat.

---

## The Identity Hierarchy

There are actually four distinct identity questions in the agent security stack, and they require different solutions:

### 1. Is this the registered application? (Process identity)

**Question:** Is the binary making this HTTP request the same OpenClaw process that was registered?

**Current state in Permitlayer:** Not verified. Any process with the bearer token is trusted.

**Solutions available today:**

- **OS-level process attestation.** macOS code signing + `SecStaticCodeCheckValidity`, Windows Authenticode, Linux process audit via `/proc/pid/exe` verification. The daemon can check the calling process's code signature before accepting a connection. This is the lowest-friction improvement and closes the most common attack (malicious script reads token from config file).

- **Unix domain socket with `SO_PEERCRED`.** If the daemon binds to a Unix socket instead of (or in addition to) TCP, the kernel provides the caller's PID/UID. The daemon can verify the process identity at the OS level before any application-layer auth.

- **SPIFFE/SPIRE workload attestation.** The SPIRE agent running on the host attests the workload's identity based on kernel-level properties (PID, UID, binary hash, container metadata) and issues a short-lived X.509 SVID. The agent authenticates to the daemon via mTLS using this SVID. No shared secrets, no config file tokens to steal. This is the approach the IETF's new AIMS framework (draft-klrc-aiagent-auth, March 2026) is standardizing — composing SPIFFE, WIMSE, and OAuth 2.0 into a formal agent identity model.

### 2. Is this agent authorized for this action? (Policy identity)

**Question:** Given that this is agent "email-read-only," is it allowed to call Gmail's send endpoint?

**Current state in Permitlayer:** Designed but partially stubbed. The `PolicyLayer` middleware is in the chain and the architecture specifies compiled IR evaluation against `(agent_id, scope, resource)` tuples. Scoped tokens with 60s TTLs limit blast radius.

**This layer is the strongest part of the current design.** Short-lived scoped tokens, fail-closed semantics, and type-system-enforced credential hygiene are the right primitives. The gap is upstream (proving the agent_id is legitimate), not in policy enforcement itself.

### 3. Is this output actually from a specific LLM? (Model provenance)

**Question:** Did Claude/GPT-4/Llama actually produce the action request, or did a script forge it?

**Current state:** Not addressed anywhere in the industry in a deployed, production form.

**Why it's hard:** LLMs don't possess private keys. The model weights don't contain a secret that can be used for cryptographic proof. Any signing would need to happen at the inference infrastructure layer — the API provider signs the response, not the model itself.

**Emerging approaches:**

- **Inference provider signing.** The LLM API provider (OpenAI, Anthropic, Google) signs each response with a provider key and includes metadata (model version, timestamp, request hash). The downstream system can verify the signature against the provider's public key. No major provider has shipped this in production yet, but it is the most architecturally clean path.

- **OpenAgents AgentID.** Launched February 2026. Each agent gets an Ed25519 keypair, a W3C DID, and verifiable credentials. Actions are signed by the agent's private key, creating a traceable chain. The limitation: the keypair belongs to the agent runtime, not the model — so it proves "this agent framework produced the action" rather than "this specific LLM produced the reasoning."

- **Mastercard Verifiable Intent.** Announced March 2026 for agentic commerce. Links consumer identity, instructions, and transaction outcomes into a tamper-resistant record with a cryptographic audit trail. Built on FIDO, EMVCo, and W3C standards. Narrow (payments only) but demonstrates the pattern.

### 4. Is the human who set this up actually who they claim to be? (User identity)

**Question:** Is the person who ran `agentsso agent register` and authorized Gmail access actually the account owner?

**Current state in Permitlayer:** Handled implicitly through the OAuth consent flow — Google/Microsoft verify the user during the OAuth grant. The daemon inherits that trust.

**This is largely solved** by the upstream IdP. The main risk is session hijacking after the initial grant, which the vault's encryption-at-rest and keyring-backed master key mitigate.

---

## Assessment: What Permitlayer Should Build and When

### MVP (now): Bearer token + process attestation

The current bearer token model is fine for launch. It matches what every competitor ships. Add `SO_PEERCRED` verification on Unix domain sockets and/or code-signature checking to close the stolen-token attack. This is a small amount of work that eliminates the most realistic threat at the consumer tier.

### V1 (3–6 months): SPIFFE-based workload identity

The IETF AIMS draft and the SPIFFE-OAuth integration work (draft-ietf-oauth-spiffe-client-auth) are converging into a real standard. Permitlayer should adopt this as the primary agent authentication mechanism for the managed service. Each registered agent gets a short-lived X.509 SVID issued by a SPIRE agent running alongside the daemon. The agent authenticates via mTLS. No bearer tokens to steal, automatic rotation, and it aligns with where the industry standards are heading.

This is also the right moment to support DID-based agent identity (the OpenAgents pattern) as an alternative for users who want portable, cross-platform agent identities.

### V2 (6–12 months): Inference provenance verification

This depends on LLM providers shipping signed responses. When they do, Permitlayer should be the first gateway that verifies them — checking that every action request flowing through the proxy is backed by a signed inference receipt from a known provider. This would be a genuine differentiator that no competitor is positioned to offer, because it requires being in the request path (which Permitlayer already is).

The play: Permitlayer becomes the chain-of-custody layer. User identity (OAuth) → agent workload identity (SPIFFE/SVID) → model provenance (signed inference) → scoped action token (HMAC) → policy enforcement → audit log. Each link in that chain is cryptographically verifiable. Nobody else is building the full stack.

---

## The Honest Assessment

The agent identity problem has three layers of difficulty:

**Solved:** User identity (OAuth + IdP) and action authorization (scoped tokens + policy). Permitlayer's design handles these well.

**Solvable now:** Process/workload identity. SPIFFE is mature, the IETF is standardizing it for agents, and it's the right next step. The main cost is operational complexity for self-hosted users — running a SPIRE agent alongside the daemon adds deployment surface. For the managed service this is invisible to the user.

**Unsolved but tractable:** Model provenance. This requires coordination with LLM providers and is outside Permitlayer's control. But the gateway position means Permitlayer can be a first mover the moment providers start signing outputs.

**Possibly unsolvable in the general case:** Proving that a specific set of model weights produced a specific output. This is an open research problem in ML (model fingerprinting, watermarking). For practical purposes, infrastructure-level attestation (the provider signs it) is sufficient — you don't need to prove which neurons fired, you need to prove which API endpoint was called and that the response wasn't tampered with in transit.

The strategic implication: Permitlayer doesn't need to solve the hardest version of this problem to win. It needs to be the layer where each solvable piece gets verified, so that when the unsolved pieces become solvable, Permitlayer is already in the right position.

---

## Sources

- [IETF draft-klrc-aiagent-auth: AI Agent Authentication and Authorization](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/)
- [IETF draft-ietf-oauth-spiffe-client-auth: OAuth SPIFFE Client Authentication](https://datatracker.ietf.org/doc/draft-ietf-oauth-spiffe-client-auth/)
- [IETF WIMSE Working Group](https://datatracker.ietf.org/group/wimse/about/)
- [OpenAgents: Introducing Agent Identity](https://openagents.org/blog/posts/2026-02-03-introducing-agent-identity)
- [Mastercard Verifiable Intent Framework](https://www.pymnts.com/mastercard/2026/mastercard-unveils-open-standard-to-verify-ai-agent-transactions/)
- [Bringing SPIFFE to OAuth for MCP (Riptides)](https://blog.riptides.io/bringing-spiffe-to-oauth-for-mcp-secure-identity-for-agentic-workloads/)
- [SPIFFE Meets OAuth2: Workload Identity in the Agentic AI Era (Riptides)](https://riptides.io/blog-post/spiffe-meets-oauth2-current-landscape-for-secure-workload-identity-in-the-agentic-ai-era/)
- [Authenticating MCP OAuth Clients With SPIFFE and SPIRE (Christian Posta)](https://blog.christianposta.com/authenticating-mcp-oauth-clients-with-spiffe/)
- [AI Agent Identity at RSAC 2026 (Biometric Update)](https://www.biometricupdate.com/202603/ai-agent-identity-and-next-gen-enterprise-authentication-prominent-at-rsac-2026)
- [AI Agent Authentication: The Authorization Gap](https://www.rockcybermusings.com/p/i-agent-authentication-authorization-gap)
- [MCP Authentication and Authorization Patterns (Aembit)](https://aembit.io/blog/mcp-authentication-and-authorization-patterns/)
- [AI Agents with DIDs and Verifiable Credentials (arXiv)](https://arxiv.org/html/2511.02841v1)
- [Verifiable Credentials for AI in 2026 (Indicio)](https://indicio.tech/blog/why-verifiable-credentials-will-power-ai-in-2026/)
- [Cryptographic Identity for Auditing Autonomous AI Agents (Dev Journal)](https://earezki.com/ai-news/2026-03-28-cryptographic-identity-systems-for-auditing-autonomous-ai-agents/)
- [PKI and AI Agents (HID Global)](https://blog.hidglobal.com/trust-standards-evolve-ai-agents-next-chapter-pki/)

---

## OpenClaw landscape and threat model (2026-04-09)

The April 7 memo named OpenClaw as the MVP integration target but did not engage with OpenClaw's own documented security posture. The 2026-04-09 session filled that gap. The findings matter for three reasons: (1) OpenClaw's threat model explicitly does not cover what permitlayer covers, which is product-defining; (2) its per-tool permission model is weaker than we assumed, which changes how permitlayer should be positioned; (3) the Q1 2026 ecosystem risk data is significant enough to reshape "why now" framing.

### Sourcing note

The material in this section is drawn from a direct WebFetch of the OpenClaw security documentation at `docs.openclaw.ai/gateway/security` (primary source) and from aggregator summaries of hardening guides and vulnerability tracking (secondary). Where a claim is aggregator-only, it is marked "aggregator-sourced" so a future reader can re-verify before citing in anything public. This flagging exists because in the same session we caught an AI-generated search result hallucinating an entire GitHub discussion — see the research-hygiene note below.

### Load-bearing facts from the primary source

From `docs.openclaw.ai/gateway/security`, verbatim:

> "Personal assistant trust model: this guidance assumes one trusted operator boundary per gateway (single-user/personal assistant model). OpenClaw is **not** a hostile multi-tenant security boundary for multiple adversarial users sharing one agent/gateway."

And on how OpenClaw treats its own extension points:

> "Plugins run in-process with the Gateway. Treat them as trusted code: Only install plugins from sources you trust."

These two quotes, together, define OpenClaw's entire security stance: one trusted operator, all extensions assumed trusted, any isolation is the operator's responsibility via OS-level boundaries. The documentation's hardening checklist then recommends exactly that — separate OS users, separate hosts, separate VPSs for separate trust boundaries.

### What OpenClaw's permission model actually allows

OpenClaw exposes per-agent tool allowlists and denylists, keyed by tool name:

```json5
{
  agents: {
    list: [
      {
        id: "gmail-agent",
        tools: { allow: ["permitlayer-gmail__*"] }
      },
      {
        id: "general-agent",
        tools: { deny: ["permitlayer-gmail__*", "permitlayer-drive__*"] }
      }
    ]
  }
}
```

What this model does **not** express, per the same documentation:

- Per-MCP-server credential scoping (every agent with the tool shares the same credential surface)
- Conditional tool exposure by caller identity or request content
- Per-request scope enforcement (there is no hook for "this call is allowed but that one is not, based on the arguments")
- Immutable audit of which agent called which tool with which arguments

This matters because our April 7 memo framed permitlayer's scoped tokens + policy layer as "partially stubbed, designed, and strongest part of the current design." After seeing what the host client provides, that framing holds up differently: **permitlayer's per-request scope enforcement is not redundant with OpenClaw, it's strictly additive.** OpenClaw's own docs push operators toward coarse tool allowlisting and OS-level isolation; permitlayer's value proposition is providing what those layers don't.

### The "plugin mental model" problem

The OpenClaw docs frame external integrations as "plugins run in-process, treat them as trusted code." When operators bring that mental model to permitlayer, they will assume permitlayer is either (a) an npm-like package they vet once and forget, or (b) a trusted in-process extension whose security properties are the operator's responsibility. **Neither is correct.**

permitlayer runs as a separate daemon, holds credentials the client never sees, and enforces access policy that the client cannot bypass. Its security boundary is out-of-band from the OpenClaw gateway. This must be corrected explicitly in onboarding copy — otherwise operators will either over-trust permitlayer (dismissing it as "just another plugin") or under-trust it (assuming the OpenClaw plugin-hardening playbook applies in full).

Proposed framing for install docs:

> "permitlayer is not an OpenClaw plugin. It runs as an independent daemon, holds sealed OAuth credentials the agent cannot read, and enforces per-request scope restrictions the host client cannot bypass. The security properties permitlayer provides are additive to — not a replacement for — OpenClaw's own hardening guidance. Follow the OpenClaw hardening checklist *and* run permitlayer."

### Q1 2026 ecosystem risk signals (aggregator-sourced)

The following numbers came from multiple aggregator summaries during the April 9 research session. They were not fetched from a single primary source and should be re-verified before citing in any public writeup. They are directionally credible because they appear consistently across independent aggregators, but any specific number may be off.

- **138 CVEs** tracked across OpenClaw and predecessors February through April 2026. Of these, **7 Critical and 49 High** severity.
- **CVE-2026-25253** (CVSS 8.8): zero-click exploit in which visiting a single malicious webpage leaks the gateway authentication token. Implication: the operator's browser is part of OpenClaw's attack surface.
- **42,665** publicly reachable OpenClaw instances verified by one security researcher (Maor Dayan); **5,194** of those confirmed vulnerable.
- **824+ malicious skills** discovered on ClawHub (OpenClaw's public skill registry) in Q1 2026. Hardening guidance treats ClawHub "like npm — trust but verify."

**Why this matters to permitlayer:** even if every claim above is off by 2x, the direction of travel is unambiguous. The consumer/prosumer AI-agent ecosystem is in its equivalent of the 2015 npm left-pad / 2017 S3 bucket moment — massive surface area, immature operator hygiene, rapidly growing threat actor interest. "You need this now" is the correct framing. "You'll need this eventually" is not.

### Inherited blast radius (strategic risk)

One risk the April 7 memo did not surface: permitlayer's security model is fundamentally bounded by the security of the client holding the session. If the OpenClaw gateway is compromised — via one of the 138 CVEs, via a malicious skill, via prompt injection — the compromised client can still call permitlayer's MCP endpoints during its session lifetime. Sealed credentials stay sealed (the agent never sees the token), but data exfiltration via tool calls is possible until the operator revokes the gateway.

This is not a fixable property of permitlayer alone. It is the fundamental limit of any proxy architecture that sits behind a potentially-compromised client. Mitigations:

1. **Document it explicitly** in install docs. Honest limits build trust faster than hand-waving.
2. **Make token rotation cheap.** Currently permitlayer has no user-facing refresh path (see the E2E shakedown section below). The operator's only recourse after a suspected client compromise is to re-run `agentsso setup <service>` for every connected service. That needs to become one command.
3. **One-command kill switch.** The middleware already has a `KillSwitchLayer`; the UX of flipping it should be a single `agentsso kill` command that operators can muscle-memory in an incident.
4. **Short-lived scoped tokens** (already in design) minimize the window in which a compromised client can enumerate data.

---

## The agent-identity competitive landscape (2026-04-09)

The April 7 memo's competitive scan covered OpenAgents AgentID (DID-based, launched February 2026) and Mastercard Verifiable Intent (narrow/payments). The April 9 research surfaced three more projects operating in or adjacent to permitlayer's space, plus one OpenClaw-internal RFC that matters strategically. This section updates the competitive picture and argues why the RFC, despite its surface overlap with permitlayer's framing, is complementary rather than substitutive.

### The verified MolTrust RFC

[**openclaw/openclaw#49971 — RFC: Native Agent Identity & Trust Verification for OpenClaw**](https://github.com/openclaw/openclaw/issues/49971)

- **Author:** MolTrust (CryptoKRI GmbH)
- **Filed:** 2026-03-18
- **Status as of 2026-04-09:** Open, proposal stage, 76 comments, no maintainer acceptance
- **Reference implementation:** `@moltrust/openclaw` on npm, source at `github.com/MoltyCel/moltrust-openclaw` (unverified — referenced in the RFC body but not independently fetched)
- **Standards foundation:** W3C DID, W3C VC, ERC-8004

The RFC proposes a trust-verification hook for OpenClaw core, with the following shape (quoted from the RFC body via a WebFetch on 2026-04-09):

```typescript
interface TrustVerificationResult {
  verified: boolean;
  score: number;           // 0-100
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  did?: string;
  credentials?: VerifiableCredential[];
  warnings?: string[];
}

interface OpenClawPlugin {
  onAgentVerify?(agentId: string): Promise<TrustVerificationResult>;
}
```

Verification is invoked at four points: skill installation, payment execution, inter-agent communication, and gateway startup.

### Why this is complementary, not competitive

A natural first reading of "OpenClaw is building native agent identity" is that it subsumes permitlayer's category. That reading is wrong, and the distinction matters for positioning.

**The RFC answers a different question than permitlayer.** It asks: *who is this agent, and should I trust it?* It outputs a verification result, a trust score, a DID, optionally some verifiable credentials. That's it. The RFC does not specify what data the agent can access, under what scope, with what audit trail, or how credentials are stored. Those are out of scope.

**permitlayer answers the complementary question.** Given that we somehow know who the agent is (whether via bearer token today, SPIFFE/SVID at V1, or a MolTrust DID tomorrow), *what Google Workspace data can it touch, with what scope, and with what immutable audit trail?* That question requires being in the request path, holding the credentials, running the scrub engine, and writing to the audit log. The MolTrust RFC does none of those things — by design. It's a verification hook, not a data gateway.

**A mature stack uses both.** MolTrust verifies: "This is agent `urn:did:moltrust:abc123` with trust score 87/A." permitlayer then decides: "Agent with score 87/A and the `gmail-read-only` role may call `gmail.messages.list` with `q:is:unread` up to 60 times per hour, requests are audited, content is scrubbed, and the kill switch is one command away."

**The right pitch framing:** *"Agent identity and secure data access are the two halves of the agent-security problem. MolTrust is tackling one half. permitlayer is tackling the other. You need both."* This is stronger than claiming permitlayer is the whole answer, and it's honest.

### Adjacent projects mentioned in the RFC thread

Two other agent-identity projects surfaced in the #49971 discussion (aggregator-sourced, not independently verified):

- **AgentNexus.** Implements `did:agentnexus` as a W3C DID method. Defines trust levels L1 through L4, "NexusProfile" identity cards, third-party certification, and a Web-of-Trust roadmap. Identity-and-trust, not data-access. Adjacent to permitlayer, not competitive.
- **TrustChain.** Bilateral signed-interaction ledger. Rust core with Python and TypeScript SDKs. Computes trust via max-flow over a signed interaction graph, resists Sybil via edge-weight discounting. Has an IETF Internet-Draft (datatracker reference in the RFC thread) and a publicly deployed demo. Again identity-and-trust, not data-access.

**Competitive density readout.** In the agent-identity-and-trust-scoring space, there are at least four projects now: MolTrust (RFC + reference impl), AgentNexus, TrustChain, and OpenAgents AgentID (from the original April 7 memo). In the secure-agent-data-access space — permitlayer's actual category — we have not yet identified a comparable open-source project with an active reference implementation. This asymmetry is interesting: the identity-verification category is crowding, the access-enforcement category is not. Two possible reasons: (1) data access is harder because it requires being in the request path and maintaining a credential vault, raising the operational bar; (2) the problem is less fashionable because it lacks the cryptographic/DID aesthetic that attracts early contributors. Either way, it's a tailwind for permitlayer at this moment.

### Strategic play

Two non-exclusive options on the MolTrust RFC:

1. **Influence play.** Engage with the RFC thread directly, propose permitlayer-alignment as a reference for how verification results should feed into downstream access-control decisions, and position permitlayer as a candidate reference implementation of the "what to do after `onAgentVerify` returns" half of the problem. This has a low floor (a few comments on an open RFC cost nothing) and a high ceiling (shaping a standard that could become widely adopted).

2. **Complement play.** Ship permitlayer's V1 with an explicit integration surface for DID-based agent identity, positioned as "bring your own identity verifier — we support MolTrust, OpenAgents AgentID, and raw DIDs out of the box." This is a product decision rather than a community one, and it lets permitlayer ride whatever agent-identity standard wins without betting on a specific one.

Both paths require tracking the RFC's progress. The highest-leverage signal to watch: whether a maintainer (not just contributors) states an acceptance position, and whether the `onAgentVerify` hook gets merged into OpenClaw core.

---

## E2E shakedown: what shipped, what's broken (2026-04-09)

The April 9 session produced the first successful end-to-end flow through permitlayer's data path: an OpenClaw agent issuing a natural-language request ("check my unread Gmail"), OpenClaw dispatching to `permitlayer-gmail__gmail-messages-list` over streamable-HTTP MCP, the daemon unsealing the Gmail OAuth credential from the vault, calling the Gmail API, flowing the response through the scrub engine and audit writer, and the agent summarizing nine messages back to the user. This is the MVP data path, and it works.

Getting there required one shipped fix, one workaround, and surfaced two open bugs.

### Shipped: strip `$schema` from MCP tool catalogs

**Symptom.** OpenClaw registered all five Gmail tools over `tools/list`, but every tool invocation failed with `no schema with key or ref "https://json-schema.org/draft/2020-12/schema"`. The MCP handshake worked; the dispatch broke.

**Diagnosis.** `schemars 1.2.1` (the workspace JSON Schema generator) emits a `"$schema": "https://json-schema.org/draft/2020-12/schema"` declaration on every root schema. `rmcp 1.3.0`'s `#[tool_router]` macro materializes those schemas once at server-construction time and stores them on `Tool::input_schema: Arc<JsonObject>` (`rmcp-1.3.0/src/model/tool.rs:27`). The MCP `tools/list` response serializes them as-is to the wire. OpenClaw's tool-call validator (AJV in strict mode, almost certainly) refuses to dispatch any tool whose `inputSchema` references an unresolvable external meta-schema, because doing so would require network-fetching the meta-schema at runtime. We reproduced the wire format directly via `curl` against the daemon's `/mcp` endpoint and confirmed five `$schema` declarations in the returned tool catalog — one per tool.

**Fix.** Added `strip_meta_schema<S>(router: &mut ToolRouter<S>)` in `crates/permitlayer-proxy/src/transport/mcp.rs`. The helper iterates each `ToolRoute`, calls `Arc::make_mut` on the `input_schema`, and removes the `$schema` key. Called once per server construction in `GmailMcpServer::new`, `CalendarMcpServer::new`, and `DriveMcpServer::new`. Zero per-request cost. Regression test `mcp_tool_input_schemas_have_no_meta_schema_declaration` in `crates/permitlayer-proxy/tests/mcp_transport.rs` covers all 15 tools across all three connectors. Full workspace test suite passes (one pre-existing flaky DNS-rebind test unrelated to this change).

**Why `$schema` was safe to drop.** The MCP specification implies the JSON Schema dialect for `inputSchema`, so the field is redundant. Stripping it loses no information and makes the tool catalog compatible with strict validators beyond OpenClaw (AJV-strict, and likely others). We left a note in the helper's doc comment: if `Tool::output_schema` is ever populated for our tools, extend the helper to strip there too.

**Cost.** About 15 lines of production code, 40 lines of test, one cross-reference we'd likely have hit eventually anyway. Caught only because we were dogfooding through a real strict-validator client. This is a case-in-point argument for keeping an end-to-end integration test against a real MCP client in CI, which we should add as a follow-up.

### Resolved: shipped default OAuth client_id was a placeholder string, not a real Google client

**Status:** fixed. The `GoogleOAuthConfig::SharedCasa` variant has been deleted; `agentsso setup` without `--oauth-client` now errors with an actionable message, and `from_client_json` is the only constructor. Historical `"shared-casa"` metadata records are rejected at refresh time with a re-setup hint. Original findings preserved below for context.

**Symptom.** `agentsso setup gmail` (without `--oauth-client`) completes the seal/verify phases cleanly but every subsequent Gmail API call either fails with `401 UNAUTHENTICATED Invalid Credentials` (if the token is sent at all) or Google's browser-consent page throws `Error 401: invalid_client — The OAuth client was not found`. The sealed token is meaningless because the `client_id` used to obtain it does not exist in any Google Cloud project.

**Root cause.** `crates/permitlayer-oauth/src/google/consent.rs:8` defines:

```rust
const SHARED_CASA_CLIENT_ID: &str = "permitlayer-casa-placeholder.apps.googleusercontent.com";
```

with a comment stating "placeholder until real CASA cert is issued." This is shipped as the **default** `GoogleOAuthConfig::SharedCasa` variant. `agentsso setup` logs `client_type=shared-casa` on startup with no warning that this client is fictional. Any user running the default setup path will produce a sealed credential that cannot authenticate to Google APIs, and will debug for hours before figuring out why.

**Why it exists.** CASA (Cloud Application Security Assessment) Tier 2+ certification is a blocking requirement for public release of restricted-scope Google connectors (Gmail, Drive). This is referenced in `crates/permitlayer-daemon/src/cli/start.rs` as NFR31. Until the CASA cert is in hand, we have no real shared client to ship. The placeholder is a stub, not a bug per se, but the failure mode is silent and deeply misleading.

**Workaround.** `agentsso setup gmail --force --oauth-client <path-to-BYO-json>`. Bring your own Google Cloud OAuth client (create a "Desktop app" OAuth client in Google Cloud Console, add yourself as a test user on the consent screen, download the JSON, point setup at it). Confirmed working end-to-end on 2026-04-09.

**Fix options (pick one, track as a story).**

1. **Fail-fast on SharedCasa until cert is issued.** `GoogleOAuthConfig::SharedCasa::new()` should return an error with a clear message pointing to `--oauth-client` as the required alternative. This is the correct interim behavior: fail loudly at setup time rather than silently producing useless credentials that fail much later.
2. **Once CASA cert is issued, replace the placeholder constant.** This is the "real" fix but is blocked on an external process.
3. **Emit a prominent warning in `agentsso setup` output** when the shared client is selected, stating that the default client is not yet functional and the user must use `--oauth-client` or wait for CASA certification. Less clean than option 1 but backward-compatible if anyone has workflows depending on the current behavior (they do not, because the current behavior is broken).

Recommendation: **option 1.** Silent failure is the worst possible UX for a credential-handling tool, and anyone hitting it will (correctly) lose trust in the whole project.

### Open bug: `ProxyService::handle` does not refresh expired OAuth access tokens

**Symptom.** Google access tokens expire after approximately one hour. When OpenClaw calls a permitlayer tool with an expired sealed token, `ProxyService::handle` unseals the stale token, sends it to Gmail, and passes Gmail's 401 back to the agent with zero retry, no refresh attempt, and no audit event. The operator's only recourse is to re-run `agentsso setup <service> --force`.

**Root cause.** The refresh infrastructure is 95% complete but unglued:

- **Refresh token is sealed correctly.** `crates/permitlayer-daemon/src/cli/setup.rs:320-329` seals the refresh token into the vault under service key `"{service}-refresh"` (e.g. `gmail-refresh`) alongside the access token.
- **Refresh logic exists and is tested.** `crates/permitlayer-oauth/src/refresh.rs:110-160` implements `refresh_with_retry()` with exponential backoff (3 attempts, 1s/2s/4s ±20% jitter), detects `invalid_grant` as non-retryable, and emits a `token-refresh` audit event on exhaustion. Has a full roundtrip test against a mock OAuth server at `refresh.rs:173-264`.
- **OAuth client accessors are ready.** `crates/permitlayer-oauth/src/client.rs:208-218` exposes `inner()` and `http_client()` with `#[allow(dead_code)] // Used by upcoming token-refresh story` comments.
- **Missing piece.** `ProxyService::handle` in `crates/permitlayer-proxy/src/service.rs` contains none of the glue code that would detect a 401 from upstream, unseal the refresh token, call `refresh_with_retry()`, re-seal the new access token, and retry the original upstream request.

**Scope of fix.** Estimated 50 to 80 lines of glue in `service.rs`, plus an integration test that proves the full refresh-then-retry round-trip. The hard parts (refresh logic, vault seal/unseal, retry with backoff, audit emission) are already written and tested in isolation.

**Interim unblock options (smaller than the full fix).**

1. **Add an `agentsso credentials refresh <service>` CLI subcommand.** This is maybe 30 lines in `crates/permitlayer-daemon/src/cli/credentials.rs` that unseal the refresh token, call `refresh_with_retry()`, and re-seal the new access token. Gives operators a single-command unblock, is strictly smaller than the full proxy integration, and the code written for the CLI path is the same code the proxy fix will eventually call. Highly recommended as the next step regardless of whether the full proxy fix ships.
2. **Re-run `agentsso setup <service> --force` every hour.** What we're doing today. Untenable.

**Why this is blocking unattended operation.** Any demo longer than an hour fails silently after the token expires. Any automated workflow (cron jobs, webhooks, long-running agents) is impossible without refresh. This is the highest-impact unglued piece in the codebase right now.

> **FIXED — 2026-04-10 (Story 1.14a + 1.14b).** Both the proxy integration and the CLI escape hatch landed:
>
> - **Story 1.14a (reactive refresh on upstream 401).** `ProxyService::try_refresh_and_retry` added at `crates/permitlayer-proxy/src/service.rs`. On upstream 401, the proxy unseals the refresh token, calls `OAuthClient::refresh`, persists new tokens with atomic rotation ordering (invariant #3), and retries the original request once. Bounded retry — exactly one refresh per request — is structurally enforced. Closed after a second adversarial code review (5 majors + 10 minors addressed across commits `d5c4683` and `0860672`). 11 distinct `token-refresh` audit outcomes: `success`, `skipped_no_refresh_token`, `invalid_grant`, `exhausted`, `persistence_failed`, `malformed_token`, `store_read_failed`, `vault_unseal_failed`, `meta_invalid`, `unknown_oauth_error`, `retry_dispatch_failed`.
> - **Story 1.14b (shared refresh core + CLI escape hatch + metadata + display fix).** The inline state machine from Story 1.14a was lifted into `permitlayer_proxy::refresh_flow::refresh_service` — a free function with an `OAuthClientResolver` closure callback. Both the proxy's `try_refresh_and_retry` and the new `agentsso credentials refresh <service>` CLI subcommand call the same shared core, guaranteeing identical audit outcomes. `CredentialMeta.last_refreshed_at: Option<String>` added with backward-compat serde. `agentsso credentials status` now shows a `last refresh:` line (Task 5b) and `compute_token_validity` computes expiry from `last_refreshed_at` when present (Task 5c) — this also fixes `deferred-work.md:58`.
> - **Interim unblock path mentioned in the original memo (#1 — `agentsso credentials refresh` CLI subcommand) is now shipped as the `Refresh(RefreshArgs)` variant on `CredentialsCommand`.**
> - **Manual end-to-end verification against real Google is pending** (Task 7 of Story 1.14b, user-run). The in-process integration test at `crates/permitlayer-proxy/tests/refresh_integration.rs` exercises all 9 refresh scenarios against mocks with 0 failures.

### Summary table

| Finding | Status | File / reference |
|---|---|---|
| `$schema` field breaks strict MCP validators | **Fixed** | `crates/permitlayer-proxy/src/transport/mcp.rs`, test in `tests/mcp_transport.rs` |
| Default OAuth `client_id` is a placeholder string | **Open** | `crates/permitlayer-oauth/src/google/consent.rs:8` |
| `ProxyService::handle` does not refresh expired tokens | **Fixed (2026-04-10, Stories 1.14a + 1.14b)** | `crates/permitlayer-proxy/src/service.rs` (proxy wrapper), `crates/permitlayer-proxy/src/refresh_flow.rs` (shared core), `crates/permitlayer-daemon/src/cli/credentials.rs` (CLI escape hatch) |
| No end-to-end test against a real MCP client | **Open, new** | Add OpenClaw-in-a-container or equivalent to CI, or accept that these bugs only surface in manual shakedowns |

---

## Research-hygiene note (2026-04-09)

During the OpenClaw landscape research in this session, we nearly cited a second RFC — "openclaw/openclaw discussion#9676 — RFC: Agent-Blind Credential Architecture" — as a real artifact with strategic relevance to permitlayer. The description returned by aggregator search engines was detailed and suspiciously convenient: "proxy sits between the agent and every upstream API. Agent sends requests with key names. Proxy resolves real values from the OS keychain, injects at the transport layer, returns only the response. The agent is blind to credential values by design, not by policy." That is a near-verbatim description of permitlayer's own architecture.

Three independent verification methods on 2026-04-09 confirmed the discussion does not exist on GitHub:

1. **GitHub GraphQL API** (`gh api graphql`) returned `NOT_FOUND — Could not resolve to a Discussion with the number of 9676`. This is authoritative; GitHub's own API says the discussion does not exist.
2. **Wayback Machine availability API** returned `archived_snapshots: {}` — zero snapshots ever captured. A real high-activity RFC would almost certainly have been archived at least once.
3. **Direct URL load in a browser** returned 404.

The most likely explanation is that aggregator search engines, which increasingly surface LLM-generated summaries alongside or instead of real content, hallucinated both the URL and the content. The hallucinated summary pattern-matched "what an agent-blind credential RFC would plausibly say" — which happens to describe permitlayer because the problem shape is obvious once you look at it. It is also possible (though less likely given the GraphQL `NOT_FOUND`) that the discussion existed briefly and was deleted.

**Two corrections this produced in the session's output.**

1. The "second RFC" is removed from permitlayer's strategic picture entirely. It is not cited in any section above. The real RFC (#49971) is verified via direct WebFetch of the issue body, and its framing in this memo does not depend on the fabricated one.
2. A broader lesson for future research: aggregator summaries of GitHub issues, RFCs, and blog posts should not be treated as authoritative until the primary source is verified. For GitHub specifically, `gh api` and GraphQL are the fastest ways to confirm an artifact exists before committing its claims to a document that will live in version control. We caught this hallucination only because the user noticed the URL 404'd in his browser and pushed back. Had he not, the fabricated RFC would have entered this memo as a cited artifact — which is the kind of small, hard-to-detect error that poisons strategic documents over time.

**The honest takeaway.** The agent-identity category is hot enough that hallucinating plausible-sounding artifacts in it is trivially easy for an LLM-summarization layer. Primary-source verification is not optional for anything load-bearing in this space. This memo's claims about the real MolTrust RFC (#49971) are based on a direct WebFetch of the issue body on 2026-04-09; the adjacent project references (AgentNexus, TrustChain) came from the same fetch but are secondary and should be re-verified before being cited externally.

---

## Additional sources (2026-04-09)

- [OpenClaw Gateway Security Documentation](https://docs.openclaw.ai/gateway/security) — primary source for the "single trusted operator per gateway" trust model and plugin-as-trusted-code framing.
- [openclaw/openclaw#49971 — RFC: Native Agent Identity & Trust Verification for OpenClaw](https://github.com/openclaw/openclaw/issues/49971) — primary source for MolTrust's proposed `onAgentVerify` hook, reference implementation, and the 76-comment discussion thread.
- [OpenClaw MCP CLI Documentation](https://docs.openclaw.ai/cli/mcp) — primary source for the `openclaw mcp set` config shape, including the critical `"transport": "streamable-http"` field that OpenClaw defaults to SSE without.
- [OpenClaw Security Best Practices 2026 (blink.new)](https://blink.new/blog/openclaw-security-best-practices-2026) — aggregator source for the 138 CVE count, CVE-2026-25253 zero-click exploit, and ecosystem risk framing. Directional only; re-verify specific numbers before public citation.
- [OpenClaw Security 2026: Best Practices, Risks, and Hardening Guide (Valletta Software)](https://vallettasoftware.com/blog/post/openclaw-security-2026-best-practices-risks-hardening-guide) — aggregator source, consistent with blink.new.
- [slowmist/openclaw-security-practice-guide](https://github.com/slowmist/openclaw-security-practice-guide) — third-party hardening guide, agent-facing framing.
