# ADR 0003: Agent identity token lookup — dual-index Argon2id + HMAC

- **Status:** Accepted
- **Date:** 2026-04-12
- **Deciders:** Story 4.4 (`agent identity registry and per-agent policy binding`) implementation
- **Relates to:** FR47, FR48, FR68, NFR4, NFR20, AR15
- **Supersedes:** n/a

## Context

Story 4.3 (`PolicyLayer middleware with fail-closed evaluation`) shipped policy enforcement against a transitional single-policy-shortcut heuristic in `permitlayer-proxy::middleware::policy::resolve_policy_name`: any unauthenticated request was auto-bound to the only policy in the set, or denied with `default-deny-no-agent-binding` if there were zero or two-or-more policies. Story 4.4 replaces that heuristic with a real bearer-token → agent-name → policy-name lookup driven by `~/.agentsso/agents/<name>.toml` files.

The hot path is `AuthLayer::call`, which runs on every inbound request. Constraints:

- **NFR4** — policy evaluation latency target is <10 ms p99 at 100 registered policies. Authentication runs *before* policy evaluation, so its latency budget is even tighter — practically <1 ms per request to leave room for the rest of the chain.
- **NFR20** — fail-closed semantics: any policy / scrubbing / vault failure must deny the request rather than fall through. Token validation inherits this invariant.
- **At-rest defense** — `~/.agentsso/agents/*.toml` files sit on disk under a 0700 directory + 0600 file modes. Either mode can be subverted by an attacker with disk read access (compromised host, lost laptop). The on-disk format must be offline-brute-force-resistant against the resulting hash material.
- **Single-user trust model** — see `memory/project_openclaw_landscape.md`. The daemon's threat model is "the user trusts their own machine"; remote authentication is out of scope until Tier 3.

The naive design — hash plaintext tokens with Argon2id and store the hash on disk, then on every auth attempt iterate the registry calling `argon2_verify` against each entry — has a fatal latency flaw:

```text
auth_time = O(n_agents × ~100 ms)
```

Argon2id with the OWASP "interactive auth" parameters (m=19456 KiB, t=2, p=1) targets ~100 ms per verification specifically to resist brute force. Two registered agents already blow the budget; ten agents would mean ~1 second of CPU per request just to authenticate.

We need a hot-path lookup that is:

1. O(1) per request, regardless of registry size,
2. Backed by an offline-brute-force-resistant on-disk format,
3. Resistant to corruption of the in-memory index (defense in depth),
4. Stateful enough to survive daemon restart (without re-prompting the user).

## Decision

**Dual-index design: Argon2id for at-rest defense, HMAC-SHA-256 for runtime O(1) lookup, both anchored to the existing master key.**

Concretely:

### On-disk schema (`~/.agentsso/agents/<name>.toml`)

```toml
name = "email-triage"
policy_name = "email-read-only"
token_hash = "$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>"
lookup_key_hex = "<64 hex chars = 32 bytes HMAC output>"
created_at = "2026-04-12T18:30:00.000Z"
last_seen_at = "2026-04-12T18:35:12.123Z"  # omitted if never used
```

The `token_hash` is the standard Argon2id PHC string with the OWASP parameters baked in. The `lookup_key_hex` is the hex-encoded output of `HMAC-SHA-256(daemon_lookup_subkey, plaintext_token)`. Both are derived from the same plaintext at register time; only derived values reach the disk.

### Daemon HMAC subkey

At daemon boot, `cli/start.rs::try_build_agent_runtime` derives a 32-byte HMAC subkey from the master key via HKDF:

```rust
Hkdf::<Sha256>::new(None, &*master_key)
    .expand(b"permitlayer-agent-token-lookup-v1", &mut subkey);
```

The subkey lives in memory only — it is never written to disk and never logged. The HKDF info string is versioned (`-v1`) so a future scheme rotation can generate a fresh subkey without colliding with old tokens.

**Story 1.15 (2026-04-14): eager master-key bootstrap.** The master key is now provisioned unconditionally at daemon boot via `cli::start::ensure_master_key_bootstrapped`, which runs before `try_build_agent_runtime` and `try_build_proxy_service`. A keystore failure at boot is a fatal `ExitCode::from(2)` rather than a silent degraded-mode boot. After Story 1.15, the lookup subkey is ALWAYS a real HKDF derivation — the pre-1.15 zero-placeholder fallback branch is deleted, the `[0u8; LOOKUP_KEY_BYTES]` equality guard in `register_agent_handler` is deleted, and the `agent.no_master_key` 503 error code is retired. The natural first-touch flow `agentsso start → agentsso agent register → agentsso setup <service>` now works because step 2 no longer depends on step 3's side effect.

### `RegistrySnapshot` indexes

The in-memory `permitlayer-core::agent::registry::RegistrySnapshot` maintains TWO HashMaps:

```rust
struct RegistrySnapshot {
    by_name: HashMap<String, AgentIdentity>,           // CRUD lookups
    by_lookup_key: HashMap<[u8; 32], AgentIdentity>,   // O(1) auth path
}
```

The snapshot is held inside `Arc<ArcSwap<RegistrySnapshot>>` so concurrent reads from `AuthLayer` are lock-free, and registry mutations (`replace_with`) atomically swap a fresh snapshot without blocking readers.

### Auth hot path

```text
1. Compute key = HMAC-SHA-256(daemon_subkey, inbound_token)        — ~1 µs
2. snapshot.by_lookup_key.get(&key)                                 — O(1)
3. argon2_verify(inbound_token, agent.token_hash)                   — ~100 ms (defense in depth)
4. Stamp AgentId + AgentPolicyBinding into request extensions
5. Pass through to inner service
```

Steps 1 and 2 dominate latency in the common case. Step 3 only fires once per *valid* token, not per agent — and it fires on the verifier path that already passes the index lookup. The Argon2id check guarantees that even if an attacker corrupts the in-memory `by_lookup_key` map (impossible without process compromise), they still cannot forge a token without computing a valid Argon2id round-trip against the on-disk hash.

### Why both layers

| Compromise scenario                            | Argon2id alone | HMAC alone | Dual-index |
| ---------------------------------------------- | -------------- | ---------- | ---------- |
| Attacker reads `~/.agentsso/agents/*.toml`     | Resists        | Defeats    | Resists    |
| Attacker corrupts `by_lookup_key` map in RAM   | Resists        | Defeats    | Resists    |
| Attacker steals a registered token's plaintext | Defeats        | Defeats    | Defeats    |
| Daemon authenticates 1000 reqs/sec             | Fails NFR4     | Meets      | Meets      |

The dual approach gets you offline-attack resistance AND O(1) hot-path lookup, at the cost of holding the lookup key in memory and writing it to disk in hex (32 extra bytes per agent file).

### `AgentBearerToken` discipline preserved

The plaintext token lives inside `permitlayer-credential::AgentBearerToken` (existing non-`Debug`, `ZeroizeOnDrop` type) from generation to display. After the `register_agent_handler` returns the `RegisterAgentResponse` body to the loopback control wire, the plaintext is dropped and zeroized. The `AgentIdentity` struct never carries plaintext bytes — only the Argon2id PHC string and the hex-encoded HMAC lookup key, both of which are derived values.

## Alternatives considered

### Single Argon2id with global salt

- **Pros:** Simplest possible scheme. Trivial to reason about.
- **Cons:** O(n × 100ms) per request — fatally slow at any registry size > 1. Dismissed immediately.

### Single SHA-256 with per-agent salt

- **Pros:** Fast lookup if you index by salted hash.
- **Cons:** SHA-256 is too fast for offline brute force. An attacker who steals the agent file can mount a GPU dictionary attack and recover plaintext tokens in hours. Dismissed.

### Single Argon2id, no runtime index, but lower parameters

- **Pros:** Removes the dual-index complexity.
- **Cons:** Lowering the Argon2id cost weakens at-rest defense. The OWASP minimum exists for a reason — going below it puts the on-disk hashes within reach of GPU brute force. Dismissed.

### JWT with HMAC signing

- **Pros:** Stateless, fast, well-understood.
- **Cons:** Tokens become bearer credentials with no central revocation. Removing an agent requires a denylist (defeats the stateless win) or token expiry (forces token rotation, hurts UX). The request latency win is real but the operational overhead is large for the single-user trust model. Defer to Tier 2 / Tier 3 where multi-user RBAC justifies the extra machinery.

### Sealed lookup key (per-agent, via Vault)

- **Pros:** Treats the HMAC lookup key as credential material and seals it under the master key, the same way OAuth tokens are sealed.
- **Cons:** Forces every agent CRUD operation through `permitlayer-vault::Vault::seal`/`unseal`, doubling the boot-time work (every agent file requires an unseal call before it can be added to the in-memory index). The lookup key is NOT a credential on its own — possessing it without the daemon's HMAC subkey gives an attacker zero authentication power, because the subkey is the secret that turns a plaintext token into a lookup key. Sealing is therefore over-engineering. The hex-encoded inline format ships and the trade-off is documented for future readers.

## Consequences

### Positive

- **O(1) auth hot path.** A registry of 1000 agents authenticates in the same wall-clock time as a registry of 1, modulo the constant ~100ms Argon2id verify on hits. Comfortably inside NFR4's budget.
- **Offline-brute-force-resistant on-disk format.** Argon2id with the OWASP parameters keeps `~/.agentsso/agents/*.toml` safe even if the file is exfiltrated.
- **Defense in depth.** The Argon2id verify after the HMAC index hit means an in-memory map corruption alone cannot forge a token.
- **No vault coupling.** Agent CRUD does not need to seal/unseal anything; the trait surface stays narrow (`AgentIdentityStore` is independent of `CredentialStore`).
- **Simple revocation.** `agentsso agent remove <name>` deletes the file and atomically swaps the registry — the removed agent's token stops working immediately, in-flight requests using the old snapshot finish, and no denylist is needed.
- **Hot-reload friendly.** `agentsso reload` (SIGHUP) re-reads the agents directory and atomically swaps the registry via `ArcSwap`, mirroring the policy hot-swap pattern from Story 4.2.

### Negative

- **Daemon must have a master key to mint tokens.** A fresh install can't run `agentsso agent register` until at least one `agentsso setup` has bootstrapped the keystore. Documented in the error remediation message; flagged in `deferred-work.md` for a future setup-flow refactor that bootstraps the master key independently of OAuth setup.
- **Master key rotation invalidates every existing token.** If the operator runs `agentsso rotate-key` (Story 1.17), the new master key derives a new HMAC subkey, which means every previously-registered agent's `lookup_key_hex` no longer matches what the daemon computes. The fix: `rotate-key` would need to also re-mint every agent's lookup key by re-computing it against the new subkey, OR force the operator to re-register every agent after rotation. Out of scope for Story 4.4; flagged for the rotation story.
- **+33% disk footprint vs base64 for the lookup key field.** Negligible (~64 chars vs ~44) for a per-agent file.
- **Two indexes to keep in sync.** Every registry mutation must rebuild both `by_name` and `by_lookup_key`. Done atomically via `RegistrySnapshot::from_agents`, but a future refactor that drifts the two could create silent auth failures. Mitigated by the Argon2id defense-in-depth check — even if `by_lookup_key` is stale, the verify step blocks the bad auth.

### Neutral

- **`AGENTSSO_TEST_*` env-var seams.** Tests use these to drive a deterministic master key without touching the OS keychain:
  - `AGENTSSO_TEST_MASTER_KEY_HEX=<64 hex chars>` — short-circuits `cli::start::ensure_master_key_bootstrapped` to return the parsed bytes directly. Fastest, fully deterministic, bypasses `bootstrap_from_keystore`.
  - `AGENTSSO_TEST_PASSPHRASE=<string>` — routes through `permitlayer-keystore::PassphraseKeyStore` (Argon2id-derived key, filesystem-persisted salt/verifier). Exercises the REAL `bootstrap_from_keystore` path including the keystore adapter contract, idempotency, and disk persistence — closes the Story 1.15 review "no real keystore e2e coverage" gap.
  - `AGENTSSO_TEST_FORCE_KEYSTORE_ERROR=1` — forces `ensure_master_key_bootstrapped` to return `Err(StartError::KeystoreConstruction)` so the fail-fast `ExitCode::from(2)` path can be tested without a real broken keychain.
  All three are gated behind `#[cfg(debug_assertions)]` — release builds compile the env var reads out entirely. MUST NOT appear in any production deployment surface.

## Threat Model

### Bearer token wire exposure

The `register_agent_handler` control endpoint returns the plaintext bearer token in the loopback `register` response body. Processes on the same machine with raw-socket capability (`CAP_NET_RAW` on Linux, `bpfilter` on macOS) can observe loopback traffic and capture the token. The net exposure is zero beyond what is printed to operator stdout by design — the token is explicitly presented to the operator as a one-time credential. Mitigation: the control endpoint binds exclusively to `127.0.0.1` (never `0.0.0.0`), limiting wire exposure to local processes only.

### HMAC lookup key timing

`RegistrySnapshot::lookup_by_key` uses `HashMap<[u8;32], _>` with the standard SipHash default hasher. The key equality check in `HashMap::get` is NOT constant-time with respect to a pinned-core local adversary with sub-microsecond timing resolution. The risk is bounded: an attacker would need to run on the same physical core with precise clock access and make millions of requests to the local control port. This attack profile is excluded by the single-user trust model assumption — an attacker with that level of local access already has equivalent code-execution. See also `registry.rs::lookup_by_key` rustdoc `# Timing` section.

### Argon2id offline brute-force

The at-rest `token_hash` field in each `~/.agentsso/agents/<name>.toml` is an Argon2id PHC string with OWASP interactive-auth parameters (m=19456 KiB, t=2, p=1, ~100 ms per verify). An attacker who exfiltrates the agent file must spend ~100 ms CPU per candidate guess, making GPU dictionary attacks impractical. The HMAC lookup key (`lookup_key_hex`) is an additional layer: even if the Argon2id hash were cracked, the attacker would need the daemon's in-memory HMAC subkey (derived at runtime from the master key via HKDF and never written to disk) to reconstruct a valid lookup key.

## Implementation references

- `crates/permitlayer-core/src/agent/registry.rs` — `compute_lookup_key`, `hash_token`, `verify_token`, `RegistrySnapshot`, `AgentRegistry`.
- `crates/permitlayer-core/src/agent/identity.rs` — `AgentIdentity`, `validate_agent_name`.
- `crates/permitlayer-core/src/store/fs/agent_fs.rs` — `AgentIdentityFsStore` (atomic-write-via-tempfile + rename + fsync, mode 0600).
- `crates/permitlayer-proxy/src/middleware/auth.rs` — `AuthLayer`, `AuthService`, the dual-index hot path.
- `crates/permitlayer-daemon/src/cli/start.rs::try_build_agent_runtime` — boot-time runtime construction + HKDF subkey derivation.
- `crates/permitlayer-daemon/src/server/control.rs::register_agent_handler` — register endpoint, the only surface where token plaintext crosses the loopback wire.
- `crates/permitlayer-daemon/tests/agent_registry_e2e.rs` — end-to-end lifecycle test (register → auth → policy → remove → reload).
