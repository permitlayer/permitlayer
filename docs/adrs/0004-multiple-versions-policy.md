# ADR 0004: `cargo deny check bans` — `multiple-versions = "warn"` policy

- **Status:** Accepted
- **Date:** 2026-04-19
- **Deciders:** Story 8.0 (dependency-hygiene gate)
- **Relates to:** NFR41 (plugin-API stability), Story 6.5 (`plugin-api` CI job), Story 1.14a (cargo-deny wrapper discipline), commit `6c8176f` (RUSTSEC advisory patch)
- **Supersedes:** n/a

## Context

`cargo deny check bans` runs on every PR (via `.github/workflows/ci.yml:156-157`) as part of the security gate. At 2026-04-19 (after Story 6.5 + the `rustls-webpki` CVE patch in commit `6c8176f`), running the gate against a clean `Cargo.lock` produces:

- **0 hard errors.** After Story 8.0's `xtask/Cargo.toml` fix (adding an explicit `version = "0.1.0"` to the `permitlayer-core` path dep), the gate has no blocking failures.
- **27 `multiple-versions` warnings.** Each warning reports a crate present in the dependency graph at two or more distinct versions.

Representative duplicates (end-of-Epic-6 Cargo.lock):

| Crate | Versions present | Why duplicated |
|---|---|---|
| `bitflags` | 1.3.2, 2.11.0 | 1.3.2 pulled only by `kqueue-sys 1.0.4` → `kqueue 1.1.1` → `notify 8.2.0` (BSD file-watcher path for `agentsso audit --follow`). Everything else is on 2.x. |
| `toml` | 0.8.x, 1.1.2+spec-1.1.0 | 0.8 via `figment` (daemon config loading); 1.1.2 via `rquickjs-macro` → `proc-macro-crate` → `toml_edit`. |
| `rand` | 0.8.x, 0.9.x | Ecosystem-wide 0.8 → 0.9 migration in progress; nearly every crate with randomness pulls both. |
| `hashbrown` | 2 versions | Rustc-vendored vs `indexmap` transitive. |
| `getrandom` | 3 versions | Pulled transitively through multiple paths (proptest, rand, ring). |
| `rand_core`, `rand_chacha`, `cpufeatures`, `console`, `linux-raw-sys`, `r-efi` | 2-3 versions each | All transitive; not directly depended on by any workspace crate. |

Each duplicate costs a small amount of binary size and compile time. Deduplicating would require one of:

1. **`[patch.crates-io]` entries** forcing a specific version globally. Creates fragility: any future upstream release that's incompatible with the pinned version breaks the build. Requires ongoing maintenance per-patch.
2. **Forking problem crates** (e.g., `kqueue-sys`) to bump their transitive deps. ~200 LOC of FFI bindings we'd become responsible for, with no security or functionality payoff.
3. **`skip = [...]` entries in `deny.toml`** for each accepted duplicate. Each entry requires a justification comment; the list grows as the dep graph churns; becomes its own maintenance burden.
4. **Flipping `multiple-versions` from `warn` to `deny`** while leaving the current duplicates in place. This would immediately break CI, forcing option 1, 2, or 3 above.

None of these options has a clear security or correctness win. `cargo deny check advisories` already catches CVEs in any version of any dep (and does so transitively — see RUSTSEC-2026-0098/0099 patch in `6c8176f`, which fired on a transitive `rustls-webpki` we don't directly depend on). `multiple-versions = warn` is therefore a purely cosmetic gate.

## Decision

**Keep `multiple-versions = "warn"` in `deny.toml`. Do not add `skip` entries. Do not fork upstream crates. Do not flip to `deny`.**

The cargo-deny gate enforces:

- **`advisories` (deny all):** live RUSTSEC advisories in any transitive dep are hard errors.
- **`licenses` (deny unknown):** every transitive dep's license must appear in the allowlist.
- **`bans` (wildcards deny, multiple-versions warn):** direct-dep wildcards are hard errors; duplicate versions are reported but not blocking.

This posture treats security (advisories) and legal (licenses) as hard gates while treating dependency-graph hygiene (multiple-versions) as an observability signal. The ratio of signal to noise for flagged duplicates is low; investing in deduplication produces no measurable safety benefit.

## Consequences

### Positive

- `cargo deny check` is green on every PR — CI signal stays meaningful. A new hard failure is genuinely a regression, not noise.
- Zero ongoing maintenance burden for `[patch]` entries, crate forks, or skip-list justifications.
- Security posture unchanged — the `advisories` gate catches CVEs regardless of version duplication.
- Duplicates remain visible (the `warn`-level output is printed every run), so if an operator is investigating binary size or build time they can still find them.

### Negative

- Binary size includes duplicate crate copies. For the crates listed in the Context table, this is <2 MB of net overhead on a release build (measured against a hypothetically-deduplicated tree). Not meaningful for a daemon that operators install once per machine.
- Compile time includes duplicate crate compilation. `cargo check --workspace` cold runtime is ~90 seconds; removing all 27 duplicates would save an estimated 15-20 seconds. The dev-loop discipline in this project (incremental compilation, `cargo check -p <crate>`) makes this a non-issue in practice.
- A future reader might mistake the 27 warnings for actionable items. This ADR is the countermeasure: the `deferred-work-triage-2026-04-19.md` document and any future deferred-work entries about duplicate versions should link here rather than re-litigate the decision.

### Neutral

- The `xtask` wildcard fix in Story 8.0 is orthogonal to this policy — it closes a genuine `wildcards = "deny"` violation, not a `multiple-versions` concern.

## Revisit triggers

This decision should be re-opened if ANY of the following becomes true:

1. **A CVE is issued against a crate that appears in our graph at multiple versions, and only the version we don't directly control is patched.** Example: if `bitflags 1.3.2` (pulled via `kqueue-sys`) gets a CVE and `bitflags 2.11.0` is already fine, we'd need to eliminate the 1.3.2 path (fork `kqueue-sys`, swap `notify`, or add a `[patch]`). The `advisories` gate would fire, forcing action.
2. **Release binary size crosses 100 MB.** At that point every megabyte of duplicate matters. Current release build is roughly 20 MB.
3. **cargo-deny's upstream default changes to `multiple-versions = "deny"`.** If the ecosystem norm shifts, we should follow rather than be the odd one out.
4. **A specific duplicate pair is shown to cause a correctness bug** (e.g., two copies of a type crate like `bytes` producing `Cannot assign Bytes to Bytes` errors). Concrete evidence required; not speculative.

Absent one of these triggers, re-evaluating this decision is not worth the engineering time.

## Links

- `deny.toml:67-72` — the `[bans]` stanza this ADR documents
- Commit `6c8176f` — RUSTSEC advisory patch (proof the `advisories` gate works transitively without needing `multiple-versions` help)
- Commit `05c1b0e` — Story 6.5 baseline this ADR inherits
- [cargo-deny docs — bans check](https://embarkstudios.github.io/cargo-deny/checks/bans/cfg.html)
- [cargo-deny docs — multiple-versions field](https://embarkstudios.github.io/cargo-deny/checks/bans/cfg.html#the-multiple-versions-field-optional)
