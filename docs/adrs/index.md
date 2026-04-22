# Architecture Decision Records

This directory holds the load-bearing design decisions for permitlayer. Each ADR captures one decision, its context, and its revisit triggers. ADRs are numbered sequentially; numbers are never reused once assigned.

| # | Title | Status | Date | Story |
|---|-------|--------|------|-------|
| [0001](0001-kill-switch-control-plane.md) | Kill switch control plane — loopback HTTP POST on a carved-out router | Accepted | 2026-04-11 | 3.2 |
| 0002 | *(unused — reserved during Story 3.2 planning, published as 0001)* | — | — | — |
| [0003](0003-agent-identity-token-lookup.md) | Agent-identity token lookup | Accepted | 2026-04-12 | 4.4 |
| [0004](0004-multiple-versions-policy.md) | `cargo deny check bans` — `multiple-versions = "warn"` policy | Accepted | 2026-04-19 | 8.0 |

## Conventions

- **Filename:** `<zero-padded-number>-<kebab-case-title>.md`
- **Status values:** `Proposed` | `Accepted` | `Superseded by <N>` | `Deprecated`
- **Superseding is forward-only:** a later ADR can supersede an earlier one, but the earlier one's file is kept for forensic traceability. Update the earlier ADR's `Status` line to `Superseded by <N>` and leave the body intact.
- **Reserved numbers:** if a number is reserved but not published (e.g., 0002 above), record the reservation here so the next author skips it.

## When to write an ADR

- A design decision that spans more than one file, more than one crate, or more than one story.
- A decision with non-obvious trade-offs that a future reader (or future-you) will want to understand.
- A decision to *not* do something obvious, with the reasoning (ADR 0004 is an example).

A one-line `// This is how we do X` comment in the code is usually enough for decisions with a single locus. ADRs are for decisions that would otherwise be re-litigated.
