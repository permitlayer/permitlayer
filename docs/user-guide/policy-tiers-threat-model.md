# Connector tiers — threat model

This is the security analysis for the Epic 9 per-service policy tiers
(`{gmail,calendar,drive}-read-only` and `-read-write`). Read
[`connector-tiers.md`](connector-tiers.md) first for how the tiers work
and how to bind an agent to one; this page is the residual-risk record.

## What an agent on the read-write tier can do

An LLM agent bound to a `-read-write` tier can, **after a human approves
the specific request at the terminal prompt**:

- **Gmail** (`gmail-read-write`): send mail as you (`gmail.send`); create,
  update, and send drafts (`gmail.compose`); modify labels, and trash /
  untrash messages (`gmail.modify`). It can **not** permanently delete
  messages — `gmail.messages.delete` is intentionally not shipped (it
  would require the broad `https://mail.google.com/` scope).
- **Calendar** (`calendar-read-write`): create, update, patch, delete,
  move, and quick-add events (`calendar.events`).
- **Drive** (`drive-read-write`): create, update, copy, and
  **permanently delete** files (`drive.file`). `drive.file` limits this
  to files the app created or opened — it cannot touch arbitrary Drive
  content — but `drive.files.delete` bypasses the trash and is **not
  reversible**.

Every one of those write operations surfaces an approval prompt
(`y` / `n` / `a` / `never`; ENTER = deny; timeout → HTTP 403
`policy.approval_timeout`). Nothing writes silently on the read-write
tier. On a `-read-only` tier, write scopes are rejected at compile time
by the policy allowlist — the agent cannot write at all, regardless of
what it asks for.

## The read-side exfiltration risk

This is the risk that is **not** eliminated by prompt-on-write, and you
must understand it before granting any tier — including read-only.

The Gmail read tools (`gmail.messages.get`, `gmail.attachments.get`,
`gmail.threads.get`, `gmail.drafts.get`, …) return **arbitrary message
content**: full bodies, attachments, and anything in them — including
**one-time passcodes / 2FA codes**, password-reset links, private
correspondence, and confidential attachments. An agent with any Gmail
read access (so: *both* tiers) can read all of that and, if it also has
network egress through some other tool, exfiltrate it. The Calendar and
Drive read tools carry the analogous risk for event details and file
contents.

Prompt-on-write does **not** mitigate this — reads are auto-approved on
both tiers by design (an agent that prompted on every message read would
be unusable). The mitigations that *do* apply:

- **Scope minimization**: each tool requests the narrowest Google scope
  that works (verified against Google's API reference). A read-only tier
  genuinely cannot write.
- **Per-request audit**: every upstream call is audited with the agent
  identity and scope. You can see, after the fact, exactly what an agent
  read.
- **Operator-chosen narrowing**: `resources = [...]` in the policy can
  restrict a tier to specific labels / calendars / folders.

## Residual risk decision (accepted, eyes open)

**The attachment/body-read exfiltration risk is accepted as a documented
residual risk.** Permitlayer does **not** redact message bodies or
attachment contents on the read path. The scrub engine is **not**
expanded to attempt this as part of Epic 9.

This is a deliberate decision, recorded here so it is auditable:

- Content-aware redaction of arbitrary message/attachment bodies (e.g.
  stripping suspected 2FA codes) is an **optional, separate future
  effort** with its own explicit decision and its own threat-model. It
  is **out of scope** for the tier work, and the scrub engine must not
  be silently broadened to cover it.
- Operators granting a Gmail tier (either one) are accepting that an
  agent can read everything in the mailbox the policy's `resources`
  allow. If that is unacceptable for a given agent, the correct control
  today is to **not grant Gmail read access to that agent**, or to
  narrow `resources`, not to rely on redaction that does not exist.

If and when a content-redaction capability is built, this section will
be revised to describe what it does and does not cover. Until then:
**read access means read access — grant it deliberately.**

## Summary

| Risk | Mitigation shipped | Residual |
|---|---|---|
| Agent writes (send/delete/modify) without human intent | Prompt-on-write default on `-read-write`; compile-deny on `-read-only` | Operator can press `a` ("always allow this rule for the session") — a deliberate, logged choice |
| Agent reads sensitive content (2FA, attachments) | Scope minimization, per-request audit, optional `resources` narrowing | **Accepted**: no body/attachment redaction; do not grant read access you would not grant a human assistant |
| Bundled vs test policy drift | Definition-identity test across both default-policy files | None (test-enforced) |
