# Connector access tiers

`agentsso` exposes Gmail, Calendar, and Drive to an agent as MCP tools.
How much an agent can do is decided by **which policy you bind it to** —
not by a different connector, a different install, or a different OAuth
grant. This page explains the tier model, how to bind an agent to a
tier, the per-service tool matrix, and the security posture.

For the full risk analysis, read the
[connector tiers threat model](policy-tiers-threat-model.md).

## The tier model

Each service has two ready-made policies:

| Tier | Gmail | Calendar | Drive |
|---|---|---|---|
| Read-only | `gmail-read-only-tier` (or the legacy `gmail-read-only`) | `calendar-read-only` | `drive-read-only` |
| Read/write | `gmail-read-write` | `calendar-read-write` | `drive-read-write` |

- **Read-only tiers** list only read scopes. The policy compiler's
  allowlist makes any write **structurally impossible** — a write
  request is rejected with HTTP 403
  `default-deny-scope-out-of-allowlist`. The agent cannot write no
  matter what it asks for.
- **Read/write tiers default to prompt-on-write.** Every read is
  auto-approved; every **write** pauses and asks you to approve it at
  the terminal running `agentsso start`:

  ```
  y       allow this one request
  n       deny this one request
  a       always allow this rule for this session
  never   never allow this rule for this session
  ```

  Pressing ENTER with no selection denies (reflexive enter keeps you
  safe). If you do not answer within the approval timeout (default 30s)
  the request is denied with HTTP 403 `policy.approval_timeout`. The
  `a` / `never` choices are forgotten on daemon restart, `agentsso
  reload`, or SIGHUP.

  Writes are tagged with greppable rule IDs (`prompt-gmail-writes`,
  `prompt-calendar-writes`, `prompt-drive-writes`) so you can find every
  approval a tier surfaced in 403 bodies and audit events.

> If the daemon has no controlling terminal (e.g. a systemd unit with
> stdin from `/dev/null`), prompt-on-write requests return HTTP 503
> `policy.approval_unavailable`. Run `agentsso start` in a foreground
> terminal, or use a read-only tier for unattended agents.

## Bind an agent to a tier

`agentsso quickstart` binds the agent to the matching shipped policy
for you — pick the tier with `--read` or `--read-write` and the verb
takes care of the policy name. The six tier policies ship in the
seeded `default.toml`.

Connect a read-only Gmail agent:

```sh
agentsso quickstart gmail --read --oauth-client ./client_secret.json
# → binds the agent to gmail-read-only
```

Give an agent read **and** write access to Calendar:

```sh
agentsso quickstart calendar --read-write --oauth-client ./client_secret.json
# → binds the agent to calendar-read-write
```

To move an existing agent between tiers, re-run `quickstart` for the
service with the other flag (e.g. `--read-write` instead of `--read`).
`quickstart` is idempotent; the second run rebinds the agent to the
new policy and emits a fresh MCP config snippet. The bearer token is
printed once during the run — capture it then, or pass
`--mcp-config-out <path>` to write the full config snippet to disk.

To narrow a tier further (e.g. only the primary calendar, or one Drive
folder), copy the tier policy in `default.toml` to a new named policy
and set `resources = ["primary"]` / a specific folder ID, then bind the
agent to your new policy name.

## Per-service tool matrix

R = read (auto-approved on both tiers). W = write (blocked on
read-only; prompt-on-write on the read/write tier).

### Gmail (26 tools)

| Tool | R/W | Read-only | Read/write |
|---|---|---|---|
| `gmail.messages.list` / `.get` | R | ✅ | ✅ |
| `gmail.threads.list` / `.get` | R | ✅ | ✅ |
| `gmail.search` | R | ✅ | ✅ |
| `gmail.attachments.get` | R | ✅ | ✅ |
| `gmail.labels.list` | R | ✅ | ✅ |
| `gmail.profile.get` | R | ✅ | ✅ |
| `gmail.history.list` | R | ✅ | ✅ |
| `gmail.drafts.list` / `.get` | R | ✅ | ✅ |
| `gmail.settings.sendAs.list` / `.filters.list` / `.language.get` / `.imap.get` / `.pop.get` / `.vacation.get` / `.forwarding.list` / `.autoForwarding.get` | R | ✅ | ✅ |
| `gmail.messages.send` | W | ❌ | prompt |
| `gmail.messages.modify` / `.trash` / `.untrash` | W | ❌ | prompt |
| `gmail.drafts.create` / `.update` / `.send` | W | ❌ | prompt |

There is **no `gmail.messages.delete`** — permanent mailbox deletion is
intentionally not shipped (it would require the broad
`https://mail.google.com/` scope). Use `gmail.messages.trash` (reversible).

### Calendar (12 tools)

| Tool | R/W | Read-only | Read/write |
|---|---|---|---|
| `calendar.calendars.list` | R | ✅ | ✅ |
| `calendar.events.list` / `.get` | R | ✅ | ✅ |
| `calendar.freebusy.query` | R | ✅ | ✅ |
| `calendar.settings.list` | R | ✅ | ✅ |
| `calendar.colors.get` | R | ✅ | ✅ |
| `calendar.events.create` / `.update` / `.patch` / `.delete` / `.move` / `.quickAdd` | W | ❌ | prompt |

(`calendar.freebusy.query` is an HTTP POST but a **read** — it uses
`calendar.readonly` and auto-approves.)

### Drive (8 tools)

| Tool | R/W | Read-only | Read/write |
|---|---|---|---|
| `drive.files.list` / `.get` / `.search` | R | ✅ | ✅ |
| `drive.about.get` | R | ✅ | ✅ |
| `drive.files.create` / `.update` / `.copy` / `.delete` | W | ❌ | prompt |

`drive.files.delete` is **permanent** (bypasses the trash). The
prompt-on-write approval is the safety gate; `drive.file` also limits
all Drive writes to files the app created or opened.

## Security posture

Read this section, and the [threat model](policy-tiers-threat-model.md),
before granting any tier.

- An agent on a **read/write** tier can — after you approve each request
  — send mail as you, permanently delete calendar events and Drive
  files, and modify your inbox. Prompt-on-write means none of this
  happens silently, but pressing `a` ("always allow for this session")
  is a real, logged decision: use it deliberately.
- An agent on **either** tier can read message bodies, attachments, and
  anything in them — **including 2FA codes and confidential
  documents**. Reads are auto-approved by design. Permitlayer does
  **not** redact this content (the scrub engine is deliberately not
  expanded to attempt it — see the threat model). If you would not hand
  a human assistant access to a mailbox, do not bind an agent to a
  Gmail tier over it; narrow `resources` or withhold the grant instead.
- Every upstream call is audited with the agent identity and scope, so
  you can review after the fact exactly what an agent did and read.

The full residual-risk record, including why content redaction is out
of scope, is in the
[connector tiers threat model](policy-tiers-threat-model.md).
