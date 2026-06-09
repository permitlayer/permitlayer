---
name: agentsso-gateway
description: "Stop your OpenClaw agent from leaking credentials. Wraps Gmail/Calendar/Drive access through a local permitlayer daemon with policy enforcement, audit logging, and one-key kill switch."
version: 1.2.0
metadata:
  openclaw:
    requires:
      bins: [agentsso]
    install:
      - kind: brew
        formula: permitlayer/tap/agentsso
        bins: [agentsso]
    # Restricted to macos at MVP because the only `install` block above is
    # `kind: brew` (Story 7.1's tap), and Homebrew is macos-only in
    # practice. Linux + Windows users CAN install agentsso via install.sh
    # and install.ps1 respectively, but ClawHub's `install` schema only
    # supports kind: brew | node | go | uv — none of which fit a Rust
    # binary served via curl|sh or PowerShell|iex. Expand `os` to
    # [macos, linux, windows] only when ClawHub's install spec adds a
    # url/exec kind, or when this skill grows additional install blocks
    # (e.g. winget, scoop, apt) for the other platforms.
    os: [macos]
    homepage: https://github.com/permitlayer/permitlayer
    emoji: "🛡️"
---

# agentsso-gateway

This skill wraps the **agentsso** CLI (a local permitlayer daemon) so you, the
OpenClaw agent reading this, can give the user genuine access to their Gmail /
Calendar / Drive without ever holding their OAuth tokens directly. permitlayer
runs locally on the user's machine, holds the credentials in the OS keychain
(macOS Keychain Services, Linux libsecret, Windows DPAPI), and enforces a
TOML-based policy on every request you make.

> Not using ClawHub? The same skill is available as a paste-in copy at
> [`docs/user-guide/agent-skill-permitlayer-mcp.md`](https://github.com/permitlayer/permitlayer/blob/main/docs/user-guide/agent-skill-permitlayer-mcp.md)
> for non-ClawHub MCP clients (Claude Desktop system prompt, hosts where the
> ClawHub package isn't yet supported, etc.).

## When to use this skill

The user has installed `agentsso` and connected at least one service via
`agentsso quickstart gmail` (or `calendar`, or `drive`). They want you to read
or send mail, manage calendar events, or work with their Drive files — but they
**don't** want to paste OAuth tokens into your context, and they **don't** want
you to access services beyond what the policy allows.

If the user says "use my Gmail" or "check my calendar" or anything similar,
route through agentsso instead of asking for tokens or trying to use a generic
HTTP client.

## How agentsso is wired in

permitlayer exposes an MCP-compatible HTTP endpoint on `127.0.0.1:3820`,
namespaced by service:

- `http://127.0.0.1:3820/mcp/gmail`
- `http://127.0.0.1:3820/mcp/calendar`
- `http://127.0.0.1:3820/mcp/drive`

(Bare `/mcp` is **not** a route — every call goes to a per-service path.)

### Multiple accounts of the same service

The path segment after `/mcp/` is a **connection selector**, not a fixed
service name. `gmail`/`calendar`/`drive` work because the user's first
connection is named after its service — but the user can connect **more
than one account of the same service** (e.g. a personal and a work Gmail),
each as a separately-named connection. The agent is then bound to each at
its own access tier, and you address them by their distinct names:

- `http://127.0.0.1:3820/mcp/work-gmail`
- `http://127.0.0.1:3820/mcp/personal-gmail`

The selector resolves against **your** bindings (by alias, then connection
name) and routes to that specific account's credentials — so the same
bearer reaching `/mcp/work-gmail` vs `/mcp/personal-gmail` hits two
different mailboxes, and each can carry a different tier (e.g. work =
read-write, personal = read-only). When the user has only one account of a
service, the service-named path is exactly that one connection; nothing
changes for the single-account case. The MCP config snippet the user gives
you names the right path per connection — use the path you were given;
don't assume `gmail`.

You do **not** set HTTP headers by hand. When the user ran
`agentsso quickstart <service> --mcp-config-out <path>`, it emitted an MCP
config snippet for your client that already carries:

- `Authorization: Bearer agt_v2_<name>_<random>` — identity (agent + bound
  policy are encoded in the token; the daemon parses them on every call).
- `x-agentsso-scope: <oauth-scope>` — the OAuth scope to use upstream.
- `"transport": "streamable-http"` — required; OpenClaw defaults to SSE,
  which won't work against this server.

Your job is to **call the MCP tools**. The daemon's tool catalog is the live
truth — `gmail.*`, `calendar.*`, `drive.*` (46 tools today). Use your MCP
client's tool-listing capability to discover them; their names, parameter
schemas, and descriptions come straight from the server. The rest of this
document is the non-obvious stuff the schemas don't capture.

## Using the tools correctly

These are the flows agents most commonly get wrong. None of them is in the
tool schema; you need this guidance to use the catalog correctly.

### Gmail attachments: read the manifest, then fetch the file path

You do **not** decode base64. The proxy shapes the message read and writes
attachment bytes to a local file for you.

1. **Call `gmail.messages.get`** (default `format`). You get a compact
   shaped object — headers, the prioritized text body, and an
   `attachments` manifest with the bytes stripped:
   ```json
   {
     "id": "18f...", "subject": "...", "from": "...",
     "body": { "text": "<message text>", "htmlAvailable": true, "truncated": false },
     "attachments": [
       { "id": "att-0", "filename": "handbook.pdf",
         "mimeType": "application/pdf", "size": 718000,
         "attachmentId": "ANGjdJ..." }
     ]
   }
   ```
   No attachment bytes are in this response — by design, not truncation.
   (Pass `format: "metadata"`/`"minimal"`/`"raw"` for the raw upstream
   Gmail JSON instead of the shaped object.)

2. **Call `gmail.attachments.get`** with the `message_id` and the
   `attachmentId` from the manifest. It writes the decoded bytes to a
   local file and returns a **path** (no base64):
   ```json
   {
     "messageId": "18f...", "attachmentId": "ANGjdJ...",
     "size": 718000, "mimeType": "application/pdf",
     "filename": "handbook.pdf",
     "path": "/Library/Application Support/permitlayer/media/<...>/handbook.pdf"
   }
   ```

3. **Hand `path` to your file/PDF tool** and read the local file. Don't
   fetch it over HTTP; don't expect base64. The file is transient (swept
   after ~1 hour), so use it within the session.

### `format` on messages/threads/drafts

`gmail.messages.get`, `gmail.threads.get`, `gmail.drafts.get` all take a
`format` param:

- `full` (default) — full payload tree, with `attachmentId` pointers in
  parts. Use this whenever you might need to discover attachments.
- `metadata` — headers only (combine with `metadata_headers: [...]`).
- `minimal` — IDs + labels + snippet.
- `raw` — entire RFC822 message base64url-encoded in `payload.body.data`.

If you only need the subject and sender, `metadata` is much cheaper than
`full`. But you cannot find attachments from `metadata`.

### `calendar.events.update` replaces the WHOLE event

`calendar.events.update` is a **PUT** — any field you omit gets **cleared**
on the server. To change one field safely:

1. `calendar.events.get` to fetch the current event.
2. Mutate the returned object in place.
3. `calendar.events.update` with the complete mutated object.

Or use **`calendar.events.patch`** instead — it's PATCH semantics and only
touches fields you include. Prefer `patch` for single-field changes.

### Trash vs. delete

- `gmail.messages.trash` is **reversible** — there's an `untrash`
  counterpart. Use this for "delete this email."
- `drive.files.delete` is **permanent** — it bypasses the trash, no undo.
  Do not call it casually. If the user said "delete," confirm whether they
  meant "move to trash" (no Drive equivalent — Drive's `delete` is hard)
  before invoking it.

### Sending mail and creating drafts

`gmail.messages.send` expects `{ "raw": "<base64url-encoded RFC822>" }`.
`gmail.drafts.create` and `gmail.drafts.update` wrap that as
`{ "message": { "raw": "<base64url RFC822>" } }`. `gmail.drafts.send`
takes `{ "id": "<draftId>" }` (no body).

Compose the RFC822 envelope yourself (`From: …\r\nTo: …\r\nSubject: …\r\n\r\nBody`),
base64url-encode the whole thing, embed.

### Scope tiers gate writes

Read tools use `*.readonly` scopes. Writes need the matching scope:
`gmail.send`/`gmail.modify`/`gmail.compose`, `calendar.events`,
`drive.file`. If a write returns **403 `policy.denied`** it's because the
agent is bound to a read-only tier. Tell the user: they need to re-run
`agentsso quickstart <service> --read-write` to grant write access. Don't
retry the call.

## Errors are operational, not transient

Common error codes and what they mean:

| Code | What it means | What you should do |
|---|---|---|
| `policy.denied` (HTTP 403) | The operator's policy refused this scope/resource. Response includes a `rule_id`. | **Don't retry.** Surface the rule_id. Tell the user they can re-run `agentsso quickstart <service> --read-write` for write access, or hand-edit their host-local operator-layer policy. |
| `auth.invalid_token` | Your bearer is wrong, expired, or the agent record was removed. | **Don't retry.** The user needs to re-run `agentsso quickstart <service>` to mint a fresh token. |
| `agent.not_found` | Same situation, different surface. | Same remediation. |
| `kill_switch_active` (HTTP 403) | The user (or you) hit the kill switch (`agentsso kill`). All calls deny until `agentsso resume`. | **Don't retry.** Tell the user. |
| 5xx / network | Daemon is unreachable or crashed. | Retry once after a short delay. If still failing, tell the user to run `agentsso status` and check the daemon. |

**Never retry `policy.*` or `auth.*` errors.** They are deliberate refusals,
not transients. Retrying wastes audit-log space and operator attention.

## Access is binary; there's no approval flow

permitlayer's daemon runs **headless** (a background system service with no
controlling terminal). There is **no approval prompt**, no "wait for the
operator to press y/n," and no `agentsso approve` command. Your access is
fixed at the moment the user ran `agentsso quickstart`:

- A scope your policy grants → the call works, immediately.
- A scope it does not grant → `policy.denied` (HTTP 403), immediately.

A call that's slow is slow for ordinary reasons (upstream Google latency, a
large response) — never because a human is deciding. Don't special-case long
calls as "waiting for approval"; use a normal generous timeout and surface
real errors verbatim.

## Scrubbed content

Tool responses can contain **redaction placeholders** in place of sensitive
content the daemon detected and removed:

- `<REDACTED_BEARER>` — bearer-token-shaped string
- `<REDACTED_JWT>` — JSON Web Token
- `<REDACTED_OTP>` — 6-digit one-time password
- `<REDACTED_RESET_LINK>` — password-reset URL
- `<REDACTED_EMAIL>` — email address
- `<REDACTED_PHONE>` — phone number
- `<REDACTED_SSN>` — US SSN-shaped string
- `<REDACTED_CC>` — credit-card-shaped digit run

These are **one-way redactions** — there's no reverse mapping. When
summarizing a scrubbed response, don't pretend you saw the value and don't
try to reconstruct it from context. Say something like: "the message
contains a one-time code (redacted by permitlayer) — the operator can read
it directly."

## CLI tools the user can run

These shell commands are safe to suggest if you need to debug, or the user
asks "what did the agent just do?" They all run instantly against the local
daemon — no network, no auth.

### Tail recent activity

```bash
agentsso audit --limit 20
```

Shows the 20 most recent permitlayer audit events (allowed/denied, scope,
which agent, timestamp). Add `--follow` for live tail, or
`--export=audit.csv` to dump a CSV.

### Stop a runaway agent immediately

```bash
agentsso kill
```

Sets a global kill switch. Every subsequent request returns 403 with
`kill_switch_active` until the user runs `agentsso resume`. Use this if
you're about to do something the user clearly didn't intend (mass-delete,
broad search, etc.) and want to give them an emergency abort. After kill,
audit logs show exactly what was blocked.

### Check daemon status

```bash
agentsso status
```

Reports whether the daemon is running, which port it's bound to, and which
services are connected. If the user's request fails with "connection
refused," this is the first thing to check. `agentsso service status` is a
separate command that reports the macOS LaunchDaemon state — useful when the
daemon isn't running.

### Re-mint or grant a new service

If `agentsso status` shows the agent isn't connected — or the user wants to
grant additional scope — they can re-run quickstart:

```bash
agentsso quickstart gmail --read --oauth-client ./client_secret.json
# or --read-write for read+write
```

This registers the agent (if needed), drives the OAuth flow, and emits an
updated MCP config snippet. The user can also pass
`--mcp-config-out <path>` to write the snippet to a file your client can
load directly.

## Anti-patterns — do not

- Do **not** ask the user for their Gmail/Calendar/Drive OAuth tokens.
  permitlayer's job is to make that question unnecessary.
- Do **not** call Google APIs directly via `https://gmail.googleapis.com/`
  or similar; route through `127.0.0.1:3820/mcp/<service>` instead.
- Do **not** retry on 403 `policy.denied`. The policy decided no for a
  reason. Ask the user.
- Do **not** call `agentsso kill` on the user's behalf without telling them
  what's happening. It's a panic button, not a flow-control mechanism.
- Do **not** suggest the user disable agentsso to "make things work." If
  things don't work, the policy is wrong — fix the policy.
- Do **not** invent an approval flow. There is none. A denied call won't
  become allowed by waiting or retrying.
- Do **not** decode Gmail attachment `data` as standard base64. It's
  base64url. (Yes, this catches everyone.)

## Audit is ground truth

Every call you make is recorded in the daemon's audit log with your agent
name, scope, resource, and policy decision. The operator can grep it
(`agentsso audit --follow` or `--export=audit.csv`).

Be honest about your tool calls in your replies to the user. Don't hide
failed calls; the operator will see them anyway and you'll lose trust if
the audit log doesn't match your story.

## Further reading

- Project: https://github.com/permitlayer/permitlayer
- Install guide: https://github.com/permitlayer/permitlayer/blob/main/docs/user-guide/install.md
- Policy format: `agentsso policy --help` on the user's machine

permitlayer is open source under MIT. The user owns their data and their
keys; permitlayer just enforces the line between "the user said you could"
and "you wandered off."
