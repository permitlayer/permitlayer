# Agent skill: using permitlayer's MCP (paste-in copy)

This is the **paste-in copy** of the agentsso-gateway skill for MCP clients
that don't install from ClawHub — for example, Claude Desktop (where you'd
drop this into a system prompt), or Linux/Windows hosts where the ClawHub
package isn't yet supported.

> ClawHub/OpenClaw users: install the skill instead — `clawhub install
> agentsso-gateway`. Same content, auto-distributed, kept in lockstep with
> this page. See
> [`install/clawhub/agentsso-gateway/SKILL.md`](../../install/clawhub/agentsso-gateway/SKILL.md).

It teaches the agent things the MCP tool schemas don't: trust model, error
semantics, scrub behavior, audit trail, and the non-obvious tool flows.
Without these, an agent will retry policy denials, panic about redacted
content, mis-decode attachments, and make up explanations for normal
operational responses.

Copy the section between the dashes below into your MCP client's skills
directory (or paste it as the system prompt for the agent that uses the
permitlayer MCP server).

---

# Working with permitlayer

You're connected to **permitlayer**, a local daemon that mediates calls to
Google Workspace (Gmail, Calendar, Drive) through a sealed credential vault
and a per-agent policy. The daemon exposes an MCP-compatible HTTP endpoint
on `127.0.0.1:3820`, namespaced by service:

- `http://127.0.0.1:3820/mcp/gmail`
- `http://127.0.0.1:3820/mcp/calendar`
- `http://127.0.0.1:3820/mcp/drive`

Bare `/mcp` is not a route — every call goes to a per-service path.

## Identity

You hold a single bearer token bound to one policy, minted when an operator
ran `agentsso quickstart <service>`. The auth headers
(`Authorization: Bearer agt_v2_<name>_<random>` and
`x-agentsso-scope: <oauth-scope>`) are baked into the MCP config snippet
your client loaded; you do **not** set them by hand. The token cannot be
refreshed or escalated by you. If a call returns `auth.invalid_token` or
`auth.unauthorized`, do not retry — the operator must re-run
`agentsso quickstart <service>` to mint a fresh token.

The MCP transport is `streamable-http` (not SSE). If your client defaults
to SSE, the daemon will reject the connection.

## Using the tools correctly

These are the flows that aren't in the tool schemas — get them right or
you'll fail in confusing ways.

### Gmail attachments are TWO calls

`gmail.messages.get` does **not** return attachment bytes. It returns the
message envelope and parts; an attachment part has metadata + a pointer.

1. **Call `gmail.messages.get`** with `format: "full"`. Walk
   `payload.parts[]` (and nested `parts[]` for multipart messages). An
   attachment part looks like:
   ```json
   {
     "filename": "handbook.pdf",
     "mimeType": "application/pdf",
     "body": { "size": 718000, "attachmentId": "ANGjdJ..." }
   }
   ```
   The `body` here is a **pointer**, not the file. `body.data` may be
   absent or tiny — that is not a truncation.

2. **Call `gmail.attachments.get`** with the `message_id` (the outer
   message's `id`) and `attachment_id` (the part's `body.attachmentId`).
   It returns:
   ```json
   { "size": 718000, "data": "<base64url-encoded bytes>" }
   ```

3. **Decode `data` as base64url**, not standard base64. Base64url uses
   `-_` in place of `+/` and may omit `=` padding (RFC 4648 §5). Decoding
   it as standard base64 corrupts the bytes and produces what looks like
   a truncated file (missing PDF `%%EOF`, broken zip central directory).
   Most stdlibs have it directly: Python
   `base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))`, Node
   `Buffer.from(s, "base64url")`, Go `base64.URLEncoding.DecodeString`,
   Rust `base64::engine::general_purpose::URL_SAFE_NO_PAD`.

There is **no silent truncation**. If an encoded attachment exceeds the
proxy's 10 MiB response cap, you get a loud too-large error, not a
half-file. So a stub-sized result means you read the wrong field (step 1's
pointer) instead of fetching the bytes (step 2).

### `format` on messages/threads/drafts

`gmail.messages.get`, `gmail.threads.get`, `gmail.drafts.get` all take a
`format` param:

- `full` (default) — full payload tree, with `attachmentId` pointers in
  parts. Use this whenever you might need to discover attachments.
- `metadata` — headers only (combine with `metadata_headers: [...]`).
- `minimal` — IDs + labels + snippet.
- `raw` — entire RFC822 message base64url-encoded in `payload.body.data`.

`metadata` is much cheaper than `full`, but you cannot find attachments
from it.

### `calendar.events.update` replaces the WHOLE event

`calendar.events.update` is a **PUT** — any field you omit gets **cleared**
on the server. To change one field safely: `calendar.events.get` →
mutate → `calendar.events.update` with the complete object. Or use
**`calendar.events.patch`** for partial updates — it only touches the
fields you include. Prefer `patch` for single-field changes.

### Trash vs. delete

- `gmail.messages.trash` is **reversible** (`untrash` counterpart). Use
  this for "delete this email."
- `drive.files.delete` is **permanent** — it bypasses the trash, no undo.
  Confirm intent before invoking.

### Sending mail and creating drafts

`gmail.messages.send` expects `{ "raw": "<base64url-encoded RFC822>" }`.
`gmail.drafts.create` / `gmail.drafts.update` wrap that as
`{ "message": { "raw": "<base64url RFC822>" } }`. `gmail.drafts.send`
takes `{ "id": "<draftId>" }` (no body).

Compose the RFC822 envelope yourself
(`From: …\r\nTo: …\r\nSubject: …\r\n\r\nBody`), base64url-encode the whole
thing, embed.

### Scope tiers gate writes

Read tools use `*.readonly` scopes. Writes need the matching scope:
`gmail.send`/`gmail.modify`/`gmail.compose`, `calendar.events`,
`drive.file`. If a write returns **403 `policy.denied`**, the agent is
bound to a read-only tier. Tell the operator they need to re-run
`agentsso quickstart <service> --read-write` to grant write access.
Don't retry.

## Errors are operational, not transient

| Code | Meaning | What you should do |
|---|---|---|
| `policy.denied` (HTTP 403) | Operator's policy refused this scope/resource. Response includes a `rule_id`. | Don't retry. Surface the rule_id. Tell the operator they can re-run `agentsso quickstart <service> --read-write` for write access, or add a host-local operator-layer policy. |
| `policy.approval_unavailable` | A `prompt`-mode rule was hit but the daemon has no way to ask a human (it runs headless). | Don't retry. Shipped policy tiers never prompt — this means the operator hand-authored a custom `prompt` policy on a headless daemon. Surface it: that policy needs `auto` or `deny`, not `prompt`. |
| `auth.invalid_token` / `agent.not_found` | Your bearer is wrong, expired, or the agent record was removed. | Don't retry. Operator must re-run `agentsso quickstart <service>`. |
| `kill_switch_active` (HTTP 403) | The user (or you) hit the kill switch (`agentsso kill`). | Don't retry. Surface it. |
| 5xx / network | Daemon is unreachable or crashed. | Retry once after a short delay. If still failing, tell the operator to check `agentsso status`. |

**Never retry `policy.*` or `auth.*` errors.** They are deliberate refusals,
not transients.

## Scrubbed content

Tool responses can contain **redaction placeholders** in place of sensitive
content the daemon detected:

- `<REDACTED_BEARER>` — bearer-token-shaped string
- `<REDACTED_JWT>` — JSON Web Token
- `<REDACTED_OTP>` — 6-digit one-time password
- `<REDACTED_RESET_LINK>` — password-reset URL
- `<REDACTED_EMAIL>` — email address
- `<REDACTED_PHONE>` — phone number
- `<REDACTED_SSN>` — US SSN-shaped string
- `<REDACTED_CC>` — credit-card-shaped digit run

These are **one-way redactions** — they have no reverse mapping you can
dereference. Don't pretend you saw the value behind the placeholder, and
don't try to reconstruct it from context. Say: "the message contains a
one-time code (redacted by permitlayer) — the operator can read it
directly."

## There is no human in the loop — access is binary

permitlayer's daemon runs **headless** (a background system service with no
controlling terminal). There is no approval prompt, no `agentsso approve`
command, no "wait for the operator to press y/n":

- A scope your policy grants → the call works, immediately.
- A scope it does not grant → `policy.denied` (HTTP 403), immediately.

A call that's slow is slow for ordinary reasons (upstream Google latency,
large response) — never because a human is deciding. Don't special-case
long calls as "waiting for approval"; use a normal generous timeout and
surface real errors verbatim.

(The `policy.approval_*` codes still exist for the rare operator who
hand-authors a custom `prompt` policy and runs the daemon in a foreground
terminal — that's not the headless deployment this skill targets. Treat any
you see as a misconfiguration to surface, not a state to wait on.)

## Audit is ground truth

Every call you make is recorded in the daemon's audit log with your agent
name, scope, resource, and policy decision. The operator can inspect it
with `agentsso audit --follow` or `agentsso audit --export=audit.csv`.

Be honest about your tool calls in replies to the user. Don't hide failed
calls; the operator will see them anyway, and you'll lose trust if the
audit log doesn't match your story.

## Summary of good citizenship

1. Trust the policy. Don't try to escalate it.
2. Treat redactions as opaque. Don't claim to see through them.
3. Access is binary and immediate — a denied scope won't become allowed by
   waiting or retrying.
4. Surface error codes verbatim when explaining failures.
5. For Gmail attachments, make TWO calls and decode base64url, not base64.
6. For `calendar.events.update`, fetch-then-update (PUT replaces everything)
   or use `events.patch`.
7. Be honest in summaries — the audit log is the ground truth.
