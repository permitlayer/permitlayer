# ADR 0008 — Media-file trust boundary for attachment delivery

**Status:** Accepted

**Date:** 2026-05-29

**Story:** Gmail attachment & message-read UX overhaul (stacks on ADR-0006 and ADR-0007).

## Context

The MCP proxy exposes `gmail.attachments.get`. The original implementation returned the attachment bytes inline as base64url in the tool result. For a 425 KB PDF that is ~140K tokens of base64 the model must swallow and decode via an `exec` script — it blew up the context and the agent turn died (`non_deliverable_terminal_turn`). Separately, `messages.get?format=full` inlined small inline-part data and tripped the proxy's 10 MiB upstream-buffer cap.

The fix delivers attachment bytes as a **local file path**, not base64: the proxy decodes the attachment and writes it to disk, returning `{ size, mimeType, filename, path }`. The agent's `pdf`/file tools read the path directly. This was chosen after verifying (against OpenClaw's source) that the real MCP client (a) does not resolve MCP `resource_link`/`resources/read`, (b) blocks loopback `127.0.0.1` in its `web_fetch`/`pdf` SSRF guard with no opt-in, and (c) accepts a local file path. OpenClaw runs same-host as the daemon, so a local path is readable.

This introduces a **new on-disk surface** the daemon writes for a client to read across the privileged-install user boundary (daemon = root, agent = operator's user). ADR-0007's "Alternatives considered" explicitly **rejected group-readable daemon subdirs** (`agents/` at `0750 +permitlayer-clients`) because daemon-private files leaked to the group have no secondary authorization gate — and `install_macos.rs` carries a "Do NOT 'fix' subdirs back to 0750" guard. `control.token` is group-readable *only* because UDS `LOCAL_PEERCRED` is the real gate; a returned file path has no such gate. So a naive `media/` at `0640 root:permitlayer-clients` would let any `permitlayer-clients` member read every agent's decrypted attachments.

## Decision

Accept a **narrow, mitigated** new trust boundary for transient attachment files, distinct from the credential vault's `0700` root-only model.

1. **Location & perms (macOS privileged install):** attachments live under `<state>/media/`, created `0710 root:permitlayer-clients` (group-**traversable**, NOT listable). Files are written `0640 root:permitlayer-clients` via `permitlayer_core::files::write_client_readable_file` (the same atomic-write + reconcile mechanism as `control.token`, with the same fail-closed behavior: any chgrp/chmod failure re-narrows to `0o600`).

2. **Per-agent isolation + unguessable path:** files are written to `media/<sha256(agent)[..16]>/<unguessable-nonce>/<sanitized-filename>`. The directory is non-listable (`0710`), the agent component is hashed, and the per-fetch nonce is returned **only** to the requesting agent. A group member who does not already hold the path cannot enumerate or guess another agent's attachments.

3. **TTL, not durable store:** a daemon background task sweeps files older than **1 hour** (well beyond an agent's read window). Media is explicitly NOT a persistent store.

4. **Single-user tiers (Linux/Windows `~/.agentsso`):** `media/` is `0700`, files `0600`, under the operator's own home. The agent IS the operator; no group exposure exists.

## Consequences

- **Accepted exposure:** on the macOS multi-user-group case, a decrypted email attachment is readable by `permitlayer-clients` members who obtain its unguessable path, for up to 1 hour. The operator curates group membership (`dseditgroup`); every member is already trusted to operate as themselves (the same trust assumption ADR-0007 documents for `control.token`). This is weaker than the vault's `0700` root-only secrecy, and is accepted *only* for transient, non-credential attachment bytes — never for vault/keystore material.
- The bytes never pass through the scrub engine (binary; see the `fetch_raw` un-scrubbed path) and never enter an MCP text result (no base64 in context).
- The attachment-fetch path uses a higher upstream body cap (`MAX_ATTACHMENT_BODY`, 50 MiB) than the JSON path (`MAX_RESPONSE_BODY`, 10 MiB), since the bytes are written to disk server-side rather than buffered into a model-visible payload.

## Alternatives considered

- **Inline base64 (status quo).** Rejected: context blow-up; the motivating failure.
- **MCP `resource_link` + `resources/read`.** Rejected: OpenClaw's embedded MCP client never calls `resources/read` (verified in its source); the link would be ignored.
- **Authenticated HTTP fetch endpoint (`GET /v1/attachments/...`).** Rejected: OpenClaw's `web_fetch`/`pdf` SSRF guard blocks loopback with no opt-in and sends no auth header, so the agent cannot reach a `127.0.0.1` proxy URL.
- **Vault-style `0700` root-only media dir.** Rejected: the agent (operator's user) could not read the file — defeats the purpose. The cross-user read is the whole point.

## Revisit if

- A remote / non-same-host MCP client is supported (the local-path contract breaks; revisit the fetch-endpoint/resource-link options).
- OpenClaw (or another supported client) gains MCP resource support or a loopback-capable authenticated fetch.
- The threat model expands to a non-cooperative `permitlayer-clients` member (the same caveat ADR-0007 carries).

## References

- ADR-0006 — macOS LaunchDaemon system-service (the privilege model).
- ADR-0007 — UDS-mediated credential-seal boundary (rejected group-readable subdirs; the `control.token` cross-user pattern this reuses).
