# ADR 0007 — UDS-mediated credential-seal boundary

**Status:** Accepted

**Date:** 2026-05-12

**Story:** 7.30 (this release; stacks on 7.25 → 7.26 → 7.27 → 7.28 → 7.29).

## Context

ADR-0006 established the post-rc.22 macOS architecture: the daemon runs as root from a LaunchDaemon at `/Library/PrivilegedHelperTools/agentsso`, owns the master key in System.keychain (`-A` ACL), and owns `/Library/Application Support/permitlayer/` (root:wheel, mode 0700 on subdirectories). Control-plane requests arrive on a Unix domain socket at `/var/run/permitlayer/control.sock` with peer identity attested via `LOCAL_PEERCRED`.

The first rc.22 dev-box install testing surfaced a cross-user breakage that ADR-0006 did not address. A non-root operator running `agentsso connect gmail --oauth-client ~/client_secret.json --agent <name>` failed at the very first step — `resolve_agent_policy_name` opened the agent store at `/Library/Application Support/permitlayer/agents/` directly, hit the 0700 root:wheel directory perms, and exited with `error: failed to open agent store: I/O failure accessing store`.

The CLI's `connect.rs` opened nine fs/keystore touchpoints (`connect.rs:467`, `:506-507`, `:558`, `:590`, `:666-670`, `:796-803`, `:804-812`, `:818-825`, `:899-904`, plus verify-side reads). Each one required either (a) the CLI to run as root or (b) the operator's UID to own the relevant fs node. ADR-0006's privilege model says only root owns these paths. Both can't be true; the symptom was the connect flow being root-only by accident.

A second related problem: the CLI calls `permitlayer_oauth::client::OAuthClient::authorize` which calls `open::that()` unconditionally to launch the operator's browser. Apple's DTS Quinn (developer.apple.com/forums/thread/756081) and TN2083 confirm `/usr/bin/open` is AppKit-linked and "isn't rated for use in a non-GUI context." Under SSH-only sessions the call silently fails with `LSOpenURLsWithRole() failed with error -54`, and the OAuth callback never arrives.

## Decision

Move the entire credential-seal critical section daemon-side. The CLI keeps the operator-interactive OAuth dance (browser launch / headless paste / device-flow) and orchestrates a sequence of UDS POSTs; the daemon owns every fs touch, every vault seal, every keystore read, every policy-file edit.

Five new endpoints under `/v1/control/*` (Story 7.30 Commits 2-6):

- `GET  /v1/control/agent/{name}/policy_name` — agent lookup.
- `GET  /v1/control/credentials/{service}/meta` — idempotent re-run check.
- `POST /v1/control/credentials/seal` — token seal + meta write.
- `POST /v1/control/credentials/{service}/verify` — Google verify probe.
- `POST /v1/control/policy/{policy_name}/scopes` — scope merge + reload.

All endpoints are gated by the existing control-plane discipline: loopback-only enforcement via `ConnectInfo<SocketAddr>` + the control-token middleware. Peer credentials attested via `LOCAL_PEERCRED` flow into every audit event (`credentials-sealed`, `credentials-verified`, `policy-scopes-added`) so the audit log carries the operator's real UID — not 0.

The CLI's `connect.rs` shrinks from nine fs/keystore touchpoints to five UDS POSTs. The daemon-running gate inverts: pre-7.30 connect refused when the daemon was UP (to prevent seal-races with the refresh path); post-7.30 it requires the daemon UP because the daemon now owns the vault. The error code is `connect.daemon_must_run`, exit 2.

The master key never leaves the daemon process. The CLI never reads `/Library/Application Support/permitlayer/vault/`. The security boundary stays exactly where ADR-0006 placed it: on the privileged daemon binary.

### Browser-launch fallback

The CLI now detects non-GUI / cross-session contexts before calling `open::that()` and prints a copy-paste URL block + `--headless` / `--device-flow` suggestions when it can't reach a usable browser. Detection heuristics:

1. `SSH_CONNECTION` / `SSH_TTY` set.
2. `SUDO_USER` set AND `getuid() == 0`, with platform-specific GUI-session probes:
   - Linux: no `DISPLAY` / `WAYLAND_DISPLAY` → non-GUI.
   - macOS: `stat -f %Su /dev/console` ≠ `$SUDO_USER` → cross-session.
3. `AGENTSSO_FORCE_BROWSER_FALLBACK=1` env (test seam).

When the heuristics don't trip, `open::that()` is wrapped in `tokio::time::timeout(Duration::from_secs(5), ...)` so a wedged `LSOpenURLsWithRole` can't stall the runtime indefinitely.

## Plaintext-token threat model

The seal endpoint accepts OAuth access + refresh tokens in the request body as JSON strings. The token plaintext crosses the UDS in cleartext (the UDS is a kernel-mediated channel; eavesdropping requires CAP_SYS_PTRACE or equivalent; `LOCAL_PEERCRED` attests the caller's UID). On the daemon side the JSON parser deserializes into `Zeroizing<String>` fields, so:

- The `Zeroizing<T>` wrapper's `Drop` impl calls `String::zeroize`, which writes zeros over the full `Vec<u8>` capacity backing the String before the allocator frees it (zeroize 1.8 `impl Zeroize for String`, `RustCrypto/utils:zeroize/src/lib.rs:524-528`).
- The deserialize chain is `Z::deserialize(deserializer)?` wrapped in `Self()` (zeroize 1.8 `impl Deserialize for Zeroizing<T>`, `RustCrypto/utils:zeroize/src/lib.rs:568-580`) — no intermediate non-zeroized `String` survives.
- The seal handler's local bindings (`access_token_str`, `refresh_token_str` on the CLI side; the deserialized `payload.access_token` on the daemon side) drop at the end of the handler scope. The total plaintext window is the handler's microsecond lifetime per request.

The non-zeroizing window is `axum`'s `Bytes` request-body buffer. `Bytes` does NOT zeroize on drop; the bytes survive in the heap allocator's freelist until reuse. This is accepted as the threat boundary. Mitigations against future drift:

- The `Zeroizing<String>` wire-format is enforced by the daemon's `CredentialsSealRequest` struct; a future refactor that replaced it with bare `String` would be visible at code review.
- The plaintext exposure is equivalent to today's CLI heap exposure pre-7.30 (which held the same plaintext for the same duration). No regression; the change moves the heap that holds plaintext from one process to another.

Revisit if: a `Bytes`-zeroizing crate lands upstream; the threat model expands to a non-cooperative root process on the same host (which already has bigger problems).

## Alternatives considered

- **Group-readable subdirs (`agents/` mode 0750 + permitlayer-clients group)**. Rejected: violates ADR-0006's privilege model. The directory perm hardening at `install_macos.rs:976-980` was explicit ("Do NOT 'fix' subdirs back to 0750") for exactly this reason — group-readable agent files leak the bearer-token hash + lookup-key hex to anyone in the group.
- **Sudo-the-CLI (`sudo agentsso connect`)**. Rejected: Quinn DTS confirms `/usr/bin/open` is broken outside GUI context, so the OAuth browser launch fails under sudo from SSH. And sudo'ing the entire CLI moves the master-key plaintext into a privileged child process for the duration of the OAuth flow, exactly the failure mode the daemon-mediated split was designed to prevent.
- **Browser-in-daemon (the daemon owns the OAuth flow)**. Rejected: the daemon has no GUI session. `open::that()` from the daemon process would hit the same `LSOpenURLsWithRole` failure as the SSH operator's CLI. The daemon could in principle drive a headless OAuth flow, but the redirect-URL paste requires an operator's terminal, which the daemon doesn't have either.

## ENOTSUP deviation from spec

The Story 7.30 spec called for an `ENOTSUP` classification branch in the seal handler, returning `credentials.unsupported_volume` when the operator's vault path is on a non-APFS volume. Pre-implementation research (RustCrypto/utils + tempfile-rs + macOS `man 2 rename`) confirmed the spec was wrong about which syscall surfaces ENOTSUP: `write_metadata_atomic` goes through `tempfile::persist` → `rustix::fs::rename` (no flags), and `CredentialFsStore::put` uses `std::fs::rename` — both are plain POSIX `rename(2)`. macOS `man 2 rename` scopes ENOTSUP to flag-bearing `renamex_np` / `renameatx_np` only, neither of which is called from these paths. The branch was dropped from the seal handler; non-APFS-volume failures surface as `EROFS` / `EIO` / `EXDEV` / `EACCES` through the generic `credentials.store_io_failed` or `credentials.meta_write_failed` arms.

If the vault is later migrated to `renameatx_np_excl` (no-clobber semantics), ENOTSUP becomes reachable and this ADR would need to be revisited.

## References

- ADR-0006 — macOS LaunchDaemon system-service. Defines the privilege model this story stays within.
- Story 7.27 — Control plane + service lifecycle. Adds the UDS listener + `LOCAL_PEERCRED`.
- Story 7.30 — UDS-mediated credential seal. The story this ADR documents.
- Apple TN2083 — Daemons and Agents. The "isn't rated for use in a non-GUI context" guidance for `/usr/bin/open`.
- Apple DTS thread 756081 — Quinn's explicit answer on `LSOpenURLsWithRole` from non-Aqua sessions.
- RustCrypto/utils `zeroize` 1.8 — `impl Deserialize for Zeroizing<T>` and `impl Zeroize for String` (the load-bearing crate guarantees).
- tempfile-rs `persist` — confirms `tempfile::persist` uses `rustix::fs::rename` with no flags on Unix.
- macOS `man 2 rename` (XNU 12377+) — confirms ENOTSUP is gated on flag-bearing variants only.

## Revisit triggers

- A `Bytes`-zeroizing axum body extractor lands upstream → reconsider the plaintext-window section.
- macOS adds a daemon-GUI-launch API → reconsider the browser-in-daemon alternative.
- The vault is migrated to no-clobber `renameatx_np_excl` → re-add the ENOTSUP classification branch.
- A multi-operator-with-the-same-UID deployment shape emerges → re-evaluate whether `peer_uid` in the audit log is sufficient for attribution.
