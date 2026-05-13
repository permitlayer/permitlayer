# ADR 0006 — macOS: LaunchDaemon system-service over per-user LaunchAgent

**Status:** Accepted

**Date:** 2026-05-12

**Story:** 7.25 (parent spec) → 7.26 → 7.27 → 7.28 → 7.29 (this release)

**Refined by:** [ADR-0007 — UDS-mediated credential-seal boundary](0007-uds-mediated-credential-seal-boundary.md) (Story 7.30) extends this LaunchDaemon model with five `/v1/control/*` endpoints so `agentsso connect` runs as a normal operator (no root, no group-write to the master-key directory). The peer-credential boundary stays where this ADR put it.

## Context

The macOS install path needs three things to be true at once:

1. The daemon runs without depending on the operator having a GUI / Aqua session. The primary deployment shape is an admin operator who manages `agentsso` over SSH on a multi-user Mac where a different end-user holds the Aqua session.
2. The master key the daemon depends on for sealed credentials survives `brew upgrade`. A new binary with a different codesign hash must continue to read the existing master-key entry — no operator-side rekey, no Apple SecurityAgent prompt, no respawn loop.
3. The end-user reaches the daemon over a local channel with kernel-attested identity (not just a shared secret).

The previous per-user LaunchAgent model (rc.21 and earlier internal builds) satisfied none of those completely. Empirical evidence gathered 2026-05-10:

- **`gui/<uid>` domain doesn't exist for SSH-only users.** `launchctl bootstrap gui/<uid> …` returns exit 125 (`Domain does not support specified action`) when the admin user has no Aqua session. Field-verified on a customer macOS 15.7.5 Intel box.
- **Login-keychain ACL writes require SecurityAgent.** A launchd-spawned process in `user/501` can read existing items, but `set_secret` (or `security add-generic-password` without `-A`) on the login keychain returns `errSecInteractionNotAllowed` (`-25308`) — by design.
- **System.keychain's default ACL is also DR-bound.** A daemon adhoc-signed with CDHash X writes a master-key item; a respawned daemon adhoc-signed with CDHash Y (post-`brew upgrade`) reads back `-25308`. The default-ACL strategy reproduces the same failure mode, just in a different keychain file.

The combination drove the entire rc.17-rc.21 ACL-break-recovery edifice (codesign DR capture, trust-anchor TOFU, auto-rekey on `-25308`). That edifice was elaborate, brittle, and structurally trying to paper over an architectural mismatch.

## Decision

Adopt the Apple-documented system-service path:

- **LaunchDaemon at `/Library/LaunchDaemons/dev.permitlayer.daemon.plist`** (root:wheel, mode 0644), installed by `sudo agentsso service install`. Runs as root, starts at boot, no GUI session required.
- **Master key in System.keychain with an `-A` (allow-all-applications) ACL.** Written via `/usr/bin/security add-generic-password -A`, which produces an `allowAllForm` ACL with no DR binding. Any root process on the box can read the item — including a `brew upgrade`-delivered binary with a different CDHash.
- **Filesystem-level protection is the security boundary.** The privileged binary lives at `/Library/PrivilegedHelperTools/agentsso` (root:wheel, mode 0755); only root can replace it. The keychain stores encrypted bytes; "any root process can read this item" is appropriate because access to running-as-root is what we control.
- **Split-listener control plane:**
  - `/v1/control/*` (14 handlers) lives on a Unix domain socket at `/var/run/permitlayer/control.sock` (mode 0660, owned `root:permitlayer-clients`). The daemon reads the caller's UID via `LOCAL_PEERCRED` and audit-logs it alongside any bearer-token claim.
  - `/mcp/*` lives on TCP loopback at `127.0.0.1:3820`. MCP clients (OpenClaw, Claude Desktop, Cursor) speak HTTP-over-streamable-http and cannot connect to Unix sockets.
- **`permitlayer-clients` macOS group** (created by `service install`) gates control-plane access. The installing operator is added automatically; additional operators are added with `dseditgroup`.
- **End-user authentication** uses per-user bearer tokens minted by `agentsso agent register <name> --policy <policy-name>` and written to `~/.agentsso/agent-bearer.token` (mode 0600, owned by the invoking user). The daemon writes the token using a `tmp + chown + atomic-rename + O_NOFOLLOW` pattern that defends against CWE-367 / filelock-CVE-2026-22701 class of TOCTOU symlink attacks.

## Empirical evidence

Verification log entries (see `docs/operations/release-verification-log.md` for the post-tag field-verify entry):

- **V2 (2026-05-10) — macOS 26.3 arm64.** A launchd-spawned adhoc-signed Rust daemon writes a master-key item to System.keychain via `keyring::Entry::set_secret`. PASS.
- **V2-EXT P1.4 (2026-05-10).** Cross-CDHash read of a System.keychain item written with the DEFAULT ACL: a different-CDHash daemon's `get_secret` returns `-25308 errSecInteractionNotAllowed`. **This is the failure mode that makes the default-ACL strategy unworkable.**
- **V2-EXT-α P1.4α (2026-05-10).** Cross-CDHash read of a System.keychain item written with the `-A` ACL: a different-CDHash daemon's `get_secret` succeeds and the bytes match. **This is the load-bearing finding that makes the `-A` strategy work.**
- **V2-EXT-α-doc (2026-05-10).** Apple's `Security` open-source review confirms the `-A` → `allowAllForm` → no-DR-binding pipeline has been stable since at least macOS 10.9; no Sequoia regression touches ACL evaluation for `-A` items. This substitutes for an empirical Intel-box re-run; the rc.22 Angie-box field-verify (Task 10.8) is the production-truth gate.

## Alternatives considered

- **Passphrase-mode keystore on macOS.** Rejected: poor UX (operator types passphrase on every boot); defeats the purpose of OS-keychain integration. Linux still has a passphrase fallback for the future-story file-based keystore path.
- **File-based `/var/lib/agentsso/master.key` mode 0400 + AES-GCM at rest.** Rejected for macOS: System.keychain is the Apple-conventional location for daemon-owned secrets and we should use it. This option is the leading candidate for the Linux future story.
- **Apple Developer Program enrollment for proper code-signing.** Deferred: the `-A` ACL strategy survives cross-CDHash reads on adhoc-signed binaries (V2-EXT-α confirmed). Enrollment becomes a forced move only if a future macOS tightens System.keychain access for adhoc-signed binaries; until then it's overhead with no payoff.
- **Dedicated `_agentsso` macOS user.** Rejected per V4 research (Tailscale / cloudflared / Docker / brew services all run daemons as root): adds install complexity (`dscl` user creation, ownership churn across the entire state tree) for marginal blast-radius reduction. Root LaunchDaemon is industry-standard for system services in this class.
- **Single-listener "everything on UDS".** Rejected: would break every existing MCP client (HTTP-over-streamable-http is TCP-only per the MCP spec). Split-listener is the smallest correct design.
- **Single-listener "everything on TCP loopback".** Rejected: loses kernel-attested peer identity for the control plane. The control plane needs to know which OS user is making each call, not just which bearer token is on the wire.

## Consequences

- **Two-step install on macOS.** `brew install permitlayer/tap/agentsso` delivers the binary; `sudo agentsso service install` provisions the system service. One-time, per machine. Caveats injected into the Homebrew formula direct the operator.
- **Plugin escape becomes root RCE.** rc.22 ships plugins in-process inside the root LaunchDaemon. Customer-installed plugins are gated by an **interactive trust-prompt on first load** (`[plugins]` `warn_on_first_load = true`, the default in `crates/permitlayer-daemon/src/config/schema.rs::PluginsConfig`): an untrusted plugin's first load triggers `TrustPromptReader` and only runs after the operator explicitly trusts its SHA-256. Built-in connectors (gmail / calendar / drive) are code we control + audit and auto-trust as `TrustTier::Builtin` (`auto_trust_builtins = true`). The trust-prompt is an integrity gate, not an isolation boundary; a malicious-but-trusted plugin still inherits root. A post-rc.22 story lands OS-level sandboxing (`sandbox_init` profile or subprocess-with-setuid jail) before rc.23 ships.
- **Linux + Windows continue on the legacy per-user layout** (`~/.agentsso/`, no system service) for now. Cross-platform system-service parity is a future epic.
- **No vault migration tooling from prior internal builds.** Under burn-the-boats, operators install rc.22 fresh and re-OAuth their connectors. No `--migrate-from-rc21` flag.
- **`agentsso autostart` is gone.** Replaced by `agentsso service install/uninstall/status`. The internal `lifecycle/autostart/` helper module survives for brew-services detection in `update`/`uninstall`/`rotate_key` flows; a follow-up story inlines those call sites and deletes the directory.

## References

- Apple Developer Forum [#657874](https://developer.apple.com/forums/thread/657874) (Quinn DTS) — System.keychain requires root.
- Apple Developer Forum [#669350](https://developer.apple.com/forums/thread/669350) (Quinn DTS) — keychain ACL binds to designated requirement; new DR ⇒ prompt.
- Apple Developer Forum [#685967](https://developer.apple.com/forums/thread/685967) — daemons have system context, not user context.
- [Apple TN3137 — On Mac Keychains](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains) — file-based vs data-protection keychain.
- [Tailscale `install_darwin.go`](https://github.com/tailscale/tailscale/blob/main/cmd/tailscaled/install_darwin.go) — `tailscaled install-system-daemon` pattern.
- [Tailscale `safesocket/unixsocket.go`](https://github.com/tailscale/tailscale/blob/main/safesocket/unixsocket.go) — UDS + peer-cred auth.
- [CWE-367 TOCTOU race](https://cwe.mitre.org/data/definitions/367.html) — defended at the token-write boundary.
- [Quarkslab ControlPlane LPE on macOS](https://blog.quarkslab.com/controlplane_lpe_macos.html) — privileged-helper-in-`/usr/local/bin/` LPE writeup.

## Revisit triggers

- A future macOS release tightens System.keychain access for adhoc-signed binaries. → revisit Apple Developer Program enrollment.
- A customer environment surfaces a `-A` ACL eval divergence between Intel and Apple Silicon that's not explained by Apple's published Security source. → revisit native `SecAccessCreate` FFI in `permitlayer-platform-macos`.
- A demand surfaces for non-root LaunchDaemon (e.g., dedicated `_agentsso` system user). → revisit per V4 research; cost is install complexity + ownership churn across the state tree.
- Plugin sandboxing lands (post-rc.22 story before rc.23). → revisit the "plugin escape = root RCE" consequence; the `allow_user_plugins: false` default may flip.
