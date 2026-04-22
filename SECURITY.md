# Security policy

## Reporting a vulnerability

Please report suspected security issues **privately** rather than in public
issues or pull requests.

- **Preferred:** open a private advisory at
  <https://github.com/botsdown/permitlayer/security/advisories/new>.
- Alternate: email `austin@botsdown.com` with the subject line
  `permitlayer security report`.

Please include:

- A description of the issue and the impact you believe it has.
- Steps to reproduce (a minimal test case, proof-of-concept, or CVE-style
  writeup).
- The commit SHA or release tag you observed the issue on.

I'll acknowledge receipt within a few business days and give you an estimated
remediation timeline. You'll be credited in the release notes unless you
prefer to remain anonymous.

## Scope

permitlayer is an identity and data-protection layer for AI agents. The
following crates carry the security-critical logic and are in scope for
advisories:

- `crates/permitlayer-credential` — the sealed credential types and their
  trait discipline. CODEOWNERS gates changes here.
- `crates/permitlayer-keystore` — OS keychain integration (macOS Keychain,
  Linux Secret Service, Windows Credential Manager).
- `crates/permitlayer-vault` — file-backed encrypted vault
  (AES-GCM + HKDF + Argon2).
- `crates/permitlayer-oauth` — OAuth 2.1 client, PKCE flow, token refresh.
- `crates/permitlayer-core` — scrub engine, policy engine, audit log
  integrity.
- `crates/permitlayer-proxy` — HTTP proxy layer between MCP clients and
  upstream providers.
- `crates/permitlayer-daemon` — the `agentsso` binary and its CLI surface.
- `install/install.sh` — installer signature verification.

## Out of scope

- Connector plugins (`crates/permitlayer-connectors/src/js/**`) — these run
  inside the QuickJS sandbox defined in `crates/permitlayer-plugins`.
  Sandbox-escape bugs are in scope; bugs inside individual connector
  business logic generally are not.
- Development tooling (`xtask/`, `scripts/`, CI workflows).

## Supported versions

permitlayer is pre-1.0; only the latest release receives security fixes.
Once 1.0 ships, this section will be updated with an explicit support
window.

## Release signing

Release tarballs are signed with ed25519 via minisign. The verifying public
key is committed at `install/permitlayer.pub` and mirrored in
`install/install.sh`. Signature files are published alongside each release
artifact on GitHub. See `scripts/sign-release.sh` for the signing workflow.
