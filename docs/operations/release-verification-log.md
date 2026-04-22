# Release verification log

One entry per release that has been end-to-end verified against the
customer-facing install paths. Appended to as part of each release's
manual AC pass.

Format: `## YYYY-MM-DD — <tag> — Story <N.N>` with a brief result
summary. Link to the GitHub Release. Note any deviations from the
expected flow.

---

## 2026-04-22 — `v0.2.0` — Story 7.1

**First release.** Shipped as stable `v0.2.0` (not `v0.2.0-rc.1` as
originally planned — see Story 7.1 Dev Agent Record for why the tag
strategy changed). Both macOS architectures (ARM64 + x86_64) ship.

### Automated CI verification (pipeline run `24802657936`)

- `brew style --fix Formula/agentsso.rb` → zero offenses remaining.
  Replaces the `brew audit --strict` pre-push check (disabled for path
  arguments in modern Homebrew; see Story 7.1 Dev Agent Record).
- `brew tap permitlayer/tap && brew install permitlayer/tap/agentsso`
  on the CI `macos-14` runner — succeeded. `agentsso --version`
  returned `0.2.0`.
- `brew services` lifecycle NOT exercised in CI (launchd is absent
  on ephemeral runners). Covered by real-machine manual verification
  below.

### Real-machine manual verification

**macOS ARM64 (Apple Silicon, `austinlowry@mac`, dev machine):**

- Install path confirmed end-to-end via the `homebrew-publish` job's
  smoke test on `macos-14` CI runner (same hardware class). `brew
  install` + `agentsso --version` = `0.2.0`.
- `brew services start agentsso` / `brew services stop agentsso`
  lifecycle not yet exercised locally. AC #3 pending.

**macOS Intel (x86_64, fresh user `angie@Angie`):**

- Initial install diagnostic: user reported `bad CPU type in
  executable` from `agentsso`. Root cause: pre-existing `/usr/local/
  bin/agentsso` from an earlier manual copy (arm64 binary) was
  shadowing the brew install. `brew list` showed no `agentsso`
  formula installed — brew had never actually run on that machine for
  this tap. After `sudo rm /usr/local/bin/agentsso` and a clean
  `brew tap permitlayer/tap && brew install permitlayer/tap/
  agentsso`, the x86_64 tarball installed correctly; `file
  /usr/local/bin/agentsso` reported `Mach-O 64-bit executable
  x86_64`. **Confirms the Intel arch branch of the formula works.**
- OAuth setup flow via `agentsso setup gmail --oauth-client ...`
  succeeded end-to-end: tokens sealed to macOS Keychain, Gmail
  tested with 1 read, scopes granted.
- Daemon lifecycle + MCP proxy use pending further testing.

### Pending AC coverage (Story 7.1 Task 8)

- AC #3: `brew services start/stop agentsso` lifecycle on real macOS
  (both arches).
- AC #9: timed `brew install` on broadband (target <30s).
- AC #5 strict: dist-generated formula passes `brew audit --strict`.
  Current behavior: formula passes `brew style --fix` + `brew style`
  (zero offenses), which covers the rubocop-style subset of
  `--strict`. Running `brew audit --strict` on a tapped formula is
  advisory-only (not in pipeline).

### Notes for future releases

- The pipeline is now fully green end-to-end. `v0.2.1+` should ship
  without manual intervention (barring new Story 1.12 scaffolding
  bugs, which this release flushed out comprehensively).
- Users who already manually copied `/usr/local/bin/agentsso` before
  v0.2.0 tap-install should `sudo rm` it first — `brew install`
  will not overwrite a file it didn't create.
