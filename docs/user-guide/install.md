# Install

permitlayer ships the `agentsso` binary for macOS (ARM64 and x86_64) and
Windows (x86_64). Linux lands in Story 7.7.

## macOS — Homebrew (recommended)

```sh
brew tap permitlayer/tap
brew install permitlayer/tap/agentsso
agentsso connect gmail --oauth-client ./client_secret.json --agent <name>
```

`brew install` downloads the architecture-matched tarball from
GitHub Releases, verifies its SHA256 digest (embedded in the
formula), and installs `agentsso` at:

- **Apple Silicon:** `/opt/homebrew/bin/agentsso`
- **Intel:** `/usr/local/bin/agentsso`

### Starting the daemon (manual or autostart)

```sh
agentsso start            # foreground for this session
# OR
agentsso autostart enable # persistent across reboots (Story 7.16: SSH-friendly)
```

`agentsso autostart enable` writes a per-user LaunchAgent at
`~/Library/LaunchAgents/dev.agentsso.daemon.plist` and bootstraps it
into launchd's `user/$UID` domain. **Works over SSH on macOS 13+** —
unlike the legacy `gui/$UID` domain, `user/$UID` is bootstrapped by
any session (gui or ssh) and persists across logout. Story 7.16
re-targeted from `gui/$UID` after the rc.15 install on Angie's box
hit `launchctl exit 125: Domain does not support specified action`
on the second command over SSH.

Check status with `agentsso autostart status` or `agentsso status`.

> **Story 7.16 changed the recommended path.** rc.15 and earlier
> formulas shipped a `service do` block that registered a
> `homebrew.mxcl.agentsso` plist via `brew services start agentsso`.
> That path is structurally broken over SSH on modern macOS (Homebrew
> internally targets the `gui/$UID` launchd domain, which doesn't
> exist for SSH-only sessions). The rc.16 formula no longer ships
> the `service do` block. If you're upgrading from rc.≤15 with brew-
> services active, the next `agentsso autostart enable` automatically
> migrates the brew-managed plist to a `*.bak.<timestamp>` backup
> and registers our user-domain plist instead.

### Upgrading

```sh
brew upgrade agentsso
```

`brew upgrade` swaps the binary in place. If you previously had
brew-services managing the daemon (rc.≤15 install path), the
brew-services plist still exists at
`~/Library/LaunchAgents/homebrew.mxcl.agentsso.plist`; the next
`agentsso autostart enable` will migrate it (back up + remove)
and bootstrap our user-domain plist.

### What happens during a `brew upgrade`

Each `brew upgrade agentsso` swap installs a binary with a different
codesign hash. macOS treats this as a security-relevant event: the
new binary's hash no longer matches the keychain ACL on the previous
binary's master-key entry, so the keychain returns OSStatus -25308
("User interaction is not allowed") on the next master-key lookup.

**rc.19+ auto-recovers headlessly on Apple Silicon and Intel macOS
alike.** (Apple Silicon worked from rc.18; Intel macOS required
Story 7.24's release-pipeline ad-hoc codesign fix to land in rc.19.)
On boot the daemon:

1. Detects the -25308.
2. Reads the persisted codesign trust anchor at
   `~/.agentsso/keystore/codesign-trust-anchor.req` (captured on
   first boot via macOS's `SecCodeCopyDesignatedRequirement` — see
   the rc.17 / rc.18 caveat below for why "first boot" means "first
   rc.18 boot on Apple Silicon, first rc.19 boot on Intel macOS").
3. Verifies the new binary's Designated Requirement against the
   stored anchor. If it matches (legitimate publisher upgrade), the
   daemon proceeds; if it doesn't (different signing identity, or a
   completely-unsigned binary), it hard-fails with exit code 7 and
   a structured banner pointing at manual re-trust.
4. Atomically rekeys the vault under a freshly-minted master key
   (the same crash-safe state machine as `agentsso rotate-key`):
   each sealed credential is re-sealed under the new key; each
   registered agent's `lookup_key_hex` is recomputed under the new
   daemon subkey.
5. Re-captures the trust anchor under the running binary's DR (so
   the next upgrade verifies against THIS binary, not whatever was
   captured on first boot).
6. Continues normal boot under the new master key.

> **rc.17 / rc.18 caveat:** rc.17 shipped this code path but a
> launchd-spawned capture bug kept the trust anchor from being
> written, so the daemon respawn-looped under launchd after every
> `brew upgrade`. Story 7.23 (rc.18) fixed the capture by switching
> from `SecCodeCopySigningInformation`'s dictionary lookup (which
> fails for adhoc-signed binaries) to `SecCodeCopyDesignatedRequirement`
> (which derives the implicit DR for adhoc). However, the
> `x86_64-apple-darwin` release tarball shipped *unsigned* — Apple's
> Intel linker doesn't auto-adhoc-sign during `cargo build` the way
> the arm64 linker does — so on Intel macOS the daemon-side fix
> still had no codesign to capture, and rc.18 respawn-looped on
> Intel boxes. Story 7.24 (rc.19) ad-hoc codesigns the x86_64
> tarball in CI before publish; rc.19 is the first release where
> the contract works headlessly end-to-end on **both** Apple Silicon
> and Intel macOS.

**Bearer tokens are preserved across the rekey.** Operators with
existing MCP-client configs continue to authenticate with their
existing `agt_v2_*` tokens after the upgrade — the rekey changes
the master key + lookup-key, not the token itself.

If verification fails (exit code 7, `AclBreakDrMismatch` banner), the
recovery path is to investigate before removing the trust anchor.
This is a security-relevant rejection: if the new binary was NOT
installed by you, do NOT clear the anchor.

> **Switching install methods is treated as a binary swap.** A binary
> built by `cargo install` has a different CDHash than the brew-
> tarball binary, so the trust anchor written by one won't match the
> other. Switching install methods after first-boot triggers the
> manual re-trust path (delete `~/.agentsso/keystore/codesign-trust-anchor.req`
> and re-launch from a TTY-attached session). Stick with one install
> method per host to avoid this friction.

### Uninstalling

```sh
brew uninstall agentsso
brew untap permitlayer/tap    # optional
```

`brew uninstall` removes the binary and the brew receipt. It does
NOT touch `~/.agentsso/` (vault, credentials, audit log) or your
OS keychain entry. To wipe those after `brew uninstall`, run:

```sh
agentsso uninstall --keep-binary --yes
```

Or, if you've already run `brew uninstall` and the binary is gone,
clean up manually:

```sh
# Remove the OS keychain master-key entry
security delete-generic-password -s io.permitlayer.master-key

# Remove user data (vault, audit log, policies, agent registrations)
rm -rf ~/.agentsso
```

See the [Uninstall section below](#uninstall--clean-removal) for the
full cross-platform reference.

## macOS / Linux — curl | sh

The `install/install.sh` one-liner is the non-Homebrew path. It
downloads the latest signed tarball from GitHub Releases, verifies
the ed25519 signature via minisign, and drops the binary at
`/usr/local/bin/agentsso`.

```sh
curl -fsSL https://raw.githubusercontent.com/permitlayer/permitlayer/main/install/install.sh | sh
```

Pin to a specific version:

```sh
curl -fsSL https://raw.githubusercontent.com/permitlayer/permitlayer/main/install/install.sh | sh -s -- --version 0.2.0
```

See `install/install.sh` for the full flag set.

## Windows — PowerShell

The `install/install.ps1` script is the Windows equivalent of `install.sh`.
Requires Windows 10 v2004 or later (PowerShell 5.1+; PowerShell 7+ also
supported and recommended).

```powershell
iwr https://raw.githubusercontent.com/permitlayer/permitlayer/main/install/install.ps1 -UseBasicParsing | iex
```

This downloads the architecture-matched zip from GitHub Releases, verifies
its sha256 sidecar (the `.zip.sha256` file dist 0.31 publishes alongside
each release artifact), extracts `agentsso.exe`, and copies it to:

- **Default:** `%LOCALAPPDATA%\Programs\agentsso\agentsso.exe`
- **Override:** set `$env:AGENTSSO_INSTALL_DIR` before running

The script also prepends the install dir to your user `PATH` (registry
`HKCU\Environment\Path`, `REG_EXPAND_SZ`) and broadcasts `WM_SETTINGCHANGE`
so newly-spawned terminals see the new PATH without logout.

### With opt-in autostart

Pass `-Autostart` to also drop a `.lnk` shortcut into your Startup folder
(`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\agentsso.lnk`) so
the daemon launches at login. The shortcut runs `agentsso.exe start`.

```powershell
& ([scriptblock]::Create((iwr https://raw.githubusercontent.com/permitlayer/permitlayer/main/install/install.ps1 -UseBasicParsing).Content)) -Autostart
```

(The `& ([scriptblock]::Create(...))` invocation is the canonical PowerShell
idiom for piping flags through `iex` — `iex` itself can't accept positional
arguments, so we wrap the script body in a scriptblock and invoke it with
the flag.)

### Other flags

```powershell
# Pin to a specific version
$env:AGENTSSO_VERSION = '0.3.0'
iwr https://raw.githubusercontent.com/permitlayer/permitlayer/main/install/install.ps1 -UseBasicParsing | iex

# Skip PATH mutation
& ([scriptblock]::Create((iwr ...).Content)) -NoModifyPath
```

### Code signing — currently NOT done

`agentsso.exe` and `install.ps1` are **not** Authenticode-signed. Trust chain
is HTTPS to GitHub Releases plus the sha256 sidecar that `install.ps1`
verifies. If you want to verify the binary out-of-band:

```powershell
# Replace <VERSION> with the actual release version (e.g. 0.3.0).
$VERSION = '0.3.0'
$expected = (iwr "https://github.com/permitlayer/permitlayer/releases/download/v$VERSION/permitlayer-daemon-x86_64-pc-windows-msvc.zip.sha256" -UseBasicParsing).Content.Trim().Split()[0]
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath path\to\downloaded.zip).Hash.ToLowerInvariant()
$expected -eq $actual
```

You will see a Microsoft Defender SmartScreen warning the first few times
you run `agentsso.exe`. This is expected for unsigned binaries — SmartScreen
builds reputation per-binary based on download volume. Click "More info" →
"Run anyway" to proceed. Authenticode signing (which removes the SmartScreen
warning) requires an EV code-signing certificate (~$400-700/year, HSM-backed
per the 2023 CA/Browser Forum baseline). It is on the roadmap for Story 7.7
or post-MVP funding; until then, sha256 verification is the supported trust
mechanism.

### Autostart — managed by `agentsso autostart`

The `-Autostart` flag's Startup-folder `.lnk` is the install-time minimum.
For permanent autostart with retry-on-failure semantics, use:

```powershell
agentsso autostart enable    # registers a Task Scheduler entry
agentsso autostart status    # show current state + which mechanism
agentsso autostart disable   # remove autostart entirely
```

`agentsso autostart enable` automatically detects an existing
`-Autostart` shortcut from `install.ps1` and migrates it to Task
Scheduler in one step (no need to delete the `.lnk` first). Task
Scheduler is preferred over the Startup-folder shortcut because it:

- Restarts automatically on crash (`<RestartOnFailure>` configured —
  Startup-folder `.lnk` does not).
- Does NOT silently die after 72 hours (the OS default — overridden to
  `<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>`).
- Does NOT stop when you undock a laptop (battery defaults overridden).

If you ever want to remove autostart manually instead of via the CLI:

```powershell
schtasks /Delete /TN "AgentSSO Daemon" /F
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\agentsso.lnk" -ErrorAction SilentlyContinue
```

### Uninstall

```powershell
agentsso uninstall
```

Same flow as macOS / Linux — see the [Uninstall section
below](#uninstall--clean-removal) for the full reference, including
the `--keep-data`, `--keep-binary`, and `--yes` flags.

## Build from source

Requires Rust (toolchain version pinned in `rust-toolchain.toml`).

```sh
git clone https://github.com/permitlayer/permitlayer.git
cd permitlayer
./scripts/bootstrap.sh   # installs toolchain + nextest + lld
cargo build --release -p permitlayer-daemon
cp target/release/agentsso /usr/local/bin/agentsso
```

## Verifying your download

Every release artifact ships with a `.minisig` sibling signed by an
ed25519 key embedded in `install/install.sh` and `install/install.ps1`.
The install scripts verify it automatically on every install — there
is no manual step you need to take in the curl-pipe-sh / iwr-iex flow.
If you downloaded the tarball or zip directly from the GitHub Release
page and want to verify it by hand:

```sh
# Fetch the embedded public key from the install script (one-time):
curl -sSL https://github.com/permitlayer/permitlayer/raw/main/install/install.sh \
  | sed -n 's/^PUBKEY="\([^"]*\)"/\1/p' > permitlayer.pub

# Verify the download:
minisign -Vm agentsso-<version>-<target>.tar.xz -p permitlayer.pub
```

permitlayer does not currently ship platform-native signatures
(Apple Developer ID + notarization, GPG, Authenticode) — these are
the trust paths each OS's GUI ecosystem expects, but they require
paid certificate provisioning out of scope for the current release.
Until that lands, minisign is the supported integrity guarantee, plus
the sha256 sums GitHub publishes alongside every Release. macOS users
who download the tarball directly will see a Gatekeeper "unidentified
developer" warning; right-click → Open works around it, or install
via Homebrew (no warning). Windows users who download the zip
directly will see a SmartScreen warning; click **More info** →
**Run anyway**, or use the `install.ps1` flow which verifies via
sha256 + minisign.

## Autostart — `agentsso autostart enable`

permitlayer ships a single autostart path: `agentsso autostart enable`,
which writes a per-user LaunchAgent and bootstraps it into launchd's
`user/$UID` domain (Story 7.16 fix; Apple's headless-friendly target
that works over SSH on macOS 13+).

| Path | Label | Enabled by | Managed by |
|------|-------|-----------|-----------|
| permitlayer autostart | `dev.agentsso.daemon` | `agentsso autostart enable` | `agentsso autostart ...` |

> **Story 7.16 dropped the legacy `brew services` path.** Earlier docs
> described two autostart mechanisms (the Homebrew-managed
> `homebrew.mxcl.agentsso` plist, and our own
> `dev.agentsso.daemon` plist). The Homebrew path was structurally
> broken over SSH on macOS 13+ — Homebrew internally calls
> `launchctl enable gui/$UID/homebrew.mxcl.agentsso`, but the
> `gui/$UID` domain doesn't exist for SSH-only sessions, so the
> command returns exit 125 ("Domain does not support specified
> action"). `agentsso autostart enable` (Story 7.16) targets
> `user/$UID` instead, which is bootstrapped by any session.
> Existing rc.≤15 users with brew-services active are migrated
> automatically on first `agentsso autostart enable` (the brew plist
> is renamed to `*.bak.<timestamp>` rather than deleted).

### Migrating from rc.≤15 brew-services autostart

If you originally installed permitlayer at rc.≤15 and ran
`brew services start agentsso`, your `~/Library/LaunchAgents/`
contains a `homebrew.mxcl.agentsso.plist`. After `brew upgrade
agentsso` to rc.16+, your next `agentsso autostart enable` will:

1. Detect the brew plist (validates `<Label>` + `<ProgramArguments>[0]`
   reference our binary; refuses if hand-rolled).
2. Run `brew services stop agentsso` (best-effort).
3. Run `launchctl bootout gui/$UID/homebrew.mxcl.agentsso` (tolerating
   exit 125 for the SSH case).
4. Rename the plist to `*.bak.<RFC3339-timestamp>` (NOT delete —
   recoverable if mis-detected).
5. Bootstrap the new `dev.agentsso.daemon` plist into `user/$UID`.

You'll see one informational stderr line: `migrated from
brew-services autostart to user-domain LaunchAgent (brew plist
backed up to <path>)`.

> **Important:** the migration runs on `agentsso autostart enable`,
> not on `brew upgrade` or `agentsso connect`. If you upgrade from
> rc.≤15 and run `agentsso connect <service>` (or any other command)
> as your first post-upgrade action, the brew plist remains in place
> and Homebrew may re-launch a stale binary at next login. Run
> `agentsso autostart enable` (or `agentsso autostart status` first
> to inspect the conflict) before relying on autostart after an
> rc.≤15 → rc.16 upgrade.

### Conflict case: manual `agentsso start` + `agentsso autostart enable`

If you've manually run `agentsso start` in a terminal and then enable
autostart, the autostart-enrolled daemon detects the conflict via its
PID-file check and exits with code 3 (a deliberate "won't start,
can't take over" signal). The autostart plist won't respawn-loop;
the launchd job records a single error and stops.

**Recovery:**

```sh
agentsso status               # confirm the manual instance is running
agentsso stop                 # graceful SIGTERM, blocks <10s
agentsso autostart enable     # re-enroll cleanly
launchctl print user/$(id -u)/dev.agentsso.daemon | head -10
```

## Autostart on Linux

`agentsso autostart enable` writes a per-user systemd unit at
`~/.config/systemd/user/agentsso.service` and runs
`systemctl --user enable --now agentsso.service`. No `sudo` required.

```sh
agentsso autostart enable    # systemd-user unit + enable + start
agentsso autostart status    # current state
agentsso autostart disable   # stop + disable + remove unit file
journalctl --user -u agentsso -f   # tail daemon logs
```

**Linger note.** By default, user-systemd sessions exit at logout — so
the daemon stops at logout and starts again at next login. This matches
macOS LaunchAgent semantics. If you want the daemon to keep running
even when no user is logged in (e.g., on a headless workstation), enable
linger separately:

```sh
sudo loginctl enable-linger $USER
```

This is a one-time setup, not part of `agentsso autostart enable` (it
requires `sudo`, which the autostart command deliberately avoids).

**WSL note.** WSL1 doesn't have systemd at all. WSL2 has it only when
`[boot]\nsystemd=true` is set in `/etc/wsl.conf` (default OFF on older
WSL2 setups). `agentsso autostart enable` will detect missing systemd
and emit a clean error rather than silently doing nothing.

## Autostart at-a-glance — all three platforms

| Platform | Mechanism | Artifact location |
|----------|-----------|-------------------|
| macOS | LaunchAgent | `~/Library/LaunchAgents/dev.agentsso.daemon.plist` |
| Linux | systemd-user | `~/.config/systemd/user/agentsso.service` |
| Windows | Task Scheduler | `AgentSSO Daemon` (registry) + `~/.agentsso/autostart/task-scheduler.xml` |

In all three cases:

- **OPT-IN** (off by default). The setup wizard asks; the default is NO.
- **No `sudo`/admin required** — uses per-user mechanisms only.
- **Restart-on-crash, NOT restart-on-clean-exit.** `agentsso stop` does
  not respawn-loop the daemon (lesson from Story 7.1's v0.2.1 hotfix).
- `agentsso autostart status` is the authoritative cross-platform check.

`agentsso connect <service>` (Story 7.13 verb; replaces the prior
`agentsso setup`) is the canonical onboarding command. It composes
credential sealing + policy update + agent rebind in one idempotent
command. Pass `--device-flow` (Story 7.17) for truly headless boxes
where no browser is reachable on the target.

## Device-flow OAuth client setup (scripted install — Story 7.17)

The default `--oauth-client ./client_secret.json` flow uses an OAuth
client of type **Desktop app**. The `--device-flow` path requires a
*different* OAuth client type — Google's **TV and Limited Input
Device** type — because the device-flow grant is registered server-
side per client. Reusing a Desktop-app client with `--device-flow`
causes Google to return `invalid_grant` mid-polling, which permitlayer
surfaces as `device_flow_protocol`.

You only need this if you're scripting `agentsso connect` on a box
without a browser (CI runners, cloud-init provisioning,
fully-headless servers). Scenarios #1 (interactive) and #2
(SSH + `--headless`) keep using the existing Desktop-app client.

### Create the device-flow OAuth client

1. Open [Google Cloud Console → APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials).
2. Click **Create Credentials → OAuth client ID**.
3. **Application type:** select **TV and Limited Input Device** (NOT
   "Desktop app" — that's the type the existing client uses).
4. Give the client a name like `permitlayer-device-flow`.
5. Click **Create**, then **Download JSON**. Save the file as
   `client_secret_device.json` (the name is convention; only the path
   matters to the CLI).

The downloaded JSON has the same `{"installed": {...}}` wrapper as
the Desktop-app client; the JSON shape does not by itself distinguish
device-flow from loopback clients. The distinction is server-side
metadata Google associates with the client ID.

### Run the scripted-install scenario

```sh
agentsso connect gmail \
  --oauth-client ./client_secret_device.json \
  --agent ci-bot \
  --device-flow \
  --device-flow-timeout 300 \
  --non-interactive

AGENTSSO_BEARER_TOKEN=$(agentsso agent register ci-bot --policy default --json | jq -r .bearer_token)

agentsso autostart enable
```

What each flag does:

- `--device-flow` — switches the OAuth dispatch from loopback /
  paste-redirect to RFC 8628 device flow. Mutually exclusive with
  `--headless`.
- `--device-flow-timeout 300` — bound the operator's local wait at
  300 seconds. Hard ceiling at Google's `expires_in` (typically
  1800s). Without this flag the default is 120s.
- `--non-interactive` — skip all prompts. Compatible with
  `--device-flow` (the canonical scripted-headless invocation).
- `agent register --json` — emit the bearer-token response as compact
  single-line JSON to stdout for safe `jq -r` capture (no human-
  formatted text to parse with `awk`).
- `--token-out <path>` — alternative to `--json` when you want only
  the token bytes written to a 0o600 file (no stdout pollution at
  all).

> **Tip:** put `client_secret_device.json` in your CI's secrets store
> rather than checking it in. The JSON contains the client secret;
> exposure lets a third party impersonate your OAuth application
> (though not your users — they still have to consent).

### What happens at run time

1. The CLI POSTs to Google's `/device/code` endpoint and prints a
   verification URL + short user code on stdout.
2. The operator opens the URL on any device with a browser (laptop,
   phone, kiosk), enters the user code, and approves consent.
3. Meanwhile the target box is polling `/token` once every 5
   seconds (RFC 8628). When Google records consent, `/token`
   returns 200 with `access_token`, and `agentsso connect` continues
   into Phase 4 (seal + store) exactly like the loopback flow.

If the operator never approves, the polling loop terminates at
`--device-flow-timeout` with a structured `device_flow_timeout` error
on stderr and exit code 3.

## Uninstall — clean removal

`agentsso uninstall` is a single-command teardown for the binary, the
OS keychain master-key entry, the autostart artifact, and (optionally)
the data directory at `~/.agentsso/`. It is **destructive by design**
but **fail-soft per step** — a half-uninstall is worse than an
uninstall-with-warnings, so each step warn-and-continues if it can't
complete.

### Default (full removal)

```sh
agentsso uninstall
```

Prompts:

```
This will remove:
  • the agentsso binary at /usr/local/bin/agentsso
  • /Users/maya/.agentsso/ (vault, audit log, policies, agent registrations)
  • the OS keychain master-key entry (io.permitlayer.master-key / master)
  • autostart at login (launchd, if enabled)

Continue? [y/N]
```

Default answer is `n`. Press `y` + Enter to proceed. The teardown
runs in this order:

1. Stop the daemon (read PID file, SIGTERM, wait ≤10s).
2. Disable autostart (idempotent — no-op if not enabled).
3. Delete the OS keychain master-key entry.
4. Remove `~/.agentsso/`.
5. Remove the binary.

The binary is last so you can re-run `agentsso uninstall` if any
earlier step warned.

### Flags

| Flag | Effect |
|------|--------|
| `--yes` | Skip the confirmation prompt. **Required** in non-tty contexts (CI, scripts, pipes) — uninstall refuses to silently proceed in scripts. |
| `--keep-data` | Preserve `vault/`, `audit/`, `policies/`, `agents/`, `scrub-rules/`, `plugins/`, `crashes/`, `logs/`. Still wipes `keystore/` + `agentsso.pid` (the passphrase verifier and stale PID become garbage once the master key is deleted). |
| `--keep-binary` | Leave the agentsso binary on disk. Auto-applied for Homebrew-managed binaries (see below). |
| `--non-interactive` | Treat as scripted invocation; implies `--yes` is required. |

### Homebrew (and other package-manager) installs

`agentsso uninstall` deliberately **refuses** to delete a
Homebrew-managed binary — Homebrew owns the receipt and the
`brew-services` plist, so removing the binary out from under brew
would leave inconsistent state. The command detects:

- A `Cellar/agentsso/<version>/` segment in `current_exe()` (Apple
  Silicon: `/opt/homebrew/Cellar/...`; Intel: `/usr/local/Cellar/...`).
- An `INSTALL_RECEIPT.json` in any ancestor directory.
- `dpkg -S` or `rpm -qf` reporting package ownership on Linux.

When detected, the binary step prints a warn-and-skip line pointing
at the package manager's uninstall command. Use:

```sh
# macOS — Homebrew install:
agentsso uninstall --keep-binary --yes   # cleans keychain + autostart + data
brew uninstall agentsso                  # cleans the binary + brew receipt
```

If `brew services` is currently managing the daemon at uninstall
time (legacy rc.≤15 install path; see Story 7.16 callout above),
`agentsso uninstall` refuses up front (exit code 3) with a
remediation pointing you at:

```sh
brew services stop agentsso
agentsso uninstall
```

This avoids leaving Homebrew's plist respawning the daemon at every
login until you `brew uninstall agentsso`. (rc.16+ users won't hit
this — the new formula doesn't ship a `service do` block, so brew
never registers a launchd plist. The migration on first
`agentsso autostart enable` cleans up any leftover.)

### Re-install after uninstall

```sh
agentsso uninstall --yes
curl -fsSL https://raw.githubusercontent.com/permitlayer/permitlayer/main/install/install.sh | sh
agentsso connect gmail --oauth-client ./client_secret.json --agent <name>
```

A clean uninstall guarantees the next install mints a fresh master
key, creates a new vault, and hits no "passphrase verifier mismatch"
or "vault dir exists with stale meta" errors.

### Manual cleanup (when `agentsso uninstall` is unavailable)

If you've lost the binary before running uninstall (e.g., you deleted
it manually first), here's the per-platform manual sequence:

**macOS / Linux:**

```sh
# 1. Stop any running daemon
pkill -TERM agentsso

# 2. Remove the OS keychain entry
security delete-generic-password -s io.permitlayer.master-key  # macOS
secret-tool clear service io.permitlayer.master-key            # Linux

# 3. Remove autostart artifacts
launchctl bootout gui/$(id -u)/dev.agentsso.daemon
rm -f ~/Library/LaunchAgents/dev.agentsso.daemon.plist
systemctl --user disable --now agentsso.service
rm -f ~/.config/systemd/user/agentsso.service

# 4. Remove user data
rm -rf ~/.agentsso

# 5. Remove the binary
rm -f /usr/local/bin/agentsso
```

**Windows:**

```powershell
# 1. Stop the daemon
Get-Process agentsso -ErrorAction SilentlyContinue | Stop-Process

# 2. Remove the Credential Manager entry
cmdkey /delete:io.permitlayer.master-key

# 3. Remove autostart
schtasks /Delete /TN "AgentSSO Daemon" /F
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\agentsso.lnk" -ErrorAction SilentlyContinue

# 4. Remove user data + binary
Remove-Item "$env:APPDATA\agentsso" -Recurse -ErrorAction SilentlyContinue
Remove-Item "$env:LOCALAPPDATA\Programs\agentsso" -Recurse -ErrorAction SilentlyContinue

# 5. Remove from user PATH manually: System Properties → Environment
#    Variables → User → Path, delete the agentsso entry.
```

## Update — staying current

`agentsso update` checks for and applies new releases without
disturbing your vault, audit log, policies, agent registrations, or
the OS-keychain master key. State preservation is the entire point —
upgrading should never cost you a re-OAuth-consent or a wiped audit
trail.

### Check what's available (no changes)

```sh
agentsso update
```

Queries the GitHub Releases API for the latest stable release and
prints a version-delta summary:

```
→ update available  ✓ 0.3.0 → 0.4.0
    Release v0.4.0
    published: 2026-04-26T12:00:00Z

    ## What's new
    - Fixed credential refresh edge case
    - Added Drive scope filtering

→ run 'agentsso update --apply' to install
```

If you're already current, you'll see `✓ already on the latest
release`. The check-only path makes no filesystem changes.

### Apply the update in place

```sh
agentsso update --apply           # interactive — prompts for confirmation
agentsso update --apply --yes     # non-interactive (CI / scripts)
```

Sequence:

1. Re-runs the version check.
2. Validates free disk space (~4× the download size, for staging +
   backup + slack).
3. Prompts for confirmation (skipped on `--yes`).
4. Downloads the platform-correct release archive + minisign
   signature.
5. **Verifies the signature** against the embedded ed25519 public
   key (`install/permitlayer.pub` — the same key the curl|sh and
   PowerShell installers use). Refuses to apply on signature
   mismatch.
6. Extracts the archive into a tempdir, with path-traversal
   hardening (no `..`, no absolute paths).
7. Stages the new binary at `<install_dir>/agentsso.new`.
8. Stops the running daemon (graceful SIGTERM, ≤10s wait).
9. Atomic-renames `agentsso` → `agentsso.old` then `agentsso.new`
   → `agentsso`.
10. Runs any pending schema migrations.
11. Re-writes the autostart artifact if the binary path drifted.
12. Restarts the daemon and waits up to 30s for it to come up.
13. Cleans up `agentsso.old`.

State preservation is byte-exact: `~/.agentsso/{vault, audit,
policies, agents, scrub-rules, plugins}` and the OS-keychain master
key are never touched.

### What gets preserved across updates

- `~/.agentsso/vault/` — sealed credentials
- `~/.agentsso/audit/` — append-only JSONL audit log
- `~/.agentsso/policies/` — agent policy TOML files
- `~/.agentsso/agents/` — registered agent identities
- `~/.agentsso/scrub-rules/` — custom scrub rules
- `~/.agentsso/plugins/` — third-party connector plugins
- `~/.agentsso/keystore/` — passphrase verifier (when applicable)
- The OS keychain master-key entry (`io.permitlayer.master-key`)
- The autostart artifact at login (artifact path is auto-corrected
  if the binary moved)

### v0.4 vault-format migration

v0.4 introduces a vault-format upgrade. Running `agentsso update
--apply` on a v0.3 install will atomically migrate the vault to
the new format and create a backup at
`~/.agentsso/vault.pre-v2-backup/` that is **removed on success**.
If the migration fails, the backup is preserved and the update rolls
back; you can recover by `mv ~/.agentsso/vault.pre-v2-backup
~/.agentsso/vault` after investigating the failure.

The new format adds a per-envelope `key_id` byte that future
rotate-key versions use to track which master key sealed each
credential. v0.3 binaries cannot read v0.4 envelopes — this is a
forward-only migration. Reversibility is via binary rollback +
manual backup restore (the same posture as the broader update
framework's "binary rollback, not data rollback" stance).

### Rollback on failure

If anything between staging and post-restart-verification fails —
download error, signature mismatch, archive validation, swap
failure, migration error, daemon-won't-restart — the update flow
restores the previous binary by atomic-rename inverse and
re-spawns the daemon on the old version. You'll see a structured
error block + an `update-rolled-back` audit event with the failure
step and reason.

### Homebrew install — refused with redirect

If you installed via `brew install permitlayer/tap/agentsso`,
`agentsso update --apply` refuses with exit code 3 and points you
at Homebrew's upgrade flow:

```
error: agentsso at /opt/homebrew/Cellar/agentsso/0.3.0/bin/agentsso
       is managed by brew; use that package manager's upgrade command

  remediation: brew upgrade agentsso
```

The bare `agentsso update` (check-only) still works on a Homebrew
install — useful for spotting "is there a new release?" without
leaving the terminal.

### Linux distro packages — same posture

If a future release ships as a `.deb` or `.rpm` and the running
binary is at `/usr/bin/agentsso` with `dpkg -S` or `rpm -qf`
returning a package owner, `--apply` refuses with the
`apt upgrade agentsso` or `dnf upgrade agentsso` remediation.
(MVP only ships curl|sh + brew + PowerShell installers; this is
a forward-compat guard.)

### Brew-services running (legacy — Story 7.16 supersedes)

> **Story 7.16:** rc.16+ formulas no longer ship a `service do` block,
> so a fresh install will never reach this state. Users upgrading
> from rc.≤15 with `brew services start agentsso` previously active
> will still see this until they run `agentsso autostart enable`
> (which migrates the brew plist to a `*.bak.<timestamp>` backup;
> see "Migrating from rc.≤15 brew-services autostart" above).

If `brew services list` shows agentsso as `started` or
`scheduled`, `--apply` refuses with exit code 3:

```
error: agentsso is being managed by `brew services`. Running
       `agentsso update --apply` under this state would conflict
       with Homebrew's plist.

  remediation: brew services stop agentsso && agentsso update --apply
       OR (rc.16+):
               agentsso autostart enable   # migrates the brew plist
               agentsso update --apply
```

Same refusal pattern as `agentsso uninstall` — a different
lifecycle owner is already in charge.

### Audit events

Every observable step emits an audit event you can review with
`agentsso audit`:

- `update-check-requested` — at the start of a check or apply.
- `update-check-result` — version delta + update_available flag.
- `update-apply-started` — confirmed apply, just before download.
- `update-signature-verified` — minisign keyid + algorithm.
- `update-migrations-checked` — `migrations_applied` count + ids.
- `update-completed` — successful end-state with elapsed_ms.
- `update-rolled-back` — failure step + reason if anything aborted.

### What's NOT in MVP

- **No daemon-side periodic check.** `agentsso update` is on-
  demand only at MVP. A future story adds an opt-in
  `agentsso update --enable-auto` that checks daily and prints a
  "you have an update available" line on `agentsso status`.
- **No `--allow-unsigned`.** The bootstrap installer has
  `--allow-unsigned` for one-shot edge cases; an in-place update
  has no equivalent excuse — refuse-and-stop is the only path.
- **No automatic apply.** Even with the future opt-in periodic
  check, applying still requires a manual `agentsso update --apply`.

## Rotate the master key — `agentsso rotate-key`

`agentsso rotate-key` mints a fresh 32-byte master encryption key,
re-encrypts every credential in your vault under the new key, and
replaces the old master key in your OS keychain. Your Google
connections survive — refresh tokens are preserved, no re-OAuth-
consent needed.

### When to run it

Run rotate-key when you suspect your master key may be compromised:
a stolen device backup, a suspicious filesystem-restore from
untrusted media, or a security-baseline policy that mandates
periodic rotation.

If you don't have a specific reason to rotate, **don't**. The OS
keychain protects the master key with hardware-backed encryption on
modern macOS (Secure Enclave on Apple Silicon) and Windows
(DPAPI / TPM-backed); periodic rotation without a triggering event
adds risk (an interrupted rotation can leave the vault in a
transient state that requires `agentsso rotate-key` to be re-run)
without security gain.

### Stop the daemon first

```sh
agentsso stop
agentsso rotate-key --yes
```

`rotate-key` refuses to run while the daemon is up — the daemon
holds an in-memory copy of the OLD master key, and rotating around
it would desync the daemon's view of authentication state. The
refusal is fast and produces a clean structured error pointing you
at `agentsso stop`.

### Confirmation prompt

By default, `rotate-key` prints a manifest and waits for `y/N`:

```text
This will rotate the agentsso master encryption key:

  • Mint a fresh 32-byte master key from your OS RNG
  • Re-encrypt every credential in ~/.agentsso/vault/ under the new key
  • Replace the old master key in your OS keychain (idempotent overwrite)
  • Rebuild every agent's HMAC lookup key under the new master-derived
    subkey AND issue a fresh agt_v2_* bearer token for each agent
    (operator must update agent configs with the printed tokens —
    old tokens are invalidated)

Existing OAuth refresh tokens are preserved.

If the rotation is interrupted, re-run `agentsso rotate-key` to
finish; the keystore stages both keys atomically before any vault
write begins, so every crash mode is recoverable.

Continue? [y/N]
```

Pass `--yes` to skip the prompt (required from CI / non-tty
contexts):

```sh
agentsso rotate-key --yes
```

### What gets invalidated

- ✅ **OAuth refresh tokens are preserved.** Your Google
  connections (`gmail`, `calendar`, `drive`) keep working without
  re-consent.
- ✅ **Agent registrations are preserved.** Every agent registered
  via `agentsso agent register <name>` keeps its name, policy
  binding, and `created_at` timestamp.
- ⚠️ **Agent bearer tokens are replaced.** Rotation re-issues a
  fresh `agt_v2_<name>_<random>` bearer token for every registered
  agent and writes them to a mode-`0600` file at
  `~/.agentsso/rotate-key-output.<pid>`. The operator reads that
  file, updates each agent's configuration with the new token, then
  removes the file by hand. The old tokens stop authenticating
  immediately.

  **Plaintext bearer tokens are NEVER printed to stdout.** Terminal
  scrollback, multiplexer scrollback (tmux/screen), shell history,
  process accounting, screen recording, screen sharing, and CI log
  capture are all out of `agentsso`'s control — the file-with-`0600`
  is the only plaintext-bearing surface, by design.

Sample post-rotation output:

```text
✓ master key rotated → 1f7c4e9b… → 94be5108… (3 entries, 2 agents rerolled, 412ms)

New agent tokens written to:
  /Users/you/.agentsso/rotate-key-output.91234

Read the file (mode 0600), update your agent configs, then `rm` it.
The previous agt_v1_*/agt_v2_* tokens are now invalid.
```

The file content is one `<agent_name>=<token>` per line plus a
header comment, e.g.:

```text
# rotate-key new agent tokens — keep secret, mode 0600
# Format: <agent_name>=<token>
email-triage=agt_v2_email-triage_AbCdEf123…
calendar-bot=agt_v2_calendar-bot_GhIjKl456…
```

### Token format change in v0.4

Story 7.6b switched the bearer-token format from `agt_v1_<random>`
to `agt_v2_<name>_<random>`. Old `agt_v1_*` tokens stop working at
the first daemon restart after upgrade — the auth path uses the
agent name encoded in the v2 prefix to look up the agent in O(1)
regardless of registry size.

Why the change: the v1 path required a global Argon2id sweep at
auth time as the registry grew (~100ms per registered agent per
auth). The v2 format encodes the agent name in the token prefix so
auth can compute a single HMAC against the agent's `lookup_key_hex`
index and verify in O(1). For operators with 1–5 agents the v1
latency was tolerable, but v2 future-proofs the auth path for any
registry size.

Operator-visible cost: existing v1 tokens stop authenticating after
upgrade. There are two ways to mint fresh v2 tokens:

1. **Run `agentsso rotate-key`.** Phase E re-issues every agent's
   bearer token under the new master-derived subkey. Single command,
   covers every registered agent at once. Recommended.
2. **Re-register each agent individually.** For each `agentsso agent
   register <name>` invocation, the daemon issues a fresh v2 token
   on the existing master key. Useful if you're not also rotating
   the master key.

There is no automatic migration — v1 → v2 is a hard cut at deploy
time, motivated by the small pre-1.0 user base. Rotation OR
re-register is required for each agent before its requests will
authenticate again.

### Passphrase-mode users

If you're running on Linux without a usable libsecret backend (or
forced into passphrase mode via `--keystore-fallback=passphrase`),
`agentsso rotate-key` refuses with:

```text
error: rotate_key_passphrase_adapter
  the passphrase keystore rotates by changing the passphrase, not by
  minting a new master key. A dedicated `agentsso change-passphrase`
  command will be added in a future story; for now, the passphrase-
  mode rotation path is unavailable.
  remediation: (future) agentsso change-passphrase — not yet implemented
```

Passphrase rotation lands in a future story.

### Crash recovery — `rotate-key` is crash-safe by construction

Story 7.6b's rotation is a single forward pass under the vault
advisory lock with a transient previous-master-key keystore slot
AND a small marker file at `~/.agentsso/vault/.rotation-state`
(mode `0600`, TOML, ~6 lines) that records the in-flight phase.
Every crash mid-rotation falls into one of three buckets defined
by the marker's `keystore_phase`:

- **`pre-previous`** or **`pre-primary`** — the new master key was
  generated in the crashed process's RAM but never made it to disk.
  Recovery is "abandon the rotation and start fresh": run
  `agentsso keystore-clear-previous` to clear the keystore's
  previous-key slot AND remove the marker file, then re-run
  `agentsso rotate-key`.
- **`committed`** — both keystore slots are staged and verified.
  Recovery is "re-run `agentsso rotate-key`" — the resume path
  picks up Phase D / E / F from where the previous attempt
  stopped and converges idempotently.

Re-run `agentsso rotate-key` after the crash. The command reads
the marker file FIRST (it is the authoritative record of in-flight
state), then verifies the keystore matches what the marker claims,
and resumes from the correct phase: it walks the vault, re-encrypts
any envelope still keyed by the OLD master key, completes the agent
rebuild, and clears the previous-key slot to finalize. Vault
backups are NOT required for rotation safety.

If you also try to start the daemon while a rotation is incomplete,
`agentsso start` refuses to boot with exit code 6 and a structured
"vault rotation incomplete" banner. Re-run rotate-key to fix the
state, then `agentsso start` will succeed.

### Audit events

Every rotation emits a `master-key-rotated` audit event with:

- `old_keyid` — HMAC-SHA256 fingerprint of the old key (16 hex chars).
- `new_keyid` — same for the new key.
- `kdf` — `"HKDF-SHA256"` (the KDF used to derive the agent-token
  lookup subkey from the master key).
- `vault_reseal_count` — number of credentials re-encrypted.
- `agents_rerolled_count` — number of agents that received a fresh
  v2 bearer token.
- `elapsed_ms` — rotation duration.

Failures emit `master-key-rotation-failed` with `failure_phase`
(`A`–`F`), `failure_reason`, and `partial_state` (one of `clean`,
`both-keys-in-keystore`, `vault-mixed`, `vault-uniform-keystore-both`,
`agents-mid-rebuild`, `single-slot-clean`). Both event types live
under the `master-key-*` namespace; review them with `agentsso
audit | grep master-key-`.

### Exit codes

`agentsso rotate-key` exits with one of:

- **0** — rotation succeeded.
- **3** — resource conflict (daemon running, brew-services
  managing agentsso, vault lock held by another process).
- **4** — auth / keystore failure (passphrase adapter,
  `set_master_key` rejected, RNG failure, `key_id` overflow at 255).
- **5** — rotation failure during the forward pass (re-run
  `agentsso rotate-key` to resume — the previous-key slot stays
  populated through Phase F, and the rotation-state marker file at
  `~/.agentsso/vault/.rotation-state` records the in-flight phase).

Exit code **6** is emitted ONLY by `agentsso start`, not by
`agentsso rotate-key`: it indicates the daemon detected an in-flight
rotation (either via the marker file OR via mixed `key_id` values
in the vault) and refused to boot. Re-run `agentsso rotate-key` to
resume the rotation, or — if you intend to abandon a rotation that
crashed at `pre-previous` or `pre-primary` — run `agentsso
keystore-clear-previous` and remove the marker file before retrying.
