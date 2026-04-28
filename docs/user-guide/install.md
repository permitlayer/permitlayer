# Install

permitlayer ships the `agentsso` binary for macOS (ARM64 and x86_64) and
Windows (x86_64). Linux lands in Story 7.7.

## macOS — Homebrew (recommended)

```sh
brew tap permitlayer/tap
brew install permitlayer/tap/agentsso
agentsso setup gmail
```

`brew install` downloads the architecture-matched tarball from
GitHub Releases, verifies its SHA256 digest (embedded in the
formula), and installs `agentsso` at:

- **Apple Silicon:** `/opt/homebrew/bin/agentsso`
- **Intel:** `/usr/local/bin/agentsso`

### Running as a Homebrew-managed service

Homebrew can register the daemon as a `launchd` user-service:

```sh
brew services start agentsso
```

This generates `~/Library/LaunchAgents/homebrew.mxcl.agentsso.plist`
and starts the daemon. The service restarts only on real crashes
(`keep_alive crashed: true` — signal-killed exits like SIGSEGV,
SIGABRT, OOM-kill) and survives logout/login. Deliberate non-zero
exits — e.g. `agentsso start`'s exit-3 when another instance is
already bound to the port — are NOT respawned, so a configuration
conflict with a manually-started daemon shows up as a single
`error 78` row in `brew services list` rather than a respawn loop.

Check status with `brew services list` or `agentsso status`.

To stop:

```sh
brew services stop agentsso
```

### Upgrading

```sh
brew upgrade agentsso
```

If the service is running, `brew` stops it, installs the new
binary, and you can restart with `brew services start agentsso`.

### Uninstalling

For a Homebrew install, `brew uninstall agentsso` is the canonical
path — it removes the binary, the brew receipt, and tears down the
brew-services plist if the service is running. `agentsso uninstall`
deliberately **refuses** when it detects `brew services` is managing
the daemon (it would otherwise leave Homebrew's plist respawning a
missing binary at every login).

```sh
brew services stop agentsso   # if the service is running
brew uninstall agentsso
brew untap permitlayer/tap    # optional
```

`brew uninstall` does NOT touch `~/.agentsso/` (vault, credentials,
audit log) or your OS keychain entry. To wipe those after `brew
uninstall`, run:

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

Every release artifact is signed two ways: a **platform-native**
signature your OS already trusts (Gatekeeper / GPG / Authenticode)
and a **cross-platform `minisign` sentinel** anyone can verify with
one tool regardless of OS. You don't have to verify by hand — the
install scripts and your OS's trust chain do it automatically — but
the option is there if you want defense-in-depth.

### macOS

Apple Gatekeeper validates the Developer ID signature + notarization
ticket the first time you run `agentsso`. No manual step required.
If you want to inspect the signature explicitly:

```sh
codesign -dv --verbose=4 $(which agentsso)
spctl --assess --type execute --verbose=4 $(which agentsso)
```

`spctl --assess` exits 0 if the binary is properly signed,
notarized, and stapled. A non-zero exit means Gatekeeper would
refuse the binary at first launch — re-download and report it.

### Linux

The `.tar.xz` release artifact ships with a `.asc` GPG signature
sibling. Verify it before extracting:

```sh
# Fetch the public key (one-time setup):
gpg --keyserver hkps://keys.openpgp.org --recv-keys <FINGERPRINT>

# Verify the download:
gpg --verify agentsso-<version>-x86_64-unknown-linux-gnu.tar.xz.asc \
             agentsso-<version>-x86_64-unknown-linux-gnu.tar.xz
```

The expected fingerprint is documented in `install/install.sh`'s
download step and on the GitHub release page.

### Windows

Authenticode validation happens at download time via SmartScreen
and at first run via Windows Defender. To inspect the signature
manually: right-click `agentsso.exe` → **Properties** → **Digital
Signatures** tab. The signer should be the permitlayer organization.

If your Authenticode cert is non-EV and recently issued, SmartScreen
may show "Windows protected your PC" until the cert builds reputation
(typically 3-6 months). Click **More info** → **Run anyway** if
you've independently verified the binary via `minisign`.

### Cross-platform — `minisign`

Every artifact ships with a `.minisig` sibling signed by the same
ed25519 key embedded in `install/install.sh:31` and
`install/install.ps1:67`. Verify on any OS:

```sh
# Fetch the embedded public key from the install script (one-time):
curl -sSL https://github.com/permitlayer/permitlayer/raw/main/install/install.sh \
  | grep -A1 'PERMITLAYER_PUBKEY=' \
  | tail -1 > permitlayer.pub

# Verify the download:
minisign -Vm agentsso-<version>-<target>.tar.xz -p permitlayer.pub
```

The OS-native signatures are the path your ecosystem expects;
`minisign` is the cross-platform belt-and-suspenders option.

## Autostart — two mechanisms, pick one

permitlayer offers two distinct autostart paths on macOS. They are
**mutually exclusive** — if you enable both, two daemons will try
to bind port 3820 and one will crash-loop.

| Path | Label | Enabled by | Managed by |
|------|-------|-----------|-----------|
| Homebrew service | `homebrew.mxcl.agentsso` | `brew services start agentsso` | `brew services ...` |
| Standalone autostart | `dev.agentsso.daemon` | `agentsso autostart enable` | `agentsso autostart ...` |

`brew services` is the right choice if you already use Homebrew
for lifecycle management of other services. The standalone path
(shipping in Story 7.3) works regardless of whether Homebrew is
installed.

If you switch mechanisms, disable the old one first:

```sh
# Switching from brew services → standalone:
brew services stop agentsso
agentsso autostart enable

# Switching from standalone → brew services:
agentsso autostart disable
brew services start agentsso
```

### Third collision case: manual `agentsso start` + `brew services start`

There's also a third way to collide that the table above doesn't cover:
running the daemon **manually in a terminal** (`agentsso start`) and then
trying to take it over with `brew services`.

**Symptom:** `brew services start agentsso` reports "Successfully started"
but `brew services list` shows the agentsso row in `error` state with exit
code 78. Nothing seems to work; `agentsso status` shows the daemon is
running but you can't manage it via brew.

**Why it happens:** The manual `agentsso` already has port 3820 bound. When
launchd tries to start a second instance via `brew services`, the daemon
detects the conflict via its PID-file check and exits with code 3 — a
deliberate "won't start, can't take over" signal. v0.2.1+ formulas
respect this and don't respawn-loop, but the launchd job still records
the error.

**Recovery:**

```sh
# Verify nothing is hung:
agentsso status                           # may show running

# Stop the manual instance:
agentsso stop                             # graceful SIGTERM, blocks <10s

# Now brew services can take over cleanly:
brew services start agentsso

# Always verify after a start:
brew services list | grep agentsso        # expect: started (not error)
```

**Diagnostic when in doubt:** the daemon's startup error message lands in
`/opt/homebrew/var/log/agentsso.log` (Apple Silicon) or
`/usr/local/var/log/agentsso.log` (Intel). `tail -n 20 <path>` after a
failed `brew services start` shows exactly which conflict was detected.

The general rule: **`brew services list | grep agentsso` is the
authoritative status check.** `brew services start`'s "Successfully
started" message means launchd accepted the request, not that the
daemon is actually running under brew's management. Verify after every
start.

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

The setup wizard (`agentsso setup` with no service argument) walks you
through both connecting a Google service AND deciding about autostart.
Per-service flows (`agentsso setup gmail|calendar|drive`) skip the
autostart prompt — they're for users scripting OAuth setup who don't
want a follow-up question.

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
time, `agentsso uninstall` refuses up front (exit code 3) with a
remediation pointing you at:

```sh
brew services stop agentsso
agentsso uninstall
```

This avoids leaving Homebrew's plist respawning the daemon at every
login until you `brew uninstall agentsso`.

### Re-install after uninstall

```sh
agentsso uninstall --yes
curl -fsSL https://raw.githubusercontent.com/permitlayer/permitlayer/main/install/install.sh | sh
agentsso setup gmail --oauth-client ./client_secret.json
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

### Brew-services running

If `brew services list` shows agentsso as `started` or
`scheduled`, `--apply` refuses with exit code 3:

```
error: agentsso is being managed by `brew services`. Running
       `agentsso update --apply` under this state would conflict
       with Homebrew's plist.

  remediation: brew services stop agentsso && agentsso update --apply
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
