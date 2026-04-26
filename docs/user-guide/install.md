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

```sh
brew services stop agentsso   # if the service is running
brew uninstall agentsso
brew untap permitlayer/tap    # optional
```

`brew uninstall` does NOT remove `~/.agentsso/` — your vault,
credentials, and audit log stay put. Remove them manually if you
want a full clean:

```sh
rm -rf ~/.agentsso
```

(This deletes encrypted credentials, the vault master key, and
audit history. Only do this if you intend to re-run
`agentsso setup gmail` from scratch.)

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

### Uninstall — Story 7.4 will own this

There is currently no `agentsso uninstall` command. To remove cleanly:

```powershell
# Stop the daemon (if running)
agentsso stop

# Remove the binary
Remove-Item "$env:LOCALAPPDATA\Programs\agentsso" -Recurse

# Remove autostart shortcut (if you used -Autostart)
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\agentsso.lnk" -ErrorAction SilentlyContinue

# Remove user data (vault, audit log, policies). This deletes encrypted
# credentials and the vault master key — only do this if you want a full
# clean re-install.
Remove-Item "$env:APPDATA\agentsso" -Recurse -ErrorAction SilentlyContinue

# Remove from user PATH (manual): open System Properties → Environment
# Variables → User → Path, and delete the agentsso entry.
```

Story 7.4 will replace all of the above with `agentsso uninstall`.

## Build from source

Requires Rust (toolchain version pinned in `rust-toolchain.toml`).

```sh
git clone https://github.com/permitlayer/permitlayer.git
cd permitlayer
./scripts/bootstrap.sh   # installs toolchain + nextest + lld
cargo build --release -p permitlayer-daemon
cp target/release/agentsso /usr/local/bin/agentsso
```

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
