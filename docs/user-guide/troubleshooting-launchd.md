# launchd troubleshooting reference

This is a focused reference for one stubborn class of macOS launchd
failure that operators hit when wiring `agentsso` up — and when
wiring an MCP client such as the OpenClaw gateway alongside it:

```
Bootstrap failed: 5: Input/output error
```

The errno 5 is generic and the wording is misleading. This page
explains what it actually means, gives a copy-paste diagnostic
recipe that works for both the root daemon and per-user agents, and
calls out two specific traps.

For the cross-user provisioning flow itself, see the
[multi-user setup runbook](multi-user-setup.md). For single-machine
lifecycle issues, see the
[install guide's troubleshooting section](install.md#troubleshooting).

## What `Bootstrap failed: 5: Input/output error` actually means

`launchctl bootstrap` reports `5: Input/output error` for a whole
**class** of conditions, not one specific I/O fault. The two that
matter in practice:

1. **The label is already loaded in the target domain.** `bootstrap`
   will not load a service that is already bootstrapped; it bails
   with errno 5 instead of a clear "already loaded" message.
2. **The label is `disabled` in the target domain.** A service that
   has been disabled with `launchctl disable` (or left disabled by a
   degraded `bootout`, see [below](#trap-openclaw-gateway-stop-leaves-the-service-disabled))
   cannot be bootstrapped until it is re-enabled. `bootstrap` again
   reports the same generic errno 5.

So `Bootstrap failed: 5` almost always means **"already loaded"** or
**"disabled"**, not a disk or hardware error.

### Use the correct domain

This error class hits two different kinds of jobs, and they live in
**different launchd domains**. Targeting the wrong domain produces
the same errno 5 (or a "service not found"), which sends people down
the wrong path.

| Job | Type | Domain target | Plist location |
|---|---|---|---|
| agentsso daemon | system LaunchDaemon | `system` / `system/dev.permitlayer.daemon` | `/Library/LaunchDaemons/dev.permitlayer.daemon.plist` |
| OpenClaw gateway | per-user LaunchAgent | `gui/$(id -u)` / `gui/$(id -u)/ai.openclaw.gateway` | `~/Library/LaunchAgents/ai.openclaw.gateway.plist` |

- The **agentsso daemon** (`dev.permitlayer.daemon`) is a
  system-domain LaunchDaemon. Operate on it with `sudo` and the
  `system/` domain: `system/dev.permitlayer.daemon`.
- A **per-user LaunchAgent** like the OpenClaw gateway
  (`ai.openclaw.gateway`) lives in the **per-user GUI domain**:
  `gui/$(id -u)/ai.openclaw.gateway`. Operate on it as the user,
  **without** `sudo`.

> **Do not "just re-run it as root" for a `gui/$UID` user agent.**
> The errno 5 wording tempts you to escalate with `sudo`, but `sudo
> launchctl bootstrap system ...` targets the *system* domain, which
> is the wrong domain for a per-user agent — that will never load the
> user's gateway and only adds confusion. For a per-user agent, stay
> in `gui/$(id -u)` as the logged-in user.

## Diagnostic recipe (reusable for any label)

Substitute `<domain>`, `<label>`, `<plist>`, and `<process>` per the
table above. For the agentsso daemon, prefix the `launchctl` commands
that touch `system/` with `sudo`; for a `gui/$UID` agent, run them as
the user without `sudo`.

### 1. Is it `disabled`?

```sh
launchctl print-disabled <domain> | grep <label>
```

A line ending `=> disabled` (or `=> true`) means the label is
disabled in that domain and `bootstrap` will fail errno 5 until it is
enabled.

### 2. Is it already loaded?

```sh
launchctl list | grep <label>
```

A matching line means the label is already bootstrapped in your
domain — `bootstrap` will fail errno 5 because it is already loaded.
(For the system daemon, use `sudo launchctl list | grep <label>`.)

### 3. Is a process actually running?

```sh
pgrep -fl <process>
```

This tells you whether the underlying process exists at all,
independent of what launchd's bookkeeping claims. A label can be
"loaded" with no live process (crashed, throttled) or a process can
linger after a degraded unload.

### 4. Remediate based on what you found

- **It is `disabled`** → enable it first, *then* bootstrap:

  ```sh
  launchctl enable <domain>/<label>
  launchctl bootstrap <domain> <plist>
  ```

- **It is stuck loaded** → bootout first, *then* bootstrap:

  ```sh
  launchctl bootout <domain>/<label>
  launchctl bootstrap <domain> <plist>
  ```

The ordering is the whole point:

- **`enable` takes a `<domain>/<label>` target; `bootstrap` takes a
  `<domain>` and a `<plist>` path.** Enable *before* bootstrap when
  the label is disabled.
- **Bootout *before* bootstrap when the label is loaded** — you
  cannot bootstrap over an already-loaded label.

`bootout` is asynchronous: it sends `SIGTERM` and returns before the
process is gone. If a subsequent `bootstrap` fails with errno 5 or
"service already loaded", the previous instance is still tearing
down. Poll until the label is unloaded before bootstrapping again:

```sh
# system daemon example — adjust domain/label for a gui/$UID agent
until ! sudo launchctl print system/dev.permitlayer.daemon >/dev/null 2>&1; do
  sleep 1
done
sudo launchctl bootstrap system /Library/LaunchDaemons/dev.permitlayer.daemon.plist
```

> **As of v1.2.2, `agentsso setup` and `agentsso doctor --fix` do this
> poll-until-released wait for you** before every `bootstrap`. The
> service-domain release lags the `bootout` exit proportional to the
> daemon's uptime, so on a long-uptime daemon the old code could fail
> the bootstrap (and its rollback) and leave the daemon down. The manual
> loop above is only needed when you are driving `launchctl` by hand —
> not when going through `setup`/`doctor`. (Upgrading *from* a pre-1.2.2
> binary runs the old code for that one hop, so a single first-upgrade
> failure can still occur; re-run `sudo agentsso setup --upgrade` and it
> succeeds.)

Worked example for the agentsso daemon (disabled case):

```sh
sudo launchctl print-disabled system | grep dev.permitlayer.daemon
sudo launchctl enable system/dev.permitlayer.daemon
sudo launchctl bootstrap system /Library/LaunchDaemons/dev.permitlayer.daemon.plist
```

Worked example for the OpenClaw gateway (per-user agent):

```sh
launchctl print-disabled "gui/$(id -u)" | grep ai.openclaw.gateway
launchctl enable "gui/$(id -u)/ai.openclaw.gateway"
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/ai.openclaw.gateway.plist
```

## Trap: `openclaw gateway stop` leaves the service `disabled`

`openclaw gateway stop` may fall back to a **degraded bootout**. When
it cannot stop the service the privileged way, it prints something
like:

```
Not privileged to stop service ... left service unloaded
```

and unloads the agent in a way that leaves the label **`disabled`**
in `gui/$UID`. The gateway is now both unloaded *and* disabled.

The trap: a subsequent plain `launchctl bootstrap "gui/$(id -u)"
~/Library/LaunchAgents/ai.openclaw.gateway.plist` then fails with
`Bootstrap failed: 5: Input/output error` — because the label is
disabled, not because anything is actually wrong with the plist or
the process. Re-running it harder, or with `sudo`, does not help (and
`sudo` targets the wrong domain — see
[Use the correct domain](#use-the-correct-domain)).

**Fix:** enable the label before bootstrapping it:

```sh
launchctl enable "gui/$(id -u)/ai.openclaw.gateway"
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/ai.openclaw.gateway.plist
```

This is OpenClaw-specific behavior, documented here because operators
wiring OpenClaw to agentsso routinely hit it while restarting the
gateway during setup.

## Cross-reference: a different daemon failure class

If the **agentsso daemon** will not bootstrap, errno 5 is not the
only thing to check. A bootstrap that succeeds but the daemon then
exits — or a bootstrap blocked for a permissions reason rather than a
load/disabled reason — is a **different failure class** with its own
remediation: a control-token / `UnsafeMode` boot failure.

Check the boot-failure log (root-readable, hence `sudo`):

```sh
sudo tail -n 100 /Library/Logs/permitlayer/daemon.log
```

Look for an `UnsafeMode` or `ControlTokenBootstrap` error. That is
**not** the launchd `Bootstrap failed: 5` class covered on this page
— it is a `control.token` file-permissions problem and has separate
remediation. See the
[install guide's troubleshooting section](install.md#troubleshooting)
for the daemon-stopped and master-key paths.

## `sudo agentsso setup` refused — what now?

`agentsso setup` is self-healing: it repairs the common refusal
conditions (a wedged LaunchDaemon, a stale binary, a broken version
symlink) itself rather than handing you commands to run. So most of the
manual `launchctl bootout`/`bootstrap` dance above is a fallback for
when you are *not* using `setup`. When `setup` does refuse, the message
tells you exactly what to do — and it will **never** tell you to
`sudo rm` a file. The refusals you may see:

- **`setup.requires_root`** — you ran `agentsso setup` without `sudo`.
  On an interactive terminal `setup` re-elevates itself; if it can't
  (or `AGENTSSO_NO_SUDO_ELEVATE=1` is set), re-run with `sudo`.
- **`setup.heal_needs_decision`** — a legacy operator policy shadows a
  shipped policy and `setup` is non-interactive (so it can't prompt).
  This is the only refusal that needs *your* decision. Re-run with the
  flag that matches your intent (both archive the shadow recoverably
  and then continue — neither asks you to delete anything):
  - `sudo agentsso setup --upgrade` — keep all your config, just move
    the daemon-crashing shadow aside. **This is the routine answer.**
  - `sudo agentsso setup --fresh-install` — archive the shadow **and**
    wipe operator state for a clean slate (destructive; deliberate
    resets only).
  The archived file lands in
  `/Library/Application Support/permitlayer/policies/.legacy-seed-snapshot-<timestamp>/`,
  recoverable for ~30 days. `agentsso doctor` reports any present
  snapshot; `sudo agentsso doctor --fix` garbage-collects snapshots
  older than 30 days.
- **`setup.versioned_binary_mismatch`** — a *different* binary of the
  same version is already staged (same version, different bytes —
  possible tamper, or a corrupted prior install). `setup` refuses to
  silently overwrite. Re-run with `--replace-binary` if you know it's
  a corrupted prior install; the message also shows a `codesign
  --verify` command to investigate first.
- **`setup.fresh_install_wipe_failed` / `setup.legacy_helper_unremovable`**
  — a path `setup` needed to clear is held by something else (a running
  process with it open, a locked/immutable file, or a permissions
  issue). The per-path error names the cause; resolve the holder, then
  re-run. `setup` already retried transient I/O before refusing.

If `setup` rolled back after a post-cutover failure
(`setup.rolled_back` / `setup.rollback_incomplete` /
`setup.failed_no_rollback`), the message states whether the prior
daemon was restored. Check `/Library/Logs/permitlayer/daemon.log`,
then re-run `sudo agentsso setup`. (As of v1.2.2 the most common cause
of `setup.rollback_incomplete` — the post-`bootout` bootstrap race on a
long-uptime daemon — is gated by a poll-until-released wait, so this
outcome should now be rare. If you do hit it, re-running `setup` clears
it.)

## See also

- [Cross-user / multi-machine setup runbook](multi-user-setup.md) —
  the provisioning sequence and the two access-problem false alarms.
- [Installing agentsso](install.md) — canonical lifecycle and
  per-symptom troubleshooting.
