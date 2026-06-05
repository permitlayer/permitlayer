# Installing agentsso

`agentsso` is the permitlayer daemon. On macOS it installs as a root
LaunchDaemon system service. End-users authenticate to it locally,
either over a Unix domain socket (control plane) or TCP loopback (MCP).

This guide is the canonical install reference. The
[README](../../README.md) quickstart points here for the full
lifecycle.

Two companion runbooks cover scenarios this guide does not:

- [Cross-user / multi-machine setup runbook](multi-user-setup.md) —
  provisioning across more than one OS user (the most common
  "it doesn't work" trap).
- [launchd troubleshooting reference](troubleshooting-launchd.md) —
  diagnosing `Bootstrap failed: 5: Input/output error` for the
  daemon or a per-user agent.

## Prerequisites

- macOS 13 (Ventura) or later. Apple Silicon and Intel both supported.
- [Homebrew](https://brew.sh/) installed. The Homebrew prefix
  (`/opt/homebrew` on Apple Silicon, `/usr/local` on Intel) is
  detected automatically.
- Administrator (`sudo`) access on the machine. The system-service
  install needs root once at setup time; routine use does not.
- A Google Cloud project with a Desktop OAuth client for each Google
  Workspace service you plan to connect (Gmail / Calendar / Drive).
  See [Creating an OAuth client](#creating-an-oauth-client) below.

Linux and Windows builds compile but ship a legacy per-user layout
under `~/.agentsso/` and are not yet supported end-to-end.

## Install

```sh
brew tap permitlayer/tap
brew install permitlayer/tap/agentsso
```

This places the `agentsso` binary at `/opt/homebrew/bin/agentsso` (or
`/usr/local/bin/agentsso` on Intel). The binary on its own does
nothing useful — the daemon needs to be installed as a system
service.

## Set up the system service

Run, once per machine:

```sh
sudo agentsso setup
```

`sudo agentsso setup` is the canonical install **and** upgrade verb. It
is idempotent: run it on a fresh machine to install, and run it again
after every `brew upgrade agentsso` to roll the new binary into place
and re-bootstrap the LaunchDaemon. It detects and repairs the common
refusal conditions itself (re-staging the privileged binary, re-pointing
the version symlink, re-bootstrapping a wedged LaunchDaemon) rather
than handing you a list of `launchctl` commands to run by hand.

What setup does:

1. Copies the binary to `/Library/PrivilegedHelperTools/agentsso`
   (root:wheel, mode 0755).
2. Writes `/Library/LaunchDaemons/dev.permitlayer.daemon.plist`
   (root:wheel, mode 0644).
3. Creates `/Library/Application Support/permitlayer/` for vault,
   agents, plugins, and audit logs (root:wheel, mode 0700).
4. Creates `/Library/Logs/permitlayer/` for daemon logs (root:wheel,
   mode 0750).
5. Creates `/var/run/permitlayer/` for the control-plane socket
   (root:wheel, mode 0755).
6. Creates the `permitlayer-clients` macOS group and adds the
   invoking operator to it (`dseditgroup`).
7. Provisions a master key in System.keychain with an `-A`
   (allow-all-applications) ACL so the key survives `brew upgrade`
   without operator intervention.
8. Loads the LaunchDaemon via `launchctl bootstrap`. The daemon
   starts immediately and on every boot thereafter.

macOS may display a "Background item added" notification. If
`agentsso service status` doesn't show the daemon running, open
**System Settings → General → Login Items → Allow in the
Background** and confirm permitlayer is enabled.

> The older `sudo agentsso service install` verb still works as a
> redirect into `setup`. The CLI prints a loud one-time notice telling
> you to use `setup` going forward; no scripts break, but new docs and
> automation should use `setup`.

### Legacy-policy migration on upgrade

The one decision `setup` cannot make for you is what to do with a
**legacy operator policy that shadows a shipped (managed) policy** —
older releases seeded operator policies that now collide with the
managed bundle and would crash the daemon on boot. On an interactive
terminal `setup` prompts you (default Yes) before archiving the shadow
aside. For non-interactive / scripted runs, pass one of:

| Flag | Effect |
|------|--------|
| (none, interactive TTY) | Prompts before archiving any shadowing policy; archives on Yes. |
| `--upgrade` | Preserve **all** your operator config; archive only the daemon-crashing shadow(s) aside, then continue. Use this for routine upgrades. |
| `--fresh-install` | Archive the shadow(s) **and** wipe operator state (vault, agents, policies) for a clean slate. Destructive — only for a deliberate reset. |

In every case the archived shadow is **moved, not deleted** — into
`/Library/Application Support/permitlayer/policies/.legacy-seed-snapshot-<timestamp>/`,
recoverable for ~30 days (`agentsso doctor --fix` garbage-collects
snapshots older than 30 days). `setup` never asks you to `sudo rm` a
file: if a path is in the way, it either heals it or tells you exactly
what is holding it.

```sh
sudo agentsso setup              # install, or upgrade with an interactive prompt
sudo agentsso setup --upgrade    # scripted upgrade: keep config, archive shadows, continue
```

To add additional operators to the control-plane group:

```sh
sudo dseditgroup -o edit -a <username> -t user permitlayer-clients
```

## Creating an OAuth client

permitlayer uses bring-your-own OAuth credentials. You create the
OAuth client in your own Google Cloud project, and `agentsso` uses
those credentials to mint per-user tokens scoped to your Google
account.

1. Open <https://console.cloud.google.com/apis/credentials>.
2. Click **Create Credentials → OAuth client ID**.
3. Pick **Application type: Desktop app**.
4. Download the JSON file (`client_secret_*.json`).

For headless / SSH-only installs (CI runners, cloud-init,
fully-remote servers without a local browser), pick **Application
type: TV and Limited Input Device** instead and use the
`--device-flow` flag below.

## Connect a service

From your **end-user** account (not from `sudo`), connect a Google
service in one command. `quickstart` registers the agent under a
shipped policy (read-only or read+write), drives the OAuth flow, seals
the resulting tokens into the OS keychain, and emits an MCP config
snippet for your client:

```sh
agentsso quickstart gmail    --read --oauth-client ./client_secret.json
agentsso quickstart calendar --read-write --oauth-client ./client_secret.json
agentsso quickstart drive    --read-write --oauth-client ./client_secret.json
```

Pick `--read` for read-only or `--read-write` for read+write. The flag
both binds the agent to the matching shipped policy (`<svc>-read-only`
or `<svc>-read-write`) **and** decides which OAuth scopes the Google
consent screen requests — `--read-write` pulls in the write scopes
(e.g. `gmail.send`/`compose`/`modify`) so the sealed credential can
actually write, not just the policy. A browser opens for Google
consent; tokens are sealed locally. `quickstart` is idempotent — re-run
it any time to refresh scope, rotate credentials, or repoint a client.
(Re-running `--read-write` over an existing read-only credential
re-prompts for consent to add the write scopes.)

Useful flags:

- `--mcp-config-out <path>` — write the MCP client config snippet to
  a file (auth headers + URL + `streamable-http` transport) so your
  client can load it directly.
- `--agent <name>` — override the default agent name
  (`<service>-quickstart`). Useful when one operator runs several
  parallel agents.
- `--non-interactive` — require all decisions on the command line; no
  prompts. Pair with `--read` / `--read-write` (required) for
  scripted installs.

How much each agent can do with a connected service depends on the
policy tier you pick. See [Connector access
tiers](connector-tiers.md) for the read-only vs read+write tier model,
the per-service tool matrix, and the security posture.

> Older docs and CI scripts may still call `agentsso agent register`
> followed by `agentsso connect <service>`. Those verbs still work,
> but `quickstart` collapses them into one idempotent command and is
> the documented entry point.

### Connecting over SSH

If the operator account has no local browser (SSH session, `su`
without GUI), use `--headless`:

```sh
agentsso quickstart gmail --read --oauth-client ./client_secret.json --headless
```

`agentsso` prints the authorization URL, you complete consent in any
browser, and paste the redirect URL back at the prompt.

### Fully-headless / scripted installs

For boxes with no browser anywhere on the operator side (CI runners,
Ansible-driven provisioning), use `--device-flow` with a TV /
Limited Input OAuth client:

```sh
agentsso quickstart gmail --read --oauth-client ./client_secret_device.json \
  --agent ci-bot --device-flow --device-flow-timeout 300 --non-interactive
```

`agentsso` prints a URL and a code. Complete consent on any device
with a browser (laptop, phone); polling completes without any
operator action on the target machine.

## Verify

```sh
agentsso service status                      # daemon process state + bind addresses
curl http://127.0.0.1:3820/health            # round-trip a request through the MCP plane
```

`agentsso service status` checks that `launchd` thinks the daemon
should be running and the bearer-token-bearing socket is bound.
The `curl` against `/health` round-trips an actual HTTP request and
returns a JSON envelope when the daemon is serving. If either fails,
see [Troubleshooting](#troubleshooting).

## Point your MCP client at agentsso

`agentsso quickstart` emits an MCP config snippet at the end of its
run (and writes it to `--mcp-config-out <path>` if you supplied one)
that already carries:

- `"transport": "streamable-http"` (required — OpenClaw defaults to
  SSE, which won't work).
- `"url": "http://127.0.0.1:3820/mcp/<service>"` (Gmail / Calendar /
  Drive each have their own per-service path; bare `/mcp` is not a
  route).
- `Authorization: Bearer agt_v2_<name>_<random>` — auth is wired up for
  you; you don't set headers by hand. There is no client scope header:
  on the `/mcp` path the daemon derives each tool's required scope
  server-side, so the snippet carries only the bearer.

The exact paste target depends on your client:

- **OpenClaw**: paste the snippet into the MCP servers section of
  `~/.openclaw/config.json`, or point OpenClaw at the file you wrote
  with `--mcp-config-out`.
- **Claude Desktop**: in the MCP servers section of the desktop
  app's settings, paste the same snippet (or transcribe URL + headers).
- **Cursor**: same pattern — `streamable-http` transport at port
  3820, with the headers from the snippet.

## Uninstall

```sh
sudo agentsso service uninstall   # stop the daemon, remove all state
brew uninstall agentsso           # remove the binary
```

(`agentsso uninstall` is the documented one-step verb that wraps both;
either path works.)

`service uninstall` is idempotent: it tears down the LaunchDaemon,
deletes the master key from System.keychain, removes
`/Library/Application Support/permitlayer/`,
`/Library/Logs/permitlayer/`, `/var/run/permitlayer/`, and the
`permitlayer-clients` group. It does not touch the `agentsso` binary
itself — that's `brew uninstall`'s job.

Per-user state at `~/.agentsso/` (the bearer token in particular)
is left in place by `service uninstall`. The bearer token will no
longer authenticate to anything once the daemon is gone, so clear it
explicitly to avoid leaving an orphan credential file on disk:

```sh
rm -rf ~/.agentsso/
```

Each end-user with a registered agent should do this on their own
account.

## Troubleshooting

### `agentsso service status` shows the daemon stopped

Check the daemon log:

```sh
sudo tail -n 100 /Library/Logs/permitlayer/daemon.log
```

Inspect the LaunchDaemon's own bookkeeping:

```sh
sudo launchctl print system/dev.permitlayer.daemon | less
```

The `state =` line near the top tells you whether launchd thinks the
daemon should be running and why it isn't. If you see
`Bootstrap failed: 5: Input/output error` (for the daemon or a
per-user agent like the OpenClaw gateway), use the
[launchd troubleshooting reference](troubleshooting-launchd.md).
Other common failures:

- **Background item disabled**: System Settings → General → Login
  Items shows permitlayer toggled off. Toggle on, then
  `sudo launchctl kickstart -k system/dev.permitlayer.daemon`.
- **Master-key item missing or unreadable**: typically only happens
  if someone manually removed the System.keychain entry. Run
  `sudo agentsso uninstall && sudo agentsso setup` to mint a fresh
  one — this discards any sealed credentials, so each end-user with a
  connected service will need to re-run
  `agentsso quickstart <service> --read|--read-write --oauth-client
  <json>` to reconnect.
- **Stale binary after `brew upgrade agentsso`**: the privileged
  helper copy at `/Library/PrivilegedHelperTools/agentsso` is what
  the LaunchDaemon executes; `brew upgrade` only refreshes
  `/opt/homebrew/bin/agentsso`. Re-run `sudo agentsso setup` after
  every `brew upgrade` to roll the new binary into place and
  re-bootstrap the LaunchDaemon (`setup` is the canonical
  install/upgrade verb — see [above](#set-up-the-system-service)).
  The master key in System.keychain is preserved (`-A` ACL is
  independent of the binary's codesign hash), so sealed credentials
  survive the upgrade.

### `agentsso quickstart` returns a permission error

If you're not the operator who ran `sudo agentsso setup`, you may not
be in the `permitlayer-clients` group. Add yourself:

```sh
sudo dseditgroup -o edit -a "$(whoami)" -t user permitlayer-clients
```

(`$(whoami)` is quoted so AD / Open Directory accounts whose usernames
contain spaces — e.g. `first.last@corp` or federated identities —
don't word-split through to `dseditgroup`'s arg parser.)

Log out and back in so the new group membership takes effect.

If you are provisioning across more than one OS user, or the error
persists after re-login, work through the
[cross-user setup runbook](multi-user-setup.md#two-false-alarms-that-look-identical):
the same error has two distinct root causes (stale session vs. `setup`
run as the wrong user) that need different fixes.

### `agentsso quickstart` says `connect.daemon_must_run`

`agentsso quickstart` writes credentials through the daemon (the daemon
owns the master key and the vault directory). It refuses to run if
the daemon isn't reachable. The structured remediation block branches
on the detected failure:

- **Helper binary not installed** (no `/var/run/permitlayer/control.sock`):
  run `sudo agentsso setup`.
- **Helper installed but the LaunchDaemon isn't running**:
  `sudo launchctl kickstart -k system/dev.permitlayer.daemon`.
- **Helper running but the listener is wedged** (`kickstart -k`
  didn't restore the socket): fully re-bootstrap the daemon:
  ```sh
  sudo launchctl bootout system/dev.permitlayer.daemon
  # Wait for the previous instance to actually exit. `launchctl bootout`
  # is async — it sends SIGTERM and returns before the process is gone
  # (default `ExitTimeOut` 20s). Bootstrapping while the old instance
  # is still tearing down can fail with "Bootstrap failed: 5: Input/output
  # error" or "Service already loaded". This loop polls until the service
  # label is unloaded:
  until ! sudo launchctl print system/dev.permitlayer.daemon >/dev/null 2>&1; do
    sleep 1
  done
  sudo launchctl bootstrap system /Library/LaunchDaemons/dev.permitlayer.daemon.plist
  ```
- **Socket connect with EACCES** (you're not in the group):
  see the permission-error troubleshooting above.

### `agentsso quickstart` hangs on "waiting for browser consent" over SSH

`/usr/bin/open` can't reach a usable browser from an SSH session or
from a process whose owning user doesn't hold the Aqua session.
The CLI detects most of these cases automatically and prints a
copy-paste URL block with `--headless` / `--device-flow` suggestions.

If detection doesn't trip (e.g. you're under `sudo -i` from SSH which
masks `SSH_CONNECTION`) and `agentsso quickstart` appears to hang,
press Ctrl-C and re-run with one of:

- `--headless` — print the OAuth URL, accept the pasted redirect URL
  via stdin. Best for SSH from a machine that has a browser.
- `--device-flow` — Google OAuth 2.0 device flow (RFC 8628). Best for
  truly browser-less hosts (CI runners, cloud-init). Requires an
  OAuth client of type **TV and Limited Input Device** (separate
  Google client type from the Desktop app type).

### MCP client can't connect to `127.0.0.1:3820`

Verify the daemon is bound:

```sh
sudo lsof -iTCP:3820 -sTCP:LISTEN
```

You should see one `agentsso` process listening. If nothing's
listening, check `agentsso service status` and the daemon log.

### Increasing log verbosity

```sh
sudo launchctl setenv AGENTSSO_LOG__LEVEL debug
sudo launchctl kickstart -k system/dev.permitlayer.daemon
```

Revert with `sudo launchctl unsetenv AGENTSSO_LOG__LEVEL` and
another `kickstart`. The daemon does not honor `RUST_LOG`.

### Running the daemon in the foreground (dev)

For local development, the LaunchDaemon-installed daemon can be
stopped and the binary invoked directly:

```sh
sudo launchctl bootout system/dev.permitlayer.daemon
sudo /Library/PrivilegedHelperTools/agentsso start
```

`agentsso start` runs in the foreground with logs on stdout/stderr.
Stop with Ctrl-C; restart the LaunchDaemon with
`sudo launchctl bootstrap system /Library/LaunchDaemons/dev.permitlayer.daemon.plist`
when you're done. This mode is not intended for production — it
bypasses the LaunchDaemon's auto-restart behavior.
