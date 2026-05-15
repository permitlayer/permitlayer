# Installing agentsso

`agentsso` is the permitlayer daemon. On macOS it installs as a root
LaunchDaemon system service. End-users authenticate to it locally,
either over a Unix domain socket (control plane) or TCP loopback (MCP).

This guide is the canonical install reference. The
[README](../../README.md) quickstart points here for the full
lifecycle.

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
sudo agentsso service install
```

This command:

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

To add additional operators to the control-plane group:

```sh
sudo dseditgroup -o edit -a <username> -t user permitlayer-clients
```

## Register an agent

From your **end-user** account (not from `sudo`), mint a per-user
bearer token. The agent name is positional; `--policy` is required
and must reference a policy that already exists under
`/Library/Application Support/permitlayer/policies/`. The seeded
`gmail-read-only` policy is a safe starting point:

```sh
agentsso agent register <name> --policy gmail-read-only
```

The token is written to `~/.agentsso/agent-bearer.token` (mode 0600,
owned by you), and is also echoed once to stdout for piping into MCP
client configs. Add `--json` to get a single-line JSON envelope
(`{"status":"ok","name":"...","policy_name":"...","bearer_token":"..."}`)
suitable for `jq` parsing in scripted installs.

The token survives daemon restarts. If you need to rotate it, delete
the file and re-run `agentsso agent register <name> --policy
<policy-name>`.

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

From your end-user account:

```sh
agentsso connect gmail   --oauth-client ./client_secret.json --agent <name>
agentsso connect calendar --oauth-client ./client_secret.json --agent <name>
agentsso connect drive   --oauth-client ./client_secret.json --agent <name>
```

A browser opens for Google consent. Tokens are sealed into the OS
keychain. The `--agent <name>` flag is required; `connect` composes
credential sealing, policy update, and agent rebind in one
idempotent command.

### Connecting over SSH

If the operator account has no local browser (SSH session, `su`
without GUI), use `--headless`:

```sh
agentsso connect gmail --oauth-client ./client_secret.json --agent <name> --headless
```

`agentsso` prints the authorization URL, you complete consent in any
browser, and paste the redirect URL back at the prompt.

### Fully-headless / scripted installs

For boxes with no browser anywhere on the operator side (CI runners,
Ansible-driven provisioning), use `--device-flow` with a TV /
Limited Input OAuth client:

```sh
agentsso connect gmail --oauth-client ./client_secret_device.json --agent ci-bot \
  --device-flow --device-flow-timeout 300 --non-interactive
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

MCP clients connect with transport `streamable-http` and authenticate
via the bearer token from `~/.agentsso/agent-bearer.token`. Gmail uses
`http://127.0.0.1:3820/mcp/gmail`; Calendar and Drive use
`http://127.0.0.1:3820/mcp/calendar` and
`http://127.0.0.1:3820/mcp/drive`. Bare `/mcp` is not a route.
The exact config syntax depends on your client:

- **OpenClaw**: in your `~/.openclaw/config.json`, set the MCP
  server's `transport` to `streamable-http` and `url` to
  `http://127.0.0.1:3820/mcp/gmail`. Read the bearer token via shell
  substitution or paste it directly.
- **Claude Desktop**: in the MCP servers section of the desktop
  app's settings, add a `streamable-http` transport pointed at
  `http://127.0.0.1:3820/mcp/gmail`.
- **Cursor**: same pattern — `streamable-http` transport at port
  3820.

## Uninstall

```sh
sudo agentsso service uninstall   # stop the daemon, remove all state
brew uninstall agentsso           # remove the binary
```

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
daemon should be running and why it isn't. Common failures:

- **Background item disabled**: System Settings → General → Login
  Items shows permitlayer toggled off. Toggle on, then
  `sudo launchctl kickstart -k system/dev.permitlayer.daemon`.
- **Master-key item missing or unreadable**: typically only happens
  if someone manually removed the System.keychain entry. Run
  `sudo agentsso service uninstall && sudo agentsso service install`
  to mint a fresh one — this discards any sealed credentials, so each
  end-user with a registered agent will need to re-run
  `agentsso agent register <name> --policy <policy-name>` and re-run
  `agentsso connect <service> --agent <name>` for any services they
  had connected.
- **Stale binary after `brew upgrade agentsso`**: the privileged
  helper copy at `/Library/PrivilegedHelperTools/agentsso` is what
  the LaunchDaemon executes; `brew upgrade` only refreshes
  `/opt/homebrew/bin/agentsso`. Re-run `sudo agentsso service
  install` after every `brew upgrade` to copy the new binary into
  place and kick the LaunchDaemon. The master key in System.keychain
  is preserved (`-A` ACL is independent of the binary's codesign
  hash), so sealed credentials survive the upgrade.

### `agentsso connect` returns a permission error

If you're not the operator who ran `sudo agentsso service install`,
you may not be in the `permitlayer-clients` group. Add yourself:

```sh
sudo dseditgroup -o edit -a "$(whoami)" -t user permitlayer-clients
```

(`$(whoami)` is quoted so AD / Open Directory accounts whose usernames
contain spaces — e.g. `first.last@corp` or federated identities —
don't word-split through to `dseditgroup`'s arg parser.)

Log out and back in so the new group membership takes effect.

### `agentsso connect` says `connect.daemon_must_run`

`agentsso connect` writes credentials through the daemon (the daemon
owns the master key and the vault directory). It refuses to run if
the daemon isn't reachable. The structured remediation block branches
on the detected failure:

- **Helper binary not installed** (no `/var/run/permitlayer/control.sock`):
  run `sudo agentsso service install`.
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

### `agentsso connect` hangs on "waiting for browser consent" over SSH

`/usr/bin/open` can't reach a usable browser from an SSH session or
from a process whose owning user doesn't hold the Aqua session.
The CLI detects most of these cases automatically and prints a
copy-paste URL block with `--headless` / `--device-flow` suggestions.

If detection doesn't trip (e.g. you're under `sudo -i` from SSH which
masks `SSH_CONNECTION`) and `agentsso connect` appears to hang,
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
