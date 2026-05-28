# Cross-user / multi-machine setup runbook

This runbook covers provisioning `agentsso` for cross-user use — the
common case where one person installs the system service and one or
more **operator** accounts (possibly on a fresh machine) connect
agents and Google Workspace services through it.

It exists because every step below has a failure mode that looks like
a different problem than it is. Follow the sequence in order; the
[disambiguation section](#two-false-alarms-that-look-identical)
explains the two traps that waste the most time.

This is the cross-user companion to the canonical
[install guide](install.md). Read that first for the single-machine
lifecycle; come back here when more than one OS user is involved.

## The provisioning sequence (in order)

Do these in order. Skipping or reordering steps 2–4 is the single
biggest source of "it doesn't work" reports.

### 1. Install the binary

Same as a single-user install — use the canonical commands:

```sh
brew tap permitlayer/tap
brew install permitlayer/tap/agentsso
```

or, via the install script:

```sh
curl -fsSL https://raw.githubusercontent.com/permitlayer/permitlayer/main/install/install.sh | sh
```

The binary alone does nothing — the daemon must be installed as a
system service next.

### 2. Install the system service AS THE OPERATOR ACCOUNT

Run this **logged in as the operator account who will use agentsso**,
and supply `sudo` when prompted:

```sh
sudo agentsso setup
```

**Do this from the operator's own login session.** Do **not** run it
from a root shell (`sudo su -`, `sudo -i`, then `agentsso setup`), and
do not run it while logged in as a *different* user than the one who
will later run `agentsso quickstart`.

**Why this matters.** `setup` binds the cross-user auth identity to
the *invoking operator's* UID and username, and it adds *that* user
(and only that user) to the `permitlayer-clients` group. The daemon's
control socket is gated to that principal. If you run `setup` as the
wrong user — or from a root shell where the invoking identity is
`root` rather than the operator — you authorize the wrong principal.
The daemon comes up fine, but the operator who actually needs it is
locked out, and the symptom
([see below](#two-false-alarms-that-look-identical)) looks exactly
like "the daemon isn't running."

If you have already made this mistake, the fix is to re-run
`sudo agentsso setup` from the *correct* operator's login session.
It is idempotent for the system-service bits and re-binds the identity
to the right user.

### 3. Add the operator(s) to `permitlayer-clients`

Step 2 already added the *invoking* operator to the
`permitlayer-clients` group. You do **not** need to repeat that for
the operator who ran `setup`.

For **additional** operator accounts on the same machine, an admin
must add each one explicitly:

```sh
sudo dseditgroup -o edit -a <username> -t user permitlayer-clients
```

The control socket is mode `0660`, owned `root:permitlayer-clients`.
Group membership is what authorizes a uid to open it; there is no
per-user allowlist beyond the group.

### 4. Log out and back in

**Group membership does not apply to an already-running session.**
macOS computes a process's group set at login (and SSH session
start). Adding a user to `permitlayer-clients` — including the
automatic add in step 2 — does **not** retroactively grant the
membership to a shell, login session, or SSH session that was already
open when the group changed.

Log out of the GUI and back in (or disconnect and reconnect the SSH
session), then verify the membership is live in the **current**
session:

```sh
id -Gn | tr ' ' '\n' | grep permitlayer-clients
```

If that prints `permitlayer-clients`, the current session can open
the control socket. If it prints nothing, you are still in a stale
session — log out fully and back in. Do **not** proceed to step 5
until this check passes; every downstream failure traces back to
here.

### 5. Connect a service

From the operator account (the one that now shows
`permitlayer-clients` in `id -Gn`):

```sh
agentsso quickstart <service> --read|--read-write --oauth-client <path>
```

`<service>` is `gmail`, `calendar`, or `drive`. `quickstart` registers
the agent under the matching shipped policy (`<svc>-read-only` or
`<svc>-read-write`), drives the OAuth flow, and emits an MCP config
snippet for the client. A browser opens for Google consent; tokens
are sealed into the OS keychain. See the
[install guide](install.md#connect-a-service) for the SSH /
device-flow variants and the full flag list.

#### `--oauth-client` must point at a stable path

Point `--oauth-client` at a **stable** path — somewhere that survives
reboots and macOS housekeeping. Do **not** point it at `~/Downloads`:
Downloads is subject to "remove items from the Trash / Downloads
after 30 days" cleanup and to manual tidying, and the path is a
provisioning input you may need again.

A good home is a per-operator config directory you control, e.g.:

```sh
mkdir -p ~/.config/agentsso
mv ~/Downloads/client_secret_*.json ~/.config/agentsso/client_secret.json
agentsso quickstart gmail --read --oauth-client ~/.config/agentsso/client_secret.json
```

Once connected, the client credentials are read at connect time and
sealed into the encrypted vault; the original file is no longer
needed by the daemon at runtime (you may keep it for re-provisioning
another service later, or delete it — either is safe). Keeping it in
a stable location simply means you do not have to re-download it from
Google Cloud Console the next time you connect another service for
this client.

## Two false alarms that look identical

Both of the failures below surface as the **same** error. You will
see one of:

- `forbidden_missing_control_token`
- `connect.daemon_must_run`
- a plain "daemon not running" / "daemon unreachable" message

The error text says "daemon" — but in both cases below **the daemon
is running fine**. What is actually happening is that the kernel will
not let your uid open the control socket
(`/var/run/permitlayer/control.sock`, mode `0660`,
`root:permitlayer-clients`). "Unreachable" here almost always means
"not permitted," not "not up."

**First, confirm the daemon really is up** so you stop chasing a
process that isn't the problem:

```sh
agentsso service status
```

If that shows the daemon running (and
[the launchd troubleshooting reference](troubleshooting-launchd.md)
if it genuinely is not), the daemon is fine and you are looking at
one of these two access problems:

### Symptom (a): operator not in the group *in this session*

The operator is a member of `permitlayer-clients` on paper, but the
**current** shell/login/SSH session predates the group change, so the
session's group set does not include it.

Disambiguate:

```sh
id -Gn | tr ' ' '\n' | grep permitlayer-clients
```

- **Prints nothing** → this is symptom (a). The membership is not
  active in this session.
- **Prints `permitlayer-clients`** → this is *not* symptom (a); skip
  to symptom (b).

**Fix:** log out and back in (or reconnect the SSH session) so the
session picks up the membership, then re-check with `id -Gn`. If the
user was never actually added, add them
([step 3](#3-add-the-operators-to-permitlayer-clients)) first, then
re-login.

### Symptom (b): `setup` ran as the wrong user

`id -Gn` shows `permitlayer-clients` for the current operator — so
group membership is fine — but `agentsso quickstart` still reports the
daemon error. This means the daemon's cross-user identity was bound
to a *different* operator UID, because `sudo agentsso setup` was run
as the wrong user or from a root shell
([see step 2](#2-install-the-system-service-as-the-operator-account)).
The daemon is up, the socket is openable, but the daemon refuses the
control token because it is gated to a different principal.

**Fix:** re-run `sudo agentsso setup` **from the correct operator's
login session** (not from `sudo -i` / `sudo su -`). This re-binds the
cross-user identity to the operator who actually needs it. Then retry
`agentsso quickstart <service>`.

### Quick disambiguation table

| `agentsso service status` | `id -Gn ... grep permitlayer-clients` | Diagnosis | Fix |
|---|---|---|---|
| daemon running | prints nothing | Symptom (a) — stale session | Re-login; verify `id -Gn` |
| daemon running | prints `permitlayer-clients` | Symptom (b) — wrong install principal | Re-run `setup` as the correct operator |
| daemon **not** running | (either) | Not an access problem | See [launchd troubleshooting](troubleshooting-launchd.md) |

## See also

- [Installing agentsso](install.md) — canonical single-machine
  lifecycle and per-symptom troubleshooting.
- [launchd troubleshooting reference](troubleshooting-launchd.md) —
  for the case where the daemon genuinely will not start
  (`Bootstrap failed: 5`).
