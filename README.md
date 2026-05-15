# permitlayer

**The guard between your agent and your data.**

permitlayer is an open-core identity and data-protection layer for AI
agents. It runs as a local daemon (`agentsso`) that brokers OAuth tokens to
upstream providers (starting with Google Workspace), scrubs sensitive
patterns out of responses before they reach the model, enforces per-agent
policy on every request, and writes a tamper-evident audit log.

MCP clients connect to it over Streamable HTTP; upstream providers see a
normal OAuth client. The tokens never touch the agent.

> **Status:** alpha. The `agentsso` binary version is tracked in
> `Cargo.toml`; the plugin host-API surface is separately versioned at
> `1.0.0-rc.1` and is what [CHANGELOG.md](CHANGELOG.md) documents.
> The fully-supported install path is macOS (ARM64 + Intel) via
> Homebrew with `sudo agentsso service install`; Linux and Windows
> builds compile but ship a legacy per-user layout under
> `~/.agentsso/` and are not yet supported end-to-end.

## Install

> **Pre-release.** Binaries are signed (ed25519 / minisign) and
> published to [GitHub Releases](https://github.com/permitlayer/permitlayer/releases),
> but the first stable tag is still pending. The Homebrew and curl
> paths below work once a release is cut.

### macOS — Homebrew (recommended)

```sh
brew tap permitlayer/tap
brew install permitlayer/tap/agentsso
sudo agentsso service install                       # one-time, per machine
# Log out + back in (or open a new login shell) — the install adds
# you to permitlayer-clients; group membership doesn't take effect in
# your current shell. Then, from your end-user account:
agentsso agent register <name> --policy gmail-read-only
agentsso connect gmail --oauth-client ./client_secret.json --agent <name>
```

`sudo agentsso service install` provisions a root LaunchDaemon at
`/Library/LaunchDaemons/dev.permitlayer.daemon.plist`, creates
`/Library/Application Support/permitlayer/`, sets up the
`permitlayer-clients` macOS group, and starts the daemon. macOS will
display a "Background item added" notification — if the daemon doesn't
appear running, check **System Settings → General → Login Items →
Allow in the Background**. If `agentsso agent register` returns a
permission error, your `permitlayer-clients` group membership hasn't
taken effect yet — log out and back in.

`agentsso agent register <name> --policy <policy-name>` mints a
per-user bearer token at `~/.agentsso/agent-bearer.token` (mode 0600).
MCP clients (OpenClaw / Claude Desktop / Cursor) read that token and
connect to the daemon with transport `streamable-http`. Gmail uses
`http://127.0.0.1:3820/mcp/gmail`; Calendar and Drive use
`/mcp/calendar` and `/mcp/drive`.

Running the daemon and end-user under different OS accounts? See
[Running the daemon and the agent under different OS users](#running-the-daemon-and-the-agent-under-different-os-users)
below — additional operators need to be added to the
`permitlayer-clients` group explicitly.

See [docs/user-guide/install.md](docs/user-guide/install.md) for the
full lifecycle (`brew upgrade`, `brew uninstall`, `service status`,
troubleshooting).

### macOS / Linux — curl | sh

```sh
curl -fsSL https://raw.githubusercontent.com/permitlayer/permitlayer/main/install/install.sh | sh
```

### Build from source

Requires Rust (toolchain version pinned in `rust-toolchain.toml`).
The one-time bootstrap script installs the toolchain, nextest, and
lld; see [Development setup](#development-setup) below.

```sh
git clone https://github.com/permitlayer/permitlayer.git
cd permitlayer
cargo build --release -p permitlayer-daemon
cp target/release/agentsso /usr/local/bin/agentsso   # or anywhere on PATH
```

The OAuth setup flow was restructured immediately before the first
public commit — please validate end-to-end on a fresh machine before
trusting it with real credentials, and file an issue if something
surprises you.

## Quickstart

permitlayer uses **bring-your-own OAuth credentials** — you create an OAuth
client in your own Google Cloud project, and permitlayer uses it. This
keeps tokens scoped to your Google account, not a shared app.

1. **Set up the daemon** (one-time per machine):

   ```sh
   sudo agentsso service install
   agentsso service status        # confirm daemon is running
   ```

   After this completes, log out and back in (or open a new login
   shell) so your new `permitlayer-clients` group membership takes
   effect. Steps 2-6 below run from your end-user account, NOT under
   `sudo`.

2. **Register an agent** (from your end-user account, once per MCP client):

   ```sh
   agentsso agent register <name> --policy gmail-read-only
   ```

   `--policy` is required and must name a policy that already exists
   under `/Library/Application Support/permitlayer/policies/`. The
   seeded `gmail-read-only` policy is a safe starting point. Add
   `--json` for a `jq`-parseable envelope (scripted installs).

   Mints a bearer token at `~/.agentsso/agent-bearer.token` (mode 0600,
   owned by you). MCP clients read this file.

3. **Create a Google OAuth client** (one-time):

   - <https://console.cloud.google.com/apis/credentials> → **Create
     Credentials** → **OAuth client ID** → **Application type: Desktop app**.
   - Download the JSON file (Google calls it `client_secret_*.json`).

4. **Connect Gmail** (or `calendar`, `drive`):

   ```sh
   agentsso connect gmail --oauth-client ./client_secret_XXXX.json --agent <name>
   ```

   A browser window opens for Google consent. Tokens get sealed into the
   OS keychain (System.keychain on macOS; Secret Service on Linux;
   Credential Manager on Windows). The `--agent <name>` flag is required;
   `connect` composes credential sealing + policy update + agent rebind in
   one idempotent command.

5. **Point your MCP client** at `http://127.0.0.1:3820/mcp/gmail` with
   transport `streamable-http`, using the bearer token from step 2.
   Bare `/mcp` is not a route; Calendar and Drive are available at
   `/mcp/calendar` and `/mcp/drive`.

6. **Inspect activity**:

   ```sh
   agentsso audit --follow
   ```

### Connect over SSH or under `su`

If `agentsso connect` cannot reach a usable browser (SSH session, `su user`
without GUI access, headless server, etc.), pass `--headless` instead:

```sh
agentsso connect gmail --oauth-client ./client_secret.json --agent <name> --headless
```

For truly headless boxes (no browser available at all on the target
machine, e.g. CI runners, cloud-init provisioning, fully-headless
servers), use `--device-flow` instead. The daemon prints a URL + code,
you complete consent on any device with a browser (laptop, phone), and
polling completes without operator interaction at the target machine:

```sh
# Scripted-install scenario (CI, Ansible, cloud-init):
# OAuth client must be type "TV and Limited Input Device" (NOT "Desktop app").
# See the "Fully-headless / scripted installs" section in
# docs/user-guide/install.md for the OAuth client setup details.
sudo agentsso service install
# Mint a bearer token first — `connect` requires the agent to be
# pre-registered. `--json` parses cleanly through jq for scripted use.
AGENTSSO_BEARER_TOKEN=$(agentsso agent register ci-bot --policy gmail-read-only --json | jq -r .bearer_token)
agentsso connect gmail --oauth-client ./client_secret_device.json --agent ci-bot \
  --device-flow --device-flow-timeout 300 --non-interactive
```

`--device-flow` is mutually exclusive with `--headless` (the paste-
redirect flow takes a different code path). It is compatible with
`--non-interactive` — that's the canonical scripted-headless invocation.

In headless mode the daemon prints the authorization URL, attempts to
copy it to your terminal's clipboard via OSC 52 (works in iTerm2,
Kitty, Wezterm, VS Code's integrated terminal — silently no-ops in
others, in which case mouse-select the URL above), and then waits for
you to paste the redirect URL back.

Workflow:

1. Copy the printed authorization URL.
2. Open it in any browser — local or on a different machine.
3. Approve consent.
4. Your browser will redirect to `http://127.0.0.1:<port>/callback?...`
   and show a "connection refused" error. **That's expected** — this
   host isn't listening, that's the whole point of `--headless`.
5. Copy the full redirect URL from your browser's address bar.
6. Paste it into the `agentsso connect` prompt and press Enter.

The daemon validates the pasted URL against the redirect URI it
issued (scheme, host, port, path, and CSRF state must all match)
and exchanges the authorization code for tokens locally.

For diagnostic detail on startup failures, run the daemon with
`AGENTSSO_LOG__LEVEL=debug` (the daemon does not honor `RUST_LOG`).

### Running the daemon and the agent under different OS users

On macOS the daemon runs as `root` via LaunchDaemon. End-users
authenticate to it on two separate channels:

- **Control plane** (`/v1/control/*` — `agent register`, `agent list`,
  `kill`, `resume`, `reload`, `connectors list`, `status --connections`)
  lives on a Unix domain socket at `/var/run/permitlayer/control.sock`,
  mode `0660`, owned `root:permitlayer-clients`. Members of the
  `permitlayer-clients` group can connect; the daemon reads the
  caller's UID via `LOCAL_PEERCRED` and audit-logs it alongside any
  bearer-token claim. `sudo agentsso service install` adds the
  invoking operator to that group; add additional operators with
  `sudo dseditgroup -o edit -a <user> -t user permitlayer-clients`,
  then have the user log out and back in for the group membership to
  take effect.

- **MCP data plane** (`/mcp/*`) lives on TCP loopback at
  `127.0.0.1:3820`. MCP clients (OpenClaw, Claude Desktop, Cursor)
  speak HTTP-over-streamable-http, which is TCP-only; we keep this
  channel on loopback specifically for compatibility. The daemon
  authenticates MCP clients via per-user bearer tokens minted by
  `agentsso agent register <name> --policy <policy-name>` and written
  to `~/.agentsso/agent-bearer.token` (mode `0600`, owned by the
  invoking user). MCP clients read the token **value** from that file
  (not the path — e.g., Claude Desktop's `env` block needs the bearer
  string itself, not a `~/.agentsso/...` path expression).

  If the operator who ran `sudo agentsso service install` is a
  different OS account than the end-user who'll run
  `agentsso agent register`, that end-user must be added to the
  `permitlayer-clients` group too — `sudo dseditgroup -o edit -a
  <end-user> -t user permitlayer-clients` then log them out and back
  in.

The split is deliberate. The control plane gets kernel-attested peer
identity from UDS; the MCP plane gets backward-compatibility with
existing HTTP-only MCP clients.

The MCP plane's TCP bind address is configurable via the
`AGENTSSO_HTTP__BIND_ADDR` env var (figment env-layering applies via
`Env::prefixed("AGENTSSO_").split("__")`, so `AGENTSSO_HTTP__BIND_ADDR=
127.0.0.1:3920` overrides the default `127.0.0.1:3820`). Set it in
the LaunchDaemon plist's `EnvironmentVariables` if you need a
non-default port — `sudo agentsso service install` regenerates the
plist, so this is a one-time edit per machine.

## What's in the box

- **OAuth broker** with PKCE + automatic refresh, backed by a sealed
  on-disk vault (AES-GCM + HKDF + Argon2) and the OS keychain.
- **Scrub engine** — built-in rules for bearer tokens, OTPs, password-reset
  links, and common PII patterns. Replaces matches with stable placeholders
  that round-trip across the proxy boundary.
- **Policy engine** — per-agent, per-resource, per-method allow/prompt/deny
  rules. Policy decisions are logged.
- **Kill switch** — `agentsso kill` flips the daemon into a state where
  every upstream call returns an audited refusal. Recover with
  `agentsso resume`.
- **Connector plugins** — Gmail/Calendar/Drive ship as sandboxed JS
  plugins running in an embedded QuickJS runtime. Write your own with
  `agentsso connectors new`.
- **Audit log** — append-only JSON lines with an integrity chain. Export
  to CSV with `agentsso audit --export=./audit.csv`.

Read the architecture memos and ADRs under [`docs/`](docs/) for design
details.

## Documentation

- [CHANGELOG.md](CHANGELOG.md) — release notes, host-API surface history
- [docs/adrs/](docs/adrs/) — architecture decision records
- [docs/agent-identity-memo.md](docs/agent-identity-memo.md) — identity
  model design
- [CONTRIBUTING.md](CONTRIBUTING.md) — dev workflow, test gates,
  CODEOWNERS policy
- [SECURITY.md](SECURITY.md) — vulnerability reporting

## License

MIT. See [LICENSE](LICENSE).

---

## Development setup

```sh
./scripts/bootstrap.sh        # one-time: Rust toolchain + nextest + lld
cargo nextest run --workspace  # run the test suite
```

The toolchain version is pinned in `rust-toolchain.toml`. The bootstrap
script is idempotent.

### macOS (required — do this first)

Two one-time steps keep test runs fast and non-hanging on macOS:

**1. Enable Developer Mode for your terminal app**

macOS XProtect scans newly compiled binaries before allowing execution.
With many test binaries per workspace run, this can make
`cargo nextest run` appear stuck for several minutes after a cold build.
The fix is a one-time system setting:

```sh
sudo spctl developer-mode enable-terminal
```

Then open **System Settings → Privacy & Security → Developer Tools**
and toggle **your terminal app** on. Fully quit and relaunch it after.

> **macOS Sequoia (15+) notes**
>
> `spctl developer-mode enable-terminal` only reveals the toggle in
> System Settings — you still need to enable it in the GUI. Add the
> **exact app** you run `cargo` from (Terminus, iTerm2, Warp — not just
> "Terminal") and fully quit and relaunch.
>
> **tmux users:** tmux's server is started independently and may not
> inherit the Developer Tools exemption. If cargo still hangs inside
> tmux, try running it directly in your terminal first to confirm.
>
> If `cargo nextest run` appears completely hung even with Developer
> Tools enabled, `syspolicyd` may have a scan backlog from a prior
> session. Kill it to clear the queue:
>
> ```sh
> sudo killall syspolicyd
> ```
>
> launchd restarts it automatically within seconds.

See the [nextest antivirus guide](https://nexte.st/book/antivirus-gatekeeper.html)
for background.

**2. (Optional) Install lld**

LLVM's linker cuts incremental link times noticeably on local dev
builds. It is **not** wired on by default because the `brew` install
path (`/opt/homebrew/opt/lld/bin/ld64.lld`) is specific to
Homebrew-on-Apple-Silicon and breaks CI runners. To opt in locally:

```sh
brew install lld
```

Then uncomment the `[target.aarch64-apple-darwin]` block in
`.cargo/config.toml` in a local-only copy (do not commit the change —
it will break CI).

### Running tests

```sh
# Fast: skips slow macOS Keychain conformance tests (~130s each)
cargo nextest run --workspace

# Full: includes Keychain tests (requires macOS Keychain access)
cargo nextest run --workspace --profile full
```

The Keychain tests hit `securityd` directly and are excluded from the
default profile. Run them when touching `permitlayer-keystore`.

### Validation xtasks

```sh
cargo xtask validate-credentials       # trait discipline on the 4 policed types
cargo xtask validate-plugin-api        # host-api.lock snapshot gate
cargo xtask validate-plugin-api --update  # update the snapshot after intentional changes
```

Both run in CI; run locally before pushing.

### Windows

Install rustup from <https://rustup.rs>, reopen your shell, then run
`cargo nextest run --workspace`.
