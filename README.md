# permitlayer

**The guard between your agent and your data.**

permitlayer is an open-core identity and data-protection layer for AI
agents. It runs as a local daemon (`agentsso`) that brokers OAuth tokens to
upstream providers (starting with Google Workspace), scrubs sensitive
patterns out of responses before they reach the model, enforces per-agent
policy on every request, and writes a tamper-evident audit log.

MCP clients connect to it over Streamable HTTP; upstream providers see a
normal OAuth client. The tokens never touch the agent.

> **Status:** 1.0. The `agentsso` binary version is tracked in
> `Cargo.toml` (currently `1.0.0`); the plugin host-API surface is
> separately versioned at `1.0.0-rc.1` and is what
> [CHANGELOG.md](CHANGELOG.md) documents — they have independent
> cadences by design.
> The fully-supported install path is macOS (ARM64 + Intel) via
> Homebrew with `sudo agentsso setup`; Linux and Windows
> builds compile but ship a legacy per-user layout under
> `~/.agentsso/` and are not yet supported end-to-end.

## Install

> Binaries are signed (ed25519 / minisign) and published to
> [GitHub Releases](https://github.com/permitlayer/permitlayer/releases).
> The first stable release is **v1.0.0** (2026-05-28). Install via
> Homebrew or the curl script below.

### macOS — Homebrew (recommended)

```sh
brew tap permitlayer/tap
brew install permitlayer/tap/agentsso
sudo agentsso setup                                  # one-time, per machine
# Log out + back in (or open a new login shell) — the install adds
# you to permitlayer-clients; group membership doesn't take effect in
# your current shell. Then, from your end-user account, connect a service
# in one command (registers the agent + drives OAuth + emits MCP config):
agentsso quickstart gmail --read --oauth-client ./client_secret.json
# Use --read-write instead of --read to grant write access.
```

`sudo agentsso setup` provisions a root LaunchDaemon at
`/Library/LaunchDaemons/dev.permitlayer.daemon.plist`, creates
`/Library/Application Support/permitlayer/`, sets up the
`permitlayer-clients` macOS group, and starts the daemon. macOS will
display a "Background item added" notification — if the daemon doesn't
appear running, check **System Settings → General → Login Items →
Allow in the Background**. If `agentsso quickstart` returns a
permission error, your `permitlayer-clients` group membership hasn't
taken effect yet — log out and back in.

`agentsso quickstart <service> --read|--read-write --oauth-client
<json>` registers the agent under the matching shipped policy (e.g.
`gmail-read-only` or `gmail-read-write`), mints a bearer token, drives
the OAuth flow, and emits an MCP config snippet. Pass
`--mcp-config-out <path>` to write the snippet to a file your MCP client
can load directly. MCP clients (OpenClaw / Claude Desktop / Cursor)
connect to the daemon with transport `streamable-http`. Gmail uses
`http://127.0.0.1:3820/mcp/gmail`; Calendar and Drive use
`/mcp/calendar` and `/mcp/drive`. Bare `/mcp` is not a route.

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
   sudo agentsso setup
   agentsso service status        # confirm daemon is running
   ```

   After this completes, log out and back in (or open a new login
   shell) so your new `permitlayer-clients` group membership takes
   effect. Steps 2-4 below run from your end-user account, NOT under
   `sudo`.

2. **Create a Google OAuth client** (one-time):

   - <https://console.cloud.google.com/apis/credentials> → **Create
     Credentials** → **OAuth client ID** → **Application type: Desktop app**.
   - Download the JSON file (Google calls it `client_secret_*.json`).

3. **Connect Gmail** (or `calendar`, `drive`) in one command:

   ```sh
   agentsso quickstart gmail --read --oauth-client ./client_secret_XXXX.json
   # Use --read-write instead of --read for read+write scope.
   # Add --mcp-config-out <path> to write the MCP client snippet to a file.
   ```

   `quickstart` registers the agent under the matching shipped policy
   (`gmail-read-only` or `gmail-read-write`), mints a bearer token,
   drives the Google consent flow, and prints an MCP config snippet for
   your client. A browser window opens for Google consent. Tokens get
   sealed into the OS keychain (System.keychain on macOS; Secret Service
   on Linux; Credential Manager on Windows). It is idempotent — re-run
   it any time to refresh scope or rotate credentials.

4. **Point your MCP client** at `http://127.0.0.1:3820/mcp/gmail` with
   transport `streamable-http`, using the bearer token from the snippet
   quickstart emitted. The `/mcp` path needs no client scope header — the
   daemon derives each tool's scope server-side. Bare `/mcp` is not a
   route; Calendar and Drive are at `/mcp/calendar` and `/mcp/drive`.

5. **Inspect activity**:

   ```sh
   agentsso audit --follow
   ```

### Connect over SSH or under `su`

If `agentsso quickstart` cannot reach a usable browser (SSH session,
`su user` without GUI access, headless server, etc.), pass `--headless`:

```sh
agentsso quickstart gmail --read --oauth-client ./client_secret.json --headless
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
sudo agentsso setup
agentsso quickstart gmail --read --oauth-client ./client_secret_device.json \
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
  bearer-token claim. `sudo agentsso setup` adds the invoking operator
  to that group; add additional operators with
  `sudo dseditgroup -o edit -a <user> -t user permitlayer-clients`,
  then have the user log out and back in for the group membership to
  take effect.

- **MCP data plane** (`/mcp/*`) lives on TCP loopback at
  `127.0.0.1:3820`. MCP clients (OpenClaw, Claude Desktop, Cursor)
  speak HTTP-over-streamable-http, which is TCP-only; we keep this
  channel on loopback specifically for compatibility. The daemon
  authenticates MCP clients via per-user bearer tokens minted by
  `agentsso quickstart <service>` (which calls `agent register`
  internally under a shipped policy and emits an MCP config snippet
  carrying the bearer token). MCP clients read the `Authorization`
  header from that snippet directly; the `/mcp` path needs no client
  scope header (the daemon derives each tool's scope server-side). The
  REST data plane (`/v1/tools/*`) is different — it *does* require an
  `x-agentsso-scope` header per request.

  If the operator who ran `sudo agentsso setup` is a different OS
  account than the end-user who'll run `agentsso quickstart`, that
  end-user must be added to the `permitlayer-clients` group too —
  `sudo dseditgroup -o edit -a <end-user> -t user permitlayer-clients`
  then log them out and back in.

The split is deliberate. The control plane gets kernel-attested peer
identity from UDS; the MCP plane gets backward-compatibility with
existing HTTP-only MCP clients.

The MCP plane's TCP bind address is configurable via the
`AGENTSSO_HTTP__BIND_ADDR` env var (figment env-layering applies via
`Env::prefixed("AGENTSSO_").split("__")`, so `AGENTSSO_HTTP__BIND_ADDR=
127.0.0.1:3920` overrides the default `127.0.0.1:3820`). Set it in
the LaunchDaemon plist's `EnvironmentVariables` if you need a
non-default port — `sudo agentsso setup` regenerates the plist, so
this is a one-time edit per machine.

## What's in the box

- **OAuth broker** with PKCE + automatic refresh, backed by a sealed
  on-disk vault (AES-GCM + HKDF + Argon2) and the OS keychain.
- **Scrub engine** — built-in rules for bearer tokens, OTPs, password-reset
  links, and common PII patterns. Replaces matches with one-way redaction
  placeholders (`<REDACTED_BEARER>`, `<REDACTED_OTP>`, ...) before content
  reaches the agent.
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
- [docs/user-guide/agent-skill-permitlayer-mcp.md](docs/user-guide/agent-skill-permitlayer-mcp.md)
  — paste-in skill / system prompt for non-ClawHub MCP clients (Claude
  Desktop, Linux/Windows hosts). ClawHub/OpenClaw users get the same skill
  via `clawhub install agentsso-gateway`. Covers policy semantics, scrub
  placeholders, error retry rules, audit expectations, and the non-obvious
  tool flows (Gmail two-step attachments, base64url decoding, etc.)
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
> Tools enabled, `syspolicyd` may have a scan backlog — or have wedged
> into a runaway loop (pegging a full core steadily, independent of any
> build). Kill it to clear either:
>
> ```sh
> sudo killall syspolicyd
> ```
>
> launchd restarts it automatically within seconds. After restarting it,
> also re-run your build — processes that were already blocked on the old
> daemon do not recover.
>
> **Diagnose hung-vs-slow quickly** (so you don't wait it out): sample
> CPU ~20s after launch. A healthy `rustc`/`nextest` shows state `R`
> with >0% CPU; if it sits at state `S` / 0.0% CPU for minutes while
> `syspolicyd` pegs a core, it's wedged — restart the daemon, don't wait.
>
> ```sh
> ps -o pid,%cpu,state,comm -ax | grep -iE 'rustc|nextest|syspolicyd' | grep -v grep
> ```
>
> Also run only **one** cargo invocation at a time — overlapping
> `cargo`/`nextest` runs are a known trigger for the `syspolicyd` backlog.

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
