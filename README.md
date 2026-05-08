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
> Desktop binaries are macOS ARM64 only for now; Linux and Windows are
> planned.

## Install

> **Pre-release.** Binaries are signed (ed25519 / minisign) and
> published to [GitHub Releases](https://github.com/permitlayer/permitlayer/releases),
> but the first stable tag is still pending. The Homebrew and curl
> paths below work once a release is cut.

### macOS — Homebrew (recommended)

```sh
brew tap permitlayer/tap
brew install permitlayer/tap/agentsso
agentsso connect gmail --oauth-client ./client_secret.json --agent <name>
```

Start the daemon and enable login-autostart (SSH-friendly per Story
7.16 — works over SSH on macOS 13+ without a GUI session):

```sh
agentsso start            # foreground for this session
agentsso autostart enable # persistent across reboots
```

See [docs/user-guide/install.md](docs/user-guide/install.md) for the
full lifecycle (`brew upgrade`, `brew uninstall`, autostart details).

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

1. **Create a Google OAuth client** (one-time):

   - <https://console.cloud.google.com/apis/credentials> → **Create
     Credentials** → **OAuth client ID** → **Application type: Desktop app**.
   - Download the JSON file (Google calls it `client_secret_*.json`).

2. **Connect Gmail** (or `calendar`, `drive`):

   ```sh
   agentsso connect gmail --oauth-client ./client_secret_XXXX.json --agent <name>
   ```

   A browser window opens for Google consent. Tokens get sealed into the
   OS keychain (Keychain on macOS; Secret Service on Linux; Credential
   Manager on Windows). The `--agent <name>` flag is required (Story 7.13
   verb rename); `connect` composes credential sealing + policy update +
   agent rebind in one idempotent command.

3. **Start the daemon**:

   ```sh
   agentsso start
   ```

   It listens on `127.0.0.1:3820` by default. Point your MCP client at
   `http://127.0.0.1:3820/mcp` with transport `streamable-http`.

4. **Inspect activity**:

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
# See docs/user-guide/install.md → "Device-flow OAuth client setup".
agentsso connect gmail --oauth-client ./client_secret_device.json --agent ci-bot \
  --device-flow --device-flow-timeout 300 --non-interactive
AGENTSSO_BEARER_TOKEN=$(agentsso agent register ci-bot --policy default --json | jq -r .bearer_token)
agentsso autostart enable
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

On macOS, `su`-ing to a user that is not the foreground GUI user also
requires unlocking that user's login keychain in the same shell:

```sh
security unlock-keychain ~/Library/Keychains/login.keychain-db
```

Otherwise the keychain rejects the master-key probe with `User
interaction is not allowed`.

#### Recovery after `brew upgrade agentsso`

`brew upgrade agentsso` reinstalls the binary with a different codesign
hash, which invalidates the macOS Keychain ACL on the existing
master-key entry. Symptom: the next `agentsso start &` logs
`keychain backend 'apple' is unavailable: User interaction is not allowed.
(OSStatus -25308)`.

Behavior on rc.12 and later, by context:

- **Interactive terminal (or SSH with TTY)**: the daemon drops to a
  passphrase prompt automatically. Type any passphrase you'll
  remember; the daemon mints a fresh master key under that
  passphrase and stores `~/.agentsso/keystore/passphrase.state` to
  remember the choice across restarts. **The fallback's derived key
  cannot unseal credentials sealed under the previous native key**,
  so existing connectors are stale until you re-run `connect`.
- **launchd-managed contexts (legacy `brew services start agentsso`,
  Story 7.16's `agentsso autostart enable`) / `ssh -T`**: no
  controlling terminal. The daemon fails fast with a structured
  `PassphrasePromptUnavailable` error. The recovery path is one of
  the manual steps below, run from an interactive shell.

Two recovery paths after fallback fires (or for the headless case):

1. **(Preferred)** Re-run `agentsso connect gmail --oauth-client ... --agent <name>`
   under the new master key. Any other configured connectors must be
   re-connected too. The vault is preserved; only the OAuth seal
   regenerates.
2. **(Faster, but loses unrelated state)** Wipe the keychain entry,
   the passphrase fallback state, and the vault, then let the daemon
   mint a fresh master key on next boot:

   ```sh
   agentsso stop 2>/dev/null
   security delete-generic-password -s io.permitlayer.master-key -a master
   rm -rf ~/.agentsso/vault ~/.agentsso/keystore/passphrase.state
   agentsso start &
   ```

For diagnostic detail, run with `AGENTSSO_LOG__LEVEL=debug` (the daemon
does not honor `RUST_LOG`).

> **Known gap (still tracked for v0.4):** headless launchd recovery
> remains unsolved. Both legacy `brew services start agentsso` (now
> dropped per Story 7.16) and `agentsso autostart enable` cannot prompt
> for a passphrase from a non-interactive launchd context, so they
> still require manual `security` / `agentsso connect` recovery from an
> interactive shell. Real fix options under consideration:
> `--passphrase-from-env`, vault rekey on detected ACL break, or keychain
> partition-list authorization on install.

### Running the daemon and the agent under different OS users

A common multi-user pattern: run the daemon as one user (e.g.
`vault-keeper`) so the OAuth refresh token and master key live in a
filesystem the agent's OS user (e.g. `agent`) cannot read. The agent
talks to the daemon over loopback with a bearer token issued by
`agentsso agent register`.

All control-plane CLI commands (`agent register`, `agent list`,
`agent remove`, `kill`, `resume`, `reload`, `connectors list`,
`status --connections`) require an operator authentication token.
The daemon mints `<home>/control.token` (mode `0o600`) at startup
and persists it across restarts.

**Same-user invocation** reads the token automatically from the
daemon owner's home directory (the file is mode `0o600`, only
readable by the owner):

```sh
# As the daemon-owner user:
agentsso agent list
agentsso kill
```

**Cross-user invocation** requires the operator to share the token
explicitly via the `AGENTSSO_CONTROL_TOKEN` env var. The calling user
cannot read `<home>/control.token` from a different user's home (mode
`0o600` blocks it):

```sh
# As the agent user, against a daemon owned by a different user:
AGENTSSO_CONTROL_TOKEN=$(sudo cat /Users/<svc-user>/.agentsso/control.token) \
AGENTSSO_HTTP__BIND_ADDR=127.0.0.1:3820 \
  agentsso agent register angie --policy gmail-read-only
```

If the daemon owner has overridden the default `127.0.0.1:3820`,
point the caller at the right port via `AGENTSSO_HTTP__BIND_ADDR`.

**Token rotation.** The token survives daemon restarts (Codex review
finding from 2026-05-05: rotating on every restart would break ops
automation that holds the token). To rotate explicitly, stop the
daemon, delete `<home>/control.token`, and start the daemon again —
it'll mint a fresh token. All in-flight tokens lose access as soon
as the file is replaced.

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
