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
agentsso setup gmail
```

To run the daemon under a Homebrew-managed `launchd` service:

```sh
brew services start agentsso
```

See [docs/user-guide/install.md](docs/user-guide/install.md) for the
full Homebrew lifecycle (`brew upgrade`, `brew uninstall`, how it
coexists with `agentsso autostart enable`).

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

2. **Authorize Gmail** (or `calendar`, `drive`):

   ```sh
   agentsso setup gmail --oauth-client ./client_secret_XXXX.json
   ```

   A browser window opens for Google consent. Tokens get sealed into the
   OS keychain (Keychain on macOS; Secret Service on Linux; Credential
   Manager on Windows).

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

### Setup over SSH or under `su`

If `agentsso setup` cannot reach a usable browser (SSH session, `su user`
without GUI access, headless server, etc.), pass `--no-browser` to
print the authorization URL instead of launching a browser:

```sh
agentsso setup gmail --oauth-client ./client_secret.json --no-browser
```

Open the printed URL in any browser that can reach `127.0.0.1` on this
host (the local callback server is loopback-bound). After consent, the
redirect lands automatically. If your browser is on a different
machine, copy the resulting redirect URL and `curl` it from the host
running setup.

On macOS, `su`-ing to a user that is not the foreground GUI user also
requires unlocking that user's login keychain in the same shell:

```sh
security unlock-keychain ~/Library/Keychains/login.keychain-db
```

Otherwise the keychain rejects the master-key probe with `User
interaction is not allowed`.

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
