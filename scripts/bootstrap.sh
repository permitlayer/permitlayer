#!/bin/sh
# permitlayer contributor bootstrap — installs the Rust toolchain pinned by
# rust-toolchain.toml and ensures `cargo` is available in future shells.
#
# Idempotent: safe to run repeatedly. Supports macOS + Linux.
# Windows contributors: install rustup from https://rustup.rs, then re-open
# your shell and run `cargo install cargo-nextest --locked && cargo nextest run --workspace`.

set -eu

CARGO_ENV="$HOME/.cargo/env"
SOURCE_LINE='. "$HOME/.cargo/env"'

# 1. Already on PATH? Nothing to do.
if command -v cargo >/dev/null 2>&1; then
    printf 'cargo already on PATH (%s) — nothing to do.\n' "$(command -v cargo)"
    exit 0
fi

# 2. Installed but not sourced? Wire it into the user's shell rc and exit.
if [ -x "$HOME/.cargo/bin/cargo" ]; then
    printf 'cargo is installed but not on PATH in this shell.\n'
else
    # 3. Not installed at all — fetch rustup non-interactively. Using
    #    --default-toolchain none lets rust-toolchain.toml drive the version
    #    on first cargo invocation, matching CI.
    printf 'Installing rustup (https://rustup.rs)...\n'
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain none --profile minimal

    # Fetch the toolchain pinned by rust-toolchain.toml now, so the first
    # `cargo` invocation isn't a surprise download.
    SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
    REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
    (cd "$REPO_ROOT" && "$HOME/.cargo/bin/rustup" show)
fi

# Pick the rc file that matches the user's login shell.
case "${SHELL:-}" in
    */zsh)  RC_FILE="$HOME/.zshrc" ;;
    */bash)
        # macOS bash reads .bash_profile on login; Linux bash reads .bashrc.
        if [ "$(uname -s)" = "Darwin" ]; then
            RC_FILE="$HOME/.bash_profile"
        else
            RC_FILE="$HOME/.bashrc"
        fi
        ;;
    *)      RC_FILE="" ;;
esac

if [ -n "$RC_FILE" ]; then
    # Append only if the sourcing line isn't already there (any form).
    if [ -f "$RC_FILE" ] && grep -qs '\.cargo/env' "$RC_FILE"; then
        printf '%s already sources ~/.cargo/env — skipping rc edit.\n' "$RC_FILE"
    else
        printf '\n# Rust (rustup)\n%s\n' "$SOURCE_LINE" >> "$RC_FILE"
        printf 'Appended cargo env sourcing to %s\n' "$RC_FILE"
    fi
else
    printf 'Unknown shell (%s) — add this line to your shell rc manually:\n  %s\n' \
        "${SHELL:-unset}" "$SOURCE_LINE"
fi

printf '\nDone. Activate cargo in THIS shell with:\n  %s\n' "$SOURCE_LINE"
printf 'Or open a new terminal. Then run the post-install steps below.\n'

# Source cargo into the current shell so we can install nextest immediately
# if cargo is now available.
if [ -f "$CARGO_ENV" ]; then
    # shellcheck disable=SC1090
    . "$CARGO_ENV"
fi

# Install cargo-nextest (the test runner used by this project).
if command -v cargo >/dev/null 2>&1; then
    if ! cargo nextest --version >/dev/null 2>&1; then
        printf '\nInstalling cargo-nextest...\n'
        cargo install cargo-nextest --locked
    else
        printf '\ncargo-nextest already installed — skipping.\n'
    fi
else
    printf '\ncargo not on PATH yet — install cargo-nextest manually after restarting your shell:\n'
    printf '  cargo install cargo-nextest --locked\n'
fi

# macOS-specific setup advice.
if [ "$(uname -s)" = "Darwin" ]; then
    printf '\n--- macOS setup (one-time) ---\n'
    if ! brew list lld >/dev/null 2>&1; then
        printf 'Installing lld (faster linker)...\n'
        brew install lld
    else
        printf 'lld already installed — skipping.\n'
    fi

    printf '\nIMPORTANT: One-time macOS setup to reduce XProtect scanning overhead:\n'
    printf '  sudo spctl developer-mode enable-terminal\n'
    printf 'Then enable YOUR terminal app in System Settings → Privacy & Security →\n'
    printf 'Developer Tools (e.g. Terminus, iTerm2, Warp — not just "Terminal") and\n'
    printf 'fully quit and relaunch it. This can substantially reduce first-launch\n'
    printf 'delays when running test binaries.\n'
    printf 'NOTE: if you run cargo inside tmux, the exemption may not apply — run\n'
    printf 'directly in your terminal to confirm. See README.md for details.\n'
    printf '\nNote: we investigated ad-hoc codesigning via a cargo runner\n'
    printf 'at scripts/xprotect-runner.sh. Measurement on 2026-04-21 showed no\n'
    printf 'measurable speedup (hash change from signing triggers a fresh scan),\n'
    printf 'so the runner is NOT wired in .cargo/config.toml today. The script\n'
    printf 'is retained for future experimentation.\n'
    printf '\nIf cargo nextest run appears completely hung, syspolicyd may have a scan\n'
    printf 'backlog from a prior run. Clear it with:\n'
    printf '  sudo killall syspolicyd\n'
    printf '(launchd restarts it automatically within seconds) — the bulk of slow\n'
    printf 'runs on this project come from this backlog state, not per-binary scan\n'
    printf 'cost.\n'
fi

printf '\nAll set! Run the test suite with:\n  cargo nextest run --workspace\n'
