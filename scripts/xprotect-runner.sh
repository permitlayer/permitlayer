#!/bin/sh
# xprotect-runner.sh — macOS-only cargo target runner that ad-hoc
# codesigns test binaries before launch so XProtect / `syspolicyd`
# skips its ~6-8s first-launch trust scan.
#
# Wired into .cargo/config.toml under
# `[target.'cfg(target_os = "macos")'] runner = "scripts/xprotect-runner.sh"`.
# Invoked by cargo for `cargo run|test|bench` and by nextest for
# `cargo nextest list|run`. NOT invoked for `cargo build` or direct
# `./target/debug/deps/<binary>` launches.
#
# Story 8.8a — repo-local experiment. See the Story 8.8a spec for
# framing, measurement protocol, and known limitations (build-script
# binaries are NOT covered; MDM-overridden environments fail open).
#
# # Design
#
# `codesign --sign=- --force` adds an ad-hoc signature (no identity
# required). macOS XProtect caches its scan verdict by binary hash —
# once a signed binary has been seen, subsequent launches skip the
# scan. cargo's own PR #15908 uses this same technique in its
# benchmarking methodology.
#
# The fast path uses an extended attribute `com.permitlayer.xprotect-signed`
# as the "already processed" marker — NOT `codesign -dv`, which only
# proves the binary has some signature (every `--force` replaces whatever
# was there, and `--sign=-` replaces its own signatures, so `codesign -dv`
# is useless for idempotence). The xattr is lost when cargo relinks (new
# inode), which is exactly the right signal for "re-sign on rebuild."
#
# # Invariants
#
# - POSIX sh only (not bash). Matches scripts/bootstrap.sh discipline.
# - `set -eu`. Any unset var or unchecked non-zero exit is a bug.
# - stderr for diagnostics; stdout is NEVER touched (nextest's list
#   phase parses stdout and breaks on surprise output).
# - Fail-open: signing failures never block builds. The runner logs
#   once per shell via a sentinel env var and falls through to exec.
# - Final `exec "$@"` preserves PID, signals, stdin/stdout/stderr,
#   and exit code — critical for test harnesses that `waitpid` or
#   send signals to the child.

set -eu

RUNNER_VERSION="v1"
MARKER="com.permitlayer.xprotect-signed"

# 1. Missing args → exit 0. Cargo always passes at least the binary
#    path in normal use; this guard is defensive for direct manual
#    invocation. Checked before touching `$1` so `set -u` stays happy.
if [ $# -lt 1 ]; then
    exit 0
fi

# 2. Non-executable first arg → exec directly. Cargo occasionally hands
#    runners non-binary targets during custom build flows. If `exec`
#    can't run the target it will fail — that's the correct signal.
if [ ! -x "$1" ]; then
    exec "$@"
fi

# 3. Non-macOS → exec directly. The cfg(target_os = "macos") gate in
#    .cargo/config.toml should prevent this, but defense-in-depth.
if [ "$(uname -s)" != "Darwin" ]; then
    exec "$@"
fi

# 4. Missing codesign → one-time warning to stderr, then exec. The
#    sentinel env var is `export`ed into child processes so a single
#    nextest run with dozens of binary launches produces one line,
#    not dozens.
if ! command -v codesign >/dev/null 2>&1; then
    if [ -z "${PERMITLAYER_XPROTECT_WARNED:-}" ]; then
        printf 'xprotect-runner: codesign not found; skipping sign-and-bypass\n' >&2
        export PERMITLAYER_XPROTECT_WARNED=1
    fi
    exec "$@"
fi

# 5. Fast path: xattr marker present with matching runner version →
#    binary was already processed by this runner for this exact build.
#    Skip signing and exec immediately.
current_marker=$(xattr -p "$MARKER" "$1" 2>/dev/null || true)
if [ "$current_marker" = "$RUNNER_VERSION" ]; then
    exec "$@"
fi

# 6. Sign. Failures are non-fatal — fall through to step 7 either way.
#    - --sign=- : ad-hoc (no identity, no keychain).
#    - --force : replace any prior signature (linker signatures, prior
#      runner passes from an older $RUNNER_VERSION, etc).
#    - --timestamp=none : no Apple timestamp server round-trip.
#    - --preserve-metadata=entitlements : harmless for unsigned inputs;
#      defensive against binaries that carry entitlements.
if codesign --sign=- --force --timestamp=none --preserve-metadata=entitlements "$1" >/dev/null 2>&1; then
    # 7. Mark as processed. xattr write can fail on exotic filesystems
    #    (NFS, some fuse mounts) — harmless; the runner will re-sign
    #    on the next launch, foregoing only the warm-path optimization.
    xattr -w "$MARKER" "$RUNNER_VERSION" "$1" >/dev/null 2>&1 || true
else
    # Signing failed — likely MDM policy, SIP enforcement, or similar.
    # Log once per shell, continue.
    if [ -z "${PERMITLAYER_XPROTECT_SIGN_FAILED:-}" ]; then
        printf 'xprotect-runner: codesign failed for %s; proceeding unsigned\n' "$1" >&2
        export PERMITLAYER_XPROTECT_SIGN_FAILED=1
    fi
fi

# 8. exec. Preserves PID, signals, stdin/stdout/stderr, exit code.
exec "$@"
