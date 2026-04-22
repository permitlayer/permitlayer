#!/bin/sh
# sign-release.sh — Sign release artifacts with ed25519 via minisign.
#
# Usage:
#   ./scripts/sign-release.sh <file> [<key-file>]
#   RELEASE_SIGNING_KEY_FILE=/path/to/key ./scripts/sign-release.sh <file>
#
# The signing key can be provided via:
#   1. Second argument: path to minisign secret key file
#   2. RELEASE_SIGNING_KEY_FILE env var: path to minisign secret key file
#   3. RELEASE_SIGNING_KEY env var: key file contents (used in CI)
#
# Key generation:
#   minisign -G -p install/permitlayer.pub -s /path/to/permitlayer.key
#
# The public key is committed at install/permitlayer.pub.
# The secret key is stored as the RELEASE_SIGNING_KEY GitHub secret.

set -eu

if [ $# -lt 1 ]; then
    echo "Usage: $0 <file> [<key-file>]" >&2
    exit 1
fi

FILE="$1"

if [ ! -f "$FILE" ]; then
    echo "error: file not found: $FILE" >&2
    exit 1
fi

# Ensure minisign is available
if ! command -v minisign >/dev/null 2>&1; then
    echo "error: minisign not found. Install with: brew install minisign" >&2
    exit 1
fi

# Resolve key file
KEY_FILE="${2:-}"
if [ -z "$KEY_FILE" ]; then
    KEY_FILE="${RELEASE_SIGNING_KEY_FILE:-}"
fi

CLEANUP_KEY=""
if [ -z "$KEY_FILE" ] && [ -n "${RELEASE_SIGNING_KEY:-}" ]; then
    # Write key contents from env var to temp file (CI use case)
    KEY_FILE="$(mktemp)"
    CLEANUP_KEY="$KEY_FILE"
    trap 'rm -f "$CLEANUP_KEY"' EXIT
    echo "${RELEASE_SIGNING_KEY}" > "$KEY_FILE"
fi

if [ -z "$KEY_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "error: no signing key provided." >&2
    echo "Provide key file as second argument, or set RELEASE_SIGNING_KEY_FILE or RELEASE_SIGNING_KEY env var." >&2
    exit 1
fi

BASENAME="$(basename "$FILE")"
minisign -Sm "$FILE" -s "$KEY_FILE" -t "${BASENAME} signed by permitlayer release pipeline"

echo "Signed: ${FILE}.minisig"

# Clean up temp key file if created
if [ -n "$CLEANUP_KEY" ]; then
    rm -f "$CLEANUP_KEY"
fi
