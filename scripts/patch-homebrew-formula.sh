#!/bin/sh
# patch-homebrew-formula.sh — inject a class-doc comment, a `caveats`
# block, and a `service do` block into a dist-generated Homebrew formula.
#
# dist (cargo-dist 0.31) generates a Homebrew formula from a fixed Jinja
# template (cargo-dist/templates/installer/homebrew.rb.j2) that does NOT
# emit a class-doc comment, `caveats`, or `service do`. Story 7.1 requires
# all three:
#
#   - class-doc comment — required by rubocop's `Style/Documentation`
#     cop that `brew style --fix` enforces but cannot autocorrect.
#   - `caveats` — users need post-install instructions pointing at
#     `agentsso setup gmail` as the next step.
#   - `service do` — `brew services start agentsso` needs this block
#     to register a launchd plist at `homebrew.mxcl.agentsso`.
#
# This script performs two injections in a single awk pass:
#
#   1. Prepend a one-line `# ... formula.` comment immediately above
#      the `class Agentsso < Formula` line (anchor: `^class Agentsso`).
#
#   2. Insert the service + caveats snippet (from
#      scripts/homebrew-service-block.rb.snippet) immediately before the
#      first flush-left `^end$` (the one that closes the class body).
#      dist's template indents every inner-method `end` with two spaces,
#      so `^end$` is stable against changes inside methods.
#
# If dist's template ever reshapes such that either anchor drifts (class
# line not starting with `class Agentsso`, or class-closing `end` no
# longer flush-left), the unit test
# (scripts/test-patch-homebrew-formula.sh) will fail loudly and this
# script needs updating in lockstep with the dist upgrade.
#
# Usage:
#   patch-homebrew-formula.sh <input.rb> [output.rb]
#
# If [output.rb] is omitted, writes to stdout.
#
# Exit codes:
#   0  patch applied successfully
#   1  input file missing or not a regular file, or usage error
#   2  one or both anchors not found — dist template shape changed
#   3  snippet file missing

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SNIPPET_PATH="${SCRIPT_DIR}/homebrew-service-block.rb.snippet"

# The class-doc comment prepended above `class Agentsso < Formula`.
# Kept short — rubocop's Style/Documentation only requires any `#`
# comment; we use this to carry one-line context for a reader opening
# the tap's Formula/agentsso.rb cold.
CLASS_DOC_COMMENT="# Homebrew formula for agentsso, the permitlayer daemon binary."

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "usage: $0 <input.rb> [output.rb]" >&2
    exit 1
fi

INPUT="$1"
OUTPUT="${2:-/dev/stdout}"

if [ ! -f "$INPUT" ]; then
    echo "error: input file not found: $INPUT" >&2
    exit 1
fi

if [ ! -f "$SNIPPET_PATH" ]; then
    echo "error: snippet file not found: $SNIPPET_PATH" >&2
    exit 3
fi

# Verify both anchors exist before touching anything.
if ! grep -q '^class Agentsso' "$INPUT"; then
    echo "error: anchor '^class Agentsso' not found in $INPUT" >&2
    echo "       dist template shape may have changed; update this script." >&2
    exit 2
fi
if ! grep -q '^end$' "$INPUT"; then
    echo "error: anchor '^end$' not found in $INPUT" >&2
    echo "       dist template shape may have changed; update this script." >&2
    exit 2
fi

# Single-pass awk: prepend class-doc comment before the class line,
# append service+caveats snippet before the class-closing `end`.
awk -v snippet_path="$SNIPPET_PATH" -v class_doc="$CLASS_DOC_COMMENT" '
BEGIN {
    # Read the snippet into memory once.
    snippet = ""
    while ((getline line < snippet_path) > 0) {
        snippet = snippet line "\n"
    }
    close(snippet_path)
    doc_emitted = 0
    snippet_emitted = 0
}
/^class Agentsso/ && !doc_emitted {
    print class_doc
    doc_emitted = 1
    print
    next
}
/^end$/ && !snippet_emitted {
    # Emit the snippet immediately before the class-closing `end`,
    # separated by a blank line for readability.
    printf "\n%s", snippet
    snippet_emitted = 1
}
{ print }
END {
    if (!doc_emitted) {
        print "error: class-doc anchor did not match any line" > "/dev/stderr"
        exit 2
    }
    if (!snippet_emitted) {
        print "error: class-closing `end` anchor did not match any line" > "/dev/stderr"
        exit 2
    }
}
' "$INPUT" > "$OUTPUT"
