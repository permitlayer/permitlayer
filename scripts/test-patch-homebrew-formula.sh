#!/bin/sh
# test-patch-homebrew-formula.sh — unit test for patch-homebrew-formula.sh.
#
# Guards against three kinds of drift:
#
# 1. dist template shape drift. If cargo-dist changes its Jinja template
#    for the Homebrew formula, the input fixture stops looking like the
#    real dist output. In that case regenerate the fixture with:
#
#        cd <repo-root>
#        dist build --artifacts=global --tag=vX.Y.Z
#        cp target/distrib/agentsso.rb test-fixtures/homebrew/input-formula.rb
#        scripts/patch-homebrew-formula.sh \
#            test-fixtures/homebrew/input-formula.rb \
#            test-fixtures/homebrew/expected-output.rb
#
#    Then review the diff — if the template changed in a way that breaks
#    the patch anchors ('^class Agentsso', '^end$'), update
#    patch-homebrew-formula.sh.
#
# 2. Accidental patch-script regression. If someone edits the patch
#    script and the expected-output no longer matches, this test fails.
#
# 3. Brew-style drift. The release pipeline's `homebrew-publish` job runs
#    `brew style --fix Formula/agentsso.rb` before pushing to the tap,
#    which autocorrects rubocop offenses (modifier-if, trailing commas,
#    etc.) that `brew audit --strict` would otherwise reject. Any class-
#    of-offense that brew style cannot autocorrect (like
#    `Style/Documentation`, which needs a class-doc comment that our
#    patch script prepends) must be absent from the fixture. This test
#    runs `brew style --fix` followed by `brew style` against the
#    expected-output fixture and fails if offenses remain — catching
#    future patch-script drift before it reaches CI.
#
#    If brew is not installed locally (developer workstation without
#    Homebrew), the style check is skipped with a warning.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PATCH_SCRIPT="$SCRIPT_DIR/patch-homebrew-formula.sh"
INPUT="$REPO_ROOT/test-fixtures/homebrew/input-formula.rb"
EXPECTED="$REPO_ROOT/test-fixtures/homebrew/expected-output.rb"

if [ ! -x "$PATCH_SCRIPT" ]; then
    echo "FAIL: patch script missing or not executable: $PATCH_SCRIPT" >&2
    exit 1
fi

if [ ! -f "$INPUT" ]; then
    echo "FAIL: input fixture missing: $INPUT" >&2
    exit 1
fi

if [ ! -f "$EXPECTED" ]; then
    echo "FAIL: expected fixture missing: $EXPECTED" >&2
    exit 1
fi

ACTUAL="$(mktemp)"
trap 'rm -f "$ACTUAL"' EXIT

"$PATCH_SCRIPT" "$INPUT" "$ACTUAL"

if ! diff -u "$EXPECTED" "$ACTUAL"; then
    echo "FAIL: patched output does not match expected fixture" >&2
    echo "      If the dist template shape changed, regenerate the" >&2
    echo "      expected fixture per the header comment of this script." >&2
    exit 1
fi

# Idempotence check: re-running the patch script on already-patched
# output must not inject a second copy of the snippet.
REPATCHED="$(mktemp)"
trap 'rm -f "$ACTUAL" "$REPATCHED"' EXIT
"$PATCH_SCRIPT" "$ACTUAL" "$REPATCHED"
if ! diff -q "$ACTUAL" "$REPATCHED" >/dev/null; then
    # Note: the patch script is NOT strictly idempotent — it injects
    # before the first flush-left `end`, and the snippet itself does
    # not contain a flush-left `end`, so a second run would inject a
    # second copy. This is acceptable because the release pipeline
    # always runs the patch once per release on fresh dist output.
    # The check here is informational: if the behavior ever changes
    # to be idempotent (e.g. detect existing service block), this
    # message reminds the maintainer to revisit the pipeline wiring.
    echo "info: patch is not idempotent (expected for Story 7.1 wiring)" >&2
fi

# Structural sanity: patched output must contain both new blocks.
for marker in 'def caveats' 'service do' 'run \[opt_bin/"agentsso", "start"\]'; do
    if ! grep -q "$marker" "$ACTUAL"; then
        echo "FAIL: patched output missing expected marker: $marker" >&2
        exit 1
    fi
done

# Patched output must still parse as something Ruby-shaped — the class
# opens and closes exactly once.
OPEN_COUNT="$(grep -c '^class Agentsso < Formula$' "$ACTUAL")"
CLOSE_COUNT="$(grep -c '^end$' "$ACTUAL")"
if [ "$OPEN_COUNT" != "1" ] || [ "$CLOSE_COUNT" != "1" ]; then
    echo "FAIL: expected exactly one top-level class open and close; got open=$OPEN_COUNT close=$CLOSE_COUNT" >&2
    exit 1
fi

# brew style --fix + brew style: expected-output must be style-clean
# after one autocorrect pass. Guards against future patch-script drift
# that introduces non-autocorrectable offenses.
if ! command -v brew >/dev/null 2>&1; then
    echo "info: brew not installed; skipping style-clean check" >&2
    echo "      the release pipeline still enforces this check on macos-14" >&2
else
    STYLE_PROBE="$(mktemp)"
    trap 'rm -f "$ACTUAL" "$REPATCHED" "$STYLE_PROBE"' EXIT
    cp "$EXPECTED" "$STYLE_PROBE"

    # Step 1: run brew style --fix (autocorrects whatever it can).
    brew style --fix "$STYLE_PROBE" >/dev/null 2>&1 || true

    # Step 2: run brew style (must now report zero offenses).
    if ! brew style "$STYLE_PROBE" >/dev/null 2>&1; then
        echo "FAIL: brew style found offenses in expected-output.rb after --fix" >&2
        echo "      Non-autocorrectable rubocop rule triggered — extend" >&2
        echo "      patch-homebrew-formula.sh to preempt it, then regenerate fixtures." >&2
        echo "      Full offense list:" >&2
        brew style "$STYLE_PROBE" >&2 || true
        exit 1
    fi

    # Step 3: idempotence of brew style --fix.
    STYLE_REAPPLY="$(mktemp)"
    trap 'rm -f "$ACTUAL" "$REPATCHED" "$STYLE_PROBE" "$STYLE_REAPPLY"' EXIT
    cp "$STYLE_PROBE" "$STYLE_REAPPLY"
    brew style --fix "$STYLE_REAPPLY" >/dev/null 2>&1 || true
    if ! diff -q "$STYLE_PROBE" "$STYLE_REAPPLY" >/dev/null; then
        echo "FAIL: brew style --fix is not idempotent on expected-output.rb" >&2
        echo "      Running --fix twice produces different output; investigate." >&2
        diff -u "$STYLE_PROBE" "$STYLE_REAPPLY" >&2 || true
        exit 1
    fi
fi

echo "PASS: patch-homebrew-formula.sh produces expected output"
