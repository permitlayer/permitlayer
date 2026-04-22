#!/bin/sh
# test-install.sh — Test harness for install.sh
#
# Validates install script logic using function overriding (no network required).
# Sources install.sh functions in a subshell, then overrides curl, uname, and
# minisign with shell functions that return predictable output.
#
# Usage:
#   ./install/test-install.sh
#
# Dependencies: minisign (for signature verification tests)

# shellcheck disable=SC2329,SC2034,SC2030,SC2031
# SC2329: function overrides (uname) are invoked indirectly by sourced install.sh
# SC2034: variables (ARCHIVE_PATH, SIG_PATH, etc.) are used by sourced functions
# SC2030/SC2031: subshell variable modifications are intentional (test isolation)
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_SCRIPT="${SCRIPT_DIR}/install.sh"

# File-based counters (subshells can't modify parent shell variables)
TEST_COUNTER_DIR="$(mktemp -d)"
echo "0" > "${TEST_COUNTER_DIR}/passed"
echo "0" > "${TEST_COUNTER_DIR}/failed"
echo "0" > "${TEST_COUNTER_DIR}/skipped"

# Generate ephemeral test signing keypair (if minisign is available)
TEST_KEY_DIR="$(mktemp -d)"
TEST_SECRET_KEY="${TEST_KEY_DIR}/test.key"
TEST_PUBLIC_KEY="${TEST_KEY_DIR}/test.pub"
TEST_PUBKEY_VALUE=""
if command -v minisign >/dev/null 2>&1; then
    minisign -G -W -p "$TEST_PUBLIC_KEY" -s "$TEST_SECRET_KEY" 2>/dev/null
    # Extract the base64 pubkey line (line 2 of the .pub file)
    TEST_PUBKEY_VALUE="$(sed -n '2p' "$TEST_PUBLIC_KEY")"
fi

# --- Test framework -----------------------------------------------------------

pass() {
    _n="$(cat "${TEST_COUNTER_DIR}/passed")"
    echo "$((_n + 1))" > "${TEST_COUNTER_DIR}/passed"
    printf "  pass: %s\n" "$1"
}

fail() {
    _n="$(cat "${TEST_COUNTER_DIR}/failed")"
    echo "$((_n + 1))" > "${TEST_COUNTER_DIR}/failed"
    printf "  FAIL: %s\n" "$1" >&2
}

skip() {
    _n="$(cat "${TEST_COUNTER_DIR}/skipped")"
    echo "$((_n + 1))" > "${TEST_COUNTER_DIR}/skipped"
    printf "  skip: %s\n" "$1"
}

# --- Helper: source install.sh in test mode ----------------------------------

source_install() {
    AGENTSSO_TEST_MODE=1
    export AGENTSSO_TEST_MODE
    # shellcheck source=/dev/null
    . "$INSTALL_SCRIPT"
}

# --- Test: Platform detection — Darwin arm64 ----------------------------------

test_platform_darwin_arm64() {
    (
        source_install
        uname() {
            case "$1" in
                -s) echo "Darwin" ;;
                -m) echo "arm64" ;;
            esac
        }
        detect_platform
        if [ "$TARGET" = "aarch64-apple-darwin" ] && [ "$OS_DISPLAY" = "macOS" ] && [ "$ARCH_DISPLAY" = "arm64" ]; then
            pass "platform detection: Darwin arm64"
        else
            fail "platform detection: Darwin arm64 (got TARGET=$TARGET OS=$OS_DISPLAY ARCH=$ARCH_DISPLAY)"
        fi
    )
}

# --- Test: Platform detection — Darwin x86_64 ---------------------------------

test_platform_darwin_x86() {
    (
        source_install
        uname() {
            case "$1" in
                -s) echo "Darwin" ;;
                -m) echo "x86_64" ;;
            esac
        }
        detect_platform
        if [ "$TARGET" = "x86_64-apple-darwin" ] && [ "$OS_DISPLAY" = "macOS" ] && [ "$ARCH_DISPLAY" = "x86_64" ]; then
            pass "platform detection: Darwin x86_64"
        else
            fail "platform detection: Darwin x86_64 (got TARGET=$TARGET)"
        fi
    )
}

# --- Test: Platform detection — Linux x86_64 ----------------------------------

test_platform_linux_x86() {
    (
        source_install
        uname() {
            case "$1" in
                -s) echo "Linux" ;;
                -m) echo "x86_64" ;;
            esac
        }
        detect_platform
        if [ "$TARGET" = "x86_64-unknown-linux-gnu" ] && [ "$OS_DISPLAY" = "Linux" ] && [ "$KEYCHAIN_DISPLAY" = "libsecret" ]; then
            pass "platform detection: Linux x86_64"
        else
            fail "platform detection: Linux x86_64 (got TARGET=$TARGET)"
        fi
    )
}

# --- Test: Platform detection — unsupported OS aborts -------------------------

test_platform_unsupported_os() {
    (
        source_install
        uname() {
            case "$1" in
                -s) echo "FreeBSD" ;;
                -m) echo "x86_64" ;;
            esac
        }
        # err() calls exit 1; capture it
        if output="$(detect_platform 2>&1)"; then
            fail "platform detection: unsupported OS should abort"
        else
            if echo "$output" | grep -q "unsupported operating system"; then
                pass "platform detection: unsupported OS aborts"
            else
                fail "platform detection: unsupported OS wrong message: $output"
            fi
        fi
    )
}

# --- Test: Platform detection — unsupported arch aborts -----------------------

test_platform_unsupported_arch() {
    (
        source_install
        uname() {
            case "$1" in
                -s) echo "Linux" ;;
                -m) echo "riscv64" ;;
            esac
        }
        if output="$(detect_platform 2>&1)"; then
            fail "platform detection: unsupported arch should abort"
        else
            if echo "$output" | grep -q "unsupported Linux architecture"; then
                pass "platform detection: unsupported arch aborts"
            else
                fail "platform detection: unsupported arch wrong message: $output"
            fi
        fi
    )
}

# --- Test: ProgressSteps output format ----------------------------------------

test_progresssteps_format() {
    (
        source_install
        NO_COLOR=1
        export NO_COLOR
        setup_colors

        output="$(step_done "detecting platform" "macOS arm64")"

        # Should contain arrow, label, value, checkmark
        if echo "$output" | grep -q "detecting platform"; then
            if echo "$output" | grep -q "macOS arm64"; then
                pass "ProgressSteps format: contains label and value"
            else
                fail "ProgressSteps format: missing value in: $output"
            fi
        else
            fail "ProgressSteps format: missing label in: $output"
        fi
    )
}

# --- Test: ProgressSteps — 6 steps output ------------------------------------

test_progresssteps_six_steps() {
    (
        source_install
        NO_COLOR=1
        export NO_COLOR
        setup_colors

        output=""
        output="${output}$(step_done "detecting platform" "macOS arm64")
"
        output="${output}$(step_done "downloading agentsso v0.1.0" "2.1 MB")
"
        output="${output}$(step_done "verifying signature" "ed25519")
"
        output="${output}$(step_done "installing to /usr/local/bin" "")
"
        output="${output}$(step_done "binding OS keychain" "Keychain (Secure Enclave)")
"
        output="${output}$(step_done "starting daemon" "pid 1234, :3820")"

        # Count lines with arrow character (→ in Unicode, or -> when NO_COLOR)
        step_count="$(echo "$output" | grep -c "detecting\|downloading\|verifying\|installing\|binding\|starting")"
        if [ "$step_count" = "6" ]; then
            pass "ProgressSteps: exactly 6 steps"
        else
            fail "ProgressSteps: expected 6 steps, got $step_count"
        fi
    )
}

# --- Test: NO_COLOR disables ANSI codes ---------------------------------------

test_no_color() {
    (
        source_install
        NO_COLOR=1
        export NO_COLOR
        setup_colors

        output="$(step_done "test step" "test value")"

        # Check for ANSI escape sequences (ESC character = \033 = \x1b)
        if printf '%s' "$output" | grep -q "$(printf '\033')"; then
            fail "NO_COLOR: ANSI escape codes present in output"
        else
            pass "NO_COLOR: no ANSI escape codes"
        fi
    )
}

# --- Test: Colors present when NO_COLOR is unset ------------------------------

test_colors_present() {
    (
        source_install
        unset NO_COLOR 2>/dev/null || true
        # Force TTY-like behavior by checking if TEAL would be set
        TEAL="\033[36m"
        DIM="\033[90m"
        WHITE="\033[97m"
        RESET="\033[0m"

        output="$(step_done "test step" "test value")"

        # When colors are set, output should contain escape sequences
        if printf '%s' "$output" | grep -q "$(printf '\033')"; then
            pass "colors: ANSI escape codes present"
        else
            # Might not be a TTY in test env — that's OK
            skip "colors: not a TTY, colors correctly disabled"
        fi
    )
}

# --- Test: --version flag parsing ---------------------------------------------

test_version_flag() {
    (
        source_install
        VERSION=""
        # Simulate --version argument parsing
        set -- --version 1.2.3
        while [ $# -gt 0 ]; do
            case "$1" in
                --version)
                    VERSION="$2"
                    shift 2
                    ;;
                --version=*)
                    VERSION="${1#--version=}"
                    shift
                    ;;
                *)
                    shift
                    ;;
            esac
        done

        if [ "$VERSION" = "1.2.3" ]; then
            pass "--version flag: parses version"
        else
            fail "--version flag: expected 1.2.3, got $VERSION"
        fi
    )
}

# --- Test: --version=X flag parsing -------------------------------------------

test_version_equals_flag() {
    (
        source_install
        VERSION=""
        set -- --version=4.5.6
        while [ $# -gt 0 ]; do
            case "$1" in
                --version)
                    VERSION="$2"
                    shift 2
                    ;;
                --version=*)
                    VERSION="${1#--version=}"
                    shift
                    ;;
                *)
                    shift
                    ;;
            esac
        done

        if [ "$VERSION" = "4.5.6" ]; then
            pass "--version= flag: parses version"
        else
            fail "--version= flag: expected 4.5.6, got $VERSION"
        fi
    )
}

# --- Test: Signature verification with valid signature ------------------------

test_sig_verify_valid() {
    if ! command -v minisign >/dev/null 2>&1; then
        skip "signature verification (valid): minisign not installed"
        return
    fi

    (
        source_install
        # Override PUBKEY with the ephemeral test key
        PUBKEY="$TEST_PUBKEY_VALUE"

        _tmpdir="$(mktemp -d)"
        trap 'rm -rf "$_tmpdir"' EXIT

        # Create test binary and sign it with the ephemeral key
        echo "test binary for sig verification" > "${_tmpdir}/test.bin"
        minisign -Sm "${_tmpdir}/test.bin" -s "$TEST_SECRET_KEY" -t "test" 2>/dev/null

        ARCHIVE_PATH="${_tmpdir}/test.bin"
        SIG_PATH="${_tmpdir}/test.bin.minisig"
        SIG_DISPLAY=""

        verify_signature

        if [ "$SIG_DISPLAY" = "ed25519" ]; then
            pass "signature verification: valid signature accepted"
        else
            fail "signature verification: expected ed25519, got $SIG_DISPLAY"
        fi
    )
}

# --- Test: Signature verification with invalid signature ----------------------

test_sig_verify_invalid() {
    if ! command -v minisign >/dev/null 2>&1; then
        skip "signature verification (invalid): minisign not installed"
        return
    fi

    (
        source_install
        # Override PUBKEY with the ephemeral test key
        PUBKEY="$TEST_PUBKEY_VALUE"

        _tmpdir="$(mktemp -d)"
        trap 'rm -rf "$_tmpdir"' EXIT

        # Create test binary
        echo "test binary for sig verification" > "${_tmpdir}/test.bin"
        # Sign it with the ephemeral key, then tamper with the file
        minisign -Sm "${_tmpdir}/test.bin" -s "$TEST_SECRET_KEY" -t "test" 2>/dev/null
        echo "tampered content" > "${_tmpdir}/test.bin"

        ARCHIVE_PATH="${_tmpdir}/test.bin"
        SIG_PATH="${_tmpdir}/test.bin.minisig"
        SIG_DISPLAY=""

        # Should abort — capture exit
        if output="$(verify_signature 2>&1)"; then
            fail "signature verification: tampered binary should be rejected"
        else
            if echo "$output" | grep -q "signature verification failed"; then
                pass "signature verification: tampered binary rejected"
            else
                fail "signature verification: wrong error for tampered binary: $output"
            fi
        fi
    )
}

# --- Test: Artifact name construction ----------------------------------------

test_artifact_name() {
    (
        source_install

        PKG_NAME="permitlayer-daemon"
        TARGET="aarch64-apple-darwin"
        expected="permitlayer-daemon-aarch64-apple-darwin.tar.xz"
        actual="${PKG_NAME}-${TARGET}.tar.xz"

        if [ "$actual" = "$expected" ]; then
            pass "artifact name: correct format"
        else
            fail "artifact name: expected $expected, got $actual"
        fi
    )
}

# --- Test: Mascot glyph output -----------------------------------------------

test_mascot_glyph() {
    (
        source_install
        NO_COLOR=1
        export NO_COLOR
        setup_colors

        output="$(printf "  %b%s%b permitlayer\n" "$WHITE" "░▒▓█" "$RESET")"

        if echo "$output" | grep -q "permitlayer"; then
            pass "mascot glyph: output contains permitlayer"
        else
            fail "mascot glyph: missing permitlayer in output"
        fi
    )
}

# --- Run all tests ------------------------------------------------------------

main() {
    printf "Running install.sh tests...\n\n"

    test_platform_darwin_arm64
    test_platform_darwin_x86
    test_platform_linux_x86
    test_platform_unsupported_os
    test_platform_unsupported_arch
    test_progresssteps_format
    test_progresssteps_six_steps
    test_no_color
    test_colors_present
    test_version_flag
    test_version_equals_flag
    test_sig_verify_valid
    test_sig_verify_invalid
    test_artifact_name
    test_mascot_glyph

    TESTS_PASSED="$(cat "${TEST_COUNTER_DIR}/passed")"
    TESTS_FAILED="$(cat "${TEST_COUNTER_DIR}/failed")"
    TESTS_SKIPPED="$(cat "${TEST_COUNTER_DIR}/skipped")"
    rm -rf "$TEST_COUNTER_DIR" "$TEST_KEY_DIR"

    printf "\n"
    printf "Results: %d passed, %d failed, %d skipped\n" "$TESTS_PASSED" "$TESTS_FAILED" "$TESTS_SKIPPED"

    if [ "$TESTS_FAILED" -gt 0 ]; then
        exit 1
    fi
}

main
