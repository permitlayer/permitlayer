#!/bin/sh
# install.sh — curl | sh installer for agentsso
# POSIX sh compatible (no bashisms). Works on macOS /bin/sh and Linux dash.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/permitlayer/permitlayer/main/install/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/permitlayer/permitlayer/main/install/install.sh | sh -s -- --version 0.2.0
#
# Environment:
#   NO_COLOR=1  — disable ANSI color output
#   AGENTSSO_INSTALL_DIR — override install directory (default: /usr/local/bin)

set -eu

# --- Configuration -----------------------------------------------------------

REPO_OWNER="permitlayer"
REPO_NAME="permitlayer"
BIN_NAME="agentsso"
PKG_NAME="permitlayer-daemon"
INSTALL_DIR="${AGENTSSO_INSTALL_DIR:-/usr/local/bin}"
AGENTSSO_HOME="${HOME}/.agentsso"
PID_FILE="${AGENTSSO_HOME}/agentsso.pid"
DAEMON_LOG="${AGENTSSO_HOME}/daemon.log"
DEFAULT_PORT="3820"

# Minisign ed25519 public key for release signature verification.
# Generated with: minisign -G -p install/permitlayer.pub -s <secret>
# Mirror of install/permitlayer.pub — if these diverge, release verification
# will fail on downloaded tarballs.
# untrusted comment: minisign public key D67754E8C6888574
PUBKEY="RWR0hYjG6FR31smbyN0CT1/Pfg+yl8nTATUaIAq4jUXlvvFOckj99ipC"

# --- Color helpers ------------------------------------------------------------

setup_colors() {
    if [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
        TEAL=""
        DIM=""
        WHITE=""
        RESET=""
    else
        TEAL="\033[36m"
        DIM="\033[90m"
        WHITE="\033[97m"
        RESET="\033[0m"
    fi
}

# --- Output helpers -----------------------------------------------------------

# Print a completed step in ProgressSteps format (UX-DR9)
# Usage: step_done "step label" "value"
step_done() {
    _label="$1"
    _value="$2"
    # Pad label to align values (longest label is ~32 chars)
    if [ -n "$_value" ]; then
        printf "  %b\342\206\222 %-36s%b%b%s%b %b\342\234\223%b\n" \
            "$DIM" "$_label" "$RESET" \
            "$WHITE" "$_value" "$RESET" \
            "${TEAL}" "${RESET}"
    else
        printf "  %b\342\206\222 %-36s%b%b\342\234\223%b\n" \
            "$DIM" "$_label" "$RESET" \
            "${TEAL}" "${RESET}"
    fi
}

err() {
    printf "  error: %s\n" "$1" >&2
    exit 1
}

warn() {
    printf "  warning: %s\n" "$1" >&2
}

# --- Argument parsing ---------------------------------------------------------

VERSION=""
FORCE=0
ALLOW_DOWNGRADE=0
ALLOW_UNSIGNED=0
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
        --force)
            FORCE=1
            shift
            ;;
        --allow-downgrade)
            ALLOW_DOWNGRADE=1
            shift
            ;;
        --allow-unsigned)
            ALLOW_UNSIGNED=1
            shift
            ;;
        *)
            err "unknown argument: $1"
            ;;
    esac
done

# --- Platform detection -------------------------------------------------------

detect_platform() {
    _os="$(uname -s)"
    _arch="$(uname -m)"

    case "$_os" in
        Darwin)
            OS_DISPLAY="macOS"
            case "$_arch" in
                arm64)
                    TARGET="aarch64-apple-darwin"
                    ARCH_DISPLAY="arm64"
                    KEYCHAIN_DISPLAY="Keychain (Secure Enclave)"
                    ;;
                x86_64)
                    TARGET="x86_64-apple-darwin"
                    ARCH_DISPLAY="x86_64"
                    KEYCHAIN_DISPLAY="Keychain (Secure Enclave)"
                    ;;
                *)
                    err "unsupported macOS architecture: $_arch"
                    ;;
            esac
            ;;
        Linux)
            OS_DISPLAY="Linux"
            case "$_arch" in
                x86_64)
                    TARGET="x86_64-unknown-linux-gnu"
                    ARCH_DISPLAY="x86_64"
                    KEYCHAIN_DISPLAY="libsecret"
                    ;;
                *)
                    err "unsupported Linux architecture: $_arch"
                    ;;
            esac
            ;;
        *)
            err "unsupported operating system: $_os"
            ;;
    esac
}

# --- Version resolution -------------------------------------------------------

resolve_version() {
    if [ -z "$VERSION" ]; then
        VERSION="$(curl -fsSL --connect-timeout 10 --max-time 30 \
            "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest" \
            | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/p')" \
            || err "failed to fetch latest release version from GitHub"
        if [ -z "$VERSION" ]; then
            err "could not determine latest release version"
        fi
    fi
    # Strip leading 'v' if present
    VERSION="${VERSION#v}"
}

# --- Existing installation check ----------------------------------------------

check_existing() {
    _existing="$(command -v "$BIN_NAME" 2>/dev/null || true)"
    if [ -n "$_existing" ]; then
        _current_ver="$("$_existing" --version 2>/dev/null | sed -n 's/.*[[:space:]]\{1,\}\([0-9][0-9.]*\).*/\1/p' || true)"
        if [ "$_current_ver" = "$VERSION" ] && [ "$FORCE" != "1" ]; then
            warn "${BIN_NAME} ${VERSION} is already installed at ${_existing}"
            warn "to reinstall, use --force"
            exit 0
        elif [ "$_current_ver" = "$VERSION" ]; then
            warn "reinstalling ${BIN_NAME} ${VERSION} (--force)"
        elif [ -n "$_current_ver" ]; then
            # Detect downgrades and refuse unless explicitly allowed. A
            # social-engineered `curl | sh --force --version <OLD>` could
            # otherwise install a known-bad previous release silently.
            if _version_is_older "$VERSION" "$_current_ver" && [ "$ALLOW_DOWNGRADE" != "1" ]; then
                err "refusing to downgrade ${BIN_NAME} from ${_current_ver} to ${VERSION}. Re-run with \`--allow-downgrade\` if this is intentional."
            fi
            warn "changing ${BIN_NAME} from ${_current_ver} to ${VERSION} (at ${_existing})"
        fi
    fi
}

# Return 0 if $1 is a strictly-older semver than $2, else 1.
# Uses `sort -V` (GNU coreutils + BSD sort on macOS 13+ both support it).
_version_is_older() {
    _a="$1"
    _b="$2"
    # Identical versions aren't a downgrade.
    if [ "$_a" = "$_b" ]; then
        return 1
    fi
    # If the sorted-first line equals $_a, then $_a < $_b.
    _first="$(printf '%s\n%s\n' "$_a" "$_b" | sort -V | head -n1)"
    [ "$_first" = "$_a" ]
}

# --- Download -----------------------------------------------------------------

download_release() {
    ARTIFACT_NAME="${PKG_NAME}-${TARGET}.tar.xz"
    DOWNLOAD_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/v${VERSION}/${ARTIFACT_NAME}"
    SIG_URL="${DOWNLOAD_URL}.minisig"

    TMPDIR_DL="$(mktemp -d)"
    trap 'rm -rf "$TMPDIR_DL"' EXIT

    ARCHIVE_PATH="${TMPDIR_DL}/${ARTIFACT_NAME}"
    SIG_PATH="${TMPDIR_DL}/${ARTIFACT_NAME}.minisig"

    # Fetch the signature first so we can fail fast if it's missing in
    # non-interactive mode — avoids wasting a large tarball download when
    # the install is going to abort anyway. A dropped .minisig (MITM, cache
    # poisoning, partial release) MUST NOT silently bypass verification.
    #
    # `--retry 5 --retry-delay 2 --retry-all-errors` covers the brief
    # asset-CDN propagation window after a fresh release (~10s on
    # GitHub's edge). Without `--retry-all-errors`, curl's `--retry`
    # only retries on a hardcoded list of transient codes (408, 429,
    # 5xx) and network errors — NOT on the 404 that GitHub's edge
    # returns during the ~5–10s window between `dist host` uploading
    # the asset and the CDN serving it. Surfaced as a re-occurrence
    # in v0.3.0-rc.6's smoke jobs (run 25239722738): the v0.3.0-rc.5
    # round of this fix (PR #9) added `--retry` but missed
    # `--retry-all-errors`, so curl exited 22 in <1s on the 404
    # without retrying. Confirmed by direct curl ~25 minutes later
    # to the same URL: 200 with valid 351-byte minisig content.
    #
    # `--retry-all-errors` requires curl >= 7.71.0 (June 2020).
    # Targets: ubuntu-22.04 (curl 7.81.0), Apple silicon macOS
    # default (Sonoma 8.4.0), Intel macOS recent (Big Sur 7.77.0).
    # All in scope.
    curl -fsSL --connect-timeout 10 --max-time 30 \
        --retry 5 --retry-delay 2 --retry-all-errors \
        -o "$SIG_PATH" "$SIG_URL" 2>/dev/null || SIG_PATH=""
    if [ -z "$SIG_PATH" ] && [ ! -t 0 ] && [ "$ALLOW_UNSIGNED" != "1" ]; then
        err "no signature file available for ${ARTIFACT_NAME} and non-interactive mode is in use. Re-run with \`--allow-unsigned\` to bypass (not recommended) or install interactively."
    fi

    curl -fsSL --connect-timeout 10 --max-time 120 -o "$ARCHIVE_PATH" "$DOWNLOAD_URL" \
        || err "failed to download ${DOWNLOAD_URL}"

    # Calculate download size for display
    if [ -f "$ARCHIVE_PATH" ]; then
        _bytes="$(wc -c < "$ARCHIVE_PATH" | tr -d ' ')"
        _mb="$(echo "scale=1; $_bytes / 1048576" | bc 2>/dev/null || echo "?")"
        DOWNLOAD_SIZE="${_mb} MB"
    else
        DOWNLOAD_SIZE="?"
    fi
}

# --- Signature verification ---------------------------------------------------

verify_signature() {
    if [ -z "$SIG_PATH" ] || [ ! -f "$SIG_PATH" ]; then
        _no_sig_warning
        return
    fi

    # Try minisign first
    if command -v minisign >/dev/null 2>&1; then
        if minisign -Vm "$ARCHIVE_PATH" -P "$PUBKEY" >/dev/null 2>&1; then
            SIG_DISPLAY="ed25519"
            return
        else
            err "signature verification failed. The downloaded binary may be corrupted or tampered with."
        fi
    fi

    # Fallback: try openssl ed25519 verification (available on macOS 13+, modern Linux)
    if command -v openssl >/dev/null 2>&1; then
        if _verify_openssl; then
            SIG_DISPLAY="ed25519 (openssl)"
            return
        else
            err "signature verification failed. The downloaded binary may be corrupted or tampered with."
        fi
    fi

    # Last resort: warn and ask for consent
    _no_sig_warning
}

# Verify ed25519 signature using openssl.
# Minisign signature format: line 1 = untrusted comment, line 2 = base64(2-byte algo + 8-byte keyid + 64-byte sig)
# Minisign pubkey format: base64(2-byte algo + 8-byte keyid + 32-byte ed25519 pubkey)
_verify_openssl() {
    _sig_dir="$(mktemp -d)"

    # Extract raw ed25519 public key (skip 10-byte header: 2 algo + 8 keyid)
    printf '%s' "$PUBKEY" | base64 -d 2>/dev/null | tail -c 32 > "${_sig_dir}/pubkey.raw" || { rm -rf "$_sig_dir"; return 1; }

    # Extract raw ed25519 signature from .minisig (line 2, skip 10-byte header)
    _sig_line="$(sed -n '2p' "$SIG_PATH")"
    printf '%s' "$_sig_line" | base64 -d 2>/dev/null | tail -c 64 > "${_sig_dir}/sig.raw" || { rm -rf "$_sig_dir"; return 1; }

    # Convert raw pubkey to PEM format for openssl
    # Ed25519 public key DER prefix: 302a300506032b6570032100 (12 bytes) + 32-byte key
    printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00' > "${_sig_dir}/pubkey.der"
    cat "${_sig_dir}/pubkey.raw" >> "${_sig_dir}/pubkey.der"
    openssl pkey -inform DER -pubin -in "${_sig_dir}/pubkey.der" -out "${_sig_dir}/pubkey.pem" 2>/dev/null \
        || { rm -rf "$_sig_dir"; return 1; }

    # Verify signature
    _result=0
    openssl pkeyutl -verify -pubin -inkey "${_sig_dir}/pubkey.pem" \
        -rawin -in "$ARCHIVE_PATH" -sigfile "${_sig_dir}/sig.raw" >/dev/null 2>&1 \
        || _result=1

    rm -rf "$_sig_dir"
    return "$_result"
}

_no_sig_warning() {
    if [ -z "$SIG_PATH" ] || [ ! -f "$SIG_PATH" ]; then
        warn "no signature file available for this release"
    else
        warn "minisign not found and openssl unavailable — cannot verify signature. install minisign with: brew install minisign"
    fi

    SIG_DISPLAY="not verified"

    # If stdin is a TTY, ask for consent.
    if [ -t 0 ]; then
        printf "  continue without signature verification? [y/N] "
        read -r _answer </dev/tty
        case "$_answer" in
            y|Y|yes|Yes) ;;
            *) err "aborted by user" ;;
        esac
    elif [ "$ALLOW_UNSIGNED" = "1" ]; then
        warn "non-interactive mode with --allow-unsigned: proceeding without signature verification"
    else
        err "non-interactive mode requires signature verification. install minisign (\`brew install minisign\`) or re-run with \`--allow-unsigned\` to bypass (not recommended)."
    fi
}

# --- Installation -------------------------------------------------------------

install_binary() {
    # Extract binary from tarball
    _extract_dir="${TMPDIR_DL}/extract"
    mkdir -p "$_extract_dir"

    # Handle both .tar.xz and .tar.gz
    case "$ARTIFACT_NAME" in
        *.tar.xz)
            xz -d < "$ARCHIVE_PATH" | tar xf - -C "$_extract_dir" 2>/dev/null \
                || tar xf "$ARCHIVE_PATH" -C "$_extract_dir" \
                || err "failed to extract archive"
            ;;
        *.tar.gz)
            tar xzf "$ARCHIVE_PATH" -C "$_extract_dir" \
                || err "failed to extract archive"
            ;;
        *)
            err "unsupported archive format: ${ARTIFACT_NAME}"
            ;;
    esac

    # Find the binary — dist places it inside a subdirectory
    _bin_path="$(find "$_extract_dir" -name "$BIN_NAME" -type f 2>/dev/null | head -1)"
    if [ -z "$_bin_path" ]; then
        err "binary '${BIN_NAME}' not found in archive"
    fi

    # Install to target directory
    if [ -w "$INSTALL_DIR" ]; then
        cp "$_bin_path" "${INSTALL_DIR}/${BIN_NAME}"
        chmod +x "${INSTALL_DIR}/${BIN_NAME}"
    else
        sudo cp "$_bin_path" "${INSTALL_DIR}/${BIN_NAME}"
        sudo chmod +x "${INSTALL_DIR}/${BIN_NAME}"
    fi
}

# --- Daemon startup -----------------------------------------------------------

start_daemon() {
    mkdir -p "$AGENTSSO_HOME"

    # Stop existing daemon if running (upgrade scenario)
    if [ -f "$PID_FILE" ]; then
        _old_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
        if [ -n "$_old_pid" ]; then
            if kill -0 "$_old_pid" 2>/dev/null; then
                kill "$_old_pid" 2>/dev/null || true
                # Wait up to 3s for graceful shutdown
                _shutdown_wait=0
                while kill -0 "$_old_pid" 2>/dev/null && [ "$_shutdown_wait" -lt 3 ]; do
                    sleep 1
                    _shutdown_wait=$((_shutdown_wait + 1))
                done
            fi
            rm -f "$PID_FILE"
        fi
    fi

    # Start daemon in background (agentsso start is foreground-blocking)
    nohup "${INSTALL_DIR}/${BIN_NAME}" start > "$DAEMON_LOG" 2>&1 &

    # Wait up to 5s for PID file to appear
    _waited=0
    while [ ! -f "$PID_FILE" ] && [ "$_waited" -lt 5 ]; do
        sleep 1
        _waited=$((_waited + 1))
    done

    if [ -f "$PID_FILE" ]; then
        DAEMON_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
        DAEMON_STATUS="ok"
    else
        DAEMON_PID=""
        DAEMON_STATUS="warning"
        warn "daemon PID file not found after 5s. start manually with: ${BIN_NAME} start"
    fi
}

# --- Main ---------------------------------------------------------------------

main() {
    START_TIME="$(date +%s)"

    setup_colors

    # ASCII mascot glyph (UX-DR24)
    printf "\n"
    printf "  %b%s%b permitlayer\n" "$WHITE" "░▒▓█" "$RESET"
    printf "       the guard between your agent and your data\n"
    printf "\n"

    # Step 1: Detect platform
    detect_platform
    step_done "detecting platform" "${OS_DISPLAY} ${ARCH_DISPLAY}"

    # Resolve version (auto-detect latest if not specified)
    resolve_version

    # Check for existing installation
    check_existing

    # Step 2: Download
    download_release
    step_done "downloading ${BIN_NAME} v${VERSION}" "${DOWNLOAD_SIZE}"

    # Step 3: Verify signature
    SIG_DISPLAY="not verified"
    verify_signature
    step_done "verifying signature" "${SIG_DISPLAY}"

    # Step 4: Install binary
    install_binary
    step_done "installing to ${INSTALL_DIR}" ""

    # Step 5: Binding OS keychain (initialized on first daemon start)
    step_done "binding OS keychain" "${KEYCHAIN_DISPLAY}"

    # Step 6: Start daemon
    start_daemon
    if [ "$DAEMON_STATUS" = "ok" ] && [ -n "$DAEMON_PID" ]; then
        step_done "starting daemon" "pid ${DAEMON_PID}, :${DEFAULT_PORT}"
    else
        step_done "starting daemon" "manual start needed"
    fi

    # Elapsed time
    END_TIME="$(date +%s)"
    ELAPSED="$((END_TIME - START_TIME))"
    printf "\n"
    printf "  installed in %ss\n" "$ELAPSED"
    printf "\n"
    printf "  next:  %s setup gmail\n" "$BIN_NAME"
    printf "\n"
}

# Allow sourcing for testing without executing main
if [ "${AGENTSSO_TEST_MODE:-}" != "1" ]; then
    main "$@"
fi
