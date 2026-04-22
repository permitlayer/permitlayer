#!/usr/bin/env bash
# Smoke test suite for permitlayer/agentsso.
#
# Prerequisites:
#   - cargo build --release
#   - agentsso setup gmail --oauth-client <path> (token must not be expired)
#   - agentsso start (daemon running on default port 3820)
#
# Usage:
#   ./scripts/smoke-test.sh            # run all tests
#   ./scripts/smoke-test.sh --no-mcp   # skip MCP/Gmail tests (no daemon needed)

set -euo pipefail

AGENTSSO="./target/release/agentsso"
BASE_URL="http://localhost:3820"
PASS=0
FAIL=0
SKIP_MCP=false

for arg in "$@"; do
  case "$arg" in
    --no-mcp) SKIP_MCP=true ;;
  esac
done

pass() { PASS=$((PASS + 1)); printf "  \033[32m✓\033[0m %s\n" "$1"; }
fail() { FAIL=$((FAIL + 1)); printf "  \033[31m✕\033[0m %s: %s\n" "$1" "$2"; }

echo "=== permitlayer smoke tests ==="
echo

# ── CLI: config ──────────────────────────────────────────────────

echo "-- config --"

original_theme=$($AGENTSSO config get theme 2>/dev/null)

$AGENTSSO config set theme=molt >/dev/null 2>&1
got=$($AGENTSSO config get theme 2>/dev/null)
if [ "$got" = "molt" ]; then pass "config set/get theme=molt"; else fail "config set/get" "expected molt, got $got"; fi

list_out=$($AGENTSSO config list 2>/dev/null)
if echo "$list_out" | grep -q "molt"; then pass "config list shows current theme"; else fail "config list" "$list_out"; fi

$AGENTSSO config set "theme=$original_theme" >/dev/null 2>&1
got=$($AGENTSSO config get theme 2>/dev/null)
if [ "$got" = "$original_theme" ]; then pass "config reset to $original_theme"; else fail "config reset" "got $got"; fi

if ! $AGENTSSO config set theme=invalid 2>/dev/null; then pass "config rejects invalid theme"; else fail "config reject" "accepted invalid theme"; fi

echo

# ── CLI: empty state ─────────────────────────────────────────────

echo "-- empty state --"

tmp_home=$(mktemp -d)
empty_out=$(AGENTSSO_PATHS__HOME="$tmp_home" $AGENTSSO credentials status 2>/dev/null)
rm -rf "$tmp_home"

if echo "$empty_out" | grep -q "◖"; then pass "empty state shows ◖ glyph"; else fail "empty state glyph" "$empty_out"; fi
if echo "$empty_out" | grep -q "agentsso setup"; then pass "empty state shows populate command"; else fail "empty state command" "$empty_out"; fi

echo

# ── CLI: credentials ─────────────────────────────────────────────

echo "-- credentials --"

cred_out=$($AGENTSSO credentials status 2>/dev/null || true)
if echo "$cred_out" | grep -q "gmail"; then pass "credentials status shows gmail"; else fail "credentials status" "$cred_out"; fi
if echo "$cred_out" | grep -qE "(valid|expired)"; then pass "credentials status shows token validity"; else fail "credentials validity" "$cred_out"; fi

echo

# ── xtask: contrast ──────────────────────────────────────────────

echo "-- contrast --"

contrast_out=$(cargo xtask contrast-check 2>&1)
if echo "$contrast_out" | grep -q "All pairs pass"; then pass "WCAG contrast check"; else fail "contrast" "$contrast_out"; fi

echo

# ── Daemon / MCP tests (require running daemon) ─────────────────

if [ "$SKIP_MCP" = true ]; then
  echo "-- daemon/mcp (skipped: --no-mcp) --"
  echo
else
  echo "-- daemon --"

  health=$(curl -sf "$BASE_URL/health" 2>/dev/null || echo "")
  if [ -z "$health" ]; then
    echo "  daemon not reachable at $BASE_URL — skipping network tests"
    echo "  start with: $AGENTSSO start"
    echo
  else
    if echo "$health" | grep -q '"healthy"'; then pass "health endpoint"; else fail "health" "$health"; fi

    status_out=$($AGENTSSO status 2>/dev/null || true)
    if echo "$status_out" | grep -q "healthy"; then pass "CLI status"; else fail "CLI status" "$status_out"; fi
    if echo "$status_out" | grep -qE "[0-9]+[hms]"; then pass "status uses formatted uptime"; else fail "status uptime format" "$status_out"; fi

    echo

    echo "-- mcp --"

    # Initialize MCP session.
    init_response=$(curl -s -X POST "$BASE_URL/mcp" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json, text/event-stream" \
      -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke-test","version":"0.1.0"}}}' \
      -D /tmp/smoke-mcp-headers 2>/dev/null)

    SESSION=$(grep -i 'mcp-session-id' /tmp/smoke-mcp-headers 2>/dev/null | tr -d '\r' | awk '{print $2}')
    rm -f /tmp/smoke-mcp-headers

    if echo "$init_response" | grep -q '"protocolVersion"'; then pass "MCP initialize"; else fail "MCP init" "$init_response"; fi

    if [ -n "$SESSION" ]; then
      # Send initialized notification.
      curl -s -X POST "$BASE_URL/mcp" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -H "Mcp-Session-Id: $SESSION" \
        -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null 2>&1

      # List tools.
      tools_response=$(curl -s -X POST "$BASE_URL/mcp" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -H "Mcp-Session-Id: $SESSION" \
        -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' 2>/dev/null)

      if echo "$tools_response" | grep -q "gmail.search"; then pass "MCP tools/list (5 gmail tools)"; else fail "MCP tools/list" "$tools_response"; fi

      # Search inbox.
      search_response=$(curl -s -X POST "$BASE_URL/mcp" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -H "Mcp-Session-Id: $SESSION" \
        -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"gmail.search","arguments":{"query":"in:inbox","max_results":2}}}' 2>/dev/null)

      if echo "$search_response" | grep -q 'messages'; then
        pass "MCP gmail.search returns messages"
      else
        # Token may have expired.
        if echo "$search_response" | grep -q 'isError.*true'; then
          fail "MCP gmail.search" "error (token may be expired — re-run agentsso setup gmail)"
        else
          fail "MCP gmail.search" "unexpected response"
        fi
      fi

      # Read a message (extract first ID from search — unescape the SSE JSON text field).
      msg_id=$(echo "$search_response" | python3 -c "
import sys, json, re
for line in sys.stdin:
    line = line.strip()
    if not line.startswith('data: {'):
        continue
    d = json.loads(line[6:])
    text = d.get('result',{}).get('content',[{}])[0].get('text','')
    inner = json.loads(text)
    msgs = inner.get('messages', [])
    if msgs:
        print(msgs[0]['id'])
        break
" 2>/dev/null)
      if [ -n "$msg_id" ]; then
        get_response=$(curl -s -X POST "$BASE_URL/mcp" \
          -H "Content-Type: application/json" \
          -H "Accept: application/json, text/event-stream" \
          -H "Mcp-Session-Id: $SESSION" \
          -d "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"gmail.messages.get\",\"arguments\":{\"id\":\"$msg_id\",\"format\":\"metadata\"}}}" 2>/dev/null)

        if echo "$get_response" | grep -q 'threadId'; then pass "MCP gmail.messages.get"; else fail "MCP messages.get" "unexpected response"; fi
      else
        fail "MCP gmail.messages.get" "no message ID from search"
      fi
    else
      fail "MCP session" "no session ID returned"
    fi

    echo
  fi
fi

# ── Summary ──────────────────────────────────────────────────────

echo "=== results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then exit 1; fi
