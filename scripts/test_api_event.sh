#!/usr/bin/env sh
# Validation script: tests the full forwarding pipeline end-to-end.
# Steps:
#   1. Call /forwarding/test to verify DMZ connectivity.
#   2. Inject a unique event via /test-event (goes through rule engine + forwarder).
#   3. Poll DMZ /events for the same event ID for up to 10 seconds.
#   4. Exit 1 if the event is not found.
set -eu

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8088}"
DMZ_HOST="${DMZ_HOST:-192.168.10.70}"
DMZ_PORT="${DMZ_PORT:-9000}"

BASE="http://${HOST}:${PORT}"
DMZ_BASE="http://${DMZ_HOST}:${DMZ_PORT}"

pass() { printf '\033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$1"; exit 1; }
info() { printf 'INFO %s\n' "$1"; }

# ── 1. /forwarding/test ────────────────────────────────────────────────────────
info "Step 1: calling /forwarding/test on ${BASE}"
FWD_RESULT=$(curl -sf -X POST "${BASE}/forwarding/test" \
  -H "Content-Type: application/json" 2>&1) || fail "/forwarding/test request failed"

echo "${FWD_RESULT}"

FWD_SUCCESS=$(echo "${FWD_RESULT}" | grep -o '"success":[^,}]*' | cut -d: -f2 | tr -d ' "')
if [ "${FWD_SUCCESS}" != "true" ]; then
  fail "/forwarding/test reported success=false — check DMZ connectivity before proceeding"
fi
pass "/forwarding/test succeeded"

# ── 2. Inject event via /test-event ───────────────────────────────────────────
EVENT_ID="valtest-$(date +%s%N 2>/dev/null || date +%s)"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "1970-01-01T00:00:00Z")

info "Step 2: injecting event ${EVENT_ID} via /test-event"
INJECT_RESULT=$(curl -sf -X POST "${BASE}/test-event" \
  -H "Content-Type: application/json" \
  -d "{
    \"event\": {
      \"id\": \"${EVENT_ID}\",
      \"timestamp\": \"${TIMESTAMP}\",
      \"source_type\": \"validation\",
      \"asset_name\": \"validation-script\",
      \"asset_ip\": \"127.0.0.1\",
      \"severity\": \"info\",
      \"protocol\": \"json\",
      \"event_category\": \"system\",
      \"message\": \"forwarding validation probe\",
      \"tags\": {\"kind\": \"validation\"}
    }
  }" 2>&1) || fail "/test-event request failed"

echo "${INJECT_RESULT}"
pass "event injected: ${EVENT_ID}"

# ── 3. Poll DMZ /events for the event ID ──────────────────────────────────────
info "Step 3: polling DMZ ${DMZ_BASE}/events for event ${EVENT_ID} (up to 10 seconds)"
FOUND=false
i=0
while [ $i -lt 10 ]; do
  DMZ_EVENTS=$(curl -sf "${DMZ_BASE}/events?limit=100" 2>/dev/null || echo "")
  if echo "${DMZ_EVENTS}" | grep -q "${EVENT_ID}"; then
    FOUND=true
    break
  fi
  sleep 1
  i=$((i + 1))
done

if [ "${FOUND}" = "true" ]; then
  pass "event ${EVENT_ID} found in DMZ /events after ${i}s"
else
  fail "event ${EVENT_ID} NOT found in DMZ /events after 10 seconds — forwarding pipeline broken"
fi
