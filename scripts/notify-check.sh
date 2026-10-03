#!/usr/bin/env bash
# End-to-end notification check against real channels.
# Usage (build first: cargo build --release):
#   TELEGRAM_BOT_TOKEN=... [TELEGRAM_CHAT_ID=...] bash scripts/notify-check.sh
#   SLACK_URL=... bash scripts/notify-check.sh
#   WEBHOOK_URL=... bash scripts/notify-check.sh
# Starts a throwaway picket-server with those credentials, injects one
# Critical event, waits until the incident is created and notified, then
# prints the server log (delivery errors show up there).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${PICKET_SERVER_BIN:-$ROOT/target/release/picket-server}"
PORT="${NOTIFY_CHECK_PORT:-18790}"
TOKEN="${NOTIFY_CHECK_TOKEN:-notify-check-token}"
WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() { [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

if [ ! -x "$BIN" ]; then
  echo "server binary not found at $BIN (run: cargo build --release)" >&2
  exit 1
fi
if [ -z "${TELEGRAM_BOT_TOKEN:-}${SLACK_URL:-}${WEBHOOK_URL:-}" ]; then
  echo "set TELEGRAM_BOT_TOKEN, SLACK_URL and/or WEBHOOK_URL" >&2
  exit 1
fi

CHANNELS=()
[ -n "${TELEGRAM_BOT_TOKEN:-}" ] && CHANNELS+=("\"telegram\"")
[ -n "${SLACK_URL:-}" ] && CHANNELS+=("\"slack\"")
[ -n "${WEBHOOK_URL:-}" ] && CHANNELS+=("\"webhook\"")
ROUTE="[$(IFS=,; echo "${CHANNELS[*]}")]"

cat > "$WORK/server.toml" <<EOF
listen = "127.0.0.1:$PORT"
db_url = "sqlite://$WORK/notify.db"
auth_token = "$TOKEN"
scan_interval_secs = 5

[notify]
slack_url = "${SLACK_URL:-}"
webhook_url = "${WEBHOOK_URL:-}"

[notify.routing]
Critical = $ROUTE
Warning = $ROUTE
Info = []
EOF

"$BIN" --config "$WORK/server.toml" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 50); do
  curl -fsS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/v1/ping" >/dev/null 2>&1 && break
  sleep 0.2
done

NOW_MS=$(( $(date +%s) * 1000 ))
curl -fsS -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"batch\":[{\"id\":\"nc-fail-$NOW_MS\",\"ts\":$((NOW_MS - 5000)),\"host_id\":\"notify-check\",\"key\":\"svc:check.service\",\"kind\":\"ServiceFailed\",\"severity\":\"Critical\",\"summary\":\"notify check\",\"evidence\":[]}]}" \
  "http://127.0.0.1:$PORT/v1/telemetry" >/dev/null
echo "event injected — waiting for the correlation scan…"

# the incident appears after the next scan; the notifier sends right after
for _ in $(seq 1 30); do
  grep -q "^incident " "$WORK/server.log" && break
  sleep 1
done
sleep 5 # delivery (and, for an unknown Telegram chat, getUpdates) takes a moment

echo "---- server log ----"
cat "$WORK/server.log"
echo "--------------------"
if ! grep -q "^incident " "$WORK/server.log"; then
  echo "FAIL: no incident was created" >&2
  exit 1
fi
if grep -Eq "send failed|notify .* failed|token check failed|no chat registered" "$WORK/server.log"; then
  echo "FAIL: delivery problem — see the log above" >&2
  exit 1
fi
echo "OK: incident created and handed to: ${CHANNELS[*]} — check the channel(s)"
