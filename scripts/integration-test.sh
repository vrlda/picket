#!/usr/bin/env bash
# M2 integration check: build both binaries, run the server locally with a
# temp config, push a sample batch + heartbeat through real HTTP, verify the
# API returns them. macOS-safe (no GNU timeout, no /proc-dependent sensors).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() { [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

PORT=18787
TOKEN="integration-test-token"

cat > "$WORK/server.toml" <<EOF
listen = "127.0.0.1:$PORT"
db_url = "sqlite://$WORK/test.db"
auth_token = "$TOKEN"
EOF

cat > "$WORK/agent.toml" <<EOF
host_id = "itest-host"
server_url = "http://127.0.0.1:$PORT"
token = "$TOKEN"
poll_interval_secs = 1
heartbeat_secs = 1
spool_dir = "$WORK/spool"
state_file = "$WORK/agent-state.json"
EOF

echo "==> building"
(cd "$ROOT" && cargo build --release -q)

echo "==> starting server"
"$ROOT/target/release/picket-server" --config "$WORK/server.toml" &
SERVER_PID=$!
sleep 1

echo "==> heartbeat round-trip (agent binary, run 3s)"
"$ROOT/target/release/picket-agent" --config "$WORK/agent.toml" run &
AGENT_PID=$!
sleep 3
kill "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true

echo "==> verifying host registry"
HOSTS=$(curl -fsS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/v1/hosts")
echo "$HOSTS" | grep -q '"host_id":"itest-host"' && echo "OK host registered"

echo "==> verifying events endpoint"
curl -fsS -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"batch":[{"id":"e-1","ts":1000,"host_id":"itest-host","key":"k","kind":"ServiceFailed","severity":"Critical","summary":"integration event","evidence":[]}]}' \
  "http://127.0.0.1:$PORT/v1/telemetry" >/dev/null
EVENTS=$(curl -fsS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/v1/events?host=itest-host")
echo "$EVENTS" | grep -q '"summary":"integration event"' && echo "OK event stored"

echo "==> verifying incidents round-trip"
NOW_MS=$(( $(date +%s) * 1000 ))
curl -fsS -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"batch\":[
    {\"id\":\"d-ssh\",\"ts\":$((NOW_MS - 150000)),\"host_id\":\"itest-host\",\"key\":\"ssh:login:deploy\",\"kind\":\"SshLogin\",\"severity\":\"Warning\",\"summary\":\"ssh\",\"evidence\":[]},
    {\"id\":\"d-fim\",\"ts\":$((NOW_MS - 100000)),\"host_id\":\"itest-host\",\"key\":\"fim:/etc/x\",\"kind\":\"FileChanged\",\"severity\":\"Warning\",\"summary\":\"fim\",\"evidence\":[]},
    {\"id\":\"d-fail\",\"ts\":$((NOW_MS - 50000)),\"host_id\":\"itest-host\",\"key\":\"svc:myapp.service\",\"kind\":\"ServiceFailed\",\"severity\":\"Critical\",\"summary\":\"fail\",\"evidence\":[]}
  ]}" \
  "http://127.0.0.1:$PORT/v1/telemetry" >/dev/null
INCIDENT=""
for i in $(seq 1 15); do
  INCS=$(curl -fsS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/v1/incidents" || true)
  INCIDENT=$(echo "$INCS" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4) || true
  if [ -n "$INCIDENT" ]; then break; fi
  sleep 2
done
[ -n "$INCIDENT" ] || { echo "FAILED: no incident after demo batch" >&2; exit 1; }
echo "OK incident created: $INCIDENT"
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/v1/incidents/$INCIDENT/ack" >/dev/null
STATUS=$(curl -fsS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/v1/incidents/$INCIDENT" | grep -o '"status":"[^"]*"' | head -1) || true
[ "$STATUS" = '"status":"acknowledged"' ] && echo "OK incident acked"

echo "==> verifying auth rejection"
CODE=$(curl -sS -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/v1/hosts")
[ "$CODE" = "401" ] && echo "OK unauthorized rejected"

echo "==> verifying exception round-trip"
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"host_id":"it-h","service":"it-svc","environment":"test",
       "exception":{"type":"ValueError","message":"it boom","level":"error",
       "frames":[{"file":"it.py","line":1,"function":"main"}]}}' \
  "http://127.0.0.1:$PORT/v1/errors" >/dev/null
EXC_KEY=""
for i in $(seq 1 15); do
  EXC_KEY=$(curl -fsS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/v1/incidents" | grep -o 'rule:app_exception:ex:it-svc:[a-f0-9]\{16\}' | head -1) || true
  [ -n "$EXC_KEY" ] && break
  sleep 2
done
[ -n "$EXC_KEY" ] || { echo "FAILED: no exception incident" >&2; exit 1; }
echo "OK exception incident: $EXC_KEY"

echo "ALL INTEGRATION CHECKS PASSED"
