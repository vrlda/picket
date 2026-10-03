#!/usr/bin/env bash
# M4 demo (Linux): real agent + server; drives the product-spec §7 scenario
# against a systemd unit; polls the API until the incident appears.
# Requires: systemd, root, curl.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
SERVER_PID=""
AGENT_PID=""
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null || true
  rm -rf "$WORK"
  systemctl stop picket-demo 2>/dev/null || true
  rm -f /etc/systemd/system/picket-demo.service /etc/picket-demo.conf
  systemctl daemon-reload 2>/dev/null || true
}
trap cleanup EXIT

PORT=18788
TOKEN="demo-token"
SVC="picket-demo"

cat > "$WORK/server.toml" <<EOF
listen = "127.0.0.1:$PORT"
db_url = "sqlite://$WORK/demo.db"
auth_token = "$TOKEN"
EOF

cat > "$WORK/agent.toml" <<EOF
host_id = "demo-host"
server_url = "http://127.0.0.1:$PORT"
token = "$TOKEN"
poll_interval_secs = 2
heartbeat_secs = 2
spool_dir = "$WORK/spool"
watch_paths = ["/etc/picket-demo.conf"]
EOF

echo "==> building"
(cd "$ROOT" && cargo build --release -q)

echo "==> demo unit + config"
cat > /etc/systemd/system/$SVC.service <<UNIT
[Unit]
Description=Picket demo unit

[Service]
ExecStart=/bin/sh -c 'test -f /etc/picket-demo.conf && exit 1 || sleep 3600'
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
rm -f /etc/picket-demo.conf   # healthy: no config file → unit stays up
systemctl daemon-reload && systemctl start $SVC

echo "==> starting server + agent"
"$ROOT/target/release/picket-server" --config "$WORK/server.toml" &
SERVER_PID=$!
sleep 1
"$ROOT/target/release/picket-agent" --config "$WORK/agent.toml" run &
AGENT_PID=$!
sleep 5

echo "==> scenario"
# config file appears (FIM event) → unit restarted (journald ServiceRestarted)
# → unit exits 1 (journald + systemd sensor ServiceFailed)
touch /etc/picket-demo.conf
systemctl restart $SVC
sleep 20

echo "==> polling for the incident"
for i in $(seq 1 30); do
  INCS=$(curl -fsS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/v1/incidents" || true)
  if echo "$INCS" | grep -q 'rule:config_change_outage:demo-host'; then
    echo "$INCS" | head -c 2000
    echo
    echo "DEMO PASSED"
    exit 0
  fi
  sleep 2
done
echo "DEMO FAILED: no config-change incident" >&2
exit 1
