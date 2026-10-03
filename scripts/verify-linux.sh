#!/usr/bin/env bash
# 1.0 verification on a Linux box. Runs every integration surface once.
#
# Invoke as root with an intact PATH and bash (sudo sh strips PATH → cargo
# not found, and dash has no pipefail):
#   sudo env "PATH=$PATH" bash scripts/verify-linux.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FAILED=0

# a stale persisted-state file from a manual agent run would seed the journal
# cursor at real-now and make the engine tests' fixture lines get skipped
rm -f /var/lib/picket/agent-state.json

step() { echo; echo "==> $1"; }

step "build + tests"
(cd "$ROOT" && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo build --release)

step "integration (agent <-> server)"
"$ROOT/scripts/integration-test.sh"

step "discover"
"$ROOT/target/release/picket-agent" --config /dev/null discover | tee /tmp/picket-discover.txt
grep -q "Docker detected" /tmp/picket-discover.txt || { echo "discover output missing rows" >&2; FAILED=1; }

step "demo scenario"
"$ROOT/scripts/demo.sh"

step "install (fresh unit)"
# a live server so the agent's registration is provable
cat > /tmp/picket-verify-server.toml <<EOF
listen = "127.0.0.1:18789"
db_url = "sqlite:///tmp/picket-verify.db"
auth_token = "verify-token"
EOF
"$ROOT/target/release/picket-server" --config /tmp/picket-verify-server.toml &
VERIFY_SERVER_PID=$!
trap 'kill "$VERIFY_SERVER_PID" 2>/dev/null || true; systemctl stop picket-agent 2>/dev/null || true; rm -f /tmp/picket-verify-server.toml /tmp/picket-verify.db /tmp/picket-install.txt /var/lib/picket/agent-state.json' EXIT
sleep 1

SERVER_URL="http://127.0.0.1:18789" TOKEN="verify-token" \
  PICKET_BINARY="$ROOT/target/release/picket-agent" \
  "$ROOT/scripts/install.sh" 2>&1 | tee /tmp/picket-install.txt
grep -q "install complete" /tmp/picket-install.txt || { echo "install failed" >&2; FAILED=1; }
systemctl status picket-agent --no-pager | grep -q "Active: active" || { echo "unit not active" >&2; FAILED=1; }
sleep 5
HOSTS=$(curl -fsS -H "Authorization: Bearer verify-token" "http://127.0.0.1:18789/v1/hosts" || true)
echo "$HOSTS" | grep -q '"host_id"' || { echo "agent never registered via heartbeat" >&2; FAILED=1; }
journalctl -u picket-agent --no-pager -n 20 2>/dev/null | grep -q "\[audit\]" || echo "note: audit lines not found in journal (check journald access)"

if [ "$FAILED" -eq 0 ]; then
  echo
  echo "VERIFY-LINUX PASSED"
else
  echo "VERIFY-LINUX FAILED" >&2
  exit 1
fi
