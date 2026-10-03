#!/usr/bin/env bash
# Picket control-plane installer (non-interactive, safe to re-run).
#
#   sudo bash scripts/install-server.sh [--with-agent [--host-id <name>]]
#        [--domain <name> | --no-proxy --public-url <https://...>]
#        [--telegram-token <bot token>] [--telegram-chat-id <id>]
#        [--runner-id <id>]
#
# What it does:
#   - installs picket-server (+ agent, runner) from the latest release
#   - generates the auth token and a runner token, writes
#     /etc/picket/server.toml with autonomous response on: every
#     Warning/Critical incident becomes an agent task for profile "ops"
#   - HTTPS: Caddy reverse proxy with an automatic certificate for --domain,
#     or <public-ip>.sslip.io when no domain is given (no DNS work needed)
#   - --with-agent: also monitors this host (agent talks to 127.0.0.1)
#
# Re-running keeps the existing config and secrets. The last lines of output
# are KEY=VALUE pairs (also stored in /etc/picket/install.env, root only)
# that agents and the runner need.
set -euo pipefail

DOMAIN=""
PUBLIC_URL=""
NO_PROXY=0
WITH_AGENT=0
HOST_ID=""
TG_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TG_CHAT="${TELEGRAM_CHAT_ID:-}"
RUNNER_ID="runner"
LISTEN="127.0.0.1:8787"
CONFIG_DIR="/etc/picket"
DATA_DIR="/var/lib/picket"
INSTALL_DIR="/usr/local/bin"
REPO="vrlda/picket"

need_value() { [ "$2" -ge 2 ] || { echo "$1 requires a value" >&2; exit 1; }; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --domain) need_value "$1" "$#"; DOMAIN="$2"; shift 2 ;;
    --public-url) need_value "$1" "$#"; PUBLIC_URL="${2%/}"; shift 2 ;;
    --no-proxy) NO_PROXY=1; shift ;;
    --with-agent) WITH_AGENT=1; shift ;;
    --host-id) need_value "$1" "$#"; HOST_ID="$2"; shift 2 ;;
    --telegram-token) need_value "$1" "$#"; TG_TOKEN="$2"; shift 2 ;;
    --telegram-chat-id) need_value "$1" "$#"; TG_CHAT="$2"; shift 2 ;;
    --runner-id) need_value "$1" "$#"; RUNNER_ID="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd is required" >&2; exit 1; }
if [ "$NO_PROXY" = 1 ] && [ -z "$PUBLIC_URL" ]; then
  echo "--no-proxy needs --public-url (the https URL your own proxy serves)" >&2
  exit 1
fi

gen_token() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

case "$(uname -m)" in
  x86_64|amd64) TARGET="x86_64-unknown-linux-musl"; CADDY_ARCH="amd64" ;;
  aarch64|arm64) TARGET="aarch64-unknown-linux-musl"; CADDY_ARCH="arm64" ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---------- binaries ----------
echo "==> downloading the latest Picket release ($TARGET)"
LATEST_JSON="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest")"
TAG="$(printf '%s' "$LATEST_JSON" | grep -o '"tag_name"[^,]*' | sed 's/.*"\([^"]*\)"$/\1/' | head -n 1)"
ASSET_URL="$(printf '%s' "$LATEST_JSON" | grep -o '"browser_download_url": *"[^"]*'"$TARGET"'.tar.gz"' | sed 's/.*"\([^"]*\)"$/\1/' | head -n 1)"
[ -n "$TAG" ] && [ -n "$ASSET_URL" ] || { echo "no $TARGET build in the latest release" >&2; exit 1; }
ASSET="$(basename "$ASSET_URL")"
curl -fsSL "$ASSET_URL" -o "$WORK/$ASSET"
EXPECTED="$(curl -fsSL "https://github.com/$REPO/releases/download/$TAG/SHA256SUMS" | awk -v a="$ASSET" '$2 == a { print $1 }')"
[ "$(sha256_of "$WORK/$ASSET")" = "$EXPECTED" ] || { echo "checksum mismatch — aborting" >&2; exit 1; }
mkdir -p "$WORK/bin"
tar -xzf "$WORK/$ASSET" -C "$WORK/bin"
for b in picket-server picket-agent picket-runner; do
  install -m 0755 "$WORK/bin/$b" "$INSTALL_DIR/$b"
done
echo "installed $TAG"

# ---------- user, config, secrets ----------
if ! getent passwd picket >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin picket
fi
mkdir -p "$CONFIG_DIR" "$DATA_DIR"
chown picket:picket "$DATA_DIR"

if [ -f "$CONFIG_DIR/install.env" ]; then
  # shellcheck disable=SC1091
  . "$CONFIG_DIR/install.env"
fi
AUTH_TOKEN="${PICKET_AUTH_TOKEN:-$(gen_token)}"
RUNNER_ID="${PICKET_RUNNER_ID:-$RUNNER_ID}"
RUNNER_TOKEN="${PICKET_RUNNER_TOKEN:-$(gen_token)}"

if [ -f "$CONFIG_DIR/server.toml" ]; then
  echo "==> keeping existing $CONFIG_DIR/server.toml"
else
  echo "==> writing $CONFIG_DIR/server.toml"
  cat > "$CONFIG_DIR/server.toml" <<EOF
listen = "$LISTEN"
auth_token = "$AUTH_TOKEN"

# The machine that runs Claude Code (picket-runner) connects with this.
[runners.$RUNNER_ID]
token = "$RUNNER_TOKEN"

# How hard the agent may be pushed; HOW it runs (tools, hosts, ssh) is
# configured in the runner's runner.toml.
[agent_profiles.ops]
max_attempts = 2
max_tasks_per_incident = 3
max_tasks_per_hour = 10

# Autonomous response: every Warning/Critical incident (service down, disk
# full, ...) goes to the agent unless its rule dispatches one itself.
[auto_agent]
profile = "ops"
min_severity = "Warning"
EOF
fi
chown root:picket "$CONFIG_DIR/server.toml"
chmod 640 "$CONFIG_DIR/server.toml"

touch "$CONFIG_DIR/server.env"
set_env() {
  local key="$1" value="$2"
  [ -n "$value" ] || return 0
  grep -v "^$key=" "$CONFIG_DIR/server.env" > "$WORK/env" || true
  printf '%s=%s\n' "$key" "$value" >> "$WORK/env"
  cat "$WORK/env" > "$CONFIG_DIR/server.env"
}
set_env TELEGRAM_BOT_TOKEN "$TG_TOKEN"
set_env TELEGRAM_CHAT_ID "$TG_CHAT"
chown root:picket "$CONFIG_DIR/server.env"
chmod 640 "$CONFIG_DIR/server.env"

echo "==> starting picket-server"
install -m 0644 "$WORK/bin/picket-server.service" /etc/systemd/system/picket-server.service
systemctl daemon-reload
systemctl enable picket-server >/dev/null
systemctl restart picket-server
for _ in $(seq 1 30); do
  curl -fsS "http://$LISTEN/v1/ping" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "http://$LISTEN/v1/ping" >/dev/null || {
  journalctl -u picket-server -n 30 --no-pager >&2
  echo "picket-server did not come up" >&2
  exit 1
}

# ---------- HTTPS ----------
if [ "$NO_PROXY" = 0 ]; then
  if [ -z "$DOMAIN" ]; then
    IP="$(curl -fsS4 https://api.ipify.org || curl -fsS4 https://ifconfig.me)"
    [ -n "$IP" ] || { echo "cannot detect the public IPv4 — pass --domain" >&2; exit 1; }
    DOMAIN="$(printf '%s' "$IP" | tr . -).sslip.io"
  fi
  PUBLIC_URL="https://$DOMAIN"
  if ! systemctl is-active --quiet picket-caddy \
    && ss -ltnH '( sport = :443 or sport = :80 )' 2>/dev/null | grep -q .; then
    echo "ports 80/443 are already in use by another web server." >&2
    echo "Add a reverse proxy from https://<your domain> to http://$LISTEN there," >&2
    echo "then re-run with: --no-proxy --public-url https://<your domain>" >&2
    exit 2
  fi
  if [ ! -x "$INSTALL_DIR/caddy" ]; then
    echo "==> installing Caddy (automatic HTTPS)"
    CADDY_JSON="$(curl -fsSL https://api.github.com/repos/caddyserver/caddy/releases/latest)"
    CADDY_TAG="$(printf '%s' "$CADDY_JSON" | grep -o '"tag_name"[^,]*' | sed 's/.*"\([^"]*\)"$/\1/' | head -n 1)"
    CADDY_VER="${CADDY_TAG#v}"
    CADDY_TGZ="caddy_${CADDY_VER}_linux_${CADDY_ARCH}.tar.gz"
    CADDY_BASE="https://github.com/caddyserver/caddy/releases/download/$CADDY_TAG"
    curl -fsSL "$CADDY_BASE/$CADDY_TGZ" -o "$WORK/$CADDY_TGZ"
    CADDY_SUM="$(curl -fsSL "$CADDY_BASE/caddy_${CADDY_VER}_checksums.txt" | awk -v a="$CADDY_TGZ" '$2 == a { print $1 }')"
    [ "$(sha512sum "$WORK/$CADDY_TGZ" | awk '{print $1}')" = "$CADDY_SUM" ] || { echo "caddy checksum mismatch" >&2; exit 1; }
    tar -xzf "$WORK/$CADDY_TGZ" -C "$WORK" caddy
    install -m 0755 "$WORK/caddy" "$INSTALL_DIR/caddy"
  fi
  mkdir -p /etc/picket-caddy /var/lib/picket-caddy
  chown picket:picket /var/lib/picket-caddy
  cat > /etc/picket-caddy/Caddyfile <<EOF
$DOMAIN {
	reverse_proxy $LISTEN
}
EOF
  cat > /etc/systemd/system/picket-caddy.service <<UNIT
[Unit]
Description=HTTPS for Picket (Caddy)
After=network-online.target picket-server.service
Wants=network-online.target

[Service]
User=picket
Group=picket
Environment=HOME=/var/lib/picket-caddy XDG_DATA_HOME=/var/lib/picket-caddy XDG_CONFIG_HOME=/var/lib/picket-caddy
ExecStart=$INSTALL_DIR/caddy run --config /etc/picket-caddy/Caddyfile --adapter caddyfile
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/picket-caddy

[Install]
WantedBy=multi-user.target
UNIT
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow 80/tcp >/dev/null && ufw allow 443/tcp >/dev/null
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-service=http --add-service=https >/dev/null && firewall-cmd --reload >/dev/null
  fi
  systemctl daemon-reload
  systemctl enable picket-caddy >/dev/null
  systemctl restart picket-caddy
  echo "==> waiting for the certificate for $DOMAIN"
  for _ in $(seq 1 60); do
    curl -fsS "$PUBLIC_URL/v1/ping" >/dev/null 2>&1 && break
    sleep 2
  done
  curl -fsS "$PUBLIC_URL/v1/ping" >/dev/null || {
    journalctl -u picket-caddy -n 30 --no-pager >&2
    echo "$PUBLIC_URL is not reachable — is port 80/443 open in the provider's firewall?" >&2
    exit 1
  }
fi

cat > "$CONFIG_DIR/install.env" <<EOF
PICKET_URL=$PUBLIC_URL
PICKET_AUTH_TOKEN=$AUTH_TOKEN
PICKET_RUNNER_ID=$RUNNER_ID
PICKET_RUNNER_TOKEN=$RUNNER_TOKEN
EOF
chmod 600 "$CONFIG_DIR/install.env"

# ---------- this host's own agent ----------
if [ "$WITH_AGENT" = 1 ]; then
  echo "==> installing the agent on this host"
  AGENT_SCRIPT="$(dirname "$0")/install.sh"
  if [ ! -f "$AGENT_SCRIPT" ]; then
    AGENT_SCRIPT="$WORK/install.sh"
    curl -fsSL "https://raw.githubusercontent.com/$REPO/main/scripts/install.sh" -o "$AGENT_SCRIPT"
  fi
  PICKET_BINARY="$WORK/bin/picket-agent" bash "$AGENT_SCRIPT" \
    --server-url "http://$LISTEN" --token "$AUTH_TOKEN" ${HOST_ID:+--host-id "$HOST_ID"}
fi

echo "==> done"
cat "$CONFIG_DIR/install.env"
