#!/usr/bin/env bash
# Watchtower agent installer.
#
# Invocation styles:
#   one command (fetches the latest release, verifies the checksum, installs):
#     curl -fsSL https://raw.githubusercontent.com/vrlda/watchtower/main/scripts/install.sh \
#       | sudo bash -s -- --server-url http://control.example.com --token secret
#   flags:
#     sudo bash scripts/install.sh --server-url http://control.example.com --token secret
#   env vars (fallback for the flags):
#     SERVER_URL=http://control.example.com TOKEN=secret sh install.sh
#   local build:
#     WATCHTOWER_BINARY=/path/to/watchtower-agent sh install.sh
#   pinned release:
#     INSTALL_URL=<release tarball URL> INSTALL_SHA256=<checksum> sh install.sh
set -euo pipefail

SERVER_URL="${SERVER_URL:-}"
TOKEN="${TOKEN:-}"
BINARY_SRC="${WATCHTOWER_BINARY:-}"
INSTALL_URL="${INSTALL_URL:-}"
INSTALL_SHA256="${INSTALL_SHA256:-}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/watchtower"
SPOOL_DIR="/var/lib/watchtower/spool"
UNIT_NAME="watchtower-agent.service"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --server-url)
      [ "$#" -ge 2 ] || { echo "--server-url requires a value" >&2; exit 1; }
      SERVER_URL="$2"
      shift 2
      ;;
    --token)
      [ "$#" -ge 2 ] || { echo "--token requires a value" >&2; exit 1; }
      TOKEN="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [ -z "$SERVER_URL" ] || [ -z "$TOKEN" ]; then
  echo "usage: sudo bash install.sh --server-url <url> --token <token>" >&2
  echo "   or: SERVER_URL=<url> TOKEN=<token> sh install.sh" >&2
  exit 1
fi

# Bearer credentials travel with every agent request. HTTP is safe only for a
# local development control plane; remote deployments must terminate TLS.
case "$SERVER_URL" in
  https://*) ;;
  http://localhost|http://localhost:*|http://localhost/*|http://127.0.0.1|http://127.0.0.1:*|http://127.0.0.1/*|http://[[]::1[]]|http://[[]::1[]]:*|http://[[]::1[]]/*) ;;
  *)
    echo "server URL must use https (http is allowed only for localhost)" >&2
    exit 1
    ;;
esac

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root" >&2
  exit 1
fi

# Portable checksum verify: sha256sum on Linux, shasum on macOS.
verify_sha256() {
  local file="$1" expected="$2"
  if command -v sha256sum >/dev/null 2>&1; then
    echo "$expected  $file" | sha256sum -c - >/dev/null
  else
    echo "$expected  $file" | shasum -a 256 -c - >/dev/null
  fi
}

# No explicit install source: resolve the latest release from the GitHub API.
# The asset name comes from the API, not constructed from the tag: release.sh
# names the tarball after the crate version (e.g. 0.1.0), which differs from
# the git tag (e.g. v0.2.0).
if [ -z "$INSTALL_URL" ] && [ -z "$INSTALL_SHA256" ] && [ -z "$BINARY_SRC" ]; then
  echo "==> resolving latest release"
  LATEST_JSON="$(curl -fsSL https://api.github.com/repos/vrlda/watchtower/releases/latest)" || {
    echo "failed to query GitHub for the latest release" >&2
    exit 1
  }
  TAG="$(printf '%s' "$LATEST_JSON" | grep -o '"tag_name"[^,]*' | sed 's/.*"\([^"]*\)"$/\1/' | head -n 1)" || true
  [ -n "$TAG" ] || { echo "could not parse the latest release tag" >&2; exit 1; }
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64) TARGET="x86_64-unknown-linux-musl" ;;
    aarch64|arm64) TARGET="aarch64-unknown-linux-musl" ;;
    *) echo "unsupported architecture: $ARCH" >&2; exit 1 ;;
  esac
  BASE="https://github.com/vrlda/watchtower/releases/download/$TAG"
  ASSET_URL="$(printf '%s' "$LATEST_JSON" | grep -o '"browser_download_url": *"[^"]*'"$TARGET"'.tar.gz"' | sed 's/.*"\([^"]*\)"$/\1/' | head -n 1)" || true
  [ -n "$ASSET_URL" ] || { echo "could not find a $TARGET asset in release $TAG" >&2; exit 1; }
  ASSET="$(basename "$ASSET_URL")"
  INSTALL_URL="$BASE/$ASSET"
  SHA_SUMS="$(curl -fsSL "$BASE/SHA256SUMS")" || {
    echo "could not fetch SHA256SUMS for $TAG — re-tag or use INSTALL_URL+INSTALL_SHA256" >&2
    exit 1
  }
  INSTALL_SHA256="$(printf '%s' "$SHA_SUMS" | awk -v a="$ASSET" '$2 == a { print $1 }' | head -n 1)" || true
  [ -n "$INSTALL_SHA256" ] || { echo "no checksum for $ASSET in SHA256SUMS" >&2; exit 1; }
fi

echo "==> installing binary"
if [ -n "$INSTALL_URL" ]; then
  if [ -z "$INSTALL_SHA256" ]; then
    echo "INSTALL_SHA256 is required when using INSTALL_URL" >&2
    exit 1
  fi
  TMP="$(mktemp)"
  trap 'rm -f "$TMP"' EXIT
  echo "downloading $INSTALL_URL"
  curl -fsSL "$INSTALL_URL" -o "$TMP"
  verify_sha256 "$TMP" "$INSTALL_SHA256" || { echo "checksum mismatch — aborting" >&2; exit 1; }
  tar -xzf "$TMP" -C "$INSTALL_DIR"
  chmod 0755 "$INSTALL_DIR/watchtower-agent" "$INSTALL_DIR/watchtower-server"
elif [ -n "$BINARY_SRC" ]; then
  install -m 0755 "$BINARY_SRC" "$INSTALL_DIR/watchtower-agent"
else
  echo "set WATCHTOWER_BINARY or INSTALL_URL(+INSTALL_SHA256)" >&2
  exit 1
fi

echo "==> creating service user"
if ! getent passwd watchtower >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin watchtower
fi

echo "==> writing config"
mkdir -p "$CONFIG_DIR" "$SPOOL_DIR"
cat > "$CONFIG_DIR/agent.toml" <<EOF
host_id = "auto"
server_url = "$SERVER_URL"
token = "$TOKEN"
poll_interval_secs = 15
heartbeat_secs = 30
spool_dir = "$SPOOL_DIR"
EOF
chown -R watchtower:watchtower "$SPOOL_DIR"
chown watchtower:watchtower "$CONFIG_DIR/agent.toml"
chmod 600 "$CONFIG_DIR/agent.toml"

echo "==> installing systemd unit"
# supplementary groups: journal + adm always exist; docker only where present
SUPP_GROUPS="systemd-journal adm"
if getent group docker >/dev/null 2>&1; then
  SUPP_GROUPS="$SUPP_GROUPS docker"
fi
cat > "/etc/systemd/system/$UNIT_NAME" <<UNIT
[Unit]
Description=Watchtower agent
After=network-online.target
Wants=network-online.target

[Service]
User=watchtower
Group=watchtower
SupplementaryGroups=$SUPP_GROUPS
ExecStart=$INSTALL_DIR/watchtower-agent run
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$SPOOL_DIR
RuntimeDirectory=watchtower
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable "$UNIT_NAME"
systemctl start "$UNIT_NAME"

echo "==> discovery checklist"
"$INSTALL_DIR/watchtower-agent" --config "$CONFIG_DIR/agent.toml" discover || true

echo "install complete: server will register on first heartbeat"
