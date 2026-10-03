#!/usr/bin/env bash
# watchtower-runner installer for the machine that runs Claude Code (a Mac
# or a Linux box). Run as the user who is logged in to `claude` and whose
# ssh keys reach the servers — not as root. Safe to re-run.
#
#   bash scripts/install-runner.sh --server-url https://wt.example.com \
#     --runner-id <id> --token <runner token> \
#     --host <host id>=<ssh destination> [--host ...] [--model <model>]
#
# --host maps a Watchtower host id (what the server shows) to how this
# machine reaches it over ssh, e.g. --host 3f9c...=root@203.0.113.10.
# The agent gets SSH access to those hosts and may fix them (profile "ops",
# production = "remediate"). Every host must accept key-based ssh
# non-interactively; the install fails otherwise.
set -euo pipefail

SERVER_URL=""
RUNNER_ID=""
TOKEN=""
MODEL=""
HOSTS=()
REPO="vrlda/watchtower"
BASE_DIR="$HOME/.watchtower-runner"
BIN_DIR="$HOME/.local/bin"

need_value() { [ "$2" -ge 2 ] || { echo "$1 requires a value" >&2; exit 1; }; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --server-url) need_value "$1" "$#"; SERVER_URL="${2%/}"; shift 2 ;;
    --runner-id) need_value "$1" "$#"; RUNNER_ID="$2"; shift 2 ;;
    --token) need_value "$1" "$#"; TOKEN="$2"; shift 2 ;;
    --host) need_value "$1" "$#"; HOSTS+=("$2"); shift 2 ;;
    --model) need_value "$1" "$#"; MODEL="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done
[ -n "$SERVER_URL" ] && [ -n "$RUNNER_ID" ] && [ -n "$TOKEN" ] || {
  echo "usage: bash install-runner.sh --server-url <url> --runner-id <id> --token <token> --host <id>=<ssh dest> ..." >&2
  exit 1
}
[ "$(id -u)" -ne 0 ] || { echo "run as your user, not root (the runner uses your claude login and ssh keys)" >&2; exit 1; }

OS="$(uname -s)"
case "$OS/$(uname -m)" in
  Darwin/arm64) TARGET="aarch64-apple-darwin" ;;
  Darwin/x86_64) TARGET="x86_64-apple-darwin" ;;
  Linux/x86_64|Linux/amd64) TARGET="x86_64-unknown-linux-musl" ;;
  Linux/aarch64|Linux/arm64) TARGET="aarch64-unknown-linux-musl" ;;
  *) echo "unsupported platform: $OS/$(uname -m)" >&2; exit 1 ;;
esac

# launchd/systemd start the runner with a bare PATH: record absolute paths
CLAUDE_BIN="$(command -v claude || true)"
for c in "$HOME/.claude/local/claude" "$HOME/.local/bin/claude" /opt/homebrew/bin/claude /usr/local/bin/claude; do
  [ -n "$CLAUDE_BIN" ] && break
  [ -x "$c" ] && CLAUDE_BIN="$c"
done
[ -n "$CLAUDE_BIN" ] || { echo "the claude CLI is not installed (https://claude.com/claude-code) — install it and log in first" >&2; exit 1; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> downloading watchtower-runner ($TARGET)"
LATEST_JSON="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest")"
TAG="$(printf '%s' "$LATEST_JSON" | grep -o '"tag_name"[^,]*' | sed 's/.*"\([^"]*\)"$/\1/' | head -n 1)"
ASSET_URL="$(printf '%s' "$LATEST_JSON" | grep -o '"browser_download_url": *"[^"]*'"$TARGET"'.tar.gz"' | sed 's/.*"\([^"]*\)"$/\1/' | head -n 1)"
[ -n "$TAG" ] && [ -n "$ASSET_URL" ] || { echo "no $TARGET build in the latest release" >&2; exit 1; }
ASSET="$(basename "$ASSET_URL")"
curl -fsSL "$ASSET_URL" -o "$WORK/$ASSET"
EXPECTED="$(curl -fsSL "https://github.com/$REPO/releases/download/$TAG/SHA256SUMS" | awk -v a="$ASSET" '$2 == a { print $1 }')"
[ "$(sha256_of "$WORK/$ASSET")" = "$EXPECTED" ] || { echo "checksum mismatch — aborting" >&2; exit 1; }
tar -xzf "$WORK/$ASSET" -C "$WORK" watchtower-runner
mkdir -p "$BIN_DIR" "$BASE_DIR"
install -m 0755 "$WORK/watchtower-runner" "$BIN_DIR/watchtower-runner"
echo "installed $TAG to $BIN_DIR/watchtower-runner"

echo "==> writing $BASE_DIR/runner.toml"
CONFIG="$BASE_DIR/runner.toml"
umask 077
{
  echo "server_url = \"$SERVER_URL\""
  echo "runner_id = \"$RUNNER_ID\""
  echo "token = \"$TOKEN\""
  echo "work_dir = \"$BASE_DIR\""
  echo
  echo "# Incidents on any host: diagnose and fix over ssh, no code repository."
  echo "[profiles.ops]"
  echo "production = \"remediate\""
  echo "claude_bin = \"$CLAUDE_BIN\""
  [ -z "$MODEL" ] || echo "model = \"$MODEL\""
  for h in ${HOSTS[@]+"${HOSTS[@]}"}; do
    id="${h%%=*}"
    dest="${h#*=}"
    [ -n "$id" ] && [ "$id" != "$h" ] || { echo "--host must be <host id>=<ssh destination>: $h" >&2; exit 1; }
    echo
    echo "[hosts.\"$id\"]"
    echo "ssh = \"$dest\""
  done
} > "$CONFIG"
umask 022

echo "==> checking claude, ssh and the server connection"
"$BIN_DIR/watchtower-runner" --config "$CONFIG" check

echo "==> starting the runner service"
PATH_LINE="$(dirname "$CLAUDE_BIN"):/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
if [ "$OS" = Darwin ]; then
  PLIST="$HOME/Library/LaunchAgents/com.watchtower.runner.plist"
  mkdir -p "$HOME/Library/LaunchAgents" "$HOME/Library/Logs"
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.watchtower.runner</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BIN_DIR/watchtower-runner</string>
    <string>--config</string>
    <string>$CONFIG</string>
    <string>run</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>$PATH_LINE</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>$HOME/Library/Logs/watchtower-runner.log</string>
  <key>StandardOutPath</key><string>$HOME/Library/Logs/watchtower-runner.log</string>
</dict>
</plist>
EOF
  launchctl bootout "gui/$(id -u)/com.watchtower.runner" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$PLIST"
  LOG="$HOME/Library/Logs/watchtower-runner.log"
  echo "runner started (launchd: com.watchtower.runner, log: $LOG)"
  echo "note: the runner works only while this Mac is awake — keep it on power with sleep disabled"
else
  UNIT_DIR="$HOME/.config/systemd/user"
  mkdir -p "$UNIT_DIR"
  cat > "$UNIT_DIR/watchtower-runner.service" <<EOF
[Unit]
Description=Watchtower agent-task runner

[Service]
Environment=PATH=$PATH_LINE
ExecStart=$BIN_DIR/watchtower-runner --config $CONFIG run
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
EOF
  # keep the user service running without a login session
  loginctl enable-linger "$(id -un)" 2>/dev/null || sudo -n loginctl enable-linger "$(id -un)" 2>/dev/null \
    || echo "warning: could not enable lingering — the runner stops when you log out" >&2
  systemctl --user daemon-reload
  systemctl --user enable --now watchtower-runner >/dev/null
  systemctl --user restart watchtower-runner
  echo "runner started (systemd --user: watchtower-runner, logs: journalctl --user -u watchtower-runner)"
fi
