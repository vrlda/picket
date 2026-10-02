#!/usr/bin/env bash
# Build a release tarball + checksums.
# Usage: TARGETS="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu" sh scripts/release.sh
# Cross targets need a C toolchain (see the zig wrapper used during M3-M5 checks).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(grep -m1 '^version' "$ROOT/crates/wt-common/Cargo.toml" | sed 's/version = "\(.*\)"/\1/' | tr -d ' "')"
TARGETS="${TARGETS:-$(rustc -vV | sed -n 's/^host: //p')}"
DIST="$ROOT/dist"
mkdir -p "$DIST"

for target in $TARGETS; do
  echo "==> building $target"
  (cd "$ROOT" && cargo build --release --target "$target" -p watchtower-agent -p watchtower-server -p watchtower-runner)
  TARBALL="$DIST/watchtower-$VERSION-$target.tar.gz"
  cat > "$ROOT/target/$target/release/watchtower-server.service" <<UNIT
[Unit]
Description=Watchtower control plane
After=network-online.target
Wants=network-online.target

[Service]
User=watchtower
Group=watchtower
# TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID / TELEGRAM_BOT_PASSWORD (optional file)
EnvironmentFile=-/etc/watchtower/server.env
ExecStart=/usr/local/bin/watchtower-server
Restart=always
RestartSec=5
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/watchtower
NoNewPrivileges=yes
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNIT
  tar -C "$ROOT/target/$target/release" -czf "$TARBALL" watchtower-agent watchtower-server watchtower-runner watchtower-server.service
  echo "built $TARBALL"
done

echo "==> checksums"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$DIST" && sha256sum watchtower-*.tar.gz > SHA256SUMS)
else
  (cd "$DIST" && shasum -a 256 watchtower-*.tar.gz > SHA256SUMS)
fi
cat "$DIST/SHA256SUMS"
