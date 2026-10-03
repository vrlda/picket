#!/usr/bin/env bash
# Build a release tarball + checksums.
# Usage: TARGETS="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu" sh scripts/release.sh
# Cross targets need a C toolchain (see the zig wrapper used during M3-M5 checks).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(grep -m1 '^version' "$ROOT/crates/picket-common/Cargo.toml" | sed 's/version = "\(.*\)"/\1/' | tr -d ' "')"
TARGETS="${TARGETS:-$(rustc -vV | sed -n 's/^host: //p')}"
DIST="$ROOT/dist"
mkdir -p "$DIST"

for target in $TARGETS; do
  echo "==> building $target"
  (cd "$ROOT" && cargo build --release --target "$target" -p picket-agent -p picket-server -p picket-runner)
  TARBALL="$DIST/picket-$VERSION-$target.tar.gz"
  cat > "$ROOT/target/$target/release/picket-server.service" <<UNIT
[Unit]
Description=Picket control plane
After=network-online.target
Wants=network-online.target

[Service]
User=picket
Group=picket
# TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID / TELEGRAM_BOT_PASSWORD (optional file)
EnvironmentFile=-/etc/picket/server.env
ExecStart=/usr/local/bin/picket-server
Restart=always
RestartSec=5
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/picket
NoNewPrivileges=yes
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNIT
  tar -C "$ROOT/target/$target/release" -czf "$TARBALL" picket-agent picket-server picket-runner picket-server.service
  echo "built $TARBALL"
done

echo "==> checksums"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$DIST" && sha256sum picket-*.tar.gz > SHA256SUMS)
else
  (cd "$DIST" && shasum -a 256 picket-*.tar.gz > SHA256SUMS)
fi
cat "$DIST/SHA256SUMS"
