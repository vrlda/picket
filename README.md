# Watchtower

[![CI](https://github.com/vrlda/watchtower/actions/workflows/ci.yml/badge.svg)](https://github.com/vrlda/watchtower/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Production server autopilot. One small agent watches the health and security of a server; a control plane correlates the signals into incidents and tells you about them. No per-seat pricing, no cloud dependency — it runs on your own box or VPS.

## What it watches

| Area | Signals |
|---|---|
| **Host health** | CPU/memory/swap/load spikes, network-device errors, disk + inode exhaustion, read-only filesystems, OOM kills, kernel panics, clock changes, reboots |
| **Services** | systemd state changes, crash loops, unexpected restarts, app error-rate spikes (journald patterns) |
| **Security** | SSH logins, failures, brute-force, first-seen IPs, root/sudo activity, file changes (inotify), authorized_keys edits, new users, package installs, cron/systemd persistence changes, /tmp + /dev/shm execution, reverse-shell patterns, unexpected executables |
| **Network** | New listening ports (TCP + UDP), new outbound destinations, connection-rate spikes, port scans |
| **Applications** | Access-log parsing (5xx rate, request-rate spikes), TLS certificate expiry, Docker containers (state + crash loops), **in-app exception capture** with SDKs for Rust, Python, Node, and Go |
| **Uptime** | External HTTP(S) probes with failure thresholds |

## How it works

- **Agent** (`watchtower-agent`) — a single binary per host. Polls systemd/journald/procfs, batches events, POSTs them to the control plane. JSONL disk spool with ack-based drain survives server outages; state (seen IPs, journal cursor, baselines) persists across restarts.
- **Server** (`watchtower-server`) — ingests events, runs rule-based correlation, groups them into **incidents**, and notifies. SQLite by default, Postgres supported. Web UI included. An incident absorbs follow-up events (one timeline per problem) with a re-notify throttle.
- **Exception capture** — apps POST exceptions to `/v1/errors`; the server fingerprints them (type + service + first frames) and each recurring bug becomes one incident — same list, timeline, resolve and notify flow as infra events.

## Quick start

```bash
cargo build --release

# agent, one-shot diagnostics on this host:
./target/release/watchtower-agent check

# control plane (server.toml: listen, db_url, auth_token, [[probes]]):
./target/release/watchtower-server --config /etc/watchtower/server.toml
```

## Install (Linux)

One command (fetches the latest release, verifies the checksum, installs):

```bash
curl -fsSL https://raw.githubusercontent.com/vrlda/watchtower/main/scripts/install.sh \
  | sudo bash -s -- --server-url https://control.example.com --token secret
```

The `--server-url`/`--token` flags also work on a local script run (`SERVER_URL`/`TOKEN`
env vars are the flag fallback):

```bash
sudo bash scripts/install.sh --server-url https://control.example.com --token secret
```

Pin a version (the tarball URL pattern is `<release>/download/<tag>/`; tarballs are
named after the crate version, not the tag):

```bash
INSTALL_URL=https://github.com/vrlda/watchtower/releases/download/v0.2.1/watchtower-0.2.1-x86_64-unknown-linux-musl.tar.gz \
  INSTALL_SHA256=<hash from SHA256SUMS> \
  SERVER_URL=https://control.example.com TOKEN=secret \
  sudo bash scripts/install.sh
```

From a local build:

```bash
WATCHTOWER_BINARY=target/release/watchtower-agent \
  SERVER_URL=https://control.example.com TOKEN=secret \
  sudo bash scripts/install.sh
```

The agent runs as a dedicated `watchtower` user, `NoNewPrivileges=yes`, no capabilities.
Remote control planes must use HTTPS (terminate TLS at a reverse proxy if needed). The
installer permits plain HTTP only for loopback development addresses.

## Web UI

`http://<server>:8787/` — hosts, events, incidents (timeline, evidence, acknowledge/resolve). Token-prompted, static files served by the server itself (`WATCHTOWER_UI_DIR` for installed deploys).

## Notifications

Telegram and generic webhook (routing editable in `server.toml` `[notify.routing]`). Critical/Warning incidents notify by default; the same incident re-notifies at most once per `notify_min_interval_secs` (default 60s).

### Telegram setup

1. In Telegram, talk to [@BotFather](https://t.me/BotFather): `/newbot` → pick a name → copy the token (`123456:ABC…`).
2. Start the server with the token, plus **one** of the two ways to choose the chat:

   ```bash
   # A) recommended — password handshake: send /start to your bot, then the password
   TELEGRAM_BOT_TOKEN=<token> TELEGRAM_BOT_PASSWORD=<secret> watchtower-server --config server.toml

   # B) pinned chat — no handshake at all (required when several servers share one bot)
   TELEGRAM_BOT_TOKEN=<token> TELEGRAM_CHAT_ID=<chat id> watchtower-server --config server.toml
   ```

   With only `TELEGRAM_BOT_TOKEN`, the first chat that messages the bot becomes the target — convenient,
   but anyone who finds the bot first gets your alerts.
3. Check the server log: `telegram: bot @yourbot ready` confirms the token, then `telegram: delivering to chat …`
   (or a hint telling you what is still missing).
4. Verify delivery end to end: `TELEGRAM_BOT_TOKEN=… TELEGRAM_CHAT_ID=… bash scripts/notify-check.sh`.

To find a chat id for option B: message the bot, then open `https://api.telegram.org/bot<token>/getUpdates`
and read `message.chat.id` (group ids are negative; add the bot to the group first).

The registered/discovered chat is stored in the database, so restarts keep delivering. Messages are plain
text, capped at Telegram's 4096-character limit (newest 10 timeline entries + a link to the full incident),
and failed sends are retried. Wrong passwords lock a chat out after 5 attempts; the accepted password
message is deleted from the chat.

## Exception capture SDKs

Zero-dependency, config via `WATCHTOWER_ENDPOINT` / `WATCHTOWER_TOKEN` / `WATCHTOWER_HOST_ID` / `WATCHTOWER_SERVICE` / `WATCHTOWER_ENVIRONMENT`:

| Language | Location | Test |
|---|---|---|
| Rust | `crates/watchtower-sdk` | `cargo test -p watchtower-sdk` |
| Python | `sdk/python/watchtower.py` | `python3 sdk/python/test_watchtower.py` |
| Node | `sdk/node/watchtower.js` | `node --test sdk/node/test.js` |
| Go | `sdk/go/watchtower.go` | `cd sdk/go && go test ./...` |

Python's `capture_exception()` grabs the current exception; Rust adds `capture_panic()`. Any language can POST directly (curl reference in the README below, section "API"). Levels: `fatal`/`error` → Critical, `warning` → Warning, `info`/`debug` → Info. Non-goals: breadcrumbs, session replay, APM, release tracking.

## API

| Endpoint | Purpose |
|---|---|
| `POST /v1/telemetry` | Agent event batches (idempotent per event id) |
| `POST /v1/heartbeat` | Host registration/heartbeat |
| `POST /v1/errors` | App exception capture (fingerprint-grouped) |
| `GET /v1/hosts` | Host registry |
| `GET /v1/events?host=&kind=&severity=&since=&limit=` | Event queries (ordered by ts, id — never arrival order) |
| `GET /v1/incidents` | Incidents with timelines |

Curl exception reference:

```bash
curl -fsS -X POST http://SERVER:8787/v1/errors \
  -H "Authorization: Bearer $WATCHTOWER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"host_id":"web-1","service":"api","environment":"prod",
       "exception":{"type":"ValueError","message":"bad input","level":"error",
       "frames":[{"file":"app.py","line":42,"function":"validate"}]}}'
```

## Configuration

Agent (`agent.toml`): `state_file`, `watch_paths`, `watch_authorized_keys`, `ssh_brute_threshold`, `ssh_brute_window_secs`, `error_patterns`, `error_window_secs`, `error_threshold`, `docker_enabled`, `cert_paths`, `cert_warn_days`, `cert_crit_days`, `cert_scan_interval_secs`, `access_log_paths`, `request_rate_threshold`, `request_rate_window_secs`, `process_scan_interval_secs`, `scan_threshold`, `scan_window_secs`.

Server (`server.toml`): `listen`, `db_url` (sqlite default; `postgres://` supported), `auth_token`, `host_tokens` (per-host tokens — an agent presenting one is attributed to that host, payload `host_id` overridden), `notify_min_interval_secs`, `[[probes]]` (uptime checks), `[notify.routing]`.

## Development

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
./scripts/integration-test.sh        # end-to-end against a live server
bash -n scripts/*.sh                 # shell syntax
python3 sdk/python/test_watchtower.py && node --test sdk/node/test.js
cd sdk/go && go test ./...
```

On a Linux box with systemd (the tests exercise journald/systemctl/procfs):

```bash
sudo env "PATH=$PATH" bash scripts/verify-linux.sh
```

CI runs all of the above (ubuntu + macos + Postgres + SDK jobs).

## License

MIT — see [LICENSE](LICENSE).
