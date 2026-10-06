# Picket

[![CI](https://github.com/vrlda/picket/actions/workflows/ci.yml/badge.svg)](https://github.com/vrlda/picket/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Production server and application autopilot. A small agent watches the health and security of your servers, your apps send exceptions and custom business events, and a control plane correlates it all into incidents — then tells a human, or hands the incident to a coding agent (Claude Code) on an always-on machine and verifies the fix from production telemetry. No per-seat pricing, no cloud dependency — it runs on your own box or VPS.

From the maker of [Vulta](https://vulta.one), non-custodial card and crypto payments that settle straight to your own wallet.

## What it watches

| Area | Signals |
|---|---|
| **Host health** | CPU/memory/swap/load spikes, network-device errors, disk + inode exhaustion, read-only filesystems, OOM kills, kernel panics, clock changes, reboots |
| **Services** | systemd state changes, crash loops, unexpected restarts, app error-rate spikes (journald patterns) |
| **Security** | SSH logins, failures, brute-force, first-seen IPs, root/sudo activity, file changes (inotify), authorized_keys edits, new users, package installs, cron/systemd persistence changes, /tmp + /dev/shm execution, reverse-shell patterns, unexpected executables |
| **Network** | New listening ports (TCP + UDP), new outbound destinations, connection-rate spikes, port scans |
| **Applications** | Access-log parsing (5xx rate, request-rate spikes), TLS certificate expiry, Docker containers (state + crash loops), **in-app exception capture** with SDKs for Rust, Python, Node, and Go |
| **Uptime** | External HTTP(S) probes with failure thresholds |
| **Business events** | Anything your app reports: `payment.request_failed`, `checkout.conversion_sample`, `merchant.webhook_failed`, … with attributes and measurements; rules count, group and threshold them |

## How it works

- **Agent** (`picket-agent`) — a single binary per host. Polls systemd/journald/procfs, batches events, POSTs them to the control plane. JSONL disk spool with ack-based drain survives server outages; state (seen IPs, journal cursor, baselines) persists across restarts.
- **Server** (`picket-server`) — ingests events, runs rule-based correlation, groups them into **incidents**, and notifies. SQLite by default, Postgres supported. Headless — no web UI: you get alerted, and you acknowledge/resolve straight from the Telegram alert. An incident absorbs follow-up events (one timeline per problem) with a re-notify throttle.
- **Exception capture** — apps POST exceptions to `/v1/errors`; the server fingerprints them (type + service + first frames) and each recurring bug becomes one incident — same list, timeline, resolve and notify flow as infra events.
- **Custom events** — apps POST structured events to `/v1/events`; threshold rules (count / window / group-by / conditions) turn them into incidents, e.g. "10 payment failures for merchant mer_123 in 2 minutes" or "conversion below 70% on ≥100 attempts".
- **Runner** (`picket-runner`, optional) — runs on an always-on Mac or workstation, connects **outbound only** (works behind NAT), takes agent tasks for incidents and runs Claude Code on them: **over SSH on the affected host** (restart a dead service, free a full disk, revert a bad config) and/or in an isolated git worktree of your code. It reports a structured result. Picket resolves the incident only once it **observes recovery** — an agent saying "fixed" is not proof.

```
events (hosts, exceptions, apps) → rules → incident → notify (Telegram/Slack/webhook)
                                                     → agent task → runner → Claude Code → fix
                                                                    ↑                        ↓
                                        Picket verifies recovery ← production telemetry
```

## Quick start

```bash
cargo build --release

# agent, one-shot diagnostics on this host:
./target/release/picket-agent check

# control plane (server.toml: listen, db_url, auth_token, [[probes]]):
./target/release/picket-server --config /etc/picket/server.toml
```

## Install with Claude Code (hands-off)

Open this repository in Claude Code on the machine that should run the agent (e.g. your Mac, with SSH access to the servers) and say:

> Install Picket on root@203.0.113.10 as server and agent, and on deploy@198.51.100.7 as an agent.

Claude follows [`.claude/skills/install-picket/SKILL.md`](.claude/skills/install-picket/SKILL.md): control plane with automatic HTTPS (Caddy; `<ip>.sslip.io` if you have no domain), agents on every host, Telegram, and `picket-runner` on your machine with SSH access to all hosts — then verifies every piece. The only thing it asks you for is a Telegram bot token. The scripts it uses work on their own too: [`scripts/install-server.sh`](scripts/install-server.sh), [`scripts/install.sh`](scripts/install.sh) (agent), [`scripts/install-runner.sh`](scripts/install-runner.sh) (macOS/Linux).

## Install (Linux)

One command (fetches the latest release, verifies the checksum, installs):

```bash
curl -fsSL https://raw.githubusercontent.com/vrlda/picket/main/scripts/install.sh \
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
INSTALL_URL=https://github.com/vrlda/picket/releases/download/v0.6.0/picket-0.6.0-x86_64-unknown-linux-musl.tar.gz \
  INSTALL_SHA256=<hash from SHA256SUMS> \
  SERVER_URL=https://control.example.com TOKEN=secret \
  sudo bash scripts/install.sh
```

From a local build:

```bash
PICKET_BINARY=target/release/picket-agent \
  SERVER_URL=https://control.example.com TOKEN=secret \
  sudo bash scripts/install.sh
```

The agent runs as a dedicated `picket` user, `NoNewPrivileges=yes`, no capabilities.
Remote control planes must use HTTPS (terminate TLS at a reverse proxy if needed). The
installer permits plain HTTP only for loopback development addresses.

## Notifications

Telegram, Slack and generic webhook (routing editable in `server.toml` `[notify.routing]`). Critical/Warning incidents notify by default; the same incident re-notifies at most once per `notify_min_interval_secs` (default 60s).

### Telegram setup

1. In Telegram, talk to [@BotFather](https://t.me/BotFather): `/newbot` → pick a name → copy the token (`123456:ABC…`).
2. Start the server with the token, plus **one** of the two ways to choose the chat:

   ```bash
   # A) recommended — password handshake: send /start to your bot, then the password
   TELEGRAM_BOT_TOKEN=<token> TELEGRAM_BOT_PASSWORD=<secret> picket-server --config server.toml

   # B) pinned chat — no handshake at all
   TELEGRAM_BOT_TOKEN=<token> TELEGRAM_CHAT_ID=<chat id> picket-server --config server.toml
   ```

   With only `TELEGRAM_BOT_TOKEN`, the first chat that messages the bot becomes the target — convenient,
   but anyone who finds the bot first gets your alerts.
3. Check the server log: `telegram: bot @yourbot ready` confirms the token, then `telegram: delivering to chat …`
   (or a hint telling you what is still missing).
4. Verify delivery end to end: `TELEGRAM_BOT_TOKEN=… TELEGRAM_CHAT_ID=… bash scripts/notify-check.sh`.

To find a chat id for option B: message the bot, then open `https://api.telegram.org/bot<token>/getUpdates`
and read `message.chat.id` (group ids are negative; add the bot to the group first).

For a systemd install, put these variables in `/etc/picket/server.env` (the shipped unit reads it).

**Alerts and buttons.** Every alert carries **👀 Acknowledge** and **✅ Resolve** buttons. Pressing one updates
the incident and edits the alert in place ("✅ Resolved by @alice at …"), so everyone in the chat sees who took
it; after Acknowledge only Resolve remains, after Resolve the buttons disappear. Only presses from the
registered chat count — in a group chat, every member can act on alerts.

**One bot per server.** The buttons reach the server through the bot's update stream, which Telegram lets only
one process read. Several servers: create one bot per server (bots are free) and add them all to the same group.

The registered/discovered chat is stored in the database, so restarts keep delivering. Messages are plain
text, capped at Telegram's 4096-character limit (newest 10 timeline entries; the full timeline is at
`GET /v1/incidents/{id}`), and failed sends are retried. Wrong passwords lock a chat out after 5 attempts;
the accepted password message is deleted from the chat.

## SDKs: exceptions and custom events

Zero-dependency, config via `PICKET_ENDPOINT` / `PICKET_TOKEN` / `PICKET_HOST_ID` / `PICKET_SERVICE` / `PICKET_ENVIRONMENT`:

| Language | Location | Test |
|---|---|---|
| Rust | `crates/picket-sdk` | `cargo test -p picket-sdk` |
| Python | `sdk/python/picket.py` | `python3 sdk/python/test_picket.py` |
| Node | `sdk/node/picket.js` | `node --test sdk/node/test.js` |
| Go | `sdk/go/picket.go` | `cd sdk/go && go test ./...` |

Exceptions: `capture(...)`; Python's `capture_exception()` grabs the current exception; Rust adds `capture_panic()`. Levels: `fatal`/`error` → Critical, `warning` → Warning, `info`/`debug` → Info.

Custom events: `capture_event` (Node `captureEvent`, Go `CaptureEvent`):

```python
wt.capture_event("payment.request_failed", "Payment request failed",
                 severity="warning", subject=f"merchant:{merchant_id}",
                 attributes={"merchant_id": merchant_id, "provider": "a", "status_code": 502},
                 measurements={"latency_ms": 812})
```

Kinds are dotted lowercase names (`[a-z0-9._-]`, ≤128 chars, at least one dot); the built-in PascalCase kinds are reserved. `attributes` are dimensions rules can group and filter on; `measurements` are numbers rules can compare. Custom events become incidents only through rules — no rule, no alert. Non-goals: analytics, breadcrumbs, session replay, APM.

## Rules for custom events

```toml
# 10 failures for the same merchant within 2 minutes → one incident per merchant
[[rule]]
id = "merchant_payment_failures"
trigger = "payment.request_failed"
count = 10
window_secs = 120
group_by = ["attributes.merchant_id"]
severity = "Critical"
headline = "Payment failures for merchant {attributes.merchant_id} ({count} in {window}s)"
cause = "Repeated payment failures exceeded the threshold."
recommended_actions = ["Inspect recent failed requests", "Compare with successful requests"]
[rule.recovery]          # auto-resolve after 2 quiet minutes (verified recovery)
window_secs = 120

# business signal: conversion below 70% on meaningful volume
[[rule]]
id = "conversion_low"
trigger = "payment.conversion_sample"
group_by = ["attributes.merchant_id"]
severity = "Warning"
headline = "Conversion {measurements.conversion_rate} for {attributes.merchant_id}"
[[rule.where]]
field = "measurements.attempts"
op = ">="                # eq neq gt gte lt lte exists (or == != > >= < <=)
value = 100
[[rule.where]]
field = "measurements.conversion_rate"
op = "<"
value = 0.70
```

- `count` events matching `trigger` and every `where` within `window_secs`, per `group_by` key, open one incident keyed `rule:<id>:merchant_id=mer_123`; later matches absorb into it.
- Fields: `attributes.<name>`, `measurements.<name>`, `source` (alias `service`), `environment`, `subject`, `kind`, `severity`, `host_id`, `key`. Templates fill any of them (`{attributes.merchant_id}`), plus `{count}` and `{window}`.
- Exceptions from `/v1/errors` carry `source`, `environment` and `attributes.exception_type`, so `trigger = "AppException"` rules can group by service too.
- Existing rules (`supporting` / `min_supporting`) keep working unchanged.

## Autonomous response (agent dispatch)

An incident can wake a coding agent on an always-on machine — no human in the loop as transport.

**Simplest form — every incident, fixed over SSH.** On the server:

```toml
[runners.home-mac]
token = "<long random token>"

[agent_profiles.ops]

[auto_agent]              # incidents whose rule dispatches no agent itself
profile = "ops"
min_severity = "Warning"  # Info | Warning | Critical
```

On the runner (`runner.toml`):

```toml
[profiles.ops]            # no workspace: the agent works on the hosts
production = "remediate"  # none | diagnose | remediate (default)

[hosts."<host id>"]       # how to reach each Picket host; without an
ssh = "root@203.0.113.10" # entry the agent uses `ssh <host id>` (~/.ssh/config)
```

The agent gets the incident's host (and the other configured hosts) with an `ssh` command line. With `remediate` it may restart/reload services and containers, free disk space, fix permissions, renew certificates, revert a recent config change and stop runaway processes — capturing state first and listing every state-changing command in its result. It never deletes application data or backups, runs migrations, reboots, or touches firewall/SSH/auth settings or packages: those come back to you as `needs_human` with the exact commands it would run. `production` applies to every profile, including the code profiles below (set `none` to keep a profile off the hosts); `picket-runner check` verifies non-interactive SSH to every `[hosts]` entry.

**Per-rule dispatch, with code changes:**

**1. Server** (`server.toml`): a runner, a profile, and a rule that dispatches to it:

```toml
[runners.home-mac]
token = "<long random token>"
labels = ["payments"]

[agent_profiles.payment_api]
labels = ["payments"]          # or runner = "home-mac"
max_attempts = 2               # execution retries (runner crash, timeout, lost lease)
max_tasks_per_incident = 2     # fix → new failure → fix … loop guard
max_tasks_per_hour = 6
verify_timeout_secs = 1800     # fix must be observed within this time

[[rule]]
id = "merchant_payment_failures"
# … trigger / count / group_by as above, plus [rule.recovery] …
[[rule.dispatch]]
type = "agent"
profile = "payment_api"
[[rule.dispatch]]
type = "notify"
channel = "telegram"
policy = "on_agent_result"     # always | on_open | on_agent_start | on_agent_result |
                               # on_agent_success | on_agent_failure | on_escalation |
                               # on_verified_resolution | never
```

Without `notify` actions a rule uses the severity routing; agent start/success notices stay quiet then, while failures, escalations and verified recovery always reach you.

**2. Runner** (`runner.toml` on the machine with the code and the `claude` CLI). *How* the agent runs is configured here, never on the server — Picket can't make your machine run a command:

```toml
server_url = "https://picket.example.com"
runner_id = "home-mac"
token = "<same token>"
work_dir = "/Users/dan/.picket-runner"   # worktrees + logs

[profiles.payment_api]
adapter = "claude-code"         # or "command" with command = ["my-agent", ...] (prompt on stdin)
workspace = "/Users/dan/code/payment-platform"
autonomy = "patch"              # investigate | patch | commit | deploy
timeout_secs = 1800
blocked_paths = ["src/ledger/**", "src/settlement/**", "migrations/**"]
require_human_approval_paths = ["src/auth/**"]
prompt_file = "/Users/dan/.picket-runner/payment-api.md"   # optional extra instructions
# allowed_tools = ["Read", "Grep", "Glob", "Edit", "Write", "Bash(cargo test:*)"]
# model = "claude-opus-5-5"
```

```bash
picket-runner --config runner.toml check   # workspaces, CLI, ssh to [hosts], server connection
picket-runner --config runner.toml run      # or install deploy/com.picket.runner.plist (macOS) /
                                                 # deploy/picket-runner.service (Linux)
```

**What happens:** incident → durable task (one active task per incident) → the runner's long-poll claims it under a lease → Claude Code runs in a fresh git worktree on branch `picket/<task>` (your checkout is never touched) with the incident context → it classifies the problem (platform bug vs. client integration vs. invalid input vs. provider issue …), fixes within its autonomy, runs tests, and ends with a structured result → the runner checks the **actual** changes against the autonomy level and path rules (violations become a human escalation) → Picket records everything in the incident's activity log:

- `fixed` + `[rule.recovery]` → *awaiting verification*; the incident resolves only after the trigger stays quiet for the recovery window. A recurring failure resets the timer; no recovery within `verify_timeout_secs` → you're told the fix didn't verify.
- `fixed` with `fix_type: "mitigation"` (symptom relieved, root cause remains: a raised timeout, a restart of a leaking process) → you're always told, with the real fix still needed (`follow_up`), even on rules where agent successes stay quiet.
- `no_change` → diagnosis recorded (e.g. "merchant signs webhooks with the wrong secret").
- `needs_human` → Telegram gets the diagnosis and *exactly* what decision is needed; the incident is not re-dispatched.
- Runner offline / CLI crash / quota / timeout → retried up to `max_attempts`, then you're told. A task no runner picks up within 5 minutes alerts too.

**Security model:** runner tokens only reach runner endpoints; each claimed task gets its own context token (hashed at rest, valid only while the task runs) for the read-only context API; the context is secret-redacted (authorization headers, cookies, tokens, JWTs, private keys, URL credentials, card numbers); repository and production credentials stay on the runner; incident data is fenced in the prompt as **untrusted production data** — a merchant writing "ignore previous instructions…" into a request field is evidence, not an instruction.

## API

| Endpoint | Purpose |
|---|---|
| `POST /v1/telemetry` | Agent event batches (idempotent per event id) |
| `POST /v1/heartbeat` | Host registration/heartbeat |
| `POST /v1/errors` | App exception capture (fingerprint-grouped) |
| `GET /v1/hosts` | Host registry |
| `POST /v1/events` | One custom event (`kind` + `summary` required; idempotent per `id`) |
| `GET /v1/events?host=&kind=&severity=&source=&environment=&subject=&incident_id=&since=&until=&attr.<name>=&limit=` | Event queries (ordered by ts, id — never arrival order) |
| `GET /v1/incidents` | Incidents |
| `GET /v1/incidents/{id}` | Incident with timeline, activity log and agent tasks |
| `GET /v1/incidents/{id}/events` | The incident's events (same filters as `/v1/events`) |
| `POST /v1/incidents/{id}/ack` · `/resolve` | Acknowledge / resolve (409 if the incident is already resolved) |
| `POST /v1/runners/register` · `/heartbeat` | Runner check-in (runner token) |
| `GET /v1/agent-tasks/next?timeout=30` | Long-poll: claims the next task under a lease (runner token) |
| `POST /v1/agent-tasks/{id}/heartbeat` · `/started` · `/complete` · `/fail` | Lease renewal and results (runner token; 409 = lease lost) |
| `GET /v1/agent-tasks/{id}/context` · `/events` | Incident context for the working agent (task token; redacted) |

Curl exception reference:

```bash
curl -fsS -X POST http://SERVER:8787/v1/errors \
  -H "Authorization: Bearer $PICKET_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"host_id":"web-1","service":"api","environment":"prod",
       "exception":{"type":"ValueError","message":"bad input","level":"error",
       "frames":[{"file":"app.py","line":42,"function":"validate"}]}}'
```

## Configuration

Agent (`agent.toml`): `state_file`, `watch_paths`, `watch_authorized_keys`, `ssh_brute_threshold`, `ssh_brute_window_secs`, `error_patterns`, `error_window_secs`, `error_threshold`, `docker_enabled`, `cert_paths`, `cert_warn_days`, `cert_crit_days`, `cert_scan_interval_secs`, `access_log_paths`, `request_rate_threshold`, `request_rate_window_secs`, `process_scan_interval_secs`, `scan_threshold`, `scan_window_secs`.

Server (`server.toml`): `listen`, `db_url` (sqlite default; `postgres://` supported), `auth_token`, `host_tokens` (per-host tokens — an agent presenting one is attributed to that host, payload `host_id` overridden), `[event_sources.<name>]` (`token`, `source`, `environment` — a per-application token that can only post events and pins their source), `notify_min_interval_secs`, `[[probes]]` (uptime checks), `[notify.routing]`, `[[rule]]` (with `count`, `group_by`, `[[rule.where]]`, `[rule.recovery]`, `[[rule.dispatch]]`), `[runners.<id>]`, `[agent_profiles.<name>]`, `[auto_agent]` (`profile`, `min_severity`). Runner (`runner.toml`): `server_url`, `runner_id`, `token`, `work_dir`, `[hosts.<host id>]` (`ssh`), `[profiles.<name>]` (`workspace`, `autonomy`, `production`, `adapter`, `model`, ...).

## Development

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
./scripts/integration-test.sh        # end-to-end against a live server
bash -n scripts/*.sh                 # shell syntax
python3 sdk/python/test_picket.py && node --test sdk/node/test.js
cd sdk/go && go test ./...
```

On a Linux box with systemd (the tests exercise journald/systemctl/procfs):

```bash
sudo env "PATH=$PATH" bash scripts/verify-linux.sh
```

CI runs all of the above (ubuntu + macos + Postgres + SDK jobs).

## License

MIT — see [LICENSE](LICENSE).
