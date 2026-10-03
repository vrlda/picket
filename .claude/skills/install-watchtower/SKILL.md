---
name: install-watchtower
description: Install Watchtower end to end on the user's servers over SSH — control plane, agents, HTTPS, Telegram, and the Claude Code runner on this machine — with no manual steps. Use when the user asks to install, set up or deploy Watchtower on one or more servers.
---

# Install Watchtower

The user names servers and roles, e.g. "install it on root@1.2.3.4 as server
and agent, and on deploy@5.6.7.8 as an agent". You do everything else. The
only thing you may need from them is a Telegram bot token (step 0).

Layout you are building:

- **server host**: `watchtower-server` behind Caddy (automatic HTTPS), plus
  `watchtower-agent` monitoring the host itself.
- **agent hosts**: `watchtower-agent`, reporting to the server over HTTPS.
- **this machine** (where you, Claude Code, run): `watchtower-runner`. It
  takes incidents from the server and runs `claude` headless with SSH access
  to every host, so incidents get fixed autonomously.

Run the scripts from this checkout (`scripts/`). They download the latest
release binaries and verify checksums, and they are safe to re-run: if a
step fails, fix the cause and run it again.

## 0. Inputs

- SSH destinations and roles: from the user's request. Ask only if a role
  is ambiguous.
- Telegram: ask once, in a single message, for a bot token (BotFather →
  /newbot) and ask them to send any message to the bot. Then get the chat id
  yourself:
  `curl -s https://api.telegram.org/bot<TOKEN>/getUpdates` →
  `result[-1].message.chat.id`. If they don't want Telegram, continue without
  it.
- A domain is optional. Without one, the server gets `<ip-with-dashes>.sslip.io`
  with a real certificate.

## 1. Preflight (every host)

```bash
ssh -o BatchMode=yes <dest> 'id -u; sudo -n true && echo sudo-ok; uname -m; systemctl --version | head -1; hostname -s'
```

You need key-based SSH, root or passwordless sudo, systemd, and x86_64 or
aarch64. If a check fails, tell the user exactly what is missing. Don't work
around missing access.

**Pick a host id for each host:** its short hostname, unless it's
meaningless (e.g. `ubuntu`, `localhost`, a cloud default like
`ip-10-0-0-5`) or two hosts share it. In that case use a name from the
user's words ("web", "db") or the IP with dashes. The host id is how the host
appears in alerts, and it's what the runner's `--host` maps to an SSH
destination, so use the same id everywhere below.

On this machine: `claude --version` must work and you must be logged in.
The runner also needs this machine to stay on: say so if it's a laptop.

## 2. Server host

```bash
scp scripts/install-server.sh scripts/install.sh <server>:/tmp/
ssh <server> 'sudo bash /tmp/install-server.sh --with-agent --host-id <its host id> \
  --runner-id <short name of this machine, e.g. home-mac> \
  [--telegram-token <token> --telegram-chat-id <chat id>] [--domain <domain>]'
```

The last lines of output are `WATCHTOWER_URL`, `WATCHTOWER_AUTH_TOKEN`,
`WATCHTOWER_RUNNER_ID` and `WATCHTOWER_RUNNER_TOKEN`. They are also kept in
`/etc/watchtower/install.env`, readable by root only. Treat them as secrets:
don't echo them back to the user.

- Exit code 2 means ports 80/443 are already taken by another web server.
  Add a reverse proxy in that server from the public name to
  `http://127.0.0.1:8787`, reload it, then re-run with
  `--no-proxy --public-url https://<name>`.
- "not reachable" means the provider's firewall or security group blocks
  80/443. If you have a CLI for the provider, open them. Otherwise tell the
  user the exact ports.

## 3. Agent hosts

```bash
scp scripts/install.sh <host>:/tmp/
ssh <host> 'sudo bash /tmp/install.sh --server-url <WATCHTOWER_URL> --token <WATCHTOWER_AUTH_TOKEN> --host-id <its host id>'
```

## 4. Runner (this machine)

```bash
bash scripts/install-runner.sh --server-url <WATCHTOWER_URL> \
  --runner-id <WATCHTOWER_RUNNER_ID> --token <WATCHTOWER_RUNNER_TOKEN> \
  --host <server host id>=<its ssh dest> \
  --host <each agent host id>=<its ssh dest>
```

Use the same SSH destinations you used above. The script runs
`watchtower-runner check` first: Claude CLI found, every host reachable over
SSH, server connection OK. It installs the service only if the check passes.

## 5. Verify, then report

```bash
curl -fsS -H "Authorization: Bearer <WATCHTOWER_AUTH_TOKEN>" <WATCHTOWER_URL>/v1/hosts
```

Every host should be listed with a recent `last_seen`. Agents heartbeat
every 30s, so wait up to a minute. The runner log should say
`<runner id> connected to <url>`. On macOS the log is
`~/Library/Logs/watchtower-runner.log`; on Linux use
`journalctl --user -u watchtower-runner`.

Tell the user, briefly:

- what runs where;
- that Warning/Critical incidents go to Telegram, and to Claude on this
  machine, which may fix hosts over SSH. It restarts services, frees disk and
  reverts bad config. It never deletes data, reboots, or changes
  firewall/SSH/auth settings; for those it asks a human on Telegram;
- the server URL. Don't include tokens.

## Changing things later

- **Add a host**: run step 3 on it, then re-run step 4 with the extra `--host`.
- **Read-only Claude**: set `production = "diagnose"` in
  `~/.watchtower-runner/runner.toml` under `[profiles.ops]`, then restart the
  runner.
- **No autonomous response**: remove `[auto_agent]` from
  `/etc/watchtower/server.toml` and restart `watchtower-server`.
