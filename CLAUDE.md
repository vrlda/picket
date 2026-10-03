# Picket

Server monitoring with Telegram alerts and autonomous incident response:
agents on each server → control plane (`picket-server`) → Telegram,
plus `picket-runner`, which hands incidents to Claude Code with SSH
access to the hosts.

**Installing on the user's servers:** follow
`.claude/skills/install-picket/SKILL.md`. It is fully scripted and needs
no manual steps from the user apart from a Telegram bot token.

## Development

- Rust workspace: `crates/{picket-common,agent,server,runner,picket-sdk}`. SDKs live in `sdk/`.
- Before pushing, run `cargo fmt --all`, then
  `cargo clippy --workspace --all-targets -- -D warnings`, then `cargo test --workspace`.
- Releases: bump `version` in every `crates/*/Cargo.toml` and the README
  install URL, then run the Release workflow (`workflow_dispatch`, input `tag`).
