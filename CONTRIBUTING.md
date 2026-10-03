# Contributing

Picket is built plan-first: every milestone ships with a task-by-task
TDD plan under `docs/superpowers/plans/` before code lands.

## Workflow

1. Write the plan (or extend an existing one) in `docs/superpowers/plans/`.
2. Execute task-by-task with tests-first discipline (red → green → commit).
3. Every task gets a spec-compliance review and a code-quality review before
   the next task starts.

## Conventions

- Rust edition 2021, `cargo fmt`, `clippy --all-targets -- -D warnings` clean.
- OS reads (procfs, journalctl, systemctl, docker) go through injectable
  readers — unit tests never need root or a real host; fixtures live in
  `crates/*/tests/fixtures/`.
- Timestamps are i64 unix millis everywhere; wire enum names are PascalCase.
- Event timelines are ordered by (ts, id) — never arrival order.
- Shell scripts: bash with `set -euo pipefail`; verify with `bash -n`.

## Verifying

    cargo test --workspace
    cargo clippy --workspace --all-targets -- -D warnings
    cargo fmt --all --check
    ./scripts/integration-test.sh
    # on a Linux box: sudo sh scripts/verify-linux.sh
