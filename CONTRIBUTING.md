# Contributing

Thanks for contributing.

## Ground rules

- One PR = one focused change.
- Add tests for behavior changes.
- Keep secrets out of commits.
- Prefer small, reviewable diffs.

## Local checks

- Ensure workflows pass on your PR.
- For `hwvault`, run:
  - `cargo build --release --bin openclaw-hwvault-resolver`
  - `cargo test --bin openclaw-hwvault-resolver`

## Security-sensitive changes

For auth, token, policy, or secret-resolution changes:

- document threat assumptions
- include negative tests (deny-paths)
- include migration notes if behavior changes
