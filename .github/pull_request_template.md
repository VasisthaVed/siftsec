## Summary

<!-- Describe what this PR changes and why. -->

## Verification

Run the mandatory local gates before requesting review:

- [ ] `uv run ruff check .`
- [ ] `uv run ruff format --check siftsec tests`
- [ ] `uv run mypy siftsec`
- [ ] `uv run pytest`
- [ ] `cargo test --release` and `cargo clippy --all-targets --all-features -- -D warnings` (if `rust/` was modified)
