# Contributing to siftsec

## Adding a Detection Rule in 5 Steps

1. **Read the engineering invariants:** Review [docs/decisions.md](docs/decisions.md) and [docs/ai-rules.md](docs/ai-rules.md) before writing code.
2. **Keep rules pure:** Rules in `siftsec/rules/` must not import cloud SDKs (`boto3`, `kubernetes`, `google-cloud-*`) or `subprocess`. Declare `required_attrs` so missing attributes emit `Status.ERROR` instead of false passes.
3. **Zero hardcoding:** Put all thresholds, ports, extensions, and weights in `SiftsecConfig` (`siftsec/config.py`).
4. **Redact secrets at construction:** Any matched credential or token must pass through `redact()` inside `BaseRule._build()`.
5. **Run the mandatory verification gate** before opening a PR:

```bash
uv run ruff check .
uv run ruff format --check siftsec tests
uv run mypy siftsec
uv run pytest
```

If you modified `rust/siftsec-core/`, also run:

```bash
cd rust/siftsec-core
cargo fmt --all -- --check
cargo test --release
cargo clippy --all-targets --all-features -- -D warnings
```

All contributions are licensed under the Apache-2.0 License with Developer Certificate of Origin (DCO).
