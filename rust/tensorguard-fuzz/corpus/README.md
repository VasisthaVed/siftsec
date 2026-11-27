# Fuzz Seed Corpus (`rust/tensorguard-fuzz`)

- `json_stream/`: seed payloads for `parse_bounded` (`seed_sarif.json`, `seed_mcp.json`).
- `dedup/`: TODO(10.2) — seed normalized findings from multiple scanners.
- `graph/`: TODO(10.3) — seed correlation topologies (`DiGraph<u32>`).

> Note: `cargo-fuzz` requires Linux + nightly toolchain (`cargo +nightly fuzz run <target>`).
