<div align="center">

# siftsec

**Correlate, deduplicate, and rank scanner findings by attacker reachability.**

<p>
  <a href="https://github.com/VasisthaVed/siftsec/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/VasisthaVed/siftsec/ci.yml?branch=main&style=flat-square&label=CI" alt="CI Status"></a>
  <a href="https://github.com/VasisthaVed/siftsec/actions/workflows/rust-gates.yml"><img src="https://img.shields.io/github/actions/workflow/status/VasisthaVed/siftsec/rust-gates.yml?branch=main&style=flat-square&label=Rust%20Gates" alt="Rust Gates"></a>
  <a href="https://github.com/VasisthaVed/siftsec/actions/workflows/wheels.yml"><img src="https://img.shields.io/github/actions/workflow/status/VasisthaVed/siftsec/wheels.yml?branch=main&style=flat-square&label=Wheels" alt="Wheels"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.12%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.12+"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.88%2B-DEA584?style=flat-square&logo=rust&logoColor=black" alt="Rust 1.88+"></a>
  <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json&style=flat-square" alt="Ruff"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License: Apache-2.0"></a>
</p>

</div>

---

## The Problem

Engineering teams already run multiple static, container, and cloud posture scanners, yet triage queues keep growing:

- **61% of security alerts** are false positives in the developer's specific code path (Safeguard, 540-developer survey, 2026).
- **68% of organizations** run 3 or more overlapping scanners on every pull request (Safeguard, 2026).
- **54% of developers** have bypassed a security gate in the last 12 months because it blocked a release without clear justification (Safeguard, 2026).

Running a fourth scanner adds more noise to the same queue. `siftsec` sits downstream of existing scanners: it normalizes their SARIF 2.1.0 and native JSON outputs into a single schema, deduplicates overlapping findings across tools, and ranks what remains by graph reachability.

---

## Quickstart

### CLI (Built-in Posture & Demo)

```bash
uv run siftsec --help
uv run siftsec scan --demo --output siftsec-demo.sarif
uv run siftsec list-rules
```

### Correlation & Reachability Pipeline (Python API)

```python
from siftsec.ingest import ingest_sarif_bytes, index_findings
from siftsec.ingest.graph import build_graph_and_score

# 1. Normalize SARIF 2.1.0 outputs from multiple scanners
findings = ingest_sarif_bytes(modelaudit_sarif, source_tool="modelaudit")
findings += ingest_sarif_bytes(trivy_sarif, source_tool="trivy")

# 2. Collapse duplicates deterministically across tools
deduped = index_findings(findings)

# 3. Compute shortest-witness attacker reachability over topology graph
result = build_graph_and_score(graph_payload)
```

---

## What It Does / What It Does Not

| What `siftsec` Does | What `siftsec` Does Not Do |
| :--- | :--- |
| Ingests SARIF 2.1.0 and native JSON from existing scanners (`ModelAudit`, `Trivy`, `Prowler`, `Semgrep`, `MCPiranha`, `mcpvuln`, `agent-bom`, `mcp-tool-auditor`, `agent-audit-kit`, `Cisco MCP Scanner`) | Does not replace primary vulnerability, SAST, or cloud posture scanners |
| Deduplicates findings pointing to the same component, rule/CWE, and location across tools | Does not ship a web dashboard or hosted SaaS control plane |
| Ranks findings by attacker reachability over a directed resource, skill, and `model_handoff` graph | Does not maintain a persistent database or telemetry backend |
| Explains each finding's severity, merged `sources`, and shortest witness path | Does not write to, modify, or mutate any cloud account or cluster |

---

## Architecture & Performance

```text
scanners  -->  ingest  -->  dedup  -->  reachability  -->  score  -->  SARIF
(already       (10.1)       (10.2)      (10.3)             (10.4)      (10.5)
 running)

  Python 3.12+ / Rust FFI (PyO3 0.29, abi3-py312)
  ├── parse_json_bounded : 64 MiB cap + depth pre-pass + serde_stacker
  ├── index_findings     : SipHash-1-3 primary index on sha256(component|rule|loc)
  ├── build_graph_and_score : petgraph DiGraph BFS shortest-witness (max_hops=8)
  └── pure-Python fallback  : identical behavior when siftsec._core is absent
```

### Measured Benchmarks (Criterion, release build)

| Stage | Workload | Measured Latency | Gate |
| :--- | :--- | :--- | :--- |
| Cross-tool dedup (`10.2`) | 200 normalized findings | **0.471 ms** | <= 5 ms |
| Graph BFS reachability (`10.3`) | 1,000 nodes / 5,000 edges | **3.36 ms** | <= 40 ms |

Input streams pass through `parse_json_bounded` before tree allocation (64 MiB byte cap, nesting-depth pre-pass, and `serde_stacker` recursion guard). Deduplication keys use Rust's SipHash-1-3 `HashMap` to prevent hash-flooding DoS on untrusted scanner inputs, and all graph/dedup outputs are sorted deterministically before crossing back to Python.

---

## Compatibility

- **Python:** 3.12+
- **Prebuilt wheels (`abi3-py312`):** `linux-x86_64`, `macos-arm64`, `windows-x64`
- **Rust toolchain (source builds):** Rust 1.88+

---

## Development & Verification

```bash
# Sync Python dev environment
uv sync --extra dev

# Build and install the native Rust extension locally
uvx maturin build --release --strip --manifest-path rust/siftsec-core/Cargo.toml --out dist
uv pip install --force-reinstall dist/siftsec_core-*.whl

# Run all quality, type, and test gates
uv run ruff check .
uv run ruff format --check siftsec tests
uv run mypy siftsec
uv run pytest
```

For Rust-only checks:

```bash
cd rust/siftsec-core
cargo fmt --all -- --check
cargo test --release
cargo clippy --all-targets --all-features -- -D warnings
```

---

## Limitations

- Static analysis cannot detect Semantic Compliance Hijacking (0.00% detection rate across evaluated scanners, 2026 research).
- Reachability uses static graph traversal over collected topology snapshots, not runtime eBPF or agent instrumentation.
- End-to-end alert-reduction and precision benchmark results are pending Phase 10.6 (this line will be updated with measured numbers, or a published negative result, when 10.6 completes).

---

## Threat Model, Security & Docs

- **Vulnerability disclosure:** [SECURITY.md](SECURITY.md)
- **Threat model:** [docs/threat-model.md](docs/threat-model.md)
- **Architecture & ADRs:** [docs/architecture.md](docs/architecture.md) · [docs/decisions.md](docs/decisions.md)
- **Migration guide:** [MIGRATION.md](MIGRATION.md)

---

## License

Apache-2.0 — see [LICENSE](LICENSE).
