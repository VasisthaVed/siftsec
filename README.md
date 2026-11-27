# siftsec

`siftsec` — take scanner output from tools you already run, collapse the duplicates, and rank by what an attacker can actually reach.

---

## The Problem

Engineering teams already run multiple static, container, and cloud posture scanners, yet triage queues keep growing:

- **61% of security alerts** are false positives in the developer's specific code path (Safeguard, 540-developer survey, 2026).
- **68% of organizations** run 3 or more overlapping scanners on every pull request (Safeguard, 2026).
- **54% of developers** have bypassed a security gate in the last 12 months because it blocked a release without clear justification (Safeguard, 2026).

Running a fourth scanner adds more noise to the same queue. `siftsec` sits downstream of existing scanners: it normalizes their SARIF 2.1.0 and native JSON outputs into a single schema, deduplicates overlapping findings across tools, and ranks what remains by graph reachability.

---

## Quickstart

```bash
pip install siftsec
siftsec ingest --sarif modelaudit.sarif --sarif trivy.sarif --out combined.sarif
siftsec reach --sarif combined.sarif --cloud-snapshot cloud.json
```

---

## What It Does / What It Does Not

| What `siftsec` Does | What `siftsec` Does Not Do |
| :--- | :--- |
| Ingests SARIF 2.1.0 and native JSON from existing scanners (`ModelAudit`, `Trivy`, `Prowler`, `Semgrep`, `MCPiranha`, `mcpvuln`, `agent-bom`, `mcp-tool-auditor`, `agent-audit-kit`, `Cisco MCP Scanner`) | Does not act as a primary vulnerability or cloud scanner |
| Deduplicates findings that point to the same component, rule/CWE, and location across tools | Does not ship a web dashboard or SaaS control plane |
| Ranks findings by attacker reachability over a resource and dependency graph | Does not maintain a persistent database or telemetry backend |
| Explains each finding's severity, merged tool sources, and graph path in SARIF, JSON, or Markdown | Does not write to, modify, or mutate any cloud account or cluster |

---

## Architecture

```text
scanners  -->  ingest  -->  dedup  -->  reachability  -->  score  -->  SARIF
(already       (10.1)       (10.2)      (10.3)             (10.4)      (10.5)
 running)

  Python / Rust FFI (PyO3, abi3-py312)
  - parse_json_bounded: byte cap + depth pre-pass + serde_stacker
  - SipHash-1-3 primary index on untrusted SARIF keys
  - Pure-Python fallback when native extension is unavailable
```

### How It Works

Each input stream passes through `parse_json_bounded`, which enforces three hard limits before allocating a JSON tree: a 64 MiB byte cap, a byte-level nesting-depth pre-pass (default 64), and `serde_stacker` recursion protection. Normalized findings carry `schema_version = 1` and are keyed deterministically by `sha256(component_hash | rule_or_cwe | location)` using Rust's default SipHash-1-3 `HashMap` to prevent hash-flooding DoS on untrusted scanner inputs. Merged entities preserve every contributing tool in `sources` and sort deterministically before crossing back to Python. A pure-Python fallback implementation provides identical behavior when the compiled `siftsec._core` wheel is absent.

---

## Compatibility

- **Python:** 3.12+
- **Prebuilt wheels (`abi3-py312`):** `linux-x86_64`, `linux-aarch64`, `macos-arm64`, `macos-x86_64`, `windows-x64`
- **Rust toolchain (source builds):** Rust 1.88+

---

## Limitations

- Static analysis cannot detect Semantic Compliance Hijacking (0.00% detection rate across evaluated scanners, 2026 research).
- Reachability uses static graph traversal over collected topology snapshots, not runtime eBPF or agent instrumentation.
- `siftsec` is not a primary scanner — it composes output from tools you already run in CI.
- End-to-end alert-reduction and precision benchmark results are pending Phase 10.6 (this line will be updated with measured numbers, or a published negative result, when 10.6 completes).

---

## Threat Model & Security

- **Vulnerability disclosure:** See [SECURITY.md](SECURITY.md) for the 90-day coordinated disclosure policy.
- **Threat model:** See [docs/threat-model.md](docs/threat-model.md) for the STRIDE traceability matrix, hostile-input parser bounds, and secret-redaction guarantees.
- **Migration:** Upgrading from an earlier release? See [MIGRATION.md](MIGRATION.md).

---

## Research & Credits

See [docs/research.md](docs/research.md) for the underlying research references, including Rust parsing speedup benchmarks, the Iterative Vector Reconstruction (IVR) inversion literature, and the MCPZoo evaluation corpus (with arXiv identifiers).

---

## License

Apache-2.0 — see [LICENSE](LICENSE).
