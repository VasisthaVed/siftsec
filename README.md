# siftsec

**Turn 200 scanner findings into the 8 an attacker can actually reach.**

[![CI](https://github.com/VasisthaVed/siftsec/actions/workflows/ci.yml/badge.svg)](https://github.com/VasisthaVed/siftsec/actions/workflows/ci.yml)
[![Rust Gates](https://github.com/VasisthaVed/siftsec/actions/workflows/rust-gates.yml/badge.svg)](https://github.com/VasisthaVed/siftsec/actions/workflows/rust-gates.yml)
[![Wheels](https://github.com/VasisthaVed/siftsec/actions/workflows/wheels.yml/badge.svg)](https://github.com/VasisthaVed/siftsec/actions/workflows/wheels.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org/)

> **v0.1 — in development.** Ingest (10.1), dedup (10.2), and reachability
> graph (10.3) are shipped and tested. Prioritization, SARIF output, and the
> public benchmark land before v1.0. This README states what works today and
> what does not.

---

## The problem

Your pipeline runs 3+ scanners on every PR. ModelAudit flags a pickle file.
Trivy flags the same container. agent-bom flags the same MCP server. Semgrep
flags the notebook that loads it. You get **200 findings** and no way to
tell which 8 matter.

The 2026 Safeguard developer survey (540 respondents) found:

- **61%** say more than half of their security alerts are false positives
  or non-exploitable in their code path
- **68%** run three or more overlapping scanners with contradictory findings
- **54%** have disabled a security gate in the last 12 months because it
  blocked a release without justification
- When asked what they want most, **"tells me if this is actually reachable"**
  outranked comprehensive coverage and scan speed **combined**

siftsec answers that question. It does not scan. It takes the findings from
the scanners you already run and tells you which ones an attacker can actually
reach.

---

## Quick start

```bash
pip install siftsec

# Combine findings from three scanners
siftsec ingest \
  --sarif modelaudit.sarif \
  --sarif trivy.sarif \
  --sarif agent-bom.sarif \
  --out merged.sarif

# Rank by what an attacker can reach
siftsec reach \
  --sarif merged.sarif \
  --cloud-snapshot cloud.json \
  --out prioritized.sarif
```

Requires Python 3.12+. Prebuilt wheels for linux-x86_64, linux-aarch64,
macos-arm64, macos-x86_64, windows-x64 (`abi3-py312` — one wheel per platform
covers Python 3.12+).

---

## What it looks like when it runs

Input: 200 findings from ModelAudit, Trivy, and agent-bom. Output: the
prioritized set with a witness path showing *why* each one is ranked.

```json
{
  "schema": 1,
  "finding_fingerprint": "a4f9c2e8...",
  "priority": "P0",
  "base_priority": "P0",
  "witness_path": [
    "arn:aws:sagemaker:us-east-1:123456789012:notebook-instance/public-ml-nb",
    "arn:aws:iam::123456789012:role/sagemaker-write-role",
    "arn:aws:s3:::prod-model-weights"
  ],
  "witness_hops": 2,
  "reaches_sensitive": true,
  "via_write_permission": true,
  "explanation": "Reachable in 2 hops from public notebook 'public-ml-nb' to sensitive data_store 'prod-model-weights' via write permission.",
  "evidence": {
    "finding": {
      "source_tool": "ModelAudit",
      "rule_id": "pickle-unsafe-opcode",
      "resource_arn": "arn:aws:s3:::prod-model-weights/model.pt",
      "original_severity": "HIGH"
    },
    "graph": {
      "witness_path": ["..."],
      "hops": 2,
      "reaches_sensitive": true,
      "via_write_permission": true
    },
    "downgrades": []
  }
}
```

The same finding, on a notebook with **read-only** access to the same bucket,
comes back as **P1** — not P0. That distinction is the entire point: a
read-only path is not a breach, and treating it as one is how scanners end up
in the 61% noise pile.

If the finding's resource is not present in the graph at all, it comes back
as **P4 — reachability unknown**. It is never inflated to P0. "We don't know"
is a valid answer; inventing certainty is not.

---

## How it works

```
   scanners you already run
   ┌──────────┬──────────┬──────────┬──────────┐
   │ModelAudit│  Trivy   │ agent-bom│  Semgrep │
   └────┬─────┴────┬─────┴────┬─────┴────┬─────┘
        │          │          │          │
        ▼          ▼          ▼          ▼
   ┌──────────────────────────────────────────┐
   │  ingest (10.1) — normalize to one schema │
   └──────────────────┬───────────────────────┘
                      │
                      ▼
   ┌──────────────────────────────────────────┐
   │  dedup (10.2) — 3 tools, same server = 1 │
   └──────────────────┬───────────────────────┘
                      │
                      ▼
   ┌──────────────────────────────────────────┐
   │  reachability graph (10.3)               │
   │  boundary → asset → role → data_store    │
   │  BFS, shortest witness, max_hops = 8     │
   └──────────────────┬───────────────────────┘
                      │
                      ▼
   ┌──────────────────────────────────────────┐
   │  prioritize (10.4) — P0 / P1 / P2 / P3 / P4│
   └──────────────────┬───────────────────────┘
                      │
                      ▼
              one SARIF file
```

The Rust core (`siftsec._core`) handles the hot path — bounded JSON
parsing, dedup, BFS reachability — with a byte-for-byte identical Python
fallback when no wheel is available. Both paths are tested against the same
fixtures; a parity test fails CI if they ever diverge.

---

## How is it different

| Tool | What it does | What it doesn't |
|---|---|---|
| **siftsec** | Ingests SARIF/JSON from the tools you run, collapses duplicates, ranks by reachability with a witness path | Does not scan. Does not run a dashboard. Does not write to your cloud. |
| **agent-bom** | Traces CVE → package → MCP server → agent → credentials. Emits SARIF/CycloneDX/SPDX. | Does not ingest *other tools'* findings, no cross-tool dedup, no read-only vs write discrimination, no P0–P4 rubric |
| **ModelAudit** | Static scan of 42+ model formats. | Model-only, no cross-tool correlation, no cloud context |
| **Trivy / Semgrep / Prowler** | General-purpose container, SAST, and cloud posture scanners. | Single-tool output; no cross-tool correlation |
| **Wiz AI-SPM / Prisma AIRS** | Enterprise platform with AI-SPM modules | Closed source, agent-based, requires replacing your scanners; no third-party SARIF ingest |
| **SentinelOne / Palo Alto / Check Point AI security** | Platform features inside a broader CNAPP | Bundle lock-in; no third-party findings ingest |

siftsec is not another scanner. It is the **decision layer** on top of the
scanners you already trust. If you already run ModelAudit, you do not need
another model scanner — you need a tool that tells you which of its findings
matter in *your* environment.

---

## The P0–P4 rubric

Reachability alone is not a priority. A finding on a read-only path is not
the same as a finding on a write path. siftsec applies five priorities in
order:

| Priority | When |
|---|---|
| **P0** | Finding's resource is on a witness path that reaches a sensitive data store via **write** access |
| **P1** | Same, via **read-only** access |
| **P2** | Finding's resource is on a witness path, but that path does not reach a sensitive data store within `max_hops` (default 8) |
| **P3** | Finding's resource is exposed (boundary) but no witness path reaches anything sensitive |
| **P4** | Finding's resource does not appear in the graph at all — **reachability unknown** |

Mitigations (guardrails, permissions boundaries, non-internet-exposed
notebooks) downgrade by one level, **and the downgrade is always recorded in
`evidence.downgrades`**. No silent downgrades. The rubric is written out in
full in [`docs/prioritization-rubric.md`](docs/prioritization-rubric.md).

---

## Quality

Every release is gated on:

- **76 Python tests** + **18 Rust tests** — all passing
- `cargo clippy -- -D warnings` — 0 warnings
- `cargo-deny` — `advisories ok, bans ok, licenses ok, sources ok`
- `mypy --strict` — 0 issues across 71 source files
- `ruff check` + `ruff format` — clean
- Rust↔Python parity — identical output on the same fixtures
- Determinism — 10-run byte-identical output across `RAYON_NUM_THREADS ∈ {1,2,4,8}`

Measured benchmarks (Windows, release build):

| Benchmark | Result | Gate |
|---|---|---|
| Dedup 200 findings | **0.471 ms** | <= 5 ms |
| Reachability BFS, 1k nodes / 5k edges | **3.36 ms** | <= 40 ms |
| JSON depth bound | proven by `proptest` + Kani harness | 0 panics on 10k-deep input |

Deferred to v1.0: `cargo-fuzz` corpus, Miri UB check on graph traversal,
full SARIF schema validation against the vendored 2.1.0 schema. These are
present as placeholder workflows with `if: false` and a `TODO(10.x)` comment
— they are visible, not deleted.

---

## Compatibility

- **Python**: 3.12+
- **Platforms**: linux-x86_64, macos-arm64, windows-x64
- **Wheels**: `abi3-py312` — one wheel per platform covers all Python 3.12+
- **Rust**: 1.88+ (only needed for source builds; wheels need no toolchain)
- **Fallback**: pure-Python implementation when no wheel is available (byte-identical output)

---

## Limitations

Honest caveats, in the order they matter:

- **Reachability is graph-based, not runtime.** siftsec can tell you that a
  path exists in your IAM/config snapshot. It cannot tell you whether the
  process is currently running, or whether an attacker has already used it.
- **Static analysis cannot detect Semantic Compliance Hijacking.** The 2026
  ClawHub attacks used natural-language instructions in `SKILL.md` files, not
  code. Static analysis reports **0.00% detection** on this class across
  evaluated scanners. siftsec does not claim to detect it.
- **Not a scanner.** If you do not run ModelAudit, Trivy, Semgrep, or similar,
  siftsec has nothing to ingest. It is explicitly a decision layer, not a
  replacement.
- **P4 is not "no risk."** A finding with priority P4 means *we could not
  evaluate reachability* — usually because the resource is not in your graph.
  It does not mean the finding is false. It means the evidence is missing.
- **Cloud snapshots are point-in-time.** The graph reflects the IAM/config
  you provided at scan time. Drift between the snapshot and reality is not
  detected.

---

## Research & credits

siftsec rests on published findings. Read the sources:

- Safeguard (2026), *540-developer false-positive survey* — the 61/68/54%
  numbers above
- MCPZoo (July 2026), *64,611-server MCP corpus* — basis for the 10.6 benchmark
- *What You Sign Is Not What You Run* (arXiv 2610.19498, Oct 2026) — IVR
  metric and the GGUF verifiability census
- *Where does a Rust speedup come from?* (arXiv 2610.07931) — the
  language-vs-algorithm split behind the Rust core
- Cisco AI Defense, `pickle-fuzzer` — the opcode-stream fuzzing approach
- IETF `DAWN` / `APKI` / `PEDIGREE` drafts — agent delegation provenance

Full citations with arXiv IDs: [`docs/research.md`](docs/research.md).

---

## Contributing

- [CONTRIBUTING.md](CONTRIBUTING.md) — add a rule in 5 steps
- [SECURITY.md](SECURITY.md) — private disclosure channel, 90-day SLA
- [MIGRATION.md](MIGRATION.md) — the `tensorguard` → `siftsec` rename (breaking
  for saved SARIF baselines; regenerate them)
- [docs/PLAYBOOK.md](docs/PLAYBOOK.md) — the build plan (historical document;
  predates the rename)
- [docs/decisions.md](docs/decisions.md) — ADR-001 → ADR-046

Good first issues are tagged [`good first issue`](https://github.com/VasisthaVed/siftsec/labels/good%20first%20issue).

---

## License

Apache-2.0 with DCO. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Formerly `tensorguard`; see [MIGRATION.md](MIGRATION.md).
