<div align="center">

<img src="https://img.shields.io/badge/Siftsec-ai--spm-0D1117?style=for-the-badge&logo=shield&logoColor=white" alt="Siftsec"/>

# Siftsec · `siftsec`

**AI Security Posture Management — from model weights to agent runtimes**

Statically audit model files, MCP servers, AWS AI services, and Kubernetes GPU workloads.  
Deterministic. Offline-capable. No data leaves your environment.

[![Siftsec CI](https://github.com/VasisthaVed/siftsec/actions/workflows/ci.yml/badge.svg)](https://github.com/VasisthaVed/siftsec/actions/workflows/ci.yml)
[![Rust Gates](https://github.com/VasisthaVed/siftsec/actions/workflows/rust-gates.yml/badge.svg)](https://github.com/VasisthaVed/siftsec/actions/workflows/rust-gates.yml)
[![Wheels](https://github.com/VasisthaVed/siftsec/actions/workflows/wheels.yml/badge.svg)](https://github.com/VasisthaVed/siftsec/actions/workflows/wheels.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-CE422B?logo=rust&logoColor=white)](https://rustup.rs/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-22C55E.svg)](LICENSE)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS-DC2626)](https://atlas.mitre.org/)
[![OWASP LLM 2026](https://img.shields.io/badge/OWASP-LLM%20Top%2010%202026-F97316)](https://genai.owasp.org/)
[![NIST AI 600-1](https://img.shields.io/badge/NIST-AI%20600--1-7C3AED)](https://www.nist.gov/itl/ai-risk-management-framework)

</div>

---

## Why Siftsec?

Traditional CSPM tools see AI workloads as generic cloud blobs — open ports, unencrypted buckets, standard IAM. Siftsec was built for the actual attack surface of modern AI stacks.

| Attack Surface | Traditional CSPM | 🛡️ Siftsec |
| :--- | :--- | :--- |
| **Model Weights** (`.pt` / `.pkl`) | Passive blob check | Disassembles **pickle opcodes** via `pickletools.genops()` — never `pickle.loads()` — and enforces SafeTensors |
| **Vector DBs (RAG)** | Treats OpenSearch like SQL | Audits for public access, missing FGAC, and **Embedding Inversion** (`LLM09:2026`) |
| **Autonomous Agents** | Generic IAM syntax check | Audits **Bedrock Guardrails**, **Excessive Agency** (`LLM03:2026`), wildcard roles, and trust conditions |
| **MCP Tool Runtimes** | Invisible | Audits `mcp.json` for unpinned `npx`/`uvx` rug pulls, plaintext secrets, Unicode tag smuggling, and lockfile drift |
| **Multi-scanner correlation** | ❌ | **Phase 10+:** ingests Prowler, Trivy, MCPiranha, ModelAudit, Semgrep output and deduplicates across tools |
| **Unknown ≠ Fail** | Silently skips or false-passes on `AccessDenied` | Every unreadable attribute emits `Status.ERROR` — coverage gaps are **visible**, never hidden |

---

## ⚡ Quickstart

### 1 · Zero-credential demo (10 seconds)
```bash
git clone https://github.com/VasisthaVed/siftsec.git
cd siftsec
uv sync --extra dev
uv run siftsec scan --demo
```

### 2 · Local model & MCP audit
```bash
# Scan local model files (.pt/.pkl/.safetensors) and workspace MCP configs
uv run siftsec scan --local --path .

# Include your HuggingFace cache
uv run siftsec scan --local --path . --include-hf-cache
```

### 3 · AWS environment scan
```bash
# Verify credentials & read-only permissions first
uv run siftsec doctor --profile my-sandbox --region us-east-1

# Scan AWS AI services
uv run siftsec scan --aws --regions us-east-1,us-west-2 --profile my-sandbox
```

### 4 · Multi-format export (JSON / SARIF / Markdown)
```bash
uv run siftsec scan --demo --format sarif --output results.sarif
uv run siftsec scan --demo --format json
uv run siftsec scan --demo --format markdown
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Siftsec Pipeline                             │
│                                                                         │
│  ┌──────────────┐    ┌────────────────────┐    ┌──────────────────────┐ │
│  │  Collectors  │───►│  CloudResource     │───►│  37 Auto-Discovered  │ │
│  │              │    │  (typed, gapped)   │    │  Rules               │ │
│  │  Local       │    │                   │    │                      │ │
│  │  AWS Boto3   │    │  Unknown ≠ Fail   │    │  Pure functions      │ │
│  │  Kubernetes  │    │  gaps → ERROR     │    │  No network/I-O      │ │
│  │  GCP         │    │  score → None     │    │  shlex-quoted fixes  │ │
│  └──────────────┘    └────────────────────┘    └──────────┬───────────┘ │
│                                                           │             │
│  ┌────────────────────────────────────────────────────────▼───────────┐ │
│  │                 Phase 10 · Ingest & Correlate (new)                │ │
│  │                                                                    │ │
│  │   Prowler  Trivy  MCPiranha  ModelAudit  Semgrep  mcp-tool-auditor │ │
│  │        └──────────────┬────────────────────────────────┘          │ │
│  │                       ▼                                           │ │
│  │             Rust core (pyo3 · abi3-py312)                         │ │
│  │             parse_json_bounded · 3-bound safety                   │ │
│  │             dedup · correlate · reachability graph                │ │
│  └─────────────────────────────────┬──────────────────────────────────┘ │
│                                    │                                    │
│  ┌─────────────────────────────────▼──────────────────────────────────┐ │
│  │          Reporters: Console · JSON · SARIF 2.1.0 · Markdown        │ │
│  │          Secrets redacted · Fingerprinted · GitHub Code Scanning   │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

> **Phase 10 Rust core** (`rust/siftsec-core`, `pyo3 = "0.28.3"`, `abi3-py312`):  
> `parse_json_bounded` enforces three safety limits simultaneously — byte cap, recursion depth, compression ratio — before any SARIF / MCP JSON is parsed. Falls back gracefully to a pure-Python implementation if the native wheel is unavailable.

---

## 📊 Phase Status

| Phase | Description | Status |
| :---: | :--- | :---: |
| **0** | Hardening baseline — `SiftsecConfig`, `BaseRule`, `Status.ERROR` coverage gaps | ✅ Done |
| **1** | Local scanner — pickle opcode disassembly, SafeTensors, zip-bomb guards | ✅ Done |
| **2** | AWS collectors — S3, SageMaker, Bedrock, ECR, OpenSearch, IAM | ✅ Done |
| **3** | AWS rules — 37 auto-discovered rules, MITRE ATLAS + OWASP mapping | ✅ Done |
| **4** | CLI & reporters — Console, JSON, SARIF 2.1.0, Markdown, `siftsec doctor` | ✅ Done |
| **5** | Kubernetes + GPU — K8s GPU workload auditing, stress-test suite | ✅ Done |
| **6** | GCP + multi-cloud — GCP collector, multi-cloud expansion | ✅ Done |
| **7** | AI-BOM + supply chain — SBOM generation, provenance tracking, bounded reads | ✅ Done |
| **8** | Hardening & trust — threat model, security policy, JSON logging, debug bundle | ✅ Done |
| **9** | Attack-path correlation — graph-based kill-chain correlation, scan diff, compliance export | ✅ Done |
| **10.1** | Hybrid Rust/Python core — `parse_json_bounded`, SARIF/JSON ingest adapters (10 tools) | ✅ Done |
| **10.2** | Dedup engine — `FindingIndex` (SipHash-1-3), deterministic merge key, ≤5ms/200 findings | 🔄 Next |
| **10.3** | Correlation graph — `petgraph DiGraph<u32>`, skill-node schema, `model→model` edges | 📋 Planned |
| **10.4** | Reachability BFS — blast-radius scoring, predecessor path, ≥5× raw→reachable reduction | 📋 Planned |
| **10.5** | Wedge-A prioritization — cross-tool severity fusion, EPSS-style scoring | 📋 Planned |
| **10.6** | Benchmark & falsification — ≥5× reduction, ≥50% precision gate; negative-result published if not met | 📋 Planned |
| **11** | Model signing & PQ — ML-DSA-65 (FIPS 204), subliminal-channel mitigation | 📋 Planned |
| **12** | EU AI Act compliance — Reg. (EU) 2026/1744 deadline 2027-12-02 | 📋 Planned |
| **13** | Plugin ecosystem — third-party collector + rule authoring API | 📋 Planned |

---

## 🔧 Developer Setup

### Prerequisites

```bash
# 1. Python 3.12+ via uv
pip install uv
uv python install 3.12

# 2. Rust toolchain (required for the native core extension)
# Windows (winget)
winget install --id Rustlang.Rustup -e

# macOS / Linux
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install 1.88 --profile minimal
```

### Install & Run

```bash
git clone https://github.com/VasisthaVed/siftsec.git
cd siftsec
uv sync --extra dev

# Build and install the Rust extension wheel (required for Rust-path tests)
cd rust/siftsec-core
cargo test --release     # must pass before the wheel build
cd ../..
maturin build --release --manifest-path rust/siftsec-core/Cargo.toml --out dist
uv pip install --force-reinstall dist/siftsec_core-*.whl

# Quality gates (all must pass)
uv run ruff check .
uv run ruff format --check siftsec tests
uv run mypy siftsec
uv run pytest                         # 71+ tests, including Rust parity suite
```

### Environment Variables

All tunables live in [`SiftsecConfig`](siftsec/config.py) — zero hardcoded magic numbers. Override at runtime:

```bash
export SIFTSEC_DEFAULT_FAIL_ON=CRITICAL
export SIFTSEC_APP_NAME="Siftsec-Prod"
export SIFTSEC_MAX_FILE_BYTES=104857600   # 100 MB cap
```

---

## 📋 Rule Coverage (37 Active Rules)

Run `uv run siftsec list-rules` to list all auto-discovered rules.

| Domain | Rules | Key Checks |
| :--- | :--- | :--- |
| **Local Models** | `SIFTSEC-LOCAL-001..004` | Dangerous pickle opcodes (`os`, `subprocess`), unallowlisted globals, zip-bomb ratio/size limits, SafeTensors header offset |
| **MCP Config** | `SIFTSEC-MCP-001..006` | Unpinned `npx`/`uvx`/`:latest`, plaintext `env` secrets, Unicode tag smuggling (`U+E0000–E007F`), Base64 injection, lockfile drift, non-TLS HTTP |
| **Amazon S3** | `SIFTSEC-S3-001..004` | KMS CMK encryption, Public Access Block, Object Versioning, Pickle-vs-SafeTensors heuristic |
| **SageMaker** | `SIFTSEC-SAGEMAKER-001..007` | Direct Internet Access, VPC subnet, `RootAccess`, Endpoint+DataCapture KMS, `EnableNetworkIsolation`, Studio `VpcOnly`, IMDSv2 |
| **Bedrock** | `SIFTSEC-BEDROCK-001..004` | Invocation Logging, Knowledge Base KMS, Agent Guardrails, Agent session KMS |
| **ECR** | `SIFTSEC-ECR-001..003` | `scanOnPush` (Inspector ENHANCED-aware), `IMMUTABLE` tags, public policy |
| **OpenSearch** | `SIFTSEC-VECTOR-001`, `SIFTSEC-OPENSEARCH-002..004,007` | VPC isolation, FGAC, node-to-node TLS, `Principal: "*"` policy, AOSS `AllowFromPublic` |
| **IAM + Shadow AI** | `SIFTSEC-IAM-001..003`, `SIFTSEC-SHADOW-001` | Wildcard actions, `*FullAccess` managed policies, missing source conditions, EC2 SGs exposing AI ports |

---

## 🔄 GitHub Code Scanning (SARIF)

```yaml
- name: Siftsec SIFTSEC Scan
  run: uv run siftsec scan --local --path . --format sarif --output results.sarif

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## 🆚 How Siftsec Differs from Peers

> **Strategy:** ingest, don't reimplement. Siftsec ingests output from commodity scanners (`mcp-tool-auditor`, `MCPiranha`, `agent-audit-kit`, Prowler, Trivy) and **correlates across tools** — the thing none of them do individually.

| Tool | Scope | Siftsec relationship |
| :--- | :--- | :--- |
| `mcp-tool-auditor` | MCP rug-pull / HMAC schema drift | **Ingested** as Phase 10.1 adapter |
| `MCPiranha` | Tool poisoning, cross-server shadowing | **Ingested** as Phase 10.1 adapter |
| `agent-audit-kit` | 10-platform taint-flow analysis | **Ingested** as Phase 10.1 adapter |
| `Prowler` | AWS/GCP/Azure CSPM findings | **Ingested** (native SARIF) |
| `Trivy` | Container + IaC SBOM / CVE | **Ingested** (native SARIF) |
| `Wiz / Prisma AIRS` | Enterprise CNAPP | Not a target — Siftsec is the **correlation layer you add on top** |

---

## ⚠️ Limitations & Non-Goals

- **Static pickle scanning:** `pickletools.genops()` is defense-in-depth — novel obfuscation chains can evade it. Always prefer `.safetensors`.
- **Config-level MCP audit:** `LocalMcpCollector` inspects `mcp.json` statically and **never spawns** untrusted servers.
- **Read-only guarantee:** Siftsec never modifies cloud infrastructure or writes to production vector databases.
- **Fuzz targets** (`rust/siftsec-fuzz`) are Linux-only (`cargo-fuzz` requires nightly on Linux).

---

## 📚 Documentation

| Document | Description |
| :--- | :--- |
| [Roadmap.md](Roadmap.md) | Master vision, all phases, ADR index |
| [docs/ai-rules.md](docs/ai-rules.md) | Rule authoring guide |
| [docs/decisions.md](docs/decisions.md) | Architecture Decision Records |
| [docs/threat-model.md](docs/threat-model.md) | AI threat model & kill chains |
| [docs/siftsec-rules-catalog.md](docs/siftsec-rules-catalog.md) | Full rules catalog |
| [docs/architecture.md](docs/architecture.md) | System architecture & design |
| [docs/aws-iam-permissions.md](docs/aws-iam-permissions.md) | AWS least-privilege IAM policy |

---

## Contributing

Pull requests targeting `main` trigger the full CI matrix — Python lint/type/test, Rust `cargo test --release`, `cargo-deny` license + advisory check, and `abi3-py312` wheel builds across Ubuntu / macOS / Windows.

Please run all gates locally before opening a PR:

```bash
uv run ruff check .
uv run ruff format --check siftsec tests
uv run mypy siftsec
uv run pytest
cd rust/siftsec-core && cargo test --release
```

---

<div align="center">

**Apache-2.0** · Built with [PyO3](https://pyo3.rs/) · Aligned to [MITRE ATLAS](https://atlas.mitre.org/), [OWASP LLM Top 10 2026](https://genai.owasp.org/), [NIST AI 600-1](https://www.nist.gov/itl/ai-risk-management-framework)

</div>
