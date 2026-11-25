<div align="center">

# 🛡️ TensorGuard (`ai-spm`)

**AI Security Posture Management (AI-SPM) Scanner**  
*Discover, audit, and secure AI/ML infrastructure, model weights, vector databases, and autonomous agents from the metal up.*

[![CI](https://github.com/VasisthaVed/tensorguard/actions/workflows/ci.yml/badge.svg)](https://github.com/VasisthaVed/tensorguard/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS-red.svg)](https://atlas.mitre.org/)
[![OWASP LLM 2026](https://img.shields.io/badge/OWASP-LLM%20Top%2010%202026-orange.svg)](https://genai.owasp.org/)
[![NIST AI 600-1](https://img.shields.io/badge/NIST-AI%20600--1-purple.svg)](https://www.nist.gov/itl/ai-risk-management-framework)

</div>

---

## Why TensorGuard?

Traditional CSPM tools (Prowler, Trivy, ScoutSuite) inspect generic cloud primitives—open ports, unencrypted EBS volumes, or standard S3 buckets. **They treat AI workloads as dumb infrastructure.**

| Attack Surface | Traditional CSPM | 🛡️ TensorGuard (`ai-spm`) |
| :--- | :--- | :--- |
| **Model Weights (`.pt`, `.pkl`)** | Sees a passive blob in S3 | Audits **Pickle RCE deserialization risks** (`AML.T0010`) and enforces **SafeTensors** |
| **Vector Databases (RAG)** | Treats OpenSearch/Qdrant like SQL | Flags public vector endpoints exposed to **Embedding Inversion (`Vec2Text` / `LLM09:2026`)** |
| **Autonomous Agents** | Checks generic IAM syntax | Audits **Bedrock Guardrails**, **Excessive Agency (`LLM03:2026`)**, and wildcard agent roles |
| **MCP Tool Runtimes** | Blind to Model Context Protocol | Scans **MCP tool manifests** for hidden prompt injection & rug-pull drift (`ASI10`) |
| **Unknown ≠ Pass** | Silently skips or fails on `AccessDenied` | Tracks **coverage gaps (`Status.ERROR`)** cleanly and never inflates scores (`None` if unscanned) |

---

## ⚡ Quickstart (Zero Credentials Required)

Run TensorGuard immediately in simulated `--demo` mode to inspect the engine, rules, and Rich reporting:

```bash
git clone https://github.com/VasisthaVed/tensorguard.git
cd tensorguard
uv sync --extra dev
uv run tensorguard scan --demo
```

List all dynamically discovered rules:

```bash
uv run tensorguard list-rules
```

> Both `tensorguard` and `ai-spm` CLI entry points are installed.

---

## 🏗️ 7-Tier Bottom-Up AI Defense Architecture

```text
[Tier 6] AI Supply Chain & Provenance   ──► AIBOM (CycloneDX 1.7 / SPDX 3.0), Weight Signing
[Tier 5] MCP & Tool Runtimes            ──► Tool Poisoning, Manifest Hash-Pinning
[Tier 4] Autonomous Agents & Guardrails ──► Bedrock Guardrails, Confused-Deputy Prevention
[Tier 3] Inference Gateways & Shadow AI ──► Invocation Logging, Ollama/vLLM Port Discovery
[Tier 2] Vector Databases & RAG         ──► VPC Isolation, FGAC, Vec2Text & PoisonedRAG Defense
[Tier 1] Model Weights & Containers     ──► KMS CMK, SafeTensors vs Pickle, ECR Scan-on-Push
[Tier 0] Infra, GPU Runtime & Secrets   ──► SageMaker DIA/RootAccess, K8s GPU & Secret Redaction
```

---

## 📋 Active Rules (Demo / Foundation Set)

| Rule ID | Service | Severity | Threat & Framework Mapping |
| :--- | :--- | :--- | :--- |
| `AI-SPM-S3-001` | S3 | `MEDIUM` | Model Weight Storage Lacks KMS CMK Encryption (`AML.T0044`, `LLM02:2026`) |
| `AI-SPM-S3-002` | S3 | `CRITICAL` | Public Access Allowed on AI Model/Dataset Bucket (`AML.T0044`, `LLM02:2026`, `LLM05:2026`) |
| `AI-SPM-S3-004` | S3 | `MEDIUM` | Insecure Model Serialization Heuristic: Pickle vs SafeTensors (`AML.T0010`, `LLM04:2026`) |
| `AI-SPM-SAGEMAKER-001` | SageMaker | `HIGH` | Notebook Direct Internet Access Enabled (`AML.T0044`, `LLM02:2026`) |
| `AI-SPM-BEDROCK-003` | Bedrock | `HIGH` | Bedrock Agent Missing Active Guardrail (`LLM01:2026`, `LLM03:2026`, `MG-3.1`) |
| `AI-SPM-VECTOR-001` | OpenSearch | `CRITICAL` | Vector Database Publicly Exposed / Inversion Risk (`AML.T0044`, `LLM02:2026`, `LLM09:2026`) |
| `AI-SPM-IAM-001` | IAM | `HIGH` | Excessive Agency: Wildcard Permissions on AI Roles (`LLM03:2026`, `ASI05`) |
| `AI-SPM-MCP-001` | MCP | `CRITICAL` | MCP Tool Manifest Poisoning / Hidden Injections (`AML.T0010`, `LLM04:2026`, `ASI10`) |

---

## ⚙️ Dynamic Configuration (Zero Hardcoding)

All scoring weights, file extension heuristics, shadow AI ports, and fail thresholds are governed by `AISPMConfig` ([config.py](ai_spm/config.py)) and overridable via `AI_SPM_*` environment variables:

```bash
export AI_SPM_DEFAULT_FAIL_ON=CRITICAL
export AI_SPM_APP_NAME="TensorGuard-Prod"
```

Rules are auto-discovered at runtime via `pkgutil.iter_modules` and `importlib.metadata.entry_points(group="ai_spm.rules")`.

---

## 🔄 GitHub Code Scanning (SARIF v2.1.0)

Export findings directly into GitHub's **Security → Code Scanning** tab:

```yaml
- name: Run TensorGuard AI-SPM Scan
  run: uv run tensorguard scan --demo --output results.sarif

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## ⚠️ Current Status, Limitations & Non-Goals

* **Current Milestone (Phase 0 Complete):** The core engine (`CloudResource`, `Finding`, `fingerprint`, `redact`, weighted `posture_score`, `BaseRule`, `ScanRunner` exception barrier, `ConsoleReporter`, `SARIFReporter`) and `--demo` simulator are live.
* **In Progress (Phase 1 → 2):** Local static Pickle opcode scanning (`pickletools.genops`), local MCP config auditing, and live AWS Boto3 collectors (`S3`, `SageMaker`, `Bedrock`, `ECR`, `OpenSearch`, `IAM`, `EC2`) are queued next per [PLAYBOOK.md](docs/PLAYBOOK.md).
* **Non-Goals:** TensorGuard is a **read-only posture & static supply-chain auditor**. It never executes untrusted model files (`pickle.loads` / `torch.load`), never spawns untrusted MCP servers, and never mutates cloud infrastructure without explicit opt-in.

---

## 📚 Documentation & Build Playbook

- [Build Playbook (Phases 0–9)](docs/PLAYBOOK.md) — Single source of truth for implementation
- [Engineering Decisions & Standards](docs/decisions.md) — ADRs 001–008 & coding guidelines
- [AI Threat Model & Kill Chains](docs/threat-model.md) — Attack surfaces & adversary personas
- [Security Rules Catalog](docs/ai-spm-rules-catalog.md) — Full 18-rule specification
- [Engineering & Zero-Hardcoding Rules](docs/ai-rules.md) — Contributor & AI coding directives
- [Master Vision & Roadmap](Roadmap.md) — 7-Tier architecture & research references
