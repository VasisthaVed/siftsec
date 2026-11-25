<div align="center">

# 🛡️ TensorGuard (`ai-spm`)

**AI Security Posture Management (AI-SPM) Scanner**  
*Discover, audit, and secure AI/ML infrastructure, model weights, vector databases, and autonomous agents from the metal up.*

[![CI](https://github.com/VasisthaVed/tensorguard/actions/workflows/ci.yml/badge.svg)](https://github.com/VasisthaVed/tensorguard/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS-red.svg)](https://atlas.mitre.org/)
[![OWASP LLM 2025](https://img.shields.io/badge/OWASP-LLM%20Top%2010%202025-orange.svg)](https://genai.owasp.org/)
[![NIST AI 600-1](https://img.shields.io/badge/NIST-AI%20600--1-purple.svg)](https://www.nist.gov/itl/ai-risk-management-framework)

</div>

---

## Why TensorGuard?

Traditional CSPM tools (Prowler, Trivy, ScoutSuite) inspect generic cloud primitives—open ports, unencrypted EBS volumes, or standard S3 buckets. **They treat AI workloads as dumb infrastructure.**

| Attack Surface | Traditional CSPM | 🛡️ TensorGuard (`ai-spm`) |
| :--- | :--- | :--- |
| **Model Weights (`.pt`, `.pkl`)** | Sees a passive blob in S3 | Detects **Pickle RCE deserialization risks** (`AML.T0010`) and enforces **SafeTensors** |
| **Vector Databases (RAG)** | Treats OpenSearch/Qdrant like SQL | Flags public vector endpoints exposed to **Embedding Inversion (`Vec2Text`)** |
| **Autonomous Agents** | Checks generic IAM syntax | Audits **Bedrock Guardrails**, **excessive agency (`LLM06`)**, and wildcard agent roles |
| **MCP Tool Runtimes** | Blind to Model Context Protocol | Scans **MCP tool manifests** for hidden prompt injection & rug-pull drift |
| **Posture Scoring** | Binary pass/fail counts | **Severity-weighted CSPM posture score (0–100)** + native **SARIF v2.1.0** |

---

## ⚡ 10-Second Quickstart (Zero Credentials Required)

Test TensorGuard immediately using the built-in `--demo` simulation mode:

```bash
git clone https://github.com/VasisthaVed/tensorguard.git
cd tensorguard
uv sync --extra dev
uv run ai-spm scan --demo
```

Or list all dynamically discovered rules:

```bash
uv run ai-spm list-rules
```

### Sample Terminal Output

```text
┌───────────────────── 🛡️  AI-SPM Security Audit Report ──────────────────────┐
│ AI Security Posture Score: 26/100  |  Passed: 3  |  Failed: 8  |  Total: 11 │
└─────────────────────────────────────────────────────────────────────────────┘
                           Security Findings Summary
┌────────┬──────────┬──────────────────────┬─────────────────┬────────────────┐
│ Status │ Severity │ Rule ID              │ Resource        │ Threat Mapping │
├────────┼──────────┼──────────────────────┼─────────────────┼────────────────┤
│ FAILED │ CRITICAL │ AI-SPM-S3-001        │ corp-ai-model…  │ AML.T0044      │
│ FAILED │ CRITICAL │ AI-SPM-S3-002        │ corp-ai-model…  │ AML.T0044      │
│ FAILED │ HIGH     │ AI-SPM-S3-004        │ corp-ai-model…  │ AML.T0010      │
│ PASSED │ CRITICAL │ AI-SPM-S3-001        │ corp-ai-safete… │ AML.T0044      │
│ FAILED │ CRITICAL │ AI-SPM-SAGEMAKER-001 │ ml-research-dev │ AML.T0043      │
│ FAILED │ CRITICAL │ AI-SPM-BEDROCK-003   │ FIN-REPORT-AGE… │ LLM01, LLM06   │
│ FAILED │ CRITICAL │ AI-SPM-VECTOR-001    │ rag-vector-clu… │ AML.T0044      │
│ FAILED │ HIGH     │ AI-SPM-IAM-001       │ BedrockExecAdm… │ LLM06:2025     │
│ FAILED │ CRITICAL │ AI-SPM-MCP-001       │ untrusted-gith… │ AML.T0010      │
└────────┴──────────┴──────────────────────┴─────────────────┴────────────────┘
```

---

## 🏗️ 7-Tier Bottom-Up AI Defense Architecture

TensorGuard is designed around a layered defense model covering the full AI stack:

```text
[Tier 6] AI Supply Chain & Provenance   ──► AIBOM (CycloneDX / SPDX 3.0), Weight Signing
[Tier 5] MCP & Tool Runtimes            ──► Tool Poisoning, Manifest Hash-Pinning
[Tier 4] Autonomous Agents & Guardrails ──► Bedrock Guardrails, Confused-Deputy Prevention
[Tier 3] Inference Gateways & Shadow AI ──► Invocation Logging, Ollama/vLLM Port Discovery
[Tier 2] Vector Databases & RAG         ──► VPC Isolation, FGAC, Vec2Text & PoisonedRAG Defense
[Tier 1] Model Weights & Containers     ──► KMS CMK, SafeTensors vs Pickle, ECR Scan-on-Push
[Tier 0] Infra, GPU Runtime & Secrets   ──► SageMaker DIA/RootAccess, K8s GPU & API Key Leaks
```

---

## 📋 Implemented Rules

| Rule ID | Service | Severity | Threat & Framework Mapping |
| :--- | :--- | :--- | :--- |
| `AI-SPM-S3-001` | S3 | `CRITICAL` | Model Weight Storage KMS CMK Encryption (`AML.T0044`, `LLM02:2025`) |
| `AI-SPM-S3-002` | S3 | `CRITICAL` | Public Access Block on AI Model/Dataset Bucket (`AML.T0044`, `AML.T0020`) |
| `AI-SPM-S3-004` | S3 | `HIGH` | Insecure Model Serialization: Pickle vs SafeTensors (`AML.T0010`, `LLM03:2025`) |
| `AI-SPM-SAGEMAKER-001` | SageMaker | `CRITICAL` | Notebook Direct Internet Access Enabled (`AML.T0043`, `LLM02:2025`) |
| `AI-SPM-BEDROCK-003` | Bedrock | `CRITICAL` | Bedrock Agent Missing Active Guardrail (`LLM01:2025`, `LLM06:2025`, `MG-3.1`) |
| `AI-SPM-VECTOR-001` | OpenSearch | `CRITICAL` | Vector Database Publicly Exposed / Inversion Risk (`AML.T0044`, `LLM02:2025`) |
| `AI-SPM-IAM-001` | IAM | `HIGH` | Excessive Agency: Wildcard Permissions on AI Roles (`AML.T0043`, `LLM06:2025`) |
| `AI-SPM-MCP-001` | MCP | `CRITICAL` | MCP Tool Manifest Poisoning / Hidden Injections (`AML.T0010`, `LLM03:2025`) |

---

## ⚙️ Dynamic Configuration (Zero Hardcoding)

All scoring weights, file extension heuristics, shadow AI ports, and fail thresholds are dynamically driven by `AISPMConfig` (`ai_spm/config.py`) and can be overridden via environment variables:

```bash
export AI_SPM_DEFAULT_FAIL_ON=CRITICAL
export AI_SPM_APP_NAME="TensorGuard-Prod"
```

Rules are auto-discovered at runtime via `pkgutil.iter_modules` and `importlib.metadata.entry_points(group="ai_spm.rules")`.

---

## 🔄 GitHub Code Scanning (SARIF) Integration

Export OASIS SARIF v2.1.0 findings directly into GitHub's **Security → Code Scanning** tab:

```yaml
- name: Run TensorGuard AI-SPM Scan
  run: uv run ai-spm scan --demo --output results.sarif

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## 📚 Documentation & Research

- [Master Architecture & 12-Phase Roadmap](Roadmap.md)
- [AI Threat Model & Kill Chains](doc/threat-model.md)
- [Security Rules Catalog](doc/ai-spm-rules-catalog.md)
- [System Architecture & Design](doc/architecture.md)
- [Architectural Decisions Log (ADRs)](doc/decisions.md)
- [Engineering & Zero-Hardcoding Directives](doc/ai-rules.md)
