<div align="center">

# 🛡️ TensorGuard (`ai-spm`)

**AI Security Posture Management (AI-SPM) Scanner**  
*Discover, audit, and secure AI/ML infrastructure, model weights, vector databases, MCP servers, and autonomous agents from the metal up.*

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
| **Model Weights (`.pt`, `.pkl`)** | Sees a passive blob | Statically disassembles **pickle opcodes via `pickletools.genops()`** (never `pickle.loads()`) and enforces **SafeTensors** |
| **Vector Databases (RAG)** | Treats OpenSearch like SQL | Audits OpenSearch & Serverless (`aoss`) for public access & **Embedding Inversion (`Vec2Text` / `LLM09:2026`)** |
| **Autonomous Agents** | Checks generic IAM syntax | Audits **Bedrock Guardrails**, **Excessive Agency (`LLM03:2026`)**, trust conditions, and wildcard roles |
| **MCP Tool Runtimes** | Blind to Model Context Protocol | Audits **`mcp.json`** for unpinned `npx`/`uvx` rug pulls, plaintext secrets, Unicode tag smuggling, & lockfile drift (`ASI10`) |
| **Unknown ≠ Pass** | Silently skips or fails on `AccessDenied` | Tracks **coverage gaps (`Status.ERROR`)** cleanly and returns `None` (`N/A`) when unscanned |

---

## ⚡ Quickstart

### 1. Zero-Credential Demo (10 Seconds)
```bash
git clone https://github.com/VasisthaVed/tensorguard.git
cd tensorguard
uv sync --extra dev
uv run tensorguard scan --demo
```

### 2. Local AI & MCP Audit (Your Laptop / CI Repo)
```bash
# Scan local model files (.pt/.pkl/.safetensors) and workspace MCP configs
uv run tensorguard scan --local --path .

# Include your local HuggingFace cache (~/.cache/huggingface/hub)
uv run tensorguard scan --local --path . --include-hf-cache
```

### 3. Live AWS Environment Scan
```bash
# Check credentials & read-only permissions first
uv run tensorguard doctor --profile my-sandbox --region us-east-1

# Scan AWS AI services across regions
uv run tensorguard scan --aws --regions us-east-1,us-west-2 --profile my-sandbox
```

### 4. Multi-Format Export (JSON, SARIF, Markdown)
```bash
uv run tensorguard scan --demo --format sarif --output results.sarif
uv run tensorguard scan --demo --format json
uv run tensorguard scan --demo --format markdown
```

---

## 🧠 How It Works (Deterministic Core, Zero Hallucinations)

TensorGuard uses a **pure, deterministic two-stage pipeline** (`Collector → Typed CloudResource → Pure BaseRule → Multi-Sink Reporter`). It does **not** send your infrastructure topology to external LLMs or risk hallucinated pass/fail verdicts—every finding is reproducible, offline-capable, and backed by an explicit fingerprint (`sha256(rule_id | resource_arn | scope)`).

```text
[Local / AWS Collectors] ──► [Typed CloudResource + gaps] ──► [37 Auto-Discovered Rules] ──► [Console / JSON / SARIF / MD]
   (Boto3 adaptive,             (Unknown != Fail;               (Pure, no network/I/O,        (Redacted secrets,
    pickletools, MCP)            no raw dicts)                   shlex-quoted fixes)           weighted score 0-100)
```

---

## 📋 Rule Coverage (37 Active Rules)

Run `uv run tensorguard list-rules` to see all dynamically discovered rules:

* **Local Model & Archive Security (`AI-SPM-LOCAL-001`..`004`):** Dangerous pickle opcodes (`os`, `subprocess`), unallowlisted globals, zip-bomb ratio/size limits, SafeTensors header offset validation.
* **MCP Config & Rug-Pull Defense (`AI-SPM-MCP-001`..`006`):** Unpinned `npx`/`uvx`/docker `:latest`, plaintext `env` secrets, Unicode tag smuggling (`U+E0000–U+E007F`), Base64 injection markers, lockfile drift, non-TLS HTTP / pipe-to-shell.
* **Amazon S3 (`AI-SPM-S3-001`..`004`):** KMS CMK encryption, effective Public Access Block, dataset Object Versioning, Pickle vs SafeTensors heuristic.
* **Amazon SageMaker (`AI-SPM-SAGEMAKER-001`..`007`):** Direct Internet Access, VPC subnet attachment, `RootAccess` disabled, Endpoint & DataCapture KMS, Training Job `EnableNetworkIsolation`, Studio Domain `VpcOnly`, IMDSv2 enforcement.
* **Amazon Bedrock (`AI-SPM-BEDROCK-001`..`004`):** Model Invocation Logging, Knowledge Base DataSource KMS, Agent active Guardrails, Agent session KMS.
* **Amazon ECR (`AI-SPM-ECR-001`..`003`):** `scanOnPush` (respecting registry `ENHANCED` Inspector scanning), `IMMUTABLE` image tags, public policy check.
* **Amazon OpenSearch & Serverless (`AI-SPM-VECTOR-001`, `AI-SPM-OPENSEARCH-002`..`004`, `007`):** VPC isolation, FGAC, node-to-node TLS, public `Principal: "*"` policy, AOSS `AllowFromPublic=true`.
* **AWS IAM & Shadow AI (`AI-SPM-IAM-001`..`003`, `AI-SPM-SHADOW-001`):** Wildcard actions, broad `*FullAccess` managed policies, missing `aws:SourceAccount`/`SourceArn` trust conditions, EC2 Security Groups exposing AI ports (`11434`, `8000`, `8001`, `8080`, `6333`, `19530`).

---

## ⚙️ Dynamic Configuration (Zero Hardcoding)

All scoring weights, file extension heuristics, shadow AI ports, and fail thresholds are governed by `AISPMConfig` ([config.py](ai_spm/config.py)) and overridable via `AI_SPM_*` environment variables:

```bash
export AI_SPM_DEFAULT_FAIL_ON=CRITICAL
export AI_SPM_APP_NAME="TensorGuard-Prod"
```

---

## 🔄 GitHub Code Scanning (SARIF v2.1.0)

```yaml
- name: Run TensorGuard AI-SPM Scan
  run: uv run tensorguard scan --local --path . --format sarif --output results.sarif

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## ⚠️ Limitations & Non-Goals

* **Static Pickle Scanning:** `pickletools.genops()` is defense-in-depth—novel obfuscation chains can exist. Always prefer `.safetensors`.
* **Config-Level MCP Audit:** `LocalMcpCollector` inspects `mcp.json` statically and never spawns untrusted servers.
* **Read-Only Guarantee:** TensorGuard never modifies cloud infrastructure or writes to production vector databases.

---

## 📚 Documentation

- [AI Threat Model & Kill Chains](docs/threat-model.md)
- [Security Rules Catalog](docs/ai-spm-rules-catalog.md)
- [System Architecture & Design](docs/architecture.md)
- [AWS Least-Privilege IAM Policy](docs/aws-iam-permissions.md)
- [Master Vision & Roadmap](Roadmap.md)
