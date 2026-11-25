# AI-SPM Scanner: Product Requirements Document (PRD)

## 1. Product Summary
**Product Name:** AI-SPM (AI Security Posture Management) Scanner  
**Status:** In Development (Phase 1-5)  
**Primary Language/Runtime:** Python 3.12+ (managed with `uv`)  
**Target Environment:** AWS Cloud (S3, SageMaker, Bedrock, ECR, OpenSearch / Vector DBs)  

---

## 2. Problem Statement
Enterprise adoption of Large Language Models (LLMs), generative AI agents, and custom ML pipelines has drastically outpaced security controls. Traditional Cloud Security Posture Management (CSPM) solutions are blind to AI-specific risks:
- They do not distinguish between general S3 buckets and multi-million-dollar proprietary LLM model weights.
- They cannot inspect Bedrock model invocation logging or detect Bedrock agents operating without guardrails.
- They fail to monitor vector databases where sensitive corporate knowledge is stored in vector embeddings vulnerable to model inversion attacks.
- They do not detect Shadow AI instances (e.g. unapproved SageMaker instances with unrestricted public internet egress).

---

## 3. User Personas

| Persona | Role | Primary Need |
| :--- | :--- | :--- |
| **DevSecOps / AppSec Engineer** | Cloud Security | Automate AI security checks in CI/CD pipelines and generate SARIF / Markdown reports for PR gating. |
| **MLOps / AI Engineer** | Platform Engineering | Ensure SageMaker training jobs and Bedrock knowledge bases meet enterprise compliance without slowing deployment velocity. |
| **Chief Information Security Officer (CISO)** | Security Leadership | Comprehensive visibility into AI attack surfaces, shadow AI usage, and compliance with OWASP Top 10 for LLMs and MITRE ATLAS. |

---

## 4. Functional Requirements

### 4.1 Discovery & Inventory
- **FR-1:** Automatically discover all AI/ML-related AWS resources in specified or active regions.
- **FR-2:** Tag-based classification (`workload=ai`, `project=ml`, `data=model`) and heuristic classification based on naming patterns and service types.
- **FR-3:** Identify untagged Shadow AI resources running in the target account.

### 4.2 Security Rule Evaluation
- **FR-4:** Execute detection rules matching `doc/ai-spm-rules-catalog.md` across S3, SageMaker, Bedrock, ECR, and OpenSearch.
- **FR-5:** Tag every finding with:
  - Severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`)
  - Target AWS Resource ARN & ID
  - Detailed failure rationale
  - Remediation instructions (CLI/IaC commands)
  - MITRE ATLAS technique IDs
  - OWASP Top 10 for LLM vulnerability categories

### 4.3 CLI & UX
- **FR-6:** Provide a polished Typer CLI (`ai-spm scan`, `ai-spm list-rules`).
- **FR-7:** Live terminal rendering with `rich` tables, progress meters, and color-coded severity summaries.
- **FR-8:** Support multiple output formats:
  - Console (`terminal`)
  - JSON (`json`)
  - Markdown (`markdown`)
  - SARIF (`sarif`) for GitHub Code Scanning

### 4.4 CI/CD Integration & Exit Gating
- **FR-9:** Support `--fail-on <SEVERITY>` flag. Exit with non-zero exit code (`1`) when any finding matches or exceeds the threshold.

---

## 5. Non-Functional Requirements

### 5.1 Resilience & Availability
- **NFR-1:** **Zero-Crash Guarantee:** The scanner must handle missing IAM permissions (`AccessDenied`), API throttling, or regional service unavailability gracefully without terminating prematurely.
- **NFR-2:** **Automatic Pagination:** 100% of AWS list and describe operations must support pagination tokens.

### 5.2 Performance
- **NFR-3:** An audit of 1,000 resources must finish in under 30 seconds using concurrent thread workers.
- **NFR-4:** Memory consumption must not exceed 250 MB under standard workloads.

### 5.3 Quality & Maintainability
- **NFR-5:** Strictly typed codebase passing `mypy --strict`.
- **NFR-6:** Clean code audited with `ruff`.
- **NFR-7:** Minimum 85% test coverage enforced via `pytest-cov`.
