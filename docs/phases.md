# Siftsec (`siftsec`): Phase-by-Phase Build & Execution Guide

This file is the **practical execution manual** derived from [`Roadmap.md`](file:///c:/Pro/PROJECT/SIFTSEC/Roadmap.md) and [`docs/detailed-roadmap.md`](file:///c:/Pro/PROJECT/SIFTSEC/docs/detailed-roadmap.md). For every phase from **Phase 0** to **Phase 7**, it specifies:
1. **Exact files** to create or edit.
2. **How features are built** and wired together.
3. **Tools, libraries, and commands** used to build and verify each phase.

---

## Phase 0: Foundations (Fast & Easy Core)

**Objective:** Keep the core engine tiny, strictly typed, and zero-hardcoded so every future feature plugs in cleanly.

### Files & Changes
* [`siftsec/config.py`](file:///c:/Pro/PROJECT/SIFTSEC/siftsec/config.py) *(exists — extend)*:
  - Add `ai_name_patterns`, `ignored_rules`, `local_mcp_paths`, `dangerous_pickle_modules`, and `secret_patterns` to `SiftsecConfig`.
  - Add optional YAML/TOML config file loader (`--config`).
* `siftsec/engine/context.py` *(new)*:
  - Define `ScanContext(BaseModel)` holding `account_id`, `regions`, `services`, `min_severity`, `fail_on`, and `ai_only`.
* [`siftsec/engine/models.py`](file:///c:/Pro/PROJECT/SIFTSEC/siftsec/engine/models.py) *(exists — extend)*:
  - Add `ScanSummary(BaseModel)` with `total_resources`, `findings`, `posture_score`, and `errors`.
* [`siftsec/engine/runner.py`](file:///c:/Pro/PROJECT/SIFTSEC/siftsec/engine/runner.py) *(exists — harden)*:
  - Wrap `rule.evaluate(resource)` in a `try...except Exception` barrier emitting `Status.ERROR` findings instead of crashing.
  - Filter findings by `ScanContext.min_severity`.
* `siftsec/utils/logger.py` *(new)*:
  - Structured `rich.logging.RichHandler` logger controlled by `--verbose` / `--quiet`.

### Tools & Commands
```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy siftsec
uv run pytest
```

---

## Phase 1: Real Local AI Scanner (`siftsec scan --local`)

**Objective:** Make Siftsec immediately useful on any developer's laptop or CI repo with **zero cloud credentials**.

### Features & Files
1. **Safe Pickle Opcode Scanner** — `siftsec/scanners/pickle_scanner.py` *(new)*:
   * Uses Python stdlib `pickletools.genops()` and `zipfile.ZipFile` (never `pickle.loads()` or `torch.load()`).
   * Streams `.pt`, `.pth`, `.bin`, `.pkl` files and flags `GLOBAL` / `STACK_GLOBAL` / `INST` opcodes importing modules in `settings.dangerous_pickle_modules` (`os`, `subprocess`, `posix`, `builtins.eval`, `socket`).
2. **Local Model & HuggingFace Cache Collector** — `siftsec/collectors/local_models.py` *(new)*:
   * Scans target directories (`--path`) or `~/.cache/huggingface` for model artifacts, emitting `CloudResource` items with opcode scan results.
3. **Local MCP Manifest Auditor** — `siftsec/collectors/mcp_local.py` *(new)*:
   * Reads `~/.cursor/mcp.json`, Claude Desktop config, and `./.mcp.json`.
   * Checks for unpinned `npx`/`uvx` commands (rug-pull risk), plaintext keys in `env`, SHA-256 drift against `.siftsec-lock.json`, and hidden Unicode/Base64 prompt-injection markers.
4. **Local Rules** — `siftsec/rules/local.py` *(new)*:
   * `SIFTSEC-LOCAL-001` (Pickle dangerous opcodes), `SIFTSEC-MCP-002` (Unpinned / drifted MCP manifest), `SIFTSEC-SECRETS-001` (Redacted leaked AI keys).
5. **CLI Wiring** — [`siftsec/cli.py`](file:///c:/Pro/PROJECT/SIFTSEC/siftsec/cli.py):
   * Add `--local` and `--path` flags to `siftsec scan`.

### Tools & Verification
* **Libraries:** `pickletools`, `zipfile`, `hashlib`, `json`, `re` (stdlib — zero extra dependencies).
* **Tests (`tests/test_local_scanners.py`):** Construct synthetic pickle opcodes in memory + temp `mcp.json` fixtures using `pytest`'s `tmp_path`, then run `uv run pytest`.

---

## Phase 2: Resilient AWS Collector Layer (Boto3)

**Objective:** Collect real AWS AI infrastructure safely across regions with automatic pagination, adaptive backoff, and graceful permission handling.

### Features & Files
1. **AWS Session & Client Factory** — `siftsec/collectors/aws/client.py` *(new)*:
   * Configures `botocore.config.Config(retries={"max_attempts": 5, "mode": "adaptive"}, user_agent_extra="Siftsec/0.1.0")`.
   * Resolves `account_id` (`sts:GetCallerIdentity`) and enabled regions (`ec2:DescribeRegions`).
2. **Base AWS Collector** — `siftsec/collectors/aws/base.py` *(new)*:
   * Provides universal `paginate()` helper (`get_paginator` + `NextToken`/`Marker` fallback).
   * Provides `@handle_aws_errors` barrier catching `ClientError` (`AccessDenied`, `UnauthorizedOperation`, `ThrottlingException`).
   * Implements `classify_ai_workload()` using `settings.ai_workload_tags` and `settings.ai_name_patterns`.
3. **Service Collectors** — `siftsec/collectors/aws/` *(new)*:
   * `s3.py` (`S3Collector`): buckets, encryption, public access block, versioning, tags, object key sampling (`MaxKeys=200`).
   * `sagemaker.py` (`SageMakerCollector`): notebooks, endpoint configs, training jobs.
   * `bedrock.py` (`BedrockCollector`): model invocation logging, agents, knowledge bases & data sources.
   * `ecr.py` (`ECRCollector`): AI repositories, `scanOnPush`, `imageTagMutability`.
   * `opensearch.py` (`OpenSearchCollector`): domains, `VPCOptions`, `AdvancedSecurityOptions`, `NodeToNodeEncryptionOptions`.
   * `iam.py` (`IAMCollector`): policies on roles attached to discovered AI resources.

### Tools & Verification
* **Libraries:** `boto3`, `botocore`, `concurrent.futures.ThreadPoolExecutor`.
* **Testing Tools:** `moto[all]` (`@mock_aws`) and `botocore.stub.Stubber` in `tests/collectors/test_aws_*.py` to simulate real AWS responses and `AccessDenied` errors without live AWS credentials.

---

## Phase 3: Complete AWS Rule Suite (18 Rules)

**Objective:** Cover all 18 rules defined in [`docs/siftsec-rules-catalog.md`](file:///c:/Pro/PROJECT/SIFTSEC/docs/siftsec-rules-catalog.md) and [`Roadmap.md`](file:///c:/Pro/PROJECT/SIFTSEC/Roadmap.md).

### Files & Features
* Expand [`siftsec/rules/s3.py`](file:///c:/Pro/PROJECT/SIFTSEC/siftsec/rules/s3.py): add `SIFTSEC-S3-003` (Object Versioning).
* Split/organize into `siftsec/rules/aws/` (`sagemaker.py`, `bedrock.py`, `ecr.py`, `opensearch.py`, `shadow_ai.py`):
  - `SIFTSEC-SAGEMAKER-002` through `005` (VPC, RootAccess, Endpoint KMS, Training Network Isolation).
  - `SIFTSEC-BEDROCK-001`, `002` (Invocation Logging, KB KMS CMK).
  - `SIFTSEC-ECR-001`, `002` (Scan on Push, Immutable Tags).
  - `SIFTSEC-VECTOR-002`, `003` (FGAC, Node-to-Node TLS).
  - `SIFTSEC-SHADOW-001` (Security Groups exposing `settings.shadow_ai_ports` to `0.0.0.0/0`).

### Tools & Verification
* `tests/rules/test_*.py`: At least 1 `PASSED` + 1 `FAILED` unit test per rule.
* Run `uv run pytest --cov=siftsec --cov-report=term-missing` (target `>=85%` coverage).

---

## Phase 4: Multi-Sink Reporters, Demo Assets & PyPI Release

**Objective:** Make Siftsec frictionless to adopt in CI/CD, PRs, and open-source communities.

### Files & Features
* `siftsec/reporters/json_rep.py` *(new)*: Export `ScanSummary` as structured JSON.
* `siftsec/reporters/markdown.py` *(new)*: GitHub-Flavored Markdown table + collapsible remediation details for PR comments.
* [`siftsec/cli.py`](file:///c:/Pro/PROJECT/SIFTSEC/siftsec/cli.py): Add `--format [console|json|sarif|markdown]`, `--min-severity`, `--regions`, `--profile`.
* `action.yml` *(new)*: Reusable GitHub Action wrapping `uvx siftsec scan`.
* `docs/demo.tape` *(new)*: Terminal demo script recorded with Charm `vhs` for a crisp GIF in [`README.md`](file:///c:/Pro/PROJECT/SIFTSEC/README.md).

### Tools & Commands
```bash
uv build
uv run twine check dist/*
uv publish
```

---

## Phase 5: Kubernetes GPU Runtime Security

**Objective:** Audit EKS/GKE/self-hosted clusters running PyTorch, vLLM, or Triton on GPUs.

### Files & Features
* [`pyproject.toml`](file:///c:/Pro/PROJECT/SIFTSEC/pyproject.toml): Add optional extra `k8s = ["kubernetes>=29.0.0"]`.
* `siftsec/collectors/k8s.py` *(new)*: Collects GPU nodes, NVIDIA GPU Operator DaemonSets, and Pods requesting `nvidia.com/gpu`.
* `siftsec/rules/k8s_gpu.py` *(new)*:
  - `SIFTSEC-K8S-GPU-001`: NVIDIA Container Toolkit `< v1.17.8` (`CVE-2025-23266` / NVIDIAScape).
  - `SIFTSEC-K8S-GPU-002`: Time-slicing without NVIDIA MIG hardware partitioning.
  - `SIFTSEC-K8S-GPU-003`: Privileged pods or `/dev/nvidia*` `hostPath` mounts.

---

## Phase 6: Multi-Cloud Expansion (GCP Vertex AI & Azure AI Foundry)

**Objective:** Extend `BaseCollector` to GCP and Azure using the same `CloudResource` schema.

### Files & Features
* [`pyproject.toml`](file:///c:/Pro/PROJECT/SIFTSEC/pyproject.toml): Add optional extras `gcp` (`google-cloud-aiplatform`, `google-cloud-storage`) and `azure` (`azure-mgmt-machinelearningservices`, `azure-identity`).
* `siftsec/collectors/gcp/` *(new)*: Vertex AI Workbench, GCS model buckets, VPC Service Controls.
* `siftsec/collectors/azure/` *(new)*: Azure ML Compute, Azure Blob, Azure AI Content Safety.
* `siftsec/rules/gcp.py` & `siftsec/rules/azure.py` *(new)*.

---

## Phase 7: AI Supply Chain (AIBOM & RAG Canaries)

**Objective:** Automate EU AI Act / NIST AI 600-1 supply-chain artifacts and runtime RAG tamper checks.

### Files & Features
* `siftsec/reporters/aibom.py` *(new)*: Generates **CycloneDX v1.7 ML-BOM** / **SPDX 3.0 AI Profile** JSON from discovered models (with SHA-256 hashes), datasets, vector stores, and MCP tools.
* `siftsec/scanners/rag_canary.py` *(new)*: Inserts and verifies canary embeddings in vector databases to detect unauthorized corpus tampering (*PoisonedRAG* / *AuthChain* mitigation).
* [`siftsec/cli.py`](file:///c:/Pro/PROJECT/SIFTSEC/siftsec/cli.py): Add `--sbom [cyclonedx|spdx]` flag.
