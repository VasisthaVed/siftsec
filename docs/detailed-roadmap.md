# AI-SPM Scanner: Detailed Engineering Roadmap & Implementation Plan

This document expands the high-level roadmap into a complete, phase-by-phase implementation blueprint for building the **AI-SPM (AI Security Posture Management) Scanner**.

---

## 1. High-Level Architecture & Workflow

```
+-----------------------------------------------------------------------------------+
|                                  Typer CLI                                        |
|  ai-spm scan --services s3,sagemaker,bedrock,ecr,opensearch --output report.json  |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                                 Scan Context                                      |
|    - AWS Session Manager (Profile, SSO, IAM Role, Default/Multi-Region)            |
|    - Tag & Workload Filter Engine (Auto-detect AI resources & Shadow AI)          |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        AWS Collectors Layer (Boto3)                               |
|   +-------------------+  +-------------------+  +-------------------+              |
|   |   S3 Collector    |  |SageMaker Collector|  | Bedrock Collector |  ...         |
|   +-------------------+  +-------------------+  +-------------------+              |
|     * Boto3 Pagination Engine                                                     |
|     * Graceful Degradation (ClientError -> AccessDenied / Throttling)             |
|     * Pydantic Resource Normalization (AWSResource models)                        |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                          Rule Evaluation Engine                                   |
|   +---------------------------------------------------------------------------+   |
|   |  Rule Registry (Discovers active BaseRule subclasses)                     |   |
|   |  Rule Evaluator (Pure execution: resource -> Finding[PASS/FAIL/ERROR])    |   |
|   +---------------------------------------------------------------------------+   |
|     * MITRE ATLAS & OWASP LLM Metadata Tagging                                    |
|     * Remediation Generator (AWS CLI & CloudFormation/Terraform hints)            |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                             Reporters & Sinks                                     |
|  +--------------------+  +--------------------+  +--------------------+           |
|  | Rich Terminal UI   |  | JSON / SARIF Sink  |  | Markdown Report    |           |
|  +--------------------+  +--------------------+  +--------------------+           |
|  * Exit code evaluation (0 = Clean, 1 = Critical/High violations detected)        |
+-----------------------------------------------------------------------------------+
```

---

## 2. Phase-by-Phase Execution Plan

### Phase 1: Scaffolding, Core Models & Rule Engine Foundation

**Goal:** Establish a rock-solid Python project scaffolding using `uv`, configure code quality gates, and build typed Pydantic v2 data models for resources, findings, and the abstract `BaseRule`.

#### Tasks & Deliverables:
1. **Repository Setup:**
   - Initialize `pyproject.toml` with `uv` containing dependencies:
     - Core: `boto3 >= 1.34.0`, `pydantic >= 2.6.0`, `typer[all] >= 0.12.0`, `rich >= 13.7.0`.
     - Dev/Test: `pytest >= 8.0.0`, `pytest-cov`, `pytest-asyncio`, `moto[all] >= 5.0.0`, `ruff >= 0.3.0`, `mypy >= 1.8.0`.
   - Setup `.gitignore`, `README.md`, and `ruff.toml` / `pyproject.toml` linting configurations.
2. **Pydantic Data Models (`ai_spm/engine/models.py`):**
   - `Severity` Enum: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`.
   - `Status` Enum: `PASSED`, `FAILED`, `ERROR`, `SKIPPED`.
   - `AWSResource`:
     ```python
     class AWSResource(BaseModel):
         arn: str
         id: str
         name: str
         service: str
         region: str
         account_id: str
         tags: dict[str, str] = Field(default_factory=dict)
         metadata: dict[str, Any] = Field(default_factory=dict)
         is_ai_workload: bool = False
     ```
   - `Finding`:
     ```python
     class Finding(BaseModel):
         rule_id: str
         rule_title: str
         service: str
         resource_arn: str
         resource_id: str
         status: Status
         severity: Severity
         message: str
         remediation: str
         mitre_atlas: list[str] = Field(default_factory=list)
         owasp_llm: list[str] = Field(default_factory=list)
         region: str
         timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
     ```
3. **Abstract BaseRule Class (`ai_spm/rules/base.py`):**
   - Provide abstract interface with metadata properties:
     - `rule_id`, `title`, `description`, `severity`, `service`, `mitre_atlas`, `owasp_llm`.
     - Abstract method: `evaluate(self, resource: AWSResource) -> Finding`.
4. **Rule Registry (`ai_spm/rules/registry.py`):**
   - Automatic registration and filtering of rules by service, minimum severity, or rule ID.

---

### Phase 2: AWS API Abstraction & Robust Collector Engine

**Goal:** Create an enterprise-grade Boto3 wrapper capable of automatic pagination, credential handling, rate-limiting backoff, and graceful degradation on permission denials.

#### Tasks & Deliverables:
1. **Central AWS Session & Client Factory (`ai_spm/collectors/aws_client.py`):**
   - Automatic credential resolution (Environment variables, `~/.aws/credentials`, IAM Role assumption, AWS SSO).
   - Configured with `botocore.config.Config(retries={'max_attempts': 5, 'mode': 'adaptive'})`.
2. **Base Collector (`ai_spm/collectors/base.py`):**
   - Handles multi-region iteration.
   - Common safe execution decorator `@handle_aws_errors` catching `ClientError` (specifically `AccessDeniedException`, `UnauthorizedOperation`, `ThrottlingException`).
   - Standardized paginator method:
     ```python
     def paginate(self, client: Any, method_name: str, result_key: str, **kwargs) -> Iterator[dict]:
         if client.can_paginate(method_name):
             paginator = client.get_paginator(method_name)
             for page in paginator.paginate(**kwargs):
                 yield from page.get(result_key, [])
         else:
             # Manual continuation token fallback
             ...
     ```
3. **AI Resource & Shadow AI Detection Heuristics:**
   - Detect AI workloads using:
     - Tag filters: `workload=ai`, `project=ml`, `data=model`, `env=llm`, etc.
     - S3 bucket naming patterns: `*model*`, `*dataset*`, `*weights*`, `*bedrock*`, `*sagemaker*`, `*rag*`.
     - ECR repository naming patterns: `*ai*`, `*torch*`, `*vllm*`, `*tgi*`, `*sagemaker*`.
4. **Service Collectors:**
   - `S3Collector`: Lists buckets, encryption configurations, public access blocks, versioning, and bucket policies.
   - `SageMakerCollector`: Lists notebook instances, models, training jobs, endpoint configs, and domain spaces.
   - `BedrockCollector`: Checks model invocation logging, foundation model access, knowledge bases, data source encryption, and guardrails.
   - `ECRCollector`: Lists repositories, image scan-on-push settings, and tag mutability.
   - `OpenSearchCollector`: Lists domains, VPC settings, node-to-node encryption, and fine-grained access control.

---

### Phase 3: AI-SPM Rule Implementation

**Goal:** Implement all 16 detection rules across the 5 core AI services based on `docs/ai-spm-rules-catalog.md`.

#### Tasks & Deliverables:
1. **S3 Rules:**
   - `AI-SPM-S3-001`: Unencrypted AI Model Weights Storage (Require KMS CMK).
   - `AI-SPM-S3-002`: Public Access Allowed on AI Datasets/Artifacts.
   - `AI-SPM-S3-003`: Missing Object Versioning on Training Datasets.
2. **SageMaker Rules:**
   - `AI-SPM-SAGEMAKER-001`: Notebook Direct Internet Access Enabled.
   - `AI-SPM-SAGEMAKER-002`: Notebook Missing Custom VPC Attachment.
   - `AI-SPM-SAGEMAKER-003`: Root Privileges Enabled on Notebook Instance.
   - `AI-SPM-SAGEMAKER-004`: Endpoint Unencrypted Storage Volume.
   - `AI-SPM-SAGEMAKER-005`: Training Job Missing Network Isolation.
3. **Bedrock Rules:**
   - `AI-SPM-BEDROCK-001`: Model Invocation Logging Disabled.
   - `AI-SPM-BEDROCK-002`: Knowledge Base Data Source Missing KMS CMK.
   - `AI-SPM-BEDROCK-003`: Bedrock Agent Missing Guardrails / Filter Controls.
4. **ECR Rules:**
   - `AI-SPM-ECR-001`: AI Image Vulnerability Scan on Push Disabled.
   - `AI-SPM-ECR-002`: AI Image Tag Immutability Disabled.
5. **OpenSearch / Vector DB Rules:**
   - `AI-SPM-OPENSEARCH-001`: Vector DB Domain Exposed to Public Internet.
   - `AI-SPM-OPENSEARCH-002`: Fine-Grained Access Control (FGAC) Disabled.
   - `AI-SPM-OPENSEARCH-003`: Node-to-Node Encryption Disabled.

---

### Phase 4: CLI Application & Reporting Engine

**Goal:** Build an ergonomic, professional CLI with `typer` and `rich`, providing multi-format reports (Console, JSON, Markdown, SARIF).

#### Tasks & Deliverables:
1. **Typer CLI Interface (`ai_spm/cli.py`):**
   - Command: `ai-spm scan [OPTIONS]`
     - `--regions`: Comma-separated AWS regions (e.g., `us-east-1,us-west-2`) or `all`.
     - `--services`: Filter specific services (`s3`, `sagemaker`, `bedrock`, `ecr`, `opensearch`).
     - `--severity`: Minimum severity to report (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
     - `--output`: Filepath to write the scan report.
     - `--format`: `terminal`, `json`, `markdown`, `sarif`.
     - `--fail-on`: Exit with code 1 if findings meet or exceed this severity (for CI/CD gating).
     - `--profile`: AWS CLI named profile.
   - Command: `ai-spm list-rules`: Displays the full rule catalog with severities and threat model mappings.
2. **Reporters (`ai_spm/reporters/`):**
   - `ConsoleReporter`: Rich tables with color-coded severities, finding summaries, and progress bars.
   - `JSONReporter`: Complete structured JSON export with timestamps, resource metadata, and findings.
   - `MarkdownReporter`: Executive security summary and detailed remediation tables suitable for GitHub PR comments.
   - `SARIFReporter`: OASIS SARIF format for native integration into GitHub Code Scanning alerts.

---

### Phase 5: Production CI/CD & Testing Suite

**Goal:** Comprehensive automated test coverage and GitHub Actions pipeline to enforce security scanning on PRs.

#### Tasks & Deliverables:
1. **Test Infrastructure:**
   - Unit tests for every rule using synthetic Pydantic `AWSResource` payloads.
   - Integration tests with `moto` mocking S3, SageMaker, ECR, and OpenSearch API responses.
   - CLI end-to-end tests using Typer's `CliRunner`.
2. **GitHub Action Integration:**
   - Pre-built reusable GitHub Action / Workflow (`.github/workflows/ai-spm.yml`).
   - Runs `ai-spm scan --fail-on HIGH --format sarif --output ai-spm-results.sarif`.
   - Uploads SARIF results to `github/codeql-action/upload-sarif`.

---

## 3. Extensibility & Future Milestones

* **Phase 6 (Multi-Cloud):** Expand AI-SPM collectors to Google Cloud Vertex AI (Model Registry, Notebooks, Vertex Search) and Azure OpenAI / Azure AI Foundry.
* **Phase 7 (Local / Shadow LLM Discovery):** Network port discovery for unauthenticated local inference servers (Ollama, vLLM, LocalAI, LM Studio) running in EC2/ECS/EKS.
* **Phase 8 (Automated Remediation / PR Generation):** One-click Terraform/CloudFormation fix generation to remediate findings automatically.
