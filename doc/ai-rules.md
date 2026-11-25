# AI & Developer Engineering Rules (AI-Rules)

This document establishes the mandatory engineering rules, architectural constraints, security principles, and coding standards for all AI assistants and human developers contributing to the **AI-SPM Scanner** project.

---

## 1. Prime Directives for AI Coding Assistants

1. **Zero Hallucinated AWS APIs:** All AWS calls must map directly to legitimate `boto3` client methods (AWS SDK for Python v1.34+). Never guess method names or response payloads. Verify parameter dictionaries and return structures against the official Boto3 documentation.
2. **Resilience & Graceful Degradation:** An AWS scan must NEVER crash due to missing IAM permissions (`AccessDenied`, `UnauthorizedOperation`), throttling (`ThrottlingException`, `RequestLimitExceeded`), or missing resources (`ResourceNotFoundException`). Unpermitted API calls must be logged as warnings or marked as `PERMISSION_DENIED` scan findings, allowing the scan of other services to continue uninterrupted.
3. **Mandatory Pagination:** AWS resource lists must always paginate using `boto3.client.get_paginator(...)` where available, or explicit token continuation (`NextToken`, `Marker`, `ContinuationToken`). Assuming single-page responses (< 50 or 100 items) is strictly prohibited.
4. **Strict Typing & Pydantic Validation:** All internal entities (Resources, Rules, Findings, Scan Context, Configuration) must be strictly typed using Python 3.12+ type hints and validated via **Pydantic v2**. Raw untyped dictionaries must not be passed beyond the AWS Collector layer.
5. **No Production AWS Credential Leakage:** Tests and local development runs must NEVER require real AWS credentials. All unit and integration tests must run against mocked AWS services using `moto` or explicit dependency injection with stubbed responses.
6. **Zero Hardcoding & Dynamic-First Design:** Never hardcode magic numbers, scoring weights, file extension lists, port lists, thresholds, or rule/collector imports inside business logic.
   - All tunable parameters (severity weights, insecure model extensions, shadow AI ports, AI tag heuristics, default fail thresholds) must live in `ai_spm/config.py` (`AISPMConfig` via `pydantic-settings`) and be overridable via environment variables (`AI_SPM_*`) or config files.
   - Rules and collectors must be discovered dynamically (`pkgutil.iter_modules` / `importlib.metadata.entry_points`), never via static import lists.
   - Remediation messages must dynamically interpolate actual resource attributes (`resource.name`, `resource.region`, `resource.arn`), never static `<bucket>` placeholders.

---

## 2. Project Architecture & Code Structure

The repository must follow a clean, modular, domain-driven structure:

```
ai_spm/
├── __init__.py
├── cli.py                  # Typer CLI application entry point
├── config.py               # Pydantic v2 application configuration
├── engine/                 # Core scanning and rule evaluation engine
│   ├── __init__.py
│   ├── runner.py           # Orchestrates discovery, rule execution, and reporting
│   ├── context.py          # Scan context (AWS session, account, region, tags)
│   └── finding.py          # Finding data models and severity enums
├── collectors/             # AWS API abstraction and resource collectors
│   ├── __init__.py
│   ├── base.py             # Abstract BaseCollector with pagination & error handling
│   ├── s3.py               # Model storage and bucket inventory
│   ├── sagemaker.py        # Notebooks, training jobs, models, endpoints
│   ├── bedrock.py          # Foundation models, custom models, guardrails, logging
│   ├── ecr.py              # AI container image scanning and policy
│   └── opensearch.py       # Vector DB clusters & serverless collections
├── rules/                  # Security Posture Detection Rules
│   ├── __init__.py
│   ├── base.py             # Abstract BaseRule definition
│   ├── registry.py         # Rule registration, discovery, and filtering
│   ├── s3/                 # S3-specific AI rules
│   ├── sagemaker/          # SageMaker-specific AI rules
│   ├── bedrock/            # Bedrock-specific AI rules
│   ├── ecr/                # ECR-specific AI rules
│   └── opensearch/         # OpenSearch / Vector DB rules
├── reporters/              # Finding exporters and formatters
│   ├── __init__.py
│   ├── base.py             # Abstract BaseReporter
│   ├── console.py          # Rich terminal table and panel output
│   ├── json.py             # Machine-readable JSON output
│   ├── markdown.py         # Summary and audit report in Markdown
│   └── sarif.py            # SARIF format for GitHub Security integration
└── utils/
    ├── __init__.py
    ├── aws.py              # AWS session and client factory
    └── logger.py           # Structured logging (loguru or rich.logging)
```

---

## 3. Python Standards & Tooling

* **Python Version:** `>=3.12` (Targeting 3.12 and 3.13).
* **Package & Environment Manager:** `uv` is the primary package manager. (Compatibility with `poetry` and `pip` pyproject standard).
* **Linting & Formatting:** `ruff` for linting and code formatting (`ruff check` and `ruff format`).
* **Type Checking:** `mypy` in strict mode (`--strict`). Every function signature must contain parameter types and return type annotations.
* **Testing:** `pytest` + `pytest-asyncio` + `pytest-cov` + `moto[all]`. Code coverage target: `>=85%`.

---

## 4. Rule Implementation Rules

Every security detection rule implemented in the scanner must adhere to the following contract:

1. **Inherit from `BaseRule`:**
   ```python
   from ai_spm.rules.base import BaseRule
   from ai_spm.engine.finding import Finding, Severity, Status
   from ai_spm.collectors.models import AWSResource


   class S3ModelBucketEncryptedRule(BaseRule):
       rule_id: str = "AI-SPM-S3-001"
       title: str = "AI Model Weight S3 Bucket Must Use KMS Customer-Managed Key Encryption"
       severity: Severity = Severity.HIGH
       service: str = "s3"
       mitre_atlas: list[str] = ["AML.T0044"]  # Full ML Model Access
       owasp_llm: list[str] = ["LLM02:2025"]  # Sensitive Information Disclosure

       def evaluate(self, resource: AWSResource) -> Finding: ...
   ```
2. **Deterministic Evaluation:** Rule evaluation must be pure and side-effect free. It receives an `AWSResource` data model and produces a `Finding` (`PASSED`, `FAILED`, `ERROR`, or `SKIPPED`).
3. **No Direct Network/Boto3 Calls in Rules:** Rules must never invoke Boto3 directly. All AWS API calls and data fetching must take place in the `collectors/` layer. The rule logic inspects pre-collected, validated resource schemas.
4. **False-Positive Suppression via Tagging:**
   - By default, general infrastructure checks (like generic S3 buckets) should focus on AI workloads.
   - Resources must be tagged with AI indicators (e.g., `workload=ai`, `data=model`, `component=rag`, `framework=pytorch`) or identified by known AI naming heuristics (e.g., bucket names containing `model`, `weights`, `checkpoint`, `dataset`, `bedrock`, `sagemaker`) unless explicitly configured for full account scanning.
5. **Actionable Remediation Guidance:** Every failing finding must include step-by-step remediation instructions (AWS CLI commands or Terraform/CloudFormation code snippets) to enable rapid remediation.

---

## 5. AWS Collector Guidelines

1. **Client Pooling & Session Management:** Use a centralized AWS session manager supporting assume-role, AWS SSO, environment variables, and instance profiles.
2. **Explicit Rate Limiting & Backoff:** Wrap API calls with exponential backoff using `botocore.config.Config(retries={'max_attempts': 5, 'mode': 'adaptive'})`.
3. **Region Awareness:** Support scanning specific regions (`--region us-east-1,us-west-2`) or all active enabled regions in the AWS account.
4. **Resource Normalization:** Transform raw Boto3 dictionary responses into typed Pydantic models before returning them to the engine.

---

## 6. Testing Directives

1. **Unit Tests:**
   - Every rule must have a corresponding test suite in `tests/rules/` with at least two test cases:
     1. A compliant resource returning `Status.PASSED`.
     2. A non-compliant resource returning `Status.FAILED` with correct severity and remediation text.
2. **Moto Integration Tests:**
   - Test collectors in `tests/collectors/` against simulated AWS infrastructure using `moto`.
3. **CLI End-to-End Tests:**
   - Test CLI invocations using Typer's `CliRunner` verifying exit codes (`0` for pass, `1` for critical/high failures when `--fail-on-severity` is set).

---

## 7. Versioning, Git & CI Directives

1. **Conventional Commits:** All git commit messages must follow standard conventional commit syntax:
   - `feat: add Bedrock guardrail evaluation rule`
   - `fix: handle AccessDenied on SageMaker DescribeNotebookInstance`
   - `docs: update AI-SPM threat model with MITRE ATLAS AML.T0044`
   - `test: add moto unit tests for OpenSearch vector collector`
2. **CI Gates:**
   - GitHub Actions workflow running:
     1. `ruff check .`
     2. `ruff format --check .`
     3. `mypy ai_spm`
     4. `pytest --cov=ai_spm --cov-report=term-missing`
