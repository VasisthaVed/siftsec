# SIFTSEC Scanner: System Architecture & Design

This document details the architectural design, component interactions, data pipelines, and error handling mechanisms of the **SIFTSEC (AI Security Posture Management) Scanner**.

---

## 1. System Context & Overview

The SIFTSEC Scanner is an agentic, modular CLI and scanning engine designed to audit cloud environments (initially AWS) for security misconfigurations, data leakage risks, and compliance gaps across artificial intelligence and machine learning infrastructure.

```
                           +----------------------+
                           |   Operator / CI-CD   |
                           +----------------------+
                                      |
                                      v
                           +----------------------+
                           |      Typer CLI       |
                           +----------------------+
                                      |
                       +--------------+--------------+
                       |                             |
                       v                             v
            +--------------------+         +--------------------+
            | AWS Collector Engine|         | Rule Registry      |
            +--------------------+         +--------------------+
                       |                             |
          (Raw AWS SDK Responses)                    |
                       |                             |
                       v                             |
            +--------------------+                   |
            | Pydantic Normalizer|                   |
            +--------------------+                   |
                       |                             |
             (AWSResource Models)                    |
                       |                             |
                       +--------------+--------------+
                                      |
                                      v
                           +----------------------+
                           | Rule Evaluator Engine|
                           +----------------------+
                                      |
                               (Findings Stream)
                                      |
                                      v
                           +----------------------+
                           |   Reporters Layer    |
                           +----------------------+
                               /      |      \
                              v       v       v
                        [Terminal]  [JSON]  [SARIF / Markdown]
```

---

## 2. Core Components

### 2.1 CLI Layer (`siftsec/cli.py`)
- Powered by `typer` for command routing and option parsing.
- Handles flags: `--services`, `--regions`, `--severity`, `--output`, `--format`, `--fail-on`, `--profile`, `--ai-tag-filter`.
- Integrates with `rich` to provide spinners, progress bars, and colored terminal formatting.
- Determines exit codes:
  - `0`: Scan completed with no violations exceeding threshold.
  - `1`: Scan completed with violations matching or exceeding `--fail-on` (default: `HIGH`).
  - `2`: Fatal initialization or configuration error.

### 2.2 Scan Context & AWS Session Manager (`siftsec/engine/context.py` & `siftsec/collectors/aws_client.py`)
- Resolves AWS identity:
  - Account ID (`sts:GetCallerIdentity`).
  - Active credentials (env vars, shared credentials, WebIdentity token, ECS/EC2 metadata).
  - Target regions (explicit list or auto-discovery via `ec2:DescribeRegions`).
- Configures Boto3 client factory with adaptive retries (`max_attempts=5`) and custom user-agent (`User-Agent: SIFTSEC-Scanner/1.0`).

### 2.3 AWS Collector Abstraction (`siftsec/collectors/`)
- Abstract base: `BaseCollector` defines:
  - `collect(self, context: ScanContext) -> list[AWSResource]`
  - Standardized pagination handling across varied Boto3 pagination token formats.
  - Exception barrier isolating individual service failures.
- Specialized Collectors:
  - `S3Collector`: Evaluates S3 buckets, encryption configs, public access block configurations, and bucket policies.
  - `SageMakerCollector`: Fetches Notebooks, Training Jobs, Inference Endpoints, Models, and Domain Spaces.
  - `BedrockCollector`: Fetches Model Invocation Logging, Knowledge Base data sources, and Bedrock Agents.
  - `ECRCollector`: Inspects repository scan-on-push policies, KMS encryption, and tag mutability.
  - `OpenSearchCollector`: Evaluates cluster and serverless configurations, VPC network modes, encryption, and FGAC.

### 2.4 Pydantic Normalization Layer (`siftsec/collectors/models.py`)
- Converts raw heterogeneous AWS API payloads into standardized `AWSResource` instances.
- Performs AI Workload Classification:
  - **Tag-based:** Matches tags such as `workload=ai`, `project=ml`, `component=rag`.
  - **Name/Pattern-based:** Evaluates regex heuristics for model weights, embeddings, or inference pipelines.
  - **Service-inherent:** SageMaker and Bedrock resources are classified as AI workloads by default.

### 2.5 Rule Engine & Registry (`siftsec/engine/runner.py` & `siftsec/rules/`)
- `BaseRule`: Immutable interface containing rule metadata (ID, title, severity, service, OWASP/MITRE mappings) and the abstract `evaluate` method.
- `RuleRegistry`: Auto-loads rules using Python reflection or entry points; filters rules based on CLI flags.
- `RuleRunner`:
  - Executes rules against collected resources.
  - Guarantees error isolation: if a single rule raises an unexpected exception during evaluation, it outputs a finding with `Status.ERROR` rather than crashing the scan.

### 2.6 Reporters & Export Sinks (`siftsec/reporters/`)
- `ConsoleReporter`: Rich tables grouped by service and severity, with clear summary statistics.
- `JSONReporter`: Fully serialized output conforming to an explicit JSON schema for automated parsing.
- `MarkdownReporter`: Clean GFM report suitable for automated PR comments or audit logs.
- `SARIFReporter`: OASIS Static Analysis Results Format (v2.1.0) compatible with GitHub Advanced Security.

---

## 3. Resilience & Error Handling Strategy

| Error Scenario | Root Cause | SIFTSEC Handling Strategy |
| :--- | :--- | :--- |
| **`AccessDenied` / `UnauthorizedOperation`** | Missing IAM read permission on specific API | Log warning, record a `Status.ERROR` finding noting the missing permission, and continue scanning remaining services. |
| **`ThrottlingException` / `RequestLimitExceeded`** | AWS API rate limits exceeded | Boto3 adaptive exponential backoff with jitter up to 5 attempts. |
| **Invalid Region** | Specified region not enabled for account | Skip region with informational log; proceed with valid regions. |
| **Unrecognized Resource Payload** | AWS API schema change or new feature | Pydantic lenient parsing with extra fields stored in `metadata: dict[str, Any]` without failing validation. |

---

## 4. Performance & Scalability Targets

- **Execution Concurrency:** Multi-threaded or asynchronous regional scanning using `concurrent.futures.ThreadPoolExecutor` across AWS regions.
- **Scan Latency Target:** Complete scan of an enterprise AWS account (< 5,000 resources) in under 60 seconds.
- **Memory Footprint:** Streaming resource evaluation to maintain working memory under 250 MB.
