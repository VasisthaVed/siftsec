# AI-SPM: Architectural Decisions & Implementation Log (`decisions.md`)

This document records the architectural decisions, design trade-offs, engineering blueprints, and milestones implemented for the **AI-SPM Scanner**.

---

## 1. Architectural Decision Records (ADRs)

### ADR 001: Strict Schema Validation via Pydantic v2
* **Context:** Traditional CSPMs pass untyped dictionaries, leading to runtime key errors and brittle collectors when cloud APIs change.
* **Decision:** All resources, findings, and evaluation outputs are strictly validated via **Pydantic v2** (`CloudResource`, `Finding`, `Severity`, `Status`, `CloudProvider`).
* **Consequences:** Provides full IDE autocompletion, compile-time type validation, zero runtime `KeyError` crashes, and clean serialization to JSON and SARIF.

### ADR 002: Pure, Deterministic Rule Evaluation
* **Context:** Coupling network/AWS SDK calls inside detection rules makes testing slow, fragile, and dependent on live cloud credentials.
* **Decision:** Rules inherit from `BaseRule` and implement a pure, side-effect-free `evaluate(resource: CloudResource) -> Finding` method. All API calls are isolated in the `collectors/` layer.
* **Consequences:** Rules can be unit-tested in milliseconds without mock credentials, and can evaluate both live AWS resources and simulated demo environments identically.

### ADR 003: The Zero-Credential Simulation Engine (`--demo`)
* **Context:** Over 80% of open-source visitors bounce if they must configure AWS IAM credentials before testing a security tool.
* **Decision:** Built an in-memory `MockCollector` that yields a realistic synthetic enterprise environment (vulnerable PyTorch checkpoints in S3, unencrypted buckets, public OpenSearch vector cluster, Bedrock agent without guardrails, wildcard IAM roles, and poisoned MCP tool metadata).
* **Consequences:** Enables any developer or prospective user to run `uvx ai-spm scan --demo` in under 5 seconds, seeing an immediate Rich terminal report with a calculated AI Posture Score.

### ADR 004: Native OASIS SARIF v2.1.0 Exporter
* **Context:** Developers want automated CI/CD integration without paying for third-party enterprise dashboards.
* **Decision:** Implemented `SARIFReporter` producing OASIS SARIF v2.1.0 JSON payloads.
* **Consequences:** Allows instant integration with GitHub Actions (`upload-sarif`), populating findings directly into the GitHub repository's native **Security → Code Scanning alerts** tab.

### ADR 005: 7-Tier AI Defense Architecture
* **Context:** Generic CSPMs focus only on cloud infrastructure, missing AI-specific threats like embedding inversion, pickle deserialization, and agent tool poisoning.
* **Decision:** Organized detection taxonomy into 7 foundational tiers:
  * Tier 0: GPU Runtime, Infrastructure, Secrets & IAM Baseline
  * Tier 1: Model Weights, Deserialization (Pickle vs SafeTensors) & ECR
  * Tier 2: Vector Databases, RAG Pipelines & Semantic Inversion
  * Tier 3: Inference Gateways, Shadow AI & Foundation Models
  * Tier 4: Autonomous Agents & Guardrails
  * Tier 5: MCP Tool Runtimes & Manifest Integrity
  * Tier 6: AI Supply Chain & AI Bill of Materials (AIBOM)

---

## 2. Completed Implementation Milestones

1. **Repository & Build Setup:**
   * Initialized Git repository.
   * Created `pyproject.toml` with `uv` targeting Python 3.12/3.13.
   * Resolved and installed all 77 dependencies (`boto3`, `pydantic`, `typer`, `rich`, `pytest`, `ruff`, `mypy`).
   * Configured `.gitignore` and `README.md`.

2. **Core Data Models (`ai_spm/engine/models.py`):**
   * `Severity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`
   * `Status`: `PASSED`, `FAILED`, `ERROR`, `SKIPPED`
   * `CloudProvider`: `AWS`, `GCP`, `AZURE`, `KUBERNETES`, `MCP`
   * `CloudResource`: Normalized multi-cloud asset abstraction
   * `Finding`: Normalized audit finding with MITRE ATLAS, OWASP LLM, and NIST AI 600-1 mappings.

3. **Rule Registry & Initial Detection Rules:**
   * `BaseRule` abstract class and dynamic `RuleRegistry`.
   * **`AI-SPM-S3-001`**: Model weight storage KMS CMK encryption.
   * **`AI-SPM-S3-002`**: S3 public access block configuration.
   * **`AI-SPM-S3-004`**: Insecure model serialization (legacy `.pt`/`.pkl` vs `.safetensors`).
   * **`AI-SPM-SAGEMAKER-001`**: SageMaker Direct Internet Access (DIA) enabled.
   * **`AI-SPM-BEDROCK-003`**: Bedrock Agent missing active Guardrail.
   * **`AI-SPM-VECTOR-001`**: Vector database publicly exposed (Vec2Text inversion risk).
   * **`AI-SPM-IAM-001`**: Excessive agency: wildcard permissions on AI execution roles.
   * **`AI-SPM-MCP-001`**: MCP tool manifest poisoning and hidden prompt injections.

4. **Multi-Sink Reporting Layer:**
   * `ConsoleReporter`: Rich terminal dashboard, color-coded severity tables, actionable remediation panels, and calculated composite AI Posture Score (0–100).
   * `SARIFReporter`: GitHub Code Scanning native export.

5. **CLI Application (`ai_spm/cli.py`):**
   * `ai-spm scan --demo`: Instant in-memory simulation scan.
   * `ai-spm list-rules`: View all registered detection rules.
   * Configurable threshold exit codes (`--fail-on HIGH` / `--fail-on CRITICAL`).

6. **Automated Testing Suite (`tests/test_ai_spm.py`):**
   * 5 automated test cases verifying model validation, rule evaluation, mock collection, and CLI commands. 100% passing.

---

## 3. Marketplace Skills & Ecosystem Integrations

During discovery, the following marketplace extensions were identified for potential future integration:
* **Orca Security Plugin (`antigravity-plugins-partners/plugin/orca-security`):** Useful for cross-correlating cloud posture findings with enterprise cloud asset graphs.
* **Harness Plugin (`antigravity-plugins-partners/plugin/harness-antigravity`):** Useful for investigating CI/CD pipeline findings and automated deployment gates.
