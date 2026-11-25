# AI-SPM / TensorGuard — Build Playbook (Phases 0–9)

This replaces `phases.md` + `detailed-roadmap.md` as the single source of truth while you code. Every sub-phase (`0.1`, `0.2`, `1.1` …) has the same shape: **Goal → Files → Code → Standards → Tests → Done when**. One sub-phase = one branch = one PR = one agent session (matches your one-agent-per-session discipline).

**Layout of this doc:** Part A review + locked decisions → Part B global standards → Phase 0 (foundation) → Phase 1 (local scanner) → Phase 2 (AWS collectors) → Phase 3 (rules) → Phase 4 (CLI/reporters/release) → Phases 5–7 (your existing K8s / multi-cloud / AIBOM) → Phases 8–9 (new: hardening + remediation/ops features).

---

# PART A — Review of the current docs

## A1. What's genuinely good (keep)

- **Collector → typed resource → pure rule** pipeline (ADR-002). This is the right spine; it's what makes the tool testable without AWS.
- **Zero-hardcoding via `AISPMConfig`** (ADR-001) and **entry-point rule discovery** (ADR-003).
- **Never `pickle.loads`; use `pickletools.genops`** (ADR-004) and **never spawn MCP servers** (ADR-005). Both are real security-tool-grade decisions.
- **Exception barriers + adaptive retries** (ADR-006), **weighted score** (ADR-007), **secret redaction before any reporter** (ADR-008).
- Starting with a local, zero-credential scanner is smart: it ships value fast and proves the engine before AWS complexity.

## A2. Contradictions between the docs (these WILL bite you mid-coding)

| # | Conflict | Where | Resolution (locked below) |
| --- | --- | --- | --- |
| 1 | Project name `AI-SPM` vs `TensorGuard` | all docs | **D-01** |
| 2 | Rule count 16 vs 18 | detailed-roadmap omits S3-004 + IAM-001 | **D-02** (catalog = 18 AWS rules, authoritative) |
| 3 | `AI-SPM-OPENSEARCH-00x` vs `AI-SPM-VECTOR-00x` | catalog vs phases | **D-03** |
| 4 | `AWSResource` vs `CloudResource` | ai-rules vs ADR-002 | **D-04** |
| 5 | Models in `engine/finding.py` vs `engine/models.py` | ai-rules vs roadmap | **D-05** |
| 6 | `collectors/s3.py` vs `collectors/aws/s3.py`; `aws_client.py` vs `aws/client.py` | ai-rules vs phases | **D-06** |
| 7 | CLI flags: `--fail-on` vs `--fail-on-severity`; `--severity` vs `--min-severity`; `--region` vs `--regions` | 4 different docs | **D-07** |
| 8 | AccessDenied → `PERMISSION_DENIED` finding vs `Status.ERROR` | ai-rules vs architecture | **D-08** |
| 9 | Severity disagrees: BEDROCK-003 HIGH (catalog body) vs CRITICAL (matrix); S3-001 CRITICAL (catalog) vs HIGH (ai-rules example) | catalog / ai-rules | **D-09** |
| 10 | Exit code 1 for "critical/high" vs "≥ `--fail-on`" | ai-rules vs architecture | **D-07** |
| 11 | `pydantic-settings` required by ADR-001 but missing from dependency list | detailed-roadmap | fixed in 0.1 |
| 12 | "No raw dicts past the collector" (ai-rules) vs `metadata: dict[str, Any]` on the resource | ai-rules vs roadmap | **D-04** (typed attribute models) |
| 13 | `pytest-asyncio` listed but the whole engine is sync/threaded | ai-rules | dropped (0.1) |
| 14 | Shadow-AI rule needs security groups (EC2) but no EC2 collector exists | phases P3 | added in 2.10 |
| 15 | IAM-001 remediation links to `file:///c:/Pro/PROJECT/...` — a local Windows path baked into a shipped finding | catalog | removed; remediation text must be self-contained |

## A3. Technical-correctness issues in the rules (verify before coding each rule)

1. **S3-001 "unencrypted" can never happen.** Since Jan 2023 every S3 bucket has SSE-S3 by default. The real check is *"is it SSE-KMS with a customer-managed key?"*. Also handle `aws:kms:dsse`, and check the key is CMK not `alias/aws/s3` (requires `kms:DescribeKey` → `KeyManager == 'CUSTOMER'`). Making that **CRITICAL** will make the scanner look noisy/alarmist — SSE-S3 on a model bucket is a **MEDIUM** hygiene gap; *no* encryption policy + public = critical (that's S3-002).
2. **S3-002:** `GetPublicAccessBlock` **raises** `NoSuchPublicAccessBlockConfiguration` when none is set — that is a FAIL, not an error. Also the *account-level* block (`s3control.get_public_access_block`) can compensate for a bucket with no block; and `GetBucketPolicyStatus.IsPublic` + ACL grants to `AllUsers` are better ground-truth signals than the four booleans alone.
3. **S3 buckets are global but regional for API calls.** `list_buckets` once, then `get_bucket_location` (returns `None` for us-east-1) and call per-bucket APIs with a client in the bucket's region, or you'll get `301 PermanentRedirect`.
4. **S3-004** can't distinguish "safe" vs "unsafe" `.bin`/`.pt` from the key name alone — it is a *heuristic*; ship it as **MEDIUM/"informational heuristic"** and let the local pickle scanner (1.x) give real proof.
5. **ECR-001:** repo-level `scanOnPush` is superseded when **registry-level enhanced scanning** (Inspector) is on — call `ecr.get_registry_scanning_configuration` first, otherwise you'll false-positive on accounts using Inspector. ECR immutability also has newer exclusion modes; treat any `IMMUTABLE*` value as pass (verify against current boto3 docs).
6. **BEDROCK-002 "default AWS-managed key"** is indistinguishable from "absent" in `GetDataSource` — document as "no CMK configured". Guardrail "status active" needs a second call (`bedrock.get_guardrail`), not just `GetAgent`.
7. **BEDROCK clients:** knowledge bases/agents are the `bedrock-agent` client; logging config is the `bedrock` client. Bedrock isn't in every region → expect `EndpointConnectionError`/`UnknownServiceError`-style failures; treat as "service unavailable in region" (SKIPPED), not ERROR.
8. **OpenSearch** `DescribeDomain` is per-domain → `list_domain_names` then `describe_domains` (batches of 5). **OpenSearch Serverless** (`opensearchserverless`: collections + network/encryption/data-access policies) is mentioned in the catalog but has **no rules** — public network policy (`AllowFromPublic: true`) is the single most important vector-DB check. Add rules (3.x). Also check the domain *access policy* for `Principal: "*"` and `DomainEndpointOptions.EnforceHTTPS`.
9. **IAM-001:** needs policy *document* retrieval (`get_policy_version`, inline `get_role_policy`), permissions boundaries, and the **trust policy** (confused-deputy: service principal without `aws:SourceAccount`/`aws:SourceArn`). IAM is global → collect once, not per region. `Action:"s3:*"` with `Resource:"*"` is the right signal; `Action:"*"` alone with a narrow resource shouldn't be HIGH.
10. **SAGEMAKER-004** `KmsKeyId` on EndpointConfig covers the ML storage volume only for instance types with attachable EBS; NVMe-backed instances (e.g. `ml.g5`) don't take a volume key. Also check `DataCaptureConfig.KmsKeyId` (inference payloads — arguably the more sensitive data).
11. **Framework mappings need an audit.** `AML.T0043` is *Craft Adversarial Data*, not "excessive agency/exfiltration" — it's mis-used on SAGEMAKER-001 and IAM-001. Also, **OWASP Top 10 for LLM Applications (2026 Edition)** (published Aug 2026) renumbered several categories: `LLM03:2026` is now *Excessive Agency*, `LLM04:2026` is *Model Supply Chain*, `LLM05:2026` is *Training Data Poisoning*, and `LLM09:2026` is *Vector and Embedding Weaknesses* (complemented by OWASP Agentic Top 10 `ASI01–ASI10`). Put mappings in a data file (`rules/frameworks.yaml`), reviewed against the live ATLAS/OWASP 2026 pages.
12. **CVE citations:** re-check every CVE id against NVD before shipping (I'm not confident `CVE-2024-34340` is a PyTorch/pickle issue — treat all CVE refs in the docs as *unverified* until you've opened the NVD entry). `CVE-2025-23266` (NVIDIAScape, toolkit fixed in 1.17.8) is the one I'm confident about.
13. **Performance target** "5,000 resources < 60s" is unrealistic for per-resource describe/get calls. Make it a *measured* target per service in Phase 8 rather than a promise.
14. **moto coverage:** moto's Bedrock / bedrock-agent / OpenSearch Serverless support is partial. Plan on `botocore.stub.Stubber` or hand-built response fixtures for those, `moto` for S3/ECR/IAM/EC2/SageMaker/OpenSearch.

## A4. What's missing (added in this playbook)

- **Unknown ≠ fail:** a resource attribute we couldn't read (AccessDenied) must not produce FAILED. (0.3/0.5)
- **Finding fingerprints + baseline/suppression file** (accept-risk with expiry & justification). Without this nobody can adopt it in CI. (0.6)
- **Versioned JSON output schema**, golden-file tests for every reporter. (4.x)
- **Scanner self-security:** read-only IAM policy shipped with the tool, no secret logging, pinned CI actions, SBOM + signed releases. (8.x)
- **Cross-resource correlation** (public SG → notebook → wildcard role = attack path). (9.x)
- **Scan diff / drift** between two runs. (9.x)
- **Fuzzing + property tests** for the pickle scanner & parsers (hostile input!). (1.x/8.x)
- **Rule docs auto-generated** from rule metadata so `docs/` can't drift. (4.x)

---

# PART A2 — Locked decisions (copy these into `decisions.md` as ADR-009+)

| ID | Decision |
| --- | --- |
| **D-01** | Distribution/package name **`tensorguard`**, import package **`ai_spm`**, CLI command **`tensorguard`** with alias **`ai-spm`** (both in `[project.scripts]`). Rule IDs keep the `AI-SPM-*` prefix. |
| **D-02** | Authoritative rule list = the 18 AWS rules in the catalog + new rules added in Phase 3. `detailed-roadmap.md`'s "16" is retired. |
| **D-03** | Service tokens are **`S3, SAGEMAKER, BEDROCK, ECR, OPENSEARCH, IAM, EC2, LOCAL, MCP, SECRETS, SHADOW, K8S, GCP, AZURE`**. `VECTOR` is retired → `OPENSEARCH` (and `OPENSEARCH` covers Serverless). IDs are immutable once released (never renumber; deprecate instead). |
| **D-04** | Single model `CloudResource` (alias `AWSResource = CloudResource` kept for one release only). Service-specific data lives in a **discriminated-union `attributes`** of typed Pydantic models (`kind: Literal["s3_bucket"]`…). Unreadable attributes are `None` + recorded in `resource.gaps: dict[str, str]` (attribute → error code). `metadata: dict[str, Any]` is only for unrecognized extra fields (architecture §3). |
| **D-05** | All domain models in `ai_spm/engine/models.py` (enums, `CloudResource`, `Finding`, `ScanSummary`). No `finding.py`. |
| **D-06** | AWS code under `ai_spm/collectors/aws/` (`client.py`, `base.py`, `s3.py`…). Local collectors under `ai_spm/collectors/local/`. Rules under `ai_spm/rules/<provider>/<service>.py` (one module per service, not one file per rule). |
| **D-07** | CLI flags: `--regions`, `--services`, `--min-severity`, `--fail-on`, `--format`, `--output`, `--profile`, `--config`, `--baseline`, `--ai-only/--all-resources`, `--verbose/--quiet`. Exit codes: **0** = no finding ≥ `--fail-on` (default `HIGH`); **1** = at least one finding ≥ `--fail-on`; **2** = config/init/fatal error; **3** = scan completed but *incomplete* (≥1 collector gap) **only when `--strict-coverage`** is set. |
| **D-08** | Permission problems yield `Status.ERROR` findings with `error_code="AccessDenied"` (never `FAILED`), excluded from the score numerator *and* denominator, and counted in `ScanSummary.coverage_gaps`. No `PERMISSION_DENIED` enum value. |
| **D-09** | Severity is defined **once**, in the rule class. The summary matrix in docs is *generated* from rule metadata (4.x). Re-rating: S3-001 → flat **MEDIUM** (SSE-S3 vs CMK; since Jan 2023 all S3 buckets have default encryption); BEDROCK-003 → **HIGH**; S3-004 → **MEDIUM**. |
| **D-10** | Python `>=3.12`; `uv` + committed `uv.lock`; `mypy --strict` with `boto3-stubs[...]`. |
| **D-11** | Rules are `ClassVar` metadata + pure `evaluate`. Rule metadata additionally carries `resource_kinds: ClassVar[frozenset[str]]` so the runner only feeds applicable resources (no `isinstance` guesswork inside rules). |
| **D-12** | Every `Finding` has a stable `fingerprint = sha256(rule_id \| resource_arn \| scope)[:32]` (where `scope` disambiguates multi-finding-per-resource rules) for baseline/diff/SARIF stability. |

---

# PART B — Global engineering standards (apply to every sub-phase)

## B1. Sub-phase workflow

1. Branch `feat/<phase>-<slug>` (e.g. `feat/0-3-models`). One sub-phase per branch.
2. **Tests first or alongside** — failing test committed before/with the code.
3. Run the gate locally before commit: `uv run ruff check . && uv run ruff format --check . && uv run mypy ai_spm && uv run pytest -q`.
4. Conventional commit (`feat(models): add CloudResource with discriminated attrs`).
5. Update `docs/CHANGELOG.md` (Keep-a-Changelog format) in the same PR.
6. **Definition of Done (every sub-phase):** gate green · new public code has docstrings (contract + *why* comments only) · coverage on touched modules ≥ 90% · no new `Any` outside the collector boundary · no hardcoded tunables · no network in tests · you can explain the diff in two sentences.

## B2. Multi-agent guardrails (you already know why)

- One agent edits one sub-phase; others are read-only reviewers.
- Every agent prompt starts with: *"Read `docs/ai-rules.md` + `docs/PLAYBOOK.md` sub-phase X.Y. Touch only the files listed. Show a full diff before applying. Do not rename public symbols."*
- Freeze interfaces with **contract tests** (0.5/2.2): if an agent changes `BaseRule.evaluate`'s signature a test fails immediately.
- `CODEOWNERS`-style rule: only you merge changes to `engine/models.py`, `rules/base.py`, `collectors/aws/base.py`.

## B3. Code rules (mypy-strict friendly)

- Early returns, ≤ 2 nesting levels; functions ≤ \~40 lines; no module-level mutable state.
- `from __future__ import annotations` not needed on 3.12 — use `X | None`, `list[str]`.
- Pydantic models: `model_config = ConfigDict(frozen=True, extra="forbid")` for rule/finding/config models; `extra="allow"` **only** on raw-payload ingestion models.
- Time: always timezone-aware UTC; inject a `clock: Callable[[], datetime]` where tests need determinism.
- No `print()`; use the logger. No `assert` for runtime validation.
- Secrets: any string that matches `settings.secret_patterns` is passed through `utils.redact.redact()` **at Finding construction**, not at reporter time (defense in depth).

## B4. Test pyramid & fixtures

```
tests/
  conftest.py              # make_resource(), make_finding(), fake_clock, aws_credentials(monkeypatch)
  unit/engine/  unit/rules/  unit/collectors/  unit/reporters/  unit/utils/
  integration/aws/         # moto + Stubber
  integration/cli/         # typer CliRunner, exit codes
  golden/                  # expected JSON/SARIF/Markdown outputs
  fuzz/                    # hypothesis (pickle, mcp json)
```

- `conftest.py` autouse fixture sets `AWS_ACCESS_KEY_ID=testing` etc. and **blocks sockets** (`pytest-socket` `--disable-socket`) — guarantees ADR-002/ai-rules §1.5.
- Rule tests are table-driven: `@pytest.mark.parametrize("attrs,status", [...])`; every rule ≥ 1 PASSED, ≥ 1 FAILED, ≥ 1 *unknown-attribute → ERROR/SKIPPED* case, and asserts remediation interpolates `resource.name`/`region`.

## B5. Final target repository tree

```
ai_spm/
  __init__.py  __main__.py  py.typed
  cli.py                    config.py            errors.py
  engine/   models.py  attrs.py  context.py  runner.py  scoring.py  suppressions.py  fingerprint.py
  collectors/
    base.py  registry.py
    aws/    client.py base.py classify.py s3.py sagemaker.py bedrock.py ecr.py opensearch.py iam.py ec2.py orchestrator.py
    local/  models.py mcp.py
    k8s.py  gcp/  azure/                      # later phases
  scanners/ pickle_scanner.py  secrets.py  rag_canary.py
  rules/
    base.py registry.py frameworks.yaml
    aws/  s3.py sagemaker.py bedrock.py ecr.py opensearch.py iam.py shadow_ai.py
    local.py  k8s_gpu.py  gcp.py  azure.py
  reporters/ base.py console.py json_rep.py markdown.py sarif.py aibom.py
  utils/  logger.py  redact.py  aws_arn.py  text.py
tests/ ...   docs/ ...   action.yml   pyproject.toml   uv.lock
```

---

# PHASE 0 — Foundation (the part you must get right once)

> Rule for Phase 0: *no AWS, no CLI polish, no rules beyond one demo rule.* Everything later plugs into what is built here. Budget: take your time; this is the phase agents most often corrupt.

## 0.1 Repo scaffold & toolchain

**Goal:** reproducible dev env + gates before any real code.

**Files:** `pyproject.toml`, `uv.lock`, `.gitignore`, `.editorconfig`, `.pre-commit-config.yaml`, `README.md` (stub), `LICENSE`, `SECURITY.md` (stub), `docs/CHANGELOG.md`, `ai_spm/__init__.py` (`__version__` via `importlib.metadata`), `ai_spm/py.typed`, `tests/conftest.py`.

**Code (`pyproject.toml` essentials):**

```toml
[project]
name = "tensorguard"
dynamic = ["version"]
requires-python = ">=3.12"
dependencies = [
  "boto3>=1.34", "pydantic>=2.6", "pydantic-settings>=2.2",
  "typer>=0.12", "rich>=13.7", "pyyaml>=6",
]
[project.optional-dependencies]
k8s = ["kubernetes>=29"]
gcp = ["google-cloud-aiplatform", "google-cloud-storage"]
azure = ["azure-mgmt-machinelearningservices", "azure-identity"]
[project.scripts]
tensorguard = "ai_spm.cli:app"
ai-spm = "ai_spm.cli:app"
[project.entry-points."ai_spm.rules"]   # built-ins use the same mechanism external plugins do
[dependency-groups]
dev = ["pytest>=8", "pytest-cov", "pytest-xdist", "pytest-socket", "hypothesis",
       "moto[all]>=5", "ruff", "mypy", "types-PyYAML", "pip-audit",
       "boto3-stubs[s3,sagemaker,bedrock,bedrock-agent,ecr,opensearch,opensearchserverless,iam,ec2,sts,s3control,kms]"]
[tool.ruff]
line-length = 100
target-version = "py312"
[tool.ruff.lint]
select = ["E","F","I","UP","B","SIM","S","PL","RUF","ANN","C4","PTH","T20"]  # S = bandit rules
[tool.mypy]
strict = true
plugins = ["pydantic.mypy"]
[tool.pytest.ini_options]
addopts = "-ra --strict-markers --disable-socket --cov=ai_spm --cov-fail-under=85"
```

**Standards:** `S` (bandit) ruff rules on — a security tool must lint clean on its own rules (add `# noqa: S...` only with a *why*). `T20` bans `print`. Pin Python in `.python-version`.

**Tests:** one smoke test `assert ai_spm.__version__`.

**Done when:** `uv sync && uv run pytest` green on a clean clone; pre-commit installed.

---

## 0.2 Configuration (`ai_spm/config.py`)

**Goal:** every tunable in one validated place (ADR-001).

**Files:** `ai_spm/config.py`, `tests/unit/test_config.py`, `docs/configuration.md` (generated later).

**Code:**

```python
from functools import lru_cache
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from ai_spm.engine.models import Severity

class AISPMConfig(BaseSettings):
    """Single source of tunables. Precedence: CLI flag > env (AI_SPM_*) > config file > defaults."""
    model_config = SettingsConfigDict(env_prefix="AI_SPM_", env_nested_delimiter="__",
                                      extra="forbid", frozen=True)

    severity_weights: dict[Severity, int] = {Severity.CRITICAL: 10, Severity.HIGH: 5,
        Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFORMATIONAL: 0}
    default_fail_on: Severity = Severity.HIGH
    ai_workload_tags: dict[str, list[str]] = {"workload": ["ai", "ml", "llm"], "data": ["model", "dataset"],
        "component": ["rag", "vectordb"], "framework": ["pytorch", "tensorflow"]}
    ai_name_patterns: dict[str, list[str]] = {   # per service: regex list
        "s3": [r"model", r"weights", r"checkpoint", r"dataset", r"bedrock", r"sagemaker", r"\brag\b"],
        "ecr": [r"torch", r"vllm", r"tgi", r"sagemaker", r"inference", r"train"]}
    insecure_model_extensions: list[str] = [".pt", ".pth", ".bin", ".pkl", ".pickle", ".ckpt", ".joblib"]
    safe_model_extensions: list[str] = [".safetensors", ".gguf", ".onnx"]
    dangerous_pickle_modules: list[str] = ["os", "posix", "nt", "subprocess", "socket", "builtins", "sys", "shutil", "runpy", "importlib"]
    dangerous_pickle_callables: list[str] = ["eval", "exec", "compile", "__import__", "system", "popen"]
    shadow_ai_ports: dict[int, str] = {11434: "ollama", 8000: "vllm", 8080: "localai", 1234: "lm-studio", 7860: "gradio", 8888: "jupyter"}
    secret_patterns: dict[str, str] = {}          # name -> regex (defaults filled in 1.6)
    s3_key_sample_size: int = Field(200, ge=1, le=1000)
    max_zip_uncompressed_bytes: int = 5 * 1024**3
    max_workers: int = Field(8, ge=1, le=64)
    boto_max_attempts: int = Field(5, ge=1, le=10)
    ignored_rules: frozenset[str] = frozenset()
    local_mcp_paths: list[str] = ["~/.cursor/mcp.json", "~/.config/Claude/claude_desktop_config.json", "./.mcp.json"]

    @field_validator("ai_name_patterns")
    @classmethod
    def _compile_ok(cls, v: dict[str, list[str]]) -> dict[str, list[str]]:
        import re
        for pats in v.values():
            for p in pats:
                re.compile(p)         # fail fast at startup, not mid-scan
        return v

@lru_cache
def get_settings() -> AISPMConfig: return AISPMConfig()
```

**Standards:** config is **frozen**; tests override via `monkeypatch.setenv` + `get_settings.cache_clear()`. YAML/TOML file support via `settings_customise_sources` with `YamlConfigSettingsSource` (`--config path`). Rule-specific overrides use `rule_options: dict[str, dict[str, Any]]` keyed by rule id (validated by each rule's own options model in 0.5).

**Tests:** invalid enum env → `ValidationError` at startup; invalid regex → error; env overrides defaults; unknown key → error (typos in config must not be silently ignored).

**Done when:** no module outside `config.py` contains a port number, extension list, weight or threshold (add a grep-based test: `tests/unit/test_no_hardcoding.py` scanning `ai_spm/rules` & `collectors` for port-like literals and `.pt`-style extension literals).

---

## 0.3 Domain models (`ai_spm/engine/models.py`, `engine/attrs.py`, `engine/fingerprint.py`)

**Goal:** the typed vocabulary of the whole system. Get this right; everything depends on it.

**Code (`models.py`):**

```python
from enum import StrEnum
from datetime import datetime, UTC
from pydantic import BaseModel, ConfigDict, Field

class Severity(StrEnum):
    CRITICAL="CRITICAL"; HIGH="HIGH"; MEDIUM="MEDIUM"; LOW="LOW"; INFORMATIONAL="INFORMATIONAL"
    @property
    def rank(self) -> int:            # single place that defines ordering
        return {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFORMATIONAL":0}[self.value]
    def __ge__(self, other: "Severity") -> bool: return self.rank >= other.rank

class Status(StrEnum):
    PASSED="PASSED"; FAILED="FAILED"; ERROR="ERROR"; SKIPPED="SKIPPED"

class CloudResource(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    provider: str = "aws"
    arn: str                      # globally unique id (ARN, or synthetic id for local/k8s)
    id: str; name: str
    service: str                  # D-03 token, lower-case: "s3"
    kind: str                     # discriminator of attributes: "s3_bucket"
    region: str; account_id: str
    tags: dict[str, str] = Field(default_factory=dict)
    is_ai_workload: bool = False
    ai_reason: str | None = None  # why classified AI ("tag workload=ai") - explainability
    attributes: Attrs             # discriminated union from attrs.py
    gaps: dict[str, str] = Field(default_factory=dict)   # attr -> error code (D-04/D-08)
    metadata: dict[str, Any] = Field(default_factory=dict)  # unrecognized extras only

class Finding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    rule_id: str; rule_title: str; service: str
    resource_arn: str; resource_id: str; resource_name: str; region: str
    status: Status; severity: Severity
    message: str
    remediation: str = ""           # required when status==FAILED (validator)
    evidence: dict[str, str] = Field(default_factory=dict)   # already-redacted facts
    error_code: str | None = None   # for ERROR findings
    mitre_atlas: list[str] = []; owasp_llm: list[str] = []; references: list[str] = []
    fingerprint: str                # D-12
    suppressed: bool = False; suppression_reason: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

class ScanSummary(BaseModel):
    total_resources: int; ai_resources: int
    findings: list[Finding]
    posture_score: int | None       # None if nothing evaluated
    coverage_gaps: list[CoverageGap]   # service/region/api/error_code
    started_at: datetime; finished_at: datetime
    tool_version: str; schema_version: str = "1.0"
```

A `model_validator` on `Finding` enforces: `FAILED ⇒ remediation != ""` and `ERROR ⇒ error_code or message`.

**`attrs.py`:** one typed model per resource kind, e.g.

```python
class S3BucketAttrs(BaseModel):
    kind: Literal["s3_bucket"] = "s3_bucket"
    sse_algorithm: Literal["AES256","aws:kms","aws:kms:dsse"] | None = None
    kms_key_arn: str | None = None;  kms_key_is_cmk: bool | None = None
    public_access_block: PublicAccessBlock | None = None     # None => unreadable OR absent (see gaps)
    pab_absent: bool | None = None
    is_public_by_policy: bool | None = None
    versioning: Literal["Enabled","Suspended","Disabled"] | None = None
    sampled_keys: list[str] = []
    model_extension_counts: dict[str, int] = {}
Attrs = Annotated[S3BucketAttrs | SageMakerNotebookAttrs | ..., Field(discriminator="kind")]
```

Convention: **`None` = unknown**, never "false". A rule must check `resource.gaps` / `None` before concluding FAILED.

**`fingerprint.py`:** `def fingerprint(rule_id, arn, scope="") -> str: return sha256(f"{rule_id}|{arn}|{scope}".encode()).hexdigest()[:32]` — `scope` disambiguates multi-finding-per-resource rules (e.g. which SG rule).

**Standards:** models are the *only* thing crossing layer boundaries. `frozen=True` prevents rules mutating shared resources (threads!). Add `Attrs` kinds incrementally — each collector sub-phase (2.x) adds its attrs model in the same PR.

**Tests:** round-trip `model_dump_json()/model_validate_json()`; discriminator picks the right class; `Finding(FAILED, remediation="")` raises; `Severity` ordering table-test; fingerprint stable across runs and differs per scope.

**Done when:** `mypy --strict` passes with **zero** `Any` except `metadata`.

---

## 0.4 Errors, logging, redaction

**Files:** `ai_spm/errors.py`, `ai_spm/utils/logger.py`, `ai_spm/utils/redact.py`.

**Code:**

```python
# errors.py
class AISPMError(Exception): exit_code = 2
class ConfigError(AISPMError): ...
class CredentialsError(AISPMError): ...        # no usable AWS creds -> exit 2 with a helpful message
class CollectorError(AISPMError): ...          # internal; barrier converts to CoverageGap
# redact.py
def redact(text: str, patterns: Mapping[str, Pattern[str]]) -> str:
    """Mask secret values keeping a 4-char prefix for triage: sk-proj-****"""
```

**Logger:** `RichHandler` to **stderr** (stdout is reserved for machine-readable output like `--format json` piped to `jq`!). `--verbose` = DEBUG, `--quiet` = ERROR. Add a `logging.Filter` that runs `redact()` over every record (secrets in tracebacks/boto debug logs are a classic leak). Silence `botocore`/`urllib3` at DEBUG unless `-vv`.

**Tests:** redaction catches `AKIA[0-9A-Z]{16}`, `sk-…`, `ghp_…`, `Bearer …`; logger never writes to stdout; filter masks a secret inside an exception message.

**Done when:** a test proves `--format json` stdout is valid JSON even at `--verbose`.

---

## 0.5 `BaseRule`, rule metadata, registry

**Files:** `ai_spm/rules/base.py`, `ai_spm/rules/registry.py`, `ai_spm/rules/frameworks.yaml`, `tests/unit/rules/test_registry.py`, `tests/unit/rules/test_contract.py`.

**Code (`base.py`):**

```python
class BaseRule(ABC):
    rule_id: ClassVar[str]; title: ClassVar[str]; description: ClassVar[str]
    severity: ClassVar[Severity]; service: ClassVar[str]
    resource_kinds: ClassVar[frozenset[str]]
    ai_only: ClassVar[bool] = True              # skip non-AI resources unless --all-resources
    mitre_atlas: ClassVar[tuple[str, ...]] = (); owasp_llm: ClassVar[tuple[str, ...]] = ()
    required_attrs: ClassVar[tuple[str, ...]] = ()   # runner returns ERROR if any is in resource.gaps
    def __init__(self, settings: AISPMConfig) -> None: self.settings = settings

    @abstractmethod
    def evaluate(self, resource: CloudResource) -> Finding: ...

    # helpers so rules stay 5-10 lines
    def passed(self, r: CloudResource, msg: str) -> Finding: ...
    def failed(self, r: CloudResource, msg: str, remediation: str, *, scope: str = "", evidence: dict[str,str] | None = None) -> Finding: ...
    def skipped(self, r, why) -> Finding: ...
```

`failed()` auto-fills `rule_id/title/severity/frameworks/fingerprint/region/arn` and runs `redact()` over message/evidence. Rule authors can't forget a field.

**`__init_subclass__` validation:** on class creation assert `rule_id` matches `^AI-SPM-[A-Z0-9]+-\d{3}$`, required ClassVars exist, `service` ∈ D-03 tokens → a malformed rule fails at **import**, not at runtime.

**Registry:** `discover()` = `pkgutil.walk_packages(ai_spm.rules.__path__)` (internal) + `entry_points(group="ai_spm.rules")` (external, ADR-003). Collect `BaseRule.__subclasses__()` recursively, instantiate with settings, **reject duplicate `rule_id`s** (raise at startup), apply `ignored_rules`, `--services`, `--min-severity`. `rules_for(kind)` index for O(1) dispatch.

**Framework mapping:** `frameworks.yaml` maps `rule_id → {mitre_atlas:[…], owasp_llm:[…], cis:[…], securityhub:[…]}` loaded once; ClassVars may override. One reviewable file to audit mappings (A3-11).

**Standards:** rules take no constructor args besides settings; **no** `import boto3`/`requests`/`open()` in `ai_spm/rules/**` — enforce with a test that AST-parses the package for those imports (ADR-002 verification).

**Tests:** contract test over *all discovered rules*: has remediation on every FAILED path (call with a synthetic failing fixture per rule via a `FIXTURES` registry), duplicate-id detection, bad-id rejected, AST no-I/O test, evaluate runs `< 5 ms`.

**Done when:** a demo rule `AI-SPM-DEMO-001` is discovered with no manual registration (delete it before 3.x).

---

## 0.6 Runner, scoring, suppressions & baseline

**Files:** `engine/context.py`, `engine/runner.py`, `engine/scoring.py`, `engine/suppressions.py`.

**`ScanContext` (frozen):** `account_id, partition, regions, services, min_severity, fail_on, ai_only, profile, baseline_path`.

**Runner algorithm:**

```python
def run(self, resources: Iterable[CloudResource]) -> Iterator[Finding]:
    for r in resources:
        if self.ctx.ai_only and not r.is_ai_workload: continue
        for rule in self.registry.rules_for(r.kind):
            if missing := [a for a in rule.required_attrs if a in r.gaps]:
                yield rule.error(r, code=r.gaps[missing[0]], msg=f"cannot evaluate: {missing}"); continue
            try:
                yield rule.evaluate(r)
            except Exception as exc:   # noqa: BLE001 - barrier by design (ADR-006)
                log.exception("rule crashed"); yield rule.error(r, code=type(exc).__name__, msg=str(exc))
```

Streaming generator = bounded memory (architecture §4). Findings then pass through `suppressions.apply()`.

**Scoring (`scoring.py`):**

```python
def posture_score(findings, weights) -> int | None:
    ev = [f for f in findings if f.status in (Status.PASSED, Status.FAILED) and not f.suppressed]
    if not ev: return None           # "nothing evaluated" is NOT 100
    num = sum(weights[f.severity] for f in ev if f.status is Status.PASSED)
    den = sum(weights[f.severity] for f in ev)
    return 100 if den == 0 else round(100 * num / den)
```

(ADR-007 had `return 100` for empty — returning 100 on an unscanned account is a false-assurance bug.)

**Suppressions / baseline (`.tensorguard.yaml` section or `--baseline file.json`):**

```yaml
suppressions:
  - rule_id: AI-SPM-S3-003
    resource: "arn:aws:s3:::scratch-datasets-*"    # fnmatch on ARN
    reason: "ephemeral scratch data"
    expires: 2027-03-01                             # REQUIRED; expired suppressions re-surface + warn
    owner: "corvo"
```

Suppressed findings stay in output (`suppressed=true`) but don't count to exit code or score. Baseline file = list of accepted fingerprints (`tensorguard baseline create`), so CI fails only on **new** findings.

**Tests:** crashing rule → one ERROR finding, scan continues; gaps → ERROR not FAILED; empty → score `None`; weights edge cases; expired suppression re-surfaces; glob matching; baseline hides old, shows new.

**Done when:** a 10k-synthetic-resource run stays < 250 MB RSS (measure with `tracemalloc` in a marked slow test).

---

## 0.7 CI, pre-commit, release hygiene

**Files:** `.github/workflows/ci.yml`, `.pre-commit-config.yaml`, `.github/dependabot.yml`, `CODEOWNERS`.

**CI jobs:** `lint` (ruff check + format) · `types` (mypy) · `test` (matrix 3.12/3.13, `--cov-fail-under=85`) · `audit` (`pip-audit`, `uv lock --check`) · sockets disabled everywhere. Pin third-party actions **by commit SHA**; `permissions: contents: read` at workflow top; never expose secrets to PR workflows from forks.

**Pre-commit:** ruff, ruff-format, mypy (local hook), `detect-secrets`, conventional-commit message check.

**Done when:** a deliberately broken commit (type error) is rejected locally *and* in CI. **Phase 0 exit gate:** demo rule + synthetic resource → runner → findings → score, all under test, zero AWS.

---

# PHASE 1 — Local AI Scanner (`tensorguard scan --local`)

> Zero cloud credentials. Hostile input is the norm here (you are parsing files an attacker may have crafted), so **every parser in this phase is bounded: size limits, time limits, no execution, no extraction to disk.**

## 1.1 Local resource kinds & attrs

**Files:** `engine/attrs.py` (extend), `collectors/local/models.py`.

**Code:**

```python
class LocalModelFileAttrs(BaseModel):
    kind: Literal["local_model_file"] = "local_model_file"
    path: str; size_bytes: int; sha256: str | None = None      # hash streamed, chunked
    format: Literal["pickle","torch_zip","safetensors","gguf","onnx","keras_h5","unknown"]
    pickle_hits: list[PickleHit] = []        # module, callable, opcode, offset, severity_hint
    scan_error: str | None = None            # parse failure / limit exceeded
    zip_ratio_exceeded: bool = False
    safetensors_header_ok: bool | None = None
class McpServerAttrs(BaseModel):
    kind: Literal["mcp_server"] = "mcp_server"
    config_path: str; server_name: str; runner: Literal["npx","uvx","docker","node","python","binary","remote"]
    command: str; args: list[str]; url: str | None
    pinned: bool; definition_sha256: str; lock_state: Literal["match","drift","new","no_lock"]
    env_secret_keys: list[str] = []            # key NAMES only, never values
    hidden_unicode: list[str] = []             # "U+E0041 at args[2]"
    suspicious_blobs: list[str] = []
class SecretHitAttrs(BaseModel):
    kind: Literal["secret_hit"] = "secret_hit"
    path: str; line: int; pattern_name: str; redacted_preview: str   # "sk-proj-****"
```

Synthetic ARN scheme: `local://file/<sha1(abs_path)>`, `local://mcp/<sha1(config_path+server)>`; `provider="local"`, `region="local"`, `account_id="local"`; `is_ai_workload=True` always (the whole local mode is AI-scoped).

**Standards:** the raw secret value **never** exists in any attrs model — redact in the collector, before the model is built. A test asserts `model_dump_json()` of a hit never contains the planted secret.

**Done when:** models validate, `mypy --strict` clean, round-trip tests pass.

---

## 1.2 Safe pickle opcode scanner (`ai_spm/scanners/pickle_scanner.py`)

**Goal:** decide *statically* whether a pickle can import dangerous callables, without ever deserializing (ADR-004).

**Algorithm:** stream `pickletools.genops()`; track string pushes + memo so `STACK_GLOBAL` (protocol 4+) can resolve `(module, name)`; flag `GLOBAL`/`INST`/`STACK_GLOBAL` targets against config.

**Code:**

```python
_STRING_PUSH = {"SHORT_BINUNICODE","BINUNICODE","BINUNICODE8","UNICODE","STRING","BINSTRING","SHORT_BINSTRING"}

def scan_pickle_stream(fp: IO[bytes], cfg: AISPMConfig, *, max_ops: int = 5_000_000) -> PickleScanResult:
    strings: list[str] = []; memo: dict[int, str] = {}; hits: list[PickleHit] = []
    try:
        for n, (op, arg, pos) in enumerate(pickletools.genops(fp)):
            if n > max_ops: return PickleScanResult(hits, error="max_ops_exceeded")
            name = op.name
            if name in _STRING_PUSH and isinstance(arg, str):
                strings.append(arg); del strings[:-8]
            elif name == "MEMOIZE":
                memo[len(memo)] = strings[-1] if strings else ""
            elif name in ("BINPUT", "LONG_BINPUT"):
                memo[int(arg)] = strings[-1] if strings else ""
            elif name in ("BINGET", "LONG_BINGET", "GET"):
                strings.append(memo.get(int(arg), "")); del strings[:-8]
            elif name in ("GLOBAL", "INST"):
                mod, _, attr = str(arg).partition(" ");  _classify(mod, attr, name, pos, cfg, hits)
            elif name == "STACK_GLOBAL" and len(strings) >= 2:
                _classify(strings[-2], strings[-1], name, pos, cfg, hits)
    except (ValueError, EOFError, pickle.UnpicklingError, IndexError, KeyError) as exc:
        # Truncated/obfuscated pickles are themselves a signal: report, don't crash.
        return PickleScanResult(hits, error=f"parse_error:{type(exc).__name__}")
    return PickleScanResult(hits)

def _classify(mod, attr, op, pos, cfg, hits):
    root = mod.split(".")[0]
    if (mod, attr) in cfg.allowed_pickle_globals: return        # e.g. torch._utils._rebuild_tensor_v2
    sev = ("CRITICAL" if root in cfg.dangerous_pickle_modules or attr in cfg.dangerous_pickle_callables
           else "MEDIUM")                                      # unknown global: not proven bad
    hits.append(PickleHit(module=mod, callable=attr, opcode=op, offset=pos, severity_hint=sev))
```

**Containers (`scan_model_file(path) -> LocalModelFileAttrs`):**

1. Sniff **magic bytes, not extension** (`PK\x03\x04` → zip; `\x80\x02`–`\x80\x05` → raw pickle; `GGUF`; HDF5 `\x89HDF`; safetensors = u64 length + `{`).
2. **Zip (`torch_zip`):** `zipfile.ZipFile` → for each member ending `.pkl`/`data.pkl`: check `info.file_size ≤ cfg.max_zip_uncompressed_bytes` and compression ratio `file_size / max(compress_size,1) ≤ cfg.max_zip_ratio` (new config key, default 200) **before** opening; stream via a `LimitedReader` that raises past the cap. Never `extract*()`; flag member names with `..` or absolute paths (you never write to disk, but they indicate a crafted archive).
3. **Raw pickle:** stream the file directly.
4. Hash with chunked `hashlib.sha256` (feeds AIBOM in 7.x).
5. Time budget per file via `cfg.per_file_timeout_s` (check elapsed between opcodes).

**Config additions (0.2):** `allowed_pickle_globals: frozenset[tuple[str,str]]` (seed: `torch._utils._rebuild_tensor_v2`, `torch.FloatStorage`, `collections.OrderedDict`, `torch._utils._rebuild_parameter`… — build the list by scanning a few known-clean public checkpoints and reviewing manually), `max_zip_ratio`, `per_file_timeout_s`, `max_pickle_ops`.

**Honest limitation (document in README):** static opcode scanning has known bypass classes (e.g. getattr-chains via allowed modules, nested/encoded payloads). It is *defense in depth*, not proof of safety; "clean" means *no known-dangerous imports found*. Prefer `.safetensors`. Finding text must say this.

**Tests:** build test pickles from raw opcode bytes (never `pickle.loads` them); STACK\_GLOBAL with memoized strings; protocol 0–5 coverage; truncated stream → `error`, not exception; zip containing a flagged `data.pkl`; zip bomb (`max_zip_ratio` lowered in the test); benign torch-style fixture → zero hits; `hypothesis` random bytes never raise.

**Done when:** a test proves `pickle.loads`/`torch.load` are never called (monkeypatch both to raise).

---

## 1.3 Local model collector (`collectors/local/models.py`)

**Files:** `collectors/local/__init__.py`, `collectors/local/models.py`, `collectors/base.py` (generic `BaseCollector` Protocol).

**Behavior:** `LocalModelCollector.collect(ctx) -> Iterator[CloudResource]` walks `--path` (default `.`), plus `~/.cache/huggingface/hub` when `--include-hf-cache`; matches `cfg.insecure_model_extensions + safe_model_extensions`; also detects model files by magic bytes if the extension is missing. Iterative `os.scandir` walk (no recursion limit), **don't follow symlinks** (a symlink to `/etc` or a loop is an attack/accident), skip `.git`, `node_modules`, `.venv`, respect `--exclude` globs, cap total files (`cfg.max_local_files`).

**Standards:** per-file errors (`PermissionError`, `OSError`) become `gaps["scan"] = "PermissionError"` on that resource, not exceptions. Use `ThreadPoolExecutor(cfg.max_workers)` — hashing is I/O bound.

**Safetensors check:** read the 8-byte header length `N`; require `N ≤ cfg.max_safetensors_header` (default 100 MB) and `N + 8 ≤ file_size`; `json.loads` the header; verify every tensor's `data_offsets` are ordered and within `file_size - 8 - N`. Sets `safetensors_header_ok`.

**Tests:** `tmp_path` trees with a symlink loop, an unreadable file (skip on Windows), extension-less pickle, 0-byte file, absurd header length.

**Done when:** scanning a 5k-file synthetic tree meets a recorded baseline (store in `tests/perf/`).

---

## 1.4 Local MCP manifest auditor (`collectors/local/mcp.py`)

**Goal:** static audit of MCP configs — *never launch or connect to a server* (ADR-005).

**Config discovery:** `cfg.local_mcp_paths` (via `Path.expanduser`) + workspace `./.mcp.json`, `./.cursor/mcp.json`, `./.vscode/mcp.json`. Parse with `json.loads` under a 5 MB limit; accept both `mcpServers` (Cursor/Claude Desktop) and `servers` (VS Code) keys. Invalid JSON → a resource with `gaps["parse"]`.

**Per-server derivation:**

```python
runner = classify_runner(command, args)            # npx | uvx | docker | node | python | binary | remote
pinned = {
  "npx":   any(re.search(r"@\d+\.\d+\.\d+", a) for a in args if not a.startswith("-")),
  "uvx":   any(re.search(r"(==|@)\S+", a) for a in args),
  "docker": all(":latest" not in a and ("@sha256:" in a or re.search(r":\d", a)) for a in image_args),
}.get(runner, True)
definition_sha256 = sha256(json.dumps(server_def, sort_keys=True, separators=(",",":")).encode()).hexdigest()
```

**Checks (each becomes an attr; rules in 1.6):**

- **Unpinned runners:** `npx -y pkg` with no version; `uvx pkg`; docker `:latest`/no digest.
- **Plaintext secrets in `env`:** literal values matching `cfg.secret_patterns` **or** key names matching `(?i)(api[_-]?key|token|secret|password)` whose value isn't a `${VAR}`/`$VAR` reference. Store key *names* only.
- **Hidden Unicode / smuggling:** scan every string (name, args, env values) for Unicode **tag characters U+E0000–U+E007F**, zero-width (U+200B–200F, U+2060, U+FEFF), bidi overrides (U+202A–202E, U+2066–2069), and long Base64 runs (`[A-Za-z0-9+/]{80,}={0,2}`) that decode to printable text containing phrases from `cfg.injection_markers`.
- **Transport:** remote `url` using `http://` (non-TLS), or non-loopback binding for local servers.
- **Shell-pipe launchers:** `sh -c "curl … | sh"`, `bash -c` with remote fetch.
- **Drift:** compare `definition_sha256` against `.tensorguard-lock.json` (`{config_path: {server: sha256}}`): `match | drift | new | no_lock`. `tensorguard mcp lock` writes the lock (explicit, reviewed in git) — this is the rug-pull defense: drift means the definition changed since you approved it.

**Standards:** this is *config-level* audit only — tool descriptions live on the server and can't be read without connecting; say so in the docs, and plan an opt-in sandboxed mode later (9.x) for allow-listed servers.

**Tests:** one fixture JSON per check; tag-char payload fixture (`"".join(chr(0xE0000+ord(c)) for c in "ignore previous")`); lock match/drift/new; a 10 MB config → rejected cleanly.

**Done when:** secret *values* are provably absent from all outputs (`json`, console, SARIF) in a test.

---

## 1.5 Secrets scanner (`scanners/secrets.py`)

**Config defaults (fill `secret_patterns` in 0.2):**

```python
{"aws_access_key": r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
 "github_token": r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
 "openai_key": r"\bsk-(proj-)?[A-Za-z0-9_-]{20,}\b",
 "anthropic_key": r"\bsk-ant-[A-Za-z0-9_-]{20,}\b",
 "huggingface_token": r"\bhf_[A-Za-z0-9]{30,}\b",
 "slack_token": r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
 "google_api_key": r"\bAIza[0-9A-Za-z_-]{35}\b",
 "private_key_block": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"}
```

(Starting points only — verify each vendor's current token format before release; formats change.)

**Behavior:** scan text-ish files only (`.env*`, `.json`, `.yaml/.yml`, `.toml`, `.py`, `.ipynb` cells, `Dockerfile`, `.sh`); skip binaries via a NUL-byte sniff of the first 8 KB; per-file cap 2 MB; line-by-line regex; optional Shannon-entropy gate for generic `key=...` assignments (threshold in config). Each hit → `SecretHitAttrs` with `redacted_preview = value[:4] + "****"`. **Never** log or store the value; if you need dedupe, use `hmac(run_salt, value)`.

**Tests:** planted secrets of each kind; `.ipynb` JSON cells; a false-positive corpus (UUIDs, git SHAs, base64 images) → zero hits; secret never appears in `repr()`/logs (`caplog`).

---

## 1.6 Local rules (`rules/local.py`) — supersedes the IDs in `phases.md`

| Rule ID | Severity | Resource kind | Fails when |
| --- | --- | --- | --- |
| `AI-SPM-LOCAL-001` | CRITICAL | `local_model_file` | any `pickle_hits` with `severity_hint=CRITICAL` |
| `AI-SPM-LOCAL-002` | MEDIUM | `local_model_file` | pickle format present with unknown (non-allowlisted) globals, no CRITICAL |
| `AI-SPM-LOCAL-003` | HIGH | `local_model_file` | zip ratio/size limit exceeded or `scan_error` is a limit breach |
| `AI-SPM-LOCAL-004` | MEDIUM | `local_model_file` | `.safetensors` header invalid |
| `AI-SPM-MCP-001` | HIGH | `mcp_server` | unpinned runner (`pinned=False`) |
| `AI-SPM-MCP-002` | HIGH | `mcp_server` | `env_secret_keys` non-empty |
| `AI-SPM-MCP-003` | CRITICAL | `mcp_server` | hidden Unicode or injection-marker blob found |
| `AI-SPM-MCP-004` | HIGH | `mcp_server` | `lock_state == "drift"` (rug-pull) |
| `AI-SPM-MCP-005` | MEDIUM | `mcp_server` | non-TLS remote / pipe-to-shell launcher |
| `AI-SPM-SECRETS-001` | HIGH | `secret_hit` | always FAILED when the resource exists (the hit *is* the finding) |

**Rule shape (reference implementation — every later rule copies this):**

```python
class PickleDangerousOpcodes(BaseRule):
    rule_id = "AI-SPM-LOCAL-001"
    title = "Model file imports dangerous callables via pickle opcodes"
    description = "..."; severity = Severity.CRITICAL; service = "local"
    resource_kinds = frozenset({"local_model_file"})
    required_attrs = ("scan",)
    owasp_llm = ("LLM03:2025",); mitre_atlas = ("AML.T0010",)   # verify in frameworks.yaml

    def evaluate(self, resource: CloudResource) -> Finding:
        a = narrow(resource, LocalModelFileAttrs)          # typed helper; raises a typed error the runner turns into ERROR
        bad = [h for h in a.pickle_hits if h.severity_hint == "CRITICAL"]
        if not bad:
            return self.passed(resource, f"No dangerous pickle imports found in {resource.name}")
        top = bad[0]
        return self.failed(
            resource,
            f"{resource.name} imports {top.module}.{top.callable} via {top.opcode} at byte {top.offset}",
            remediation=(f"Do not load {a.path}. Re-export weights as safetensors "
                         f"(`safetensors.torch.save_file`) from a trusted source, or verify provenance and hash."),
            evidence={"module": top.module, "callable": top.callable, "hits": str(len(bad))},
            scope=f"{top.module}.{top.callable}")
```

**Rule multiplicity decision:** `evaluate` returns **one** `Finding`; multiple hits aggregate into `evidence` + a count. This keeps fingerprints stable (`scope` = worst hit).

**Tests:** the B4 table-driven pattern for each of the 10 rules; the AST no-I/O test must pass.

---

## 1.7 Minimal CLI wiring for local mode

**Files:** `ai_spm/cli.py`, `ai_spm/__main__.py`.

```python
app = typer.Typer(no_args_is_help=True, add_completion=False)

@app.command()
def scan(
    local: bool = typer.Option(False, "--local"),
    path: list[Path] = typer.Option([Path(".")], "--path"),
    fail_on: Severity | None = typer.Option(None, "--fail-on"),
    fmt: Format = typer.Option(Format.console, "--format"),
    output: Path | None = typer.Option(None, "--output"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    try: ...
    except AISPMError as e: console_err.print(f"[red]error:[/] {e}"); raise typer.Exit(e.exit_code)
```

The exit-code function lives in `engine/scoring.py` (`exit_code(findings, fail_on) -> int`) so CLI and tests share it. **A top-level `except Exception` converts anything unexpected to exit 2 with a short message and writes the traceback to the log only** — CI must never read a raw stack trace as a "pass".

**Tests:** `CliRunner` for exit 0/1/2; `--format json` stdout parses; missing `--path` dir → exit 2.

---

## 1.8 Hostile-input & fuzz suite (do not skip — this is the credibility sub-phase)

**Files:** `tests/fuzz/test_pickle_fuzz.py`, `tests/fuzz/test_mcp_fuzz.py`, `tests/fuzz/test_safetensors_fuzz.py`.

- `hypothesis` `binary()` → `scan_pickle_stream` never raises and returns within the op/time budget.
- Mutational fuzz: take a valid torch zip, flip random bytes → scanner returns a result/error, never raises.
- `hypothesis` JSON strategies for MCP configs (deep nesting, huge strings, non-list `args`) → auditor degrades to `gaps`, never raises. Cap JSON depth (reject > 64).
- Resource-exhaustion tests: zip bomb, 1M-op pickle, giant safetensors header → bounded memory/time.

**Phase 1 exit gate:** `tensorguard scan --local --path tests/fixtures/malicious` → exit 1 with expected findings; `--path tests/fixtures/clean` → exit 0; no network; full gate green.

---

# PHASE 2 — Resilient AWS Collector Layer

> Principles for the whole phase: **(1) classify early, describe lazily** (don't make 8 calls per bucket for 3,000 non-AI buckets); **(2) unknown ≠ fail** (every unreadable attribute lands in `resource.gaps`); **(3) collectors never raise out of `collect()`**; **(4) every collector declares the IAM actions it needs** so the scanner's own least-privilege policy is generated, not hand-maintained.

## 2.1 Session & client factory (`collectors/aws/client.py`)

**Goal:** one place that creates boto3 clients correctly (retries, user-agent, thread-safety, partitions, assume-role).

**Code:**

```python
@dataclass(frozen=True)
class AwsIdentity:
    account_id: str; arn: str; partition: str          # "aws" | "aws-cn" | "aws-us-gov"

class AwsClientFactory:
    """Thread-safe client cache. boto3 Sessions are NOT thread-safe to create clients from; clients are."""
    def __init__(self, session: boto3.Session, cfg: AISPMConfig) -> None:
        self._session, self._lock, self._cache = session, threading.Lock(), {}
        self._boto_cfg = BotoConfig(
            retries={"max_attempts": cfg.boto_max_attempts, "mode": "adaptive"},
            user_agent_extra=f"TensorGuard/{__version__}",
            connect_timeout=cfg.boto_connect_timeout_s, read_timeout=cfg.boto_read_timeout_s,
            max_pool_connections=cfg.max_workers * 2)
    def client(self, service: str, region: str | None = None) -> Any:
        key = (service, region)
        with self._lock:
            if key not in self._cache:
                self._cache[key] = self._session.client(service, region_name=region, config=self._boto_cfg)
            return self._cache[key]

def resolve_identity(factory) -> AwsIdentity: ...      # sts.get_caller_identity -> parse partition from ARN
def resolve_regions(factory, requested: list[str] | Literal["all"], service: str) -> list[str]: ...
```

**Details that matter:**

- **Credentials:** `boto3.Session(profile_name=...)`; environment, shared config, SSO, IMDS, web-identity all work via the default chain. For `--role-arn` use `botocore` `AssumeRoleCredentialFetcher` wrapped in `DeferredRefreshableCredentials` so credentials **refresh during long scans** (a plain one-shot `assume_role` expires at 1h and breaks big scans). Support `--external-id`.
- **No creds found** → `CredentialsError` (exit 2) with an actionable message ("set AWS\_PROFILE or run `aws sso login`"), *not* a boto traceback.
- **Regions:** `--regions all` → `ec2:DescribeRegions` (enabled regions only; opt-in regions disabled in the account fail with `OptInRequired`/`AuthFailure`). Fallback when DescribeRegions is denied: `session.get_available_regions(service, partition_name=...)`. **Always intersect with the regions each service is actually offered in** (`get_available_regions("bedrock")`) so unsupported regions are silently skipped, not reported as errors.
- **Partition-aware ARNs** via `utils/aws_arn.py` (`build_arn(partition, service, region, account, resource)`), never hand-concatenated `arn:aws:` strings (breaks GovCloud/China).
- **Timeouts** are mandatory (a hung connection must not hang CI).

**Standards:** no module-level boto3 clients; the factory is injected (this is what makes `moto`/`Stubber` testing trivial).

**Tests:** `moto` STS identity; partition parsing from `arn:aws-us-gov:...`; user-agent present (inspect `client.meta.config.user_agent_extra`); `max_attempts`/`mode` set; credential-less env → `CredentialsError`; concurrent `client()` calls return one cached instance.

**Done when:** nothing outside `client.py` imports `boto3`/`botocore.config` (AST test, with `collectors/aws/*` allowed to import `botocore.exceptions` only).

---

## 2.2 `BaseCollector`: pagination, error barrier, gaps (`collectors/aws/base.py`)

**Goal:** the shared machinery that makes each service collector \~100 lines and uniformly resilient (ADR-006).

**Error classification table (`classify_client_error(exc) -> ErrorKind`):**

| Kind | AWS error codes (non-exhaustive — verify) | Handling |
| --- | --- | --- |
| `DENIED` | `AccessDenied`, `AccessDeniedException`, `UnauthorizedOperation`, `AuthorizationError`, `AuthFailure`, HTTP 403 | `gaps[attr]="AccessDenied"`, one warning per (service,api) |
| `THROTTLED` | `Throttling`, `ThrottlingException`, `RequestLimitExceeded`, `TooManyRequestsException`, `SlowDown` after adaptive retries exhausted | `gaps[attr]="Throttled"` + coverage gap |
| `GONE` | `NoSuchBucket`, `ResourceNotFoundException`, `NoSuchEntity`, `NotFoundException` | resource deleted mid-scan → drop it, log DEBUG |
| `ABSENT` | per-call allow-list: `NoSuchPublicAccessBlockConfiguration`, `ServerSideEncryptionConfigurationNotFoundError`, `NoSuchBucketPolicy`, `NoSuchTagSet`, `RepositoryPolicyNotFoundException` | **value is "not configured"** (a legitimate answer, not an error) |
| `REGION_UNAVAILABLE` | `OptInRequired`, `UnrecognizedClientException`/`InvalidClientTokenId` (disabled region), `EndpointConnectionError`, `UnknownServiceError` | skip the (service,region), INFO log |
| `OTHER` | anything else | `gaps[attr]=<code>`, WARNING with code, continue |

**Code:**

```python
ABSENT = object()   # sentinel: "API says: not configured"

class BaseCollector(ABC):
    service: ClassVar[str]                       # "s3"
    required_actions: ClassVar[tuple[str, ...]]  # exact IAM action names (NOT API method names!)
    scope: ClassVar[Literal["regional", "global"]] = "regional"

    def __init__(self, factory: AwsClientFactory, cfg: AISPMConfig, identity: AwsIdentity) -> None: ...
    @abstractmethod
    def collect(self, region: str | None) -> Iterator[CloudResource]: ...

    def paginate(self, client, method: str, result_key: str, **kw) -> Iterator[Mapping[str, Any]]:
        if client.can_paginate(method):
            for page in client.get_paginator(method).paginate(**kw): yield from page.get(result_key, [])
            return
        token_in, token_out = self._token_names(method)          # NextToken/Marker/ContinuationToken per API
        while True:
            resp = getattr(client, method)(**kw, **({token_in: token} if token else {}))
            yield from resp.get(result_key, [])
            if not (token := resp.get(token_out)): return

    def call(self, gaps: dict[str, str], attr: str, fn: Callable[..., T], /, *args, absent: frozenset[str] = frozenset(), **kw) -> T | None | object:
        """Run one API call inside the barrier. Returns value, ABSENT (if error code in `absent`), or None (+ gaps[attr])."""
        try: return fn(*args, **kw)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in absent: return ABSENT
            kind = classify_client_error(e)
            if kind is ErrorKind.GONE: raise ResourceGone from e
            gaps[attr] = "AccessDenied" if kind is ErrorKind.DENIED else code
            self._note_gap(kind, attr, code); return None
        except (BotoCoreError, TimeoutError) as e:
            gaps[attr] = type(e).__name__; return None
```

`collect()` of every collector is wrapped by `safe_collect()` in the orchestrator: an *unexpected* exception becomes one `CoverageGap(service, region, error_code=type(exc).__name__)` and the scan continues — but unexpected exceptions also log a full traceback (they mean a collector bug).

**`required_actions` + generated IAM policy:** `scripts/gen_iam_policy.py` imports all collectors, unions `required_actions`, writes `docs/iam-policy.json` (ReadOnly, `Resource:"*"` where the API doesn't support resource-level permissions). A unit test asserts the checked-in file equals the generated one → you can't add an API call without declaring its permission. **Gotcha: IAM action names ≠ API method names** (e.g. `get_bucket_encryption` needs `s3:GetEncryptionConfiguration`; OpenSearch's prefix is `es:`; Bedrock agent calls use `bedrock:`). Check each against the AWS *Service Authorization Reference*.

**Tests:** paginator + manual-token fallback; **150-item pagination** (create >100 items, assert all collected — the classic single-page bug); each `ErrorKind` mapping via `Stubber.add_client_error`; `ABSENT` passthrough; `ResourceGone` drops resource; `gen_iam_policy` drift test.

**Done when:** a **blanket-deny contract test** passes for every registered collector (`Stubber`/patched client raising `AccessDenied` on *every* call → `collect()` yields only resources-with-gaps or nothing, never raises).

---

## 2.3 AI workload classification (`collectors/aws/classify.py`)

**Goal:** decide `is_ai_workload` + `ai_reason` deterministically and explainably.

```python
def classify(service: str, name: str, tags: Mapping[str, str], cfg: AISPMConfig, *, extra_signals: Sequence[str] = ()) -> tuple[bool, str | None]:
    for key, wanted in cfg.ai_workload_tags.items():            # 1) tags win (explicit intent)
        if (v := _tag(tags, key)) is not None and v.lower() in wanted: return True, f"tag {key}={v}"
    if service in cfg.ai_inherent_services: return True, f"service {service} is AI by nature"   # sagemaker, bedrock
    for pat in cfg.compiled_name_patterns(service):            # 2) name heuristics (precompiled once)
        if pat.search(name): return True, f"name matches /{pat.pattern}/"
    return (True, extra_signals[0]) if extra_signals else (False, None)  # 3) content signals (e.g. model files in bucket)
```

- Tag **keys** matched case-insensitively; also honor an explicit opt-out tag `tensorguard:ignore=true` and explicit opt-in `tensorguard:ai=true` (config-named).
- `--all-resources` bypasses AI-only filtering at the runner level (classification still computed for reporting).
- Name patterns use word-boundary-aware regexes (`\bmodel\b`, not `model` — "remodel-invoices" shouldn't match).

**Tests:** table of (service, name, tags) → (bool, reason); opt-in/opt-out tags; case-insensitivity; `ai_reason` always populated when True; no ReDoS (`hypothesis` text vs patterns with a timeout).

---

## 2.4 S3 collector (`collectors/aws/s3.py`) — the template for the others

**Flow (per account; S3 is `scope="global"`):**

1. `list_buckets` (paginated; newer API returns `BucketRegion` — use it, else `get_bucket_location`; `None`/`""` → `us-east-1`; `EU` → `eu-west-1`).
2. **Tags first** (`get_bucket_tagging`, `NoSuchTagSet` → `{}`) → `classify()`.
3. If `ctx.ai_only` and not AI by tag/name → **stop** (yield nothing, or a light resource if `--all-resources`).
4. Deep describe with a client **in the bucket's region**: `get_bucket_encryption` (absent code → no config), if `aws:kms`: `kms.describe_key` to set `kms_key_is_cmk` (`KeyManager=="CUSTOMER"`; alias/ARN/ID forms all accepted; no `KMSMasterKeyID` with `aws:kms` ⇒ AWS-managed `aws/s3`); `get_public_access_block` (absent ⇒ `pab_absent=True`); account-level `s3control.get_public_access_block(AccountId=...)` **once per scan, cached**; `get_bucket_policy_status` (`NoSuchBucketPolicy` ⇒ `is_public_by_policy=False`); `get_bucket_versioning` (missing `Status` ⇒ `"Disabled"`); `list_objects_v2(MaxKeys=cfg.s3_key_sample_size)` **only for AI buckets** → `sampled_keys`, `model_extension_counts` (extension matching case-insensitive, via config lists).
5. Post-sample classification: if still non-AI but model-like files found → `classify(..., extra_signals=["contains model files"])`.
6. Build `CloudResource(kind="s3_bucket", arn=f"arn:{partition}:s3:::{name}", region=bucket_region, attributes=S3BucketAttrs(...), gaps=gaps)`.

**Standards:** never download object bodies; never `list_objects_v2` more than one page for sampling (cost + privacy); respect `--exclude-buckets` globs. S3 request cost: log the total API calls made at the end of a scan (`ScanSummary.api_calls`) so users can see what the scan cost them.

**Tests (moto):** KMS-CMK bucket, SSE-S3 bucket, no-PAB bucket, public-policy bucket, versioned/unversioned, bucket with `.pt` and `.safetensors`, cross-region bucket (client region routing), **non-AI bucket skipped with zero deep calls** (assert on moto's call log/Stubber), AccessDenied on encryption only → resource emitted with `gaps["encryption"]`.

---

## 2.5 SageMaker collector (`collectors/aws/sagemaker.py`)

**Kinds & calls (all regional):**

- `sagemaker_notebook`: `list_notebook_instances` → `describe_notebook_instance` (`DirectInternetAccess`, `RootAccess`, `SubnetId`, `SecurityGroups`, `KmsKeyId`, `RoleArn`, `InstanceMetadataServiceConfiguration.MinimumInstanceMetadataServiceVersion`) + `list_tags` (needs ARN).
- `sagemaker_endpoint_config`: `list_endpoint_configs` → `describe_endpoint_config` (`KmsKeyId`, `DataCaptureConfig.KmsKeyId`, `ProductionVariants[].InstanceType`, `ExecutionRoleArn`); link live `sagemaker_endpoint` via `list_endpoints`/`describe_endpoint` (so you can tell which configs are *in use*).
- `sagemaker_training_job`: `list_training_jobs(CreationTimeAfter=now-cfg.sagemaker_training_lookback_days)` capped at `cfg.max_training_jobs` (jobs can number in the tens of thousands — scanning all history is a perf and noise trap) → `describe_training_job` (`EnableNetworkIsolation`, `VpcConfig`, `AlgorithmSpecification.TrainingImage`, `RoleArn`, `EnableInterContainerTrafficEncryption`, `OutputDataConfig.KmsKeyId`).
- `sagemaker_model`: `list_models` → `describe_model` (`EnableNetworkIsolation`, `VpcConfig`, `ExecutionRoleArn`).
- `sagemaker_domain`: `list_domains` → `describe_domain` (`AppNetworkAccessType` = `PublicInternetOnly`|`VpcOnly`, `KmsKeyId`, `SubnetIds`).

**"Third-party container" for SAGEMAKER-005:** compare the image's registry account (`<acct>.dkr.ecr.<region>.amazonaws.com`) against `cfg.aws_owned_ecr_account_ids` (config, not code — e.g. the Deep Learning Containers registry; **look up the current list, don't trust memory**). Store `image_is_aws_owned: bool | None`.

**New rules this enables (added in 3.x):** `SAGEMAKER-006` domain `PublicInternetOnly`; `SAGEMAKER-007` notebook IMDSv1 allowed (`MinimumInstanceMetadataServiceVersion == "1"`); `SAGEMAKER-008` model/training job without VPC config.

**Tests (moto + Stubber):** moto covers notebooks/endpoint configs/training jobs well; use `Stubber` for domains if moto lacks fields. Include: >100 notebooks (pagination), lookback filter honored, tag-less notebook (service-inherent AI), `AccessDenied` on `ListTags` only.

---

## 2.6 Bedrock collector (`collectors/aws/bedrock.py`)

**Clients:** `bedrock` (control plane) and `bedrock-agent`. **Region reality:** Bedrock/Agents aren't in every region → `REGION_UNAVAILABLE` → skip silently.

- `bedrock_account_config` (one synthetic resource per region): `bedrock.get_model_invocation_logging_configuration()` → `loggingConfig` absent/empty ⇒ `logging_enabled=False`; else `cloudwatch_enabled`, `s3_enabled`, `s3_bucket`, `log_group`, text/image/embedding data delivery flags.
- `bedrock_guardrail`: `list_guardrails` → `get_guardrail` (`status`, `kmsKeyArn`, which filter policies are configured).
- `bedrock_custom_model`: `list_custom_models` → `get_custom_model` (`modelKmsKeyArn`, `trainingDataConfig`, `outputDataConfig`).
- `bedrock_agent`: `list_agents` → `get_agent` (`guardrailConfiguration{guardrailIdentifier, guardrailVersion}`, `agentResourceRoleArn`, `customerEncryptionKeyArn`, `agentStatus`) → resolve the guardrail ID against collected guardrails to learn if it is `READY`.
- `bedrock_kb` + `bedrock_data_source`: `list_knowledge_bases` → `get_knowledge_base` (`roleArn`, `storageConfiguration.type` + the vector store ARN — **this links KB → OpenSearch collection/domain**, enabling 9.x attack-path analysis) → `list_data_sources` → `get_data_source` (`serverSideEncryptionConfiguration.kmsKeyArn`).
- Tags via `list_tags_for_resource`.

**Standards:** all Bedrock resources are AI by service (`classify` inherent). Normalize camelCase API keys to snake\_case in attrs. Guardrail/agent cross-references happen in the **orchestrator's post-pass** (collectors stay stateless) — see 2.11.

**Tests:** Stubber fixtures (moto's Bedrock coverage is partial — hand-written response fixtures live in `tests/fixtures/aws/bedrock/*.json`, copied from real redacted API responses); logging config absent; agent with guardrail pointing to a missing guardrail → `gaps`; region without Bedrock → no error.

---

## 2.7 ECR collector (`collectors/aws/ecr.py`)

- `describe_repositories` (paginated) → `scanOnPush`, `imageTagMutability` (record the raw string), `encryptionConfiguration{encryptionType,kmsKey}`; `list_tags_for_resource(resourceArn=...)`; `get_repository_policy` (`RepositoryPolicyNotFoundException` ⇒ ABSENT) → flag principal `"*"` without conditions as `policy_allows_public`.
- **Once per region:** `get_registry_scanning_configuration` → `scan_type` (`BASIC`|`ENHANCED`), so rules know whether repo-level `scanOnPush` is moot (A3-5).
- Classification: name patterns from config (`ecr` list) + tags; **skip ECR Public** (different API: `ecr-public`) and document it.

**Tests (moto):** >100 repos (pagination), enhanced-scanning registry, immutable repo, KMS-encrypted repo, public policy.

---

## 2.8 OpenSearch collector (`collectors/aws/opensearch.py`)

**Managed domains:** `opensearch.list_domain_names` (no paginator) → `describe_domains(DomainNames=<batches of 5>)` (note: batches) → attrs: `vpc_id`, `subnet_ids`, `security_group_ids`, `fgac_enabled` (`AdvancedSecurityOptions.Enabled`), `internal_user_db`, `node_to_node_encryption`, `encryption_at_rest` (+ `kms_key_id`), `enforce_https`, `tls_policy`, `access_policy` (parsed JSON; `public_principal` derived: any `Allow` statement with `Principal` `"*"`/`{"AWS":"*"}` and no `Condition`), `engine_version`; tags via `list_tags(ARN=...)`. **Serverless (`opensearchserverless`, regional):** `list_collections` (paginated) → `batch_get_collection(ids=<batches of 100>)` (`type` = `VECTORSEARCH`/`SEARCH`/`TIMESERIES`, `kmsKeyArn`); `list_security_policies(type="network")` + `get_security_policy(name, type)` → evaluate each policy's `Rules[].Resource` (`collection/<pattern>`, `fnmatch`) → per-collection `network_public: bool` (`AllowFromPublic: true` and no `SourceVPCEs` restriction); same for `encryption` policies (`AWSOwnedKey: true` ⇒ not CMK). Data-access policies (`type="data"`) → later (9.x). **Classification:** `component=vectordb`/`workload=ai` tags, name patterns, or **linked from a Bedrock KB** (post-pass sets `is_ai_workload` via the KB's vector-store ARN — resources are frozen, so the orchestrator rebuilds them with `model_copy(update=...)`).

**Tests:** moto for managed domains; Stubber for Serverless; domain with `Principal:"*"`; VPC vs public; 12 domains → 3 batches.

---

## 2.9 IAM collector (`collectors/aws/iam.py`) — `scope="global"`, two-phase

IAM is queried **only for roles referenced by discovered AI resources** (`role_arn` attrs from notebooks, endpoint configs, training jobs, models, agents, KBs) — never enumerate all roles.

- Per role: `get_role` (trust policy — boto3 returns it already URL-decoded as a dict; `PermissionsBoundary`), `list_attached_role_policies` (paginated), `list_role_policies` + `get_role_policy`, and for each managed policy `get_policy` → `get_policy_version(VersionId=DefaultVersionId)`; **cache managed policy documents by ARN** (the same AWS-managed policy is attached to many roles).
- Normalize into `IamRoleAttrs`: `statements: list[PolicyStatement(effect, actions, not_actions, resources, not_resources, has_condition)]` (always coerce string → list; handle `NotAction`/`NotResource`), `attached_managed_arns`, `trust_principals`, `trust_has_source_condition` (`aws:SourceAccount`/`aws:SourceArn`/`sts:ExternalId`), `permissions_boundary_arn`.
- Config `broad_managed_policy_arns` (e.g. `AdministratorAccess`, `AmazonSageMakerFullAccess`, `AmazonBedrockFullAccess`, `AmazonS3FullAccess`) — rule input, not code.
- Cross-account/service-linked roles: `AccessDenied` on `get_role` for roles in other accounts → gap, not error.
- IAM calls have low rate limits → per-service concurrency cap (`cfg.max_concurrency_per_service["iam"]`, default 2).

**Tests (moto IAM):** inline + attached + AWS-managed; `NotAction` statement; string-vs-list normalization; role in another account (Stubber `AccessDenied`); 120 attached policies (pagination).

---

## 2.10 EC2 security-group collector (`collectors/aws/ec2.py`) — enables the Shadow-AI rule

`describe_security_groups` (paginated) → `ec2_security_group` with normalized `ingress: list[IngressRule(protocol, from_port, to_port, cidrs_v4, cidrs_v6, source_sg_ids)]` (`protocol "-1"` ⇒ all ports). The **collector stores raw facts; the rule intersects with `cfg.shadow_ai_ports`** (config tunability stays in config; the same SG data is reused by other rules). Optional enrichment (`describe_network_interfaces` filtered by `group-id`) to mark SGs **attached vs unattached**, so exposure on an unused SG is downgraded. Classification: SG is AI-relevant only when it matches a port rule, so `is_ai_workload` is set by the rule path — simplest: always collect when `ShadowAI` is enabled and let the rule skip SGs with no AI-port exposure.

**Tests (moto EC2):** 0.0.0.0/0 on 11434, `::/0`, port range 8000–8100 including 8000, `-1` protocol, SG-to-SG reference (not world-open), IPv6-only exposure.

---

## 2.11 Orchestrator (`collectors/aws/orchestrator.py`)

**Goal:** fan out (collector × region) tasks safely, then run post-passes.

```python
class AwsOrchestrator:
    def run(self, ctx: ScanContext) -> CollectionResult: ...   # resources + coverage_gaps + api_calls
```

1. Resolve identity → regions per service (2.1).
2. Build tasks: `global` collectors once; `regional` collectors per region.
3. `ThreadPoolExecutor(cfg.max_workers)`; per-service `BoundedSemaphore` from `cfg.max_concurrency_per_service`; **per-task timeout** (`cfg.collector_timeout_s`) — on timeout record a `CoverageGap` and move on (note: threads can't be killed; the timeout is enforced by not waiting on the future and by boto's own timeouts).
4. `safe_collect` wrapper: any exception → `CoverageGap`.
5. **Post-pass A (links):** Bedrock agent→guardrail status; KB→vector store marks OpenSearch as AI; endpoint→config in-use flags.
6. **Post-pass B (IAM):** gather `role_arn`s from collected attrs → `IamCollector.collect_roles(arns)`.
7. **Determinism:** sort by `(service, region, arn)` before returning → golden tests and diffs are stable.
8. **Progress:** emit events (`task_started/finished/gap`) to an optional callback; the Rich progress bar (4.x) subscribes; core stays UI-free.
9. **Cancellation:** `KeyboardInterrupt` → stop submitting, `executor.shutdown(cancel_futures=True)`, return partial results flagged `incomplete=True` (exit code 2 unless `--allow-partial`).

**Tests:** 2 regions × 5 collectors with one collector raising `RuntimeError` → others complete, one gap; ordering determinism (shuffle completion order with `sleep` jitter); timeout path; post-pass linking (Stubber/moto combo); API-call counter.

---

## 2.12 AWS test harness & fixtures (`tests/integration/aws/`)

- `conftest.py`: `aws_env` autouse (fake creds, `AWS_DEFAULT_REGION`), `mock_aws` context, `factory` fixture building an `AwsClientFactory` on the mocked session, builders (`make_ai_bucket`, `make_notebook`, `make_domain`…).
- **Stubber helpers:** `deny(client, "get_bucket_encryption")`, `throttle(client, method, times=6)`.
- **Contract tests (parametrized over *every* collector class discovered via `BaseCollector.__subclasses__()`):** blanket-deny · blanket-throttle · empty account (yields nothing, no error) · declares `required_actions` · never calls `boto3.client(...)` directly (AST test).
- **Record-replay (optional):** a `scripts/record_fixtures.py` that you run *manually* against a sandbox account to capture **redacted** real responses into `tests/fixtures/aws/` — the only path from real AWS into tests; scrub account IDs/ARNs with `redact`.

**Phase 2 exit gate:** `tensorguard scan --regions us-east-1 --services s3,sagemaker` against `moto` server mode (or a real sandbox account) returns resources, a correct coverage-gap list under a restricted IAM role, and is deterministic across 3 runs.

---

# PHASE 3 — Complete AWS Rule Suite

> **Severity principle (new, locks D-09 further):** a rule's severity is its **intrinsic** risk in isolation. *Contextual escalation* (public + wildcard role + sensitive data) belongs to the correlation engine (9.1), not to ad-hoc `if` branches inside rules. This keeps findings explainable and stops the catalog's CRITICAL-inflation. Where the Security Hub control severity is known, align to it (verify each against the current Security Hub controls reference).

## 3.1 Rule authoring kit

**Files:** `rules/base.py` (extend), `rules/remediation.py`, `rules/frameworks.yaml` (complete), `scripts/gen_rule_docs.py`, `tests/unit/rules/fixtures.py`.

**Remediation builder (copy-paste-safe — this is a security issue, not polish):** resource names/tags are **attacker-influenceable strings** that end up in commands users paste into terminals. All interpolation goes through escapers:

```python
@dataclass(frozen=True)
class Remediation:
    summary: str
    cli: tuple[str, ...] = ()          # each already shlex-quoted
    terraform: str | None = None
    cloudformation: str | None = None
    docs_url: str | None = None
    def render(self) -> str: ...        # markdown w/ fenced blocks; plain-text variant for SARIF

def sh(v: str) -> str: return shlex.quote(v)                    # shell
def tf(v: str) -> str: return json.dumps(v)[1:-1]              # HCL string body (escapes quotes, ${ })
```

Example for S3-001: `cli=(f"aws s3api put-bucket-encryption --bucket {sh(r.name)} --server-side-encryption-configuration '{...}' --region {sh(r.region)}",)`, plus a Terraform `aws_s3_bucket_server_side_encryption_configuration` snippet with `bucket = "{tf(r.name)}"`. **Test:** a resource named `x'; rm -rf ~ #` produces remediation text where that string appears only inside quotes (`shlex.split` round-trips to the literal name).

**`narrow(resource, AttrsType)`** helper (typed, raises `AttrsMismatch` → runner converts to ERROR). **`RULE_FIXTURES`**: each rule module exports `FIXTURES: list[Case(attrs, expected_status, note)]` consumed by *both* the rule's own tests and the global contract test (0.5).

**Docs generator:** `scripts/gen_rule_docs.py` renders `docs/rules/<rule_id>.md` + `docs/rules/README.md` (the severity/framework matrix) **from the rule classes + `frameworks.yaml`**. A test fails if the checked-in docs differ from generated → the catalog's current "matrix disagrees with body" bug becomes impossible.

**Framework audit checklist (do once, record decisions in `frameworks.yaml` comments):** open the current MITRE ATLAS matrix, the **OWASP LLM Top 10 (2026 Edition)**, and the **OWASP Agentic Top 10 (2026)** (`ASI01–ASI10`) and verify every ID/title pair; prefer *no* mapping over a wrong one; add `cis:` / `securityhub:` ids only after checking the control exists and its title matches.

---

## 3.2 S3 rules (`rules/aws/s3.py`) — kind `s3_bucket`

| ID | Sev | Fails when | Unknown (`required_attrs`) |
| --- | --- | --- | --- |
| `AI-SPM-S3-001` | **MEDIUM** | default encryption is not SSE-KMS/DSSE-KMS **with a customer-managed key** (`sse_algorithm in {AES256, None}` or `kms_key_is_cmk is False`) | `encryption` (and `kms_key` if KMS) → ERROR; `kms_key_is_cmk is None` while KMS → SKIPPED w/ note |
| `AI-SPM-S3-002` | **CRITICAL** | effective public exposure: `is_public_by_policy` **or** (PAB absent/any flag off **and** account-level PAB not fully on) | `public_access` |
| `AI-SPM-S3-003` | **MEDIUM** | `versioning != "Enabled"` on buckets classified as *training data* (`data=dataset` tag, `dataset` name, or non-model objects) | `versioning` |
| `AI-SPM-S3-004` | **MEDIUM** (heuristic) | `model_extension_counts` has pickle-family extensions **and** zero `.safetensors` siblings in the sample | `sampled_keys` (sampling denied → SKIPPED) |

Notes: (1) S3-001 is **flat MEDIUM** — this supersedes the two-tier rating in D-09 because "unencrypted" can't occur anymore (A3-1). (2) S3-002 uses *effective* exposure: account-level block + bucket-level block + policy status. (3) S3-004 text must say "heuristic based on key names in a sample of N objects; run `scan --local` on the artifacts for proof". (4) Add `AI-SPM-S3-005` (**LOW**): bucket policy lacks a `aws:SecureTransport` deny — requires collecting the policy document (`get_bucket_policy`), parse once.

**Reference rule:**

```python
class ModelBucketNoCmk(BaseRule):
    rule_id = "AI-SPM-S3-001"; severity = Severity.MEDIUM; service = "s3"
    title = "AI bucket default encryption is not SSE-KMS with a customer-managed key"
    resource_kinds = frozenset({"s3_bucket"}); required_attrs = ("encryption",)
    def evaluate(self, r):
        a = narrow(r, S3BucketAttrs)
        if a.sse_algorithm in ("aws:kms", "aws:kms:dsse") and a.kms_key_is_cmk:
            return self.passed(r, f"{r.name} uses a customer-managed KMS key")
        if a.sse_algorithm in ("aws:kms", "aws:kms:dsse") and a.kms_key_is_cmk is None:
            return self.skipped(r, "KMS key ownership could not be determined (kms:DescribeKey denied)")
        why = "SSE-S3 (AES256)" if a.sse_algorithm in ("AES256", None) else "the AWS-managed aws/s3 key"
        return self.failed(r, f"{r.name} in {r.region} encrypts with {why}", remediation=s3_cmk_fix(r).render(),
                           evidence={"sse": str(a.sse_algorithm)})
```

---

## 3.3 SageMaker rules (`rules/aws/sagemaker.py`)

| ID | Sev | Kind | Fails when |
| --- | --- | --- | --- |
| `SAGEMAKER-001` | HIGH | notebook | `DirectInternetAccess == "Enabled"` (align with Security Hub `SageMaker.1`) |
| `SAGEMAKER-002` | HIGH | notebook | no `SubnetId` (not in a customer VPC) |
| `SAGEMAKER-003` | HIGH | notebook | `RootAccess == "Enabled"` |
| `SAGEMAKER-004` | MEDIUM | endpoint config | `KmsKeyId` absent **and** instance type supports volume encryption; separately flags `DataCaptureConfig` enabled without CMK |
| `SAGEMAKER-005` | HIGH | training job | `EnableNetworkIsolation == False` **and** `image_is_aws_owned is False` (else PASSED/SKIPPED) |
| `SAGEMAKER-006` *(new)* | HIGH | domain | `AppNetworkAccessType == "PublicInternetOnly"` |
| `SAGEMAKER-007` *(new)* | MEDIUM | notebook | IMDSv1 allowed (`MinimumInstanceMetadataServiceVersion == "1"`) |
| `SAGEMAKER-008` *(new)* | MEDIUM | model / training job | no `VpcConfig` |

Notebook rules apply to `Status in {InService, Pending, Updating}` only (stopped notebooks: LOW-confidence → still report, but add `evidence["status"]`). The doc's original CRITICAL for 001 is re-rated HIGH; the 9.1 correlation engine escalates it when the notebook role is also over-privileged.

---

## 3.4 Bedrock rules (`rules/aws/bedrock.py`)

| ID | Sev | Kind | Fails when |
| --- | --- | --- | --- |
| `BEDROCK-001` | HIGH | account\_config | logging disabled, or no CloudWatch *and* no S3 destination |
| `BEDROCK-002` | HIGH | data\_source | no `kmsKeyArn` (message: "no customer-managed key configured") |
| `BEDROCK-003` | HIGH | agent | no `guardrailIdentifier`, **or** referenced guardrail not `READY` / not found |
| `BEDROCK-004` *(new)* | MEDIUM | custom\_model | no `modelKmsKeyArn` |
| `BEDROCK-005` *(new)* | MEDIUM | agent | no `customerEncryptionKeyArn` (session/memory data) |

`BEDROCK-001` caveat: logging configuration is per region — emit one synthetic `bedrock_account_config` per scanned region **where Bedrock is available and the account has used it** (don't fail regions with no Bedrock usage; use presence of any model access/agent/guardrail as the usage signal, else SKIPPED).

---

## 3.5 ECR rules (`rules/aws/ecr.py`)

| ID | Sev | Fails when |
| --- | --- | --- |
| `ECR-001` | HIGH | `scanOnPush == False` **and** registry `scan_type == BASIC` (if registry is ENHANCED → PASSED with note) |
| `ECR-002` | MEDIUM | `imageTagMutability == "MUTABLE"` |
| `ECR-003` *(new)* | HIGH | repository policy allows pull/push to `Principal:"*"` without conditions |
| `ECR-004` *(new)* | LOW | encryption type is `AES256` (not KMS) on AI repos |

---

## 3.6 OpenSearch / vector-DB rules (`rules/aws/opensearch.py`) — prefix stays `OPENSEARCH` (D-03)

| ID | Sev | Kind | Fails when |
| --- | --- | --- | --- |
| `OPENSEARCH-001` | CRITICAL | domain | no `vpc_id` (public endpoint) **and** (`public_principal` **or** FGAC disabled) — a public endpoint protected by FGAC + SigV4 is HIGH, not CRITICAL (see note) |
| `OPENSEARCH-002` | HIGH | domain | FGAC disabled |
| `OPENSEARCH-003` | HIGH | domain | node-to-node encryption disabled |
| `OPENSEARCH-004` *(new)* | CRITICAL | domain | access policy has `Allow` + `Principal:"*"` + no `Condition` |
| `OPENSEARCH-005` *(new)* | HIGH | domain | encryption at rest disabled |
| `OPENSEARCH-006` *(new)* | MEDIUM | domain | `EnforceHTTPS` false or weak TLS policy |
| `OPENSEARCH-007` *(new)* | CRITICAL | serverless collection | network policy `AllowFromPublic: true` |
| `OPENSEARCH-008` *(new)* | MEDIUM | serverless collection | encryption policy uses AWS-owned key |

*Note:* to keep "one severity per rule" while expressing the public+auth nuance, split into two rules: `001` = **public endpoint** (HIGH) and `004` = **public endpoint + open policy** (CRITICAL). Severity stays intrinsic and the pair tells the story.

---

## 3.7 IAM rules (`rules/aws/iam.py`) — kind `iam_role`

| ID | Sev | Fails when |
| --- | --- | --- |
| `IAM-001` | HIGH | an `Allow` statement grants `*` or a service-wildcard (`s3:*`, `dynamodb:*`, `iam:*`, `sts:AssumeRole`… from config `wildcard_action_services`) on `Resource:"*"` with no `Condition` |
| `IAM-002` | HIGH | role has an attached policy in `cfg.broad_managed_policy_arns` |
| `IAM-003` | MEDIUM | trust policy allows a service principal (`sagemaker.amazonaws.com`, `bedrock.amazonaws.com`) with **no** `aws:SourceAccount`/`aws:SourceArn` condition (confused deputy) |
| `IAM-004` | LOW | AI execution role has no permissions boundary (only when org config says boundaries are required: `cfg.require_permissions_boundary`) |

**Evaluation helper (`rules/aws/_policy.py`, pure):** `statement_grants(stmt, action_pattern) -> bool` using `fnmatch` on lower-cased actions; handles `NotAction`/`NotResource` conservatively (treat `NotAction` + `Allow` as *broad*); `is_wildcard_resource(stmt)`; never attempts full IAM simulation (document: this is a lint, not an authorization oracle). Property-test the helper with `hypothesis` against a small reference implementation.

Remediation must not link to local paths (A2-15) — point to AWS docs URL + show a **scoped example policy** generated from the role's actually-used services where known (stretch goal: `iam:GenerateServiceLastAccessedDetails`, 9.x).

---

## 3.8 Shadow-AI exposure rule (`rules/aws/shadow_ai.py`)

`AI-SPM-SHADOW-001` (kind `ec2_security_group`): for each `IngressRule` open to `0.0.0.0/0` or `::/0`, compute the intersection of its port range (protocol `-1` = all) with `cfg.shadow_ai_ports`. **Fails** with `evidence={"ports":"11434(ollama),8888(jupyter)"}`; `scope` = sorted port list for a stable fingerprint. Severity HIGH; document that **attached-to-instance** enrichment upgrades confidence (not severity). Tests include the port-range-contains-port, `-1`, IPv6, SG-reference-only (pass), and unattached-SG cases.

---

## 3.9 Rule QA gates (run once the suite exists)

1. **Coverage matrix test:** every `resource_kind` produced by any collector has ≥ 1 rule; every rule has fixtures for PASSED / FAILED / unknown.
2. **Remediation injection test** (3.1) across *all* rules using hostile names.
3. **Mutation testing** on `rules/` with `mutmut` (or `cosmic-ray`) — target ≥ 80% mutants killed; rules are small and pure, so this is cheap and exposes weak assertions.
4. **Severity/framework docs drift test** (3.1).
5. **Dry-run on real data:** run against a *sandbox* AWS account seeded with one compliant + one non-compliant resource per rule (Terraform in `tests/e2e/sandbox/`, applied manually; never in CI). Record expected-findings JSON as a golden.

**Phase 3 exit gate:** all rules registered by discovery only; `tensorguard rules list` prints the generated matrix; coverage ≥ 90% on `rules/`; sandbox e2e matches golden.

---

# PHASE 4 — CLI, Reporters, GitHub Action & Release

## 4.1 Full CLI (`cli.py`)

**Commands:** `scan` · `rules list|show <id>` · `baseline create` · `mcp lock` · `config show|validate` · `doctor` · `version`.

`scan` options (D-07): `--regions us-east-1,eu-west-1|all`, `--services`, `--min-severity`, `--fail-on`, `--format console|json|sarif|markdown`, `--output PATH` (repeatable: `--format json --output a.json --format sarif --output b.sarif` — emit several sinks from one scan), `--profile`, `--role-arn`, `--external-id`, `--config`, `--baseline`, `--local`, `--path`, `--ai-only/--all-resources`, `--strict-coverage`, `--allow-partial`, `--exclude-buckets`, `-v/-q`.

**Config precedence** (document + test): CLI > env `AI_SPM_*` > `--config` file > `.tensorguard.yaml` in CWD > defaults. `config show` prints the **effective** config with the source of each value.

**`doctor`:** verifies Python, credentials, identity, enabled regions, and runs a *permission probe* — one cheap call per collector (`required_actions`) — printing which collectors will have gaps and the exact missing actions. This is the highest-value UX feature for a tool that must run under restricted roles.

**Output safety:** write reports **atomically** (`tmp` + `os.replace`), mode `0600` (findings expose infrastructure layout), refuse to overwrite without `--force` when the path exists and isn't a regular file. stdout only carries the primary machine-readable report; everything else → stderr.

**Tests:** `CliRunner` matrix for every option; exit-code table (D-07); multi-sink; unknown region → exit 2; `--strict-coverage` with a gap → exit 3; `doctor` with Stubber-denied APIs.

---

## 4.2 Console reporter (`reporters/console.py`)

ADR-007 layout: `Table(expand=True)`; `no_wrap=True` on `Status`/`Severity`/`Rule ID`; `ratio` + `overflow="ellipsis"` on `Resource`/`Message`. Sections: header (account, regions, duration, tool version) → **posture score panel** (with "N resources not evaluated" when gaps) → findings grouped by severity then service → **Coverage gaps table** (service, region, API, code) → next-steps hint. Respect `NO_COLOR` and non-TTY (plain text, no spinners). Snapshot-test at widths **60/80/120** with `Console(width=..., record=True)`.

## 4.3 JSON reporter + versioned schema (`reporters/json_rep.py`)

Dump `ScanSummary.model_dump(mode="json")`; export the JSON Schema to `docs/schema/scan-summary-1.json` from `ScanSummary.model_json_schema()`; **schema policy:** additive fields = minor (same `schema_version` major), removals/renames = new major + deprecation window. Golden test + `jsonschema` validation of every produced report.

## 4.4 SARIF reporter (`reporters/sarif.py`)

- SARIF **2.1.0**; `tool.driver` = name/version/`informationUri` + one `reportingDescriptor` per rule (`id`, `name`, `shortDescription`, `fullDescription`, `help.markdown` = remediation, `defaultConfiguration.level`, `properties.tags`, `properties.security-severity`).
- `security-severity` numeric mapping from config (defaults CRITICAL 9.5, HIGH 8.0, MEDIUM 5.5, LOW 3.0, INFO 0.0) → GitHub tiers (>= 9.0 critical, 7.0–8.9 high, 4.0–6.9 medium, 0.1–3.9 low).
- **Cloud findings have no file.** GitHub requires a `physicalLocation`: map to a configurable placeholder path (`--sarif-location-root` default `.tensorguard/<provider>/<account>/<region>/<service>/<name>`) and keep the real identity in `logicalLocations[].fullyQualifiedName = ARN`. **Local findings** use real repo-relative URIs with `uriBaseId: "%SRCROOT%"` and a `region.startLine` when known.
- `partialFingerprints: {"tensorguardFingerprint/v1": finding.fingerprint}` so alerts persist across runs and don't reopen. Suppressed findings → `suppressions: [{kind: "external", justification}]`.
- Honor GitHub limits (upload size/result count): sort by severity and truncate with a notice result; log it.
- Only `PASSED` omitted; `ERROR` findings become `level: "note"` coverage notes (or go to `invocations[].toolExecutionNotifications`) so permission gaps don't open security alerts.
- **Validate** every golden SARIF against the vendored official 2.1.0 JSON schema in tests.

## 4.5 Markdown reporter (`reporters/markdown.py`)

GFM: score + counts badge line, top-N findings table, per-service `<details>` with remediation, coverage-gap section. **Escape all resource-derived strings** (names/tags are untrusted → they must not inject markdown/HTML/mentions into a PR comment: escape `|`, backticks, `<`, `@`, `[`). Hard cap **60,000 chars** (GitHub comment limit is 65,536) with a "truncated — see artifact" footer. Golden tests incl. a hostile-name fixture.

## 4.6 Rule/baseline/lock subcommands

`rules list` renders the generated matrix (Rich table or `--format json`); `rules show AI-SPM-S3-001` prints description, remediation template, frameworks, fixtures. `baseline create` writes accepted fingerprints (stable-sorted, with `created_at`, tool version, optional `--expires`); `mcp lock` writes `.tensorguard-lock.json` deterministically (sorted keys, trailing newline).

## 4.7 GitHub Action (`action.yml`) & sample workflow

Composite action: `astral-sh/setup-uv` (**pinned SHA**) → `uvx --from tensorguard==${{ inputs.version }} tensorguard scan ... --format sarif --output tg.sarif` → `github/codeql-action/upload-sarif` (pinned) → optional step-summary/PR comment (Markdown, size-capped). **Inputs:** `version` (required pin; no `latest` default — supply-chain hygiene), `regions`, `services`, `fail-on`, `baseline`, `config`, `local-path`. **AWS auth in CI = OIDC, never static keys:** document `aws-actions/configure-aws-credentials` with `role-to-assume`, and ship a sample **trust policy** (`token.actions.githubusercontent.com:aud = sts.amazonaws.com`, `:sub = repo:ORG/REPO:ref:refs/heads/main` — *scoped*, not `repo:ORG/*`) and the generated read-only `docs/iam-policy.json`. Workflow `permissions:` = `contents: read`, `security-events: write`, `id-token: write` only. **Fork PR rule:** AWS scans run only on `push`/`workflow_dispatch`/same-repo PRs; `--local` scans can run on forks (no secrets needed).

## 4.8 Packaging, release & docs

- `uv build` → `twine check` → **PyPI Trusted Publishing (OIDC)** from a tag-triggered workflow (no API tokens in secrets); version from git tag (`hatch-vcs` or `uv-dynamic-versioning`); `CHANGELOG` section must exist for the tag (CI check).
- Release artifacts: wheel + sdist + **CycloneDX SBOM of the tool itself** + Sigstore/PEP 740 attestations; `pip-audit` gate; reproducible `uv.lock`.
- Optional container image: multi-stage, non-root, `python:3.12-slim` pinned by digest, no shell entrypoint tricks.
- **README structure:** 60-second quickstart → "what it checks" (generated rule table) → required IAM permissions (generated) → CI snippet → **"Limitations & non-goals"** (static pickle scan limits, S3-004 heuristic, config-only MCP audit, IAM lint ≠ simulator) → threat model link. Honest limitations build more trust than a feature list.
- `docs/demo.tape` (Charm `vhs`) generating the README GIF from a *fixture* account (no real ARNs in public media!).
- `SECURITY.md` (private reporting channel, response SLA), `CONTRIBUTING.md` (= condensed Part B + "add a rule in 5 steps"), issue templates (false-positive report asks for rule ID + redacted attrs JSON).

## 4.9 End-to-end & golden suite

`tests/integration/cli/` runs each reporter against one canonical synthetic `ScanSummary` fixture with frozen clock → byte-compare to `tests/golden/*`. Update goldens only via `pytest --update-golden` (and review the diff — this is where multi-agent edits silently drift output).

**Phase 4 exit gate:** `pipx run tensorguard scan --local` works on a clean machine; SARIF uploads and renders in a real GitHub repo; wheel installs in a fresh venv; `doctor` correctly reports a restricted role.

---

# PHASE 5 — Kubernetes GPU Runtime Security (optional extra `k8s`)

## 5.1 K8s collector (`collectors/k8s.py`)

**Files:** `collectors/k8s.py`, `engine/attrs.py` (+`k8s_pod`, `k8s_node`, `k8s_daemonset`).

- Loads kubeconfig via `kubernetes.config.load_kube_config(context=...)` (`--kube-context`), **read-only verbs only** (`list` pods/nodes/daemonsets, `get` clusterpolicies if CRD present). Paginate with `limit`/`_continue` (the client's `list_*` with `limit=500` loop) — clusters can have 10k+ pods.
- Node attrs: GPU capacity (`nvidia.com/gpu`), labels (`nvidia.com/mig.config`, `nvidia.com/gpu.product`), driver/toolkit versions from GPU-Operator labels or the operator DaemonSet image tags.
- Pod attrs: `privileged`, `hostPath` volumes (flag `/dev/nvidia*`, `/var/run/docker.sock`), `hostNetwork`/`hostPID`, GPU `resources.limits`, image refs (digest vs tag), `runtimeClassName`, `securityContext.runAsNonRoot`.
- AI classification: GPU request, GPU node scheduling, or labels from config (`vllm`, `triton`, `torchserve`).
- Cloud-managed clusters: EKS discovery is out of scope for 5.x (use kubeconfig); the AWS collector may *list* EKS clusters later (9.x). **Standards:** never `exec` into pods, never read Secrets, never `get` ConfigMaps. RBAC for the scanner = `ClusterRole` with `list` on pods/nodes/daemonsets only (ship `docs/k8s-rbac.yaml`, generated like the IAM policy). **Tests:** `kubernetes` client objects built from fixtures (no cluster); a `kind` cluster job is an *optional* nightly CI job, not a gate.

## 5.2 K8s GPU rules (`rules/k8s_gpu.py`)

- `AI-SPM-K8S-001` (CRITICAL): NVIDIA Container Toolkit version `< 1.17.8` (parse semver from operator image tag / node label; covers **NVIDIA Security Bulletin 5659**: `CVE-2025-23266` NVIDIAScape & `CVE-2025-23267` symlink attack). Unknown version → SKIPPED, not FAILED.
- `AI-SPM-K8S-002` (MEDIUM): GPU time-slicing configured without MIG partitioning on a multi-tenant node (heuristic: >1 namespace schedules GPU pods on the node and no `mig.config` label).
- `AI-SPM-K8S-003` (HIGH): privileged pod or `hostPath` mount of `/dev/nvidia*` / container runtime socket.
- `AI-SPM-K8S-004` (MEDIUM): GPU workload image pulled by mutable tag, not digest. **Tests:** version-parse table (`1.17.7` fail, `1.17.8` pass, `v1.17.8-rc1`, garbage → SKIPPED), pod fixtures.

---

# PHASE 6 — Multi-Cloud Expansion (do ONE second cloud, not both at once)

## 6.1 Provider abstraction refactor (prerequisite)

Before any GCP/Azure code, make the engine provider-neutral **without breaking rules**: `Collector` Protocol (`provider`, `collect(ctx)`), provider registry via entry points (`ai_spm.collectors`), `ScanContext.providers`, provider-prefixed service tokens (D-03: `GCP`, `AZURE`). Contract tests from 2.12 generalize to every provider. Resist adding `if provider == ...` anywhere in engine/reporters.

## 6.2 GCP (`collectors/gcp/`, `rules/gcp.py`) — recommended second cloud if your consultancy clients use Vertex AI

Vertex AI Workbench instances (public IP, root access, CMEK), Vertex endpoints (CMEK, private endpoint / VPC peering), GCS model buckets (public access prevention, uniform bucket-level access, CMEK, versioning), VPC Service Controls perimeter coverage (read-only checks via `accesscontextmanager`). Auth via ADC; per-API `PermissionDenied` → same gap model. IAM-equivalent policy file generated the same way.

## 6.3 Azure (`collectors/azure/`, `rules/azure.py`)

Azure ML workspaces/computes (public network access, managed identity, CMK), Azure OpenAI accounts (public access, key-based auth enabled, content filter policy), Blob storage for models (public access, encryption). Auth via `DefaultAzureCredential`; throttling = HTTP 429 with `Retry-After` honoring.

**Standards:** each provider ships its own *classification config block*, `required_permissions` generator, moto-equivalent fixture strategy (recorded, redacted SDK responses), and a README "limitations" section. **Do not copy the AWS rule IDs' semantics** — equivalent controls get their own IDs.

---

# PHASE 7 — AI Supply Chain (AIBOM, provenance, RAG integrity)

## 7.1 Model/dataset inventory & provenance model

Extend attrs: `sha256` (streamed), `format`, `source` (HF repo id from cache metadata, S3 URI, git remote), `license` (from model card / `config.json` where present), `size`, `created`. Local collector reads `~/.cache/huggingface` `refs/` + `snapshots/` structure for repo id + commit hash (no network). New rules: `AI-SPM-SUPPLY-001` (model without pinned revision/hash in code/config), `-002` (model license missing/unknown), `-003` (artifact hash not in allowlist file `.tensorguard-models.lock`).

## 7.2 AIBOM reporter (`reporters/aibom.py`)

Emit **CycloneDX 1.7 ML-BOM** (released Oct 2025 / ratified as **ECMA-424 2nd Edition** Dec 2025; `machine-learning-model` + `data` components, `modelCard`, hashes, `services` for vector stores/endpoints, `dependencies` linking MCP tools → servers) and optionally **SPDX 3.0 AI profile**. Validate output with the official CycloneDX 1.7 JSON schema in tests; deterministic ordering (sort components by bom-ref) + stable `serialNumber` option for diffing. `--sbom cyclonedx|spdx`.

## 7.3 RAG canary (`scanners/rag_canary.py`) — **opt-in, write-capable: treat as a separate, dangerous mode**

Everything else in this tool is *read-only*; canary insertion **writes to a production vector DB**. Therefore: separate subcommand (`tensorguard rag canary plant|verify`), explicit `--i-understand-this-writes` flag, a *separate* IAM policy (never merged into the scan policy), canary docs tagged with a unique ID + TTL + cleanup command, dry-run default, and a documented failure mode (what if the DB is multi-tenant?). Verification = query for canary embeddings and compare hash/vector/metadata to detect tampering. Ship **last**, and consider shipping it as a separate package (`tensorguard-rag`) so the core's read-only guarantee stays intact and auditable.

---

# PHASE 8 — Hardening & Trust (new)

## 8.1 Threat-model the scanner itself (`docs/threat-model.md`)

STRIDE pass over: (a) **hostile input** (model files, MCP configs, resource names/tags) → parser bounds, no execution, escaping in all sinks; (b) **credential exposure** (read-only AWS creds in memory/logs/CI) → redaction filters, OIDC-only CI, no creds in reports; (c) **report tampering/leakage** (findings reveal topology) → `0600`, SARIF to private repos only unless user opts in; (d) **plugin/entry-point abuse** (ADR-003) → plugins are normal installed packages, `tensorguard plugins list` shows origin, `--no-plugins` flag; (e) **supply chain** of the tool → 8.3. Every threat gets a mitigation *and a test that proves it* (traceability table).

## 8.2 Performance & scale budgets

Replace the "5,000 resources < 60 s" promise with measured budgets: `tests/perf/` using `moto`-seeded accounts at 100/1k/5k resources, recording wall time, peak RSS (`tracemalloc`/`resource`), API calls per service. CI nightly compares to a stored baseline and fails on >25% regression. Optimizations to try in order: classify-early/lazy describe (2.4), per-service concurrency tuning, batching (`describe_domains`), response caching of managed policies/KMS keys, skipping unchanged resources with `--since` (9.2).

## 8.3 Supply-chain & release security

`pip-audit` + `uv lock --check` gates; Dependabot/Renovate; GitHub **OpenSSF Scorecard** workflow; dependency-review action on PRs; pinned-by-SHA actions; minimal dependency policy (every new runtime dep needs a one-line justification in the PR); SBOM + provenance attestation per release; `SECURITY.md` + a tested vulnerability-disclosure process.

## 8.4 Platform compatibility matrix (you're on Windows — this matters)

CI matrix: ubuntu/macos/windows × py3.12/3.13. Rules: all paths via `pathlib`; no hardcoded separators; `0600` perms are a no-op on Windows (document + use ACL-safe fallback); `os.replace` for atomic writes (works on Windows); test CRLF/BOM handling in config and MCP JSON parsing; `ruff`'s `PTH` rules enforce `pathlib`; never print absolute local paths into *published* artifacts (strip home dir in SARIF/Markdown unless `--include-paths`).

## 8.5 Observability

`--log-json` structured logs (timestamp, level, collector, region, api, code), `ScanSummary.api_calls` per service, `--timings` per-collector durations, `--debug-bundle` that writes a **redacted** diagnostics zip for bug reports (config effective-values, versions, coverage gaps; no resource data).

## 8.6 Docs site

MkDocs Material: quickstart, rule reference (generated), IAM permissions (generated), CI recipes, threat model, plugin guide, FAQ ("why did I get ERROR findings?" → permission gaps). Docs build is a CI job (broken links fail).

## 8.7 Continuous fuzzing & mutation

Nightly CI: extended `hypothesis` profile (`max_examples=10_000`) for the pickle/MCP/safetensors/policy parsers; weekly `mutmut` on `rules/` and `engine/`; corpus of regression inputs committed under `tests/fuzz/corpus/`.

---

# PHASE 9 — Advanced Features (new — what turns a linter into a product)

## 9.1 Correlation / attack-path engine (`engine/graph.py`, `rules/correlation/`)

Build a graph from collected resources (`networkx` or a tiny own adjacency map): nodes = resources, edges = `uses_role`, `reads_bucket`, `member_of_sg`, `kb_uses_vectorstore`, `agent_uses_guardrail`, `in_vpc`. Edges come from attrs already collected (role ARNs, KB storage config, SG ids). **Path rules** are expressed as predicates over graphs and emit `Finding`s with `scope=path` and **escalated severity**, e.g.: *internet-exposed notebook → role with `s3:*` on `*` → CRITICAL*; *public vector DB → KB → agent without guardrail → CRITICAL*. Output includes the path (`a → b → c`) in `evidence`. This is where "CRITICAL" is earned (keeps 3.x honest).

## 9.2 Scan history, diff & drift

`tensorguard diff old.json new.json` → *new / fixed / changed-severity* findings by fingerprint; `--since FILE` skips unchanged resources (resource hash). Markdown sink gains a "since last scan" section. Enables the PR comment: *"This PR introduces 2 new findings"*.

## 9.3 Remediation PR generation (original Phase 8 idea, hardened)

Generate **patches, never apply**: Terraform/CloudFormation snippets rendered from `Remediation` objects (3.1) into a `remediation/` folder or a unified diff against detected IaC (`--iac-path`, simple `aws_s3_bucket*` resource matching by name). `--format pr-patch`. Guardrails: output is reviewed text, no cloud writes, every patch cites its finding fingerprint; unsupported resources are listed, not guessed.

## 9.3b Org-wide scanning

`--org`: `organizations:ListAccounts` → assume `--org-role-name` (default `TensorGuardReadOnly`) per account → run orchestrator per account (bounded concurrency) → merged report with an `account_id` dimension. Ship a CloudFormation StackSet template for the read-only role (generated from `docs/iam-policy.json`).

## 9.4 Least-privilege suggestions

For IAM-001 findings: `iam:GenerateServiceLastAccessedDetails` (+ optionally CloudTrail Access Analyzer policy generation) to suggest a scoped policy. Output as advisory, flagged "verify before applying".

## 9.5 Compliance evidence export

Map rules → controls in `frameworks.yaml` for **NIST AI RMF / AI 600-1, ISO/IEC 42001, EU AI Act (record-keeping, cybersecurity)**, CIS AWS. `tensorguard report compliance --framework nist-ai-rmf` prints control → rules → pass/fail evidence. State clearly it is *evidence support*, not certification. (Verify each control reference against the current published text.)

## 9.6 Native sinks

**AWS Security Hub (ASFF)** via `BatchImportFindings` (opt-in write — own IAM policy, like 7.3), Slack/Teams webhook summary (no resource details by default), OpenTelemetry metrics (`--otlp-endpoint`) for score over time.

## 9.7 Plugin SDK & community rule packs

`docs/plugin-guide.md` + a template repo (`tensorguard-rules-example`) exposing `ai_spm.rules`/`ai_spm.collectors` entry points, a `tensorguard plugins list/verify` command, and a **rule-pack test harness** (`tensorguard.testing` module exporting `make_resource`, contract test runner) so third parties can't ship rules that violate the purity contract.

## 9.8 Optional sandboxed live-MCP inspection

Extends 1.4: for *allow-listed* servers only, run them in a locked-down container (no network, read-only FS, seccomp), call `tools/list`, hash tool descriptions, scan for injection/Unicode markers, and detect post-approval mutation (true rug-pull detection). Off by default; separate extra; heavy documentation of the sandbox guarantees and their limits.

---

# PART C — Execution plan

## C1. Recommended order & releases

| Release | Contents | Why this order |
| --- | --- | --- |
| **v0.0 (internal)** | Phase 0 complete | Foundation; nothing user-visible |
| **v0.1** | Phase 1 + console/JSON reporters (4.2, 4.3) + minimal CLI | Zero-credential, immediately useful, proves engine → **first public release** |
| **v0.2** | 2.1–2.4 + 3.2 (S3 only) + 4.4 SARIF | **Vertical slice on real AWS** before breadth — finds integration bugs when they're cheap |
| **v0.3** | rest of Phase 2 + Phase 3 | Breadth, now on a proven slice |
| **v0.4** | 4.1 `doctor`, 4.5–4.8 (Action, release pipeline) | Adoption features |
| **v0.5** | Phase 8.1–8.3 + 9.2 (diff/baseline polish) | Trust + CI usability |
| **v1.0** | + 9.1 correlation, 9.3 patches, perf budgets met | "Product" threshold |
| **post-1.0** | Phases 5, 6 (one cloud), 7, remaining 9.x | Expansion driven by real users |

## C2. Agent prompt template (paste at the top of every agent session)

```
You are implementing sub-phase <X.Y> of docs/PLAYBOOK.md for the ai_spm package.
Read first: docs/ai-rules.md, docs/decisions.md (ADR-001..012), PLAYBOOK sub-phase <X.Y>.
Scope: touch ONLY the files listed in the sub-phase. If you think another file must change, STOP and say why.
Rules: Python 3.12, mypy --strict, pydantic v2, no new `Any`, no hardcoded tunables (use AISPMConfig),
       no boto3/network/file I/O in rules, no real credentials, tests first.
Deliver: (1) a plan listing files + public signatures, (2) the full diff, (3) test results of
         `uv run ruff check . && uv run ruff format --check . && uv run mypy ai_spm && uv run pytest -q`.
Do not rename or change signatures of engine/models.py, rules/base.py, collectors/aws/base.py.
If an AWS API name, parameter or response shape is uncertain, say so and cite the boto3 docs page — do not guess.
```

## C3. Risk register (top items)

| Risk | Likelihood | Mitigation (sub-phase) |
| --- | --- | --- |
| Mis-mapped MITRE/OWASP/CVE refs damage credibility | High (already present) | 3.1 audit + `frameworks.yaml`; verify CVEs on NVD |
| False positives (S3-001, S3-004, OPENSEARCH-001) kill adoption | High | severity re-rating (A3/3.x), baseline/suppressions (0.6), heuristic labeling |
| Permission gaps read as "all clear" | Medium | gaps ≠ fail (D-08), score `None`, `--strict-coverage`, `doctor` |
| Multi-agent drift in core models | Medium | B2 guardrails, contract tests, golden tests, CODEOWNERS |
| Scope creep into Phases 5–9 before v0.3 | High | C1 release gates; each release has an exit gate |
| Write-capable features (7.3, 9.6) erode the read-only trust story | Medium | separate subcommand/package + separate IAM policy |
| Boto3/AWS API drift (new enum values, fields) | Medium | lenient parsing (`extra="allow"` on ingestion only), nightly moto/boto upgrade job |

## C4. Decisions I need from you (answer in a comment or in chat)

1. **Name:** confirm `tensorguard` (package/CLI) + `ai_spm` import + `AI-SPM-*` rule IDs (D-01).
2. **Severity re-rating** (S3-001 → MEDIUM, SageMaker-001 → HIGH, BEDROCK-003 → HIGH, OPENSEARCH split 001/004): accept, or do you want the original catalog severities for marketing reasons?
3. **Second cloud** (Phase 6): GCP or Azure first — whichever your consulting clients actually run.
4. **Write-capable features** (7.3 canary, 9.6 Security Hub): ship as separate package, or inside core behind flags?
5. **License** (MIT/Apache-2.0/BSL?) — decide before the first public release because plugin authors care.

## C5. Per-sub-phase checklist (copy into each PR description)

- [ ] Files match the playbook list (no extras) - \[ \] Types: `mypy --strict` clean, no new `Any`
- [ ] No hardcoded tunables - \[ \] Unknown ≠ fail honored - \[ \] Tests: PASSED / FAILED / unknown + hostile-input where parsing
- [ ] Secrets redacted at construction - \[ \] Docs/CHANGELOG updated - \[ \] Generated artifacts (rule docs, IAM policy, schema) regenerated
- [ ] Gate green locally **and** in CI - \[ \] I can explain the diff in two sentences
