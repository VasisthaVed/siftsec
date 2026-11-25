"""Core Pydantic v2 domain models for TensorGuard (D-04, D-05, D-08, D-12)."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ai_spm.engine.fingerprint import fingerprint as compute_fingerprint


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

    @property
    def rank(self) -> int:
        return {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "INFORMATIONAL": 0,
        }[self.value]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


class Status(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class CloudProvider(StrEnum):
    AWS = "AWS"
    GCP = "GCP"
    AZURE = "AZURE"
    KUBERNETES = "KUBERNETES"
    LOCAL = "LOCAL"
    MCP = "MCP"


class CoverageGap(BaseModel):
    """Records a partial scan gap (e.g., AccessDenied) without masking it as PASSED."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    region: str
    api: str
    error_code: str


class CloudResource(BaseModel):
    """Normalized cloud or local AI asset emitted by collectors."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    arn: str
    id: str
    name: str
    service: str
    kind: str = ""
    provider: CloudProvider = CloudProvider.AWS
    region: str = "global"
    account_id: str = "unknown"
    tags: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    gaps: dict[str, str] = Field(default_factory=dict)
    is_ai_workload: bool = True
    ai_reason: str | None = None


AWSResource = CloudResource


class Finding(BaseModel):
    """Immutable security posture finding with stable fingerprint and framework mappings."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str
    rule_title: str
    service: str
    resource_arn: str
    resource_id: str
    resource_name: str = ""
    status: Status
    severity: Severity
    message: str
    remediation: str = ""
    evidence: dict[str, str] = Field(default_factory=dict)
    error_code: str | None = None
    mitre_atlas: list[str] = Field(default_factory=list)
    owasp_llm: list[str] = Field(default_factory=list)
    nist_ai_rmf: list[str] = Field(default_factory=list)
    region: str = "global"
    fingerprint: str = ""
    suppressed: bool = False
    suppression_reason: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def _validate_invariants(self) -> "Finding":
        if self.status is Status.FAILED and not self.remediation.strip():
            raise ValueError("FAILED findings must include non-empty remediation guidance")
        if self.status is Status.ERROR and not (self.error_code or self.message.strip()):
            raise ValueError("ERROR findings must include error_code or message")
        if not self.fingerprint:
            object.__setattr__(
                self,
                "fingerprint",
                compute_fingerprint(self.rule_id, self.resource_arn),
            )
        if not self.resource_name:
            object.__setattr__(self, "resource_name", self.resource_id)
        return self


class ScanSummary(BaseModel):
    """Top-level scan report envelope for JSON/Markdown/SARIF serialization."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    total_resources: int
    ai_resources: int
    findings: list[Finding]
    posture_score: int | None
    coverage_gaps: list[CoverageGap] = Field(default_factory=list)
    started_at: datetime
    finished_at: datetime
    tool_version: str
    schema_version: str = "1.0"
