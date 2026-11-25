from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


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
    MCP = "MCP"


class CloudResource(BaseModel):
    arn: str
    id: str
    name: str
    service: str
    provider: CloudProvider = CloudProvider.AWS
    region: str = "global"
    account_id: str = "unknown"
    tags: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    is_ai_workload: bool = True


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
    nist_ai_rmf: list[str] = Field(default_factory=list)
    region: str = "global"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
