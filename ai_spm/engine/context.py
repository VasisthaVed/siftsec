"""Immutable scan execution context."""

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ai_spm.engine.models import Severity


class ScanContext(BaseModel):
    """Read-only scan parameters passed through collectors, runner, and reporters."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    account_id: str = "local"
    partition: str = "aws"
    regions: list[str] = Field(default_factory=list)
    services: list[str] | None = None
    min_severity: Severity = Severity.LOW
    fail_on: Severity = Severity.HIGH
    ai_only: bool = True
    profile: str | None = None
    baseline_path: Path | None = None
