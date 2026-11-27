"""Normalized finding schema for cross-tool correlation (Phase 10.1, schema=1)."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from siftsec.engine.models import Severity


class NormalizedFinding(BaseModel):
    """Schema-versioned finding normalized from external SARIF/JSON scanners."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = Field(default=1, alias="schema")
    source_tool: str
    rule_id: str
    severity: Severity
    asset_id: str
    asset_kind: Literal[
        "model",
        "mcp_server",
        "skill",
        "cloud_resource",
        "container",
        "code",
        "unknown",
    ] = "unknown"
    component_hash: str | None = None
    location: str = ""
    message: str
    evidence: dict[str, str] = Field(default_factory=dict)
    framework_requirements: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
