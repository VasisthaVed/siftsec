# SPDX-License-Identifier: Apache-2.0
"""Normalized finding and reachability graph schemas (Phase 10.1–10.3, schema=1)."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from siftsec.engine.models import Severity

NodeKind = Literal["boundary", "ai_asset", "identity", "data_store", "skill", "model"]
EdgeKind = Literal[
    "uses_role",
    "reads_bucket",
    "member_of_sg",
    "kb_uses_vectorstore",
    "agent_uses_guardrail",
    "skill_uses_agent",
    "model_handoff",
]


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


class Node(BaseModel):
    """Graph node (ADR-043 includes first-class `skill` and `model` node kinds)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    kind: NodeKind
    sensitive: bool = False
    boundary: bool = False
    display_name: str = ""


class Edge(BaseModel):
    """Directed graph edge (ADR-043 includes `model_handoff` credential-inheritance edge)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str
    target: str
    kind: EdgeKind
    confidence: float = 1.0
    provenance: str = ""
    actions: list[str] = Field(default_factory=list)


class GraphPayload(BaseModel):
    """Cross-boundary FFI payload for reachability graph evaluation (schema=1, ADR-032)."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    schema_version: Literal[1] = Field(default=1, alias="schema")
    nodes: list[Node]
    edges: list[Edge]
    max_hops: int = Field(default=8, ge=1, le=32)


class ReachabilityResult(BaseModel):
    """Deterministic reachability + one-line score output from Rust graph engine."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    schema_version: Literal[1] = Field(default=1, alias="schema")
    reachable: bool
    witness_path: list[str]
    hops: int
    reaches_sensitive: bool
    via_write_permission: bool
    severity: str
    explanation: str
    witnesses: list[list[str]] = Field(default_factory=list)
