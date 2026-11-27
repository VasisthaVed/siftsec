"""Phase 10.2 cross-tool deduplication tests (Exit Gate #1)."""

from pathlib import Path

from siftsec.engine.models import Severity
from siftsec.ingest import NormalizedFinding, index_findings, ingest_sarif_bytes

_FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "ingest"


def test_three_tools_one_server() -> None:
    """Exit Gate #1: modelaudit, trivy, and agent-bom on the same MCP server -> 1 entity."""
    modelaudit_raw = (_FIXTURE_DIR / "modelaudit.sarif").read_bytes()
    trivy_raw = (_FIXTURE_DIR / "trivy.sarif").read_bytes()

    ma_findings = ingest_sarif_bytes(modelaudit_raw)
    trivy_findings = ingest_sarif_bytes(trivy_raw)
    assert ma_findings and trivy_findings

    # Align the same MCP server artifact across all 3 tools under different asset_id names
    # while sharing component_hash, CWE/rule, and location from the real SARIF fixtures.
    shared_hash = "dc957e635ed9bf33c5b566f8c03353845494ba4a968a93877352e179e88ddc42"
    shared_location = ".mcp.json"
    shared_cwe = "CWE-502"

    f_modelaudit = ma_findings[0].model_copy(
        update={
            "source_tool": "modelaudit",
            "asset_id": "mcp://filesystem-alpha",
            "asset_kind": "mcp_server",
            "component_hash": shared_hash,
            "location": shared_location,
            "evidence": {"cwe": shared_cwe},
            "sources": ["modelaudit"],
        }
    )
    f_trivy = trivy_findings[0].model_copy(
        update={
            "source_tool": "trivy",
            "asset_id": "arn:aws:ecs:us-east-1:123456789012:service/mcp-fs",
            "asset_kind": "mcp_server",
            "component_hash": shared_hash,
            "location": shared_location,
            "evidence": {"cwe": shared_cwe},
            "sources": ["trivy"],
        }
    )
    f_agent_bom = NormalizedFinding(
        source_tool="agent-bom",
        rule_id="ABOM-MCP-502",
        severity=Severity.CRITICAL,
        asset_id="pkg:mcp/filesystem-server@1.0.0",
        asset_kind="mcp_server",
        component_hash=shared_hash,
        location=shared_location,
        message="Untrusted deserialization / tool server risk",
        evidence={"cwe": shared_cwe},
        sources=["agent-bom"],
    )

    merged = index_findings([f_modelaudit, f_trivy, f_agent_bom])
    assert len(merged) == 1
    assert merged[0].sources == ["modelaudit", "trivy", "agent-bom"]
    assert merged[0].severity == Severity.CRITICAL
