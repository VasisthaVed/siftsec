# SPDX-License-Identifier: Apache-2.0
"""Bounded SARIF 2.1.0 ingest adapter for ModelAudit, Trivy, Semgrep, agent-bom, MCPiranha."""

from typing import Any

from siftsec._core_loader import parse_json_bounded
from siftsec.engine.models import Severity
from siftsec.ingest.models import NormalizedFinding

_SARIF_LEVEL_MAP: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFORMATIONAL,
}


def _infer_asset_kind(tool_name: str, uri: str) -> str:
    low_tool = tool_name.lower()
    low_uri = uri.lower()
    if "modelaudit" in low_tool or low_uri.endswith(
        (".pkl", ".pt", ".pth", ".safetensors", ".gguf", ".onnx")
    ):
        return "model"
    if "skill" in low_uri or "clawhub" in low_tool:
        return "skill"
    if any(t in low_tool for t in ("mcp", "mcpiranha", "agent-bom", "agent-audit")):
        return "mcp_server"
    if "prowler" in low_tool:
        return "cloud_resource"
    if "trivy" in low_tool:
        return "container"
    return "code"


def ingest_sarif_bytes(
    data: bytes,
    *,
    source_override: str | None = None,
    max_depth: int = 64,
    max_bytes: int = 64 * 1024 * 1024,
) -> list[NormalizedFinding]:
    """Parse SARIF 2.1.0 bytes safely and normalize every result without silent drops."""
    doc = parse_json_bounded(data, max_depth=max_depth, max_bytes=max_bytes)
    if not isinstance(doc, dict):
        raise ValueError("SARIF root must be a JSON object")

    runs = doc.get("runs")
    if not isinstance(runs, list):
        raise ValueError("SARIF document missing 'runs' list")

    normalized: list[NormalizedFinding] = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        driver = run.get("tool", {}).get("driver", {}) if isinstance(run.get("tool"), dict) else {}
        tool_name = source_override or str(driver.get("name") or "unknown")

        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId") or "UNKNOWN")
            level = str(result.get("level") or "warning").lower()
            sev = _SARIF_LEVEL_MAP.get(level, Severity.MEDIUM)

            msg_obj = result.get("message")
            message = (
                str(msg_obj.get("text", "")) if isinstance(msg_obj, dict) else str(msg_obj or "")
            )

            locs = result.get("locations") or []
            uri = ""
            if isinstance(locs, list) and locs and isinstance(locs[0], dict):
                phys = locs[0].get("physicalLocation", {})
                if isinstance(phys, dict):
                    art = phys.get("artifactLocation", {})
                    if isinstance(art, dict):
                        uri = str(art.get("uri") or "")

            props: dict[str, Any] = (
                result.get("properties", {}) if isinstance(result.get("properties"), dict) else {}
            )
            comp_hash = props.get("component_hash") or props.get("sha256")
            asset_id = str(props.get("asset_id") or uri or rule_id)
            kind = _infer_asset_kind(tool_name, uri)

            normalized.append(
                NormalizedFinding(
                    source_tool=tool_name,
                    rule_id=rule_id,
                    severity=sev,
                    asset_id=asset_id,
                    asset_kind=kind,  # type: ignore[arg-type]
                    component_hash=str(comp_hash) if comp_hash else None,
                    location=uri,
                    message=message,
                    sources=[tool_name],
                )
            )

    return normalized
