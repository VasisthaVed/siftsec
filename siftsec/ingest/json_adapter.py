"""Bounded native JSON ingest adapter for Prowler, ModelAudit, mcpvuln, and agent-bom."""

from typing import Any

from siftsec._core_loader import parse_json_bounded
from siftsec.engine.models import Severity
from siftsec.ingest.models import NormalizedFinding

_SEV_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "error": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFORMATIONAL,
    "informational": Severity.INFORMATIONAL,
}


def _norm_sev(raw: Any) -> Severity:
    return _SEV_MAP.get(str(raw or "medium").lower(), Severity.MEDIUM)


def ingest_json_bytes(
    data: bytes,
    *,
    source_tool: str,
    max_depth: int = 64,
    max_bytes: int = 64 * 1024 * 1024,
) -> list[NormalizedFinding]:
    """Normalize native JSON output from Prowler, ModelAudit, mcpvuln, or agent-bom."""
    doc = parse_json_bounded(data, max_depth=max_depth, max_bytes=max_bytes)
    low_tool = source_tool.lower()

    items: list[dict[str, Any]]
    if isinstance(doc, list):
        items = [x for x in doc if isinstance(x, dict)]
    elif isinstance(doc, dict):
        raw_list = (
            doc.get("issues")
            or doc.get("findings")
            or doc.get("vulnerabilities")
            or doc.get("results")
            or []
        )
        if not isinstance(raw_list, list):
            raise ValueError(f"Unexpected JSON findings structure for {source_tool}")
        items = [x for x in raw_list if isinstance(x, dict)]
    else:
        raise ValueError("JSON root must be an object or array")

    out: list[NormalizedFinding] = []
    for item in items:
        # Prowler native JSON uses StatusExtended / CheckID / ResourceArn / Severity
        if "prowler" in low_tool:
            if str(item.get("Status") or "").upper() == "PASS":
                continue
            rule_id = str(item.get("CheckID") or item.get("rule_id") or "PROWLER-UNKNOWN")
            asset_id = str(item.get("ResourceArn") or item.get("ResourceId") or rule_id)
            msg = str(item.get("StatusExtended") or item.get("message") or "")
            sev = _norm_sev(item.get("Severity"))
            kind = "cloud_resource"
        else:
            rule_id = str(item.get("rule_id") or item.get("id") or item.get("check") or "UNKNOWN")
            asset_id = str(
                item.get("asset_id")
                or item.get("server")
                or item.get("location")
                or item.get("file")
                or rule_id
            )
            msg = str(item.get("message") or item.get("description") or item.get("title") or "")
            sev = _norm_sev(item.get("severity"))
            kind = (
                "model"
                if "modelaudit" in low_tool
                else "mcp_server"
                if any(k in low_tool for k in ("mcp", "agent-bom", "agent-audit"))
                else "unknown"
            )

        comp_hash = item.get("sha256") or item.get("component_hash")
        loc = str(item.get("location") or item.get("file") or item.get("ResourceId") or "")
        out.append(
            NormalizedFinding(
                source_tool=source_tool,
                rule_id=rule_id,
                severity=sev,
                asset_id=asset_id,
                asset_kind=kind,  # type: ignore[arg-type]
                component_hash=str(comp_hash) if comp_hash else None,
                location=loc,
                message=msg,
                sources=[source_tool],
            )
        )
    return out
