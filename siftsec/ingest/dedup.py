# SPDX-License-Identifier: Apache-2.0
"""Cross-tool finding deduplication wrapper (Phase 10.2)."""

import hashlib
import importlib
from typing import Any

from siftsec.engine.models import Severity
from siftsec.ingest.models import NormalizedFinding

_SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFORMATIONAL": 0,
}

try:
    try:
        _native: Any = importlib.import_module("siftsec._core")
    except ImportError:
        _native = importlib.import_module("_core")
    _HAS_NATIVE_DEDUP = hasattr(_native, "index_findings")
except ImportError:
    _native = None
    _HAS_NATIVE_DEDUP = False


def _py_index_findings(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    buckets: dict[str, list[NormalizedFinding]] = {}
    for f in findings:
        comp = f.component_hash or f.asset_id
        rule_or_cwe = f.evidence.get("cwe") or f.rule_id
        raw = f"{comp}|{rule_or_cwe}|{f.location}".encode()
        key = hashlib.sha256(raw).hexdigest()
        buckets.setdefault(key, []).append(f)

    merged: list[NormalizedFinding] = []
    for group in buckets.values():
        acc = group[0].model_copy(deep=True)
        sources = list(acc.sources or [acc.source_tool])
        reqs = list(acc.framework_requirements)
        ev = dict(acc.evidence)
        sev = acc.severity
        for item in group[1:]:
            if _SEVERITY_RANK.get(item.severity.value, 0) > _SEVERITY_RANK.get(sev.value, 0):
                sev = item.severity
            for s in item.sources or [item.source_tool]:
                if s not in sources:
                    sources.append(s)
            for req in item.framework_requirements:
                if req not in reqs:
                    reqs.append(req)
            for k, v in item.evidence.items():
                ev.setdefault(k, v)
        merged.append(
            acc.model_copy(
                update={
                    "severity": sev,
                    "sources": sources,
                    "framework_requirements": reqs,
                    "evidence": ev,
                }
            )
        )

    merged.sort(
        key=lambda f: (
            -_SEVERITY_RANK.get(f.severity.value, 0),
            f.rule_id,
            f.asset_id,
        )
    )
    return merged


def index_findings(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    """Deduplicate normalized findings across tools using Rust _core.index_findings."""
    if not findings:
        return []
    if _HAS_NATIVE_DEDUP:
        payload = [f.model_dump(mode="json", by_alias=True) for f in findings]
        raw_merged: list[dict[str, Any]] = _native.index_findings(payload)
        return [
            NormalizedFinding.model_validate({**item, "severity": Severity(item["severity"])})
            for item in raw_merged
        ]
    return _py_index_findings(findings)
