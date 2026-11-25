"""Scan diff and drift analysis between two JSONReporter snapshots (Phase 9.2)."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ScanDiffResult:
    """Fingerprinted comparison of failed findings between an old and new scan."""

    added: list[dict[str, Any]]
    fixed: list[dict[str, Any]]
    unchanged_count: int
    changed_severity: list[dict[str, Any]]


def _index_failed(path: Path) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, dict[str, Any]] = {}
    for item in data.get("findings", []):
        if item.get("status") == "FAILED" and not item.get("suppressed", False):
            fp = str(item.get("fingerprint", ""))
            if fp:
                out[fp] = item
    return out


def diff_scans(old_path: Path, new_path: Path) -> ScanDiffResult:
    """Compute added, fixed, and severity-changed failed findings across two JSON scans."""
    old_map = _index_failed(old_path)
    new_map = _index_failed(new_path)

    added = [new_map[fp] for fp in sorted(set(new_map) - set(old_map))]
    fixed = [old_map[fp] for fp in sorted(set(old_map) - set(new_map))]
    common = sorted(set(old_map) & set(new_map))
    changed_severity: list[dict[str, Any]] = []
    for fp in common:
        old_sev = old_map[fp].get("severity")
        new_sev = new_map[fp].get("severity")
        if old_sev != new_sev:
            changed_severity.append(
                {
                    "fingerprint": fp,
                    "rule_id": new_map[fp].get("rule_id"),
                    "resource_arn": new_map[fp].get("resource_arn"),
                    "old_severity": old_sev,
                    "new_severity": new_sev,
                }
            )

    return ScanDiffResult(
        added=added,
        fixed=fixed,
        unchanged_count=len(common),
        changed_severity=changed_severity,
    )
