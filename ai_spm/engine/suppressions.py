"""Finding suppressions (with mandatory expiry) and fingerprint baselines (Phase 0.6 / 4.6)."""

import json
from datetime import date
from fnmatch import fnmatch
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from ai_spm.engine.models import Finding


class SuppressionRule(BaseModel):
    """Config-driven suppression rule requiring owner and expiration date."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str
    resource: str
    reason: str
    expires: date
    owner: str


def load_baseline_fingerprints(path: Path | None) -> set[str]:
    """Load accepted finding fingerprints from a baseline JSON file."""
    if path is None or not path.is_file():
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and isinstance(data.get("fingerprints"), list):
        return {str(fp) for fp in data["fingerprints"]}
    return set()


def apply_suppressions(
    findings: list[Finding],
    suppressions: list[SuppressionRule],
    *,
    baseline_fingerprints: set[str] | None = None,
    today: date | None = None,
) -> list[Finding]:
    """Mark matching non-expired or baselined findings as suppressed without deleting them."""
    ref_date = today or date.today()
    baseline = baseline_fingerprints or set()
    updated: list[Finding] = []

    for f in findings:
        if f.fingerprint in baseline:
            updated.append(
                f.model_copy(
                    update={"suppressed": True, "suppression_reason": "Accepted in baseline"}
                )
            )
            continue

        matched_reason: str | None = None
        for sup in suppressions:
            if sup.rule_id != f.rule_id:
                continue
            if not fnmatch(f.resource_arn, sup.resource):
                continue
            if sup.expires < ref_date:
                # Expired suppressions must re-surface automatically.
                continue
            matched_reason = f"{sup.reason} (owner={sup.owner}, expires={sup.expires.isoformat()})"
            break

        if matched_reason:
            updated.append(
                f.model_copy(update={"suppressed": True, "suppression_reason": matched_reason})
            )
        else:
            updated.append(f)

    return updated
