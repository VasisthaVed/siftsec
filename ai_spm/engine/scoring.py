"""Severity-weighted CSPM posture scoring and CI exit-code evaluation."""

from collections.abc import Mapping, Sequence

from ai_spm.engine.models import Finding, Severity, Status


def posture_score(
    findings: Sequence[Finding],
    weights: Mapping[Severity, int],
) -> int | None:
    """Compute weighted pass-rate score (0-100), or None when nothing was evaluated."""
    evaluated = [
        f for f in findings if f.status in (Status.PASSED, Status.FAILED) and not f.suppressed
    ]
    if not evaluated:
        # Returning 100 on an unscanned account would create false assurance.
        return None

    numerator = sum(weights.get(f.severity, 1) for f in evaluated if f.status is Status.PASSED)
    denominator = sum(weights.get(f.severity, 1) for f in evaluated)
    if denominator == 0:
        return 100
    return round(100 * numerator / denominator)


def exit_code(
    findings: Sequence[Finding],
    fail_on: Severity,
    *,
    strict_coverage: bool = False,
    coverage_gaps_count: int = 0,
) -> int:
    """Return 1 if any unsuppressed FAILED finding meets fail_on, 3 on strict gaps, else 0."""
    has_blocking = any(
        f.status is Status.FAILED and not f.suppressed and f.severity >= fail_on for f in findings
    )
    if has_blocking:
        return 1
    if strict_coverage and coverage_gaps_count > 0:
        return 3
    return 0
