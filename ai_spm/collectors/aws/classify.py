"""Deterministic, explainable AI workload classification (Phase 2.3)."""

import re
from collections.abc import Mapping, Sequence

from ai_spm.config import AISPMConfig


def _get_tag_ci(tags: Mapping[str, str], target_key: str) -> str | None:
    lowered = target_key.lower()
    for k, v in tags.items():
        if k.lower() == lowered:
            return v
    return None


def classify_ai_workload(
    service: str,
    name: str,
    tags: Mapping[str, str],
    cfg: AISPMConfig,
    *,
    extra_signals: Sequence[str] = (),
) -> tuple[bool, str | None]:
    """Classify whether a resource is an AI/ML workload and explain why."""
    if (ignore := _get_tag_ci(tags, "tensorguard:ignore")) and ignore.lower() == "true":
        return False, None
    if (opt_in := _get_tag_ci(tags, "tensorguard:ai")) and opt_in.lower() == "true":
        return True, "tag tensorguard:ai=true"

    for key, wanted_values in cfg.ai_workload_tags.items():
        val = _get_tag_ci(tags, key)
        if val is not None and val.lower() in {w.lower() for w in wanted_values}:
            return True, f"tag {key}={val}"

    if service.lower() in cfg.ai_inherent_services:
        return True, f"service {service} is AI by nature"

    for raw_pattern in cfg.ai_name_patterns.get(service.lower(), []):
        if re.search(raw_pattern, name, flags=re.IGNORECASE):
            return True, f"name matches /{raw_pattern}/"

    if extra_signals:
        return True, extra_signals[0]

    return False, None
