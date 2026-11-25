"""Redacted diagnostics bundle writer for bug reports (Phase 8.5)."""

import json
import platform
import sys
import zipfile
from pathlib import Path

from ai_spm import __version__
from ai_spm.config import AISPMConfig
from ai_spm.engine.models import CoverageGap
from ai_spm.utils.redact import redact


def write_debug_bundle(
    dest: Path,
    *,
    cfg: AISPMConfig,
    coverage_gaps: list[CoverageGap],
    timings: dict[str, float],
) -> None:
    """Write a redacted diagnostics zip without raw cloud resource topology or secrets."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    versions = {
        "tensorguard": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
    }
    safe_cfg = json.loads(redact(cfg.model_dump_json()))
    gaps_data = [g.model_dump() for g in coverage_gaps]

    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("versions.json", json.dumps(versions, indent=2))
        zf.writestr("config_effective.json", json.dumps(safe_cfg, indent=2))
        zf.writestr("coverage_gaps.json", json.dumps(gaps_data, indent=2))
        zf.writestr("timings.json", json.dumps(timings, indent=2))
