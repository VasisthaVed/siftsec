"""External scanner ingest adapters (Phase 10.1)."""

from ai_spm.ingest.models import NormalizedFinding
from ai_spm.ingest.sarif_adapter import ingest_sarif_bytes

__all__ = ["NormalizedFinding", "ingest_sarif_bytes"]
