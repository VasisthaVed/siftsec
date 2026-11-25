"""External scanner ingest adapters (Phase 10.1)."""

from ai_spm.ingest.json_adapter import ingest_json_bytes
from ai_spm.ingest.models import NormalizedFinding
from ai_spm.ingest.sarif_adapter import ingest_sarif_bytes

__all__ = ["NormalizedFinding", "ingest_json_bytes", "ingest_sarif_bytes"]
