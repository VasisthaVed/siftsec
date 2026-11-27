"""External scanner ingest adapters (Phase 10.1)."""

from siftsec.ingest.json_adapter import ingest_json_bytes
from siftsec.ingest.models import NormalizedFinding
from siftsec.ingest.sarif_adapter import ingest_sarif_bytes

__all__ = ["NormalizedFinding", "ingest_json_bytes", "ingest_sarif_bytes"]
