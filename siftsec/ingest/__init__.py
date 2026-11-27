"""External scanner ingest adapters and deduplication (Phase 10.1–10.2)."""

from siftsec.ingest.dedup import index_findings
from siftsec.ingest.json_adapter import ingest_json_bytes
from siftsec.ingest.models import NormalizedFinding
from siftsec.ingest.sarif_adapter import ingest_sarif_bytes

__all__ = ["NormalizedFinding", "index_findings", "ingest_json_bytes", "ingest_sarif_bytes"]
