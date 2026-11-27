"""Versioned JSON report exporter (Phase 4.3)."""

from siftsec.engine.models import ScanSummary


class JSONReporter:
    """Serializes ScanSummary to versioned JSON."""

    def export(self, summary: ScanSummary) -> str:
        return summary.model_dump_json(indent=2)
