"""Phase 10.3 reachability graph exit-gate tests (Scenarios #1-#5)."""

import json
from pathlib import Path
from typing import Any

from siftsec.ingest.graph import build_graph_and_score

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "graph"


def _load(name: str) -> dict[str, Any]:
    return dict(json.loads((_FIXTURES / name).read_text(encoding="utf-8")))


def test_notebook_to_model_bucket_critical() -> None:
    """Exit Gate #1: internet-exposed notebook -> s3:* role -> sensitive bucket => CRITICAL."""
    res = build_graph_and_score(_load("scenario_1_notebook_to_s3.json"))
    assert res.schema_version == 1
    assert res.reachable is True
    assert res.reaches_sensitive is True
    assert res.via_write_permission is True
    assert len(res.witness_path) == 3
    assert res.hops == 2
    assert res.severity == "CRITICAL"


def test_readonly_role_is_low_not_critical() -> None:
    """Exit Gate #2: read-only role (s3:GetObject only) => reachable=True, via_write=False, LOW."""
    res = build_graph_and_score(_load("scenario_2_readonly_role.json"))
    assert res.reachable is True
    assert res.reaches_sensitive is True
    assert res.via_write_permission is False
    assert res.severity == "LOW"


def test_compromised_skill_to_credential_critical() -> None:
    """Exit Gate #3 (ADR-043): untrusted registry -> skill -> agent -> PassRole -> bucket."""
    res = build_graph_and_score(_load("scenario_3_compromised_skill.json"))
    assert res.reachable is True
    assert res.via_write_permission is True
    assert any("skill://" in node_id for node_id in res.witness_path)
    assert res.severity == "CRITICAL"


def test_model_handoff_inherits_credentials() -> None:
    """Exit Gate #4 (ADR-043): model_A (write creds) -> model_handoff -> model_B -> bucket."""
    res = build_graph_and_score(_load("scenario_4_model_handoff.json"))
    assert res.reachable is True
    assert res.via_write_permission is True
    assert "model://router/model-a" in res.witness_path
    assert "model://worker/model-b" in res.witness_path
    assert res.severity == "CRITICAL"


def test_no_path_returns_empty() -> None:
    """Exit Gate #5: no path from boundary to sensitive bucket => reachable=False, empty witness."""
    res = build_graph_and_score(_load("scenario_5_no_path.json"))
    assert res.reachable is False
    assert res.witness_path == []
    assert res.hops == 0
    assert res.severity == "INFO"
