import json
from pathlib import Path
from typing import Any

import pytest

from ai_spm._core_loader import HAS_RUST, parse_json_bounded
from ai_spm._fallback.json_stream import parse_json_bounded as py_parse_json_bounded
from ai_spm.ingest import ingest_sarif_bytes

_FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "ingest"
_REAL_SARIF_FIXTURES = [
    pytest.param(_FIXTURE_DIR / "modelaudit.sarif", id="modelaudit-0.2.58"),
    pytest.param(_FIXTURE_DIR / "trivy.sarif", id="trivy-0.76.2"),
]


@pytest.mark.parametrize("fixture_path", _REAL_SARIF_FIXTURES)
def test_fallback_json_stream_parses_real_sarif_fixtures(fixture_path: Path) -> None:
    payload = fixture_path.read_bytes()
    assert json.loads(payload) == py_parse_json_bounded(payload, max_depth=64)


@pytest.mark.parametrize("fixture_path", _REAL_SARIF_FIXTURES)
def test_rust_python_parity_on_real_sarif_fixtures(fixture_path: Path) -> None:
    """ADR-030: Both Rust _tg_core and Python _fallback must produce identical output."""
    assert HAS_RUST is True, "_tg_core extension is not loaded"
    payload = fixture_path.read_bytes()
    rust_parsed: Any = parse_json_bounded(payload, max_depth=64)
    assert rust_parsed == py_parse_json_bounded(payload, max_depth=64)

    findings = ingest_sarif_bytes(payload)
    assert len(findings) >= 1
    assert all(f.schema_version == 1 for f in findings)
