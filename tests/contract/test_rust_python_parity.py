import json
from typing import Any

import pytest

from ai_spm._core_loader import HAS_RUST, parse_json_bounded
from ai_spm._fallback.json_stream import parse_json_bounded as py_parse_json_bounded

PARITY_FIXTURES: list[bytes] = [
    b'{"schema": 1, "tool": "ModelAudit", "items": [1, 2, 3]}',
    b'[{"a": true, "b": null}]',
    (b"[" * 8) + b"42" + (b"]" * 8),
]


@pytest.mark.parametrize("payload", PARITY_FIXTURES)
def test_fallback_json_stream_parses_valid_fixtures(payload: bytes) -> None:
    assert json.loads(payload) == py_parse_json_bounded(payload, max_depth=64)


@pytest.mark.parametrize("payload", PARITY_FIXTURES)
def test_rust_python_parity_when_tg_core_compiled(payload: bytes) -> None:
    """ADR-030: Both Rust _tg_core and Python _fallback must produce identical output."""
    assert HAS_RUST is True, "_tg_core extension is not loaded"
    rust_parsed: Any = parse_json_bounded(payload, max_depth=64)
    assert rust_parsed == py_parse_json_bounded(payload, max_depth=64)
