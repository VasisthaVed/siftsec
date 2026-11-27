"""Property-based fuzzing tests for hostile binary and JSON inputs (Phase 1.8)."""

import io
import json
import tempfile
from pathlib import Path

from hypothesis import given
from hypothesis import settings as hyp_settings
from hypothesis import strategies as st

from siftsec.collectors.local.mcp import LocalMcpCollector
from siftsec.config import SiftsecConfig
from siftsec.scanners.pickle_scanner import scan_pickle_stream, validate_safetensors_header

_CFG = SiftsecConfig()


@hyp_settings(max_examples=200)
@given(data=st.binary(max_size=2048))
def test_fuzz_pickle_stream_never_crashes(data: bytes) -> None:
    res = scan_pickle_stream(io.BytesIO(data), _CFG)
    assert res is not None


@hyp_settings(max_examples=100)
@given(data=st.binary(max_size=1024))
def test_fuzz_safetensors_header_never_crashes(data: bytes) -> None:
    with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as tmp:
        tmp.write(data)
        tmp_path = Path(tmp.name)
    try:
        ok = validate_safetensors_header(tmp_path, len(data), _CFG)
        assert isinstance(ok, bool)
    finally:
        tmp_path.unlink(missing_ok=True)


@hyp_settings(max_examples=100)
@given(
    payload=st.one_of(
        st.text(max_size=500),
        st.dictionaries(st.text(max_size=20), st.text(max_size=50), max_size=5).map(json.dumps),
    )
)
def test_fuzz_mcp_collector_never_crashes(payload: str) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_path = Path(tmpdir) / ".mcp.json"
        cfg_path.write_text(payload, encoding="utf-8")
        resources = LocalMcpCollector(paths=[Path(tmpdir)]).collect()
        assert isinstance(resources, list)
