"""Python wrapper for Rust reachability graph engine (Phase 10.3, ADR-032)."""

import importlib
import json
from typing import Any

from siftsec.ingest.models import GraphPayload, ReachabilityResult

try:
    try:
        _native: Any = importlib.import_module("siftsec._core")
    except ImportError:
        _native = importlib.import_module("_core")
except ImportError as exc:
    raise ImportError("siftsec._core native extension is required for graph reachability") from exc


def build_graph_and_score(payload: GraphPayload | dict[str, Any]) -> ReachabilityResult:
    """Validate schema=1 input, invoke Rust BFS reachability engine, and validate schema=1 output."""
    if isinstance(payload, dict):
        if payload.get("schema", payload.get("schema_version")) != 1:
            raise ValueError(f"Unsupported input graph schema: {payload.get('schema')}")
        validated = GraphPayload.model_validate(payload)
    else:
        validated = payload

    raw_json = validated.model_dump_json(by_alias=True)
    out_json: str = _native.build_graph_and_score(raw_json)
    out_data = json.loads(out_json)
    if not isinstance(out_data, dict) or out_data.get("schema") != 1:
        raise ValueError(
            f"Unsupported output graph schema: {out_data.get('schema') if isinstance(out_data, dict) else type(out_data)}"
        )
    return ReachabilityResult.model_validate(out_data)
