"""Runtime loader for compiled ai_spm._tg_core with pure-Python fallback (ADR-030)."""

import importlib
import json
import logging
from typing import Any

logger = logging.getLogger("ai_spm.core_loader")

HAS_RUST: bool

try:
    try:
        _native: Any = importlib.import_module("ai_spm._tg_core")
    except ImportError:
        _native = importlib.import_module("_tg_core")

    def parse_json_bounded(
        data: bytes,
        max_depth: int = 64,
        max_bytes: int = 64 * 1024 * 1024,
    ) -> dict[str, Any] | list[Any]:
        raw = _native.parse_json_bounded(data, max_depth, max_bytes)
        parsed = json.loads(raw)
        if not isinstance(parsed, (dict, list)):
            raise ValueError("top-level JSON payload must be an object or array")
        return parsed

    HAS_RUST = True
except ImportError:
    from ai_spm._fallback.json_stream import parse_json_bounded

    HAS_RUST = False
    logger.warning("Rust extension unavailable; using pure-Python fallback.")

__all__ = ["HAS_RUST", "parse_json_bounded"]
