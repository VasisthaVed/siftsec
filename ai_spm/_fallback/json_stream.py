"""Bounded pure-Python JSON parser matching rust/tensorguard-core/src/json_stream.rs."""

import json
from typing import Any

DEFAULT_MAX_JSON_BYTES = 64 * 1024 * 1024


def parse_json_bounded(
    data: bytes,
    max_depth: int = 64,
    max_bytes: int = DEFAULT_MAX_JSON_BYTES,
) -> dict[str, Any] | list[Any]:
    """Enforce size, pre-pass nesting depth, and valid JSON object/array decoding."""
    if len(data) > max_bytes:
        raise MemoryError(f"input exceeds maximum size ({len(data)} > {max_bytes} bytes)")

    depth = 0
    in_string = False
    escape = False
    for b in data:
        if in_string:
            if escape:
                escape = False
            elif b == 0x5C:  # '\\'
                escape = True
            elif b == 0x22:  # '"'
                in_string = False
            continue
        if b == 0x22:
            in_string = True
        elif b in (0x7B, 0x5B):  # '{' or '['
            depth += 1
            if depth > max_depth:
                raise ValueError(f"input exceeds maximum nesting depth ({depth} > {max_depth})")
        elif b in (0x7D, 0x5D) and depth > 0:  # '}' or ']'
            depth -= 1

    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"malformed json: {exc}") from exc

    if not isinstance(parsed, (dict, list)):
        raise ValueError("top-level JSON payload must be an object or array")
    return parsed
