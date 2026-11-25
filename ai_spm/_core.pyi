from typing import Any

def parse_json_bounded(
    data: bytes,
    max_depth: int = 64,
    max_bytes: int = 64 * 1024 * 1024,
) -> dict[str, Any] | list[Any]: ...
