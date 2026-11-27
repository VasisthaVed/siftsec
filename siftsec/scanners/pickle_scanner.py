"""Static pickle opcode and model container scanner (ADR-004).

Never invokes pickle.loads() or torch.load(); streams opcodes with pickletools.genops().
"""

import hashlib
import json
import pickle
import pickletools
import struct
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Literal

from siftsec.config import SiftsecConfig
from siftsec.engine.attrs import LocalModelFileAttrs, PickleHit

_STRING_PUSH_OPS = frozenset(
    {
        "SHORT_BINUNICODE",
        "BINUNICODE",
        "BINUNICODE8",
        "UNICODE",
        "STRING",
        "BINSTRING",
        "SHORT_BINSTRING",
    }
)

ModelFormat = Literal[
    "pickle",
    "torch_zip",
    "safetensors",
    "gguf",
    "onnx",
    "keras_h5",
    "unknown",
]


@dataclass
class PickleScanResult:
    """Result of streaming a single pickle bytecode stream."""

    hits: list[PickleHit] = field(default_factory=list)
    error: str | None = None


class _LimitExceededError(Exception):
    """Raised when a streamed zip member exceeds max_bytes."""


class _LimitedReader:
    """File-like wrapper enforcing a strict byte ceiling on compressed streams."""

    def __init__(self, raw: IO[bytes], max_bytes: int) -> None:
        self._raw = raw
        self._remaining = max_bytes

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            chunk = self._raw.read(self._remaining + 1)
        else:
            chunk = self._raw.read(min(size, self._remaining + 1))
        self._remaining -= len(chunk)
        if self._remaining < 0:
            raise _LimitExceededError("uncompressed_limit_exceeded")
        return chunk

    def readline(self, size: int = -1) -> bytes:
        line = self._raw.readline(size)
        self._remaining -= len(line)
        if self._remaining < 0:
            raise _LimitExceededError("uncompressed_limit_exceeded")
        return line


def _classify_global(
    module: str,
    callable_name: str,
    opcode: str,
    offset: int | None,
    cfg: SiftsecConfig,
    hits: list[PickleHit],
) -> None:
    if (module, callable_name) in cfg.allowed_pickle_globals:
        return
    root = module.split(".", maxsplit=1)[0]
    sev: Literal["CRITICAL", "MEDIUM"] = (
        "CRITICAL"
        if root in cfg.dangerous_pickle_modules or callable_name in cfg.dangerous_pickle_callables
        else "MEDIUM"
    )
    hits.append(
        PickleHit(
            module=module,
            callable_name=callable_name,
            opcode=opcode,
            offset=offset,
            severity_hint=sev,
        )
    )


def scan_pickle_stream(
    fp: IO[bytes],
    cfg: SiftsecConfig,
    *,
    max_ops: int | None = None,
    timeout_s: float | None = None,
) -> PickleScanResult:
    """Disassemble pickle opcodes statically without instantiating any objects."""
    op_limit = max_ops if max_ops is not None else cfg.max_pickle_ops
    deadline = time.monotonic() + (timeout_s if timeout_s is not None else cfg.per_file_timeout_s)
    strings: list[str] = []
    memo: dict[int, str] = {}
    hits: list[PickleHit] = []

    try:
        for n, (op, arg, pos) in enumerate(pickletools.genops(fp)):
            if n > op_limit:
                return PickleScanResult(hits=hits, error="max_ops_exceeded")
            if n % 4096 == 0 and time.monotonic() > deadline:
                return PickleScanResult(hits=hits, error="timeout_exceeded")

            name = op.name
            if name in _STRING_PUSH_OPS and isinstance(arg, str):
                strings.append(arg)
                if len(strings) > 8:
                    del strings[:-8]
            elif name == "MEMOIZE":
                memo[len(memo)] = strings[-1] if strings else ""
            elif name in ("BINPUT", "LONG_BINPUT") and isinstance(arg, int):
                memo[arg] = strings[-1] if strings else ""
            elif name in ("BINGET", "LONG_BINGET", "GET") and isinstance(arg, int):
                strings.append(memo.get(arg, ""))
                if len(strings) > 8:
                    del strings[:-8]
            elif name == "DUP" and strings:
                strings.append(strings[-1])
            elif name == "POP" and strings:
                strings.pop()
            elif name in ("GLOBAL", "INST"):
                mod, _, attr = str(arg).partition(" ")
                _classify_global(mod, attr, name, pos, cfg, hits)
            elif name == "STACK_GLOBAL" and len(strings) >= 2:
                _classify_global(strings[-2], strings[-1], name, pos, cfg, hits)
    except _LimitExceededError:
        return PickleScanResult(hits=hits, error="max_zip_bytes_exceeded")
    except (ValueError, EOFError, pickle.UnpicklingError, IndexError, KeyError, OSError) as exc:
        # Truncated or obfuscated pickles are suspicious themselves; report, never crash.
        return PickleScanResult(hits=hits, error=f"parse_error:{type(exc).__name__}")

    return PickleScanResult(hits=hits)


def sniff_model_format(path: Path) -> ModelFormat:
    """Identify model format via magic bytes before falling back to extension."""
    try:
        with path.open("rb") as f:
            head = f.read(16)
    except OSError:
        return "unknown"

    if head.startswith(b"PK\x03\x04"):
        return "torch_zip"
    if len(head) >= 2 and head[0] == 0x80 and head[1] in (2, 3, 4, 5):
        return "pickle"
    if head.startswith(b"GGUF"):
        return "gguf"
    if head.startswith(b"\x89HDF\r\n\x1a\n"):
        return "keras_h5"

    suffix = path.suffix.lower()
    if suffix == ".safetensors":
        return "safetensors"
    if suffix == ".onnx":
        return "onnx"
    if suffix in (".pkl", ".pickle", ".joblib"):
        return "pickle"
    return "unknown"


def validate_safetensors_header(path: Path, size_bytes: int, cfg: SiftsecConfig) -> bool:
    """Verify safetensors 8-byte header length and tensor data_offsets bounds."""
    if size_bytes < 8:
        return False
    try:
        with path.open("rb") as f:
            header_len = struct.unpack("<Q", f.read(8))[0]
            if header_len == 0 or header_len > cfg.max_safetensors_header:
                return False
            if 8 + header_len > size_bytes:
                return False
            raw_header = f.read(header_len)
        header = json.loads(raw_header.decode("utf-8"))
        if not isinstance(header, dict):
            return False
        payload_size = size_bytes - 8 - header_len
        for key, meta in header.items():
            if key == "__metadata__":
                continue
            if not isinstance(meta, dict):
                return False
            offsets = meta.get("data_offsets")
            if not isinstance(offsets, list) or len(offsets) != 2:
                return False
            start, end = offsets
            if not (isinstance(start, int) and isinstance(end, int)):
                return False
            if start < 0 or end < start or end > payload_size:
                return False
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, struct.error):
        return False
    return True


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_model_file(path: Path, cfg: SiftsecConfig) -> LocalModelFileAttrs:
    """Safely inspect a local model artifact without executing serialized code."""
    size_bytes = path.stat().st_size
    fmt = sniff_model_format(path)
    file_hash = _sha256_file(path)

    if fmt == "safetensors":
        ok = validate_safetensors_header(path, size_bytes, cfg)
        return LocalModelFileAttrs(
            path=str(path),
            size_bytes=size_bytes,
            sha256=file_hash,
            format=fmt,
            safetensors_header_ok=ok,
        )

    if fmt == "pickle":
        with path.open("rb") as f:
            res = scan_pickle_stream(f, cfg)
        return LocalModelFileAttrs(
            path=str(path),
            size_bytes=size_bytes,
            sha256=file_hash,
            format=fmt,
            pickle_hits=res.hits,
            scan_error=res.error,
        )

    if fmt == "torch_zip":
        hits: list[PickleHit] = []
        scan_error: str | None = None
        ratio_exceeded = False
        cumulative_bytes = 0
        try:
            with zipfile.ZipFile(path, "r") as zf:
                for info in zf.infolist():
                    if ".." in Path(info.filename).parts or info.filename.startswith("/"):
                        scan_error = "suspicious_zip_path"
                        break
                    if not info.filename.endswith(".pkl"):
                        continue
                    cumulative_bytes += info.file_size
                    ratio = info.file_size / max(info.compress_size, 1)
                    if (
                        info.file_size > cfg.max_zip_uncompressed_bytes
                        or cumulative_bytes > cfg.max_zip_uncompressed_bytes
                        or ratio > cfg.max_zip_ratio
                    ):
                        ratio_exceeded = True
                        scan_error = "zip_limit_exceeded"
                        break
                    with zf.open(info, "r") as member:
                        limited = _LimitedReader(member, cfg.max_zip_uncompressed_bytes)
                        res = scan_pickle_stream(limited, cfg)  # type: ignore[arg-type]
                        hits.extend(res.hits)
                        if res.error:
                            scan_error = res.error
        except (zipfile.BadZipFile, OSError) as exc:
            scan_error = f"zip_error:{type(exc).__name__}"

        return LocalModelFileAttrs(
            path=str(path),
            size_bytes=size_bytes,
            sha256=file_hash,
            format=fmt,
            pickle_hits=hits,
            scan_error=scan_error,
            zip_ratio_exceeded=ratio_exceeded,
        )

    return LocalModelFileAttrs(
        path=str(path),
        size_bytes=size_bytes,
        sha256=file_hash,
        format=fmt,
    )
