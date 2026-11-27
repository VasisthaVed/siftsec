# SPDX-License-Identifier: Apache-2.0
"""Local model artifact collector using iterative, symlink-safe traversal."""

import hashlib
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from siftsec.collectors.base import BaseCollector
from siftsec.config import SiftsecConfig, settings
from siftsec.engine.attrs import LocalModelFileAttrs
from siftsec.engine.models import CloudProvider, CloudResource
from siftsec.scanners.pickle_scanner import scan_model_file, sniff_model_format

_SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "__pycache__", ".mypy_cache"})
_HF_MODEL_DIR_RE = re.compile(r"^models--([^/\\]+)--([^/\\]+)$")
_README_LICENSE_RE = re.compile(r"^license:\s*([A-Za-z0-9._-]+)", re.MULTILINE | re.IGNORECASE)


def _extract_provenance(path: Path) -> tuple[str | None, str | None, str | None]:
    """Extract offline HuggingFace repo/commit/license metadata if present."""
    source: str | None = None
    revision: str | None = None
    license_id: str | None = None

    parts = path.parts
    for idx, part in enumerate(parts):
        m = _HF_MODEL_DIR_RE.match(part)
        if m:
            source = f"hf://{m.group(1)}/{m.group(2)}"
            if idx + 2 < len(parts) and parts[idx + 1] == "snapshots":
                revision = parts[idx + 2]
            break

    parent = path.parent
    cfg_path = parent / "config.json"
    if cfg_path.is_file() and not cfg_path.is_symlink():
        try:
            with cfg_path.open("r", encoding="utf-8", errors="ignore") as f:
                data = json.loads(f.read(65536))
            if isinstance(data, dict) and isinstance(data.get("license"), str):
                license_id = data["license"].strip()
        except (OSError, ValueError):
            pass

    if not license_id:
        readme = parent / "README.md"
        if readme.is_file() and not readme.is_symlink():
            try:
                with readme.open("r", encoding="utf-8", errors="ignore") as f:
                    head = f.read(8192)
                lm = _README_LICENSE_RE.search(head)
                if lm:
                    license_id = lm.group(1).strip()
            except OSError:
                pass

    return source, revision, license_id


def _load_model_allowlist(paths: list[Path]) -> set[str] | None:
    """Load approved SHA-256 digests from .siftsec-models.lock if present."""
    digests: set[str] = set()
    found = False
    for base in paths:
        lock = (base if base.is_dir() else base.parent) / ".siftsec-models.lock"
        if lock.is_file() and not lock.is_symlink():
            found = True
            try:
                raw = json.loads(lock.read_text(encoding="utf-8"))
                for item in raw.get("models", []):
                    if isinstance(item, dict) and isinstance(item.get("sha256"), str):
                        digests.add(item["sha256"].lower())
                    elif isinstance(item, str):
                        digests.add(item.lower())
            except (OSError, ValueError):
                pass
    return digests if found else None


class LocalModelCollector(BaseCollector):
    """Scans local directories and HuggingFace caches for model weight artifacts."""

    def __init__(
        self,
        paths: list[Path] | None = None,
        cfg: SiftsecConfig | None = None,
        *,
        include_hf_cache: bool = False,
    ) -> None:
        self.cfg = cfg or settings
        self.paths = list(paths) if paths else [Path(".")]
        if include_hf_cache:
            hf_cache = Path("~/.cache/huggingface/hub").expanduser()
            if hf_cache.exists():
                self.paths.append(hf_cache)

    def _discover_model_files(self) -> list[Path]:
        target_exts = frozenset(
            ext.lower()
            for ext in (self.cfg.insecure_model_extensions + self.cfg.safe_model_extensions)
        )
        discovered: list[Path] = []
        stack = [p.resolve() for p in self.paths if p.exists()]

        while stack and len(discovered) < self.cfg.max_local_files:
            current = stack.pop()
            if current.is_symlink():
                continue
            if current.is_file():
                discovered.append(current)
                continue
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name not in _SKIP_DIRS:
                                stack.append(Path(entry.path))
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        p = Path(entry.path)
                        if p.suffix.lower() in target_exts or (
                            not p.suffix and sniff_model_format(p) in ("pickle", "torch_zip")
                        ):
                            discovered.append(p)
                            if len(discovered) >= self.cfg.max_local_files:
                                break
            except OSError:
                continue

        return discovered

    def _scan_one(self, path: Path, allowlist: set[str] | None = None) -> CloudResource:
        abs_str = str(path.resolve())
        arn_hash = hashlib.sha256(abs_str.encode()).hexdigest()[:16]
        arn = f"local://file/{arn_hash}"

        try:
            attrs = scan_model_file(path, self.cfg)
            source, revision, license_id = _extract_provenance(path)
            allowlist_match: bool | None = None
            if allowlist is not None and attrs.sha256:
                allowlist_match = attrs.sha256.lower() in allowlist
            enriched = attrs.model_copy(
                update={
                    "source": source,
                    "revision": revision,
                    "license_id": license_id,
                    "allowlist_match": allowlist_match,
                }
            )
            return CloudResource(
                arn=arn,
                id=path.name,
                name=path.name,
                service="local",
                kind="local_model_file",
                provider=CloudProvider.LOCAL,
                region="local",
                account_id="local",
                is_ai_workload=True,
                ai_reason="local model file",
                metadata=enriched.model_dump(),
            )
        except OSError as exc:
            fallback = LocalModelFileAttrs(
                path=abs_str,
                size_bytes=0,
                format="unknown",
                scan_error=type(exc).__name__,
            )
            return CloudResource(
                arn=arn,
                id=path.name,
                name=path.name,
                service="local",
                kind="local_model_file",
                provider=CloudProvider.LOCAL,
                region="local",
                account_id="local",
                is_ai_workload=True,
                ai_reason="local model file",
                gaps={"scan": type(exc).__name__},
                metadata=fallback.model_dump(),
            )

    def collect(self) -> list[CloudResource]:
        files = self._discover_model_files()
        if not files:
            return []
        allowlist = _load_model_allowlist(self.paths)
        with ThreadPoolExecutor(max_workers=self.cfg.max_workers) as pool:
            return list(pool.map(lambda p: self._scan_one(p, allowlist), files))
