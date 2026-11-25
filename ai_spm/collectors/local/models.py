"""Local model artifact collector using iterative, symlink-safe traversal."""

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ai_spm.collectors.base import BaseCollector
from ai_spm.config import AISPMConfig, settings
from ai_spm.engine.attrs import LocalModelFileAttrs
from ai_spm.engine.models import CloudProvider, CloudResource
from ai_spm.scanners.pickle_scanner import scan_model_file, sniff_model_format

_SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "__pycache__", ".mypy_cache"})


class LocalModelCollector(BaseCollector):
    """Scans local directories and HuggingFace caches for model weight artifacts."""

    def __init__(
        self,
        paths: list[Path] | None = None,
        cfg: AISPMConfig | None = None,
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

    def _scan_one(self, path: Path) -> CloudResource:
        abs_str = str(path.resolve())
        arn_hash = hashlib.sha256(abs_str.encode()).hexdigest()[:16]
        arn = f"local://file/{arn_hash}"

        try:
            attrs = scan_model_file(path, self.cfg)
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
                metadata=attrs.model_dump(),
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
        with ThreadPoolExecutor(max_workers=self.cfg.max_workers) as pool:
            return list(pool.map(self._scan_one, files))
