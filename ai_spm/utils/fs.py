"""Cross-platform atomic file writing with strict permissions."""

import os
import tempfile
from pathlib import Path

from ai_spm.errors import AISPMError


def atomic_write_secure(path: Path, data: str, *, force: bool = False) -> None:
    """Write text atomically to path via temp file + os.replace with 0600 mode on POSIX."""
    if path.exists():
        if not path.is_file():
            raise AISPMError(f"Refusing to write to non-regular file: {path}")
        if not force:
            raise AISPMError(f"Output file already exists (pass --force to overwrite): {path}")

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp_tensorguard_")
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
    except Exception:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise
