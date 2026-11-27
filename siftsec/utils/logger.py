"""Structured stderr logger with automatic secret redaction."""

import json
import logging
import sys
from datetime import UTC, datetime

from rich.console import Console
from rich.logging import RichHandler

from siftsec.utils.redact import redact


class _RedactingFilter(logging.Filter):
    """Ensure no matched secret values reach stderr logs or tracebacks."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if record.args:
            if isinstance(record.args, tuple):
                record.args = tuple(redact(a) if isinstance(a, str) else a for a in record.args)
            elif isinstance(record.args, dict):
                record.args = {
                    k: redact(v) if isinstance(v, str) else v for k, v in record.args.items()
                }
        return True


class _JsonFormatter(logging.Formatter):
    """Emit structured, secret-redacted JSON log lines."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact(record.getMessage()),
        }
        return json.dumps(payload, separators=(",", ":"))


def configure_logging(
    *,
    verbose: bool = False,
    quiet: bool = False,
    json_logs: bool = False,
) -> logging.Logger:
    """Configure root siftsec logger to write redacted Rich or JSON output to stderr."""
    level = logging.DEBUG if verbose else logging.ERROR if quiet else logging.WARNING
    handler: logging.Handler
    if json_logs:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(_JsonFormatter())
    else:
        err_console = Console(stderr=True)
        handler = RichHandler(
            console=err_console,
            show_time=False,
            show_path=verbose,
            rich_tracebacks=verbose,
        )
    handler.addFilter(_RedactingFilter())

    logger = logging.getLogger("siftsec")
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger
