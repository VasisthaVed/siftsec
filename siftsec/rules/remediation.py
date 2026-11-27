# SPDX-License-Identifier: Apache-2.0
"""Injection-safe remediation rendering helpers (Phase 3.1)."""

import json
import shlex
from dataclasses import dataclass


def sh(value: str) -> str:
    """Shell-escape an untrusted resource name or region for CLI commands."""
    return shlex.quote(value)


def tf(value: str) -> str:
    """Escape an untrusted string for safe interpolation inside HCL double quotes."""
    return json.dumps(value)[1:-1]


@dataclass(frozen=True)
class Remediation:
    """Structured remediation guidance with shell- and HCL-safe rendering."""

    summary: str
    cli: tuple[str, ...] = ()
    terraform: str | None = None

    def render(self) -> str:
        parts = [self.summary]
        if self.cli:
            parts.append("CLI: " + " && ".join(self.cli))
        if self.terraform:
            parts.append(f"Terraform:\n{self.terraform}")
        return "\n".join(parts)
