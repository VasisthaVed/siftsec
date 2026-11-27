# SPDX-License-Identifier: Apache-2.0
"""Secret redaction utilities applied at Finding construction and log output."""

import re
from collections.abc import Mapping

DEFAULT_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "github_pat": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    "openai_key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    "anthropic_key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
    "huggingface_token": re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
}


def _mask_match(match: re.Match[str]) -> str:
    value = match.group(0)
    prefix = value[:4] if len(value) > 4 else ""
    return f"{prefix}****"


def redact(
    text: str,
    patterns: Mapping[str, re.Pattern[str]] | None = None,
) -> str:
    """Mask any secret substrings in text, preserving a 4-char prefix for triage."""
    if not text:
        return text
    active = patterns if patterns is not None else DEFAULT_SECRET_PATTERNS
    masked = text
    for pat in active.values():
        masked = pat.sub(_mask_match, masked)
    return masked
