"""Deterministic finding fingerprint generation (D-12)."""

import hashlib


def fingerprint(rule_id: str, resource_arn: str, scope: str = "") -> str:
    """Compute a stable 32-char SHA-256 fingerprint for deduplication and baselines."""
    payload = f"{rule_id}|{resource_arn}|{scope}".encode()
    return hashlib.sha256(payload).hexdigest()[:32]
