"""Custom exception hierarchy for TensorGuard (AI-SPM)."""


class AISPMError(Exception):
    """Base exception for fatal TensorGuard errors mapped to CLI exit codes."""

    exit_code: int = 2


class ConfigError(AISPMError):
    """Raised when configuration or CLI flags are invalid."""


class CredentialsError(AISPMError):
    """Raised when no usable cloud credentials are available."""


class CollectorError(AISPMError):
    """Internal collector failure converted to a CoverageGap by the orchestrator."""
