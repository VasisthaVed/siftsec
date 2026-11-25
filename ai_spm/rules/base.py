"""Abstract BaseRule contract and Finding builder helpers."""

from abc import ABC, abstractmethod
from typing import ClassVar

from ai_spm.engine.fingerprint import fingerprint
from ai_spm.engine.models import CloudResource, Finding, Severity, Status
from ai_spm.utils.redact import redact


class BaseRule(ABC):
    """Base interface for all pure, side-effect-free AI-SPM security rules."""

    rule_id: ClassVar[str]
    title: ClassVar[str]
    description: ClassVar[str]
    severity: ClassVar[Severity]
    service: ClassVar[str]
    required_attrs: ClassVar[tuple[str, ...]] = ()
    mitre_atlas: ClassVar[list[str]] = []
    owasp_llm: ClassVar[list[str]] = []
    nist_ai_rmf: ClassVar[list[str]] = []

    @abstractmethod
    def evaluate(self, resource: CloudResource) -> Finding:
        """Evaluate resource and return a Finding without performing I/O."""

    def _build(
        self,
        resource: CloudResource,
        status: Status,
        message: str,
        *,
        remediation: str = "",
        scope: str = "",
        evidence: dict[str, str] | None = None,
        error_code: str | None = None,
    ) -> Finding:
        safe_msg = redact(message)
        safe_remediation = redact(remediation)
        safe_evidence = {k: redact(v) for k, v in (evidence or {}).items()}
        return Finding(
            rule_id=self.rule_id,
            rule_title=self.title,
            service=self.service,
            resource_arn=resource.arn,
            resource_id=resource.id,
            resource_name=resource.name,
            status=status,
            severity=self.severity,
            message=safe_msg,
            remediation=safe_remediation,
            evidence=safe_evidence,
            error_code=error_code,
            mitre_atlas=list(self.mitre_atlas),
            owasp_llm=list(self.owasp_llm),
            nist_ai_rmf=list(self.nist_ai_rmf),
            region=resource.region,
            fingerprint=fingerprint(self.rule_id, resource.arn, scope),
        )

    def passed(self, resource: CloudResource, message: str) -> Finding:
        return self._build(resource, Status.PASSED, message)

    def failed(
        self,
        resource: CloudResource,
        message: str,
        remediation: str,
        *,
        scope: str = "",
        evidence: dict[str, str] | None = None,
    ) -> Finding:
        return self._build(
            resource,
            Status.FAILED,
            message,
            remediation=remediation,
            scope=scope,
            evidence=evidence,
        )

    def skipped(self, resource: CloudResource, reason: str) -> Finding:
        return self._build(resource, Status.SKIPPED, reason)

    def error(self, resource: CloudResource, code: str, message: str) -> Finding:
        return self._build(resource, Status.ERROR, message, error_code=code)
