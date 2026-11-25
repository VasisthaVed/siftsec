from abc import ABC, abstractmethod

from ai_spm.engine.models import CloudResource, Finding, Severity


class BaseRule(ABC):
    rule_id: str
    title: str
    description: str
    severity: Severity
    service: str
    mitre_atlas: list[str] = []
    owasp_llm: list[str] = []
    nist_ai_rmf: list[str] = []

    @abstractmethod
    def evaluate(self, resource: CloudResource) -> Finding:
        """Evaluate resource and return a Finding."""
        pass
