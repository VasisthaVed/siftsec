from ai_spm.collectors.base import BaseCollector
from ai_spm.engine.models import Finding
from ai_spm.rules.registry import registry


class ScanRunner:
    def __init__(self, collector: BaseCollector, services: list[str] | None = None) -> None:
        self.collector = collector
        self.services = services

    def run(self) -> list[Finding]:
        resources = self.collector.collect()
        findings: list[Finding] = []

        rules = registry.get_rules(self.services)

        for resource in resources:
            for rule in rules:
                if rule.service.lower() == resource.service.lower():
                    finding = rule.evaluate(resource)
                    findings.append(finding)

        return findings
