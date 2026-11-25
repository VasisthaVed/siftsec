"""Rule evaluation runner with gap handling and per-rule exception barriers."""

import logging

from ai_spm.collectors.base import BaseCollector
from ai_spm.engine.context import ScanContext
from ai_spm.engine.models import Finding
from ai_spm.rules.registry import registry

log = logging.getLogger("ai_spm.runner")


class ScanRunner:
    """Executes registered rules against collected resources with error isolation."""

    def __init__(
        self,
        collector: BaseCollector,
        services: list[str] | None = None,
        context: ScanContext | None = None,
    ) -> None:
        self.collector = collector
        self.context = context or ScanContext(services=services)
        self.services = services if services is not None else self.context.services

    def run(self) -> list[Finding]:
        resources = self.collector.collect()
        findings: list[Finding] = []
        rules = registry.get_rules(self.services)

        for resource in resources:
            if self.context.ai_only and not resource.is_ai_workload:
                continue
            for rule in rules:
                if rule.service.lower() != resource.service.lower():
                    continue
                if (
                    rule.resource_kinds
                    and resource.kind
                    and resource.kind not in rule.resource_kinds
                ):
                    continue
                if (
                    rule.resource_kinds
                    and resource.kind
                    and resource.kind not in rule.resource_kinds
                ):
                    continue
                missing = [attr for attr in rule.required_attrs if attr in resource.gaps]
                if missing:
                    # Unknown != fail: surface unreadable attributes as ERROR findings (D-08).
                    findings.append(
                        rule.error(
                            resource,
                            code=resource.gaps[missing[0]],
                            message=f"Cannot evaluate {rule.rule_id}: missing {missing}",
                        )
                    )
                    continue
                try:
                    findings.append(rule.evaluate(resource))
                except Exception as exc:  # noqa: BLE001 - barrier isolates single-rule bugs
                    log.exception("Rule %s crashed on %s", rule.rule_id, resource.arn)
                    findings.append(rule.error(resource, code=type(exc).__name__, message=str(exc)))

        return findings
