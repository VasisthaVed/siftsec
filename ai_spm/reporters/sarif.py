import json

from ai_spm.config import settings
from ai_spm.engine.models import Finding, Severity, Status


class SARIFReporter:
    """Produces OASIS SARIF v2.1.0 JSON compatible with GitHub Code Scanning."""

    @staticmethod
    def _map_severity(severity: Severity) -> str:
        if severity in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if severity == Severity.MEDIUM:
            return "warning"
        return "note"

    def export(self, findings: list[Finding]) -> str:
        rules_map = {}
        results = []

        for f in findings:
            if f.status == Status.FAILED:
                rule_id = f.rule_id
                if rule_id not in rules_map:
                    rules_map[rule_id] = {
                        "id": rule_id,
                        "shortDescription": {"text": f.rule_title},
                        "help": {"text": f.remediation},
                        "properties": {
                            "security-severity": "8.5" if f.severity == Severity.CRITICAL else "6.5"
                        },
                    }

                results.append(
                    {
                        "ruleId": rule_id,
                        "level": self._map_severity(f.severity),
                        "message": {"text": f.message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f.resource_arn},
                                }
                            }
                        ],
                    }
                )

        sarif_payload = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": settings.app_name,
                            "version": settings.app_version,
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

        return json.dumps(sarif_payload, indent=2)
