# SPDX-License-Identifier: Apache-2.0
"""OASIS SARIF v2.1.0 reporter for GitHub Code Scanning (Phase 4.4)."""

import json

from siftsec.config import settings
from siftsec.engine.models import Finding, Severity, Status

_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFORMATIONAL: "0.0",
}


class SARIFReporter:
    """Produces OASIS SARIF v2.1.0 JSON compatible with GitHub Code Scanning."""

    @staticmethod
    def _map_severity(severity: Severity, status: Status) -> str:
        if status is Status.ERROR:
            return "note"
        if severity in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if severity is Severity.MEDIUM:
            return "warning"
        return "note"

    def export(self, findings: list[Finding]) -> str:
        rules_map: dict[str, dict[str, object]] = {}
        results: list[dict[str, object]] = []

        ordered = sorted(
            (f for f in findings if f.status in (Status.FAILED, Status.ERROR)),
            key=lambda f: f.severity.rank,
            reverse=True,
        )

        for f in ordered:
            rule_id = f.rule_id
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": f.rule_title,
                    "shortDescription": {"text": f.rule_title},
                    "help": {"text": f.remediation or f.message},
                    "properties": {
                        "tags": f.mitre_atlas + f.owasp_llm,
                        "security-severity": _SECURITY_SEVERITY.get(f.severity, "5.5"),
                    },
                }

            safe_id = f.resource_id.replace(":", "_").replace("/", "_")
            loc_uri = f".siftsec/{f.service}/{f.region}/{safe_id}"

            result_obj: dict[str, object] = {
                "ruleId": rule_id,
                "level": self._map_severity(f.severity, f.status),
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": loc_uri},
                        },
                        "logicalLocations": [
                            {
                                "fullyQualifiedName": f.resource_arn,
                                "kind": "resource",
                            }
                        ],
                    }
                ],
                "partialFingerprints": {
                    "siftsecFingerprint/v1": f.fingerprint,
                },
            }
            if f.suppressed:
                result_obj["suppressions"] = [
                    {
                        "kind": "external",
                        "justification": f.suppression_reason or "Suppressed by baseline",
                    }
                ]
            results.append(result_obj)

        sarif_payload = {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata05/os/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": settings.app_name,
                            "version": settings.app_version,
                            "informationUri": "https://github.com/VasisthaVed/siftsec",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(sarif_payload, indent=2)
