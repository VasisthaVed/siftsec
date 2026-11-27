import json

import pytest

from siftsec._core_loader import HAS_RUST, parse_json_bounded
from siftsec.engine.models import Severity
from siftsec.ingest import ingest_json_bytes, ingest_sarif_bytes


@pytest.mark.parametrize(
    "payload",
    [
        b"[" * 100_000,
        b'{"a":' * 10_000,
        b"\x80\x04\x95\x10\x00",
        b"\xff\xfe\xfd",
    ],
)
def test_bounded_json_rejects_hostile_inputs_without_crash(payload: bytes) -> None:
    with pytest.raises((ValueError, MemoryError)):
        parse_json_bounded(payload, max_depth=64)


def test_bounded_json_depth_and_size_caps() -> None:
    ok_payload = (b"[" * 4) + b"1" + (b"]" * 4)
    assert parse_json_bounded(ok_payload, max_depth=4) == [[[[1]]]]

    too_deep = (b"[" * 5) + b"1" + (b"]" * 5)
    with pytest.raises(ValueError, match="depth"):
        parse_json_bounded(too_deep, max_depth=4)

    with pytest.raises(MemoryError, match="maximum size"):
        parse_json_bounded(b"{}", max_depth=4, max_bytes=1)

    assert isinstance(HAS_RUST, bool)


def test_sarif_ingest_adapter_normalizes_modelaudit_and_mcpiranha() -> None:
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ModelAudit"}},
                "results": [
                    {
                        "ruleId": "MA-PICKLE-001",
                        "level": "error",
                        "message": {"text": "Suspicious posix.system opcode"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "weights.pkl"}}}
                        ],
                        "properties": {"sha256": "abc123"},
                    }
                ],
            },
            {
                "tool": {"driver": {"name": "MCPiranha"}},
                "results": [
                    {
                        "ruleId": "MCP-RUGPULL-001",
                        "level": "warning",
                        "message": {"text": "Tool description modified"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": ".mcp.json"}}}
                        ],
                        "properties": {"asset_id": "mcp://filesystem"},
                    }
                ],
            },
        ],
    }

    findings = ingest_sarif_bytes(json.dumps(sarif).encode("utf-8"))
    assert len(findings) == 2
    assert findings[0].schema_version == 1
    assert findings[0].source_tool == "ModelAudit"
    assert findings[0].asset_kind == "model"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].component_hash == "abc123"

    assert findings[1].source_tool == "MCPiranha"
    assert findings[1].asset_kind == "mcp_server"
    assert findings[1].asset_id == "mcp://filesystem"
    assert findings[1].severity == Severity.MEDIUM


def test_sarif_and_json_adapters_cover_prowler_trivy_skill_and_mcpvuln() -> None:
    sarif_extra = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Trivy"}},
                "results": [
                    {
                        "ruleId": "CVE-2025-1",
                        "level": "note",
                        "message": {"text": "Container vuln"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "Dockerfile"}}}
                        ],
                    }
                ],
            },
            {
                "tool": {"driver": {"name": "ClawHub"}},
                "results": [
                    {
                        "ruleId": "SKILL-001",
                        "level": "error",
                        "message": {"text": "Malicious SKILL.md"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "skills/SKILL.md"}}}
                        ],
                    }
                ],
            },
            {
                "tool": {"driver": {"name": "Prowler"}},
                "results": [
                    {
                        "ruleId": "s3_bucket_public",
                        "level": "error",
                        "message": {"text": "Public bucket"},
                    }
                ],
            },
            {
                "tool": {"driver": {"name": "Semgrep"}},
                "results": [
                    {
                        "ruleId": "py-eval",
                        "level": "warning",
                        "message": {"text": "eval()"},
                    }
                ],
            },
        ],
    }
    sarif_findings = ingest_sarif_bytes(json.dumps(sarif_extra).encode("utf-8"))
    assert [f.asset_kind for f in sarif_findings] == [
        "container",
        "skill",
        "cloud_resource",
        "code",
    ]

    with pytest.raises(ValueError, match="SARIF root"):
        ingest_sarif_bytes(b"[]")
    with pytest.raises(ValueError, match="runs"):
        ingest_sarif_bytes(b"{}")

    prowler_json = json.dumps(
        [
            {"CheckID": "s3_pass", "Status": "PASS", "Severity": "low", "ResourceArn": "arn:ok"},
            {
                "CheckID": "s3_public",
                "Status": "FAIL",
                "Severity": "critical",
                "ResourceArn": "arn:aws:s3:::ai-weights",
                "StatusExtended": "Bucket is public",
            },
        ]
    ).encode("utf-8")
    p_findings = ingest_json_bytes(prowler_json, source_tool="Prowler")
    assert len(p_findings) == 1
    assert p_findings[0].severity == Severity.CRITICAL
    assert p_findings[0].asset_kind == "cloud_resource"

    mcpvuln_json = json.dumps(
        {
            "vulnerabilities": [
                {
                    "id": "MCPV-1",
                    "severity": "high",
                    "server": "github-mcp",
                    "description": "Token leak",
                    "sha256": "deadbeef",
                }
            ]
        }
    ).encode("utf-8")
    m_findings = ingest_json_bytes(mcpvuln_json, source_tool="mcpvuln")
    assert len(m_findings) == 1
    assert m_findings[0].asset_kind == "mcp_server"
    assert m_findings[0].component_hash == "deadbeef"
