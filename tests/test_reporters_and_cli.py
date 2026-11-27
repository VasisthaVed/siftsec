# SPDX-License-Identifier: Apache-2.0
"""Tests for JSON, Markdown, SARIF reporters, atomic_write_secure, and CLI doctor."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from siftsec.cli import app
from siftsec.collectors.mock import MockCollector
from siftsec.config import settings
from siftsec.engine.models import CoverageGap, ScanSummary, Severity, Status
from siftsec.engine.runner import ScanRunner
from siftsec.engine.scoring import posture_score
from siftsec.errors import AISPMError
from siftsec.reporters.json_rep import JSONReporter
from siftsec.reporters.markdown import MarkdownReporter
from siftsec.reporters.sarif import SARIFReporter
from siftsec.utils.fs import atomic_write_secure

runner = CliRunner()


def _sample_summary() -> ScanSummary:
    from datetime import UTC, datetime

    findings = ScanRunner(MockCollector()).run()
    return ScanSummary(
        total_resources=7,
        ai_resources=7,
        findings=findings,
        posture_score=posture_score(findings, settings.severity_weights),
        coverage_gaps=[
            CoverageGap(
                service="bedrock", region="us-west-2", api="list_agents", error_code="AccessDenied"
            )
        ],
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        tool_version="0.1.0",
    )


def test_json_markdown_and_sarif_reporters() -> None:
    summary = _sample_summary()

    json_out = JSONReporter().export(summary)
    parsed_json = json.loads(json_out)
    assert parsed_json["schema_version"] == "1.0"
    assert len(parsed_json["findings"]) == len(summary.findings)

    md_out = MarkdownReporter().export(summary)
    assert "Siftsec SIFTSEC Report" in md_out
    assert "Coverage Gaps" in md_out

    sarif_out = SARIFReporter().export(summary.findings)
    sarif_doc = json.loads(sarif_out)
    assert sarif_doc["version"] == "2.1.0"
    first_result = sarif_doc["runs"][0]["results"][0]
    assert "siftsecFingerprint/v1" in first_result["partialFingerprints"]
    assert first_result["locations"][0]["logicalLocations"][0]["kind"] == "resource"


def test_markdown_escapes_hostile_resource_names() -> None:
    from datetime import UTC, datetime

    from siftsec.engine.models import Finding

    hostile = Finding(
        rule_id="SIFTSEC-S3-001",
        rule_title="Test",
        service="s3",
        resource_arn="arn:aws:s3:::evil|@here<script>",
        resource_id="evil|@here<script>",
        status=Status.FAILED,
        severity=Severity.HIGH,
        message="Bucket evil|@here<script> failed",
        remediation="Fix it",
    )
    summary = ScanSummary(
        total_resources=1,
        ai_resources=1,
        findings=[hostile],
        posture_score=0,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        tool_version="0.1.0",
    )
    md = MarkdownReporter().export(summary)
    assert "<script>" not in md
    assert "&lt;script&gt;" in md
    assert "@here" not in md  # zero-width space inserted after @


def test_atomic_write_secure(tmp_path: Path) -> None:
    target = tmp_path / "out.json"
    atomic_write_secure(target, '{"ok": true}')
    assert target.read_text(encoding="utf-8") == '{"ok": true}'

    with pytest.raises(AISPMError):
        atomic_write_secure(target, '{"ok": false}', force=False)

    atomic_write_secure(target, '{"ok": false}', force=True)
    assert target.read_text(encoding="utf-8") == '{"ok": false}'


def test_cli_doctor_version_and_formats() -> None:
    res_ver = runner.invoke(app, ["version"])
    assert res_ver.exit_code == 0
    assert "siftsec" in res_ver.output

    res_doc = runner.invoke(app, ["doctor"])
    assert res_doc.exit_code == 0
    assert "Siftsec Doctor" in res_doc.output

    res_json = runner.invoke(app, ["scan", "--demo", "--format", "json", "--fail-on", "CRITICAL"])
    assert res_json.exit_code == 1
    assert '"schema_version": "1.0"' in res_json.output
