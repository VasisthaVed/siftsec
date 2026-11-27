# SPDX-License-Identifier: Apache-2.0
import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from siftsec.cli import app
from siftsec.collectors.base import BaseCollector
from siftsec.collectors.mock import MockCollector
from siftsec.config import SiftsecConfig
from siftsec.engine.fingerprint import fingerprint
from siftsec.engine.models import CloudProvider, CloudResource, Finding, Severity, Status
from siftsec.engine.runner import ScanRunner
from siftsec.engine.scoring import exit_code, posture_score
from siftsec.reporters.console import ConsoleReporter
from siftsec.rules.base import BaseRule
from siftsec.rules.registry import registry
from siftsec.utils.redact import redact

runner = CliRunner()


def test_models_and_severity_ordering() -> None:
    assert Severity.CRITICAL >= Severity.HIGH >= Severity.MEDIUM >= Severity.LOW

    res = CloudResource(
        arn="arn:aws:s3:::test-bucket",
        id="test-bucket",
        name="test-bucket",
        service="s3",
        provider=CloudProvider.AWS,
    )
    assert res.name == "test-bucket"
    assert res.is_ai_workload is True

    finding = Finding(
        rule_id="SIFTSEC-S3-001",
        rule_title="Test Rule",
        service="s3",
        resource_arn=res.arn,
        resource_id=res.id,
        status=Status.FAILED,
        severity=Severity.HIGH,
        message="Failed encryption",
        remediation="Fix it",
    )
    assert finding.status == Status.FAILED
    assert len(finding.fingerprint) == 32

    with pytest.raises(ValidationError):
        Finding(
            rule_id="SIFTSEC-S3-001",
            rule_title="Test Rule",
            service="s3",
            resource_arn=res.arn,
            resource_id=res.id,
            status=Status.FAILED,
            severity=Severity.HIGH,
            message="Failed without remediation",
            remediation="",
        )


def test_fingerprint_and_redaction() -> None:
    fp1 = fingerprint("SIFTSEC-S3-001", "arn:aws:s3:::b1", "scope-a")
    fp2 = fingerprint("SIFTSEC-S3-001", "arn:aws:s3:::b1", "scope-a")
    fp3 = fingerprint("SIFTSEC-S3-001", "arn:aws:s3:::b1", "scope-b")
    assert fp1 == fp2
    assert fp1 != fp3

    raw = "Found key sk-proj-1234567890abcdefghij and AKIAIOSFODNN7EXAMPLE"
    masked = redact(raw)
    assert "1234567890" not in masked
    assert "IOSFODNN7EXAMPLE" not in masked
    assert "sk-p****" in masked
    assert "AKIA****" in masked


def test_runner_exception_barrier_and_gaps() -> None:
    class _SingleResourceCollector(BaseCollector):
        def collect(self) -> list[CloudResource]:
            return [
                CloudResource(
                    arn="arn:aws:s3:::gap-bucket",
                    id="gap-bucket",
                    name="gap-bucket",
                    service="s3",
                    gaps={"encryption": "AccessDenied"},
                )
            ]

    class _CrashingRule(BaseRule):
        rule_id = "SIFTSEC-TEST-999"
        title = "Crashing Test Rule"
        description = "Simulates an unexpected rule bug."
        severity = Severity.LOW
        service = "s3"

        def evaluate(self, resource: CloudResource) -> Finding:
            raise RuntimeError("boom")

    registry.register(_CrashingRule())
    try:
        findings = ScanRunner(collector=_SingleResourceCollector(), services=["s3"]).run()
        error_findings = [f for f in findings if f.rule_id == "SIFTSEC-TEST-999"]
        assert len(error_findings) == 1
        assert error_findings[0].status is Status.ERROR
        assert error_findings[0].error_code == "RuntimeError"
    finally:
        registry._rules.pop("SIFTSEC-TEST-999", None)


def test_mock_collector_and_runner() -> None:
    collector = MockCollector()
    resources = collector.collect()
    assert len(resources) >= 5

    scan_runner = ScanRunner(collector=collector)
    findings = scan_runner.run()
    assert len(findings) > 0

    failed = [f for f in findings if f.status == Status.FAILED]
    assert len(failed) >= 3


def test_rules_registry() -> None:
    rules = registry.get_rules()
    assert len(rules) >= 8

    s3_rules = registry.get_rules(services=["s3"])
    assert len(s3_rules) >= 3
    for r in s3_rules:
        assert r.service == "s3"


def test_cli_list_rules() -> None:
    result = runner.invoke(app, ["list-rules"])
    assert result.exit_code == 0
    assert "SIFTSEC-S3-001" in result.output
    assert "SIFTSEC-BEDROCK-003" in result.output


def test_cli_scan_demo() -> None:
    findings = ScanRunner(collector=MockCollector()).run()
    assert not any(f.status is Status.ERROR for f in findings)

    result = runner.invoke(app, ["scan", "--demo", "--fail-on", "CRITICAL"])
    assert result.exit_code == 1
    assert "AI Security Posture Score" in result.output
    assert "SIFTSEC-S3-001" in result.output


def test_dynamic_config_and_weighted_score(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIFTSEC_APP_NAME", "Custom-SIFTSEC")
    cfg = SiftsecConfig()
    assert cfg.app_name == "Custom-SIFTSEC"
    assert ".pt" in cfg.insecure_model_extensions

    # Empty findings must return None (unscanned != 100)
    assert posture_score([], cfg.severity_weights) is None
    assert exit_code([], Severity.HIGH) == 0

    reporter = ConsoleReporter()
    findings = [
        Finding(
            rule_id="R1",
            rule_title="T1",
            service="s3",
            resource_arn="arn:1",
            resource_id="res1",
            status=Status.PASSED,
            severity=Severity.CRITICAL,
            message="ok",
            remediation="none",
        ),
        Finding(
            rule_id="R2",
            rule_title="T2",
            service="s3",
            resource_arn="arn:2",
            resource_id="res2",
            status=Status.FAILED,
            severity=Severity.CRITICAL,
            message="bad",
            remediation="fix",
        ),
    ]
    assert reporter.calculate_score(findings) == 50
    assert exit_code(findings, Severity.CRITICAL) == 1
