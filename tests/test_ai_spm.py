from typer.testing import CliRunner

from ai_spm.cli import app
from ai_spm.collectors.mock import MockCollector
from ai_spm.config import AISPMConfig
from ai_spm.engine.models import CloudProvider, CloudResource, Finding, Severity, Status
from ai_spm.engine.runner import ScanRunner
from ai_spm.reporters.console import ConsoleReporter
from ai_spm.rules.registry import registry

runner = CliRunner()


def test_models_creation() -> None:
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
        rule_id="AI-SPM-S3-001",
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


def test_mock_collector_and_runner() -> None:
    collector = MockCollector()
    resources = collector.collect()
    assert len(resources) >= 5

    scan_runner = ScanRunner(collector=collector)
    findings = scan_runner.run()
    assert len(findings) > 0

    # Ensure rule failures were correctly caught
    failed = [f for f in findings if f.status == Status.FAILED]
    assert len(failed) >= 3


def test_rules_registry() -> None:
    rules = registry.get_rules()
    assert len(rules) >= 7

    s3_rules = registry.get_rules(services=["s3"])
    assert len(s3_rules) >= 3
    for r in s3_rules:
        assert r.service == "s3"


def test_cli_list_rules() -> None:
    result = runner.invoke(app, ["list-rules"])
    assert result.exit_code == 0
    assert "AI-SPM-S3-001" in result.output
    assert "AI-SPM-BEDROCK-003" in result.output


def test_cli_scan_demo() -> None:
    result = runner.invoke(app, ["scan", "--demo", "--fail-on", "CRITICAL"])
    # Demo has critical findings so it exits with 1
    assert result.exit_code == 1
    assert "AI Security Posture Score" in result.output
    assert "AI-SPM-S3-001" in result.output


def test_dynamic_config_and_weighted_score(monkeypatch) -> None:
    monkeypatch.setenv("AI_SPM_APP_NAME", "Custom-AI-SPM")
    cfg = AISPMConfig()
    assert cfg.app_name == "Custom-AI-SPM"
    assert ".pt" in cfg.insecure_model_extensions

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
