import json
from pathlib import Path

from typer.testing import CliRunner

from ai_spm.cli import app
from ai_spm.engine.diff import diff_scans
from ai_spm.engine.graph import evaluate_attack_paths
from ai_spm.engine.models import CloudProvider, CloudResource, Severity, Status

runner = CliRunner()


def test_attack_path_correlation_detects_all_three_critical_chains() -> None:
    resources = [
        CloudResource(
            arn="arn:aws:sagemaker:us-east-1:123:notebook-instance/nb-exposed",
            id="nb-exposed",
            name="nb-exposed",
            service="sagemaker",
            kind="sagemaker_notebook",
            metadata={
                "kind": "sagemaker_notebook",
                "direct_internet": "Enabled",
                "role_arn": "arn:aws:iam::123:role/s3-admin",
            },
        ),
        CloudResource(
            arn="arn:aws:iam::123:role/s3-admin",
            id="s3-admin",
            name="s3-admin",
            service="iam",
            kind="iam_role",
            metadata={
                "kind": "iam_role",
                "statements": [{"effect": "Allow", "actions": ["s3:*"], "resources": ["*"]}],
            },
        ),
        CloudResource(
            arn="k8s://pod/prod/priv-gpu",
            id="priv-gpu",
            name="priv-gpu",
            service="k8s",
            kind="k8s_pod",
            provider=CloudProvider.KUBERNETES,
            metadata={"kind": "k8s_pod", "privileged": True, "node_name": "gpu-node-1"},
        ),
        CloudResource(
            arn="k8s://node/gpu-node-1",
            id="gpu-node-1",
            name="gpu-node-1",
            service="k8s",
            kind="k8s_node",
            provider=CloudProvider.KUBERNETES,
            metadata={"kind": "k8s_node", "toolkit_version": "1.17.7"},
        ),
        CloudResource(
            arn="arn:aws:bedrock:us-east-1:123:data-source/ds-rag",
            id="ds-rag",
            name="ds-rag",
            service="bedrock",
            kind="bedrock_data_source",
            metadata={
                "kind": "bedrock_data_source",
                "knowledge_base_id": "kb-1",
                "vector_store_arn": "arn:aws:opensearch:us-east-1:123:domain/rag-vec",
            },
        ),
        CloudResource(
            arn="arn:aws:opensearch:us-east-1:123:domain/rag-vec",
            id="rag-vec",
            name="rag-vec",
            service="opensearch",
            kind="opensearch_domain",
            metadata={"kind": "opensearch_domain", "public_principal": True},
        ),
    ]

    findings = evaluate_attack_paths(resources)
    assert {f.rule_id for f in findings} == {
        "AI-SPM-PATH-001",
        "AI-SPM-PATH-002",
        "AI-SPM-PATH-003",
    }
    for f in findings:
        assert f.status == Status.FAILED
        assert f.severity == Severity.CRITICAL
        assert f.evidence.get("scope") == "path"
        assert "->" in f.evidence.get("path", "")


def test_scan_diff_and_compliance_cli(tmp_path: Path) -> None:
    old_file = tmp_path / "old.json"
    new_file = tmp_path / "new.json"
    old_file.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "fingerprint": "fp-fixed",
                        "rule_id": "AI-SPM-S3-001",
                        "resource_arn": "arn:1",
                        "status": "FAILED",
                        "severity": "HIGH",
                    },
                    {
                        "fingerprint": "fp-same",
                        "rule_id": "AI-SPM-S3-002",
                        "resource_arn": "arn:2",
                        "status": "FAILED",
                        "severity": "MEDIUM",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    new_file.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "fingerprint": "fp-same",
                        "rule_id": "AI-SPM-S3-002",
                        "resource_arn": "arn:2",
                        "status": "FAILED",
                        "severity": "HIGH",
                    },
                    {
                        "fingerprint": "fp-new",
                        "rule_id": "AI-SPM-K8S-001",
                        "resource_arn": "k8s://node/1",
                        "status": "FAILED",
                        "severity": "CRITICAL",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    diff = diff_scans(old_file, new_file)
    assert [x["fingerprint"] for x in diff.added] == ["fp-new"]
    assert [x["fingerprint"] for x in diff.fixed] == ["fp-fixed"]
    assert diff.unchanged_count == 1
    assert len(diff.changed_severity) == 1
    assert diff.changed_severity[0]["new_severity"] == "HIGH"

    res_diff = runner.invoke(app, ["diff", str(old_file), str(new_file), "--fail-on-new"])
    assert res_diff.exit_code == 1

    res_comp = runner.invoke(app, ["report-compliance", "--framework", "owasp-llm"])
    assert res_comp.exit_code == 0
    comp_data = json.loads(res_comp.output)
    assert comp_data["framework"] == "owasp-llm"
    assert len(comp_data["controls"]) > 0
