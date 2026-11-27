"""Unit tests for Phase 3 AWS rules, resource_kinds dispatch, and remediation escaping."""

import shlex

from siftsec.collectors.base import BaseCollector
from siftsec.engine.attrs import (
    BedrockAccountConfigAttrs,
    BedrockAgentAttrs,
    BedrockDataSourceAttrs,
    EC2SecurityGroupAttrs,
    ECRRepositoryAttrs,
    IamRoleAttrs,
    IngressRule,
    OpenSearchDomainAttrs,
    OpenSearchServerlessAttrs,
    SageMakerDomainAttrs,
    SageMakerEndpointConfigAttrs,
    SageMakerNotebookAttrs,
    SageMakerTrainingJobAttrs,
)
from siftsec.engine.models import CloudResource, Status
from siftsec.engine.runner import ScanRunner
from siftsec.rules.remediation import sh, tf


class _ListCollector(BaseCollector):
    def __init__(self, items: list[CloudResource]) -> None:
        self._items = items

    def collect(self) -> list[CloudResource]:
        return self._items


def _res(
    service: str,
    kind: str,
    name: str = "res-1",
    meta: dict[str, object] | None = None,
) -> CloudResource:
    return CloudResource(
        arn=f"arn:aws:{service}:us-east-1:123456789012:{kind}/{name}",
        id=name,
        name=name,
        service=service,
        kind=kind,
        region="us-east-1",
        account_id="123456789012",
        metadata=meta or {},
    )


def test_remediation_injection_escaping() -> None:
    hostile = "x'; rm -rf ~ #"
    escaped_cli = f"aws s3api list --bucket {sh(hostile)}"
    # shlex.split must parse the quoted name back as a single literal token
    assert shlex.split(escaped_cli)[-1] == hostile
    assert '\\"' in tf('a"b')


def test_sagemaker_rules_and_kind_dispatch() -> None:
    bad_nb = _res(
        "sagemaker",
        "sagemaker_notebook",
        "nb-bad",
        SageMakerNotebookAttrs(
            direct_internet_access="Enabled",
            root_access="Enabled",
            subnet_id=None,
            min_imdsv_version="1",
        ).model_dump(),
    )
    good_nb = _res(
        "sagemaker",
        "sagemaker_notebook",
        "nb-good",
        SageMakerNotebookAttrs(
            direct_internet_access="Disabled",
            root_access="Disabled",
            subnet_id="subnet-123",
            min_imdsv_version="2",
        ).model_dump(),
    )
    bad_ep = _res(
        "sagemaker",
        "sagemaker_endpoint_config",
        "ep-bad",
        SageMakerEndpointConfigAttrs(kms_key_id=None).model_dump(),
    )
    bad_job = _res(
        "sagemaker",
        "sagemaker_training_job",
        "job-bad",
        SageMakerTrainingJobAttrs(
            enable_network_isolation=False, image_is_aws_owned=False
        ).model_dump(),
    )
    bad_dom = _res(
        "sagemaker",
        "sagemaker_domain",
        "dom-bad",
        SageMakerDomainAttrs(app_network_access_type="PublicInternetOnly").model_dump(),
    )

    findings = ScanRunner(
        _ListCollector([bad_nb, good_nb, bad_ep, bad_job, bad_dom]),
        services=["sagemaker"],
    ).run()
    failed = {(f.resource_id, f.rule_id) for f in findings if f.status is Status.FAILED}
    passed = {(f.resource_id, f.rule_id) for f in findings if f.status is Status.PASSED}

    assert ("nb-bad", "SIFTSEC-SAGEMAKER-001") in failed
    assert ("nb-bad", "SIFTSEC-SAGEMAKER-002") in failed
    assert ("nb-bad", "SIFTSEC-SAGEMAKER-003") in failed
    assert ("nb-bad", "SIFTSEC-SAGEMAKER-007") in failed
    assert ("nb-good", "SIFTSEC-SAGEMAKER-002") in passed
    assert ("ep-bad", "SIFTSEC-SAGEMAKER-004") in failed
    assert ("job-bad", "SIFTSEC-SAGEMAKER-005") in failed
    assert ("dom-bad", "SIFTSEC-SAGEMAKER-006") in failed
    # Ensure notebook rule did not fire on domain
    assert all(f.resource_id != "dom-bad" or f.rule_id == "SIFTSEC-SAGEMAKER-006" for f in findings)


def test_bedrock_ecr_opensearch_iam_and_shadow_rules() -> None:
    b_log_off = _res(
        "bedrock",
        "bedrock_account_config",
        "log",
        BedrockAccountConfigAttrs(logging_enabled=False, bedrock_in_use=True).model_dump(),
    )
    b_ds = _res(
        "bedrock",
        "bedrock_data_source",
        "ds-1",
        BedrockDataSourceAttrs(knowledge_base_id="kb-1", kms_key_arn=None).model_dump(),
    )
    b_ag = _res(
        "bedrock",
        "bedrock_agent",
        "ag-1",
        BedrockAgentAttrs(guardrail_id="gr-1", customer_encryption_key_arn=None).model_dump(),
    )
    ecr_enh = _res(
        "ecr",
        "ecr_repository",
        "ecr-enh",
        ECRRepositoryAttrs(
            scan_on_push=False,
            registry_scan_type="ENHANCED",
            image_tag_mutability="MUTABLE",
            policy_allows_public=True,
        ).model_dump(),
    )
    os_dom = _res(
        "opensearch",
        "opensearch_domain",
        "vec-dom",
        {
            **OpenSearchDomainAttrs(
                vpc_id=None,
                fgac_enabled=False,
                node_to_node_encryption=False,
                public_principal=True,
            ).model_dump(),
            "in_vpc": False,
        },
    )
    os_aoss = _res(
        "opensearch",
        "opensearch_serverless",
        "vec-aoss",
        {
            **OpenSearchServerlessAttrs(network_public=True).model_dump(),
            "in_vpc": False,
        },
    )
    iam_role = _res(
        "iam",
        "iam_role",
        "bad-role",
        {
            **IamRoleAttrs(
                attached_managed_arns=["arn:aws:iam::aws:policy/AdministratorAccess"],
                trust_principals=["bedrock.amazonaws.com"],
                trust_has_source_condition=False,
            ).model_dump(),
            "has_wildcard_policy": True,
        },
    )
    sg_shadow = _res(
        "ec2",
        "ec2_security_group",
        "sg-ollama",
        EC2SecurityGroupAttrs(
            attached=True,
            ingress=[
                IngressRule(protocol="tcp", from_port=11430, to_port=11440, cidrs_v4=["0.0.0.0/0"])
            ],
        ).model_dump(),
    )

    findings = ScanRunner(
        _ListCollector([b_log_off, b_ds, b_ag, ecr_enh, os_dom, os_aoss, iam_role, sg_shadow])
    ).run()
    failed_ids = {f.rule_id for f in findings if f.status is Status.FAILED}
    passed_ids = {f.rule_id for f in findings if f.status is Status.PASSED}

    assert "SIFTSEC-BEDROCK-001" in failed_ids
    assert "SIFTSEC-BEDROCK-002" in failed_ids
    assert "SIFTSEC-BEDROCK-004" in failed_ids
    assert "SIFTSEC-ECR-001" in passed_ids  # ENHANCED scanning overrides scanOnPush=False
    assert "SIFTSEC-ECR-002" in failed_ids
    assert "SIFTSEC-ECR-003" in failed_ids
    assert "SIFTSEC-OPENSEARCH-002" in failed_ids
    assert "SIFTSEC-OPENSEARCH-003" in failed_ids
    assert "SIFTSEC-OPENSEARCH-004" in failed_ids
    assert "SIFTSEC-OPENSEARCH-007" in failed_ids
    assert "SIFTSEC-IAM-002" in failed_ids
    assert "SIFTSEC-IAM-003" in failed_ids
    assert "SIFTSEC-SHADOW-001" in failed_ids
