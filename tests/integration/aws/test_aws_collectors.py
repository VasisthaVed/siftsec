"""Integration tests for SageMaker, Bedrock, ECR, OpenSearch, IAM, EC2, and AwsOrchestrator."""

import json

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from siftsec.collectors.aws.bedrock import BedrockCollector
from siftsec.collectors.aws.client import AwsClientFactory, AwsIdentity, resolve_identity
from siftsec.collectors.aws.ec2 import EC2SecurityGroupCollector
from siftsec.collectors.aws.ecr import ECRCollector
from siftsec.collectors.aws.iam import IAMCollector
from siftsec.collectors.aws.opensearch import OpenSearchCollector
from siftsec.collectors.aws.orchestrator import AwsOrchestrator
from siftsec.collectors.aws.sagemaker import SageMakerCollector
from siftsec.config import SiftsecConfig
from siftsec.engine.context import ScanContext


@pytest.fixture(autouse=True)
def _fake_aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


def test_ecr_and_ec2_collectors_with_moto() -> None:
    with mock_aws():
        cfg = SiftsecConfig()
        factory = AwsClientFactory(boto3.Session(region_name="us-east-1"), cfg)
        identity = resolve_identity(factory)

        # ECR: one AI repo, one non-AI repo
        ecr = factory.client("ecr", "us-east-1")
        ecr.create_repository(
            repositoryName="vllm-inference",
            imageTagMutability="IMMUTABLE",
            imageScanningConfiguration={"scanOnPush": True},
        )
        ecr.create_repository(repositoryName="generic-nginx")

        ecr_col = ECRCollector(factory, cfg, identity, ai_only=True)
        ecr_res = ecr_col.collect_region("us-east-1")
        assert [r.name for r in ecr_res] == ["vllm-inference"]
        assert ecr_res[0].metadata["image_tag_mutability"] == "IMMUTABLE"

        # EC2: SG exposing Ollama 11434 to 0.0.0.0/0
        ec2 = factory.client("ec2", "us-east-1")
        sg = ec2.create_security_group(GroupName="ollama-sg", Description="Ollama")
        ec2.authorize_security_group_ingress(
            GroupId=sg["GroupId"],
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 11434,
                    "ToPort": 11434,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
        ec2_col = EC2SecurityGroupCollector(factory, cfg, identity)
        sgs = ec2_col.collect_region("us-east-1")
        ollama = next(r for r in sgs if r.name == "ollama-sg")
        assert ollama.metadata["ingress"][0]["from_port"] == 11434
        assert "0.0.0.0/0" in ollama.metadata["ingress"][0]["cidrs_v4"]


def test_sagemaker_and_iam_collectors_with_moto() -> None:
    with mock_aws():
        cfg = SiftsecConfig()
        factory = AwsClientFactory(boto3.Session(region_name="us-east-1"), cfg)
        identity = resolve_identity(factory)

        iam = factory.client("iam", "us-east-1")
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "sagemaker.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"aws:SourceAccount": identity.account_id}},
                }
            ],
        }
        role = iam.create_role(
            RoleName="SageMakerExecRole",
            AssumeRolePolicyDocument=json.dumps(trust),
        )
        role_arn = role["Role"]["Arn"]
        iam.put_role_policy(
            RoleName="SageMakerExecRole",
            PolicyName="WildcardS3",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
                }
            ),
        )

        sm = factory.client("sagemaker", "us-east-1")
        sm.create_notebook_instance(
            NotebookInstanceName="ai-research-nb",
            InstanceType="ml.t3.medium",
            RoleArn=role_arn,
            DirectInternetAccess="Enabled",
        )

        sm_col = SageMakerCollector(factory, cfg, identity)
        sm_res = sm_col.collect_region("us-east-1")
        assert len(sm_res) == 1
        assert sm_res[0].metadata["direct_internet_access"] == "Enabled"

        iam_col = IAMCollector(factory, cfg, identity)
        iam_res = iam_col.collect_roles([role_arn])
        assert len(iam_res) == 1
        assert iam_res[0].metadata["has_wildcard_policy"] is True
        assert iam_res[0].metadata["trust_has_source_condition"] is True


def test_bedrock_and_opensearch_with_stubber() -> None:
    cfg = SiftsecConfig()
    session = boto3.Session(region_name="us-east-1")
    factory = AwsClientFactory(session, cfg)
    identity = AwsIdentity(
        account_id="123456789012", arn="arn:aws:iam::123456789012:root", partition="aws"
    )

    # Stub Bedrock + Bedrock Agent
    bedrock = factory.client("bedrock", "us-east-1")
    agent_client = factory.client("bedrock-agent", "us-east-1")
    with Stubber(bedrock) as sb_b, Stubber(agent_client) as sb_a:
        sb_b.add_response(
            "list_guardrails",
            {
                "guardrails": [
                    {
                        "id": "gr-1",
                        "arn": "arn:aws:bedrock:us-east-1:123456789012:guardrail/gr-1",
                        "name": "gr",
                        "status": "READY",
                        "version": "1",
                        "createdAt": "2026-01-01T00:00:00Z",
                        "updatedAt": "2026-01-01T00:00:00Z",
                    }
                ]
            },
        )
        sb_b.add_response(
            "get_guardrail",
            {
                "guardrailId": "gr-1",
                "guardrailArn": "arn:aws:bedrock:us-east-1:123456789012:guardrail/gr-1",
                "name": "gr",
                "status": "READY",
                "version": "1",
                "blockedInputMessaging": "Blocked",
                "blockedOutputsMessaging": "Blocked",
                "createdAt": "2026-01-01T00:00:00Z",
                "updatedAt": "2026-01-01T00:00:00Z",
                "statusReasons": [],
                "failureRecommendations": [],
            },
        )
        sb_a.add_response(
            "list_agents",
            {
                "agentSummaries": [
                    {
                        "agentId": "ag-1",
                        "agentName": "fin-agent",
                        "agentStatus": "PREPARED",
                        "updatedAt": "2026-01-01T00:00:00Z",
                    }
                ]
            },
        )
        sb_a.add_response(
            "get_agent",
            {
                "agent": {
                    "agentId": "ag-1",
                    "agentName": "fin-agent",
                    "agentArn": "arn:aws:bedrock:us-east-1:123456789012:agent/ag-1",
                    "agentVersion": "DRAFT",
                    "agentStatus": "PREPARED",
                    "agentResourceRoleArn": "arn:aws:iam::123456789012:role/BedrockRole",
                    "idleSessionTTLInSeconds": 600,
                    "createdAt": "2026-01-01T00:00:00Z",
                    "updatedAt": "2026-01-01T00:00:00Z",
                }
            },
        )
        sb_a.add_response("list_knowledge_bases", {"knowledgeBaseSummaries": []})
        sb_b.add_response("get_model_invocation_logging_configuration", {})

        res = BedrockCollector(factory, cfg, identity).collect_region("us-east-1")
        kinds = {r.kind for r in res}
        assert {"bedrock_account_config", "bedrock_guardrail", "bedrock_agent"} <= kinds

    # Stub OpenSearch Serverless
    aoss = factory.client("opensearchserverless", "us-east-1")
    os_client = factory.client("opensearch", "us-east-1")
    with Stubber(os_client) as sb_os, Stubber(aoss) as sb_aoss:
        sb_os.add_response("list_domain_names", {"DomainNames": []})
        sb_aoss.add_response(
            "list_collections",
            {
                "collectionSummaries": [
                    {
                        "id": "col-1",
                        "name": "rag-vec",
                        "arn": "arn:aws:aoss:us-east-1:123456789012:collection/col-1",
                        "status": "ACTIVE",
                    }
                ]
            },
        )
        sb_aoss.add_response(
            "batch_get_collection",
            {
                "collectionDetails": [
                    {
                        "id": "col-1",
                        "name": "rag-vec",
                        "arn": "arn:aws:aoss:us-east-1:123456789012:collection/col-1",
                        "type": "VECTORSEARCH",
                    }
                ]
            },
        )
        sb_aoss.add_response("list_security_policies", {"securityPolicySummaries": []})
        sb_aoss.add_response("list_security_policies", {"securityPolicySummaries": []})

        os_res = OpenSearchCollector(factory, cfg, identity, ai_only=True).collect_region(
            "us-east-1"
        )
        assert len(os_res) == 1
        assert os_res[0].kind == "opensearch_serverless"


def test_orchestrator_end_to_end_moto() -> None:
    with mock_aws():
        cfg = SiftsecConfig()
        factory = AwsClientFactory(boto3.Session(region_name="us-east-1"), cfg)
        s3 = factory.client("s3", "us-east-1")
        s3.create_bucket(Bucket="corp-model-bucket")

        ctx = ScanContext(regions=["us-east-1"], services=["s3", "ecr", "ec2"])
        result = AwsOrchestrator(factory, cfg).run(ctx)
        assert any(r.name == "corp-model-bucket" for r in result.resources)
        assert result.incomplete is False
