# SPDX-License-Identifier: Apache-2.0
"""Integration tests for AwsClientFactory, AWSBaseCollector, and S3Collector via moto + Stubber."""

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from siftsec.collectors.aws.base import ABSENT, AWSBaseCollector, ResourceGoneError
from siftsec.collectors.aws.classify import classify_ai_workload
from siftsec.collectors.aws.client import AwsClientFactory, AwsIdentity, resolve_identity
from siftsec.collectors.aws.s3 import S3Collector
from siftsec.config import SiftsecConfig
from siftsec.engine.models import CloudResource, Status
from siftsec.engine.runner import ScanRunner
from siftsec.errors import CredentialsError
from siftsec.utils.aws_arn import build_arn, parse_partition_from_arn


@pytest.fixture(autouse=True)
def _fake_aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


def test_arn_helpers_and_credentials_error(monkeypatch: pytest.MonkeyPatch) -> None:
    assert build_arn("aws-us-gov", "s3", "", "", "my-bucket") == "arn:aws-us-gov:s3:::my-bucket"
    assert parse_partition_from_arn("arn:aws-cn:iam::123456789012:root") == "aws-cn"

    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")

    factory = AwsClientFactory(boto3.Session(region_name="us-east-1"), SiftsecConfig())
    with pytest.raises(CredentialsError):
        resolve_identity(factory)


def test_client_factory_identity_and_user_agent() -> None:
    with mock_aws():
        cfg = SiftsecConfig()
        factory = AwsClientFactory(boto3.Session(region_name="us-east-1"), cfg)
        identity = resolve_identity(factory)
        assert identity.partition == "aws"
        assert len(identity.account_id) == 12

        c1 = factory.client("s3", "us-east-1")
        c2 = factory.client("s3", "us-east-1")
        assert c1 is c2
        assert "Siftsec/" in c1.meta.config.user_agent_extra


def test_base_collector_pagination_and_error_barrier() -> None:
    class _DummyCollector(AWSBaseCollector):
        service = "s3"

        def collect_region(self, region: str | None) -> list[CloudResource]:
            return []

    with mock_aws():
        cfg = SiftsecConfig()
        factory = AwsClientFactory(boto3.Session(region_name="us-east-1"), cfg)
        identity = AwsIdentity(
            account_id="123456789012", arn="arn:aws:iam::123:root", partition="aws"
        )
        col = _DummyCollector(factory, cfg, identity)

        # Verify pagination across >120 items
        s3 = factory.client("s3", "us-east-1")
        s3.create_bucket(Bucket="paginated-bucket")
        for i in range(125):
            s3.put_object(Bucket="paginated-bucket", Key=f"obj-{i:03d}.txt", Body=b"x")
        items = list(
            col.paginate(s3, "list_objects_v2", "Contents", Bucket="paginated-bucket", MaxKeys=50)
        )
        assert len(items) == 125

        # Stubber AccessDenied -> gaps[attr] = "AccessDenied", returns None
        stub_s3 = boto3.client("s3", region_name="us-east-1")
        with Stubber(stub_s3) as stubber:
            stubber.add_client_error("get_bucket_encryption", service_error_code="AccessDenied")
            gaps: dict[str, str] = {}
            res = col.call(gaps, "encryption", stub_s3.get_bucket_encryption, Bucket="b")
            assert res is None
            assert gaps["encryption"] == "AccessDenied"

        # Stubber ABSENT -> returns ABSENT sentinel without populating gaps
        with Stubber(stub_s3) as stubber:
            stubber.add_client_error(
                "get_public_access_block",
                service_error_code="NoSuchPublicAccessBlockConfiguration",
            )
            gaps2: dict[str, str] = {}
            res2 = col.call(
                gaps2,
                "public_access",
                stub_s3.get_public_access_block,
                Bucket="b",
                absent=frozenset({"NoSuchPublicAccessBlockConfiguration"}),
            )
            assert res2 is ABSENT
            assert gaps2 == {}

        # Stubber NoSuchBucket -> raises ResourceGoneError
        with Stubber(stub_s3) as stubber:
            stubber.add_client_error("get_bucket_tagging", service_error_code="NoSuchBucket")
            with pytest.raises(ResourceGoneError):
                col.call({}, "tags", stub_s3.get_bucket_tagging, Bucket="b")


def test_classify_ai_workload() -> None:
    cfg = SiftsecConfig()
    assert classify_ai_workload("s3", "corp-model-weights", {}, cfg)[0] is True
    assert classify_ai_workload("s3", "remodel-invoices", {}, cfg)[0] is False
    assert classify_ai_workload("s3", "my-bucket", {"workload": "AI"}, cfg)[0] is True
    assert (
        classify_ai_workload("s3", "corp-model-weights", {"siftsec:ignore": "true"}, cfg)[0]
        is False
    )
    assert classify_ai_workload("bedrock", "anything", {}, cfg)[0] is True


def test_s3_collector_with_moto() -> None:
    with mock_aws():
        cfg = SiftsecConfig()
        factory = AwsClientFactory(boto3.Session(region_name="us-east-1"), cfg)
        identity = resolve_identity(factory)

        s3 = factory.client("s3", "us-east-1")
        kms = factory.client("kms", "us-east-1")
        key_id = kms.create_key(Description="AI CMK")["KeyMetadata"]["KeyId"]

        # 1. Compliant KMS CMK + PAB + SafeTensors bucket
        s3.create_bucket(Bucket="ai-safetensors-prod")
        s3.put_bucket_tagging(
            Bucket="ai-safetensors-prod",
            Tagging={"TagSet": [{"Key": "workload", "Value": "ai"}]},
        )
        s3.put_bucket_encryption(
            Bucket="ai-safetensors-prod",
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": key_id,
                        }
                    }
                ]
            },
        )
        s3.put_public_access_block(
            Bucket="ai-safetensors-prod",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        s3.put_object(Bucket="ai-safetensors-prod", Key="weights.safetensors", Body=b"ok")

        # 2. Vulnerable cross-region AI bucket (us-west-2, default SSE, no PAB, .pt file)
        s3_west = factory.client("s3", "us-west-2")
        s3_west.create_bucket(
            Bucket="ml-weights-west",
            CreateBucketConfiguration={"LocationConstraint": "us-west-2"},
        )
        s3_west.put_object(Bucket="ml-weights-west", Key="ckpt.pt", Body=b"pt")

        # 3. Non-AI bucket (should be skipped when ai_only=True)
        s3.create_bucket(Bucket="corp-billing-logs")

        collector = S3Collector(factory, cfg, identity, ai_only=True)
        resources = collector.collect()
        names = {r.name for r in resources}
        assert names == {"ai-safetensors-prod", "ml-weights-west"}

        # Evaluate S3 rules against collected moto resources
        findings = ScanRunner(collector=collector, services=["s3"]).run()
        failed = {(f.resource_id, f.rule_id) for f in findings if f.status is Status.FAILED}
        passed = {(f.resource_id, f.rule_id) for f in findings if f.status is Status.PASSED}

        assert ("ai-safetensors-prod", "SIFTSEC-S3-001") in passed
        assert ("ai-safetensors-prod", "SIFTSEC-S3-002") in passed
        assert ("ml-weights-west", "SIFTSEC-S3-001") in failed
        assert ("ml-weights-west", "SIFTSEC-S3-004") in failed


def test_s3_unknown_encryption_emits_error_not_fail() -> None:
    from siftsec.collectors.base import BaseCollector

    class _GapCollector(BaseCollector):
        def collect(self) -> list[CloudResource]:
            return [
                CloudResource(
                    arn="arn:aws:s3:::denied-bucket",
                    id="denied-bucket",
                    name="denied-bucket",
                    service="s3",
                    gaps={"encryption": "AccessDenied"},
                )
            ]

    findings = ScanRunner(collector=_GapCollector(), services=["s3"]).run()
    s3_001 = next(f for f in findings if f.rule_id == "SIFTSEC-S3-001")
    assert s3_001.status is Status.ERROR
    assert s3_001.error_code == "AccessDenied"
