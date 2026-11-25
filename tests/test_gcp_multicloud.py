from types import SimpleNamespace
from typing import Any

from ai_spm.collectors.base import ProviderCollector, provider_registry
from ai_spm.collectors.gcp import GcpCollector
from ai_spm.engine.context import ScanContext
from ai_spm.engine.models import CloudProvider, CloudResource, Status
from ai_spm.engine.runner import ScanRunner
from ai_spm.rules.gcp import (
    GcpGcsCmekAndVersioningRule,
    GcpGcsPublicAccessPreventionRule,
    GcpGcsUniformAccessRule,
    GcpVertexEndpointPrivateRule,
    GcpVertexWorkbenchCmekRule,
    GcpVertexWorkbenchPublicIpRule,
)


class PermissionDenied(Exception):  # noqa: N818
    pass


def test_provider_registry_and_protocol() -> None:
    cls = provider_registry.get(CloudProvider.GCP)
    assert cls is GcpCollector
    assert isinstance(GcpCollector(), ProviderCollector)


def test_gcp_collector_collects_ai_buckets_vertex_and_gaps() -> None:
    buckets = [
        SimpleNamespace(
            name="corp-ai-models",
            location="US-CENTRAL1",
            labels={"env": "prod"},
            iam_configuration=SimpleNamespace(
                public_access_prevention="inherited",
                uniform_bucket_level_access_enabled=False,
            ),
            default_kms_key_name=None,
            versioning_enabled=False,
        ),
        SimpleNamespace(
            name="corp-payroll-logs",
            location="US",
            labels={},
            iam_configuration=SimpleNamespace(
                public_access_prevention="enforced",
                uniform_bucket_level_access_enabled=True,
            ),
            default_kms_key_name="projects/p/locations/us/keyRings/r/cryptoKeys/k",
            versioning_enabled=True,
        ),
    ]
    storage_client = SimpleNamespace(list_buckets=lambda project: buckets)

    workbenches = [
        SimpleNamespace(
            name="projects/my-proj/locations/us-central1/instances/wb-1",
            labels={"ai": "true"},
            gce_setup=SimpleNamespace(
                disable_public_ip=False,
                metadata={"notebook-disable-root": "false"},
                boot_disk=SimpleNamespace(kms_key=None),
                network_interfaces=[SimpleNamespace(network="default")],
            ),
        )
    ]
    wb_client = SimpleNamespace(list_instances=lambda parent: workbenches)

    def _deny_endpoints(parent: str) -> Any:
        raise PermissionDenied("aiplatform.endpoints.list denied")

    ep_client = SimpleNamespace(list_endpoints=_deny_endpoints)

    collector = GcpCollector(
        project_id="my-proj",
        regions=["us-central1"],
        storage_client=storage_client,
        workbench_client=wb_client,
        endpoint_client=ep_client,
    )
    result = collector.collect_with_gaps(ScanContext(regions=["us-central1"], ai_only=True))

    # Non-AI payroll bucket filtered out when ai_only=True
    assert {r.kind for r in result.resources} == {"gcp_gcs_bucket", "gcp_vertex_workbench"}
    assert len(result.coverage_gaps) == 1
    assert result.coverage_gaps[0].api == "aiplatform.list_endpoints"
    assert result.coverage_gaps[0].error_code == "PermissionDenied"


def test_gcp_rules_pass_fail_and_gap_error() -> None:
    bad_wb = CloudResource(
        arn="gcp://notebooks/wb-bad",
        id="wb-bad",
        name="wb-bad",
        service="gcp_vertex",
        kind="gcp_vertex_workbench",
        provider=CloudProvider.GCP,
        metadata={"kind": "gcp_vertex_workbench", "no_public_ip": False, "kms_key_name": None},
    )
    assert GcpVertexWorkbenchPublicIpRule().evaluate(bad_wb).status == Status.FAILED
    assert GcpVertexWorkbenchCmekRule().evaluate(bad_wb).status == Status.FAILED

    good_wb = CloudResource(
        arn="gcp://notebooks/wb-good",
        id="wb-good",
        name="wb-good",
        service="gcp_vertex",
        kind="gcp_vertex_workbench",
        provider=CloudProvider.GCP,
        metadata={
            "kind": "gcp_vertex_workbench",
            "no_public_ip": True,
            "kms_key_name": "projects/p/keyRings/r/cryptoKeys/k",
        },
    )
    assert GcpVertexWorkbenchPublicIpRule().evaluate(good_wb).status == Status.PASSED
    assert GcpVertexWorkbenchCmekRule().evaluate(good_wb).status == Status.PASSED

    bad_ep = CloudResource(
        arn="gcp://aiplatform/ep-bad",
        id="ep-bad",
        name="ep-bad",
        service="gcp_vertex",
        kind="gcp_vertex_endpoint",
        provider=CloudProvider.GCP,
        metadata={"kind": "gcp_vertex_endpoint", "private_endpoint_enabled": False},
    )
    assert GcpVertexEndpointPrivateRule().evaluate(bad_ep).status == Status.FAILED

    bad_bucket = CloudResource(
        arn="gcp://gcs/b-bad",
        id="b-bad",
        name="b-bad",
        service="gcp_gcs",
        kind="gcp_gcs_bucket",
        provider=CloudProvider.GCP,
        metadata={
            "kind": "gcp_gcs_bucket",
            "public_access_prevention": "inherited",
            "uniform_bucket_level_access": False,
            "kms_key_name": None,
            "versioning_enabled": False,
        },
    )
    assert GcpGcsPublicAccessPreventionRule().evaluate(bad_bucket).status == Status.FAILED
    assert GcpGcsUniformAccessRule().evaluate(bad_bucket).status == Status.FAILED
    assert GcpGcsCmekAndVersioningRule().evaluate(bad_bucket).status == Status.FAILED

    # Gap on required_attrs emits ERROR instead of false PASSED/FAILED via ScanRunner
    gap_bucket = CloudResource(
        arn="gcp://gcs/b-gap",
        id="b-gap",
        name="b-gap",
        service="gcp_gcs",
        kind="gcp_gcs_bucket",
        provider=CloudProvider.GCP,
        gaps={"public_access_prevention": "PermissionDenied"},
        metadata={"kind": "gcp_gcs_bucket"},
    )
    from ai_spm.collectors.base import BaseCollector

    class _OneCollector(BaseCollector):
        def collect(self) -> list[CloudResource]:
            return [gap_bucket]

    findings = ScanRunner(collector=_OneCollector(), context=ScanContext()).run()
    pap_finding = [f for f in findings if f.rule_id == "AI-SPM-GCP-004"][0]
    assert pap_finding.status == Status.ERROR
