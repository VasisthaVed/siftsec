"""Amazon SageMaker collector (Phase 2.5)."""

import re
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar, Literal

from ai_spm.collectors.aws.base import AWSBaseCollector, ResourceGoneError
from ai_spm.engine.attrs import (
    SageMakerDomainAttrs,
    SageMakerEndpointConfigAttrs,
    SageMakerNotebookAttrs,
    SageMakerTrainingJobAttrs,
)
from ai_spm.engine.models import CloudProvider, CloudResource

_ECR_ACCOUNT_RE = re.compile(r"^(\d{12})\.dkr\.ecr\.")


class SageMakerCollector(AWSBaseCollector):
    """Collects SageMaker notebooks, endpoint configs, training jobs, and domains."""

    service: ClassVar[str] = "sagemaker"
    scope: ClassVar[Literal["regional", "global"]] = "regional"
    required_actions: ClassVar[tuple[str, ...]] = (
        "sagemaker:ListNotebookInstances",
        "sagemaker:DescribeNotebookInstance",
        "sagemaker:ListEndpointConfigs",
        "sagemaker:DescribeEndpointConfig",
        "sagemaker:ListEndpoints",
        "sagemaker:ListTrainingJobs",
        "sagemaker:DescribeTrainingJob",
        "sagemaker:ListDomains",
        "sagemaker:DescribeDomain",
        "sagemaker:ListTags",
    )

    def _get_tags(self, client: Any, arn: str, gaps: dict[str, str]) -> dict[str, str]:
        resp = self.call(gaps, "tags", client.list_tags, ResourceArn=arn)
        if not isinstance(resp, dict):
            return {}
        return {str(t["Key"]): str(t["Value"]) for t in resp.get("Tags", [])}

    def collect_region(self, region: str | None) -> list[CloudResource]:
        target_region = region or "us-east-1"
        sm = self.factory.client("sagemaker", region=target_region)
        resources: list[CloudResource] = []

        resources.extend(self._collect_notebooks(sm, target_region))
        resources.extend(self._collect_endpoint_configs(sm, target_region))
        resources.extend(self._collect_training_jobs(sm, target_region))
        resources.extend(self._collect_domains(sm, target_region))
        return resources

    def _collect_notebooks(self, sm: Any, region: str) -> list[CloudResource]:
        out: list[CloudResource] = []
        list_gaps: dict[str, str] = {}
        try:
            items = list(self.paginate(sm, "list_notebook_instances", "NotebookInstances"))
        except Exception:  # noqa: BLE001
            return out

        for nb in items:
            name = str(nb["NotebookInstanceName"])
            arn = str(nb["NotebookInstanceArn"])
            gaps: dict[str, str] = dict(list_gaps)
            try:
                desc = self.call(
                    gaps, "describe", sm.describe_notebook_instance, NotebookInstanceName=name
                )
                tags = self._get_tags(sm, arn, gaps)
                if isinstance(desc, dict):
                    imds = desc.get("InstanceMetadataServiceConfiguration", {})
                    attrs = SageMakerNotebookAttrs(
                        status=str(
                            desc.get(
                                "NotebookInstanceStatus",
                                nb.get("NotebookInstanceStatus", "Unknown"),
                            )
                        ),
                        direct_internet_access=desc.get("DirectInternetAccess"),
                        root_access=desc.get("RootAccess"),
                        subnet_id=desc.get("SubnetId"),
                        security_groups=list(desc.get("SecurityGroups", [])),
                        kms_key_id=desc.get("KmsKeyId"),
                        role_arn=desc.get("RoleArn"),
                        min_imdsv_version=imds.get("MinimumInstanceMetadataServiceVersion"),
                    )
                    meta = attrs.model_dump()
                else:
                    meta = SageMakerNotebookAttrs().model_dump()
                out.append(
                    CloudResource(
                        arn=arn,
                        id=name,
                        name=name,
                        service="sagemaker",
                        kind="sagemaker_notebook",
                        provider=CloudProvider.AWS,
                        region=region,
                        account_id=self.identity.account_id,
                        tags=tags,
                        gaps=gaps,
                        is_ai_workload=True,
                        ai_reason="service sagemaker is AI by nature",
                        metadata=meta,
                    )
                )
            except ResourceGoneError:
                continue
        return out

    def _collect_endpoint_configs(self, sm: Any, region: str) -> list[CloudResource]:
        out: list[CloudResource] = []
        in_use_configs: set[str] = set()
        ep_gaps: dict[str, str] = {}
        ep_resp = self.call(ep_gaps, "endpoints", sm.list_endpoints)
        if isinstance(ep_resp, dict):
            for ep in ep_resp.get("Endpoints", []):
                ep_name = ep.get("EndpointName")
                if ep_name:
                    ep_desc = self.call(
                        ep_gaps, "endpoint_desc", sm.describe_endpoint, EndpointName=ep_name
                    )
                    if isinstance(ep_desc, dict) and ep_desc.get("EndpointConfigName"):
                        in_use_configs.add(str(ep_desc["EndpointConfigName"]))

        cfg_resp = self.call({}, "endpoint_configs", sm.list_endpoint_configs)
        if not isinstance(cfg_resp, dict):
            return out

        for ec in cfg_resp.get("EndpointConfigs", []):
            name = str(ec["EndpointConfigName"])
            arn = str(ec["EndpointConfigArn"])
            gaps: dict[str, str] = {}
            try:
                desc = self.call(
                    gaps, "describe", sm.describe_endpoint_config, EndpointConfigName=name
                )
                if isinstance(desc, dict):
                    dc = desc.get("DataCaptureConfig", {})
                    attrs = SageMakerEndpointConfigAttrs(
                        kms_key_id=desc.get("KmsKeyId"),
                        data_capture_enabled=bool(dc.get("EnableCapture", False)),
                        data_capture_kms_key_id=dc.get("KmsKeyId"),
                        instance_types=[
                            str(v.get("InstanceType", ""))
                            for v in desc.get("ProductionVariants", [])
                        ],
                        in_use=name in in_use_configs,
                    )
                    meta = attrs.model_dump()
                else:
                    meta = SageMakerEndpointConfigAttrs().model_dump()
                out.append(
                    CloudResource(
                        arn=arn,
                        id=name,
                        name=name,
                        service="sagemaker",
                        kind="sagemaker_endpoint_config",
                        provider=CloudProvider.AWS,
                        region=region,
                        account_id=self.identity.account_id,
                        gaps=gaps,
                        is_ai_workload=True,
                        ai_reason="service sagemaker is AI by nature",
                        metadata=meta,
                    )
                )
            except ResourceGoneError:
                continue
        return out

    def _collect_training_jobs(self, sm: Any, region: str) -> list[CloudResource]:
        out: list[CloudResource] = []
        after = datetime.now(UTC) - timedelta(days=self.cfg.sagemaker_training_lookback_days)
        resp = self.call({}, "training_jobs", sm.list_training_jobs, CreationTimeAfter=after)
        if not isinstance(resp, dict):
            return out

        for job in resp.get("TrainingJobSummaries", [])[: self.cfg.max_training_jobs]:
            name = str(job["TrainingJobName"])
            arn = str(job["TrainingJobArn"])
            gaps: dict[str, str] = {}
            try:
                desc = self.call(gaps, "describe", sm.describe_training_job, TrainingJobName=name)
                if isinstance(desc, dict):
                    image = str(desc.get("AlgorithmSpecification", {}).get("TrainingImage", ""))
                    match = _ECR_ACCOUNT_RE.match(image)
                    aws_owned = (
                        match.group(1) in self.cfg.aws_owned_ecr_account_ids if match else None
                    )
                    attrs = SageMakerTrainingJobAttrs(
                        enable_network_isolation=desc.get("EnableNetworkIsolation"),
                        has_vpc_config=bool(desc.get("VpcConfig", {}).get("Subnets")),
                        training_image=image or None,
                        image_is_aws_owned=aws_owned,
                        role_arn=desc.get("RoleArn"),
                        output_kms_key_id=desc.get("OutputDataConfig", {}).get("KmsKeyId"),
                    )
                    meta = attrs.model_dump()
                else:
                    meta = SageMakerTrainingJobAttrs().model_dump()
                out.append(
                    CloudResource(
                        arn=arn,
                        id=name,
                        name=name,
                        service="sagemaker",
                        kind="sagemaker_training_job",
                        provider=CloudProvider.AWS,
                        region=region,
                        account_id=self.identity.account_id,
                        gaps=gaps,
                        is_ai_workload=True,
                        ai_reason="service sagemaker is AI by nature",
                        metadata=meta,
                    )
                )
            except ResourceGoneError:
                continue
        return out

    def _collect_domains(self, sm: Any, region: str) -> list[CloudResource]:
        out: list[CloudResource] = []
        resp = self.call({}, "domains", sm.list_domains)
        if not isinstance(resp, dict):
            return out
        for dom in resp.get("Domains", []):
            dom_id = str(dom["DomainId"])
            arn = str(dom["DomainArn"])
            name = str(dom.get("DomainName", dom_id))
            gaps: dict[str, str] = {}
            try:
                desc = self.call(gaps, "describe", sm.describe_domain, DomainId=dom_id)
                if isinstance(desc, dict):
                    attrs = SageMakerDomainAttrs(
                        app_network_access_type=desc.get("AppNetworkAccessType"),
                        kms_key_id=desc.get("KmsKeyId"),
                        subnet_ids=list(desc.get("SubnetIds", [])),
                    )
                    meta = attrs.model_dump()
                else:
                    meta = SageMakerDomainAttrs().model_dump()
                out.append(
                    CloudResource(
                        arn=arn,
                        id=dom_id,
                        name=name,
                        service="sagemaker",
                        kind="sagemaker_domain",
                        provider=CloudProvider.AWS,
                        region=region,
                        account_id=self.identity.account_id,
                        gaps=gaps,
                        is_ai_workload=True,
                        ai_reason="service sagemaker is AI by nature",
                        metadata=meta,
                    )
                )
            except ResourceGoneError:
                continue
        return out
