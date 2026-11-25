"""Google Cloud Platform (Vertex AI & GCS) read-only AI-SPM collector (Phase 6.2)."""

import re
from typing import Any

from ai_spm.collectors.base import BaseCollector, CollectorResult, provider_registry
from ai_spm.config import AISPMConfig, settings
from ai_spm.engine.attrs import (
    GcpGcsBucketAttrs,
    GcpVertexEndpointAttrs,
    GcpVertexWorkbenchAttrs,
)
from ai_spm.engine.context import ScanContext
from ai_spm.engine.models import CloudProvider, CloudResource, CoverageGap
from ai_spm.errors import AISPMError


def _is_permission_error(exc: Exception) -> bool:
    name = type(exc).__name__.lower()
    return "permissiondenied" in name or "forbidden" in name or "unauthorized" in name


class GcpCollector(BaseCollector):
    """Read-only collector for Vertex AI Workbench, Vertex Endpoints, and GCS model buckets."""

    provider = CloudProvider.GCP

    def __init__(
        self,
        *,
        project_id: str | None = None,
        regions: list[str] | None = None,
        cfg: AISPMConfig | None = None,
        storage_client: Any = None,
        workbench_client: Any = None,
        endpoint_client: Any = None,
    ) -> None:
        self.project_id = project_id
        self.regions = regions or ["us-central1"]
        self.cfg = cfg or settings
        self._storage_client = storage_client
        self._workbench_client = workbench_client
        self._endpoint_client = endpoint_client

    def _init_storage(self) -> Any:
        if self._storage_client is not None:
            return self._storage_client
        try:
            from google.cloud import storage  # type: ignore[import-not-found]
        except ImportError as exc:
            raise AISPMError(
                "GCP extra is not installed. Run `pip install tensorguard[gcp]`."
            ) from exc
        return storage.Client(project=self.project_id)

    def _init_workbench(self) -> Any:
        if self._workbench_client is not None:
            return self._workbench_client
        try:
            from google.cloud import notebooks_v2
        except ImportError:
            return None
        return notebooks_v2.NotebookServiceClient()

    def _init_endpoint(self, region: str) -> Any:
        if self._endpoint_client is not None:
            return self._endpoint_client
        try:
            from google.cloud import aiplatform_v1
        except ImportError:
            return None
        return aiplatform_v1.EndpointServiceClient(
            client_options={"api_endpoint": f"{region}-aiplatform.googleapis.com"}
        )

    def _is_ai_bucket(self, name: str, labels: dict[str, str]) -> bool:
        low_name = name.lower()
        patterns = self.cfg.ai_name_patterns.get("gcp_gcs", [])
        if any(re.search(pat, low_name) for pat in patterns):
            return True
        for k, v in labels.items():
            allowed = self.cfg.ai_workload_tags.get(k.lower(), [])
            if v.lower() in allowed:
                return True
        return False

    def collect(self) -> list[CloudResource]:
        return self.collect_with_gaps(ScanContext(regions=self.regions)).resources

    def collect_with_gaps(self, ctx: ScanContext) -> CollectorResult:
        project = self.project_id or ctx.gcp_project or "default-project"
        regions = ctx.regions or self.regions
        resources: list[CloudResource] = []
        gaps: list[CoverageGap] = []

        # 1. GCS model/dataset buckets
        storage_client = self._init_storage()
        try:
            for bucket in storage_client.list_buckets(project=project):
                b_name = str(getattr(bucket, "name", "unknown"))
                labels = dict(getattr(bucket, "labels", None) or {})
                is_ai = self._is_ai_bucket(b_name, labels)
                if ctx.ai_only and not is_ai:
                    continue
                iam_cfg = getattr(bucket, "iam_configuration", None)
                pap = getattr(iam_cfg, "public_access_prevention", None) if iam_cfg else None
                ubla = (
                    getattr(iam_cfg, "uniform_bucket_level_access_enabled", None)
                    if iam_cfg
                    else None
                )
                attrs = GcpGcsBucketAttrs(
                    public_access_prevention=str(pap) if pap is not None else None,
                    uniform_bucket_level_access=bool(ubla) if ubla is not None else None,
                    kms_key_name=getattr(bucket, "default_kms_key_name", None),
                    versioning_enabled=bool(getattr(bucket, "versioning_enabled", False)),
                )
                resources.append(
                    CloudResource(
                        arn=f"gcp://storage.googleapis.com/projects/{project}/buckets/{b_name}",
                        id=b_name,
                        name=b_name,
                        service="gcp_gcs",
                        kind="gcp_gcs_bucket",
                        provider=CloudProvider.GCP,
                        region=str(getattr(bucket, "location", "global")).lower(),
                        account_id=project,
                        tags=labels,
                        is_ai_workload=is_ai,
                        ai_reason="ai keyword/label match" if is_ai else None,
                        metadata=attrs.model_dump(),
                    )
                )
        except Exception as exc:  # noqa: BLE001
            if _is_permission_error(exc):
                gaps.append(
                    CoverageGap(
                        service="gcp_gcs",
                        region="global",
                        api="storage.list_buckets",
                        error_code=type(exc).__name__,
                    )
                )
            else:
                raise

        # 2. Vertex AI Workbench instances & Endpoints per region
        wb_client = self._init_workbench()
        for region in regions:
            parent = f"projects/{project}/locations/{region}"
            if wb_client is not None:
                try:
                    for inst in wb_client.list_instances(parent=parent):
                        full_name = str(getattr(inst, "name", "unknown"))
                        short_name = full_name.rsplit("/", 1)[-1]
                        gce_setup = getattr(inst, "gce_setup", None)
                        disable_public = (
                            getattr(gce_setup, "disable_public_ip", None) if gce_setup else None
                        )
                        metadata_map = dict(
                            (getattr(gce_setup, "metadata", None) or {}) if gce_setup else {}
                        )
                        boot_disk = getattr(gce_setup, "boot_disk", None) if gce_setup else None
                        kms = getattr(boot_disk, "kms_key", None) if boot_disk else None
                        net_ifaces = (
                            getattr(gce_setup, "network_interfaces", None) or []
                            if gce_setup
                            else []
                        )
                        network = str(getattr(net_ifaces[0], "network", "")) if net_ifaces else None
                        wb_attrs = GcpVertexWorkbenchAttrs(
                            no_public_ip=bool(disable_public)
                            if disable_public is not None
                            else None,
                            root_access_disabled=(
                                metadata_map.get("notebook-disable-root") == "true"
                            ),
                            kms_key_name=str(kms) if kms else None,
                            network=network or None,
                        )
                        resources.append(
                            CloudResource(
                                arn=f"gcp://notebooks.googleapis.com/{full_name}",
                                id=short_name,
                                name=short_name,
                                service="gcp_vertex",
                                kind="gcp_vertex_workbench",
                                provider=CloudProvider.GCP,
                                region=region,
                                account_id=project,
                                tags=dict(getattr(inst, "labels", None) or {}),
                                is_ai_workload=True,
                                ai_reason="vertex workbench",
                                metadata=wb_attrs.model_dump(),
                            )
                        )
                except Exception as exc:  # noqa: BLE001
                    if _is_permission_error(exc):
                        gaps.append(
                            CoverageGap(
                                service="gcp_vertex",
                                region=region,
                                api="notebooks.list_instances",
                                error_code=type(exc).__name__,
                            )
                        )
                    else:
                        raise

            ep_client = self._init_endpoint(region)
            if ep_client is not None:
                try:
                    for ep in ep_client.list_endpoints(parent=parent):
                        full_name = str(getattr(ep, "name", "unknown"))
                        short_name = str(
                            getattr(ep, "display_name", "") or full_name.rsplit("/", 1)[-1]
                        )
                        vpc_net = getattr(ep, "network", None)
                        priv_cfg = getattr(ep, "private_service_connect_config", None)
                        is_priv = bool(vpc_net) or bool(
                            priv_cfg and getattr(priv_cfg, "enable_private_service_connect", False)
                        )
                        enc = getattr(ep, "encryption_spec", None)
                        kms = getattr(enc, "kms_key_name", None) if enc else None
                        ep_attrs = GcpVertexEndpointAttrs(
                            private_endpoint_enabled=is_priv,
                            kms_key_name=str(kms) if kms else None,
                            vpc_network=str(vpc_net) if vpc_net else None,
                        )
                        resources.append(
                            CloudResource(
                                arn=f"gcp://aiplatform.googleapis.com/{full_name}",
                                id=short_name,
                                name=short_name,
                                service="gcp_vertex",
                                kind="gcp_vertex_endpoint",
                                provider=CloudProvider.GCP,
                                region=region,
                                account_id=project,
                                tags=dict(getattr(ep, "labels", None) or {}),
                                is_ai_workload=True,
                                ai_reason="vertex endpoint",
                                metadata=ep_attrs.model_dump(),
                            )
                        )
                except Exception as exc:  # noqa: BLE001
                    if _is_permission_error(exc):
                        gaps.append(
                            CoverageGap(
                                service="gcp_vertex",
                                region=region,
                                api="aiplatform.list_endpoints",
                                error_code=type(exc).__name__,
                            )
                        )
                    else:
                        raise

        return CollectorResult(resources=resources, coverage_gaps=gaps)


provider_registry.register(CloudProvider.GCP, GcpCollector)
