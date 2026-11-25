"""Multi-region AWS orchestrator with bounded concurrency and post-pass linking (Phase 2.11)."""

import logging
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Literal

from ai_spm.collectors.aws.base import AWSBaseCollector
from ai_spm.collectors.aws.bedrock import BedrockCollector
from ai_spm.collectors.aws.client import (
    AwsClientFactory,
    AwsIdentity,
    resolve_identity,
    resolve_regions,
)
from ai_spm.collectors.aws.ec2 import EC2SecurityGroupCollector
from ai_spm.collectors.aws.ecr import ECRCollector
from ai_spm.collectors.aws.iam import IAMCollector
from ai_spm.collectors.aws.opensearch import OpenSearchCollector
from ai_spm.collectors.aws.s3 import S3Collector
from ai_spm.collectors.aws.sagemaker import SageMakerCollector
from ai_spm.config import AISPMConfig
from ai_spm.engine.context import ScanContext
from ai_spm.engine.models import CloudResource, CoverageGap

log = logging.getLogger("ai_spm.collectors.aws.orchestrator")


@dataclass
class CollectionResult:
    """Deterministic output of an AWS multi-region collection pass."""

    resources: list[CloudResource] = field(default_factory=list)
    coverage_gaps: list[CoverageGap] = field(default_factory=list)
    incomplete: bool = False


class AwsOrchestrator:
    """Fans out AWS collectors across regions, links cross-resource edges, and collects AI IAM roles."""

    def __init__(self, factory: AwsClientFactory, cfg: AISPMConfig) -> None:
        self.factory = factory
        self.cfg = cfg

    def _build_collectors(self, identity: AwsIdentity, ctx: ScanContext) -> list[AWSBaseCollector]:
        all_cols: list[AWSBaseCollector] = [
            S3Collector(self.factory, self.cfg, identity, ai_only=ctx.ai_only),
            SageMakerCollector(self.factory, self.cfg, identity),
            BedrockCollector(self.factory, self.cfg, identity),
            ECRCollector(self.factory, self.cfg, identity, ai_only=ctx.ai_only),
            OpenSearchCollector(self.factory, self.cfg, identity, ai_only=ctx.ai_only),
            EC2SecurityGroupCollector(self.factory, self.cfg, identity),
        ]
        if not ctx.services:
            return all_cols
        wanted = {s.lower() for s in ctx.services}
        return [c for c in all_cols if c.service in wanted]

    def run(self, ctx: ScanContext) -> CollectionResult:
        identity = resolve_identity(self.factory)
        collectors = self._build_collectors(identity, ctx)
        requested_regions: list[str] | Literal["all"] = (
            "all" if not ctx.regions or ctx.regions == ["all"] else ctx.regions
        )

        semaphores = {
            svc: threading.BoundedSemaphore(limit)
            for svc, limit in self.cfg.max_concurrency_per_service.items()
        }
        resources: list[CloudResource] = []
        gaps: list[CoverageGap] = []
        incomplete = False

        tasks: list[tuple[AWSBaseCollector, str | None]] = []
        for col in collectors:
            if col.scope == "global":
                tasks.append((col, None))
            else:
                for reg in resolve_regions(
                    self.factory, requested_regions, col.service, identity.partition
                ):
                    tasks.append((col, reg))

        def _exec(col: AWSBaseCollector, reg: str | None) -> list[CloudResource]:
            sem = semaphores.get(col.service)
            if sem:
                with sem:
                    return col.collect_region(reg)
            return col.collect_region(reg)

        with ThreadPoolExecutor(max_workers=self.cfg.max_workers) as pool:
            future_map: dict[Future[list[CloudResource]], tuple[AWSBaseCollector, str | None]] = {
                pool.submit(_exec, col, reg): (col, reg) for col, reg in tasks
            }
            try:
                for fut, (task_col, task_reg) in future_map.items():
                    try:
                        resources.extend(fut.result(timeout=self.cfg.collector_timeout_s))
                    except Exception as exc:  # noqa: BLE001
                        log.exception(
                            "Collector %s (%s) failed", task_col.service, task_reg or "global"
                        )
                        gaps.append(
                            CoverageGap(
                                service=task_col.service,
                                region=task_reg or "global",
                                api="collect",
                                error_code=type(exc).__name__,
                            )
                        )
            except KeyboardInterrupt:
                incomplete = True
                pool.shutdown(wait=False, cancel_futures=True)

        resources = self._post_pass_links(resources)

        for col in collectors:
            gaps.extend(col.coverage_gaps)

        # Post-pass B: collect IAM roles referenced by discovered AI resources
        want_iam = not ctx.services or "iam" in {s.lower() for s in ctx.services}
        if want_iam:
            role_arns = {
                str(r.metadata["role_arn"]) for r in resources if r.metadata.get("role_arn")
            }
            if role_arns:
                iam_col = IAMCollector(self.factory, self.cfg, identity)
                resources.extend(iam_col.collect_roles(role_arns))

        resources.sort(key=lambda r: (r.service, r.region, r.arn))
        return CollectionResult(resources=resources, coverage_gaps=gaps, incomplete=incomplete)

    @staticmethod
    def _post_pass_links(resources: list[CloudResource]) -> list[CloudResource]:
        """Resolve cross-resource references (Bedrock guardrails, KB -> OpenSearch)."""
        guardrail_ready: dict[str, bool] = {
            str(r.metadata.get("guardrail_id")): r.metadata.get("status") == "READY"
            for r in resources
            if r.kind == "bedrock_guardrail"
        }
        kb_vector_arns: set[str] = {
            str(r.metadata.get("vector_store_arn"))
            for r in resources
            if r.kind == "bedrock_data_source" and r.metadata.get("vector_store_arn")
        }

        updated: list[CloudResource] = []
        for r in resources:
            if r.kind == "bedrock_agent":
                gr_id = r.metadata.get("guardrail_id")
                if gr_id:
                    new_meta = dict(r.metadata)
                    new_meta["guardrail_ready"] = guardrail_ready.get(str(gr_id), False)
                    r = r.model_copy(update={"metadata": new_meta})
            elif (
                r.kind in ("opensearch_domain", "opensearch_serverless") and r.arn in kb_vector_arns
            ):
                r = r.model_copy(
                    update={
                        "is_ai_workload": True,
                        "ai_reason": "linked from Bedrock Knowledge Base",
                    }
                )
            updated.append(r)
        return updated
