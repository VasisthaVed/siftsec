"""Amazon ECR collector for AI/ML container repositories (Phase 2.7)."""

from typing import Any, ClassVar, Literal

from ai_spm.collectors.aws.base import (
    ABSENT,
    AWSBaseCollector,
    ResourceGoneError,
    policy_allows_public_principal,
)
from ai_spm.collectors.aws.classify import classify_ai_workload
from ai_spm.engine.attrs import ECRRepositoryAttrs
from ai_spm.engine.models import CloudProvider, CloudResource

_ABSENT_REPO_POLICY = frozenset({"RepositoryPolicyNotFoundException"})


class ECRCollector(AWSBaseCollector):
    """Collects ECR repositories and registry-level scanning configuration."""

    service: ClassVar[str] = "ecr"
    scope: ClassVar[Literal["regional", "global"]] = "regional"
    required_actions: ClassVar[tuple[str, ...]] = (
        "ecr:DescribeRepositories",
        "ecr:GetRegistryScanningConfiguration",
        "ecr:GetRepositoryPolicy",
        "ecr:ListTagsForResource",
    )

    def __init__(self, *args: Any, ai_only: bool = True, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.ai_only = ai_only

    def collect_region(self, region: str | None) -> list[CloudResource]:
        target_region = region or "us-east-1"
        ecr = self.factory.client("ecr", region=target_region)
        out: list[CloudResource] = []

        reg_gaps: dict[str, str] = {}
        reg_scan_type: Literal["BASIC", "ENHANCED"] | None = None
        reg_cfg = self.call(reg_gaps, "registry_scanning", ecr.get_registry_scanning_configuration)
        if isinstance(reg_cfg, dict):
            raw_type = reg_cfg.get("scanningConfiguration", {}).get("scanType")
            if raw_type in ("BASIC", "ENHANCED"):
                reg_scan_type = raw_type

        repos = self.safe_paginate(
            ecr, "describe_repositories", "repositories", region=target_region
        )
        for repo in repos:
            name = str(repo["repositoryName"])
            arn = str(repo["repositoryArn"])
            gaps: dict[str, str] = {}
            try:
                tag_resp = self.call(gaps, "tags", ecr.list_tags_for_resource, resourceArn=arn)
                tags = (
                    {str(t["Key"]): str(t["Value"]) for t in tag_resp.get("tags", [])}
                    if isinstance(tag_resp, dict)
                    else {}
                )
                is_ai, ai_reason = classify_ai_workload("ecr", name, tags, self.cfg)
                if self.ai_only and not is_ai:
                    continue

                pol_public: bool | None = None
                pol_resp = self.call(
                    gaps,
                    "policy",
                    ecr.get_repository_policy,
                    repositoryName=name,
                    absent=_ABSENT_REPO_POLICY,
                )
                if pol_resp is ABSENT:
                    pol_public = False
                elif isinstance(pol_resp, dict):
                    pol_public = policy_allows_public_principal(
                        str(pol_resp.get("policyText", "{}"))
                    )

                enc = repo.get("encryptionConfiguration", {})
                attrs = ECRRepositoryAttrs(
                    scan_on_push=repo.get("imageScanningConfiguration", {}).get("scanOnPush"),
                    registry_scan_type=reg_scan_type,
                    image_tag_mutability=repo.get("imageTagMutability"),
                    encryption_type=enc.get("encryptionType"),
                    kms_key=enc.get("kmsKey"),
                    policy_allows_public=pol_public,
                )
                out.append(
                    CloudResource(
                        arn=arn,
                        id=name,
                        name=name,
                        service="ecr",
                        kind="ecr_repository",
                        provider=CloudProvider.AWS,
                        region=target_region,
                        account_id=self.identity.account_id,
                        tags=tags,
                        gaps=gaps,
                        is_ai_workload=is_ai,
                        ai_reason=ai_reason,
                        metadata=attrs.model_dump(),
                    )
                )
            except ResourceGoneError:
                continue
        return out
