"""Amazon ECR security rules for AI/ML container repositories (Phase 3.5)."""

from siftsec.engine.attrs import ECRRepositoryAttrs
from siftsec.engine.models import CloudResource, Finding, Severity
from siftsec.rules.base import BaseRule
from siftsec.rules.registry import registry
from siftsec.rules.remediation import sh


class ECRScanOnPushRule(BaseRule):
    rule_id = "SIFTSEC-ECR-001"
    title = "ECR AI Repository Vulnerability Scan on Push Disabled"
    description = (
        "Enable scanOnPush or registry-level Enhanced Scanning on AI container repositories."
    )
    severity = Severity.HIGH
    service = "ecr"
    resource_kinds = frozenset({"ecr_repository"})
    mitre_atlas = ["AML.T0010"]
    owasp_llm = ["LLM04:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = ECRRepositoryAttrs.model_validate(resource.metadata)
        if attrs.registry_scan_type == "ENHANCED":
            return self.passed(
                resource,
                f"ECR repository '{resource.name}' is covered by registry ENHANCED scanning.",
            )
        if attrs.scan_on_push:
            return self.passed(resource, f"ECR repository '{resource.name}' enables scanOnPush.")
        return self.failed(
            resource,
            f"ECR repository '{resource.name}' has scanOnPush disabled under BASIC scanning.",
            remediation=(
                f"aws ecr put-image-scanning-configuration --repository-name {sh(resource.name)} "
                f"--region {sh(resource.region)} --image-scanning-configuration scanOnPush=true"
            ),
        )


class ECRImmutableTagsRule(BaseRule):
    rule_id = "SIFTSEC-ECR-002"
    title = "ECR AI Repository Image Tag Immutability Disabled"
    description = "Enforce IMMUTABLE image tags to prevent overwriting inference container tags."
    severity = Severity.MEDIUM
    service = "ecr"
    resource_kinds = frozenset({"ecr_repository"})
    mitre_atlas = ["AML.T0010"]
    owasp_llm = ["LLM04:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = ECRRepositoryAttrs.model_validate(resource.metadata)
        if attrs.image_tag_mutability and attrs.image_tag_mutability.startswith("IMMUTABLE"):
            return self.passed(
                resource, f"ECR repository '{resource.name}' enforces immutable tags."
            )
        return self.failed(
            resource,
            f"ECR repository '{resource.name}' allows mutable tags ({attrs.image_tag_mutability}).",
            remediation=(
                f"aws ecr put-image-tag-mutability --repository-name {sh(resource.name)} "
                f"--region {sh(resource.region)} --image-tag-mutability IMMUTABLE"
            ),
        )


class ECRPublicPolicyRule(BaseRule):
    rule_id = "SIFTSEC-ECR-003"
    title = "ECR AI Repository Policy Allows Public Access"
    description = "ECR repository policies must not grant unconditioned access to Principal '*'."
    severity = Severity.HIGH
    service = "ecr"
    resource_kinds = frozenset({"ecr_repository"})
    required_attrs = ("policy",)
    owasp_llm = ["LLM02:2026", "LLM04:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = ECRRepositoryAttrs.model_validate(resource.metadata)
        if not attrs.policy_allows_public:
            return self.passed(resource, f"ECR repository '{resource.name}' policy is not public.")
        return self.failed(
            resource,
            f"ECR repository '{resource.name}' policy grants unconditioned Principal '*' access.",
            remediation=f"Restrict repository policy on {sh(resource.name)} ({sh(resource.region)}) to specific AWS accounts/IAM principals.",
        )


registry.register(ECRScanOnPushRule())
registry.register(ECRImmutableTagsRule())
registry.register(ECRPublicPolicyRule())
