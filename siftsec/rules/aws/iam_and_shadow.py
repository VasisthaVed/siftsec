"""IAM AI execution role rules and EC2 Shadow AI port exposure rule (Phase 3.7-3.8)."""

from siftsec.config import settings
from siftsec.engine.attrs import EC2SecurityGroupAttrs, IamRoleAttrs, IngressRule
from siftsec.engine.models import CloudResource, Finding, Severity
from siftsec.rules.base import BaseRule
from siftsec.rules.registry import registry
from siftsec.rules.remediation import sh


class IAMBroadManagedPolicyRule(BaseRule):
    rule_id = "SIFTSEC-IAM-002"
    title = "AI Execution Role Attaches Broad AWS-Managed FullAccess Policy"
    description = "Avoid AdministratorAccess, PowerUserAccess, or *FullAccess policies on AI roles."
    severity = Severity.HIGH
    service = "iam"
    resource_kinds = frozenset({"iam_role"})
    required_attrs = ("role",)
    owasp_llm = ["LLM03:2026", "ASI05"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = IamRoleAttrs.model_validate(resource.metadata)
        broad = [a for a in attrs.attached_managed_arns if a in settings.broad_managed_policy_arns]
        if not broad:
            return self.passed(
                resource, f"IAM role '{resource.name}' has no broad FullAccess policies."
            )
        return self.failed(
            resource,
            f"IAM role '{resource.name}' attaches broad managed policy {broad[0]}.",
            remediation=f"Detach {sh(broad[0])} from role {sh(resource.name)} and replace with least-privilege permissions.",
            evidence={"policy_arn": broad[0]},
        )


class IAMTrustConfusedDeputyRule(BaseRule):
    rule_id = "SIFTSEC-IAM-003"
    title = "AI Service Trust Policy Missing SourceAccount / SourceArn Condition"
    description = (
        "Service-principal trust policies should require aws:SourceAccount or aws:SourceArn."
    )
    severity = Severity.MEDIUM
    service = "iam"
    resource_kinds = frozenset({"iam_role"})
    required_attrs = ("role",)
    owasp_llm = ["LLM03:2026", "ASI05"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = IamRoleAttrs.model_validate(resource.metadata)
        if not attrs.trust_principals or attrs.trust_has_source_condition:
            return self.passed(resource, f"IAM role '{resource.name}' trust policy is scoped.")
        return self.failed(
            resource,
            f"IAM role '{resource.name}' trusts {attrs.trust_principals} without aws:SourceAccount/SourceArn.",
            remediation=f"Add StringEquals/ArnLike aws:SourceAccount condition to trust policy on {sh(resource.name)}.",
        )


def _rule_exposes_port(rule: IngressRule, target_port: int) -> bool:
    is_world = "0.0.0.0/0" in rule.cidrs_v4 or "::/0" in rule.cidrs_v6
    if not is_world:
        return False
    if rule.protocol == "-1":
        return True
    if rule.from_port is None or rule.to_port is None:
        return False
    return rule.from_port <= target_port <= rule.to_port


class ShadowAIPortExposureRule(BaseRule):
    rule_id = "SIFTSEC-SHADOW-001"
    title = "Security Group Exposes AI Inference Port to Public Internet"
    description = (
        "Inference servers (Ollama, vLLM, Triton, Qdrant, Milvus) must not be world-accessible."
    )
    severity = Severity.HIGH
    service = "ec2"
    resource_kinds = frozenset({"ec2_security_group"})
    owasp_llm = ["LLM02:2026", "LLM06:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = EC2SecurityGroupAttrs.model_validate(resource.metadata)
        exposed: list[str] = []
        for port, label in sorted(settings.shadow_ai_ports.items()):
            if any(_rule_exposes_port(ir, port) for ir in attrs.ingress):
                exposed.append(f"{port}({label})")

        if not exposed:
            return self.passed(
                resource, f"Security group '{resource.name}' exposes no Shadow AI ports."
            )
        port_summary = ",".join(exposed)
        return self.failed(
            resource,
            f"Security group '{resource.name}' exposes AI ports [{port_summary}] to 0.0.0.0/0 or ::/0.",
            remediation=(
                f"Restrict ingress on security group {sh(resource.id)} in {sh(resource.region)} "
                "to private VPC CIDRs or specific security groups."
            ),
            evidence={"ports": port_summary, "attached": str(attrs.attached)},
            scope=port_summary,
        )


registry.register(IAMBroadManagedPolicyRule())
registry.register(IAMTrustConfusedDeputyRule())
registry.register(ShadowAIPortExposureRule())
