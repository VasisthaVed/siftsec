import shlex

from siftsec.config import settings
from siftsec.engine.models import CloudResource, Finding, Severity
from siftsec.rules.base import BaseRule
from siftsec.rules.registry import registry


class SageMakerDirectInternetAccessRule(BaseRule):
    rule_id = "SIFTSEC-SAGEMAKER-001"
    title = "SageMaker Notebook Direct Internet Access Enabled"
    description = "Notebooks must not have direct internet access to prevent unmonitored egress."
    severity = Severity.HIGH
    service = "sagemaker"
    resource_kinds = frozenset({"sagemaker_notebook"})
    required_attrs = ("describe",)
    mitre_atlas = ["AML.T0044"]
    owasp_llm = ["LLM02:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        dia = str(resource.metadata.get("direct_internet_access", "Enabled"))
        if dia.lower() == "disabled":
            return self.passed(
                resource, f"SageMaker notebook '{resource.name}' has DirectInternetAccess disabled."
            )

        return self.failed(
            resource,
            f"SageMaker notebook '{resource.name}' has direct outbound internet access enabled.",
            remediation=(
                f"Recreate notebook {shlex.quote(resource.name)} in region "
                f"{shlex.quote(resource.region)} with DirectInternetAccess=Disabled inside private VPC subnets."
            ),
        )


class BedrockGuardrailsRule(BaseRule):
    rule_id = "SIFTSEC-BEDROCK-003"
    title = "Bedrock Agent Missing Active Guardrail"
    description = "Bedrock Agents must have an active Guardrail configured to prevent excessive agency and prompt injection."
    severity = Severity.HIGH
    service = "bedrock"
    resource_kinds = frozenset({"bedrock_agent"})
    required_attrs = ("describe",)
    mitre_atlas = []
    owasp_llm = ["LLM01:2026", "LLM03:2026"]
    nist_ai_rmf = ["MG-3.1"]

    def evaluate(self, resource: CloudResource) -> Finding:
        guardrail_id = resource.metadata.get("guardrail_id")
        if guardrail_id:
            return self.passed(
                resource,
                f"Bedrock agent '{resource.name}' is protected by Guardrail {guardrail_id}.",
            )

        return self.failed(
            resource,
            f"Bedrock agent '{resource.name}' has no Guardrail attached.",
            remediation=(
                f"aws bedrock-agent update-agent --agent-id {shlex.quote(resource.id)} "
                f"--region {shlex.quote(resource.region)} "
                "--guardrail-configuration guardrailIdentifier=<guardrail-id>,guardrailVersion=1"
            ),
        )


class OpenSearchVectorPublicAccessRule(BaseRule):
    rule_id = "SIFTSEC-VECTOR-001"
    title = "Vector Database Publicly Exposed (Embedding Inversion Risk)"
    description = (
        "Vector databases must reside inside private VPCs to prevent embedding inversion attacks."
    )
    severity = Severity.CRITICAL
    service = "opensearch"
    resource_kinds = frozenset({"opensearch_domain"})
    mitre_atlas = ["AML.T0044"]
    owasp_llm = ["LLM02:2026", "LLM09:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        in_vpc = bool(resource.metadata.get("in_vpc", False))
        if in_vpc:
            return self.passed(
                resource, f"Vector database '{resource.name}' is isolated inside a VPC."
            )

        return self.failed(
            resource,
            f"Vector database '{resource.name}' has a public endpoint with no VPC isolation.",
            remediation=(
                f"Migrate vector domain {shlex.quote(resource.name)} ({shlex.quote(resource.region)}) "
                "into private VPC subnets and enable Fine-Grained Access Control (FGAC)."
            ),
        )


class IAMWildcardPermissionsRule(BaseRule):
    rule_id = "SIFTSEC-IAM-001"
    title = "Excessive Agency: Wildcard Actions in AI Execution Role"
    description = "AI agent and inference roles must not contain unrestricted wildcard permissions."
    severity = Severity.HIGH
    service = "iam"
    resource_kinds = frozenset({"iam_role"})
    required_attrs = ("role",)
    mitre_atlas = []
    owasp_llm = ["LLM03:2026", "ASI05"]

    def evaluate(self, resource: CloudResource) -> Finding:
        has_wildcard = bool(resource.metadata.get("has_wildcard_policy", False))
        if not has_wildcard:
            return self.passed(
                resource, f"IAM role '{resource.name}' follows least-privilege scoping."
            )

        return self.failed(
            resource,
            f"IAM role '{resource.name}' grants wildcard ('*') administrative access.",
            remediation=(
                f"Scope down IAM role {shlex.quote(resource.name)} ({resource.arn}) "
                "to explicit service actions and target resource ARNs."
            ),
        )


class MCPToolPoisoningRule(BaseRule):
    rule_id = "SIFTSEC-MCP-001"
    title = "MCP Tool Manifest Poisoning: Suspicious Payload in Metadata"
    description = (
        "MCP tool descriptions must not contain obfuscated instructions or injection markers."
    )
    severity = Severity.CRITICAL
    service = "mcp"
    mitre_atlas = ["AML.T0010"]
    owasp_llm = ["LLM04:2026", "ASI10"]

    def evaluate(self, resource: CloudResource) -> Finding:
        suspicious = bool(resource.metadata.get("has_suspicious_instructions", False))
        if not suspicious:
            return self.passed(
                resource,
                f"MCP server '{resource.name}' tool definitions passed security inspection.",
            )

        return self.failed(
            resource,
            f"MCP server '{resource.name}' tool description contains hidden prompt injection markers.",
            remediation=(
                f"Remove or quarantine MCP server {shlex.quote(resource.name)} ({resource.arn}) "
                "and enforce manifest SHA-256 hash-pinning."
            ),
        )


_ = settings

registry.register(SageMakerDirectInternetAccessRule())
registry.register(BedrockGuardrailsRule())
registry.register(OpenSearchVectorPublicAccessRule())
registry.register(IAMWildcardPermissionsRule())
registry.register(MCPToolPoisoningRule())
