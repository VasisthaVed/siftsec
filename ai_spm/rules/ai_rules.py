from ai_spm.config import settings
from ai_spm.engine.models import CloudResource, Finding, Severity, Status
from ai_spm.rules.base import BaseRule
from ai_spm.rules.registry import registry


class SageMakerDirectInternetAccessRule(BaseRule):
    rule_id = "AI-SPM-SAGEMAKER-001"
    title = "SageMaker Notebook Direct Internet Access Enabled"
    description = "Notebooks must not have direct internet access to prevent unmonitored egress."
    severity = Severity.CRITICAL
    service = "sagemaker"
    mitre_atlas = ["AML.T0043"]
    owasp_llm = ["LLM02:2025"]

    def evaluate(self, resource: CloudResource) -> Finding:
        dia = resource.metadata.get("direct_internet_access", "Enabled")
        if dia.lower() == "disabled":
            status = Status.PASSED
            msg = f"SageMaker notebook '{resource.name}' has DirectInternetAccess disabled."
        else:
            status = Status.FAILED
            msg = (
                f"SageMaker notebook '{resource.name}' has direct outbound internet access enabled."
            )

        return Finding(
            rule_id=self.rule_id,
            rule_title=self.title,
            service=self.service,
            resource_arn=resource.arn,
            resource_id=resource.id,
            status=status,
            severity=self.severity,
            message=msg,
            remediation=(
                f"Recreate notebook '{resource.name}' in region '{resource.region}' "
                "with DirectInternetAccess=Disabled inside private VPC subnets."
            ),
            mitre_atlas=self.mitre_atlas,
            owasp_llm=self.owasp_llm,
            region=resource.region,
        )


class BedrockGuardrailsRule(BaseRule):
    rule_id = "AI-SPM-BEDROCK-003"
    title = "Bedrock Agent Missing Active Guardrail"
    description = "Bedrock Agents must have an active Guardrail configured to prevent excessive agency and prompt injection."
    severity = Severity.CRITICAL
    service = "bedrock"
    mitre_atlas = ["AML.T0043"]
    owasp_llm = ["LLM01:2025", "LLM06:2025"]
    nist_ai_rmf = ["MG-3.1"]

    def evaluate(self, resource: CloudResource) -> Finding:
        guardrail_id = resource.metadata.get("guardrail_id")
        if guardrail_id:
            status = Status.PASSED
            msg = f"Bedrock agent '{resource.name}' is protected by Guardrail {guardrail_id}."
        else:
            status = Status.FAILED
            msg = f"Bedrock agent '{resource.name}' has no Guardrail attached."

        return Finding(
            rule_id=self.rule_id,
            rule_title=self.title,
            service=self.service,
            resource_arn=resource.arn,
            resource_id=resource.id,
            status=status,
            severity=self.severity,
            message=msg,
            remediation=(
                f"aws bedrock-agent update-agent --agent-id {resource.id} --region {resource.region} "
                "--guardrail-configuration guardrailIdentifier=<guardrail-id>,guardrailVersion=1"
            ),
            mitre_atlas=self.mitre_atlas,
            owasp_llm=self.owasp_llm,
            nist_ai_rmf=self.nist_ai_rmf,
            region=resource.region,
        )


class OpenSearchVectorPublicAccessRule(BaseRule):
    rule_id = "AI-SPM-VECTOR-001"
    title = "Vector Database Publicly Exposed (Embedding Inversion Risk)"
    description = (
        "Vector databases must reside inside private VPCs to prevent embedding inversion attacks."
    )
    severity = Severity.CRITICAL
    service = "opensearch"
    mitre_atlas = ["AML.T0044"]
    owasp_llm = ["LLM02:2025"]

    def evaluate(self, resource: CloudResource) -> Finding:
        in_vpc = resource.metadata.get("in_vpc", False)
        if in_vpc:
            status = Status.PASSED
            msg = f"Vector database '{resource.name}' is isolated inside a VPC."
        else:
            status = Status.FAILED
            msg = f"Vector database '{resource.name}' has a public endpoint with no VPC isolation."

        return Finding(
            rule_id=self.rule_id,
            rule_title=self.title,
            service=self.service,
            resource_arn=resource.arn,
            resource_id=resource.id,
            status=status,
            severity=self.severity,
            message=msg,
            remediation=(
                f"Migrate vector domain '{resource.name}' ({resource.region}) into private VPC subnets "
                "and enable Fine-Grained Access Control (FGAC)."
            ),
            mitre_atlas=self.mitre_atlas,
            owasp_llm=self.owasp_llm,
            region=resource.region,
        )


class IAMWildcardPermissionsRule(BaseRule):
    rule_id = "AI-SPM-IAM-001"
    title = "Excessive Agency: Wildcard Actions in AI Execution Role"
    description = "AI agent and inference roles must not contain unrestricted wildcard permissions."
    severity = Severity.HIGH
    service = "iam"
    mitre_atlas = ["AML.T0043"]
    owasp_llm = ["LLM06:2025"]

    def evaluate(self, resource: CloudResource) -> Finding:
        has_wildcard = resource.metadata.get("has_wildcard_policy", False)
        if not has_wildcard:
            status = Status.PASSED
            msg = f"IAM role '{resource.name}' follows least-privilege scoping."
        else:
            status = Status.FAILED
            msg = f"IAM role '{resource.name}' grants wildcard ('*') administrative access."

        return Finding(
            rule_id=self.rule_id,
            rule_title=self.title,
            service=self.service,
            resource_arn=resource.arn,
            resource_id=resource.id,
            status=status,
            severity=self.severity,
            message=msg,
            remediation=(
                f"Scope down IAM role '{resource.name}' ({resource.arn}) to explicit service actions "
                "and target resource ARNs."
            ),
            mitre_atlas=self.mitre_atlas,
            owasp_llm=self.owasp_llm,
            region=resource.region,
        )


class MCPToolPoisoningRule(BaseRule):
    rule_id = "AI-SPM-MCP-001"
    title = "MCP Tool Manifest Poisoning: Suspicious Payload in Metadata"
    description = (
        "MCP tool descriptions must not contain obfuscated instructions or injection markers."
    )
    severity = Severity.CRITICAL
    service = "mcp"
    mitre_atlas = ["AML.T0010"]
    owasp_llm = ["LLM03:2025", "LLM06:2025"]

    def evaluate(self, resource: CloudResource) -> Finding:
        suspicious = resource.metadata.get("has_suspicious_instructions", False)
        if not suspicious:
            status = Status.PASSED
            msg = f"MCP server '{resource.name}' tool definitions passed security inspection."
        else:
            status = Status.FAILED
            msg = f"MCP server '{resource.name}' tool description contains hidden prompt injection markers."

        return Finding(
            rule_id=self.rule_id,
            rule_title=self.title,
            service=self.service,
            resource_arn=resource.arn,
            resource_id=resource.id,
            status=status,
            severity=self.severity,
            message=msg,
            remediation=(
                f"Remove or quarantine MCP server '{resource.name}' ({resource.arn}) "
                "and enforce manifest SHA-256 hash-pinning."
            ),
            mitre_atlas=self.mitre_atlas,
            owasp_llm=self.owasp_llm,
            region=resource.region,
        )


# Ensure config is referenced cleanly across the rules layer
_ = settings

registry.register(SageMakerDirectInternetAccessRule())
registry.register(BedrockGuardrailsRule())
registry.register(OpenSearchVectorPublicAccessRule())
registry.register(IAMWildcardPermissionsRule())
registry.register(MCPToolPoisoningRule())
