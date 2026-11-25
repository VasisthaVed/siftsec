"""Amazon OpenSearch & Serverless Vector DB rules (Phase 3.6)."""

from ai_spm.engine.attrs import OpenSearchDomainAttrs, OpenSearchServerlessAttrs
from ai_spm.engine.models import CloudResource, Finding, Severity
from ai_spm.rules.base import BaseRule
from ai_spm.rules.registry import registry
from ai_spm.rules.remediation import sh


class OpenSearchFGACRule(BaseRule):
    rule_id = "AI-SPM-OPENSEARCH-002"
    title = "OpenSearch Vector DB Fine-Grained Access Control (FGAC) Disabled"
    description = "Enable FGAC on OpenSearch domains to enforce multi-tenant RAG isolation."
    severity = Severity.HIGH
    service = "opensearch"
    resource_kinds = frozenset({"opensearch_domain"})
    owasp_llm = ["LLM02:2026", "LLM09:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = OpenSearchDomainAttrs.model_validate(resource.metadata)
        if attrs.fgac_enabled:
            return self.passed(resource, f"OpenSearch domain '{resource.name}' enables FGAC.")
        return self.failed(
            resource,
            f"OpenSearch domain '{resource.name}' has Fine-Grained Access Control disabled.",
            remediation=f"Enable AdvancedSecurityOptions (FGAC) on OpenSearch domain {sh(resource.name)}.",
        )


class OpenSearchNodeToNodeEncryptionRule(BaseRule):
    rule_id = "AI-SPM-OPENSEARCH-003"
    title = "OpenSearch Vector DB Node-to-Node Encryption Disabled"
    description = "Encrypt inter-node cluster traffic containing vector embeddings."
    severity = Severity.HIGH
    service = "opensearch"
    resource_kinds = frozenset({"opensearch_domain"})
    owasp_llm = ["LLM02:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = OpenSearchDomainAttrs.model_validate(resource.metadata)
        if attrs.node_to_node_encryption:
            return self.passed(
                resource, f"OpenSearch domain '{resource.name}' encrypts node-to-node traffic."
            )
        return self.failed(
            resource,
            f"OpenSearch domain '{resource.name}' disables node-to-node encryption.",
            remediation=f"Enable NodeToNodeEncryptionOptions on OpenSearch domain {sh(resource.name)}.",
        )


class OpenSearchPublicAccessPolicyRule(BaseRule):
    rule_id = "AI-SPM-OPENSEARCH-004"
    title = "OpenSearch Vector DB Access Policy Allows Public Principal '*'"
    description = "OpenSearch domain access policies must not allow unconditioned Principal '*'."
    severity = Severity.CRITICAL
    service = "opensearch"
    resource_kinds = frozenset({"opensearch_domain"})
    mitre_atlas = ["AML.T0044"]
    owasp_llm = ["LLM02:2026", "LLM09:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = OpenSearchDomainAttrs.model_validate(resource.metadata)
        if not attrs.public_principal:
            return self.passed(
                resource, f"OpenSearch domain '{resource.name}' restricts access policy principals."
            )
        return self.failed(
            resource,
            f"OpenSearch domain '{resource.name}' access policy grants unconditioned Principal '*' access.",
            remediation=f"Replace Principal '*' in access policy for {sh(resource.name)} with explicit IAM roles/VPC conditions.",
        )


class OpenSearchServerlessPublicNetworkRule(BaseRule):
    rule_id = "AI-SPM-OPENSEARCH-007"
    title = "OpenSearch Serverless Vector Collection Allows Public Network Access"
    description = "Serverless vector collections must restrict network policies to VPC endpoints."
    severity = Severity.CRITICAL
    service = "opensearch"
    resource_kinds = frozenset({"opensearch_serverless"})
    mitre_atlas = ["AML.T0044"]
    owasp_llm = ["LLM02:2026", "LLM09:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = OpenSearchServerlessAttrs.model_validate(resource.metadata)
        if attrs.network_public is None:
            return self.skipped(
                resource, f"Network policy could not be resolved for '{resource.name}'."
            )
        if not attrs.network_public:
            return self.passed(
                resource, f"Serverless collection '{resource.name}' restricts public access."
            )
        return self.failed(
            resource,
            f"OpenSearch Serverless collection '{resource.name}' network policy sets AllowFromPublic=true.",
            remediation=f"Update AOSS network security policy for {sh(resource.name)} to AllowFromPublic=false with SourceVPCEs.",
        )


registry.register(OpenSearchFGACRule())
registry.register(OpenSearchNodeToNodeEncryptionRule())
registry.register(OpenSearchPublicAccessPolicyRule())
registry.register(OpenSearchServerlessPublicNetworkRule())
