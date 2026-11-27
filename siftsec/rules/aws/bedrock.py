"""Amazon Bedrock security rules (Phase 3.4)."""

from siftsec.engine.attrs import (
    BedrockAccountConfigAttrs,
    BedrockAgentAttrs,
    BedrockDataSourceAttrs,
)
from siftsec.engine.models import CloudResource, Finding, Severity
from siftsec.rules.base import BaseRule
from siftsec.rules.registry import registry
from siftsec.rules.remediation import sh


class BedrockInvocationLoggingRule(BaseRule):
    rule_id = "SIFTSEC-BEDROCK-001"
    title = "Bedrock Model Invocation Logging Disabled"
    description = (
        "Enable Model Invocation Logging to CloudWatch or S3 for prompt injection forensics."
    )
    severity = Severity.HIGH
    service = "bedrock"
    resource_kinds = frozenset({"bedrock_account_config"})
    required_attrs = ("logging",)
    owasp_llm = ["LLM01:2026", "LLM02:2026"]
    nist_ai_rmf = ["MS-2.7"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = BedrockAccountConfigAttrs.model_validate(resource.metadata)
        if not attrs.bedrock_in_use:
            return self.skipped(
                resource, f"No Bedrock agents/guardrails/KBs active in {resource.region}."
            )
        if attrs.logging_enabled:
            return self.passed(
                resource, f"Bedrock invocation logging enabled in {resource.region}."
            )
        return self.failed(
            resource,
            f"Bedrock Model Invocation Logging is disabled in {resource.region}.",
            remediation=(
                f"aws bedrock put-model-invocation-logging-configuration --region {sh(resource.region)} "
                '--logging-config \'{"cloudWatchConfig":{"logGroupName":"/aws/bedrock/invocations"}}\''
            ),
        )


class BedrockDataSourceKmsRule(BaseRule):
    rule_id = "SIFTSEC-BEDROCK-002"
    title = "Bedrock Knowledge Base Data Source Missing KMS CMK"
    description = "Knowledge Base data sources should configure a Customer-Managed KMS Key."
    severity = Severity.HIGH
    service = "bedrock"
    resource_kinds = frozenset({"bedrock_data_source"})
    required_attrs = ("describe",)
    mitre_atlas = ["AML.T0044"]
    owasp_llm = ["LLM02:2026", "LLM09:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = BedrockDataSourceAttrs.model_validate(resource.metadata)
        if attrs.kms_key_arn:
            return self.passed(resource, f"DataSource '{resource.name}' uses KMS CMK.")
        return self.failed(
            resource,
            f"Bedrock DataSource '{resource.name}' has no customer-managed key configured.",
            remediation=(
                f"Configure serverSideEncryptionConfiguration.kmsKeyArn on DataSource {sh(resource.id)} "
                f"(KB {sh(attrs.knowledge_base_id)})."
            ),
        )


class BedrockAgentSessionKmsRule(BaseRule):
    rule_id = "SIFTSEC-BEDROCK-004"
    title = "Bedrock Agent Missing Customer KMS Key for Session Memory"
    description = "Bedrock Agent session and memory data should use a Customer-Managed KMS Key."
    severity = Severity.MEDIUM
    service = "bedrock"
    resource_kinds = frozenset({"bedrock_agent"})
    required_attrs = ("describe",)
    owasp_llm = ["LLM02:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = BedrockAgentAttrs.model_validate(resource.metadata)
        if attrs.customer_encryption_key_arn:
            return self.passed(
                resource, f"Bedrock Agent '{resource.name}' configures customer KMS key."
            )
        return self.failed(
            resource,
            f"Bedrock Agent '{resource.name}' lacks customerEncryptionKeyArn.",
            remediation=(
                f"aws bedrock-agent update-agent --agent-id {sh(resource.id)} "
                f"--region {sh(resource.region)} --customer-encryption-key-arn <kms-key-arn>"
            ),
        )


registry.register(BedrockInvocationLoggingRule())
registry.register(BedrockDataSourceKmsRule())
registry.register(BedrockAgentSessionKmsRule())
