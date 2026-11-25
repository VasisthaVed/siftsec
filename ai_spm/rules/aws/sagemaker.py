"""Amazon SageMaker security rules (Phase 3.3)."""

from ai_spm.engine.attrs import (
    SageMakerDomainAttrs,
    SageMakerEndpointConfigAttrs,
    SageMakerNotebookAttrs,
    SageMakerTrainingJobAttrs,
)
from ai_spm.engine.models import CloudResource, Finding, Severity
from ai_spm.rules.base import BaseRule
from ai_spm.rules.registry import registry
from ai_spm.rules.remediation import sh


class SageMakerNotebookVpcRule(BaseRule):
    rule_id = "AI-SPM-SAGEMAKER-002"
    title = "SageMaker Notebook Missing Custom VPC Attachment"
    description = "Notebooks must run inside a private VPC subnet for controlled egress."
    severity = Severity.HIGH
    service = "sagemaker"
    resource_kinds = frozenset({"sagemaker_notebook"})
    required_attrs = ("describe",)
    owasp_llm = ["LLM02:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = SageMakerNotebookAttrs.model_validate(resource.metadata)
        if attrs.subnet_id:
            return self.passed(
                resource, f"Notebook '{resource.name}' is attached to subnet {attrs.subnet_id}."
            )
        return self.failed(
            resource,
            f"SageMaker notebook '{resource.name}' is not attached to a custom VPC subnet.",
            remediation=f"Recreate notebook {sh(resource.name)} in {sh(resource.region)} with a private SubnetId.",
        )


class SageMakerNotebookRootAccessRule(BaseRule):
    rule_id = "AI-SPM-SAGEMAKER-003"
    title = "Root Privileges Enabled on SageMaker Notebook Instance"
    description = "Disable RootAccess to prevent tampering with telemetry agents and OS logs."
    severity = Severity.HIGH
    service = "sagemaker"
    resource_kinds = frozenset({"sagemaker_notebook"})
    required_attrs = ("describe",)
    owasp_llm = ["LLM03:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = SageMakerNotebookAttrs.model_validate(resource.metadata)
        if str(attrs.root_access).lower() == "disabled":
            return self.passed(resource, f"Notebook '{resource.name}' has RootAccess disabled.")
        return self.failed(
            resource,
            f"SageMaker notebook '{resource.name}' has RootAccess={attrs.root_access}.",
            remediation=(
                f"aws sagemaker update-notebook-instance --notebook-instance-name {sh(resource.name)} "
                f"--region {sh(resource.region)} --root-access Disabled"
            ),
        )


class SageMakerEndpointKmsRule(BaseRule):
    rule_id = "AI-SPM-SAGEMAKER-004"
    title = "SageMaker Endpoint Config Missing KMS Encryption"
    description = "EndpointConfig storage volumes and DataCaptureConfig should use KMS CMKs."
    severity = Severity.MEDIUM
    service = "sagemaker"
    resource_kinds = frozenset({"sagemaker_endpoint_config"})
    required_attrs = ("describe",)
    mitre_atlas = ["AML.T0044"]
    owasp_llm = ["LLM02:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = SageMakerEndpointConfigAttrs.model_validate(resource.metadata)
        if not attrs.kms_key_id:
            return self.failed(
                resource,
                f"EndpointConfig '{resource.name}' lacks KmsKeyId for storage encryption.",
                remediation=f"Recreate EndpointConfig {sh(resource.name)} with a Customer-Managed KmsKeyId.",
            )
        if attrs.data_capture_enabled and not attrs.data_capture_kms_key_id:
            return self.failed(
                resource,
                f"EndpointConfig '{resource.name}' enables DataCapture without KmsKeyId.",
                remediation=f"Configure DataCaptureConfig.KmsKeyId on EndpointConfig {sh(resource.name)}.",
                scope="data_capture",
            )
        return self.passed(resource, f"EndpointConfig '{resource.name}' configures KMS encryption.")


class SageMakerTrainingNetworkIsolationRule(BaseRule):
    rule_id = "AI-SPM-SAGEMAKER-005"
    title = "SageMaker Training Job Missing Network Isolation"
    description = "Training jobs running custom non-AWS containers should enable network isolation."
    severity = Severity.HIGH
    service = "sagemaker"
    resource_kinds = frozenset({"sagemaker_training_job"})
    required_attrs = ("describe",)
    mitre_atlas = ["AML.T0010"]
    owasp_llm = ["LLM04:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = SageMakerTrainingJobAttrs.model_validate(resource.metadata)
        if attrs.enable_network_isolation:
            return self.passed(
                resource, f"Training job '{resource.name}' enables network isolation."
            )
        if attrs.image_is_aws_owned is True:
            return self.passed(
                resource, f"Training job '{resource.name}' uses an AWS-owned DLC image."
            )
        return self.failed(
            resource,
            f"Training job '{resource.name}' runs custom container without EnableNetworkIsolation=True.",
            remediation=f"Set EnableNetworkIsolation=True on training job {sh(resource.name)}.",
        )


class SageMakerDomainPublicInternetRule(BaseRule):
    rule_id = "AI-SPM-SAGEMAKER-006"
    title = "SageMaker Studio Domain Uses PublicInternetOnly Network Mode"
    description = "SageMaker Domains should use VpcOnly mode instead of PublicInternetOnly."
    severity = Severity.HIGH
    service = "sagemaker"
    resource_kinds = frozenset({"sagemaker_domain"})
    required_attrs = ("describe",)
    owasp_llm = ["LLM02:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = SageMakerDomainAttrs.model_validate(resource.metadata)
        if attrs.app_network_access_type == "VpcOnly":
            return self.passed(resource, f"SageMaker Domain '{resource.name}' uses VpcOnly mode.")
        return self.failed(
            resource,
            f"SageMaker Domain '{resource.name}' uses {attrs.app_network_access_type or 'PublicInternetOnly'}.",
            remediation=f"Configure AppNetworkAccessType=VpcOnly on SageMaker Domain {sh(resource.name)}.",
        )


class SageMakerNotebookImdsv2Rule(BaseRule):
    rule_id = "AI-SPM-SAGEMAKER-007"
    title = "SageMaker Notebook Allows IMDSv1"
    description = "Require IMDSv2 (MinimumInstanceMetadataServiceVersion='2') to mitigate SSRF."
    severity = Severity.MEDIUM
    service = "sagemaker"
    resource_kinds = frozenset({"sagemaker_notebook"})
    required_attrs = ("describe",)

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = SageMakerNotebookAttrs.model_validate(resource.metadata)
        if attrs.min_imdsv_version == "2":
            return self.passed(resource, f"Notebook '{resource.name}' enforces IMDSv2.")
        return self.failed(
            resource,
            f"SageMaker notebook '{resource.name}' allows IMDSv1 (version={attrs.min_imdsv_version}).",
            remediation=(
                f"aws sagemaker update-notebook-instance --notebook-instance-name {sh(resource.name)} "
                f"--region {sh(resource.region)} "
                "--instance-metadata-service-configuration MinimumInstanceMetadataServiceVersion=2"
            ),
        )


registry.register(SageMakerNotebookVpcRule())
registry.register(SageMakerNotebookRootAccessRule())
registry.register(SageMakerEndpointKmsRule())
registry.register(SageMakerTrainingNetworkIsolationRule())
registry.register(SageMakerDomainPublicInternetRule())
registry.register(SageMakerNotebookImdsv2Rule())
