# SPDX-License-Identifier: Apache-2.0
"""Google Cloud Platform (Vertex AI & GCS) security posture rules (Phase 6.2)."""

from siftsec.engine.attrs import (
    GcpGcsBucketAttrs,
    GcpVertexEndpointAttrs,
    GcpVertexWorkbenchAttrs,
)
from siftsec.engine.models import CloudResource, Finding, Severity
from siftsec.rules.base import BaseRule
from siftsec.rules.registry import registry
from siftsec.rules.remediation import sh


class GcpVertexWorkbenchPublicIpRule(BaseRule):
    rule_id = "SIFTSEC-GCP-001"
    title = "Vertex AI Workbench Instance Exposes Public IP"
    description = "Vertex AI Workbench notebooks should disable public IPs and route traffic over private VPC."
    severity = Severity.HIGH
    service = "gcp_vertex"
    resource_kinds = frozenset({"gcp_vertex_workbench"})
    required_attrs = ("no_public_ip",)
    mitre_atlas = ["AML.T0000"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = GcpVertexWorkbenchAttrs.model_validate(resource.metadata)
        if attrs.no_public_ip is True:
            return self.passed(
                resource, f"Vertex Workbench '{resource.name}' has public IP disabled."
            )
        return self.failed(
            resource,
            f"Vertex Workbench '{resource.name}' allows a public IP address.",
            remediation=(
                f"Recreate or update Workbench instance {sh(resource.name)} in "
                f"{sh(resource.region)} with --no-public-ip enabled."
            ),
        )


class GcpVertexWorkbenchCmekRule(BaseRule):
    rule_id = "SIFTSEC-GCP-002"
    title = "Vertex AI Workbench Boot Disk Lacks Customer-Managed Encryption Key (CMEK)"
    description = (
        "Encrypt Vertex AI Workbench disks with Cloud KMS CMEK to retain key revocation control."
    )
    severity = Severity.MEDIUM
    service = "gcp_vertex"
    resource_kinds = frozenset({"gcp_vertex_workbench"})

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = GcpVertexWorkbenchAttrs.model_validate(resource.metadata)
        if attrs.kms_key_name:
            return self.passed(resource, f"Vertex Workbench '{resource.name}' uses CMEK.")
        return self.failed(
            resource,
            f"Vertex Workbench '{resource.name}' uses Google-managed encryption instead of CMEK.",
            remediation=(
                f"Configure a Cloud KMS CMEK key on Vertex Workbench {sh(resource.name)}."
            ),
        )


class GcpVertexEndpointPrivateRule(BaseRule):
    rule_id = "SIFTSEC-GCP-003"
    title = "Vertex AI Prediction Endpoint Is Publicly Routable"
    description = "Serve sensitive AI inference over Private Service Connect or VPC peering rather than public endpoints."
    severity = Severity.HIGH
    service = "gcp_vertex"
    resource_kinds = frozenset({"gcp_vertex_endpoint"})
    required_attrs = ("private_endpoint_enabled",)
    owasp_llm = ["LLM10:2025"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = GcpVertexEndpointAttrs.model_validate(resource.metadata)
        if attrs.private_endpoint_enabled is True:
            return self.passed(
                resource, f"Vertex endpoint '{resource.name}' is restricted to private VPC/PSC."
            )
        return self.failed(
            resource,
            f"Vertex endpoint '{resource.name}' is exposed as a public prediction endpoint.",
            remediation=(
                f"Deploy Vertex endpoint {sh(resource.name)} using Private Service Connect "
                f"or VPC peering."
            ),
        )


class GcpGcsPublicAccessPreventionRule(BaseRule):
    rule_id = "SIFTSEC-GCP-004"
    title = "GCS AI Model Bucket Does Not Enforce Public Access Prevention"
    description = "Model/training GCS buckets must set publicAccessPrevention to 'enforced'."
    severity = Severity.CRITICAL
    service = "gcp_gcs"
    resource_kinds = frozenset({"gcp_gcs_bucket"})
    required_attrs = ("public_access_prevention",)
    owasp_llm = ["LLM06:2025"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = GcpGcsBucketAttrs.model_validate(resource.metadata)
        if (attrs.public_access_prevention or "").lower() == "enforced":
            return self.passed(
                resource, f"GCS bucket '{resource.name}' enforces Public Access Prevention."
            )
        return self.failed(
            resource,
            f"GCS AI bucket '{resource.name}' has public_access_prevention={attrs.public_access_prevention!r}.",
            remediation=(
                f"Run `gcloud storage buckets update gs://{sh(resource.name)} "
                f"--public-access-prevention`."
            ),
        )


class GcpGcsUniformAccessRule(BaseRule):
    rule_id = "SIFTSEC-GCP-005"
    title = "GCS AI Bucket Missing Uniform Bucket-Level Access"
    description = "Disable legacy per-object ACLs on AI buckets using Uniform Bucket-Level Access."
    severity = Severity.MEDIUM
    service = "gcp_gcs"
    resource_kinds = frozenset({"gcp_gcs_bucket"})
    required_attrs = ("uniform_bucket_level_access",)

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = GcpGcsBucketAttrs.model_validate(resource.metadata)
        if attrs.uniform_bucket_level_access is True:
            return self.passed(
                resource, f"GCS bucket '{resource.name}' enables Uniform Bucket-Level Access."
            )
        return self.failed(
            resource,
            f"GCS AI bucket '{resource.name}' allows legacy object-level ACLs.",
            remediation=(
                f"Run `gcloud storage buckets update gs://{sh(resource.name)} "
                f"--uniform-bucket-level-access`."
            ),
        )


class GcpGcsCmekAndVersioningRule(BaseRule):
    rule_id = "SIFTSEC-GCP-006"
    title = "GCS AI Bucket Lacks CMEK or Object Versioning"
    description = "Model artifact buckets should enable object versioning and Cloud KMS CMEK."
    severity = Severity.MEDIUM
    service = "gcp_gcs"
    resource_kinds = frozenset({"gcp_gcs_bucket"})

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = GcpGcsBucketAttrs.model_validate(resource.metadata)
        if attrs.kms_key_name and attrs.versioning_enabled is True:
            return self.passed(
                resource, f"GCS bucket '{resource.name}' enables CMEK and versioning."
            )
        return self.failed(
            resource,
            f"GCS AI bucket '{resource.name}' missing CMEK ({bool(attrs.kms_key_name)}) "
            f"or versioning ({attrs.versioning_enabled}).",
            remediation=(
                f"Enable Cloud KMS CMEK and object versioning on gs://{sh(resource.name)}."
            ),
        )


registry.register(GcpVertexWorkbenchPublicIpRule())
registry.register(GcpVertexWorkbenchCmekRule())
registry.register(GcpVertexEndpointPrivateRule())
registry.register(GcpGcsPublicAccessPreventionRule())
registry.register(GcpGcsUniformAccessRule())
registry.register(GcpGcsCmekAndVersioningRule())
