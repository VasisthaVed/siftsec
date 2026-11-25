import shlex

from ai_spm.config import settings
from ai_spm.engine.models import CloudResource, Finding, Severity
from ai_spm.rules.base import BaseRule
from ai_spm.rules.registry import registry


class S3ModelEncryptionRule(BaseRule):
    rule_id = "AI-SPM-S3-001"
    title = "AI Model Weight Storage Lacks KMS CMK Encryption"
    description = (
        "Model weights must be encrypted at rest using AWS KMS Customer-Managed Keys (CMK)."
    )
    severity = Severity.MEDIUM
    service = "s3"
    required_attrs = ("encryption",)
    mitre_atlas = ["AML.T0044"]
    owasp_llm = ["LLM02:2026"]
    nist_ai_rmf = ["MP-4.1"]

    def evaluate(self, resource: CloudResource) -> Finding:
        enc_type = resource.metadata.get("encryption_type", "NONE")
        kms_key = resource.metadata.get("kms_key_id")
        kms_is_cmk = resource.metadata.get("kms_key_is_cmk")

        if enc_type in (settings.preferred_kms_encryption, "aws:kms:dsse"):
            if kms_is_cmk is False or (kms_key and "alias/aws/s3" in str(kms_key)):
                pass
            elif kms_is_cmk is None and "kms_key" in resource.gaps:
                return self.skipped(
                    resource,
                    "KMS key ownership could not be determined (kms:DescribeKey denied).",
                )
            elif kms_key:
                return self.passed(
                    resource, f"S3 bucket '{resource.name}' uses Customer-Managed KMS Key."
                )

        remediation = (
            f"aws s3api put-bucket-encryption --bucket {shlex.quote(resource.name)} "
            f"--region {shlex.quote(resource.region)} "
            "--server-side-encryption-configuration "
            '\'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}\''
        )
        return self.failed(
            resource,
            f"S3 bucket '{resource.name}' uses default or non-CMK encryption (enc: {enc_type}).",
            remediation=remediation,
            evidence={"encryption_type": str(enc_type)},
        )


class S3BlockPublicAccessRule(BaseRule):
    rule_id = "AI-SPM-S3-002"
    title = "Public Access Allowed on AI Model/Dataset Bucket"
    description = "All public access block settings must be enabled on AI artifact buckets."
    severity = Severity.CRITICAL
    service = "s3"
    required_attrs = ("public_access",)
    mitre_atlas = ["AML.T0044", "AML.T0020"]
    owasp_llm = ["LLM02:2026", "LLM05:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        pab = resource.metadata.get("public_access_block", {})
        all_blocked = all(
            [
                pab.get("BlockPublicAcls", False),
                pab.get("IgnorePublicAcls", False),
                pab.get("BlockPublicPolicy", False),
                pab.get("RestrictPublicBuckets", False),
            ]
        )
        if all_blocked:
            return self.passed(resource, f"S3 bucket '{resource.name}' blocks all public access.")

        remediation = (
            f"aws s3api put-public-access-block --bucket {shlex.quote(resource.name)} "
            f"--region {shlex.quote(resource.region)} "
            "--public-access-block-configuration "
            "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
        )
        return self.failed(
            resource,
            f"S3 bucket '{resource.name}' has public access block disabled or incomplete.",
            remediation=remediation,
        )


class S3InsecureSerializationRule(BaseRule):
    rule_id = "AI-SPM-S3-004"
    title = "Insecure Model Deserialization Format Detected (Pickle vs SafeTensors)"
    description = "Model storage contains legacy serialized checkpoints vulnerable to RCE."
    severity = Severity.MEDIUM
    service = "s3"
    required_attrs = ("sampled_keys",)
    mitre_atlas = ["AML.T0010"]
    owasp_llm = ["LLM04:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        extensions = resource.metadata.get("model_file_extensions", [])
        insecure_found = [ext for ext in extensions if ext in settings.insecure_model_extensions]
        has_safe = any(ext in settings.safe_model_extensions for ext in extensions)

        if not (insecure_found and not has_safe):
            return self.passed(
                resource,
                f"Bucket '{resource.name}' enforces safe serialization formats or has no vulnerable pickles.",
            )

        remediation = (
            f"Heuristic warning: convert checkpoints in s3://{resource.name} ({insecure_found}) to "
            f"{settings.safe_model_extensions[0]} or run `tensorguard scan --local` for opcode verification."
        )
        return self.failed(
            resource,
            f"Bucket '{resource.name}' stores legacy pickle files {insecure_found} without safe formats.",
            remediation=remediation,
            evidence={"extensions": ",".join(insecure_found)},
        )


class S3DatasetVersioningRule(BaseRule):
    rule_id = "AI-SPM-S3-003"
    title = "Missing Object Versioning on AI Training Dataset Bucket"
    description = (
        "Enable S3 Object Versioning to protect training/fine-tuning datasets from tampering."
    )
    severity = Severity.MEDIUM
    service = "s3"
    resource_kinds = frozenset({"s3_bucket"})
    required_attrs = ("versioning",)
    mitre_atlas = ["AML.T0020"]
    owasp_llm = ["LLM05:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        is_dataset = (
            "dataset" in resource.name.lower() or resource.tags.get("data", "").lower() == "dataset"
        )
        if not is_dataset:
            return self.skipped(
                resource, f"Bucket '{resource.name}' is not tagged/named as a dataset."
            )
        ver = resource.metadata.get("versioning")
        if ver == "Enabled":
            return self.passed(
                resource, f"S3 bucket '{resource.name}' has Object Versioning enabled."
            )
        return self.failed(
            resource,
            f"S3 bucket '{resource.name}' has Object Versioning {ver or 'Disabled'}.",
            remediation=(
                f"aws s3api put-bucket-versioning --bucket {shlex.quote(resource.name)} "
                f"--region {shlex.quote(resource.region)} --versioning-configuration Status=Enabled"
            ),
        )


registry.register(S3ModelEncryptionRule())
registry.register(S3BlockPublicAccessRule())
registry.register(S3DatasetVersioningRule())
registry.register(S3InsecureSerializationRule())
