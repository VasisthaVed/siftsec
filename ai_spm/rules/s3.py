from ai_spm.config import settings
from ai_spm.engine.models import CloudResource, Finding, Severity, Status
from ai_spm.rules.base import BaseRule
from ai_spm.rules.registry import registry


class S3ModelEncryptionRule(BaseRule):
    rule_id = "AI-SPM-S3-001"
    title = "AI Model Weight Storage Lacks KMS CMK Encryption"
    description = (
        "Model weights must be encrypted at rest using AWS KMS Customer-Managed Keys (CMK)."
    )
    severity = Severity.CRITICAL
    service = "s3"
    mitre_atlas = ["AML.T0044"]
    owasp_llm = ["LLM02:2025"]
    nist_ai_rmf = ["MP-4.1"]

    def evaluate(self, resource: CloudResource) -> Finding:
        enc_type = resource.metadata.get("encryption_type", "NONE")
        kms_key = resource.metadata.get("kms_key_id")

        if (
            enc_type == settings.preferred_kms_encryption
            and kms_key
            and "alias/aws/s3" not in kms_key
        ):
            status = Status.PASSED
            msg = f"S3 bucket '{resource.name}' uses Customer-Managed KMS Key."
        else:
            status = Status.FAILED
            msg = f"S3 bucket '{resource.name}' uses default or unencrypted storage (enc: {enc_type})."

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
                f"aws s3api put-bucket-encryption --bucket {resource.name} --region {resource.region} "
                "--server-side-encryption-configuration "
                '\'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}\''
            ),
            mitre_atlas=self.mitre_atlas,
            owasp_llm=self.owasp_llm,
            nist_ai_rmf=self.nist_ai_rmf,
            region=resource.region,
        )


class S3BlockPublicAccessRule(BaseRule):
    rule_id = "AI-SPM-S3-002"
    title = "Public Access Allowed on AI Model/Dataset Bucket"
    description = "All public access block settings must be enabled on AI artifact buckets."
    severity = Severity.CRITICAL
    service = "s3"
    mitre_atlas = ["AML.T0044", "AML.T0020"]
    owasp_llm = ["LLM02:2025", "LLM03:2025"]

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
            status = Status.PASSED
            msg = f"S3 bucket '{resource.name}' blocks all public access."
        else:
            status = Status.FAILED
            msg = f"S3 bucket '{resource.name}' has public access block disabled or incomplete."

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
                f"aws s3api put-public-access-block --bucket {resource.name} --region {resource.region} "
                "--public-access-block-configuration "
                "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
            ),
            mitre_atlas=self.mitre_atlas,
            owasp_llm=self.owasp_llm,
            region=resource.region,
        )


class S3InsecureSerializationRule(BaseRule):
    rule_id = "AI-SPM-S3-004"
    title = "Insecure Model Deserialization Format Detected (Pickle vs SafeTensors)"
    description = "Model storage contains legacy serialized checkpoints vulnerable to RCE."
    severity = Severity.HIGH
    service = "s3"
    mitre_atlas = ["AML.T0010", "AML.T0020"]
    owasp_llm = ["LLM03:2025"]

    def evaluate(self, resource: CloudResource) -> Finding:
        extensions = resource.metadata.get("model_file_extensions", [])
        insecure_found = [ext for ext in extensions if ext in settings.insecure_model_extensions]
        has_safe = any(ext in settings.safe_model_extensions for ext in extensions)

        if insecure_found and not has_safe:
            status = Status.FAILED
            msg = f"Bucket '{resource.name}' stores legacy pickle files {insecure_found} without safe formats."
        else:
            status = Status.PASSED
            msg = f"Bucket '{resource.name}' enforces safe serialization formats or has no vulnerable pickles."

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
                f"Convert checkpoints in s3://{resource.name} ({insecure_found}) to "
                f"{settings.safe_model_extensions[0]} or enforce torch.load(..., weights_only=True)."
            ),
            mitre_atlas=self.mitre_atlas,
            owasp_llm=self.owasp_llm,
            region=resource.region,
        )


registry.register(S3ModelEncryptionRule())
registry.register(S3BlockPublicAccessRule())
registry.register(S3InsecureSerializationRule())
