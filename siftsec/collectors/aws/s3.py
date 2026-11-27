"""Amazon S3 collector for AI model weights and training datasets (Phase 2.4)."""

from collections import Counter
from pathlib import PurePosixPath
from typing import Any, ClassVar, Literal

from siftsec.collectors.aws.base import ABSENT, AWSBaseCollector, ResourceGoneError
from siftsec.collectors.aws.classify import classify_ai_workload
from siftsec.engine.attrs import PublicAccessBlock, S3BucketAttrs
from siftsec.engine.models import CloudProvider, CloudResource
from siftsec.utils.aws_arn import build_arn

_ABSENT_TAGS = frozenset({"NoSuchTagSet", "NoSuchTagSetError"})
_ABSENT_ENC = frozenset({"ServerSideEncryptionConfigurationNotFoundError"})
_ABSENT_PAB = frozenset({"NoSuchPublicAccessBlockConfiguration"})
_ABSENT_POLICY = frozenset({"NoSuchBucketPolicy"})


def _normalize_region(loc: str | None) -> str:
    if not loc:
        return "us-east-1"
    if loc == "EU":
        return "eu-west-1"
    return loc


class S3Collector(AWSBaseCollector):
    """Collects S3 buckets, classifying AI workloads early before deep describes."""

    service: ClassVar[str] = "s3"
    scope: ClassVar[Literal["regional", "global"]] = "global"
    required_actions: ClassVar[tuple[str, ...]] = (
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketTagging",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketVersioning",
        "s3:ListBucket",
        "s3:GetAccountPublicAccessBlock",
        "kms:DescribeKey",
    )

    def __init__(self, *args: Any, ai_only: bool = True, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.ai_only = ai_only
        self._account_pab_cached: bool | None = None
        self._account_pab_checked = False

    def _get_account_pab(self, gaps: dict[str, str]) -> bool | None:
        if self._account_pab_checked:
            return self._account_pab_cached
        self._account_pab_checked = True
        s3control = self.factory.client("s3control", region="us-east-1")
        resp = self.call(
            gaps,
            "account_public_access",
            s3control.get_public_access_block,
            AccountId=self.identity.account_id,
            absent=_ABSENT_PAB,
        )
        if resp is ABSENT:
            self._account_pab_cached = False
        elif isinstance(resp, dict):
            conf = resp.get("PublicAccessBlockConfiguration", {})
            self._account_pab_cached = all(
                bool(conf.get(k, False))
                for k in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            )
        return self._account_pab_cached

    def collect_region(self, region: str | None) -> list[CloudResource]:
        global_s3 = self.factory.client("s3", region="us-east-1")
        list_gaps: dict[str, str] = {}
        buckets = self.call(list_gaps, "list_buckets", global_s3.list_buckets)
        if not isinstance(buckets, dict):
            return []

        resources: list[CloudResource] = []
        for bucket in buckets.get("Buckets", []):
            name = str(bucket["Name"])
            try:
                res = self._inspect_bucket(global_s3, name, bucket.get("BucketRegion"))
                if res is not None:
                    resources.append(res)
            except ResourceGoneError:
                continue
        return resources

    def _inspect_bucket(
        self,
        global_s3: Any,
        name: str,
        hinted_region: str | None,
    ) -> CloudResource | None:
        gaps: dict[str, str] = {}
        bucket_region = hinted_region
        if not bucket_region:
            loc_resp = self.call(gaps, "location", global_s3.get_bucket_location, Bucket=name)
            if isinstance(loc_resp, dict):
                bucket_region = _normalize_region(loc_resp.get("LocationConstraint"))
            else:
                bucket_region = "us-east-1"

        regional_s3 = self.factory.client("s3", region=bucket_region)

        tags: dict[str, str] = {}
        tag_resp = self.call(
            gaps, "tags", regional_s3.get_bucket_tagging, Bucket=name, absent=_ABSENT_TAGS
        )
        if isinstance(tag_resp, dict):
            tags = {str(t["Key"]): str(t["Value"]) for t in tag_resp.get("TagSet", [])}

        is_ai, ai_reason = classify_ai_workload("s3", name, tags, self.cfg)
        if self.ai_only and not is_ai:
            return None

        # Encryption + CMK ownership check
        sse_alg: Literal["AES256", "aws:kms", "aws:kms:dsse"] | None = None
        kms_key_arn: str | None = None
        kms_is_cmk: bool | None = None
        enc_resp = self.call(
            gaps,
            "encryption",
            regional_s3.get_bucket_encryption,
            Bucket=name,
            absent=_ABSENT_ENC,
        )
        if enc_resp is ABSENT:
            sse_alg = "AES256"
        elif isinstance(enc_resp, dict):
            rules = enc_resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if rules:
                default_sse = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                raw_alg = default_sse.get("SSEAlgorithm")
                if raw_alg in ("AES256", "aws:kms", "aws:kms:dsse"):
                    sse_alg = raw_alg
                kms_key_arn = default_sse.get("KMSMasterKeyID")
                if sse_alg in ("aws:kms", "aws:kms:dsse"):
                    if not kms_key_arn or "alias/aws/s3" in kms_key_arn:
                        kms_is_cmk = False
                    else:
                        kms = self.factory.client("kms", region=bucket_region)
                        key_resp = self.call(gaps, "kms_key", kms.describe_key, KeyId=kms_key_arn)
                        if isinstance(key_resp, dict):
                            kms_is_cmk = (
                                key_resp.get("KeyMetadata", {}).get("KeyManager") == "CUSTOMER"
                            )

        # Public access block + account PAB + policy status
        pab_obj: PublicAccessBlock | None = None
        pab_absent: bool | None = None
        pab_resp = self.call(
            gaps,
            "public_access",
            regional_s3.get_public_access_block,
            Bucket=name,
            absent=_ABSENT_PAB,
        )
        if pab_resp is ABSENT:
            pab_absent = True
        elif isinstance(pab_resp, dict):
            pab_absent = False
            conf = pab_resp.get("PublicAccessBlockConfiguration", {})
            pab_obj = PublicAccessBlock(
                block_public_acls=bool(conf.get("BlockPublicAcls", False)),
                ignore_public_acls=bool(conf.get("IgnorePublicAcls", False)),
                block_public_policy=bool(conf.get("BlockPublicPolicy", False)),
                restrict_public_buckets=bool(conf.get("RestrictPublicBuckets", False)),
            )

        acct_pab = self._get_account_pab(gaps)

        is_public_policy: bool | None = None
        pol_resp = self.call(
            gaps,
            "policy_status",
            regional_s3.get_bucket_policy_status,
            Bucket=name,
            absent=_ABSENT_POLICY,
        )
        if pol_resp is ABSENT:
            is_public_policy = False
        elif isinstance(pol_resp, dict):
            is_public_policy = bool(pol_resp.get("PolicyStatus", {}).get("IsPublic", False))

        # Versioning
        versioning: Literal["Enabled", "Suspended", "Disabled"] | None = None
        ver_resp = self.call(gaps, "versioning", regional_s3.get_bucket_versioning, Bucket=name)
        if isinstance(ver_resp, dict):
            raw_ver = ver_resp.get("Status")
            versioning = raw_ver if raw_ver in ("Enabled", "Suspended") else "Disabled"

        # Sample keys (single page, never download bodies)
        sampled_keys: list[str] = []
        ext_counts: Counter[str] = Counter()
        obj_resp = self.call(
            gaps,
            "sampled_keys",
            regional_s3.list_objects_v2,
            Bucket=name,
            MaxKeys=self.cfg.s3_key_sample_size,
        )
        if isinstance(obj_resp, dict):
            for obj in obj_resp.get("Contents", []):
                key = str(obj["Key"])
                sampled_keys.append(key)
                ext = PurePosixPath(key).suffix.lower()
                if ext in (self.cfg.insecure_model_extensions + self.cfg.safe_model_extensions):
                    ext_counts[ext] += 1

        attrs = S3BucketAttrs(
            sse_algorithm=sse_alg,
            kms_key_arn=kms_key_arn,
            kms_key_is_cmk=kms_is_cmk,
            public_access_block=pab_obj,
            pab_absent=pab_absent,
            account_pab_all_enabled=acct_pab,
            is_public_by_policy=is_public_policy,
            versioning=versioning,
            sampled_keys=sampled_keys,
            model_extension_counts=dict(ext_counts),
        )

        # Keep compatibility metadata populated for existing rules until Phase 3 attrs migration
        compat_meta = attrs.model_dump()
        compat_meta["encryption_type"] = sse_alg or "NONE"
        compat_meta["kms_key_id"] = kms_key_arn
        compat_meta["model_file_extensions"] = list(ext_counts.keys())
        if pab_obj is not None:
            compat_meta["public_access_block"] = {
                "BlockPublicAcls": pab_obj.block_public_acls,
                "IgnorePublicAcls": pab_obj.ignore_public_acls,
                "BlockPublicPolicy": pab_obj.block_public_policy,
                "RestrictPublicBuckets": pab_obj.restrict_public_buckets,
            }
        elif pab_absent:
            compat_meta["public_access_block"] = {}

        return CloudResource(
            arn=build_arn(self.identity.partition, "s3", "", "", name),
            id=name,
            name=name,
            service="s3",
            kind="s3_bucket",
            provider=CloudProvider.AWS,
            region=bucket_region,
            account_id=self.identity.account_id,
            tags=tags,
            gaps=gaps,
            is_ai_workload=is_ai,
            ai_reason=ai_reason,
            metadata=compat_meta,
        )
