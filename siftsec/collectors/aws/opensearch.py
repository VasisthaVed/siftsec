# SPDX-License-Identifier: Apache-2.0
"""Amazon OpenSearch Service & OpenSearch Serverless collector (Phase 2.8)."""

import json
from fnmatch import fnmatch
from typing import Any, ClassVar, Literal

from siftsec.collectors.aws.base import (
    AWSBaseCollector,
    ResourceGoneError,
    policy_allows_public_principal,
)
from siftsec.collectors.aws.classify import classify_ai_workload
from siftsec.engine.attrs import OpenSearchDomainAttrs, OpenSearchServerlessAttrs
from siftsec.engine.models import CloudProvider, CloudResource


class OpenSearchCollector(AWSBaseCollector):
    """Collects OpenSearch managed domains (batches of 5) and Serverless collections."""

    service: ClassVar[str] = "opensearch"
    scope: ClassVar[Literal["regional", "global"]] = "regional"
    required_actions: ClassVar[tuple[str, ...]] = (
        "es:ListDomainNames",
        "es:DescribeDomains",
        "es:ListTags",
        "aoss:ListCollections",
        "aoss:BatchGetCollection",
        "aoss:ListSecurityPolicies",
        "aoss:GetSecurityPolicy",
    )

    def __init__(self, *args: Any, ai_only: bool = True, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.ai_only = ai_only

    def collect_region(self, region: str | None) -> list[CloudResource]:
        target_region = region or "us-east-1"
        out: list[CloudResource] = []
        out.extend(self._collect_domains(target_region))
        out.extend(self._collect_serverless(target_region))
        return out

    def _collect_domains(self, region: str) -> list[CloudResource]:
        os_client = self.factory.client("opensearch", region=region)
        out: list[CloudResource] = []

        list_resp = self.call({}, "domains", os_client.list_domain_names)
        if not isinstance(list_resp, dict):
            return out

        names = [str(d["DomainName"]) for d in list_resp.get("DomainNames", [])]
        # AWS DescribeDomains supports at most 5 domains per call.
        for idx in range(0, len(names), 5):
            batch = names[idx : idx + 5]
            desc_resp = self.call(
                {}, "describe_domains", os_client.describe_domains, DomainNames=batch
            )
            if not isinstance(desc_resp, dict):
                continue

            for dom in desc_resp.get("DomainStatusList", []):
                name = str(dom["DomainName"])
                arn = str(dom["ARN"])
                gaps: dict[str, str] = {}
                try:
                    tag_resp = self.call(gaps, "tags", os_client.list_tags, ARN=arn)
                    tags = (
                        {str(t["Key"]): str(t["Value"]) for t in tag_resp.get("TagList", [])}
                        if isinstance(tag_resp, dict)
                        else {}
                    )
                    is_ai, ai_reason = classify_ai_workload("opensearch", name, tags, self.cfg)
                    if self.ai_only and not is_ai:
                        continue

                    vpc_opts = dom.get("VPCOptions") or {}
                    adv = dom.get("AdvancedSecurityOptions") or {}
                    n2n = dom.get("NodeToNodeEncryptionOptions") or {}
                    ear = dom.get("EncryptionAtRestOptions") or {}
                    ep_opts = dom.get("DomainEndpointOptions") or {}

                    attrs = OpenSearchDomainAttrs(
                        vpc_id=vpc_opts.get("VPCId"),
                        subnet_ids=list(vpc_opts.get("SubnetIds", [])),
                        fgac_enabled=adv.get("Enabled"),
                        node_to_node_encryption=n2n.get("Enabled"),
                        encryption_at_rest=ear.get("Enabled"),
                        kms_key_id=ear.get("KmsKeyId"),
                        enforce_https=ep_opts.get("EnforceHTTPS"),
                        public_principal=policy_allows_public_principal(dom.get("AccessPolicies")),
                    )
                    meta = attrs.model_dump()
                    meta["in_vpc"] = bool(attrs.vpc_id)
                    out.append(
                        CloudResource(
                            arn=arn,
                            id=name,
                            name=name,
                            service="opensearch",
                            kind="opensearch_domain",
                            provider=CloudProvider.AWS,
                            region=region,
                            account_id=self.identity.account_id,
                            tags=tags,
                            gaps=gaps,
                            is_ai_workload=is_ai,
                            ai_reason=ai_reason,
                            metadata=meta,
                        )
                    )
                except ResourceGoneError:
                    continue
        return out

    def _collect_serverless(self, region: str) -> list[CloudResource]:
        aoss = self.factory.client("opensearchserverless", region=region)
        out: list[CloudResource] = []

        summaries = self.safe_paginate(
            aoss, "list_collections", "collectionSummaries", region=region
        )
        if not summaries:
            return out

        ids = [str(c["id"]) for c in summaries]
        collections: list[dict[str, Any]] = []
        for idx in range(0, len(ids), 100):
            batch_resp = self.call(
                {}, "batch_get_collection", aoss.batch_get_collection, ids=ids[idx : idx + 100]
            )
            if isinstance(batch_resp, dict):
                collections.extend(batch_resp.get("collectionDetails", []))

        net_policies = self._load_policies(aoss, "network")
        enc_policies = self._load_policies(aoss, "encryption")

        for col in collections:
            name = str(col["name"])
            arn = str(col["arn"])
            col_id = str(col["id"])
            is_ai, ai_reason = classify_ai_workload(
                "opensearch",
                name,
                {},
                self.cfg,
                extra_signals=["VECTORSEARCH collection"]
                if col.get("type") == "VECTORSEARCH"
                else (),
            )
            if self.ai_only and not is_ai:
                continue

            net_public = self._is_collection_public(name, net_policies)
            aws_owned_key = self._is_collection_aws_owned_key(name, enc_policies)

            attrs = OpenSearchServerlessAttrs(
                collection_type=col.get("type"),
                kms_key_arn=col.get("kmsKeyArn"),
                network_public=net_public,
                aws_owned_encryption_key=aws_owned_key,
            )
            meta = attrs.model_dump()
            meta["in_vpc"] = not bool(net_public) if net_public is not None else False
            out.append(
                CloudResource(
                    arn=arn,
                    id=col_id,
                    name=name,
                    service="opensearch",
                    kind="opensearch_serverless",
                    provider=CloudProvider.AWS,
                    region=region,
                    account_id=self.identity.account_id,
                    is_ai_workload=is_ai,
                    ai_reason=ai_reason,
                    metadata=meta,
                )
            )
        return out

    def _load_policies(self, aoss: Any, policy_type: str) -> list[dict[str, Any]]:
        resp = self.call(
            {}, f"{policy_type}_policies", aoss.list_security_policies, type=policy_type
        )
        if not isinstance(resp, dict):
            return []
        loaded: list[dict[str, Any]] = []
        for summary in resp.get("securityPolicySummaries", []):
            det = self.call(
                {},
                f"{policy_type}_policy",
                aoss.get_security_policy,
                name=summary["name"],
                type=policy_type,
            )
            if isinstance(det, dict) and "securityPolicyDetail" in det:
                loaded.append(det["securityPolicyDetail"])
        return loaded

    @staticmethod
    def _matches_collection(policy_detail: dict[str, Any], collection_name: str) -> bool:
        raw_pol = policy_detail.get("policy")
        rules = raw_pol if isinstance(raw_pol, list) else []
        for rule in rules:
            for res in rule.get("Rules", []):
                for target in res.get("Resource", []):
                    if fnmatch(f"collection/{collection_name}", str(target)):
                        return True
        return False

    def _is_collection_public(
        self, collection_name: str, net_policies: list[dict[str, Any]]
    ) -> bool | None:
        for det in net_policies:
            raw_pol = det.get("policy", [])
            if isinstance(raw_pol, str):
                try:
                    raw_pol = json.loads(raw_pol)
                except json.JSONDecodeError:
                    continue
            if not isinstance(raw_pol, list):
                continue
            for entry in raw_pol:
                matched = any(
                    fnmatch(f"collection/{collection_name}", str(t))
                    for r in entry.get("Rules", [])
                    for t in r.get("Resource", [])
                )
                if matched:
                    return bool(entry.get("AllowFromPublic", False)) and not bool(
                        entry.get("SourceVPCEs")
                    )
        return None

    def _is_collection_aws_owned_key(
        self, collection_name: str, enc_policies: list[dict[str, Any]]
    ) -> bool | None:
        for det in enc_policies:
            pol = det.get("policy")
            if not isinstance(pol, dict):
                continue
            matched = any(
                fnmatch(f"collection/{collection_name}", str(t))
                for r in pol.get("Rules", [])
                for t in r.get("Resource", [])
            )
            if matched:
                return bool(pol.get("AWSOwnedKey", False))
        return None
