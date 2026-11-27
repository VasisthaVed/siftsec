"""Two-phase AWS IAM collector inspecting only roles referenced by AI resources (Phase 2.9)."""

import json
from collections.abc import Iterable
from typing import Any, ClassVar, Literal

from siftsec.collectors.aws.base import AWSBaseCollector, ResourceGoneError
from siftsec.engine.attrs import IamRoleAttrs, PolicyStatement
from siftsec.engine.models import CloudProvider, CloudResource


def _as_str_list(val: Any) -> list[str]:
    if val is None:
        return []
    if isinstance(val, str):
        return [val]
    if isinstance(val, list):
        return [str(x) for x in val]
    return [str(val)]


def _parse_statements(doc: dict[str, Any]) -> list[PolicyStatement]:
    raw_stmts = doc.get("Statement", [])
    if isinstance(raw_stmts, dict):
        raw_stmts = [raw_stmts]
    out: list[PolicyStatement] = []
    for s in raw_stmts:
        if not isinstance(s, dict):
            continue
        out.append(
            PolicyStatement(
                effect=str(s.get("Effect", "")),
                actions=_as_str_list(s.get("Action")),
                not_actions=_as_str_list(s.get("NotAction")),
                resources=_as_str_list(s.get("Resource")),
                not_resources=_as_str_list(s.get("NotResource")),
                has_condition=bool(s.get("Condition")),
            )
        )
    return out


class IAMCollector(AWSBaseCollector):
    """Collects IAM policies and trust relationships for AI-referenced role ARNs."""

    service: ClassVar[str] = "iam"
    scope: ClassVar[Literal["regional", "global"]] = "global"
    required_actions: ClassVar[tuple[str, ...]] = (
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._policy_cache: dict[str, list[PolicyStatement]] = {}

    def collect_region(self, region: str | None) -> list[CloudResource]:
        return []

    def collect_roles(self, role_arns: Iterable[str]) -> list[CloudResource]:
        iam = self.factory.client("iam", region="us-east-1")
        out: list[CloudResource] = []
        for arn in sorted(set(role_arns)):
            if not arn:
                continue
            role_name = arn.rsplit("/", maxsplit=1)[-1]
            gaps: dict[str, str] = {}
            try:
                role_resp = self.call(gaps, "role", iam.get_role, RoleName=role_name)
                if not isinstance(role_resp, dict):
                    out.append(
                        CloudResource(
                            arn=arn,
                            id=role_name,
                            name=role_name,
                            service="iam",
                            kind="iam_role",
                            provider=CloudProvider.AWS,
                            region="global",
                            account_id=self.identity.account_id,
                            gaps=gaps,
                            is_ai_workload=True,
                            ai_reason="attached to AI resource",
                            metadata=IamRoleAttrs().model_dump(),
                        )
                    )
                    continue

                role_obj = role_resp["Role"]
                trust_doc = role_obj.get("AssumeRolePolicyDocument") or {}
                trust_principals, trust_has_cond = self._parse_trust(trust_doc)
                boundary = (role_obj.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")

                statements: list[PolicyStatement] = []
                attached_arns: list[str] = []

                for pol in self.paginate(
                    iam, "list_attached_role_policies", "AttachedPolicies", RoleName=role_name
                ):
                    pol_arn = str(pol["PolicyArn"])
                    attached_arns.append(pol_arn)
                    statements.extend(self._fetch_managed_policy(iam, pol_arn, gaps))

                inline_names = list(
                    self.paginate(iam, "list_role_policies", "PolicyNames", RoleName=role_name)
                )
                for p_name in inline_names:
                    inline_resp = self.call(
                        gaps,
                        "inline_policy",
                        iam.get_role_policy,
                        RoleName=role_name,
                        PolicyName=p_name,
                    )
                    if isinstance(inline_resp, dict):
                        doc = inline_resp.get("PolicyDocument") or {}
                        if isinstance(doc, str):
                            doc = json.loads(doc)
                        statements.extend(_parse_statements(doc))

                has_wildcard = any(
                    st.effect == "Allow"
                    and ("*" in st.actions or any(a.endswith(":*") for a in st.actions))
                    and "*" in st.resources
                    and not st.has_condition
                    for st in statements
                )

                attrs = IamRoleAttrs(
                    statements=statements,
                    attached_managed_arns=attached_arns,
                    trust_principals=trust_principals,
                    trust_has_source_condition=trust_has_cond,
                    permissions_boundary_arn=boundary,
                )
                meta = attrs.model_dump()
                meta["has_wildcard_policy"] = has_wildcard

                out.append(
                    CloudResource(
                        arn=str(role_obj.get("Arn", arn)),
                        id=role_name,
                        name=role_name,
                        service="iam",
                        kind="iam_role",
                        provider=CloudProvider.AWS,
                        region="global",
                        account_id=self.identity.account_id,
                        gaps=gaps,
                        is_ai_workload=True,
                        ai_reason="attached to AI resource",
                        metadata=meta,
                    )
                )
            except ResourceGoneError:
                continue
        return out

    def _fetch_managed_policy(
        self, iam: Any, policy_arn: str, gaps: dict[str, str]
    ) -> list[PolicyStatement]:
        if policy_arn in self._policy_cache:
            return self._policy_cache[policy_arn]
        pol_resp = self.call(gaps, "managed_policy", iam.get_policy, PolicyArn=policy_arn)
        if not isinstance(pol_resp, dict):
            return []
        ver_id = pol_resp["Policy"]["DefaultVersionId"]
        ver_resp = self.call(
            gaps,
            "managed_policy_version",
            iam.get_policy_version,
            PolicyArn=policy_arn,
            VersionId=ver_id,
        )
        if not isinstance(ver_resp, dict):
            return []
        doc = ver_resp["PolicyVersion"].get("Document") or {}
        if isinstance(doc, str):
            doc = json.loads(doc)
        parsed = _parse_statements(doc)
        self._policy_cache[policy_arn] = parsed
        return parsed

    @staticmethod
    def _parse_trust(trust_doc: dict[str, Any]) -> tuple[list[str], bool]:
        principals: list[str] = []
        has_source_cond = False
        raw = trust_doc.get("Statement", [])
        if isinstance(raw, dict):
            raw = [raw]
        for stmt in raw:
            p = stmt.get("Principal", {})
            if isinstance(p, dict) and "Service" in p:
                principals.extend(_as_str_list(p["Service"]))
            cond_str = json.dumps(stmt.get("Condition", {})).lower()
            if any(k in cond_str for k in ("aws:sourceaccount", "aws:sourcearn", "sts:externalid")):
                has_source_cond = True
        return principals, has_source_cond
