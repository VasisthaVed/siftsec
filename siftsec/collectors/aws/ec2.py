"""EC2 Security Group collector for Shadow AI port exposure (Phase 2.10)."""

from typing import ClassVar, Literal

from siftsec.collectors.aws.base import AWSBaseCollector
from siftsec.engine.attrs import EC2SecurityGroupAttrs, IngressRule
from siftsec.engine.models import CloudProvider, CloudResource
from siftsec.utils.aws_arn import build_arn


class EC2SecurityGroupCollector(AWSBaseCollector):
    """Collects EC2 Security Groups and normalized ingress rules."""

    service: ClassVar[str] = "ec2"
    scope: ClassVar[Literal["regional", "global"]] = "regional"
    required_actions: ClassVar[tuple[str, ...]] = (
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkInterfaces",
    )

    def collect_region(self, region: str | None) -> list[CloudResource]:
        target_region = region or "us-east-1"
        ec2 = self.factory.client("ec2", region=target_region)
        out: list[CloudResource] = []

        attached_sgs: set[str] = set()
        eni_gaps: dict[str, str] = {}
        try:
            for eni in self.paginate(ec2, "describe_network_interfaces", "NetworkInterfaces"):
                for g in eni.get("Groups", []):
                    if g.get("GroupId"):
                        attached_sgs.add(str(g["GroupId"]))
        except Exception:  # noqa: BLE001
            eni_gaps["attached"] = "DescribeNetworkInterfacesError"

        for sg in self.paginate(ec2, "describe_security_groups", "SecurityGroups"):
            sg_id = str(sg["GroupId"])
            name = str(sg.get("GroupName", sg_id))
            tags = {str(t["Key"]): str(t["Value"]) for t in sg.get("Tags", [])}
            ingress_rules: list[IngressRule] = []
            for perm in sg.get("IpPermissions", []):
                ingress_rules.append(
                    IngressRule(
                        protocol=str(perm.get("IpProtocol", "-1")),
                        from_port=perm.get("FromPort"),
                        to_port=perm.get("ToPort"),
                        cidrs_v4=[
                            str(r["CidrIp"]) for r in perm.get("IpRanges", []) if r.get("CidrIp")
                        ],
                        cidrs_v6=[
                            str(r["CidrIpv6"])
                            for r in perm.get("Ipv6Ranges", [])
                            if r.get("CidrIpv6")
                        ],
                        source_sg_ids=[
                            str(g["GroupId"])
                            for g in perm.get("UserIdGroupPairs", [])
                            if g.get("GroupId")
                        ],
                    )
                )

            attrs = EC2SecurityGroupAttrs(
                vpc_id=sg.get("VpcId"),
                attached=sg_id in attached_sgs if not eni_gaps else None,
                ingress=ingress_rules,
            )
            arn = build_arn(
                self.identity.partition,
                "ec2",
                target_region,
                self.identity.account_id,
                f"security-group/{sg_id}",
            )
            out.append(
                CloudResource(
                    arn=arn,
                    id=sg_id,
                    name=name,
                    service="ec2",
                    kind="ec2_security_group",
                    provider=CloudProvider.AWS,
                    region=target_region,
                    account_id=self.identity.account_id,
                    tags=tags,
                    gaps=dict(eni_gaps),
                    is_ai_workload=True,
                    ai_reason="shadow-ai ingress inspection",
                    metadata=attrs.model_dump(),
                )
            )
        return out
