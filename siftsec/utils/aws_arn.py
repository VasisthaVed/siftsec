# SPDX-License-Identifier: Apache-2.0
"""Partition-aware AWS ARN construction and parsing helpers."""


def build_arn(
    partition: str,
    service: str,
    region: str,
    account_id: str,
    resource: str,
) -> str:
    """Build a valid AWS ARN across commercial, GovCloud, and China partitions."""
    return f"arn:{partition}:{service}:{region}:{account_id}:{resource}"


def parse_partition_from_arn(arn: str) -> str:
    """Extract AWS partition ('aws', 'aws-us-gov', 'aws-cn') from an ARN."""
    parts = arn.split(":", maxsplit=2)
    if len(parts) >= 2 and parts[0] == "arn" and parts[1]:
        return parts[1]
    return "aws"
