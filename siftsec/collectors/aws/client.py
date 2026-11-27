# SPDX-License-Identifier: Apache-2.0
"""Thread-safe Boto3 session and client factory (Phase 2.1)."""

import threading
from dataclasses import dataclass
from typing import Any, Literal

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    PartialCredentialsError,
)

from siftsec import __version__
from siftsec.config import SiftsecConfig
from siftsec.errors import CredentialsError
from siftsec.utils.aws_arn import parse_partition_from_arn


@dataclass(frozen=True)
class AwsIdentity:
    """Resolved AWS caller identity and partition."""

    account_id: str
    arn: str
    partition: str


class AwsClientFactory:
    """Thread-safe Boto3 client cache with adaptive retries and explicit timeouts."""

    def __init__(self, session: boto3.Session, cfg: SiftsecConfig) -> None:
        self._session = session
        self._lock = threading.Lock()
        self._cache: dict[tuple[str, str | None], Any] = {}
        self._boto_cfg = BotoConfig(
            retries={"max_attempts": cfg.boto_max_attempts, "mode": "adaptive"},
            user_agent_extra=f"Siftsec/{__version__}",
            connect_timeout=cfg.boto_connect_timeout_s,
            read_timeout=cfg.boto_read_timeout_s,
            max_pool_connections=cfg.max_workers * 2,
        )

    @property
    def session(self) -> boto3.Session:
        return self._session

    def client(self, service: str, region: str | None = None) -> Any:
        key = (service, region)
        with self._lock:
            if key not in self._cache:
                self._cache[key] = self._session.client(
                    service,
                    region_name=region,
                    config=self._boto_cfg,
                )
            return self._cache[key]


def resolve_identity(factory: AwsClientFactory) -> AwsIdentity:
    """Resolve AWS account ID and partition via sts:GetCallerIdentity."""
    try:
        sts = factory.client("sts")
        resp = sts.get_caller_identity()
        arn = str(resp["Arn"])
        return AwsIdentity(
            account_id=str(resp["Account"]),
            arn=arn,
            partition=parse_partition_from_arn(arn),
        )
    except (NoCredentialsError, PartialCredentialsError) as exc:
        raise CredentialsError(
            "No usable AWS credentials found. Set AWS_PROFILE, export credentials, or run `aws sso login`."
        ) from exc
    except (ClientError, BotoCoreError) as exc:
        raise CredentialsError(f"Failed to verify AWS caller identity: {exc}") from exc


def resolve_regions(
    factory: AwsClientFactory,
    requested: list[str] | Literal["all"],
    service: str,
    partition: str = "aws",
) -> list[str]:
    """Resolve target regions intersected with regions where the service is offered."""
    available = set(factory.session.get_available_regions(service, partition_name=partition))
    if requested != "all":
        if not available:
            return list(requested)
        return [r for r in requested if r in available]

    try:
        ec2 = factory.client("ec2", region="us-east-1")
        resp = ec2.describe_regions(AllRegions=False)
        enabled = [str(r["RegionName"]) for r in resp.get("Regions", [])]
    except (ClientError, BotoCoreError):
        enabled = sorted(available)

    if not available:
        return enabled
    return [r for r in enabled if r in available]
