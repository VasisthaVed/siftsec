"""Base AWS collector with pagination, error classification, and gap barriers (Phase 2.2)."""

import json
import logging
from abc import abstractmethod
from collections.abc import Callable, Iterator, Mapping
from enum import StrEnum
from typing import Any, ClassVar, Literal, TypeVar

from botocore.exceptions import BotoCoreError, ClientError

from ai_spm.collectors.aws.client import AwsClientFactory, AwsIdentity
from ai_spm.collectors.base import BaseCollector
from ai_spm.config import AISPMConfig
from ai_spm.engine.models import CoverageGap

log = logging.getLogger("ai_spm.collectors.aws")
T = TypeVar("T")

# Sentinel distinguishing "API confirmed resource has no such sub-config" from "unreadable".
ABSENT = object()

_DENIED_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "AuthorizationError",
        "AuthFailure",
    }
)
_THROTTLED_CODES = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "RequestLimitExceeded",
        "TooManyRequestsException",
        "SlowDown",
    }
)
_GONE_CODES = frozenset(
    {
        "NoSuchBucket",
        "ResourceNotFoundException",
        "NoSuchEntity",
        "NotFoundException",
    }
)
_UNAVAILABLE_CODES = frozenset(
    {
        "OptInRequired",
        "UnrecognizedClientException",
        "InvalidClientTokenId",
    }
)


class ErrorKind(StrEnum):
    DENIED = "DENIED"
    THROTTLED = "THROTTLED"
    GONE = "GONE"
    REGION_UNAVAILABLE = "REGION_UNAVAILABLE"
    OTHER = "OTHER"


class ResourceGoneError(Exception):
    """Raised internally when a resource was deleted mid-scan."""


def classify_client_error(exc: ClientError) -> ErrorKind:
    """Classify a Botocore ClientError into a deterministic handling category."""
    err = exc.response.get("Error", {})
    code = str(err.get("Code", "Unknown"))
    http_status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")

    if code in _DENIED_CODES or http_status == 403:
        return ErrorKind.DENIED
    if code in _THROTTLED_CODES:
        return ErrorKind.THROTTLED
    if code in _GONE_CODES:
        return ErrorKind.GONE
    if code in _UNAVAILABLE_CODES:
        return ErrorKind.REGION_UNAVAILABLE
    return ErrorKind.OTHER


def policy_allows_public_principal(policy: str | Mapping[str, Any] | None) -> bool:
    """Return True if an IAM/resource policy grants unconditioned access to Principal '*'."""
    if not policy:
        return False
    if isinstance(policy, str):
        try:
            doc: Any = json.loads(policy)
        except json.JSONDecodeError:
            return False
    else:
        doc = policy
    if not isinstance(doc, Mapping):
        return False

    stmts = doc.get("Statement", [])
    if isinstance(stmts, Mapping):
        stmts = [stmts]
    for stmt in stmts:
        if not isinstance(stmt, Mapping) or stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        is_star = principal == "*" or (
            isinstance(principal, Mapping) and principal.get("AWS") in ("*", ["*"])
        )
        if is_star and not stmt.get("Condition"):
            return True
    return False


class AWSBaseCollector(BaseCollector):
    """Shared pagination and exception-barrier base for all AWS service collectors."""

    service: ClassVar[str]
    required_actions: ClassVar[tuple[str, ...]] = ()
    scope: ClassVar[Literal["regional", "global"]] = "regional"

    def __init__(
        self,
        factory: AwsClientFactory,
        cfg: AISPMConfig,
        identity: AwsIdentity,
    ) -> None:
        self.factory = factory
        self.cfg = cfg
        self.identity = identity
        self._warned_gaps: set[tuple[str, str]] = set()
        self.coverage_gaps: list[CoverageGap] = []

    @abstractmethod
    def collect_region(self, region: str | None) -> list[Any]:
        """Collect normalized CloudResource objects for a region (or None if global)."""

    def collect(self) -> list[Any]:
        return self.collect_region(None if self.scope == "global" else "us-east-1")

    def paginate(
        self,
        client: Any,
        method: str,
        result_key: str,
        token_in: str = "NextToken",
        token_out: str = "NextToken",
        **kwargs: Any,
    ) -> Iterator[Mapping[str, Any]]:
        """Iterate all pages via native boto3 paginator or manual token continuation."""
        if client.can_paginate(method):
            paginator = client.get_paginator(method)
            for page in paginator.paginate(**kwargs):
                yield from page.get(result_key, [])
            return

        token: str | None = None
        while True:
            call_kw = dict(kwargs)
            if token:
                call_kw[token_in] = token
            resp = getattr(client, method)(**call_kw)
            yield from resp.get(result_key, [])
            token = resp.get(token_out)
            if not token:
                return

    def safe_paginate(
        self,
        client: Any,
        method: str,
        result_key: str,
        region: str = "global",
        token_in: str = "NextToken",
        token_out: str = "NextToken",
        **kwargs: Any,
    ) -> list[Mapping[str, Any]]:
        """Paginate inside an exception barrier, recording CoverageGap on failure."""
        try:
            return list(
                self.paginate(
                    client, method, result_key, token_in=token_in, token_out=token_out, **kwargs
                )
            )
        except ClientError as exc:
            kind = classify_client_error(exc)
            if kind is ErrorKind.REGION_UNAVAILABLE:
                log.info("Skipping %s in %s (%s)", self.service, region, kind)
                return []
            code = (
                "AccessDenied"
                if kind is ErrorKind.DENIED
                else str(exc.response.get("Error", {}).get("Code", "ClientError"))
            )
            self._record_coverage_gap(region, method, code)
            return []
        except (BotoCoreError, TimeoutError) as exc:
            self._record_coverage_gap(region, method, type(exc).__name__)
            return []

    def call(
        self,
        gaps: dict[str, str],
        attr: str,
        fn: Callable[..., T],
        *args: Any,
        absent: frozenset[str] = frozenset(),
        region: str = "global",
        **kwargs: Any,
    ) -> T | object | None:
        """Execute one AWS API call inside an exception barrier."""
        try:
            return fn(*args, **kwargs)
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", "ClientError"))
            if code in absent:
                return ABSENT
            kind = classify_client_error(exc)
            if kind is ErrorKind.GONE:
                raise ResourceGoneError from exc
            if kind is ErrorKind.REGION_UNAVAILABLE:
                return None
            gap_code = "AccessDenied" if kind is ErrorKind.DENIED else code
            gaps[attr] = gap_code
            self._log_gap_once(attr, gap_code)
            return None
        except (BotoCoreError, TimeoutError) as exc:
            gap_code = type(exc).__name__
            gaps[attr] = gap_code
            self._log_gap_once(attr, gap_code)
            return None

    def _record_coverage_gap(self, region: str, api: str, code: str) -> None:
        self.coverage_gaps.append(
            CoverageGap(service=self.service, region=region, api=api, error_code=code)
        )
        self._log_gap_once(api, code)

    def _log_gap_once(self, attr: str, code: str) -> None:
        key = (self.service, attr)
        if key not in self._warned_gaps:
            self._warned_gaps.add(key)
            log.warning("Coverage gap on %s.%s (%s)", self.service, attr, code)
