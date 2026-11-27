from abc import ABC, abstractmethod
from importlib.metadata import entry_points
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from siftsec.engine.context import ScanContext
from siftsec.engine.models import CloudProvider, CloudResource, CoverageGap


class CollectorResult(BaseModel):
    """Normalized output from a provider collector including any permission gaps."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    resources: list[CloudResource] = Field(default_factory=list)
    coverage_gaps: list[CoverageGap] = Field(default_factory=list)


@runtime_checkable
class ProviderCollector(Protocol):
    """Provider-neutral collector contract for AWS, GCP, Kubernetes, and future clouds."""

    provider: CloudProvider

    def collect_with_gaps(self, ctx: ScanContext) -> CollectorResult:
        """Collect resources and surface any read-permission gaps without raising."""
        ...


class ProviderRegistry:
    """Registry of provider collectors supporting explicit registration and entry points."""

    def __init__(self) -> None:
        self._collectors: dict[CloudProvider, type[ProviderCollector]] = {}

    def register(self, provider: CloudProvider, cls: type[ProviderCollector]) -> None:
        self._collectors[provider] = cls

    def get(self, provider: CloudProvider) -> type[ProviderCollector] | None:
        return self._collectors.get(provider)

    def all_providers(self) -> list[CloudProvider]:
        return sorted(self._collectors.keys(), key=lambda p: p.value)

    def discover_entry_points(self, group: str = "siftsec.collectors") -> int:
        loaded = 0
        for ep in entry_points(group=group):
            obj = ep.load()
            prov = getattr(obj, "provider", None)
            if isinstance(prov, CloudProvider):
                self._collectors[prov] = obj
                loaded += 1
        return loaded


provider_registry = ProviderRegistry()


class BaseCollector(ABC):
    @abstractmethod
    def collect(self) -> list[CloudResource]:
        """Collect and normalize resources."""
        pass
