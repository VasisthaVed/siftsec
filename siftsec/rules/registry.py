import importlib
import pkgutil
from collections.abc import Iterable
from importlib.metadata import entry_points
from types import ModuleType

from siftsec.rules.base import BaseRule


class RuleRegistry:
    """Registry that dynamically discovers and manages SIFTSEC detection rules."""

    def __init__(self) -> None:
        self._rules: dict[str, BaseRule] = {}

    def register(self, rule: BaseRule) -> None:
        self._rules[rule.rule_id] = rule

    def discover_package(self, package: ModuleType, exclude: set[str] | None = None) -> None:
        """Auto-discover and import all rule modules recursively within a package."""
        skip = exclude or {"base", "registry", "remediation"}
        prefix = f"{package.__name__}."
        for _, module_name, is_pkg in pkgutil.walk_packages(package.__path__, prefix):
            short_name = module_name.rsplit(".", maxsplit=1)[-1]
            if is_pkg or short_name in skip or short_name.startswith("_"):
                continue
            importlib.import_module(module_name)

    def discover_entry_points(self, group: str = "siftsec.rules") -> None:
        """Load external third-party rule plugins via Python entry points."""
        for ep in entry_points(group=group):
            loaded = ep.load()
            if isinstance(loaded, BaseRule):
                self.register(loaded)

    def get_rules(self, services: Iterable[str] | None = None) -> list[BaseRule]:
        if not services:
            return list(self._rules.values())
        norm_services = {s.lower() for s in services}
        return [r for r in self._rules.values() if r.service.lower() in norm_services]

    def get_rule(self, rule_id: str) -> BaseRule | None:
        return self._rules.get(rule_id)


registry = RuleRegistry()
