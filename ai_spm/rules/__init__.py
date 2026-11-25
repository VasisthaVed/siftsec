import ai_spm.rules as _rules_pkg
from ai_spm.rules.registry import registry

# Dynamically discover all rule modules in ai_spm/rules and external plugins
registry.discover_package(_rules_pkg)
registry.discover_entry_points()
