# SPDX-License-Identifier: Apache-2.0
import siftsec.rules as _rules_pkg
from siftsec.rules.registry import registry

# Dynamically discover all rule modules in siftsec/rules and external plugins
registry.discover_package(_rules_pkg)
registry.discover_entry_points()
