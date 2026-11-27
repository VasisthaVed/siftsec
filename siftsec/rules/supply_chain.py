# SPDX-License-Identifier: Apache-2.0
"""AI Supply Chain security rules (Phase 7.1): provenance, license, and model allowlists."""

import re

from siftsec.engine.attrs import LocalModelFileAttrs
from siftsec.engine.models import CloudResource, Finding, Severity
from siftsec.rules.base import BaseRule
from siftsec.rules.registry import registry
from siftsec.rules.remediation import sh

_COMMIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")


class SupplyChainPinnedRevisionRule(BaseRule):
    rule_id = "SIFTSEC-SUPPLY-001"
    title = "AI Model Artifact Lacks Pinned Immutable Revision Hash"
    description = (
        "External/HuggingFace models should pin an immutable commit SHA instead of mutable refs."
    )
    severity = Severity.MEDIUM
    service = "local"
    resource_kinds = frozenset({"local_model_file"})
    owasp_llm = ["LLM03:2025"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = LocalModelFileAttrs.model_validate(resource.metadata)
        if not attrs.source:
            return self.skipped(
                resource, f"Local model '{resource.name}' has no external source metadata."
            )
        if attrs.revision and _COMMIT_SHA_RE.match(attrs.revision):
            return self.passed(
                resource,
                f"Model '{resource.name}' from {attrs.source} pins revision {attrs.revision[:12]}.",
            )
        return self.failed(
            resource,
            f"Model '{resource.name}' from {attrs.source} lacks a pinned immutable commit revision.",
            remediation=f"Pin an explicit commit SHA revision for {sh(attrs.source)} in model config.",
        )


class SupplyChainLicenseRule(BaseRule):
    rule_id = "SIFTSEC-SUPPLY-002"
    title = "AI Model Artifact Missing License Provenance"
    description = "Model artifacts should declare an explicit license in model card or config.json."
    severity = Severity.LOW
    service = "local"
    resource_kinds = frozenset({"local_model_file"})

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = LocalModelFileAttrs.model_validate(resource.metadata)
        if attrs.license_id:
            return self.passed(
                resource, f"Model '{resource.name}' declares license '{attrs.license_id}'."
            )
        return self.failed(
            resource,
            f"Model '{resource.name}' has unknown/missing license metadata.",
            remediation=(
                f"Record SPDX license identifier in config.json or README.md alongside {sh(resource.name)}."
            ),
        )


class SupplyChainModelAllowlistRule(BaseRule):
    rule_id = "SIFTSEC-SUPPLY-003"
    title = "Model Artifact SHA-256 Not in Approved Allowlist (.siftsec-models.lock)"
    description = "Verify local model weights match organization-approved SHA-256 digests."
    severity = Severity.HIGH
    service = "local"
    resource_kinds = frozenset({"local_model_file"})
    owasp_llm = ["LLM03:2025"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = LocalModelFileAttrs.model_validate(resource.metadata)
        if attrs.allowlist_match is None:
            return self.skipped(
                resource,
                f"No .siftsec-models.lock allowlist configured for '{resource.name}'.",
            )
        if attrs.allowlist_match is True:
            return self.passed(
                resource, f"Model '{resource.name}' SHA-256 matches .siftsec-models.lock."
            )
        return self.failed(
            resource,
            f"Model '{resource.name}' (sha256={attrs.sha256}) is not present in .siftsec-models.lock.",
            remediation=(
                f"Verify model provenance for {sh(resource.name)} and update .siftsec-models.lock if approved."
            ),
        )


registry.register(SupplyChainPinnedRevisionRule())
registry.register(SupplyChainLicenseRule())
registry.register(SupplyChainModelAllowlistRule())
