# SPDX-License-Identifier: Apache-2.0
"""Detection rules for local model files and MCP server configurations (Phase 1)."""

import shlex

from siftsec.engine.attrs import LocalModelFileAttrs, McpServerAttrs
from siftsec.engine.models import CloudResource, Finding, Severity
from siftsec.rules.base import BaseRule
from siftsec.rules.registry import registry


def _as_local_model(resource: CloudResource) -> LocalModelFileAttrs | None:
    if resource.kind != "local_model_file":
        return None
    return LocalModelFileAttrs.model_validate(resource.metadata)


def _as_mcp_server(resource: CloudResource) -> McpServerAttrs | None:
    if resource.kind != "mcp_server":
        return None
    return McpServerAttrs.model_validate(resource.metadata)


class PickleDangerousOpcodesRule(BaseRule):
    rule_id = "SIFTSEC-LOCAL-001"
    title = "Model file imports dangerous callables via pickle opcodes"
    description = "Static pickletools inspection detected arbitrary code execution imports (e.g. os, subprocess)."
    severity = Severity.CRITICAL
    service = "local"
    required_attrs = ("scan",)
    mitre_atlas = ["AML.T0010"]
    owasp_llm = ["LLM04:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = _as_local_model(resource)
        if attrs is None:
            return self.skipped(resource, "Not a local_model_file resource.")
        bad = [h for h in attrs.pickle_hits if h.severity_hint == "CRITICAL"]
        if not bad:
            return self.passed(resource, f"No dangerous pickle imports found in '{resource.name}'.")
        top = bad[0]
        return self.failed(
            resource,
            f"'{resource.name}' imports {top.module}.{top.callable_name} via {top.opcode} at byte {top.offset}.",
            remediation=(
                f"Do not load {shlex.quote(attrs.path)}. Re-export weights as .safetensors from a trusted source."
            ),
            evidence={
                "module": top.module,
                "callable": top.callable_name,
                "hits": str(len(bad)),
            },
            scope=f"{top.module}.{top.callable_name}",
        )


class PickleUnknownGlobalsRule(BaseRule):
    rule_id = "SIFTSEC-LOCAL-002"
    title = "Model file uses pickle format with non-allowlisted global imports"
    description = "Pickle checkpoints contain globals outside the safe allowlist; static scanning is defense-in-depth only."
    severity = Severity.MEDIUM
    service = "local"
    required_attrs = ("scan",)
    mitre_atlas = ["AML.T0010"]
    owasp_llm = ["LLM04:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = _as_local_model(resource)
        if attrs is None:
            return self.skipped(resource, "Not a local_model_file resource.")
        unknown = [h for h in attrs.pickle_hits if h.severity_hint == "MEDIUM"]
        if not unknown:
            return self.passed(
                resource, f"No unallowlisted pickle globals found in '{resource.name}'."
            )
        top = unknown[0]
        return self.failed(
            resource,
            f"'{resource.name}' contains non-allowlisted global {top.module}.{top.callable_name}.",
            remediation=(
                f"Verify provenance of {shlex.quote(attrs.path)} and prefer .safetensors over pickle checkpoints."
            ),
            evidence={"module": top.module, "callable": top.callable_name},
            scope=f"{top.module}.{top.callable_name}",
        )


class ModelArchiveLimitRule(BaseRule):
    rule_id = "SIFTSEC-LOCAL-003"
    title = "Model archive exceeded decompression/parse safety limits"
    description = "Zip bomb ratio or opcode budget exceeded while inspecting model archive."
    severity = Severity.HIGH
    service = "local"
    required_attrs = ("scan",)
    mitre_atlas = ["AML.T0010"]
    owasp_llm = ["LLM04:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = _as_local_model(resource)
        if attrs is None:
            return self.skipped(resource, "Not a local_model_file resource.")
        if attrs.zip_ratio_exceeded or (
            attrs.scan_error
            and attrs.scan_error
            in (
                "zip_limit_exceeded",
                "max_zip_bytes_exceeded",
                "max_ops_exceeded",
                "timeout_exceeded",
            )
        ):
            return self.failed(
                resource,
                f"'{resource.name}' breached archive/parser bounds ({attrs.scan_error}).",
                remediation=f"Quarantine {shlex.quote(attrs.path)}; archive may be a zip bomb or crafted pickle.",
                evidence={"scan_error": str(attrs.scan_error)},
            )
        return self.passed(resource, f"'{resource.name}' parsed within safety bounds.")


class SafetensorsHeaderRule(BaseRule):
    rule_id = "SIFTSEC-LOCAL-004"
    title = "Invalid or malformed SafeTensors header"
    description = "SafeTensors file failed 8-byte header length or tensor offset validation."
    severity = Severity.MEDIUM
    service = "local"
    required_attrs = ("scan",)
    owasp_llm = ["LLM04:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = _as_local_model(resource)
        if attrs is None or attrs.format != "safetensors":
            return self.skipped(resource, "Not a safetensors file.")
        if attrs.safetensors_header_ok is False:
            return self.failed(
                resource,
                f"SafeTensors file '{resource.name}' has a malformed or out-of-bounds header.",
                remediation=f"Re-download or verify SHA-256 of {shlex.quote(attrs.path)}.",
            )
        return self.passed(resource, f"SafeTensors header valid for '{resource.name}'.")


class McpUnpinnedRunnerRule(BaseRule):
    rule_id = "SIFTSEC-MCP-002"
    title = "MCP server uses unpinned dynamic runner (rug-pull risk)"
    description = "Unpinned npx/uvx/docker runners can silently execute mutated upstream code."
    severity = Severity.HIGH
    service = "mcp"
    mitre_atlas = ["AML.T0010"]
    owasp_llm = ["LLM04:2026", "ASI10"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = _as_mcp_server(resource)
        if attrs is None:
            return self.skipped(resource, "Not an mcp_server resource.")
        if attrs.pinned:
            return self.passed(
                resource, f"MCP server '{attrs.server_name}' pins its runner/version."
            )
        return self.failed(
            resource,
            f"MCP server '{attrs.server_name}' runs unpinned {attrs.runner} command '{attrs.command}'.",
            remediation=(
                f"Pin an explicit version or SHA-256 digest for '{attrs.server_name}' in {shlex.quote(attrs.config_path)}."
            ),
            evidence={"runner": attrs.runner},
        )


class McpEnvSecretRule(BaseRule):
    rule_id = "SIFTSEC-MCP-003"
    title = "Plaintext secret or API key stored in MCP server env config"
    description = (
        "MCP config env blocks should reference environment variables, not literal secrets."
    )
    severity = Severity.HIGH
    service = "mcp"
    owasp_llm = ["LLM02:2026", "ASI10"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = _as_mcp_server(resource)
        if attrs is None:
            return self.skipped(resource, "Not an mcp_server resource.")
        if not attrs.env_secret_keys:
            return self.passed(
                resource, f"MCP server '{attrs.server_name}' has no plaintext env secrets."
            )
        return self.failed(
            resource,
            f"MCP server '{attrs.server_name}' stores literal secrets in env keys: {attrs.env_secret_keys}.",
            remediation=(
                f"Move secret values for {attrs.env_secret_keys} into a secret manager or ${{VAR}} reference."
            ),
            evidence={"keys": ",".join(attrs.env_secret_keys)},
        )


class McpHiddenInjectionRule(BaseRule):
    rule_id = "SIFTSEC-MCP-004"
    title = "Hidden Unicode smuggling or prompt-injection markers in MCP config"
    description = (
        "MCP config arguments contain tag characters, bidi overrides, or injection payloads."
    )
    severity = Severity.CRITICAL
    service = "mcp"
    mitre_atlas = ["AML.T0010"]
    owasp_llm = ["LLM01:2026", "ASI10"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = _as_mcp_server(resource)
        if attrs is None:
            return self.skipped(resource, "Not an mcp_server resource.")
        issues = attrs.hidden_unicode + attrs.suspicious_blobs
        if not issues:
            return self.passed(
                resource, f"MCP server '{attrs.server_name}' contains no hidden smuggling markers."
            )
        return self.failed(
            resource,
            f"MCP server '{attrs.server_name}' contains suspicious markers: {issues[0]}.",
            remediation=f"Remove or audit '{attrs.server_name}' in {shlex.quote(attrs.config_path)} immediately.",
            evidence={"markers": str(len(issues))},
        )


class McpManifestDriftRule(BaseRule):
    rule_id = "SIFTSEC-MCP-005"
    title = "MCP server configuration drifted from lockfile (rug-pull indicator)"
    description = "Server SHA-256 differs from approved .siftsec-lock.json baseline."
    severity = Severity.HIGH
    service = "mcp"
    owasp_llm = ["LLM04:2026", "ASI10"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = _as_mcp_server(resource)
        if attrs is None:
            return self.skipped(resource, "Not an mcp_server resource.")
        if attrs.lock_state == "drift":
            return self.failed(
                resource,
                f"MCP server '{attrs.server_name}' definition SHA-256 drifted from lockfile.",
                remediation="Inspect config diff and re-approve with `siftsec mcp lock` if intentional.",
                evidence={"sha256": attrs.definition_sha256[:12]},
            )
        return self.passed(
            resource, f"MCP server '{attrs.server_name}' lock state: {attrs.lock_state}."
        )


class McpTransportRule(BaseRule):
    rule_id = "SIFTSEC-MCP-006"
    title = "Insecure MCP transport (plaintext HTTP or pipe-to-shell launcher)"
    description = "Remote MCP servers must use HTTPS/TLS and never pipe remote scripts to shell."
    severity = Severity.MEDIUM
    service = "mcp"
    owasp_llm = ["LLM04:2026", "ASI10"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = _as_mcp_server(resource)
        if attrs is None:
            return self.skipped(resource, "Not an mcp_server resource.")
        if attrs.insecure_transport or attrs.pipe_to_shell:
            why = "pipe-to-shell launcher" if attrs.pipe_to_shell else f"non-TLS URL {attrs.url}"
            return self.failed(
                resource,
                f"MCP server '{attrs.server_name}' uses {why}.",
                remediation=f"Switch '{attrs.server_name}' to HTTPS/mTLS or a pinned local package.",
            )
        return self.passed(
            resource, f"MCP server '{attrs.server_name}' uses safe transport configuration."
        )


registry.register(PickleDangerousOpcodesRule())
registry.register(PickleUnknownGlobalsRule())
registry.register(ModelArchiveLimitRule())
registry.register(SafetensorsHeaderRule())
registry.register(McpUnpinnedRunnerRule())
registry.register(McpEnvSecretRule())
registry.register(McpHiddenInjectionRule())
registry.register(McpManifestDriftRule())
registry.register(McpTransportRule())
