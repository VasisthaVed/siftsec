"""Kubernetes GPU runtime security rules (Phase 5.2)."""

import re

from ai_spm.engine.attrs import K8sNodeAttrs, K8sPodAttrs
from ai_spm.engine.models import CloudResource, Finding, Severity
from ai_spm.rules.base import BaseRule
from ai_spm.rules.registry import registry
from ai_spm.rules.remediation import sh

_SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([A-Za-z0-9.]+))?")
_DANGEROUS_HOST_PATH_PREFIXES = ("/dev/nvidia", "/var/run/docker.sock", "/run/containerd")


def parse_semver(raw: str | None) -> tuple[int, int, int, bool] | None:
    """Parse semver string into (major, minor, patch, is_prerelease) or None if unparseable."""
    if not raw:
        return None
    m = _SEMVER_RE.match(raw.strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), bool(m.group(4))


class K8sNvidiaToolkitCveRule(BaseRule):
    rule_id = "AI-SPM-K8S-001"
    title = "NVIDIA Container Toolkit Vulnerable to Container Escape (Bulletin 5659)"
    description = "NVIDIA Container Toolkit < 1.17.8 is vulnerable to CVE-2025-23266 (NVIDIAScape) and CVE-2025-23267."
    severity = Severity.CRITICAL
    service = "k8s"
    resource_kinds = frozenset({"k8s_node"})
    owasp_llm = ["LLM04:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = K8sNodeAttrs.model_validate(resource.metadata)
        parsed = parse_semver(attrs.toolkit_version)
        if parsed is None:
            return self.skipped(
                resource,
                f"NVIDIA Container Toolkit version unknown/unparseable on node '{resource.name}'.",
            )
        major, minor, patch, is_pre = parsed
        # A prerelease (e.g. v1.17.8-rc1) precedes 1.17.8 final.
        is_safe = (major, minor, patch) > (1, 17, 8) or (
            (major, minor, patch) == (1, 17, 8) and not is_pre
        )
        if is_safe:
            return self.passed(
                resource,
                f"Node '{resource.name}' runs patched NVIDIA Container Toolkit ({attrs.toolkit_version}).",
            )
        return self.failed(
            resource,
            f"GPU node '{resource.name}' runs vulnerable NVIDIA Container Toolkit {attrs.toolkit_version} (< 1.17.8).",
            remediation=(
                f"Upgrade NVIDIA Container Toolkit / GPU Operator on node {sh(resource.name)} to >= v1.17.8."
            ),
            evidence={"toolkit_version": str(attrs.toolkit_version)},
        )


class K8sGpuTimeSlicingWithoutMigRule(BaseRule):
    rule_id = "AI-SPM-K8S-002"
    title = "Multi-Tenant GPU Node Uses Time-Slicing Without MIG Isolation"
    description = (
        "Multiple namespaces share a physical GPU node without NVIDIA MIG hardware partitioning."
    )
    severity = Severity.MEDIUM
    service = "k8s"
    resource_kinds = frozenset({"k8s_node"})

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = K8sNodeAttrs.model_validate(resource.metadata)
        if attrs.multi_tenant_gpu_namespaces > 1 and not attrs.mig_config:
            return self.failed(
                resource,
                f"GPU node '{resource.name}' schedules {attrs.multi_tenant_gpu_namespaces} namespaces without MIG.",
                remediation=(
                    f"Enable NVIDIA Multi-Instance GPU (MIG) partitioning on node {sh(resource.name)}."
                ),
                evidence={"namespaces": str(attrs.multi_tenant_gpu_namespaces)},
            )
        return self.passed(resource, f"GPU node '{resource.name}' isolation check passed.")


class K8sPrivilegedGpuPodRule(BaseRule):
    rule_id = "AI-SPM-K8S-003"
    title = "Privileged AI/GPU Pod or Sensitive HostPath Mount"
    description = "AI pods must not run privileged, share hostPID, or mount /dev/nvidia* or container sockets."
    severity = Severity.HIGH
    service = "k8s"
    resource_kinds = frozenset({"k8s_pod"})

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = K8sPodAttrs.model_validate(resource.metadata)
        bad_paths = [
            p
            for p in attrs.host_paths
            if any(p.startswith(prefix) for prefix in _DANGEROUS_HOST_PATH_PREFIXES)
        ]
        if not (attrs.privileged or attrs.host_pid or bad_paths):
            return self.passed(
                resource, f"AI pod '{resource.name}' avoids privileged/hostPath flags."
            )
        return self.failed(
            resource,
            f"AI pod '{resource.name}' in '{attrs.namespace}' uses privileged={attrs.privileged}, "
            f"hostPID={attrs.host_pid}, bad_host_paths={bad_paths}.",
            remediation=(
                f"Remove privileged/hostPID and hostPath mounts from pod {sh(resource.name)} "
                f"in namespace {sh(attrs.namespace)}; use CDI/GPU Operator device plugin."
            ),
        )


class K8sMutableImageTagRule(BaseRule):
    rule_id = "AI-SPM-K8S-004"
    title = "GPU Workload Pulls Container Image by Mutable Tag Instead of Digest"
    description = "Pin AI/ML pod container images by @sha256: digest to prevent supply-chain drift."
    severity = Severity.MEDIUM
    service = "k8s"
    resource_kinds = frozenset({"k8s_pod"})
    owasp_llm = ["LLM04:2026"]

    def evaluate(self, resource: CloudResource) -> Finding:
        attrs = K8sPodAttrs.model_validate(resource.metadata)
        if not attrs.images or attrs.all_images_use_digest:
            return self.passed(
                resource, f"AI pod '{resource.name}' pins container images by digest."
            )
        unpinned = [img for img in attrs.images if "@sha256:" not in img]
        return self.failed(
            resource,
            f"AI pod '{resource.name}' pulls mutable image tag(s): {unpinned}.",
            remediation=f"Pin images for pod {sh(resource.name)} using immutable @sha256: digests.",
        )


registry.register(K8sNvidiaToolkitCveRule())
registry.register(K8sGpuTimeSlicingWithoutMigRule())
registry.register(K8sPrivilegedGpuPodRule())
registry.register(K8sMutableImageTagRule())
