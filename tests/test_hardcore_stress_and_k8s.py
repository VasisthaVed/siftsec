import ast
import json
import tracemalloc
from datetime import UTC, date, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from typer.testing import CliRunner

import siftsec.rules  # noqa: F401
from siftsec import __version__
from siftsec.cli import app
from siftsec.collectors.base import BaseCollector
from siftsec.collectors.k8s import K8sCollector
from siftsec.config import settings
from siftsec.engine.context import ScanContext
from siftsec.engine.models import (
    CloudProvider,
    CloudResource,
    Finding,
    ScanSummary,
    Severity,
    Status,
)
from siftsec.engine.runner import ScanRunner
from siftsec.engine.scoring import exit_code, posture_score
from siftsec.engine.suppressions import (
    SuppressionRule,
    apply_suppressions,
    load_baseline_fingerprints,
)
from siftsec.reporters.json_rep import JSONReporter
from siftsec.reporters.markdown import MarkdownReporter, escape_md
from siftsec.reporters.sarif import SARIFReporter
from siftsec.rules.k8s_gpu import (
    K8sGpuTimeSlicingWithoutMigRule,
    K8sMutableImageTagRule,
    K8sNvidiaToolkitCveRule,
    K8sPrivilegedGpuPodRule,
    parse_semver,
)

runner = CliRunner()
RULES_DIR = Path(__file__).resolve().parent.parent / "siftsec" / "rules"


# ---------------------------------------------------------------------------
# 1. Architectural AST Purity & No-Hardcoding Contracts
# ---------------------------------------------------------------------------


def test_rules_ast_purity_no_sdk_or_subprocess_imports() -> None:
    """Every rule module must stay pure: no network/SDK/subprocess imports."""
    forbidden_roots = {"boto3", "botocore", "requests", "urllib", "subprocess", "kubernetes"}
    for py_file in sorted(RULES_DIR.glob("*.py")):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    assert root not in forbidden_roots, (
                        f"{py_file.name} imports forbidden SDK/IO module '{alias.name}'"
                    )
            elif isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                assert root not in forbidden_roots, (
                    f"{py_file.name} imports from forbidden module '{node.module}'"
                )


def test_rules_no_hardcoded_shadow_ports_or_model_extensions() -> None:
    """Shadow-AI ports and model file extensions must live in SiftsecConfig, not rules."""
    forbidden_ports = {11434, 6333, 19530}
    forbidden_exts = {".pt", ".pth", ".pkl", ".safetensors"}
    for py_file in sorted(RULES_DIR.glob("*.py")):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant):
                if isinstance(node.value, int) and node.value in forbidden_ports:
                    pytest.fail(f"{py_file.name} hardcodes port {node.value}")
                if isinstance(node.value, str) and node.value.lower() in forbidden_exts:
                    pytest.fail(f"{py_file.name} hardcodes extension {node.value!r}")


# ---------------------------------------------------------------------------
# 2. 2,000-Resource Scale & Memory Stress Test
# ---------------------------------------------------------------------------


class _BulkCollector(BaseCollector):
    def __init__(self, items: list[CloudResource]) -> None:
        self._items = items

    def collect(self) -> list[CloudResource]:
        return self._items


def test_scale_2000_resources_memory_and_determinism() -> None:
    """2,000 multi-service resources must scan cleanly under 150 MB peak traced RAM."""
    resources: list[CloudResource] = []
    for i in range(500):
        resources.append(
            CloudResource(
                arn=f"arn:aws:s3:::ai-bucket-{i}",
                id=f"ai-bucket-{i}",
                name=f"ai-bucket-{i}",
                service="s3",
                kind="s3_bucket",
                is_ai_workload=True,
                tags={"ai": "true"},
                metadata={
                    "kind": "s3_bucket",
                    "public_access_block": {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False,
                    },
                    "encryption": "NONE",
                    "versioning": "Disabled",
                    "logging": False,
                },
            )
        )
        resources.append(
            CloudResource(
                arn=f"arn:aws:sagemaker:us-east-1:111122223333:notebook-instance/nb-{i}",
                id=f"nb-{i}",
                name=f"nb-{i}",
                service="sagemaker",
                kind="sagemaker_notebook",
                is_ai_workload=True,
                metadata={
                    "kind": "sagemaker_notebook",
                    "direct_internet": "Enabled",
                    "root_access": "Enabled",
                    "kms_key_id": None,
                },
            )
        )
        resources.append(
            CloudResource(
                arn=f"k8s://prod/node/gpu-node-{i}",
                id=f"gpu-node-{i}",
                name=f"gpu-node-{i}",
                service="k8s",
                kind="k8s_node",
                provider=CloudProvider.KUBERNETES,
                is_ai_workload=True,
                metadata={
                    "kind": "k8s_node",
                    "toolkit_version": "1.17.7",
                    "gpu_capacity": 4,
                    "mig_config": None,
                    "multi_tenant_gpu_namespaces": 3,
                },
            )
        )
        resources.append(
            CloudResource(
                arn=f"k8s://prod/pod/vllm-{i}",
                id=f"vllm-{i}",
                name=f"vllm-{i}",
                service="k8s",
                kind="k8s_pod",
                provider=CloudProvider.KUBERNETES,
                is_ai_workload=True,
                metadata={
                    "kind": "k8s_pod",
                    "namespace": "prod",
                    "privileged": True,
                    "host_pid": False,
                    "host_paths": ["/dev/nvidia0"],
                    "images": ["vllm/vllm-openai:latest"],
                    "all_images_use_digest": False,
                },
            )
        )

    assert len(resources) == 2000
    ctx = ScanContext(regions=["us-east-1"])

    tracemalloc.start()
    try:
        findings_run_1 = ScanRunner(collector=_BulkCollector(resources), context=ctx).run()
        findings_run_2 = ScanRunner(collector=_BulkCollector(resources), context=ctx).run()
        _, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert peak_bytes < 150 * 1024 * 1024
    assert len(findings_run_1) > 2000
    assert [f.fingerprint for f in findings_run_1] == [f.fingerprint for f in findings_run_2]

    summary = ScanSummary(
        total_resources=len(resources),
        ai_resources=len(resources),
        findings=findings_run_1,
        posture_score=posture_score(findings_run_1, settings.severity_weights),
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        tool_version=__version__,
    )

    json_out = json.loads(JSONReporter().export(summary))
    assert len(json_out["findings"]) == len(findings_run_1)

    sarif_out = json.loads(SARIFReporter().export(findings_run_1))
    assert len(sarif_out["runs"][0]["results"]) > 0

    md_out = MarkdownReporter().export(summary)
    assert len(md_out) <= 60_000


# ---------------------------------------------------------------------------
# 3. K8s GPU Collector (Pagination) & Rules (CVE-2025-23266/23267, MIG, HostPath)
# ---------------------------------------------------------------------------


def _make_k8s_node(
    name: str,
    *,
    toolkit_ver: str | None = "1.17.7",
    gpu_count: str = "2",
    mig_strategy: str | None = None,
) -> Any:
    labels: dict[str, str] = {}
    if toolkit_ver is not None:
        labels["nvidia.com/container-toolkit.version"] = toolkit_ver
    if mig_strategy is not None:
        labels["nvidia.com/mig.config"] = mig_strategy
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name, labels=labels),
        status=SimpleNamespace(
            capacity={"nvidia.com/gpu": gpu_count},
            allocatable={"nvidia.com/gpu": gpu_count},
        ),
    )


def _make_k8s_pod(
    name: str,
    namespace: str,
    *,
    node_name: str = "gpu-1",
    privileged: bool = False,
    host_pid: bool = False,
    host_paths: list[str] | None = None,
    images: list[str] | None = None,
) -> Any:
    containers = [
        SimpleNamespace(
            image=img,
            resources=SimpleNamespace(limits={"nvidia.com/gpu": "1"}, requests={}),
            security_context=SimpleNamespace(privileged=privileged, run_as_non_root=True),
        )
        for img in (images or ["nvcr.io/nvidia/tritonserver:24.08-py3"])
    ]
    volumes = [SimpleNamespace(host_path=SimpleNamespace(path=p)) for p in (host_paths or [])]
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name, namespace=namespace),
        spec=SimpleNamespace(
            node_name=node_name,
            host_network=False,
            host_pid=host_pid,
            runtime_class_name="nvidia",
            containers=containers,
            volumes=volumes,
        ),
    )


def test_k8s_collector_pagination_and_tenant_counting() -> None:
    """K8sCollector must paginate _continue tokens and count unique GPU namespaces."""
    node_calls: list[str | None] = []

    def list_node(limit: int = 500, _continue: str | None = None) -> Any:
        node_calls.append(_continue)
        if _continue is None:
            return SimpleNamespace(
                items=[_make_k8s_node("gpu-1", toolkit_ver="1.17.7")],
                metadata=SimpleNamespace(_continue="page-2"),
            )
        return SimpleNamespace(
            items=[_make_k8s_node("gpu-2", toolkit_ver="1.17.8", mig_strategy="all-1g.5gb")],
            metadata=SimpleNamespace(_continue=None),
        )

    def list_pod_for_all_namespaces(limit: int = 500, _continue: str | None = None) -> Any:
        return SimpleNamespace(
            items=[
                _make_k8s_pod(
                    "pod-a",
                    "team-alpha",
                    node_name="gpu-1",
                    privileged=True,
                    host_paths=["/dev/nvidia0"],
                ),
                _make_k8s_pod(
                    "pod-b",
                    "team-beta",
                    node_name="gpu-1",
                    images=["vllm/vllm-openai@sha256:" + "a" * 64],
                ),
            ],
            metadata=SimpleNamespace(_continue=None),
        )

    def list_daemon_set_for_all_namespaces(limit: int = 500, _continue: str | None = None) -> Any:
        return SimpleNamespace(items=[], metadata=SimpleNamespace(_continue=None))

    core_v1 = SimpleNamespace(
        list_node=list_node,
        list_pod_for_all_namespaces=list_pod_for_all_namespaces,
    )
    apps_v1 = SimpleNamespace(list_daemon_set_for_all_namespaces=list_daemon_set_for_all_namespaces)

    resources = K8sCollector(core_v1=core_v1, apps_v1=apps_v1).collect()
    assert node_calls == [None, "page-2"]
    nodes = [r for r in resources if r.kind == "k8s_node"]
    assert len(nodes) == 2
    assert nodes[0].metadata["multi_tenant_gpu_namespaces"] == 2


@pytest.mark.parametrize(
    ("version", "expected_status"),
    [
        ("1.17.7", Status.FAILED),
        ("v1.17.8-rc1", Status.FAILED),
        ("1.17.8", Status.PASSED),
        ("1.18.0", Status.PASSED),
        ("not-a-semver", Status.SKIPPED),
        (None, Status.SKIPPED),
    ],
)
def test_k8s_nvidia_toolkit_cve_rule(version: str | None, expected_status: Status) -> None:
    res = CloudResource(
        arn="k8s://node/gpu-1",
        id="gpu-1",
        name="gpu-1",
        service="k8s",
        kind="k8s_node",
        provider=CloudProvider.KUBERNETES,
        is_ai_workload=True,
        metadata={"kind": "k8s_node", "toolkit_version": version, "gpu_capacity": 1},
    )
    finding = K8sNvidiaToolkitCveRule().evaluate(res)
    assert finding.status == expected_status


def test_k8s_gpu_time_slicing_and_pod_isolation_rules() -> None:
    shared_node = CloudResource(
        arn="k8s://node/shared",
        id="shared",
        name="shared",
        service="k8s",
        kind="k8s_node",
        provider=CloudProvider.KUBERNETES,
        is_ai_workload=True,
        metadata={
            "kind": "k8s_node",
            "mig_config": None,
            "multi_tenant_gpu_namespaces": 2,
        },
    )
    assert K8sGpuTimeSlicingWithoutMigRule().evaluate(shared_node).status == Status.FAILED

    mig_node = CloudResource(
        arn="k8s://node/mig",
        id="mig",
        name="mig",
        service="k8s",
        kind="k8s_node",
        provider=CloudProvider.KUBERNETES,
        is_ai_workload=True,
        metadata={
            "kind": "k8s_node",
            "mig_config": "all-1g.5gb",
            "multi_tenant_gpu_namespaces": 3,
        },
    )
    assert K8sGpuTimeSlicingWithoutMigRule().evaluate(mig_node).status == Status.PASSED

    bad_pod = CloudResource(
        arn="k8s://pod/bad",
        id="bad",
        name="bad",
        service="k8s",
        kind="k8s_pod",
        provider=CloudProvider.KUBERNETES,
        is_ai_workload=True,
        metadata={
            "kind": "k8s_pod",
            "namespace": "prod",
            "privileged": True,
            "host_pid": True,
            "host_paths": ["/dev/nvidia0"],
            "images": ["vllm/vllm-openai:latest"],
            "all_images_use_digest": False,
        },
    )
    assert K8sPrivilegedGpuPodRule().evaluate(bad_pod).status == Status.FAILED
    assert K8sMutableImageTagRule().evaluate(bad_pod).status == Status.FAILED

    pinned_pod = CloudResource(
        arn="k8s://pod/good",
        id="good",
        name="good",
        service="k8s",
        kind="k8s_pod",
        provider=CloudProvider.KUBERNETES,
        is_ai_workload=True,
        metadata={
            "kind": "k8s_pod",
            "namespace": "prod",
            "privileged": False,
            "host_pid": False,
            "host_paths": [],
            "images": ["vllm/vllm-openai@sha256:" + "b" * 64],
            "all_images_use_digest": True,
        },
    )
    assert K8sPrivilegedGpuPodRule().evaluate(pinned_pod).status == Status.PASSED
    assert K8sMutableImageTagRule().evaluate(pinned_pod).status == Status.PASSED


# ---------------------------------------------------------------------------
# 4. Suppressions, Mandatory Expiry, Baseline & MCP Lock CLI Tests
# ---------------------------------------------------------------------------


def _sample_finding(fp: str = "fp-123") -> Finding:
    return Finding(
        rule_id="SIFTSEC-S3-001",
        rule_title="Public S3 model bucket",
        severity=Severity.CRITICAL,
        status=Status.FAILED,
        resource_arn="arn:aws:s3:::models",
        resource_id="models",
        service="s3",
        message="Public access",
        remediation="Block public access",
        fingerprint=fp,
    )


def test_suppressions_expiry_enforcement_and_scoring() -> None:
    """Active suppression hides from posture_score/exit_code; expired one re-surfaces."""
    f = _sample_finding()
    active_rule = SuppressionRule(
        rule_id="SIFTSEC-S3-001",
        resource="arn:aws:s3:::models",
        reason="Legacy bucket migration",
        expires=date(2026, 12, 31),
        owner="secops",
    )
    expired_rule = SuppressionRule(
        rule_id="SIFTSEC-S3-001",
        resource="arn:aws:s3:::models",
        reason="Old waiver",
        expires=date(2025, 1, 1),
        owner="secops",
    )

    suppressed = apply_suppressions([f], [active_rule], today=date(2026, 6, 1))
    assert suppressed[0].suppressed is True
    assert posture_score(suppressed, settings.severity_weights) is None
    assert exit_code(suppressed, Severity.HIGH) == 0

    resurfaced = apply_suppressions([f], [expired_rule], today=date(2026, 6, 1))
    assert resurfaced[0].suppressed is False
    assert posture_score(resurfaced, settings.severity_weights) == 0
    assert exit_code(resurfaced, Severity.HIGH) == 1


def test_cli_baseline_create_scan_and_mcp_lock(tmp_path: Path) -> None:
    """baseline-create + scan --baseline suppresses demo findings; mcp-lock pins SHA-256."""
    baseline_file = tmp_path / "baseline.json"
    res1 = runner.invoke(app, ["baseline-create", "--demo", "--output", str(baseline_file)])
    assert res1.exit_code == 0, res1.output
    fps = load_baseline_fingerprints(baseline_file)
    assert len(fps) > 0

    res2 = runner.invoke(
        app,
        ["scan", "--demo", "--baseline", str(baseline_file), "--fail-on", "LOW"],
    )
    assert res2.exit_code == 0, res2.output

    mcp_cfg = tmp_path / ".mcp.json"
    mcp_cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    lock_file = tmp_path / ".siftsec-lock.json"
    res3 = runner.invoke(
        app,
        ["mcp-lock", "--path", str(tmp_path), "--output", str(lock_file)],
    )
    assert res3.exit_code == 0, res3.output
    lock_data = json.loads(lock_file.read_text(encoding="utf-8"))
    assert len(lock_data["servers"]) == 1
    assert len(lock_data["servers"][0]["sha256"]) == 64


# ---------------------------------------------------------------------------
# 5. Hypothesis Fuzzing for Semver & Markdown Escaping
# ---------------------------------------------------------------------------


@given(st.text())
def test_fuzz_parse_semver_never_crashes(raw: str) -> None:
    result = parse_semver(raw)
    if result is not None:
        major, minor, patch, is_pre = result
        assert major >= 0 and minor >= 0 and patch >= 0
        assert isinstance(is_pre, bool)


@given(st.text())
def test_fuzz_escape_md_blocks_html_tables_and_mentions(raw: str) -> None:
    escaped = escape_md(raw)
    assert "<" not in escaped
    assert ">" not in escaped
    assert "\r" not in escaped
    assert "\n" not in escaped
    # Any '@' must be followed by a zero-width space so GitHub doesn't ping teams/users.
    for idx, ch in enumerate(escaped):
        if ch == "@":
            assert idx + 1 < len(escaped) and escaped[idx + 1] == "\u200b"
