import hashlib
import json
from pathlib import Path

from typer.testing import CliRunner

from ai_spm.cli import app
from ai_spm.collectors.local.models import LocalModelCollector
from ai_spm.engine.models import CloudProvider, CloudResource, Status
from ai_spm.reporters.aibom import AIBOMReporter
from ai_spm.rules.supply_chain import (
    SupplyChainLicenseRule,
    SupplyChainModelAllowlistRule,
    SupplyChainPinnedRevisionRule,
)

runner = CliRunner()


def test_hf_cache_provenance_license_and_allowlist_rules(tmp_path: Path) -> None:
    snap_dir = (
        tmp_path
        / "models--meta-llama--Llama-3-8B"
        / "snapshots"
        / "0123456789abcdef0123456789abcdef01234567"
    )
    snap_dir.mkdir(parents=True)
    model_file = snap_dir / "weights.safetensors"
    header = json.dumps({"__metadata__": {"format": "pt"}}).encode("utf-8")
    payload = len(header).to_bytes(8, "little") + header + b"\x00" * 16
    model_file.write_bytes(payload)
    (snap_dir / "config.json").write_text(json.dumps({"license": "llama3"}), encoding="utf-8")

    digest = hashlib.sha256(payload).hexdigest()
    (tmp_path / ".tensorguard-models.lock").write_text(
        json.dumps({"models": [{"sha256": digest}]}),
        encoding="utf-8",
    )

    resources = LocalModelCollector(paths=[tmp_path]).collect()
    assert len(resources) == 1
    res = resources[0]
    assert res.metadata["source"] == "hf://meta-llama/Llama-3-8B"
    assert res.metadata["revision"] == "0123456789abcdef0123456789abcdef01234567"
    assert res.metadata["license_id"] == "llama3"
    assert res.metadata["allowlist_match"] is True

    assert SupplyChainPinnedRevisionRule().evaluate(res).status == Status.PASSED
    assert SupplyChainLicenseRule().evaluate(res).status == Status.PASSED
    assert SupplyChainModelAllowlistRule().evaluate(res).status == Status.PASSED

    # Unapproved digest + mutable ref + missing license must FAIL
    bad_res = CloudResource(
        arn="local://file/bad",
        id="bad.safetensors",
        name="bad.safetensors",
        service="local",
        kind="local_model_file",
        provider=CloudProvider.LOCAL,
        metadata={
            "kind": "local_model_file",
            "path": "/tmp/bad.safetensors",
            "size_bytes": 16,
            "sha256": "deadbeef",
            "format": "safetensors",
            "source": "hf://evil/model",
            "revision": "main",
            "license_id": None,
            "allowlist_match": False,
        },
    )
    assert SupplyChainPinnedRevisionRule().evaluate(bad_res).status == Status.FAILED
    assert SupplyChainLicenseRule().evaluate(bad_res).status == Status.FAILED
    assert SupplyChainModelAllowlistRule().evaluate(bad_res).status == Status.FAILED


def test_aibom_cyclonedx_17_and_spdx_30_deterministic(tmp_path: Path) -> None:
    resources = [
        CloudResource(
            arn="local://file/z-model",
            id="z-model",
            name="z-model.safetensors",
            service="local",
            kind="local_model_file",
            provider=CloudProvider.LOCAL,
            metadata={
                "sha256": "a" * 64,
                "format": "safetensors",
                "revision": "abcdef1",
                "license_id": "Apache-2.0",
            },
        ),
        CloudResource(
            arn="arn:aws:s3:::a-dataset-bucket",
            id="a-dataset-bucket",
            name="a-dataset-bucket",
            service="s3",
            kind="s3_bucket",
            provider=CloudProvider.AWS,
            metadata={},
        ),
        CloudResource(
            arn="local://mcp/fs",
            id="fs",
            name="filesystem",
            service="mcp",
            kind="mcp_server",
            provider=CloudProvider.MCP,
            metadata={"definition_sha256": "b" * 64},
        ),
    ]

    reporter = AIBOMReporter()
    cdx_1 = json.loads(reporter.export_cyclonedx(resources, serial_number="urn:uuid:fixed"))
    cdx_2 = json.loads(
        reporter.export_cyclonedx(list(reversed(resources)), serial_number="urn:uuid:fixed")
    )
    assert cdx_1["bomFormat"] == "CycloneDX"
    assert cdx_1["specVersion"] == "1.7"
    assert [c["bom-ref"] for c in cdx_1["components"]] == [
        c["bom-ref"] for c in cdx_2["components"]
    ]
    assert cdx_1["components"][0]["type"] == "data"
    assert cdx_1["components"][1]["type"] == "machine-learning-model"
    assert "modelCard" in cdx_1["components"][1]
    assert cdx_1["components"][2]["type"] == "application"

    spdx = json.loads(reporter.export_spdx(resources))
    assert spdx["spdxVersion"] == "SPDX-3.0"
    assert len(spdx["@graph"]) == 3

    sbom_out = tmp_path / "aibom.cdx.json"
    res = runner.invoke(app, ["scan", "--demo", "--sbom", "cyclonedx", "--output", str(sbom_out)])
    assert res.exit_code in (0, 1)
    assert json.loads(sbom_out.read_text(encoding="utf-8"))["specVersion"] == "1.7"
