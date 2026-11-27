"""AI Bill of Materials (AIBOM) reporter for CycloneDX 1.7 ML-BOM and SPDX 3.0 AI profile."""

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from siftsec import __version__
from siftsec.engine.models import CloudResource


def _component_type(res: CloudResource) -> str:
    if res.kind in ("local_model_file", "sagemaker_model", "sagemaker_endpoint"):
        return "machine-learning-model"
    if res.kind in ("s3_bucket", "gcp_gcs_bucket", "bedrock_data_source"):
        return "data"
    return "application"


class AIBOMReporter:
    """Generates deterministic CycloneDX 1.7 ML-BOM and SPDX 3.0 AI-profile manifests."""

    def export_cyclonedx(
        self,
        resources: list[CloudResource],
        *,
        serial_number: str | None = None,
    ) -> str:
        components: list[dict[str, Any]] = []
        services: list[dict[str, Any]] = []
        dependencies: list[dict[str, Any]] = []
        mcp_refs: list[str] = []

        for res in sorted(resources, key=lambda r: r.arn):
            bom_ref = res.arn
            ctype = _component_type(res)
            comp: dict[str, Any] = {
                "type": ctype,
                "bom-ref": bom_ref,
                "name": res.name,
                "version": str(res.metadata.get("revision") or "unknown"),
                "properties": [
                    {"name": "siftsec:provider", "value": str(res.provider)},
                    {"name": "siftsec:service", "value": res.service},
                    {"name": "siftsec:kind", "value": res.kind or "unknown"},
                ],
            }
            sha = res.metadata.get("sha256") or res.metadata.get("definition_sha256")
            if isinstance(sha, str) and sha:
                comp["hashes"] = [{"alg": "SHA-256", "content": sha}]
            lic = res.metadata.get("license_id")
            if isinstance(lic, str) and lic:
                comp["licenses"] = [{"license": {"id": lic}}]
            if ctype == "machine-learning-model":
                comp["modelCard"] = {
                    "modelParameters": {
                        "task": "inference",
                        "architectureFamily": str(res.metadata.get("format") or "unknown"),
                    }
                }
            components.append(comp)

            if res.kind in (
                "opensearch_domain",
                "opensearch_serverless",
                "gcp_vertex_endpoint",
                "sagemaker_endpoint",
            ):
                services.append(
                    {
                        "bom-ref": f"svc:{bom_ref}",
                        "name": res.name,
                        "endpoints": [res.arn],
                    }
                )
            if res.kind == "mcp_server":
                mcp_refs.append(bom_ref)

        for ref in sorted(mcp_refs):
            dependencies.append({"ref": ref, "dependsOn": []})

        bom: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "serialNumber": serial_number or f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(UTC).isoformat(),
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "siftsec",
                            "version": __version__,
                        }
                    ]
                },
            },
            "components": components,
            "services": services,
            "dependencies": dependencies,
        }
        return json.dumps(bom, indent=2)

    def export_spdx(
        self,
        resources: list[CloudResource],
        *,
        namespace: str | None = None,
    ) -> str:
        doc_ns = namespace or "https://siftsec.local/spdx/aibom"
        elements: list[dict[str, Any]] = []
        for idx, res in enumerate(sorted(resources, key=lambda r: r.arn)):
            elem_type = (
                "ai_AIPackage"
                if res.kind in ("local_model_file", "sagemaker_model", "gcp_vertex_endpoint")
                else "software_Package"
            )
            elem: dict[str, Any] = {
                "type": elem_type,
                "spdxId": f"{doc_ns}#item-{idx}",
                "name": res.name,
                "originator": str(res.provider),
                "comment": res.arn,
            }
            sha = res.metadata.get("sha256") or res.metadata.get("definition_sha256")
            if isinstance(sha, str) and sha:
                elem["verifiedUsing"] = [{"type": "Hash", "algorithm": "sha256", "hashValue": sha}]
            elements.append(elem)

        doc = {
            "@context": "https://spdx.org/rdf/3.0.0/spdx-context.jsonld",
            "spdxVersion": "SPDX-3.0",
            "@graph": elements,
        }
        return json.dumps(doc, indent=2)
