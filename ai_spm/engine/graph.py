"""Attack-path correlation engine over collected AI/cloud resources (Phase 9.1)."""

from dataclasses import dataclass, field

from ai_spm.engine.fingerprint import fingerprint
from ai_spm.engine.models import CloudResource, Finding, Severity, Status
from ai_spm.rules.k8s_gpu import parse_semver
from ai_spm.utils.redact import redact


@dataclass
class ResourceGraph:
    """Directed adjacency graph linking AI workloads, IAM roles, vector DBs, and nodes."""

    nodes: dict[str, CloudResource] = field(default_factory=dict)
    edges: dict[str, list[tuple[str, str]]] = field(default_factory=dict)

    @classmethod
    def from_resources(cls, resources: list[CloudResource]) -> "ResourceGraph":
        graph = cls()
        for res in resources:
            graph.nodes[res.arn] = res
            graph.nodes[res.id] = res
            graph.edges.setdefault(res.arn, [])

        for res in resources:
            meta = res.metadata
            # SageMaker / Bedrock -> IAM Role
            role_arn = meta.get("role_arn")
            if isinstance(role_arn, str) and role_arn in graph.nodes:
                graph.edges[res.arn].append(("uses_role", role_arn))

            # Bedrock DataSource / KB -> Vector Store
            vs_arn = meta.get("vector_store_arn")
            if isinstance(vs_arn, str) and vs_arn in graph.nodes:
                graph.edges[res.arn].append(("uses_vectorstore", vs_arn))

            # K8s Pod -> K8s Node
            node_name = meta.get("node_name")
            if res.kind == "k8s_pod" and isinstance(node_name, str) and node_name in graph.nodes:
                graph.edges[res.arn].append(("scheduled_on", graph.nodes[node_name].arn))

        return graph


def _role_has_wildcard_s3(role_res: CloudResource) -> bool:
    for stmt in role_res.metadata.get("statements", []):
        if not isinstance(stmt, dict) or stmt.get("effect") != "Allow":
            continue
        actions = [str(a).lower() for a in stmt.get("actions", [])]
        resources = [str(r) for r in stmt.get("resources", [])]
        if any(a in ("*", "s3:*") for a in actions) and "*" in resources:
            return True
    return False


def evaluate_attack_paths(resources: list[CloudResource]) -> list[Finding]:
    """Detect multi-hop CRITICAL attack paths across correlated AI resources."""
    graph = ResourceGraph.from_resources(resources)
    findings: list[Finding] = []

    for res in resources:
        # Path 1: Internet-exposed SageMaker Notebook -> Wildcard S3 IAM Role
        if res.kind == "sagemaker_notebook" and res.metadata.get("direct_internet") == "Enabled":
            for rel, target_arn in graph.edges.get(res.arn, []):
                if rel != "uses_role":
                    continue
                role = graph.nodes.get(target_arn)
                if role and _role_has_wildcard_s3(role):
                    path_str = f"{res.arn} -> uses_role -> {role.arn}"
                    findings.append(
                        Finding(
                            rule_id="AI-SPM-PATH-001",
                            rule_title="Attack Path: Internet-Exposed Notebook with Wildcard S3 Role",
                            service="correlation",
                            resource_arn=res.arn,
                            resource_id=res.id,
                            resource_name=res.name,
                            status=Status.FAILED,
                            severity=Severity.CRITICAL,
                            message=redact(
                                f"Notebook '{res.name}' has direct internet access and assumes "
                                f"wildcard S3 role '{role.name}'."
                            ),
                            remediation=(
                                "Disable DirectInternetAccess on the notebook and scope the IAM "
                                "role to specific model/dataset bucket prefixes."
                            ),
                            evidence={"path": redact(path_str), "scope": "path"},
                            mitre_atlas=["AML.T0000", "AML.T0025"],
                            owasp_llm=["LLM06:2025"],
                            region=res.region,
                            fingerprint=fingerprint("AI-SPM-PATH-001", res.arn, path_str),
                        )
                    )

        # Path 2: Privileged K8s GPU Pod -> Vulnerable NVIDIA Toolkit Node (< 1.17.8)
        if res.kind == "k8s_pod" and res.metadata.get("privileged") is True:
            for rel, target_arn in graph.edges.get(res.arn, []):
                if rel != "scheduled_on":
                    continue
                node = graph.nodes.get(target_arn)
                if not node:
                    continue
                parsed = parse_semver(node.metadata.get("toolkit_version"))
                if parsed is not None:
                    maj, min_, pat, is_pre = parsed
                    is_vuln = (maj, min_, pat) < (1, 17, 8) or (
                        (maj, min_, pat) == (1, 17, 8) and is_pre
                    )
                    if is_vuln:
                        path_str = f"{res.arn} -> scheduled_on -> {node.arn}"
                        findings.append(
                            Finding(
                                rule_id="AI-SPM-PATH-002",
                                rule_title=(
                                    "Attack Path: Privileged GPU Pod on Vulnerable NVIDIA Toolkit Node"
                                ),
                                service="correlation",
                                resource_arn=res.arn,
                                resource_id=res.id,
                                resource_name=res.name,
                                status=Status.FAILED,
                                severity=Severity.CRITICAL,
                                message=redact(
                                    f"Privileged pod '{res.name}' runs on GPU node '{node.name}' "
                                    f"with vulnerable toolkit {node.metadata.get('toolkit_version')}."
                                ),
                                remediation=(
                                    "Drop privileged securityContext on the pod and upgrade NVIDIA "
                                    "Container Toolkit to >= v1.17.8."
                                ),
                                evidence={"path": redact(path_str), "scope": "path"},
                                owasp_llm=["LLM04:2026"],
                                region=res.region,
                                fingerprint=fingerprint("AI-SPM-PATH-002", res.arn, path_str),
                            )
                        )

        # Path 3: Public Vector Store -> Bedrock DataSource
        if res.kind == "bedrock_data_source":
            for rel, target_arn in graph.edges.get(res.arn, []):
                if rel != "uses_vectorstore":
                    continue
                vs = graph.nodes.get(target_arn)
                if vs and (
                    vs.metadata.get("public_principal") is True
                    or vs.metadata.get("network_public") is True
                ):
                    path_str = f"{res.arn} -> uses_vectorstore -> {vs.arn}"
                    findings.append(
                        Finding(
                            rule_id="AI-SPM-PATH-003",
                            rule_title="Attack Path: Bedrock RAG DataSource Backed by Public Vector DB",
                            service="correlation",
                            resource_arn=res.arn,
                            resource_id=res.id,
                            resource_name=res.name,
                            status=Status.FAILED,
                            severity=Severity.CRITICAL,
                            message=redact(
                                f"Bedrock data source '{res.name}' reads from publicly exposed "
                                f"vector store '{vs.name}'."
                            ),
                            remediation=(
                                "Restrict vector store network/resource policy to private VPC "
                                "access and attach a Bedrock Guardrail."
                            ),
                            evidence={"path": redact(path_str), "scope": "path"},
                            owasp_llm=["LLM06:2025", "LLM08:2025"],
                            region=res.region,
                            fingerprint=fingerprint("AI-SPM-PATH-003", res.arn, path_str),
                        )
                    )

    return findings
