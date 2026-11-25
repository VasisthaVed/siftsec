import hashlib
import json
import sys
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

import boto3
import typer
from rich.console import Console

# Trigger dynamic rule auto-discovery
import ai_spm.rules  # noqa: F401
from ai_spm import __version__
from ai_spm.collectors.aws.client import AwsClientFactory, resolve_identity
from ai_spm.collectors.aws.orchestrator import AwsOrchestrator
from ai_spm.collectors.base import BaseCollector
from ai_spm.collectors.gcp import GcpCollector
from ai_spm.collectors.k8s import K8sCollector
from ai_spm.collectors.local.mcp import LocalMcpCollector
from ai_spm.collectors.local.models import LocalModelCollector
from ai_spm.collectors.mock import MockCollector
from ai_spm.config import settings
from ai_spm.engine.context import ScanContext
from ai_spm.engine.models import CloudResource, CoverageGap, ScanSummary, Severity, Status
from ai_spm.engine.runner import ScanRunner
from ai_spm.engine.scoring import exit_code, posture_score
from ai_spm.engine.suppressions import apply_suppressions, load_baseline_fingerprints
from ai_spm.errors import AISPMError
from ai_spm.reporters.aibom import AIBOMReporter
from ai_spm.reporters.console import ConsoleReporter
from ai_spm.reporters.json_rep import JSONReporter
from ai_spm.reporters.markdown import MarkdownReporter
from ai_spm.reporters.sarif import SARIFReporter
from ai_spm.rules.registry import registry
from ai_spm.utils.fs import atomic_write_secure
from ai_spm.utils.logger import configure_logging

app = typer.Typer(
    name="tensorguard",
    help="TensorGuard (AI-SPM): AI Security Posture Management Scanner CLI",
    no_args_is_help=True,
    add_completion=False,
)
err_console = Console(stderr=True)
out_console = Console()


class OutputFormat(StrEnum):
    console = "console"
    json = "json"
    sarif = "sarif"
    markdown = "markdown"


class SbomFormat(StrEnum):
    cyclonedx = "cyclonedx"
    spdx = "spdx"


class _CompositeCollector(BaseCollector):
    def __init__(self, collectors: list[BaseCollector]) -> None:
        self._collectors = collectors

    def collect(self) -> list[CloudResource]:
        resources: list[CloudResource] = []
        for col in self._collectors:
            resources.extend(col.collect())
        return resources


class _PreCollectedCollector(BaseCollector):
    def __init__(self, items: list[CloudResource]) -> None:
        self._items = items

    def collect(self) -> list[CloudResource]:
        return self._items


def _collect_target_resources(
    *,
    demo: bool,
    local: bool,
    aws: bool,
    gcp: bool,
    k8s: bool,
    path: list[Path],
    include_hf_cache: bool,
    gcp_project: str | None,
    kube_context: str | None,
    profile: str | None,
    ctx: ScanContext,
) -> tuple[list[CloudResource], list[CoverageGap]]:
    """Collect cloud, local, Kubernetes, or demo resources into a unified list."""
    resources: list[CloudResource] = []
    coverage_gaps: list[CoverageGap] = []

    if local:
        for p in path:
            if not p.exists():
                raise AISPMError(f"Target path does not exist: {p}")
        collector: BaseCollector = _CompositeCollector(
            [
                LocalModelCollector(paths=path, include_hf_cache=include_hf_cache),
                LocalMcpCollector(paths=path),
            ]
        )
        resources.extend(collector.collect())

    if aws:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        factory = AwsClientFactory(session, settings)
        col_result = AwsOrchestrator(factory, settings).run(ctx)
        resources.extend(col_result.resources)
        coverage_gaps.extend(col_result.coverage_gaps)

    if gcp:
        gcp_res = GcpCollector(
            project_id=gcp_project, regions=ctx.regions, cfg=settings
        ).collect_with_gaps(ctx)
        resources.extend(gcp_res.resources)
        coverage_gaps.extend(gcp_res.coverage_gaps)

    if k8s:
        resources.extend(K8sCollector(kube_context=kube_context, cfg=settings).collect())

    if not (local or aws or gcp or k8s):
        if not demo:
            err_console.print(
                "[yellow]No target specified (--local / --aws / --gcp / --k8s). "
                "Running in --demo mode.[/]"
            )
        resources.extend(MockCollector().collect())

    return resources, coverage_gaps


@app.command()
def scan(
    demo: bool = typer.Option(False, "--demo", "-d", help="Run zero-credential demo simulation"),
    local: bool = typer.Option(
        False, "--local", "-l", help="Scan local model files and MCP configurations"
    ),
    aws: bool = typer.Option(False, "--aws", help="Scan live AWS environment via Boto3"),
    gcp: bool = typer.Option(False, "--gcp", help="Scan Google Cloud (Vertex AI & GCS)"),
    gcp_project: str | None = typer.Option(None, "--gcp-project", help="GCP project ID for --gcp"),
    k8s: bool = typer.Option(False, "--k8s", help="Scan Kubernetes GPU cluster (read-only)"),
    kube_context: str | None = typer.Option(
        None, "--kube-context", help="Kubernetes context name for --k8s"
    ),
    path: list[Path] = typer.Option(
        [Path(".")], "--path", "-p", help="Local path(s) to scan when --local is enabled"
    ),
    include_hf_cache: bool = typer.Option(
        False, "--include-hf-cache", help="Also scan ~/.cache/huggingface/hub in --local mode"
    ),
    regions: str = typer.Option(
        "us-east-1", "--regions", "-r", help="Comma-separated AWS regions or 'all'"
    ),
    profile: str | None = typer.Option(None, "--profile", help="AWS CLI named profile"),
    services: str | None = typer.Option(
        None, "--services", "-s", help="Comma-separated services to scan (e.g. s3,bedrock,mcp)"
    ),
    ai_only: bool = typer.Option(
        True, "--ai-only/--all-resources", help="Filter non-AI cloud resources"
    ),
    baseline: Path | None = typer.Option(
        None, "--baseline", "-b", help="Baseline JSON file of accepted finding fingerprints"
    ),
    fmt: OutputFormat = typer.Option(OutputFormat.console, "--format", "-f", help="Output format"),
    sbom: SbomFormat | None = typer.Option(
        None, "--sbom", help="Emit AI Bill of Materials (cyclonedx or spdx)"
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output file path"),
    sarif: bool = typer.Option(False, "--sarif", help="Shortcut for --format sarif"),
    force: bool = typer.Option(False, "--force", help="Overwrite existing output file"),
    strict_coverage: bool = typer.Option(
        False, "--strict-coverage", help="Exit 3 if any collector permission gaps occur"
    ),
    fail_on: Severity = typer.Option(
        settings.default_fail_on,
        "--fail-on",
        help="Fail with exit code 1 if findings meet or exceed severity",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose debug logging"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Show only errors in logs"),
) -> None:
    """Scan AI/ML workloads for security posture and threat misconfigurations."""
    configure_logging(verbose=verbose, quiet=quiet)
    started_at = datetime.now(UTC)

    try:
        selected_services = [s.strip() for s in services.split(",")] if services else None
        region_list = [r.strip() for r in regions.split(",") if r.strip()]
        ctx = ScanContext(
            regions=region_list,
            services=selected_services,
            fail_on=fail_on,
            ai_only=ai_only,
            profile=profile,
            gcp_project=gcp_project,
        )

        resources, coverage_gaps = _collect_target_resources(
            demo=demo,
            local=local,
            aws=aws,
            gcp=gcp,
            k8s=k8s,
            path=path,
            include_hf_cache=include_hf_cache,
            gcp_project=gcp_project,
            kube_context=kube_context,
            profile=profile,
            ctx=ctx,
        )

        raw_findings = ScanRunner(collector=_PreCollectedCollector(resources), context=ctx).run()
        baseline_fps = load_baseline_fingerprints(baseline)
        findings = apply_suppressions(raw_findings, [], baseline_fingerprints=baseline_fps)
        finished_at = datetime.now(UTC)
        summary = ScanSummary(
            total_resources=len(resources),
            ai_resources=sum(1 for r in resources if r.is_ai_workload),
            findings=findings,
            posture_score=posture_score(findings, settings.severity_weights),
            coverage_gaps=coverage_gaps,
            started_at=started_at,
            finished_at=finished_at,
            tool_version=__version__,
        )

        active_fmt = OutputFormat.sarif if sarif else fmt
        if sbom is SbomFormat.cyclonedx:
            payload = AIBOMReporter().export_cyclonedx(resources)
        elif sbom is SbomFormat.spdx:
            payload = AIBOMReporter().export_spdx(resources)
        elif active_fmt is OutputFormat.json:
            payload = JSONReporter().export(summary)
        elif active_fmt is OutputFormat.sarif:
            payload = SARIFReporter().export(findings)
        elif active_fmt is OutputFormat.markdown:
            payload = MarkdownReporter().export(summary)
        else:
            payload = ""
            ConsoleReporter().render(findings)

        if output:
            out_text = payload or JSONReporter().export(summary)
            atomic_write_secure(output, out_text, force=force)
            err_console.print(f"[green]Report saved to {output}[/]")
        elif payload:
            out_console.print(payload, soft_wrap=True)

        code = exit_code(
            findings,
            fail_on,
            strict_coverage=strict_coverage,
            coverage_gaps_count=len(coverage_gaps),
        )
        if code != 0:
            raise typer.Exit(code=code)
    except AISPMError as exc:
        err_console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(code=exc.exit_code) from exc


@app.command("doctor")
def doctor(
    profile: str | None = typer.Option(None, "--profile", help="AWS CLI named profile"),
    region: str = typer.Option("us-east-1", "--region", help="AWS region to probe"),
) -> None:
    """Check Python environment, AWS credentials, and read-only collector readiness."""
    configure_logging()
    out_console.print(f"[bold cyan]TensorGuard Doctor[/] (v{__version__})")
    out_console.print(f" • Python: {sys.version.split()[0]}")
    out_console.print(f" • Registered rules: {len(registry.get_rules())}")

    import importlib.util

    k8s_ready = importlib.util.find_spec("kubernetes") is not None
    gcp_ready = (
        importlib.util.find_spec("google") is not None
        and importlib.util.find_spec("google.cloud.storage") is not None
    )
    out_console.print(
        f" • Optional K8s extra: {'[green]installed[/]' if k8s_ready else '[yellow]not installed (tensorguard[k8s])[/]'}"
    )
    out_console.print(
        f" • Optional GCP extra: {'[green]installed[/]' if gcp_ready else '[yellow]not installed (tensorguard[gcp])[/]'}"
    )

    try:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        factory = AwsClientFactory(session, settings)
        identity = resolve_identity(factory)
        out_console.print(
            f" • AWS Identity: [green]{identity.arn}[/] (partition={identity.partition})"
        )
    except AISPMError as exc:
        out_console.print(f" • AWS Identity: [yellow]Not configured ({exc})[/]")
        return

    probes = [
        ("s3", "list_buckets", {}),
        ("sagemaker", "list_notebook_instances", {}),
        ("bedrock", "list_guardrails", {}),
        ("ecr", "describe_repositories", {}),
        ("opensearch", "list_domain_names", {}),
        ("ec2", "describe_security_groups", {"MaxResults": 5}),
    ]
    for svc, method, kw in probes:
        try:
            client = factory.client(svc, region=region)
            getattr(client, method)(**kw)
            out_console.print(f" • [green]OK[/] {svc}.{method}")
        except Exception as exc:  # noqa: BLE001
            out_console.print(f" • [yellow]GAP[/] {svc}.{method}: {type(exc).__name__}")


@app.command("list-rules")
def list_rules() -> None:
    """List all registered AI-SPM detection rules."""
    rules = registry.get_rules()
    out_console.print(f"[bold cyan]Registered AI-SPM Rules ({len(rules)} total):[/]\n")
    for r in rules:
        out_console.print(f" • [bold yellow]{r.rule_id}[/]: [white]{r.title}[/] [{r.severity}]")


@app.command("baseline-create")
def baseline_create(
    demo: bool = typer.Option(False, "--demo", "-d", help="Create baseline from demo scan"),
    local: bool = typer.Option(False, "--local", "-l", help="Create baseline from local scan"),
    aws: bool = typer.Option(False, "--aws", help="Create baseline from AWS scan"),
    gcp: bool = typer.Option(False, "--gcp", help="Create baseline from GCP scan"),
    gcp_project: str | None = typer.Option(None, "--gcp-project", help="GCP project ID"),
    k8s: bool = typer.Option(False, "--k8s", help="Create baseline from Kubernetes GPU scan"),
    kube_context: str | None = typer.Option(None, "--kube-context", help="Kubernetes context"),
    path: list[Path] = typer.Option([Path(".")], "--path", "-p", help="Local path(s) to scan"),
    regions: str = typer.Option("us-east-1", "--regions", "-r", help="AWS regions"),
    profile: str | None = typer.Option(None, "--profile", help="AWS CLI named profile"),
    output: Path = typer.Option(
        Path(".tensorguard-baseline.json"),
        "--output",
        "-o",
        help="Destination baseline file path",
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite existing baseline file"),
) -> None:
    """Snapshot current FAILED finding fingerprints into an accepted baseline file."""
    configure_logging()
    try:
        ctx = ScanContext(
            regions=[r.strip() for r in regions.split(",") if r.strip()],
            profile=profile,
            gcp_project=gcp_project,
        )
        resources, _ = _collect_target_resources(
            demo=demo,
            local=local,
            aws=aws,
            gcp=gcp,
            k8s=k8s,
            path=path,
            include_hf_cache=False,
            gcp_project=gcp_project,
            kube_context=kube_context,
            profile=profile,
            ctx=ctx,
        )
        findings = ScanRunner(collector=_PreCollectedCollector(resources), context=ctx).run()
        fingerprints = sorted({f.fingerprint for f in findings if f.status == Status.FAILED})
        payload = json.dumps(
            {
                "version": 1,
                "generated_at": datetime.now(UTC).isoformat(),
                "fingerprints": fingerprints,
            },
            indent=2,
        )
        atomic_write_secure(output, payload, force=force)
        out_console.print(
            f"[green]Baseline saved to {output}[/] ({len(fingerprints)} fingerprints)"
        )
    except AISPMError as exc:
        err_console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(code=exc.exit_code) from exc


@app.command("mcp-lock")
def mcp_lock(
    path: list[Path] = typer.Option(
        [Path(".")], "--path", "-p", help="Local path(s) to inspect for MCP configs"
    ),
    output: Path = typer.Option(
        Path(".tensorguard-lock.json"),
        "--output",
        "-o",
        help="Destination MCP lockfile path",
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite existing lockfile"),
) -> None:
    """Generate a SHA-256 integrity lockfile for discovered MCP server definitions."""
    configure_logging()
    try:
        for p in path:
            if not p.exists():
                raise AISPMError(f"Target path does not exist: {p}")
        resources = LocalMcpCollector(paths=path).collect()
        locked_servers: list[dict[str, str]] = []
        for res in sorted(resources, key=lambda r: r.arn):
            canonical = json.dumps(
                {
                    "server_name": res.name,
                    "command": res.metadata.get("command"),
                    "args": res.metadata.get("args", []),
                    "env_keys": sorted(str(k) for k in res.metadata.get("env_keys", [])),
                    "url": res.metadata.get("url"),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            locked_servers.append(
                {
                    "resource_id": res.arn,
                    "server_name": res.name,
                    "sha256": digest,
                }
            )
        payload = json.dumps(
            {
                "version": 1,
                "generated_at": datetime.now(UTC).isoformat(),
                "servers": locked_servers,
            },
            indent=2,
        )
        atomic_write_secure(output, payload, force=force)
        out_console.print(
            f"[green]MCP lockfile saved to {output}[/] ({len(locked_servers)} servers)"
        )
    except AISPMError as exc:
        err_console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(code=exc.exit_code) from exc


@app.command("version")
def version() -> None:
    """Show installed TensorGuard version."""
    out_console.print(f"tensorguard {__version__}")


if __name__ == "__main__":
    app()
