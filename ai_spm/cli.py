from pathlib import Path

import typer
from rich.console import Console

# Trigger dynamic rule auto-discovery
import ai_spm.rules  # noqa: F401
from ai_spm.collectors.mock import MockCollector
from ai_spm.config import settings
from ai_spm.engine.models import Severity, Status
from ai_spm.engine.runner import ScanRunner
from ai_spm.reporters.console import ConsoleReporter
from ai_spm.reporters.sarif import SARIFReporter
from ai_spm.rules.registry import registry

app = typer.Typer(
    name="ai-spm",
    help="AI Security Posture Management (AI-SPM) Scanner CLI",
    add_completion=False,
)
console = Console()


@app.command()
def scan(
    demo: bool = typer.Option(
        False, "--demo", "-d", help="Run in zero-credential demo simulation mode"
    ),
    services: str = typer.Option(
        None, "--services", "-s", help="Comma-separated services to scan (e.g. s3,bedrock,mcp)"
    ),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path"),
    sarif: bool = typer.Option(False, "--sarif", help="Export findings in SARIF v2.1.0 format"),
    fail_on: str = typer.Option(
        settings.default_fail_on.value,
        "--fail-on",
        help="Fail with exit code 1 if findings meet or exceed severity",
    ),
) -> None:
    """Scan AI/ML workloads for security posture and threat misconfigurations."""
    if not demo:
        console.print(
            "[yellow]Live AWS scanning requires credentials. Running in --demo mode for testing.[/]"
        )

    collector = MockCollector()
    selected_services = [s.strip() for s in services.split(",")] if services else None

    runner = ScanRunner(collector=collector, services=selected_services)
    findings = runner.run()

    reporter = ConsoleReporter()
    reporter.render(findings)

    if output or sarif:
        sarif_reporter = SARIFReporter()
        sarif_json = sarif_reporter.export(findings)
        if output:
            output.write_text(sarif_json, encoding="utf-8")
            console.print(f"[green]Report saved to {output}[/]")
        elif sarif:
            console.print(sarif_json)

    fail_severities = (
        [Severity.CRITICAL]
        if fail_on.upper() == Severity.CRITICAL
        else [Severity.CRITICAL, Severity.HIGH]
    )
    has_blocking_failures = any(
        f.status == Status.FAILED and f.severity in fail_severities for f in findings
    )

    if has_blocking_failures:
        raise typer.Exit(code=1)


@app.command("list-rules")
def list_rules() -> None:
    """List all registered AI-SPM detection rules."""
    rules = registry.get_rules()
    console.print(f"[bold cyan]Registered AI-SPM Rules ({len(rules)} total):[/]\n")
    for r in rules:
        console.print(f" • [bold yellow]{r.rule_id}[/]: [white]{r.title}[/] [{r.severity}]")


if __name__ == "__main__":
    app()
