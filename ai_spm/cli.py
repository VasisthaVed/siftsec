from pathlib import Path

import typer
from rich.console import Console

# Trigger dynamic rule auto-discovery
import ai_spm.rules  # noqa: F401
from ai_spm.collectors.mock import MockCollector
from ai_spm.config import settings
from ai_spm.engine.context import ScanContext
from ai_spm.engine.models import Severity
from ai_spm.engine.runner import ScanRunner
from ai_spm.engine.scoring import exit_code
from ai_spm.errors import AISPMError
from ai_spm.reporters.console import ConsoleReporter
from ai_spm.reporters.sarif import SARIFReporter
from ai_spm.rules.registry import registry
from ai_spm.utils.logger import configure_logging

app = typer.Typer(
    name="tensorguard",
    help="TensorGuard (AI-SPM): AI Security Posture Management Scanner CLI",
    no_args_is_help=True,
    add_completion=False,
)
err_console = Console(stderr=True)
out_console = Console()


@app.command()
def scan(
    demo: bool = typer.Option(
        False, "--demo", "-d", help="Run in zero-credential demo simulation mode"
    ),
    services: str | None = typer.Option(
        None, "--services", "-s", help="Comma-separated services to scan (e.g. s3,bedrock,mcp)"
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output file path"),
    sarif: bool = typer.Option(False, "--sarif", help="Export findings in SARIF v2.1.0 format"),
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

    try:
        if not demo:
            err_console.print(
                "[yellow]Live AWS scanning requires credentials. Running in --demo mode for testing.[/]"
            )

        selected_services = [s.strip() for s in services.split(",")] if services else None
        ctx = ScanContext(services=selected_services, fail_on=fail_on)
        runner = ScanRunner(collector=MockCollector(), context=ctx)
        findings = runner.run()

        if sarif and not output:
            out_console.print(SARIFReporter().export(findings))
        else:
            ConsoleReporter().render(findings)
            if output:
                output.write_text(SARIFReporter().export(findings), encoding="utf-8")
                err_console.print(f"[green]Report saved to {output}[/]")

        code = exit_code(findings, fail_on)
        if code != 0:
            raise typer.Exit(code=code)
    except AISPMError as exc:
        err_console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(code=exc.exit_code) from exc


@app.command("list-rules")
def list_rules() -> None:
    """List all registered AI-SPM detection rules."""
    rules = registry.get_rules()
    out_console.print(f"[bold cyan]Registered AI-SPM Rules ({len(rules)} total):[/]\n")
    for r in rules:
        out_console.print(f" • [bold yellow]{r.rule_id}[/]: [white]{r.title}[/] [{r.severity}]")


if __name__ == "__main__":
    app()
