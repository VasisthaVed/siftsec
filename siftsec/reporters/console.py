from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from siftsec.config import settings
from siftsec.engine.models import Finding, Severity, Status
from siftsec.engine.scoring import posture_score


class ConsoleReporter:
    """Renders responsive Rich terminal audit tables and remediation panels."""

    def __init__(self) -> None:
        self.console = Console()

    def calculate_score(self, findings: list[Finding]) -> int | None:
        return posture_score(findings, settings.severity_weights)

    def render(self, findings: list[Finding]) -> None:
        score = self.calculate_score(findings)
        if score is None:
            score_display = "[yellow bold]N/A[/]"
            color = "yellow"
        else:
            color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
            score_display = f"[{color} bold]{score}/100[/]"

        passed_count = sum(1 for f in findings if f.status is Status.PASSED)
        failed_count = sum(1 for f in findings if f.status is Status.FAILED)
        error_count = sum(1 for f in findings if f.status is Status.ERROR)

        self.console.print()
        self.console.print(
            Panel(
                f"[bold white]AI Security Posture Score:[/] {score_display}  "
                f"|  [green]Passed:[/] {passed_count}  "
                f"|  [red]Failed:[/] {failed_count}  "
                f"|  [yellow]Errors:[/] {error_count}  "
                f"|  [cyan]Total:[/] {len(findings)}",
                title=f"[bold magenta]🛡️  {settings.app_name} Security Audit Report[/]",
                border_style=color,
            )
        )

        table = Table(
            title="Security Findings Summary",
            show_header=True,
            header_style="bold cyan",
            expand=True,
        )
        table.add_column("Status", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Rule ID", no_wrap=True)
        table.add_column("Resource", ratio=2, overflow="ellipsis")
        table.add_column("Framework / Threat", ratio=2, overflow="ellipsis")

        for f in findings:
            st_color = (
                "red bold"
                if f.status is Status.FAILED
                else "yellow bold"
                if f.status is Status.ERROR
                else "green"
            )
            sev_color = (
                "red bold"
                if f.severity is Severity.CRITICAL
                else "yellow bold"
                if f.severity is Severity.HIGH
                else "blue"
            )

            threats = ", ".join(f.mitre_atlas + f.owasp_llm) or "—"
            table.add_row(
                f"[{st_color}]{f.status}[/]",
                f"[{sev_color}]{f.severity}[/]",
                f.rule_id,
                f.resource_id,
                threats,
            )

        self.console.print(table)
        self.console.print()

        failed_findings = [f for f in findings if f.status is Status.FAILED]
        if failed_findings:
            self.console.print("[bold red]Actionable Remediation Guidance:[/]")
            for f in failed_findings:
                self.console.print(
                    Panel(
                        f"[bold white]{f.message}[/]\n\n"
                        f"[bold green]Remediation:[/] [yellow]{f.remediation}[/]\n"
                        f"[cyan]Threat Mapping:[/] MITRE: {f.mitre_atlas} | OWASP: {f.owasp_llm}",
                        title=f"[{f.severity}] {f.rule_id}: {f.rule_title}",
                        border_style="red" if f.severity is Severity.CRITICAL else "yellow",
                    )
                )
