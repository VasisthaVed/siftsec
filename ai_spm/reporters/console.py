from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ai_spm.config import settings
from ai_spm.engine.models import Finding, Severity, Status


class ConsoleReporter:
    def __init__(self) -> None:
        self.console = Console()

    def calculate_score(self, findings: list[Finding]) -> int:
        """Calculate severity-weighted pass-rate posture score (0-100)."""
        evaluated = [f for f in findings if f.status in (Status.PASSED, Status.FAILED)]
        if not evaluated:
            return 100

        total_weight = 0
        passed_weight = 0
        for f in evaluated:
            weight = settings.severity_weights.get(f.severity, 1)
            total_weight += weight
            if f.status == Status.PASSED:
                passed_weight += weight

        if total_weight == 0:
            return 100

        return round((passed_weight / total_weight) * 100)

    def render(self, findings: list[Finding]) -> None:
        score = self.calculate_score(findings)
        color = "green" if score >= 80 else "yellow" if score >= 50 else "red"

        passed_count = sum(1 for f in findings if f.status == Status.PASSED)
        failed_count = sum(1 for f in findings if f.status == Status.FAILED)

        self.console.print()
        self.console.print(
            Panel(
                f"[bold white]AI Security Posture Score:[/] [{color} bold]{score}/100[/]  "
                f"|  [green]Passed:[/] {passed_count}  "
                f"|  [red]Failed:[/] {failed_count}  "
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
            st_color = "red bold" if f.status == Status.FAILED else "green"
            sev_color = (
                "red bold"
                if f.severity == Severity.CRITICAL
                else "yellow bold"
                if f.severity == Severity.HIGH
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

        failed_findings = [f for f in findings if f.status == Status.FAILED]
        if failed_findings:
            self.console.print("[bold red]Actionable Remediation Guidance:[/]")
            for f in failed_findings:
                self.console.print(
                    Panel(
                        f"[bold white]{f.message}[/]\n\n"
                        f"[bold green]Remediation:[/] [yellow]{f.remediation}[/]\n"
                        f"[cyan]Threat Mapping:[/] MITRE: {f.mitre_atlas} | OWASP: {f.owasp_llm}",
                        title=f"[{f.severity}] {f.rule_id}: {f.rule_title}",
                        border_style="red" if f.severity == Severity.CRITICAL else "yellow",
                    )
                )
