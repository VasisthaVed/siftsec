# SPDX-License-Identifier: Apache-2.0
"""GitHub-Flavored Markdown PR reporter with untrusted-string escaping (Phase 4.5)."""

from siftsec.engine.models import ScanSummary, Status

_MAX_MARKDOWN_CHARS = 60_000


def escape_md(text: str) -> str:
    """Escape untrusted resource names/tags so they cannot inject Markdown, HTML, or @mentions."""
    out = text
    for ch, rep in (
        ("\\", "\\\\"),
        ("|", "\\|"),
        ("`", "\\`"),
        ("<", "&lt;"),
        (">", "&gt;"),
        ("@", "@\u200b"),
        ("[", "\\["),
        ("]", "\\]"),
        ("\r", " "),
        ("\n", " "),
    ):
        out = out.replace(ch, rep)
    return out


class MarkdownReporter:
    """Renders size-capped GFM audit summary suitable for GitHub PR comments."""

    def export(self, summary: ScanSummary) -> str:
        score_str = f"{summary.posture_score}/100" if summary.posture_score is not None else "N/A"
        failed = [f for f in summary.findings if f.status is Status.FAILED and not f.suppressed]
        passed_n = sum(1 for f in summary.findings if f.status is Status.PASSED)
        error_n = sum(1 for f in summary.findings if f.status is Status.ERROR)

        lines: list[str] = [
            "## 🛡️ Siftsec SIFTSEC Report",
            "",
            f"**Posture Score:** `{score_str}` | **Passed:** {passed_n} | **Failed:** {len(failed)} | **Errors:** {error_n}",
            "",
        ]

        if failed:
            lines.extend(
                [
                    "| Severity | Rule ID | Resource | Message |",
                    "| :--- | :--- | :--- | :--- |",
                ]
            )
            sorted_failed = sorted(failed, key=lambda f: f.severity.rank, reverse=True)
            for f in sorted_failed:
                lines.append(
                    f"| **{f.severity}** | `{f.rule_id}` | `{escape_md(f.resource_id)}` | {escape_md(f.message)} |"
                )
            lines.append("")
            lines.append("<details><summary>Remediation Guidance</summary>\n")
            for f in sorted_failed:
                lines.append(f"### `{f.rule_id}` — `{escape_md(f.resource_id)}`")
                lines.append(f"```text\n{f.remediation}\n```\n")
            lines.append("</details>")
        else:
            lines.append("✅ No failed AI security posture checks.")

        if summary.coverage_gaps:
            lines.extend(["", "### Coverage Gaps", ""])
            for gap in summary.coverage_gaps:
                lines.append(
                    f"- `{escape_md(gap.service)}` ({escape_md(gap.region)}) `{escape_md(gap.api)}`: `{escape_md(gap.error_code)}`"
                )

        rendered = "\n".join(lines)
        if len(rendered) > _MAX_MARKDOWN_CHARS:
            footer = (
                "\n\n... *(truncated to fit GitHub comment limit; see full JSON/SARIF artifact)*"
            )
            return rendered[: _MAX_MARKDOWN_CHARS - len(footer)] + footer
        return rendered
