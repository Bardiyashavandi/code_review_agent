"""
report_generator.py
---------------------
Renders an agent.PipelineResult into a human-readable Markdown report.

Usage:
    from report_generator import generate_markdown_report, write_report

    markdown_text = generate_markdown_report(pipeline_result)
    path = write_report(pipeline_result, "review_report.md")
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

UTC = timezone.utc  # datetime.UTC was added in Python 3.11; timezone.utc works on 3.9+

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _escape(text) -> str:
    """Escape angle brackets so model/Semgrep text can't inject raw HTML/markup."""
    if text is None:
        return ""
    return str(text).replace("<", "&lt;").replace(">", "&gt;")


def generate_markdown_report(result) -> str:
    """Build the full Markdown report text from a PipelineResult."""
    lines: list[str] = []

    fetch = result.fetch_result
    scan = result.scan_report
    review = result.review_report

    lines.append(f"# Code Review Report: {_escape(result.repo_url)}")
    lines.append("")
    lines.append(f"- **Generated:** {datetime.now(UTC).isoformat(timespec='seconds')}")
    lines.append(f"- **Model:** {_escape(review.model)}")
    lines.append(f"- **Files fetched:** {len(fetch.files)}" + (" (truncated)" if fetch.truncated else ""))
    lines.append(f"- **Files scanned by Semgrep:** {scan.scanned}")
    lines.append(f"- **Semgrep findings:** {len(scan.findings)}")
    lines.append(f"- **Total duration:** {result.duration_s:.2f}s")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(_escape(review.summary) or "(no summary provided)")
    lines.append("")

    if result.stage_errors:
        lines.append("## Stage Errors")
        lines.append("")
        for err in result.stage_errors:
            lines.append(f"- **{_escape(err.stage)}**: {_escape(err.message)}")
        lines.append("")

    lines.append("## Issues")
    lines.append("")

    if not review.issues:
        lines.append("No issues found.")
        lines.append("")
    else:
        by_severity: dict[str, list] = {level: [] for level in SEVERITY_ORDER}
        for issue in review.issues:
            by_severity.setdefault(issue.severity, []).append(issue)

        ordered_keys = list(SEVERITY_ORDER) + [
            k for k in by_severity if k not in SEVERITY_ORDER
        ]

        for severity in ordered_keys:
            issues = by_severity.get(severity, [])
            if not issues:
                continue
            lines.append(f"### {severity}")
            lines.append("")
            for issue in issues:
                location = f"{_escape(issue.path)}:{issue.line}"
                lines.append(f"**{_escape(issue.title)}** ({location})")
                lines.append("")
                lines.append(_escape(issue.description))
                lines.append("")
                lines.append(f"*Suggested fix:* {_escape(issue.suggested_fix)}")
                if getattr(issue, "rule_id", None):
                    lines.append(f"*Rule:* `{_escape(issue.rule_id)}`")
                lines.append("")

    if scan.skipped:
        lines.append("## Skipped Files")
        lines.append("")
        for path in scan.skipped:
            lines.append(f"- {_escape(path)}")
        lines.append("")

    return "\n".join(lines)


def write_report(result, output_path: str) -> str:
    """Render the report and write it to output_path (UTF-8), creating parent dirs."""
    parent = os.path.dirname(output_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    text = generate_markdown_report(result)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(text)

    return output_path
