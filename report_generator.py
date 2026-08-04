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
from pathlib import Path

UTC = timezone.utc  # datetime.UTC was added in Python 3.11; timezone.utc works on 3.9+

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# ---------------------------------------------------------------------------
# Path confinement for model-controlled output paths
# ---------------------------------------------------------------------------
#
# write_report()'s own default usage and main.py's CLI --out flag are
# deliberately NOT restricted by this -- both are operated by a trusted
# local human who can already write anywhere their own filesystem
# permissions allow, and main.py's --out is a documented, intentional
# "write wherever I point you" feature, not a vulnerability.
#
# confine_report_path() exists specifically for agent.py's
# generate_report_file_tool, the one call site where output_path is
# model-controlled (ADK chat mode) and therefore untrusted. See
# specs/write_action_gate_spec.md.

DEFAULT_OUTPUT_DIR = "reports"


class ReportPathError(ValueError):
    """Raised when a requested report output path resolves outside the
    designated output directory. A ValueError subclass so existing
    tool-input-validation conventions (e.g. "repo_url must be a non-empty
    string") still apply, but distinguishable by callers that want to
    handle this case specifically."""


def confine_report_path(output_path: str, base_dir: str = DEFAULT_OUTPUT_DIR) -> str:
    """Resolve `output_path` against `base_dir` and confirm the result
    stays inside it. Rejects (raises ReportPathError) any path that would
    escape `base_dir` -- an absolute path, a `../` traversal, or any
    combination thereof -- rather than silently redirecting it somewhere
    "safe". Returns the resolved absolute path (inside base_dir) on
    success, as a string, ready to pass to write_report().

    A relative `output_path` (the expected case, e.g. "review_report.md"
    or "findings/security.md") is resolved *relative to base_dir*, not the
    process's current working directory -- so "review_report.md" always
    means "<base_dir>/review_report.md", never wherever the process
    happens to be running from.
    """
    base = Path(base_dir).resolve()

    raw = Path(output_path)
    candidate = raw.resolve() if raw.is_absolute() else (base / raw).resolve()

    try:
        candidate.relative_to(base)
    except ValueError:
        raise ReportPathError(
            f"output_path {output_path!r} resolves to {candidate}, which is "
            f"outside the designated report output directory ({base}). "
            "Rejected, not redirected -- pass a path inside that directory."
        )

    return str(candidate)


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

    # Layer B of the prompt-injection defense (see specs/injection_defense_spec.md,
    # injection_scanner.py) -- a heuristic pre-scan of fetched content run
    # BEFORE it ever reached GeminiReviewer. Omitted entirely when empty, so
    # a clean repo's report isn't cluttered with an empty section header.
    injection_findings = getattr(result, "injection_findings", None) or []
    if injection_findings:
        lines.append("## Potential Prompt Injection Detected")
        lines.append("")
        lines.append(
            "The scan below runs on fetched content before it reaches the "
            "reviewer and only flags suspicious patterns — it never blocks "
            "or strips anything. This is a visibility backstop; the model "
            "itself is separately instructed to ignore any such embedded "
            "instructions and report them as findings rather than comply."
        )
        lines.append("")
        for match in injection_findings:
            location = f"{_escape(match.path)}:{match.line}"
            lines.append(f"- **{_escape(match.category)}** ({location}): `{_escape(match.snippet)}`")
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
