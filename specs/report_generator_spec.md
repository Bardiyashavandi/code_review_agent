# Spec: `report_generator` Module

**Project:** AI Code Review Agent
**Module:** `report_generator.py`
**Version:** 1.0
**Status:** Draft

---

## 1. Purpose

Render a `PipelineResult` (from `agent.py`) into a human-readable Markdown report: summary, prioritized issues, Semgrep stats, and any stage errors. This is the artifact a user actually reads.

---

## 2. Public Interface

```python
from report_generator import generate_markdown_report

markdown_text = generate_markdown_report(pipeline_result)
```

```python
from report_generator import write_report

path = write_report(pipeline_result, output_path="review_report.md")
```

---

## 3. Behavior

- Header: repo URL, model used, files fetched/scanned, total duration, generation timestamp (UTC, ISO 8601).
- Summary section: `review_report.summary` text.
- Stage errors section: only rendered if `stage_errors` is non-empty; lists stage + message.
- Issues section: grouped by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW` in that order); each issue shows path:line, title, description, suggested fix, and linked `rule_id` if present.
- If `issues` is empty, render "No issues found." instead of an empty section.
- All text inserted from model/Semgrep output (titles, descriptions, messages) is treated as plain text — never interpreted as Markdown structure beyond normal escaping, so a malicious title can't break report layout or inject raw HTML (escape `<`, `>` is sufficient for Markdown render safety in most renderers, but is intentionally NOT required to look "pretty" — correctness/safety over polish).
- `write_report` creates parent directories if needed, writes UTF-8, and returns the path written.

---

## 4. Tests (`tests/test_report_generator.py`)

| Test ID | Scenario | Expected |
|---|---|---|
| `test_header_contains_repo_url` | basic result | URL present in output |
| `test_no_issues_renders_placeholder` | empty issues | "No issues found." present |
| `test_issues_grouped_by_severity_order` | mixed severities | CRITICAL section appears before LOW section |
| `test_stage_errors_section_omitted_when_empty` | no stage errors | no "Stage Errors" heading |
| `test_stage_errors_section_present_when_nonempty` | 1 stage error | heading + message present |
| `test_write_report_creates_file` | tmp_path | file exists, contains expected content |
| `test_write_report_creates_parent_dirs` | nested tmp path | directories created |

---

## 5. Out of Scope

HTML/PDF rendering, charts, multi-repo aggregate reports.
