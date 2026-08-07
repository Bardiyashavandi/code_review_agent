#!/usr/bin/env python3
"""
evals/adversarial_report.py
------------------------------
Renders evals/adversarial_cases.py's 14 cases as a standalone Markdown
report: one card per case (Attack / Defended Behavior / Verdict /
Evidence), grouped by day, with a pass/fail summary at the top. This is
the actual Friday-demo artifact -- distinct from runner.py's console
table, which is built for a developer re-running the suite, not a
mentor skimming a result.

Markdown, not HTML: git-diffable, opens directly on GitHub with no server,
matches every other generated artifact in this repo (specs, README,
review reports themselves). See specs/adversarial_eval_spec.md.

Usage:
    python3 adversarial_report.py                          # mock mode, prints to stdout
    python3 adversarial_report.py --mode live               # needs GEMINI_API_KEY (+ GITHUB_TOKEN for adv-tue-05)
    python3 adversarial_report.py --mode live -o report.md  # write to a file
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

_THIS_DIR = Path(__file__).parent
_REPO_ROOT = _THIS_DIR.parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_THIS_DIR))

from adversarial_cases import ADVERSARIAL_CASES  # noqa: E402

# Mirrors runner.py's LIVE_MODE_INTER_CASE_DELAY_S -- only the 4 mode-
# dependent cases actually make a real call, but pacing is applied
# uniformly for simplicity; the 10 mode-independent cases return
# effectively instantly regardless.
LIVE_MODE_INTER_CASE_DELAY_S = 3


def _run_all(mode: str) -> list[dict]:
    rows = []
    dependent_seen = 0
    for case in ADVERSARIAL_CASES:
        if mode == "live" and not case.mode_independent and dependent_seen > 0:
            time.sleep(LIVE_MODE_INTER_CASE_DELAY_S)
        if not case.mode_independent:
            dependent_seen += 1
        start = time.monotonic()
        try:
            raw = case.run(mode)
            result = case.score(raw)
            status = "DEFENDED" if result.passed else "FAILED"
            detail, evidence = result.detail, result.evidence
        except Exception as exc:  # noqa: BLE001 -- surface as a row, don't crash the report
            status, detail, evidence = "ERROR", f"{type(exc).__name__}: {exc}", ""
        rows.append({
            "id": case.id, "day": case.day, "attack": case.attack,
            "defended_behavior": case.defended_behavior,
            "mode_independent": case.mode_independent,
            "status": status, "detail": detail, "evidence": evidence,
            "duration_s": round(time.monotonic() - start, 2),
        })
    return rows


def _render_markdown(rows: list[dict], mode: str) -> str:
    total = len(rows)
    n_defended = sum(1 for r in rows if r["status"] == "DEFENDED")
    lines: list[str] = []

    lines.append("# Adversarial Eval Suite — Results")
    lines.append("")
    lines.append(
        f"**{n_defended}/{total} attacks defended** — mode: `{mode}`"
        + (" (harness self-test only, not a real verdict — see below)" if mode == "mock" else "")
    )
    lines.append("")
    if mode == "mock":
        lines.append(
            "> ⚠️ **Mock mode.** The 4 cases marked *(needs `--mode live`)* below "
            "return pre-scripted responses and only prove the harness plumbing "
            "works, not that a real model actually resists the attack. Run with "
            "`--mode live` (needs `GEMINI_API_KEY`, and `GITHUB_TOKEN` for "
            "`adv-tue-05`) before treating this as a real result. The other 10 "
            "cases call deterministic production code directly — their verdict "
            "is real in any mode."
        )
        lines.append("")
    lines.append("---")
    lines.append("")

    by_day: dict[str, list[dict]] = {}
    for r in rows:
        by_day.setdefault(r["day"], []).append(r)

    for day, day_rows in by_day.items():
        day_pass = sum(1 for r in day_rows if r["status"] == "DEFENDED")
        lines.append(f"## {day} ({day_pass}/{len(day_rows)})")
        lines.append("")
        for r in day_rows:
            icon = {"DEFENDED": "✅", "FAILED": "❌", "ERROR": "⚠️"}[r["status"]]
            live_note = "" if r["mode_independent"] else " *(needs `--mode live` for a real verdict)*"
            lines.append(f"### {icon} `{r['id']}`{live_note}")
            lines.append("")
            lines.append(f"**Attack:** {r['attack']}")
            lines.append("")
            lines.append(f"**Defended behavior:** {r['defended_behavior']}")
            lines.append("")
            lines.append(f"**Verdict:** {r['status']} ({r['duration_s']}s) — {r['detail']}")
            lines.append("")
            if r["evidence"]:
                lines.append("**Evidence:**")
                lines.append("```")
                lines.append(r["evidence"])
                lines.append("```")
                lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Render the adversarial eval suite as a Markdown report.")
    parser.add_argument("--mode", choices=["mock", "live"], default="mock")
    parser.add_argument("-o", "--output", default=None, help="Write to this path instead of stdout")
    args = parser.parse_args()

    rows = _run_all(args.mode)
    report = _render_markdown(rows, args.mode)

    if args.output:
        Path(args.output).write_text(report)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(report)

    n_fail = sum(1 for r in rows if r["status"] != "DEFENDED")
    sys.exit(1 if n_fail else 0)


if __name__ == "__main__":
    main()
