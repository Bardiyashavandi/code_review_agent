#!/usr/bin/env python3
"""
evals/runner.py
------------------
Runs the full eval suite (evals/cases.py + evals/cost_estimate_cases.py)
and prints a pass/fail table.

Two modes:

  --mode live (the real eval)
      Constructs a real CodeReviewAgent with your GEMINI_API_KEY and calls
      the actual pipeline methods (generate_injection_audit, deduplicate_
      findings, generate_risk_scores, validate_review_findings, ...)
      against the fixture files/synthetic findings in each case. Scores
      real Gemini judgment. Requires GEMINI_API_KEY and GITHUB_TOKEN (the
      latter only because CodeReviewAgent's constructor requires a
      non-empty token; no GitHub network calls are made) and a working
      `semgrep` on PATH (CodeReviewAgent's constructor builds a
      SemgrepRunner even though these cases never call scan()). Live-mode
      cases are paced LIVE_MODE_INTER_CASE_DELAY_S apart (mirroring
      gemini_reviewer.py's own INTER_BATCH_DELAY_S) so an 18-case run
      doesn't rate-limit itself out of a clean result on free-tier RPM.

  --mode mock (default, harness self-test ONLY)
      Patches google.genai.Client to return each case's pre-scripted
      "ideal" response instead of calling Gemini. This proves the
      runner's plumbing, scoring logic, and result table all work
      correctly -- it does NOT tell you whether the real pipeline
      catches real vulnerabilities, since the "ideal" response is
      authored by the same person who wrote the scorer. Treat mock-mode
      passes as "the harness works", not "the pipeline works".

  The 2 cost_estimate cases are identical in both modes -- they touch no
  LLM at all, so they're a genuine, deterministic pass/fail regardless of
  --mode.

Usage:
    python3 runner.py                       # mock mode (default)
    python3 runner.py --mode live           # real eval, needs GEMINI_API_KEY
    python3 runner.py --mode live --category detection
    python3 runner.py --mode live --only det-01-sqli,fp-02-enum-table-name
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

_THIS_DIR = Path(__file__).parent
_REPO_ROOT = _THIS_DIR.parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_THIS_DIR))

from cases import ALL_CASES, FIXTURES_DIR, EvalCase  # noqa: E402
from cost_estimate_cases import run_cost_estimate_case_1, run_cost_estimate_case_2  # noqa: E402
from scorers import ScoreResult  # noqa: E402

_RESET, _BOLD, _DIM = "\033[0m", "\033[1m", "\033[2m"
_RED, _GREEN, _YELLOW, _CYAN = "\033[31m", "\033[32m", "\033[33m", "\033[36m"

# Free-tier Gemini RPM is tight enough that 18 back-to-back calls with zero
# pacing can exhaust it before the run finishes (gemini_reviewer.py's own
# production review() path already has this exact problem solved via
# INTER_BATCH_DELAY_S between batches). Mirror that here so --mode live
# doesn't rate-limit itself out of a clean run. Cost-estimate cases don't
# call this at all (no LLM), so they're unaffected.
LIVE_MODE_INTER_CASE_DELAY_S = 3


def _c(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{code}{text}{_RESET}"


def _build_live_agent():
    from agent import CodeReviewAgent

    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    github_token = os.environ.get("GITHUB_TOKEN", "eval-placeholder-token")
    if not gemini_key:
        print(_c(
            "GEMINI_API_KEY is not set. --mode live needs a real key "
            "(no GitHub network calls are made; GITHUB_TOKEN can stay a "
            "placeholder, but a real semgrep binary must be on PATH since "
            "CodeReviewAgent's constructor builds a SemgrepRunner).",
            _RED,
        ))
        sys.exit(1)
    return CodeReviewAgent(github_token=github_token, gemini_api_key=gemini_key)


def _mock_generate_content_factory(mock_text: str):
    def _fake(model, contents, config):
        return SimpleNamespace(text=mock_text)
    return _fake


def _run_llm_backed_case(case: EvalCase, mode: str) -> tuple[ScoreResult, float]:
    start = time.monotonic()
    if mode == "mock":
        with patch("agent.GitHubFetcher"), patch("agent.SemgrepRunner"), \
             patch("gemini_reviewer.genai.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_client.models.generate_content.side_effect = _mock_generate_content_factory(case.mock_text)

            from agent import CodeReviewAgent
            agent = CodeReviewAgent(github_token="mock-token", gemini_api_key="mock-key")
            raw = case.run(agent, FIXTURES_DIR)
    else:
        agent = _run_llm_backed_case._live_agent
        raw = case.run(agent, FIXTURES_DIR)

    result = case.score(raw)
    duration = time.monotonic() - start
    return result, duration


def _run_cost_estimate_cases(tmp_dir: Path) -> list[tuple[str, str, ScoreResult, float]]:
    out = []
    for case_id, description, fn in [
        ("cost-01-mixed-reliability",
         "RPD/token math on a realistic mix: real calls, no-usage-metadata call, "
         "cache hit, and a call from a different UTC day -- cross-checked against "
         "view_trace.py on the same file",
         run_cost_estimate_case_1),
        ("cost-02-stale-tokens-masking",
         "A tokens_available=False span with a stale/garbage total_tokens value must "
         "not leak into the sum; a span missing tokens_available entirely must "
         "resolve to 0, not crash",
         run_cost_estimate_case_2),
    ]:
        start = time.monotonic()
        result = fn(tmp_dir)
        duration = time.monotonic() - start
        out.append((case_id, description, result, duration))
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the code-review-agent eval suite.")
    parser.add_argument("--mode", choices=["mock", "live"], default="mock")
    parser.add_argument("--category", default=None,
                         help="Only run cases in this category "
                              "(detection|false_positive|dedup|risk_scoring|cost_estimate)")
    parser.add_argument("--only", default=None, help="Comma-separated case IDs to run")
    parser.add_argument("--json-out", default=None, help="Write full results as JSON to this path")
    args = parser.parse_args()

    only_ids = set(args.only.split(",")) if args.only else None

    print()
    print(_c(f"Eval suite — mode: {args.mode}", _BOLD + _CYAN))
    if args.mode == "mock":
        print(_c(
            "  mock mode: LLM-backed cases return pre-scripted responses. "
            "This is a harness self-test, NOT a real pipeline evaluation. "
            "Run with --mode live for real scores.",
            _YELLOW,
        ))
    print()

    llm_cases = [
        c for c in ALL_CASES
        if (only_ids is None or c.id in only_ids)
        and (args.category is None or c.category == args.category)
    ]

    if args.mode == "live":
        _run_llm_backed_case._live_agent = _build_live_agent()

    rows: list[dict] = []

    for i, case in enumerate(llm_cases):
        if args.mode == "live" and i > 0:
            time.sleep(LIVE_MODE_INTER_CASE_DELAY_S)
        try:
            result, duration = _run_llm_backed_case(case, args.mode)
            status = "PASS" if result.passed else "FAIL"
            detail = result.detail
        except Exception as exc:  # noqa: BLE001 — surface any failure as a row, don't crash the suite
            status, detail, duration = "ERROR", f"{type(exc).__name__}: {exc}", 0.0
        rows.append({
            "id": case.id, "category": case.category, "description": case.description,
            "status": status, "detail": detail, "duration_s": round(duration, 2),
        })

    if only_ids is None and (args.category is None or args.category == "cost_estimate"):
        with tempfile.TemporaryDirectory() as tmp:
            for case_id, description, result, duration in _run_cost_estimate_cases(Path(tmp)):
                if only_ids is not None and case_id not in only_ids:
                    continue
                status = "PASS" if result.passed else "FAIL"
                rows.append({
                    "id": case_id, "category": "cost_estimate", "description": description,
                    "status": status, "detail": result.detail, "duration_s": round(duration, 2),
                })

    _print_table(rows)

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(rows, indent=2))
        print(f"\nFull results written to {args.json_out}")

    n_fail = sum(1 for r in rows if r["status"] != "PASS")
    sys.exit(1 if n_fail else 0)


def _print_table(rows: list[dict]) -> None:
    by_category: dict[str, list[dict]] = {}
    for r in rows:
        by_category.setdefault(r["category"], []).append(r)

    total_pass = sum(1 for r in rows if r["status"] == "PASS")
    total = len(rows)

    for category, crows in by_category.items():
        cat_pass = sum(1 for r in crows if r["status"] == "PASS")
        print(_c(f"── {category} ({cat_pass}/{len(crows)}) ", _BOLD) + "─" * 40)
        for r in crows:
            icon = {"PASS": _c("✓ PASS ", _GREEN), "FAIL": _c("✗ FAIL ", _RED),
                     "ERROR": _c("‼ ERROR", _RED)}[r["status"]]
            print(f"  {icon}  {r['id']:<32} ({r['duration_s']}s)")
            print(f"          {r['description']}")
            print(_c(f"          {r['detail']}", _DIM))
        print()

    color = _GREEN if total_pass == total else (_RED if total_pass == 0 else _YELLOW)
    print(_c(f"TOTAL: {total_pass}/{total} passed", _BOLD + color))
    print()


if __name__ == "__main__":
    main()
